use hbb_common::{
    config::{Config, Socks5Server},
    log::{self, info},
    proxy::{Proxy, ProxyScheme},
    tls::{get_cached_tls_type, is_plain, upsert_tls_type, TlsType},
};
use reqwest::{blocking::Client as SyncClient, Client as AsyncClient};

macro_rules! configure_http_client {
    ($builder:expr, $tls_type:expr, $Client: ty) => {{
        // https://github.com/rustdesk/rustdesk/issues/11569
        // https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.no_proxy
        let mut builder = $builder.no_proxy();

        match $tls_type {
            TlsType::Plain => {}
            TlsType::NativeTls => {
                builder = builder.use_native_tls();
            }
            TlsType::Rustls => {
                builder = builder.use_rustls_tls();
            }
        }

        let client = if let Some(conf) = Config::get_socks() {
            let proxy_result = Proxy::from_conf(&conf, None);

            match proxy_result {
                Ok(proxy) => {
                    let proxy_setup = match &proxy.intercept {
                        ProxyScheme::Http { host, .. } => {
                            reqwest::Proxy::all(format!("http://{}", host))
                        }
                        ProxyScheme::Https { host, .. } => {
                            reqwest::Proxy::all(format!("https://{}", host))
                        }
                        ProxyScheme::Socks5 { addr, .. } => {
                            reqwest::Proxy::all(&format!("socks5://{}", addr))
                        }
                    };

                    match proxy_setup {
                        Ok(p) => {
                            builder = builder.proxy(p);
                            if let Some(auth) = proxy.intercept.maybe_auth() {
                                let basic_auth =
                                    format!("Basic {}", auth.get_basic_authorization());
                                if let Ok(auth) = basic_auth.parse() {
                                    builder = builder.default_headers(
                                        vec![(reqwest::header::PROXY_AUTHORIZATION, auth)]
                                            .into_iter()
                                            .collect(),
                                    );
                                }
                            }
                            builder.build().unwrap_or_else(|e| {
                                info!("Failed to create a proxied client: {}", e);
                                <$Client>::new()
                            })
                        }
                        Err(e) => {
                            info!("Failed to set up proxy: {}", e);
                            <$Client>::new()
                        }
                    }
                }
                Err(e) => {
                    info!("Failed to configure proxy: {}", e);
                    <$Client>::new()
                }
            }
        } else {
            builder.build().unwrap_or_else(|e| {
                info!("Failed to create a client: {}", e);
                <$Client>::new()
            })
        };

        client
    }};
}

pub fn create_http_client(tls_type: TlsType) -> SyncClient {
    let builder = SyncClient::builder();
    configure_http_client!(builder, tls_type, SyncClient)
}

pub fn create_http_client_async(tls_type: TlsType) -> AsyncClient {
    let builder = AsyncClient::builder();
    configure_http_client!(builder, tls_type, AsyncClient)
}

pub fn get_url_for_tls<'a>(url: &'a str, proxy_conf: &'a Option<Socks5Server>) -> &'a str {
    if is_plain(url) {
        if let Some(conf) = proxy_conf {
            if conf.proxy.starts_with("https://") {
                return &conf.proxy;
            }
        }
    }
    url
}

pub fn create_http_client_with_url(url: &str) -> SyncClient {
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let tls_type = get_cached_tls_type(tls_url);
    let is_tls_cached = tls_type.is_some();
    let tls_type = tls_type.unwrap_or(TlsType::NativeTls);
    let mut client = create_http_client(tls_type);
    if is_tls_cached {
        return client;
    }
    if let Err(e) = client.head(url).send() {
        if e.is_request() {
            log::warn!(
                "Failed to connect to server {} with native-tls: {}. Trying rustls-tls",
                tls_url,
                e
            );
            client = create_http_client(TlsType::Rustls);
            if let Err(e2) = client.head(url).send() {
                log::warn!(
                    "Failed to connect to server {} with rustls-tls: {}. Keep using rustls-tls",
                    tls_url,
                    e2
                );
            } else {
                log::info!("Successfully switched to rustls-tls");
                upsert_tls_type(tls_url, TlsType::Rustls);
            }
        } else {
            log::warn!(
                "Failed to connect to server {} with {:?}, err: {}.",
                tls_url,
                tls_type,
                e
            );
        }
    } else {
        log::info!(
            "Successfully connected to server {} with {:?}",
            tls_url,
            tls_type
        );
        upsert_tls_type(tls_url, tls_type);
    }
    client
}

pub async fn create_http_client_async_with_url(url: &str) -> AsyncClient {
    let proxy_conf = Config::get_socks();
    let tls_url = get_url_for_tls(url, &proxy_conf);
    let tls_type = get_cached_tls_type(tls_url);
    let is_tls_cached = tls_type.is_some();
    let tls_type = tls_type.unwrap_or(TlsType::NativeTls);
    let mut client = create_http_client_async(tls_type);
    if is_tls_cached {
        return client;
    }
    if let Err(e) = client.head(url).send().await {
        if e.is_request() {
            log::warn!(
                "Failed to connect to server {} with native-tls: {}. Trying rustls-tls",
                tls_url,
                e
            );
            client = create_http_client_async(TlsType::Rustls);
            if let Err(e2) = client.head(url).send().await {
                log::warn!(
                    "Failed to connect to server {} with rustls-tls: {}. Keep using rustls-tls",
                    tls_url,
                    e2
                );
            } else {
                log::info!("Successfully switched to rustls-tls");
                upsert_tls_type(tls_url, TlsType::Rustls);
            }
        } else {
            log::warn!(
                "Failed to connect to server {} with {:?}, err: {}.",
                tls_url,
                tls_type,
                e
            );
        }
    } else {
        log::info!(
            "Successfully connected to server {} with {:?}",
            tls_url,
            tls_type
        );
        upsert_tls_type(tls_url, tls_type);
    }
    client
}
