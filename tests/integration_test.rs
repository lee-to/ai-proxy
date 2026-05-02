use axum::{Router, routing::any};
use bytes::Bytes;
use std::sync::Arc;
use tokio::net::TcpListener;

// We need to reference the library types. Since this is a binary crate,
// we'll test through HTTP requests to the proxy and a mock upstream.

/// Start a mock upstream server that echoes the request body back.
async fn start_mock_upstream() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|body: Bytes| async move {
                // Echo the received body back, so we can verify what the proxy sent
                body
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_json_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::body::Body;
    use axum::response::Response;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|body: Bytes| async move {
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

/// Start a mock upstream that returns SSE-style streaming response.
async fn start_sse_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::body::Body;
    use axum::response::Response;
    use futures_util::stream;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|| async {
                let chunks = vec![
                    Ok::<_, std::io::Error>(Bytes::from("data: {\"type\":\"content\"}\n\n")),
                    Ok(Bytes::from("data: {\"type\":\"done\"}\n\n")),
                ];
                let stream = stream::iter(chunks);
                let body = Body::from_stream(stream);
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(body)
                    .unwrap()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_sse_placeholder_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::body::Body;
    use axum::response::Response;
    use futures_util::stream;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|| async {
                let chunks = vec![
                    Ok::<_, std::io::Error>(Bytes::from("data: hello [EMA")),
                    Ok(Bytes::from("IL_1]\n\n")),
                ];
                let body = Body::from_stream(stream::iter(chunks));
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(body)
                    .unwrap()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_usage_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::body::Body;
    use axum::response::Response;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|| async {
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":11,"total_tokens":18}}"#,
                    ))
                    .unwrap()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_gzip_response_upstream() -> (String, tokio::task::JoinHandle<()>, Vec<u8>) {
    use axum::body::Body;
    use axum::response::Response;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(b"{\"ok\":true}").unwrap();
    let compressed = encoder.finish().unwrap();
    let upstream_body = compressed.clone();

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(move || {
                let body = upstream_body.clone();
                async move {
                    Response::builder()
                        .header("content-encoding", "gzip")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle, compressed)
}

async fn start_header_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::http::HeaderMap;
    use axum::response::Response;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|headers: HeaderMap, body: Bytes| async move {
                let content_encoding = headers
                    .get("content-encoding")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                Response::builder()
                    .header("x-received-content-encoding", content_encoding)
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_custom_header_echo_upstream(
    header_name: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    use axum::http::HeaderMap;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(move |headers: HeaderMap| async move {
                headers
                    .get(header_name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .to_string()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_cookie_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::body::Body;
    use axum::response::Response;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|| async {
                Response::builder()
                    .header("set-cookie", "a=1; Path=/")
                    .header("set-cookie", "b=2; Path=/")
                    .body(Body::from("ok"))
                    .unwrap()
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_query_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::extract::OriginalUri;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|OriginalUri(uri): OriginalUri| async move {
                uri.path_and_query()
                    .map(|value| value.as_str().to_string())
                    .unwrap_or_else(|| uri.path().to_string())
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn start_websocket_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::accept_async;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut websocket) = accept_async(stream).await else {
                    return;
                };
                while let Some(message) = websocket.next().await {
                    let Ok(message) = message else {
                        break;
                    };
                    let message = match message {
                        tokio_tungstenite::tungstenite::Message::Text(text) => {
                            tokio_tungstenite::tungstenite::Message::Text(
                                format!(
                                    r#"{} {{"upstream_key":"sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}}"#,
                                    text
                                )
                                .into(),
                            )
                        }
                        other => other,
                    };
                    if websocket.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (url, handle)
}

async fn start_websocket_usage_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut websocket) = accept_async(stream).await else {
                    return;
                };
                if websocket.next().await.is_some() {
                    let usage = r#"{"type":"response.completed","response":{"model":"gpt-test","usage":{"input_tokens":21,"output_tokens":34,"total_tokens":55}}}"#;
                    let _ = websocket.send(Message::Text(usage.into())).await;
                }
            });
        }
    });

    (url, handle)
}

async fn start_tcp_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            });
        }
    });

    (addr.to_string(), handle)
}

async fn start_tls_echo_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use ai_proxy::mitm::normalize_connect_host;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = normalize_connect_host(&addr.to_string()).unwrap();

    let key_pair = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![host])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .unwrap();
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|req: Request<Incoming>| async move {
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    Ok::<_, std::convert::Infallible>(Response::new(Body::from(body)))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            });
        }
    });

    (addr.to_string(), handle)
}

async fn start_tls_sse_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use ai_proxy::mitm::normalize_connect_host;
    use axum::body::Body;
    use futures_util::stream;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = normalize_connect_host(&addr.to_string()).unwrap();

    let key_pair = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![host])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .unwrap();
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|_req: Request<Incoming>| async move {
                    let chunks = vec![
                        Ok::<_, std::io::Error>(Bytes::from("data: {\"type\":\"content\"}\n\n")),
                        Ok(Bytes::from("data: {\"type\":\"done\"}\n\n")),
                    ];
                    let body = Body::from_stream(stream::iter(chunks));
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(body)
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            });
        }
    });

    (addr.to_string(), handle)
}

fn write_temp_mitm_ca() -> (std::path::PathBuf, std::path::PathBuf, reqwest::Certificate) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static CA_COUNTER: AtomicU64 = AtomicU64::new(0);

    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "ai-proxy test ca");
    params.distinguished_name = distinguished_name;

    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = CA_COUNTER.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    let base =
        std::env::temp_dir().join(format!("ai-proxy-mitm-ca-{process_id}-{nonce}-{counter}"));
    fs::create_dir_all(&base).unwrap();
    let cert_path = base.join("ca.pem");
    let key_path = base.join("ca-key.pem");
    fs::write(&cert_path, cert_pem.as_bytes()).unwrap();
    fs::write(&key_path, key_pem).unwrap();
    let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();

    (cert_path, key_path, reqwest_cert)
}

fn write_temp_mitm_ca_with_der() -> (
    std::path::PathBuf,
    std::path::PathBuf,
    reqwest::Certificate,
    rustls::pki_types::CertificateDer<'static>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static CA_COUNTER: AtomicU64 = AtomicU64::new(0);

    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "ai-proxy test ca");
    params.distinguished_name = distinguished_name;

    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = CA_COUNTER.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    let base = std::env::temp_dir().join(format!(
        "ai-proxy-mitm-ca-der-{process_id}-{nonce}-{counter}"
    ));
    fs::create_dir_all(&base).unwrap();
    let cert_path = base.join("ca.pem");
    let key_path = base.join("ca-key.pem");
    fs::write(&cert_path, cert_pem.as_bytes()).unwrap();
    fs::write(&key_path, key_pem).unwrap();
    let reqwest_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

    (cert_path, key_path, reqwest_cert, rustls_cert)
}

/// Build and start the proxy server pointed at the given upstream URL.
async fn start_proxy(upstream_url: &str) -> (String, tokio::task::JoinHandle<()>) {
    start_proxy_with_scanner(upstream_url, true).await
}

async fn start_proxy_with_scanner(
    upstream_url: &str,
    scanner_enabled: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    start_proxy_with_options(upstream_url, scanner_enabled, "body").await
}

async fn start_proxy_with_options(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .unwrap();

    start_proxy_with_custom_client(
        upstream_url,
        scanner_enabled,
        scan_scope,
        http_client,
        None,
        false,
        vec![],
        "inspect",
    )
    .await
}

async fn start_proxy_with_placeholder_restore(
    upstream_url: &str,
    scan_scope: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .unwrap();

    start_proxy_with_custom_client_redaction_and_telemetry(
        upstream_url,
        true,
        scan_scope,
        http_client,
        None,
        false,
        vec![],
        "inspect",
        None,
        "placeholder",
        true,
    )
    .await
}

async fn start_mitm_proxy_with_options(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    excluded_hosts: Vec<String>,
) -> (String, tokio::task::JoinHandle<()>) {
    start_mitm_proxy_with_websocket_mode(
        upstream_url,
        scanner_enabled,
        scan_scope,
        cert_path,
        key_path,
        excluded_hosts,
        "inspect",
    )
    .await
}

async fn start_mitm_proxy_with_websocket_mode(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    excluded_hosts: Vec<String>,
    websocket_mode: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    start_mitm_proxy_with_websocket_mode_and_telemetry(
        upstream_url,
        scanner_enabled,
        scan_scope,
        cert_path,
        key_path,
        excluded_hosts,
        websocket_mode,
        None,
    )
    .await
}

async fn start_mitm_proxy_with_websocket_mode_and_telemetry(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    excluded_hosts: Vec<String>,
    websocket_mode: &str,
    telemetry_store: Option<Arc<ai_proxy::telemetry_store::TelemetryStore>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .unwrap();
    let mitm_authority = ai_proxy::mitm::MitmAuthority::load(&cert_path, &key_path, 256).unwrap();

    start_proxy_with_custom_client_and_telemetry(
        upstream_url,
        scanner_enabled,
        scan_scope,
        http_client,
        Some(Arc::new(mitm_authority)),
        true,
        excluded_hosts,
        websocket_mode,
        telemetry_store,
    )
    .await
}

async fn start_proxy_with_custom_client(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
    http_client: reqwest::Client,
    mitm_authority: Option<Arc<ai_proxy::mitm::MitmAuthority>>,
    mitm_enabled: bool,
    mitm_excluded_hosts: Vec<String>,
    websocket_mode: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    start_proxy_with_custom_client_and_telemetry(
        upstream_url,
        scanner_enabled,
        scan_scope,
        http_client,
        mitm_authority,
        mitm_enabled,
        mitm_excluded_hosts,
        websocket_mode,
        None,
    )
    .await
}

async fn start_proxy_with_custom_client_and_telemetry(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
    http_client: reqwest::Client,
    mitm_authority: Option<Arc<ai_proxy::mitm::MitmAuthority>>,
    mitm_enabled: bool,
    mitm_excluded_hosts: Vec<String>,
    websocket_mode: &str,
    telemetry_store: Option<Arc<ai_proxy::telemetry_store::TelemetryStore>>,
) -> (String, tokio::task::JoinHandle<()>) {
    start_proxy_with_custom_client_redaction_and_telemetry(
        upstream_url,
        scanner_enabled,
        scan_scope,
        http_client,
        mitm_authority,
        mitm_enabled,
        mitm_excluded_hosts,
        websocket_mode,
        telemetry_store,
        "partial",
        false,
    )
    .await
}

async fn start_proxy_with_custom_client_redaction_and_telemetry(
    upstream_url: &str,
    scanner_enabled: bool,
    scan_scope: &str,
    http_client: reqwest::Client,
    mitm_authority: Option<Arc<ai_proxy::mitm::MitmAuthority>>,
    mitm_enabled: bool,
    mitm_excluded_hosts: Vec<String>,
    websocket_mode: &str,
    telemetry_store: Option<Arc<ai_proxy::telemetry_store::TelemetryStore>>,
    redaction_strategy: &str,
    response_restore_enabled: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    use ai_proxy::config::*;
    use ai_proxy::middleware::ScanPipeline;
    use ai_proxy::middleware::regex_scanner::RegexScanner;
    use ai_proxy::middleware::structural_scanner::StructuralScanner;
    use ai_proxy::proxy::{AppState, proxy_handler};
    use ai_proxy::redactor::Redactor;

    let config = Config {
        proxy: ProxyConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            anthropic_upstream_url: upstream_url.to_string(),
            codex_upstream_url: upstream_url.to_string(),
            codex_subscription_url: format!("{}/backend-api/codex/responses", upstream_url),
            codex_subscription_routing_enabled: true,
            rate_limit_enabled: true,
            max_body_size: 10 * 1024 * 1024,
            connect_timeout_secs: 10,
            request_timeout_secs: 30,
            rate_limit_rps: 1000,
            mitm_enabled,
            mitm_ca_cert_path: None,
            mitm_ca_key_path: None,
            mitm_cert_cache_size: 256,
            mitm_excluded_hosts,
            websocket_mode: websocket_mode.to_string(),
        },
        dashboard: DashboardConfig::default(),
        redaction: RedactionConfig {
            strategy: redaction_strategy.to_string(),
            prefix_len: 3,
            suffix_len: 3,
            mask: "***...***".to_string(),
            response_restore_enabled,
            restorable_categories: vec![
                "email".to_string(),
                "person_name".to_string(),
                "phone".to_string(),
            ],
        },
        scanner: ScannerConfig {
            enabled: scanner_enabled,
            scan_scope: scan_scope.to_string(),
            header_whitelist: vec!["authorization".to_string()],
            model: ModelScannerConfig::default(),
            privacy_filter: PrivacyFilterScannerConfig::default(),
            regex: RegexScannerConfig {
                enabled: true,
                patterns: vec![
                    RegexPattern {
                        name: "aws_access_key".to_string(),
                        pattern: "AKIA[0-9A-Z]{16}".to_string(),
                    },
                    RegexPattern {
                        name: "anthropic_api_key".to_string(),
                        pattern: "sk-ant-[A-Za-z0-9-]{20,}".to_string(),
                    },
                    RegexPattern {
                        name: "email".to_string(),
                        pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}".to_string(),
                    },
                ],
            },
            entropy: EntropyScannerConfig {
                enabled: false,
                threshold: 4.5,
                min_length: 20,
                max_length: 256,
                keywords: vec![],
                keyword_proximity: 50,
            },
            structural: StructuralScannerConfig {
                enabled: true,
                detect_jwt: true,
                detect_connection_strings: true,
                detect_env_patterns: true,
            },
        },
    };

    let mut pipeline = ScanPipeline::new();
    if config.scanner.enabled {
        pipeline.add_scanner(Box::new(RegexScanner::new(&config.scanner.regex)));
        pipeline.add_scanner(Box::new(StructuralScanner::new(&config.scanner.structural)));
    }

    let redactor = Redactor::new(&config.redaction);

    let state = Arc::new(AppState {
        config,
        pipeline,
        redactor,
        http_client,
        mitm_authority,
        telemetry_store,
    });

    let app = Router::new()
        .route("/{*path}", any(proxy_handler))
        .fallback(any(proxy_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

#[tokio::test]
async fn test_proxy_redacts_aws_key_in_body() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-type", "application/json")
        .body(r#"{"messages":[{"content":"My AWS key is AKIAIOSFODNN7EXAMPLE"}]}"#)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();

    // The echoed body should NOT contain the original AWS key
    assert!(
        !body.contains("AKIAIOSFODNN7EXAMPLE"),
        "AWS key should be redacted, got: {}",
        body
    );
    // Should contain the masked version
    assert!(
        body.contains("***...***"),
        "Should contain mask pattern, got: {}",
        body
    );
}

#[tokio::test]
async fn test_proxy_restores_reversible_email_but_not_secret_placeholder() {
    let (upstream_url, _upstream_handle) = start_json_echo_upstream().await;
    let (proxy_url, _proxy_handle) =
        start_proxy_with_placeholder_restore(&upstream_url, "body").await;

    let email = "ada@example.com";
    let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"email":"{email}","key":"{secret}"}}"#))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(
        body.contains(email),
        "Email placeholder should be restored in downstream response, got: {body}"
    );
    assert!(
        !body.contains(secret),
        "Secret placeholder must not be restored, got: {body}"
    );
    assert!(
        body.contains("[API_KEY_1]"),
        "Secret should remain an irreversible typed placeholder, got: {body}"
    );
}

#[tokio::test]
async fn test_proxy_full_scan_restores_header_and_query_placeholders() {
    let (header_upstream_url, _header_handle) =
        start_custom_header_echo_upstream("x-user-email").await;
    let (header_proxy_url, _header_proxy_handle) =
        start_proxy_with_placeholder_restore(&header_upstream_url, "full").await;
    let email = "ada@example.com";
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let header_response = client
        .post(format!("{}/v1/messages", header_proxy_url))
        .header("x-user-email", email)
        .body("{}")
        .send()
        .await
        .unwrap();
    let header_body = header_response.text().await.unwrap();
    assert_eq!(header_body, email);

    let (query_upstream_url, _query_handle) = start_query_echo_upstream().await;
    let (query_proxy_url, _query_proxy_handle) =
        start_proxy_with_placeholder_restore(&query_upstream_url, "full").await;
    let query_response = client
        .get(format!("{}/v1/messages?email={}", query_proxy_url, email))
        .send()
        .await
        .unwrap();
    let query_body = query_response.text().await.unwrap();
    assert!(
        query_body.contains(email),
        "Query placeholder should be restored in response, got: {query_body}"
    );
}

#[tokio::test]
async fn test_proxy_restores_split_sse_placeholder() {
    let (upstream_url, _upstream_handle) = start_sse_placeholder_upstream().await;
    let (proxy_url, _proxy_handle) =
        start_proxy_with_placeholder_restore(&upstream_url, "body").await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-type", "application/json")
        .body(r#"{"email":"ada@example.com"}"#)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(
        body.contains("data: hello ada@example.com"),
        "Split SSE placeholder should be restored, got: {body}"
    );
}

#[tokio::test]
async fn test_proxy_persists_usage_without_changing_response() {
    let (upstream_url, _upstream_handle) = start_usage_upstream().await;
    let telemetry_store = Arc::new(
        ai_proxy::telemetry_store::TelemetryStore::open_in_memory(24)
            .await
            .unwrap(),
    );
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .unwrap();
    let (proxy_url, _proxy_handle) = start_proxy_with_custom_client_and_telemetry(
        &upstream_url,
        false,
        "body",
        http_client,
        None,
        false,
        vec![],
        "inspect",
        Some(telemetry_store.clone()),
    )
    .await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-test","input":"hello"}"#)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(
        body,
        r#"{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":11,"total_tokens":18}}"#
    );

    let dashboard = telemetry_store.usage_dashboard(24).await.unwrap();
    assert_eq!(dashboard.totals.input_tokens, 7);
    assert_eq!(dashboard.totals.output_tokens, 11);
    assert_eq!(dashboard.totals.total_tokens, 18);
    assert_eq!(dashboard.totals.request_count, 1);
}

#[tokio::test]
async fn test_proxy_redacts_anthropic_key() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .body(format!(r#"{{"key":"{}"}}"#, secret))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(
        !body.contains(secret),
        "Anthropic key should be redacted, got: {}",
        body
    );
}

#[tokio::test]
async fn test_proxy_can_disable_secret_scanning() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy_with_scanner(&upstream_url, false).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .body(format!(r#"{{"key":"{}"}}"#, secret))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(
        body.contains(secret),
        "Secret should pass through unchanged when scanning is disabled, got: {}",
        body
    );
}

#[tokio::test]
async fn test_proxy_preserves_non_utf8_body() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let binary_body = vec![0xff, 0xfe, 0xfd, b'A', b'K', b'I', b'A'];
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-type", "application/octet-stream")
        .body(binary_body.clone())
        .send()
        .await
        .unwrap();

    let body = response.bytes().await.unwrap();
    assert_eq!(body.as_ref(), binary_body.as_slice());
}

#[tokio::test]
async fn test_proxy_rejects_content_encoding_when_decode_fails() {
    let (upstream_url, _upstream_handle) = start_header_echo_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let corrupt_gzip = vec![0x1f, 0x8b, 0xff, 0xff];
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-encoding", "gzip")
        .body(corrupt_gzip.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_proxy_rejects_oversized_decompressed_body() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let oversized_body = vec![b'a'; 10 * 1024 * 1024 + 1];
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&oversized_body).unwrap();
    let compressed = encoder.finish().unwrap();

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-encoding", "gzip")
        .body(compressed)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_proxy_passes_clean_body_unchanged() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let clean_body = r#"{"messages":[{"content":"Hello, how are you?"}]}"#;
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("content-type", "application/json")
        .body(clean_body)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, clean_body, "Clean body should pass through unchanged");
}

#[tokio::test]
async fn test_proxy_forwards_headers() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .header("x-custom-header", "test-value")
        .header("anthropic-version", "2023-06-01")
        .body("hello")
        .send()
        .await
        .unwrap();

    // Just verify the proxy doesn't error out
    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_proxy_streams_sse_response() {
    let (upstream_url, _upstream_handle) = start_sse_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .body("test")
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());

    let body = response.text().await.unwrap();
    assert!(
        body.contains("data: {\"type\":\"content\"}"),
        "SSE data should be streamed through, got: {}",
        body
    );
    assert!(
        body.contains("data: {\"type\":\"done\"}"),
        "All SSE events should arrive, got: {}",
        body
    );
}

#[tokio::test]
async fn test_proxy_preserves_compressed_upstream_response() {
    let (upstream_url, _upstream_handle, compressed) = start_gzip_response_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .build()
        .unwrap();
    let response = client
        .get(format!("{}/v1/messages", proxy_url))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let body = response.bytes().await.unwrap();
    assert_eq!(body.as_ref(), compressed.as_slice());
}

#[tokio::test]
async fn test_proxy_supports_http_connect_tunnel() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let (target_addr, _target_handle) = start_tcp_echo_upstream().await;
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;
    let proxy_addr = proxy_url.trim_start_matches("http://");

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let response_text = String::from_utf8(response).unwrap();
    assert!(
        response_text.starts_with("HTTP/1.1 200"),
        "CONNECT response should be 200, got: {response_text}"
    );

    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn test_mitm_connect_redacts_https_body() {
    let (target_addr, _target_handle) = start_tls_echo_upstream().await;
    let upstream_url = format!("https://{target_addr}");
    let (cert_path, key_path, ca_cert) = write_temp_mitm_ca();
    let (proxy_url, _proxy_handle) =
        start_mitm_proxy_with_options(&upstream_url, true, "body", cert_path, key_path, vec![])
            .await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();

    let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    let response = client
        .post(format!("https://{target_addr}/v1/messages"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"key":"{}"}}"#, secret))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(
        !body.contains(secret),
        "MITM HTTPS body should be redacted, got: {body}"
    );
    assert!(
        body.contains("***...***"),
        "MITM HTTPS body should contain mask, got: {body}"
    );
}

#[tokio::test]
async fn test_mitm_codex_responses_routes_to_subscription_url() {
    let (target_addr, _target_handle) = start_tls_echo_upstream().await;
    let (subscription_url, _subscription_handle) = start_query_echo_upstream().await;
    let (cert_path, key_path, ca_cert) = write_temp_mitm_ca();
    let (proxy_url, _proxy_handle) =
        start_mitm_proxy_with_options(&subscription_url, true, "body", cert_path, key_path, vec![])
            .await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();

    let response = client
        .post(format!("https://{target_addr}/v1/responses?foo=bar"))
        .header("authorization", "Bearer opaque-subscription-token")
        .body(r#"{"model":"gpt-5","input":"hello"}"#)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, "/backend-api/codex/responses?foo=bar");
}

#[tokio::test]
async fn test_mitm_rejects_websocket_upgrade_for_codex_fallback() {
    let (target_addr, _target_handle) = start_tls_echo_upstream().await;
    let (subscription_url, _subscription_handle) = start_query_echo_upstream().await;
    let (cert_path, key_path, ca_cert) = write_temp_mitm_ca();
    let (proxy_url, _proxy_handle) = start_mitm_proxy_with_websocket_mode(
        &subscription_url,
        true,
        "body",
        cert_path,
        key_path,
        vec![],
        "reject",
    )
    .await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();

    let response = client
        .get(format!("https://{target_addr}/v1/responses"))
        .header("authorization", "Bearer opaque-subscription-token")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn test_mitm_proxies_websocket_upgrade_and_redacts_text_frames() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_tungstenite::client_async;
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    let (subscription_url, _subscription_handle) = start_websocket_echo_upstream().await;
    let (cert_path, key_path, _ca_cert, ca_der) = write_temp_mitm_ca_with_der();
    let (proxy_url, _proxy_handle) =
        start_mitm_proxy_with_options(&subscription_url, true, "body", cert_path, key_path, vec![])
            .await;
    let proxy_addr = proxy_url.trim_start_matches("http://");
    let target_authority = "localhost:443";

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!("CONNECT {target_authority} HTTP/1.1\r\nHost: {target_authority}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let response_text = String::from_utf8(response).unwrap();
    assert!(
        response_text.starts_with("HTTP/1.1 200"),
        "CONNECT response should be 200, got: {response_text}"
    );

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, stream).await.unwrap();

    let mut request = "wss://localhost/v1/responses"
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        "Bearer opaque-subscription-token".parse().unwrap(),
    );
    request.headers_mut().insert(
        "sec-websocket-extensions",
        "permessage-deflate".parse().unwrap(),
    );
    let (mut websocket, handshake_response) = client_async(request, tls_stream).await.unwrap();
    assert_eq!(
        handshake_response.status(),
        tokio_tungstenite::tungstenite::http::StatusCode::SWITCHING_PROTOCOLS
    );
    assert!(
        handshake_response
            .headers()
            .get("sec-websocket-extensions")
            .is_none(),
        "MITM frame inspection must not negotiate compression extensions"
    );

    let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    websocket
        .send(Message::Text(format!(r#"{{"key":"{secret}"}}"#).into()))
        .await
        .unwrap();

    let echoed = websocket.next().await.unwrap().unwrap();
    let echoed_text = echoed.into_text().unwrap();
    assert!(
        !echoed_text.contains(secret),
        "WebSocket client and upstream frame secrets should be redacted, got: {echoed_text}"
    );
    assert!(
        echoed_text.contains("***...***"),
        "WebSocket frame should contain mask, got: {echoed_text}"
    );
}

#[tokio::test]
async fn test_mitm_websocket_persists_codex_usage() {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_tungstenite::client_async;
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    let (subscription_url, _subscription_handle) = start_websocket_usage_upstream().await;
    let telemetry_store = Arc::new(
        ai_proxy::telemetry_store::TelemetryStore::open_in_memory(24)
            .await
            .unwrap(),
    );
    let (cert_path, key_path, _ca_cert, ca_der) = write_temp_mitm_ca_with_der();
    let (proxy_url, _proxy_handle) = start_mitm_proxy_with_websocket_mode_and_telemetry(
        &subscription_url,
        true,
        "body",
        cert_path,
        key_path,
        vec![],
        "inspect",
        Some(telemetry_store.clone()),
    )
    .await;
    let proxy_addr = proxy_url.trim_start_matches("http://");
    let target_authority = "localhost:443";

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!("CONNECT {target_authority} HTTP/1.1\r\nHost: {target_authority}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, stream).await.unwrap();

    let mut request = "wss://localhost/v1/responses"
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        "Bearer opaque-subscription-token".parse().unwrap(),
    );
    let (mut websocket, _) = client_async(request, tls_stream).await.unwrap();
    websocket
        .send(Message::Text(
            r#"{"model":"gpt-test","input":"hello"}"#.into(),
        ))
        .await
        .unwrap();

    let usage_message = websocket.next().await.unwrap().unwrap();
    assert!(
        usage_message
            .into_text()
            .unwrap()
            .contains("response.completed")
    );

    let dashboard = telemetry_store.usage_dashboard(24).await.unwrap();
    assert_eq!(dashboard.totals.input_tokens, 21);
    assert_eq!(dashboard.totals.output_tokens, 34);
    assert_eq!(dashboard.totals.total_tokens, 55);
    assert_eq!(dashboard.by_model[0].name, "gpt-test");
}

#[tokio::test]
async fn test_mitm_connect_preserves_sse_response() {
    let (target_addr, _target_handle) = start_tls_sse_upstream().await;
    let upstream_url = format!("https://{target_addr}");
    let (cert_path, key_path, ca_cert) = write_temp_mitm_ca();
    let (proxy_url, _proxy_handle) =
        start_mitm_proxy_with_options(&upstream_url, true, "body", cert_path, key_path, vec![])
            .await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();

    let response = client
        .post(format!("https://{target_addr}/v1/messages"))
        .body("test")
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    let body = response.text().await.unwrap();
    assert!(body.contains("data: {\"type\":\"content\"}"));
    assert!(body.contains("data: {\"type\":\"done\"}"));
}

#[tokio::test]
async fn test_mitm_connect_rejects_oversized_decompressed_body() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let (target_addr, _target_handle) = start_tls_echo_upstream().await;
    let upstream_url = format!("https://{target_addr}");
    let (cert_path, key_path, ca_cert) = write_temp_mitm_ca();
    let (proxy_url, _proxy_handle) =
        start_mitm_proxy_with_options(&upstream_url, true, "body", cert_path, key_path, vec![])
            .await;

    let oversized_body = vec![b'a'; 10 * 1024 * 1024 + 1];
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&oversized_body).unwrap();
    let compressed = encoder.finish().unwrap();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();

    let response = client
        .post(format!("https://{target_addr}/v1/messages"))
        .header("content-encoding", "gzip")
        .body(compressed)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_mitm_excluded_host_uses_blind_connect_tunnel() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let (target_addr, _target_handle) = start_tcp_echo_upstream().await;
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (cert_path, key_path, _ca_cert) = write_temp_mitm_ca();
    let (proxy_url, _proxy_handle) = start_mitm_proxy_with_options(
        &upstream_url,
        true,
        "body",
        cert_path,
        key_path,
        vec!["127.0.0.1".to_string()],
    )
    .await;
    let proxy_addr = proxy_url.trim_start_matches("http://");

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(
            format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let response_text = String::from_utf8(response).unwrap();
    assert!(
        response_text.starts_with("HTTP/1.1 200"),
        "CONNECT response should be 200, got: {response_text}"
    );

    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn test_proxy_preserves_duplicate_response_headers() {
    let (upstream_url, _upstream_handle) = start_cookie_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/messages", proxy_url))
        .body("test")
        .send()
        .await
        .unwrap();

    let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies.len(), 2);
}

#[tokio::test]
async fn test_full_scan_preserves_query_when_no_secret_changes() {
    let (upstream_url, _upstream_handle) = start_query_echo_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy_with_options(&upstream_url, true, "full").await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .get(format!("{}/v1/messages?flag&x=a%20b", proxy_url))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, "/v1/messages?flag&x=a%20b");
}

#[tokio::test]
async fn test_full_scan_preserves_unchanged_query_encoding_when_redacting() {
    let (upstream_url, _upstream_handle) = start_query_echo_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy_with_options(&upstream_url, true, "full").await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .get(format!(
            "{}/v1/messages?x=a%20b&email=ada@example.com&flag",
            proxy_url
        ))
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert!(
        body.contains("x=a%20b"),
        "Unchanged query encoding should be preserved, got: {body}"
    );
    assert!(
        body.contains("email=ada***...***com"),
        "Changed query value should be redacted, got: {body}"
    );
    assert!(
        body.ends_with("&flag"),
        "Flag query segment should be preserved, got: {body}"
    );
}

#[tokio::test]
async fn test_codex_responses_routes_to_codex_upstream() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let clean_body = r#"{"model":"gpt-5","input":"hello"}"#;
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer sk-test")
        .header("content-type", "application/json")
        .body(clean_body)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(
        body, clean_body,
        "Codex request should pass through unchanged"
    );
}

#[tokio::test]
async fn test_codex_non_api_key_auth_uses_subscription_upstream_by_default() {
    let (upstream_url, _upstream_handle) = start_query_echo_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let clean_body = r#"{"model":"gpt-5","input":"hello"}"#;
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer opaque-provider-token")
        .body(clean_body)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, "/backend-api/codex/responses");
}

#[tokio::test]
async fn test_codex_subscription_forces_store_false() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer opaque-provider-token")
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-5","input":"compact","store":true}"#)
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["store"], serde_json::Value::Bool(false));
    assert_eq!(
        body["model"],
        serde_json::Value::String("gpt-5".to_string())
    );
    assert_eq!(
        body["input"],
        serde_json::Value::String("compact".to_string())
    );
}

#[tokio::test]
async fn test_codex_subscription_adds_store_false_when_missing() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer opaque-provider-token")
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-5","input":"compact"}"#)
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["store"], serde_json::Value::Bool(false));
    assert_eq!(body["stream"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn test_codex_subscription_forces_stream_true() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer opaque-provider-token")
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-5","input":"compact","store":false,"stream":false}"#)
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["store"], serde_json::Value::Bool(false));
    assert_eq!(body["stream"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn test_codex_api_key_route_preserves_store_true() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer sk-test")
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-5","input":"hello","store":true,"stream":false}"#)
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["store"], serde_json::Value::Bool(true));
    assert_eq!(body["stream"], serde_json::Value::Bool(false));
}

#[tokio::test]
async fn test_codex_subscription_preserves_compact_suffix() {
    let (upstream_url, _upstream_handle) = start_query_echo_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!(
            "{}/backend-api/codex/responses/compact?foo=bar",
            proxy_url
        ))
        .header("authorization", "Bearer opaque-provider-token")
        .body(r#"{"model":"gpt-5","input":[]}"#)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, "/backend-api/codex/responses/compact?foo=bar");
}

#[tokio::test]
async fn test_codex_subscription_compact_does_not_add_store_or_stream() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/backend-api/codex/responses/compact", proxy_url))
        .header("authorization", "Bearer opaque-provider-token")
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-5","input":[]}"#)
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert!(body.get("store").is_none());
    assert!(body.get("stream").is_none());
}

#[tokio::test]
async fn test_codex_zstd_body_is_decompressed_before_forwarding() {
    use std::io::Write;

    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let clean_body = r#"{"model":"gpt-5","input":"hello"}"#;
    let mut encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
    encoder.write_all(clean_body.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = client
        .post(format!("{}/v1/responses", proxy_url))
        .header("authorization", "Bearer sk-test")
        .header("content-type", "application/json")
        .header("content-encoding", "zstd")
        .body(compressed)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(
        body, clean_body,
        "Upstream should receive decompressed JSON"
    );
}

#[tokio::test]
async fn test_codex_does_not_match_similar_response_path() {
    let (upstream_url, _upstream_handle) = start_mock_upstream().await;
    let (proxy_url, _proxy_handle) = start_proxy(&upstream_url).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let clean_body = r#"{"model":"claude","messages":[]}"#;
    let response = client
        .post(format!("{}/v1/responsesXYZ", proxy_url))
        .header("authorization", "Bearer opaque-subscription-token")
        .body(clean_body)
        .send()
        .await
        .unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, clean_body);
}
