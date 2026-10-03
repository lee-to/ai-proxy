//! Forwarding-boundary fixtures for issue #52. All traffic stays on loopback.
use ai_proxy::{
    config::{Config, ModelScannerConfig, PrivacyFilterScannerConfig},
    middleware::{
        ScanMatch, ScanPipeline, ScanReport, SecretScanner, model_scanner::ModelScanner,
        privacy_filter_scanner::PrivacyFilterScanner, regex_scanner::RegexScanner,
    },
    mitm::MitmAuthority,
    proxy::{AppState, proxy_handler},
    redactor::Redactor,
};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::any,
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::*};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::SubscriberExt};

const CANARY: &str = "AKIA0000000000000000";
const MASKED: &str = "AKI***...***000";
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum Mode {
    Reverse,
    Mitm,
    Blind,
}

const INSPECTING_MODES: [Mode; 2] = [Mode::Reverse, Mode::Mitm];

type SessionObservers = Mutex<HashMap<String, mpsc::UnboundedSender<()>>>;
static SESSION_OBSERVERS: OnceLock<SessionObservers> = OnceLock::new();

// MITM HTTP runs in an upgraded connection outside the Axum router. Its terminal
// session event is the synchronization point for cancellation/cleanup checks.
struct SessionLayer;

#[derive(Default)]
struct SessionEvent {
    message: String,
    target: String,
}

impl Visit for SessionEvent {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "target" => self.target = format!("{value:?}"),
            _ => {}
        }
    }
}

impl<S: Subscriber> Layer<S> for SessionLayer {
    fn on_event(&self, event: &Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = SessionEvent::default();
        event.record(&mut fields);
        if matches!(
            fields.message.as_str(),
            "CONNECT MITM session completed" | "CONNECT MITM session failed"
        ) {
            let observers = SESSION_OBSERVERS.get().unwrap().lock().unwrap();
            if let Some(sender) = observers.get(&fields.target) {
                let _ = sender.send(());
            }
        }
    }
}

struct SessionObserver {
    target: String,
    receiver: mpsc::UnboundedReceiver<()>,
}

impl SessionObserver {
    fn new(target: String) -> Self {
        let observers = SESSION_OBSERVERS.get_or_init(|| Mutex::new(HashMap::new()));
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(SessionLayer),
            )
            .unwrap()
        });
        let (sender, receiver) = mpsc::unbounded_channel();
        observers.lock().unwrap().insert(target.clone(), sender);
        Self { target, receiver }
    }
}

impl Drop for SessionObserver {
    fn drop(&mut self) {
        SESSION_OBSERVERS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&self.target);
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ai-proxy-regression-{}-{nonce}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
struct ScanObservation {
    name: String,
    failed: bool,
}

struct ObservedScanner {
    inner: Box<dyn SecretScanner>,
    observations: mpsc::UnboundedSender<ScanObservation>,
}

impl SecretScanner for ObservedScanner {
    fn scan(&self, text: &str) -> Vec<ScanMatch> {
        self.scan_report(text).findings
    }

    fn scan_report(&self, text: &str) -> ScanReport {
        let report = self.inner.scan_report(text);
        let _ = self.observations.send(ScanObservation {
            name: self.name().to_string(),
            failed: !report.failed_scanners.is_empty(),
        });
        report
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

// Drop also signals cancellation, so negative assertions wait for the handler
// to terminate instead of racing it or relying on a fixed sleep.
struct TerminalRequest {
    sender: mpsc::UnboundedSender<Option<StatusCode>>,
    status: Option<StatusCode>,
}

impl Drop for TerminalRequest {
    fn drop(&mut self) {
        let _ = self.sender.send(self.status);
    }
}

async fn observe_terminal_request(
    State(sender): State<mpsc::UnboundedSender<Option<StatusCode>>>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::CONNECT {
        return next.run(request).await;
    }
    let mut terminal = TerminalRequest {
        sender,
        status: None,
    };
    let response = next.run(request).await;
    terminal.status = Some(response.status());
    response
}

trait TestIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestIo for T {}

struct Fixture {
    mode: Mode,
    proxy_addr: SocketAddr,
    upstream_addr: SocketAddr,
    client: reqwest::Client,
    tls_connector: TlsConnector,
    captured: mpsc::UnboundedReceiver<CapturedRequest>,
    upstream_progress: mpsc::UnboundedReceiver<()>,
    upstream_requests: Arc<AtomicUsize>,
    upstream_connections: Arc<AtomicUsize>,
    scans: mpsc::UnboundedReceiver<ScanObservation>,
    terminal: mpsc::UnboundedReceiver<Option<StatusCode>>,
    session: SessionObserver,
    _proxy: Task,
    _upstream: Task,
    _ca: TempDir,
}

struct CapturedRequest {
    bytes: Vec<u8>,
    complete: bool,
}

impl Fixture {
    async fn new(mode: Mode, extra_scanner: Option<Box<dyn SecretScanner>>) -> Self {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let session = SessionObserver::new(upstream_addr.to_string());
        let upstream_key = rcgen::KeyPair::generate().unwrap();
        let upstream_cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&upstream_key)
            .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![upstream_cert.der().clone()],
                PrivatePkcs8KeyDer::from(upstream_key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let (capture_sender, captured) = mpsc::unbounded_channel();
        let (progress_sender, upstream_progress) = mpsc::unbounded_channel();
        let upstream_requests = Arc::new(AtomicUsize::new(0));
        let request_count = upstream_requests.clone();
        let upstream_connections = Arc::new(AtomicUsize::new(0));
        let connection_count = upstream_connections.clone();
        let upstream = Task(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    connection = upstream_listener.accept() => {
                        let (stream, _) = connection.unwrap();
                        connection_count.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let sender = capture_sender.clone();
                        let progress = progress_sender.clone();
                        let count = request_count.clone();
                        connections.spawn(async move {
                            let Ok(stream) = acceptor.accept(stream).await else { return; };
                            let service = service_fn(move |request: hyper::Request<Incoming>| {
                                let sender = sender.clone();
                                let progress = progress.clone();
                                count.fetch_add(1, Ordering::SeqCst);
                                async move {
                                    let mut body = request.into_body();
                                    let mut captured = CapturedRequest { bytes: Vec::new(), complete: true };
                                    while let Some(frame) = body.frame().await {
                                        match frame {
                                            Ok(frame) => {
                                                if let Ok(bytes) = frame.into_data() {
                                                    captured.bytes.extend_from_slice(&bytes);
                                                    let _ = progress.send(());
                                                }
                                            }
                                            Err(_) => { captured.complete = false; break; }
                                        }
                                    }
                                    let _ = sender.send(captured);
                                    // The response never echoes the captured body. Assertions
                                    // cannot be satisfied by downstream placeholder restoration.
                                    Ok::<_, Infallible>(hyper::Response::new(Body::from("ok")))
                                }
                            });
                            let _ = http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        }));

        let ca_dir = TempDir::new();
        let cert_path = ca_dir.0.join("ca.pem");
        let authority = MitmAuthority::load(&cert_path, &ca_dir.0.join("ca-key.pem"), 8).unwrap();
        let ca_pem = std::fs::read(&cert_path).unwrap();
        let ca_der = CertificateDer::from_pem_slice(&ca_pem).unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(match mode {
                Mode::Mitm => ca_der,
                _ => upstream_cert.der().clone(),
            })
            .unwrap();
        let tls_connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));

        let mut config: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        let upstream_url = format!("https://{upstream_addr}");
        config.proxy.anthropic_upstream_url = upstream_url.clone();
        config.proxy.codex_upstream_url = upstream_url;
        config.proxy.mitm_enabled = matches!(mode, Mode::Mitm);
        config.proxy.mitm_included_hosts.clear();
        config.proxy.mitm_excluded_hosts.clear();
        config.proxy.max_body_size = 1024;
        config.proxy.request_timeout_secs = 5;
        config.scanner.enabled = true;
        config.scanner.scan_scope = "body".to_string();
        config.redaction.strategy = "partial".to_string();
        config.redaction.response_restore_enabled = false;
        config.redaction.prefix_len = 3;
        config.redaction.suffix_len = 3;
        config.redaction.mask = "***...***".to_string();

        let (scan_sender, scans) = mpsc::unbounded_channel();
        let mut pipeline = ScanPipeline::new();
        pipeline.add_scanner(Box::new(ObservedScanner {
            inner: Box::new(RegexScanner::new(&config.scanner.regex)),
            observations: scan_sender.clone(),
        }));
        if let Some(inner) = extra_scanner {
            pipeline.add_scanner(Box::new(ObservedScanner {
                inner,
                observations: scan_sender,
            }));
        }
        let state = Arc::new(AppState {
            redactor: Redactor::new(&config.redaction),
            config,
            pipeline,
            http_client: reqwest::Client::builder()
                .no_proxy()
                .add_root_certificate(reqwest::Certificate::from_der(upstream_cert.der()).unwrap())
                .timeout(DEADLINE)
                .build()
                .unwrap(),
            mitm_authority: Some(Arc::new(authority)),
            telemetry_store: None,
        });
        let (terminal_sender, terminal) = mpsc::unbounded_channel();
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(state)
            .layer(middleware::from_fn_with_state(
                terminal_sender,
                observe_terminal_request,
            ));
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy = Task(tokio::spawn(async move {
            axum::serve(proxy_listener, app).await.unwrap();
        }));
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .timeout(DEADLINE)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
            .add_root_certificate(reqwest::Certificate::from_der(upstream_cert.der()).unwrap());
        if !matches!(mode, Mode::Reverse) {
            client = client.proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap());
        }
        Self {
            mode,
            proxy_addr,
            upstream_addr,
            client: client.build().unwrap(),
            tls_connector,
            captured,
            upstream_progress,
            upstream_requests,
            upstream_connections,
            scans,
            terminal,
            session,
            _proxy: proxy,
            _upstream: upstream,
            _ca: ca_dir,
        }
    }

    fn request(&self) -> reqwest::RequestBuilder {
        let url = match self.mode {
            Mode::Reverse => format!("http://{}/v1/messages", self.proxy_addr),
            _ => format!("https://{}/v1/messages", self.upstream_addr),
        };
        self.client
            .post(url)
            .header("content-type", "application/json")
    }

    async fn capture(&mut self) -> Vec<u8> {
        let captured = timeout(DEADLINE, self.captured.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(captured.complete, "upstream received an incomplete body");
        captured.bytes
    }

    fn observations(&mut self) -> Vec<ScanObservation> {
        let mut observations = Vec::new();
        while let Ok(observation) = self.scans.try_recv() {
            observations.push(observation);
        }
        observations
    }

    fn assert_not_inspected_or_forwarded(&mut self) {
        assert_eq!(
            self.upstream_connections.load(Ordering::SeqCst),
            0,
            "{:?}",
            self.mode
        );
        assert_eq!(
            self.upstream_requests.load(Ordering::SeqCst),
            0,
            "{:?}",
            self.mode
        );
        assert!(self.captured.try_recv().is_err(), "{:?}", self.mode);
        assert!(self.observations().is_empty(), "{:?}", self.mode);
    }

    async fn connect(&self) -> Box<dyn TestIo> {
        let mut stream = TcpStream::connect(self.proxy_addr).await.unwrap();
        if matches!(self.mode, Mode::Reverse) {
            return Box::new(stream);
        }
        let request = format!(
            "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n",
            self.upstream_addr
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        timeout(DEADLINE, async {
            while !response.ends_with(b"\r\n\r\n") {
                response.push(stream.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        Box::new(
            timeout(
                DEADLINE,
                self.tls_connector
                    .connect(ServerName::try_from("127.0.0.1").unwrap(), stream),
            )
            .await
            .unwrap()
            .unwrap(),
        )
    }

    async fn terminal_status(&mut self) -> Option<StatusCode> {
        timeout(DEADLINE, self.terminal.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn cancelled_request_terminated(&mut self) {
        if matches!(self.mode, Mode::Mitm) {
            timeout(DEADLINE, self.session.receiver.recv())
                .await
                .unwrap()
                .unwrap();
        } else {
            let status = self.terminal_status().await;
            assert!(
                status.is_none() || status == Some(StatusCode::BAD_REQUEST),
                "{:?}: {status:?}",
                self.mode
            );
        }
    }
}

async fn read_response(stream: &mut Box<dyn TestIo>) -> Vec<u8> {
    let mut response = Vec::new();
    // A peer may close TLS without close_notify after a malformed HTTP stream.
    let _ = timeout(DEADLINE, stream.read_to_end(&mut response))
        .await
        .unwrap();
    response
}

async fn write_chunk(stream: &mut Box<dyn TestIo>, chunk: &[u8]) {
    stream
        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
        .await
        .unwrap();
    stream.write_all(chunk).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
}

const CHUNKED_HEADERS: &[u8] = b"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

#[tokio::test]
async fn redaction_captures_controls_and_canaries_across_request_chunks() {
    for mode in [Mode::Reverse, Mode::Mitm, Mode::Blind] {
        let mut fixture = Fixture::new(mode, None).await;
        let response = fixture
            .request()
            .body("clean control")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(fixture.capture().await, b"clean control");
        if matches!(mode, Mode::Reverse) {
            assert_eq!(fixture.terminal_status().await, Some(StatusCode::OK));
        }
        fixture.observations();

        // Try every interior canary boundary. The secret ends at EOF, so the
        // scanner cannot rely on a following delimiter or another data chunk.
        for split in 1..CANARY.len() {
            let mut stream = fixture.connect().await;
            stream.write_all(CHUNKED_HEADERS).await.unwrap();
            write_chunk(&mut stream, &CANARY.as_bytes()[..split]).await;
            write_chunk(&mut stream, &CANARY.as_bytes()[split..]).await;
            stream.write_all(b"0\r\n\r\n").await.unwrap();
            let response = read_response(&mut stream).await;
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{mode:?}, split {split}"
            );
            let expected = if matches!(mode, Mode::Blind) {
                CANARY
            } else {
                MASKED
            };
            assert_eq!(
                fixture.capture().await,
                expected.as_bytes(),
                "{mode:?}, split {split}"
            );
            let scans = fixture.observations();
            if matches!(mode, Mode::Blind) {
                assert!(scans.is_empty());
            } else {
                assert_eq!(scans.len(), 1);
                assert!(!scans[0].failed);
                if matches!(mode, Mode::Reverse) {
                    assert_eq!(fixture.terminal_status().await, Some(StatusCode::OK));
                }
            }
        }
    }
}

#[tokio::test]
async fn redaction_rejects_corrupt_compression_without_contacting_upstream() {
    for mode in INSPECTING_MODES {
        for (encoding, body) in [
            ("gzip", vec![0x1f, 0x8b, 0xff, 0xff]),
            ("zstd", vec![0x28, 0xb5, 0x2f, 0xfd, 0xff]),
        ] {
            let mut fixture = Fixture::new(mode, None).await;
            let response = fixture
                .request()
                .header("content-encoding", encoding)
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{mode:?}, {encoding}"
            );
            if matches!(mode, Mode::Reverse) {
                assert_eq!(
                    fixture.terminal_status().await,
                    Some(StatusCode::BAD_REQUEST)
                );
            }
            fixture.assert_not_inspected_or_forwarded();
        }
    }
}

#[tokio::test]
async fn redaction_distinguishes_opaque_bodies_from_successful_inspection() {
    for mode in INSPECTING_MODES {
        for (encoding, body) in [
            (Some("br"), CANARY.as_bytes().to_vec()),
            (None, [vec![0xff], CANARY.as_bytes().to_vec()].concat()),
        ] {
            let mut fixture = Fixture::new(mode, None).await;
            let mut request = fixture.request();
            if let Some(encoding) = encoding {
                request = request.header("content-encoding", encoding);
            }
            let response = request.body(body.clone()).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(fixture.capture().await, body);
            assert!(
                fixture.observations().is_empty(),
                "opaque content must not be scanned"
            );
        }
    }
}

#[tokio::test]
async fn redaction_scans_malformed_json_as_text() {
    for mode in INSPECTING_MODES {
        let mut fixture = Fixture::new(mode, None).await;
        let body = format!("{{\"secret\":\"{CANARY}");
        let response = fixture.request().body(body).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            fixture.capture().await,
            format!("{{\"secret\":\"{MASKED}").as_bytes()
        );
        let scans = fixture.observations();
        assert_eq!(scans.len(), 1);
        assert!(!scans[0].failed);
    }
}

#[tokio::test]
async fn redaction_cleans_up_truncated_and_cancelled_requests_before_scanning() {
    for mode in INSPECTING_MODES {
        for cancel in [false, true] {
            let mut fixture = Fixture::new(mode, None).await;
            let mut stream = fixture.connect().await;
            stream.write_all(CHUNKED_HEADERS).await.unwrap();
            write_chunk(&mut stream, CANARY.as_bytes()).await;
            if cancel {
                drop(stream);
            } else {
                // EOF without the mandatory terminating zero chunk.
                stream.shutdown().await.unwrap();
                let response = read_response(&mut stream).await;
                assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 400"));
            }
            fixture.cancelled_request_terminated().await;
            fixture.assert_not_inspected_or_forwarded();

            // A new request still completes: no stuck scan or poisoned state.
            let response = fixture
                .request()
                .body("after cancellation")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(fixture.capture().await, b"after cancellation");
            assert_eq!(fixture.upstream_requests.load(Ordering::SeqCst), 1);
            let scans = fixture.observations();
            assert_eq!(scans.len(), 1);
            assert!(!scans[0].failed);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum EndpointResult {
    Clean,
    InvalidJson,
    Error,
    Timeout,
}

struct ScannerEndpoint {
    url: String,
    _task: Task,
}

impl ScannerEndpoint {
    async fn new(result: EndpointResult) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(any(move || async move {
            match result {
                EndpointResult::Clean => (StatusCode::OK, r#"{"findings":[]}"#),
                EndpointResult::InvalidJson => (StatusCode::OK, "invalid json"),
                EndpointResult::Error => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                // No response is ever sent; the scanner's own deadline decides
                // the outcome, without a race against a fixture sleep.
                EndpointResult::Timeout => std::future::pending().await,
            }
        }));
        Self {
            url,
            _task: Task(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            })),
        }
    }
}

#[tokio::test]
async fn redaction_preserves_scanner_failure_policies_at_the_upstream_boundary() {
    for mode in INSPECTING_MODES {
        for result in [
            EndpointResult::Clean,
            EndpointResult::InvalidJson,
            EndpointResult::Error,
            EndpointResult::Timeout,
        ] {
            let endpoint = ScannerEndpoint::new(result).await;
            for policy in ["regex_only", "fail_closed"] {
                for scanner_name in ["model", "privacy_filter"] {
                    let scanner: Box<dyn SecretScanner> = if scanner_name == "model" {
                        Box::new(ModelScanner::new(&ModelScannerConfig {
                            endpoint: endpoint.url.clone(),
                            timeout_ms: 250,
                            fail_policy: policy.to_string(),
                            ..ModelScannerConfig::default()
                        }))
                    } else {
                        Box::new(PrivacyFilterScanner::new(&PrivacyFilterScannerConfig {
                            endpoint: endpoint.url.clone(),
                            timeout_ms: 250,
                            fail_policy: policy.to_string(),
                            ..PrivacyFilterScannerConfig::default()
                        }))
                    };
                    let mut fixture = Fixture::new(mode, Some(scanner)).await;
                    for body in [
                        "clean control".to_string(),
                        format!("prefix {CANARY} suffix"),
                    ] {
                        let response = fixture.request().body(body.clone()).send().await.unwrap();
                        assert_eq!(
                            response.status(),
                            StatusCode::OK,
                            "{mode:?}, {scanner_name}, {policy}, {result:?}"
                        );
                        let failed = !matches!(result, EndpointResult::Clean);
                        let expected = if failed && policy == "fail_closed" {
                            if body == "clean control" {
                                "cle***...***rol".to_string()
                            } else {
                                "pre***...***fix".to_string()
                            }
                        } else {
                            body.replace(CANARY, MASKED)
                        };
                        assert_eq!(
                            fixture.capture().await,
                            expected.as_bytes(),
                            "{mode:?}, {scanner_name}, {policy}, {result:?}"
                        );
                        let scans = fixture.observations();
                        assert_eq!(scans.len(), 2);
                        assert!(!scans[0].failed);
                        assert_eq!(scans[1].name, scanner_name);
                        assert_eq!(scans[1].failed, failed);
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn redaction_handles_unavailable_scanner_process_without_claiming_success() {
    let missing_command = TempDir::new();
    for mode in INSPECTING_MODES {
        for policy in ["regex_only", "fail_closed"] {
            let scanner = PrivacyFilterScanner::new(&PrivacyFilterScannerConfig {
                command: missing_command
                    .0
                    .join("does-not-exist")
                    .to_str()
                    .unwrap()
                    .to_string(),
                fail_policy: policy.to_string(),
                ..PrivacyFilterScannerConfig::default()
            });
            let mut fixture = Fixture::new(mode, Some(Box::new(scanner))).await;
            let response = fixture
                .request()
                .body(format!("prefix {CANARY} suffix"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let expected = if policy == "fail_closed" {
                "pre***...***fix".to_string()
            } else {
                format!("prefix {MASKED} suffix")
            };
            assert_eq!(fixture.capture().await, expected.as_bytes());
            let scans = fixture.observations();
            assert_eq!(scans.len(), 2);
            assert!(scans[1].failed);
            assert_eq!(scans[1].name, "privacy_filter");
        }
    }
}

#[tokio::test]
async fn blind_connect_forwards_opaque_compression_without_running_scanners() {
    let missing_command = TempDir::new();
    let scanner = PrivacyFilterScanner::new(&PrivacyFilterScannerConfig {
        command: missing_command
            .0
            .join("does-not-exist")
            .to_str()
            .unwrap()
            .to_string(),
        fail_policy: "fail_closed".to_string(),
        ..PrivacyFilterScannerConfig::default()
    });
    let mut fixture = Fixture::new(Mode::Blind, Some(Box::new(scanner))).await;
    let body = [vec![0x1f, 0x8b, 0xff, 0xff], CANARY.as_bytes().to_vec()].concat();
    let response = fixture
        .request()
        .header("content-encoding", "gzip")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.capture().await, body);
    assert!(fixture.observations().is_empty());
}

#[tokio::test]
async fn blind_connect_preserves_partial_traffic_and_closes_on_cancellation() {
    for cancel in [false, true] {
        let mut fixture = Fixture::new(Mode::Blind, None).await;
        let mut stream = fixture.connect().await;
        stream.write_all(CHUNKED_HEADERS).await.unwrap();
        write_chunk(&mut stream, CANARY.as_bytes()).await;
        // First prove that the opaque tunnel has delivered this chunk, then
        // terminate it. Partial bytes are expected in a blind tunnel.
        timeout(DEADLINE, fixture.upstream_progress.recv())
            .await
            .unwrap()
            .unwrap();
        if cancel {
            drop(stream);
        } else {
            stream.shutdown().await.unwrap();
            let _ = read_response(&mut stream).await;
        }
        let captured = timeout(DEADLINE, fixture.captured.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!captured.complete);
        assert_eq!(captured.bytes, CANARY.as_bytes());
        assert_eq!(fixture.upstream_requests.load(Ordering::SeqCst), 1);
        assert!(fixture.observations().is_empty());
    }
}

#[tokio::test]
async fn redaction_captures_decoded_compression_and_rejects_expansion_over_limit() {
    use std::io::Write;
    for mode in INSPECTING_MODES {
        for encoding in ["gzip", "zstd"] {
            for oversized in [false, true] {
                let mut fixture = Fixture::new(mode, None).await;
                let body = if oversized {
                    vec![b'a'; 1025]
                } else {
                    CANARY.as_bytes().to_vec()
                };
                let compressed = if encoding == "gzip" {
                    let mut encoder =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                    encoder.write_all(&body).unwrap();
                    encoder.finish().unwrap()
                } else {
                    zstd::stream::encode_all(body.as_slice(), 1).unwrap()
                };
                let response = fixture
                    .request()
                    .header("content-encoding", encoding)
                    .body(compressed)
                    .send()
                    .await
                    .unwrap();
                if oversized {
                    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
                    fixture.assert_not_inspected_or_forwarded();
                } else {
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(fixture.capture().await, MASKED.as_bytes());
                    let scans = fixture.observations();
                    assert_eq!(scans.len(), 1);
                    assert!(!scans[0].failed);
                }
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn redaction_handles_scanner_process_errors_and_reaps_timed_out_children() {
    for mode in INSPECTING_MODES {
        for policy in ["regex_only", "fail_closed"] {
            for script in [
                "cat >/dev/null; printf '{\"detected_spans\":[]}'",
                "cat >/dev/null; exit 1",
                "cat >/dev/null; printf 'invalid json'",
                "cat >/dev/null; printf '%s' \"$$\" >\"$1\"; while :; do :; done",
            ] {
                let directory = TempDir::new();
                let pid_path = directory.0.join("scanner.pid");
                let scanner = PrivacyFilterScanner::new(&PrivacyFilterScannerConfig {
                    command: "sh".to_string(),
                    command_args: vec![
                        "-c".to_string(),
                        script.to_string(),
                        "fixture".to_string(),
                        pid_path.to_str().unwrap().to_string(),
                    ],
                    timeout_ms: 500,
                    fail_policy: policy.to_string(),
                    ..PrivacyFilterScannerConfig::default()
                });
                let mut fixture = Fixture::new(mode, Some(Box::new(scanner))).await;
                let response = fixture
                    .request()
                    .body(format!("prefix {CANARY} suffix"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let failed = !script.contains("detected_spans");
                let expected = if failed && policy == "fail_closed" {
                    "pre***...***fix".to_string()
                } else {
                    format!("prefix {MASKED} suffix")
                };
                assert_eq!(fixture.capture().await, expected.as_bytes());
                let scans = fixture.observations();
                assert_eq!(scans.len(), 2);
                assert_eq!(scans[1].failed, failed);
                if script.contains("while") {
                    let pid = std::fs::read_to_string(pid_path).unwrap();
                    timeout(DEADLINE, async {
                        loop {
                            let status = tokio::process::Command::new("sh")
                                .args(["-c", "kill -0 \"$1\" 2>/dev/null", "fixture", &pid])
                                .status()
                                .await
                                .unwrap();
                            if !status.success() {
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("timed-out scanner process must be killed and reaped");
                }
            }
        }
    }
}
