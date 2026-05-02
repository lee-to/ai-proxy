use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    response::Response,
};
use bytes::Bytes;
use flate2::read::GzDecoder;
use futures_util::Stream;
use futures_util::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::convert::Infallible;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use tracing::{debug, error, info, warn};
use url::form_urlencoded;

use crate::config::Config;
use crate::logging::log_redaction;
use crate::middleware::ScanPipeline;
use crate::mitm::{MitmAuthority, normalize_connect_host};
use crate::redaction_context::{RedactionContext, StreamingRestore};
use crate::redactor::Redactor;
use crate::telemetry::{
    ContentCaptureRecord, RequestRecord, RequestTelemetryContext, ResponseTelemetryCollector,
    extract_model_from_json, extract_tool_events_from_json, extract_websocket_text_telemetry,
    next_request_id, now_ms,
};
use crate::telemetry_store::TelemetryStore;

/// Shared application state passed to the proxy handler.
pub struct AppState {
    pub config: Config,
    pub pipeline: ScanPipeline,
    pub redactor: Redactor,
    pub http_client: reqwest::Client,
    pub mitm_authority: Option<Arc<MitmAuthority>>,
    pub telemetry_store: Option<Arc<TelemetryStore>>,
}

/// Headers that are not safe to forward unchanged through this proxy.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "accept-encoding",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "host",
];
const CONTENT_ENCODING: &str = "content-encoding";
const CONTENT_LENGTH: &str = "content-length";
const SEC_WEBSOCKET_ACCEPT: &str = "sec-websocket-accept";
const SEC_WEBSOCKET_KEY: &str = "sec-websocket-key";
const SEC_WEBSOCKET_PROTOCOL: &str = "sec-websocket-protocol";
const SEC_WEBSOCKET_VERSION: &str = "sec-websocket-version";
const SEC_WEBSOCKET_EXTENSIONS: &str = "sec-websocket-extensions";

type UpstreamWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type ResponseByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// Catch-all proxy handler: receives any request, scans & redacts the body,
/// forwards to upstream, and streams the response back.
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let request_id = next_request_id();

    if method == Method::CONNECT {
        return handle_connect(state, req).await;
    }

    let route = upstream_route(&state, &uri, &headers);

    info!(
        request_id = %request_id,
        method = %method,
        path = %uri.path(),
        upstream = %route.base_url,
        "Incoming request"
    );

    // Build upstream URL
    let upstream_url = route
        .absolute_url
        .unwrap_or_else(|| build_upstream_url(&route.base_url, &uri));
    debug!(mode = "reverse", upstream_path = %uri.path(), "Forwarding to upstream");

    forward_request(
        &state,
        method,
        headers,
        req.into_body(),
        upstream_url,
        route.is_codex_responses || state.config.scanner.enabled,
        route.needs_codex_subscription_payload_normalization,
        "reverse",
        request_id,
    )
    .await
}

async fn handle_connect(state: Arc<AppState>, req: Request<Body>) -> Result<Response, StatusCode> {
    let Some(authority) = req
        .uri()
        .authority()
        .map(|value| value.as_str().to_string())
    else {
        warn!("CONNECT request missing authority");
        return Err(StatusCode::BAD_REQUEST);
    };

    let host = match normalize_connect_host(&authority) {
        Ok(host) => host,
        Err(error) => {
            warn!(target = %authority, error = %error, "CONNECT request has invalid authority");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let use_mitm = state.config.proxy.mitm_enabled
        && state.mitm_authority.is_some()
        && !is_mitm_excluded_host(&state, &host);

    info!(target = %authority, host = %host, mitm = use_mitm, "CONNECT tunnel requested");

    tokio::spawn(async move {
        let upgrade_timeout = Duration::from_secs(state.config.proxy.connect_timeout_secs.max(1));
        let connect_timeout_secs = state.config.proxy.connect_timeout_secs;
        let request_timeout_secs = state.config.proxy.request_timeout_secs;
        match tokio::time::timeout(upgrade_timeout, hyper::upgrade::on(req)).await {
            Err(_) => {
                warn!(target = %authority, timeout_secs = upgrade_timeout.as_secs(), "CONNECT upgrade timed out");
            }
            Ok(Err(error)) => {
                warn!(target = %authority, error = %error, "CONNECT upgrade failed");
            }
            Ok(Ok(upgraded)) => {
                if use_mitm {
                    if let Err(error) =
                        tunnel_mitm_connection(state, upgraded, authority.clone()).await
                    {
                        warn!(target = %authority, error = %error, "CONNECT MITM session failed");
                    }
                } else if let Err(error) = tunnel_upgraded_connection(
                    upgraded,
                    &authority,
                    connect_timeout_secs,
                    request_timeout_secs,
                )
                .await
                {
                    log_connect_tunnel_error(&authority, &error);
                }
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(|error| {
            error!(error = %error, "Failed to build CONNECT response");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn forward_request(
    state: &Arc<AppState>,
    method: Method,
    headers: HeaderMap,
    body: Body,
    upstream_url: String,
    allow_normalization: bool,
    force_codex_store_false: bool,
    mode: &'static str,
    request_id: String,
) -> Result<Response, StatusCode> {
    let body_bytes = match axum::body::to_bytes(body, state.config.proxy.max_body_size).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(mode, error = %e, "Failed to read request body");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let mut processed_body = match process_request_body(
        state,
        &request_id,
        &headers,
        &body_bytes,
        allow_normalization,
        force_codex_store_false,
    )
    .await
    {
        Ok(body) => body,
        Err(status) => return Err(status),
    };

    let model = extract_model_from_json(&processed_body.telemetry_bytes);
    let telemetry_context = RequestTelemetryContext {
        request_id: request_id.clone(),
        started_at_ms: now_ms(),
        method: method.to_string(),
        path: upstream_url.clone(),
        mode: mode.to_string(),
        upstream: upstream_url.clone(),
        model,
    };
    persist_request_start(state, &telemetry_context).await;
    persist_request_tool_events(
        state,
        &request_id,
        &processed_body.telemetry_bytes,
        "request",
    )
    .await;
    persist_content_capture_from_bytes(
        state,
        &request_id,
        "request",
        "http",
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        &processed_body.bytes,
        processed_body.bytes.len(),
        false,
    )
    .await;

    debug!(
        request_id = %request_id,
        mode,
        original_size = body_bytes.len(),
        forwarded_size = processed_body.bytes.len(),
        "Body processed"
    );

    let (forwarded_headers, final_upstream_url) =
        if state.config.scanner.enabled && state.config.scanner.scan_scope == "full" {
            let scanned_headers =
                scan_and_redact_headers(state, &headers, &request_id, &mut processed_body.context)
                    .await;
            let redacted_url = scan_and_redact_query_params(
                state,
                &upstream_url,
                &request_id,
                &mut processed_body.context,
            )
            .await;
            (scanned_headers, redacted_url)
        } else {
            (headers.clone(), upstream_url)
        };

    let reqwest_method = match reqwest_method(&method) {
        Ok(method) => method,
        Err(()) => {
            warn!(request_id = %request_id, method = %method, "Unsupported HTTP method");
            persist_request_finish(state, &request_id, None, Some("unsupported HTTP method")).await;
            return Err(StatusCode::NOT_IMPLEMENTED);
        }
    };
    let mut upstream_req = state
        .http_client
        .request(reqwest_method, &final_upstream_url);

    upstream_req = forward_headers(
        upstream_req,
        &forwarded_headers,
        processed_body.strip_content_encoding,
    );

    if method != Method::GET && method != Method::HEAD {
        upstream_req = upstream_req.body(processed_body.bytes);
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!(request_id = %request_id, mode, error = %e, "Failed to connect to upstream");
            persist_request_finish(
                state,
                &request_id,
                None,
                Some("failed to connect to upstream"),
            )
            .await;
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    response_from_upstream(
        upstream_resp,
        mode,
        state.clone(),
        telemetry_context,
        processed_body.context,
    )
    .await
}

async fn response_from_upstream(
    upstream_resp: reqwest::Response,
    mode: &'static str,
    state: Arc<AppState>,
    telemetry_context: RequestTelemetryContext,
    redaction_context: RedactionContext,
) -> Result<Response, StatusCode> {
    let request_id = telemetry_context.request_id.clone();
    info!(
        request_id = %request_id,
        mode,
        status = upstream_resp.status().as_u16(),
        "Upstream response received"
    );

    let status = axum::http::StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response_headers = HeaderMap::new();
    let response_content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let response_content_encoding = upstream_resp
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    for (name, value) in upstream_resp.headers() {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_ref()),
            HeaderValue::from_bytes(value.as_ref()),
        ) {
            let name_lower = n.as_str().to_ascii_lowercase();
            if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) || name_lower == CONTENT_LENGTH {
                continue;
            }
            response_headers.append(n, v);
        }
    }

    debug!(request_id = %request_id, mode, "Streaming upstream response body");
    let stream_request_id = request_id.clone();
    let stream = upstream_resp.bytes_stream().map(move |chunk| {
        let stream_request_id = stream_request_id.clone();
        chunk.map_err(move |e| {
            warn!(request_id = %stream_request_id, mode, error = %e, "Error reading upstream response chunk");
            std::io::Error::other(e)
        })
    });
    let stream: ResponseByteStream = Box::pin(stream);
    let restore_allowed = response_restore_allowed(
        response_content_type.as_deref(),
        response_content_encoding.as_deref(),
    );
    let stream: ResponseByteStream =
        if restore_allowed && stateful_restore_enabled(&redaction_context) {
            debug!(
                request_id = %request_id,
                mode,
                placeholder_count_empty = redaction_context.is_empty(),
                "Response placeholder restoration enabled"
            );
            Box::pin(restore_response_stream(stream, redaction_context))
        } else {
            debug!(
                request_id = %request_id,
                mode,
                content_type = ?response_content_type,
                content_encoding = ?response_content_encoding,
                restore_allowed,
                "Response placeholder restoration disabled"
            );
            stream
        };
    let stream = telemetry_stream(
        stream,
        state,
        telemetry_context,
        response_content_type,
        status.as_u16(),
    );

    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;

    Ok(response)
}

fn stateful_restore_enabled(context: &RedactionContext) -> bool {
    !context.is_empty()
}

fn response_restore_allowed(content_type: Option<&str>, content_encoding: Option<&str>) -> bool {
    if content_encoding
        .map(|value| {
            value.split(',').map(str::trim).any(|encoding| {
                matches!(
                    encoding.to_ascii_lowercase().as_str(),
                    "gzip" | "br" | "zstd" | "deflate"
                )
            })
        })
        .unwrap_or(false)
    {
        return false;
    }

    let Some(content_type) = content_type else {
        return false;
    };
    let mime = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();

    mime.starts_with("text/")
        || mime == "application/json"
        || mime.ends_with("+json")
        || mime == "application/x-ndjson"
        || mime == "text/event-stream"
}

fn restore_response_stream(
    stream: ResponseByteStream,
    context: RedactionContext,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send {
    futures_util::stream::unfold(
        (stream, Some(StreamingRestore::new(context)), false),
        |(mut stream, mut restore, finished)| async move {
            if finished {
                return None;
            }

            match stream.next().await {
                Some(Ok(bytes)) => {
                    let Some(adapter) = restore.as_mut() else {
                        return Some((Ok(bytes), (stream, restore, false)));
                    };
                    let report = adapter.push(bytes);
                    if !report.counts_by_category.is_empty() {
                        debug!(
                            counts_by_category = ?report.counts_by_category,
                            "Restored placeholders in response chunk"
                        );
                    }
                    Some((Ok(report.bytes), (stream, restore, false)))
                }
                Some(Err(error)) => Some((Err(error), (stream, restore, false))),
                None => {
                    if let Some(adapter) = restore.take()
                        && let Some(report) = adapter.finish()
                    {
                        if !report.counts_by_category.is_empty() {
                            debug!(
                                counts_by_category = ?report.counts_by_category,
                                "Restored placeholders in final response chunk"
                            );
                        }
                        return Some((Ok(report.bytes), (stream, restore, true)));
                    }
                    None
                }
            }
        },
    )
}

fn telemetry_stream(
    stream: ResponseByteStream,
    state: Arc<AppState>,
    context: RequestTelemetryContext,
    content_type: Option<String>,
    status_code: u16,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send {
    let telemetry_store = state.telemetry_store.clone();
    let collector = telemetry_store.as_ref().map(|_| {
        ResponseTelemetryCollector::new(
            context.request_id.clone(),
            context.model.clone(),
            context.upstream.clone(),
            "response".to_string(),
        )
    });
    let capture = if state.telemetry_store.is_some() && state.config.dashboard.capture.responses {
        Some(CapturePreviewBuffer::new(
            state.config.dashboard.capture.max_body_bytes,
        ))
    } else {
        None
    };

    futures_util::stream::unfold(
        (
            stream,
            collector,
            capture,
            state,
            context,
            content_type,
            false,
        ),
        move |(mut stream, mut collector, mut capture, state, context, content_type, finished)| async move {
            if finished {
                return None;
            }
            match stream.next().await {
                Some(Ok(bytes)) => {
                    if let Some(collector) = collector.as_mut() {
                        collector.observe_chunk(&bytes);
                    }
                    if let Some(capture) = capture.as_mut() {
                        capture.observe(&bytes);
                    }
                    Some((
                        Ok(bytes),
                        (
                            stream,
                            collector,
                            capture,
                            state,
                            context,
                            content_type,
                            false,
                        ),
                    ))
                }
                Some(Err(error)) => {
                    persist_request_finish(
                        &state,
                        &context.request_id,
                        Some(status_code),
                        Some("upstream response stream error"),
                    )
                    .await;
                    Some((
                        Err(error),
                        (
                            stream,
                            collector,
                            capture,
                            state,
                            context,
                            content_type,
                            true,
                        ),
                    ))
                }
                None => {
                    if let (Some(store), Some(collector)) =
                        (state.telemetry_store.as_ref(), collector)
                    {
                        let (usage_records, tool_events) = collector.finalize();
                        persist_response_telemetry_records(
                            store,
                            usage_records,
                            tool_events,
                            "response",
                        )
                        .await;
                    }
                    if let Some(capture) = capture {
                        persist_content_capture_from_bytes(
                            &state,
                            &context.request_id,
                            "response",
                            "http",
                            content_type.as_deref(),
                            capture.bytes(),
                            capture.observed_bytes(),
                            capture.truncated(),
                        )
                        .await;
                    }
                    persist_request_finish(&state, &context.request_id, Some(status_code), None)
                        .await;
                    None
                }
            }
        },
    )
}

async fn persist_response_telemetry_records(
    store: &TelemetryStore,
    usage_records: Vec<crate::telemetry::TokenUsageRecord>,
    tool_events: Vec<crate::telemetry::ToolEventRecord>,
    source: &str,
) {
    for usage in usage_records {
        info!(
            request_id = %usage.request_id,
            model = ?usage.model,
            input_tokens = ?usage.input_tokens,
            output_tokens = ?usage.output_tokens,
            total_tokens = ?usage.total_tokens,
            upstream = %usage.upstream,
            source,
            "Captured token usage telemetry"
        );
        if let Err(error) = store.insert_usage(&usage).await {
            warn!(
                request_id = %usage.request_id,
                error = %error,
                source,
                "Failed to persist usage telemetry"
            );
        }
    }

    for event in tool_events {
        if let Err(error) = store.insert_tool_event(&event).await {
            warn!(
                request_id = %event.request_id,
                error = %error,
                source,
                "Failed to persist tool telemetry"
            );
        }
    }
}

async fn persist_request_start(state: &AppState, context: &RequestTelemetryContext) {
    let Some(store) = state.telemetry_store.as_ref() else {
        debug!(
            request_id = %context.request_id,
            "Telemetry store disabled; skipping request persistence"
        );
        return;
    };

    let record = RequestRecord {
        request_id: context.request_id.clone(),
        started_at_ms: context.started_at_ms,
        completed_at_ms: None,
        method: context.method.clone(),
        path: context.path.clone(),
        mode: context.mode.clone(),
        upstream: context.upstream.clone(),
        model: context.model.clone(),
        status_code: None,
        error: None,
    };

    if let Err(error) = store.insert_request(&record).await {
        warn!(
            request_id = %context.request_id,
            error = %error,
            "Failed to persist request telemetry"
        );
    }
}

async fn persist_request_finish(
    state: &AppState,
    request_id: &str,
    status_code: Option<u16>,
    error_message: Option<&str>,
) {
    let Some(store) = state.telemetry_store.as_ref() else {
        debug!(
            request_id,
            "Telemetry store disabled; skipping request finish"
        );
        return;
    };

    if let Err(error) = store
        .finish_request(request_id, now_ms(), status_code, error_message)
        .await
    {
        warn!(
            request_id,
            error = %error,
            "Failed to persist request completion telemetry"
        );
    }
}

async fn persist_request_tool_events(
    state: &AppState,
    request_id: &str,
    telemetry_bytes: &[u8],
    source: &str,
) {
    let Some(store) = state.telemetry_store.as_ref() else {
        debug!(
            request_id,
            "Telemetry store disabled; skipping tool event persistence"
        );
        return;
    };

    let events = extract_tool_events_from_json(request_id, telemetry_bytes, source);
    debug!(
        request_id,
        event_count = events.len(),
        "Parsed request tool telemetry"
    );
    for event in events {
        if let Err(error) = store.insert_tool_event(&event).await {
            warn!(
                request_id = %event.request_id,
                error = %error,
                "Failed to persist request tool telemetry"
            );
        }
    }
}

async fn persist_content_capture_from_bytes(
    state: &Arc<AppState>,
    request_id: &str,
    direction: &str,
    source: &str,
    content_type: Option<&str>,
    bytes: &[u8],
    observed_bytes: usize,
    already_truncated: bool,
) {
    let Some(store) = state.telemetry_store.as_ref() else {
        return;
    };
    let capture_enabled = match direction {
        "request" => state.config.dashboard.capture.prompts,
        "response" => state.config.dashboard.capture.responses,
        _ => false,
    };
    if !capture_enabled || bytes.is_empty() {
        return;
    }

    let Some(capture_preview) = prepare_capture_preview(
        direction,
        content_type,
        bytes,
        state.config.dashboard.capture.max_body_bytes,
        observed_bytes,
        already_truncated,
    ) else {
        debug!(
            request_id,
            direction, "Skipping content capture for non-UTF-8 payload"
        );
        return;
    };
    persist_content_capture_from_text(
        state,
        store,
        request_id,
        direction,
        source,
        content_type,
        &capture_preview.preview_text,
        capture_preview.truncated,
    )
    .await;
}

async fn persist_content_capture_from_text(
    state: &Arc<AppState>,
    store: &TelemetryStore,
    request_id: &str,
    direction: &str,
    source: &str,
    content_type: Option<&str>,
    preview: &str,
    truncated: bool,
) {
    let mut redacted = false;
    let preview_text = if state.config.dashboard.capture.redact_before_store {
        if state.pipeline.is_empty() {
            warn!(
                request_id,
                direction,
                "Skipping content capture because redact_before_store is enabled but no scanners are configured"
            );
            return;
        }
        let context = RedactionContext::new(request_id, &state.config.redaction);
        redacted = true;
        let (result, _) = scan_and_redact_blocking(
            state.clone(),
            request_id.to_string(),
            preview.to_string(),
            context,
        )
        .await;
        result.text
    } else {
        preview.to_string()
    };

    let capture = ContentCaptureRecord {
        request_id: request_id.to_string(),
        observed_at_ms: now_ms(),
        direction: direction.to_string(),
        source: source.to_string(),
        content_type: content_type.map(ToOwned::to_owned),
        preview_text,
        truncated,
        redacted,
    };
    if let Err(error) = store.insert_content_capture(&capture).await {
        warn!(
            request_id,
            direction,
            error = %error,
            "Failed to persist content capture"
        );
    }
}

struct CapturePreviewBuffer {
    buffer: Vec<u8>,
    cap_bytes: usize,
    observed_bytes: usize,
    truncated: bool,
}

impl CapturePreviewBuffer {
    fn new(cap_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            cap_bytes,
            observed_bytes: 0,
            truncated: false,
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        self.observed_bytes = self.observed_bytes.saturating_add(bytes.len());
        if self.truncated {
            return;
        }
        let remaining = self.cap_bytes.saturating_sub(self.buffer.len());
        if bytes.len() > remaining {
            self.buffer.extend_from_slice(&bytes[..remaining]);
            self.truncated = true;
            return;
        }
        self.buffer.extend_from_slice(bytes);
    }

    fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    fn truncated(&self) -> bool {
        self.truncated
    }

    fn observed_bytes(&self) -> usize {
        self.observed_bytes
    }
}

struct PreparedCapturePreview {
    preview_text: String,
    truncated: bool,
}

fn prepare_capture_preview(
    direction: &str,
    content_type: Option<&str>,
    bytes: &[u8],
    max_bytes: usize,
    observed_bytes: usize,
    already_truncated: bool,
) -> Option<PreparedCapturePreview> {
    let observed_bytes = observed_bytes.max(bytes.len());
    if is_html_content_type(content_type) {
        return Some(PreparedCapturePreview {
            preview_text: html_capture_summary(direction, content_type, observed_bytes),
            truncated: false,
        });
    }

    let (preview_text, truncated) = preview_text(bytes, max_bytes)?;
    Some(PreparedCapturePreview {
        preview_text,
        truncated: already_truncated || truncated,
    })
}

fn is_html_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .map(|mime| {
            let mime = mime.trim();
            mime.eq_ignore_ascii_case("text/html")
                || mime.eq_ignore_ascii_case("application/xhtml+xml")
        })
        .unwrap_or(false)
}

fn html_capture_summary(
    direction: &str,
    content_type: Option<&str>,
    observed_bytes: usize,
) -> String {
    let content_type = content_type
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    format!(
        "[HTML {direction} body omitted from dashboard capture: content_type=\"{content_type}\", body_bytes={observed_bytes}]"
    )
}

fn preview_text(bytes: &[u8], max_bytes: usize) -> Option<(String, bool)> {
    let limit = bytes.len().min(max_bytes);
    let mut end = limit;
    loop {
        match std::str::from_utf8(&bytes[..end]) {
            Ok(text) => return Some((text.to_string(), bytes.len() > end)),
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                if valid_up_to == 0 {
                    return None;
                }
                end = valid_up_to;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_capture_preview_omits_html_body() {
        let html = b"<!doctype html><html><body>cloudflare challenge</body></html>";

        let preview = prepare_capture_preview(
            "response",
            Some("text/html; charset=UTF-8"),
            html,
            8192,
            html.len(),
            false,
        )
        .expect("html preview should be summarized");

        assert_eq!(
            preview.preview_text,
            format!(
                "[HTML response body omitted from dashboard capture: content_type=\"text/html; charset=UTF-8\", body_bytes={}]",
                html.len()
            )
        );
        assert!(!preview.truncated);
        assert!(!preview.preview_text.contains("<html>"));
    }

    #[test]
    fn prepare_capture_preview_keeps_json_text() {
        let body = br#"{"ok":true}"#;

        let preview = prepare_capture_preview(
            "response",
            Some("application/json"),
            body,
            8192,
            body.len(),
            false,
        )
        .expect("json preview should be captured");

        assert_eq!(preview.preview_text, r#"{"ok":true}"#);
        assert!(!preview.truncated);
    }

    #[test]
    fn capture_preview_buffer_counts_observed_bytes_after_cap() {
        let mut buffer = CapturePreviewBuffer::new(4);

        buffer.observe(b"abcd");
        buffer.observe(b"efgh");
        buffer.observe(b"ijkl");

        assert_eq!(buffer.bytes(), b"abcd");
        assert_eq!(buffer.observed_bytes(), 12);
        assert!(buffer.truncated());
    }

    #[test]
    fn response_restore_allows_only_uncompressed_textual_payloads() {
        assert!(response_restore_allowed(Some("application/json"), None));
        assert!(response_restore_allowed(Some("text/event-stream"), None));
        assert!(response_restore_allowed(
            Some("application/vnd.api+json"),
            None
        ));
        assert!(!response_restore_allowed(
            Some("application/json"),
            Some("gzip")
        ));
        assert!(!response_restore_allowed(
            Some("application/octet-stream"),
            None
        ));
        assert!(!response_restore_allowed(None, None));
    }

    #[test]
    fn build_upstream_url_preserves_absolute_proxy_uri() {
        let uri: Uri = "http://127.0.0.1:5180/index.html?x=1".parse().unwrap();

        let upstream = build_upstream_url("https://api.anthropic.com", &uri);

        assert_eq!(upstream, "http://127.0.0.1:5180/index.html?x=1");
    }

    #[test]
    fn build_upstream_url_joins_origin_form_uri() {
        let uri: Uri = "/v1/messages?x=1".parse().unwrap();

        let upstream = build_upstream_url("https://api.anthropic.com/", &uri);

        assert_eq!(upstream, "https://api.anthropic.com/v1/messages?x=1");
    }

    #[test]
    fn websocket_upstream_request_strips_extensions() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));

        let request = build_websocket_upstream_request("wss://example.test/ws", &headers).unwrap();

        assert!(request.headers().get(SEC_WEBSOCKET_EXTENSIONS).is_none());
        assert_eq!(
            request.headers().get("authorization").unwrap(),
            "Bearer token"
        );
    }
}

fn is_mitm_excluded_host(state: &AppState, host: &str) -> bool {
    state
        .config
        .proxy
        .mitm_excluded_hosts
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(host))
}

fn log_connect_tunnel_error(target: &str, error: &std::io::Error) {
    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    ) {
        debug!(target = %target, error = %error, "CONNECT tunnel closed");
        return;
    }

    warn!(target = %target, error = %error, "CONNECT tunnel failed");
}

async fn tunnel_upgraded_connection(
    upgraded: Upgraded,
    authority: &str,
    connect_timeout_secs: u64,
    tunnel_timeout_secs: u64,
) -> std::io::Result<()> {
    let connect_timeout = Duration::from_secs(connect_timeout_secs.max(1));
    let mut server = tokio::time::timeout(connect_timeout, TcpStream::connect(authority))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT upstream timed out")
        })??;
    let mut client = TokioIo::new(upgraded);
    if tunnel_timeout_secs > 0 {
        tokio::time::timeout(
            Duration::from_secs(tunnel_timeout_secs),
            copy_bidirectional(&mut client, &mut server),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT tunnel timed out")
        })??;
    } else {
        copy_bidirectional(&mut client, &mut server).await?;
    }
    Ok(())
}

async fn tunnel_mitm_connection(
    state: Arc<AppState>,
    upgraded: Upgraded,
    authority: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(mitm_authority) = state.mitm_authority.clone() else {
        return Err(Box::new(std::io::Error::other(
            "MITM authority is not configured",
        )));
    };

    let acceptor_authority = authority.clone();
    let acceptor = tokio::task::spawn_blocking(move || {
        mitm_authority.acceptor_for_authority(&acceptor_authority)
    })
    .await
    .map_err(|error| std::io::Error::other(format!("MITM certificate task failed: {error}")))??;
    let upgraded = TokioIo::new(upgraded);
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(state.config.proxy.connect_timeout_secs.max(1)),
        acceptor.accept(upgraded),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "CONNECT MITM TLS handshake timed out",
        )
    })??;
    debug!(target = %authority, "CONNECT MITM TLS handshake completed");

    let service_authority = authority.clone();
    let service_state = state.clone();
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let state = service_state.clone();
        let authority = service_authority.clone();
        async move { Ok::<_, Infallible>(handle_mitm_http_request(state, authority, req).await) }
    });

    let serve = http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .with_upgrades();
    if state.config.proxy.request_timeout_secs > 0 {
        tokio::time::timeout(
            Duration::from_secs(state.config.proxy.request_timeout_secs),
            serve,
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "CONNECT MITM session timed out",
            )
        })??;
    } else {
        serve.await?;
    }
    debug!(target = %authority, "CONNECT MITM session completed");

    Ok(())
}

async fn handle_mitm_http_request(
    state: Arc<AppState>,
    authority: String,
    req: hyper::Request<Incoming>,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let request_id = next_request_id();
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let route = upstream_route(&state, &uri, &headers);
    let upstream_url = route
        .absolute_url
        .unwrap_or_else(|| format!("https://{}{}", authority, path_and_query));

    if is_websocket_upgrade(&headers) {
        return handle_mitm_websocket_upgrade(state, req, upstream_url).await;
    }

    debug!(
        mode = "mitm",
        request_id = %request_id,
        method = %method,
        path = %path_and_query,
        upstream = %upstream_url,
        "Forwarding decrypted CONNECT request"
    );

    match forward_request(
        &state,
        method,
        headers,
        Body::new(req.into_body()),
        upstream_url,
        route.is_codex_responses || state.config.scanner.enabled,
        route.needs_codex_subscription_payload_normalization,
        "mitm",
        request_id,
    )
    .await
    {
        Ok(response) => response,
        Err(status) => {
            warn!(
                mode = "mitm",
                status = status.as_u16(),
                "MITM request forwarding failed"
            );
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            response
        }
    }
}

async fn handle_mitm_websocket_upgrade(
    state: Arc<AppState>,
    req: hyper::Request<Incoming>,
    upstream_url: String,
) -> Response {
    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let websocket_mode = state.config.proxy.websocket_mode.as_str();
    let request_id = next_request_id();

    if websocket_mode == "reject" {
        info!(
            mode = "mitm",
            websocket_mode,
            path = %path,
            "Rejecting WebSocket upgrade to force HTTPS fallback"
        );
        let mut response = Response::new(Body::from("websocket not supported"));
        *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
        return response;
    }

    let Some(sec_key) = headers
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
    else {
        warn!(mode = "mitm", path = %path, "WebSocket upgrade missing Sec-WebSocket-Key");
        let mut response = Response::new(Body::from("missing websocket key"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    };

    let ws_url = websocket_url_from_https(&upstream_url);
    let upstream_request = match build_websocket_upstream_request(&ws_url, &headers) {
        Ok(request) => request,
        Err(error) => {
            warn!(mode = "mitm", error = %error, upstream = %ws_url, "Failed to build upstream WebSocket request");
            let mut response = Response::new(Body::from("bad websocket upstream request"));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            return response;
        }
    };

    let (upstream_ws, upstream_response) = match connect_async(upstream_request).await {
        Ok((websocket, response)) => {
            debug!(
                mode = "mitm",
                status = response.status().as_u16(),
                upstream = %ws_url,
                "Connected upstream WebSocket"
            );
            (websocket, response)
        }
        Err(error) => {
            warn!(mode = "mitm", error = %error, upstream = %ws_url, "Failed to connect upstream WebSocket");
            let mut response = Response::new(Body::from("websocket upstream unavailable"));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            return response;
        }
    };

    let on_upgrade = hyper::upgrade::on(req);
    let state_for_task = state.clone();
    let websocket_mode_owned = websocket_mode.to_string();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(error) = proxy_mitm_websocket(
                    state_for_task,
                    upgraded,
                    upstream_ws,
                    websocket_mode_owned,
                    request_id,
                    upstream_url,
                    path,
                )
                .await
                {
                    warn!(mode = "mitm", error = %error, "WebSocket MITM session failed");
                }
            }
            Err(error) => {
                warn!(mode = "mitm", error = %error, "WebSocket upgrade failed");
            }
        }
    });

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response.headers_mut().insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("Upgrade"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    if let Ok(value) = HeaderValue::from_str(&derive_accept_key(sec_key.as_bytes())) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(SEC_WEBSOCKET_ACCEPT), value);
    }
    if let Some(protocol) = upstream_response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .cloned()
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static(SEC_WEBSOCKET_PROTOCOL), protocol);
    }
    response
}

async fn proxy_mitm_websocket(
    state: Arc<AppState>,
    upgraded: Upgraded,
    mut upstream_ws: UpstreamWebSocket,
    websocket_mode: String,
    request_id: String,
    upstream_url: String,
    path: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        mode = "mitm",
        request_id = %request_id,
        websocket_mode = %websocket_mode,
        upstream = %upstream_url,
        "Starting WebSocket MITM session"
    );
    debug!(
        mode = "mitm",
        request_id = %request_id,
        websocket_mode = %websocket_mode,
        client_to_server_redaction = websocket_mode == "inspect" && state.config.scanner.enabled,
        server_to_client_redaction = websocket_mode == "inspect" && state.config.scanner.enabled,
        "WebSocket restoration policy"
    );
    let telemetry_context = RequestTelemetryContext {
        request_id: request_id.clone(),
        started_at_ms: now_ms(),
        method: "WEBSOCKET".to_string(),
        path,
        mode: "mitm-websocket".to_string(),
        upstream: upstream_url.clone(),
        model: None,
    };
    persist_request_start(&state, &telemetry_context).await;

    let client_io = TokioIo::new(upgraded);
    let mut client_ws =
        WebSocketStream::from_raw_socket(client_io, Role::Server, Some(WebSocketConfig::default()))
            .await;
    let mut client_redaction_context = RedactionContext::new(&request_id, &state.config.redaction);
    let mut upstream_redaction_context =
        RedactionContext::new(&request_id, &state.config.redaction);

    loop {
        tokio::select! {
            client_msg = client_ws.next() => {
                let Some(client_msg) = client_msg else {
                    debug!(mode = "mitm", "Client WebSocket closed");
                    break;
                };
                let message = match client_msg {
                    Ok(message) => message,
                    Err(error) => {
                        warn!(mode = "mitm", error = %error, "Client WebSocket read failed");
                        let _ = upstream_ws.close(None).await;
                        break;
                    }
                };
                let is_close = matches!(message, Message::Close(_));
                let message = if websocket_mode == "inspect" && state.config.scanner.enabled {
                    redact_websocket_message(state.clone(), &request_id, message, &mut client_redaction_context).await
                } else {
                    message
                };
                if let Message::Text(text) = &message {
                    spawn_websocket_text_telemetry(
                        state.clone(),
                        request_id.clone(),
                        telemetry_context.model.clone(),
                        upstream_url.clone(),
                        text.to_string(),
                        "client",
                    );
                }
                if let Err(error) = upstream_ws.send(message).await {
                    warn!(mode = "mitm", error = %error, "Upstream WebSocket send failed");
                    let _ = client_ws.close(None).await;
                    break;
                }
                if is_close {
                    let _ = client_ws.close(None).await;
                    break;
                }
            }
            upstream_msg = upstream_ws.next() => {
                let Some(upstream_msg) = upstream_msg else {
                    debug!(mode = "mitm", "Upstream WebSocket closed");
                    break;
                };
                let message = match upstream_msg {
                    Ok(message) => message,
                    Err(error) => {
                        warn!(mode = "mitm", error = %error, "Upstream WebSocket read failed");
                        let _ = client_ws.close(None).await;
                        break;
                    }
                };
                let is_close = matches!(message, Message::Close(_));
                let message = if websocket_mode == "inspect" && state.config.scanner.enabled {
                    redact_websocket_message(state.clone(), &request_id, message, &mut upstream_redaction_context).await
                } else {
                    message
                };
                if let Message::Text(text) = &message {
                    spawn_websocket_text_telemetry(
                        state.clone(),
                        request_id.clone(),
                        telemetry_context.model.clone(),
                        upstream_url.clone(),
                        text.to_string(),
                        "upstream",
                    );
                }
                if let Err(error) = client_ws.send(message).await {
                    warn!(mode = "mitm", error = %error, "Client WebSocket send failed");
                    let _ = upstream_ws.close(None).await;
                    break;
                }
                if is_close {
                    let _ = upstream_ws.close(None).await;
                    break;
                }
            }
        }
    }

    let _ = client_ws.close(None).await;
    let _ = upstream_ws.close(None).await;
    persist_request_finish(
        &state,
        &request_id,
        Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
        None,
    )
    .await;

    Ok(())
}

fn spawn_websocket_text_telemetry(
    state: Arc<AppState>,
    request_id: String,
    model: Option<String>,
    upstream_url: String,
    text: String,
    direction: &'static str,
) {
    tokio::spawn(async move {
        persist_websocket_text_telemetry(
            state,
            &request_id,
            model.as_deref(),
            &upstream_url,
            &text,
            direction,
        )
        .await;
    });
}

async fn persist_websocket_text_telemetry(
    state: Arc<AppState>,
    request_id: &str,
    model: Option<&str>,
    upstream_url: &str,
    text: &str,
    direction: &str,
) {
    let Some(store) = state.telemetry_store.as_ref() else {
        debug!(
            request_id,
            direction, "Telemetry store disabled; skipping WebSocket telemetry"
        );
        return;
    };

    let (usage_records, tool_events) =
        extract_websocket_text_telemetry(request_id, model, upstream_url, text);
    debug!(
        request_id,
        direction,
        usage_count = usage_records.len(),
        tool_event_count = tool_events.len(),
        "Parsed WebSocket telemetry frame"
    );
    persist_response_telemetry_records(store, usage_records, tool_events, "websocket").await;

    let capture_direction = match direction {
        "client" => "request",
        "upstream" => "response",
        _ => return,
    };
    let capture_enabled = match capture_direction {
        "request" => state.config.dashboard.capture.prompts,
        "response" => state.config.dashboard.capture.responses,
        _ => false,
    };
    if capture_enabled
        && let Some((preview, truncated)) = preview_text(
            text.as_bytes(),
            state.config.dashboard.capture.max_body_bytes,
        )
    {
        persist_content_capture_from_text(
            &state,
            store,
            request_id,
            capture_direction,
            "websocket",
            Some("application/json"),
            &preview,
            truncated,
        )
        .await;
    }
}

fn build_websocket_upstream_request(
    ws_url: &str,
    headers: &HeaderMap,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::client::Request,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mut upstream_request = ws_url.into_client_request()?;
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_ascii_lowercase();
        if is_websocket_hop_header(&name_lower) {
            if name_lower == SEC_WEBSOCKET_EXTENSIONS {
                debug!("Stripping WebSocket extensions for MITM frame inspection");
            }
            continue;
        }
        upstream_request
            .headers_mut()
            .append(name.clone(), value.clone());
    }
    Ok(upstream_request)
}

async fn redact_websocket_message(
    state: Arc<AppState>,
    request_id: &str,
    message: Message,
    context: &mut RedactionContext,
) -> Message {
    match message {
        Message::Text(text) => {
            let original_len = text.len();
            let (redacted, updated_context) = scan_and_redact_blocking(
                state,
                request_id.to_string(),
                text.to_string(),
                context.clone(),
            )
            .await;
            *context = updated_context;
            if redacted.text.len() != original_len || redacted.text.as_str() != text.as_str() {
                info!(
                    mode = "mitm",
                    request_id,
                    original_len,
                    redacted_len = redacted.text.len(),
                    findings = redacted.findings.len(),
                    replacements = redacted.replacements.len(),
                    "Redacted WebSocket text frame"
                );
            }
            Message::Text(redacted.text.into())
        }
        other => other,
    }
}

fn websocket_url_from_https(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url.to_string()
    }
}

struct UpstreamRoute {
    base_url: String,
    absolute_url: Option<String>,
    is_codex_responses: bool,
    needs_codex_subscription_payload_normalization: bool,
}

/// Pick the upstream by endpoint shape. Anthropic-compatible traffic remains on
/// proxy.anthropic_upstream_url; Codex/OpenAI Responses traffic goes to OpenAI or the
/// ChatGPT subscription backend, matching the harness proxy behavior.
fn upstream_route(state: &AppState, uri: &Uri, headers: &HeaderMap) -> UpstreamRoute {
    if !is_codex_responses_path(uri.path()) {
        return UpstreamRoute {
            base_url: state.config.proxy.anthropic_upstream_url.clone(),
            absolute_url: None,
            is_codex_responses: false,
            needs_codex_subscription_payload_normalization: false,
        };
    }

    if state.config.proxy.codex_subscription_routing_enabled
        && !is_openai_api_key_auth(headers.get("authorization").and_then(|v| v.to_str().ok()))
    {
        return UpstreamRoute {
            base_url: state.config.proxy.codex_subscription_url.clone(),
            absolute_url: Some(subscription_upstream_url(
                state.config.proxy.codex_subscription_url.as_str(),
                uri,
            )),
            is_codex_responses: true,
            needs_codex_subscription_payload_normalization: !is_codex_compact_path(uri.path()),
        };
    }

    UpstreamRoute {
        base_url: state.config.proxy.codex_upstream_url.clone(),
        absolute_url: None,
        is_codex_responses: true,
        needs_codex_subscription_payload_normalization: false,
    }
}

fn is_codex_responses_path(path: &str) -> bool {
    path == "/v1/responses"
        || path.ends_with("/v1/responses")
        || path.contains("/v1/responses/")
        || path.contains("/backend-api/codex/responses")
}

fn is_codex_compact_path(path: &str) -> bool {
    path == "/v1/responses/compact"
        || path.ends_with("/v1/responses/compact")
        || path == "/backend-api/codex/responses/compact"
        || path.ends_with("/backend-api/codex/responses/compact")
}

fn is_openai_api_key_auth(auth: Option<&str>) -> bool {
    auth.is_some_and(|value| value.starts_with("Bearer sk-"))
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has_upgrade_websocket = headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection_has_upgrade = headers
        .get("connection")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });

    has_upgrade_websocket || connection_has_upgrade
}

fn is_websocket_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "upgrade"
            | "host"
            | SEC_WEBSOCKET_ACCEPT
            | SEC_WEBSOCKET_KEY
            | SEC_WEBSOCKET_EXTENSIONS
            | SEC_WEBSOCKET_VERSION
    )
}

fn append_query(base_url: &str, uri: &Uri) -> String {
    let Some(query) = uri.query() else {
        return base_url.to_string();
    };

    if base_url.contains('?') {
        format!("{}&{}", base_url, query)
    } else {
        format!("{}?{}", base_url, query)
    }
}

fn subscription_upstream_url(base_url: &str, uri: &Uri) -> String {
    const CODEX_RESPONSES_PATH: &str = "/backend-api/codex/responses";
    const OPENAI_RESPONSES_PATH: &str = "/v1/responses";

    let request_path = uri.path();
    let suffix = request_path
        .strip_prefix(CODEX_RESPONSES_PATH)
        .or_else(|| request_path.strip_prefix(OPENAI_RESPONSES_PATH))
        .unwrap_or("");
    let base = base_url.trim_end_matches('/');
    let with_suffix = format!("{base}{suffix}");

    append_query(&with_suffix, uri)
}

struct ProcessedBody {
    bytes: Bytes,
    telemetry_bytes: Bytes,
    strip_content_encoding: bool,
    context: RedactionContext,
}

async fn process_request_body(
    state: &Arc<AppState>,
    request_id: &str,
    headers: &HeaderMap,
    body: &Bytes,
    allow_normalization: bool,
    force_codex_store_false: bool,
) -> Result<ProcessedBody, StatusCode> {
    let normalized = if allow_normalization {
        normalize_body(headers, body, state.config.proxy.max_body_size)?
    } else {
        NormalizedBody {
            bytes: body.clone(),
            decoded: false,
        }
    };

    let normalized = if force_codex_store_false {
        normalize_codex_subscription_payload(normalized)
    } else {
        normalized
    };
    let telemetry_bytes = normalized.bytes.clone();
    let context = RedactionContext::new(request_id, &state.config.redaction);

    if !state.config.scanner.enabled {
        return Ok(ProcessedBody {
            bytes: normalized.bytes,
            telemetry_bytes,
            strip_content_encoding: normalized.decoded,
            context,
        });
    }

    let has_content_encoding = headers.get(CONTENT_ENCODING).is_some();
    if has_content_encoding && !normalized.decoded {
        warn!("Skipping secret scan because request body content-encoding could not be decoded");
        return Ok(ProcessedBody {
            bytes: normalized.bytes,
            telemetry_bytes,
            strip_content_encoding: false,
            context,
        });
    }

    let Ok(body_string) = std::str::from_utf8(&normalized.bytes) else {
        warn!("Skipping secret scan for non-UTF-8 request body");
        return Ok(ProcessedBody {
            bytes: normalized.bytes,
            telemetry_bytes,
            strip_content_encoding: normalized.decoded,
            context,
        });
    };

    let (redacted_body, context) = scan_and_redact_blocking(
        state.clone(),
        request_id.to_string(),
        body_string.to_string(),
        context,
    )
    .await;
    Ok(ProcessedBody {
        bytes: Bytes::from(redacted_body.text.into_bytes()),
        telemetry_bytes,
        strip_content_encoding: normalized.decoded,
        context,
    })
}

fn normalize_codex_subscription_payload(body: NormalizedBody) -> NormalizedBody {
    let Ok(mut json) = serde_json::from_slice::<Value>(&body.bytes) else {
        return body;
    };

    let Some(object) = json.as_object_mut() else {
        return body;
    };

    let store_was = object.get("store").cloned();
    let stream_was = object.get("stream").cloned();
    if store_was == Some(Value::Bool(false)) && stream_was == Some(Value::Bool(true)) {
        return body;
    }

    if store_was.is_some() || stream_was.is_some() {
        warn!(
            previous_store = ?store_was,
            previous_stream = ?stream_was,
            "Overriding Codex subscription request payload store/stream fields"
        );
    }
    object.insert("store".to_string(), Value::Bool(false));
    object.insert("stream".to_string(), Value::Bool(true));
    match serde_json::to_vec(&json) {
        Ok(bytes) => {
            info!("Normalized Codex subscription request payload");
            NormalizedBody {
                bytes: Bytes::from(bytes),
                decoded: body.decoded,
            }
        }
        Err(error) => {
            warn!(error = %error, "Failed to serialize Codex subscription request body");
            body
        }
    }
}

struct NormalizedBody {
    bytes: Bytes,
    decoded: bool,
}

fn normalize_body(
    headers: &HeaderMap,
    body: &Bytes,
    max_body_size: usize,
) -> Result<NormalizedBody, StatusCode> {
    let Some(encoding) = headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
    else {
        return Ok(NormalizedBody {
            bytes: body.clone(),
            decoded: false,
        });
    };

    let decoded = match encoding.as_str() {
        "gzip" => Some(decompress_gzip(body, max_body_size)?),
        "zstd" => Some(decompress_zstd(body, max_body_size)?),
        _ => None,
    };

    let normalized = decoded
        .map(|bytes| NormalizedBody {
            bytes,
            decoded: true,
        })
        .unwrap_or_else(|| NormalizedBody {
            bytes: body.clone(),
            decoded: false,
        });

    Ok(normalized)
}

fn decompress_gzip(body: &[u8], max_body_size: usize) -> Result<Bytes, StatusCode> {
    if body.len() < 2 || body[0] != 0x1f || body[1] != 0x8b {
        return Err(StatusCode::BAD_REQUEST);
    }

    let decoder = GzDecoder::new(body);
    let mut decompressed = Vec::new();
    decoder
        .take(max_body_size.saturating_add(1) as u64)
        .read_to_end(&mut decompressed)
        .map_err(|error| {
            warn!(error = %error, "Failed to decompress gzip request body");
            StatusCode::BAD_REQUEST
        })?;
    if decompressed.len() > max_body_size {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(Bytes::from(decompressed))
}

fn decompress_zstd(body: &[u8], max_body_size: usize) -> Result<Bytes, StatusCode> {
    const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
    if body.len() < ZSTD_MAGIC.len() || &body[..ZSTD_MAGIC.len()] != ZSTD_MAGIC {
        return Err(StatusCode::BAD_REQUEST);
    }

    let decoder = zstd::stream::read::Decoder::new(body).map_err(|error| {
        warn!(error = %error, "Failed to initialize zstd request body decoder");
        StatusCode::BAD_REQUEST
    })?;
    let mut decompressed = Vec::new();
    decoder
        .take(max_body_size.saturating_add(1) as u64)
        .read_to_end(&mut decompressed)
        .map_err(|error| {
            warn!(error = %error, "Failed to decompress zstd request body");
            StatusCode::BAD_REQUEST
        })?;
    if decompressed.len() > max_body_size {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok(Bytes::from(decompressed))
}

/// Scan text for secrets and redact them.
fn scan_and_redact(
    state: &AppState,
    request_id: &str,
    text: &str,
    context: &mut RedactionContext,
) -> crate::redactor::RedactionResult {
    let matches = state.pipeline.scan(text);

    if matches.is_empty() {
        debug!(request_id, "No sensitive data found");
        return crate::redactor::RedactionResult {
            text: text.to_string(),
            findings: Vec::new(),
            replacements: Vec::new(),
            skipped: 0,
        };
    }

    info!(
        request_id,
        findings = matches.len(),
        "Redacting sensitive data"
    );

    let result = state.redactor.redact_findings(text, matches, context);
    for replacement in &result.replacements {
        if let Some(finding) = result.findings.iter().find(|finding| {
            finding.start == replacement.start
                && finding.end == replacement.end
                && finding.category == replacement.category
        }) {
            log_redaction(finding, replacement.replacement_len);
        }
    }

    result
}

async fn scan_and_redact_blocking(
    state: Arc<AppState>,
    request_id: String,
    text: String,
    mut context: RedactionContext,
) -> (crate::redactor::RedactionResult, RedactionContext) {
    tokio::task::spawn_blocking(move || {
        let result = scan_and_redact(&state, &request_id, &text, &mut context);
        (result, context)
    })
    .await
    .expect("scan/redact blocking task failed")
}

/// Scan and redact non-whitelisted header values when scan_scope is "full".
async fn scan_and_redact_headers(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    request_id: &str,
    context: &mut RedactionContext,
) -> HeaderMap {
    let whitelist: Vec<String> = state
        .config
        .scanner
        .header_whitelist
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    let mut result = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str())
            || name_lower == CONTENT_ENCODING
            || whitelist.contains(&name_lower)
        {
            result.append(name.clone(), value.clone());
            continue;
        }
        if let Ok(val_str) = value.to_str() {
            let (redacted, updated_context) = scan_and_redact_blocking(
                state.clone(),
                request_id.to_string(),
                val_str.to_string(),
                context.clone(),
            )
            .await;
            *context = updated_context;
            if redacted.text != val_str {
                match HeaderValue::from_str(&redacted.text) {
                    Ok(new_val) => {
                        result.append(name.clone(), new_val);
                    }
                    Err(error) => {
                        warn!(
                            request_id,
                            header = %name,
                            error = %error,
                            "Dropping header because redacted value is invalid"
                        );
                    }
                }
                continue;
            }
        }
        result.append(name.clone(), value.clone());
    }
    result
}

/// Scan and redact query parameter values when scan_scope is "full".
async fn scan_and_redact_query_params(
    state: &Arc<AppState>,
    url: &str,
    request_id: &str,
    context: &mut RedactionContext,
) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };

    let mut segments = Vec::new();
    let mut changed = false;
    for raw_segment in query.split('&') {
        let (raw_key, raw_value) = raw_segment.split_once('=').unwrap_or((raw_segment, ""));
        let key = percent_decode_query_component(raw_key);
        let value = percent_decode_query_component(raw_value);
        let (redacted_value, updated_context) = scan_and_redact_blocking(
            state.clone(),
            request_id.to_string(),
            value.to_string(),
            context.clone(),
        )
        .await;
        *context = updated_context;
        if redacted_value.text != value {
            changed = true;
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            serializer.append_pair(&key, &redacted_value.text);
            segments.push(serializer.finish());
        } else {
            segments.push(raw_segment.to_string());
        }
    }

    if changed {
        format!("{}?{}", base, segments.join("&"))
    } else {
        url.to_string()
    }
}

fn percent_decode_query_component(value: &str) -> String {
    form_urlencoded::parse(value.as_bytes())
        .next()
        .map(|(value, _)| value.into_owned())
        .unwrap_or_default()
}

/// Build the full upstream URL from base URL and request URI.
fn build_upstream_url(base: &str, uri: &Uri) -> String {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return uri.to_string();
    }

    let base = base.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    format!("{}{}", base, path_and_query)
}

/// Convert axum Method to reqwest Method.
fn reqwest_method(method: &Method) -> Result<reqwest::Method, ()> {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).map_err(|_| ())
}

/// Forward request headers, skipping hop-by-hop headers.
fn forward_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    strip_content_encoding: bool,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        let name_str = name.as_str().to_lowercase();

        // Skip hop-by-hop headers and content-length (reqwest sets it from body)
        if HOP_BY_HOP_HEADERS.contains(&name_str.as_str())
            || name_str == CONTENT_LENGTH
            || (strip_content_encoding && name_str == CONTENT_ENCODING)
        {
            continue;
        }

        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    builder
}
