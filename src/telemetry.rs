use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

pub const DEFAULT_QUERY_WINDOW_HOURS: u64 = 24;
pub const MAX_RESPONSE_TELEMETRY_BUFFER_BYTES: usize = 1024 * 1024;
static LAST_ULID_TIMESTAMP_MS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub request_id: String,
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub method: String,
    pub path: String,
    pub mode: String,
    pub upstream: String,
    pub model: Option<String>,
    pub status_code: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TokenUsageRecord {
    pub request_id: String,
    pub observed_at_ms: i64,
    pub model: Option<String>,
    pub upstream: String,
    pub source: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ToolEventRecord {
    pub request_id: String,
    pub observed_at_ms: i64,
    pub event_kind: String,
    pub tool_name: Option<String>,
    pub call_id: Option<String>,
    pub status: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct ContentCaptureRecord {
    pub request_id: String,
    pub observed_at_ms: i64,
    pub direction: String,
    pub source: String,
    pub content_type: Option<String>,
    pub preview_text: String,
    pub truncated: bool,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTotals {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub request_count: i64,
    pub error_count: i64,
    pub auxiliary_error_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageBreakdownRow {
    pub name: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub request_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageDashboard {
    pub window_hours: u64,
    pub generated_at_ms: i64,
    pub totals: UsageTotals,
    pub by_model: Vec<UsageBreakdownRow>,
    pub by_upstream: Vec<UsageBreakdownRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEventView {
    pub observed_at_ms: i64,
    pub request_id: String,
    pub event_kind: String,
    pub tool_name: Option<String>,
    pub call_id: Option<String>,
    pub status: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolHistoryDashboard {
    pub window_hours: u64,
    pub generated_at_ms: i64,
    pub events: Vec<ToolEventView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEventView {
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub mode: String,
    pub upstream: String,
    pub model: Option<String>,
    pub status_code: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDashboard {
    pub window_hours: u64,
    pub generated_at_ms: i64,
    pub errors: Vec<ErrorEventView>,
    pub auxiliary_errors: Vec<ErrorEventView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTimelineItem {
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub mode: String,
    pub upstream: String,
    pub model: Option<String>,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub tool_event_count: i64,
    pub request_preview: Option<String>,
    pub request_truncated: bool,
    pub response_preview: Option<String>,
    pub response_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTimelineDashboard {
    pub window_hours: u64,
    pub generated_at_ms: i64,
    pub events: Vec<RequestTimelineItem>,
}

#[derive(Debug, Clone)]
pub struct RequestTelemetryContext {
    pub request_id: String,
    pub started_at_ms: i64,
    pub method: String,
    pub path: String,
    pub mode: String,
    pub upstream: String,
    pub model: Option<String>,
}

pub fn next_request_id() -> String {
    format!(
        "req-{}",
        new_ulid().expect("secure random source unavailable for request id")
    )
}

pub fn new_ulid() -> Result<String, getrandom::Error> {
    let timestamp_ms = monotonic_timestamp_ms();
    let mut bytes = [0u8; 16];
    let timestamp = timestamp_ms.to_be_bytes();
    bytes[..6].copy_from_slice(&timestamp[2..]);
    getrandom::fill(&mut bytes[6..])?;
    Ok(encode_ulid(bytes))
}

fn monotonic_timestamp_ms() -> u64 {
    let now = now_ms().max(0) as u64;
    let mut current = LAST_ULID_TIMESTAMP_MS.load(Ordering::Relaxed);
    loop {
        let next = now.max(current);
        match LAST_ULID_TIMESTAMP_MS.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(actual) => current = actual,
        }
    }
}

fn encode_ulid(bytes: [u8; 16]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut value = u128::from_be_bytes(bytes);
    let mut encoded = [b'0'; 26];
    for index in (0..26).rev() {
        encoded[index] = ALPHABET[(value & 0b11111) as usize];
        value >>= 5;
    }
    String::from_utf8(encoded.to_vec()).expect("ULID alphabet is ASCII")
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

pub fn window_start_ms(window_hours: u64) -> i64 {
    let millis = window_hours.saturating_mul(60 * 60 * 1000);
    now_ms().saturating_sub(millis.min(i64::MAX as u64) as i64)
}

pub fn extract_model_from_json(bytes: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(bytes).ok()?;
    extract_model_from_value(&value)
}

fn extract_model_from_value(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => object
            .get("model")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| object.values().find_map(extract_model_from_value)),
        Value::Array(items) => items.iter().find_map(extract_model_from_value),
        _ => None,
    }
}

pub fn extract_response_telemetry(
    request_id: &str,
    model: Option<&str>,
    upstream: &str,
    source: &str,
    bytes: &[u8],
) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
    if bytes.is_empty() {
        return (Vec::new(), Vec::new());
    }

    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return telemetry_from_value(request_id, model, upstream, source, &value);
    }

    let mut usage = Vec::new();
    let mut tools = Vec::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        let trimmed = line.trim();
        let Some(data) = trimmed.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        match serde_json::from_str::<Value>(data) {
            Ok(value) => {
                let (mut usage_rows, mut tool_rows) =
                    telemetry_from_value(request_id, model, upstream, source, &value);
                usage.append(&mut usage_rows);
                tools.append(&mut tool_rows);
            }
            Err(error) => {
                debug!(request_id, source, error = %error, "Skipping non-JSON SSE telemetry event");
            }
        }
    }

    (usage, tools)
}

pub fn extract_websocket_text_telemetry(
    request_id: &str,
    model: Option<&str>,
    upstream: &str,
    text: &str,
) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        debug!(
            request_id,
            source = "websocket",
            "WebSocket text frame is not JSON for telemetry parsing"
        );
        return (Vec::new(), Vec::new());
    };

    telemetry_from_value(request_id, model, upstream, "websocket", &value)
}

pub fn extract_tool_events_from_json(
    request_id: &str,
    bytes: &[u8],
    source: &str,
) -> Vec<ToolEventRecord> {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        debug!(
            request_id,
            source, "Telemetry request body is not JSON for tool parsing"
        );
        return Vec::new();
    };

    let mut events = Vec::new();
    collect_tool_events(&value, request_id, source, &mut events);
    events
}

fn telemetry_from_value(
    request_id: &str,
    model: Option<&str>,
    upstream: &str,
    source: &str,
    value: &Value,
) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
    let mut usage = Vec::new();
    let mut tools = Vec::new();
    collect_usage_records(value, request_id, model, upstream, source, &mut usage);
    collect_tool_events(value, request_id, source, &mut tools);
    (usage, tools)
}

fn collect_usage_records(
    value: &Value,
    request_id: &str,
    model: Option<&str>,
    upstream: &str,
    source: &str,
    usage: &mut Vec<TokenUsageRecord>,
) {
    match value {
        Value::Object(object) => {
            let current_model = model.or_else(|| object.get("model").and_then(Value::as_str));
            if let Some(record) =
                usage_record_from_object(request_id, current_model, upstream, source, value)
            {
                usage.push(record);
            }

            for child in object.values() {
                collect_usage_records(child, request_id, current_model, upstream, source, usage);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_usage_records(item, request_id, model, upstream, source, usage);
            }
        }
        _ => {}
    }
}

fn usage_record_from_object(
    request_id: &str,
    model: Option<&str>,
    upstream: &str,
    source: &str,
    value: &Value,
) -> Option<TokenUsageRecord> {
    let object = value.as_object()?;
    let record_model = model
        .map(ToOwned::to_owned)
        .or_else(|| extract_model_from_value(value));
    let input_tokens = first_i64(
        object,
        &[
            "input_tokens",
            "prompt_tokens",
            "promptTokens",
            "inputTokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
        ],
    );
    let output_tokens = first_i64(
        object,
        &[
            "output_tokens",
            "completion_tokens",
            "completionTokens",
            "outputTokens",
        ],
    );
    let total_tokens = first_i64(object, &["total_tokens", "totalTokens"])
        .or_else(|| Some(input_tokens.unwrap_or(0) + output_tokens.unwrap_or(0)))
        .filter(|total| *total > 0);

    if input_tokens.is_none() && output_tokens.is_none() && total_tokens.is_none() {
        return None;
    }

    Some(TokenUsageRecord {
        request_id: request_id.to_string(),
        observed_at_ms: now_ms(),
        model: record_model,
        upstream: upstream.to_string(),
        source: source.to_string(),
        input_tokens,
        output_tokens,
        total_tokens,
    })
}

fn collect_tool_events(
    value: &Value,
    request_id: &str,
    source: &str,
    events: &mut Vec<ToolEventRecord>,
) {
    match value {
        Value::Object(object) => {
            if let Some(Value::Array(tools)) = object.get("tools") {
                for tool in tools {
                    if let Some(tool_name) = tool_name_from_value(tool) {
                        events.push(ToolEventRecord {
                            request_id: request_id.to_string(),
                            observed_at_ms: now_ms(),
                            event_kind: "tool_definition".to_string(),
                            tool_name: Some(tool_name),
                            call_id: None,
                            status: None,
                            source: source.to_string(),
                        });
                    }
                }
            }

            if let Some(event_kind) = tool_event_kind(object.get("type").and_then(Value::as_str)) {
                events.push(ToolEventRecord {
                    request_id: request_id.to_string(),
                    observed_at_ms: now_ms(),
                    event_kind: event_kind.to_string(),
                    tool_name: tool_name_from_value(value),
                    call_id: first_string(object, &["call_id", "tool_call_id", "id"]),
                    status: first_string(object, &["status"]),
                    source: source.to_string(),
                });
            }

            for child in object.values() {
                collect_tool_events(child, request_id, source, events);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_tool_events(item, request_id, source, events);
            }
        }
        _ => {}
    }
}

fn tool_event_kind(type_value: Option<&str>) -> Option<&'static str> {
    let type_value = type_value?;
    if matches!(
        type_value,
        "tool_use" | "tool_call" | "function_call" | "web_search_call"
    ) {
        return Some("tool_call");
    }
    if matches!(
        type_value,
        "tool_result" | "function_call_output" | "tool_call_output"
    ) {
        return Some("tool_result");
    }
    None
}

fn tool_name_from_value(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    first_string(object, &["name", "tool_name"]).or_else(|| {
        object
            .get("function")
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn first_i64(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_i64))
}

fn first_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

#[derive(Debug)]
pub struct ResponseTelemetryCollector {
    request_id: String,
    model: Option<String>,
    upstream: String,
    source: String,
    buffer: Vec<u8>,
    cap_hit: bool,
}

impl ResponseTelemetryCollector {
    pub fn new(
        request_id: String,
        model: Option<String>,
        upstream: String,
        source: String,
    ) -> Self {
        Self {
            request_id,
            model,
            upstream,
            source,
            buffer: Vec::new(),
            cap_hit: false,
        }
    }

    pub fn observe_chunk(&mut self, chunk: &[u8]) {
        if self.cap_hit {
            return;
        }

        let remaining = MAX_RESPONSE_TELEMETRY_BUFFER_BYTES.saturating_sub(self.buffer.len());
        if chunk.len() > remaining {
            self.buffer.extend_from_slice(&chunk[..remaining]);
            self.cap_hit = true;
            warn!(
                request_id = %self.request_id,
                cap_bytes = MAX_RESPONSE_TELEMETRY_BUFFER_BYTES,
                "Response telemetry parse buffer cap reached"
            );
            return;
        }

        self.buffer.extend_from_slice(chunk);
    }

    pub fn finalize(self) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
        extract_response_telemetry(
            &self.request_id,
            self.model.as_deref(),
            &self.upstream,
            &self.source,
            &self.buffer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_usage_from_json_response() {
        let (usage, tools) = extract_response_telemetry(
            "req-test",
            Some("gpt-test"),
            "https://api.openai.com/v1/responses",
            "response",
            br#"{"usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}"#,
        );

        assert!(tools.is_empty());
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].input_tokens, Some(3));
        assert_eq!(usage[0].output_tokens, Some(5));
        assert_eq!(usage[0].total_tokens, Some(8));
        assert_eq!(usage[0].model.as_deref(), Some("gpt-test"));
    }

    #[test]
    fn extracts_model_from_nested_codex_usage_response() {
        let (usage, _) = extract_websocket_text_telemetry(
            "req-test",
            None,
            "https://chatgpt.com/backend-api/codex/responses",
            r#"{"type":"response.completed","response":{"model":"gpt-5.1-codex","usage":{"input_tokens":21,"output_tokens":34,"total_tokens":55}}}"#,
        );

        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].model.as_deref(), Some("gpt-5.1-codex"));
        assert_eq!(usage[0].input_tokens, Some(21));
        assert_eq!(usage[0].output_tokens, Some(34));
        assert_eq!(usage[0].total_tokens, Some(55));
    }

    #[test]
    fn extracts_usage_from_sse_response() {
        let (usage, _) = extract_response_telemetry(
            "req-test",
            None,
            "https://api.anthropic.com/v1/messages",
            "response",
            b"event: message_delta\ndata: {\"usage\":{\"input_tokens\":4,\"output_tokens\":9}}\n\n",
        );

        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].input_tokens, Some(4));
        assert_eq!(usage[0].output_tokens, Some(9));
        assert_eq!(usage[0].total_tokens, Some(13));
    }

    #[test]
    fn extracts_tool_events_without_raw_arguments() {
        let events = extract_tool_events_from_json(
            "req-test",
            br#"{"tools":[{"name":"shell","input_schema":{"secret":"do-not-store"}}],"input":[{"type":"function_call_output","call_id":"call_1","output":"raw output"}]}"#,
            "request",
        );

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_kind, "tool_definition");
        assert_eq!(events[0].tool_name.as_deref(), Some("shell"));
        assert_eq!(events[1].event_kind, "tool_result");
        assert_eq!(events[1].call_id.as_deref(), Some("call_1"));
    }
}
