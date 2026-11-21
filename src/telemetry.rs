use std::collections::{HashMap, HashSet, hash_map::Entry};
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
    if let Some(request) = gemini_request(&value) {
        return gemini_model(request).or_else(|| gemini_model(&value));
    }
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
    let mut telemetry = ParsedResponseTelemetry::new(
        request_id.to_owned(),
        model.map(ToOwned::to_owned),
        upstream.to_owned(),
        source.to_owned(),
    );
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        telemetry.observe(&value);
    } else {
        let mut sse = SseTelemetryBuffer::default();
        sse.observe_chunk(bytes, &mut telemetry);
        sse.flush(&mut telemetry);
    }

    telemetry.finish()
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

    let mut telemetry = ParsedResponseTelemetry::new(
        request_id.to_owned(),
        model.map(ToOwned::to_owned),
        upstream.to_owned(),
        "websocket".to_owned(),
    );
    telemetry.observe(&value);
    telemetry.finish()
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
    if let Some(request) = gemini_request(&value) {
        collect_gemini_request_events(request, request_id, source, &mut events);
    } else {
        collect_tool_events(&value, request_id, source, &mut events);
    }
    events
}

pub(crate) fn telemetry_url(url: &str) -> &str {
    url.split_once(['?', '#']).map_or(url, |(path, _)| path)
}

#[derive(Debug)]
struct ParsedResponseTelemetry {
    request_id: String,
    model: Option<String>,
    upstream: String,
    source: String,
    usage: Vec<TokenUsageRecord>,
    tools: Vec<ToolEventRecord>,
    gemini_usage: GeminiUsage,
    gemini_tool_ids: HashSet<(String, String)>,
    gemini_pending_calls: HashMap<u64, ToolEventRecord>,
}

impl ParsedResponseTelemetry {
    fn new(
        request_id: String,
        model: Option<String>,
        mut upstream: String,
        source: String,
    ) -> Self {
        upstream.truncate(telemetry_url(&upstream).len());
        Self {
            request_id,
            model,
            upstream,
            source,
            usage: Vec::new(),
            tools: Vec::new(),
            gemini_usage: GeminiUsage::default(),
            gemini_tool_ids: HashSet::new(),
            gemini_pending_calls: HashMap::new(),
        }
    }

    fn observe_sse_event(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        let mut lines = text
            .lines()
            .filter_map(|line| {
                line.trim()
                    .trim_start_matches('\u{feff}')
                    .strip_prefix("data:")
            })
            .map(str::trim);
        let Some(first) = lines.next() else {
            return;
        };
        if let Some(second) = lines.next() {
            let mut data = [first, second].join("\n");
            for line in lines {
                data.push('\n');
                data.push_str(line);
            }
            if let Ok(value) = serde_json::from_str::<Value>(&data) {
                self.observe(&value);
                return;
            }
            // Some upstreams send one JSON object per data line without a blank separator.
            for line in data.lines() {
                self.observe_sse_data(line);
            }
        } else {
            self.observe_sse_data(first);
        }
    }

    fn observe_sse_data(&mut self, data: &str) {
        if data.is_empty() || data == "[DONE]" {
            return;
        }
        match serde_json::from_str::<Value>(data) {
            Ok(value) => self.observe(&value),
            Err(error) => {
                debug!(request_id = %self.request_id, source = %self.source, error = %error, "Skipping non-JSON SSE telemetry event");
            }
        }
    }

    fn observe(&mut self, value: &Value) {
        if let Value::Array(items) = value {
            for item in items {
                self.observe(item);
            }
            return;
        }

        if let Some(response) = gemini_response(value) {
            self.gemini_usage.observe(value, response);
            for (position, candidate) in array_items(response, "candidates").enumerate() {
                let index = candidate
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(position as u64);
                let Some(content) = candidate.get("content") else {
                    continue;
                };
                for part in array_items(content, "parts") {
                    if let Some(tool) = part.get("functionCall").and_then(Value::as_object) {
                        self.observe_gemini_call(index, tool);
                    }
                    if let Some(tool) = part.get("functionResponse").and_then(Value::as_object) {
                        let event =
                            gemini_tool_event(tool, "tool_result", &self.request_id, &self.source);
                        self.push_gemini_tool(event);
                    }
                }
            }
            return;
        }

        collect_usage_records(
            value,
            &self.request_id,
            self.model.as_deref(),
            &self.upstream,
            &self.source,
            &mut self.usage,
        );
        collect_tool_events(value, &self.request_id, &self.source, &mut self.tools);
    }

    fn observe_gemini_call(&mut self, index: u64, tool: &serde_json::Map<String, Value>) {
        let event = gemini_tool_event(tool, "tool_call", &self.request_id, &self.source);
        let continues = tool.get("willContinue").and_then(Value::as_bool) == Some(true);
        if let Entry::Occupied(mut entry) = self.gemini_pending_calls.entry(index) {
            let pending = entry.get_mut();
            let same_call = match (&event.call_id, &pending.call_id) {
                (Some(current), Some(previous)) => current == previous,
                _ => event.tool_name.is_none(),
            };
            if same_call {
                pending.call_id = pending.call_id.take().or(event.call_id);
                pending.tool_name = pending.tool_name.take().or(event.tool_name);
                pending.status = event.status.or_else(|| pending.status.take());
                if !continues {
                    let completed = entry.remove();
                    self.push_gemini_tool(completed);
                }
                return;
            }
        }

        if event.tool_name.is_none() {
            return;
        }
        if continues {
            self.gemini_pending_calls.insert(index, event);
        } else {
            self.push_gemini_tool(event);
        }
    }

    fn push_gemini_tool(&mut self, event: ToolEventRecord) {
        if let Some(id) = event.call_id.as_deref().filter(|id| !id.is_empty())
            && !self
                .gemini_tool_ids
                .insert((event.event_kind.clone(), id.to_owned()))
        {
            return;
        }
        self.tools.push(event);
    }

    fn finish(mut self) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
        let GeminiUsage {
            model,
            input_tokens,
            output_tokens,
            total_tokens,
        } = self.gemini_usage;
        if input_tokens.is_some() || output_tokens.is_some() || total_tokens.is_some() {
            let total_tokens = total_tokens.unwrap_or_else(|| {
                input_tokens
                    .unwrap_or(0)
                    .saturating_add(output_tokens.unwrap_or(0))
            });
            self.usage.push(TokenUsageRecord {
                request_id: self.request_id,
                observed_at_ms: now_ms(),
                model: model.or(self.model),
                upstream: self.upstream,
                source: self.source,
                input_tokens,
                output_tokens,
                total_tokens: Some(total_tokens),
            });
        }
        (self.usage, self.tools)
    }
}

#[derive(Debug, Default)]
struct GeminiUsage {
    model: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    total_tokens: Option<i64>,
}

impl GeminiUsage {
    fn observe(&mut self, envelope: &Value, response: &Value) {
        self.model = gemini_model(response)
            .or_else(|| self.model.take())
            .or_else(|| gemini_model(envelope));

        let Some(metadata) = response.get("usageMetadata").and_then(Value::as_object) else {
            return;
        };
        let input_tokens = first_i64(metadata, &["promptTokenCount"]).or(self.input_tokens);
        let output_tokens = first_i64(metadata, &["candidatesTokenCount", "outputTokenCount"])
            .or(self.output_tokens);
        let total_tokens = first_i64(metadata, &["totalTokenCount"]);
        // A total from an earlier snapshot can be stale when counters change.
        if total_tokens.is_some()
            || input_tokens != self.input_tokens
            || output_tokens != self.output_tokens
        {
            self.total_tokens = total_tokens;
        }
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
    }
}

fn gemini_response(value: &Value) -> Option<&Value> {
    value
        .get("response")
        .into_iter()
        .chain(std::iter::once(value))
        .find(|response| {
            response.get("usageMetadata").is_some_and(Value::is_object)
                || response.get("candidates").is_some_and(Value::is_array)
        })
}

fn gemini_request(value: &Value) -> Option<&Value> {
    value
        .get("request")
        .into_iter()
        .chain(std::iter::once(value))
        .find(|request| {
            request.get("contents").is_some_and(Value::is_array)
                || array_items(request, "tools").any(|tool| {
                    tool.get("functionDeclarations")
                        .is_some_and(Value::is_array)
                })
        })
}

fn gemini_model(value: &Value) -> Option<String> {
    first_string(
        value.as_object()?,
        &["modelVersion", "model_version", "model_name", "model"],
    )
}

fn array_items<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn collect_gemini_request_events(
    request: &Value,
    request_id: &str,
    source: &str,
    events: &mut Vec<ToolEventRecord>,
) {
    for tool in array_items(request, "tools") {
        for declaration in array_items(tool, "functionDeclarations") {
            if let Some(name) = declaration.get("name").and_then(Value::as_str) {
                events.push(ToolEventRecord {
                    request_id: request_id.to_string(),
                    observed_at_ms: now_ms(),
                    event_kind: "tool_definition".to_string(),
                    tool_name: Some(name.to_string()),
                    call_id: None,
                    status: None,
                    source: source.to_string(),
                });
            }
        }
    }
    let Some(contents) = request.get("contents").and_then(Value::as_array) else {
        return;
    };
    // Continuation requests append the current results after the model's last turn.
    let result_start = contents
        .iter()
        .rposition(|content| gemini_function_responses(content).next().is_none())
        .map_or(0, |index| index + 1);
    for tool in contents[result_start..]
        .iter()
        .flat_map(gemini_function_responses)
    {
        events.push(gemini_tool_event(tool, "tool_result", request_id, source));
    }
}

fn gemini_function_responses(
    content: &Value,
) -> impl Iterator<Item = &serde_json::Map<String, Value>> {
    array_items(content, "parts").filter_map(|part| part.get("functionResponse")?.as_object())
}

fn gemini_tool_event(
    tool: &serde_json::Map<String, Value>,
    event_kind: &str,
    request_id: &str,
    source: &str,
) -> ToolEventRecord {
    ToolEventRecord {
        request_id: request_id.to_owned(),
        observed_at_ms: now_ms(),
        event_kind: event_kind.to_owned(),
        tool_name: first_string(tool, &["name", "tool_name"]),
        call_id: first_string(tool, &["id", "call_id", "tool_call_id"]).filter(|id| !id.is_empty()),
        status: first_string(tool, &["status"]),
        source: source.to_owned(),
    }
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

#[derive(Debug, Default)]
struct SseTelemetryBuffer {
    event: Vec<u8>,
    line_has_content: bool,
    oversized: bool,
}

impl SseTelemetryBuffer {
    fn observe_chunk(&mut self, chunk: &[u8], telemetry: &mut ParsedResponseTelemetry) {
        for part in chunk.split_inclusive(|byte| *byte == b'\n') {
            self.line_has_content |= !part.trim_ascii().is_empty();
            let ends_line = part.ends_with(b"\n");
            if ends_line && !self.line_has_content {
                self.flush(telemetry);
                continue;
            }
            if !self.oversized {
                if part.len() > MAX_RESPONSE_TELEMETRY_BUFFER_BYTES - self.event.len() {
                    self.event.clear();
                    self.oversized = true;
                    warn!(request_id = %telemetry.request_id, "Skipping oversized SSE telemetry event");
                } else {
                    self.event.extend_from_slice(part);
                }
            }
            if ends_line {
                self.line_has_content = false;
            }
        }
    }

    fn flush(&mut self, telemetry: &mut ParsedResponseTelemetry) {
        if !self.oversized && !self.event.is_empty() {
            telemetry.observe_sse_event(&self.event);
        }
        self.event.clear();
        self.line_has_content = false;
        self.oversized = false;
    }
}

#[derive(Debug)]
enum ResponseTelemetryBody {
    Pending,
    Json { bytes: Vec<u8>, cap_hit: bool },
    Sse(SseTelemetryBuffer),
}

#[derive(Debug)]
pub struct ResponseTelemetryCollector {
    telemetry: ParsedResponseTelemetry,
    body: ResponseTelemetryBody,
}

impl ResponseTelemetryCollector {
    pub fn new(
        request_id: String,
        model: Option<String>,
        upstream: String,
        source: String,
    ) -> Self {
        Self {
            telemetry: ParsedResponseTelemetry::new(request_id, model, upstream, source),
            body: ResponseTelemetryBody::Pending,
        }
    }

    pub fn observe_chunk(&mut self, mut chunk: &[u8]) {
        if matches!(self.body, ResponseTelemetryBody::Pending) {
            chunk = chunk.trim_ascii_start();
            self.body = match chunk.first() {
                None => return,
                Some(b'{' | b'[') => ResponseTelemetryBody::Json {
                    bytes: Vec::new(),
                    cap_hit: false,
                },
                Some(_) => ResponseTelemetryBody::Sse(SseTelemetryBuffer::default()),
            };
        }

        match &mut self.body {
            ResponseTelemetryBody::Pending => {}
            ResponseTelemetryBody::Json { bytes, cap_hit } => {
                if *cap_hit {
                    return;
                }
                let remaining = MAX_RESPONSE_TELEMETRY_BUFFER_BYTES - bytes.len();
                bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if chunk.len() > remaining {
                    *cap_hit = true;
                    warn!(
                        request_id = %self.telemetry.request_id,
                        cap_bytes = MAX_RESPONSE_TELEMETRY_BUFFER_BYTES,
                        "Response telemetry parse buffer cap reached"
                    );
                }
            }
            ResponseTelemetryBody::Sse(buffer) => buffer.observe_chunk(chunk, &mut self.telemetry),
        }
    }

    pub fn finalize(mut self) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
        match self.body {
            ResponseTelemetryBody::Pending => {}
            ResponseTelemetryBody::Json { bytes, .. } => {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    self.telemetry.observe(&value);
                }
            }
            ResponseTelemetryBody::Sse(mut buffer) => buffer.flush(&mut self.telemetry),
        }
        self.telemetry.finish()
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

    const GEMINI_UPSTREAM: &str =
        "https://generativelanguage.googleapis.com/v1beta/models/gemini:streamGenerateContent";
    const ANTIGRAVITY_UPSTREAM: &str =
        "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent";

    #[test]
    fn extracts_gemini_model_and_tools_from_antigravity_request() {
        let request = br#"{
            "model_name": "gemini-alias",
            "request": {
                "tools": [{"functionDeclarations": [{"name": "read_file"}]}],
                "contents": [{"parts": [
                    {"functionResponse": {
                        "id": "call_1",
                        "name": "read_file",
                        "response": {"type": "tool_use", "name": "nested_value"}
                    }}
                ]}]
            }
        }"#;

        assert_eq!(
            extract_model_from_json(request).as_deref(),
            Some("gemini-alias")
        );
        let tools = extract_tool_events_from_json("req-test", request, "request");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].event_kind, "tool_definition");
        assert_eq!(tools[0].tool_name.as_deref(), Some("read_file"));
        assert_eq!(tools[1].event_kind, "tool_result");
        assert_eq!(tools[1].call_id.as_deref(), Some("call_1"));
    }

    #[test]
    fn reports_only_the_current_gemini_tool_results() {
        let mut request = serde_json::json!({"contents": [
            {"role": "model", "parts": [{"functionCall": {"name": "lookup", "id": "old"}}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "lookup", "id": "old"}}]},
            {"role": "model", "parts": [{"text": "Old answer"}]},
            {"role": "user", "parts": [{"text": "New question"}]}
        ]});

        let tools =
            extract_tool_events_from_json("req-test", request.to_string().as_bytes(), "request");
        assert!(tools.is_empty());

        request["contents"].as_array_mut().unwrap().extend([
            serde_json::json!({"role": "model", "parts": [
                {"functionCall": {"name": "lookup", "id": "new-1"}},
                {"functionCall": {"name": "lookup", "id": "new-2"}}
            ]}),
            serde_json::json!({"role": "user", "parts": [
                {"functionResponse": {"name": "lookup", "id": "new-1"}},
                {"functionResponse": {"name": "lookup", "id": "new-2"}}
            ]}),
        ]);
        let tools =
            extract_tool_events_from_json("req-test", request.to_string().as_bytes(), "request");
        let events: Vec<_> = tools
            .iter()
            .map(|tool| (tool.event_kind.as_str(), tool.call_id.as_deref()))
            .collect();
        assert_eq!(
            events,
            [
                ("tool_result", Some("new-1")),
                ("tool_result", Some("new-2"))
            ]
        );
    }

    #[test]
    fn merges_gemini_usage_in_json_arrays_and_sse() {
        let chunks = [
            r#"{"response":{"modelVersion":"gemini-version","usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":5,"totalTokenCount":105}}}"#,
            r#"{"response":{"usageMetadata":{"outputTokenCount":20,"thoughtsTokenCount":7,"totalTokenCount":127}}}"#,
            r#"{"model":"gemini-alias","response":{"candidates":[{"content":{"parts":[{"text":"Done"}]}}]}}"#,
        ];
        let json_array = format!("[{}]", chunks.join(","));
        let sse = format!("data: {}\n\n", chunks.join("\n\ndata: "));
        for body in [json_array, sse] {
            let (usage, tools) = extract_response_telemetry(
                "req-test",
                Some("gemini-alias"),
                ANTIGRAVITY_UPSTREAM,
                "response",
                body.as_bytes(),
            );
            assert!(tools.is_empty());
            assert_eq!(usage.len(), 1);
            assert_eq!(usage[0].model.as_deref(), Some("gemini-version"));
            assert_eq!(usage[0].input_tokens, Some(100));
            assert_eq!(usage[0].output_tokens, Some(20));
            assert_eq!(usage[0].total_tokens, Some(127));
        }
    }

    #[test]
    fn derives_gemini_total_when_later_usage_omits_it() {
        let body = br#"[
            {"usageMetadata":{"promptTokenCount":100,"outputTokenCount":5,"totalTokenCount":105}},
            {"usageMetadata":{"outputTokenCount":20}}
        ]"#;
        let (usage, _) =
            extract_response_telemetry("req-test", None, GEMINI_UPSTREAM, "response", body);
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].input_tokens, Some(100));
        assert_eq!(usage[0].output_tokens, Some(20));
        assert_eq!(usage[0].total_tokens, Some(120));
    }

    #[test]
    fn reads_gemini_counters_only_from_response_metadata() {
        let body = br#"{
            "modelVersion":"gemini-version",
            "usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20,"totalTokenCount":120},
            "candidates":[{"content":{"parts":[{"functionCall":{
                "name":"process_report",
                "args":{
                    "usageMetadata":{"promptTokenCount":200,"totalTokenCount":210},
                    "promptTokenCount":200,
                    "totalTokenCount":210,
                    "type":"tool_result",
                    "name":"nested_value"
                }
            }}]}}]
        }"#;
        let (usage, tools) =
            extract_response_telemetry("req-test", None, GEMINI_UPSTREAM, "response", body);

        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].model.as_deref(), Some("gemini-version"));
        assert_eq!(usage[0].input_tokens, Some(100));
        assert_eq!(usage[0].output_tokens, Some(20));
        assert_eq!(usage[0].total_tokens, Some(120));
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].event_kind, "tool_call");
        assert_eq!(tools[0].tool_name.as_deref(), Some("process_report"));
    }

    #[test]
    fn deduplicates_gemini_sse_tools_only_with_stable_ids() {
        let body = concat!(
            r#"data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"read_file","args":{"path":"first"}}},{"functionCall":{"name":"read_file","args":{"path":"second"}}},{"functionCall":{"id":"call_1","name":"read_file"}}]}}]}"#,
            "\n\n",
            r#"data: {"candidates":[{"content":{"parts":[{"functionCall":{"id":"call_1","name":"read_file"}},{"functionResponse":{"id":"call_1","name":"read_file"}}]}}]}"#,
            "\n\n",
        );
        let (usage, tools) = extract_response_telemetry(
            "req-test",
            None,
            GEMINI_UPSTREAM,
            "response",
            body.as_bytes(),
        );

        assert!(usage.is_empty());
        let events: Vec<_> = tools
            .iter()
            .map(|tool| (tool.event_kind.as_str(), tool.call_id.as_deref()))
            .collect();
        assert_eq!(
            events,
            [
                ("tool_call", None),
                ("tool_call", None),
                ("tool_call", Some("call_1")),
                ("tool_result", Some("call_1")),
            ]
        );
    }

    #[test]
    fn reports_one_completed_call_per_candidate_when_arguments_stream() {
        let body = concat!(
            r#"data: {"candidates":[{"index":0,"content":{"parts":[{"functionCall":{"name":"lookup","willContinue":true}}]}},{"index":1,"content":{"parts":[{"functionCall":{"name":"format","willContinue":true}}]}}]}"#,
            "\n\n",
            r#"data: {"candidates":[{"index":1,"content":{"parts":[{"functionCall":{"partialArgs":[{"jsonPath":"$.text","stringValue":"part"}],"willContinue":true}}]}}]}"#,
            "\n\n",
            r#"data: {"candidates":[{"index":1,"content":{"parts":[{"functionCall":{"id":"format-1"}}]}}]}"#,
            "\n\n",
            r#"data: {"candidates":[{"index":0,"content":{"parts":[{"functionCall":{}},{"functionCall":{"name":"lookup","args":{}}}]}}]}"#,
            "\n\n",
        );
        let (_, tools) = extract_response_telemetry(
            "req-test",
            None,
            GEMINI_UPSTREAM,
            "response",
            body.as_bytes(),
        );

        let calls: Vec<_> = tools
            .iter()
            .map(|tool| (tool.tool_name.as_deref(), tool.call_id.as_deref()))
            .collect();
        assert_eq!(
            calls,
            [
                (Some("format"), Some("format-1")),
                (Some("lookup"), None),
                (Some("lookup"), None),
            ]
        );
    }

    #[test]
    fn keeps_sse_frames_after_an_oversized_event_split_across_chunks() {
        let mut collector = ResponseTelemetryCollector::new(
            "req-test".to_owned(),
            None,
            GEMINI_UPSTREAM.to_owned(),
            "response".to_owned(),
        );
        collector.observe_chunk(b"data: ");
        collector.observe_chunk(&vec![b'x'; MAX_RESPONSE_TELEMETRY_BUFFER_BYTES]);
        collector.observe_chunk(b"\r\n\r");
        collector
            .observe_chunk(b"\ndata: {\"usageMetadata\":{\r\ndata: \"totalTokenCount\":42}}\r\n\r");
        collector.observe_chunk(b"\n");

        let (usage, _) = collector.finalize();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].total_tokens, Some(42));
    }

    #[test]
    fn retains_anthropic_sse_usage_records() {
        let body = concat!(
            r#"data: {"type":"message_start","message":{"model":"claude-test","usage":{"input_tokens":40,"output_tokens":1}}}"#,
            "\n\n",
            r#"data: {"type":"message_delta","usage":{"output_tokens":12}}"#,
            "\n\n",
        );
        let (usage, _) = extract_response_telemetry(
            "req-test",
            None,
            "https://api.anthropic.com/v1/messages",
            "response",
            body.as_bytes(),
        );
        assert_eq!(usage.len(), 2);
        assert_eq!(usage[0].model.as_deref(), Some("claude-test"));
        assert_eq!(usage[0].total_tokens, Some(41));
        assert_eq!(usage[1].total_tokens, Some(12));
    }

    #[test]
    fn retains_codex_sse_tool_events() {
        let body = concat!(
            r#"data: {"type":"response.output_item.added","item":{"type":"function_call","name":"shell","call_id":"call_1"}}"#,
            "\n\n",
            r#"data: {"type":"response.output_item.done","item":{"type":"function_call","name":"shell","call_id":"call_1"}}"#,
            "\n\n",
        );
        let (_, tools) = extract_response_telemetry(
            "req-test",
            None,
            "https://api.openai.com/v1/responses",
            "response",
            body.as_bytes(),
        );
        assert_eq!(tools.len(), 2);
        assert!(
            tools
                .iter()
                .all(|tool| tool.call_id.as_deref() == Some("call_1"))
        );
    }
}
