use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

pub const DEFAULT_QUERY_WINDOW_HOURS: u64 = 24;
pub const MAX_RESPONSE_TELEMETRY_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_TELEMETRY_RECORD_BYTES: usize = 1024 * 1024;
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
        collect_tool_events(&value, request_id, source, &mut |event| events.push(event));
    }
    events
}

/// Keep connection metadata separate from query parameters and credentials.
pub(crate) fn telemetry_url(url: &str) -> String {
    let Ok(mut url) = url::Url::parse(url) else {
        return String::new();
    };
    url.set_query(None);
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.into()
}

pub(crate) fn extract_gemini_model_from_url(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    let mut segments = url.path_segments()?.rev();
    let (model, method) = segments.next()?.rsplit_once(':')?;
    match (segments.next()?, method) {
        ("models" | "tunedModels" | "dynamic", "generateContent" | "streamGenerateContent")
            if !model.is_empty() =>
        {
            Some(model.to_owned())
        }
        _ => None,
    }
}

type GeminiCallKey = (u64, Option<String>);

#[derive(Debug)]
struct ParsedResponseTelemetry {
    request_id: String,
    model: Option<String>,
    upstream: String,
    source: String,
    usage: Vec<TokenUsageRecord>,
    tools: Vec<ToolEventRecord>,
    record_budget: ResponseRecordBudget,
    gemini_usage: GeminiUsage,
    gemini_tool_ids: HashSet<(String, String)>,
    gemini_pending_calls: BTreeMap<GeminiCallKey, ToolEventRecord>,
}

impl ParsedResponseTelemetry {
    fn new(request_id: String, model: Option<String>, upstream: String, source: String) -> Self {
        Self {
            request_id,
            model,
            upstream: telemetry_url(&upstream),
            source,
            usage: Vec::new(),
            tools: Vec::new(),
            record_budget: ResponseRecordBudget::default(),
            gemini_usage: GeminiUsage::default(),
            gemini_tool_ids: HashSet::new(),
            gemini_pending_calls: BTreeMap::new(),
        }
    }

    fn observe_json(&mut self, bytes: &[u8]) -> bool {
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
            return false;
        };
        self.observe(&value);
        true
    }

    fn observe(&mut self, value: &Value) {
        if let Value::Array(items) = value {
            for item in items {
                self.observe(item);
            }
            return;
        }

        let gemini = gemini_response(value);
        self.gemini_usage.observe_model(value, gemini.is_some());
        if let Some(response) = gemini {
            self.gemini_usage.observe_usage(response);
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
            &mut |record| {
                if self
                    .record_budget
                    .reserve(record.retained_bytes(), &self.request_id)
                {
                    self.usage.push(record);
                }
            },
        );
        collect_tool_events(value, &self.request_id, &self.source, &mut |event| {
            if self
                .record_budget
                .reserve(event.retained_bytes(), &self.request_id)
            {
                self.tools.push(event);
            }
        });
    }

    fn observe_gemini_call(&mut self, index: u64, tool: &serde_json::Map<String, Value>) {
        let mut event = gemini_tool_event(tool, "tool_call", &self.request_id, &self.source);
        let continues = tool.get("willContinue").and_then(Value::as_bool) == Some(true);
        let mut key = (index, event.call_id.take());
        let pending = match (key.1.is_some(), event.tool_name.is_none()) {
            (true, true) => self
                .remove_pending_call(&key)
                .or_else(|| self.remove_pending_call(&(index, None))),
            (true, false) => self.remove_pending_call(&key),
            (false, true) => {
                // An unnamed fragment without an ID can only be matched unambiguously
                // when there is a single pending call for this candidate.
                let mut keys = self
                    .gemini_pending_calls
                    .range((index, None)..)
                    .map(|(key, _)| key)
                    .take_while(|(candidate, _)| *candidate == index);
                match (keys.next(), keys.next()) {
                    (Some(only), None) => self.remove_pending_call(&only.clone()),
                    _ => None,
                }
            }
            (false, false) => {
                if continues {
                    self.remove_pending_call(&key);
                }
                None
            }
        };
        if let Some(((_, pending_id), pending)) = pending {
            key.1 = key.1.or(pending_id);
            event.tool_name = pending.tool_name.or(event.tool_name);
            event.status = event.status.or(pending.status);
            event.observed_at_ms = pending.observed_at_ms;
        }

        if event.tool_name.is_none() {
            return;
        }
        if continues {
            if self
                .record_budget
                .reserve(pending_call_bytes(&key, &event), &self.request_id)
            {
                self.gemini_pending_calls.insert(key, event);
            }
        } else {
            event.call_id = key.1;
            self.push_gemini_tool(event);
        }
    }

    fn remove_pending_call(
        &mut self,
        key: &GeminiCallKey,
    ) -> Option<(GeminiCallKey, ToolEventRecord)> {
        let (key, event) = self.gemini_pending_calls.remove_entry(key)?;
        self.record_budget.used -= pending_call_bytes(&key, &event);
        Some((key, event))
    }

    fn push_gemini_tool(&mut self, event: ToolEventRecord) {
        let key = event
            .call_id
            .as_ref()
            .map(|id| (event.event_kind.clone(), id.clone()));
        if key
            .as_ref()
            .is_some_and(|key| self.gemini_tool_ids.contains(key))
        {
            return;
        }
        let key_bytes = key.as_ref().map_or(0, |key| {
            size_of_val(key) + key.0.capacity() + key.1.capacity()
        });
        if self
            .record_budget
            .reserve(event.retained_bytes() + key_bytes, &self.request_id)
        {
            if let Some(key) = key {
                self.gemini_tool_ids.insert(key);
            }
            self.tools.push(event);
        }
    }

    fn finish(mut self) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
        if let Some(total_tokens) = self
            .gemini_usage
            .total_tokens
            .or_else(|| self.gemini_usage.sum())
        {
            self.usage.push(TokenUsageRecord {
                request_id: self.request_id,
                observed_at_ms: now_ms(),
                model: self.gemini_usage.model.or(self.model),
                upstream: self.upstream,
                source: self.source,
                input_tokens: self.gemini_usage.input_tokens,
                output_tokens: self.gemini_usage.output_tokens,
                total_tokens: Some(total_tokens),
            });
        }
        (self.usage, self.tools)
    }
}

#[derive(Debug, Default)]
struct ResponseRecordBudget {
    used: usize,
    warned: bool,
}

impl ResponseRecordBudget {
    fn reserve(&mut self, bytes: usize, request_id: &str) -> bool {
        if bytes <= MAX_RESPONSE_TELEMETRY_RECORD_BYTES - self.used {
            self.used += bytes;
            return true;
        }
        if !self.warned {
            self.warned = true;
            warn!(request_id, "Response telemetry record limit reached");
        }
        false
    }
}

impl TokenUsageRecord {
    fn retained_bytes(&self) -> usize {
        size_of_val(self)
            + self.request_id.capacity()
            + self.model.as_ref().map_or(0, String::capacity)
            + self.upstream.capacity()
            + self.source.capacity()
    }
}

impl ToolEventRecord {
    fn retained_bytes(&self) -> usize {
        size_of_val(self)
            + self.request_id.capacity()
            + self.event_kind.capacity()
            + self.tool_name.as_ref().map_or(0, String::capacity)
            + self.call_id.as_ref().map_or(0, String::capacity)
            + self.status.as_ref().map_or(0, String::capacity)
            + self.source.capacity()
    }
}

fn pending_call_bytes(key: &GeminiCallKey, event: &ToolEventRecord) -> usize {
    size_of_val(key) + key.1.as_ref().map_or(0, String::capacity) + event.retained_bytes()
}

#[derive(Debug, Default)]
struct GeminiUsage {
    model: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    thought_tokens: Option<i64>,
    tool_prompt_tokens: Option<i64>,
    total_tokens: Option<i64>,
}

impl GeminiUsage {
    fn observe_model(&mut self, envelope: &Value, is_gemini_response: bool) {
        let mut objects = envelope
            .get("response")
            .into_iter()
            .chain(std::iter::once(envelope))
            .filter_map(Value::as_object);
        if let Some(version) = objects
            .clone()
            .find_map(|object| first_string(object, &["modelVersion", "model_version"]))
        {
            self.model = Some(version);
        } else if self.model.is_none() {
            self.model = objects
                .clone()
                .find_map(|object| first_string(object, &["model_name"]))
                .or_else(|| {
                    is_gemini_response
                        .then(|| objects.find_map(|object| first_string(object, &["model"])))
                        .flatten()
                });
        }
    }

    fn observe_usage(&mut self, response: &Value) {
        let Some(metadata) = response.get("usageMetadata").and_then(Value::as_object) else {
            return;
        };
        let deltas = [
            update_gemini_counter(
                &mut self.input_tokens,
                first_i64(metadata, &["promptTokenCount"]),
            ),
            update_gemini_counter(
                &mut self.output_tokens,
                first_i64(metadata, &["candidatesTokenCount", "outputTokenCount"]),
            ),
            update_gemini_counter(
                &mut self.thought_tokens,
                first_i64(metadata, &["thoughtsTokenCount"]),
            ),
            update_gemini_counter(
                &mut self.tool_prompt_tokens,
                first_i64(metadata, &["toolUsePromptTokenCount"]),
            ),
        ];

        if let Some(total) = first_i64(metadata, &["totalTokenCount"]) {
            self.total_tokens = Some(total);
        } else if let Some(total) = self.total_tokens {
            // Carry forward tokens included in Gemini's total even if their counters were omitted.
            let updated = deltas.into_iter().fold(total, i64::saturating_add);
            self.total_tokens = Some(updated.max(self.sum().unwrap_or(0)));
        }
    }

    fn sum(&self) -> Option<i64> {
        [
            self.input_tokens,
            self.output_tokens,
            self.thought_tokens,
            self.tool_prompt_tokens,
        ]
        .into_iter()
        .flatten()
        .reduce(i64::saturating_add)
    }
}

fn update_gemini_counter(counter: &mut Option<i64>, observed: Option<i64>) -> i64 {
    observed
        .and_then(|current| {
            counter
                .replace(current)
                .map(|previous| current.saturating_sub(previous))
        })
        .unwrap_or(0)
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
        .rposition(|content| {
            content.get("role").and_then(Value::as_str) == Some("model")
                || array_items(content, "parts").any(|part| part.get("functionCall").is_some())
        })
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
    emit: &mut impl FnMut(TokenUsageRecord),
) {
    match value {
        Value::Object(object) => {
            let current_model = model.or_else(|| object.get("model").and_then(Value::as_str));
            if let Some(record) =
                usage_record_from_object(request_id, current_model, upstream, source, value)
            {
                emit(record);
            }

            for child in object.values() {
                collect_usage_records(child, request_id, current_model, upstream, source, emit);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_usage_records(item, request_id, model, upstream, source, emit);
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
    emit: &mut impl FnMut(ToolEventRecord),
) {
    match value {
        Value::Object(object) => {
            if let Some(Value::Array(tools)) = object.get("tools") {
                for tool in tools {
                    if let Some(tool_name) = tool_name_from_value(tool) {
                        emit(ToolEventRecord {
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
                emit(ToolEventRecord {
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
                collect_tool_events(child, request_id, source, emit);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_tool_events(item, request_id, source, emit);
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
struct TelemetryBuffer {
    bytes: Vec<u8>,
    oversized: bool,
}

impl TelemetryBuffer {
    fn extend(&mut self, bytes: &[u8], telemetry: &ParsedResponseTelemetry, unit: &str) {
        if self.oversized {
            return;
        }
        let remaining = MAX_RESPONSE_TELEMETRY_BUFFER_BYTES - self.bytes.len();
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        if bytes.len() > remaining {
            self.oversized = true;
            warn!(request_id = %telemetry.request_id, unit, "Response telemetry parse buffer cap reached");
        }
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.oversized = false;
    }
}

#[derive(Debug, Default)]
struct SseTelemetryBuffer {
    line: SseTelemetryLine,
    event: JsonTelemetryBuffer,
    multiline: bool,
}

#[derive(Debug, Default)]
enum SseTelemetryLine {
    #[default]
    Start,
    Prefix(&'static [u8]),
    Data,
    Other,
}

impl SseTelemetryBuffer {
    fn observe_chunk(&mut self, chunk: &[u8], telemetry: &mut ParsedResponseTelemetry) {
        for part in chunk.split_inclusive(|byte| *byte == b'\n') {
            if let Some(line_end) = part.strip_suffix(b"\n") {
                self.observe_line_chunk(line_end, telemetry);
                self.finish_line(telemetry);
            } else {
                self.observe_line_chunk(part, telemetry);
            }
        }
    }

    fn observe_line_chunk(&mut self, mut bytes: &[u8], telemetry: &ParsedResponseTelemetry) {
        while let Some((&byte, rest)) = bytes.split_first() {
            self.line = match self.line {
                SseTelemetryLine::Start if byte.is_ascii_whitespace() => SseTelemetryLine::Start,
                SseTelemetryLine::Start if byte == b'd' => SseTelemetryLine::Prefix(b"ata:"),
                SseTelemetryLine::Start if byte == 0xef => {
                    SseTelemetryLine::Prefix(b"\xbb\xbfdata:")
                }
                SseTelemetryLine::Prefix([expected, remaining @ ..]) if byte == *expected => {
                    if remaining.is_empty() {
                        SseTelemetryLine::Data
                    } else {
                        SseTelemetryLine::Prefix(remaining)
                    }
                }
                SseTelemetryLine::Data => {
                    // Compact JSON before applying the event cap, including when a
                    // payload field spans multiple network chunks or data lines.
                    self.event.extend(bytes, telemetry, "SSE event");
                    return;
                }
                _ => {
                    self.line = SseTelemetryLine::Other;
                    return;
                }
            };
            bytes = rest;
        }
    }

    fn finish_line(&mut self, telemetry: &mut ParsedResponseTelemetry) {
        match std::mem::take(&mut self.line) {
            SseTelemetryLine::Start => self.finish_event(telemetry),
            SseTelemetryLine::Data => {
                // A complete JSON data line can be parsed even without a blank separator.
                let standalone = !self.multiline
                    && (matches!(self.event.buffer.bytes.trim_ascii(), b"" | b"[DONE]")
                        || self.event.observe(telemetry));
                if standalone || self.event.buffer.oversized {
                    self.clear_event();
                } else {
                    self.event.extend(b"\n", telemetry, "SSE event");
                    self.multiline = true;
                }
            }
            SseTelemetryLine::Prefix(_) | SseTelemetryLine::Other => {}
        }
    }

    fn finish_event(&mut self, telemetry: &mut ParsedResponseTelemetry) {
        let buffer = &self.event.buffer;
        if !buffer.oversized && !buffer.bytes.is_empty() && !self.event.observe(telemetry) {
            for line in buffer.bytes.split(|byte| *byte == b'\n') {
                if !line.trim_ascii().is_empty() && !telemetry.observe_json(line) {
                    debug!(request_id = %telemetry.request_id, source = %telemetry.source, "Skipping non-JSON SSE telemetry data");
                }
            }
        }
        self.clear_event();
    }

    fn clear_event(&mut self) {
        self.event.clear();
        self.multiline = false;
    }

    fn flush(&mut self, telemetry: &mut ParsedResponseTelemetry) {
        self.finish_line(telemetry);
        self.finish_event(telemetry);
    }
}

#[derive(Debug, Default)]
struct JsonTelemetryBuffer {
    buffer: TelemetryBuffer,
    string_start: Option<usize>,
    escaped: bool,
    skip_string: bool,
    payload_key: bool,
    payload_value: bool,
}

impl JsonTelemetryBuffer {
    fn extend(&mut self, bytes: &[u8], telemetry: &ParsedResponseTelemetry, unit: &str) {
        for &byte in bytes {
            if self.buffer.oversized {
                break;
            }
            if let Some(start) = self.string_start {
                if byte == b'"' && !self.escaped {
                    self.payload_key =
                        !self.skip_string && is_json_payload_key(&self.buffer.bytes[start..]);
                    self.string_start = None;
                    self.skip_string = false;
                } else {
                    self.escaped = byte == b'\\' && !self.escaped;
                }
                if !self.skip_string {
                    self.buffer
                        .extend(std::slice::from_ref(&byte), telemetry, unit);
                }
                continue;
            }

            let offset = self.buffer.bytes.len();
            self.buffer
                .extend(std::slice::from_ref(&byte), telemetry, unit);
            match byte {
                b'"' => {
                    self.string_start = Some(offset);
                    self.skip_string = std::mem::take(&mut self.payload_value);
                    self.payload_key = false;
                }
                b':' => self.payload_value = std::mem::take(&mut self.payload_key),
                b' ' | b'\r' | b'\n' | b'\t' => {}
                _ => {
                    self.payload_key = false;
                    self.payload_value = false;
                }
            }
        }
    }

    fn observe(&self, telemetry: &mut ParsedResponseTelemetry) -> bool {
        !self.buffer.oversized && telemetry.observe_json(&self.buffer.bytes)
    }

    fn clear(&mut self) {
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.clear();
        *self = Self {
            buffer,
            ..Self::default()
        };
    }
}

fn is_json_payload_key(open_string: &[u8]) -> bool {
    // Text, inline media, and thought signatures do not contribute telemetry.
    // Keep their quotes so the surrounding JSON shape is preserved across chunks.
    const PAYLOAD_KEYS: &[&[u8]] = &[b"text", b"data", b"thoughtSignature", b"thought_signature"];
    let key = &open_string[1..];
    if key.len() <= 6 * b"thought_signature".len() && key.contains(&b'\\') {
        let mut quoted = open_string.to_vec();
        quoted.push(b'"');
        return serde_json::from_slice::<String>(&quoted)
            .is_ok_and(|key| PAYLOAD_KEYS.contains(&key.as_bytes()));
    }
    PAYLOAD_KEYS.contains(&key)
}

#[derive(Debug, Default)]
struct JsonArrayTelemetryBuffer {
    item: JsonTelemetryBuffer,
    depth: usize,
    in_string: bool,
    escaped: bool,
    closed: bool,
}

impl JsonArrayTelemetryBuffer {
    fn observe_chunk(&mut self, chunk: &[u8], telemetry: &mut ParsedResponseTelemetry) {
        if self.closed {
            return;
        }
        let mut item_start = 0;
        for (index, &byte) in chunk.iter().enumerate() {
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.in_string = false;
                }
                continue;
            }
            match byte {
                b',' | b']' if self.depth == 0 => {
                    self.item
                        .extend(&chunk[item_start..index], telemetry, "JSON array item");
                    self.item.observe(telemetry);
                    self.item.clear();
                    if byte == b']' {
                        self.closed = true;
                        return;
                    }
                    item_start = index + 1;
                }
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
        // Follow delimiters even while discarding an oversized item so later metadata can be read.
        self.item
            .extend(&chunk[item_start..], telemetry, "JSON array item");
    }
}

#[derive(Debug)]
enum ResponseTelemetryBody {
    Pending,
    Json(JsonTelemetryBuffer),
    JsonArray(JsonArrayTelemetryBuffer),
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
                Some(b'{') => ResponseTelemetryBody::Json(JsonTelemetryBuffer::default()),
                Some(b'[') => {
                    chunk = &chunk[1..];
                    ResponseTelemetryBody::JsonArray(JsonArrayTelemetryBuffer::default())
                }
                Some(_) => ResponseTelemetryBody::Sse(SseTelemetryBuffer::default()),
            };
        }

        match &mut self.body {
            ResponseTelemetryBody::Pending => {}
            ResponseTelemetryBody::Json(buffer) => {
                buffer.extend(chunk, &self.telemetry, "JSON body")
            }
            ResponseTelemetryBody::JsonArray(buffer) => {
                buffer.observe_chunk(chunk, &mut self.telemetry)
            }
            ResponseTelemetryBody::Sse(buffer) => buffer.observe_chunk(chunk, &mut self.telemetry),
        }
    }

    pub fn finalize(mut self) -> (Vec<TokenUsageRecord>, Vec<ToolEventRecord>) {
        match self.body {
            ResponseTelemetryBody::Pending | ResponseTelemetryBody::JsonArray(_) => {}
            ResponseTelemetryBody::Json(buffer) => {
                buffer.observe(&mut self.telemetry);
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
            serde_json::json!({"role": "user", "parts": [{"text": "Summarize the results"}]}),
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
    fn keeps_gemini_thought_and_tool_prompt_tokens_in_partial_stream_totals() {
        for initial in [
            r#"{"promptTokenCount":100,"candidatesTokenCount":5,"thoughtsTokenCount":50,"toolUsePromptTokenCount":10,"totalTokenCount":165}"#,
            r#"{"promptTokenCount":100,"candidatesTokenCount":5,"totalTokenCount":165}"#,
        ] {
            let body = format!(
                "data: {{\"usageMetadata\":{initial}}}\n\ndata: {{\"usageMetadata\":{{\"candidatesTokenCount\":20}}}}\n\n"
            );
            let (usage, _) = extract_response_telemetry(
                "req-test",
                None,
                GEMINI_UPSTREAM,
                "response",
                body.as_bytes(),
            );
            assert_eq!(usage.len(), 1);
            assert_eq!(usage[0].input_tokens, Some(100));
            assert_eq!(usage[0].output_tokens, Some(20));
            assert_eq!(usage[0].total_tokens, Some(180));
        }
    }

    #[test]
    fn derives_gemini_total_from_all_reported_counters() {
        let body = br#"{"usageMetadata":{"promptTokenCount":100,"outputTokenCount":20,"thoughtsTokenCount":50,"toolUsePromptTokenCount":10}}"#;
        let (usage, _) =
            extract_response_telemetry("req-test", None, GEMINI_UPSTREAM, "response", body);
        assert_eq!(usage[0].total_tokens, Some(180));
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
    fn completes_parallel_gemini_calls_by_id_within_one_candidate() {
        let body = concat!(
            r#"data: {"candidates":[{"index":0,"content":{"parts":[{"functionCall":{"name":"lookup","id":"a","willContinue":true}},{"functionCall":{"name":"format","id":"b","willContinue":true}}]}}]}"#,
            "\n\n",
            r#"data: {"candidates":[{"index":0,"content":{"parts":[{"functionCall":{"id":"a","partialArgs":[{"jsonPath":"$.query","stringValue":"part"}],"willContinue":true}},{"functionCall":{"id":"b"}}]}}]}"#,
            "\n\n",
            r#"data: {"candidates":[{"index":0,"content":{"parts":[{"functionCall":{"id":"a"}}]}}]}"#,
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
            [(Some("format"), Some("b")), (Some("lookup"), Some("a"))]
        );
    }

    fn response_collector(upstream: &str) -> ResponseTelemetryCollector {
        ResponseTelemetryCollector::new(
            "req-test".to_owned(),
            None,
            upstream.to_owned(),
            "response".to_owned(),
        )
    }

    #[test]
    fn keeps_gemini_usage_and_tools_beside_large_inline_media() {
        let response = serde_json::json!({
            "candidates": [{
                "content": {"parts": [
                    {"inlineData": {"mimeType": "image/png", "data": "A".repeat(MAX_RESPONSE_TELEMETRY_BUFFER_BYTES)}},
                    {"text": r#"escaped quotes " and delimiters [,]}"#},
                    {"functionCall": {"id": "call-1", "name": "lookup"}}
                ]}
            }],
            "modelVersion": "gemini-image",
            "usageMetadata": {"totalTokenCount": 1024}
        });
        let json = response.to_string();
        let multiline = json.replacen("\"data\":", "\"data\"\r\ndata: :", 1);
        for body in [
            json,
            format!("[{response}]"),
            format!("data: {response}\n\n"),
            format!("\u{feff}data: {multiline}\r\n\r\n"),
        ] {
            let mut collector = response_collector(GEMINI_UPSTREAM);
            for chunk in body.as_bytes().chunks(17) {
                collector.observe_chunk(chunk);
            }

            let (usage, tools) = collector.finalize();
            assert_eq!(usage.len(), 1);
            assert_eq!(usage[0].model.as_deref(), Some("gemini-image"));
            assert_eq!(usage[0].total_tokens, Some(1024));
            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0].tool_name.as_deref(), Some("lookup"));
            assert_eq!(tools[0].call_id.as_deref(), Some("call-1"));
        }
    }

    #[test]
    fn keeps_gemini_usage_and_tools_from_long_json_arrays() {
        let mut collector = response_collector(GEMINI_UPSTREAM);
        collector.observe_chunk(b" \r\n [");
        collector.observe_chunk(
            br#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"lookup"}}]}}]},"#,
        );

        let text = r#"quotes \" and delimiters [,]}"#.repeat(40);
        let item = format!(
            "{},",
            serde_json::json!({"candidates": [{"content": {"parts": [{"text": text}]}}]})
        );
        for _ in 0..(MAX_RESPONSE_TELEMETRY_BUFFER_BYTES / item.len() + 1) {
            for part in item.as_bytes().chunks(17) {
                collector.observe_chunk(part);
            }
        }

        collector.observe_chunk(br#"{"padding":""#);
        collector.observe_chunk(&vec![b'x'; MAX_RESPONSE_TELEMETRY_BUFFER_BYTES]);
        collector.observe_chunk(br#""}, {"modelVersion":"gemini-test","usageMetadata":{"#);
        collector.observe_chunk(br#""totalTokenCount":42}}]"#);

        let (usage, tools) = collector.finalize();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].total_tokens, Some(42));
        assert_eq!(usage[0].model.as_deref(), Some("gemini-test"));
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].tool_name.as_deref(), Some("lookup"));
    }

    #[test]
    fn keeps_individual_sse_data_lines_without_blank_separators() {
        let mut collector = response_collector("https://api.openai.com/v1/responses");
        collector.observe_chunk(b"data: {\"usage\":{\"total_tokens\":10}}\n");
        let text = "x".repeat(1024);
        let line = format!("data: {{\"text\":\"{text}\"}}\n");
        for _ in 0..(MAX_RESPONSE_TELEMETRY_BUFFER_BYTES / line.len() + 1) {
            collector.observe_chunk(line.as_bytes());
        }
        collector.observe_chunk(b"data: {\"usage\":{\"total_tokens\":42}}");

        let (usage, _) = collector.finalize();
        let totals: Vec<_> = usage.iter().map(|row| row.total_tokens).collect();
        assert_eq!(totals, [Some(10), Some(42)]);
    }

    #[test]
    fn bounds_streamed_records_without_losing_final_gemini_usage() {
        let mut collector = response_collector(GEMINI_UPSTREAM);
        let metadata = "x".repeat(8 * 1024);
        for index in 0..256 {
            let event = serde_json::json!({"candidates": [
                {"index": index, "content": {"parts": [{"functionCall": {
                    "name": "pending",
                    "id": format!("pending-{index}-{metadata}"),
                    "willContinue": true
                }}]}},
                {"content": {"parts": [{"functionCall": {
                    "name": "completed",
                    "id": format!("completed-{index}-{metadata}")
                }}]}}
            ]});
            collector.observe_chunk(format!("data: {event}\n\n").as_bytes());
            let generic_usage =
                serde_json::json!({"model": metadata, "usage":{"total_tokens": 10}});
            collector.observe_chunk(format!("data: {generic_usage}\n\n").as_bytes());
        }

        let telemetry = &collector.telemetry;
        assert!(telemetry.record_budget.warned);
        assert!(!telemetry.gemini_pending_calls.is_empty());
        assert!(telemetry.gemini_pending_calls.len() < 256);
        assert!(telemetry.gemini_tool_ids.len() < 256);
        assert_eq!(telemetry.gemini_tool_ids.len(), telemetry.tools.len());
        assert!(!telemetry.usage.is_empty());
        assert!(telemetry.usage.len() < 256);

        collector.observe_chunk(b"data: {\"usageMetadata\":{\"totalTokenCount\":42}}\n\n");
        let (usage, _) = collector.finalize();
        assert_eq!(usage.last().unwrap().total_tokens, Some(42));
    }

    #[test]
    fn keeps_sse_frames_after_an_oversized_event_split_across_chunks() {
        let mut collector = response_collector(GEMINI_UPSTREAM);
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
