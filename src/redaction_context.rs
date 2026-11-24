use std::collections::{BTreeMap, HashMap, HashSet};

use bytes::Bytes;
use tracing::{debug, trace, warn};

use crate::config::RedactionConfig;
use crate::middleware::{RESTORE_POLICY_NEVER, ScanMatch};

#[derive(Debug, Clone)]
pub struct PlaceholderEntry {
    pub placeholder: String,
    pub original: String,
    pub category: String,
    pub restore_allowed: bool,
}

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub bytes: Bytes,
    pub counts_by_category: BTreeMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct RedactionContext {
    request_id: String,
    response_restore_enabled: bool,
    restorable_categories: HashSet<String>,
    entries: Vec<PlaceholderEntry>,
    // Both wire spellings point to the same request-local entry.
    restore_tokens: Vec<(String, usize)>,
    entries_by_value: HashMap<(String, String), usize>,
    counts_by_category: BTreeMap<String, usize>,
}

impl RedactionContext {
    pub fn new(request_id: impl Into<String>, config: &RedactionConfig) -> Self {
        let request_id = request_id.into();
        debug!(
            request_id = %request_id,
            response_restore_enabled = config.response_restore_enabled,
            restorable_categories = ?config.restorable_categories,
            "Creating redaction context"
        );

        Self {
            request_id,
            response_restore_enabled: config.response_restore_enabled,
            restorable_categories: config
                .restorable_categories
                .iter()
                .map(|category| category.to_ascii_lowercase())
                .collect(),
            entries: Vec::new(),
            restore_tokens: Vec::new(),
            entries_by_value: HashMap::new(),
            counts_by_category: BTreeMap::new(),
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn has_restorable_values(&self) -> bool {
        !self.restore_tokens.is_empty()
    }

    pub fn max_placeholder_len(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.placeholder.len())
            .max()
            .unwrap_or(0)
    }

    pub fn placeholder_for(&mut self, finding: &ScanMatch) -> String {
        let key = (finding.category.clone(), finding.value.clone());
        if let Some(&index) = self.entries_by_value.get(&key) {
            let existing = &mut self.entries[index];
            if existing.restore_allowed && finding.restore_policy == RESTORE_POLICY_NEVER {
                existing.restore_allowed = false;
                self.restore_tokens.retain(|(_, entry)| *entry != index);
            }
            trace!(
                request_id = %self.request_id,
                category = %finding.category,
                "Reusing existing placeholder"
            );
            return existing.placeholder.clone();
        }

        let counter = self
            .counts_by_category
            .entry(finding.category.clone())
            .or_default();
        *counter += 1;
        let placeholder = format!("[{}_{}]", finding.category.to_ascii_uppercase(), *counter);
        let restore_allowed = self.response_restore_enabled
            && finding.restore_policy != RESTORE_POLICY_NEVER
            && self
                .restorable_categories
                .contains(&finding.category.to_ascii_lowercase());

        let index = self.entries.len();
        if restore_allowed {
            self.restore_tokens.push((placeholder.clone(), index));
            self.restore_tokens
                .push((percent_encode_placeholder(&placeholder), index));
        }
        self.entries.push(PlaceholderEntry {
            placeholder: placeholder.clone(),
            original: finding.value.clone(),
            category: finding.category.clone(),
            restore_allowed,
        });
        self.entries_by_value.insert(key, index);
        debug!(
            request_id = %self.request_id,
            category = %finding.category,
            restore_allowed,
            assigned_count = self.entries.len(),
            "Assigned placeholder"
        );
        placeholder
    }

    pub fn assignment_counts_by_category(&self) -> BTreeMap<String, usize> {
        self.counts_by_category.clone()
    }

    pub fn restore_bytes(&self, bytes: Bytes) -> RestoreReport {
        self.restore_bytes_with_format(bytes, false)
    }

    fn restore_bytes_with_format(&self, bytes: Bytes, json_strings: bool) -> RestoreReport {
        if !self.response_restore_enabled || self.entries.is_empty() {
            trace!(
                request_id = %self.request_id,
                response_restore_enabled = self.response_restore_enabled,
                placeholder_count = self.entries.len(),
                "Response restoration disabled or no placeholders"
            );
            return RestoreReport {
                bytes,
                counts_by_category: BTreeMap::new(),
            };
        }

        let Ok(text) = std::str::from_utf8(&bytes) else {
            warn!(
                request_id = %self.request_id,
                "Skipping placeholder restoration for non-UTF-8 response chunk"
            );
            return RestoreReport {
                bytes,
                counts_by_category: BTreeMap::new(),
            };
        };

        let (restored, counts_by_category) = self.restore_text_with_format(text, json_strings);
        RestoreReport {
            bytes: Bytes::from(restored),
            counts_by_category,
        }
    }

    pub fn restore_text(&self, text: &str) -> (String, BTreeMap<String, usize>) {
        self.restore_text_with_format(text, false)
    }

    fn restore_text_with_format(
        &self,
        text: &str,
        json_strings: bool,
    ) -> (String, BTreeMap<String, usize>) {
        let mut restored = String::with_capacity(text.len());
        let mut counts_by_category = BTreeMap::new();
        let mut cursor = 0;
        while cursor < text.len() {
            let remaining = &text[cursor..];
            let Some((placeholder, index)) = self
                .restore_tokens
                .iter()
                .find(|(placeholder, _)| remaining.starts_with(placeholder.as_str()))
            else {
                let Some(ch) = remaining.chars().next() else {
                    break;
                };
                restored.push(ch);
                cursor += ch.len_utf8();
                continue;
            };

            let entry = &self.entries[*index];
            if json_strings {
                let encoded = serde_json::to_string(&entry.original)
                    .expect("serializing a JSON string cannot fail");
                restored.push_str(&encoded[1..encoded.len() - 1]);
            } else {
                restored.push_str(&entry.original);
            }
            *counts_by_category
                .entry(entry.category.clone())
                .or_default() += 1;
            cursor += placeholder.len();
        }

        debug!(
            request_id = %self.request_id,
            counts_by_category = ?counts_by_category,
            "Restored placeholders in text"
        );
        (restored, counts_by_category)
    }
}

fn percent_encode_placeholder(placeholder: &str) -> String {
    placeholder.replace('[', "%5B").replace(']', "%5D")
}

pub struct StreamingRestore {
    context: RedactionContext,
    pending: Vec<u8>,
    json_strings: bool,
    sse: Option<SseBuffer>,
}

impl StreamingRestore {
    pub fn new(context: RedactionContext) -> Self {
        Self::with_json_strings(context, false)
    }

    pub fn with_json_strings(context: RedactionContext, json_strings: bool) -> Self {
        debug!(
            request_id = %context.request_id(),
            max_placeholder_len = context.max_placeholder_len(),
            "Creating streaming placeholder restore adapter"
        );
        Self {
            context,
            pending: Vec::new(),
            json_strings,
            sse: None,
        }
    }

    pub(crate) fn for_sse(context: RedactionContext) -> Self {
        let mut restore = Self::new(context);
        restore.sse = Some(SseBuffer::default());
        restore
    }

    pub fn push(&mut self, chunk: Bytes) -> RestoreReport {
        if let Some(sse) = &mut self.sse {
            return sse.push(&self.context, &chunk);
        }
        self.pending.extend_from_slice(&chunk);
        let keep_len = self.longest_placeholder_prefix_suffix();
        if keep_len == self.pending.len() {
            trace!(
                request_id = %self.context.request_id(),
                pending_len = self.pending.len(),
                "Holding response chunk for streaming restore"
            );
            return RestoreReport {
                bytes: Bytes::new(),
                counts_by_category: BTreeMap::new(),
            };
        }

        let mut emit_len = self.pending.len() - keep_len;
        emit_len = floor_utf8_boundary(&self.pending, emit_len);
        if emit_len == 0 {
            trace!(
                request_id = %self.context.request_id(),
                pending_len = self.pending.len(),
                keep_len,
                "Holding response chunk for UTF-8 boundary"
            );
            return RestoreReport {
                bytes: Bytes::new(),
                counts_by_category: BTreeMap::new(),
            };
        }
        let emit = self.pending.drain(..emit_len).collect::<Vec<_>>();
        let report = self
            .context
            .restore_bytes_with_format(Bytes::from(emit), self.json_strings);
        trace!(
            request_id = %self.context.request_id(),
            emitted_len = report.bytes.len(),
            pending_len = self.pending.len(),
            keep_len,
            "Flushed streaming restore buffer"
        );
        report
    }

    pub fn finish(mut self) -> Option<RestoreReport> {
        if let Some(sse) = self.sse {
            return (!sse.event.is_empty()).then(|| restore_sse_event(&self.context, sse.event));
        }
        if self.pending.is_empty() {
            return None;
        }

        let pending = std::mem::take(&mut self.pending);
        Some(
            self.context
                .restore_bytes_with_format(Bytes::from(pending), self.json_strings),
        )
    }

    fn longest_placeholder_prefix_suffix(&self) -> usize {
        let tokens = &self.context.restore_tokens;
        let max_len = tokens
            .iter()
            .map(|(token, _)| token.len())
            .max()
            .unwrap_or(0);
        let max_candidate = self.pending.len().min(max_len.saturating_sub(1));
        for len in (1..=max_candidate).rev() {
            let suffix = &self.pending[self.pending.len() - len..];
            if tokens
                .iter()
                .any(|(token, _)| token.len() > len && token.as_bytes().starts_with(suffix))
            {
                debug!(
                    request_id = %self.context.request_id(),
                    suffix_len = len,
                    "Detected split placeholder prefix at response chunk boundary"
                );
                return len;
            }
        }
        0
    }
}

#[derive(Default, PartialEq)]
enum SseLine {
    #[default]
    Start,
    Field,
    Comment,
}

const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Default)]
struct SseBuffer {
    event: Vec<u8>,
    line: SseLine,
    checked_bom: bool,
    // A following LF belongs to the same line and must go to the same destination.
    cr_was_forwarded: Option<bool>,
    passthrough: bool,
}

impl SseBuffer {
    fn push(&mut self, context: &RedactionContext, chunk: &[u8]) -> RestoreReport {
        let mut output = Vec::new();
        let mut counts = BTreeMap::new();
        for &byte in chunk {
            if !self.checked_bom {
                const BOM: &[u8] = b"\xef\xbb\xbf";
                if byte == BOM[self.event.len()] {
                    self.event.push(byte);
                    if self.event.len() == BOM.len() {
                        output.append(&mut self.event);
                        self.checked_bom = true;
                    }
                    continue;
                }
                self.checked_bom = true;
                if !self.event.is_empty() {
                    self.line = SseLine::Field;
                }
            }

            if let Some(forwarded) = self.cr_was_forwarded.take()
                && byte == b'\n'
            {
                self.write_byte(byte, forwarded, &mut output);
                continue;
            }

            let end_line = matches!(byte, b'\r' | b'\n');
            if self.line == SseLine::Start && !end_line {
                self.line = if byte == b':' {
                    SseLine::Comment
                } else {
                    SseLine::Field
                };
            }
            let blank = self.line == SseLine::Start;
            if blank {
                if !self.event.is_empty() {
                    // An intervening heartbeat may already have been forwarded.
                    // Keep a buffered bare CR and a blank LF as two line breaks.
                    let separate_lf = self.event.ends_with(b"\r") && byte == b'\n';
                    let report = restore_sse_event(context, std::mem::take(&mut self.event));
                    output.extend_from_slice(&report.bytes);
                    if separate_lf {
                        output.push(b'\n');
                    }
                    for (category, count) in report.counts_by_category {
                        *counts.entry(category).or_default() += count;
                    }
                }
                self.passthrough = false;
            }
            let forward = blank || self.line == SseLine::Comment;
            self.write_byte(byte, forward, &mut output);
            if end_line {
                self.cr_was_forwarded = (byte == b'\r').then_some(forward || self.passthrough);
                self.line = SseLine::Start;
            }
        }
        RestoreReport {
            bytes: Bytes::from(output),
            counts_by_category: counts,
        }
    }

    fn write_byte(&mut self, byte: u8, forward: bool, output: &mut Vec<u8>) {
        if !forward && self.event.len() == MAX_SSE_EVENT_BYTES {
            output.append(&mut self.event);
            self.passthrough = true;
        }
        if forward || self.passthrough {
            output.push(byte);
        } else {
            self.event.push(byte);
        }
    }
}

fn sse_data_line(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("data:")?;
    let content = rest.strip_prefix(' ').unwrap_or(rest);
    let text = content.trim_end_matches(['\r', '\n']);
    let prefix_len = line.len() - content.len();
    Some((&line[..prefix_len], text, &content[text.len()..]))
}

fn restore_sse_event(context: &RedactionContext, event: Vec<u8>) -> RestoreReport {
    let mut counts = BTreeMap::new();
    let Ok(text) = std::str::from_utf8(&event) else {
        return RestoreReport {
            bytes: Bytes::from(event),
            counts_by_category: counts,
        };
    };
    // The event payload is the concatenation of all data lines, regardless of
    // whether an event arrived in one network chunk or many.
    let lines = || text.split_inclusive(['\r', '\n']);
    let data = lines()
        .filter_map(|line| sse_data_line(line).map(|(_, data, _)| data))
        .collect::<Vec<_>>()
        .join("\n");
    let is_json = serde_json::from_str::<&serde_json::value::RawValue>(&data).is_ok();

    let mut output = String::with_capacity(event.len());
    for line in lines() {
        let Some((prefix, data, ending)) = sse_data_line(line) else {
            output.push_str(line);
            continue;
        };
        let (restored, replacements) = context.restore_text_with_format(data, is_json);
        output.push_str(prefix);
        if !is_json && !replacements.is_empty() {
            // Keep a newline in a restored plain-text value inside the data
            // payload by spelling it as another data field.
            let restored = restored.replace("\r\n", "\n").replace('\r', "\n");
            output.push_str(&restored.replace('\n', "\ndata: "));
        } else {
            output.push_str(&restored);
        }
        output.push_str(ending);
        for (category, count) in replacements {
            *counts.entry(category).or_default() += count;
        }
    }
    RestoreReport {
        bytes: Bytes::from(output),
        counts_by_category: counts,
    }
}

fn floor_utf8_boundary(bytes: &[u8], index: usize) -> usize {
    // Only a valid, incomplete UTF-8 suffix can be completed by the next chunk.
    for start in (index.saturating_sub(3)..index).rev() {
        if bytes[start] & 0xc0 != 0x80 {
            if let Err(error) = std::str::from_utf8(&bytes[start..index])
                && error.error_len().is_none()
            {
                return start;
            }
            break;
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionConfig;
    use crate::middleware::ScanMatch;

    fn placeholder_config() -> RedactionConfig {
        RedactionConfig {
            strategy: "placeholder".to_string(),
            prefix_len: 3,
            suffix_len: 3,
            mask: "***...***".to_string(),
            response_restore_enabled: true,
            restorable_categories: vec!["email".to_string(), "person_name".to_string()],
        }
    }

    #[test]
    fn identical_values_reuse_placeholder() {
        let mut context = RedactionContext::new("req-1", &placeholder_config());
        let finding = ScanMatch::new("ada@example.com".to_string(), "regex", "email", 0, 15, 0.95);

        let first = context.placeholder_for(&finding);
        let second = context.placeholder_for(&finding);

        assert_eq!(first, "[EMAIL_1]");
        assert_eq!(second, "[EMAIL_1]");
        assert_eq!(context.assignment_counts_by_category()["email"], 1);
    }

    #[test]
    fn secret_placeholders_are_not_restored_by_default() {
        let mut context = RedactionContext::new("req-1", &placeholder_config());
        let finding = ScanMatch::new(
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz".to_string(),
            "regex",
            "anthropic_api_key",
            0,
            38,
            0.95,
        );

        let placeholder = context.placeholder_for(&finding);
        let (restored, counts) = context.restore_text(&format!("key={placeholder}"));

        assert!(!context.has_restorable_values());
        assert_eq!(placeholder, "[API_KEY_1]");
        assert_eq!(restored, "key=[API_KEY_1]");
        assert!(counts.is_empty());
    }

    #[test]
    fn streaming_restore_handles_split_placeholder() {
        let mut context = RedactionContext::new("req-1", &placeholder_config());
        let finding = ScanMatch::new("ada@example.com".to_string(), "regex", "email", 0, 15, 0.95);
        let placeholder = context.placeholder_for(&finding);
        assert_eq!(placeholder, "[EMAIL_1]");

        let mut stream = StreamingRestore::new(context);
        let first = stream.push(Bytes::from("hello [EMA"));
        let second = stream.push(Bytes::from("IL_1] done"));
        let tail = stream.finish();

        let mut combined = [first.bytes, second.bytes].concat();
        if let Some(tail) = tail {
            combined.extend_from_slice(&tail.bytes);
        }
        assert_eq!(
            std::str::from_utf8(&combined).unwrap(),
            "hello ada@example.com done"
        );
    }

    #[test]
    fn sse_restores_json_and_plain_text_without_breaking_framing() {
        let mut context = RedactionContext::new("req-sse", &placeholder_config());
        let name = "Ada \"A\" \\ Lovelace\nLondon";
        let finding = ScanMatch::new(name.into(), "model", "person_name", 0, name.len(), 0.95);
        let placeholder = context.placeholder_for(&finding);
        let input = format!(
            "event: delta\r\ndata: {{\r\ndata: \"text\":\"{placeholder}\"\r\ndata: }}\r\n\r\ndata: Hello {placeholder}\n\n"
        );
        let mut stream = StreamingRestore::for_sse(context);
        let mut output = Vec::new();
        // Exercise boundaries inside JSON, CRLF, and the placeholder.
        for chunk in input.as_bytes().chunks(5) {
            output.extend_from_slice(&stream.push(Bytes::copy_from_slice(chunk)).bytes);
        }
        assert!(stream.finish().is_none());
        let output = String::from_utf8(output).unwrap();
        let (json_event, plain_event) = output.split_once("\r\n\r\n").unwrap();
        let data = json_event
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .collect::<Vec<_>>()
            .join("\n");
        let payload: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(payload["text"], name);
        assert_eq!(
            plain_event,
            "data: Hello Ada \"A\" \\ Lovelace\ndata: London\n\n"
        );
    }

    fn name_context(name: &str) -> RedactionContext {
        let mut context = RedactionContext::new("req-stream", &placeholder_config());
        let finding = ScanMatch::new(name.into(), "model", "person_name", 0, name.len(), 0.95);
        assert_eq!(context.placeholder_for(&finding), "[PERSON_NAME_1]");
        context
    }

    #[test]
    fn reuse_keeps_the_strictest_restore_policy_in_either_order() {
        let allowed = ScanMatch::new("Ada".into(), "model", "person_name", 0, 3, 1.0);
        let mut restricted = allowed.clone();
        restricted.restore_policy = RESTORE_POLICY_NEVER.into();
        for findings in [[&allowed, &restricted], [&restricted, &allowed]] {
            let mut context = RedactionContext::new("req-policy", &placeholder_config());
            for finding in findings {
                assert_eq!(context.placeholder_for(finding), "[PERSON_NAME_1]");
            }
            assert!(!context.has_restorable_values());
            let text = "[PERSON_NAME_1] %5BPERSON_NAME_1%5D";
            let (result, counts) = context.restore_text(text);
            assert_eq!(result, text);
            assert!(counts.is_empty());
        }
    }

    #[test]
    fn sse_initial_bom_survives_chunk_splits_and_is_recognized_only_once() {
        let name = "Ada \"A\"";
        let input = "\u{feff}data: {\ndata: \"name\":\"[PERSON_NAME_1]\"}\n\n\u{feff}data: [PERSON_NAME_1]\n\n";
        let expected = format!(
            "\u{feff}data: {{\ndata: \"name\":{}}}\n\n\u{feff}data: [PERSON_NAME_1]\n\n",
            serde_json::to_string(name).unwrap()
        );
        let mut stream = StreamingRestore::for_sse(name_context(name));
        let mut output = Vec::new();
        for byte in input.bytes() {
            output.extend_from_slice(&stream.push(Bytes::from(vec![byte])).bytes);
        }
        assert!(stream.finish().is_none());
        assert_eq!(output, expected.as_bytes());
    }

    #[test]
    fn sse_comments_stream_during_an_event_and_cr_dispatches_without_lookahead() {
        for end in ["\n", "\r", "\r\n"] {
            let mut stream = StreamingRestore::for_sse(name_context("Ada"));
            assert_eq!(
                stream.push(Bytes::from("\u{feff}: leading")).bytes,
                "\u{feff}: leading"
            );
            assert_eq!(stream.push(Bytes::from(end)).bytes, end);
            let data = format!("data: [PERSON_NAME_1]{end}");
            assert!(stream.push(Bytes::from(data)).bytes.is_empty());
            for part in [":", " heartbeat", end] {
                assert_eq!(stream.push(Bytes::from(part)).bytes, part);
            }
            let report = stream.push(Bytes::from(end));
            assert_eq!(report.bytes, format!("data: Ada{end}{end}"));
            assert_eq!(report.counts_by_category["person_name"], 1);
            assert!(stream.finish().is_none());
        }
        // Moving a comment ahead of pending data must not collapse CR + blank LF.
        let mut stream = StreamingRestore::for_sse(name_context("Ada"));
        let report = stream.push(Bytes::from("data: x\r: ping\n\n"));
        assert_eq!(report.bytes, ": ping\ndata: x\r\n\n");
    }

    #[test]
    fn sse_oversized_field_passes_through_and_next_event_restores() {
        let mut stream = StreamingRestore::for_sse(name_context("Ada"));
        let oversized = format!(
            "data: {}[PERSON_NAME_1]\r\n\r\n",
            "x".repeat(MAX_SSE_EVENT_BYTES)
        );
        let mut output = Vec::new();
        for chunk in oversized.as_bytes().chunks(997) {
            output.extend_from_slice(&stream.push(Bytes::copy_from_slice(chunk)).bytes);
        }
        assert_eq!(output, oversized.as_bytes());
        assert_eq!(
            stream.push(Bytes::from("data: [PERSON_NAME_1]\n\n")).bytes,
            "data: Ada\n\n"
        );
        assert!(stream.finish().is_none());
    }

    #[test]
    fn streaming_restore_handles_every_split_of_a_percent_encoded_placeholder() {
        let wire = "%5BPERSON_NAME_1%5D";
        for split in 0..=wire.len() {
            let mut stream = StreamingRestore::new(name_context("Ada"));
            let first = stream.push(Bytes::from_static(&wire.as_bytes()[..split]));
            let second = stream.push(Bytes::from_static(&wire.as_bytes()[split..]));
            assert_eq!(
                [first.bytes, second.bytes].concat(),
                b"Ada",
                "split at {split}"
            );
            assert!(stream.finish().is_none());
        }
    }

    #[test]
    fn invalid_utf8_passes_through_without_growing_the_stream_buffer() {
        let mut stream = StreamingRestore::new(name_context("Ada"));
        for chunk in [&[0xff][..], &[0x80; 8], &[0xf0, 0x80]] {
            assert_eq!(
                stream.push(Bytes::copy_from_slice(chunk)).bytes.as_ref(),
                chunk
            );
        }
        assert_eq!(stream.push(Bytes::from("[PERSON_NAME_1]")).bytes, "Ada");
        assert!(stream.finish().is_none());
    }

    #[test]
    fn streaming_restore_holds_split_utf8_character() {
        let mut context = RedactionContext::new("req-1", &placeholder_config());
        let finding = ScanMatch::new("ada@example.com".to_string(), "regex", "email", 0, 15, 0.95);
        let placeholder = context.placeholder_for(&finding);

        let mut stream = StreamingRestore::new(context);
        let text = format!("привет {placeholder}");
        let first = stream.push(Bytes::copy_from_slice(&text.as_bytes()[..1]));
        let second = stream.push(Bytes::copy_from_slice(&text.as_bytes()[1..]));
        let tail = stream.finish();

        let mut combined = [first.bytes, second.bytes].concat();
        if let Some(tail) = tail {
            combined.extend_from_slice(&tail.bytes);
        }
        assert_eq!(
            String::from_utf8(combined).unwrap(),
            "привет ada@example.com"
        );
    }

    #[test]
    fn account_number_restores_only_when_configured_as_restorable() {
        let mut config = placeholder_config();
        config
            .restorable_categories
            .push("account_number".to_string());
        let mut context = RedactionContext::new("req-1", &config);
        let mut finding = ScanMatch::new(
            "79222222222".to_string(),
            "privacy_filter",
            "account_number",
            0,
            11,
            1.0,
        );
        finding.category = "account_number".to_string();
        finding.sensitivity_class = "pii".to_string();
        finding.restore_policy = "allow".to_string();

        let placeholder = context.placeholder_for(&finding);
        let (restored, counts) = context.restore_text(&format!("number={placeholder}"));

        assert_eq!(placeholder, "[ACCOUNT_NUMBER_1]");
        assert_eq!(restored, "number=79222222222");
        assert_eq!(counts["account_number"], 1);
    }

    #[test]
    fn restore_text_does_not_restore_placeholders_inside_original_values() {
        let mut context = RedactionContext::new("req-1", &placeholder_config());
        let first = ScanMatch::new("[EMAIL_2]".to_string(), "regex", "email", 0, 9, 0.95);
        let second = ScanMatch::new("ada@example.com".to_string(), "regex", "email", 0, 15, 0.95);
        let first_placeholder = context.placeholder_for(&first);
        let second_placeholder = context.placeholder_for(&second);

        let (restored, counts) = context.restore_text(&first_placeholder);

        assert_eq!(first_placeholder, "[EMAIL_1]");
        assert_eq!(second_placeholder, "[EMAIL_2]");
        assert_eq!(restored, "[EMAIL_2]");
        assert_eq!(counts["email"], 1);
    }
}
