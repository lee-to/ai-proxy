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
    placeholders_by_value: HashMap<(String, String), String>,
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
            placeholders_by_value: HashMap::new(),
            counts_by_category: BTreeMap::new(),
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
        if let Some(existing) = self.placeholders_by_value.get(&key) {
            trace!(
                request_id = %self.request_id,
                category = %finding.category,
                "Reusing existing placeholder"
            );
            return existing.clone();
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

        self.entries.push(PlaceholderEntry {
            placeholder: placeholder.clone(),
            original: finding.value.clone(),
            category: finding.category.clone(),
            restore_allowed,
        });
        self.placeholders_by_value.insert(key, placeholder.clone());
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

        let (restored, counts_by_category) = self.restore_text(text);
        RestoreReport {
            bytes: Bytes::from(restored),
            counts_by_category,
        }
    }

    pub fn restore_text(&self, text: &str) -> (String, BTreeMap<String, usize>) {
        let mut restored = String::with_capacity(text.len());
        let mut counts_by_category = BTreeMap::new();
        let replacements: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| entry.restore_allowed)
            .flat_map(|entry| {
                [
                    (entry.placeholder.clone(), entry),
                    (percent_encode_placeholder(&entry.placeholder), entry),
                ]
            })
            .collect();

        let mut cursor = 0;
        while cursor < text.len() {
            let remaining = &text[cursor..];
            let Some((placeholder, entry)) = replacements
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

            restored.push_str(&entry.original);
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
}

impl StreamingRestore {
    pub fn new(context: RedactionContext) -> Self {
        debug!(
            request_id = %context.request_id(),
            max_placeholder_len = context.max_placeholder_len(),
            "Creating streaming placeholder restore adapter"
        );
        Self {
            context,
            pending: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: Bytes) -> RestoreReport {
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
        let report = self.context.restore_bytes(Bytes::from(emit));
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
        if self.pending.is_empty() {
            return None;
        }

        let pending = std::mem::take(&mut self.pending);
        Some(self.context.restore_bytes(Bytes::from(pending)))
    }

    fn longest_placeholder_prefix_suffix(&self) -> usize {
        let max_len = self.context.max_placeholder_len().saturating_sub(1);
        let max_candidate = self.pending.len().min(max_len);
        for len in (1..=max_candidate).rev() {
            let suffix = &self.pending[self.pending.len() - len..];
            if self
                .context
                .entries
                .iter()
                .any(|entry| entry.placeholder.as_bytes().starts_with(suffix))
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

fn floor_utf8_boundary(bytes: &[u8], index: usize) -> usize {
    let mut idx = index.min(bytes.len());
    while idx > 0 && bytes[idx - 1] & 0b1100_0000 == 0b1000_0000 {
        idx -= 1;
    }
    if idx == 0 {
        return 0;
    }
    let leader_pos = idx - 1;
    let leader = bytes[leader_pos];
    let needed = if leader & 0b1000_0000 == 0 {
        1
    } else if leader & 0b1110_0000 == 0b1100_0000 {
        2
    } else if leader & 0b1111_0000 == 0b1110_0000 {
        3
    } else if leader & 0b1111_1000 == 0b1111_0000 {
        4
    } else {
        return leader_pos;
    };
    if leader_pos + needed <= index {
        leader_pos + needed
    } else {
        leader_pos
    }
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
