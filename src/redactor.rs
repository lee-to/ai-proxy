use crate::config::RedactionConfig;
use crate::middleware::ScanMatch;
use crate::redaction_context::RedactionContext;
use std::collections::BTreeMap;
use tracing::{debug, trace, warn};

#[derive(Debug, Clone)]
pub struct Redactor {
    strategy: String,
    prefix_len: usize,
    suffix_len: usize,
    mask: String,
}

#[derive(Debug, Clone)]
pub struct RedactionReplacement {
    pub category: String,
    pub scanner: String,
    pub start: usize,
    pub end: usize,
    pub replacement_len: usize,
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RedactionResult {
    pub text: String,
    pub findings: Vec<ScanMatch>,
    pub replacements: Vec<RedactionReplacement>,
    pub skipped: usize,
}

impl Redactor {
    pub fn new(config: &RedactionConfig) -> Self {
        debug!(
            strategy = %config.strategy,
            prefix_len = config.prefix_len,
            suffix_len = config.suffix_len,
            "Initializing redactor"
        );
        Self {
            strategy: config.strategy.clone(),
            prefix_len: config.prefix_len,
            suffix_len: config.suffix_len,
            mask: config.mask.clone(),
        }
    }

    /// Mask a secret value using partial mask strategy.
    /// For strings long enough: prefix + mask + suffix.
    /// For short strings: full mask replacement.
    pub fn redact(&self, value: &str) -> String {
        let char_count = value.chars().count();
        let visible = self.prefix_len.saturating_add(self.suffix_len);
        let hidden = char_count.saturating_sub(visible);

        if hidden <= 2 || hidden < visible {
            trace!(
                original_len = value.len(),
                "Secret too short for partial mask, using full mask"
            );
            self.mask.clone()
        } else {
            // Use char boundaries to avoid panics on multi-byte UTF-8
            let prefix: String = value.chars().take(self.prefix_len).collect();
            let suffix: String = value.chars().skip(char_count - self.suffix_len).collect();
            trace!(original_len = value.len(), "Applying partial mask");
            format!("{}{}{}", prefix, self.mask, suffix)
        }
    }

    /// Replace all occurrences of `secret` in `text` with its redacted form.
    pub fn redact_in_text(&self, text: &str, secret: &str) -> String {
        let masked = self.redact(secret);
        debug!(secret_len = secret.len(), "Redacting secret in text");
        text.replace(secret, &masked)
    }

    pub fn redact_findings(
        &self,
        text: &str,
        findings: Vec<ScanMatch>,
        context: &mut RedactionContext,
    ) -> RedactionResult {
        debug!(
            request_id = %context.request_id(),
            finding_count = findings.len(),
            strategy = %self.strategy,
            "Applying span-based redaction"
        );

        let mut result = text.to_string();
        let mut skipped = 0;
        let mut replacements = Vec::new();
        let mut sorted_findings = findings.clone();
        sorted_findings.sort_by(|left, right| {
            right
                .start
                .cmp(&left.start)
                .then_with(|| right.end.cmp(&left.end))
        });
        if self.strategy == "placeholder" {
            let mut ascending_findings = sorted_findings.clone();
            ascending_findings.sort_by(|left, right| {
                left.start
                    .cmp(&right.start)
                    .then_with(|| left.end.cmp(&right.end))
            });
            for finding in &ascending_findings {
                if finding.start < finding.end
                    && finding.end <= text.len()
                    && text.is_char_boundary(finding.start)
                    && text.is_char_boundary(finding.end)
                    && &text[finding.start..finding.end] == finding.value.as_str()
                {
                    context.placeholder_for(finding);
                }
            }
        }

        for finding in &sorted_findings {
            if finding.start >= finding.end
                || finding.end > result.len()
                || !result.is_char_boundary(finding.start)
                || !result.is_char_boundary(finding.end)
            {
                skipped += 1;
                warn!(
                    request_id = %context.request_id(),
                    scanner = %finding.scanner,
                    category = %finding.category,
                    start = finding.start,
                    end = finding.end,
                    text_len = result.len(),
                    "Skipping invalid redaction span"
                );
                continue;
            }

            if &result[finding.start..finding.end] != finding.value.as_str() {
                skipped += 1;
                warn!(
                    request_id = %context.request_id(),
                    scanner = %finding.scanner,
                    category = %finding.category,
                    start = finding.start,
                    end = finding.end,
                    "Skipping redaction span because detected value no longer matches"
                );
                continue;
            }

            let (replacement, placeholder) = if self.strategy == "placeholder" {
                let placeholder = context.placeholder_for(finding);
                (placeholder.clone(), Some(placeholder))
            } else {
                (self.redact(&finding.value), None)
            };

            result.replace_range(finding.start..finding.end, &replacement);
            replacements.push(RedactionReplacement {
                category: finding.category.clone(),
                scanner: finding.scanner.clone(),
                start: finding.start,
                end: finding.end,
                replacement_len: replacement.len(),
                placeholder,
            });
        }

        let mut counts_by_category: BTreeMap<String, usize> = BTreeMap::new();
        let mut counts_by_scanner: BTreeMap<String, usize> = BTreeMap::new();
        for replacement in &replacements {
            *counts_by_category
                .entry(replacement.category.clone())
                .or_default() += 1;
            *counts_by_scanner
                .entry(replacement.scanner.clone())
                .or_default() += 1;
        }
        debug!(
            request_id = %context.request_id(),
            replacement_count = replacements.len(),
            skipped,
            counts_by_category = ?counts_by_category,
            counts_by_scanner = ?counts_by_scanner,
            placeholder_counts_by_category = ?context.assignment_counts_by_category(),
            "Span-based redaction completed"
        );

        RedactionResult {
            text: result,
            findings,
            replacements,
            skipped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionConfig;

    fn test_redactor() -> Redactor {
        Redactor::new(&RedactionConfig {
            strategy: "partial".to_string(),
            prefix_len: 3,
            suffix_len: 3,
            mask: "***...***".to_string(),
            response_restore_enabled: false,
            restorable_categories: vec!["email".to_string(), "person_name".to_string()],
        })
    }

    #[test]
    fn test_partial_mask_long_string() {
        let r = test_redactor();
        let result = r.redact("sk-ant-abcdef123456789xyz");
        assert_eq!(result, "sk-***...***xyz");
    }

    #[test]
    fn test_full_mask_short_string() {
        let r = test_redactor();
        // 8 chars = prefix(3) + suffix(3) + 2 = 8, should be full mask
        let result = r.redact("abcdefgh");
        assert_eq!(result, "***...***");
    }

    #[test]
    fn test_full_mask_very_short() {
        let r = test_redactor();
        let result = r.redact("abc");
        assert_eq!(result, "***...***");
    }

    #[test]
    fn test_partial_mask_boundary() {
        let r = test_redactor();
        assert_eq!(r.redact("123456789"), "***...***");
        assert_eq!(r.redact("12345678901"), "***...***");
        assert_eq!(r.redact("123456789012"), "123***...***012");
    }

    #[test]
    fn test_redact_in_text() {
        let r = test_redactor();
        let text = "My key is sk-ant-abcdef123456789xyz please use it";
        let result = r.redact_in_text(text, "sk-ant-abcdef123456789xyz");
        assert_eq!(result, "My key is sk-***...***xyz please use it");
    }

    #[test]
    fn test_redact_in_text_multiple_occurrences() {
        let r = test_redactor();
        let text = "key1=AKIA1234567890ABCDEF key2=AKIA1234567890ABCDEF";
        let result = r.redact_in_text(text, "AKIA1234567890ABCDEF");
        assert!(result.contains("AKI***...***DEF"));
        assert!(!result.contains("AKIA1234567890ABCDEF"));
    }

    #[test]
    fn test_span_redaction_only_replaces_detected_span() {
        let r = test_redactor();
        let text = "first AKIA1234567890ABCDEF second AKIA1234567890ABCDEF";
        let first_start = text.find("AKIA1234567890ABCDEF").unwrap();
        let first_end = first_start + "AKIA1234567890ABCDEF".len();
        let finding = ScanMatch::new(
            "AKIA1234567890ABCDEF".to_string(),
            "regex",
            "aws_access_key",
            first_start,
            first_end,
            0.95,
        );
        let mut context = RedactionContext::new(
            "test",
            &RedactionConfig {
                strategy: "partial".to_string(),
                prefix_len: 3,
                suffix_len: 3,
                mask: "***...***".to_string(),
                response_restore_enabled: false,
                restorable_categories: vec!["email".to_string()],
            },
        );

        let result = r.redact_findings(text, vec![finding], &mut context);
        assert_eq!(result.replacements.len(), 1);
        assert_eq!(
            result.text,
            "first AKI***...***DEF second AKIA1234567890ABCDEF"
        );
    }

    #[test]
    fn test_invalid_span_is_skipped() {
        let r = test_redactor();
        let finding = ScanMatch::new("secret".to_string(), "regex", "generic_secret", 1, 99, 0.95);
        let mut context = RedactionContext::new(
            "test",
            &RedactionConfig {
                strategy: "partial".to_string(),
                prefix_len: 3,
                suffix_len: 3,
                mask: "***...***".to_string(),
                response_restore_enabled: false,
                restorable_categories: vec![],
            },
        );

        let result = r.redact_findings("short", vec![finding], &mut context);
        assert_eq!(result.text, "short");
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn test_placeholder_redaction_for_multiple_pii_categories() {
        let r = Redactor::new(&RedactionConfig {
            strategy: "placeholder".to_string(),
            prefix_len: 3,
            suffix_len: 3,
            mask: "***...***".to_string(),
            response_restore_enabled: true,
            restorable_categories: vec![
                "person_name".to_string(),
                "phone".to_string(),
                "account_number".to_string(),
            ],
        });
        let text = "Привет меня зовут Иван Иванов мой номер 79222222222! А меня зовут Вася Пупкин и телефон - 79241112312";
        let mut findings = Vec::new();
        for (value, pattern_name, category) in [
            ("Иван Иванов", "private_person", "person_name"),
            ("79222222222", "account_number", "account_number"),
            ("Вася Пупкин", "private_person", "person_name"),
            ("79241112312", "private_phone", "phone"),
        ] {
            let start = text.find(value).unwrap();
            let mut finding = ScanMatch::new(
                value.to_string(),
                "privacy_filter",
                pattern_name,
                start,
                start + value.len(),
                1.0,
            );
            finding.category = category.to_string();
            finding.sensitivity_class = "pii".to_string();
            finding.restore_policy = "allow".to_string();
            findings.push(finding);
        }
        let mut context = RedactionContext::new(
            "test",
            &RedactionConfig {
                strategy: "placeholder".to_string(),
                prefix_len: 3,
                suffix_len: 3,
                mask: "***...***".to_string(),
                response_restore_enabled: true,
                restorable_categories: vec![
                    "person_name".to_string(),
                    "phone".to_string(),
                    "account_number".to_string(),
                ],
            },
        );

        let result = r.redact_findings(text, findings, &mut context);
        assert_eq!(
            result.text,
            "Привет меня зовут [PERSON_NAME_1] мой номер [ACCOUNT_NUMBER_1]! А меня зовут [PERSON_NAME_2] и телефон - [PHONE_1]"
        );

        let (restored, counts) = context
            .restore_text("[PERSON_NAME_1] / [ACCOUNT_NUMBER_1] / [PERSON_NAME_2] / [PHONE_1]");
        assert_eq!(
            restored,
            "Иван Иванов / 79222222222 / Вася Пупкин / 79241112312"
        );
        assert_eq!(counts["person_name"], 2);
        assert_eq!(counts["account_number"], 1);
        assert_eq!(counts["phone"], 1);
    }
}
