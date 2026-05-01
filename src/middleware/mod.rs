pub mod entropy_scanner;
pub mod model_scanner;
pub mod privacy_filter_scanner;
pub mod regex_scanner;
pub mod structural_scanner;

use std::collections::{BTreeMap, HashSet};
use tracing::{debug, info, warn};

pub const RESTORE_POLICY_ALLOW: &str = "allow";
pub const RESTORE_POLICY_NEVER: &str = "never";

/// Represents a detected secret match in scanned content.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanMatch {
    /// The matched secret value.
    pub value: String,
    /// Name/type of the scanner that found it.
    pub scanner: String,
    /// Human-readable label for the pattern (e.g. "aws_access_key").
    pub pattern_name: String,
    /// Byte offset in the original text where the match starts.
    pub start: usize,
    /// Byte offset in the original text where the match ends.
    pub end: usize,
    /// Stable category used for replacement policy and audit metadata.
    pub category: String,
    /// Coarse sensitivity class, for example "secret" or "pii".
    pub sensitivity_class: String,
    /// Scanner confidence from 0.0 to 1.0.
    pub confidence: f32,
    /// Default restore policy for this category.
    pub restore_policy: String,
}

impl ScanMatch {
    pub fn new(
        value: String,
        scanner: impl Into<String>,
        pattern_name: impl Into<String>,
        start: usize,
        end: usize,
        confidence: f32,
    ) -> Self {
        let pattern_name = pattern_name.into();
        let category = category_for_pattern(&pattern_name);
        let sensitivity_class = sensitivity_class_for_category(&category).to_string();
        let restore_policy = default_restore_policy_for_category(&category).to_string();

        Self {
            value,
            scanner: scanner.into(),
            pattern_name,
            start,
            end,
            category,
            sensitivity_class,
            confidence,
            restore_policy,
        }
    }
}

pub fn category_for_pattern(pattern_name: &str) -> String {
    let normalized = pattern_name.to_ascii_lowercase();
    if normalized.contains("private_key") {
        "private_key".to_string()
    } else if normalized.contains("connection") || normalized.contains("database_url") {
        "connection_string".to_string()
    } else if normalized.contains("password") || normalized.contains("passwd") {
        "password".to_string()
    } else if normalized.contains("api_key")
        || normalized.contains("access_key")
        || normalized.contains("secret_key")
    {
        "api_key".to_string()
    } else if normalized.contains("jwt") {
        "jwt".to_string()
    } else if normalized.contains("token") {
        "token".to_string()
    } else if normalized.contains("secret")
        || normalized.contains("entropy")
        || normalized.contains("session")
    {
        "generic_secret".to_string()
    } else if normalized.contains("email") {
        "email".to_string()
    } else if normalized.contains("person") || normalized.contains("name") {
        "person_name".to_string()
    } else if normalized.contains("phone") {
        "phone".to_string()
    } else {
        "generic_secret".to_string()
    }
}

pub fn sensitivity_class_for_category(category: &str) -> &'static str {
    match category {
        "email" | "person_name" | "phone" | "address" | "url" | "date" | "account_number"
        | "ip_address" => "pii",
        _ => "secret",
    }
}

pub fn default_restore_policy_for_category(category: &str) -> &'static str {
    match sensitivity_class_for_category(category) {
        "pii" => RESTORE_POLICY_ALLOW,
        _ => RESTORE_POLICY_NEVER,
    }
}

/// Trait that all secret scanners must implement.
pub trait SecretScanner: Send + Sync {
    /// Scan the given text and return all detected secret matches.
    fn scan(&self, text: &str) -> Vec<ScanMatch>;

    /// Scanner name for logging/identification.
    fn name(&self) -> &str;
}

/// Pipeline that runs multiple scanners and deduplicates results.
pub struct ScanPipeline {
    scanners: Vec<Box<dyn SecretScanner>>,
}

impl ScanPipeline {
    pub fn new() -> Self {
        debug!("Creating empty scan pipeline");
        Self {
            scanners: Vec::new(),
        }
    }

    pub fn add_scanner(&mut self, scanner: Box<dyn SecretScanner>) {
        info!(scanner = scanner.name(), "Adding scanner to pipeline");
        self.scanners.push(scanner);
    }

    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }

    /// Run all scanners on the text, deduplicating by exact span and resolving overlaps.
    pub fn scan(&self, text: &str) -> Vec<ScanMatch> {
        if let Ok(handle) = tokio::runtime::Handle::try_current()
            && matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            )
        {
            return tokio::task::block_in_place(|| self.scan_inner(text));
        }
        self.scan_inner(text)
    }

    fn scan_inner(&self, text: &str) -> Vec<ScanMatch> {
        debug!(
            text_len = text.len(),
            scanner_count = self.scanners.len(),
            "Running scan pipeline"
        );

        let mut candidates: Vec<(usize, ScanMatch)> = Vec::new();
        let mut ordinal = 0;

        for scanner in &self.scanners {
            let matches = scanner.scan(text);
            let mut totals: BTreeMap<String, usize> = BTreeMap::new();
            for m in &matches {
                *totals.entry(m.category.clone()).or_default() += 1;
            }
            debug!(
                scanner = scanner.name(),
                matches_found = matches.len(),
                category_totals = ?totals,
                "Scanner completed"
            );

            for m in matches {
                debug!(
                    scanner = scanner.name(),
                    category = %m.category,
                    confidence = m.confidence,
                    start = m.start,
                    end = m.end,
                    "Scanner finding candidate"
                );
                candidates.push((ordinal, m));
                ordinal += 1;
            }
        }

        let results = normalize_findings(candidates, text);
        let mut totals: BTreeMap<String, usize> = BTreeMap::new();
        for m in &results {
            *totals.entry(m.category.clone()).or_default() += 1;
        }
        info!(
            total_unique_matches = results.len(),
            category_totals = ?totals,
            "Scan pipeline completed"
        );
        results
    }
}

impl Default for ScanPipeline {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_findings(candidates: Vec<(usize, ScanMatch)>, text: &str) -> Vec<ScanMatch> {
    let mut seen_exact: HashSet<(usize, usize, String)> = HashSet::new();
    let mut unique = Vec::new();

    for (ordinal, candidate) in candidates {
        let key = (candidate.start, candidate.end, candidate.category.clone());
        if seen_exact.insert(key) {
            unique.push((ordinal, candidate));
        } else {
            debug!(
                category = %candidate.category,
                start = candidate.start,
                end = candidate.end,
                "Dropping duplicate scanner finding"
            );
        }
    }

    unique.sort_by(|(left_ordinal, left), (right_ordinal, right)| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
            .then_with(|| left_ordinal.cmp(right_ordinal))
    });

    let mut accepted: Vec<(usize, ScanMatch)> = Vec::new();
    for (ordinal, candidate) in unique {
        if let Some((existing_ordinal, existing)) = accepted.last_mut()
            && spans_overlap(candidate.start, candidate.end, existing.start, existing.end)
        {
            let start = existing.start.min(candidate.start);
            let end = existing.end.max(candidate.end);
            let Some(value) = text.get(start..end) else {
                warn!(
                    start,
                    end,
                    "Skipping overlapping scanner finding union because span is not UTF-8 aligned"
                );
                continue;
            };
            debug!(
                existing_category = %existing.category,
                candidate_category = %candidate.category,
                start,
                end,
                "Merging overlapping scanner findings"
            );
            existing.value = value.to_string();
            existing.start = start;
            existing.end = end;
            existing.confidence = existing.confidence.max(candidate.confidence);
            if existing.sensitivity_class == "secret"
                || candidate.sensitivity_class == "secret"
                || existing.restore_policy == RESTORE_POLICY_NEVER
                || candidate.restore_policy == RESTORE_POLICY_NEVER
            {
                existing.category = "generic_secret".to_string();
                existing.sensitivity_class = "secret".to_string();
                existing.restore_policy = RESTORE_POLICY_NEVER.to_string();
            }
            *existing_ordinal = (*existing_ordinal).min(ordinal);
            continue;
        }
        accepted.push((ordinal, candidate));
    }

    accepted.sort_by(|(_, left), (_, right)| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.end.cmp(&right.end))
            .then_with(|| left.category.cmp(&right.category))
    });
    accepted.into_iter().map(|(_, finding)| finding).collect()
}

fn spans_overlap(left_start: usize, left_end: usize, right_start: usize, right_end: usize) -> bool {
    left_start < right_end && right_start < left_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_duplicate_and_overlapping_findings() {
        let findings = vec![
            (
                0,
                ScanMatch::new("abcdef".to_string(), "regex", "generic_secret", 0, 6, 0.90),
            ),
            (
                1,
                ScanMatch::new("abcdef".to_string(), "regex", "generic_secret", 0, 6, 0.90),
            ),
            (
                2,
                ScanMatch::new("cde".to_string(), "entropy", "high_entropy", 2, 5, 0.80),
            ),
        ];

        let normalized = normalize_findings(findings, "abcdef");
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].start, 0);
        assert_eq!(normalized[0].end, 6);
    }

    #[test]
    fn normalizes_overlapping_findings_to_union_span() {
        let findings = vec![
            (
                0,
                ScanMatch::new("abc".to_string(), "regex", "person_name", 0, 3, 0.70),
            ),
            (
                1,
                ScanMatch::new("cdef".to_string(), "entropy", "generic_secret", 2, 6, 0.80),
            ),
        ];

        let normalized = normalize_findings(findings, "abcdef");

        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].value, "abcdef");
        assert_eq!(normalized[0].start, 0);
        assert_eq!(normalized[0].end, 6);
        assert_eq!(normalized[0].category, "generic_secret");
    }

    #[test]
    fn category_mapping_prioritizes_secret_markers_over_name() {
        assert_eq!(category_for_pattern("username_token"), "token");
        assert_eq!(category_for_pattern("session_name"), "generic_secret");
        assert_eq!(category_for_pattern("customer_name"), "person_name");
    }
}
