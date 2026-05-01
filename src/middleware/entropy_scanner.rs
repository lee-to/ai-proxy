use tracing::{debug, trace};

use super::{ScanMatch, SecretScanner};
use crate::config::EntropyScannerConfig;

/// Layer 2: Shannon entropy analysis with keyword proximity detection.
pub struct EntropyScanner {
    threshold: f64,
    min_length: usize,
    max_length: usize,
    keywords: Vec<String>,
    keyword_proximity: usize,
}

impl EntropyScanner {
    pub fn new(config: &EntropyScannerConfig) -> Self {
        debug!(
            threshold = config.threshold,
            min_length = config.min_length,
            max_length = config.max_length,
            keyword_count = config.keywords.len(),
            keyword_proximity = config.keyword_proximity,
            "Initializing entropy scanner"
        );
        Self {
            threshold: config.threshold,
            min_length: config.min_length,
            max_length: config.max_length,
            keywords: config.keywords.iter().map(|k| k.to_lowercase()).collect(),
            keyword_proximity: config.keyword_proximity,
        }
    }

    /// Calculate Shannon entropy of a string.
    fn shannon_entropy(s: &str) -> f64 {
        let len = s.len() as f64;
        if len == 0.0 {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &b in s.as_bytes() {
            freq[b as usize] += 1;
        }

        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Check if any keyword appears within `proximity` bytes of position `pos` in `text`.
    fn keyword_nearby(&self, text: &str, pos: usize, len: usize) -> bool {
        let search_start = floor_char_boundary(text, pos.saturating_sub(self.keyword_proximity));
        let search_end = ceil_char_boundary(
            text,
            pos.saturating_add(len)
                .saturating_add(self.keyword_proximity)
                .min(text.len()),
        );
        let search_area = text[search_start..search_end].to_lowercase();

        self.keywords
            .iter()
            .any(|kw| search_area.contains(kw.as_str()))
    }

    /// Extract candidate tokens from text — contiguous non-whitespace sequences
    /// that look like potential secrets (alphanumeric + special chars).
    fn extract_candidates<'a>(&self, text: &'a str) -> Vec<(usize, &'a str)> {
        let mut candidates = Vec::new();
        let mut start = None;

        for (i, c) in text.char_indices() {
            if !c.is_whitespace()
                && c != '"'
                && c != '\''
                && c != ','
                && c != '{'
                && c != '}'
                && c != '['
                && c != ']'
            {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                let token = &text[s..i];
                if token.len() >= self.min_length && token.len() <= self.max_length {
                    candidates.push((s, token));
                }
                start = None;
            }
        }

        // Handle last token
        if let Some(s) = start {
            let token = &text[s..];
            if token.len() >= self.min_length && token.len() <= self.max_length {
                candidates.push((s, token));
            }
        }

        candidates
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

impl SecretScanner for EntropyScanner {
    fn scan(&self, text: &str) -> Vec<ScanMatch> {
        let mut matches = Vec::new();
        let candidates = self.extract_candidates(text);

        trace!(
            candidate_count = candidates.len(),
            "Extracted entropy candidates"
        );

        for (pos, token) in candidates {
            let entropy = Self::shannon_entropy(token);

            if entropy >= self.threshold && self.keyword_nearby(text, pos, token.len()) {
                trace!(
                    token_start = pos,
                    token_len = token.len(),
                    entropy = entropy,
                    "High-entropy token near keyword detected"
                );
                matches.push(ScanMatch::new(
                    token.to_string(),
                    "entropy",
                    "high_entropy_near_keyword",
                    pos,
                    pos + token.len(),
                    0.70,
                ));
            }
        }

        debug!(matches_found = matches.len(), "Entropy scan completed");
        matches
    }

    fn name(&self) -> &str {
        "entropy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EntropyScannerConfig;

    fn test_config() -> EntropyScannerConfig {
        EntropyScannerConfig {
            enabled: true,
            threshold: 4.0,
            min_length: 20,
            max_length: 256,
            keywords: vec![
                "key".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "password".to_string(),
            ],
            keyword_proximity: 50,
        }
    }

    #[test]
    fn test_shannon_entropy_low() {
        let entropy = EntropyScanner::shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa");
        assert!(
            entropy < 1.0,
            "Repeated chars should have low entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_shannon_entropy_high() {
        let entropy = EntropyScanner::shannon_entropy("aB3$xZ9!mK2@pL5#nR8&");
        assert!(
            entropy > 4.0,
            "Random-looking string should have high entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_detect_high_entropy_near_keyword() {
        let scanner = EntropyScanner::new(&test_config());
        let text = "secret_key = aB3xZ9mK2pL5nR8vQ4wE7jF1hG6";
        let matches = scanner.scan(text);
        assert!(
            !matches.is_empty(),
            "Should detect high-entropy value near 'key' keyword"
        );
    }

    #[test]
    fn test_no_match_without_keyword() {
        let scanner = EntropyScanner::new(&test_config());
        // High-entropy string but no keyword nearby
        let text = "data = aB3xZ9mK2pL5nR8vQ4wE7jF1hG6";
        let matches = scanner.scan(text);
        assert!(
            matches.is_empty(),
            "Should not match without nearby keyword"
        );
    }

    #[test]
    fn test_no_match_low_entropy() {
        let scanner = EntropyScanner::new(&test_config());
        let text = "secret_key = aaaaaaaaaaaaaaaaaaaaaaaaa";
        let matches = scanner.scan(text);
        assert!(matches.is_empty(), "Should not match low-entropy string");
    }

    #[test]
    fn test_short_tokens_ignored() {
        let scanner = EntropyScanner::new(&test_config());
        let text = "token = abc123";
        let matches = scanner.scan(text);
        assert!(matches.is_empty(), "Short tokens should be ignored");
    }

    #[test]
    fn keyword_proximity_handles_multibyte_boundaries() {
        let scanner = EntropyScanner::new(&test_config());
        let text = "секрет token = aB3xZ9mK2pL5nR8vQ4wE7jF1hG6";

        let matches = scanner.scan(text);

        assert!(!matches.is_empty());
    }
}
