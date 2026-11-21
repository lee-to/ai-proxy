use regex::Regex;
use tracing::{debug, trace, warn};

use super::{ScanMatch, SecretScanner};
use crate::config::RegexScannerConfig;

/// Compiled regex pattern with its metadata.
struct CompiledPattern {
    name: String,
    regex: Regex,
}

/// Layer 1: Pattern-based secret detection using pre-compiled regexes from config.
pub struct RegexScanner {
    patterns: Vec<CompiledPattern>,
}

impl RegexScanner {
    pub fn new(config: &RegexScannerConfig) -> Self {
        debug!(
            pattern_count = config.patterns.len(),
            "Initializing regex scanner"
        );

        let patterns: Vec<CompiledPattern> = config
            .patterns
            .iter()
            .filter_map(|p| match Regex::new(&p.pattern) {
                Ok(regex) => {
                    trace!(name = %p.name, pattern = %p.pattern, "Compiled regex pattern");
                    Some(CompiledPattern {
                        name: p.name.clone(),
                        regex,
                    })
                }
                Err(e) => {
                    warn!(
                        name = %p.name,
                        pattern = %p.pattern,
                        error = %e,
                        "Failed to compile regex pattern, skipping"
                    );
                    None
                }
            })
            .collect();

        debug!(compiled_count = patterns.len(), "Regex scanner initialized");
        Self { patterns }
    }
}

impl SecretScanner for RegexScanner {
    fn scan(&self, text: &str) -> Vec<ScanMatch> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(text) {
                trace!(
                    pattern_name = %pattern.name,
                    start = m.start(),
                    end = m.end(),
                    "Regex match found"
                );
                matches.push(ScanMatch::new(
                    m.as_str().to_string(),
                    "regex",
                    pattern.name.clone(),
                    m.start(),
                    m.end(),
                    0.95,
                ));
            }
        }

        debug!(matches_found = matches.len(), "Regex scan completed");
        matches
    }

    fn name(&self) -> &str {
        "regex"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RegexPattern, RegexScannerConfig};

    fn test_config() -> RegexScannerConfig {
        RegexScannerConfig {
            enabled: true,
            patterns: vec![
                RegexPattern {
                    name: "aws_access_key".to_string(),
                    pattern: "AKIA[0-9A-Z]{16}".to_string(),
                },
                RegexPattern {
                    name: "github_token".to_string(),
                    pattern: "gh[pousr]_[A-Za-z0-9_]{36,}".to_string(),
                },
                RegexPattern {
                    name: "anthropic_api_key".to_string(),
                    pattern: "sk-ant-[A-Za-z0-9-]{20,}".to_string(),
                },
            ],
        }
    }

    #[test]
    fn example_config_recognizes_supported_provider_key_formats() {
        let config: crate::config::Config =
            toml::from_str(include_str!("../../config.example.toml")).unwrap();
        let scanner = RegexScanner::new(&config.scanner.regex);
        let sample = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (key, name) in [
            (
                format!("sk-ant-api03-synthetic_{sample}"),
                "anthropic_api_key",
            ),
            (format!("sk-proj-synthetic_{sample}"), "openai_api_key"),
            (format!("sk-svcacct-synthetic_{sample}"), "openai_api_key"),
            (format!("sk-admin-synthetic_{sample}"), "openai_api_key"),
            (format!("sk-{sample}"), "openai_api_key"),
        ] {
            let matches = scanner.scan(&key);
            assert!(
                matches
                    .iter()
                    .any(|m| m.pattern_name == name && m.value == key)
            );
        }
    }

    #[test]
    fn test_detect_aws_key() {
        let scanner = RegexScanner::new(&test_config());
        let text = "my key is AKIAIOSFODNN7EXAMPLE ok";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "aws_access_key");
        assert_eq!(matches[0].value, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches[0].category, "api_key");
    }

    #[test]
    fn test_detect_github_token() {
        let scanner = RegexScanner::new(&test_config());
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let text = format!("token: {}", token);
        let matches = scanner.scan(&text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "github_token");
    }

    #[test]
    fn test_detect_anthropic_key() {
        let scanner = RegexScanner::new(&test_config());
        let text = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "anthropic_api_key");
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = RegexScanner::new(&test_config());
        let text = "This is just normal text with no secrets.";
        let matches = scanner.scan(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_multiple_matches() {
        let scanner = RegexScanner::new(&test_config());
        let text = "keys: AKIAIOSFODNN7EXAMPLE and sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_invalid_pattern_skipped() {
        let config = RegexScannerConfig {
            enabled: true,
            patterns: vec![
                RegexPattern {
                    name: "bad_pattern".to_string(),
                    pattern: "[invalid".to_string(),
                },
                RegexPattern {
                    name: "aws_access_key".to_string(),
                    pattern: "AKIA[0-9A-Z]{16}".to_string(),
                },
            ],
        };
        let scanner = RegexScanner::new(&config);
        let text = "AKIAIOSFODNN7EXAMPLE";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 1);
    }
}
