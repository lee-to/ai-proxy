use regex::Regex;
use tracing::{debug, trace};

use super::{ScanMatch, SecretScanner};
use crate::config::StructuralScannerConfig;

/// Layer 3: Structural pattern detection for JWT tokens, connection strings, and .env patterns.
pub struct StructuralScanner {
    detect_jwt: bool,
    detect_connection_strings: bool,
    detect_env_patterns: bool,
    jwt_regex: Regex,
    connection_string_regex: Regex,
    env_pattern_regex: Regex,
}

impl StructuralScanner {
    pub fn new(config: &StructuralScannerConfig) -> Self {
        debug!(
            detect_jwt = config.detect_jwt,
            detect_connection_strings = config.detect_connection_strings,
            detect_env_patterns = config.detect_env_patterns,
            "Initializing structural scanner"
        );

        Self {
            detect_jwt: config.detect_jwt,
            detect_connection_strings: config.detect_connection_strings,
            detect_env_patterns: config.detect_env_patterns,
            // JWT: signed or unsigned base64url header.payload[.signature]
            jwt_regex: Regex::new(
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.(?:[A-Za-z0-9_-]{10,})?(?:\b|$)"
            ).expect("jwt regex"),
            // Connection strings: protocol://user:pass@host or key=value pairs with password
            connection_string_regex: Regex::new(
                r"(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s]{10,}"
            ).expect("connection string regex"),
            // .env style: KEY=value where KEY looks like a secret variable name
            env_pattern_regex: Regex::new(
                r"(?im)^(?:export\s+)?(?:[A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|WEBHOOK[_-]?URL|DATABASE[_-]?URL|DB[_-]?URL)[A-Z0-9_]*|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN)\s*=\s*\S+"
            ).expect("env pattern regex"),
        }
    }

    fn scan_jwt(&self, text: &str) -> Vec<ScanMatch> {
        self.jwt_regex
            .find_iter(text)
            .map(|m| {
                trace!(start = m.start(), end = m.end(), "JWT token detected");
                ScanMatch::new(
                    m.as_str().to_string(),
                    "structural",
                    "jwt_token",
                    m.start(),
                    m.end(),
                    0.98,
                )
            })
            .collect()
    }

    fn scan_connection_strings(&self, text: &str) -> Vec<ScanMatch> {
        self.connection_string_regex
            .find_iter(text)
            .map(|m| {
                trace!(
                    start = m.start(),
                    end = m.end(),
                    "Connection string detected"
                );
                ScanMatch::new(
                    m.as_str().to_string(),
                    "structural",
                    "connection_string",
                    m.start(),
                    m.end(),
                    0.98,
                )
            })
            .collect()
    }

    fn scan_env_patterns(&self, text: &str) -> Vec<ScanMatch> {
        self.env_pattern_regex
            .find_iter(text)
            .map(|m| {
                trace!(start = m.start(), end = m.end(), ".env pattern detected");
                ScanMatch::new(
                    m.as_str().to_string(),
                    "structural",
                    "env_variable",
                    m.start(),
                    m.end(),
                    0.90,
                )
            })
            .collect()
    }
}

impl SecretScanner for StructuralScanner {
    fn scan(&self, text: &str) -> Vec<ScanMatch> {
        let mut matches = Vec::new();

        if self.detect_jwt {
            matches.extend(self.scan_jwt(text));
        }
        if self.detect_connection_strings {
            matches.extend(self.scan_connection_strings(text));
        }
        if self.detect_env_patterns {
            matches.extend(self.scan_env_patterns(text));
        }

        debug!(matches_found = matches.len(), "Structural scan completed");
        matches
    }

    fn name(&self) -> &str {
        "structural"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StructuralScannerConfig;

    fn full_config() -> StructuralScannerConfig {
        StructuralScannerConfig {
            enabled: true,
            detect_jwt: true,
            detect_connection_strings: true,
            detect_env_patterns: true,
        }
    }

    #[test]
    fn test_detect_jwt() {
        let scanner = StructuralScanner::new(&full_config());
        // Realistic JWT structure: header.payload.signature (base64url)
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let matches = scanner.scan(jwt);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "jwt_token");
    }

    #[test]
    fn test_detect_unsigned_jwt() {
        let scanner = StructuralScanner::new(&full_config());
        let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";
        let matches = scanner.scan(jwt);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "jwt_token");
    }

    #[test]
    fn test_detect_postgres_connection_string() {
        let scanner = StructuralScanner::new(&full_config());
        let text = "DATABASE_URL=postgresql://user:password123@localhost:5432/mydb";
        let matches = scanner.scan(text);
        // Should match both connection string and env pattern
        assert!(
            matches
                .iter()
                .any(|m| m.pattern_name == "connection_string")
        );
    }

    #[test]
    fn test_detect_mongodb_connection_string() {
        let scanner = StructuralScanner::new(&full_config());
        let text = "url: mongodb://admin:secret@cluster0.example.net:27017/production";
        let matches = scanner.scan(text);
        assert!(
            matches
                .iter()
                .any(|m| m.pattern_name == "connection_string")
        );
    }

    #[test]
    fn test_detect_env_pattern() {
        let scanner = StructuralScanner::new(&full_config());
        let text = "SECRET_KEY=my-super-secret-value-123";
        let matches = scanner.scan(text);
        assert!(matches.iter().any(|m| m.pattern_name == "env_variable"));
    }

    #[test]
    fn test_detect_export_env_pattern() {
        let scanner = StructuralScanner::new(&full_config());
        let text = "export API_KEY=sk-abc123def456";
        let matches = scanner.scan(text);
        assert!(matches.iter().any(|m| m.pattern_name == "env_variable"));
    }

    #[test]
    fn test_detect_common_provider_env_keys() {
        let scanner = StructuralScanner::new(&full_config());
        let text = "OPENAI_API_KEY=sk-proj-abc123\nSTRIPE_KEY=rk_live_123";
        let matches = scanner.scan(text);
        assert_eq!(
            matches
                .iter()
                .filter(|m| m.pattern_name == "env_variable")
                .count(),
            2
        );
    }

    #[test]
    fn test_no_match_plain_text() {
        let scanner = StructuralScanner::new(&full_config());
        let text = "This is just normal text with no secrets or patterns.";
        let matches = scanner.scan(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_disabled_detectors() {
        let config = StructuralScannerConfig {
            enabled: true,
            detect_jwt: false,
            detect_connection_strings: false,
            detect_env_patterns: false,
        };
        let scanner = StructuralScanner::new(&config);
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let matches = scanner.scan(jwt);
        assert!(matches.is_empty(), "Disabled detectors should not match");
    }
}
