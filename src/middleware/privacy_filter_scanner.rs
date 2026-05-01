use std::process::Stdio;
use std::time::Duration;
use std::{sync::OnceLock, sync::mpsc};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

use super::{
    ScanMatch, SecretScanner, default_restore_policy_for_category, sensitivity_class_for_category,
};
use crate::config::PrivacyFilterScannerConfig;

#[derive(Clone)]
pub struct PrivacyFilterScanner {
    config: PrivacyFilterScannerConfig,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct PrivacyFilterRequest<'a> {
    text: &'a str,
    categories: &'a [String],
}

#[derive(Debug, Deserialize)]
struct PrivacyFilterResponse {
    #[serde(default, alias = "spans")]
    findings: Vec<PrivacyFilterFinding>,
}

#[derive(Debug, Deserialize)]
struct OpfResponse {
    #[serde(default)]
    detected_spans: Vec<OpfDetectedSpan>,
}

#[derive(Debug, Deserialize)]
struct OpfDetectedSpan {
    start: usize,
    end: usize,
    label: String,
}

#[derive(Debug, Deserialize)]
struct PrivacyFilterFinding {
    start: usize,
    end: usize,
    #[serde(alias = "label")]
    category: String,
    #[serde(default = "default_confidence")]
    confidence: f32,
}

impl PrivacyFilterScanner {
    pub fn new(config: &PrivacyFilterScannerConfig) -> Self {
        info!(
            endpoint = %config.endpoint,
            command = %config.command,
            timeout_ms = config.timeout_ms,
            max_chars = config.max_chars,
            fail_policy = %config.fail_policy,
            categories = ?config.categories,
            min_confidence = config.min_confidence,
            "Initializing privacy filter scanner"
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .no_proxy()
            .build()
            .expect("privacy filter HTTP client");
        Self {
            config: config.clone(),
            client,
        }
    }

    async fn scan_async(&self, text: &str) -> Result<Vec<ScanMatch>, String> {
        let sample = if text.len() > self.config.max_chars {
            &text[..safe_prefix_boundary(text, self.config.max_chars)]
        } else {
            text
        };
        if !self.config.command.trim().is_empty() {
            return self.scan_command(sample).await;
        }

        let request = PrivacyFilterRequest {
            text: sample,
            categories: &self.config.categories,
        };

        let response = self
            .client
            .post(&self.config.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|error| format!("request_failed:{error}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("bad_status:{}", status.as_u16()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("body_failed:{error}"))?;
        let parsed = serde_json::from_slice::<PrivacyFilterResponse>(&body)
            .map_err(|error| format!("parse_failed:{error}"))?;

        Ok(self.validated_findings(sample, parsed.findings))
    }

    async fn scan_command(&self, text: &str) -> Result<Vec<ScanMatch>, String> {
        let mut command = Command::new(self.config.command.trim());
        command
            .args(&self.config.command_args)
            .arg("--format")
            .arg("json")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|error| format!("command_spawn_failed:{error}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "command_stdin_unavailable".to_string())?;
        stdin
            .write_all(text.as_bytes())
            .await
            .map_err(|error| format!("command_stdin_failed:{error}"))?;
        drop(stdin);

        let timeout = Duration::from_millis(self.config.timeout_ms);
        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| "command_timeout".to_string())?
            .map_err(|error| format!("command_wait_failed:{error}"))?;
        if !output.status.success() {
            return Err(format!("command_bad_status:{}", output.status));
        }
        let parsed = parse_opf_response_stdout(&output.stdout)
            .map_err(|error| format!("command_parse_failed:{error}"))?;
        let findings = parsed
            .detected_spans
            .into_iter()
            .map(|span| PrivacyFilterFinding {
                start: span.start,
                end: span.end,
                category: span.label,
                confidence: 1.0,
            })
            .collect();

        Ok(self.validated_findings(text, findings))
    }

    fn validated_findings(
        &self,
        text: &str,
        findings: Vec<PrivacyFilterFinding>,
    ) -> Vec<ScanMatch> {
        let allowed_labels: Vec<String> = self
            .config
            .categories
            .iter()
            .map(|category| category.to_ascii_lowercase())
            .collect();
        let allowed_categories: Vec<String> = allowed_labels
            .iter()
            .map(|label| category_for_privacy_filter_label(label))
            .collect();
        findings
            .into_iter()
            .filter_map(|finding| {
                let raw_label = finding.category.to_ascii_lowercase();
                let category = category_for_privacy_filter_label(&raw_label);
                if finding.confidence < self.config.min_confidence {
                    debug!(
                        label = %raw_label,
                        confidence = finding.confidence,
                        min_confidence = self.config.min_confidence,
                        "Dropping low-confidence privacy filter finding"
                    );
                    return None;
                }
                if !allowed_labels.is_empty()
                    && !allowed_labels.contains(&raw_label)
                    && !allowed_categories.contains(&category)
                {
                    debug!(
                        label = %raw_label,
                        "Dropping privacy filter finding for disabled label"
                    );
                    return None;
                }
                if finding.start >= finding.end
                    || finding.end > text.len()
                    || !text.is_char_boundary(finding.start)
                    || !text.is_char_boundary(finding.end)
                {
                    warn!(
                        label = %raw_label,
                        start = finding.start,
                        end = finding.end,
                        "Dropping privacy filter finding with invalid byte span"
                    );
                    return None;
                }

                let mut scan_match = ScanMatch::new(
                    text[finding.start..finding.end].to_string(),
                    "privacy_filter",
                    raw_label,
                    finding.start,
                    finding.end,
                    finding.confidence,
                );
                scan_match.category = category;
                scan_match.sensitivity_class =
                    sensitivity_class_for_category(&scan_match.category).to_string();
                scan_match.restore_policy =
                    default_restore_policy_for_category(&scan_match.category).to_string();
                Some(scan_match)
            })
            .collect()
    }
}

impl SecretScanner for PrivacyFilterScanner {
    fn scan(&self, text: &str) -> Vec<ScanMatch> {
        if text.is_empty() {
            return Vec::new();
        }

        let scanner = self.clone();
        let text = text.to_string();
        let fallback_text = text.clone();
        let (sender, receiver) = mpsc::channel();
        privacy_filter_runtime().spawn(async move {
            let _ = sender.send(scanner.scan_async(&text).await);
        });
        let result = receiver
            .recv()
            .unwrap_or_else(|_| Err("runtime_channel_closed".to_string()));

        match result {
            Ok(findings) => {
                debug!(
                    findings = findings.len(),
                    "Privacy filter scanner completed"
                );
                findings
            }
            Err(error) => {
                warn!(
                    error_class = %error,
                    fail_policy = %self.config.fail_policy,
                    "Privacy filter scanner failed"
                );
                if self.config.fail_policy == "fail_closed" && !fallback_text.is_empty() {
                    vec![ScanMatch::new(
                        fallback_text.clone(),
                        "privacy_filter",
                        "secret",
                        0,
                        fallback_text.len(),
                        0.50,
                    )]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn name(&self) -> &str {
        "privacy_filter"
    }
}

fn privacy_filter_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("privacy-filter-scanner")
            .enable_all()
            .build()
            .expect("failed to build privacy filter scanner runtime")
    })
}

fn category_for_privacy_filter_label(label: &str) -> String {
    match label {
        "private_person" | "person" | "private_name" | "name" => "person_name",
        "private_email" | "email" => "email",
        "private_phone" | "phone" => "phone",
        "private_address" | "address" => "address",
        "private_url" | "url" => "url",
        "private_date" | "date" => "date",
        "account_number" | "private_account" | "account" => "account_number",
        "private_ip" | "ip_address" | "ip" => "ip_address",
        "secret" | "private_secret" => "generic_secret",
        "api_key" | "private_api_key" => "api_key",
        "token" | "private_token" => "token",
        "password" | "private_password" => "password",
        "private_key" => "private_key",
        _ => "generic_secret",
    }
    .to_string()
}

fn default_confidence() -> f32 {
    1.0
}

fn parse_opf_response_stdout(stdout: &[u8]) -> Result<OpfResponse, serde_json::Error> {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<OpfResponse>()
        .next()
        .unwrap_or_else(|| serde_json::from_slice(stdout))
}

fn safe_prefix_boundary(text: &str, max_chars: usize) -> usize {
    let mut boundary = 0;
    for (idx, _) in text.char_indices() {
        if idx > max_chars {
            break;
        }
        boundary = idx;
    }
    boundary.max(1).min(text.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::any};
    use tokio::net::TcpListener;

    async fn start_privacy_filter_endpoint(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let app = Router::new().fallback(any(move || async move {
                axum::response::Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }));
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/scan")
    }

    fn config(endpoint: String) -> PrivacyFilterScannerConfig {
        PrivacyFilterScannerConfig {
            enabled: true,
            endpoint,
            command: String::new(),
            command_args: Vec::new(),
            timeout_ms: 1000,
            max_chars: 1024,
            fail_policy: "regex_only".to_string(),
            categories: vec!["private_email".to_string(), "private_person".to_string()],
            min_confidence: 0.70,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn privacy_filter_scanner_reads_mock_endpoint_findings() {
        let endpoint = start_privacy_filter_endpoint(
            r#"{"findings":[{"start":6,"end":21,"category":"private_email","confidence":0.93}]}"#,
        )
        .await;
        let scanner = PrivacyFilterScanner::new(&config(endpoint));

        let findings = scanner
            .scan_async("email ada@example.com ok")
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scanner, "privacy_filter");
        assert_eq!(findings[0].pattern_name, "private_email");
        assert_eq!(findings[0].category, "email");
        assert_eq!(findings[0].sensitivity_class, "pii");
        assert_eq!(findings[0].value, "ada@example.com");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn privacy_filter_scanner_accepts_spans_alias() {
        let endpoint = start_privacy_filter_endpoint(
            r#"{"spans":[{"start":0,"end":3,"label":"private_person","confidence":0.91}]}"#,
        )
        .await;
        let scanner = PrivacyFilterScanner::new(&config(endpoint));

        let findings = scanner.scan_async("Ada Lovelace").await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "person_name");
        assert_eq!(findings[0].value, "Ada");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn privacy_filter_scanner_reads_opf_command_json() {
        let command_path =
            std::env::temp_dir().join(format!("ai-proxy-opf-mock-{}", std::process::id()));
        std::fs::write(
            &command_path,
            "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"detected_spans\":[{\"start\":6,\"end\":21,\"label\":\"private_email\",\"text\":\"ada@example.com\",\"placeholder\":\"\"}]}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&command_path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut config = config(String::new());
        config.command = command_path.to_string_lossy().to_string();
        let scanner = PrivacyFilterScanner::new(&config);

        let findings = scanner
            .scan_async("email ada@example.com ok")
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_name, "private_email");
        assert_eq!(findings[0].category, "email");
        assert_eq!(findings[0].value, "ada@example.com");

        let _ = std::fs::remove_file(command_path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn privacy_filter_scanner_passes_command_args() {
        let command_path =
            std::env::temp_dir().join(format!("ai-proxy-opf-args-mock-{}", std::process::id()));
        let args_path =
            std::env::temp_dir().join(format!("ai-proxy-opf-args-seen-{}", std::process::id()));
        std::fs::write(
            &command_path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\ncat >/dev/null\nprintf '%s\\n' '{{\"detected_spans\":[]}}'\n",
                args_path.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&command_path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut config = config(String::new());
        config.command = command_path.to_string_lossy().to_string();
        config.command_args = vec!["--device".to_string(), "cpu".to_string()];
        let scanner = PrivacyFilterScanner::new(&config);

        scanner
            .scan_async("email ada@example.com ok")
            .await
            .unwrap();

        let args = std::fs::read_to_string(&args_path).unwrap();
        assert_eq!(args.trim(), "--device cpu --format json");

        let _ = std::fs::remove_file(command_path);
        let _ = std::fs::remove_file(args_path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn privacy_filter_scanner_rejects_invalid_utf8_spans() {
        let endpoint = start_privacy_filter_endpoint(
            r#"{"findings":[{"start":1,"end":3,"category":"private_person","confidence":0.99}]}"#,
        )
        .await;
        let scanner = PrivacyFilterScanner::new(&config(endpoint));

        let findings = scanner.scan_async("Ада").await.unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn privacy_filter_category_mapping() {
        assert_eq!(
            category_for_privacy_filter_label("private_email"),
            "email".to_string()
        );
        assert_eq!(
            category_for_privacy_filter_label("account_number"),
            "account_number".to_string()
        );
        assert_eq!(
            category_for_privacy_filter_label("secret"),
            "generic_secret".to_string()
        );
    }

    #[test]
    fn opf_response_parser_ignores_trailing_color_output() {
        let parsed = parse_opf_response_stdout(
            br#"{"detected_spans":[{"start":0,"end":3,"label":"private_person"}]}
color legend: private_person
color coded text:
Ada"#,
        )
        .unwrap();

        assert_eq!(parsed.detected_spans.len(), 1);
        assert_eq!(parsed.detected_spans[0].label, "private_person");
    }
}
