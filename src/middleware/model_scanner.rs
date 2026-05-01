use std::time::Duration;
use std::{sync::OnceLock, sync::mpsc};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{
    ScanMatch, SecretScanner, default_restore_policy_for_category, sensitivity_class_for_category,
};
use crate::config::ModelScannerConfig;

#[derive(Clone)]
pub struct ModelScanner {
    config: ModelScannerConfig,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct ModelRequest<'a> {
    model: &'a str,
    messages: Vec<ModelMessage<'a>>,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct ModelMessage<'a> {
    role: &'a str,
    content: String,
}

#[derive(Debug, Deserialize)]
struct DirectModelResponse {
    findings: Vec<ModelFinding>,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
struct ModelFinding {
    start: usize,
    end: usize,
    category: String,
    confidence: f32,
    #[allow(dead_code)]
    rationale_code: Option<String>,
}

impl ModelScanner {
    pub fn new(config: &ModelScannerConfig) -> Self {
        info!(
            mode = %config.mode,
            endpoint = %config.endpoint,
            model = %config.model,
            timeout_ms = config.timeout_ms,
            max_chars = config.max_chars,
            fail_policy = %config.fail_policy,
            categories = ?config.categories,
            "Initializing model scanner"
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .no_proxy()
            .build()
            .expect("model scanner HTTP client");
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
        let request = ModelRequest {
            model: &self.config.model,
            temperature: 0.0,
            messages: vec![
                ModelMessage {
                    role: "system",
                    content: "Find sensitive data spans. Return strict JSON only: {\"findings\":[{\"start\":0,\"end\":1,\"category\":\"email\",\"confidence\":0.9,\"rationale_code\":\"semantic_pii\"}]}. Use byte offsets in the provided text. Do not quote or repeat sensitive content.".to_string(),
                },
                ModelMessage {
                    role: "user",
                    content: sample.to_string(),
                },
            ],
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

        let parsed =
            parse_model_findings(&body).map_err(|error| format!("parse_failed:{error}"))?;
        Ok(self.validated_findings(sample, parsed))
    }

    fn validated_findings(&self, text: &str, findings: Vec<ModelFinding>) -> Vec<ScanMatch> {
        let allowed_categories: Vec<String> = self
            .config
            .categories
            .iter()
            .map(|category| category.to_ascii_lowercase())
            .collect();
        findings
            .into_iter()
            .filter_map(|finding| {
                let category = finding.category.to_ascii_lowercase();
                if finding.confidence < 0.70 {
                    debug!(
                        category = %category,
                        confidence = finding.confidence,
                        "Dropping low-confidence model finding"
                    );
                    return None;
                }
                if !allowed_categories.is_empty() && !allowed_categories.contains(&category) {
                    debug!(
                        category = %category,
                        "Dropping model finding for disabled category"
                    );
                    return None;
                }
                if finding.start >= finding.end
                    || finding.end > text.len()
                    || !text.is_char_boundary(finding.start)
                    || !text.is_char_boundary(finding.end)
                {
                    warn!(
                        category = %category,
                        start = finding.start,
                        end = finding.end,
                        "Dropping model finding with invalid span"
                    );
                    return None;
                }
                let mut scan_match = ScanMatch::new(
                    text[finding.start..finding.end].to_string(),
                    "model",
                    category.clone(),
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

impl SecretScanner for ModelScanner {
    fn scan(&self, text: &str) -> Vec<ScanMatch> {
        if text.is_empty() {
            return Vec::new();
        }

        let scanner = self.clone();
        let text = text.to_string();
        let fallback_text = text.clone();
        let (sender, receiver) = mpsc::channel();
        model_scanner_runtime().spawn(async move {
            let _ = sender.send(scanner.scan_async(&text).await);
        });
        let result = receiver
            .recv()
            .unwrap_or_else(|_| Err("runtime_channel_closed".to_string()));
        match result {
            Ok(findings) => {
                debug!(
                    mode = %self.config.mode,
                    model = %self.config.model,
                    findings = findings.len(),
                    "Model scanner completed"
                );
                findings
            }
            Err(error) => {
                warn!(
                    mode = %self.config.mode,
                    model = %self.config.model,
                    error_class = %error,
                    fail_policy = %self.config.fail_policy,
                    "Model scanner failed"
                );
                if self.config.fail_policy == "fail_closed" && !fallback_text.is_empty() {
                    vec![ScanMatch::new(
                        fallback_text.clone(),
                        "model",
                        "generic_secret",
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
        "model"
    }
}

fn model_scanner_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("model-scanner")
            .enable_all()
            .build()
            .expect("failed to build model scanner runtime")
    })
}

fn parse_model_findings(body: &[u8]) -> Result<Vec<ModelFinding>, serde_json::Error> {
    if let Ok(direct) = serde_json::from_slice::<DirectModelResponse>(body) {
        return Ok(direct.findings);
    }
    let chat = serde_json::from_slice::<ChatResponse>(body)?;
    let Some(choice) = chat.choices.into_iter().next() else {
        return Ok(Vec::new());
    };
    let direct = serde_json::from_str::<DirectModelResponse>(&choice.message.content)?;
    Ok(direct.findings)
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

    async fn start_model_endpoint(body: &'static str) -> String {
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

    fn config(endpoint: String) -> ModelScannerConfig {
        ModelScannerConfig {
            enabled: true,
            mode: "hybrid".to_string(),
            endpoint,
            model: "local-test".to_string(),
            timeout_ms: 1000,
            max_chars: 1024,
            fail_policy: "regex_only".to_string(),
            categories: vec!["email".to_string()],
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn model_scanner_reads_mock_endpoint_findings() {
        let endpoint = start_model_endpoint(
            r#"{"findings":[{"start":6,"end":21,"category":"email","confidence":0.92,"rationale_code":"semantic_pii"}]}"#,
        )
        .await;
        let scanner = ModelScanner::new(&config(endpoint));

        let findings = scanner
            .scan_async("email ada@example.com ok")
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "email");
        assert_eq!(findings[0].value, "ada@example.com");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn model_scanner_falls_back_on_malformed_json() {
        let endpoint = start_model_endpoint(r#"{"not_findings":true}"#).await;
        let scanner = ModelScanner::new(&config(endpoint));

        let findings = scanner
            .scan_async("email ada@example.com ok")
            .await
            .unwrap_or_default();

        assert!(findings.is_empty());
    }

    #[test]
    fn parse_chat_style_response() {
        let body = br#"{"choices":[{"message":{"content":"{\"findings\":[{\"start\":0,\"end\":3,\"category\":\"email\",\"confidence\":0.91}]}"}}]}"#;
        let findings = parse_model_findings(body).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "email");
    }
}
