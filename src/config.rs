use serde::Deserialize;
use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub dashboard: DashboardConfig,
    pub redaction: RedactionConfig,
    pub scanner: ScannerConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    #[serde(alias = "upstream_url")]
    pub anthropic_upstream_url: String,
    #[serde(default = "default_codex_upstream_url")]
    pub codex_upstream_url: String,
    #[serde(default = "default_codex_subscription_url")]
    pub codex_subscription_url: String,
    #[serde(default = "default_true")]
    pub codex_subscription_routing_enabled: bool,
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u64,
    #[serde(default)]
    pub mitm_enabled: bool,
    #[serde(default)]
    pub mitm_ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub mitm_ca_key_path: Option<PathBuf>,
    #[serde(default = "default_mitm_cert_cache_size")]
    pub mitm_cert_cache_size: usize,
    #[serde(default)]
    pub mitm_excluded_hosts: Vec<String>,
    #[serde(default = "default_websocket_mode")]
    pub websocket_mode: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DashboardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dashboard_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_dashboard_token_path")]
    pub token_path: PathBuf,
    #[serde(default = "default_dashboard_sqlite_path")]
    pub sqlite_path: PathBuf,
    #[serde(default = "default_dashboard_retention_hours")]
    pub retention_hours: u64,
    #[serde(default)]
    pub capture: DashboardCaptureConfig,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_dashboard_listen_addr(),
            token_path: default_dashboard_token_path(),
            sqlite_path: default_dashboard_sqlite_path(),
            retention_hours: default_dashboard_retention_hours(),
            capture: DashboardCaptureConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DashboardCaptureConfig {
    #[serde(default)]
    pub prompts: bool,
    #[serde(default)]
    pub responses: bool,
    #[serde(default = "default_dashboard_capture_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_true")]
    pub redact_before_store: bool,
}

impl Default for DashboardCaptureConfig {
    fn default() -> Self {
        Self {
            prompts: false,
            responses: false,
            max_body_bytes: default_dashboard_capture_max_body_bytes(),
            redact_before_store: true,
        }
    }
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024
}
fn default_codex_upstream_url() -> String {
    "https://api.openai.com".to_string()
}
fn default_codex_subscription_url() -> String {
    "https://chatgpt.com/backend-api/codex/responses".to_string()
}
fn default_connect_timeout() -> u64 {
    10
}
fn default_request_timeout() -> u64 {
    0
}
fn default_rate_limit_rps() -> u64 {
    50
}
fn default_mitm_cert_cache_size() -> usize {
    256
}
fn default_true() -> bool {
    true
}
fn default_websocket_mode() -> String {
    "inspect".to_string()
}
fn default_dashboard_listen_addr() -> String {
    "127.0.0.1:18081".to_string()
}
fn default_dashboard_token_path() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ai-proxy")
        .join("dashboard.token")
}
fn default_dashboard_sqlite_path() -> PathBuf {
    PathBuf::from("ai-proxy-telemetry.sqlite")
}
fn default_dashboard_retention_hours() -> u64 {
    24
}
fn default_dashboard_capture_max_body_bytes() -> usize {
    8192
}
fn default_restorable_categories() -> Vec<String> {
    vec!["email".to_string(), "phone".to_string()]
}
fn default_model_mode() -> String {
    "hybrid".to_string()
}
fn default_model_timeout_ms() -> u64 {
    750
}
fn default_model_max_chars() -> usize {
    8192
}
fn default_model_fail_policy() -> String {
    "regex_only".to_string()
}
fn default_model_categories() -> Vec<String> {
    default_restorable_categories()
}
fn default_privacy_filter_timeout_ms() -> u64 {
    750
}
fn default_privacy_filter_max_chars() -> usize {
    8192
}
fn default_privacy_filter_fail_policy() -> String {
    "regex_only".to_string()
}
fn default_privacy_filter_categories() -> Vec<String> {
    vec![
        "private_person".to_string(),
        "private_email".to_string(),
        "private_phone".to_string(),
        "private_address".to_string(),
        "private_url".to_string(),
        "private_date".to_string(),
        "account_number".to_string(),
        "secret".to_string(),
    ]
}
fn default_privacy_filter_min_confidence() -> f32 {
    0.70
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedactionConfig {
    pub strategy: String,
    pub prefix_len: usize,
    pub suffix_len: usize,
    pub mask: String,
    #[serde(default)]
    pub response_restore_enabled: bool,
    #[serde(default = "default_restorable_categories")]
    pub restorable_categories: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub scan_scope: String,
    pub header_whitelist: Vec<String>,
    #[serde(default)]
    pub model: ModelScannerConfig,
    #[serde(default)]
    pub privacy_filter: PrivacyFilterScannerConfig,
    pub regex: RegexScannerConfig,
    pub entropy: EntropyScannerConfig,
    pub structural: StructuralScannerConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModelScannerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_model_mode")]
    pub mode: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub model: String,
    #[serde(default = "default_model_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_model_max_chars")]
    pub max_chars: usize,
    #[serde(default = "default_model_fail_policy")]
    pub fail_policy: String,
    #[serde(default = "default_model_categories")]
    pub categories: Vec<String>,
}

impl Default for ModelScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_model_mode(),
            endpoint: String::new(),
            model: String::new(),
            timeout_ms: default_model_timeout_ms(),
            max_chars: default_model_max_chars(),
            fail_policy: default_model_fail_policy(),
            categories: default_model_categories(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrivacyFilterScannerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub command_args: Vec<String>,
    #[serde(default = "default_privacy_filter_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_privacy_filter_max_chars")]
    pub max_chars: usize,
    #[serde(default = "default_privacy_filter_fail_policy")]
    pub fail_policy: String,
    #[serde(default = "default_privacy_filter_categories")]
    pub categories: Vec<String>,
    #[serde(default = "default_privacy_filter_min_confidence")]
    pub min_confidence: f32,
}

impl Default for PrivacyFilterScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            command: String::new(),
            command_args: Vec::new(),
            timeout_ms: default_privacy_filter_timeout_ms(),
            max_chars: default_privacy_filter_max_chars(),
            fail_policy: default_privacy_filter_fail_policy(),
            categories: default_privacy_filter_categories(),
            min_confidence: default_privacy_filter_min_confidence(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegexScannerConfig {
    pub enabled: bool,
    pub patterns: Vec<RegexPattern>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegexPattern {
    pub name: String,
    pub pattern: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EntropyScannerConfig {
    pub enabled: bool,
    pub threshold: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub keywords: Vec<String>,
    pub keyword_proximity: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StructuralScannerConfig {
    pub enabled: bool,
    pub detect_jwt: bool,
    pub detect_connection_strings: bool,
    pub detect_env_patterns: bool,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading configuration");

        let content = std::fs::read_to_string(path)?;
        debug!(size_bytes = content.len(), "Config file read");

        let mut config: Config = toml::from_str(&content)?;
        config.apply_env_overrides()?;
        config.validate()?;
        info!(
            listen_addr = %config.proxy.listen_addr,
            anthropic_upstream_url = %config.proxy.anthropic_upstream_url,
            codex_upstream_url = %config.proxy.codex_upstream_url,
            scan_scope = %config.scanner.scan_scope,
            scanner_enabled = config.scanner.enabled,
            rate_limit_enabled = config.proxy.rate_limit_enabled,
            mitm_enabled = config.proxy.mitm_enabled,
            mitm_cert_cache_size = config.proxy.mitm_cert_cache_size,
            mitm_excluded_hosts = config.proxy.mitm_excluded_hosts.len(),
            websocket_mode = %config.proxy.websocket_mode,
            dashboard_enabled = config.dashboard.enabled,
            dashboard_listen_addr = %config.dashboard.listen_addr,
            dashboard_retention_hours = config.dashboard.retention_hours,
            dashboard_sqlite_path_set = !config.dashboard.sqlite_path.as_os_str().is_empty(),
            regex_patterns_count = config.scanner.regex.patterns.len(),
            "Configuration loaded successfully"
        );

        Ok(config)
    }

    fn apply_env_overrides(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        override_string("AI_PROXY_LISTEN_ADDR", &mut self.proxy.listen_addr);
        override_string(
            "AI_PROXY_ANTHROPIC_UPSTREAM_URL",
            &mut self.proxy.anthropic_upstream_url,
        );
        override_string(
            "AI_PROXY_UPSTREAM_URL",
            &mut self.proxy.anthropic_upstream_url,
        );
        override_string(
            "AI_PROXY_CODEX_UPSTREAM_URL",
            &mut self.proxy.codex_upstream_url,
        );
        override_string(
            "AI_PROXY_CODEX_SUBSCRIPTION_URL",
            &mut self.proxy.codex_subscription_url,
        );
        override_bool(
            "AI_PROXY_CODEX_SUBSCRIPTION_ROUTING_ENABLED",
            &mut self.proxy.codex_subscription_routing_enabled,
        )?;
        override_parse("AI_PROXY_MAX_BODY_SIZE", &mut self.proxy.max_body_size)?;
        override_parse(
            "AI_PROXY_CONNECT_TIMEOUT_SECS",
            &mut self.proxy.connect_timeout_secs,
        )?;
        override_parse(
            "AI_PROXY_REQUEST_TIMEOUT_SECS",
            &mut self.proxy.request_timeout_secs,
        )?;
        override_parse("AI_PROXY_RATE_LIMIT_RPS", &mut self.proxy.rate_limit_rps)?;
        override_bool(
            "AI_PROXY_RATE_LIMIT_ENABLED",
            &mut self.proxy.rate_limit_enabled,
        )?;
        override_bool("AI_PROXY_MITM_ENABLED", &mut self.proxy.mitm_enabled)?;
        override_optional_path(
            "AI_PROXY_MITM_CA_CERT_PATH",
            &mut self.proxy.mitm_ca_cert_path,
        );
        override_optional_path(
            "AI_PROXY_MITM_CA_KEY_PATH",
            &mut self.proxy.mitm_ca_key_path,
        );
        override_parse(
            "AI_PROXY_MITM_CERT_CACHE_SIZE",
            &mut self.proxy.mitm_cert_cache_size,
        )?;
        override_string_list(
            "AI_PROXY_MITM_EXCLUDED_HOSTS",
            &mut self.proxy.mitm_excluded_hosts,
        );
        override_string("AI_PROXY_WEBSOCKET_MODE", &mut self.proxy.websocket_mode);
        override_bool("AI_PROXY_DASHBOARD_ENABLED", &mut self.dashboard.enabled)?;
        override_string(
            "AI_PROXY_DASHBOARD_LISTEN_ADDR",
            &mut self.dashboard.listen_addr,
        );
        override_path(
            "AI_PROXY_DASHBOARD_TOKEN_PATH",
            &mut self.dashboard.token_path,
        );
        override_path(
            "AI_PROXY_DASHBOARD_SQLITE_PATH",
            &mut self.dashboard.sqlite_path,
        );
        override_parse(
            "AI_PROXY_DASHBOARD_RETENTION_HOURS",
            &mut self.dashboard.retention_hours,
        )?;
        override_bool(
            "AI_PROXY_DASHBOARD_CAPTURE_PROMPTS",
            &mut self.dashboard.capture.prompts,
        )?;
        override_bool(
            "AI_PROXY_DASHBOARD_CAPTURE_RESPONSES",
            &mut self.dashboard.capture.responses,
        )?;
        override_parse(
            "AI_PROXY_DASHBOARD_CAPTURE_MAX_BODY_BYTES",
            &mut self.dashboard.capture.max_body_bytes,
        )?;
        override_bool(
            "AI_PROXY_DASHBOARD_CAPTURE_REDACT_BEFORE_STORE",
            &mut self.dashboard.capture.redact_before_store,
        )?;
        override_bool(
            "AI_PROXY_SECRET_SCANNING_ENABLED",
            &mut self.scanner.enabled,
        )?;
        override_string("AI_PROXY_SCAN_SCOPE", &mut self.scanner.scan_scope);
        override_bool(
            "AI_PROXY_REGEX_SCANNER_ENABLED",
            &mut self.scanner.regex.enabled,
        )?;
        override_bool(
            "AI_PROXY_ENTROPY_SCANNER_ENABLED",
            &mut self.scanner.entropy.enabled,
        )?;
        override_bool(
            "AI_PROXY_STRUCTURAL_SCANNER_ENABLED",
            &mut self.scanner.structural.enabled,
        )?;
        override_bool(
            "AI_PROXY_MODEL_SCANNER_ENABLED",
            &mut self.scanner.model.enabled,
        )?;
        override_string("AI_PROXY_MODEL_SCANNER_MODE", &mut self.scanner.model.mode);
        override_string(
            "AI_PROXY_MODEL_SCANNER_ENDPOINT",
            &mut self.scanner.model.endpoint,
        );
        override_string(
            "AI_PROXY_MODEL_SCANNER_MODEL",
            &mut self.scanner.model.model,
        );
        override_parse(
            "AI_PROXY_MODEL_SCANNER_TIMEOUT_MS",
            &mut self.scanner.model.timeout_ms,
        )?;
        override_parse(
            "AI_PROXY_MODEL_SCANNER_MAX_CHARS",
            &mut self.scanner.model.max_chars,
        )?;
        override_string(
            "AI_PROXY_MODEL_SCANNER_FAIL_POLICY",
            &mut self.scanner.model.fail_policy,
        );
        override_string_list(
            "AI_PROXY_MODEL_SCANNER_CATEGORIES",
            &mut self.scanner.model.categories,
        );
        override_bool(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_ENABLED",
            &mut self.scanner.privacy_filter.enabled,
        )?;
        override_string(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_ENDPOINT",
            &mut self.scanner.privacy_filter.endpoint,
        );
        override_string(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_COMMAND",
            &mut self.scanner.privacy_filter.command,
        );
        override_string_list(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_COMMAND_ARGS",
            &mut self.scanner.privacy_filter.command_args,
        );
        override_parse(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_TIMEOUT_MS",
            &mut self.scanner.privacy_filter.timeout_ms,
        )?;
        override_parse(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_MAX_CHARS",
            &mut self.scanner.privacy_filter.max_chars,
        )?;
        override_string(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_FAIL_POLICY",
            &mut self.scanner.privacy_filter.fail_policy,
        );
        override_string_list(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_CATEGORIES",
            &mut self.scanner.privacy_filter.categories,
        );
        override_parse(
            "AI_PROXY_PRIVACY_FILTER_SCANNER_MIN_CONFIDENCE",
            &mut self.scanner.privacy_filter.min_confidence,
        )?;
        override_string("AI_PROXY_REDACTION_STRATEGY", &mut self.redaction.strategy);
        override_bool(
            "AI_PROXY_RESPONSE_RESTORE_ENABLED",
            &mut self.redaction.response_restore_enabled,
        )?;
        override_string_list(
            "AI_PROXY_RESTORABLE_CATEGORIES",
            &mut self.redaction.restorable_categories,
        );
        override_parse(
            "AI_PROXY_REDACTION_PREFIX_LEN",
            &mut self.redaction.prefix_len,
        )?;
        override_parse(
            "AI_PROXY_REDACTION_SUFFIX_LEN",
            &mut self.redaction.suffix_len,
        )?;
        override_string("AI_PROXY_REDACTION_MASK", &mut self.redaction.mask);

        Ok(())
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.proxy.rate_limit_enabled
            && (self.proxy.rate_limit_rps == 0 || self.proxy.rate_limit_rps > u32::MAX as u64)
        {
            return Err(config_error(
                "proxy.rate_limit_rps must be between 1 and 4294967295 when rate limiting is enabled",
            ));
        }

        if self.scanner.enabled
            && self.scanner.scan_scope != "body"
            && self.scanner.scan_scope != "full"
        {
            return Err(config_error(
                "scanner.scan_scope must be either 'body' or 'full'",
            ));
        }

        if self.proxy.mitm_enabled {
            info!(
                cert_path_set = self.proxy.mitm_ca_cert_path.is_some(),
                key_path_set = self.proxy.mitm_ca_key_path.is_some(),
                "MITM inspection enabled"
            );

            if self.proxy.mitm_ca_cert_path.is_none() {
                warn!("MITM is enabled but proxy.mitm_ca_cert_path is missing");
                return Err(config_error(
                    "proxy.mitm_ca_cert_path is required when proxy.mitm_enabled is true",
                ));
            }

            if self.proxy.mitm_ca_key_path.is_none() {
                warn!("MITM is enabled but proxy.mitm_ca_key_path is missing");
                return Err(config_error(
                    "proxy.mitm_ca_key_path is required when proxy.mitm_enabled is true",
                ));
            }

            if self.proxy.mitm_cert_cache_size == 0 {
                warn!("MITM certificate cache size must be greater than zero");
                return Err(config_error(
                    "proxy.mitm_cert_cache_size must be greater than zero when proxy.mitm_enabled is true",
                ));
            }
        } else {
            info!("MITM inspection disabled; CONNECT requests use blind tunneling");
        }

        if self.proxy.websocket_mode != "reject"
            && self.proxy.websocket_mode != "passthrough"
            && self.proxy.websocket_mode != "inspect"
        {
            return Err(config_error(
                "proxy.websocket_mode must be one of 'reject', 'passthrough', or 'inspect'",
            ));
        }

        if self.redaction.strategy != "partial" && self.redaction.strategy != "placeholder" {
            warn!(
                strategy = %self.redaction.strategy,
                "Redaction strategy is invalid"
            );
            return Err(config_error(
                "redaction.strategy must be either 'partial' or 'placeholder'",
            ));
        }

        if self.redaction.response_restore_enabled && self.redaction.strategy != "placeholder" {
            warn!("Response restoration requires redaction.strategy = 'placeholder'");
            return Err(config_error(
                "redaction.response_restore_enabled requires redaction.strategy = 'placeholder'",
            ));
        }

        if self.scanner.model.enabled {
            info!(
                mode = %self.scanner.model.mode,
                endpoint_set = !self.scanner.model.endpoint.is_empty(),
                model_set = !self.scanner.model.model.is_empty(),
                timeout_ms = self.scanner.model.timeout_ms,
                max_chars = self.scanner.model.max_chars,
                fail_policy = %self.scanner.model.fail_policy,
                categories = ?self.scanner.model.categories,
                "Model scanner enabled"
            );

            if !matches!(
                self.scanner.model.mode.as_str(),
                "hybrid" | "verify_only" | "direct"
            ) {
                warn!(mode = %self.scanner.model.mode, "Invalid model scanner mode");
                return Err(config_error(
                    "scanner.model.mode must be one of 'hybrid', 'verify_only', or 'direct'",
                ));
            }
            if self.scanner.model.endpoint.trim().is_empty()
                || self.scanner.model.model.trim().is_empty()
            {
                warn!("Model scanner endpoint and model are required when enabled");
                return Err(config_error(
                    "scanner.model.endpoint and scanner.model.model are required when scanner.model.enabled is true",
                ));
            }
            if self.scanner.model.timeout_ms == 0 || self.scanner.model.max_chars == 0 {
                warn!("Model scanner timeout_ms and max_chars must be greater than zero");
                return Err(config_error(
                    "scanner.model.timeout_ms and scanner.model.max_chars must be greater than zero",
                ));
            }
            if !matches!(
                self.scanner.model.fail_policy.as_str(),
                "regex_only" | "fail_closed"
            ) {
                warn!(
                    fail_policy = %self.scanner.model.fail_policy,
                    "Invalid model scanner fail policy"
                );
                return Err(config_error(
                    "scanner.model.fail_policy must be either 'regex_only' or 'fail_closed'",
                ));
            }
        }

        if self.scanner.regex.enabled {
            for pattern in &self.scanner.regex.patterns {
                if let Err(error) = regex::Regex::new(&pattern.pattern) {
                    warn!(
                        name = %pattern.name,
                        pattern = %pattern.pattern,
                        error = %error,
                        "Regex scanner pattern is invalid"
                    );
                    return Err(config_error(
                        "scanner.regex.patterns contains an invalid regex pattern",
                    ));
                }
            }
        }

        if self.scanner.privacy_filter.enabled {
            let has_endpoint = !self.scanner.privacy_filter.endpoint.trim().is_empty();
            let has_command = !self.scanner.privacy_filter.command.trim().is_empty();
            info!(
                endpoint_set = has_endpoint,
                command_set = has_command,
                timeout_ms = self.scanner.privacy_filter.timeout_ms,
                max_chars = self.scanner.privacy_filter.max_chars,
                fail_policy = %self.scanner.privacy_filter.fail_policy,
                categories = ?self.scanner.privacy_filter.categories,
                min_confidence = self.scanner.privacy_filter.min_confidence,
                "Privacy filter scanner enabled"
            );

            if !has_endpoint && !has_command {
                warn!("Privacy filter scanner endpoint or command is required when enabled");
                return Err(config_error(
                    "scanner.privacy_filter.endpoint or scanner.privacy_filter.command is required when scanner.privacy_filter.enabled is true",
                ));
            }
            if has_endpoint && has_command {
                warn!("Privacy filter scanner endpoint and command are mutually exclusive");
                return Err(config_error(
                    "scanner.privacy_filter.endpoint and scanner.privacy_filter.command cannot both be set",
                ));
            }
            if self.scanner.privacy_filter.timeout_ms == 0
                || self.scanner.privacy_filter.max_chars == 0
            {
                warn!("Privacy filter scanner timeout_ms and max_chars must be greater than zero");
                return Err(config_error(
                    "scanner.privacy_filter.timeout_ms and scanner.privacy_filter.max_chars must be greater than zero",
                ));
            }
            if !matches!(
                self.scanner.privacy_filter.fail_policy.as_str(),
                "regex_only" | "fail_closed"
            ) {
                warn!(
                    fail_policy = %self.scanner.privacy_filter.fail_policy,
                    "Invalid privacy filter scanner fail policy"
                );
                return Err(config_error(
                    "scanner.privacy_filter.fail_policy must be either 'regex_only' or 'fail_closed'",
                ));
            }
            if !(0.0..=1.0).contains(&self.scanner.privacy_filter.min_confidence) {
                warn!(
                    min_confidence = self.scanner.privacy_filter.min_confidence,
                    "Invalid privacy filter scanner min_confidence"
                );
                return Err(config_error(
                    "scanner.privacy_filter.min_confidence must be between 0.0 and 1.0",
                ));
            }
        }

        if self.dashboard.enabled {
            let dashboard_addr =
                self.dashboard
                    .listen_addr
                    .parse::<SocketAddr>()
                    .map_err(|error| {
                        warn!(
                            listen_addr = %self.dashboard.listen_addr,
                            error = %error,
                            "Dashboard listen address is invalid"
                        );
                        config_error("dashboard.listen_addr must be a valid socket address")
                    })?;

            if !dashboard_addr.ip().is_loopback() {
                warn!(
                    listen_addr = %self.dashboard.listen_addr,
                    "Dashboard listen address must be loopback-only"
                );
                return Err(config_error(
                    "dashboard.listen_addr must be loopback-only; use SSH tunneling for remote access",
                ));
            }

            if self.dashboard.retention_hours == 0 {
                warn!("Dashboard retention must be greater than zero");
                return Err(config_error(
                    "dashboard.retention_hours must be greater than zero",
                ));
            }

            if (self.dashboard.capture.prompts || self.dashboard.capture.responses)
                && self.dashboard.capture.max_body_bytes == 0
            {
                warn!("Dashboard capture max_body_bytes must be greater than zero");
                return Err(config_error(
                    "dashboard.capture.max_body_bytes must be greater than zero when capture is enabled",
                ));
            }

            if self.dashboard.capture.redact_before_store
                && (self.dashboard.capture.prompts || self.dashboard.capture.responses)
                && !self.has_capture_redaction_scanner()
            {
                warn!("Dashboard capture redaction requires at least one configured scanner");
                return Err(config_error(
                    "dashboard.capture.redact_before_store requires at least one scanner to be configured",
                ));
            }
        }

        Ok(())
    }

    fn has_capture_redaction_scanner(&self) -> bool {
        self.scanner.regex.enabled
            || self.scanner.entropy.enabled
            || self.scanner.structural.enabled
            || self.scanner.model.enabled
            || self.scanner.privacy_filter.enabled
    }
}

fn config_error(message: &str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn override_string(var_name: &str, target: &mut String) {
    if let Ok(value) = env::var(var_name) {
        *target = value;
    }
}

fn override_optional_path(var_name: &str, target: &mut Option<PathBuf>) {
    let Ok(value) = env::var(var_name) else {
        return;
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        *target = None;
    } else {
        *target = Some(PathBuf::from(trimmed));
    }
}

fn override_path(var_name: &str, target: &mut PathBuf) {
    let Ok(value) = env::var(var_name) else {
        return;
    };

    let trimmed = value.trim();
    if !trimmed.is_empty() {
        *target = PathBuf::from(trimmed);
    }
}

fn override_string_list(var_name: &str, target: &mut Vec<String>) {
    let Ok(value) = env::var(var_name) else {
        return;
    };

    *target = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();
}

fn override_parse<T>(var_name: &str, target: &mut T) -> Result<(), Box<dyn std::error::Error>>
where
    T: FromStr,
    T::Err: std::error::Error + 'static,
{
    let Ok(value) = env::var(var_name) else {
        return Ok(());
    };

    *target = value.parse::<T>()?;
    Ok(())
}

fn override_bool(var_name: &str, target: &mut bool) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(value) = env::var(var_name) else {
        return Ok(());
    };

    let normalized = value.trim().to_ascii_lowercase();
    *target = match normalized.as_str() {
        "1" | "true" | "on" | "yes" => true,
        "0" | "false" | "off" | "no" => false,
        _ => {
            return Err(config_error(&format!(
                "{var_name} must be one of true/false, 1/0, on/off, yes/no"
            )));
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config_with_dashboard(listen_addr: &str) -> Config {
        Config {
            proxy: ProxyConfig {
                listen_addr: "127.0.0.1:8080".to_string(),
                anthropic_upstream_url: "https://api.anthropic.com".to_string(),
                codex_upstream_url: "https://api.openai.com".to_string(),
                codex_subscription_url: "https://chatgpt.com/backend-api/codex/responses"
                    .to_string(),
                codex_subscription_routing_enabled: true,
                rate_limit_enabled: true,
                max_body_size: default_max_body_size(),
                connect_timeout_secs: default_connect_timeout(),
                request_timeout_secs: default_request_timeout(),
                rate_limit_rps: default_rate_limit_rps(),
                mitm_enabled: false,
                mitm_ca_cert_path: None,
                mitm_ca_key_path: None,
                mitm_cert_cache_size: default_mitm_cert_cache_size(),
                mitm_excluded_hosts: Vec::new(),
                websocket_mode: default_websocket_mode(),
            },
            dashboard: DashboardConfig {
                enabled: true,
                listen_addr: listen_addr.to_string(),
                token_path: default_dashboard_token_path(),
                sqlite_path: default_dashboard_sqlite_path(),
                retention_hours: default_dashboard_retention_hours(),
                capture: DashboardCaptureConfig::default(),
            },
            redaction: RedactionConfig {
                strategy: "partial".to_string(),
                prefix_len: 3,
                suffix_len: 3,
                mask: "***...***".to_string(),
                response_restore_enabled: false,
                restorable_categories: default_restorable_categories(),
            },
            scanner: ScannerConfig {
                enabled: false,
                scan_scope: "body".to_string(),
                header_whitelist: vec!["authorization".to_string()],
                model: ModelScannerConfig::default(),
                privacy_filter: PrivacyFilterScannerConfig::default(),
                regex: RegexScannerConfig {
                    enabled: true,
                    patterns: Vec::new(),
                },
                entropy: EntropyScannerConfig {
                    enabled: false,
                    threshold: 4.5,
                    min_length: 20,
                    max_length: 256,
                    keywords: Vec::new(),
                    keyword_proximity: 50,
                },
                structural: StructuralScannerConfig {
                    enabled: false,
                    detect_jwt: true,
                    detect_connection_strings: true,
                    detect_env_patterns: true,
                },
            },
        }
    }

    #[test]
    fn dashboard_rejects_non_loopback_listen_addr_when_enabled() {
        let config = minimal_config_with_dashboard("0.0.0.0:18081");
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("loopback-only"));
    }

    #[test]
    fn dashboard_accepts_loopback_listen_addr_when_enabled() {
        let config = minimal_config_with_dashboard("127.0.0.1:18081");
        config.validate().unwrap();
    }

    #[test]
    fn dashboard_capture_redaction_requires_configured_scanner() {
        let mut config = minimal_config_with_dashboard("127.0.0.1:18081");
        config.dashboard.capture.prompts = true;
        config.scanner.regex.enabled = false;
        config.scanner.entropy.enabled = false;
        config.scanner.structural.enabled = false;
        config.scanner.model.enabled = false;
        config.scanner.privacy_filter.enabled = false;

        let error = config.validate().unwrap_err().to_string();

        assert!(error.contains("redact_before_store requires at least one scanner"));
    }

    #[test]
    fn regex_scanner_rejects_invalid_pattern_when_enabled() {
        let mut config = minimal_config_with_dashboard("127.0.0.1:18081");
        config.scanner.regex.patterns = vec![RegexPattern {
            name: "bad".to_string(),
            pattern: "[invalid".to_string(),
        }];

        let error = config.validate().unwrap_err().to_string();

        assert!(error.contains("invalid regex pattern"));
    }

    #[test]
    fn privacy_filter_scanner_requires_endpoint_or_command_when_enabled() {
        let mut config = minimal_config_with_dashboard("127.0.0.1:18081");
        config.scanner.privacy_filter.enabled = true;

        let error = config.validate().unwrap_err().to_string();

        assert!(
            error.contains("scanner.privacy_filter.endpoint or scanner.privacy_filter.command")
        );
    }

    #[test]
    fn privacy_filter_scanner_accepts_command_when_enabled() {
        let mut config = minimal_config_with_dashboard("127.0.0.1:18081");
        config.scanner.privacy_filter.enabled = true;
        config.scanner.privacy_filter.command = "opf".to_string();

        config.validate().unwrap();
    }

    #[test]
    fn privacy_filter_scanner_rejects_endpoint_and_command_together() {
        let mut config = minimal_config_with_dashboard("127.0.0.1:18081");
        config.scanner.privacy_filter.enabled = true;
        config.scanner.privacy_filter.endpoint = "http://127.0.0.1:18082/scan".to_string();
        config.scanner.privacy_filter.command = "opf".to_string();

        let error = config.validate().unwrap_err().to_string();

        assert!(error.contains("cannot both be set"));
    }
}
