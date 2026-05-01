use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::any,
};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use tracing::info;

use ai_proxy::config::Config;
use ai_proxy::dashboard::serve_dashboard;
use ai_proxy::middleware::ScanPipeline;
use ai_proxy::middleware::entropy_scanner::EntropyScanner;
use ai_proxy::middleware::model_scanner::ModelScanner;
use ai_proxy::middleware::privacy_filter_scanner::PrivacyFilterScanner;
use ai_proxy::middleware::regex_scanner::RegexScanner;
use ai_proxy::middleware::structural_scanner::StructuralScanner;
use ai_proxy::mitm::MitmAuthority;
use ai_proxy::proxy::{AppState, proxy_handler};
use ai_proxy::redactor::Redactor;
use ai_proxy::telemetry_store::TelemetryStore;

type GlobalRateLimiter = Arc<
    RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
>;

async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let limiter = request
        .extensions()
        .get::<GlobalRateLimiter>()
        .cloned()
        .expect("rate limiter not in extensions");

    if limiter.check().is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(request).await)
}

#[tokio::main]
async fn main() {
    // Initialize logging
    ai_proxy::logging::init_logging();

    // Load configuration
    let config = Config::load("config.toml").expect("Failed to load config.toml");

    // Build scan pipeline
    let mut pipeline = ScanPipeline::new();
    let capture_redaction_enabled = config.dashboard.enabled
        && config.dashboard.capture.redact_before_store
        && (config.dashboard.capture.prompts || config.dashboard.capture.responses);
    let build_scan_pipeline = config.scanner.enabled || capture_redaction_enabled;

    if build_scan_pipeline && config.scanner.regex.enabled {
        pipeline.add_scanner(Box::new(RegexScanner::new(&config.scanner.regex)));
    }
    if build_scan_pipeline && config.scanner.entropy.enabled {
        pipeline.add_scanner(Box::new(EntropyScanner::new(&config.scanner.entropy)));
    }
    if build_scan_pipeline && config.scanner.structural.enabled {
        pipeline.add_scanner(Box::new(StructuralScanner::new(&config.scanner.structural)));
    }
    if build_scan_pipeline && config.scanner.model.enabled {
        if config.scanner.model.mode == "direct" {
            let mut direct_pipeline = ScanPipeline::new();
            direct_pipeline.add_scanner(Box::new(ModelScanner::new(&config.scanner.model)));
            pipeline = direct_pipeline;
        } else {
            pipeline.add_scanner(Box::new(ModelScanner::new(&config.scanner.model)));
        }
    }
    if build_scan_pipeline && config.scanner.privacy_filter.enabled {
        pipeline.add_scanner(Box::new(PrivacyFilterScanner::new(
            &config.scanner.privacy_filter,
        )));
    }

    // Build redactor
    let redactor = Redactor::new(&config.redaction);
    info!(
        strategy = %config.redaction.strategy,
        response_restore_enabled = config.redaction.response_restore_enabled,
        restorable_categories = ?config.redaction.restorable_categories,
        "Redaction policy configured"
    );

    // Build HTTP client with timeouts
    let mut http_client_builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(config.proxy.connect_timeout_secs))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd();
    if config.proxy.request_timeout_secs > 0 {
        http_client_builder =
            http_client_builder.timeout(Duration::from_secs(config.proxy.request_timeout_secs));
    }
    let http_client = http_client_builder
        .build()
        .expect("Failed to build HTTP client");

    let mitm_authority = if config.proxy.mitm_enabled {
        Some(Arc::new(
            MitmAuthority::from_config(&config.proxy).expect("Failed to load MITM CA"),
        ))
    } else {
        None
    };

    let telemetry_store = if config.dashboard.enabled {
        info!(
            listen_addr = %config.dashboard.listen_addr,
            sqlite_path = %config.dashboard.sqlite_path.display(),
            retention_hours = config.dashboard.retention_hours,
            "Telemetry persistence enabled for dashboard"
        );
        Some(Arc::new(
            TelemetryStore::open(
                &config.dashboard.sqlite_path,
                config.dashboard.retention_hours,
            )
            .await
            .expect("Failed to initialize telemetry SQLite database"),
        ))
    } else {
        info!("Telemetry persistence disabled because dashboard is disabled");
        None
    };
    let dashboard_store = telemetry_store.clone();
    if let Some(store) = telemetry_store.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
            loop {
                interval.tick().await;
                if let Err(error) = store.purge_expired().await {
                    tracing::error!(error = %error, "Telemetry retention purge failed");
                }
            }
        });
    }

    // Create shared state
    let state = Arc::new(AppState {
        config: config.clone(),
        pipeline,
        redactor,
        http_client,
        mitm_authority,
        telemetry_store,
    });

    if let Some(store) = dashboard_store {
        let dashboard_config = config.dashboard.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_dashboard(dashboard_config, store).await {
                tracing::error!(error = %error, "Dashboard server stopped with error");
            }
        });
    }

    let mut app = Router::new()
        .route("/{*path}", any(proxy_handler))
        .fallback(any(proxy_handler))
        .with_state(state);

    if config.proxy.rate_limit_enabled {
        let quota = Quota::per_second(
            NonZeroU32::new(config.proxy.rate_limit_rps as u32)
                .expect("rate_limit_rps is validated during config load"),
        );
        let rate_limiter: GlobalRateLimiter = Arc::new(RateLimiter::direct(quota));
        app = app
            .layer(middleware::from_fn(rate_limit_middleware))
            .layer(axum::Extension(rate_limiter));
    }

    let listen_addr = &config.proxy.listen_addr;
    info!(listen_addr = %listen_addr, "Starting AI proxy server");

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .expect("Failed to bind to address");

    info!(
        "AI proxy is ready — forwarding to {}",
        config.proxy.anthropic_upstream_url
    );

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}
