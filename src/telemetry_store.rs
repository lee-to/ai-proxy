use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};
use tracing::{debug, error, info};

use crate::telemetry::{
    ContentCaptureRecord, ErrorDashboard, ErrorEventView, RequestTimelineDashboard,
    RequestTimelineItem, TokenUsageRecord, ToolEventRecord, ToolEventView, ToolHistoryDashboard,
    UsageBreakdownRow, UsageDashboard, UsageTotals, now_ms, window_start_ms,
};

const AUXILIARY_ERROR_CONDITION: &str = r#"
    (
        status_code IS 403
        AND (
            path LIKE '%/backend-api/%connectors/directory/list%'
            OR path LIKE '%/backend-api/codex/analytics-events/events%'
            OR path LIKE '%/backend-api/plugins/featured%'
        )
    )
    OR (
        (error IS NOT NULL OR status_code >= 400)
        AND (
            path LIKE 'http://127.0.0.1:%'
            OR path LIKE 'http://localhost:%'
            OR path LIKE 'https://api.anthropic.com/http://127.0.0.1:%'
            OR path LIKE 'https://api.anthropic.com/http://localhost:%'
            OR path = '/scan'
            OR path = 'https://api.anthropic.com/scan'
        )
    )
"#;

#[derive(Clone)]
pub struct TelemetryStore {
    connection: Arc<Mutex<Connection>>,
    retention_hours: u64,
}

impl TelemetryStore {
    pub async fn open<P: AsRef<Path>>(path: P, retention_hours: u64) -> rusqlite::Result<Self> {
        let path = path.as_ref();
        info!(
            sqlite_path = %path.display(),
            retention_hours,
            "Opening telemetry SQLite database"
        );

        let connection = Connection::open(path)?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
            retention_hours,
        };
        store.initialize_schema().await?;
        store.purge_expired().await?;
        Ok(store)
    }

    pub async fn open_in_memory(retention_hours: u64) -> rusqlite::Result<Self> {
        info!(
            retention_hours,
            "Opening in-memory telemetry SQLite database"
        );
        let connection = Connection::open_in_memory()?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
            retention_hours,
        };
        store.initialize_schema().await?;
        Ok(store)
    }

    pub fn retention_hours(&self) -> u64 {
        self.retention_hours
    }

    async fn with_connection<R, F>(&self, operation: F) -> rusqlite::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<R> + Send + 'static,
    {
        let connection = self.connection.clone();
        tokio::task::spawn_blocking(move || {
            let connection = connection
                .lock()
                .map_err(|_| sqlite_runtime_error("telemetry SQLite connection lock poisoned"))?;
            operation(&connection)
        })
        .await
        .map_err(|error| sqlite_runtime_error(&format!("telemetry SQLite task failed: {error}")))?
    }

    async fn initialize_schema(&self) -> rusqlite::Result<()> {
        debug!("Initializing telemetry schema");
        self.with_connection(|connection| {
            connection.execute_batch(
                r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY,
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                mode TEXT NOT NULL,
                upstream TEXT NOT NULL,
                model TEXT,
                status_code INTEGER,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                model TEXT,
                upstream TEXT NOT NULL,
                source TEXT NOT NULL,
                input_tokens INTEGER,
                output_tokens INTEGER,
                total_tokens INTEGER,
                FOREIGN KEY(request_id) REFERENCES requests(request_id)
            );

            CREATE TABLE IF NOT EXISTS tool_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                event_kind TEXT NOT NULL,
                tool_name TEXT,
                call_id TEXT,
                status TEXT,
                source TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES requests(request_id)
            );

            CREATE TABLE IF NOT EXISTS content_captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                direction TEXT NOT NULL,
                source TEXT NOT NULL,
                content_type TEXT,
                preview_text TEXT NOT NULL,
                truncated INTEGER NOT NULL,
                redacted INTEGER NOT NULL,
                FOREIGN KEY(request_id) REFERENCES requests(request_id)
            );

            CREATE INDEX IF NOT EXISTS idx_requests_started_at
                ON requests(started_at_ms);
            CREATE INDEX IF NOT EXISTS idx_usage_observed_at
                ON usage_events(observed_at_ms);
            CREATE INDEX IF NOT EXISTS idx_usage_request_id
                ON usage_events(request_id);
            CREATE INDEX IF NOT EXISTS idx_tool_events_observed_at
                ON tool_events(observed_at_ms);
            CREATE INDEX IF NOT EXISTS idx_tool_events_request_id
                ON tool_events(request_id);
            CREATE INDEX IF NOT EXISTS idx_content_captures_observed_at
                ON content_captures(observed_at_ms);
            CREATE INDEX IF NOT EXISTS idx_content_captures_request_id
                ON content_captures(request_id);
            "#,
            )
        })
        .await?;
        info!("Telemetry schema ready");
        Ok(())
    }

    pub async fn insert_request(
        &self,
        request: &crate::telemetry::RequestRecord,
    ) -> rusqlite::Result<()> {
        debug!(
            request_id = %request.request_id,
            method = %request.method,
            path = %request.path,
            mode = %request.mode,
            upstream = %request.upstream,
            model = ?request.model,
            "Persisting telemetry request"
        );

        let request = request.clone();
        let log_request_id = request.request_id.clone();
        self.with_connection(move |connection| {
            connection.execute(
                r#"
            INSERT INTO requests (
                request_id,
                started_at_ms,
                completed_at_ms,
                method,
                path,
                mode,
                upstream,
                model,
                status_code,
                error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(request_id) DO UPDATE SET
                started_at_ms = excluded.started_at_ms,
                completed_at_ms = excluded.completed_at_ms,
                method = excluded.method,
                path = excluded.path,
                mode = excluded.mode,
                upstream = excluded.upstream,
                model = excluded.model,
                status_code = excluded.status_code,
                error = excluded.error
            "#,
                params![
                    request.request_id,
                    request.started_at_ms,
                    request.completed_at_ms,
                    request.method,
                    request.path,
                    request.mode,
                    request.upstream,
                    request.model,
                    request.status_code.map(i64::from),
                    request.error,
                ],
            )
        })
        .await
        .map(|_| ())
        .map_err(|error| {
            error!(
                request_id = %log_request_id,
                table = "requests",
                error = %error,
                "Failed to persist telemetry request"
            );
            error
        })
    }

    pub async fn finish_request(
        &self,
        request_id: &str,
        completed_at_ms: i64,
        status_code: Option<u16>,
        error_message: Option<&str>,
    ) -> rusqlite::Result<()> {
        debug!(
            request_id,
            status_code = ?status_code,
            has_error = error_message.is_some(),
            "Finishing telemetry request"
        );

        let request_id = request_id.to_string();
        let log_request_id = request_id.clone();
        let error_message = error_message.map(ToOwned::to_owned);
        self.with_connection(move |connection| {
            connection.execute(
                r#"
            UPDATE requests
            SET completed_at_ms = ?2,
                status_code = ?3,
                error = ?4
            WHERE request_id = ?1
            "#,
                params![
                    request_id,
                    completed_at_ms,
                    status_code.map(i64::from),
                    error_message,
                ],
            )
        })
        .await
        .map(|_| ())
        .map_err(|error| {
            error!(
                request_id = %log_request_id,
                table = "requests",
                error = %error,
                "Failed to finish telemetry request"
            );
            error
        })
    }

    pub async fn insert_usage(&self, usage: &TokenUsageRecord) -> rusqlite::Result<()> {
        debug!(
            request_id = %usage.request_id,
            model = ?usage.model,
            upstream = %usage.upstream,
            source = %usage.source,
            input_tokens = ?usage.input_tokens,
            output_tokens = ?usage.output_tokens,
            total_tokens = ?usage.total_tokens,
            "Persisting token usage telemetry"
        );

        let usage = usage.clone();
        let log_request_id = usage.request_id.clone();
        self.with_connection(move |connection| {
            connection.execute(
                r#"
            INSERT INTO usage_events (
                request_id,
                observed_at_ms,
                model,
                upstream,
                source,
                input_tokens,
                output_tokens,
                total_tokens
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
                params![
                    usage.request_id,
                    usage.observed_at_ms,
                    usage.model,
                    usage.upstream,
                    usage.source,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.total_tokens,
                ],
            )
        })
        .await
        .map(|_| ())
        .map_err(|error| {
            error!(
                request_id = %log_request_id,
                table = "usage_events",
                error = %error,
                "Failed to persist token usage telemetry"
            );
            error
        })
    }

    pub async fn insert_tool_event(&self, event: &ToolEventRecord) -> rusqlite::Result<()> {
        debug!(
            request_id = %event.request_id,
            event_kind = %event.event_kind,
            tool_name = ?event.tool_name,
            call_id = ?event.call_id,
            status = ?event.status,
            source = %event.source,
            "Persisting tool event telemetry"
        );

        let event = event.clone();
        let log_request_id = event.request_id.clone();
        self.with_connection(move |connection| {
            connection.execute(
                r#"
            INSERT INTO tool_events (
                request_id,
                observed_at_ms,
                event_kind,
                tool_name,
                call_id,
                status,
                source
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
                params![
                    event.request_id,
                    event.observed_at_ms,
                    event.event_kind,
                    event.tool_name,
                    event.call_id,
                    event.status,
                    event.source,
                ],
            )
        })
        .await
        .map(|_| ())
        .map_err(|error| {
            error!(
                request_id = %log_request_id,
                table = "tool_events",
                error = %error,
                "Failed to persist tool event telemetry"
            );
            error
        })
    }

    pub async fn insert_content_capture(
        &self,
        capture: &ContentCaptureRecord,
    ) -> rusqlite::Result<()> {
        debug!(
            request_id = %capture.request_id,
            direction = %capture.direction,
            source = %capture.source,
            content_type = ?capture.content_type,
            truncated = capture.truncated,
            redacted = capture.redacted,
            preview_len = capture.preview_text.len(),
            "Persisting content capture telemetry"
        );

        let capture = capture.clone();
        let log_request_id = capture.request_id.clone();
        self.with_connection(move |connection| {
            connection.execute(
                r#"
            INSERT INTO content_captures (
                request_id,
                observed_at_ms,
                direction,
                source,
                content_type,
                preview_text,
                truncated,
                redacted
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
                params![
                    capture.request_id,
                    capture.observed_at_ms,
                    capture.direction,
                    capture.source,
                    capture.content_type,
                    capture.preview_text,
                    capture.truncated as i64,
                    capture.redacted as i64,
                ],
            )
        })
        .await
        .map(|_| ())
        .map_err(|error| {
            error!(
                request_id = %log_request_id,
                table = "content_captures",
                error = %error,
                "Failed to persist content capture telemetry"
            );
            error
        })
    }

    pub async fn purge_expired(&self) -> rusqlite::Result<usize> {
        let cutoff_ms = window_start_ms(self.retention_hours);
        debug!(cutoff_ms, "Purging expired telemetry rows");
        let (deleted_content_captures, deleted_tool_events, deleted_usage_events, deleted_requests) =
            self.with_connection(move |connection| {
                let tx = connection.unchecked_transaction()?;
                let deleted_content_captures = tx.execute(
                    "DELETE FROM content_captures WHERE observed_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                let deleted_tool_events = tx.execute(
                    "DELETE FROM tool_events WHERE observed_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                let deleted_usage_events = tx.execute(
                    "DELETE FROM usage_events WHERE observed_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                let deleted_requests = tx.execute(
                    "DELETE FROM requests WHERE started_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                tx.commit()?;
                Ok((
                    deleted_content_captures,
                    deleted_tool_events,
                    deleted_usage_events,
                    deleted_requests,
                ))
            })
            .await?;
        let deleted = deleted_content_captures
            + deleted_tool_events
            + deleted_usage_events
            + deleted_requests;
        info!(
            cutoff_ms,
            deleted_content_captures,
            deleted_tool_events,
            deleted_usage_events,
            deleted_requests,
            "Purged expired telemetry rows"
        );
        Ok(deleted)
    }

    pub async fn usage_dashboard(&self, window_hours: u64) -> rusqlite::Result<UsageDashboard> {
        let window_start = window_start_ms(window_hours);
        let generated_at_ms = now_ms();
        debug!(window_hours, window_start, "Querying usage dashboard");

        let (totals, by_model, by_upstream) = self
            .with_connection(move |connection| {
                Ok((
                    query_usage_totals(connection, window_start)?,
                    query_usage_breakdown(connection, "model", window_start)?,
                    query_usage_breakdown(connection, "upstream", window_start)?,
                ))
            })
            .await?;
        debug!(
            window_hours,
            by_model_rows = by_model.len(),
            by_upstream_rows = by_upstream.len(),
            "Usage dashboard query complete"
        );

        Ok(UsageDashboard {
            window_hours,
            generated_at_ms,
            totals,
            by_model,
            by_upstream,
        })
    }

    pub async fn tool_history_dashboard(
        &self,
        window_hours: u64,
        limit: usize,
    ) -> rusqlite::Result<ToolHistoryDashboard> {
        let window_start = window_start_ms(window_hours);
        let generated_at_ms = now_ms();
        debug!(
            window_hours,
            limit, window_start, "Querying tool history dashboard"
        );

        let events = self
            .with_connection(move |connection| {
                let mut statement = connection.prepare(
                    r#"
            SELECT observed_at_ms, request_id, event_kind, tool_name, call_id, status, source
            FROM tool_events
            WHERE observed_at_ms >= ?1
              AND event_kind != 'tool_definition'
            ORDER BY observed_at_ms DESC
            LIMIT ?2
            "#,
                )?;
                statement
                    .query_map(params![window_start, limit as i64], |row| {
                        Ok(ToolEventView {
                            observed_at_ms: row.get(0)?,
                            request_id: row.get(1)?,
                            event_kind: row.get(2)?,
                            tool_name: row.get(3)?,
                            call_id: row.get(4)?,
                            status: row.get(5)?,
                            source: row.get(6)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .await?;

        debug!(
            event_count = events.len(),
            "Tool history dashboard query complete"
        );
        Ok(ToolHistoryDashboard {
            window_hours,
            generated_at_ms,
            events,
        })
    }

    pub async fn error_dashboard(
        &self,
        window_hours: u64,
        limit: usize,
    ) -> rusqlite::Result<ErrorDashboard> {
        let window_start = window_start_ms(window_hours);
        let generated_at_ms = now_ms();
        debug!(
            window_hours,
            limit, window_start, "Querying error dashboard"
        );

        let primary_sql = format!(
            r#"
            SELECT
                started_at_ms,
                completed_at_ms,
                request_id,
                method,
                path,
                mode,
                upstream,
                model,
                status_code,
                error
            FROM requests
            WHERE started_at_ms >= ?1
              AND (error IS NOT NULL OR status_code >= 400)
              AND NOT ({AUXILIARY_ERROR_CONDITION})
            ORDER BY started_at_ms DESC
            LIMIT ?2
            "#
        );
        let auxiliary_sql = format!(
            r#"
            SELECT
                started_at_ms,
                completed_at_ms,
                request_id,
                method,
                path,
                mode,
                upstream,
                model,
                status_code,
                error
            FROM requests
            WHERE started_at_ms >= ?1
              AND ({AUXILIARY_ERROR_CONDITION})
            ORDER BY started_at_ms DESC
            LIMIT ?2
            "#
        );

        let (errors, auxiliary_errors) = self
            .with_connection(move |connection| {
                Ok((
                    query_error_events(connection, &primary_sql, window_start, limit)?,
                    query_error_events(connection, &auxiliary_sql, window_start, limit)?,
                ))
            })
            .await?;

        debug!(
            error_count = errors.len(),
            auxiliary_error_count = auxiliary_errors.len(),
            "Error dashboard query complete"
        );
        Ok(ErrorDashboard {
            window_hours,
            generated_at_ms,
            errors,
            auxiliary_errors,
        })
    }

    pub async fn request_timeline_dashboard(
        &self,
        window_hours: u64,
        limit: usize,
    ) -> rusqlite::Result<RequestTimelineDashboard> {
        let window_start = window_start_ms(window_hours);
        let generated_at_ms = now_ms();
        debug!(
            window_hours,
            limit, window_start, "Querying request timeline dashboard"
        );

        let events = self
            .with_connection(move |connection| {
                let mut statement = connection.prepare(
                    r#"
            SELECT
                r.started_at_ms,
                r.completed_at_ms,
                r.request_id,
                r.method,
                r.path,
                r.mode,
                r.upstream,
                r.model,
                r.status_code,
                r.error,
                COALESCE((SELECT SUM(input_tokens) FROM usage_events u WHERE u.request_id = r.request_id), 0),
                COALESCE((SELECT SUM(output_tokens) FROM usage_events u WHERE u.request_id = r.request_id), 0),
                COALESCE((SELECT SUM(total_tokens) FROM usage_events u WHERE u.request_id = r.request_id), 0),
                (SELECT COUNT(*) FROM tool_events t WHERE t.request_id = r.request_id AND t.event_kind != 'tool_definition'),
                (
                    SELECT CASE
                        WHEN lower(COALESCE(c.content_type, '')) LIKE 'text/html%'
                            OR lower(COALESCE(c.content_type, '')) LIKE 'application/xhtml+xml%'
                        THEN '[HTML request body omitted from dashboard capture: content_type="' || COALESCE(c.content_type, 'unknown') || '"]'
                        ELSE c.preview_text
                    END
                    FROM content_captures c
                    WHERE c.request_id = r.request_id AND c.direction = 'request'
                    ORDER BY c.observed_at_ms ASC
                    LIMIT 1
                ),
                COALESCE((
                    SELECT CASE
                        WHEN lower(COALESCE(c.content_type, '')) LIKE 'text/html%'
                            OR lower(COALESCE(c.content_type, '')) LIKE 'application/xhtml+xml%'
                        THEN 0
                        ELSE c.truncated
                    END
                    FROM content_captures c
                    WHERE c.request_id = r.request_id AND c.direction = 'request'
                    ORDER BY c.observed_at_ms ASC
                    LIMIT 1
                ), 0),
                (
                    SELECT CASE
                        WHEN lower(COALESCE(c.content_type, '')) LIKE 'text/html%'
                            OR lower(COALESCE(c.content_type, '')) LIKE 'application/xhtml+xml%'
                        THEN '[HTML response body omitted from dashboard capture: content_type="' || COALESCE(c.content_type, 'unknown') || '"]'
                        ELSE c.preview_text
                    END
                    FROM content_captures c
                    WHERE c.request_id = r.request_id AND c.direction = 'response'
                    ORDER BY c.observed_at_ms DESC
                    LIMIT 1
                ),
                COALESCE((
                    SELECT CASE
                        WHEN lower(COALESCE(c.content_type, '')) LIKE 'text/html%'
                            OR lower(COALESCE(c.content_type, '')) LIKE 'application/xhtml+xml%'
                        THEN 0
                        ELSE c.truncated
                    END
                    FROM content_captures c
                    WHERE c.request_id = r.request_id AND c.direction = 'response'
                    ORDER BY c.observed_at_ms DESC
                    LIMIT 1
                ), 0)
            FROM requests r
            WHERE r.started_at_ms >= ?1
            ORDER BY r.started_at_ms DESC
            LIMIT ?2
            "#,
                )?;
                statement
                    .query_map(params![window_start, limit as i64], |row| {
                        let status_code: Option<i64> = row.get(8)?;
                        let request_truncated: i64 = row.get(15)?;
                        let response_truncated: i64 = row.get(17)?;
                        Ok(RequestTimelineItem {
                            started_at_ms: row.get(0)?,
                            completed_at_ms: row.get(1)?,
                            request_id: row.get(2)?,
                            method: row.get(3)?,
                            path: row.get(4)?,
                            mode: row.get(5)?,
                            upstream: row.get(6)?,
                            model: row.get(7)?,
                            status_code: status_code.and_then(|value| u16::try_from(value).ok()),
                            error: row.get(9)?,
                            input_tokens: row.get(10)?,
                            output_tokens: row.get(11)?,
                            total_tokens: row.get(12)?,
                            tool_event_count: row.get(13)?,
                            request_preview: row.get(14)?,
                            request_truncated: request_truncated != 0,
                            response_preview: row.get(16)?,
                            response_truncated: response_truncated != 0,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .await?;

        debug!(
            event_count = events.len(),
            "Request timeline dashboard query complete"
        );
        Ok(RequestTimelineDashboard {
            window_hours,
            generated_at_ms,
            events,
        })
    }
}

fn query_error_events(
    connection: &Connection,
    sql: &str,
    window_start: i64,
    limit: usize,
) -> rusqlite::Result<Vec<ErrorEventView>> {
    let mut statement = connection.prepare(sql)?;
    statement
        .query_map(params![window_start, limit as i64], |row| {
            let status_code: Option<i64> = row.get(8)?;
            Ok(ErrorEventView {
                started_at_ms: row.get(0)?,
                completed_at_ms: row.get(1)?,
                request_id: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
                mode: row.get(5)?,
                upstream: row.get(6)?,
                model: row.get(7)?,
                status_code: status_code.and_then(|value| u16::try_from(value).ok()),
                error: row.get(9)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
}

fn query_usage_totals(
    connection: &Connection,
    window_start_ms: i64,
) -> rusqlite::Result<UsageTotals> {
    let (input_tokens, output_tokens, total_tokens) = connection.query_row(
        r#"
        SELECT
            COALESCE(SUM(input_tokens), 0),
            COALESCE(SUM(output_tokens), 0),
            COALESCE(SUM(total_tokens), 0)
        FROM usage_events
        WHERE observed_at_ms >= ?1
        "#,
        params![window_start_ms],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let request_count = connection.query_row(
        "SELECT COUNT(*) FROM requests WHERE started_at_ms >= ?1",
        params![window_start_ms],
        |row| row.get(0),
    )?;
    let primary_error_sql = format!(
        r#"
        SELECT COUNT(*)
        FROM requests
        WHERE started_at_ms >= ?1
          AND (error IS NOT NULL OR status_code >= 400)
          AND NOT ({AUXILIARY_ERROR_CONDITION})
        "#
    );
    let auxiliary_error_sql = format!(
        r#"
        SELECT COUNT(*)
        FROM requests
        WHERE started_at_ms >= ?1
          AND ({AUXILIARY_ERROR_CONDITION})
        "#
    );
    let error_count =
        connection.query_row(&primary_error_sql, params![window_start_ms], |row| {
            row.get(0)
        })?;
    let auxiliary_error_count =
        connection.query_row(&auxiliary_error_sql, params![window_start_ms], |row| {
            row.get(0)
        })?;

    Ok(UsageTotals {
        input_tokens,
        output_tokens,
        total_tokens,
        request_count,
        error_count,
        auxiliary_error_count,
    })
}

fn query_usage_breakdown(
    connection: &Connection,
    column: &str,
    window_start_ms: i64,
) -> rusqlite::Result<Vec<UsageBreakdownRow>> {
    let column_expression = match column {
        "model" => "COALESCE(model, 'unknown')",
        "upstream" => "upstream",
        _ => return Ok(Vec::new()),
    };

    let sql = format!(
        r#"
        SELECT
            {column_expression} AS name,
            COALESCE(SUM(input_tokens), 0) AS input_tokens,
            COALESCE(SUM(output_tokens), 0) AS output_tokens,
            COALESCE(SUM(total_tokens), 0) AS total_tokens,
            COUNT(DISTINCT request_id) AS request_count
        FROM usage_events
        WHERE observed_at_ms >= ?1
        GROUP BY name
        ORDER BY total_tokens DESC, request_count DESC, name ASC
        "#
    );

    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map(params![window_start_ms], |row| {
            Ok(UsageBreakdownRow {
                name: row.get(0)?,
                input_tokens: row.get(1)?,
                output_tokens: row.get(2)?,
                total_tokens: row.get(3)?,
                request_count: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
}

pub async fn request_exists(store: &TelemetryStore, request_id: &str) -> rusqlite::Result<bool> {
    let request_id = request_id.to_string();
    store
        .with_connection(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT 1 FROM requests WHERE request_id = ?1",
                    params![request_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
        .await
}

fn sqlite_runtime_error(message: &str) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(message.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{
        ContentCaptureRecord, RequestRecord, TokenUsageRecord, ToolEventRecord,
    };

    #[tokio::test]
    async fn stores_usage_and_returns_dashboard_summary() {
        let store = TelemetryStore::open_in_memory(24).await.unwrap();
        let now = now_ms();
        store
            .insert_request(&RequestRecord {
                request_id: "req-1".to_string(),
                started_at_ms: now,
                completed_at_ms: Some(now),
                method: "POST".to_string(),
                path: "/v1/responses".to_string(),
                mode: "reverse".to_string(),
                upstream: "https://api.openai.com".to_string(),
                model: Some("gpt-test".to_string()),
                status_code: Some(200),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_usage(&TokenUsageRecord {
                request_id: "req-1".to_string(),
                observed_at_ms: now,
                model: Some("gpt-test".to_string()),
                upstream: "https://api.openai.com".to_string(),
                source: "response".to_string(),
                input_tokens: Some(10),
                output_tokens: Some(15),
                total_tokens: Some(25),
            })
            .await
            .unwrap();

        let dashboard = store.usage_dashboard(24).await.unwrap();
        assert_eq!(dashboard.totals.input_tokens, 10);
        assert_eq!(dashboard.totals.output_tokens, 15);
        assert_eq!(dashboard.totals.total_tokens, 25);
        assert_eq!(dashboard.totals.request_count, 1);
        assert_eq!(dashboard.by_model[0].name, "gpt-test");
    }

    #[tokio::test]
    async fn purges_rows_outside_retention_window() {
        let store = TelemetryStore::open_in_memory(24).await.unwrap();
        let old = now_ms() - (25 * 60 * 60 * 1000);
        store
            .insert_request(&RequestRecord {
                request_id: "req-old".to_string(),
                started_at_ms: old,
                completed_at_ms: Some(old),
                method: "POST".to_string(),
                path: "/v1/messages".to_string(),
                mode: "reverse".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                model: None,
                status_code: Some(200),
                error: None,
            })
            .await
            .unwrap();

        let deleted = store.purge_expired().await.unwrap();
        assert_eq!(deleted, 1);
        assert!(!request_exists(&store, "req-old").await.unwrap());
    }

    #[tokio::test]
    async fn tool_history_excludes_tool_definitions() {
        let store = TelemetryStore::open_in_memory(24).await.unwrap();
        let now = now_ms();
        store
            .insert_request(&RequestRecord {
                request_id: "req-tools".to_string(),
                started_at_ms: now,
                completed_at_ms: Some(now),
                method: "WEBSOCKET".to_string(),
                path: "/v1/responses".to_string(),
                mode: "mitm-websocket".to_string(),
                upstream: "https://chatgpt.com/backend-api/codex/responses".to_string(),
                model: Some("gpt-test".to_string()),
                status_code: Some(101),
                error: None,
            })
            .await
            .unwrap();
        for (event_kind, tool_name, call_id, status) in [
            ("tool_definition", "exec_command", None, None),
            (
                "tool_call",
                "exec_command",
                Some("call_1"),
                Some("completed"),
            ),
        ] {
            store
                .insert_tool_event(&ToolEventRecord {
                    request_id: "req-tools".to_string(),
                    observed_at_ms: now,
                    event_kind: event_kind.to_string(),
                    tool_name: Some(tool_name.to_string()),
                    call_id: call_id.map(ToOwned::to_owned),
                    status: status.map(ToOwned::to_owned),
                    source: "websocket".to_string(),
                })
                .await
                .unwrap();
        }

        let dashboard = store.tool_history_dashboard(24, 20).await.unwrap();
        assert_eq!(dashboard.events.len(), 1);
        assert_eq!(dashboard.events[0].event_kind, "tool_call");
        assert_eq!(dashboard.events[0].call_id.as_deref(), Some("call_1"));
        assert_eq!(dashboard.events[0].status.as_deref(), Some("completed"));
    }

    #[tokio::test]
    async fn request_timeline_includes_redacted_content_previews() {
        let store = TelemetryStore::open_in_memory(24).await.unwrap();
        let now = now_ms();
        store
            .insert_request(&RequestRecord {
                request_id: "req-preview".to_string(),
                started_at_ms: now,
                completed_at_ms: Some(now + 10),
                method: "POST".to_string(),
                path: "/v1/responses".to_string(),
                mode: "reverse".to_string(),
                upstream: "https://api.openai.com/v1/responses".to_string(),
                model: Some("gpt-test".to_string()),
                status_code: Some(200),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_content_capture(&ContentCaptureRecord {
                request_id: "req-preview".to_string(),
                observed_at_ms: now,
                direction: "request".to_string(),
                source: "http".to_string(),
                content_type: Some("application/json".to_string()),
                preview_text: r#"{"input":"hello [EMAIL_1]"}"#.to_string(),
                truncated: false,
                redacted: true,
            })
            .await
            .unwrap();
        store
            .insert_content_capture(&ContentCaptureRecord {
                request_id: "req-preview".to_string(),
                observed_at_ms: now + 1,
                direction: "response".to_string(),
                source: "http".to_string(),
                content_type: Some("application/json".to_string()),
                preview_text: r#"{"output_text":"ok"}"#.to_string(),
                truncated: true,
                redacted: true,
            })
            .await
            .unwrap();

        let dashboard = store.request_timeline_dashboard(24, 10).await.unwrap();
        assert_eq!(dashboard.events.len(), 1);
        assert_eq!(dashboard.events[0].request_id, "req-preview");
        assert_eq!(
            dashboard.events[0].request_preview.as_deref(),
            Some(r#"{"input":"hello [EMAIL_1]"}"#)
        );
        assert_eq!(
            dashboard.events[0].response_preview.as_deref(),
            Some(r#"{"output_text":"ok"}"#)
        );
        assert!(!dashboard.events[0].request_truncated);
        assert!(dashboard.events[0].response_truncated);
    }

    #[tokio::test]
    async fn request_timeline_omits_html_content_previews() {
        let store = TelemetryStore::open_in_memory(24).await.unwrap();
        let now = now_ms();
        store
            .insert_request(&RequestRecord {
                request_id: "req-html".to_string(),
                started_at_ms: now,
                completed_at_ms: Some(now + 10),
                method: "GET".to_string(),
                path: "/backend-api/codex/analytics-events/events".to_string(),
                mode: "mitm".to_string(),
                upstream: "https://chatgpt.com/backend-api/codex/analytics-events/events"
                    .to_string(),
                model: None,
                status_code: Some(403),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_content_capture(&ContentCaptureRecord {
                request_id: "req-html".to_string(),
                observed_at_ms: now,
                direction: "response".to_string(),
                source: "http".to_string(),
                content_type: Some("text/html; charset=UTF-8".to_string()),
                preview_text: "<html><body>challenge</body></html>".to_string(),
                truncated: true,
                redacted: true,
            })
            .await
            .unwrap();

        let dashboard = store.request_timeline_dashboard(24, 10).await.unwrap();
        assert_eq!(dashboard.events.len(), 1);
        assert_eq!(
            dashboard.events[0].response_preview.as_deref(),
            Some(
                "[HTML response body omitted from dashboard capture: content_type=\"text/html; charset=UTF-8\"]"
            )
        );
        assert!(!dashboard.events[0].response_truncated);
    }

    #[tokio::test]
    async fn error_dashboard_returns_recent_failed_requests() {
        let store = TelemetryStore::open_in_memory(24).await.unwrap();
        let now = now_ms();
        store
            .insert_request(&RequestRecord {
                request_id: "req-error".to_string(),
                started_at_ms: now,
                completed_at_ms: Some(now),
                method: "POST".to_string(),
                path: "/v1/responses".to_string(),
                mode: "mitm-websocket".to_string(),
                upstream: "https://chatgpt.com/backend-api/codex/responses".to_string(),
                model: Some("gpt-test".to_string()),
                status_code: Some(502),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_request(&RequestRecord {
                request_id: "req-aux".to_string(),
                started_at_ms: now + 1,
                completed_at_ms: Some(now + 1),
                method: "POST".to_string(),
                path: "/backend-api/codex/analytics-events/events".to_string(),
                mode: "mitm-http".to_string(),
                upstream: "https://chatgpt.com/backend-api/codex/analytics-events/events"
                    .to_string(),
                model: None,
                status_code: Some(403),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_request(&RequestRecord {
                request_id: "req-plugins".to_string(),
                started_at_ms: now + 2,
                completed_at_ms: Some(now + 2),
                method: "GET".to_string(),
                path: "/backend-api/plugins/featured?platform=codex".to_string(),
                mode: "mitm-http".to_string(),
                upstream: "https://chatgpt.com/backend-api/plugins/featured?platform=codex"
                    .to_string(),
                model: None,
                status_code: Some(403),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_request(&RequestRecord {
                request_id: "req-transport-error".to_string(),
                started_at_ms: now + 3,
                completed_at_ms: Some(now + 3),
                method: "GET".to_string(),
                path: "/v1/responses".to_string(),
                mode: "http".to_string(),
                upstream: "https://api.openai.com/v1/responses".to_string(),
                model: None,
                status_code: None,
                error: Some("upstream timeout".to_string()),
            })
            .await
            .unwrap();
        store
            .insert_request(&RequestRecord {
                request_id: "req-local-proxy".to_string(),
                started_at_ms: now + 4,
                completed_at_ms: Some(now + 4),
                method: "GET".to_string(),
                path: "https://api.anthropic.com/http://127.0.0.1:5180/index.html".to_string(),
                mode: "reverse".to_string(),
                upstream: "https://api.anthropic.com/http://127.0.0.1:5180/index.html".to_string(),
                model: None,
                status_code: Some(404),
                error: None,
            })
            .await
            .unwrap();
        store
            .insert_request(&RequestRecord {
                request_id: "req-scan-probe".to_string(),
                started_at_ms: now + 5,
                completed_at_ms: Some(now + 5),
                method: "POST".to_string(),
                path: "https://api.anthropic.com/scan".to_string(),
                mode: "reverse".to_string(),
                upstream: "https://api.anthropic.com/scan".to_string(),
                model: None,
                status_code: Some(404),
                error: None,
            })
            .await
            .unwrap();

        let dashboard = store.error_dashboard(24, 10).await.unwrap();
        assert_eq!(dashboard.errors.len(), 2);
        assert_eq!(dashboard.auxiliary_errors.len(), 4);
        assert!(
            dashboard
                .errors
                .iter()
                .any(|item| item.request_id == "req-error" && item.status_code == Some(502))
        );
        assert!(
            dashboard
                .errors
                .iter()
                .any(|item| item.request_id == "req-transport-error"
                    && item.error.as_deref() == Some("upstream timeout"))
        );
        assert!(
            dashboard
                .auxiliary_errors
                .iter()
                .any(|item| item.request_id == "req-aux" && item.status_code == Some(403))
        );
        assert!(
            dashboard
                .auxiliary_errors
                .iter()
                .any(|item| item.request_id == "req-plugins" && item.status_code == Some(403))
        );
        assert!(
            dashboard
                .auxiliary_errors
                .iter()
                .any(|item| item.request_id == "req-local-proxy" && item.status_code == Some(404))
        );
        assert!(
            dashboard
                .auxiliary_errors
                .iter()
                .any(|item| item.request_id == "req-scan-probe" && item.status_code == Some(404))
        );

        let usage = store.usage_dashboard(24).await.unwrap();
        assert_eq!(usage.totals.error_count, 2);
        assert_eq!(usage.totals.auxiliary_error_count, 4);
    }
}
