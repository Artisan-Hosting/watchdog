//! SQLite-backed usage and log ledger.
//!
//! This module stores periodic resource snapshots and stdout/stderr records so
//! watchdog can serve both current and historical telemetry over gRPC.

use std::path::Path;

use artisan_middleware::{
    aggregator::{Metrics, NetworkUsage},
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
        },
        log,
    },
    timestamp::current_timestamp,
};
use once_cell::sync::Lazy;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::Mutex;

use crate::{definitions::LEDGER_PATH, runtime_flags::runtime_flags};

#[derive(Debug, Clone)]
pub struct UsageSummary {
    pub application: String,
    pub start: u64,
    pub end: u64,
    pub avg_cpu: f32,
    pub avg_mem: f64,
    pub peak_mem: f64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub samples: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

impl LogStream {
    fn as_i64(self) -> i64 {
        match self {
            LogStream::Stdout => 1,
            LogStream::Stderr => 2,
        }
    }

    fn from_i64(value: i64) -> Option<Self> {
        match value {
            1 => Some(LogStream::Stdout),
            2 => Some(LogStream::Stderr),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LogStreamFilter {
    Stdout,
    Stderr,
    Both,
}

#[derive(Debug, Clone)]
pub struct HistoricalLogRecord {
    pub id: u64,
    pub application: String,
    pub stream: LogStream,
    pub timestamp: u64,
    pub line: String,
}

#[derive(Debug, Clone)]
pub struct HistoricalLogsPage {
    pub entries: Vec<HistoricalLogRecord>,
    pub next_cursor: u64,
    pub has_more: bool,
}

const DEFAULT_HISTORICAL_QUERY_LIMIT: u32 = 500;
const MAX_HISTORICAL_QUERY_LIMIT: u32 = 5_000;

static CONNECTION: Lazy<Mutex<Option<Connection>>> = Lazy::new(|| Mutex::new(None));

/// Opens the ledger database and ensures schema/indexes are present.
pub async fn initialise() -> Result<(), ErrorArrayItem> {
    '_open_and_prepare_db: {
        let mut guard = CONNECTION.lock().await;
        let conn = open_connection()?;
        initialise_schema(&conn)?;
        *guard = Some(conn);
    }

    log!(LogLevel::Info, "Usage ledger initialised (sqlite backing)");
    Ok(())
}

/// Persists a batch of per-application metrics samples.
pub async fn record_batch(entries: Vec<(String, Metrics)>) {
    if entries.is_empty() {
        return;
    }

    let mut guard = CONNECTION.lock().await;
    let Some(conn) = guard.as_mut() else {
        return;
    };

    if let Err(err) = insert_samples(conn, entries) {
        log!(
            LogLevel::Warn,
            "Failed to insert usage samples into ledger: {}",
            err.err_mesg
        );
    }
}

/// Returns the latest metrics sample for an application, if available.
pub async fn latest_metrics(name: &str) -> Option<Metrics> {
    let guard = CONNECTION.lock().await;
    guard
        .as_ref()
        .and_then(|conn| read_latest_sample(conn, name).ok().flatten())
}

/// Summarizes usage metrics for an application over a `[start, end]` window.
pub async fn summarize_usage(
    name: &str,
    start: u64,
    end: u64,
) -> Result<Option<UsageSummary>, ErrorArrayItem> {
    let guard = CONNECTION.lock().await;
    let Some(conn) = guard.as_ref() else {
        return Ok(None);
    };

    summarize_window(conn, name, start, end)
}

/// Persists new stdout/stderr lines for an application.
pub async fn record_stream_entries(
    application: &str,
    stream: LogStream,
    entries: &[(u64, String)],
) -> Result<(), ErrorArrayItem> {
    if application.trim().is_empty() || entries.is_empty() {
        return Ok(());
    }

    let mut guard = CONNECTION.lock().await;
    let Some(conn) = guard.as_mut() else {
        return Ok(());
    };

    insert_stream_entries(conn, application, stream, entries)
}

/// Queries paginated historical logs for an application and stream filter.
pub async fn query_historical_logs(
    application: &str,
    stream: LogStreamFilter,
    start: u64,
    end: u64,
    cursor: u64,
    limit: u32,
) -> Result<HistoricalLogsPage, ErrorArrayItem> {
    if application.trim().is_empty() {
        return Ok(HistoricalLogsPage {
            entries: Vec::new(),
            next_cursor: cursor,
            has_more: false,
        });
    }

    let guard = CONNECTION.lock().await;
    let Some(conn) = guard.as_ref() else {
        return Ok(HistoricalLogsPage {
            entries: Vec::new(),
            next_cursor: cursor,
            has_more: false,
        });
    };

    query_historical_window(conn, application, stream, start, end, cursor, limit)
}

fn open_connection() -> Result<Connection, ErrorArrayItem> {
    if let Some(parent) = Path::new(LEDGER_PATH).parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!(
                    "Failed to create ledger directory {}: {err}",
                    parent.display()
                ),
            )
        })?;
    }

    Connection::open(LEDGER_PATH).map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to open ledger database {}: {err}", LEDGER_PATH),
        )
    })
}

fn initialise_schema(conn: &Connection) -> Result<(), ErrorArrayItem> {
    let journal_mode = if runtime_flags().ledger_awol {
        log!(
            LogLevel::Warn,
            "Ledger AWOL mode active: WAL disabled (journal_mode=DELETE)"
        );
        "DELETE"
    } else {
        "WAL"
    };

    let schema = format!(
        r#"
        PRAGMA journal_mode={journal_mode};
        CREATE TABLE IF NOT EXISTS samples (
            app_name TEXT NOT NULL,
            ts INTEGER NOT NULL,
            cpu REAL NOT NULL,
            mem REAL NOT NULL,
            rx INTEGER,
            tx INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_samples_app_ts ON samples (app_name, ts);
        CREATE TABLE IF NOT EXISTS std_log_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL,
            stream INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            line TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_std_log_entries_app_stream_ts_id
            ON std_log_entries (app_name, stream, ts, id);
        CREATE INDEX IF NOT EXISTS idx_std_log_entries_app_ts_id
            ON std_log_entries (app_name, ts, id);
        CREATE TABLE IF NOT EXISTS std_log_cursors (
            app_name TEXT NOT NULL,
            stream INTEGER NOT NULL,
            last_ts INTEGER NOT NULL DEFAULT 0,
            last_count INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (app_name, stream)
        );
    "#
    );

    conn.execute_batch(&schema).map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to initialise usage ledger schema: {err}"),
        )
    })
}

fn insert_samples(
    conn: &mut Connection,
    entries: Vec<(String, Metrics)>,
) -> Result<(), ErrorArrayItem> {
    let tx = conn.transaction().map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to start ledger transaction: {err}"),
        )
    })?;

    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO samples (app_name, ts, cpu, mem, rx, tx) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .map_err(|err| {
                ErrorArrayItem::new(
                    Errors::GeneralError,
                    format!("Failed to prepare ledger insert: {err}"),
                )
            })?;

        for (name, metrics) in entries {
            let timestamp = current_timestamp() as i64;
            let (rx, tx_val) = metrics
                .other
                .as_ref()
                .map(|net| (Some(net.rx_bytes as i64), Some(net.tx_bytes as i64)))
                .unwrap_or((None, None));

            stmt.execute(params![
                name,
                timestamp,
                metrics.cpu_usage,
                metrics.memory_usage,
                rx,
                tx_val
            ])
            .map_err(|err| {
                ErrorArrayItem::new(
                    Errors::InputOutput,
                    format!("Failed to insert usage sample: {err}"),
                )
            })?;
        }
    }

    tx.commit().map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to commit usage ledger transaction: {err}"),
        )
    })
}

fn read_latest_sample(conn: &Connection, name: &str) -> Result<Option<Metrics>, ErrorArrayItem> {
    conn.prepare(
        "SELECT cpu, mem, rx, tx FROM samples WHERE app_name = ?1 ORDER BY ts DESC LIMIT 1",
    )
    .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?
    .query_row(params![name], |row| {
        let cpu: f32 = row.get(0)?;
        let mem: f64 = row.get(1)?;
        let rx: Option<i64> = row.get(2)?;
        let tx: Option<i64> = row.get(3)?;
        let other = match (rx, tx) {
            (Some(rx_bytes), Some(tx_bytes)) => Some(NetworkUsage {
                rx_bytes: rx_bytes as u64,
                tx_bytes: tx_bytes as u64,
            }),
            _ => None,
        };

        Ok(Metrics {
            cpu_usage: cpu,
            memory_usage: mem,
            other,
        })
    })
    .optional()
    .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))
}

fn summarize_window(
    conn: &Connection,
    name: &str,
    start: u64,
    end: u64,
) -> Result<Option<UsageSummary>, ErrorArrayItem> {
    if start > end {
        return Ok(None);
    }

    conn.prepare(
        r#"
        SELECT
            COUNT(*) as samples,
            COALESCE(AVG(cpu), 0.0) AS avg_cpu,
            COALESCE(AVG(mem), 0.0) AS avg_mem,
            COALESCE(MAX(mem), 0.0) AS peak_mem,
            COALESCE(MAX(rx), 0) AS max_rx,
            COALESCE(MIN(rx), 0) AS min_rx,
            COALESCE(MAX(tx), 0) AS max_tx,
            COALESCE(MIN(tx), 0) AS min_tx
        FROM samples
        WHERE app_name = ?1
          AND ts BETWEEN ?2 AND ?3
        "#,
    )
    .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?
    .query_row(params![name, start as i64, end as i64], |row| {
        let samples: u64 = row.get::<_, i64>(0)? as u64;
        let avg_cpu: f32 = row.get(1)?;
        let avg_mem: f64 = row.get(2)?;
        let peak_mem: f64 = row.get(3)?;
        let max_rx: u64 = row.get::<_, i64>(4)? as u64;
        let min_rx: u64 = row.get::<_, i64>(5)? as u64;
        let max_tx: u64 = row.get::<_, i64>(6)? as u64;
        let min_tx: u64 = row.get::<_, i64>(7)? as u64;
        let total_rx = max_rx.saturating_sub(min_rx);
        let total_tx = max_tx.saturating_sub(min_tx);

        Ok((samples, avg_cpu, avg_mem, peak_mem, total_rx, total_tx))
    })
    .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))
    .map(
        |(samples, avg_cpu, avg_mem, peak_mem, total_rx, total_tx)| {
            if samples == 0 {
                None
            } else {
                Some(UsageSummary {
                    application: name.to_string(),
                    start,
                    end,
                    avg_cpu,
                    avg_mem,
                    peak_mem,
                    total_rx,
                    total_tx,
                    samples,
                })
            }
        },
    )
}

fn insert_stream_entries(
    conn: &mut Connection,
    application: &str,
    stream: LogStream,
    entries: &[(u64, String)],
) -> Result<(), ErrorArrayItem> {
    let tx = conn.transaction().map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to start log ingestion transaction: {err}"),
        )
    })?;

    let (last_ts, last_count) = load_cursor(&tx, application, stream)?;
    let mut remaining_same_ts_skip = last_count;
    let mut to_insert: Vec<(u64, &str)> = Vec::new();

    for (timestamp, line) in entries {
        if *timestamp < last_ts {
            continue;
        }

        if *timestamp == last_ts && remaining_same_ts_skip > 0 {
            remaining_same_ts_skip -= 1;
            continue;
        }

        to_insert.push((*timestamp, line.as_str()));
    }

    if to_insert.is_empty() {
        tx.commit().map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to commit log transaction with no-op ingestion: {err}"),
            )
        })?;
        return Ok(());
    }

    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO std_log_entries (app_name, stream, ts, line) VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(|err| {
                ErrorArrayItem::new(
                    Errors::GeneralError,
                    format!("Failed to prepare log insert statement: {err}"),
                )
            })?;

        for (timestamp, line) in &to_insert {
            stmt.execute(params![
                application,
                stream.as_i64(),
                *timestamp as i64,
                *line
            ])
            .map_err(|err| {
                ErrorArrayItem::new(
                    Errors::InputOutput,
                    format!("Failed to insert log entry: {err}"),
                )
            })?;
        }
    }

    let last_inserted_ts = to_insert.last().map(|(ts, _)| *ts).unwrap_or(last_ts);
    let snapshot_count_for_last_ts = entries
        .iter()
        .filter(|(timestamp, _)| *timestamp == last_inserted_ts)
        .count() as u64;

    let updated_last_count = if last_inserted_ts == last_ts {
        last_count.max(snapshot_count_for_last_ts)
    } else {
        snapshot_count_for_last_ts
    };

    upsert_cursor(
        &tx,
        application,
        stream,
        last_inserted_ts,
        updated_last_count,
    )?;

    tx.commit().map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to commit log ingestion transaction: {err}"),
        )
    })
}

fn load_cursor(
    tx: &rusqlite::Transaction<'_>,
    application: &str,
    stream: LogStream,
) -> Result<(u64, u64), ErrorArrayItem> {
    tx.prepare(
        "SELECT last_ts, last_count FROM std_log_cursors WHERE app_name = ?1 AND stream = ?2",
    )
    .map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to prepare cursor lookup: {err}"),
        )
    })?
    .query_row(params![application, stream.as_i64()], |row| {
        let last_ts: i64 = row.get(0)?;
        let last_count: i64 = row.get(1)?;
        Ok((last_ts as u64, last_count as u64))
    })
    .optional()
    .map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to read log cursor: {err}"),
        )
    })
    .map(|value| value.unwrap_or((0, 0)))
}

fn upsert_cursor(
    tx: &rusqlite::Transaction<'_>,
    application: &str,
    stream: LogStream,
    last_ts: u64,
    last_count: u64,
) -> Result<(), ErrorArrayItem> {
    tx.execute(
        r#"
        INSERT INTO std_log_cursors (app_name, stream, last_ts, last_count, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(app_name, stream)
        DO UPDATE SET
            last_ts = excluded.last_ts,
            last_count = excluded.last_count,
            updated_at = excluded.updated_at
        "#,
        params![
            application,
            stream.as_i64(),
            last_ts as i64,
            last_count as i64,
            current_timestamp() as i64
        ],
    )
    .map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to upsert log cursor: {err}"),
        )
    })?;

    Ok(())
}

fn query_historical_window(
    conn: &Connection,
    application: &str,
    stream: LogStreamFilter,
    start: u64,
    end: u64,
    cursor: u64,
    limit: u32,
) -> Result<HistoricalLogsPage, ErrorArrayItem> {
    if start > end {
        return Ok(HistoricalLogsPage {
            entries: Vec::new(),
            next_cursor: cursor,
            has_more: false,
        });
    }

    let effective_limit = if limit == 0 {
        DEFAULT_HISTORICAL_QUERY_LIMIT
    } else {
        limit.min(MAX_HISTORICAL_QUERY_LIMIT)
    };
    let fetch_limit = effective_limit.saturating_add(1) as i64;

    let entries = match stream {
        LogStreamFilter::Stdout | LogStreamFilter::Stderr => {
            let stream_code = match stream {
                LogStreamFilter::Stdout => LogStream::Stdout.as_i64(),
                LogStreamFilter::Stderr => LogStream::Stderr.as_i64(),
                LogStreamFilter::Both => unreachable!(),
            };

            let mut stmt = conn
                .prepare(
                    r#"
                    SELECT id, app_name, stream, ts, line
                    FROM std_log_entries
                    WHERE app_name = ?1
                      AND stream = ?2
                      AND ts BETWEEN ?3 AND ?4
                      AND id > ?5
                    ORDER BY id ASC
                    LIMIT ?6
                    "#,
                )
                .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

            let rows = stmt
                .query_map(
                    params![
                        application,
                        stream_code,
                        start as i64,
                        end as i64,
                        cursor as i64,
                        fetch_limit
                    ],
                    map_historical_row,
                )
                .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))?
        }
        LogStreamFilter::Both => {
            let mut stmt = conn
                .prepare(
                    r#"
                    SELECT id, app_name, stream, ts, line
                    FROM std_log_entries
                    WHERE app_name = ?1
                      AND ts BETWEEN ?2 AND ?3
                      AND id > ?4
                    ORDER BY id ASC
                    LIMIT ?5
                    "#,
                )
                .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

            let rows = stmt
                .query_map(
                    params![
                        application,
                        start as i64,
                        end as i64,
                        cursor as i64,
                        fetch_limit
                    ],
                    map_historical_row,
                )
                .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))?
        }
    };

    let has_more = entries.len() > effective_limit as usize;
    let mut trimmed = entries;
    if has_more {
        trimmed.truncate(effective_limit as usize);
    }

    let next_cursor = trimmed.last().map(|record| record.id).unwrap_or(cursor);

    Ok(HistoricalLogsPage {
        entries: trimmed,
        next_cursor,
        has_more,
    })
}

fn map_historical_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HistoricalLogRecord> {
    let stream_value: i64 = row.get(2)?;
    let stream = LogStream::from_i64(stream_value).unwrap_or(LogStream::Stdout);
    Ok(HistoricalLogRecord {
        id: row.get::<_, i64>(0)? as u64,
        application: row.get(1)?,
        stream,
        timestamp: row.get::<_, i64>(3)? as u64,
        line: row.get(4)?,
    })
}
