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
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::Mutex;

use crate::definitions::LEDGER_PATH;

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

static CONNECTION: Lazy<Mutex<Option<Connection>>> = Lazy::new(|| Mutex::new(None));

pub async fn initialise() -> Result<(), ErrorArrayItem> {
    let mut guard = CONNECTION.lock().await;
    let conn = open_connection()?;
    initialise_schema(&conn)?;
    *guard = Some(conn);
    log!(LogLevel::Info, "Usage ledger initialised (sqlite backing)");
    Ok(())
}

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

pub async fn latest_metrics(name: &str) -> Option<Metrics> {
    let guard = CONNECTION.lock().await;
    guard
        .as_ref()
        .and_then(|conn| read_latest_sample(conn, name).ok().flatten())
}

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

fn open_connection() -> Result<Connection, ErrorArrayItem> {
    if let Some(parent) = Path::new(LEDGER_PATH).parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to create ledger directory {}: {err}", parent.display()),
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
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS samples (
            app_name TEXT NOT NULL,
            ts INTEGER NOT NULL,
            cpu REAL NOT NULL,
            mem REAL NOT NULL,
            rx INTEGER,
            tx INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_samples_app_ts ON samples (app_name, ts);
    "#,
    )
    .map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to initialise usage ledger schema: {err}"),
        )
    })
}

fn insert_samples(conn: &mut Connection, entries: Vec<(String, Metrics)>) -> Result<(), ErrorArrayItem> {
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

            stmt.execute(params![name, timestamp, metrics.cpu_usage, metrics.memory_usage, rx, tx_val])
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
            COALESCE(SUM(rx), 0) AS total_rx,
            COALESCE(SUM(tx), 0) AS total_tx
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
        let total_rx: u64 = row.get::<_, i64>(4)? as u64;
        let total_tx: u64 = row.get::<_, i64>(5)? as u64;

        Ok((samples, avg_cpu, avg_mem, peak_mem, total_rx, total_tx))
    })
    .map_err(|err| ErrorArrayItem::new(Errors::InputOutput, err.to_string()))
    .map(|(samples, avg_cpu, avg_mem, peak_mem, total_rx, total_tx)| {
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
    })
}
