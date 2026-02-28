use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use artisan_middleware::{
    aggregator::Metrics,
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
            types::stringy::Stringy,
        },
        log,
    },
    historics::UsageLedger,
};
use chrono::{Datelike, Local, LocalResult, TimeZone};
use once_cell::sync::Lazy;
use tokio::{sync::RwLock, time};

use crate::definitions::{LEDGER_ARCHIVE_DIR, LEDGER_PATH};

static LEDGER: Lazy<RwLock<UsageLedger>> = Lazy::new(|| RwLock::new(UsageLedger::new()));

/// Loads the persisted ledger if present, otherwise starts with an empty ledger.
pub async fn initialise() -> Result<(), ErrorArrayItem> {
    let loaded = if Path::new(LEDGER_PATH).exists() {
        UsageLedger::load_from_disk(LEDGER_PATH)?
    } else {
        UsageLedger::new()
    };

    let mut ledger = LEDGER.write().await;
    *ledger = loaded;
    log!(LogLevel::Info, "Usage ledger initialised");
    Ok(())
}

/// Records a batch of application metrics into the in-memory ledger.
pub async fn record_batch(entries: Vec<(String, Metrics)>) {
    if entries.is_empty() {
        return;
    }

    let mut ledger = LEDGER.write().await;
    for (name, metrics) in entries {
        ledger.update_application_usage(Stringy::from(name), metrics);
    }
}

/// Persists the current ledger to disk.
pub async fn persist() -> Result<(), ErrorArrayItem> {
    let ledger = LEDGER.read().await;
    ledger.persist_to_disk(LEDGER_PATH)
}

/// Returns the most recent metrics sample recorded for an application.
pub async fn latest_metrics(name: &str) -> Option<Metrics> {
    let ledger = LEDGER.read().await;
    let key = Stringy::from(name.to_string());
    ledger
        .applications
        .get(&key)
        .and_then(|entry| entry.last_metrics.clone())
}

/// Background helper to flush the ledger to disk at a fixed cadence.
pub async fn run_persistence_loop(interval: Duration) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(err) = persist().await {
            log!(
                LogLevel::Warn,
                "Unable to persist usage ledger to {}: {}",
                LEDGER_PATH,
                err.err_mesg
            );
        }
    }
}

/// Background task that archives and resets the ledger at local midnight.
pub async fn run_daily_archive_loop() {
    loop {
        let sleep_duration = duration_until_next_midnight();
        time::sleep(sleep_duration).await;
        if let Err(err) = rotate_and_archive().await {
            log!(
                LogLevel::Warn,
                "Failed to archive usage ledger at midnight: {}",
                err.err_mesg
            );
        }
    }
}

/// Persists the active ledger, copies it to the archive directory, and resets in-memory state.
pub async fn rotate_and_archive() -> Result<(), ErrorArrayItem> {
    {
        let ledger = LEDGER.read().await;
        ledger.persist_to_disk(LEDGER_PATH)?;
    }

    ensure_archive_dir()?;

    let archive_path = archive_file_path();
    fs::copy(LEDGER_PATH, &archive_path).map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!(
                "Failed to copy usage ledger to {}: {}",
                archive_path.display(),
                err
            ),
        )
    })?;

    {
        let mut ledger = LEDGER.write().await;
        *ledger = UsageLedger::new();
        ledger.persist_to_disk(LEDGER_PATH)?;
    }

    log!(
        LogLevel::Info,
        "Archived usage ledger to {} and reset active ledger",
        archive_path.display()
    );

    Ok(())
}

fn ensure_archive_dir() -> Result<(), ErrorArrayItem> {
    fs::create_dir_all(LEDGER_ARCHIVE_DIR).map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!(
                "Failed to create ledger archive directory {}: {}",
                LEDGER_ARCHIVE_DIR, err
            ),
        )
    })
}

fn archive_file_path() -> PathBuf {
    let now = Local::now();
    let stamp = now.format("%Y-%m-%dT%H-%M-%S").to_string();
    Path::new(LEDGER_ARCHIVE_DIR).join(format!("ledger-{stamp}.json"))
}

fn duration_until_next_midnight() -> Duration {
    let now = Local::now();
    let tomorrow = now.date_naive() + chrono::Duration::days(1);
    let midnight = match Local.with_ymd_and_hms(
        tomorrow.year(),
        tomorrow.month(),
        tomorrow.day(),
        0,
        0,
        0,
    ) {
        LocalResult::Single(dt) => dt,
        LocalResult::Ambiguous(dt, _) => dt,
        LocalResult::None => now + chrono::Duration::days(1),
    };

    (midnight - now)
        .to_std()
        .unwrap_or_else(|_| Duration::from_secs(0))
}
