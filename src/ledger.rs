use std::path::Path;
use std::time::Duration;

use artisan_middleware::{
    aggregator::Metrics,
    dusa_collection_utils::{
        core::{
            errors::ErrorArrayItem,
            logger::LogLevel,
            types::stringy::Stringy,
        },
        log,
    },
    historics::UsageLedger,
};
use once_cell::sync::Lazy;
use tokio::{sync::RwLock, time};

use crate::definitions::LEDGER_PATH;

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
