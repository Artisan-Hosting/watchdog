use artisan_middleware::{
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
        },
        log,
    },
    encryption::{simple_decrypt, simple_encrypt},
    process_manager::SupervisedProcess,
};
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::ErrorKind};
use tokio::fs;

use crate::definitions::WATCHDOG_PID_LEDGER_PATH;

static PID_CACHE: Lazy<tokio::sync::Mutex<HashMap<String, u32>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));

/// Serializable representation of the PID ledger.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedLedger {
    processes: HashMap<String, u32>,
}

impl From<HashMap<String, u32>> for PersistedLedger {
    fn from(processes: HashMap<String, u32>) -> Self {
        Self { processes }
    }
}

impl From<PersistedLedger> for HashMap<String, u32> {
    fn from(value: PersistedLedger) -> Self {
        value.processes
    }
}

/// Loads the persisted PID ledger into memory. Missing files are treated as an empty ledger.
pub async fn initialise() -> Result<(), ErrorArrayItem> {
    let persisted = load_from_disk().await?;
    let mut cache = PID_CACHE.lock().await;
    *cache = persisted;
    Ok(())
}

/// Records a freshly spawned process and persists the updated ledger.
pub async fn remember_process(name: &str, pid: u32) -> Result<(), ErrorArrayItem> {
    let mut cache = PID_CACHE.lock().await;
    cache.insert(name.to_string(), pid);
    persist_to_disk(&cache).await
}

/// Attempts to reclaim any processes that were persisted before a crash by
/// reattaching via [`SupervisedProcess`] and sending termination signals.
pub async fn reclaim_orphan_processes() -> Result<(), ErrorArrayItem> {
    let entries = {
        let cache = PID_CACHE.lock().await;
        cache.clone()
    };

    if entries.is_empty() {
        return Ok(());
    }

    for (name, pid) in entries {
        let pid_i32 = match pid.try_into() {
            Ok(value) => value,
            Err(_) => {
                log!(
                    LogLevel::Warn,
                    "Persisted PID for {} does not fit in i32; skipping",
                    name
                );
                continue;
            }
        };

        match SupervisedProcess::new(Pid::from_raw(pid_i32)) {
            Ok(mut proc) => {
                log!(
                    LogLevel::Info,
                    "Terminating orphaned process {} (PID {}) from previous watchdog instance",
                    name,
                    pid
                );
                if let Err(err) = proc.kill() {
                    log!(
                        LogLevel::Error,
                        "Failed to terminate orphaned process {} (PID {}): {}",
                        name,
                        pid,
                        err.err_mesg
                    );
                }
            }
            Err(err) => {
                log!(
                    LogLevel::Trace,
                    "Skipping persisted PID {} for {}: {}",
                    pid,
                    name,
                    err.err_mesg
                );
            }
        }
    }

    let mut cache = PID_CACHE.lock().await;
    cache.clear();
    persist_to_disk(&cache).await
}

/// Removes a process entry from the ledger and persists the change.
pub async fn forget_process(name: &str) -> Result<(), ErrorArrayItem> {
    let mut cache = PID_CACHE.lock().await;
    if cache.remove(name).is_some() {
        persist_to_disk(&cache).await?
    }
    Ok(())
}

async fn load_from_disk() -> Result<HashMap<String, u32>, ErrorArrayItem> {
    match fs::read_to_string(WATCHDOG_PID_LEDGER_PATH).await {
        Ok(raw) => {
            if raw.trim().is_empty() {
                return Ok(HashMap::new());
            }

            let decrypted = simple_decrypt(raw.as_bytes())?;
            let ledger: PersistedLedger = serde_json::from_slice(&decrypted).map_err(|err| {
                ErrorArrayItem::new(
                    Errors::GeneralError,
                    format!("Failed to parse persisted PID ledger: {}", err),
                )
            })?;

            Ok(ledger.into())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Unable to read PID ledger: {}", err),
        )),
    }
}

async fn persist_to_disk(cache: &HashMap<String, u32>) -> Result<(), ErrorArrayItem> {
    if cache.is_empty() {
        match fs::remove_file(WATCHDOG_PID_LEDGER_PATH).await {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(ErrorArrayItem::new(
                    Errors::InputOutput,
                    format!("Failed to remove PID ledger: {}", err),
                ));
            }
        }
        return Ok(());
    }

    let payload = PersistedLedger::from(cache.clone());
    let serialized = serde_json::to_vec(&payload).map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to serialize PID ledger: {}", err),
        )
    })?;

    let encrypted = simple_encrypt(&serialized)?;

    fs::write(WATCHDOG_PID_LEDGER_PATH, encrypted.to_string())
        .await
        .map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to write PID ledger: {}", err),
            )
        })
}
