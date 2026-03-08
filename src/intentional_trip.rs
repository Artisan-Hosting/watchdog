//! Internal-only intentional trip routine for the kernel watchdog module.
//!
//! This is designed for "controlled reboot" scenarios:
//! 1) Perform best-effort graceful shutdown bookkeeping (logs, integrity manifest)
//! 2) Switch the kernel watchdog heartbeat client into a fault-injection mode so
//!    the kernel module trips with `reason=verify-failed`.

use std::time::Duration;

use artisan_middleware::dusa_collection_utils::{
    core::{errors::ErrorArrayItem, logger::LogLevel},
    log,
};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    time,
};

use crate::{
    definitions::{ARTISAN_LOG_DIR, SystemInformationStore, WATCHDOG_SECURITY_AUDIT_LOG_PATH},
    functions::persist_shutdown_integrity_manifest,
    kernel_watchdog,
};

const INTENTIONAL_TRIP_ENV: &str = "AIS_WATCHDOG_INTENTIONAL_TRIP";

/// Parses the env marker used to request an intentional trip.
///
/// Convention:
/// - unset / empty => no trip
/// - "1" => trip with a default reason
/// - any other value => used as the reason string
pub(crate) fn intentional_trip_marker() -> Option<String> {
    let raw = std::env::var(INTENTIONAL_TRIP_ENV).ok()?;
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if value == "1" {
        return Some("requested via env marker".to_string());
    }
    Some(value.to_string())
}

/// Performs best-effort shutdown bookkeeping then requests an intentional kernel trip.
///
/// This function never returns on success; it waits for the kernel watchdog module
/// to reboot the system after the malformed heartbeat is sent.
pub(crate) async fn run_intentional_trip_routine(
    reason: &str,
    system_information_store: &SystemInformationStore,
) -> Result<(), ErrorArrayItem> {
    let now = artisan_middleware::timestamp::current_timestamp();
    {
        let mut info = system_information_store.write().await;
        info.security_tripped = true;
        info.security_trip_detected_at = now;
        info.security_trip_summary = format!("intentional_trip: {}", reason);
    }

    write_intentional_trip_audit_line(now, reason).await;

    if let Err(err) = persist_shutdown_integrity_manifest().await {
        log!(
            LogLevel::Warn,
            "Intentional trip: failed to persist shutdown integrity manifest: {}",
            err.err_mesg
        );
    }

    log!(
        LogLevel::Error,
        "Intentional trip requested: {}; switching kernel watchdog to malformed heartbeat mode",
        reason
    );

    kernel_watchdog::request_intentional_trip()?;

    // Give the heartbeat loop time to run; it should trip on the next malformed heartbeat.
    // The system is expected to reboot; we intentionally do not exit this process.
    loop {
        time::sleep(Duration::from_secs(60)).await;
    }
}

async fn write_intentional_trip_audit_line(detected_at_unix: u64, reason: &str) {
    if let Err(err) = fs::create_dir_all(ARTISAN_LOG_DIR).await {
        log!(
            LogLevel::Warn,
            "Intentional trip: failed to ensure audit log directory {}: {}",
            ARTISAN_LOG_DIR,
            err
        );
        return;
    }

    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(WATCHDOG_SECURITY_AUDIT_LOG_PATH)
        .await
    {
        Ok(mut audit_log) => {
            let logged_at = chrono::Utc::now().to_rfc3339();
            let line = format!(
                "{} source=watchdog_intentional_trip detected_at={} reason=\"{}\"\n",
                logged_at,
                detected_at_unix,
                sanitize_audit_field(reason),
            );
            if let Err(err) = audit_log.write_all(line.as_bytes()).await {
                log!(
                    LogLevel::Warn,
                    "Intentional trip: failed to write audit line {}: {}",
                    WATCHDOG_SECURITY_AUDIT_LOG_PATH,
                    err
                );
            }
            let _ = audit_log.flush().await;
        }
        Err(err) => {
            log!(
                LogLevel::Warn,
                "Intentional trip: failed to open audit log {}: {}",
                WATCHDOG_SECURITY_AUDIT_LOG_PATH,
                err
            );
        }
    }
}

fn sanitize_audit_field(value: &str) -> String {
    value
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('"', "'")
}

