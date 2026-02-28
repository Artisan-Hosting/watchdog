use std::time::{SystemTime, UNIX_EPOCH};

use artisan_middleware::dusa_collection_utils::{
    core::{errors::ErrorArrayItem, logger::LogLevel},
    log,
};
use chrono::{DateTime, Utc};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    process::Command,
};

use crate::definitions::{
    ARTISAN_LOG_DIR, SystemInformationStore, WATCHDOG_SECURITY_AUDIT_LOG_PATH,
    WATCHDOG_TAMPER_FLAG_PATH,
};

pub async fn consume_startup_trip_marker(
    system_information_store: &SystemInformationStore,
) -> Result<(), ErrorArrayItem> {
    let metadata = match fs::metadata(WATCHDOG_TAMPER_FLAG_PATH).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ErrorArrayItem::from(err)),
    };

    let created_at = metadata
        .created()
        .or_else(|_| metadata.modified())
        .unwrap_or_else(|_| SystemTime::now());
    let created_at_unix = unix_timestamp(created_at);
    let created_at_rfc3339 = DateTime::<Utc>::from(created_at).to_rfc3339();
    let reboot_context = query_previous_boot_reboot_context().await;
    if let Some(ctx) = reboot_context.as_ref() {
        log!(
            LogLevel::Warn,
            "Recovered AWDOG reboot context from previous boot: reason={}, phase={}",
            ctx.reason,
            ctx.phase
        );
    }
    let summary = reboot_context
        .as_ref()
        .map(|ctx| ctx.summary())
        .unwrap_or_else(|| "security tripped (reason unavailable)".to_string());

    {
        let mut info = system_information_store.write().await;
        info.security_tripped = true;
        info.security_trip_detected_at = created_at_unix;
        info.security_trip_summary = summary.clone();
    }

    if let Err(err) = fs::create_dir_all(ARTISAN_LOG_DIR).await {
        log!(
            LogLevel::Warn,
            "Failed to ensure security audit log directory {}: {}",
            ARTISAN_LOG_DIR,
            err
        );
    } else {
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(WATCHDOG_SECURITY_AUDIT_LOG_PATH)
            .await
        {
            Ok(mut audit_log) => {
                let logged_at = Utc::now().to_rfc3339();
                let reason = reboot_context
                    .as_ref()
                    .map(|ctx| sanitize_audit_field(&ctx.reason))
                    .unwrap_or_else(|| "unknown".to_string());
                let phase = reboot_context
                    .as_ref()
                    .map(|ctx| sanitize_audit_field(&ctx.phase))
                    .unwrap_or_else(|| "unknown".to_string());
                let raw_line = reboot_context
                    .as_ref()
                    .map(|ctx| sanitize_audit_field(&ctx.raw_line))
                    .unwrap_or_else(|| "unavailable".to_string());
                let line = format!(
                    "{} tamper_marker_created_at={} marker_path={} reason=\"{}\" phase=\"{}\" raw=\"{}\"\n",
                    logged_at,
                    created_at_rfc3339,
                    WATCHDOG_TAMPER_FLAG_PATH,
                    reason,
                    phase,
                    raw_line
                );
                if let Err(err) = audit_log.write_all(line.as_bytes()).await {
                    log!(
                        LogLevel::Warn,
                        "Failed to write security audit line {}: {}",
                        WATCHDOG_SECURITY_AUDIT_LOG_PATH,
                        err
                    );
                }
                if let Err(err) = audit_log.flush().await {
                    log!(
                        LogLevel::Warn,
                        "Failed to flush security audit log {}: {}",
                        WATCHDOG_SECURITY_AUDIT_LOG_PATH,
                        err
                    );
                }
            }
            Err(err) => {
                log!(
                    LogLevel::Warn,
                    "Failed to open security audit log {}: {}",
                    WATCHDOG_SECURITY_AUDIT_LOG_PATH,
                    err
                );
            }
        }
    }

    match fs::remove_file(WATCHDOG_TAMPER_FLAG_PATH).await {
        Ok(_) => {
            log!(
                LogLevel::Warn,
                "Consumed and removed security trip marker {}",
                WATCHDOG_TAMPER_FLAG_PATH
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(ErrorArrayItem::from(err)),
    }

    Ok(())
}

fn unix_timestamp(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
struct RebootContext {
    phase: String,
    reason: String,
    raw_line: String,
}

impl RebootContext {
    fn summary(&self) -> String {
        format!(
            "security tripped ({}, phase={})",
            self.reason, self.phase
        )
    }
}

async fn query_previous_boot_reboot_context() -> Option<RebootContext> {
    let output = match Command::new("journalctl")
        .args(["-b", "-1", "--no-pager"])
        .output()
        .await
    {
        Ok(output) => output,
        Err(err) => {
            log!(
                LogLevel::Warn,
                "Failed to run journalctl -b -1 while processing tamper marker: {}",
                err
            );
            return None;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log!(
            LogLevel::Warn,
            "journalctl -b -1 exited with status {} while processing tamper marker: {}",
            output.status,
            stderr.trim()
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_awdog_reboot_from_journal(&stdout)
}

fn parse_awdog_reboot_from_journal(journal_output: &str) -> Option<RebootContext> {
    journal_output
        .lines()
        .rev()
        .find_map(parse_awdog_reboot_line)
}

fn parse_awdog_reboot_line(line: &str) -> Option<RebootContext> {
    let (_, payload) = line.split_once("AWDOG_REBOOT:")?;
    let payload = payload.trim();

    let mut phase: Option<String> = None;
    let mut reason: Option<String> = None;

    for token in payload.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "phase" => phase = Some(value.to_string()),
            "reason" => reason = Some(value.to_string()),
            _ => {}
        }
    }

    let raw_line = payload
        .split_once("raw=")
        .map(|(_, raw)| raw.trim().to_string())
        .unwrap_or_else(|| payload.to_string());

    Some(RebootContext {
        phase: phase.unwrap_or_else(|| "unknown".to_string()),
        reason: reason.unwrap_or_else(|| "unknown".to_string()),
        raw_line,
    })
}

fn sanitize_audit_field(value: &str) -> String {
    value
        .replace('\n', " ")
        .replace('\r', " ")
        .replace('"', "'")
}

#[cfg(test)]
mod tests {
    use super::{parse_awdog_reboot_from_journal, parse_awdog_reboot_line};

    #[test]
    fn parses_awdog_reboot_line_fields() {
        let line = "Feb 27 kernel: AWDOG_REBOOT: phase=reboot_requested reason=timeout raw=awdog: tamper tripped: timeout";
        let parsed = parse_awdog_reboot_line(line).expect("expected AWDOG_REBOOT parse");
        assert_eq!(parsed.phase, "reboot_requested");
        assert_eq!(parsed.reason, "timeout");
        assert_eq!(parsed.raw_line, "awdog: tamper tripped: timeout");
    }

    #[test]
    fn selects_latest_awdog_reboot_entry() {
        let journal = "line a\nAWDOG_REBOOT: phase=reboot_requested reason=verify-failed raw=awdog: tamper tripped: verify-failed\nAWDOG_REBOOT: phase=reboot_requested reason=timeout raw=awdog: tamper tripped: timeout\n";
        let parsed =
            parse_awdog_reboot_from_journal(journal).expect("expected to parse latest entry");
        assert_eq!(parsed.reason, "timeout");
    }
}
