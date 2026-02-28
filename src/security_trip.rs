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
};

pub async fn refresh_startup_trip_status(
    system_information_store: &SystemInformationStore,
) -> Result<(), ErrorArrayItem> {
    let reboot_context = query_previous_boot_reboot_context().await;
    let (security_tripped, security_trip_detected_at, security_trip_summary) =
        if let Some(ctx) = reboot_context.as_ref() {
            (
                true,
                ctx.detected_at_unix,
                format!("security tripped ({}, phase={})", ctx.reason, ctx.phase),
            )
        } else {
            (false, 0, "clear".to_string())
        };

    if let Some(ctx) = reboot_context.as_ref() {
        log!(
            LogLevel::Warn,
            "Recovered AWDOG reboot context from previous boot: reason={}, phase={}",
            ctx.reason,
            ctx.phase
        );
    }

    {
        let mut info = system_information_store.write().await;
        info.security_tripped = security_tripped;
        info.security_trip_detected_at = security_trip_detected_at;
        info.security_trip_summary = security_trip_summary;
    }

    if let Some(ctx) = reboot_context.as_ref() {
        write_security_audit_line(ctx).await;
    }

    Ok(())
}

async fn write_security_audit_line(ctx: &RebootContext) {
    if let Err(err) = fs::create_dir_all(ARTISAN_LOG_DIR).await {
        log!(
            LogLevel::Warn,
            "Failed to ensure security audit log directory {}: {}",
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
            let logged_at = Utc::now().to_rfc3339();
            let reboot_detected_at =
                DateTime::<Utc>::from_timestamp(ctx.detected_at_unix as i64, 0)
                    .map(|ts| ts.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());
            let line = format!(
                "{} source=journalctl_previous_boot reboot_detected_at={} reason=\"{}\" phase=\"{}\" raw=\"{}\"\n",
                logged_at,
                reboot_detected_at,
                sanitize_audit_field(&ctx.reason),
                sanitize_audit_field(&ctx.phase),
                sanitize_audit_field(&ctx.raw_line),
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

#[derive(Debug, Clone)]
struct RebootContext {
    detected_at_unix: u64,
    phase: String,
    reason: String,
    raw_line: String,
}

async fn query_previous_boot_reboot_context() -> Option<RebootContext> {
    let output = match Command::new("journalctl")
        .args(["-b", "-1", "--no-pager", "-o", "short-unix"])
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
    let detected_at_unix = line
        .split_whitespace()
        .next()
        .and_then(|ts| ts.split('.').next())
        .and_then(|secs| secs.parse::<u64>().ok())
        .unwrap_or(0);
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
        detected_at_unix,
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
        let line = "1772248532.123456 host kernel: AWDOG_REBOOT: phase=reboot_requested reason=timeout raw=awdog: tamper tripped: timeout";
        let parsed = parse_awdog_reboot_line(line).expect("expected AWDOG_REBOOT parse");
        assert_eq!(parsed.detected_at_unix, 1772248532);
        assert_eq!(parsed.phase, "reboot_requested");
        assert_eq!(parsed.reason, "timeout");
        assert_eq!(parsed.raw_line, "awdog: tamper tripped: timeout");
    }

    #[test]
    fn selects_latest_awdog_reboot_entry() {
        let journal = "1772240000.111111 host kernel: AWDOG_REBOOT: phase=reboot_requested reason=verify-failed raw=awdog: tamper tripped: verify-failed\n1772249999.222222 host kernel: AWDOG_REBOOT: phase=reboot_requested reason=timeout raw=awdog: tamper tripped: timeout\n";
        let parsed =
            parse_awdog_reboot_from_journal(journal).expect("expected to parse latest entry");
        assert_eq!(parsed.detected_at_unix, 1772249999);
        assert_eq!(parsed.reason, "timeout");
    }
}
