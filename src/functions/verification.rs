//! Startup/shutdown integrity manifest generation and comparison.

use artisan_middleware::{
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
            types::pathtype::PathType,
        },
        log,
    },
    encryption::{simple_decrypt, simple_encrypt},
    timestamp::current_timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
};
use tokio::fs as tokio_fs;

use crate::definitions::{
    VerificationEntry, WATCHDOG_IGNORE_INTEGRITY_ENV, WATCHDOG_INTEGRITY_MANIFEST_PATH,
    WATCHDOG_INTEGRITY_ROOTS,
};

const DEBUG_OVERRIDE_ROOTS_ENV: &str = "AIS_WATCHDOG_DEBUG_HASH_ROOTS";
const DEBUG_OVERRIDE_MANIFEST_PATH_ENV: &str = "AIS_WATCHDOG_DEBUG_HASH_MANIFEST";
const MAX_REPORTED_DISCREPANCIES: usize = 25;

#[derive(Debug, Clone)]
pub struct StartupIntegrityReport {
    pub entries: Vec<VerificationEntry>,
    pub discrepancies: Vec<String>,
    pub ignored: bool,
}

impl StartupIntegrityReport {
    /// Returns `true` when no actionable integrity discrepancies were detected.
    pub fn is_healthy(&self) -> bool {
        self.ignored || self.discrepancies.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntegrityManifest {
    generated_at: u64,
    roots: Vec<String>,
    files: Vec<FileDigestRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileDigestRecord {
    path: String,
    sha256: String,
}

/// Verifies on-disk runtime roots against the previously persisted manifest.
pub async fn verify_startup_integrity() -> Result<StartupIntegrityReport, ErrorArrayItem> {
    if integrity_checks_ignored() {
        log!(
            LogLevel::Warn,
            "Startup integrity checks disabled via {} (debug-build flag)",
            WATCHDOG_IGNORE_INTEGRITY_ENV
        );
        return Ok(StartupIntegrityReport {
            entries: vec![new_summary_entry(true, "ignored", "ignored-by-debug-flag")],
            discrepancies: Vec::new(),
            ignored: true,
        });
    }

    let Some(expected) = load_manifest().await? else {
        log!(
            LogLevel::Warn,
            "No integrity manifest found at {}; startup check skipped for this boot",
            manifest_path()
        );
        return Ok(StartupIntegrityReport {
            entries: vec![new_summary_entry(true, "bootstrap", "manifest-missing")],
            discrepancies: Vec::new(),
            ignored: false,
        });
    };

    let current = build_manifest()?;
    let discrepancies = compare_manifests(&expected, &current);

    let mut entries = Vec::new();
    entries.push(new_summary_entry(
        discrepancies.is_empty(),
        &format!("files={}", expected.files.len()),
        &format!(
            "files={} diffs={}",
            current.files.len(),
            discrepancies.len()
        ),
    ));

    for (idx, detail) in discrepancies
        .iter()
        .take(MAX_REPORTED_DISCREPANCIES)
        .enumerate()
    {
        let mut entry = VerificationEntry::new();
        entry.name = format!("integrity_discrepancy_{}", idx + 1);
        entry.path = PathType::Content(detail.clone());
        entry.expected_hash = "match".to_string();
        entry.calculated_hash = "mismatch".to_string();
        entry.verified = false;
        entries.push(entry);
    }

    if discrepancies.len() > MAX_REPORTED_DISCREPANCIES {
        let mut overflow = VerificationEntry::new();
        overflow.name = "integrity_discrepancy_overflow".to_string();
        overflow.path = PathType::Content("additional discrepancies omitted".to_string());
        overflow.expected_hash = MAX_REPORTED_DISCREPANCIES.to_string();
        overflow.calculated_hash = discrepancies.len().to_string();
        overflow.verified = false;
        entries.push(overflow);
    }

    Ok(StartupIntegrityReport {
        entries,
        discrepancies,
        ignored: false,
    })
}

/// Persists a fresh integrity manifest during graceful shutdown.
pub async fn persist_shutdown_integrity_manifest() -> Result<(), ErrorArrayItem> {
    let manifest = build_manifest()?;
    let payload = serde_json::to_vec(&manifest).map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to serialize integrity manifest: {err}"),
        )
    })?;

    let encrypted = simple_encrypt(&payload)?;
    let manifest_path = manifest_path();
    if let Some(parent) = Path::new(&manifest_path).parent() {
        tokio_fs::create_dir_all(parent).await.map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to create integrity manifest directory: {err}"),
            )
        })?;
    }

    tokio_fs::write(&manifest_path, encrypted.to_string())
        .await
        .map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!(
                    "Failed to write integrity manifest {}: {err}",
                    manifest_path
                ),
            )
        })?;

    log!(
        LogLevel::Info,
        "Persisted shutdown integrity manifest with {} files to {}",
        manifest.files.len(),
        manifest_path
    );
    Ok(())
}

fn new_summary_entry(
    verified: bool,
    expected_hash: &str,
    calculated_hash: &str,
) -> VerificationEntry {
    let mut entry = VerificationEntry::new();
    entry.name = "integrity_summary".to_string();
    entry.path = PathType::Content(manifest_path());
    entry.expected_hash = expected_hash.to_string();
    entry.calculated_hash = calculated_hash.to_string();
    entry.verified = verified;
    entry
}

fn integrity_checks_ignored() -> bool {
    #[cfg(debug_assertions)]
    {
        parse_env_flag(WATCHDOG_IGNORE_INTEGRITY_ENV)
    }

    #[cfg(not(debug_assertions))]
    {
        false
    }
}

fn parse_env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "enabled"
        ),
        Err(_) => false,
    }
}

fn monitored_roots() -> Vec<String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(raw) = env::var(DEBUG_OVERRIDE_ROOTS_ENV) {
            let parsed: Vec<String> = raw
                .split(',')
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect();
            if !parsed.is_empty() {
                log!(
                    LogLevel::Warn,
                    "Using debug integrity roots override from {}: {}",
                    DEBUG_OVERRIDE_ROOTS_ENV,
                    parsed.join(", ")
                );
                return parsed;
            }
        }
    }

    WATCHDOG_INTEGRITY_ROOTS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn manifest_path() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(path) = env::var(DEBUG_OVERRIDE_MANIFEST_PATH_ENV) {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                log!(
                    LogLevel::Warn,
                    "Using debug integrity manifest override from {}: {}",
                    DEBUG_OVERRIDE_MANIFEST_PATH_ENV,
                    trimmed
                );
                return trimmed.to_string();
            }
        }
    }

    WATCHDOG_INTEGRITY_MANIFEST_PATH.to_string()
}

async fn load_manifest() -> Result<Option<IntegrityManifest>, ErrorArrayItem> {
    let path = manifest_path();
    let encrypted = match tokio_fs::read_to_string(&path).await {
        Ok(value) => value,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to read integrity manifest {}: {err}", path),
            ));
        }
    };

    if encrypted.trim().is_empty() {
        return Ok(None);
    }

    let decrypted = simple_decrypt(encrypted.as_bytes())?;
    let manifest: IntegrityManifest = serde_json::from_slice(&decrypted).map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to parse integrity manifest JSON: {err}"),
        )
    })?;
    Ok(Some(manifest))
}

fn build_manifest() -> Result<IntegrityManifest, ErrorArrayItem> {
    let roots = monitored_roots();
    let mut files: Vec<PathBuf> = Vec::new();
    for root in &roots {
        collect_files(Path::new(root), &mut files)?;
    }
    files.sort();

    let mut records = Vec::new();
    for file in files {
        let digest = hash_file(&file)?;
        records.push(FileDigestRecord {
            path: file.to_string_lossy().to_string(),
            sha256: digest,
        });
    }

    Ok(IntegrityManifest {
        generated_at: current_timestamp(),
        roots,
        files: records,
    })
}

fn collect_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), ErrorArrayItem> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(path).map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to inspect {}: {err}", path.display()),
        )
    })?;

    if metadata.file_type().is_file() {
        output.push(path.to_path_buf());
        return Ok(());
    }

    if !metadata.file_type().is_dir() {
        return Ok(());
    }

    let mut children: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to read directory {}: {err}", path.display()),
            )
        })?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .collect();
    children.sort();

    for child in children {
        collect_files(&child, output)?;
    }

    Ok(())
}

fn hash_file(path: &Path) -> Result<String, ErrorArrayItem> {
    let mut file = File::open(path).map_err(|err| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("Failed to open {} for hashing: {err}", path.display()),
        )
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|err| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("Failed to read {} for hashing: {err}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn compare_manifests(expected: &IntegrityManifest, current: &IntegrityManifest) -> Vec<String> {
    let expected_map: HashMap<&str, &str> = expected
        .files
        .iter()
        .map(|item| (item.path.as_str(), item.sha256.as_str()))
        .collect();
    let current_map: HashMap<&str, &str> = current
        .files
        .iter()
        .map(|item| (item.path.as_str(), item.sha256.as_str()))
        .collect();

    let mut discrepancies = Vec::new();

    for (path, expected_hash) in &expected_map {
        match current_map.get(path) {
            Some(current_hash) if current_hash != expected_hash => discrepancies.push(format!(
                "hash mismatch: {} expected={} actual={}",
                path, expected_hash, current_hash
            )),
            Some(_) => {}
            None => discrepancies.push(format!("missing file: {}", path)),
        }
    }

    for path in current_map.keys() {
        if !expected_map.contains_key(path) {
            discrepancies.push(format!("unexpected file: {}", path));
        }
    }

    discrepancies.sort();
    discrepancies
}
