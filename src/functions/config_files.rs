//! Safe read/write helpers for per-application config files with versioned backups.
//!
//! All mutation of `ARTISAN_CONF_DIR/<ais_name>/{Config.toml,Overrides.toml}`
//! funnels through this module: TOML validation, timestamped `.aold` backups
//! with retention, atomic replacement, and integrity-manifest re-baselining.

use artisan_middleware::dusa_collection_utils::{
    core::{
        errors::{ErrorArrayItem, Errors},
        logger::LogLevel,
    },
    log,
};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::sync::Mutex;

use crate::definitions::{AIS_PREFIX, ARTISAN_CONF_DIR, WWW_DATA_GID, WWW_DATA_UID};
use crate::functions::inventory::resolve_overrides_path;

#[allow(dead_code)]
const DEBUG_OVERRIDE_CONF_DIR_ENV: &str = "AIS_WATCHDOG_DEBUG_CONF_DIR";
/// Extension appended to timestamped config backups.
pub const CONFIG_BACKUP_EXTENSION: &str = "aold";
/// Number of `.aold` backups retained per config file.
pub const CONFIG_BACKUP_RETENTION: usize = 5;

const NEW_FILE_MODE: u32 = 0o640;
const NEW_DIR_MODE: u32 = 0o750;

/// Serializes socket-triggered config mutations and their integrity-manifest
/// rewrites. Holding one lock across both operations also makes the SHA check
/// an effective optimistic lock when multiple clients edit the same file.
static CONFIG_MUTATION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Which of the two per-application config files is being addressed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConfigFileKind {
    Config,
    Overrides,
}

impl ConfigFileKind {
    /// Canonical on-disk file name for this kind.
    pub fn canonical_file_name(&self) -> &'static str {
        match self {
            ConfigFileKind::Config => "Config.toml",
            ConfigFileKind::Overrides => "Overrides.toml",
        }
    }

    /// Maps the proto `ConfigFileKind` enum value; `None` for unspecified/unknown.
    pub fn from_proto(value: i32) -> Option<Self> {
        match value {
            1 => Some(ConfigFileKind::Config),
            2 => Some(ConfigFileKind::Overrides),
            _ => None,
        }
    }
}

/// Result of a config-file read (or scaffold) request.
#[derive(Debug, Clone)]
pub struct ConfigFileRead {
    pub found: bool,
    pub created: bool,
    pub path: PathBuf,
    pub content: String,
    pub sha256: String,
}

/// Result of a successful config-file write.
#[derive(Debug, Clone)]
pub struct ConfigFileWrite {
    pub backup_file: Option<String>,
    pub path: PathBuf,
}

/// Base directory for application config; debug builds honor
/// `AIS_WATCHDOG_DEBUG_CONF_DIR` for local end-to-end testing.
pub fn conf_dir() -> PathBuf {
    #[cfg(debug_assertions)]
    {
        if let Ok(raw) = env::var(DEBUG_OVERRIDE_CONF_DIR_ENV) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                log!(
                    LogLevel::Warn,
                    "Using debug config dir override from {}: {}",
                    DEBUG_OVERRIDE_CONF_DIR_ENV,
                    trimmed
                );
                return PathBuf::from(trimmed);
            }
        }
    }

    PathBuf::from(ARTISAN_CONF_DIR)
}

/// Rejects application names that could escape `ARTISAN_CONF_DIR`. This is the
/// security boundary for the socket-exposed config endpoints.
pub fn validate_ais_name(name: &str) -> Result<(), ErrorArrayItem> {
    let suffix = name.strip_prefix(AIS_PREFIX).unwrap_or("");
    let valid = !suffix.is_empty()
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err(ErrorArrayItem::new(
            Errors::InvalidType,
            format!("invalid application name: {:?}", name),
        ));
    }
    Ok(())
}

/// Validates that `content` is non-empty, syntactically valid TOML.
pub fn validate_toml(content: &str) -> Result<(), ErrorArrayItem> {
    if content.trim().is_empty() {
        return Err(ErrorArrayItem::new(
            Errors::InvalidType,
            "config content is empty".to_string(),
        ));
    }
    toml::from_str::<toml::Value>(content)
        .map_err(|err| ErrorArrayItem::new(Errors::InvalidType, format!("invalid TOML: {err}")))?;
    Ok(())
}

/// Resolves the on-disk path for an application's config file. For overrides,
/// an existing legacy `Overides.toml` is reused so we never leave both
/// spellings behind; new files always get the canonical name.
pub fn resolve_config_file_path(base_dir: &Path, ais_name: &str, kind: ConfigFileKind) -> PathBuf {
    let config_dir = base_dir.join(ais_name);
    match kind {
        ConfigFileKind::Config => config_dir.join(kind.canonical_file_name()),
        ConfigFileKind::Overrides => resolve_overrides_path(&config_dir)
            .unwrap_or_else(|| config_dir.join(kind.canonical_file_name())),
    }
}

/// Reads an application's config file, optionally scaffolding the directory
/// and a placeholder file when missing (setup mode).
pub fn read_config_file(
    base_dir: &Path,
    ais_name: &str,
    kind: ConfigFileKind,
    create_if_missing: bool,
) -> Result<ConfigFileRead, ErrorArrayItem> {
    validate_ais_name(ais_name)?;

    let path = resolve_config_file_path(base_dir, ais_name, kind);

    if path.is_file() {
        let content = fs::read_to_string(&path).map_err(ErrorArrayItem::from)?;
        let sha256 = sha256_hex(&content);
        return Ok(ConfigFileRead {
            found: true,
            created: false,
            path,
            content,
            sha256,
        });
    }

    if !create_if_missing {
        return Ok(ConfigFileRead {
            found: false,
            created: false,
            path,
            content: String::new(),
            sha256: String::new(),
        });
    }

    let config_dir = base_dir.join(ais_name);
    ensure_config_dir(&config_dir)?;

    let content = match kind {
        ConfigFileKind::Config => placeholder_config_toml(ais_name),
        ConfigFileKind::Overrides => placeholder_overrides_toml(ais_name),
    };
    atomic_write(&path, &content, None)?;

    log!(
        LogLevel::Info,
        "Scaffolded placeholder {} for {}",
        kind.canonical_file_name(),
        ais_name
    );

    let sha256 = sha256_hex(&content);
    Ok(ConfigFileRead {
        found: true,
        created: true,
        path,
        content,
        sha256,
    })
}

/// Validates and writes an application's config file, backing up the previous
/// version as a timestamped `.aold` and pruning old backups.
pub fn write_config_file(
    base_dir: &Path,
    ais_name: &str,
    kind: ConfigFileKind,
    content: &str,
    expected_previous_sha256: Option<&str>,
) -> Result<ConfigFileWrite, ErrorArrayItem> {
    validate_ais_name(ais_name)?;
    validate_toml(content)?;

    let config_dir = base_dir.join(ais_name);
    if !config_dir.is_dir() {
        return Err(ErrorArrayItem::new(
            Errors::NotFound,
            format!(
                "no config directory for {}; run setup to scaffold it first",
                ais_name
            ),
        ));
    }

    let path = resolve_config_file_path(base_dir, ais_name, kind);

    let previous = if path.is_file() {
        Some(fs::read_to_string(&path).map_err(ErrorArrayItem::from)?)
    } else {
        None
    };

    if let Some(expected) = expected_previous_sha256.filter(|sha| !sha.is_empty()) {
        let current_sha = previous.as_deref().map(sha256_hex).unwrap_or_default();
        if current_sha != expected {
            return Err(ErrorArrayItem::new(
                Errors::ConfigParsing,
                format!(
                    "{} changed since it was read; re-run edit to pick up the latest version",
                    path.display()
                ),
            ));
        }
    }

    let backup_file = match previous {
        Some(_) => Some(backup_config_file(&path)?),
        None => None,
    };

    let existing_meta = fs::metadata(&path).ok();
    atomic_write(&path, content, existing_meta.as_ref())?;

    Ok(ConfigFileWrite { backup_file, path })
}

/// Reads or scaffolds a config file while keeping scaffold mutations and the
/// integrity re-baseline in one serialized operation.
pub async fn read_config_file_managed(
    base_dir: &Path,
    ais_name: &str,
    kind: ConfigFileKind,
    create_if_missing: bool,
) -> Result<ConfigFileRead, ErrorArrayItem> {
    if !create_if_missing {
        return read_config_file(base_dir, ais_name, kind, false);
    }

    let _guard = CONFIG_MUTATION_LOCK.lock().await;
    let result = read_config_file(base_dir, ais_name, kind, true)?;
    if result.created {
        rebaseline_integrity_manifest().await;
    }
    Ok(result)
}

/// Validates, backs up, and replaces a config file while holding the mutation
/// lock through the integrity re-baseline.
pub async fn write_config_file_managed(
    base_dir: &Path,
    ais_name: &str,
    kind: ConfigFileKind,
    content: &str,
    expected_previous_sha256: Option<&str>,
) -> Result<ConfigFileWrite, ErrorArrayItem> {
    let _guard = CONFIG_MUTATION_LOCK.lock().await;
    let result = write_config_file(base_dir, ais_name, kind, content, expected_previous_sha256)?;
    rebaseline_integrity_manifest().await;
    Ok(result)
}

/// Rewrites the integrity manifest so config mutations do not register as
/// tampering at runtime or on next startup. The caller holds the mutation lock.
async fn rebaseline_integrity_manifest() {
    if let Err(err) = super::verification::persist_shutdown_integrity_manifest().await {
        log!(
            LogLevel::Error,
            "Failed to re-baseline integrity manifest after config mutation: {}",
            err.err_mesg
        );
    }
}

fn ensure_config_dir(config_dir: &Path) -> Result<(), ErrorArrayItem> {
    if config_dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(config_dir).map_err(ErrorArrayItem::from)?;
    fs::set_permissions(config_dir, fs::Permissions::from_mode(NEW_DIR_MODE))
        .map_err(ErrorArrayItem::from)?;
    chown_best_effort(config_dir, WWW_DATA_UID, WWW_DATA_GID);
    Ok(())
}

fn atomic_write(
    path: &Path,
    content: &str,
    previous_meta: Option<&fs::Metadata>,
) -> Result<(), ErrorArrayItem> {
    let dir = path.parent().ok_or_else(|| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("config path has no parent directory: {}", path.display()),
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let temp_path = dir.join(format!(".{}.tmp.{}", file_name, std::process::id()));

    let result: Result<(), ErrorArrayItem> = (|| {
        let mut file = File::create(&temp_path).map_err(ErrorArrayItem::from)?;
        file.write_all(content.as_bytes())
            .map_err(ErrorArrayItem::from)?;
        file.sync_all().map_err(ErrorArrayItem::from)?;
        drop(file);

        let mode = previous_meta
            .map(|meta| meta.mode() & 0o7777)
            .unwrap_or(NEW_FILE_MODE);
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode))
            .map_err(ErrorArrayItem::from)?;

        // Replacements keep the prior owner; new files default to root:www-data
        // so www-data runners can read them.
        let (uid, gid) = previous_meta
            .map(|meta| (meta.uid(), meta.gid()))
            .unwrap_or((0, WWW_DATA_GID));
        chown_best_effort(&temp_path, uid, gid);

        fs::rename(&temp_path, path).map_err(ErrorArrayItem::from)?;
        File::open(dir)
            .and_then(|directory| directory.sync_all())
            .map_err(ErrorArrayItem::from)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn chown_best_effort(path: &Path, uid: u32, gid: u32) {
    if let Err(err) = std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
        log!(
            LogLevel::Trace,
            "Failed to chown {} to {}:{}: {}",
            path.display(),
            uid,
            gid,
            err
        );
    }
}

/// Copies the current file to `<name>.<YYYYMMDD-HHMMSS>.aold` and prunes old
/// backups down to `CONFIG_BACKUP_RETENTION`. Returns the backup file name.
fn backup_config_file(path: &Path) -> Result<String, ErrorArrayItem> {
    let dir = path.parent().ok_or_else(|| {
        ErrorArrayItem::new(
            Errors::InputOutput,
            format!("config path has no parent directory: {}", path.display()),
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ErrorArrayItem::new(
                Errors::InputOutput,
                format!("config path has no file name: {}", path.display()),
            )
        })?;

    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let mut backup_name = format!("{file_name}.{stamp}.{CONFIG_BACKUP_EXTENSION}");
    let mut counter = 0u32;
    while dir.join(&backup_name).exists() {
        counter += 1;
        backup_name = format!("{file_name}.{stamp}-{counter}.{CONFIG_BACKUP_EXTENSION}");
    }

    fs::copy(path, dir.join(&backup_name)).map_err(ErrorArrayItem::from)?;
    prune_backups(dir, file_name, CONFIG_BACKUP_RETENTION)?;
    Ok(backup_name)
}

/// Deletes all but the newest `keep` backups of `file_name` in `dir`.
fn prune_backups(dir: &Path, file_name: &str, keep: usize) -> Result<(), ErrorArrayItem> {
    let prefix = format!("{file_name}.");
    let suffix = format!(".{CONFIG_BACKUP_EXTENSION}");

    let mut backups: Vec<String> = fs::read_dir(dir)
        .map_err(ErrorArrayItem::from)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name.strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(&suffix))
                .map(is_backup_timestamp)
                .unwrap_or(false)
        })
        .collect();

    if backups.len() <= keep {
        return Ok(());
    }

    // The timestamp format sorts lexicographically in chronological order.
    backups.sort();
    let excess = backups.len() - keep;
    for stale in backups.into_iter().take(excess) {
        if let Err(err) = fs::remove_file(dir.join(&stale)) {
            log!(
                LogLevel::Warn,
                "Failed to prune config backup {}: {}",
                stale,
                err
            );
        }
    }
    Ok(())
}

/// Matches `YYYYMMDD-HHMMSS` with an optional `-N` collision counter.
fn is_backup_timestamp(value: &str) -> bool {
    let (stamp, counter) = match value.split_at_checked(15) {
        Some((stamp, rest)) => (stamp, rest),
        None => return false,
    };

    let stamp_valid = stamp.len() == 15
        && stamp.as_bytes()[8] == b'-'
        && stamp
            .bytes()
            .enumerate()
            .all(|(idx, byte)| idx == 8 || byte.is_ascii_digit());
    if !stamp_valid {
        return false;
    }

    match counter.strip_prefix('-') {
        Some(digits) => !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
        None => counter.is_empty(),
    }
}

fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Placeholder `Config.toml` matching the generic runner's `[app_specific]` schema.
pub fn placeholder_config_toml(ais_name: &str) -> String {
    format!(
        r#"# Application config for {ais_name}.
# Consumed by the runner from its working directory ({conf_dir}/{ais_name}).

[app_specific]
# Seconds between directory scans for changes.
interval_seconds = 30
# Directory watched for source changes.
monitor_path = "/opt/artisan/src/{ais_name}"
# Root of the checked-out project.
project_path = "/opt/artisan/src/{ais_name}"
# Number of detected changes before a rebuild is triggered.
changes_needed = 1
# Subdirectories excluded from change detection.
ignored_subdirs = [".git", "node_modules", ".next", ".cache", "target"]
# Command used to install dependencies (uncomment to enable).
# install_command = "npm install"
# Command used to build the application (uncomment to enable).
# build_command = "npm run build"
# Command used to launch the application. REQUIRED - replace before starting.
run_command = "CHANGE_ME"
# Address of the secret server providing runtime environment values.
secret_server_addr = "127.0.0.1"
# Location the resolved environment file is written to.
env_file_location = "/opt/artisan/etc/{ais_name}/.env"
"#,
        ais_name = ais_name,
        conf_dir = ARTISAN_CONF_DIR,
    )
}

/// Placeholder `Overrides.toml` matching the middleware `AppConfig` overrides.
pub fn placeholder_overrides_toml(ais_name: &str) -> String {
    format!(
        r#"# AppConfig overrides for {ais_name}.

# Enables verbose runner diagnostics.
debug_mode = false
# One of: Trace, Debug, Info, Warn, Error.
log_level = "Info"
# Deployment environment label.
environment = "production"

[git]
default_server = "GitHub"
credentials_file = "/opt/artisan/etc/git.cf"
"#,
        ais_name = ais_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let dir = env::temp_dir().join(format!(
                "ais-config-files-test-{}-{}",
                std::process::id(),
                TEST_DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            TestDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const APP: &str = "ais_testapp1";

    fn scaffold(base: &Path) -> ConfigFileRead {
        read_config_file(base, APP, ConfigFileKind::Config, true).expect("scaffold")
    }

    #[test]
    fn placeholder_templates_are_valid_toml() {
        validate_toml(&placeholder_config_toml(APP)).expect("config template");
        validate_toml(&placeholder_overrides_toml(APP)).expect("overrides template");
    }

    #[test]
    fn validate_ais_name_rejects_traversal() {
        assert!(validate_ais_name("ais_abc123").is_ok());
        assert!(validate_ais_name("ais_ab-c_1").is_ok());
        for bad in [
            "",
            "ais_",
            "abc",
            "ais_../etc",
            "ais_a/b",
            "ais_a b",
            "../ais_a",
        ] {
            assert!(validate_ais_name(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn read_scaffolds_placeholder_once() {
        let dir = TestDir::new();
        let first = scaffold(dir.path());
        assert!(first.found && first.created);
        assert!(first.path.is_file());

        let second = read_config_file(dir.path(), APP, ConfigFileKind::Config, true).unwrap();
        assert!(second.found && !second.created);
        assert_eq!(first.sha256, second.sha256);

        let missing = read_config_file(dir.path(), APP, ConfigFileKind::Overrides, false).unwrap();
        assert!(!missing.found && !missing.created);
        assert!(!missing.path.exists());
    }

    #[test]
    fn write_rejects_invalid_toml() {
        let dir = TestDir::new();
        scaffold(dir.path());
        let err = write_config_file(dir.path(), APP, ConfigFileKind::Config, "not [ toml", None)
            .unwrap_err();
        assert!(err.err_mesg.to_string().contains("invalid TOML"));
    }

    #[test]
    fn write_rejects_stale_sha() {
        let dir = TestDir::new();
        scaffold(dir.path());
        let err = write_config_file(
            dir.path(),
            APP,
            ConfigFileKind::Config,
            "a = 1",
            Some("deadbeef"),
        )
        .unwrap_err();
        assert!(err.err_mesg.to_string().contains("changed since"));

        let current = read_config_file(dir.path(), APP, ConfigFileKind::Config, false).unwrap();
        write_config_file(
            dir.path(),
            APP,
            ConfigFileKind::Config,
            "a = 1",
            Some(&current.sha256),
        )
        .expect("matching sha accepted");
    }

    #[test]
    fn write_requires_existing_dir() {
        let dir = TestDir::new();
        let err =
            write_config_file(dir.path(), APP, ConfigFileKind::Config, "a = 1", None).unwrap_err();
        assert!(err.err_mesg.to_string().contains("run setup"));
    }

    #[test]
    fn backup_retention_keeps_last_five() {
        let dir = TestDir::new();
        scaffold(dir.path());

        for round in 0..7 {
            let content = format!("round = {round}");
            let result = write_config_file(dir.path(), APP, ConfigFileKind::Config, &content, None)
                .expect("write");
            assert!(result.backup_file.is_some());
        }

        let app_dir = dir.path().join(APP);
        let backups: Vec<String> = fs::read_dir(&app_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".aold"))
            .collect();
        assert_eq!(
            backups.len(),
            CONFIG_BACKUP_RETENTION,
            "backups: {backups:?}"
        );

        let current = fs::read_to_string(app_dir.join("Config.toml")).unwrap();
        assert_eq!(current, "round = 6");
    }

    #[test]
    fn write_is_atomic_no_temp_left_behind() {
        let dir = TestDir::new();
        scaffold(dir.path());
        write_config_file(dir.path(), APP, ConfigFileKind::Config, "a = 1", None).unwrap();

        let leftovers: Vec<String> = fs::read_dir(dir.path().join(APP))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    #[test]
    fn overrides_write_reuses_legacy_misspelling() {
        let dir = TestDir::new();
        let app_dir = dir.path().join(APP);
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(app_dir.join("Overides.toml"), "legacy = true").unwrap();

        let read = read_config_file(dir.path(), APP, ConfigFileKind::Overrides, false).unwrap();
        assert!(read.found);
        assert!(read.path.ends_with("Overides.toml"));

        write_config_file(
            dir.path(),
            APP,
            ConfigFileKind::Overrides,
            "legacy = false",
            None,
        )
        .unwrap();
        assert!(app_dir.join("Overides.toml").is_file());
        assert!(!app_dir.join("Overrides.toml").exists());
    }

    #[test]
    fn backup_timestamp_matcher() {
        assert!(is_backup_timestamp("20260719-104501"));
        assert!(is_backup_timestamp("20260719-104501-2"));
        for bad in [
            "",
            "2026",
            "20260719_104501",
            "20260719-10450x",
            "20260719-104501-",
        ] {
            assert!(!is_backup_timestamp(bad), "accepted {bad:?}");
        }
    }
}
