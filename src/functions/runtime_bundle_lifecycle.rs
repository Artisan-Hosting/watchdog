//! Watchdog's side of the Phase E unified runtime bundle: boot-time
//! migration of existing `Config.toml`/`Overrides.toml`/env-file apps into a
//! `runtime.acai` bundle (E7), and the per-start unpack / per-stop cleanup
//! lifecycle for apps that actually consume it (E8).
//!
//! Bundle *creation* is universal (every known app, system and client
//! alike) -- see `migrate_app_to_bundle`. Bundle *consumption* (unpacking
//! before spawn, cleaning up after stop) is scoped to `generic_runner`-based
//! client apps only in this phase; system apps keep using their existing
//! config-reading mechanism untouched until a later phase migrates them too.

use std::fs;
use std::path::PathBuf;

use artisan_middleware::custom_config::CustomConfig;
use artisan_middleware::dusa_collection_utils::{
    core::errors::{ErrorArrayItem, Errors},
    log,
    core::logger::LogLevel,
};
use artisan_middleware::enviornment::definitions::Enviornment_V2;
use artisan_middleware::runtime_bundle;

use crate::functions::config_files::{
    conf_dir, sha256_hex, validate_ais_name, ConfigFileKind, ConfigFileRead, ConfigFileWrite,
};
use crate::functions::inventory::resolve_overrides_path;
use crate::secrets::SecretClient;

/// Filename of the bundle inside an app's config directory
/// (`ARTISAN_CONF_DIR/<ais_name>/runtime.acai`).
pub const BUNDLE_FILE_NAME: &str = "runtime.acai";

fn bundle_path(ais_name: &str) -> PathBuf {
    conf_dir().join(ais_name).join(BUNDLE_FILE_NAME)
}

fn current_node_id() -> Result<u64, ErrorArrayItem> {
    artisan_middleware::identity::Identifier::load_from_file()
        .map(|identity| identity.id)
        .map_err(|err| {
            ErrorArrayItem::new(
                Errors::NotFound,
                format!("No machine identity yet: {}", err.err_mesg),
            )
        })
}

/// Reads one bundle-backed entry as a plain string, keyed by `kind`.
async fn read_bundle_entry(
    bundle: &std::path::Path,
    kind: ConfigFileKind,
    passphrase: &str,
) -> Result<String, ErrorArrayItem> {
    match kind {
        ConfigFileKind::Runtime => {
            let fixed = runtime_bundle::read_fixed_config(bundle, passphrase)?;
            toml::to_string(&fixed)
                .map_err(|err| ErrorArrayItem::new(Errors::ConfigParsing, err.to_string()))
        }
        ConfigFileKind::Custom => runtime_bundle::read_custom_config(bundle, passphrase)?.to_json(),
        ConfigFileKind::BundleEnv => runtime_bundle::read_env(bundle, passphrase),
        ConfigFileKind::Config | ConfigFileKind::Overrides => unreachable!(
            "read_bundle_entry only called for bundle-backed kinds, checked by the caller"
        ),
    }
}

/// Handles a `GetConfigFile` request for one of the three bundle-backed
/// kinds (Phase E, E10/E11). Returns `Ok(None)` for `Config`/`Overrides` so
/// the caller (`config_files::read_config_file_managed`) falls through to
/// the existing flat-file path unchanged.
pub async fn try_read_bundle_kind(
    ais_name: &str,
    kind: ConfigFileKind,
) -> Result<Option<ConfigFileRead>, ErrorArrayItem> {
    if !matches!(
        kind,
        ConfigFileKind::Runtime | ConfigFileKind::Custom | ConfigFileKind::BundleEnv
    ) {
        return Ok(None);
    }

    let bundle = bundle_path(ais_name);
    if !bundle.exists() {
        return Ok(Some(ConfigFileRead {
            found: false,
            created: false,
            path: bundle,
            content: String::new(),
            sha256: String::new(),
        }));
    }

    let node_id = current_node_id()?;
    let mut secret_client = SecretClient::connect().await?;
    let passphrase = secret_client.get_or_create_node_passphrase(node_id).await?;

    let content = read_bundle_entry(&bundle, kind, &passphrase).await?;
    let sha256 = sha256_hex(&content);

    Ok(Some(ConfigFileRead {
        found: true,
        created: false,
        path: bundle,
        content,
        sha256,
    }))
}

/// Handles a `SetConfigFile` request for one of the three bundle-backed
/// kinds (Phase E, E10/E11). Returns `Ok(None)` for `Config`/`Overrides` so
/// the caller falls through to the existing flat-file path unchanged.
///
/// `BundleEnv` writes are expected to come from Manager's secret-server
/// relay (E10), not a human via the UI, so callers of that kind typically
/// pass `expected_previous_sha256: None` -- Manager is the authoritative
/// source being pushed down, not a competing edit that needs reconciling.
pub async fn try_write_bundle_kind(
    ais_name: &str,
    kind: ConfigFileKind,
    content: &str,
    expected_previous_sha256: Option<&str>,
) -> Result<Option<ConfigFileWrite>, ErrorArrayItem> {
    if !matches!(
        kind,
        ConfigFileKind::Runtime | ConfigFileKind::Custom | ConfigFileKind::BundleEnv
    ) {
        return Ok(None);
    }

    let bundle = bundle_path(ais_name);
    if !bundle.exists() {
        return Err(ErrorArrayItem::new(
            Errors::NotFound,
            format!("{ais_name} has no runtime bundle yet"),
        ));
    }

    let node_id = current_node_id()?;
    let mut secret_client = SecretClient::connect().await?;
    let passphrase = secret_client.get_or_create_node_passphrase(node_id).await?;

    if let Some(expected) = expected_previous_sha256 {
        let current = read_bundle_entry(&bundle, kind, &passphrase).await?;
        if sha256_hex(&current) != expected {
            return Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "stale sha256; reload the current content and retry",
            ));
        }
    }

    match kind {
        ConfigFileKind::Runtime => {
            let fixed: Enviornment_V2 = toml::from_str(content)
                .map_err(|err| ErrorArrayItem::new(Errors::ConfigParsing, err.to_string()))?;
            runtime_bundle::commit_fixed_config(&bundle, &fixed, &passphrase)?;
        }
        ConfigFileKind::Custom => {
            let custom = CustomConfig::from_json(content)?;
            runtime_bundle::commit_custom_config(&bundle, &custom, &passphrase)?;
        }
        ConfigFileKind::BundleEnv => {
            runtime_bundle::commit_env(&bundle, content, &passphrase)?;
        }
        ConfigFileKind::Config | ConfigFileKind::Overrides => unreachable!(
            "try_write_bundle_kind only reaches here for bundle-backed kinds, checked above"
        ),
    }

    log!(
        LogLevel::Info,
        "Committed {:?} content to {}'s runtime bundle",
        kind,
        ais_name
    );

    Ok(Some(ConfigFileWrite {
        backup_file: None,
        path: bundle,
    }))
}

fn parse_toml_table(content: &str) -> toml::value::Table {
    match toml::from_str::<toml::Value>(content) {
        Ok(toml::Value::Table(table)) => table,
        _ => toml::value::Table::new(),
    }
}

fn merge_into(base: &mut toml::value::Table, overlay: toml::value::Table) {
    for (key, value) in overlay {
        base.insert(key, value);
    }
}

/// Seeds every field `Enviornment_V2` requires (i.e. every field that isn't
/// `Option<T>`) with the same fallback values `AppConfig::new()`'s
/// `set_default` calls and `placeholder_config_toml()` already use, so a
/// legacy `Config.toml`/`Overrides.toml` pair that relied on those defaults
/// (rather than stating the field explicitly) still migrates to something
/// `Enviornment_V2` can deserialize instead of failing on a missing
/// required field.
fn default_fixed_config_table(ais_name: &str) -> toml::value::Table {
    let mut table = toml::value::Table::new();
    table.insert("app_name".into(), toml::Value::String(ais_name.to_owned()));
    table.insert("max_ram_usage".into(), toml::Value::Integer(0));
    table.insert("max_cpu_usage".into(), toml::Value::Integer(0));
    table.insert("environment".into(), toml::Value::String("production".into()));
    table.insert("debug_mode".into(), toml::Value::Boolean(false));
    table.insert("log_level".into(), toml::Value::String("Info".into()));
    table.insert("interval_seconds".into(), toml::Value::Integer(30));
    table.insert(
        "monitor_path".into(),
        toml::Value::String(format!("/var/www/ais/{ais_name}")),
    );
    table.insert(
        "project_path".into(),
        toml::Value::String(format!("/var/www/ais/{ais_name}")),
    );
    table.insert("changes_needed".into(), toml::Value::Integer(1));
    table.insert(
        "ignored_subdirs".into(),
        toml::Value::Array(
            [".git", "node_modules", ".next", ".cache", "target", "bin"]
                .iter()
                .map(|s| toml::Value::String((*s).into()))
                .collect(),
        ),
    );
    // Matches `placeholder_config_toml()`'s own "replace before starting" convention.
    table.insert("run_command".into(), toml::Value::String("echo CHANGE_ME".into()));
    table
}

/// The network-free half of migration: reads whatever `Config.toml`/
/// `Overrides.toml`/env file already exist under `config_dir`, merges them
/// (overlaying real content onto the same defaults `AppConfig::new()`'s
/// `set_default` calls and `placeholder_config_toml()` already use) into an
/// `Enviornment_V2`, and returns it alongside the legacy env file's content.
/// Pulled out of `migrate_app_to_bundle` specifically so this logic -- the
/// part with real room for a merge/parsing mistake -- is unit-testable
/// without a live secret-server connection.
fn build_fixed_config_from_legacy_files(
    ais_name: &str,
    config_dir: &std::path::Path,
) -> Result<(Enviornment_V2, String), ErrorArrayItem> {
    let mut fixed_table = default_fixed_config_table(ais_name);

    if let Ok(content) = fs::read_to_string(config_dir.join("Config.toml")) {
        let root = parse_toml_table(&content);
        if let Some(toml::Value::Table(app_specific)) = root.get("app_specific").cloned() {
            merge_into(&mut fixed_table, app_specific);
        }
    }

    let overrides_path =
        resolve_overrides_path(config_dir).unwrap_or_else(|| config_dir.join("Overrides.toml"));
    if let Ok(content) = fs::read_to_string(&overrides_path) {
        merge_into(&mut fixed_table, parse_toml_table(&content));
    }

    // Legacy env file location, captured before we drop the field --
    // `secret_server_addr`/`env_file_location` are obsolete in `Enviornment_V2`
    // (E2): secrets no longer flow through a configured address the runner
    // dials itself, they arrive pre-populated by watchdog (E9/E10).
    let legacy_env_path = fixed_table
        .remove("env_file_location")
        .and_then(|v| v.as_str().map(str::to_owned))
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir.join(".env"));
    fixed_table.remove("secret_server_addr");

    let toml_text = toml::to_string(&toml::Value::Table(fixed_table)).map_err(|err| {
        ErrorArrayItem::new(Errors::ConfigParsing, format!("Assembling merged config: {err}"))
    })?;
    let fixed: Enviornment_V2 = toml::from_str(&toml_text).map_err(|err| {
        ErrorArrayItem::new(
            Errors::ConfigParsing,
            format!("Migrating {ais_name} to Enviornment_V2: {err}"),
        )
    })?;

    let env_content = fs::read_to_string(&legacy_env_path).unwrap_or_default();
    Ok((fixed, env_content))
}

/// Builds `runtime.acai` for `ais_name` from its existing
/// `Config.toml`/`Overrides.toml`/env file, if one doesn't already exist.
/// Idempotent: returns `Ok(false)` without touching anything if the bundle
/// is already there, so calling this for every known app on every watchdog
/// boot is safe.
///
/// Does not touch `Config.toml`/`Overrides.toml`/the legacy env file --
/// they're left in place, read-only, purely as a migration source. Nothing
/// currently deletes them; a `generic_runner`-based app that has been
/// switched over to reading the bundle's unpacked output (E9, not yet done)
/// simply stops needing them.
pub async fn migrate_app_to_bundle(
    ais_name: &str,
    node_id: u64,
    secret_client: &mut SecretClient,
) -> Result<bool, ErrorArrayItem> {
    validate_ais_name(ais_name)?;

    let bundle = bundle_path(ais_name);
    if bundle.exists() {
        return Ok(false);
    }

    let config_dir = conf_dir().join(ais_name);
    fs::create_dir_all(&config_dir).map_err(|err| {
        ErrorArrayItem::new(
            Errors::CreatingDirectory,
            format!("Creating {}: {}", config_dir.display(), err),
        )
    })?;

    let (fixed, local_env_content) = build_fixed_config_from_legacy_files(ais_name, &config_dir)?;

    // Prefer secret-server's fleet-wide record over whatever's on this node's
    // local disk, per E10's design: it's what lets an already-configured app
    // bootstrap cleanly on a brand-new node instead of starting blank.
    // `runner_id` here is the bare id (no `ais_` prefix), matching the
    // convention Portal's own secret-server client already uses.
    let bare_id = ais_name.trim_start_matches("ais_");
    let env_content = match secret_client
        .get_all_as_env_lines(bare_id, &fixed.environment)
        .await
    {
        Ok(remote) if !remote.is_empty() => remote,
        Ok(_) => local_env_content,
        Err(err) => {
            log!(
                LogLevel::Warn,
                "Fetching secret-server record for {} failed, falling back to local env file: {}",
                ais_name,
                err.err_mesg
            );
            local_env_content
        }
    };

    let passphrase = secret_client.get_or_create_node_passphrase(node_id).await?;

    runtime_bundle::build_bundle(&bundle, &fixed, &CustomConfig::new(), &env_content, &passphrase)?;

    log!(LogLevel::Info, "Migrated {} to a runtime bundle", ais_name);
    Ok(true)
}

/// Unpacks `ais_name`'s bundle's control-plane config (fixed TOML + custom
/// JSON) into its config directory, ready for the process about to be spawned
/// to read, and returns the bundle's `.env` content so the caller can set it
/// directly on the `Command` it's about to spawn -- env content is never
/// written to disk (see `runtime_bundle::unpack_control_plane_config`'s doc
/// comment); it reaches the process purely through inherited process
/// environment, watchdog -> generic_runner -> the app's own child, if any.
/// Called before every spawn of a bundle-consuming app: the initial boot
/// spawn and every subsequent (re)start, whether manual or automatic.
///
/// Returns `Ok(None)` if `ais_name` has no bundle yet (e.g. it's a system
/// app, out of scope for consumption in this phase) -- callers shouldn't have
/// to know which apps are on this scheme yet.
pub async fn prepare_for_start(ais_name: &str, node_id: u64) -> Result<Option<String>, ErrorArrayItem> {
    let bundle = bundle_path(ais_name);
    if !bundle.exists() {
        return Ok(None);
    }

    let mut secret_client = SecretClient::connect().await?;
    let passphrase = secret_client.get_or_create_node_passphrase(node_id).await?;

    let config_dir = conf_dir().join(ais_name);
    runtime_bundle::unpack_control_plane_config(&bundle, &passphrase, &config_dir)?;

    let env_content = runtime_bundle::read_env(&bundle, &passphrase)?;
    Ok(Some(env_content))
}

/// Parses `.env`-style `KEY=value` text (one pair per line, blank lines and
/// `#`-prefixed comments ignored) into pairs ready for `Command::envs`.
/// Lines that don't contain `=` are skipped rather than treated as an error --
/// malformed bundle env content shouldn't be able to stop an app from
/// starting.
pub fn parse_env_lines(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

/// Deletes `ais_name`'s unpacked control-plane config files, the moment
/// watchdog stops (or is about to stop) its process. A no-op if there's
/// nothing unpacked (system apps, or a bundle-consuming app that never
/// started).
pub fn cleanup_after_stop(ais_name: &str) -> Result<(), ErrorArrayItem> {
    let config_dir = conf_dir().join(ais_name);
    runtime_bundle::cleanup_unpacked_config(&config_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_config_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "watchdog_bundle_migration_test_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A minimal, sparse `Overrides.toml` (the common case -- relying on
    /// `AppConfig::new()`'s `set_default`s for everything else) plus a
    /// complete `Config.toml` (matching `placeholder_config_toml()`'s own
    /// shape) must still merge into a fully-populated `Enviornment_V2`.
    #[test]
    fn merges_sparse_overrides_with_complete_config_toml() {
        let dir = scratch_config_dir("sparse_overrides");
        fs::write(
            dir.join("Config.toml"),
            r#"
[app_specific]
interval_seconds = 45
monitor_path = "/opt/artisan/src/demo"
project_path = "/opt/artisan/src/demo"
changes_needed = 2
ignored_subdirs = [".git"]
run_command = "node server.js"
secret_server_addr = "127.0.0.1"
"#,
        )
        .unwrap();
        fs::write(
            dir.join("Overrides.toml"),
            r#"
debug_mode = true
log_level = "Debug"
environment = "production"
"#,
        )
        .unwrap();
        fs::write(dir.join(".env"), "API_KEY=abc123\n").unwrap();

        let (fixed, env_content) = build_fixed_config_from_legacy_files("ais_demo", &dir).unwrap();

        // Real content from Config.toml/Overrides.toml took precedence over defaults.
        assert_eq!(fixed.interval_seconds, 45);
        assert_eq!(fixed.run_command.to_string(), "node server.js");
        assert!(fixed.debug_mode);
        assert_eq!(fixed.environment.to_string(), "production");
        // Fields absent from both files fell back to AppConfig::new()'s defaults.
        assert_eq!(fixed.max_ram_usage, 0);
        assert_eq!(fixed.max_cpu_usage, 0);
        // The env file was read from the (now-dropped) configured location.
        assert_eq!(env_content, "API_KEY=abc123\n");

        let _ = fs::remove_dir_all(&dir);
    }

    /// An app with no `Config.toml`/`Overrides.toml` at all yet (nothing to
    /// migrate from) must still produce a valid, if placeholder, config
    /// rather than failing outright -- migration must never be the reason a
    /// boot-time pass over every known app crashes watchdog.
    #[test]
    fn produces_placeholder_defaults_when_nothing_exists_to_migrate() {
        let dir = scratch_config_dir("nothing_to_migrate");

        let (fixed, env_content) = build_fixed_config_from_legacy_files("ais_fresh", &dir).unwrap();

        assert_eq!(fixed.app_name.to_string(), "ais_fresh");
        assert_eq!(fixed.run_command.to_string(), "echo CHANGE_ME");
        assert_eq!(env_content, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_env_lines_skips_blanks_comments_and_malformed_lines() {
        let parsed = parse_env_lines(
            "API_KEY=abc123\n\n# a comment\nMALFORMED_NO_EQUALS\nDB_URL = mysql://x \n",
        );
        assert_eq!(
            parsed,
            vec![
                ("API_KEY".to_string(), "abc123".to_string()),
                ("DB_URL".to_string(), "mysql://x".to_string()),
            ]
        );
    }
}
