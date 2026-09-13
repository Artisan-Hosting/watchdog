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

use artisan_middleware::config::{Aggregator, DatabaseConfig, GitConfig};
use artisan_middleware::custom_config::CustomConfig;
use artisan_middleware::dusa_collection_utils::{
    core::errors::{ErrorArrayItem, Errors},
    log,
    core::logger::LogLevel,
};
use artisan_middleware::enviornment::definitions::Enviornment_V2;
use artisan_middleware::runtime_bundle;
use serde::Deserialize;

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
            let config_dir = conf_dir().join(ais_name);
            if config_dir.exists() {
                let _ = runtime_bundle::unpack_control_plane_config(&bundle, &passphrase, &config_dir);
                ensure_control_plane_ownership(Some(&fixed), &config_dir);
            }
        }
        ConfigFileKind::Custom => {
            let custom = CustomConfig::from_json(content)?;
            runtime_bundle::commit_custom_config(&bundle, &custom, &passphrase)?;
            let config_dir = conf_dir().join(ais_name);
            if config_dir.exists() {
                let _ = runtime_bundle::unpack_control_plane_config(&bundle, &passphrase, &config_dir);
                let fixed = runtime_bundle::read_fixed_config(&bundle, &passphrase).ok();
                ensure_control_plane_ownership(fixed.as_ref(), &config_dir);
            }
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

/// Parses `content` as TOML for migration purposes. Real deployed
/// `Config.toml`/`Overrides.toml` files drift over time -- hand edits, a
/// stray unescaped character, whatever -- and a syntax error anywhere in the
/// file must not cost us every field in it. Real `toml::from_str` is tried
/// first (it's the accurate parser: it gets quoting, escaping, arrays, and
/// nested tables right), and only on a genuine syntax error do we fall back
/// to [`loose_parse_toml`], which walks the file line by line and simply
/// skips whatever it can't make sense of.
fn parse_toml_table(content: &str) -> toml::value::Table {
    match toml::from_str::<toml::Value>(content) {
        Ok(toml::Value::Table(table)) => table,
        _ => loose_parse_toml(content),
    }
}

/// A lossy, line-by-line TOML reader used only as a fallback when real TOML
/// parsing fails outright. Understands `[section]` headers (one level deep,
/// which is all these files ever use), `key = value` lines, `#` comments
/// (ignored unless inside quotes), quoted and bare scalar values, and
/// `[a, b, c]` string arrays (the only array shape `ignored_subdirs` uses).
/// A line that doesn't fit any of that is simply skipped -- migration should
/// lose the one field, not the whole file.
fn loose_parse_toml(content: &str) -> toml::value::Table {
    let mut root = toml::value::Table::new();
    let mut current_section: Option<String> = None;

    for raw_line in content.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let section = section.trim();
            if section.is_empty() || section.contains('[') {
                continue;
            }
            current_section = Some(section.to_owned());
            root.entry(section.to_owned())
                .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
            continue;
        }

        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Some(value) = parse_loose_value(raw_value.trim()) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }

        match &current_section {
            Some(section) => {
                if let Some(toml::Value::Table(table)) = root.get_mut(section) {
                    table.insert(key.to_owned(), value);
                }
            }
            None => {
                root.insert(key.to_owned(), value);
            }
        }
    }

    root
}

/// Strips a trailing `#` comment from a line, respecting quotes so a literal
/// `#` inside a quoted value (a credentials path, say) isn't mistaken for one.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut quote_char = '"';
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote_char = ch;
            }
            c if in_quotes && c == quote_char => in_quotes = false,
            '#' if !in_quotes => return &line[..idx],
            _ => {}
        }
    }
    line
}

/// Coerces one value's textual form into a `toml::Value` on a best-effort
/// basis: a quoted string unwraps to `String`; `true`/`false` (any case) to
/// `Boolean`; a bare integer/float to `Integer`/`Float`; `[ ... ]` to an
/// `Array` of `String`s; anything else (including an empty value) falls back
/// to `String` so a stray unquoted word doesn't just vanish. Returns `None`
/// only when there's truly nothing to read.
fn parse_loose_value(raw: &str) -> Option<toml::Value> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some(inner) = strip_matching_quotes(raw) {
        return Some(toml::Value::String(inner.to_owned()));
    }

    if let Some(inner) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let items = inner
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| strip_matching_quotes(item).unwrap_or(item).to_owned())
            .map(toml::Value::String)
            .collect();
        return Some(toml::Value::Array(items));
    }

    match raw.to_ascii_lowercase().as_str() {
        "true" => return Some(toml::Value::Boolean(true)),
        "false" => return Some(toml::Value::Boolean(false)),
        _ => {}
    }
    if let Ok(i) = raw.parse::<i64>() {
        return Some(toml::Value::Integer(i));
    }
    if let Ok(f) = raw.parse::<f64>() {
        return Some(toml::Value::Float(f));
    }

    Some(toml::Value::String(raw.to_owned()))
}

fn strip_matching_quotes(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' || first == b'\'') && first == last {
            return Some(&raw[1..raw.len() - 1]);
        }
    }
    None
}

fn merge_into(base: &mut toml::value::Table, overlay: toml::value::Table) {
    for (key, value) in overlay {
        base.insert(key, value);
    }
}

/// Required (non-`Option`) scalar fields, coerced to the type
/// `Enviornment_V2` needs before the final typed deserialize -- real legacy
/// files are inconsistent about quoting numbers (`max_ram_usage = "512"`
/// alongside `interval_seconds = 30` in the same file is common), and a
/// strict deserialize rejects a string where it expects an integer. On a
/// value that can't be coerced at all, falls back to `defaults`' value
/// rather than leaving the field missing (these aren't `Option` fields).
const REQUIRED_INT_FIELDS: &[&str] =
    &["max_ram_usage", "max_cpu_usage", "interval_seconds", "changes_needed"];
const REQUIRED_BOOL_FIELDS: &[&str] = &["debug_mode"];
const REQUIRED_STRING_FIELDS: &[&str] =
    &["app_name", "environment", "monitor_path", "project_path", "run_command"];
/// `Option<u16>` fields: coerced like the required ints, but simply dropped
/// (falling back to `None`) rather than defaulted when uncoercible.
const OPTIONAL_INT_FIELDS: &[&str] = &["execution_uid", "execution_gid", "primary_listening_port"];
/// `Option<Stringy>` fields: coerced defensively, dropped when the value is
/// a shape (table/array) that can't reasonably become a string.
const OPTIONAL_STRING_FIELDS: &[&str] =
    &["install_command", "build_command", "path_modifier", "pre_build_command"];
const KNOWN_LOG_LEVELS: &[&str] = &["Error", "Warn", "Info", "Debug", "Trace"];
const KNOWN_APPLICATION_TYPES: &[&str] = &["Simple", "Next", "Angular", "Python", "Custom"];

/// Best-effort-coerces every field `Enviornment_V2` cares about in place, so
/// the final typed deserialize essentially can't fail on a legacy file's
/// quoting/casing quirks -- it costs one field to a default or `None`, never
/// the whole migration.
fn sanitize_fixed_table(table: &mut toml::value::Table, defaults: &toml::value::Table) {
    for &field in REQUIRED_INT_FIELDS {
        coerce_or_default(table, defaults, field, coerce_int);
    }
    for &field in REQUIRED_BOOL_FIELDS {
        coerce_or_default(table, defaults, field, coerce_bool);
    }
    for &field in REQUIRED_STRING_FIELDS {
        coerce_or_default(table, defaults, field, coerce_string);
    }
    coerce_or_default(table, defaults, "ignored_subdirs", coerce_string_array);
    coerce_enum_or_default(table, defaults, "log_level", KNOWN_LOG_LEVELS);

    for &field in OPTIONAL_INT_FIELDS {
        coerce_or_drop(table, field, coerce_int);
    }
    for &field in OPTIONAL_STRING_FIELDS {
        coerce_or_drop(table, field, coerce_string);
    }
    coerce_enum_or_drop(table, "application_type", KNOWN_APPLICATION_TYPES);

    drop_if_invalid::<GitConfig>(table, "git");
    drop_if_invalid::<DatabaseConfig>(table, "database");
    drop_if_invalid::<Aggregator>(table, "aggregator");
}

fn coerce_or_default(
    table: &mut toml::value::Table,
    defaults: &toml::value::Table,
    field: &str,
    coerce: impl Fn(&toml::Value) -> Option<toml::Value>,
) {
    let coerced = table.get(field).and_then(coerce);
    match coerced {
        Some(value) => {
            table.insert(field.to_owned(), value);
        }
        None => {
            if let Some(default) = defaults.get(field) {
                table.insert(field.to_owned(), default.clone());
            }
        }
    }
}

fn coerce_or_drop(
    table: &mut toml::value::Table,
    field: &str,
    coerce: impl Fn(&toml::Value) -> Option<toml::Value>,
) {
    let Some(value) = table.get(field) else {
        return;
    };
    match coerce(value) {
        Some(coerced) => {
            table.insert(field.to_owned(), coerced);
        }
        None => {
            table.remove(field);
        }
    }
}

fn coerce_enum_or_default(
    table: &mut toml::value::Table,
    defaults: &toml::value::Table,
    field: &str,
    variants: &[&str],
) {
    let matched = table
        .get(field)
        .and_then(toml::Value::as_str)
        .and_then(|s| variants.iter().find(|v| v.eq_ignore_ascii_case(s)));
    match matched {
        Some(variant) => {
            table.insert(field.to_owned(), toml::Value::String((*variant).to_owned()));
        }
        None => {
            if let Some(default) = defaults.get(field) {
                table.insert(field.to_owned(), default.clone());
            }
        }
    }
}

fn coerce_enum_or_drop(table: &mut toml::value::Table, field: &str, variants: &[&str]) {
    let Some(raw) = table.get(field).and_then(toml::Value::as_str) else {
        // Not a string at all (or absent) -- drop rather than guess.
        if table.contains_key(field) {
            table.remove(field);
        }
        return;
    };
    match variants.iter().find(|v| v.eq_ignore_ascii_case(raw)) {
        Some(variant) => {
            table.insert(field.to_owned(), toml::Value::String((*variant).to_owned()));
        }
        None => {
            table.remove(field);
        }
    }
}

/// Removes `field` from `table` if present but its value doesn't deserialize
/// as `T` -- used for the optional nested-table fields (`git`, `database`,
/// `aggregator`) where a best-effort scalar coercion doesn't make sense.
fn drop_if_invalid<T: for<'de> Deserialize<'de>>(table: &mut toml::value::Table, field: &str) {
    let Some(value) = table.get(field) else {
        return;
    };
    if T::deserialize(value.clone()).is_err() {
        table.remove(field);
    }
}

fn coerce_int(value: &toml::Value) -> Option<toml::Value> {
    match value {
        toml::Value::Integer(_) => Some(value.clone()),
        toml::Value::Float(f) => Some(toml::Value::Integer(*f as i64)),
        toml::Value::String(s) => s.trim().parse::<i64>().ok().map(toml::Value::Integer),
        _ => None,
    }
}

fn coerce_bool(value: &toml::Value) -> Option<toml::Value> {
    match value {
        toml::Value::Boolean(_) => Some(value.clone()),
        toml::Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(toml::Value::Boolean(true)),
            "false" => Some(toml::Value::Boolean(false)),
            _ => None,
        },
        _ => None,
    }
}

fn coerce_string(value: &toml::Value) -> Option<toml::Value> {
    match value {
        toml::Value::String(_) => Some(value.clone()),
        toml::Value::Integer(i) => Some(toml::Value::String(i.to_string())),
        toml::Value::Float(f) => Some(toml::Value::String(f.to_string())),
        toml::Value::Boolean(b) => Some(toml::Value::String(b.to_string())),
        _ => None,
    }
}

fn coerce_string_array(value: &toml::Value) -> Option<toml::Value> {
    match value {
        toml::Value::Array(items) => {
            let strings: Vec<toml::Value> = items
                .iter()
                .filter_map(|item| match item {
                    toml::Value::String(_) => Some(item.clone()),
                    toml::Value::Integer(i) => Some(toml::Value::String(i.to_string())),
                    toml::Value::Float(f) => Some(toml::Value::String(f.to_string())),
                    toml::Value::Boolean(b) => Some(toml::Value::String(b.to_string())),
                    _ => None,
                })
                .collect();
            Some(toml::Value::Array(strings))
        }
        _ => None,
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
    let defaults = default_fixed_config_table(ais_name);
    let mut fixed_table = defaults.clone();

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

    sanitize_fixed_table(&mut fixed_table, &defaults);

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
        Ok(_) => {
            // Secret-server confirmed empty. If this instance's own legacy
            // .env file has real content, this is the "first instance to
            // migrate" case -- push it up now, synchronously, so it becomes
            // the fleet-wide record other instances (with no local .env at
            // all) can pull down, and so Manager's periodic relay (which
            // always pushes down exactly what it reads back from
            // secret-server) doesn't turn around and wipe this bundle's env
            // with empty content the moment it next runs. A failure here
            // propagates (`?`) rather than silently building an unbacked-up
            // bundle -- this app's migration simply retries next boot.
            if !local_env_content.trim().is_empty() {
                secret_client
                    .seed_from_env_lines(bare_id, &fixed.environment, &local_env_content)
                    .await?;
                log!(
                    LogLevel::Info,
                    "Seeded secret-server from {}'s local env file (no fleet-wide record existed yet)",
                    ais_name
                );
            }
            local_env_content
        }
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

    let fixed = runtime_bundle::read_fixed_config(&bundle, &passphrase).ok();
    ensure_control_plane_ownership(fixed.as_ref(), &config_dir);

    let env_content = runtime_bundle::read_env(&bundle, &passphrase)?;
    Ok(Some(env_content))
}

/// Ensures that unpacked `runtime.toml` and `custom.json` control-plane files
/// in `config_dir` are owned by the UID and GID that the child process will run as.
///
/// Target UID/GID are derived from `fixed.execution_uid` and `fixed.execution_gid`
/// when present. If omitted (`None`), they default to `WWW_DATA_UID` / `WWW_DATA_GID`
/// (or `0:0` if `--client-root` is set).
pub fn ensure_control_plane_ownership(
    fixed: Option<&Enviornment_V2>,
    config_dir: &std::path::Path,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{chown, MetadataExt};

        let is_client_root = crate::runtime_flags::runtime_flags().client_root;
        let target_uid = if is_client_root {
            0
        } else {
            fixed
                .and_then(|f| f.execution_uid)
                .map(u32::from)
                .unwrap_or(crate::definitions::WWW_DATA_UID)
        };

        let target_gid = if is_client_root {
            0
        } else {
            fixed
                .and_then(|f| f.execution_gid)
                .map(u32::from)
                .unwrap_or(crate::definitions::WWW_DATA_GID)
        };

        let runtime_toml = config_dir.join(runtime_bundle::FIXED_CONFIG_ENTRY);
        let custom_json = config_dir.join(runtime_bundle::CUSTOM_CONFIG_ENTRY);

        for path in [&runtime_toml, &custom_json] {
            if !path.exists() {
                continue;
            }
            match path.metadata() {
                Ok(meta) => {
                    let current_uid = meta.uid();
                    let current_gid = meta.gid();
                    if current_uid != target_uid || current_gid != target_gid {
                        log!(
                            LogLevel::Info,
                            "Chowning {} from {}:{} to target process UID/GID {}:{}",
                            path.display(),
                            current_uid,
                            current_gid,
                            target_uid,
                            target_gid
                        );
                        if let Err(err) = chown(path, Some(target_uid), Some(target_gid)) {
                            log!(
                                LogLevel::Warn,
                                "Failed to chown {} to {}:{}: {}",
                                path.display(),
                                target_uid,
                                target_gid,
                                err
                            );
                        }
                    }
                }
                Err(err) => {
                    log!(
                        LogLevel::Warn,
                        "Failed to inspect metadata for {}: {}",
                        path.display(),
                        err
                    );
                }
            }
        }
    }
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

    /// The exact real-world mess this whole coercion pass exists for: some
    /// integer fields quoted, some not, plus comments scattered through both
    /// files -- must still merge into a fully-typed `Enviornment_V2` instead
    /// of failing the migration.
    #[test]
    fn coerces_inconsistently_quoted_integers() {
        let dir = scratch_config_dir("mixed_quoting");
        fs::write(
            dir.join("Config.toml"),
            r#"
[app_specific]
# some of these are quoted, some aren't -- both must work
interval_seconds = "45"
changes_needed = 2
monitor_path = "/opt/artisan/src/demo"
project_path = "/opt/artisan/src/demo"
run_command = "node server.js" # inline comment
"#,
        )
        .unwrap();
        fs::write(
            dir.join("Overrides.toml"),
            r#"
max_ram_usage = "512"
max_cpu_usage = 80
debug_mode = "true"
log_level = "debug"
environment = "production"
"#,
        )
        .unwrap();

        let (fixed, _) = build_fixed_config_from_legacy_files("ais_demo", &dir).unwrap();

        assert_eq!(fixed.interval_seconds, 45);
        assert_eq!(fixed.max_ram_usage, 512);
        assert_eq!(fixed.max_cpu_usage, 80);
        assert!(fixed.debug_mode);
        assert_eq!(format!("{:?}", fixed.log_level), "Debug");

        let _ = fs::remove_dir_all(&dir);
    }

    /// A file with an actual TOML syntax error (unbalanced quotes) must not
    /// take every other field down with it -- the parser falls back to the
    /// lossy line walker, which keeps whatever it can still make sense of.
    #[test]
    fn falls_back_to_loose_parsing_on_real_syntax_errors() {
        let dir = scratch_config_dir("syntax_error");
        fs::write(
            dir.join("Config.toml"),
            "[app_specific]\nrun_command = \"node server.js\nchanges_needed = 3\n",
        )
        .unwrap();
        fs::write(
            dir.join("Overrides.toml"),
            "debug_mode = true\nenvironment = \"staging\"\n",
        )
        .unwrap();

        let (fixed, _) = build_fixed_config_from_legacy_files("ais_demo", &dir).unwrap();

        assert_eq!(fixed.changes_needed, 3);
        assert!(fixed.debug_mode);
        assert_eq!(fixed.environment.to_string(), "staging");

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

    #[test]
    fn test_ensure_control_plane_ownership_executes_without_errors() {
        let dir = scratch_config_dir("ownership_test");
        let runtime_path = dir.join("runtime.toml");
        let custom_path = dir.join("custom.json");
        fs::write(&runtime_path, "[app_specific]\nrun_command = \"node server.js\"\n").unwrap();
        fs::write(&custom_path, "{}").unwrap();

        let sample_toml = r#"
app_name = "ais_test"
run_command = "node server.js"
environment = "production"
monitor_path = "/tmp"
project_path = "/tmp"
interval_seconds = 30
max_ram_usage = 512
max_cpu_usage = 80
debug_mode = false
log_level = "Info"
changes_needed = 0
ignored_subdirs = []
execution_uid = 1000
execution_gid = 1000
"#;
        let sample_fixed: Enviornment_V2 = toml::from_str(sample_toml).unwrap();

        ensure_control_plane_ownership(Some(&sample_fixed), &dir);

        assert!(runtime_path.exists());
        assert!(custom_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
