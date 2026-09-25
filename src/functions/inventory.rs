//! Application inventory helpers for build/spawn safety checks.

use artisan_middleware::dusa_collection_utils::{
    core::{errors::ErrorArrayItem, logger::LogLevel, types::pathtype::PathType},
    log,
};
use artisan_middleware::git_actions::GitCredentials;
use get_if_addrs::{IfAddr, get_if_addrs};
use std::{
    collections::HashSet,
    fs,
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{sync::watch, time};

use crate::definitions::{
    self, ARTISAN_BIN_DIR, ARTISAN_CONF_DIR, ClientInventoryStore, CRITICAL_APPLICATIONS,
    GIT_CONFIG_PATH,
};
use artisan_middleware::{aggregator::Status, timestamp::current_timestamp};

#[derive(Debug, Default)]
pub struct ClientInventoryDiff {
    pub expected_added: Vec<String>,
    pub expected_removed: Vec<String>,
    pub safe_added: Vec<String>,
    pub safe_removed: Vec<String>,
}

/// Builds the list of client applications considered safe to build/spawn.
/// Safe clients are those listed in git credentials that also have a valid
/// config directory under `ARTISAN_CONF_DIR/ais_<git_id>` with both TOML files
/// present and syntactically valid.
pub async fn generate_safe_client_runner_list() -> Result<Vec<String>, ErrorArrayItem> {
    let expected_clients = expected_clients_from_git_config().await?;
    let mut safe_clients: Vec<String> = Vec::new();

    for name in expected_clients {
        if CRITICAL_APPLICATIONS.iter().any(|sys| sys.ais == name) {
            continue;
        }
        match validate_client_config_dir(&name) {
            Ok(true) => safe_clients.push(name),
            Ok(false) => {}
            Err(err) => {
                log!(
                    LogLevel::Warn,
                    "Failed to validate config for {}: {}",
                    name,
                    err
                );
            }
        }
    }

    safe_clients.sort();
    safe_clients.dedup();
    Ok(safe_clients)
}

/// Periodically scans git credentials + config directories to maintain an in-memory
/// inventory of expected and safe client applications. When an application becomes
/// safe (both TOMLs valid), we seed a placeholder status entry (Stopped, no metrics)
/// and automatically attempt to build the client runner if the binary is missing.
pub async fn monitor_client_inventory(
    inventory_store: ClientInventoryStore,
    client_status_store: definitions::ClientApplicationStatusStore,
    build_status_store: definitions::BuildStatusStore,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(interval);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(_) if *shutdown.borrow() => {
                        log!(LogLevel::Info, "Client inventory monitor loop shutting down");
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        log!(LogLevel::Info, "Client inventory monitor loop shutting down (sender dropped)");
                        break;
                    }
                }
            }
            _ = ticker.tick() => {}
        }

        let diff = match refresh_client_inventory_once(&inventory_store).await {
            Ok(diff) => diff,
            Err(err) => {
                log!(
                    LogLevel::Warn,
                    "Client inventory scan failed; keeping previous snapshot: {}",
                    err.err_mesg
                );
                continue;
            }
        };

        if !diff.safe_added.is_empty() || !diff.safe_removed.is_empty() {
            log!(
                LogLevel::Info,
                "Client inventory updated: +{} safe, -{} safe",
                diff.safe_added.len(),
                diff.safe_removed.len()
            );
        }

        // Bundle migration otherwise only ever runs once, at watchdog's own
        // startup, for whatever was already safe at that moment (see
        // `main.rs`'s `'_runtime_bundle_migration` block) -- an app that
        // becomes safe afterward (e.g. a repo added to this node without a
        // watchdog restart) would never get a `runtime.acai` bundle, so
        // Manager's secrets-sync loop would silently skip it forever
        // (`get_app_environment` returning `Ok(None)` reads as "no bundle
        // yet, nothing to sync" over there). Running migration here too,
        // for exactly the apps that just became safe, closes that gap
        // without needing a restart.
        migrate_newly_safe_apps(&diff).await;

        let safe_clients = {
            let guard = inventory_store.read().await;
            guard.safe_clients.clone()
        };

        seed_placeholder_client_statuses(&client_status_store, &safe_clients).await;
        auto_build_safe_clients(
            &inventory_store,
            &build_status_store,
            safe_clients.clone(),
            Duration::from_secs(60),
        )
        .await;
        retry_missing_bundles(&inventory_store, &safe_clients, Duration::from_secs(60)).await;
    }
}

/// Attempts `migrate_app_to_bundle` for every app in `diff.safe_added`.
///
/// A "safe" transition is only ever visible once: the moment some caller's
/// `refresh_client_inventory_once` diffs it in, the in-memory snapshot moves
/// on and no later scan (this loop's next tick included) will ever see that
/// same transition again. Several RPC handlers call
/// `refresh_client_inventory_once` directly and, until this existed, threw
/// the resulting diff away -- most importantly `get_config_file`'s
/// scaffold-on-create-if-missing path, which is exactly what a freshly
/// added-to-this-node app's first config write goes through (see
/// `Portal::write_watchdog_file`'s scaffold-then-set pattern). That call
/// would mark the app safe off the placeholder file alone and silently eat
/// the transition, so the real config write immediately afterward -- and
/// this loop's next tick -- both saw the app as already safe and never
/// migrated it: config populated, build succeeds, but no `runtime.acai` ever
/// gets created, so the app can never actually start. Every caller that
/// observes a non-empty `safe_added` must route it through here.
pub async fn migrate_newly_safe_apps(diff: &ClientInventoryDiff) {
    if diff.safe_added.is_empty() {
        return;
    }

    match artisan_middleware::identity::Identifier::load_from_file() {
        Ok(identity) => match crate::secrets::SecretClient::connect().await {
            Ok(mut secret_client) => {
                for ais_name in &diff.safe_added {
                    match super::runtime_bundle_lifecycle::migrate_app_to_bundle(
                        ais_name,
                        identity.id,
                        &mut secret_client,
                    )
                    .await
                    {
                        Ok(true) => {
                            log!(LogLevel::Info, "Runtime bundle created for {}", ais_name)
                        }
                        Ok(false) => {} // already migrated, nothing to do
                        Err(err) => log!(
                            LogLevel::Warn,
                            "Runtime bundle migration failed for {}: {}",
                            ais_name,
                            err.err_mesg
                        ),
                    }
                }
            }
            Err(err) => log!(
                LogLevel::Warn,
                "Skipping runtime bundle migration for newly-safe apps; secret-server unreachable: {}",
                err.err_mesg
            ),
        },
        Err(err) => log!(
            LogLevel::Warn,
            "Skipping runtime bundle migration for newly-safe apps; no machine identity yet: {}",
            err.err_mesg
        ),
    }
}

pub async fn refresh_client_inventory_once(
    inventory_store: &ClientInventoryStore,
) -> Result<ClientInventoryDiff, ErrorArrayItem> {
    let expected_clients = expected_clients_from_git_config().await?;
    let safe_clients = safe_clients_from_expected(&expected_clients);

    let mut diff = ClientInventoryDiff::default();

    {
        let prev = inventory_store.read().await;
        let prev_expected: HashSet<String> = prev.expected_clients.iter().cloned().collect();
        let prev_safe: HashSet<String> = prev.safe_clients.iter().cloned().collect();

        let next_expected: HashSet<String> = expected_clients.iter().cloned().collect();
        let next_safe: HashSet<String> = safe_clients.iter().cloned().collect();

        diff.expected_added = next_expected
            .difference(&prev_expected)
            .cloned()
            .collect();
        diff.expected_removed = prev_expected
            .difference(&next_expected)
            .cloned()
            .collect();
        diff.safe_added = next_safe.difference(&prev_safe).cloned().collect();
        diff.safe_removed = prev_safe.difference(&next_safe).cloned().collect();
    }

    {
        let mut store = inventory_store.write().await;
        store.expected_clients = expected_clients;
        store.safe_clients = safe_clients;
        store.last_scan = current_timestamp();
    }

    Ok(diff)
}

fn safe_clients_from_expected(expected: &[String]) -> Vec<String> {
    let mut safe: Vec<String> = Vec::new();
    for name in expected {
        if CRITICAL_APPLICATIONS.iter().any(|sys| sys.ais == name) {
            continue;
        }
        if matches!(validate_client_config_dir(name), Ok(true)) {
            safe.push(name.clone());
        }
    }
    safe.sort();
    safe.dedup();
    safe
}

async fn expected_clients_from_git_config() -> Result<Vec<String>, ErrorArrayItem> {
    let git_credential_file: PathType = PathType::Content(GIT_CONFIG_PATH.to_string());
    let git_credentials_array = GitCredentials::new_vec(Some(&git_credential_file)).await?;

    let mut expected: Vec<String> = Vec::new();
    for project in git_credentials_array {
        expected.push(format!("ais_{}", project.generate_id()));
    }

    expected.sort();
    expected.dedup();
    Ok(expected)
}

fn validate_client_config_dir(ais_name: &str) -> Result<bool, io::Error> {
    let config_dir = PathBuf::from(format!("{}/{}", ARTISAN_CONF_DIR, ais_name));
    if !config_dir.is_dir() {
        return Ok(false);
    }

    let config_path = config_dir.join("Config.toml");
    if !config_path.is_file() {
        return Ok(false);
    }

    let overrides_path = resolve_overrides_path(&config_dir);
    let Some(overrides_path) = overrides_path else {
        return Ok(false);
    };

    Ok(is_valid_toml_file(&config_path)? && is_valid_toml_file(&overrides_path)?)
}

pub(crate) fn resolve_overrides_path(config_dir: &Path) -> Option<PathBuf> {
    let correct = config_dir.join("Overrides.toml");
    if correct.is_file() {
        return Some(correct);
    }
    let misspelled = config_dir.join("Overides.toml");
    if misspelled.is_file() {
        return Some(misspelled);
    }
    None
}

fn is_valid_toml_file(path: &Path) -> Result<bool, io::Error> {
    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(false);
    }
    Ok(toml::from_str::<toml::Value>(&raw).is_ok())
}

pub async fn seed_placeholder_client_statuses(
    client_status_store: &definitions::ClientApplicationStatusStore,
    safe_clients: &[String],
) {
    let now = current_timestamp();
    let mut guard = client_status_store.write().await;
    for client in safe_clients {
        guard.entry(client.clone()).or_insert_with(|| {
            definitions::ApplicationStatus::new(
                Status::Stopped,
                0.0,
                0.0,
                None,
                now,
                definitions::empty_output_buffer(),
                definitions::empty_output_buffer(),
                None,
            )
        });
    }
}

pub async fn auto_build_safe_clients(
    inventory_store: &ClientInventoryStore,
    build_status_store: &definitions::BuildStatusStore,
    safe_clients: Vec<String>,
    retry_backoff: Duration,
) {
    for client in safe_clients {
        let binary_path = PathBuf::from(format!("{}/{}", ARTISAN_BIN_DIR, client));
        if binary_path.is_file() {
            continue;
        }

        let now = current_timestamp();
        let should_build = {
            let mut guard = inventory_store.write().await;
            let last = guard.last_build_attempt.get(&client).copied().unwrap_or(0);
            let allowed_at = last.saturating_add(retry_backoff.as_secs());
            if now < allowed_at {
                false
            } else {
                guard.last_build_attempt.insert(client.clone(), now);
                true
            }
        };

        if !should_build {
            continue;
        }

        let build_store = build_status_store.clone();
        let client_name = client.clone();
        tokio::spawn(async move {
            log!(
                LogLevel::Info,
                "Auto-building newly detected client application: {}",
                client_name
            );
            let result = crate::scripts::build_runner_binary(&client_name).await;
            let status = match result {
                Ok(_) => definitions::BuildStatus::success(client_name.clone(), false),
                Err(_) => definitions::BuildStatus::failure(client_name.clone(), false),
            };
            {
                let mut store = build_store.write().await;
                store.insert(client_name.clone(), status);
            }
        });
    }
}

/// Retries `migrate_app_to_bundle` for every safe client still missing a
/// `runtime.acai`, on the same attempt-then-backoff cadence
/// `auto_build_safe_clients` already uses for missing binaries.
///
/// `migrate_newly_safe_apps` only ever fires once, at the moment an app is
/// first observed as safe -- if that one shot fails (secret-server
/// unreachable during a cold-boot race is the case that surfaced this: the
/// box is pingable, but `SecretClient::connect()` also depends on minting a
/// session from `ais_auth` and resolving/handshaking TLS to
/// `secrets.ah.internal`, any of which can still be coming up), the app was
/// otherwise stuck with no bundle -- and therefore never actually starting,
/// even though config/build both looked fine -- until another
/// safe->unsafe->safe toggle or a full watchdog restart. Called every tick
/// of `monitor_client_inventory`, this makes that recoverable without
/// either.
pub async fn retry_missing_bundles(
    inventory_store: &ClientInventoryStore,
    safe_clients: &[String],
    retry_backoff: Duration,
) {
    for client in safe_clients {
        if super::runtime_bundle_lifecycle::bundle_path(client).is_file() {
            continue;
        }

        let now = current_timestamp();
        let should_attempt = {
            let mut guard = inventory_store.write().await;
            let last = guard.last_bundle_attempt.get(client).copied().unwrap_or(0);
            let allowed_at = last.saturating_add(retry_backoff.as_secs());
            if now < allowed_at {
                false
            } else {
                guard.last_bundle_attempt.insert(client.clone(), now);
                true
            }
        };

        if !should_attempt {
            continue;
        }

        match artisan_middleware::identity::Identifier::load_from_file() {
            Ok(identity) => match crate::secrets::SecretClient::connect().await {
                Ok(mut secret_client) => {
                    match super::runtime_bundle_lifecycle::migrate_app_to_bundle(
                        client,
                        identity.id,
                        &mut secret_client,
                    )
                    .await
                    {
                        Ok(true) => log!(
                            LogLevel::Info,
                            "Runtime bundle created for {} (retry)",
                            client
                        ),
                        Ok(false) => {} // created by someone else in the meantime
                        Err(err) => log!(
                            LogLevel::Warn,
                            "Runtime bundle migration retry failed for {}: {}",
                            client,
                            err.err_mesg
                        ),
                    }
                }
                Err(err) => log!(
                    LogLevel::Warn,
                    "Runtime bundle migration retry for {} skipped; secret-server unreachable: {}",
                    client,
                    err.err_mesg
                ),
            },
            Err(err) => log!(
                LogLevel::Warn,
                "Runtime bundle migration retry for {} skipped; no machine identity yet: {}",
                client,
                err.err_mesg
            ),
        }
    }
}

/// Collects all host IPv4 addresses, excluding loopback and common
/// container-bridge interfaces (Docker/Podman/veth/cni).
pub fn get_all_ipv4() -> io::Result<Vec<Ipv4Addr>> {
    let interfaces = get_if_addrs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut ips: Vec<Ipv4Addr> = interfaces
        .into_iter()
        .filter(|iface| {
            let name = iface.name.to_lowercase();
            if name == "lo" {
                return false;
            }
            if name.starts_with("docker")
                || name.starts_with("br-")
                || name.starts_with("veth")
                || name.starts_with("cni")
                || name.starts_with("flannel.")
                || name.contains("docker")
                || name.contains("vethernet")
            {
                return false;
            }
            true
        })
        .filter_map(|iface| match iface.addr {
            IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(v4.ip),
            _ => None,
        })
        .collect();

    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}
