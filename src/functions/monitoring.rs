//! Runtime monitoring and process-control functions exposed to gRPC handlers.

use crate::{
    definitions::{self, ARTISAN_BIN_DIR, ARTISAN_CONF_DIR, ApplicationStatus, SupervisedProcesses},
    ebpf, ledger, pid_persistence,
    scripts::{build_application, build_runner_binary, revert_to_vetted},
};
use artisan_middleware::{
    aggregator::{Metrics, NetworkUsage},
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
            types::pathtype::PathType,
        },
        log,
    },
    process_manager::{SupervisedChild, SupervisedProcess, spawn_complex_process},
    resource_monitor::{ResourceMonitor, ResourceMonitorLock},
};
use nix::sys::signal::{
    Signal::{self, SIGHUP},
    kill,
};
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fs, io,
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{Mutex, watch},
    time,
};
mod state_refresh;

const WWW_DATA_USER: &str = "www-data";
const WWW_DATA_HOME: &str = "/var/www";
const WWW_DATA_NVM_DIR: &str = "/var/www/.nvm";
const WWW_DATA_UID: u32 = 33;
const WWW_DATA_GID: u32 = 33;
const ROOT_USER: &str = "root";
const ROOT_HOME: &str = "/root";
const CLIENT_CACHE_HOME: &str = "/var/www/.cache/ais_watchdog";
const CLIENT_GO_PATH: &str = "/var/www/.local/share/ais_go";
const CLIENT_GO_BIN_DIR: &str = "/var/www/.local/share/ais_go/bin";
const CLIENT_GO_BUILD_CACHE: &str = "/var/www/.cache/ais_watchdog/go-build";
const CLIENT_GO_MOD_CACHE: &str = "/var/www/.cache/ais_watchdog/go-mod";
const CLIENT_GO_TMP_DIR: &str = "/var/www/.cache/ais_watchdog/go-tmp";
const CLIENT_LOCAL_BIN_DIR: &str = "/var/www/.local/bin";
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const RESOURCE_MONITOR_MAX_STALENESS: Duration = Duration::from_millis(1_500);
const RESOURCE_MONITOR_MAX_CONSECUTIVE_FAILURES: u64 = 5;
const STDX_MONITOR_MAX_STALENESS: Duration = Duration::from_millis(2_500);
const STDX_MONITOR_MAX_CONSECUTIVE_FAILURES: u64 = 8;
const PROCESS_STORE_LOCK_TIMEOUT: Duration = Duration::from_millis(400);
const LOCK_TIMEOUT_PATTERN: &str = "Timeout while trying to acquire";

#[derive(Clone, Copy, Debug, Default)]
struct SkipStats {
    total: u64,
    consecutive: u64,
}

static STDX_UNHEALTHY_LATCH: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));
static SKIPPED_TASKS: Lazy<Mutex<HashMap<&'static str, SkipStats>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Periodically refreshes application status data for both system-critical
/// and client-managed processes. Stats for each cohort are stored separately
/// so operators can reason about platform health without sifting through
/// tenant workloads.
pub async fn monitor_application_states(
    system_status_store: definitions::SystemApplicationStatusStore,
    client_status_store: definitions::ClientApplicationStatusStore,
    system_information_store: definitions::SystemInformationStore,
    process_store: definitions::ChildProcessArray,
    client_inventory_store: definitions::ClientInventoryStore,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(interval);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(_) if *shutdown.borrow() => {
                        log!(LogLevel::Info, "Application state monitor loop shutting down");
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        log!(LogLevel::Info, "Application state monitor loop shutting down (sender dropped)");
                        break;
                    }
                }
            }
            _ = ticker.tick() => {}
        }

        log!(LogLevel::Trace, "monitor_application_states tick");
        match state_refresh::refresh_system_statuses_once(&system_status_store, &process_store)
            .await
        {
            Ok(_) => clear_skip_streak("state_refresh_system").await,
            Err(err) => {
                record_skip_if_lock_timeout("state_refresh_system", &err).await;
                log!(
                    LogLevel::Warn,
                    "Failed to refresh application statuses: {}",
                    err.err_mesg
                );
            }
        }

        match state_refresh::refresh_client_statuses_once(
            &client_status_store,
            &process_store,
            &client_inventory_store,
        )
            .await
        {
            Ok(_) => clear_skip_streak("state_refresh_client").await,
            Err(err) => {
                record_skip_if_lock_timeout("state_refresh_client", &err).await;
                log!(
                    LogLevel::Trace,
                    "Failed to refresh client application statuses: {}",
                    err.err_mesg
                );
            }
        }

        state_refresh::refresh_manager_linked_once(&system_information_store).await;
    }
}

/// Runtime loop for monitor-health checks and network usage aggregation.
/// Resource monitor + eBPF checks run at `interval`; stdx checks run at `stdx_interval`.
pub async fn monitor_runtime_health(
    process_store: definitions::ChildProcessArray,
    system_status_store: definitions::SystemApplicationStatusStore,
    client_status_store: definitions::ClientApplicationStatusStore,
    interval: Duration,
    stdx_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = time::interval(interval);
    let base_ms = interval.as_millis().max(1);
    let stdx_every = ((stdx_interval.as_millis().max(base_ms)) / base_ms) as u64;
    let mut tick_count: u64 = 0;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(_) if *shutdown.borrow() => {
                        log!(LogLevel::Info, "Runtime health monitor loop shutting down");
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        log!(LogLevel::Info, "Runtime health monitor loop shutting down (sender dropped)");
                        break;
                    }
                }
            }
            _ = ticker.tick() => {}
        }

        tick_count = tick_count.wrapping_add(1);
        let divisor = stdx_every.max(1);
        let check_stdx = tick_count % divisor == 0;

        if let Err(err) = refresh_runtime_health_and_network(
            &process_store,
            &system_status_store,
            &client_status_store,
            check_stdx,
        )
        .await
        {
            record_skip_if_lock_timeout("runtime_health_pass", &err).await;
            log!(
                LogLevel::Warn,
                "Failed runtime monitor pass: {}",
                err.err_mesg
            );
        } else {
            clear_skip_streak("runtime_health_pass").await;
        }

        if let Err(err) = ebpf::cleanup_dead_pids() {
            log!(
                LogLevel::Trace,
                "Failed to prune eBPF PID map: {}",
                err.err_mesg
            );
        }
    }
}

fn is_lock_timeout_error(err: &ErrorArrayItem) -> bool {
    err.err_mesg.contains(LOCK_TIMEOUT_PATTERN)
}

async fn record_skip_if_lock_timeout(task: &'static str, err: &ErrorArrayItem) {
    if !is_lock_timeout_error(err) {
        return;
    }

    let mut tracker = SKIPPED_TASKS.lock().await;
    let stats = tracker.entry(task).or_default();
    stats.total = stats.total.saturating_add(1);
    stats.consecutive = stats.consecutive.saturating_add(1);
    let consecutive = stats.consecutive;
    let total = stats.total;

    if matches!(consecutive, 1 | 3 | 5 | 10) || consecutive % 25 == 0 {
        log!(
            LogLevel::Warn,
            "Lock contention skipped {} (consecutive={}, total={})",
            task,
            consecutive,
            total
        );
    }
}

async fn clear_skip_streak(task: &'static str) {
    let mut tracker = SKIPPED_TASKS.lock().await;
    if let Some(stats) = tracker.get_mut(task) {
        if stats.consecutive > 0 {
            log!(
                LogLevel::Info,
                "{} lock contention recovered after {} skipped passes (total skips={})",
                task,
                stats.consecutive,
                stats.total
            );
            stats.consecutive = 0;
        }
    }
}

async fn refresh_runtime_health_and_network(
    process_store: &definitions::ChildProcessArray,
    system_status_store: &definitions::SystemApplicationStatusStore,
    client_status_store: &definitions::ClientApplicationStatusStore,
    check_stdx: bool,
) -> Result<(), ErrorArrayItem> {
    let mut runtime_snapshots: HashMap<String, RuntimeSnapshot> = HashMap::new();
    let process_names: Vec<String> = {
        let processes = process_store
            .try_read_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
            .await?;
        processes.keys().cloned().collect()
    };

    '_collect_runtime_snapshots: {
        for name in process_names {
            let mut snapshot = {
                let mut processes = process_store
                    .try_write_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
                    .await?;
                let Some(process) = processes.get_mut(&name) else {
                    continue;
                };
                collect_runtime_snapshot_for_process(&name, process, check_stdx).await
            };

            if let Some(pid) = snapshot.pid {
                snapshot.network_usage = compute_network_usage_for_pid(&name, pid).await;
            }

            runtime_snapshots.insert(name, snapshot);
        }
    }

    record_runtime_snapshots_in_ledger(&runtime_snapshots).await;
    apply_runtime_snapshots_to_status_stores(
        system_status_store,
        client_status_store,
        &runtime_snapshots,
    )
    .await;
    Ok(())
}

async fn record_runtime_snapshots_in_ledger(snapshots: &HashMap<String, RuntimeSnapshot>) {
    let mut entries: Vec<(String, Metrics)> = Vec::new();
    for (name, snapshot) in snapshots {
        if snapshot.cpu_usage.is_none()
            && snapshot.memory_usage.is_none()
            && snapshot.network_usage.is_none()
        {
            continue;
        }

        entries.push((
            name.clone(),
            Metrics {
                cpu_usage: snapshot.cpu_usage.unwrap_or_default(),
                memory_usage: snapshot.memory_usage.unwrap_or_default(),
                other: snapshot.network_usage.clone(),
            },
        ));
    }

    if !entries.is_empty() {
        ledger::record_batch(entries).await;
    }
}

async fn collect_runtime_snapshot_for_process(
    name: &str,
    process: &mut definitions::SupervisedProcesses,
    check_stdx: bool,
) -> RuntimeSnapshot {
    let mut snapshot = RuntimeSnapshot::default();

    match process {
        definitions::SupervisedProcesses::Child(child) => {
            ensure_resource_monitor_healthy_for_child(name, child).await;
            if check_stdx {
                ensure_stdx_monitor_healthy_for_child(name, child).await;
            }

            let mut metrics = child.get_metrics().await.ok();
            backfill_tree_usage_metrics(name, &child.monitor, &mut metrics).await;
            if let Some(metrics) = metrics {
                snapshot.cpu_usage = Some(metrics.cpu_usage);
                snapshot.memory_usage = Some(metrics.memory_usage);
            }

            if let Ok(pid) = child.get_pid().await {
                snapshot.pid = Some(pid);
            }
        }
        definitions::SupervisedProcesses::Process(proc) => {
            mark_stdx_healthy(name).await;
            ensure_resource_monitor_healthy_for_process(name, proc).await;

            let mut metrics = proc.get_metrics().await.ok();
            backfill_tree_usage_metrics(name, &proc.monitor, &mut metrics).await;
            if let Some(metrics) = metrics {
                snapshot.cpu_usage = Some(metrics.cpu_usage);
                snapshot.memory_usage = Some(metrics.memory_usage);
            }

            snapshot.pid = Some(proc.get_pid() as u32);
        }
    }

    snapshot
}

async fn should_log_stdx_unhealthy(name: &str) -> bool {
    let mut guard = STDX_UNHEALTHY_LATCH.lock().await;
    if guard.contains(name) {
        false
    } else {
        guard.insert(name.to_string());
        true
    }
}

async fn mark_stdx_healthy(name: &str) {
    let mut guard = STDX_UNHEALTHY_LATCH.lock().await;
    guard.remove(name);
}

async fn ensure_resource_monitor_healthy_for_child(name: &str, child: &mut SupervisedChild) {
    if !child.resource_monitor_valid(
        RESOURCE_MONITOR_MAX_STALENESS,
        RESOURCE_MONITOR_MAX_CONSECUTIVE_FAILURES,
    ) {
        let snapshot = child.resource_watchdog_snapshot();
        log!(
            LogLevel::Warn,
            "Resource monitor watchdog unhealthy for {} (running={}, starts={}, last_heartbeat_ms={}, consecutive_failures={}); restarting monitor",
            name,
            snapshot.running,
            snapshot.start_count,
            snapshot.last_heartbeat_unix_ms,
            snapshot.consecutive_failures
        );
        child.terminate_monitor();
        child.monitor_usage().await;
    } else if !child.monitoring() {
        log!(
            LogLevel::Warn,
            "Resource monitor task not running for {}; restarting monitor",
            name
        );
        child.monitor_usage().await;
    }
}

async fn ensure_stdx_monitor_healthy_for_child(name: &str, child: &mut SupervisedChild) {
    if !child.stdx_monitor_valid(
        STDX_MONITOR_MAX_STALENESS,
        STDX_MONITOR_MAX_CONSECUTIVE_FAILURES,
    ) {
        let snapshot = child.stdx_watchdog_snapshot();
        if should_log_stdx_unhealthy(name).await {
            log!(
                LogLevel::Warn,
                "Stdx monitor watchdog unhealthy for {} (running={}, starts={}, last_heartbeat_ms={}, consecutive_failures={}); restarting monitor",
                name,
                snapshot.running,
                snapshot.start_count,
                snapshot.last_heartbeat_unix_ms,
                snapshot.consecutive_failures
            );
        }
        child.terminate_stdx();
        child.monitor_stdx().await;
    } else {
        mark_stdx_healthy(name).await;
        if !child.monitoring_stdx() {
            log!(
                LogLevel::Warn,
                "Stdx monitor task not running for {}; restarting monitor",
                name
            );
            child.monitor_stdx().await;
        }
    }
}

async fn ensure_resource_monitor_healthy_for_process(name: &str, proc: &mut SupervisedProcess) {
    if !proc.resource_monitor_valid(
        RESOURCE_MONITOR_MAX_STALENESS,
        RESOURCE_MONITOR_MAX_CONSECUTIVE_FAILURES,
    ) {
        let snapshot = proc.resource_watchdog_snapshot();
        log!(
            LogLevel::Warn,
            "Resource monitor watchdog unhealthy for {} (running={}, starts={}, last_heartbeat_ms={}, consecutive_failures={}); restarting monitor",
            name,
            snapshot.running,
            snapshot.start_count,
            snapshot.last_heartbeat_unix_ms,
            snapshot.consecutive_failures
        );
        proc.terminate_monitor();
        proc.monitor_usage().await;
    } else if !proc.monitoring() {
        log!(
            LogLevel::Warn,
            "Resource monitor task not running for {}; restarting monitor",
            name
        );
        proc.monitor_usage().await;
    }
}

async fn compute_network_usage_for_pid(name: &str, pid: u32) -> Option<NetworkUsage> {
    let network_pids = collect_network_tree_pids(pid);
    register_network_tree_pids(name, &network_pids).await;
    aggregate_network_usage_for_pids(name, &network_pids)
}

async fn apply_runtime_snapshots_to_status_stores(
    system_status_store: &definitions::SystemApplicationStatusStore,
    client_status_store: &definitions::ClientApplicationStatusStore,
    snapshots: &HashMap<String, RuntimeSnapshot>,
) {
    let now = artisan_middleware::timestamp::current_timestamp();
    {
        let mut store = system_status_store.write().await;
        for (name, snapshot) in snapshots {
            if let Some(status) = store.get_mut(name) {
                apply_runtime_snapshot(status, snapshot, now);
            }
        }
    }
    {
        let mut store = client_status_store.write().await;
        for (name, snapshot) in snapshots {
            if let Some(status) = store.get_mut(name) {
                apply_runtime_snapshot(status, snapshot, now);
            }
        }
    }
}

fn apply_runtime_snapshot(status: &mut ApplicationStatus, snapshot: &RuntimeSnapshot, now: u64) {
    if let Some(cpu_usage) = snapshot.cpu_usage {
        status.cpu_usage = cpu_usage;
    }
    if let Some(memory_usage) = snapshot.memory_usage {
        status.memory_usage = memory_usage;
    }
    if let Some(pid) = snapshot.pid {
        status.pid = Some(pid);
    }
    status.network_usage = snapshot.network_usage.clone();
    status.last_updated = now;
}

async fn backfill_tree_usage_metrics(
    name: &str,
    monitor: &ResourceMonitorLock,
    metrics: &mut Option<Metrics>,
) {
    let should_attempt = metrics
        .as_ref()
        .map(|value| value.cpu_usage <= 0.0)
        .unwrap_or(true);

    if !should_attempt {
        return;
    }

    let monitor_guard = match monitor.0.try_read().await {
        Ok(guard) => guard,
        Err(err) => {
            log!(
                LogLevel::Trace,
                "Failed to lock monitor for tree usage fallback on {}: {}",
                name,
                err
            );
            return;
        }
    };

    let (tree_cpu, tree_memory) = match monitor_guard.aggregate_tree_usage() {
        Ok(values) => values,
        Err(err) => {
            log!(
                LogLevel::Trace,
                "Failed to compute tree usage fallback on {}: {}",
                name,
                err.err_mesg
            );
            return;
        }
    };

    if tree_cpu <= 0.0 && tree_memory <= 0.0 {
        return;
    }

    let entry = metrics.get_or_insert_with(|| Metrics {
        cpu_usage: 0.0,
        memory_usage: 0.0,
        other: None,
    });

    if tree_cpu > entry.cpu_usage {
        entry.cpu_usage = tree_cpu;
    }

    if tree_memory > entry.memory_usage {
        entry.memory_usage = tree_memory;
    }

    log!(
        LogLevel::Trace,
        "Applied tree usage fallback for {}: cpu={:.2}% mem={:.2}MB",
        name,
        entry.cpu_usage,
        entry.memory_usage
    );
}

fn collect_network_tree_pids(root_pid: u32) -> Vec<u32> {
    let root_pid_i32 = match i32::try_from(root_pid) {
        Ok(value) => value,
        Err(_) => return vec![root_pid],
    };

    let mut visited = HashSet::new();
    match ResourceMonitor::collect_all_pids(root_pid_i32, &mut visited) {
        Ok(pids) => {
            let mut out: Vec<u32> = pids
                .into_iter()
                .filter_map(|pid| u32::try_from(pid).ok())
                .collect();
            if out.is_empty() {
                out.push(root_pid);
            }
            out
        }
        Err(_) => vec![root_pid],
    }
}

async fn register_network_tree_pids(name: &str, pids: &[u32]) {
    for pid in pids {
        if let Err(err) = ebpf::register_pid_with_retry(*pid).await {
            log!(
                LogLevel::Trace,
                "Failed to register network-tracked PID {} for {}: {}",
                pid,
                name,
                err.err_mesg
            );
        }
    }
}

fn aggregate_network_usage_for_pids(name: &str, pids: &[u32]) -> Option<NetworkUsage> {
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;
    let mut any = false;

    for pid in pids {
        match ebpf::usage_for_pid(*pid) {
            Ok(Some(usage)) => {
                rx_bytes = rx_bytes.saturating_add(usage.rx_bytes);
                tx_bytes = tx_bytes.saturating_add(usage.tx_bytes);
                any = true;
            }
            Ok(None) => {}
            Err(err) => {
                log!(
                    LogLevel::Trace,
                    "Failed to read eBPF usage for PID {} ({}): {}",
                    pid,
                    name,
                    err.err_mesg
                );
            }
        }
    }

    if any {
        Some(NetworkUsage { rx_bytes, tx_bytes })
    } else {
        None
    }
}

#[derive(Default, Clone)]
struct RuntimeSnapshot {
    cpu_usage: Option<f32>,
    memory_usage: Option<f64>,
    network_usage: Option<NetworkUsage>,
    pid: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessStoreKind {
    System,
    Client,
    Custom(&'static str),
}

#[derive(Clone)]
pub struct ProcessStoreHandle {
    kind: ProcessStoreKind,
    store: definitions::ChildProcessArray,
}

impl ProcessStoreHandle {
    /// Creates a writable handle for the system process registry.
    pub fn system(store: &definitions::ChildProcessArray) -> Self {
        Self {
            kind: ProcessStoreKind::System,
            store: store.clone(),
        }
    }

    /// Creates a writable handle for the client process registry.
    pub fn client(store: &definitions::ChildProcessArray) -> Self {
        Self {
            kind: ProcessStoreKind::Client,
            store: store.clone(),
        }
    }

    /// Creates a named custom handle for read/lookup use-cases.
    pub fn custom(label: &'static str, store: &definitions::ChildProcessArray) -> Self {
        Self {
            kind: ProcessStoreKind::Custom(label),
            store: store.clone(),
        }
    }

    /// Returns the logical store kind for this handle.
    pub fn kind(&self) -> ProcessStoreKind {
        self.kind
    }

    /// Inserts or replaces a process entry in this store.
    pub async fn insert(
        &self,
        name: &str,
        process: definitions::SupervisedProcesses,
    ) -> Result<(), ErrorArrayItem> {
        let mut guard = self
            .store
            .try_write_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
            .await?;
        guard.insert(name.to_string(), process);
        Ok(())
    }

    /// Removes a process entry from this store.
    pub async fn remove(&self, name: &str) -> Result<(), ErrorArrayItem> {
        let mut guard = self
            .store
            .try_write_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
            .await?;
        guard.remove(name);
        Ok(())
    }

    /// Indicates if this handle can be used for write operations.
    pub fn is_writable(&self) -> bool {
        matches!(
            self.kind(),
            ProcessStoreKind::System | ProcessStoreKind::Client
        )
    }
}

/// Removes and returns the first matching process from the provided stores.
pub async fn take_process_by_name(
    name: &str,
    stores: &[ProcessStoreHandle],
) -> Result<Option<(ProcessStoreHandle, definitions::SupervisedProcesses)>, ErrorArrayItem> {
    for store_ref in stores {
        let handle = store_ref.clone();
        let mut guard = handle
            .store
            .try_write_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
            .await?;
        let process = guard.remove(name);
        drop(guard);
        if let Some(process) = process {
            return Ok(Some((handle, process)));
        }
    }

    Ok(None)
}

pub struct CommandStubResult {
    pub accepted: bool,
    pub message: String,
}

impl CommandStubResult {
    fn new(accepted: bool, message: String) -> Self {
        Self { accepted, message }
    }
}

/// Applies the runtime environment expected by client apps running as `www-data`.
pub fn configure_www_data_command(command: &mut Command) {
    configure_client_runtime_command(command, true);
}

/// Applies a hardened runtime environment for client application processes.
///
/// When `run_as_www_data` is true the command drops privileges to `www-data`.
/// Otherwise it runs as root but still gets the same environment reset and
/// sandbox defaults.
pub fn configure_client_runtime_command(command: &mut Command, run_as_www_data: bool) {
    prepare_client_runtime_directories(run_as_www_data);

    let (user, home) = if run_as_www_data {
        command.uid(WWW_DATA_UID);
        command.gid(WWW_DATA_GID);
        (WWW_DATA_USER, WWW_DATA_HOME)
    } else {
        (ROOT_USER, ROOT_HOME)
    };

    // Avoid inheriting root shell/session state from watchdog.
    command.env_clear();
    command.stdin(Stdio::null());
    command.kill_on_drop(true);

    let node_bin = format!("{}/versions/node/v23.5.0/bin", WWW_DATA_NVM_DIR);
    let combined_path =
        format!("{node_bin}:{CLIENT_LOCAL_BIN_DIR}:{CLIENT_GO_BIN_DIR}:{DEFAULT_PATH}");

    command.env("HOME", home);
    command.env("USER", user);
    command.env("LOGNAME", user);
    command.env("NVM_DIR", WWW_DATA_NVM_DIR);
    command.env("PATH", combined_path);
    command.env("SHELL", "/bin/bash");
    command.env("LANG", "C.UTF-8");
    command.env("LC_ALL", "C.UTF-8");
    command.env("TMPDIR", CLIENT_GO_TMP_DIR);
    command.env("XDG_CACHE_HOME", CLIENT_CACHE_HOME);
    command.env("GOPATH", CLIENT_GO_PATH);
    command.env("GOCACHE", CLIENT_GO_BUILD_CACHE);
    command.env("GOMODCACHE", CLIENT_GO_MOD_CACHE);
    command.env("GOTMPDIR", CLIENT_GO_TMP_DIR);
    // Ignore host/user Go env files so client builds stay deterministic.
    command.env("GOENV", "off");
    command.env("RUST_BACKTRACE", "0");

    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            // Restrictive default file mode for any files created by client apps.
            nix::libc::umask(0o027);

            // Prevent privilege gain via setuid/setgid binaries after launch.
            if nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }
}

fn prepare_client_runtime_directories(run_as_www_data: bool) {
    let runtime_dirs = [
        CLIENT_CACHE_HOME,
        CLIENT_GO_PATH,
        CLIENT_GO_BIN_DIR,
        CLIENT_GO_BUILD_CACHE,
        CLIENT_GO_MOD_CACHE,
        CLIENT_GO_TMP_DIR,
        CLIENT_LOCAL_BIN_DIR,
    ];

    for dir in runtime_dirs {
        if let Err(err) = fs::create_dir_all(dir) {
            log!(
                LogLevel::Warn,
                "Failed to create client runtime dir {}: {}",
                dir,
                err
            );
        }
    }

    if run_as_www_data {
        #[cfg(unix)]
        for dir in runtime_dirs {
            if let Err(err) = std::os::unix::fs::chown(dir, Some(WWW_DATA_UID), Some(WWW_DATA_GID))
            {
                log!(
                    LogLevel::Trace,
                    "Failed to chown client runtime dir {} to www-data: {}",
                    dir,
                    err
                );
            }
        }
    }
}

/// Attempts to start an application and register its spawned process handle.
pub async fn start_application_stub(
    application: &str,
    stores: &[ProcessStoreHandle],
    client_inventory_store: &definitions::ClientInventoryStore,
) -> Result<CommandStubResult, ErrorArrayItem> {
    let Some((resolved_application, is_system_app)) =
        resolve_start_application(application, client_inventory_store).await?
    else {
        return Ok(CommandStubResult::new(
            false,
            format!(
                "[stub] start command rejected for {application}; application is not in the allowed system/client runtime inventory"
            ),
        ));
    };

    '_select_target_store: {
        let handle = match take_process_by_name(&resolved_application, stores).await {
            Ok(Some((handle, _stale_process))) => {
                log!(
                    LogLevel::Debug,
                    "Found existing (possibly stale) entry for {} in {:?}, replacing it",
                    resolved_application,
                    handle.kind()
                );
                handle.remove(&resolved_application).await.ok();
                handle
            }
            Ok(None) => {
                let preferred_kind = if is_system_app {
                    ProcessStoreKind::System
                } else {
                    ProcessStoreKind::Client
                };

                if let Some(target) = stores.iter().find(|store| store.kind() == preferred_kind) {
                    target.clone()
                } else {
                    let default_handle =
                        stores.iter().find(|s| s.is_writable()).ok_or_else(|| {
                            ErrorArrayItem::new(Errors::NotFound, "No writable store available")
                        })?;
                    default_handle.clone()
                }
            }
            Err(err) => return Err(err),
        };

        return start_with_handle(&resolved_application, handle, is_system_app).await;
    }
}

async fn resolve_start_application(
    requested: &str,
    client_inventory_store: &definitions::ClientInventoryStore,
) -> Result<Option<(String, bool)>, ErrorArrayItem> {
    let input = requested.trim();
    if input.is_empty() {
        return Ok(None);
    }

    for system_app in definitions::CRITICAL_APPLICATIONS {
        if input == system_app.ais || input == system_app.canonical {
            return Ok(Some((system_app.ais.to_string(), true)));
        }
    }

    let safe_clients = {
        let guard = client_inventory_store.read().await;
        guard.safe_clients.clone()
    };

    if safe_clients.contains(&input.to_string()) {
        return Ok(Some((input.to_string(), false)));
    }

    if !input.starts_with("ais_") {
        let prefixed = format!("ais_{}", input);
        if safe_clients.contains(&prefixed) {
            return Ok(Some((prefixed, false)));
        }
    }

    Ok(None)
}

/// Launches the process using a pre-selected handle/store target.
async fn start_with_handle(
    application: &str,
    handle: ProcessStoreHandle,
    is_system_app: bool,
) -> Result<CommandStubResult, ErrorArrayItem> {
    let origin = handle.kind();
    let binary_path = PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, application));
    let working_dir = PathType::Content(format!("{}/{}", ARTISAN_CONF_DIR, application));

    if !binary_path.exists() {
        return Ok(CommandStubResult::new(
            true,
            format!(
                "[stub] start command located {application} in {origin:?} registry; Failed: {} not found",
                binary_path
            ),
        ));
    }

    let mut command = Command::new(binary_path);
    if !is_system_app {
        let run_as_www_data = !crate::runtime_flags::runtime_flags().client_root;
        if !run_as_www_data {
            log!(
                LogLevel::Warn,
                "Running {} without www-data UID/GID due to --client-root",
                application
            );
        }
        configure_client_runtime_command(&mut command, run_as_www_data);
    }
    match spawn_complex_process(&mut command, Some(working_dir), true, true).await {
        Ok(mut child) => {
            if let Ok(pid) = child.get_pid().await {
                log!(LogLevel::Info, "Started: {}:{}", application, pid);

                match ebpf::register_pid_with_retry(pid).await {
                    Ok(_) => pid_persistence::clear_pid_failure(pid).await,
                    Err(err) => {
                        if !pid_persistence::is_pid_marked_dead(pid).await {
                            log!(
                                LogLevel::Warn,
                                "Failed to register {} (PID {}) with eBPF tracker: {}",
                                application,
                                pid,
                                err.err_mesg
                            );
                        }
                        pid_persistence::record_pid_failure(pid).await;
                    }
                }

                if let Err(err) = pid_persistence::remember_process(application, pid).await {
                    log!(
                        LogLevel::Error,
                        "Failed to persist PID for {}: {}",
                        application,
                        err.err_mesg
                    );
                }
            }

            // Start monitoring before reinserting
            child.monitor_stdx().await;
            child.monitor_usage().await;

            handle
                .insert(application, SupervisedProcesses::Child(child))
                .await?;

            Ok(CommandStubResult::new(
                true,
                format!("[stub] start command located {application} in {origin:?} registry; OK"),
            ))
        }
        Err(err) => {
            log!(LogLevel::Error, "Failed to spawn: {}: {}", application, err);
            Ok(CommandStubResult::new(
                true,
                format!(
                    "[stub] start command located {application} in {origin:?} registry; Failed: {}",
                    err
                ),
            ))
        }
    }
}

/// Sends a graceful shutdown signal (`SIGUSR1`) to a managed application.
pub async fn stop_application_stub(
    application: &str,
    stores: &[ProcessStoreHandle],
) -> Result<CommandStubResult, ErrorArrayItem> {
    match take_process_by_name(application, stores).await? {
        Some((handle, process)) => {
            let origin = handle.kind();
            let pid_result = match &process {
                SupervisedProcesses::Child(child) => child.get_pid().await.map(|p| p as i32),
                SupervisedProcesses::Process(proc) => Ok(proc.get_pid() as i32),
            };

            match pid_result {
                Ok(pid) => {
                    // Send SIGUSR1 instead of killing the process outright
                    let res = kill(Pid::from_raw(pid), Signal::SIGUSR1);
                    if res.is_ok() {
                        log!(
                            LogLevel::Info,
                            "Sent SIGUSR1 to {} (pid={}), requesting graceful shutdown",
                            application,
                            pid
                        );

                        // Optionally: wait briefly for graceful exit
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

                        // Remove from store; the process should terminate itself gracefully
                        handle.remove(application).await.ok();

                        Ok(CommandStubResult::new(
                            true,
                            format!(
                                "[stub] stop command located {application} in {origin:?} registry; graceful shutdown initiated (SIGUSR1)"
                            ),
                        ))
                    } else {
                        let err = std::io::Error::last_os_error();
                        log!(
                            LogLevel::Error,
                            "Failed to send SIGUSR1 to {} (pid={}): {}",
                            application,
                            pid,
                            err
                        );
                        Ok(CommandStubResult::new(
                            true,
                            format!(
                                "[stub] stop command located {application} in {origin:?} registry; Failed to send SIGUSR1: {}",
                                err
                            ),
                        ))
                    }
                }
                Err(err) => Ok(CommandStubResult::new(
                    true,
                    format!(
                        "[stub] stop command located {application} in {origin:?} registry; Failed to resolve PID: {}",
                        err.err_mesg
                    ),
                )),
            }
        }
        None => Ok(CommandStubResult::new(
            false,
            format!("[stub] stop command could not find {application} in any process registry"),
        )),
    }
}

/// Sends `SIGHUP` to a managed application to request a reload.
pub async fn reload_application_stub(
    application: &str,
    stores: &[ProcessStoreHandle],
) -> Result<CommandStubResult, ErrorArrayItem> {
    match take_process_by_name(application, stores).await? {
        Some((_, process)) => {
            // let origin = process.kind();

            match process {
                SupervisedProcesses::Child(supervised_child) => {
                    match supervised_child.get_pid().await {
                        Ok(pid) => {
                            let res = kill(Pid::from_raw(pid as i32), SIGHUP);
                            if !res.is_err() {
                                log!(LogLevel::Trace, "Sent SIGHUP to pid: {}", pid);
                                Ok(CommandStubResult::new(
                                    true,
                                    format!(
                                        "[stub] reload command located {application} registry; OK"
                                    ),
                                ))
                            } else {
                                let err = io::Error::last_os_error();
                                Ok(CommandStubResult::new(
                                    true,
                                    format!(
                                        "[stub] reload command located {application} registry; Failed to send SIGHUP to pid {}: {}",
                                        pid, err
                                    ),
                                ))
                            }
                        }
                        Err(err) => Ok(CommandStubResult::new(
                            true,
                            format!(
                                "[stub] reload command located {application} in registry; Failed: {}",
                                err.err_mesg
                            ),
                        )),
                    }
                }
                SupervisedProcesses::Process(supervised_process) => {
                    let pid = supervised_process.get_pid();
                    let res = kill(Pid::from_raw(pid), SIGHUP);
                    if !res.is_err() {
                        log!(LogLevel::Trace, "Sent SIGHUP to pid: {}", pid);
                        Ok(CommandStubResult::new(
                            true,
                            format!("[stub] reload command located {application} in registry; OK"),
                        ))
                    } else {
                        let err = io::Error::last_os_error();
                        Ok(CommandStubResult::new(
                            true,
                            format!(
                                "[stub] reload command located {application} in registry; Failed to send SIGHUP to pid {}: {}",
                                pid, err
                            ),
                        ))
                    }
                }
            }
        }
        None => Ok(CommandStubResult::new(
            false,
            format!("[stub] reload command could not find {application} in any process registry"),
        )),
    }
}

/// Rebuilds a managed application binary and falls back to vetted binary on failure.
pub async fn rebuild_application_stub(
    application: &str,
    _stores: &[ProcessStoreHandle],
    client_inventory_store: &definitions::ClientInventoryStore,
) -> Result<CommandStubResult, ErrorArrayItem> {
    '_system_rebuild_path: {
        if definitions::CRITICAL_APPLICATIONS
            .iter()
            .any(|system_app| system_app.ais == application)
        {
            let app_name = application.to_string();
            return match build_application(&app_name).await {
                Ok(_) => {
                    log!(
                        LogLevel::Info,
                        "Rebuilt critical application: {}",
                        application
                    );
                    Ok(CommandStubResult::new(
                        true,
                        format!("[stub] rebuild command completed for system app {application}"),
                    ))
                }
                Err(err) => {
                    log!(
                        LogLevel::Error,
                        "Failed to rebuild system app {}: {}",
                        application,
                        err.err_mesg
                    );
                    let app_name = application.to_string();
                    if let Err(fallback_err) = revert_to_vetted(&app_name).await {
                        log!(
                            LogLevel::Error,
                            "Failed to fall back to vetted binary for {}: {}",
                            application,
                            fallback_err.err_mesg
                        );
                    }
                    Ok(CommandStubResult::new(
                        false,
                        format!(
                            "[stub] rebuild command failed for system app {application}: {}",
                            err.err_mesg
                        ),
                    ))
                }
            };
        }
    }

    '_client_rebuild_path: {
        let safe_clients = {
            let guard = client_inventory_store.read().await;
            guard.safe_clients.clone()
        };

        let resolved = if safe_clients.contains(&application.to_string()) {
            application.to_string()
        } else if !application.starts_with("ais_") {
            let prefixed = format!("ais_{}", application);
            if safe_clients.contains(&prefixed) {
                prefixed
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        if resolved.is_empty() {
            return Ok(CommandStubResult::new(
                false,
                format!(
                    "[stub] rebuild command rejected for {application}; application is not in the vetted client runner list"
                ),
            ));
        }

        log!(LogLevel::Info, "Rebuilding client runner: {}", resolved);
        let runner_name = resolved;
        return match build_runner_binary(&runner_name).await {
            Ok(_) => Ok(CommandStubResult::new(
                true,
                format!(
                    "[stub] rebuild command completed for client app {}",
                    runner_name
                ),
            )),
            Err(err) => {
                log!(
                    LogLevel::Error,
                    "Failed to rebuild client app {}: {}",
                    runner_name,
                    err.err_mesg
                );
                if let Err(fallback_err) = revert_to_vetted(&runner_name).await {
                    log!(
                        LogLevel::Error,
                        "Failed to fallback to vetted binary for {}: {}",
                        runner_name,
                        fallback_err.err_mesg
                    );
                }
                Ok(CommandStubResult::new(
                    false,
                    format!(
                        "[stub] rebuild command failed for client app {}: {}",
                        runner_name,
                        err.err_mesg
                    ),
                ))
            }
        };
    }
}
