use artisan_middleware::{
    aggregator::{Metrics, NetworkUsage, Status},
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
    state_persistence::{AppState, StatePersistence},
};
use get_if_addrs::{IfAddr, get_if_addrs};
use nix::sys::signal::{
    Signal::{self, SIGHUP},
    kill,
};
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    env, fmt, fs, io,
    net::Ipv4Addr,
    time::Duration,
};
use tokio::{process::Command, sync::Mutex, time};

use crate::functions::inventory::generate_safe_client_runner_list;
use crate::{
    definitions::{
        self, ARTISAN_BIN_DIR, ApplicationIdentifiers, ApplicationStatus, SupervisedProcesses,
    },
    ebpf,
    ledger,
    scripts::{build_application, build_runner_binary, revert_to_vetted},
};

const WWW_DATA_USER: &str = "www-data";
const WWW_DATA_HOME: &str = "/var/www";
const WWW_DATA_NVM_DIR: &str = "/var/www/.nvm";
const WWW_DATA_UID: u32 = 33;
const WWW_DATA_GID: u32 = 33;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const STATE_STALE_THRESHOLD_SECONDS: u64 = 30;
const WATCHDOG_DECLARED_DEAD_MESSAGE: &str = "watchdog declared dead";
const RESOURCE_MONITOR_MAX_STALENESS: Duration = Duration::from_millis(1_500);
const RESOURCE_MONITOR_MAX_CONSECUTIVE_FAILURES: u64 = 5;
const STDX_MONITOR_MAX_STALENESS: Duration = Duration::from_millis(2_500);
const STDX_MONITOR_MAX_CONSECUTIVE_FAILURES: u64 = 8;

static LAST_SEEN_STATE_PIDS: Lazy<Mutex<HashMap<String, u32>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static STATE_IO_QUEUE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static STDX_UNHEALTHY_LATCH: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

// pub async fn build_critical(name: &str) -> Result<(), ErrorArrayItem> {
//     let ais_name = definitions::ais_name(name);
//     let critical_app_path_root = PathType::Str(definitions::ARTISAN_APPS_DIR.into());
//     let _critical_app_path = PathType::PathBuf(critical_app_path_root.join(&ais_name));

//     build_application(&ais_name)?;

//     // find the folder or target we're building
//     // run git reset --hard to ensure no changes or bs are holding us up
//     // run the actual build command,
//     // ensure we copied the artifacts to the right dir
//     // run cargo cleanup on the dir
//     Ok(())
// }

/// Periodically refreshes application status data for both system-critical
/// and client-managed processes. Stats for each cohort are stored separately
/// so operators can reason about platform health without sifting through
/// tenant workloads.
pub async fn monitor_application_states(
    system_status_store: definitions::SystemApplicationStatusStore,
    client_status_store: definitions::ClientApplicationStatusStore,
    process_store: definitions::ChildProcessArray,
    interval: Duration,
) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        log!(LogLevel::Trace, "monitor_application_states tick");
        if let Err(err) = refresh_system_statuses_once(&system_status_store, &process_store).await {
            log!(
                LogLevel::Warn,
                "Failed to refresh application statuses: {}",
                err.err_mesg
            );
        }

        if let Err(err) = refresh_client_statuses_once(&client_status_store, &process_store).await {
            log!(
                LogLevel::Trace,
                "Failed to refresh client application statuses: {}",
                err.err_mesg
            );
        }
    }
}

/// Runtime loop for fast monitor-health checks and network usage aggregation.
///
/// - Resource monitor watchdog checks run at `interval`.
/// - Stdout/stderr watchdog checks run at `stdx_interval`.
/// - eBPF PID registration/aggregation runs at `interval`.
pub async fn monitor_runtime_health(
    process_store: definitions::ChildProcessArray,
    system_status_store: definitions::SystemApplicationStatusStore,
    client_status_store: definitions::ClientApplicationStatusStore,
    interval: Duration,
    stdx_interval: Duration,
) {
    let mut ticker = time::interval(interval);
    let base_ms = interval.as_millis().max(1);
    let stdx_every = ((stdx_interval.as_millis().max(base_ms)) / base_ms) as u64;
    let mut tick_count: u64 = 0;

    loop {
        ticker.tick().await;
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
            log!(
                LogLevel::Warn,
                "Failed runtime monitor pass: {}",
                err.err_mesg
            );
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

async fn refresh_runtime_health_and_network(
    process_store: &definitions::ChildProcessArray,
    system_status_store: &definitions::SystemApplicationStatusStore,
    client_status_store: &definitions::ClientApplicationStatusStore,
    check_stdx: bool,
) -> Result<(), ErrorArrayItem> {
    let mut runtime_snapshots: HashMap<String, RuntimeSnapshot> = HashMap::new();
    let mut processes = process_store.try_write().await?;

    for (name, process) in processes.iter_mut() {
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
                match child.get_pid().await {
                    Ok(pid) => {
                        snapshot.pid = Some(pid);
                        snapshot.network_usage =
                            compute_network_usage_for_pid(name, pid).await;
                    }
                    Err(_) => snapshot.network_usage = None,
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
                let pid = proc.get_pid() as u32;
                snapshot.pid = Some(pid);
                snapshot.network_usage = compute_network_usage_for_pid(name, pid).await;
            }
        }
        runtime_snapshots.insert(name.clone(), snapshot);
    }

    drop(processes);
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
        if let Some(metrics) = runtime_snapshot_to_metrics(snapshot) {
            entries.push((name.clone(), metrics));
        }
    }

    if entries.is_empty() {
        return;
    }

    ledger::record_batch(entries).await;
}

fn runtime_snapshot_to_metrics(snapshot: &RuntimeSnapshot) -> Option<Metrics> {
    if snapshot.cpu_usage.is_none()
        && snapshot.memory_usage.is_none()
        && snapshot.network_usage.is_none()
    {
        return None;
    }

    Some(Metrics {
        cpu_usage: snapshot.cpu_usage.unwrap_or_default(),
        memory_usage: snapshot.memory_usage.unwrap_or_default(),
        other: snapshot.network_usage.clone(),
    })
}

fn is_system_application_name(name: &str) -> bool {
    definitions::CRITICAL_APPLICATIONS
        .iter()
        .any(|system_app| system_app.ais == name)
}

async fn update_last_seen_pid(name: &str, pid: Option<u32>) {
    let mut guard = LAST_SEEN_STATE_PIDS.lock().await;
    match pid {
        Some(pid) => {
            guard.insert(name.to_string(), pid);
        }
        None => {
            guard.remove(name);
        }
    }
}

async fn clear_last_seen_pid(name: &str) {
    update_last_seen_pid(name, None).await;
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
    let now = current_timestamp_wrapper();
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

fn should_track_state(state: &AppState) -> bool {
    matches!(
        state.status,
        Status::Running | Status::Starting | Status::Idle | Status::Warning
    )
}

fn mark_state_dead_if_stale(name: &str, state: &mut AppState) {
    let now = current_timestamp_wrapper();
    let age_seconds = now.saturating_sub(state.last_updated);
    if age_seconds < STATE_STALE_THRESHOLD_SECONDS {
        return;
    }

    state.data = WATCHDOG_DECLARED_DEAD_MESSAGE.to_string();
    state.status = Status::Stopped;
    state.pid = 0;
    state.last_updated = now;

    if state
        .stderr
        .last()
        .map(|(_, message)| message.as_str() == WATCHDOG_DECLARED_DEAD_MESSAGE)
        != Some(true)
    {
        state
            .stderr
            .push((now, WATCHDOG_DECLARED_DEAD_MESSAGE.to_string()));
    }

    log!(
        LogLevel::Warn,
        "State snapshot for {} is stale by {}s (threshold {}s); marking as stopped",
        name,
        age_seconds,
        STATE_STALE_THRESHOLD_SECONDS
    );
}

async fn reconcile_process_store_with_state(
    process_store: &definitions::ChildProcessArray,
    name: &str,
    state: &mut AppState,
) -> Result<(), ErrorArrayItem> {
    mark_state_dead_if_stale(name, state);

    if !should_track_state(state) || state.pid == 0 {
        clear_last_seen_pid(name).await;
        return Ok(());
    }

    let desired_pid = state.pid;

    let last_seen_pid = {
        let guard = LAST_SEEN_STATE_PIDS.lock().await;
        guard.get(name).copied()
    };

    let entry_exists = {
        let guard = process_store.try_read().await?;
        guard.contains_key(name)
    };

    if entry_exists && last_seen_pid.is_none() {
        update_last_seen_pid(name, Some(desired_pid)).await;
        return Ok(());
    }

    if entry_exists && last_seen_pid == Some(desired_pid) {
        update_last_seen_pid(name, Some(desired_pid)).await;
        return Ok(());
    }

    let pid_i32 = match i32::try_from(desired_pid) {
        Ok(pid) => pid,
        Err(_) => {
            log!(
                LogLevel::Warn,
                "State snapshot reported pid {} for {} but it exceeds platform limits; skipping reattachment",
                desired_pid,
                name
            );
            return Ok(());
        }
    };

    if crate::pid_persistence::is_pid_marked_dead(desired_pid).await {
        return Ok(());
    }

    log!(
        LogLevel::Trace,
        "Reattaching {} with desired pid {}",
        name,
        desired_pid
    );
    match SupervisedProcess::new(Pid::from_raw(pid_i32)) {
        Ok(mut proc) => {
            proc.monitor_usage().await;

            {
                let mut guard = process_store.try_write().await?;
                guard.insert(name.to_string(), SupervisedProcesses::Process(proc));
            }

            match ebpf::register_pid_with_retry(desired_pid).await {
                Ok(_) => crate::pid_persistence::clear_pid_failure(desired_pid).await,
                Err(err) => {
                    if !crate::pid_persistence::is_pid_marked_dead(desired_pid).await {
                        log!(
                            LogLevel::Warn,
                            "Failed to register {} (PID {}) with eBPF tracker after reattachment: {}",
                            name,
                            desired_pid,
                            err.err_mesg
                        );
                    }
                    crate::pid_persistence::record_pid_failure(desired_pid).await;
                }
            }

            if let Err(err) = crate::pid_persistence::remember_process(name, desired_pid).await {
                log!(
                    LogLevel::Error,
                    "Failed to persist PID {} for {} after reattachment: {}",
                    desired_pid,
                    name,
                    err.err_mesg
                );
            }

            update_last_seen_pid(name, Some(desired_pid)).await;

            log!(
                LogLevel::Info,
                "Detected PID change for {} -> {} via state snapshot; reattached without stdout capture",
                name,
                desired_pid
            );
        }
        Err(err) => {
            log!(
                LogLevel::Warn,
                "Detected PID {} for {} in state snapshot but failed to attach supervisor: {}",
                desired_pid,
                name,
                err.err_mesg
            );
        }
    }

    Ok(())
}

async fn refresh_system_statuses_once(
    status_store: &definitions::SystemApplicationStatusStore,
    process_store: &definitions::ChildProcessArray,
) -> Result<(), ErrorArrayItem> {
    let mut known_names: HashSet<String> = HashSet::new();
    let mut new_statuses: HashMap<String, ApplicationStatus> = HashMap::new();

    for app in definitions::CRITICAL_APPLICATIONS.iter() {
        known_names.insert(app.ais.to_string());
        let mut state = load_state_snapshot(app).await;
        if let Some(snapshot) = state.as_mut() {
            if let Err(err) =
                reconcile_process_store_with_state(process_store, app.ais, snapshot).await
            {
                log!(
                    LogLevel::Warn,
                    "Failed to reconcile state for {}: {}",
                    app.ais,
                    err.err_mesg
                );
            }
        } else {
            clear_last_seen_pid(app.ais).await;
        }
        let observations = collect_process_observations(process_store, app.ais).await?;

        let app_status = merge_state_and_observations(state, observations, true)
            .expect("system applications should always produce a status");

        new_statuses.insert(app.ais.to_string(), app_status);
    }

    if let Ok(dir) = fs::read_dir("/tmp") {
        for entry in dir.flatten() {
            let file_name_os = entry.file_name();
            let Some(file_name) = file_name_os.to_str() else {
                continue;
            };

            if !file_name.starts_with('.') || !file_name.ends_with(".state") {
                continue;
            }

            let ais_name = &file_name[1..file_name.len() - 6];

            if known_names.contains(ais_name) {
                continue;
            }

            if let Some(mut state) = load_state_snapshot_by_name(ais_name).await {
                if !state.system_application {
                    clear_last_seen_pid(ais_name).await;
                    continue;
                }

                if let Err(err) =
                    reconcile_process_store_with_state(process_store, ais_name, &mut state).await
                {
                    log!(
                        LogLevel::Warn,
                        "Failed to reconcile state for {}: {}",
                        ais_name,
                        err.err_mesg
                    );
                }

                let observations = match collect_process_observations(process_store, ais_name).await
                {
                    Ok(observations) => observations,
                    Err(err) => {
                        log!(
                            LogLevel::Warn,
                            "Failed to collect observations for {}: {}",
                            ais_name,
                            err.err_mesg
                        );
                        continue;
                    }
                };

                if let Some(status) = merge_state_and_observations(Some(state), observations, true)
                {
                    new_statuses.insert(ais_name.to_string(), status);
                    known_names.insert(ais_name.to_string());
                }
            } else {
                clear_last_seen_pid(ais_name).await;
            }
        }
    }

    {
        let mut store = status_store.write().await;
        *store = new_statuses;
    }

    Ok(())
}

async fn refresh_client_statuses_once(
    client_store: &definitions::ClientApplicationStatusStore,
    process_store: &definitions::ChildProcessArray,
) -> Result<(), ErrorArrayItem> {
    let process_names: Vec<String> = {
        let guard = process_store.try_read().await?;
        guard
            .keys()
            .filter(|name| !is_system_application_name(name))
            .cloned()
            .collect()
    };

    let mut new_statuses: HashMap<String, ApplicationStatus> = HashMap::new();
    let mut known_names: HashSet<String> = HashSet::new();

    for name in process_names {
        known_names.insert(name.clone());

        let mut state = load_state_snapshot_by_name(&name).await;
        if let Some(snapshot) = state.as_mut() {
            if snapshot.system_application {
                clear_last_seen_pid(&name).await;
                continue;
            }

            if let Err(err) =
                reconcile_process_store_with_state(process_store, &name, snapshot).await
            {
                log!(
                    LogLevel::Warn,
                    "Failed to reconcile state for {}: {}",
                    name,
                    err.err_mesg
                );
            }
        } else {
            clear_last_seen_pid(&name).await;
        }

        let observations = collect_process_observations(process_store, &name).await?;

        if let Some(status) = merge_state_and_observations(state, observations, false) {
            new_statuses.insert(name.clone(), status);
        }
    }

    if let Ok(dir) = fs::read_dir("/tmp") {
        for entry in dir.flatten() {
            if let Some(file_name) = entry.file_name().to_str() {
                if !file_name.starts_with('.') || !file_name.ends_with(".state") {
                    continue;
                }

                let ais_name = &file_name[1..file_name.len() - 6];

                if is_system_application_name(ais_name) {
                    continue;
                }

                if known_names.contains(ais_name) {
                    continue;
                }

                if let Some(mut state) = load_state_snapshot_by_name(ais_name).await {
                    if state.system_application {
                        clear_last_seen_pid(ais_name).await;
                        continue;
                    }

                    if let Err(err) =
                        reconcile_process_store_with_state(process_store, ais_name, &mut state)
                            .await
                    {
                        log!(
                            LogLevel::Warn,
                            "Failed to reconcile state for {}: {}",
                            ais_name,
                            err.err_mesg
                        );
                    }

                    if let Some(status) = merge_state_and_observations(
                        Some(state),
                        ProcessObservations::default(),
                        false,
                    ) {
                        new_statuses.insert(ais_name.to_string(), status);
                    }

                    known_names.insert(ais_name.to_string());
                }
            }
        }
    }

    let mut store = client_store.write().await;
    *store = new_statuses;

    Ok(())
}

async fn load_state_snapshot(app: &ApplicationIdentifiers) -> Option<AppState> {
    load_state_snapshot_by_name(app.ais).await
}

async fn load_state_snapshot_by_name(name: &str) -> Option<AppState> {
    let path = state_file_path(name);
    if let Some(state) = throttled_state_load(path).await {
        Some(state)
    } else {
        log!(
            LogLevel::Trace,
            "Unable to load state for {} (see prior logs)",
            name
        );
        None
    }
}

async fn throttled_state_load(path: PathType) -> Option<AppState> {
    let display = path.to_string();
    let delay_ms = rand::thread_rng().gen_range(1_000..=3_000);
    log!(
        LogLevel::Trace,
        "Queueing state read for {} with delay {}ms",
        display,
        delay_ms
    );

    let _guard = STATE_IO_QUEUE.lock().await;
    log!(
        LogLevel::Trace,
        "State read acquired slot for {}; sleeping {}ms",
        display,
        delay_ms
    );
    time::sleep(Duration::from_millis(delay_ms as u64)).await;

    match StatePersistence::load_state(&path).await {
        Ok(state) => {
            log!(
                LogLevel::Debug,
                "Loaded state file {} after {}ms delay",
                display,
                delay_ms
            );
            Some(state)
        }
        Err(err) => {
            log!(
                LogLevel::Trace,
                "State file load failed for {} after {}ms delay: {}",
                display,
                delay_ms,
                err
            );
            None
        }
    }
}

async fn collect_process_observations(
    process_store: &definitions::ChildProcessArray,
    name: &str,
) -> Result<ProcessObservations, ErrorArrayItem> {
    let mut processes = process_store.try_write().await?;
    let observations = if let Some(process) = processes.get_mut(name) {
        observe_supervised_process(name, process).await?
    } else {
        ProcessObservations::default()
    };

    Ok(observations)
}

async fn observe_supervised_process(
    name: &str,
    process: &mut definitions::SupervisedProcesses,
) -> Result<ProcessObservations, ErrorArrayItem> {
    let mut observations = ProcessObservations::default();

    match process {
        definitions::SupervisedProcesses::Child(child) => {
            if let Ok(stdout) = child.get_std_out().await {
                observations.stdout = Some(stdout);
            }
            if let Ok(stderr) = child.get_std_err().await {
                observations.stderr = Some(stderr);
            }
            if let Ok(pid) = child.get_pid().await {
                observations.pid = Some(pid);
            }
        }
        definitions::SupervisedProcesses::Process(proc) => {
            observations.pid = Some(proc.get_pid() as u32);
        }
    }

    if let Some(metrics) = ledger::latest_metrics(name).await {
        observations.metrics = Some(metrics);
    }

    Ok(observations)
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

fn merge_state_and_observations(
    state: Option<AppState>,
    observations: ProcessObservations,
    allow_empty: bool,
) -> Option<ApplicationStatus> {
    let has_state = state.is_some();

    let (status_value, last_updated, pid_from_state, stdout_from_state, stderr_from_state) =
        match state {
            Some(ref state) => (
                state.status.clone(),
                state.last_updated,
                Some(state.pid),
                state.stdout.clone(),
                state.stderr.clone(),
            ),
            None => (
                artisan_middleware::aggregator::Status::Unknown,
                current_timestamp_wrapper(),
                None,
                Vec::new(),
                Vec::new(),
            ),
        };

    let metrics = observations.metrics;
    let stdout_obs = observations.stdout;
    let stderr_obs = observations.stderr;
    let pid_obs = observations.pid;

    let has_observation = metrics.is_some()
        || pid_obs.is_some()
        || stdout_obs.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || stderr_obs.as_ref().map(|v| !v.is_empty()).unwrap_or(false);

    if !allow_empty && !has_state && !has_observation {
        return None;
    }

    let cpu_usage: f32 = metrics.as_ref().map(|m| m.cpu_usage).unwrap_or_default();
    let memory_usage: f64 = metrics.as_ref().map(|m| m.memory_usage).unwrap_or_default();
    let network_usage = metrics.as_ref().and_then(|m| m.other.clone());

    let pid = pid_obs.or(pid_from_state);
    let stdout_entries = stdout_obs.unwrap_or(stdout_from_state);
    let stderr_entries = stderr_obs.unwrap_or(stderr_from_state);

    let stdout_buffer = definitions::rolling_buffer_from_entries(stdout_entries);
    let stderr_buffer = definitions::rolling_buffer_from_entries(stderr_entries);

    Some(ApplicationStatus::new(
        status_value,
        cpu_usage,
        memory_usage,
        pid,
        last_updated,
        stdout_buffer,
        stderr_buffer,
        network_usage,
    ))
}

/// Collects all IPv4 addresses on the host, excluding localhost and
/// common container/virtual bridge interfaces (Docker/Podman/veth).
pub fn get_all_ipv4() -> io::Result<Vec<Ipv4Addr>> {
    let interfaces = get_if_addrs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Interface-name patterns to exclude (case-insensitive)
    // - Linux: lo, docker0, br-*, veth*, cni*, flannel.*
    // - Podman: cni-podman0
    // - Windows: vEthernet (DockerNAT), anything containing "docker"
    // - macOS with Docker: bridge/utun variations sometimes appear; filter "bridge" conservatively only if it mentions docker.
    let mut ips: Vec<Ipv4Addr> = interfaces
        .into_iter()
        .filter(|iface| {
            let n = iface.name.to_lowercase();
            // skip loopback interface by name
            if n == "lo" {
                return false;
            }
            // common docker/podman/bridge/veth names
            if n.starts_with("docker") {
                return false;
            }
            if n.starts_with("br-") {
                return false;
            }
            if n.starts_with("veth") {
                return false;
            }
            if n.starts_with("cni") {
                return false;
            }
            if n.starts_with("flannel.") {
                return false;
            }
            // windows docker virtual switch
            if n.contains("docker") {
                return false;
            }
            if n.contains("vethernet") {
                return false;
            }
            true
        })
        .filter_map(|iface| {
            match iface.addr {
                IfAddr::V4(v4) => {
                    let ip = v4.ip;
                    // exclude localhost by address
                    if ip.is_loopback() {
                        return None;
                    }
                    Some(ip)
                }
                _ => None,
            }
        })
        .collect();

    // Deduplicate (interfaces can expose the same IP via aliases)
    ips.sort_unstable();
    ips.dedup();

    Ok(ips)
}

fn state_file_path(ais_name: &str) -> PathType {
    PathType::Content(format!("/tmp/.{}.state", ais_name))
}

fn current_timestamp_wrapper() -> u64 {
    artisan_middleware::timestamp::current_timestamp()
}

#[derive(Default)]
struct ProcessObservations {
    metrics: Option<Metrics>,
    stdout: Option<Vec<(u64, String)>>,
    stderr: Option<Vec<(u64, String)>>,
    pid: Option<u32>,
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

impl fmt::Display for ProcessStoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessStoreKind::System => write!(f, "system"),
            ProcessStoreKind::Client => write!(f, "client"),
            ProcessStoreKind::Custom(label) => write!(f, "{label}"),
        }
    }
}

#[derive(Clone)]
pub struct ProcessStoreHandle {
    kind: ProcessStoreKind,
    store: definitions::ChildProcessArray,
}

impl ProcessStoreHandle {
    pub fn system(store: &definitions::ChildProcessArray) -> Self {
        Self {
            kind: ProcessStoreKind::System,
            store: store.clone(),
        }
    }

    pub fn client(store: &definitions::ChildProcessArray) -> Self {
        Self {
            kind: ProcessStoreKind::Client,
            store: store.clone(),
        }
    }

    pub fn custom(label: &'static str, store: &definitions::ChildProcessArray) -> Self {
        Self {
            kind: ProcessStoreKind::Custom(label),
            store: store.clone(),
        }
    }

    pub fn kind(&self) -> ProcessStoreKind {
        self.kind
    }

    pub async fn insert(
        &self,
        name: &str,
        process: definitions::SupervisedProcesses,
    ) -> Result<(), ErrorArrayItem> {
        let mut guard = self.store.try_write().await?;
        guard.insert(name.to_string(), process);
        Ok(())
    }

    pub async fn remove(&self, name: &str) -> Result<(), ErrorArrayItem> {
        let mut guard = self.store.try_write().await?;
        guard.remove(name);
        Ok(())
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self.kind(),
            ProcessStoreKind::System | ProcessStoreKind::Client
        )
    }
}

pub async fn take_process_by_name(
    name: &str,
    stores: &[ProcessStoreHandle],
) -> Result<Option<(ProcessStoreHandle, definitions::SupervisedProcesses)>, ErrorArrayItem> {
    for store_ref in stores {
        let handle = store_ref.clone();
        let mut guard = handle.store.try_write().await?;
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

pub fn configure_www_data_command(command: &mut Command) {
    command.uid(WWW_DATA_UID);
    command.gid(WWW_DATA_GID);

    command.env("HOME", WWW_DATA_HOME);
    command.env("USER", WWW_DATA_USER);
    command.env("LOGNAME", WWW_DATA_USER);
    command.env("NVM_DIR", WWW_DATA_NVM_DIR);
    command.env("SHELL", "/bin/bash");

    // let nvm_bin = format!("{}/bin", WWW_DATA_NVM_DIR);
    let node_bin = format!("{}/versions/node/v23.5.0/bin", WWW_DATA_NVM_DIR);

    let existing_path = env::var("PATH").unwrap_or_else(|_| DEFAULT_PATH.to_string());
    let mut segments = Vec::new();
    segments.push(node_bin);
    // segments.push(nvm_bin);
    segments.push(existing_path);
    let combined_path = segments.join(":");
    command.env("PATH", combined_path);
}

// #[derive(Clone, Copy)]
// enum CommandAction {
//     Start,
//     Stop,
//     Reload,
//     Rebuild,
// }

// impl fmt::Display for CommandAction {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let action = match self {
//             CommandAction::Start => "start",
//             CommandAction::Stop => "stop",
//             CommandAction::Reload => "reload",
//             CommandAction::Rebuild => "rebuild",
//         };
//         write!(f, "{action}")
//     }
// }

pub async fn start_application_stub(
    application: &str,
    stores: &[ProcessStoreHandle],
) -> Result<CommandStubResult, ErrorArrayItem> {
    let is_system_app = definitions::CRITICAL_APPLICATIONS
        .iter()
        .any(|system_app| system_app.ais == application);

    // Try to find existing handle
    let handle = match take_process_by_name(application, stores).await {
        Ok(Some((handle, _stale_process))) => {
            log!(
                LogLevel::Debug,
                "Found existing (possibly stale) entry for {} in {:?}, replacing it",
                application,
                handle.kind()
            );
            // Drop stale entry before respawning
            handle.remove(application).await.ok();
            handle
        }
        Ok(None) => {
            // Pick preferred store based on application type
            let preferred_kind = if is_system_app {
                ProcessStoreKind::System
            } else {
                ProcessStoreKind::Client
            };

            if let Some(target) = stores.iter().find(|store| store.kind() == preferred_kind) {
                target.clone()
            } else {
                let default_handle = stores.iter().find(|s| s.is_writable()).ok_or_else(|| {
                    ErrorArrayItem::new(Errors::NotFound, "No writable store available")
                })?;
                default_handle.clone()
            }
        }
        Err(err) => return Err(err),
    };

    // Now perform the actual spawn
    start_with_handle(application, handle, is_system_app).await
}

/// Helper: launches the process using the provided handle
async fn start_with_handle(
    application: &str,
    handle: ProcessStoreHandle,
    is_system_app: bool,
) -> Result<CommandStubResult, ErrorArrayItem> {
    let origin = handle.kind();
    let binary_path = PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, application));
    let working_dir = PathType::Content(format!("/etc/{}", application));

    if !binary_path.exists() {
        return Ok(CommandStubResult::new(
            true,
            format!(
                "[stub] start command located {application} in {origin} registry; Failed: {} not found",
                binary_path
            ),
        ));
    }

    let mut command = Command::new(binary_path);
    if !is_system_app {
        configure_www_data_command(&mut command);
    }
    match spawn_complex_process(&mut command, Some(working_dir), true, true).await {
        Ok(mut child) => {
            if let Ok(pid) = child.get_pid().await {
                log!(LogLevel::Info, "Started: {}:{}", application, pid);

                match ebpf::register_pid_with_retry(pid).await {
                    Ok(_) => crate::pid_persistence::clear_pid_failure(pid).await,
                    Err(err) => {
                        if !crate::pid_persistence::is_pid_marked_dead(pid).await {
                            log!(
                                LogLevel::Warn,
                                "Failed to register {} (PID {}) with eBPF tracker: {}",
                                application,
                                pid,
                                err.err_mesg
                            );
                        }
                        crate::pid_persistence::record_pid_failure(pid).await;
                    }
                }

                if let Err(err) = crate::pid_persistence::remember_process(application, pid).await {
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
                format!("[stub] start command located {application} in {origin} registry; OK"),
            ))
        }
        Err(err) => {
            log!(LogLevel::Error, "Failed to spawn: {}: {}", application, err);
            Ok(CommandStubResult::new(
                true,
                format!(
                    "[stub] start command located {application} in {origin} registry; Failed: {}",
                    err
                ),
            ))
        }
    }
}

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
                                "[stub] stop command located {application} in {origin} registry; graceful shutdown initiated (SIGUSR1)"
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
                                "[stub] stop command located {application} in {origin} registry; Failed to send SIGUSR1: {}",
                                err
                            ),
                        ))
                    }
                }
                Err(err) => Ok(CommandStubResult::new(
                    true,
                    format!(
                        "[stub] stop command located {application} in {origin} registry; Failed to resolve PID: {}",
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

pub async fn rebuild_application_stub(
    application: &str,
    _stores: &[ProcessStoreHandle],
) -> Result<CommandStubResult, ErrorArrayItem> {
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

    let client_applications = generate_safe_client_runner_list().await?;
    if !client_applications.contains(&application.to_string()) {
        return Ok(CommandStubResult::new(
            false,
            format!(
                "[stub] rebuild command rejected for {application}; application is not in the vetted client runner list"
            ),
        ));
    }

    log!(LogLevel::Info, "Rebuilding client runner: {}", application);
    let runner_name = application.to_string();
    match build_runner_binary(&runner_name).await {
        Ok(_) => Ok(CommandStubResult::new(
            true,
            format!("[stub] rebuild command completed for client app {application}"),
        )),
        Err(err) => {
            log!(
                LogLevel::Error,
                "Failed to rebuild client app {}: {}",
                application,
                err.err_mesg
            );
            let runner_name = application.to_string();
            if let Err(fallback_err) = revert_to_vetted(&runner_name).await {
                log!(
                    LogLevel::Error,
                    "Failed to fallback to vetted binary for {}: {}",
                    application,
                    fallback_err.err_mesg
                );
            }
            Ok(CommandStubResult::new(
                false,
                format!(
                    "[stub] rebuild command failed for client app {application}: {}",
                    err.err_mesg
                ),
            ))
        }
    }
}
