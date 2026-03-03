//! State refresh and reconciliation for monitored applications.
//!
//! This module is responsible for loading `/tmp/.ais_*.state` snapshots,
//! reconciling the process store to reported PIDs, and merging those snapshots
//! with live observations collected from supervised process handles.

use artisan_middleware::{
    aggregator::{Metrics, Status},
    dusa_collection_utils::{
        core::{errors::ErrorArrayItem, logger::LogLevel, types::pathtype::PathType},
        log,
    },
    process_manager::SupervisedProcess,
    state_persistence::{AppState, StatePersistence},
};
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fs,
    time::Duration,
};
use tokio::{sync::Mutex, time};

use crate::{
    definitions::{
        self, ARTISAN_TMP_DIR, ApplicationIdentifiers, ApplicationStatus, SupervisedProcesses,
    },
    ebpf, ledger, pid_persistence,
};

const STATE_STALE_THRESHOLD_SECONDS: u64 = 30;
const WATCHDOG_DECLARED_DEAD_MESSAGE: &str = "watchdog declared dead";
const PROCESS_STORE_LOCK_TIMEOUT: Duration = Duration::from_millis(400);

static LAST_SEEN_STATE_PIDS: Lazy<Mutex<HashMap<String, u32>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static STATE_IO_QUEUE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Default)]
struct ProcessObservations {
    metrics: Option<Metrics>,
    stdout: Option<Vec<(u64, String)>>,
    stderr: Option<Vec<(u64, String)>>,
    pid: Option<u32>,
}

/// Refreshes all system-application statuses from state snapshots and process
/// observations, then replaces the system status store atomically.
pub(super) async fn refresh_system_statuses_once(
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
        persist_application_logs(app.ais, &app_status).await;

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
                    persist_application_logs(ais_name, &status).await;
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

/// Refreshes all client-application statuses from state snapshots and process
/// observations, then replaces the client status store atomically.
pub(super) async fn refresh_client_statuses_once(
    client_store: &definitions::ClientApplicationStatusStore,
    process_store: &definitions::ChildProcessArray,
) -> Result<(), ErrorArrayItem> {
    let process_names: Vec<String> = {
        let guard = process_store
            .try_read_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
            .await?;
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
            persist_application_logs(&name, &status).await;
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
                        persist_application_logs(ais_name, &status).await;
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
        let guard = process_store
            .try_read_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
            .await?;
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

    if pid_persistence::is_pid_marked_dead(desired_pid).await {
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
                let mut guard = process_store
                    .try_write_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
                    .await?;
                guard.insert(name.to_string(), SupervisedProcesses::Process(proc));
            }

            match ebpf::register_pid_with_retry(desired_pid).await {
                Ok(_) => pid_persistence::clear_pid_failure(desired_pid).await,
                Err(err) => {
                    if !pid_persistence::is_pid_marked_dead(desired_pid).await {
                        log!(
                            LogLevel::Warn,
                            "Failed to register {} (PID {}) with eBPF tracker after reattachment: {}",
                            name,
                            desired_pid,
                            err.err_mesg
                        );
                    }
                    pid_persistence::record_pid_failure(desired_pid).await;
                }
            }

            if let Err(err) = pid_persistence::remember_process(name, desired_pid).await {
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
    let mut processes = process_store
        .try_write_with_timeout(Some(PROCESS_STORE_LOCK_TIMEOUT))
        .await?;
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
                Status::Unknown,
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

async fn persist_application_logs(name: &str, status: &ApplicationStatus) {
    let stdout_entries = status.stdout.get_latest_time();
    if let Err(err) =
        ledger::record_stream_entries(name, ledger::LogStream::Stdout, &stdout_entries).await
    {
        log!(
            LogLevel::Trace,
            "Failed to persist stdout logs for {}: {}",
            name,
            err.err_mesg
        );
    }

    let stderr_entries = status.stderr.get_latest_time();
    if let Err(err) =
        ledger::record_stream_entries(name, ledger::LogStream::Stderr, &stderr_entries).await
    {
        log!(
            LogLevel::Trace,
            "Failed to persist stderr logs for {}: {}",
            name,
            err.err_mesg
        );
    }
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

fn state_file_path(ais_name: &str) -> PathType {
    PathType::Content(format!("{}/.{}.state", ARTISAN_TMP_DIR, ais_name))
}

fn current_timestamp_wrapper() -> u64 {
    artisan_middleware::timestamp::current_timestamp()
}

#[cfg(test)]
mod tests {
    use super::{WATCHDOG_DECLARED_DEAD_MESSAGE, mark_state_dead_if_stale};
    use artisan_middleware::{
        aggregator::Status, config::AppConfig,
        dusa_collection_utils::core::version::SoftwareVersion, state_persistence::AppState,
    };

    #[test]
    fn stale_state_is_marked_stopped() {
        let now = artisan_middleware::timestamp::current_timestamp();
        let mut state = AppState {
            name: "ais_demo".to_string(),
            version: SoftwareVersion::dummy(),
            status: Status::Running,
            pid: 42,
            data: String::new(),
            last_updated: now.saturating_sub(120),
            stared_at: now.saturating_sub(300),
            event_counter: 0,
            error_log: Vec::new(),
            config: AppConfig::dummy(),
            system_application: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };

        mark_state_dead_if_stale("ais_demo", &mut state);
        assert_eq!(state.status, Status::Stopped);
        assert_eq!(state.pid, 0);
        assert_eq!(state.data, WATCHDOG_DECLARED_DEAD_MESSAGE);
        assert!(!state.stderr.is_empty());
    }
}
