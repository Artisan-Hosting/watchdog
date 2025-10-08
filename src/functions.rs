use artisan_middleware::{
    dusa_collection_utils::{
        core::{errors::ErrorArrayItem, logger::LogLevel, types::pathtype::PathType},
        log,
    },
    git_actions::GitCredentials,
    state_persistence::{AppState, StatePersistence},
};
use get_if_addrs::{IfAddr, get_if_addrs};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::Ipv4Addr,
    time::Duration,
};
use tokio::time;

use crate::{
    definitions::{
        self, ARTISAN_BIN_DIR, ApplicationIdentifiers, ApplicationStatus, CRITICAL_APPLICATIONS,
        GIT_CONFIG_PATH, VerificationEntry,
    },
    ebpf,
};

// ! touching this will ruin your day
const VERIFICATION_MATRIX: [(&str, &str, Option<&str>); 2] = [
    (
        "ledger",
        definitions::LEDGER_PATH,
        None, // don't check, just verify the file exists
    ),
    (
        "credentials",
        definitions::GIT_CONFIG_PATH,
        None, // don't check, just verify the file exists
    ),
];

pub fn verify_path(path: PathType) -> Result<VerificationEntry, ErrorArrayItem> {
    let mut verification_entry = VerificationEntry::new();

    let matrix = &VERIFICATION_MATRIX;

    matrix.iter().for_each(|entry| {
        let argument_path_string = path.to_string();

        // found a valid entry
        if entry.1 == argument_path_string {
            // verify the path exists
            verification_entry.name = entry.0.to_owned();
            verification_entry.path = path.clone();
            verification_entry.expected_hash = if let Some(data) = entry.2 {
                data.to_owned()
            } else {
                "".to_owned()
            };

            // checking hash
            if verification_entry.expected_hash == "" {
                verification_entry.verified = path.exists();
                log!(
                    LogLevel::Warn,
                    "Skipped hash for :{}",
                    verification_entry.name
                );
            } else {
                let new_hash = "hash"; // implement a full file hash utils
                verification_entry.calculated_hash = new_hash.to_owned();

                verification_entry.verified =
                    verification_entry.expected_hash == verification_entry.calculated_hash;
            }
        }
    });

    Ok(verification_entry)
}

/// Builds the list of client application binaries that should be built/spawned.
/// The resulting list excludes core system processes and only includes entries
/// that have a matching credential in the git configuration.
pub async fn generate_safe_client_runner_list() -> Result<Vec<String>, ErrorArrayItem> {
    let mut application_list: Vec<String> = Vec::new();

    // Reading all the bins in the default path
    let dir_read: fs::ReadDir = match fs::read_dir(ARTISAN_BIN_DIR) {
        Ok(data) => data,
        Err(err) => {
            log!(
                LogLevel::Error,
                "Failed to read bins from /opt/artisan/bin: {}",
                err
            );
            return Err(ErrorArrayItem::from(err));
        }
    };

    for entry in dir_read {
        match entry {
            Ok(maybe_file) => {
                if let Ok(filetype) = maybe_file.file_type() {
                    if filetype.is_file() {
                        match maybe_file.file_name().into_string() {
                            Ok(name) => {
                                application_list.push(name);
                            }
                            Err(err) => {
                                log!(
                                    LogLevel::Error,
                                    "Skipping file, has a stupid file name: {:?}",
                                    err
                                );
                            }
                        };
                    }
                }
            }
            Err(err) => {
                log!(
                    LogLevel::Error,
                    "Failed to read bins from /opt/artisan/bin: {}",
                    err
                );
                continue;
            }
        }
    }

    // Pasring the git configuration
    let git_credential_file: PathType = PathType::Content(GIT_CONFIG_PATH.to_string());
    let git_credentials_array = match GitCredentials::new_vec(Some(&git_credential_file)).await {
        Ok(data) => data,
        Err(err) => {
            log!(LogLevel::Error, "{}", err);
            return Err(err);
        }
    };

    let mut git_project_hashes: Vec<String> = Vec::new();

    for project in git_credentials_array {
        git_project_hashes.push(project.generate_id().to_string());
    }

    let mut system_applications: Vec<String> = Vec::new();
    let system_applications_identifiers = CRITICAL_APPLICATIONS.to_vec();

    system_applications_identifiers.iter().for_each(|entry| {
        system_applications.push(entry.ais.to_string());
    });

    // filtering out system applications and files that dont match the git config file given to the manager
    let client_applications_names: Vec<String> = application_list
        .into_iter()
        .filter(|name| !system_applications.contains(name))
        .filter(|name| {
            let stripped_name = name.replace("ais_", "");
            git_project_hashes.contains(&stripped_name)
        })
        .collect();

    Ok(client_applications_names)
}

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

        if let Err(err) = ebpf::cleanup_dead_pids() {
            log!(
                LogLevel::Trace,
                "Failed to prune eBPF PID map: {}",
                err.err_mesg
            );
        }
    }
}

async fn refresh_system_statuses_once(
    status_store: &definitions::SystemApplicationStatusStore,
    process_store: &definitions::ChildProcessArray,
) -> Result<(), ErrorArrayItem> {
    for app in definitions::CRITICAL_APPLICATIONS.iter() {
        let state = load_state_snapshot(app).await;
        let observations = collect_process_observations(process_store, app.ais).await?;

        let app_status = merge_state_and_observations(state, observations, true)
            .expect("system applications should always produce a status");

        let mut store = status_store.write().await;
        store.insert(app.ais.to_string(), app_status);
    }

    Ok(())
}

async fn refresh_client_statuses_once(
    client_store: &definitions::ClientApplicationStatusStore,
    process_store: &definitions::ChildProcessArray,
) -> Result<(), ErrorArrayItem> {
    let processes = process_store.try_read().await?;
    let mut new_statuses: HashMap<String, ApplicationStatus> = HashMap::new();
    let mut known_names: HashSet<String> = HashSet::new();

    for (name, process) in processes.iter() {
        if definitions::CRITICAL_APPLICATIONS
            .iter()
            .any(|system_app| system_app.ais == name)
        {
            continue;
        }

        known_names.insert(name.clone());

        let state = load_state_snapshot_by_name(name).await;
        let observations = observe_supervised_process(process).await?;

        if let Some(status) = merge_state_and_observations(state, observations, false) {
            new_statuses.insert(name.clone(), status);
        }
    }

    drop(processes);

    if let Ok(dir) = fs::read_dir("/tmp") {
        for entry in dir.flatten() {
            if let Some(file_name) = entry.file_name().to_str() {
                if !file_name.starts_with('.') || !file_name.ends_with(".state") {
                    continue;
                }

                let ais_name = &file_name[1..file_name.len() - 6];

                if definitions::CRITICAL_APPLICATIONS
                    .iter()
                    .any(|system_app| system_app.ais == ais_name)
                {
                    continue;
                }

                if known_names.contains(ais_name) {
                    continue;
                }

                if let Some(state) = load_state_snapshot_by_name(ais_name).await {
                    if state.system_application {
                        continue;
                    }

                    if let Some(status) = merge_state_and_observations(
                        Some(state),
                        ProcessObservations::default(),
                        false,
                    ) {
                        new_statuses.insert(ais_name.to_string(), status);
                    }
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
    match StatePersistence::load_state(&path).await {
        Ok(state) => Some(state),
        Err(err) => {
            log!(
                LogLevel::Trace,
                "Unable to load state for {}: {}",
                name,
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
    let processes = process_store.try_read().await?;
    let observations = if let Some(process) = processes.get(name) {
        observe_supervised_process(process).await?
    } else {
        ProcessObservations::default()
    };

    Ok(observations)
}

async fn observe_supervised_process(
    process: &definitions::SupervisedProcesses,
) -> Result<ProcessObservations, ErrorArrayItem> {
    let mut observations = ProcessObservations::default();

    match process {
        definitions::SupervisedProcesses::Child(child) => {
            if let Ok(metrics) = child.get_metrics().await {
                observations.metrics = Some(metrics);
            }
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
            if let Ok(metrics) = proc.get_metrics().await {
                observations.metrics = Some(metrics);
            }
            observations.pid = Some(proc.get_pid() as u32);
        }
    }

    if let Some(pid) = observations.pid {
        match ebpf::usage_for_pid(pid) {
            Ok(Some(usage)) => {
                if let Some(metrics) = observations.metrics.as_mut() {
                    metrics.other = Some(usage);
                } else {
                    observations.metrics = Some(artisan_middleware::aggregator::Metrics {
                        cpu_usage: 0.0,
                        memory_usage: 0.0,
                        other: Some(usage),
                    });
                }
            }
            Ok(None) => {}
            Err(err) => {
                log!(
                    LogLevel::Trace,
                    "Failed to read eBPF usage for PID {}: {}",
                    pid,
                    err.err_mesg
                );
            }
        }
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
    metrics: Option<artisan_middleware::aggregator::Metrics>,
    stdout: Option<Vec<(u64, String)>>,
    stderr: Option<Vec<(u64, String)>>,
    pid: Option<u32>,
}
