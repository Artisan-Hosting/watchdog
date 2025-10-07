use std::{fs, time::Duration};

use artisan_middleware::{
    dusa_collection_utils::{
        core::{errors::ErrorArrayItem, logger::LogLevel, types::pathtype::PathType},
        log,
    },
    git_actions::GitCredentials,
    state_persistence::{AppState, StatePersistence},
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

pub async fn monitor_application_states(
    status_store: definitions::ApplicationStatusStore,
    process_store: definitions::ChildProcessArray,
    interval: Duration,
) {
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(err) = refresh_application_statuses_once(&status_store, &process_store).await {
            log!(
                LogLevel::Warn,
                "Failed to refresh application statuses: {}",
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

async fn refresh_application_statuses_once(
    status_store: &definitions::ApplicationStatusStore,
    process_store: &definitions::ChildProcessArray,
) -> Result<(), ErrorArrayItem> {
    for app in definitions::CRITICAL_APPLICATIONS.iter() {
        let state = load_state_snapshot(app).await;
        let observations = collect_process_observations(process_store, app).await?;

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
        let cpu_usage: f32 = metrics.as_ref().map(|m| m.cpu_usage).unwrap_or_default();
        let memory_usage: f64 = metrics.as_ref().map(|m| m.memory_usage).unwrap_or_default();
        let network_usage = metrics.as_ref().and_then(|m| m.other.clone());

        let pid = observations.pid.or(pid_from_state);

        let stdout_entries = observations.stdout.unwrap_or(stdout_from_state);
        let stderr_entries = observations.stderr.unwrap_or(stderr_from_state);

        let stdout_buffer = definitions::rolling_buffer_from_entries(stdout_entries);
        let stderr_buffer = definitions::rolling_buffer_from_entries(stderr_entries);

        let app_status = ApplicationStatus::new(
            status_value,
            cpu_usage,
            memory_usage,
            pid,
            last_updated,
            stdout_buffer,
            stderr_buffer,
            network_usage,
        );

        let mut store = status_store.write().await;
        store.insert(app.ais.to_string(), app_status);
    }

    Ok(())
}

async fn load_state_snapshot(app: &ApplicationIdentifiers) -> Option<AppState> {
    let path = state_file_path(app.ais);
    match StatePersistence::load_state(&path).await {
        Ok(state) => Some(state),
        Err(err) => {
            log!(
                LogLevel::Trace,
                "Unable to load state for {}: {}",
                app.ais,
                err
            );
            None
        }
    }
}

async fn collect_process_observations(
    process_store: &definitions::ChildProcessArray,
    app: &ApplicationIdentifiers,
) -> Result<ProcessObservations, ErrorArrayItem> {
    let processes = process_store.try_read().await?;
    let mut observations = ProcessObservations::default();

    if let Some(process) = processes.get(app.ais) {
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
