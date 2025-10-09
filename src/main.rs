use artisan_middleware::{
    dusa_collection_utils::{
        core::{
            errors::{ErrorArray, ErrorArrayItem},
            logger::LogLevel,
            types::pathtype::PathType,
        },
        log,
    },
    process_manager::spawn_complex_process,
};
use std::{os::unix::fs::chown, time::Duration};
use tokio::process::Command;

use crate::{definitions::VerificationEntry, functions::generate_safe_client_runner_list};
use crate::{
    definitions::{self as defs, ARTISAN_BIN_DIR, CRITICAL_APPLICATIONS},
    scripts::build_runner_binary,
};
use crate::{
    functions::{monitor_application_states, verify_path},
    scripts::{build_application, revert_to_vetted},
};

pub mod definitions;
pub mod ebpf;
pub mod functions;
pub mod grpc;
pub mod pid_persistence;
pub mod scripts;

#[tokio::main]
async fn main() -> Result<(), ErrorArrayItem> {
    //  Create / Define state data for the system as we initialize everything
    //// define shape for verification status
    //// define shape for build status for each application / include if we failed and are running the vetted versions
    // define the shape for the  current running status / memory / cpu and warning / error information for the applications
    // define a small language that covers the following
    // controls applications. start / stop / reload
    // status, can return it's building / running

    let system_application_status_store = defs::new_system_application_status_store();
    let client_application_status_store = defs::new_client_application_status_store();
    let build_status_store = defs::new_build_status_store();
    let verification_status_store = defs::new_verification_status_store();
    let system_information_store = defs::new_system_information_store();
    let system_process_store = defs::new_child_process_array();

    crate::pid_persistence::initialise().await?;
    crate::pid_persistence::reclaim_orphan_processes().await?;

    {
        let system_status_store = system_application_status_store.clone();
        let client_status_store = client_application_status_store.clone();
        let process_store = system_process_store.clone();
        tokio::spawn(async move {
            monitor_application_states(
                system_status_store,
                client_status_store,
                process_store,
                Duration::from_secs(5),
            )
            .await;
        });
    }

    {
        let system_store = system_application_status_store.clone();
        let client_store = client_application_status_store.clone();
        let build_store = build_status_store.clone();
        let verification_store = verification_status_store.clone();
        let system_info_store = system_information_store.clone();
        let process_store = system_process_store.clone();
        tokio::spawn(async move {
            if let Err(err) = grpc::serve_watchdog(
                system_store,
                client_store,
                build_store,
                verification_store,
                system_info_store,
                process_store,
            )
            .await
            {
                log!(
                    LogLevel::Error,
                    "Failed to start watchdog gRPC server: {}",
                    err
                );
            }
        });
    }

    '_hash_verification: {
        let mut verification_results: Vec<VerificationEntry> = Vec::new();

        for path in defs::CORE_VERIFICATION_PATHS.iter() {
            let path: PathType = PathType::Str((*path).into());
            match verify_path(path) {
                Ok(result) => verification_results.push(result),
                Err(err) => {
                    // something went really wrong
                    ErrorArray::from(err).display(true);
                }
            }
        }

        verification_results
            .iter()
            .for_each(|entry| match entry.verified {
                true => {
                    log!(LogLevel::Info, "Verified: {}", entry.name);
                }
                false => {
                    log!(LogLevel::Error, "Verified Failed: {}", entry.name);
                }
            });

        {
            let mut store = verification_status_store.write().await;
            *store = verification_results.clone();
        }
    }

    '_building_critial_apps: {
        for app in defs::CRITICAL_APPLICATIONS {
            let ais_key = app.ais.to_string();
            let ais_name = ais_key.as_str();

            log!(LogLevel::Info, "Building: {}!", ais_name);
            match build_application(ais_name) {
                Ok(_) => {
                    log!(LogLevel::Info, "Built: {}!", ais_name);

                    {
                        let mut statuses = build_status_store.write().await;
                        statuses
                            .insert(ais_key.clone(), defs::BuildStatus::success(ais_name, false));
                    }
                }
                Err(err) => {
                    log!(LogLevel::Error, "Failed to build {}!", ais_name);
                    log!(
                        LogLevel::Error,
                        "Got the following error: {}!",
                        err.err_mesg
                    );
                    log!(
                        LogLevel::Warn,
                        "Attemping to fallback to earlier version for: {}",
                        ais_name
                    );

                    let fallback_used = match revert_to_vetted(ais_name) {
                        Ok(_) => {
                            log!(
                                LogLevel::Info,
                                "Fellback to older version of: {}!",
                                ais_name
                            );
                            true
                        }
                        Err(err) => {
                            log!(
                                LogLevel::Error,
                                "Failed to fall back to earlier version, help...."
                            );
                            ErrorArray::from(err).display(false);
                            false
                        }
                    };

                    {
                        let mut statuses = build_status_store.write().await;
                        statuses.insert(
                            ais_key.clone(),
                            defs::BuildStatus::failure(ais_name, fallback_used),
                        );
                    }
                }
            }
        }

        log!(
            LogLevel::Info,
            "Finished building system level applications"
        );
    }

    '_spawning_system_applications: {
        let system_app_array: Vec<definitions::ApplicationIdentifiers> =
            CRITICAL_APPLICATIONS.to_vec();

        for app in system_app_array {
            if app.canonical != "welcome" {
                let binary_path = PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, app.ais));
                let working_dir = PathType::Content(format!("/etc/{}", app.ais)); //This is the production value
                // let working_dir = PathType::Content(format!("/opt/artisan/apps/{}", app.ais));

                // assembling command
                let mut command = Command::new(binary_path);
                match spawn_complex_process(&mut command, Some(working_dir), true, true).await {
                    Ok(mut child) => {
                        let pid_result = child.get_pid().await;

                        match pid_result {
                            Ok(pid) => {
                                log!(LogLevel::Info, "Started: {}:{}", app.ais, pid);

                                if let Err(err) = ebpf::register_pid(pid) {
                                    log!(
                                        LogLevel::Warn,
                                        "Failed to register {} (PID {}) with eBPF tracker: {}",
                                        app.ais,
                                        pid,
                                        err.err_mesg
                                    );
                                }

                                if let Err(err) =
                                    crate::pid_persistence::remember_process(app.ais, pid).await
                                {
                                    log!(
                                        LogLevel::Error,
                                        "Failed to persist PID for {}: {}",
                                        app.ais,
                                        err.err_mesg
                                    );
                                }
                            }
                            Err(err) => {
                                log!(
                                    LogLevel::Error,
                                    "Failed to resolve PID for {}: {}",
                                    app.ais,
                                    err
                                );
                            }
                        }

                        child.monitor_stdx().await;
                        child.monitor_usage().await;
                        if let Ok(mut store) = system_process_store.try_write().await {
                            store.insert(
                                app.ais.to_string(),
                                definitions::SupervisedProcesses::Child(child),
                            );
                        }
                        //  ! LEAVE COMMENTED
                        // state.data = format!(
                        //     "{} started, with working dir: {}",
                        //     system_app.0, config_path
                        // );
                        // state.event_counter += 1;
                        // save_state(state, state_path).await?;
                    }
                    Err(err) => {
                        log!(LogLevel::Error, "Failed to spawn: {}: {}", app.ais, err);
                        continue;
                    }
                };
            }
        }

        log!(LogLevel::Info, "Spawned all system applications");
    }

    {
        let mut info = system_information_store.write().await;
        info.system_apps_initialized = true;
    }

    // Shared list reused for build + spawn so we don't drift between passes.
    let client_applications = match generate_safe_client_runner_list().await {
        Ok(data) => data,
        Err(err) => {
            log!(
                LogLevel::Error,
                "Failed to compile safe runner list: {}",
                err.err_mesg
            );
            Vec::new()
        }
    };

    '_building_client_runners: {
        log!(LogLevel::Info, "Building client runners");

        for runner in &client_applications {
            log!(LogLevel::Info, "Building: {}!", runner);
            if let Err(err) = build_runner_binary(runner) {
                log!(
                    LogLevel::Error,
                    "Failed to build: {}:{}. Attempting fallback",
                    runner,
                    err.err_mesg
                );
                if let Err(err) = revert_to_vetted(runner) {
                    log!(
                        LogLevel::Error,
                        "Failed to fallback for {}: {}",
                        runner,
                        err.err_mesg
                    );
                }
            } else {
                log!(LogLevel::Info, "Built: {}!", runner);
            }
        }

        log!(LogLevel::Info, "Built all client runners");
    }

    '_starting_client_applications: {
        log!(LogLevel::Info, "Starting client application spawning");

        for client_app in &client_applications {
            let binary_path = PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, client_app));
            let working_dir = PathType::Content(format!("/etc/{}", client_app)); // This is the production value
            // let working_dir = PathType::Content(format!("/opt/artisan/apps/{}", client_app)); // This is the production value
            // let working_dir = PathType::Content(format!("/tmp"));

            // uhhhhhh
            if let Err(err) = chown(&binary_path, Some(33), Some(33)) {
                log!(LogLevel::Error, "Failed to chown: {}", err.to_string())
            };

            let mut command = Command::new(binary_path);
            crate::functions::configure_www_data_command(&mut command);
            match spawn_complex_process(&mut command, Some(working_dir), true, true).await {
                Ok(mut child) => {
                    let pid_result = child.get_pid().await;

                    match pid_result {
                        Ok(pid) => {
                            log!(LogLevel::Info, "Started: {}:{}", client_app, pid);

                            if let Err(err) = ebpf::register_pid(pid) {
                                log!(
                                    LogLevel::Warn,
                                    "Failed to register {} (PID {}) with eBPF tracker: {}",
                                    client_app,
                                    pid,
                                    err.err_mesg
                                );
                            }

                            if let Err(err) =
                                crate::pid_persistence::remember_process(client_app, pid).await
                            {
                                log!(
                                    LogLevel::Error,
                                    "Failed to persist PID for {}: {}",
                                    client_app,
                                    err.err_mesg
                                );
                            }
                        }
                        Err(err) => {
                            log!(
                                LogLevel::Error,
                                "Failed to resolve PID for {}: {}",
                                client_app,
                                err
                            );
                        }
                    }

                    child.monitor_stdx().await;
                    child.monitor_usage().await;
                    if let Ok(mut store) = system_process_store.try_write().await {
                        store.insert(
                            client_app.clone(),
                            definitions::SupervisedProcesses::Child(child),
                        );
                    }
                }
                Err(err) => {
                    log!(LogLevel::Error, "Failed to spawn: {}: {}", client_app, err);
                    continue;
                }
            };
        }

        log!(LogLevel::Info, "Spawned all client applications");
    }

    loop {}
    // create threads to parse the statefiles on occasion
    // watching for and storing warning / errors and catching crashes
}
