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
#[cfg(not(unix))]
use tokio::signal::ctrl_c;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;

use crate::{
    definitions::VerificationEntry, functions::generate_safe_client_runner_list,
    scripts::clean_cargo_projects,
};
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
pub mod kernel_watchdog;
pub mod pid_persistence;
pub mod scripts;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), ErrorArrayItem> {
    log!(LogLevel::Debug, "Watchdog runtime starting up");

    // Initializing kernel components
    '_kernel_watchdog: {
        match kernel_watchdog::start_kernel_watchdog() {
            Ok(_) => {
                log!(LogLevel::Info, "Kernel watchdog heartbeat thread started");
            }
            Err(err) => {
                log!(
                    LogLevel::Error,
                    "Failed to initialise kernel watchdog client: {}",
                    err.err_mesg
                );
            }
        }
    }

    // Defining initial variables
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
        log!(LogLevel::Debug, "Launching application state monitor task");
        tokio::spawn(async move {
            log!(LogLevel::Trace, "Application state monitor loop started");
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
        log!(LogLevel::Debug, "Launching gRPC server task");
        tokio::spawn(async move {
            log!(LogLevel::Trace, "gRPC server task initialising");
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
        log!(
            LogLevel::Debug,
            "Starting verification of {} core paths",
            defs::CORE_VERIFICATION_PATHS.len()
        );

        let mut verification_results: Vec<VerificationEntry> = Vec::new();
        let mut verification_tasks: JoinSet<(String, Result<VerificationEntry, ErrorArrayItem>)> =
            JoinSet::new();

        for path in defs::CORE_VERIFICATION_PATHS.iter() {
            let label = path.to_string();
            verification_tasks.spawn(async move {
                let path_type: PathType = PathType::Str(label.clone().into());
                log!(LogLevel::Trace, "Verifying path: {}", label);
                let outcome = verify_path(path_type);
                (label, outcome)
            });
        }

        while let Some(task) = verification_tasks.join_next().await {
            match task {
                Ok((label, Ok(entry))) => {
                    log!(LogLevel::Debug, "Verification succeeded: {}", label);
                    verification_results.push(entry);
                }
                Ok((label, Err(err))) => {
                    log!(
                        LogLevel::Error,
                        "Verification errored for {}: {}",
                        label,
                        err.err_mesg
                    );
                    ErrorArray::from(err).display(true);
                }
                Err(join_err) => {
                    log!(
                        LogLevel::Error,
                        "Verification task join failure: {}",
                        join_err
                    );
                }
            }
        }

        for entry in &verification_results {
            if entry.verified {
                log!(LogLevel::Info, "Verified: {}", entry.name);
            } else {
                log!(LogLevel::Error, "Verification failed: {}", entry.name);
            }
        }

        {
            let mut store = verification_status_store.write().await;
            *store = verification_results.clone();
        }
    }

    '_building_critial_apps: {
        log!(
            LogLevel::Debug,
            "Dispatching build tasks for {} critical applications",
            defs::CRITICAL_APPLICATIONS.len()
        );

        let mut build_tasks: JoinSet<Result<(), ()>> = JoinSet::new();

        for app in defs::CRITICAL_APPLICATIONS {
            let ais = app.ais.to_string();
            let canonical = app.canonical.to_string();
            let build_status_store = build_status_store.clone();

            build_tasks.spawn(async move {
                log!(
                    LogLevel::Debug,
                    "Starting build task for {} ({})",
                    canonical,
                    ais
                );

                match build_application(&ais).await {
                    Ok(_) => {
                        log!(LogLevel::Info, "Built critical application: {}", ais);

                        {
                            let mut statuses = build_status_store.write().await;
                            statuses.insert(
                                ais.clone(),
                                defs::BuildStatus::success(ais.clone(), false),
                            );
                        }

                        if let Err(err) = clean_cargo_projects(&ais).await {
                            log!(
                                LogLevel::Error,
                                "Failed to run cargo clean for {}: {}",
                                ais,
                                err.err_mesg
                            );
                        } else {
                            log!(LogLevel::Trace, "Completed cargo clean for {}", ais);
                        }

                        Ok(())
                    }
                    Err(err) => {
                        log!(LogLevel::Error, "Failed to build {}: {}", ais, err.err_mesg);
                        log!(
                            LogLevel::Warn,
                            "Attempting fallback to vetted binary for {}",
                            ais
                        );

                        let fallback_used = match revert_to_vetted(&ais).await {
                            Ok(_) => {
                                log!(LogLevel::Info, "Reverted to vetted binary for {}", ais);
                                true
                            }
                            Err(fallback_err) => {
                                log!(
                                    LogLevel::Error,
                                    "Fallback to vetted binary failed for {}: {}",
                                    ais,
                                    fallback_err.err_mesg
                                );
                                false
                            }
                        };

                        {
                            let mut statuses = build_status_store.write().await;
                            statuses.insert(
                                ais.clone(),
                                defs::BuildStatus::failure(ais.clone(), fallback_used),
                            );
                        }

                        Err(())
                    }
                }
            });
        }

        while let Some(joined) = build_tasks.join_next().await {
            if let Err(join_err) = joined {
                log!(
                    LogLevel::Error,
                    "Critical build task join failure: {}",
                    join_err
                );
            }
        }

        log!(
            LogLevel::Info,
            "Finished building system level applications"
        );
    }

    '_spawning_system_applications: {
        log!(
            LogLevel::Debug,
            "Spawning {} system applications",
            CRITICAL_APPLICATIONS.len()
        );

        let mut spawn_tasks: JoinSet<()> = JoinSet::new();

        for app in CRITICAL_APPLICATIONS {
            if app.canonical == "welcome" {
                continue;
            }

            let ais = app.ais.to_string();
            let canonical = app.canonical.to_string();
            let process_store = system_process_store.clone();

            spawn_tasks.spawn(async move {
                log!(
                    LogLevel::Debug,
                    "Launching system process {} ({})",
                    canonical,
                    ais
                );

                let binary_path = PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, ais));
                let working_dir = PathType::Content(format!("/etc/{}", ais));
                let mut command = Command::new(binary_path);

                match spawn_complex_process(&mut command, Some(working_dir), true, true).await {
                    Ok(mut child) => {
                        match child.get_pid().await {
                            Ok(pid) => {
                                log!(
                                    LogLevel::Info,
                                    "Started system app {} with pid {}",
                                    ais,
                                    pid
                                );

                                if let Err(err) = ebpf::register_pid(pid) {
                                    log!(
                                        LogLevel::Warn,
                                        "Failed to register {} (PID {}) with eBPF tracker: {}",
                                        ais,
                                        pid,
                                        err.err_mesg
                                    );
                                }

                                if let Err(err) =
                                    crate::pid_persistence::remember_process(&ais, pid).await
                                {
                                    log!(
                                        LogLevel::Error,
                                        "Failed to persist PID for {}: {}",
                                        ais,
                                        err.err_mesg
                                    );
                                }
                            }
                            Err(err) => {
                                log!(
                                    LogLevel::Error,
                                    "Failed to resolve PID for {}: {}",
                                    ais,
                                    err
                                );
                            }
                        }

                        child.monitor_stdx().await;
                        child.monitor_usage().await;
                        if let Ok(mut store) = process_store.try_write().await {
                            store.insert(
                                ais.clone(),
                                definitions::SupervisedProcesses::Child(child),
                            );
                        }
                    }
                    Err(err) => {
                        log!(
                            LogLevel::Error,
                            "Failed to spawn system app {}: {}",
                            ais,
                            err
                        );
                    }
                }
            });
        }

        while let Some(result) = spawn_tasks.join_next().await {
            if let Err(join_err) = result {
                log!(
                    LogLevel::Error,
                    "System spawn task join failure: {}",
                    join_err
                );
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
        log!(
            LogLevel::Debug,
            "Dispatching build tasks for {} client runners",
            client_applications.len()
        );

        let mut runner_tasks: JoinSet<()> = JoinSet::new();

        for runner in client_applications.iter().cloned() {
            runner_tasks.spawn(async move {
                log!(LogLevel::Debug, "Building client runner {}", runner);
                match build_runner_binary(&runner).await {
                    Ok(_) => {
                        log!(LogLevel::Info, "Built client runner: {}", runner);
                        if let Err(err) = clean_cargo_projects(&runner).await {
                            log!(
                                LogLevel::Error,
                                "Failed to run cargo clean for {}: {}",
                                runner,
                                err.err_mesg
                            );
                        } else {
                            log!(LogLevel::Trace, "Completed cargo clean for {}", runner);
                        }
                    }
                    Err(err) => {
                        log!(
                            LogLevel::Error,
                            "Failed to build client runner {}: {}",
                            runner,
                            err.err_mesg
                        );
                        if let Err(fallback_err) = revert_to_vetted(&runner).await {
                            log!(
                                LogLevel::Error,
                                "Failed to fallback for {}: {}",
                                runner,
                                fallback_err.err_mesg
                            );
                        }
                    }
                }
            });
        }

        while let Some(result) = runner_tasks.join_next().await {
            if let Err(join_err) = result {
                log!(
                    LogLevel::Error,
                    "Client build task join failure: {}",
                    join_err
                );
            }
        }

        log!(LogLevel::Info, "Built all client runners");
    }

    '_starting_client_applications: {
        log!(
            LogLevel::Debug,
            "Spawning {} client applications",
            client_applications.len()
        );

        let mut client_tasks: JoinSet<()> = JoinSet::new();

        for client_app in client_applications.iter().cloned() {
            let process_store = system_process_store.clone();
            client_tasks.spawn(async move {
                log!(
                    LogLevel::Debug,
                    "Launching client application {}",
                    client_app
                );

                let binary_path = PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, client_app));
                let working_dir = PathType::Content(format!("/etc/{}", client_app));

                if let Err(err) = chown(&binary_path, Some(33), Some(33)) {
                    log!(
                        LogLevel::Error,
                        "Failed to chown binary {}: {}",
                        client_app,
                        err
                    );
                }

                let mut command = Command::new(binary_path);
                crate::functions::configure_www_data_command(&mut command);

                match spawn_complex_process(&mut command, Some(working_dir), true, true).await {
                    Ok(mut child) => {
                        match child.get_pid().await {
                            Ok(pid) => {
                                log!(
                                    LogLevel::Info,
                                    "Started client app {} with pid {}",
                                    client_app,
                                    pid
                                );

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
                                    crate::pid_persistence::remember_process(&client_app, pid).await
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
                        if let Ok(mut store) = process_store.try_write().await {
                            store.insert(
                                client_app.clone(),
                                definitions::SupervisedProcesses::Child(child),
                            );
                        }
                    }
                    Err(err) => {
                        log!(
                            LogLevel::Error,
                            "Failed to spawn client app {}: {}",
                            client_app,
                            err
                        );
                    }
                }
            });
        }

        while let Some(result) = client_tasks.join_next().await {
            if let Err(join_err) = result {
                log!(
                    LogLevel::Error,
                    "Client spawn task join failure: {}",
                    join_err
                );
            }
        }

        log!(LogLevel::Info, "Spawned all client applications");
    }

    log!(
        LogLevel::Debug,
        "Main thread waiting for termination signal"
    );

    #[cfg(unix)]
    {
        let mut term = signal(SignalKind::terminate()).map_err(ErrorArrayItem::from)?;
        let mut interrupt = signal(SignalKind::interrupt()).map_err(ErrorArrayItem::from)?;

        tokio::select! {
            _ = term.recv() => {
                log!(LogLevel::Info, "Received SIGTERM; beginning shutdown");
            }
            _ = interrupt.recv() => {
                log!(LogLevel::Info, "Received SIGINT; beginning shutdown");
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c().await.map_err(ErrorArrayItem::from)?;
        log!(
            LogLevel::Info,
            "Received termination signal (ctrl-c); beginning shutdown"
        );
    }

    log!(LogLevel::Debug, "Shutdown signal handled; exiting main");

    Ok(())
}
