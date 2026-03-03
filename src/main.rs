//! Watchdog daemon entrypoint: startup validation, build/spawn orchestration,
//! runtime monitoring loops, and gRPC service bootstrap.

use artisan_middleware::{
    aggregator::Status,
    dusa_collection_utils::{
        core::{
            errors::ErrorArrayItem,
            logger::{LogLevel, set_log_level},
            types::pathtype::PathType,
        },
        log,
    },
    process_manager::spawn_complex_process,
    timestamp::current_timestamp,
};
use std::{os::unix::fs::chown, time::Duration};
use tokio::process::Command;
#[cfg(not(unix))]
use tokio::signal::ctrl_c;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::{
    definitions::{self as defs, ARTISAN_BIN_DIR, ARTISAN_CONF_DIR, CRITICAL_APPLICATIONS},
    functions::{
        configure_www_data_command, generate_safe_client_runner_list, monitor_application_states,
        monitor_runtime_health, persist_shutdown_integrity_manifest, verify_startup_integrity,
    },
    runtime_flags::runtime_flags,
    scripts::{
        build_application, build_runner_binary, clean_cargo_projects, clean_runner_workspace,
        revert_to_vetted,
    },
};

pub mod definitions;
pub mod ebpf;
pub mod functions;
pub mod grpc;
pub mod kernel_watchdog;
pub mod ledger;
pub mod pid_persistence;
pub mod runtime_flags;
pub mod scripts;
pub mod security_trip;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), ErrorArrayItem> {
    let runtime_flags = runtime_flags();
    if let Some(level) = runtime_flags.yap_level {
        set_log_level(level);
    }

    log!(LogLevel::Debug, "Watchdog runtime starting up");
    #[cfg(debug_assertions)]
    {
        if !runtime_flags.recognized_args.is_empty() {
            log!(
                LogLevel::Warn,
                "Debug runtime flags active: {}",
                runtime_flags.recognized_args.join(", ")
            );
        }
        if !runtime_flags.unknown_args.is_empty() {
            log!(
                LogLevel::Warn,
                "Unknown debug flags ignored: {}",
                runtime_flags.unknown_args.join(", ")
            );
        }
    }

    // Initializing kernel components
    '_kernel_watchdog: {
        if runtime_flags.skip_kernel_watchdog() {
            log!(
                LogLevel::Warn,
                "Kernel watchdog registration skipped by runtime flags"
            );
        } else {
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
    }

    // Defining initial variables
    let system_application_status_store = defs::new_system_application_status_store();
    let client_application_status_store = defs::new_client_application_status_store();
    let build_status_store = defs::new_build_status_store();
    let verification_status_store = defs::new_verification_status_store();
    let system_information_store = defs::new_system_information_store();
    let system_process_store = defs::new_child_process_array();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut state_monitor_task: Option<JoinHandle<()>> = None;
    let mut runtime_monitor_task: Option<JoinHandle<()>> = None;
    let grpc_task: JoinHandle<()>;

    match security_trip::refresh_startup_trip_status(&system_information_store).await {
        Ok(_) => {}
        Err(err) => {
            log!(
                LogLevel::Warn,
                "Failed to refresh startup security trip status: {}",
                err.err_mesg
            );
        }
    }
    apply_debug_security_marker(&system_information_store).await;

    pid_persistence::initialise().await?;
    pid_persistence::reclaim_orphan_processes().await?;
    ledger::initialise().await?;

    if ebpf::manager().is_active() {
        log!(LogLevel::Info, "eBPF network tracking is active");
    } else {
        log!(
            LogLevel::Warn,
            "eBPF network tracking is inactive; network usage will be unavailable"
        );
    }

    if runtime_flags.any_mock_enabled() {
        log!(
            LogLevel::Warn,
            "Mock runtime mode enabled; monitor loops are disabled"
        );
    } else {
        {
            let system_status_store = system_application_status_store.clone();
            let client_status_store = client_application_status_store.clone();
            let process_store = system_process_store.clone();
            let shutdown = shutdown_rx.clone();
            log!(LogLevel::Debug, "Launching application state monitor task");
            state_monitor_task = Some(tokio::spawn(async move {
                log!(LogLevel::Trace, "Application state monitor loop started");
                monitor_application_states(
                    system_status_store,
                    client_status_store,
                    process_store,
                    Duration::from_secs(2),
                    shutdown,
                )
                .await;
            }));
        }

        {
            let process_store = system_process_store.clone();
            let system_status_store = system_application_status_store.clone();
            let client_status_store = client_application_status_store.clone();
            let shutdown = shutdown_rx.clone();
            log!(LogLevel::Debug, "Launching runtime monitor health task");
            runtime_monitor_task = Some(tokio::spawn(async move {
                log!(LogLevel::Trace, "Runtime monitor health loop started");
                monitor_runtime_health(
                    process_store,
                    system_status_store,
                    client_status_store,
                    Duration::from_millis(250),
                    Duration::from_millis(500),
                    shutdown,
                )
                .await;
            }));
        }
    }

    {
        let system_store = system_application_status_store.clone();
        let client_store = client_application_status_store.clone();
        let build_store = build_status_store.clone();
        let verification_store = verification_status_store.clone();
        let system_info_store = system_information_store.clone();
        let process_store = system_process_store.clone();
        let shutdown = shutdown_rx.clone();
        log!(LogLevel::Debug, "Launching gRPC server task");
        grpc_task = tokio::spawn(async move {
            log!(LogLevel::Trace, "gRPC server task initialising");
            if let Err(err) = grpc::serve_watchdog(
                system_store,
                client_store,
                build_store,
                verification_store,
                system_info_store,
                process_store,
                shutdown,
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
        if runtime_flags.skip_hash_check() {
            log!(
                LogLevel::Warn,
                "Startup integrity verification skipped by runtime flags"
            );

            let mut entry = defs::VerificationEntry::new();
            entry.name = "integrity_summary".to_string();
            entry.path = PathType::Content(defs::WATCHDOG_INTEGRITY_MANIFEST_PATH.to_string());
            entry.expected_hash = "enabled".to_string();
            entry.calculated_hash = "skipped-by-runtime-flag".to_string();
            entry.verified = true;

            let mut store = verification_status_store.write().await;
            *store = vec![entry];
        } else {
            log!(
                LogLevel::Debug,
                "Starting startup integrity verification over {} roots",
                defs::WATCHDOG_INTEGRITY_ROOTS.len()
            );

            let verification_report = verify_startup_integrity().await?;

            for entry in &verification_report.entries {
                if entry.verified {
                    log!(LogLevel::Info, "Verified: {}", entry.name);
                } else {
                    log!(LogLevel::Error, "Verification failed: {}", entry.name);
                }
            }

            {
                let mut store = verification_status_store.write().await;
                *store = verification_report.entries.clone();
            }

            if !verification_report.is_healthy() {
                for detail in verification_report.discrepancies.iter().take(20) {
                    log!(LogLevel::Error, "Integrity discrepancy: {}", detail);
                }

                if runtime_flags.suppress_hash_trip() {
                    log!(
                        LogLevel::Warn,
                        "Integrity discrepancies detected but runtime flags suppressed panic/trip"
                    );
                } else {
                    panic!(
                        "Startup integrity verification failed with {} discrepancies",
                        verification_report.discrepancies.len()
                    );
                }
            }
        }
    }

    '_building_critial_apps: {
        if runtime_flags.mock_system_enabled() {
            log!(
                LogLevel::Warn,
                "Mock system mode enabled; skipping system build stage"
            );
            let system_apps: Vec<String> = defs::CRITICAL_APPLICATIONS
                .iter()
                .filter(|app| app.canonical != "welcome")
                .map(|app| app.ais.to_string())
                .collect();
            seed_mock_statuses(
                &system_application_status_store,
                &system_apps,
                "system applications",
            )
            .await;
        } else {
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
                let no_build = runtime_flags.no_build;
                let no_clean = runtime_flags.no_clean;

                build_tasks.spawn(async move {
                    log!(
                        LogLevel::Debug,
                        "Starting build task for {} ({})",
                        canonical,
                        ais
                    );

                    if no_build {
                        log!(
                            LogLevel::Warn,
                            "Skipping build for {} due to --no-build; forcing vetted fallback",
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
                                if fallback_used {
                                    defs::BuildStatus::success(ais.clone(), true)
                                } else {
                                    defs::BuildStatus::failure(ais.clone(), false)
                                },
                            );
                        }

                        return if fallback_used { Ok(()) } else { Err(()) };
                    }

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

                            if no_clean {
                                log!(
                                    LogLevel::Warn,
                                    "Skipping cargo clean for {} due to --no-clean",
                                    ais
                                );
                            } else if let Err(err) = clean_cargo_projects(&ais).await {
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
    }

    '_spawning_system_applications: {
        if runtime_flags.mock_system_enabled() {
            log!(
                LogLevel::Warn,
                "Mock system mode enabled; skipping system spawn stage"
            );
        } else {
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
                    let working_dir = PathType::Content(format!("{}/{}", ARTISAN_CONF_DIR, ais));
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

                                    match ebpf::register_pid_with_retry(pid).await {
                                        Ok(_) => pid_persistence::clear_pid_failure(pid).await,
                                        Err(err) => {
                                            if !pid_persistence::is_pid_marked_dead(pid).await {
                                                log!(
                                                    LogLevel::Warn,
                                                    "Failed to register {} (PID {}) with eBPF tracker: {}",
                                                    ais,
                                                    pid,
                                                    err.err_mesg
                                                );
                                            }
                                            pid_persistence::record_pid_failure(pid).await;
                                        }
                                    }

                                    if let Err(err) = pid_persistence::remember_process(&ais, pid).await {
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
        if runtime_flags.mock_client_enabled() {
            log!(
                LogLevel::Warn,
                "Mock client mode enabled; skipping client build stage"
            );
            seed_mock_statuses(
                &client_application_status_store,
                &client_applications,
                "client applications",
            )
            .await;
        } else {
            log!(
                LogLevel::Debug,
                "Dispatching build tasks for {} client runners",
                client_applications.len()
            );

            let mut runner_tasks: JoinSet<()> = JoinSet::new();

            for runner in client_applications.iter().cloned() {
                let no_build = runtime_flags.no_build;
                runner_tasks.spawn(async move {
                    if no_build {
                        log!(
                            LogLevel::Warn,
                            "Skipping build for {} due to --no-build; forcing vetted fallback",
                            runner
                        );
                        if let Err(fallback_err) = revert_to_vetted(&runner).await {
                            log!(
                                LogLevel::Error,
                                "Failed to fallback for {}: {}",
                                runner,
                                fallback_err.err_mesg
                            );
                        }
                        return;
                    }

                    log!(LogLevel::Debug, "Building client runner {}", runner);
                    match build_runner_binary(&runner).await {
                        Ok(_) => {
                            log!(LogLevel::Info, "Built client runner: {}", runner);
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

            if !client_applications.is_empty() {
                match clean_runner_workspace().await {
                    Ok(_) => log!(
                        LogLevel::Debug,
                        "Cleaned shared runner workspace after builds"
                    ),
                    Err(err) => log!(
                        LogLevel::Warn,
                        "Failed to clean runner workspace: {}",
                        err.err_mesg
                    ),
                }
            }

            log!(LogLevel::Info, "Built all client runners");
        }
    }

    '_starting_client_applications: {
        if runtime_flags.mock_client_enabled() {
            log!(
                LogLevel::Warn,
                "Mock client mode enabled; skipping client spawn stage"
            );
        } else {
            log!(
                LogLevel::Debug,
                "Spawning {} client applications",
                client_applications.len()
            );

            let mut client_tasks: JoinSet<()> = JoinSet::new();

            for client_app in client_applications.iter().cloned() {
                let process_store = system_process_store.clone();
                let client_root = runtime_flags.client_root;
                client_tasks.spawn(async move {
                    log!(
                        LogLevel::Debug,
                        "Launching client application {}",
                        client_app
                    );

                    let binary_path =
                        PathType::Content(format!("{}/{}", ARTISAN_BIN_DIR, client_app));
                    let working_dir =
                        PathType::Content(format!("{}/{}", ARTISAN_CONF_DIR, client_app));

                    if !client_root {
                        if let Err(err) = chown(&binary_path, Some(33), Some(33)) {
                            log!(
                                LogLevel::Error,
                                "Failed to chown binary {}: {}",
                                client_app,
                                err
                            );
                        }
                    }

                    let mut command = Command::new(binary_path);
                    if client_root {
                        log!(
                            LogLevel::Warn,
                            "Running {} without www-data UID/GID due to --client-root",
                            client_app
                        );
                    } else {
                        configure_www_data_command(&mut command);
                    }

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

                                    match ebpf::register_pid_with_retry(pid).await {
                                        Ok(_) => pid_persistence::clear_pid_failure(pid).await,
                                        Err(err) => {
                                            if !pid_persistence::is_pid_marked_dead(pid).await {
                                                log!(
                                                    LogLevel::Warn,
                                                    "Failed to register {} (PID {}) with eBPF tracker: {}",
                                                    client_app,
                                                    pid,
                                                    err.err_mesg
                                                );
                                            }
                                            pid_persistence::record_pid_failure(pid).await;
                                        }
                                    }

                                    if let Err(err) =
                                        pid_persistence::remember_process(&client_app, pid).await
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

    if shutdown_tx.send(true).is_err() {
        log!(
            LogLevel::Trace,
            "Shutdown signal receivers were already dropped"
        );
    }

    terminate_process_monitors(&system_process_store).await;

    if let Some(handle) = state_monitor_task.take() {
        shutdown_background_task("application state monitor", handle, Duration::from_secs(2)).await;
    }
    if let Some(handle) = runtime_monitor_task.take() {
        shutdown_background_task("runtime health monitor", handle, Duration::from_secs(2)).await;
    }
    shutdown_background_task("gRPC server", grpc_task, Duration::from_secs(3)).await;

    if let Err(err) = persist_shutdown_integrity_manifest().await {
        log!(
            LogLevel::Error,
            "Failed to persist shutdown integrity manifest: {}",
            err.err_mesg
        );
    }

    log!(LogLevel::Debug, "Shutdown signal handled; exiting main");

    Ok(())
}

async fn terminate_process_monitors(process_store: &defs::ChildProcessArray) {
    let mut processes = match process_store
        .try_write_with_timeout(Some(Duration::from_secs(1)))
        .await
    {
        Ok(guard) => guard,
        Err(err) => {
            log!(
                LogLevel::Warn,
                "Unable to acquire process store for monitor shutdown: {}",
                err.err_mesg
            );
            return;
        }
    };

    for (name, process) in processes.iter_mut() {
        match process {
            defs::SupervisedProcesses::Child(child) => {
                child.terminate_stdx();
                child.terminate_monitor();
                log!(
                    LogLevel::Trace,
                    "Stopped stdx/resource monitors for {}",
                    name
                );
            }
            defs::SupervisedProcesses::Process(proc) => {
                proc.terminate_monitor();
                log!(LogLevel::Trace, "Stopped resource monitor for {}", name);
            }
        }
    }
}

async fn shutdown_background_task(name: &str, mut handle: JoinHandle<()>, timeout: Duration) {
    tokio::select! {
        result = &mut handle => {
            if let Err(err) = result {
                log!(LogLevel::Warn, "Background task {name} ended with join error: {}", err);
            } else {
                log!(LogLevel::Debug, "Background task {name} shut down cleanly");
            }
        }
        _ = tokio::time::sleep(timeout) => {
            log!(LogLevel::Warn, "Background task {name} did not stop in {:?}; aborting", timeout);
            handle.abort();
            let _ = handle.await;
        }
    }
}

#[cfg(debug_assertions)]
async fn apply_debug_security_marker(store: &defs::SystemInformationStore) {
    let mut info = store.write().await;
    info.security_tripped = true;
    info.security_trip_detected_at = current_timestamp();
    info.security_trip_summary = if runtime_flags().startup_args_present() {
        "DEV arguments passed".to_string()
    } else {
        "DEV build".to_string()
    };
}

#[cfg(not(debug_assertions))]
async fn apply_debug_security_marker(_store: &defs::SystemInformationStore) {}

async fn seed_mock_statuses(store: &defs::ApplicationStatusStore, apps: &[String], label: &str) {
    if apps.is_empty() {
        return;
    }

    let now = current_timestamp();
    let mut guard = store.write().await;
    for (index, app) in apps.iter().enumerate() {
        let cpu_usage = 0.10 + ((index % 4) as f32) * 0.07;
        let memory_usage = 6.0 + (index as f64 * 1.5);
        guard.insert(
            app.to_string(),
            defs::ApplicationStatus::new(
                Status::Unknown,
                cpu_usage,
                memory_usage,
                None,
                now,
                defs::empty_output_buffer(),
                defs::empty_output_buffer(),
                None,
            ),
        );
    }

    log!(
        LogLevel::Warn,
        "Mocked {} with {} placeholder entries",
        label,
        apps.len()
    );
}
