use artisan_middleware::{
    dusa_collection_utils::{
        core::{
            errors::{ErrorArray, ErrorArrayItem, Errors},
            logger::LogLevel,
            types::pathtype::PathType,
        },
        log,
    },
    process_manager::spawn_complex_process,
};
use byteorder::{LittleEndian, WriteBytesExt};
use getrandom::getrandom;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use nix::ioctl_write_ptr;
use nix::unistd;
use sha2::Sha256;
use std::{
    fs::OpenOptions,
    os::{fd::AsRawFd, unix::fs::chown},
    process, thread,
    time::{Duration, SystemTime},
};
use tokio::process::Command;

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
pub mod pid_persistence;
pub mod scripts;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), ErrorArrayItem> {
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

    '_kernel_watchdog: {
        match start_kernel_watchdog() {
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

                    if let Err(err) = clean_cargo_projects(ais_name) {
                        log!(
                            LogLevel::Error,
                            "Failed to run cargo clean {}. {}",
                            ais_name,
                            err.err_mesg
                        );
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
                if let Err(err) = clean_cargo_projects(&runner) {
                    log!(
                        LogLevel::Error,
                        "Failed to run cargo clean {}. {}",
                        runner,
                        err.err_mesg
                    );
                }
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
}

// ----- kernel watchdog client -----

const AWDOG_DEV: &str = "/dev/awdog";
const AWDOG_KEY_LEN: usize = 32;
const AWDOG_MAC_LEN: usize = 32;
const AWDOG_MODULE_UUID: [u8; 16] = *b"AWDOGMOD-UUIDv10";

#[repr(C)]
#[derive(Clone, Copy)]
struct AwdogRegister {
    pid: u32,
    exe_fingerprint: u64,
    key_len: u32,
    key: [u8; AWDOG_KEY_LEN],
    hb_period_ms: u32,
    hb_timeout_ms: u32,
    session_id: u64,
    proto_ver: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct AwdogHb {
    monotonic_nonce: u64,
    pid: u32,
    exe_fingerprint: u64,
    ts_ns: u64,
    mac: [u8; AWDOG_MAC_LEN],
}

const AWDOG_IOC_MAGIC: u8 = 0xA7;
const AWDOG_IOCTL_REGISTER_NR: u8 = 0x01;
const AWDOG_IOCTL_UNREG_NR: u8 = 0x02;
ioctl_write_ptr!(
    awdog_ioctl_register,
    AWDOG_IOC_MAGIC,
    AWDOG_IOCTL_REGISTER_NR,
    AwdogRegister
);
ioctl_write_ptr!(awdog_ioctl_unreg, AWDOG_IOC_MAGIC, AWDOG_IOCTL_UNREG_NR, u8);

fn start_kernel_watchdog() -> Result<(), ErrorArrayItem> {
    let root_k = unseal_root_k_from_tpm()?;
    let kc = hkdf_derive_kc(&root_k, &AWDOG_MODULE_UUID);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(AWDOG_DEV)
        .map_err(ErrorArrayItem::from)?;
    let fd = file.as_raw_fd();

    println!(
        "REGISTER ioctl number: 0x{:x}",
        nix::request_code_write!(
            AWDOG_IOC_MAGIC,
            AWDOG_IOCTL_REGISTER_NR,
            std::mem::size_of::<AwdogRegister>()
        )
    );

    let pid = process::id();
    let exe_fp = exe_fingerprint();
    let reg = AwdogRegister {
        pid,
        exe_fingerprint: exe_fp,
        key_len: AWDOG_KEY_LEN as u32,
        key: kc,
        hb_period_ms: 2000,
        hb_timeout_ms: 6000,
        session_id: 1,
        proto_ver: 1,
    };

    unsafe {
        awdog_ioctl_register(fd, &reg).map_err(|err| {
            ErrorArrayItem::new(
                Errors::GeneralError,
                format!("Watchdog register ioctl failed: {err}"),
            )
        })?;
    }

    let hb_period = Duration::from_millis(reg.hb_period_ms as u64);
    let hb_key = reg.key;

    thread::Builder::new()
        .name("awdog-heartbeat".into())
        .spawn(move || run_heartbeat_loop(file, hb_key, pid, exe_fp, hb_period))
        .map_err(ErrorArrayItem::from)?;

    Ok(())
}

fn run_heartbeat_loop(
    file: std::fs::File,
    kc: [u8; AWDOG_KEY_LEN],
    pid: u32,
    exe_fp: u64,
    period: Duration,
) {
    let mut nonce: u64 = 1;

    loop {
        let hb = build_hb(&kc, nonce, pid, exe_fp);
        let hb_bytes = unsafe {
            std::slice::from_raw_parts(
                (&hb as *const AwdogHb) as *const u8,
                std::mem::size_of::<AwdogHb>(),
            )
        };

        match unistd::write(&file, hb_bytes) {
            Ok(wrote) if wrote as usize == hb_bytes.len() => {}
            Ok(wrote) => {
                log!(
                    LogLevel::Warn,
                    "Partial watchdog heartbeat write ({} of {} bytes)",
                    wrote,
                    hb_bytes.len()
                );
            }
            Err(err) => {
                log!(LogLevel::Error, "Watchdog heartbeat write failed: {}", err);
                break;
            }
        }

        nonce = nonce.wrapping_add(1);
        thread::sleep(period);
    }

    let unreg_arg: u8 = 0;
    unsafe {
        if let Err(err) = awdog_ioctl_unreg(file.as_raw_fd(), &unreg_arg) {
            log!(
                LogLevel::Warn,
                "Watchdog unregister ioctl failed during shutdown: {}",
                err
            );
        }
    }
}

fn hkdf_derive_kc(root_k: &[u8; AWDOG_KEY_LEN], module_uuid: &[u8; 16]) -> [u8; AWDOG_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, root_k);
    let mut okm = [0u8; AWDOG_KEY_LEN];
    let mut info = b"artisan-watchdog v1".to_vec();
    info.extend_from_slice(module_uuid);
    hk.expand(&info, &mut okm)
        .expect("hkdf expand should not fail with fixed output size");
    okm
}

fn unseal_root_k_from_tpm() -> Result<[u8; AWDOG_KEY_LEN], ErrorArrayItem> {
    let mut k = [0u8; AWDOG_KEY_LEN];
    getrandom(&mut k).map_err(|err| {
        ErrorArrayItem::new(
            Errors::GeneralError,
            format!("Failed to read entropy for watchdog key: {err}"),
        )
    })?;
    Ok(k)
}

fn exe_fingerprint() -> u64 {
    0xA1B2C3D4E5F60789u64
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn hmac_mac(kc: &[u8; AWDOG_KEY_LEN], hb_no_mac: &[u8]) -> [u8; AWDOG_MAC_LEN] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(kc).unwrap();
    mac.update(hb_no_mac);
    let out = mac.finalize().into_bytes();
    let mut mac_bytes = [0u8; AWDOG_MAC_LEN];
    mac_bytes.copy_from_slice(&out);
    mac_bytes
}

fn build_hb(kc: &[u8; AWDOG_KEY_LEN], nonce: u64, pid: u32, exe_fp: u64) -> AwdogHb {
    let ts_ns = now_ns();
    let mut aad = Vec::with_capacity(8 + 4 + 8 + 8);
    aad.write_u64::<LittleEndian>(nonce).unwrap();
    aad.write_u32::<LittleEndian>(pid).unwrap();
    aad.write_u64::<LittleEndian>(exe_fp).unwrap();
    aad.write_u64::<LittleEndian>(ts_ns).unwrap();

    let mac = hmac_mac(kc, &aad);

    AwdogHb {
        monotonic_nonce: nonce,
        pid,
        exe_fingerprint: exe_fp,
        ts_ns,
        mac,
    }
}
