//! Kernel watchdog client helpers.
//!
//! This module contains the support code that interacts with the `awdog` kernel
//! module. Keeping it separate from `main.rs` allows the application bootstrap
//! logic to stay focused while the lower-level protocol pieces are documented
//! and easier to maintain.

use std::{
    fs::OpenOptions, hash::{DefaultHasher, Hash, Hasher}, os::fd::AsRawFd, process, thread, time::{Duration, Instant, SystemTime}
};

use artisan_middleware::{
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
        },
        log,
    },
    identity::Identifier,
};
use byteorder::{LittleEndian, WriteBytesExt};
use getrandom::getrandom;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use nix::{ioctl_none, ioctl_write_ptr, unistd};
use prost::Message;
use sha2::Sha256;

/// Character device exposed by the `awdog` kernel module.
const AWDOG_DEV: &str = "/dev/awdog";
/// Size (in bytes) of symmetric keys shared with the watchdog kernel module.
const AWDOG_KEY_LEN: usize = 32;
/// Size (in bytes) of MAC outputs for watchdog heartbeats.
const AWDOG_MAC_LEN: usize = 32;
/// Fixed UUID that uniquely identifies the watchdog client to the kernel.
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
// ioctl_write_ptr!(awdog_ioctl_unreg, AWDOG_IOC_MAGIC, AWDOG_IOCTL_UNREG_NR, u8);
ioctl_none!(awdog_ioctl_unreg, AWDOG_IOC_MAGIC, AWDOG_IOCTL_UNREG_NR);

/// Start the user-space watchdog client and spawn the heartbeat thread.
///
/// This registers the current process with the kernel module and then spins up
/// a background thread that periodically emits authenticated heartbeats. Any
/// errors encountered while registering are surfaced to the caller so they can
/// be logged by the application bootstrap code.
pub fn start_kernel_watchdog() -> Result<(), ErrorArrayItem> {
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

/// Continuously emit heartbeats to the kernel watchdog module until an error
/// occurs or the thread is shut down via process termination.
fn run_heartbeat_loop(
    file: std::fs::File,
    kc: [u8; AWDOG_KEY_LEN],
    pid: u32,
    exe_fp: u64,
    period: Duration,
) {
    let mut nonce: u64 = 1;
    let mut last_send: Option<Instant> = None;

    loop {
        let hb = build_hb(&kc, nonce, pid, exe_fp);
        let hb_bytes = unsafe {
            std::slice::from_raw_parts(
                (&hb as *const AwdogHb) as *const u8,
                std::mem::size_of::<AwdogHb>(),
            )
        };
        let send_started = Instant::now();

        match unistd::write(&file, hb_bytes) {
            Ok(wrote) if wrote as usize == hb_bytes.len() => {
                let gap_ms = last_send
                    .map(|prev| send_started.duration_since(prev).as_millis())
                    .unwrap_or(0);
                last_send = Some(send_started);
                let hb_mtn = hb.monotonic_nonce;
                let hb_ts_ns = hb.ts_ns;
                log!(
                    LogLevel::Trace,
                    "Watchdog heartbeat sent (nonce={} ts_ns={} gap_ms={})",
                    hb_mtn,
                    hb_ts_ns,
                    gap_ms,
                );
            }
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

    unsafe {
        if let Err(err) = awdog_ioctl_unreg(file.as_raw_fd()) {
            log!(
                LogLevel::Warn,
                "Watchdog unregister ioctl failed during shutdown: {}",
                err
            );
        }
    }
}

/// HKDF helper that derives the per-session key used to authenticate heartbeats.
fn hkdf_derive_kc(root_k: &[u8; AWDOG_KEY_LEN], module_uuid: &[u8; 16]) -> [u8; AWDOG_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, root_k);
    let mut okm = [0u8; AWDOG_KEY_LEN];
    let mut info = b"artisan-watchdog v1".to_vec();
    info.extend_from_slice(module_uuid);
    hk.expand(&info, &mut okm)
        .expect("hkdf expand should not fail with fixed output size");
    okm
}

/// Placeholder TPM interface that currently sources entropy from the system RNG.
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

/// Unique fingerprint for the current binary used by the kernel to detect
/// tampering. Stubbed for now until a real measurement is wired in.
#[allow(irrefutable_let_patterns)]
fn exe_fingerprint() -> u64 {
    // Just ignore this, it's a fingerprint
    
    // current library version 
    // current software version 
    // the id value of the current identifier
    let mut stupid_fp: Vec<u8> = Vec::new();

    stupid_fp.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());

    if let val = artisan_middleware::version::aml_version().encode() {
        let upper = (val >> 8) as u8;
        let lower = (val & 0xFF) as u8;
        stupid_fp.push(upper);
        stupid_fp.push(lower);
    }

    let baseline = stupid_fp.len();

    if let Ok(identity) = Identifier::load_from_file() {
        stupid_fp.extend_from_slice(&identity.id.encode_to_vec());
    }

    if stupid_fp.len() == baseline {
        log!(LogLevel::Warn, "May have failed to load identity file");
    }

    let mut hasher = DefaultHasher::new();
    stupid_fp.hash(&mut hasher);
    hasher.finish()
}

/// Current system time expressed as nanoseconds since the Unix epoch.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Compute an HMAC over the heartbeat payload using the kernel-provided key.
fn hmac_mac(kc: &[u8; AWDOG_KEY_LEN], hb_no_mac: &[u8]) -> [u8; AWDOG_MAC_LEN] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(kc).unwrap();
    mac.update(hb_no_mac);
    let out = mac.finalize().into_bytes();
    let mut mac_bytes = [0u8; AWDOG_MAC_LEN];
    mac_bytes.copy_from_slice(&out);
    mac_bytes
}

/// Construct a heartbeat message that can be sent directly to the kernel module.
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
