use anyhow::Result;
use std::{fs::OpenOptions, os::fd::AsRawFd, time::{Duration, SystemTime}};
use std::io::Write;
use std::thread;
use nix::libc;
use nix::ioctl_write_ptr;
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use byteorder::{LittleEndian, WriteBytesExt};

const AWDOG_DEV: &str = "/dev/awdog";
const AWDOG_KEY_LEN: usize = 32;
const AWDOG_MAC_LEN: usize = 32;

#[repr(C, packed)]
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

/* ioctl numbers must match the UAPI */
const AWDOG_IOC_MAGIC: u8 = 0xA7;
const AWDOG_IOCTL_REGISTER_NR: u8 = 0x01;
const AWDOG_IOCTL_UNREG_NR: u8 = 0x02;
ioctl_write_ptr!(awdog_ioctl_register, AWDOG_IOC_MAGIC, AWDOG_IOCTL_REGISTER_NR, AwdogRegister);
ioctl_write_ptr!(awdog_ioctl_unreg,    AWDOG_IOC_MAGIC, AWDOG_IOCTL_UNREG_NR,    u8);

fn hkdf_derive_kc(root_k: &[u8;32], module_uuid: &[u8;16]) -> [u8;32] {
    let hk = Hkdf::<Sha256>::new(None, root_k);
    let mut okm = [0u8; 32];
    let mut info = b"artisan-watchdog v1".to_vec();
    info.extend_from_slice(module_uuid);
    hk.expand(&info, &mut okm).expect("hkdf expand");
    okm
}

/* Placeholder: implement your TPM unseal with tss-esapi */
fn unseal_root_k_from_tpm() -> Result<[u8;32]> {
    // TODO: load sealed object, PolicyPCR(PCR7 if you chose that), Unseal
    // For now, **ONLY FOR DEV TESTING**, use a random or fixed test key:
    let mut k = [0u8;32];
    getrandom::getrandom(&mut k)?;
    Ok(k)
}

fn exe_fingerprint() -> u64 {
    // simplest: hash of /proc/self/exe inode (demo-only; replace with your method)
    // You can pass a stable 64-bit id here that's checked by kernel
    0xA1B2C3D4E5F60789u64
}

fn now_ns() -> u64 {
    let dur = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    dur.as_nanos() as u64
}

fn hmac_mac(kc: &[u8;32], hb_no_mac: &[u8]) -> [u8;32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(kc).unwrap();
    mac.update(hb_no_mac);
    let out = mac.finalize().into_bytes();
    let mut mac_bytes = [0u8;32];
    mac_bytes.copy_from_slice(&out);
    mac_bytes
}

fn build_hb(kc: &[u8;32], nonce: u64, pid: u32, exe_fp: u64) -> AwdogHb {
    let ts_ns = now_ns();

    // Serialize the AAD in little-endian to match kernel struct layout
    let mut aad = Vec::with_capacity(8+4+8+8);
    aad.write_u64::<LittleEndian>(nonce).unwrap();
    aad.write_u32::<LittleEndian>(pid).unwrap();
    aad.write_u64::<LittleEndian>(exe_fp).unwrap();
    aad.write_u64::<LittleEndian>(ts_ns).unwrap();

    let mac = hmac_mac(kc, &aad);
    AwdogHb { monotonic_nonce: nonce, pid, exe_fingerprint: exe_fp, ts_ns, mac }
}

fn main() -> Result<()> {
    // 1) TPM unseal and derive Kc (NO boot_id in derivation, as requested)
    let root_k = unseal_root_k_from_tpm()?;         // replace with real unseal
    let module_uuid: [u8;16] = *b"AWDOGMOD-UUIDv1"; // pick a fixed UUID & share with kernel docs
    let kc = hkdf_derive_kc(&root_k, &module_uuid);

    // 2) Open device
    let file = OpenOptions::new().read(true).write(true).open(AWDOG_DEV)?;
    let fd = file.as_raw_fd();

    // 3) REGISTER
    let pid = std::process::id();
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
    unsafe { awdog_ioctl_register(fd, &reg as *const _ as *const libc::c_void) }?;

    // 4) Heartbeat loop
    let mut nonce: u64 = 1;
    loop {
        let hb = build_hb(&kc, nonce, pid, exe_fp);
        let hb_bytes = unsafe {
            std::slice::from_raw_parts((&hb as *const AwdogHb) as *const u8, std::mem::size_of::<AwdogHb>())
        };
        let wrote = nix::unistd::write(fd, hb_bytes)?;
        if wrote as usize != std::mem::size_of::<AwdogHb>() {
            eprintln!("partial write: {}", wrote);
        }
        nonce = nonce.wrapping_add(1);
        thread::sleep(Duration::from_millis(reg.hb_period_ms as u64));
    }

    // (never reached)
    // unsafe { awdog_ioctl_unreg(fd, &0u8 as *const _ as *const libc::c_void) }?;
    // Ok(())
}
