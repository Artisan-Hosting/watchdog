## 🧭 Original idea recap

The plan was:

1. **Use the TPM (v2.0) as the root of trust** for the watchdog’s shared secret.
2. Derive a session-specific symmetric key (`K`) from TPM-resident data rather than storing it in the filesystem.
3. Use that derived key only in memory to authenticate heartbeats (the `HMAC-SHA256` over the nonce/metadata).
4. Optionally tie the key derivation to one or more **PCR values** so the kernel module only accepts heartbeats if the platform booted in a known-good state.

---

## 🧩 Step-by-step integration plan

### 1. Pick the PCRs

PCRs are extend-only registers that represent boot state.

| PCR   | Meaning (typical)                       | Why use                         |
| ----- | --------------------------------------- | ------------------------------- |
| 0–2   | Firmware & bootloader                   | Detect firmware tamper          |
| 4     | Boot manager                            | Detect GRUB/systemd-boot change |
| **7** | Secure Boot & kernel image measurements | Detect kernel replacement       |

→ We can start with **PCR 7** (as you already suggested).
If PCR 7 changes, it means Secure Boot hash chain broke.

---

### 2. Define a fixed TPM key object

Create a persistent TPM key once, sealed under TPM SRK (storage root key):

```bash
tpm2_createprimary -C o -g sha256 -G ecc -c primary.ctx
tpm2_create -C primary.ctx -G aes128 -u aes.pub -r aes.priv -c aes.ctx
tpm2_evictcontrol -C o -c aes.ctx 0x81000010
```

Now you have persistent handle `0x81000010` that lives across reboots.

---

### 3. In userspace: derive the runtime key

Rust pseudocode using `tss-esapi` crate:

```rust
use tss_esapi::{Context, TctiNameConf, structures::{Digest, PcrSelectionListBuilder}};
use sha2::{Sha256, Digest as _};

fn derive_watchdog_key() -> anyhow::Result<[u8; 32]> {
    // connect to /dev/tpmrm0
    let mut ctx = Context::new(TctiNameConf::from_environment_variable().unwrap())?;
    
    // read PCR 7
    let pcr_sel = PcrSelectionListBuilder::new()
        .with_sha256_selection(&[7])
        .build();
    let (update_counter, pcrs) = ctx.pcr_read(pcr_sel)?;
    let pcr_digest = pcrs.pcr_bank(sha2::Sha256::new().algorithm()).unwrap()[0].value();
    
    // unseal or derive
    let mut hasher = Sha256::new();
    hasher.update(pcr_digest);
    hasher.update(b"AWDOGMOD-UUIDv10");
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}
```

This yields a reproducible 256-bit key tied to the current PCR 7 value.

> 💡 If Secure Boot or kernel changes, PCR 7 changes → derived key changes → watchdog fails to authenticate → saver triggers reboot.

---

### 4. Feed that key into your register ioctl

Replace your existing random key generator with the TPM-derived one:

```rust
let key = derive_watchdog_key()?;
let reg = AwdogRegister {
    key,
    key_len: key.len() as u32,
    hb_period_ms: 1000,
    hb_timeout_ms: 5000,
    ..
};
unsafe { awdog_ioctl_register(fd, &reg)?; }
```

---

### 5. Kernel side

You *don’t* need TPM access in the kernel for this design — the kernel watchdog module just verifies the HMAC with whatever key was passed during REGISTER.

If you later want to enforce TPM attestation directly in-kernel:

* Use the **tpm_chip** interface (`tpm2_get_pcr_digest()` or `tpm_pcr_read()`) to read PCR 7 and compute the same derivation.
* Compare that to a userspace-provided digest.

But keeping TPM access in userspace is simpler and safer at this stage.

---

### 6. Optional hard-binding (future)

Once everything works, you can:

* Seal the AES key inside the TPM so it’s only unsealed if PCR 7 matches expected hash.
* Add a small daemon or kernel helper that performs the unseal during boot before starting your userland watchdog.

---

## ✅ TL;DR Implementation path

1. Read PCR 7 via `tss-esapi` in Rust.
2. Derive 32-byte key = `SHA256(PCR7 || "AWDOGMOD-UUIDv10")`.
3. Pass that key in your REGISTER ioctl.
4. Kernel uses it for HMAC verify — no TPM logic needed there.
5. Optional: later move unseal step into early boot or kernel.
# Incremental implementation (current work)

1. **Provision NV index**: reserve NV index `0x0150_0020` under the owner hierarchy with owner read/write bits set, 32-byte data area, empty auth, and pre-load it with the watchdog root key (`root_k`).
2. **Runtime access pattern**: watchdog connects via `/dev/tpmrm0`, starts a null-auth session (handled by `execute_with_nullauth_session`), sets the NV handle auth to empty, then reads the 32-byte blob using owner authorization (`NvAuth::Owner`).
3. **Integration checkpoints**: surface descriptive errors when the NV index is missing or short; document provisioning commands so deployment can bake the blob during manufacturing.
4. **Future tightenings**: once PCR policy is finalised, hang the same NV slot off a policy session, or migrate back to the sealed-object approach that binds to PCR 7.
