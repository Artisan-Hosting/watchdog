use std::{env, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(&["proto/watchdog.proto"], &["proto"])?;
    build_ebpf()?;
    Ok(())
}

fn build_ebpf() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rustc-check-cfg=cfg(ebpf_supported)");
    println!("cargo:rerun-if-changed=src/ebpf/network.c");
    println!("cargo:rerun-if-changed=src/ebpf/macros.h");
    println!("cargo:rerun-if-changed=src/ebpf/vmlinux.h");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_arch != "x86_64" || target_os != "linux" {
        println!(
            "cargo:warning=Skipping eBPF build for target {target_arch}-{target_os}; using dummy tracker"
        );
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let obj_path = out_dir.join("network.o");

    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-c",
            "src/ebpf/network.c",
            "-I",
            "src/ebpf",
            "-I",
            "/usr/include",        // ensure libbpf headers are visible
            "-D__TARGET_ARCH_x86", // required for CO-RE BPF
            "-o",
        ])
        .arg(&obj_path)
        .status();

    match status {
        Ok(exit_status) if exit_status.success() => {
            println!("cargo:rustc-env=EBPF_OBJECT={}", obj_path.display());
            println!("cargo:rustc-cfg=ebpf_supported");
        }
        Ok(exit_status) => {
            let code = exit_status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string());
            println!(
                "cargo:warning=Failed to build eBPF object (exit code {code}); falling back to dummy tracker"
            );
        }
        Err(err) => {
            println!(
                "cargo:warning=Failed to spawn clang for eBPF build: {err}; falling back to dummy tracker"
            );
        }
    }

    Ok(())
}
