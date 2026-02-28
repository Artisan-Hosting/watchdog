use std::{env, fs, path::{Path, PathBuf}, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(&["proto/watchdog.proto"], &["proto"])?;
    configure_version_env_vars()?;
    build_ebpf()?;
    Ok(())
}

fn configure_version_env_vars() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let lock_path = manifest_dir.join("Cargo.lock");
    let toml_path = manifest_dir.join("Cargo.toml");

    if let Ok(lock_content) = fs::read_to_string(&lock_path) {
        if let Some(version) = extract_lockfile_package_version(&lock_content, "artisan_middleware")
        {
            println!("cargo:rustc-env=ARTISAN_MIDDLEWARE_VERSION={version}");
            return Ok(());
        }
    }

    if let Ok(toml_content) = fs::read_to_string(&toml_path) {
        if let Some(version) = extract_toml_dependency_version(&toml_content, "artisan_middleware")
        {
            println!("cargo:rustc-env=ARTISAN_MIDDLEWARE_VERSION={version}");
            return Ok(());
        }
    }

    println!("cargo:warning=Unable to resolve artisan_middleware version; using unknown");
    println!("cargo:rustc-env=ARTISAN_MIDDLEWARE_VERSION=unknown");
    Ok(())
}

fn extract_lockfile_package_version(content: &str, package_name: &str) -> Option<String> {
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if current_name.as_deref() == Some(package_name) {
                return current_version;
            }
            current_name = None;
            current_version = None;
            in_package = true;
            continue;
        }

        if !in_package || trimmed.is_empty() {
            continue;
        }

        if let Some(value) = parse_toml_assignment(trimmed, "name") {
            current_name = Some(value.to_string());
            continue;
        }
        if let Some(value) = parse_toml_assignment(trimmed, "version") {
            current_version = Some(value.to_string());
        }
    }

    if current_name.as_deref() == Some(package_name) {
        return current_version;
    }
    None
}

fn extract_toml_dependency_version(content: &str, dependency_name: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(dependency_name) {
            continue;
        }
        let (name, rhs) = trimmed.split_once('=')?;
        if name.trim() != dependency_name {
            continue;
        }
        let rhs = rhs.trim();
        if rhs.starts_with('"') {
            return parse_quoted(rhs).map(ToString::to_string);
        }
        if rhs.starts_with('{') {
            if let Some(version_field_index) = rhs.find("version") {
                let version_segment = &rhs[version_field_index..];
                if let Some((_, value)) = version_segment.split_once('=') {
                    return parse_quoted(value.trim()).map(ToString::to_string);
                }
            }
        }
    }
    None
}

fn parse_toml_assignment<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (lhs, rhs) = line.split_once('=')?;
    if lhs.trim() != key {
        return None;
    }
    parse_quoted(rhs.trim())
}

fn parse_quoted(input: &str) -> Option<&str> {
    let trimmed = input.trim();
    let rest = trimmed.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
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

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let header_path = manifest_dir.join("src/ebpf/vmlinux.h");
    if let Err(err) = refresh_vmlinux_header(&header_path) {
        println!(
            "cargo:warning=Unable to refresh vmlinux.h from host BTF data: {err}; using existing header"
        );
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

fn refresh_vmlinux_header(header_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "bpftool exited with status {}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_string())
        )
        .into());
    }

    fs::write(header_path, output.stdout)?;
    Ok(())
}
