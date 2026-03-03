//! Application inventory helpers for build/spawn safety checks.

use artisan_middleware::dusa_collection_utils::{
    core::{errors::ErrorArrayItem, logger::LogLevel, types::pathtype::PathType},
    log,
};
use artisan_middleware::git_actions::GitCredentials;
use get_if_addrs::{IfAddr, get_if_addrs};
use std::{fs, io, net::Ipv4Addr};

use crate::definitions::{ARTISAN_BIN_DIR, CRITICAL_APPLICATIONS, GIT_CONFIG_PATH};

/// Builds the list of client application binaries that should be built/spawned.
/// The resulting list excludes core system processes and only includes entries
/// that have a matching credential in the git configuration.
pub async fn generate_safe_client_runner_list() -> Result<Vec<String>, ErrorArrayItem> {
    let mut application_list: Vec<String> = Vec::new();

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
                            Ok(name) => application_list.push(name),
                            Err(err) => {
                                log!(
                                    LogLevel::Error,
                                    "Skipping file, has a stupid file name: {:?}",
                                    err
                                );
                            }
                        }
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

    let system_applications: Vec<String> = CRITICAL_APPLICATIONS
        .iter()
        .map(|entry| entry.ais.to_string())
        .collect();

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

/// Collects all host IPv4 addresses, excluding loopback and common
/// container-bridge interfaces (Docker/Podman/veth/cni).
pub fn get_all_ipv4() -> io::Result<Vec<Ipv4Addr>> {
    let interfaces = get_if_addrs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut ips: Vec<Ipv4Addr> = interfaces
        .into_iter()
        .filter(|iface| {
            let name = iface.name.to_lowercase();
            if name == "lo" {
                return false;
            }
            if name.starts_with("docker")
                || name.starts_with("br-")
                || name.starts_with("veth")
                || name.starts_with("cni")
                || name.starts_with("flannel.")
                || name.contains("docker")
                || name.contains("vethernet")
            {
                return false;
            }
            true
        })
        .filter_map(|iface| match iface.addr {
            IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(v4.ip),
            _ => None,
        })
        .collect();

    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}
