use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use artisan_middleware::dusa_collection_utils::{
    core::{errors::Errors, logger::LogLevel},
    log,
};

use crate::definitions::ARTISAN_APPS_DIR;

use super::{ScriptResult, io_error, new_error};

pub fn clean_cargo_projects(app_name: &str) -> ScriptResult<()> {

    let app_dir = Path::new(ARTISAN_APPS_DIR).join(app_name);
    if !app_dir.is_dir() {
        return Err(new_error(
            Errors::NotFound,
            format!(
                "Application directory does not exist: {}",
                app_dir.display()
            ),
        ));
    }

    let mut manifests = Vec::new();
    collect_manifests(&app_dir, &mut manifests)?;

    for manifest in manifests {
        if let Some(dir) = manifest.parent() {
            log!(LogLevel::Info, "Running cargo clean in {}", dir.display());
            run_cargo_clean(dir)?;
        }
    }

    Ok(())
}

fn collect_manifests(dir: &Path, manifests: &mut Vec<PathBuf>) -> ScriptResult<()> {
    for entry in fs::read_dir(dir)
        .map_err(|err| io_error(format!("Unable to read directory: {}", dir.display()), err))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                log!(
                    LogLevel::Warn,
                    "Skipping unreadable directory entry in {}: {}",
                    dir.display(),
                    err
                );
                continue;
            }
        };

        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                log!(
                    LogLevel::Warn,
                    "Unable to determine file type for {}: {}",
                    path.display(),
                    err
                );
                continue;
            }
        };

        if file_type.is_dir() {
            collect_manifests(&path, manifests)?;
        } else if file_type.is_file()
            && path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name == "Cargo.toml")
        {
            manifests.push(path);
        }
    }

    Ok(())
}

// allow this so we can clean as we go, incase we have low system space.
pub fn run_cargo_clean(dir: &Path) -> ScriptResult<()> {
    let status = Command::new("cargo")
        .arg("clean")
        .current_dir(dir)
        .status()
        .map_err(|err| {
            io_error(
                format!("Failed to invoke cargo clean in {}", dir.display()),
                err,
            )
        })?;

    if !status.success() {
        return Err(new_error(
            Errors::GeneralError,
            format!(
                "cargo clean failed in {} with status {:?}",
                dir.display(),
                status.code()
            ),
        ));
    }

    Ok(())
}
