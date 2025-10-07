use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use artisan_middleware::dusa_collection_utils::core::errors::Errors;

use crate::definitions::{
    ARTISAN_APPS_DIR, ARTISAN_BIN_DIR, ARTISAN_LOG_DIR, ARTISAN_VETTED_DIR, BUILD_LOG_PREFIX,
    CARGO_ROOT_BIN, CARGO_SYSTEM_BIN, RELEASE_BRANCH, VETTED_LATEST_SUFFIX,
};

use super::{
    ScriptResult, append_block, append_line, deployment_stamp, io_error, new_error,
    replace_symlink, timestamp_string,
};

pub fn build_application(app_name: &str) -> ScriptResult<()> {
    if app_name.is_empty() {
        return Err(new_error(
            Errors::GeneralError,
            "Application name cannot be empty",
        ));
    }

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

    prepare_directories()?;

    let log_base = format!("{BUILD_LOG_PREFIX}{app_name}");
    let build_log = Path::new(ARTISAN_LOG_DIR).join(format!("{}.log", log_base));
    let error_log = Path::new(ARTISAN_LOG_DIR).join(format!("{}_error.log", log_base));

    append_line(
        &build_log,
        &format!("[{}] Starting build for {}", timestamp_string(), app_name),
    )?;

    append_line(
        &build_log,
        &format!(
            "[{}] Resetting the repo folder incase we edited any files",
            timestamp_string()
        ),
    )?;
    run_command(
        "git",
        ["reset", "--hard"],
        &app_dir,
        &build_log,
        &error_log,
        &format!("Failed to reset dir {}", app_name),
    )?;

    append_line(
        &build_log,
        &format!(
            "[{}] Pulling latest changes from '{}' branch",
            timestamp_string(),
            RELEASE_BRANCH
        ),
    )?;
    run_command(
        "git",
        ["pull", "origin", RELEASE_BRANCH],
        &app_dir,
        &build_log,
        &error_log,
        &format!("Failed to pull latest changes for {}", app_name),
    )?;

    append_line(
        &build_log,
        &format!("[{}] Starting cargo build...", timestamp_string()),
    )?;
    let cargo_path = cargo_path();
    run_command_with_env(
        cargo_path,
        ["build", "--release"],
        &app_dir,
        [("CARGO_TARGET_DIR", app_dir.join("target"))],
        &build_log,
        &error_log,
        &format!("Build failed for {}", app_name),
    )?;

    let target_path = app_dir.join("target").join("release").join(app_name);

    if !target_path.is_file() {
        append_line(
            &error_log,
            &format!(
                "[{}] ERROR: Build failed. No binary at {}",
                timestamp_string(),
                target_path.display()
            ),
        )?;
        return Err(new_error(
            Errors::NotFound,
            format!(
                "Expected build artifact not found at {}",
                target_path.display()
            ),
        ));
    }

    append_line(
        &build_log,
        &format!("[{}] Build successful", timestamp_string()),
    )?;

    let bin_path = Path::new(ARTISAN_BIN_DIR).join(app_name);
    copy_artifact(&target_path, &bin_path, &build_log)?;

    let vetted_target =
        Path::new(ARTISAN_VETTED_DIR).join(format!("{}_{}", app_name, deployment_stamp()));
    copy_artifact(&target_path, &vetted_target, &build_log)?;

    let symlink_path =
        Path::new(ARTISAN_VETTED_DIR).join(format!("{}{}", app_name, VETTED_LATEST_SUFFIX));
    replace_symlink(&vetted_target, &symlink_path)?;

    append_line(
        &build_log,
        &format!(
            "[{}] Deployed to {} and saved to {}",
            timestamp_string(),
            Path::new(ARTISAN_BIN_DIR).display(),
            vetted_target.display()
        ),
    )?;

    Ok(())
}

pub(crate) fn prepare_directories() -> ScriptResult<()> {
    for dir in [ARTISAN_BIN_DIR, ARTISAN_VETTED_DIR, ARTISAN_LOG_DIR] {
        fs::create_dir_all(dir)
            .map_err(|err| io_error(format!("Unable to create directory {}", dir), err))?;
    }
    Ok(())
}

pub(crate) fn run_command(
    program: &str,
    args: impl IntoIterator<Item = &'static str>,
    current_dir: &Path,
    build_log: &Path,
    error_log: &Path,
    context: &str,
) -> ScriptResult<()> {
    run_command_with_env(
        program,
        args,
        current_dir,
        [],
        build_log,
        error_log,
        context,
    )
}

pub(crate) fn run_command_with_env(
    program: &str,
    args: impl IntoIterator<Item = &'static str>,
    current_dir: &Path,
    envs: impl IntoIterator<Item = (&'static str, PathBuf)>,
    build_log: &Path,
    error_log: &Path,
    context: &str,
) -> ScriptResult<()> {
    let mut command = Command::new(program);
    command.args(args);
    command.current_dir(current_dir);

    for (key, value) in envs {
        command.env(key, value);
    }

    let output = command
        .output()
        .map_err(|err| io_error(format!("{context}: unable to start {program}"), err))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    append_block(build_log, stdout.as_ref())?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    append_block(error_log, stderr.as_ref())?;

    if !output.status.success() {
        return Err(new_error(
            Errors::GeneralError,
            format!("{context}: exited with status {:?}", output.status.code()),
        ));
    }

    Ok(())
}

pub(crate) fn cargo_path() -> &'static str {
    if Path::new(CARGO_ROOT_BIN).exists() {
        CARGO_ROOT_BIN
    } else {
        CARGO_SYSTEM_BIN
    }
}

pub(crate) fn copy_artifact(
    source: &Path,
    destination: &Path,
    build_log: &Path,
) -> ScriptResult<()> {
    fs::copy(source, destination).map_err(|err| {
        io_error(
            format!(
                "Unable to copy {} to {}",
                source.display(),
                destination.display()
            ),
            err,
        )
    })?;

    append_line(
        build_log,
        &format!(
            "[{}] Copied {} to {}",
            timestamp_string(),
            source.display(),
            destination.display()
        ),
    )?;

    Ok(())
}
