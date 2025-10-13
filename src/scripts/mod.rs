use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use crate::definitions::AIS_RUNNER_SRC_DIR;
use artisan_middleware::dusa_collection_utils::{
    core::{
        errors::{ErrorArrayItem, Errors},
        logger::LogLevel,
    },
    log,
};
use tokio::task;

pub mod build;
pub mod build_runner;
pub mod clean;
pub mod revert;

pub use build::build_application as build_application_sync;
pub use build_runner::build_runner_binary as build_runner_binary_sync;
pub use clean::clean_cargo_projects as clean_cargo_projects_sync;
pub use revert::revert_to_vetted as revert_to_vetted_sync;

pub type ScriptResult<T> = Result<T, ErrorArrayItem>;

pub(crate) fn new_error(kind: Errors, message: impl Into<String>) -> ErrorArrayItem {
    ErrorArrayItem::new(kind, message)
}

pub(crate) fn io_error(context: impl Into<String>, error: io::Error) -> ErrorArrayItem {
    ErrorArrayItem::new(
        Errors::InputOutput,
        format!("{}: {}", context.into(), error),
    )
}

pub(crate) fn append_line(path: &Path, message: &str) -> ScriptResult<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| io_error("Unable to open log file", err))?;
    writeln!(file, "{}", message).map_err(|err| io_error("Unable to write to log file", err))?;
    Ok(())
}

pub(crate) fn append_block(path: &Path, content: &str) -> ScriptResult<()> {
    if content.trim().is_empty() {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| io_error("Unable to open log file", err))?;

    writeln!(file, "{}", content.trim_end_matches('\n'))
        .map_err(|err| io_error("Unable to write to log file", err))?;
    Ok(())
}

pub(crate) fn timestamp_string() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub(crate) fn deployment_stamp() -> String {
    chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()
}

async fn run_script_job<F, T>(label: &'static str, job: F) -> ScriptResult<T>
where
    F: FnOnce() -> ScriptResult<T> + Send + 'static,
    T: Send + 'static,
{
    log!(LogLevel::Debug, "Queueing script job: {label}");
    let join_result = task::spawn_blocking(move || {
        log!(LogLevel::Trace, "Starting script job: {label}");
        let result = job();
        match &result {
            Ok(_) => log!(LogLevel::Trace, "Script job completed: {label}"),
            Err(err) => log!(
                LogLevel::Debug,
                "Script job {label} failed: {}",
                err.err_mesg
            ),
        }
        result
    })
    .await
    .map_err(|err| {
        new_error(
            Errors::GeneralError,
            format!("Blocking task panicked for {label}: {err}"),
        )
    })?;

    join_result
}

pub async fn build_application(app_name: &str) -> ScriptResult<()> {
    let name = app_name.to_string();
    run_script_job("build_application", move || build::build_application(&name)).await
}

pub async fn build_runner_binary(runner_name: &str) -> ScriptResult<()> {
    let name = runner_name.to_string();
    run_script_job("build_runner_binary", move || {
        build_runner::build_runner_binary(&name)
    })
    .await
}

pub async fn clean_cargo_projects(app_name: &str) -> ScriptResult<()> {
    let name = app_name.to_string();
    run_script_job("clean_cargo_projects", move || {
        clean::clean_cargo_projects(&name)
    })
    .await
}

pub async fn revert_to_vetted(app_name: &str) -> ScriptResult<()> {
    let name = app_name.to_string();
    run_script_job("revert_to_vetted", move || revert::revert_to_vetted(&name)).await
}

pub async fn clean_runner_workspace() -> ScriptResult<()> {
    use std::path::Path;
    run_script_job("clean_runner_workspace", move || {
        clean::run_cargo_clean(Path::new(AIS_RUNNER_SRC_DIR))
    })
    .await
}

#[cfg(unix)]
pub(crate) fn replace_symlink(target: &Path, link: &Path) -> ScriptResult<()> {
    use std::os::unix::fs::symlink;

    if link.exists() || link.symlink_metadata().is_ok() {
        if let Err(err) = std::fs::remove_file(link) {
            if err.kind() != io::ErrorKind::NotFound {
                return Err(io_error(
                    format!("Unable to remove existing link at {}", link.display()),
                    err,
                ));
            }
        }
    }

    symlink(target, link).map_err(|err| {
        io_error(
            format!(
                "Unable to create symlink from {} to {}",
                link.display(),
                target.display()
            ),
            err,
        )
    })
}

#[cfg(not(unix))]
pub(crate) fn replace_symlink(_target: &Path, _link: &Path) -> ScriptResult<()> {
    Err(new_error(
        Errors::GeneralError,
        "Symlink replacement is not supported on this platform",
    ))
}
