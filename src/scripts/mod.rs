use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use artisan_middleware::dusa_collection_utils::core::errors::{ErrorArrayItem, Errors};

pub mod build;
pub mod build_runner;
pub mod clean;
pub mod revert;

pub use build::build_application;
pub use build_runner::build_runner_binary;
pub use clean::clean_cargo_projects;
pub use revert::revert_to_vetted;

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
