use std::{fs, path::Path};

use artisan_middleware::dusa_collection_utils::core::errors::Errors;

use crate::definitions::{
    ARTISAN_BIN_DIR, ARTISAN_LOG_DIR, ARTISAN_VETTED_DIR, BUILD_LOG_PREFIX, VETTED_LATEST_SUFFIX,
};

use super::build::prepare_directories;
use super::{ScriptResult, append_line, io_error, new_error, timestamp_string};

pub fn revert_to_vetted(app_name: &str) -> ScriptResult<()> {
    if app_name.is_empty() {
        return Err(new_error(
            Errors::GeneralError,
            "Application name cannot be empty",
        ));
    }

    prepare_directories()?;

    let vetted_path =
        Path::new(ARTISAN_VETTED_DIR).join(format!("{}{}", app_name, VETTED_LATEST_SUFFIX));
    let target_path = Path::new(ARTISAN_BIN_DIR).join(app_name);
    let log_path =
        Path::new(ARTISAN_LOG_DIR).join(format!("{BUILD_LOG_PREFIX}{app_name}_revert.log"));

    if !vetted_path.is_file() {
        append_line(
            &log_path,
            &format!(
                "[{}] No vetted binary available for {}",
                timestamp_string(),
                app_name
            ),
        )?;
        return Err(new_error(
            Errors::NotFound,
            format!("No vetted binary available for {}", app_name),
        ));
    }

    append_line(
        &log_path,
        &format!(
            "[{}] Reverting {} to vetted binary",
            timestamp_string(),
            app_name
        ),
    )?;

    fs::copy(&vetted_path, &target_path).map_err(|err| {
        io_error(
            format!(
                "Unable to copy {} to {}",
                vetted_path.display(),
                target_path.display()
            ),
            err,
        )
    })?;

    // ! LEAVE COMMENTED FOR NOW
    // let service_name = format!("{}.service", app_name);
    // let status = Command::new("systemctl")
    //     .arg("restart")
    //     .arg(&service_name)
    //     .status()
    //     .map_err(|err| io_error(format!("Failed to restart {}", service_name), err))?;

    // if !status.success() {
    //     return Err(new_error(
    //         Errors::GeneralError,
    //         format!(
    //             "systemctl restart {} exited with status {:?}",
    //             service_name,
    //             status.code()
    //         ),
    //     ));
    // }

    append_line(
        &log_path,
        &format!(
            "[{}] Restarted {} with vetted binary",
            timestamp_string(),
            app_name
        ),
    )?;

    Ok(())
}
