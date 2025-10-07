use std::{fs, path::Path};

use artisan_middleware::dusa_collection_utils::core::errors::Errors;

use crate::definitions::{
    AIS_RUNNER_SRC_DIR, ARTISAN_BIN_DIR, ARTISAN_LOG_DIR, ARTISAN_VETTED_DIR, BUILD_LOG_PREFIX,
    RELEASE_BRANCH, VETTED_LATEST_SUFFIX,
};

use super::{
    ScriptResult, append_line, deployment_stamp, io_error, new_error, replace_symlink,
    timestamp_string,
};

use super::build::{
    cargo_path, copy_artifact, prepare_directories, run_command, run_command_with_env,
};

pub fn build_runner_binary(runner_name: &str) -> ScriptResult<()> {
    if runner_name.is_empty() {
        return Err(new_error(
            Errors::GeneralError,
            "Runner name cannot be empty",
        ));
    }

    let src_dir = Path::new(AIS_RUNNER_SRC_DIR);
    if !src_dir.is_dir() {
        return Err(new_error(
            Errors::NotFound,
            format!(
                "Runner source directory does not exist: {}",
                src_dir.display()
            ),
        ));
    }

    prepare_directories()?;

    let log_base = format!("{BUILD_LOG_PREFIX}{runner_name}");
    let build_log = Path::new(ARTISAN_LOG_DIR).join(format!("{}.log", log_base));
    let error_log = Path::new(ARTISAN_LOG_DIR).join(format!("{}_error.log", log_base));

    append_line(
        &build_log,
        &format!(
            "[{}] Starting build for runner {}",
            timestamp_string(),
            runner_name
        ),
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
        &src_dir,
        &build_log,
        &error_log,
        &format!("Failed to reset dir {}", runner_name),
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
        src_dir,
        &build_log,
        &error_log,
        &format!("Failed to pull latest changes for runner {}", runner_name),
    )?;

    let cargo_toml_path = src_dir.join("Cargo.toml");
    append_line(
        &build_log,
        &format!(
            "[{}] Setting crate name to {}",
            timestamp_string(),
            runner_name
        ),
    )?;

    let original_toml = rewrite_crate_name(&cargo_toml_path, runner_name)?;

    let build_result = (|| -> ScriptResult<()> {
        append_line(
            &build_log,
            &format!("[{}] Starting cargo build...", timestamp_string()),
        )?;

        let target_dir = src_dir.join("target");
        run_command_with_env(
            cargo_path(),
            ["build", "--release"],
            src_dir,
            [("CARGO_TARGET_DIR", target_dir.clone())],
            &build_log,
            &error_log,
            &format!("Build failed for runner {}", runner_name),
        )?;

        let target_path = target_dir.join("release").join(runner_name);
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
                    "Runner build artifact not found at {}",
                    target_path.display()
                ),
            ));
        }

        append_line(
            &build_log,
            &format!("[{}] Build successful", timestamp_string()),
        )?;

        let bin_path = Path::new(ARTISAN_BIN_DIR).join(runner_name);
        copy_artifact(&target_path, &bin_path, &build_log)?;

        let vetted_target =
            Path::new(ARTISAN_VETTED_DIR).join(format!("{}_{}", runner_name, deployment_stamp()));
        copy_artifact(&target_path, &vetted_target, &build_log)?;

        let symlink_path =
            Path::new(ARTISAN_VETTED_DIR).join(format!("{}{}", runner_name, VETTED_LATEST_SUFFIX));
        replace_symlink(&vetted_target, &symlink_path)?;

        append_line(
            &build_log,
            &format!(
                "[{}] Deployed runner binary as {}",
                timestamp_string(),
                runner_name
            ),
        )?;

        Ok(())
    })();

    let revert_result = revert_crate_name(&cargo_toml_path, &original_toml, &build_log);

    if let Err(err) = revert_result.as_ref() {
        let _ = append_line(
            &error_log,
            &format!(
                "[{}] Failed to restore Cargo.toml: {}",
                timestamp_string(),
                err
            ),
        );
    }

    match build_result {
        Ok(_) => revert_result,
        Err(primary_err) => {
            if revert_result.is_err() {
                // Prefer logging to error log but ignore failure here as we already attempted above.
            }
            Err(primary_err)
        }
    }
}

fn rewrite_crate_name(path: &Path, new_name: &str) -> ScriptResult<String> {
    let original = fs::read_to_string(path)
        .map_err(|err| io_error(format!("Unable to read {}", path.display()), err))?;

    let mut updated_lines = Vec::new();
    let mut in_package_section = false;
    let mut replaced = false;

    for line in original.lines() {
        let trimmed = line.trim();
        if let Some(stripped) = trimmed.strip_prefix('[') {
            in_package_section = stripped.starts_with("package]");
        }

        if in_package_section && trimmed.starts_with("name") && !replaced {
            let leading_whitespace_len = line.len() - line.trim_start().len();
            let (indent, _rest) = line.split_at(leading_whitespace_len);
            updated_lines.push(format!("{indent}name = \"{new_name}\""));
            replaced = true;
        } else {
            updated_lines.push(line.to_string());
        }
    }

    if !replaced {
        return Err(new_error(
            Errors::GeneralError,
            "Unable to locate package name in Cargo.toml",
        ));
    }

    let mut updated = updated_lines.join("\n");
    if original.ends_with('\n') {
        updated.push('\n');
    }

    fs::write(path, updated)
        .map_err(|err| io_error(format!("Unable to update {}", path.display()), err))?;

    Ok(original)
}

fn revert_crate_name(path: &Path, original: &str, build_log: &Path) -> ScriptResult<()> {
    append_line(
        build_log,
        &format!(
            "[{}] Reverting Cargo.toml to original state",
            timestamp_string()
        ),
    )?;

    fs::write(path, original)
        .map_err(|err| io_error(format!("Unable to restore {}", path.display()), err))
}
