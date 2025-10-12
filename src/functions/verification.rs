use artisan_middleware::dusa_collection_utils::{
    core::{
        errors::ErrorArrayItem,
        logger::LogLevel,
        types::pathtype::PathType,
    },
    log,
};

use crate::definitions::{self, VerificationEntry};

const VERIFICATION_MATRIX: [(&str, &str, Option<&str>); 2] = [
    (
        "ledger",
        definitions::LEDGER_PATH,
        None,
    ),
    (
        "credentials",
        definitions::GIT_CONFIG_PATH,
        None,
    ),
];

pub fn verify_path(path: PathType) -> Result<VerificationEntry, ErrorArrayItem> {
    let mut verification_entry = VerificationEntry::new();

    VERIFICATION_MATRIX.iter().for_each(|entry| {
        let argument_path_string = path.to_string();

        if entry.1 == argument_path_string {
            verification_entry.name = entry.0.to_owned();
            verification_entry.path = path.clone();
            verification_entry.expected_hash = entry.2.unwrap_or("").to_owned();

            if verification_entry.expected_hash.is_empty() {
                verification_entry.verified = path.exists();
                log!(
                    LogLevel::Warn,
                    "Skipped hash for :{}",
                    verification_entry.name
                );
            } else {
                let new_hash = "hash";
                verification_entry.calculated_hash = new_hash.to_owned();
                verification_entry.verified =
                    verification_entry.expected_hash == verification_entry.calculated_hash;
            }
        }
    });

    Ok(verification_entry)
}
