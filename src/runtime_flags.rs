//! Debug-only runtime flag parsing and convenience accessors.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use once_cell::sync::Lazy;

/// Debug-build runtime switches that alter startup/build/monitor behavior.
///
/// In release builds this always resolves to the default all-false state.
#[derive(Debug, Clone, Default)]
pub struct RuntimeFlags {
    /// Skip local build attempts and force vetted-binary fallback paths.
    pub no_build: bool,
    /// Skip both kernel watchdog registration and startup hash verification.
    pub insecure: bool,
    /// Skip only kernel watchdog registration.
    pub no_kernel: bool,
    /// Allow hash verification to fail without tripping runtime shutdown.
    pub no_hash: bool,
    /// Skip system-app cargo clean after successful builds.
    pub no_clean: bool,
    /// Force dummy eBPF implementation even if native eBPF is available.
    pub dummy_ebpf: bool,
    /// Disable SQLite WAL mode for ledger writes.
    pub ledger_awol: bool,
    /// Runtime log verbosity override.
    pub yap_level: Option<LogLevel>,
    /// Spawn client apps as current user instead of www-data.
    pub client_root: bool,
    /// Mock system app inventory/status and skip build/spawn.
    pub mock_system: bool,
    /// Mock client app inventory/status and skip build/spawn.
    pub mock_client: bool,
    /// Enable both mock system and mock client behavior.
    pub mock_all: bool,
    /// On orphan reclaim failure, force-kill tracked pid before dropping.
    pub kill_on_drop: bool,
    /// Recognized debug args used at process startup.
    pub recognized_args: Vec<String>,
    /// Unknown debug args observed at process startup.
    pub unknown_args: Vec<String>,
}

impl RuntimeFlags {
    /// Returns `true` if any recognized debug startup arguments were passed.
    pub fn startup_args_present(&self) -> bool {
        !self.recognized_args.is_empty()
    }

    /// Returns `true` when kernel watchdog registration should be skipped.
    pub fn skip_kernel_watchdog(&self) -> bool {
        self.insecure || self.no_kernel
    }

    /// Returns `true` when startup integrity verification should be skipped.
    pub fn skip_hash_check(&self) -> bool {
        self.insecure
    }

    /// Returns `true` when integrity mismatch should not trip runtime shutdown.
    pub fn suppress_hash_trip(&self) -> bool {
        self.insecure || self.no_hash
    }

    /// Returns `true` when system application build/spawn should be mocked.
    pub fn mock_system_enabled(&self) -> bool {
        self.mock_all || self.mock_system
    }

    /// Returns `true` when client application build/spawn should be mocked.
    pub fn mock_client_enabled(&self) -> bool {
        self.mock_all || self.mock_client
    }

    /// Returns `true` if either system or client mock mode is enabled.
    pub fn any_mock_enabled(&self) -> bool {
        self.mock_system_enabled() || self.mock_client_enabled()
    }

    /// Parses runtime args in debug builds and returns defaults in release builds.
    pub fn parse() -> Self {
        #[cfg(debug_assertions)]
        {
            Self::parse_debug_args(std::env::args().skip(1))
        }

        #[cfg(not(debug_assertions))]
        {
            Self::default()
        }
    }

    #[cfg(debug_assertions)]
    fn parse_debug_args<I>(args: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut flags = RuntimeFlags::default();
        let mut iter = args.into_iter().peekable();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--no-build" => {
                    flags.no_build = true;
                    flags.recognized_args.push(arg);
                }
                "--insecure" => {
                    flags.insecure = true;
                    flags.recognized_args.push(arg);
                }
                "--no-kernel" => {
                    flags.no_kernel = true;
                    flags.recognized_args.push(arg);
                }
                "--no-hash" => {
                    flags.no_hash = true;
                    flags.recognized_args.push(arg);
                }
                "--no-clean" => {
                    flags.no_clean = true;
                    flags.recognized_args.push(arg);
                }
                "--dummy-ebpf" => {
                    flags.dummy_ebpf = true;
                    flags.recognized_args.push(arg);
                }
                "--ledger-awol" => {
                    flags.ledger_awol = true;
                    flags.recognized_args.push(arg);
                }
                "--client-root" => {
                    flags.client_root = true;
                    flags.recognized_args.push(arg);
                }
                "--mock-system" => {
                    flags.mock_system = true;
                    flags.recognized_args.push(arg);
                }
                "--mock-client" => {
                    flags.mock_client = true;
                    flags.recognized_args.push(arg);
                }
                "--mock-all" => {
                    flags.mock_all = true;
                    flags.recognized_args.push(arg);
                }
                "--kill-on-drop" => {
                    flags.kill_on_drop = true;
                    flags.recognized_args.push(arg);
                }
                "--yap-level" => {
                    if let Some(value) = iter.next() {
                        if let Some(level) = parse_log_level(&value) {
                            flags.yap_level = Some(level);
                            flags.recognized_args.push(format!("--yap-level {}", value));
                        } else {
                            flags.unknown_args.push(format!("--yap-level {}", value));
                        }
                    } else {
                        flags.unknown_args.push("--yap-level".to_string());
                    }
                }
                _ if arg.starts_with("--yap-level=") => {
                    let (_, raw_level) = arg.split_once('=').unwrap_or(("", ""));
                    if let Some(level) = parse_log_level(raw_level) {
                        flags.yap_level = Some(level);
                        flags.recognized_args.push(arg);
                    } else {
                        flags.unknown_args.push(arg);
                    }
                }
                _ if arg.starts_with("--") => {
                    flags.unknown_args.push(arg);
                }
                _ => {}
            }
        }

        flags
    }
}

#[cfg(debug_assertions)]
fn parse_log_level(value: &str) -> Option<LogLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "error" => Some(LogLevel::Error),
        "warn" | "warning" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        "debug" => Some(LogLevel::Debug),
        "trace" => Some(LogLevel::Trace),
        _ => None,
    }
}

static RUNTIME_FLAGS: Lazy<RuntimeFlags> = Lazy::new(RuntimeFlags::parse);

pub fn runtime_flags() -> &'static RuntimeFlags {
    &RUNTIME_FLAGS
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::{RuntimeFlags, parse_log_level};

    #[test]
    fn parses_bool_switches_and_yap_level() {
        let flags = RuntimeFlags::parse_debug_args(vec![
            "--no-build".to_string(),
            "--mock-client".to_string(),
            "--yap-level=debug".to_string(),
        ]);

        assert!(flags.no_build);
        assert!(flags.mock_client);
        assert_eq!(flags.yap_level, parse_log_level("debug"));
        assert_eq!(flags.unknown_args.len(), 0);
    }

    #[test]
    fn records_unknown_yap_level_as_unknown_arg() {
        let flags = RuntimeFlags::parse_debug_args(vec!["--yap-level=silly".to_string()]);
        assert!(flags.yap_level.is_none());
        assert_eq!(flags.unknown_args, vec!["--yap-level=silly".to_string()]);
    }
}
