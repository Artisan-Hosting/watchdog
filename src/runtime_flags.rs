use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use once_cell::sync::Lazy;

#[derive(Debug, Clone, Default)]
pub struct RuntimeFlags {
    pub no_build: bool,
    pub insecure: bool,
    pub no_kernel: bool,
    pub no_hash: bool,
    pub no_clean: bool,
    pub dummy_ebpf: bool,
    pub ledger_awol: bool,
    pub yap_level: Option<LogLevel>,
    pub client_root: bool,
    pub mock_system: bool,
    pub mock_client: bool,
    pub mock_all: bool,
    pub kill_on_drop: bool,
    pub recognized_args: Vec<String>,
    pub unknown_args: Vec<String>,
}

impl RuntimeFlags {
    pub fn startup_args_present(&self) -> bool {
        !self.recognized_args.is_empty()
    }

    pub fn skip_kernel_watchdog(&self) -> bool {
        self.insecure || self.no_kernel
    }

    pub fn skip_hash_check(&self) -> bool {
        self.insecure
    }

    pub fn suppress_hash_trip(&self) -> bool {
        self.insecure || self.no_hash
    }

    pub fn mock_system_enabled(&self) -> bool {
        self.mock_all || self.mock_system
    }

    pub fn mock_client_enabled(&self) -> bool {
        self.mock_all || self.mock_client
    }

    pub fn any_mock_enabled(&self) -> bool {
        self.mock_system_enabled() || self.mock_client_enabled()
    }

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
