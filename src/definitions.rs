use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use artisan_middleware::{
    aggregator::{NetworkUsage, Status},
    dusa_collection_utils::{
        core::{
            logger::LogLevel,
            types::{pathtype::PathType, rb::RollingBuffer, rwarc::LockWithTimeout},
        },
        log,
    },
    identity::Identifier,
    process_manager::{SupervisedChild, SupervisedProcess},
    timestamp::current_timestamp,
};
use tokio::sync::RwLock;

use crate::functions::get_all_ipv4;

/// Base directory housing all Artisan applications.
pub const ARTISAN_APPS_DIR: &str = "/opt/artisan/apps";
/// Directory where built binaries are deployed.
pub const ARTISAN_BIN_DIR: &str = "/opt/artisan/bin";
/// Directory storing vetted build artifacts.
pub const ARTISAN_VETTED_DIR: &str = "/opt/artisan/vetted";
/// Default location for build and revert logs.
pub const ARTISAN_LOG_DIR: &str = "/opt/artisan/log";
/// Directory containing deployment helper scripts.
pub const ARTISAN_SCRIPT_DIR: &str = "/opt/artisan/scripts";

/// Canonical location for the cargo binary when running under the root user.
pub const CARGO_ROOT_BIN: &str = "/root/.cargo/bin/cargo";
/// Default binary name for cargo when the root-specific binary is absent.
pub const CARGO_SYSTEM_BIN: &str = "cargo";

/// Path to the ledger file expected on every host.
pub const LEDGER_PATH: &str = "/opt/artisan/ledger.json";
/// Path to the git credential file required during verification.
pub const GIT_CONFIG_PATH: &str = "/opt/artisan/git.cf";
/// Path to the main build helper script shipped with the platform.
pub const BUILD_SCRIPT_PATH: &str = "/opt/artisan/scripts/build.sh";
/// Path to the runner build helper script shipped with the platform.
pub const BUILD_RUNNER_SCRIPT_PATH: &str = "/opt/artisan/scripts/build_runner.sh";

/// Prefix applied to AIS application crates and binaries.
pub const AIS_PREFIX: &str = "ais_";
/// Name of the manager application (without prefix).
pub const APP_MANAGER: &str = "manager";
/// Name of the git monitor application (without prefix).
pub const APP_GITMON: &str = "gitmon";
/// Name of the mailer application (without prefix).
pub const APP_MAILLER: &str = "mailler";
/// Name of the welcome application (without prefix).
pub const APP_WELCOME: &str = "welcome";

/// Path to the AIS runner source tree.
pub const AIS_RUNNER_SRC_DIR: &str = "/opt/artisan/apps/ais_runner";

/// String prefix used when constructing build log file names.
pub const BUILD_LOG_PREFIX: &str = "build";

/// Git branch that watchdog pulls during automated builds.
pub const RELEASE_BRANCH: &str = "release";

/// Suffix appended to vetted binary symlinks.
pub const VETTED_LATEST_SUFFIX: &str = "_latest";

/// Maximum number of stdout/stderr entries we retain per application.
pub const APPLICATION_STD_BUFFER_SIZE: usize = 500;
/// Filesystem path to the watchdog gRPC Unix domain socket.
pub const WATCHDOG_SOCKET_PATH: &str = "/tmp/artisan_watchdog.sock";
/// Location where we persist encrypted PID ledgers for crash recovery.
pub const WATCHDOG_PID_LEDGER_PATH: &str = "/tmp/.artisan_watchdog_pids";

/// Canonical list of files that must be present for watchdog to proceed.
pub const CORE_VERIFICATION_PATHS: [&str; 2] = [LEDGER_PATH, GIT_CONFIG_PATH];

/// Returns the AIS-qualified name for the provided application identifier.
pub fn ais_name(component: &str) -> String {
    format!("{AIS_PREFIX}{component}")
}

/// AIS-qualified manager identifier.
pub const AIS_MANAGER: &str = "ais_manager";
/// AIS-qualified git monitor identifier.
pub const AIS_GITMON: &str = "ais_gitmon";
/// AIS-qualified mailer identifier.
pub const AIS_MAILLER: &str = "ais_mailler";
/// AIS-qualified welcome identifier.
pub const AIS_WELCOME: &str = "ais_welcome";

/// Canonical identifiers for a platform application.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ApplicationIdentifiers {
    pub canonical: &'static str,
    pub ais: &'static str,
}

impl ApplicationIdentifiers {
    /// Creates a new `ApplicationIdentifiers` pair.
    pub const fn new(canonical: &'static str, ais: &'static str) -> Self {
        Self { canonical, ais }
    }
}

/// Critical application definitions, including both canonical and AIS-qualified identifiers.
pub const CRITICAL_APPLICATIONS: [ApplicationIdentifiers; 2] = [
    ApplicationIdentifiers::new(APP_MANAGER, AIS_MANAGER),
    // ApplicationIdentifiers::new(APP_GITMON, AIS_GITMON),
    ApplicationIdentifiers::new(APP_MAILLER, AIS_MAILLER),
    // ApplicationIdentifiers::new(APP_WELCOME, AIS_WELCOME),
];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SimpleStatus {
    Successful,
    Failed,
}

#[derive(Debug, Clone)]
pub struct BuildStatus {
    pub name: String,
    pub status: SimpleStatus,
    pub timestamp: u64,
    pub vetted: bool, // If we found and can / will spawn the vetted version
}

impl BuildStatus {
    pub fn new(name: impl Into<String>, status: SimpleStatus, vetted: bool) -> Self {
        Self {
            name: name.into(),
            status,
            timestamp: current_timestamp(),
            vetted,
        }
    }

    pub fn success(name: impl Into<String>, vetted: bool) -> Self {
        Self::new(name, SimpleStatus::Successful, vetted)
    }

    pub fn failure(name: impl Into<String>, vetted: bool) -> Self {
        Self::new(name, SimpleStatus::Failed, vetted)
    }
}

#[derive(Debug, Clone)]
pub struct VerificationEntry {
    pub name: String,
    pub path: PathType,
    pub expected_hash: String,
    pub calculated_hash: String,
    pub verified: bool,
    pub timestamp: u64,
}

impl VerificationEntry {
    pub fn new() -> Self {
        Self {
            name: "".to_owned(),
            path: PathType::Str("".into()),
            expected_hash: "".to_owned(),
            calculated_hash: "".to_owned(),
            verified: false,
            timestamp: current_timestamp(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationStatus {
    pub status: Status,
    pub cpu_usage: f32,
    pub memory_usage: f64,
    pub pid: Option<u32>,
    pub last_updated: u64,
    pub stdout: RollingBuffer,
    pub stderr: RollingBuffer,
    pub network_usage: Option<NetworkUsage>,
}

impl ApplicationStatus {
    pub fn new(
        status: Status,
        cpu_usage: f32,
        memory_usage: f64,
        pid: Option<u32>,
        last_updated: u64,
        stdout: RollingBuffer,
        stderr: RollingBuffer,
        network_usage: Option<NetworkUsage>,
    ) -> Self {
        Self {
            status,
            cpu_usage,
            memory_usage,
            pid,
            last_updated,
            stdout,
            stderr,
            network_usage,
        }
    }
}

pub enum SupervisedProcesses {
    Child(SupervisedChild),
    Process(SupervisedProcess),
}

pub type ApplicationStatusStore = Arc<RwLock<HashMap<String, ApplicationStatus>>>;
pub type SystemApplicationStatusStore = ApplicationStatusStore;
pub type ClientApplicationStatusStore = ApplicationStatusStore;
pub type BuildStatusStore = Arc<RwLock<HashMap<String, BuildStatus>>>;
pub type VerificationStatusStore = Arc<RwLock<Vec<VerificationEntry>>>;
pub type SystemInformationStore = Arc<RwLock<ArtisanSystemInformation>>;
pub type ChildProcessArray = Arc<LockWithTimeout<HashMap<String, SupervisedProcesses>>>;

pub fn new_application_status_store() -> ApplicationStatusStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Returns a fresh store for system-critical application statuses.
pub fn new_system_application_status_store() -> SystemApplicationStatusStore {
    new_application_status_store()
}

/// Returns a fresh store for tenant/client application statuses.
pub fn new_client_application_status_store() -> ClientApplicationStatusStore {
    new_application_status_store()
}

pub fn new_build_status_store() -> BuildStatusStore {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn new_verification_status_store() -> VerificationStatusStore {
    Arc::new(RwLock::new(Vec::new()))
}

pub fn new_system_information_store() -> SystemInformationStore {
    Arc::new(RwLock::new(ArtisanSystemInformation::default()))
}

pub fn new_child_process_array() -> ChildProcessArray {
    Arc::new(LockWithTimeout::new(HashMap::new()))
}

pub fn rolling_buffer_from_entries(entries: Vec<(u64, String)>) -> RollingBuffer {
    let mut trimmed: Vec<(u64, String)> = entries
        .into_iter()
        .rev()
        .take(APPLICATION_STD_BUFFER_SIZE)
        .collect();
    trimmed.reverse();
    let capacity_headroom = APPLICATION_STD_BUFFER_SIZE.saturating_sub(trimmed.len());
    RollingBuffer::from(trimmed, capacity_headroom)
}

pub fn empty_output_buffer() -> RollingBuffer {
    RollingBuffer::new(APPLICATION_STD_BUFFER_SIZE)
}

pub enum AisCommands {
    Start(String),
    Stop(String),
    Reload(String),
    Rebuild(String), // add set command
    Status(String),
    Info,
    Set(String, SetConfigValue), // set ais_ffffff build_command "npm run build"
    Get(String, GetConfigValue),
}

pub enum SetConfigValue {
    BuildCommand(String),
    RunCommand(String),
    DependenciesCommand(String),
    LogLevel(String),
    MemoryCap(u32),
    CpuCap(u32),
    MonitorDirectory(String),
    WorkingDirectory(String),
    ChangesNeeded(u32),
    DirScanInterval(u32),
}

pub enum GetConfigValue {
    BuildCommand,
    RunCommand,
    DependenciesCommand,
    LogLevel,
    MemoryCap,
    CpuCap,
    MonitorDirectory,
    WorkingDirectory,
    ChangesNeeded,
    DirScanInterval,
}
#[derive(Debug, Clone)]
pub struct ArtisanSystemInformation {
    pub identity: Option<Identifier>,  // read from the file we verified
    pub system_apps_initialized: bool, // Only true if all services are running
    pub ip_addrs: Vec<Ipv4Addr>,       // every ip v4 on the system exept docker and localhost ips
    pub manager_linked: bool, // The manager will ping us when it starts indicating we're all the way online
}

impl ArtisanSystemInformation {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for ArtisanSystemInformation {
    fn default() -> Self {
        let ips = match get_all_ipv4() {
            Ok(data) => data,
            Err(err) => {
                log!(LogLevel::Warn, "Failed to pull ips: {}", err.to_string());
                Vec::new()
            }
        };

        Self {
            identity: Identifier::load_from_file().unwrap().into(),
            system_apps_initialized: true,
            ip_addrs: ips,
            manager_linked: false,
        }
    }
}
