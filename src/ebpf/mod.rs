use artisan_middleware::{
    aggregator::NetworkUsage,
    dusa_collection_utils::{
        core::{errors::ErrorArrayItem, logger::LogLevel},
        log,
    },
};
use once_cell::sync::Lazy;
use std::env;
use tokio::time::{Duration, sleep};

#[cfg(ebpf_supported)]
mod linux;

mod dummy;

#[allow(clippy::large_enum_variant)]
enum Tracker {
    #[cfg(ebpf_supported)]
    Real(linux::BandwidthTracker),
    Dummy(dummy::BandwidthTracker),
}

pub struct EbpfManager {
    tracker: Tracker,
    active: bool,
}

impl EbpfManager {
    fn initialize() -> Self {
        #[cfg(ebpf_supported)]
        {
            match linux::BandwidthTracker::new() {
                Ok(inner) => {
                    log!(
                        LogLevel::Info,
                        "eBPF network tracker initialized for this platform"
                    );
                    return Self {
                        tracker: Tracker::Real(inner),
                        active: true,
                    };
                }
                Err(err) => {
                    log!(
                        LogLevel::Warn,
                        "eBPF initialization failed, falling back to dummy tracker: {}",
                        err.err_mesg
                    );
                }
            }
        }

        let target = format!("{}-{}", env::consts::OS, env::consts::ARCH);
        log!(
            LogLevel::Info,
            "eBPF network tracking disabled on this platform ({target}); returning dummy data"
        );
        Self {
            tracker: Tracker::Dummy(dummy::BandwidthTracker::new()),
            active: false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn register_pid(&self, pid: u32) -> Result<(), ErrorArrayItem> {
        match &self.tracker {
            #[cfg(ebpf_supported)]
            Tracker::Real(tracker) => tracker.track_pid(pid),
            Tracker::Dummy(tracker) => tracker.track_pid(pid),
        }
    }

    pub fn usage_for_pid(&self, pid: u32) -> Result<Option<NetworkUsage>, ErrorArrayItem> {
        match &self.tracker {
            #[cfg(ebpf_supported)]
            Tracker::Real(tracker) => tracker.get_usage(pid),
            Tracker::Dummy(tracker) => tracker.get_usage(pid),
        }
    }

    pub fn cleanup_dead_pids(&self) -> Result<(), ErrorArrayItem> {
        match &self.tracker {
            #[cfg(ebpf_supported)]
            Tracker::Real(tracker) => tracker.cleanup_dead_pids(),
            Tracker::Dummy(tracker) => tracker.cleanup_dead_pids(),
        }
    }
}

static MANAGER: Lazy<EbpfManager> = Lazy::new(EbpfManager::initialize);

pub fn manager() -> &'static EbpfManager {
    &MANAGER
}

pub fn register_pid(pid: u32) -> Result<(), ErrorArrayItem> {
    manager().register_pid(pid)
}

pub fn usage_for_pid(pid: u32) -> Result<Option<NetworkUsage>, ErrorArrayItem> {
    manager().usage_for_pid(pid)
}

pub fn cleanup_dead_pids() -> Result<(), ErrorArrayItem> {
    manager().cleanup_dead_pids()
}

pub async fn register_pid_with_retry(pid: u32) -> Result<(), ErrorArrayItem> {
    let mut delay = Duration::from_millis(50);
    const MAX_ATTEMPTS: usize = 3;

    for attempt in 1..=MAX_ATTEMPTS {
        match manager().register_pid(pid) {
            Ok(_) => return Ok(()),
            Err(err) => {
                let lower = err.err_mesg.to_lowercase();
                let should_retry = lower.contains("would block") && attempt < MAX_ATTEMPTS;
                if should_retry {
                    sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_millis(500));
                    continue;
                }
                return Err(err);
            }
        }
    }

    // The loop always returns; unreachable
    unreachable!()
}
