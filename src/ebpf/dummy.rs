//! Dummy network tracker used when eBPF is unavailable or disabled.

use artisan_middleware::{
    aggregator::NetworkUsage, dusa_collection_utils::core::errors::ErrorArrayItem,
};

/// No-op tracker that always reports empty network usage.
pub struct BandwidthTracker;

impl BandwidthTracker {
    /// Creates a no-op tracker.
    pub fn new() -> Self {
        Self
    }

    /// Accepts PID registration but does not persist anything.
    pub fn track_pid(&self, _pid: u32) -> Result<(), ErrorArrayItem> {
        Ok(())
    }

    /// Always returns `None` to indicate no network data is available.
    pub fn get_usage(&self, _pid: u32) -> Result<Option<NetworkUsage>, ErrorArrayItem> {
        Ok(None)
    }

    /// No-op cleanup for the dummy tracker.
    pub fn cleanup_dead_pids(&self) -> Result<(), ErrorArrayItem> {
        Ok(())
    }
}
