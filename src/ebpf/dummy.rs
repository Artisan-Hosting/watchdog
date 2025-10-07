use artisan_middleware::{
    aggregator::NetworkUsage, dusa_collection_utils::core::errors::ErrorArrayItem,
};

pub struct BandwidthTracker;

impl BandwidthTracker {
    pub fn new() -> Self {
        Self
    }

    pub fn track_pid(&self, _pid: u32) -> Result<(), ErrorArrayItem> {
        Ok(())
    }

    pub fn get_usage(&self, _pid: u32) -> Result<Option<NetworkUsage>, ErrorArrayItem> {
        Ok(None)
    }

    pub fn cleanup_dead_pids(&self) -> Result<(), ErrorArrayItem> {
        Ok(())
    }
}
