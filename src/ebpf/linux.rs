use artisan_middleware::{
    aggregator::NetworkUsage,
    dusa_collection_utils::{
        core::{
            errors::{ErrorArrayItem, Errors},
            logger::LogLevel,
        },
        log,
    },
    process_manager::is_pid_active,
};
use aya::programs::ProgramError;
use aya::{Bpf, include_bytes_aligned, maps::HashMap as BpfHashMap, programs::KProbe};
use bytemuck::Zeroable;
use std::{convert::TryInto, sync::RwLock};

#[derive(Clone, Copy, Debug, Zeroable)]
#[repr(C)]
pub struct TrafficStats {
    rx_bytes: u64,
    tx_bytes: u64,
}

unsafe impl aya::Pod for TrafficStats {}

impl TrafficStats {
    pub fn to_network_usage(&self) -> NetworkUsage {
        NetworkUsage {
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
        }
    }
}

pub struct BandwidthTracker {
    bpf: RwLock<Bpf>,
}

impl BandwidthTracker {
    pub fn new() -> Result<Self, ErrorArrayItem> {
        let bpf_data = include_bytes_aligned!(env!("EBPF_OBJECT"));
        let mut bpf = Bpf::load(bpf_data)
            .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

        let probes = [
            ("bpf_tcp_sendmsg", "tcp_sendmsg"),
            ("bpf_tcp_recvmsg", "tcp_cleanup_rbuf"),
            ("bpf_udp_sendmsg", "udp_sendmsg"),
            ("bpf_udp_recvmsg", "udp_recvmsg"),
        ];

        for (prog_name, attach_point) in probes {
            let program = bpf.program_mut(prog_name).ok_or_else(|| {
                ErrorArrayItem::new(
                    Errors::GeneralError,
                    format!("BPF program {prog_name} not found"),
                )
            })?;

            let kprobe: &mut KProbe = program.try_into().map_err(|err: ProgramError| {
                ErrorArrayItem::new(Errors::GeneralError, err.to_string())
            })?;

            kprobe.load().map_err(|err: ProgramError| {
                ErrorArrayItem::new(Errors::GeneralError, err.to_string())
            })?;

            kprobe
                .attach(attach_point, 0)
                .map_err(|err: ProgramError| {
                    ErrorArrayItem::new(Errors::GeneralError, err.to_string())
                })?;

            log!(
                LogLevel::Debug,
                "Attached probe {prog_name} to {attach_point}"
            );
        }

        Ok(Self {
            bpf: RwLock::new(bpf),
        })
    }

    pub fn track_pid(&self, pid: u32) -> Result<(), ErrorArrayItem> {
        let mut bpf = self.bpf.try_write().map_err(|err| {
            ErrorArrayItem::new(
                Errors::GeneralError,
                format!("Can't lock BPF handle: {err}"),
            )
        })?;

        let map_data = bpf.map_mut("pid_traffic_map").ok_or_else(|| {
            ErrorArrayItem::new(Errors::GeneralError, "pid_traffic_map not found")
        })?;

        let mut map: BpfHashMap<_, u32, TrafficStats> = BpfHashMap::try_from(map_data)
            .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

        if map.get(&pid, 0).is_ok() {
            return Ok(());
        }

        let initial = TrafficStats {
            rx_bytes: 0,
            tx_bytes: 0,
        };

        map.insert(pid, initial, 0)
            .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

        log!(LogLevel::Debug, "Registered eBPF tracking for PID {pid}");

        Ok(())
    }

    pub fn get_usage(&self, pid: u32) -> Result<Option<NetworkUsage>, ErrorArrayItem> {
        let bpf = self.bpf.try_read().map_err(|err| {
            ErrorArrayItem::new(
                Errors::GeneralError,
                format!("Can't lock BPF handle: {err}"),
            )
        })?;

        let map_data = bpf.map("pid_traffic_map").ok_or_else(|| {
            ErrorArrayItem::new(Errors::GeneralError, "pid_traffic_map not found")
        })?;

        let map: BpfHashMap<_, u32, TrafficStats> = BpfHashMap::try_from(map_data)
            .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

        match map.get(&pid, 0) {
            Ok(stats) => Ok(Some(stats.to_network_usage())),
            Err(_) => Ok(None),
        }
    }

    pub fn cleanup_dead_pids(&self) -> Result<(), ErrorArrayItem> {
        let mut bpf = self.bpf.try_write().map_err(|err| {
            ErrorArrayItem::new(
                Errors::GeneralError,
                format!("Can't lock BPF handle: {err}"),
            )
        })?;

        let map_data = bpf.map_mut("pid_traffic_map").ok_or_else(|| {
            ErrorArrayItem::new(Errors::GeneralError, "pid_traffic_map not found")
        })?;

        let mut map: BpfHashMap<_, u32, TrafficStats> = BpfHashMap::try_from(map_data)
            .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;

        let mut to_remove = Vec::new();
        let mut iter = map.iter();

        while let Some(Ok((pid, _))) = iter.next() {
            if !is_pid_active(pid as i32)? {
                to_remove.push(pid);
            }
        }

        for pid in to_remove {
            map.remove(&pid)
                .map_err(|err| ErrorArrayItem::new(Errors::GeneralError, err.to_string()))?;
            log!(LogLevel::Debug, "Removed defunct PID {pid} from eBPF map");
        }

        Ok(())
    }
}
