use std::path::{Path, PathBuf};
use std::io;
use crate::functions::sandbox_policy::AppPolicy;

#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    pub memory_max_bytes: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub pids_max: u64,
}

pub fn limits_from_policy(policy: &AppPolicy) -> Limits {
    todo!()
}

pub struct AppCgroup {
    pub path: PathBuf,
}

impl AppCgroup {
    pub fn create(root: &Path, app: &str) -> io::Result<Self> {
        todo!()
    }
    pub fn apply_limits(&self, limits: &Limits) -> io::Result<()> {
        todo!()
    }
    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        todo!()
    }
    pub fn stats(&self) -> io::Result<CgStats> {
        todo!()
    }
    pub fn kill(&self) -> io::Result<()> {
        todo!()
    }
    pub fn remove(&self) -> io::Result<()> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CgStats {
    pub memory_current: u64,
    pub memory_max: u64,
    pub cpu_usage_usec: u64,
    pub oom_kill_count: u64,
    pub pids_current: u64,
}

pub fn parse_cpu_stat(content: &str) -> Option<u64> {
    todo!()
}

pub fn parse_memory_events(content: &str) -> u64 {
    todo!()
}

pub fn parse_memory_max(content: &str) -> u64 {
    todo!()
}

#[cfg(test)]
#[allow(unused_imports)]
mod derived_a1_1 {
    use super::*;
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::functions::sandbox_policy::AppPolicy;

        fn create_policy(memory_max_mb: u64, cpu_max_millicores: u64, pids_max: u64) -> AppPolicy {
            AppPolicy {
                version: 1,
                sandbox: true,
                runtime: "node".to_string(),
                runtime_version: None,
                memory_max_mb,
                cpu_max_millicores,
                pids_max,
                tmp_max_mb: 256,
            }
        }

        // case a1_1 begin
        #[test]
        fn case_a1_1() {
            let policy = create_policy(512, 250, 512);
            let limits = limits_from_policy(&policy);
            assert_eq!(limits.memory_max_bytes, 536870912);
        }
        // case a1_1 end



        // case a2_2 begin
        #[test]
        fn case_a2_2() {
            let policy = create_policy(128, 8000, 0);
            let limits = limits_from_policy(&policy);
            assert_eq!(limits.memory_max_bytes, 134217728);
            assert_eq!(limits.cpu_quota, 800000);
            assert_eq!(limits.pids_max, 0);
        }
        // case a2_2 end

        // case a3_1 begin
        #[test]
        fn case_a3_1() {
            let content = "usage_usec 123456\nuser_usec 100\nsystem_usec 23\n";
            assert_eq!(parse_cpu_stat(content), Some(123456));
        }
        // case a3_1 end


        // case a4_1 begin
        #[test]
        fn case_a4_1() {
            let content = "user_usec 100\nsystem_usec 23\n";
            assert_eq!(parse_cpu_stat(content), None);
        }
        // case a4_1 end



        // case a5_1 begin
        #[test]
        fn case_a5_1() {
            let content = "low 0\nhigh 0\nmax 1\noom 2\noom_kill 3\n";
            assert_eq!(parse_memory_events(content), 3);
        }
        // case a5_1 end


        // case a6_1 begin
        #[test]
        fn case_a6_1() {
            let content = "low 0\nhigh 0\nmax 1\noom 2\n";
            assert_eq!(parse_memory_events(content), 0);
        }
        // case a6_1 end



        // case a7_1 begin
        #[test]
        fn case_a7_1() {
            let content = "max\n";
            assert_eq!(parse_memory_max(content), u64::MAX);
        }
        // case a7_1 end

        // case a8_1 begin
        #[test]
        fn case_a8_1() {
            let content = "536870912\n";
            assert_eq!(parse_memory_max(content), 536870912);
        }
        // case a8_1 end
    }
}
