use std::path::{Path, PathBuf};
use std::fs;
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
    Limits {
        memory_max_bytes: policy.memory_max_mb * 1048576,
        cpu_quota: policy.cpu_max_millicores * 100,
        cpu_period: 100000,
        pids_max: policy.pids_max,
    }
}

pub struct AppCgroup {
    pub path: PathBuf,
}

impl AppCgroup {
    pub fn create(root: &Path, app: &str) -> io::Result<Self> {
        let path = root.join("apps").join(app);
        match fs::create_dir_all(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {}", path.display(), e))),
        }
        Ok(AppCgroup { path })
    }

    fn write_file(&self, name: &str, contents: &str) -> io::Result<()> {
        let p = self.path.join(name);
        fs::write(&p, contents).map_err(|e| io::Error::new(e.kind(), format!("{}: {}", p.display(), e)))
    }

    pub fn apply_limits(&self, limits: &Limits) -> io::Result<()> {
        self.write_file("memory.max", &limits.memory_max_bytes.to_string())?;
        match self.write_file("memory.swap.max", "0") {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.write_file("cpu.max", &format!("{} {}", limits.cpu_quota, limits.cpu_period))?;
        self.write_file("pids.max", &limits.pids_max.to_string())?;
        Ok(())
    }

    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        self.write_file("cgroup.procs", &pid.to_string())
    }

    fn read_file(&self, name: &str) -> io::Result<String> {
        let p = self.path.join(name);
        fs::read_to_string(&p).map_err(|e| io::Error::new(e.kind(), format!("{}: {}", p.display(), e)))
    }

    pub fn stats(&self) -> io::Result<CgStats> {
        let memory_current = self.read_file("memory.current")?.trim().parse::<u64>().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {}", self.path.display(), e)))?;
        let memory_max = parse_memory_max(&self.read_file("memory.max")?);
        let cpu_usage_usec = self.read_file("cpu.stat").ok().and_then(|c| parse_cpu_stat(&c)).unwrap_or(0);
        let oom_kill_count = self.read_file("memory.events").ok().map(|c| parse_memory_events(&c)).unwrap_or(0);
        let pids_current = self.read_file("pids.current")?.trim().parse::<u64>().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {}", self.path.display(), e)))?;
        Ok(CgStats { memory_current, memory_max, cpu_usage_usec, oom_kill_count, pids_current })
    }

    pub fn kill(&self) -> io::Result<()> {
        if self.write_file("cgroup.kill", "1").is_ok() {
            return Ok(());
        }
        for _ in 0..20 {
            let procs = match fs::read_to_string(self.path.join("cgroup.procs")) {
                Ok(s) => s,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {}", self.path.display(), e))),
            };
            let pids: Vec<u32> = procs.lines().filter_map(|l| l.trim().parse().ok()).collect();
            if pids.is_empty() {
                return Ok(());
            }
            for pid in pids {
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix::sys::signal::Signal::SIGKILL).ok();
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }

    pub fn remove(&self) -> io::Result<()> {
        let mut last_err = None;
        for _ in 0..20 {
            match fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => last_err = Some(io::Error::new(e.kind(), format!("{}: {}", self.path.display(), e))),
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

pub fn parse_cpu_stat(content: &str) -> Option<u64> {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("usage_usec") {
            return parts.next().and_then(|v| v.parse::<u64>().ok());
        }
    }
    None
}

pub fn parse_memory_events(content: &str) -> u64 {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("oom_kill") {
            return parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        }
    }
    0
}

pub fn parse_memory_max(content: &str) -> u64 {
    let trimmed = content.trim();
    if trimmed == "max" {
        return u64::MAX;
    }
    trimmed.parse::<u64>().unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct CgStats {
    pub memory_current: u64,
    pub memory_max: u64,
    pub cpu_usage_usec: u64,
    pub oom_kill_count: u64,
    pub pids_current: u64,
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
