use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppPolicy {
    pub version: u32,
    pub sandbox: bool,
    pub runtime: String,
    pub runtime_version: Option<String>,
    pub memory_max_mb: u64,
    pub cpu_max_millicores: u64,
    pub pids_max: u64,
    pub tmp_max_mb: u64,
}

const RUNTIMES: [&str; 7] = ["node", "static", "python", "go", "rust", "ruby", "custom"];

/// `^ais_[0-9a-f]{8}$` — nothing else. Rejects path traversal and bare paths too.
fn valid_app(app: &str) -> bool {
    app.len() == 12 && app.starts_with("ais_") && app[4..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn parse_policy(s: &str) -> Result<AppPolicy, String> {
    let policy: AppPolicy = toml::from_str(s).map_err(|e| e.to_string())?;
    if policy.version != 1 {
        return Err(format!("version must be 1, got {}", policy.version));
    }
    if !(128..=16384).contains(&policy.memory_max_mb) {
        return Err(format!(
            "memory_max_mb must be in 128..=16384, got {}",
            policy.memory_max_mb
        ));
    }
    if !(50..=8000).contains(&policy.cpu_max_millicores) {
        return Err(format!(
            "cpu_max_millicores must be in 50..=8000, got {}",
            policy.cpu_max_millicores
        ));
    }
    if !(64..=4096).contains(&policy.pids_max) {
        return Err(format!(
            "pids_max must be in 64..=4096, got {}",
            policy.pids_max
        ));
    }
    if !(16..=2048).contains(&policy.tmp_max_mb) {
        return Err(format!(
            "tmp_max_mb must be in 16..=2048, got {}",
            policy.tmp_max_mb
        ));
    }
    if !RUNTIMES.contains(&policy.runtime.as_str()) {
        return Err(format!("unknown runtime: {}", policy.runtime));
    }
    Ok(policy)
}

pub fn policy_dir() -> PathBuf {
    std::env::var_os("AIS_POLICY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(crate::definitions::ARTISAN_CONF_DIR).join("policy"))
}

fn policy_file(app: &str) -> Result<PathBuf, String> {
    if !valid_app(app) {
        return Err(format!("invalid app name: {app}"));
    }
    Ok(policy_dir().join(format!("{app}.toml")))
}

pub fn read_policy(app: &str) -> Result<Option<AppPolicy>, String> {
    let path = policy_file(app)?;
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    parse_policy(&text).map(Some)
}

pub fn write_policy(app: &str, toml: &str) -> Result<(), String> {
    let policy = parse_policy(toml)?;
    let path = policy_file(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        // Enforce 0700 on the directory we just created.
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, toml).map_err(|e| e.to_string())?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    // Re-assert mode in case the filesystem did not preserve it across rename.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    Ok(())
}

static UID_ALLOCATION: Mutex<()> = Mutex::new(());

const UID_START: u32 = 2_000_000;
const UID_END: u32 = 2_099_999;

pub fn ensure_uid(app: &str) -> io::Result<u32> {
    ensure_uid_in_range(app, UID_START, UID_END)
}

fn uid_file(app: &str) -> Result<PathBuf, String> {
    if !valid_app(app) {
        return Err(format!("invalid app name: {app}"));
    }
    Ok(policy_dir().join(format!("{app}.uid")))
}

/// The uids recorded in every `*.uid` file. A missing dir means nothing is allocated yet.
fn uids_in_use(dir: &Path) -> io::Result<Vec<u32>> {
    let mut used = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(used),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".uid") {
            continue;
        }
        let text = fs::read_to_string(entry.path())?;
        if let Ok(uid) = text.trim().parse::<u32>() {
            used.push(uid);
        }
    }
    Ok(used)
}

pub fn ensure_uid_in_range(app: &str, lo: u32, hi_inclusive: u32) -> io::Result<u32> {
    if !valid_app(app) {
        return Err(io::Error::other("invalid app name"));
    }
    let _one_at_a_time = UID_ALLOCATION.lock().unwrap_or_else(|e| e.into_inner());

    let dir = policy_dir();
    let path = uid_file(app).map_err(|e| io::Error::other(e))?;

    if let Some(existing) = fs::read_to_string(&path).ok().and_then(|t| t.trim().parse::<u32>().ok()) {
        if (lo..=hi_inclusive).contains(&existing) {
            return Ok(existing);
        }
    }

    let used = uids_in_use(&dir)?;
    let chosen = (lo..=hi_inclusive).find(|u| !used.contains(u)).ok_or_else(|| {
        io::Error::other("no free uid left in the sandbox range")
    })?;

    fs::create_dir_all(&dir)?;

    // Written whole, then moved into place, so a crash never leaves half a number.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, format!("{chosen}\n"))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &path)?;
    Ok(chosen)
}

#[cfg(test)]
#[allow(unused_imports)]
mod derived_tc_sbx_001_a1_01 {
    use super::*;
    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // case TC_SBX_001_A1_01 begin
    #[test]
    fn case_TC_SBX_001_A1_01() {
        let input = "version = 1\nsandbox = true\nruntime = \"node\"\nruntime_version = \"22\"\nmemory_max_mb = 512\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n";
        let expected = AppPolicy {
            version: 1,
            sandbox: true,
            runtime: "node".to_string(),
            runtime_version: Some("22".to_string()),
            memory_max_mb: 512,
            cpu_max_millicores: 250,
            pids_max: 512,
            tmp_max_mb: 256,
        };
        assert_eq!(parse_policy(input), Ok(expected));
    }
    // case TC_SBX_001_A1_01 end


    // case TC_SBX_001_A2_01 begin
    #[test]
    fn case_TC_SBX_001_A2_01() {
        let input = "version = 1\nsandbox = true\nruntime = \"node\"\nmemory_max_mb = 512\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\nnetwork = true\n";
        let res = parse_policy(input);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("network"));
    }
    // case TC_SBX_001_A2_01 end



    // case TC_SBX_001_A3_03 begin
    #[test]
    fn case_TC_SBX_001_A3_03() {
        let input = "version = 2\nsandbox = true\nruntime = \"node\"\nmemory_max_mb = 512\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n";
        assert!(parse_policy(input).is_err());
    }
    // case TC_SBX_001_A3_03 end

    // case TC_SBX_001_A4_01 begin
    #[test]
    fn case_TC_SBX_001_A4_01() {
        let make = |mem: i64| format!("version = 1\nsandbox = true\nruntime = \"node\"\nmemory_max_mb = {mem}\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n");
        assert!(parse_policy(&make(127)).is_err());
        assert!(parse_policy(&make(128)).is_ok());
        assert!(parse_policy(&make(16384)).is_ok());
        assert!(parse_policy(&make(16385)).is_err());
    }
    // case TC_SBX_001_A4_01 end





    // case TC_SBX_001_A5_02 begin
    #[test]
    fn case_TC_SBX_001_A5_02() {
        let toml = "version = 1\nsandbox = true\nruntime = \"java\"\nmemory_max_mb = 512\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n";
        assert!(parse_policy(toml).is_err());
    }
    // case TC_SBX_001_A5_02 end


    // case TC_SBX_001_A6_02 begin
    #[test]
    fn case_TC_SBX_001_A6_02() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let test_dir = std::env::temp_dir().join(format!("ais_test_a6_02_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        unsafe { std::env::set_var("AIS_POLICY_DIR", &test_dir); }

        let valid_toml = "version = 1\nsandbox = true\nruntime = \"node\"\nmemory_max_mb = 512\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n";
        let invalid_apps = ["ais_ab12cd3", "ais_ab12cd345", "ais_AB12CD34", "ais_XYZ"];
        for app in &invalid_apps {
            assert!(write_policy(app, valid_toml).is_err(), "write_policy should reject {app}");
            assert!(read_policy(app).is_err(), "read_policy should reject {app}");
            assert!(ensure_uid(app).is_err(), "ensure_uid should reject {app}");
        }
        assert!(!test_dir.exists(), "no file or directory should be created for invalid apps");

        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        let _ = std::fs::remove_dir_all(&test_dir);
    }
    // case TC_SBX_001_A6_02 end

    // case TC_SBX_001_A7_02 begin
    #[test]
    fn case_TC_SBX_001_A7_02() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("AIS_POLICY_DIR", "/custom/test/policy/dir"); }
        let dir = policy_dir();
        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        assert_eq!(dir, std::path::PathBuf::from("/custom/test/policy/dir"));
    }
    // case TC_SBX_001_A7_02 end



    // case TC_SBX_001_A8_03 begin
    #[test]
    fn case_TC_SBX_001_A8_03() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let test_dir = std::env::temp_dir().join(format!("ais_test_a8_03_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        unsafe { std::env::set_var("AIS_POLICY_DIR", &test_dir); }

        std::fs::write(test_dir.join("ais_ab12cd34.toml"), "invalid toml :::").unwrap();
        assert!(read_policy("ais_ab12cd34").is_err());

        let bad_policy = "version = 1\nsandbox = true\nruntime = \"node\"\nmemory_max_mb = 10\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n";
        std::fs::write(test_dir.join("ais_ab12cd34.toml"), bad_policy).unwrap();
        assert!(read_policy("ais_ab12cd34").is_err());

        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        let _ = std::fs::remove_dir_all(&test_dir);
    }
    // case TC_SBX_001_A8_03 end



    // case TC_SBX_001_A9_03 begin
    #[test]
    fn case_TC_SBX_001_A9_03() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let test_dir = std::env::temp_dir().join(format!("ais_test_a9_03_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        unsafe { std::env::set_var("AIS_POLICY_DIR", &test_dir); }

        let toml1 = "version = 1\nsandbox = true\nruntime = \"node\"\nmemory_max_mb = 512\ncpu_max_millicores = 250\npids_max = 512\ntmp_max_mb = 256\n";
        let toml2 = "version = 1\nsandbox = true\nruntime = \"rust\"\nmemory_max_mb = 1024\ncpu_max_millicores = 500\npids_max = 1024\ntmp_max_mb = 512\n";
        assert_eq!(write_policy("ais_ab12cd34", toml1), Ok(()));
        assert_eq!(write_policy("ais_ab12cd34", toml2), Ok(()));

        let policy = read_policy("ais_ab12cd34").unwrap().unwrap();
        assert_eq!(policy.runtime, "rust");
        assert_eq!(policy.memory_max_mb, 1024);

        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        let _ = std::fs::remove_dir_all(&test_dir);
    }
    // case TC_SBX_001_A9_03 end

    // case TC_SBX_001_A10_01 begin
    #[test]
    fn case_TC_SBX_001_A10_01() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let test_dir = std::env::temp_dir().join(format!("ais_test_a10_01_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        unsafe { std::env::set_var("AIS_POLICY_DIR", &test_dir); }

        assert_eq!(ensure_uid_in_range("ais_aaaaaaaa", 10, 12).unwrap(), 10);
        let uid_content = std::fs::read_to_string(test_dir.join("ais_aaaaaaaa.uid")).unwrap();
        assert_eq!(uid_content, "10\n");

        assert_eq!(ensure_uid_in_range("ais_aaaaaaaa", 10, 12).unwrap(), 10);
        assert_eq!(ensure_uid_in_range("ais_bbbbbbbb", 10, 12).unwrap(), 11);
        assert_eq!(ensure_uid_in_range("ais_cccccccc", 10, 12).unwrap(), 12);
        assert!(ensure_uid_in_range("ais_dddddddd", 10, 12).is_err());

        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        let _ = std::fs::remove_dir_all(&test_dir);
    }
    // case TC_SBX_001_A10_01 end

    // case TC_SBX_001_A11_01 begin
    #[test]
    fn case_TC_SBX_001_A11_01() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let test_dir = std::env::temp_dir().join(format!("ais_test_a11_01_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        unsafe { std::env::set_var("AIS_POLICY_DIR", &test_dir); }

        std::fs::write(test_dir.join("ais_aaaaaaaa.uid"), "2000000\n").unwrap();
        let uid = ensure_uid("ais_bbbbbbbb").unwrap();
        assert_eq!(uid, 2000001);
        assert!(uid >= 2_000_000 && uid <= 2_099_999);

        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        let _ = std::fs::remove_dir_all(&test_dir);
    }
    // case TC_SBX_001_A11_01 end

    // case TC_SBX_001_A12_01 begin
    #[test]
    fn case_TC_SBX_001_A12_01() {
        let _lock = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let test_dir = std::env::temp_dir().join(format!("ais_test_a12_01_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        unsafe { std::env::set_var("AIS_POLICY_DIR", &test_dir); }

        let handles: Vec<_> = (1..=8)
            .map(|i| {
                std::thread::spawn(move || {
                    let app = format!("ais_{:08x}", i);
                    ensure_uid(&app).unwrap()
                })
            })
            .collect();

        let mut uids = Vec::new();
        for h in handles {
            uids.push(h.join().unwrap());
        }

        for &uid in &uids {
            assert!(uid >= 2_000_000 && uid <= 2_099_999);
        }
        let mut sorted = uids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 8);

        unsafe { std::env::remove_var("AIS_POLICY_DIR"); }
        let _ = std::fs::remove_dir_all(&test_dir);
    }
    // case TC_SBX_001_A12_01 end
}
