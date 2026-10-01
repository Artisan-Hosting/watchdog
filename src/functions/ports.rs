//! Listening ports for customer apps.
//!
//! Nothing used to assign a port: a customer's app listened on whatever it
//! defaulted to, and a vhost backend `{node, port}` had to be typed in by hand.
//! The node is the authority on what is free on it, so the watchdog picks one,
//! remembers it, and hands it to the app as `PORT`.
//!
//! * **Opt-in per app** (`auto_port = true` under `[app_specific]` in its
//!   `Config.toml`, which Portal's customer deploy writes). Apps that were
//!   deployed before this existed keep their own ports: injecting `PORT` into an
//!   app that reads it would silently move it off the port its vhost points at.
//! * **Stable.** The choice is stored in `<conf_dir>/<app>/port` and reused on
//!   every start, so the vhost never has to change.
//! * **Free.** Skips ports other apps have been given, and ports something is
//!   already listening on.
//! * One allocation at a time, so two apps starting together cannot be given the
//!   same port.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The range customer apps are given ports from.
pub const PORT_RANGE_START: u16 = 20000;
pub const PORT_RANGE_END: u16 = 29999;

static ALLOCATION: Mutex<()> = Mutex::new(());

/// `<conf_dir>/<app>/port`
pub fn port_file(conf_dir: &Path, app: &str) -> PathBuf {
    conf_dir.join(app).join("port")
}

/// The stored port for `app`, if there is a valid one.
pub fn read_port(conf_dir: &Path, app: &str) -> Option<u16> {
    let text = fs::read_to_string(port_file(conf_dir, app)).ok()?;
    let port: u16 = text.trim().parse().ok()?;
    (PORT_RANGE_START..=PORT_RANGE_END).contains(&port).then_some(port)
}

/// Every port another app has been given.
pub fn ports_in_use(conf_dir: &Path, except: &str) -> HashSet<u16> {
    let mut used = HashSet::new();
    let Ok(entries) = fs::read_dir(conf_dir) else { return used };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == except {
            continue;
        }
        if let Some(port) = read_port(conf_dir, &name) {
            used.insert(port);
        }
    }
    used
}

/// The lowest port in the range that is neither `used` nor `is_bound`.
pub fn pick_port(used: &HashSet<u16>, is_bound: impl Fn(u16) -> bool) -> Option<u16> {
    (PORT_RANGE_START..=PORT_RANGE_END).find(|p| !used.contains(p) && !is_bound(*p))
}

/// Whether something is already listening on `port` (on any address we care about).
fn is_bound(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_err() || TcpListener::bind(("127.0.0.1", port)).is_err()
}

/// Whether this app's `Config.toml` asks for an automatic port.
pub fn wants_auto_port(config_toml: &str) -> bool {
    toml::from_str::<toml::Table>(config_toml)
        .ok()
        .and_then(|t| t.get("app_specific")?.get("auto_port")?.as_bool())
        .unwrap_or(false)
}

/// The app's port: the stored one, or a newly allocated and stored one.
pub fn ensure_port(conf_dir: &Path, app: &str) -> io::Result<u16> {
    ensure_port_with(conf_dir, app, is_bound)
}

pub(crate) fn ensure_port_with(conf_dir: &Path, app: &str, bound: impl Fn(u16) -> bool) -> io::Result<u16> {
    let _one_at_a_time = ALLOCATION.lock().unwrap_or_else(|e| e.into_inner());

    if let Some(existing) = read_port(conf_dir, app) {
        return Ok(existing);
    }
    let used = ports_in_use(conf_dir, app);
    let port = pick_port(&used, bound)
        .ok_or_else(|| io::Error::other("no free port left in the customer app range"))?;

    // Written whole, then moved into place, so a crash never leaves half a number.
    let path = port_file(conf_dir, app);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, format!("{port}\n"))?;
    fs::rename(&tmp, &path)?;
    Ok(port)
}

/// The port to start `app` with, if it opted in: reads its `Config.toml` and
/// allocates on first use. `Ok(None)` for apps that did not ask for one.
pub fn port_for_start(app: &str) -> io::Result<Option<u16>> {
    let conf_dir = Path::new(crate::definitions::ARTISAN_CONF_DIR);
    let Ok(config) = fs::read_to_string(conf_dir.join(app).join("Config.toml")) else {
        return Ok(None);
    };
    if !wants_auto_port(&config) {
        return Ok(None);
    }
    ensure_port(conf_dir, app).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ais-ports-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn app(conf: &Path, name: &str) {
        fs::create_dir_all(conf.join(name)).unwrap();
    }

    #[test]
    fn the_lowest_free_port_is_picked_skipping_used_and_bound_ones() {
        let used: HashSet<u16> = [20000, 20001].into_iter().collect();
        assert_eq!(pick_port(&used, |p| p == 20002), Some(20003));
        assert_eq!(pick_port(&HashSet::new(), |_| false), Some(PORT_RANGE_START));
        assert_eq!(pick_port(&HashSet::new(), |_| true), None, "nothing free");
    }

    #[test]
    fn an_app_is_given_a_port_once_and_keeps_it() {
        let dir = conf();
        app(&dir, "ais_aaaa1111");
        let first = ensure_port_with(&dir, "ais_aaaa1111", |_| false).unwrap();
        // Even if the first choice is now "bound" (the app itself is listening on it), it is reused.
        let again = ensure_port_with(&dir, "ais_aaaa1111", |_| true).unwrap();
        assert_eq!((first, again), (PORT_RANGE_START, PORT_RANGE_START));
        assert_eq!(read_port(&dir, "ais_aaaa1111"), Some(PORT_RANGE_START));
    }

    #[test]
    fn two_apps_never_share_a_port() {
        let dir = conf();
        for name in ["ais_aaaa1111", "ais_bbbb2222", "ais_cccc3333"] {
            app(&dir, name);
        }
        let ports: HashSet<u16> =
            ["ais_aaaa1111", "ais_bbbb2222", "ais_cccc3333"].iter().map(|n| ensure_port_with(&dir, n, |_| false).unwrap()).collect();
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn a_port_something_else_is_listening_on_is_skipped() {
        let dir = conf();
        app(&dir, "ais_aaaa1111");
        let port = ensure_port_with(&dir, "ais_aaaa1111", |p| p < 20005).unwrap();
        assert_eq!(port, 20005);
    }

    #[test]
    fn a_garbage_or_out_of_range_file_is_not_trusted() {
        let dir = conf();
        app(&dir, "ais_aaaa1111");
        for bad in ["not a number", "80", "70000", ""] {
            fs::write(port_file(&dir, "ais_aaaa1111"), bad).unwrap();
            assert_eq!(read_port(&dir, "ais_aaaa1111"), None, "{bad:?}");
        }
    }

    #[test]
    fn only_apps_that_ask_for_it_get_a_port() {
        assert!(wants_auto_port("[app_specific]\nauto_port = true\nrun_command = \"x\"\n"));
        assert!(!wants_auto_port("[app_specific]\nauto_port = false\n"));
        assert!(!wants_auto_port("[app_specific]\nrun_command = \"x\"\n"), "legacy apps keep their own ports");
        assert!(!wants_auto_port("not toml {{{"));
    }

    #[test]
    fn a_real_bind_check_sees_a_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(is_bound(port));
    }
}
