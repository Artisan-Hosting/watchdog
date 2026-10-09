use crate::functions::sandbox_policy::AppPolicy;

pub fn sandbox_env(policy: &AppPolicy, port: Option<u16>) -> Vec<(String, String)> {
    todo!()
}

#[cfg(test)]
#[allow(unused_imports)]
mod derived_tests {
    use super::*;
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::functions::sandbox_policy::AppPolicy;

        fn create_policy(runtime: &str, runtime_version: Option<&str>) -> AppPolicy {
            AppPolicy {
                version: 1,
                sandbox: true,
                runtime: runtime.to_string(),
                runtime_version: runtime_version.map(|s| s.to_string()),
                memory_max_mb: 1024,
                cpu_max_millicores: 1000,
                pids_max: 100,
                tmp_max_mb: 100,
            }
        }

        // case node_22_port_3000 begin
        #[test]
        fn case_node_22_port_3000() {
            let policy = create_policy("node", Some("22"));
            let env = sandbox_env(&policy, Some(3000));
            assert!(env.contains(&("PORT".to_string(), "3000".to_string())));
            assert!(env.contains(&("AIS_RUNTIME_VERSION".to_string(), "22".to_string())));
            assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/node/22/bin:/usr/local/bin:/usr/bin:/bin".to_string())));
            assert!(env.contains(&("NODE_ENV".to_string(), "production".to_string())));
            assert!(env.contains(&("npm_config_cache".to_string(), "/home/app/.npm".to_string())));
        }
        // case node_22_port_3000 end

        // case node_20_path begin
        #[test]
        fn case_node_20_path() {
            let policy = create_policy("node", Some("20"));
            let env = sandbox_env(&policy, None);
            assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/node/20/bin:/usr/local/bin:/usr/bin:/bin".to_string())));
        }
        // case node_20_path end

        // case node_default_version_path begin
        #[test]
        fn case_node_default_version_path() {
            let policy = create_policy("node", None);
            let env = sandbox_env(&policy, None);
            assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/node/22/bin:/usr/local/bin:/usr/bin:/bin".to_string())));
        }
        // case node_default_version_path end



        // case static_runtime_env_with_version begin
        #[test]
        fn case_static_runtime_env_with_version() {
            let policy = create_policy("static", Some("20"));
            let env = sandbox_env(&policy, None);
            assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/node/20/bin:/usr/local/bin:/usr/bin:/bin".to_string())));
            assert!(env.contains(&("NODE_ENV".to_string(), "production".to_string())));
            assert!(env.contains(&("npm_config_cache".to_string(), "/home/app/.npm".to_string())));
        }
        // case static_runtime_env_with_version end

        // case ais_runtime_version_present_when_set begin
        #[test]
        fn case_ais_runtime_version_present_when_set() {
            let policy = create_policy("node", Some("22"));
            let env = sandbox_env(&policy, None);
            assert!(env.iter().any(|(k, v)| k == "AIS_RUNTIME_VERSION" && v == "22"));
        }
        // case ais_runtime_version_present_when_set end

        // case port_present_when_set begin
        #[test]
        fn case_port_present_when_set() {
            let policy = create_policy("node", Some("22"));
            let env = sandbox_env(&policy, Some(3000));
            assert!(env.iter().any(|(k, v)| k == "PORT" && v == "3000"));
        }
        // case port_present_when_set end


        // case base_entries_present_static_default begin
        #[test]
        fn case_base_entries_present_static_default() {
            let policy = create_policy("static", None);
            let env = sandbox_env(&policy, None);
            let base = vec![
                ("HOME", "/home/app"), ("USER", "app"), ("LOGNAME", "app"),
                ("SHELL", "/bin/sh"), ("LANG", "C.UTF-8"), ("LC_ALL", "C.UTF-8"),
                ("TMPDIR", "/tmp"), ("AIS_SANDBOX", "1"), ("AIS_WORKSPACE", "/app"),
                ("AIS_RUNTIME", "static")
            ];
            for (k, v) in base {
                assert!(env.contains(&(k.to_string(), v.to_string())));
            }
        }
        // case base_entries_present_static_default end






        // case path_suffix_present_node_18 begin
        #[test]
        fn case_path_suffix_present_node_18() {
            let policy = create_policy("node", Some("18"));
            let env = sandbox_env(&policy, None);
            let path = env.iter().find(|(k, _)| k == "PATH").unwrap().1.clone();
            assert!(path.ends_with(":/usr/local/bin:/usr/bin:/bin"));
        }
        // case path_suffix_present_node_18 end
    }
}
