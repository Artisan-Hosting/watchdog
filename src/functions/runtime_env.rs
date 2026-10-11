use crate::functions::sandbox_policy::AppPolicy;

pub fn sandbox_env(policy: &AppPolicy, port: Option<u16>) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = vec![
        ("HOME".to_string(), "/home/app".to_string()),
        ("USER".to_string(), "app".to_string()),
        ("LOGNAME".to_string(), "app".to_string()),
        ("SHELL".to_string(), "/bin/sh".to_string()),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TMPDIR".to_string(), "/tmp".to_string()),
        ("AIS_SANDBOX".to_string(), "1".to_string()),
        ("AIS_WORKSPACE".to_string(), "/app".to_string()),
        ("AIS_RUNTIME".to_string(), policy.runtime.clone()),
    ];

    if let Some(v) = &policy.runtime_version {
        env.push(("AIS_RUNTIME_VERSION".to_string(), v.clone()));
    }
    if let Some(p) = port {
        env.push(("PORT".to_string(), p.to_string()));
    }

    let node_minor = match policy.runtime.as_str() {
        "node" | "static" => match policy.runtime_version.as_deref() {
            Some("20") => "20",
            _ => "22",
        },
        _ => "",
    };
    if !node_minor.is_empty() {
        env.push(("PATH".to_string(), format!("/opt/runtimes/node/{}/bin:/usr/local/bin:/usr/bin:/bin", node_minor)));
        env.push(("NODE_ENV".to_string(), "production".to_string()));
        env.push(("npm_config_cache".to_string(), "/home/app/.npm".to_string()));
    }

    env
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

#[cfg(test)]
#[allow(unused_imports)]
mod derived_0 {
    use super::*;



            // case 2 begin
            #[test]
            fn case_2() {
                let policy = crate::functions::sandbox_policy::AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "python".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                assert!(env.contains(&("PATH".to_string(), "/app/current/.venv/bin:/usr/local/bin:/usr/bin:/bin".to_string())), "PATH mismatch");
                assert!(env.contains(&("PIP_CACHE_DIR".to_string(), "/home/app/.cache/pip".to_string())), "PIP_CACHE_DIR mismatch");
                assert!(env.contains(&("PYTHONUNBUFFERED".to_string(), "1".to_string())), "PYTHONUNBUFFERED mismatch");
            }
            // case 2 end


    // case 4 begin
    #[test]
    fn case_4() {
        use crate::functions::sandbox_policy::AppPolicy;
        let policy = AppPolicy {
            version: 1,
            sandbox: true,
            runtime: "go".to_string(),
            runtime_version: None,
            memory_max_mb: 1024,
            cpu_max_millicores: 1000,
            pids_max: 100,
            tmp_max_mb: 100,
        };
        let env = sandbox_env(&policy, None);
        assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/go/bin:/usr/local/bin:/usr/bin:/bin".to_string())), "PATH mismatch");
        assert!(env.contains(&("GOPATH".to_string(), "/home/app/go".to_string())), "GOPATH mismatch");
        assert!(env.contains(&("GOCACHE".to_string(), "/home/app/.cache/go-build".to_string())), "GOCACHE mismatch");
        assert!(env.contains(&("GOTOOLCHAIN".to_string(), "auto".to_string())), "GOTOOLCHAIN mismatch");
        assert!(env.contains(&("CGO_ENABLED".to_string(), "0".to_string())), "CGO_ENABLED mismatch");
    }
    // case 4 end

            // case 5 begin
            #[test]
            fn case_5() {
                use crate::functions::sandbox_policy::AppPolicy;
                let policy = AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "rust".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/cargo/bin:/opt/runtimes/node/22/bin:/usr/local/bin:/usr/bin:/bin".to_string())), "PATH mismatch");
                assert!(env.contains(&("CARGO_HOME".to_string(), "/home/app/.cargo".to_string())), "CARGO_HOME mismatch");
                assert!(env.contains(&("CARGO_TARGET_DIR".to_string(), "/app/target".to_string())), "CARGO_TARGET_DIR mismatch");
            }
            // case 5 end


            // case 10 begin
            #[test]
            fn case_10() {
                let policy = crate::functions::sandbox_policy::AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "rust".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                let path = env.iter().find(|(k, _)| k == "PATH").expect("PATH not found").1.clone();
                assert!(path.ends_with(":/usr/local/bin:/usr/bin:/bin"), "PATH suffix mismatch: {}", path);
            }
            // case 10 end


            // case 12 begin
            #[test]
            fn case_12() {
                let policy = crate::functions::sandbox_policy::AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "custom".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                let path = env.iter().find(|(k, _)| k == "PATH").expect("PATH not found").1.clone();
                assert!(path.ends_with(":/usr/local/bin:/usr/bin:/bin"), "PATH suffix mismatch: {}", path);
            }
            // case 12 end




            // case 22 begin
            #[test]
            fn case_22() {
                let policy = crate::functions::sandbox_policy::AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "rust".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/cargo/bin:/opt/runtimes/node/22/bin:/usr/local/bin:/usr/bin:/bin".to_string())), "PATH mismatch");
            }
            // case 22 end

            // case 23 begin
            #[test]
            fn case_23() {
                let policy = crate::functions::sandbox_policy::AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "ruby".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                assert!(env.contains(&("PATH".to_string(), "/usr/bin:/opt/runtimes/node/22/bin:/usr/local/bin:/usr/bin:/bin".to_string())), "PATH mismatch");
            }
            // case 23 end

            // case 24 begin
            #[test]
            fn case_24() {
                let policy = crate::functions::sandbox_policy::AppPolicy {
                    version: 1,
                    sandbox: true,
                    runtime: "custom".to_string(),
                    runtime_version: None,
                    memory_max_mb: 1024,
                    cpu_max_millicores: 1000,
                    pids_max: 100,
                    tmp_max_mb: 100,
                };
                let env = sandbox_env(&policy, None);
                assert!(env.contains(&("PATH".to_string(), "/opt/runtimes/node/22/bin:/usr/local/bin:/usr/bin:/bin".to_string())), "PATH mismatch");
            }
            // case 24 end
}

#[cfg(test)]
#[allow(unused_imports)]
mod derived_t1_a1_python_base_vars {
    use super::*;






}

#[cfg(test)]
#[allow(unused_imports)]
mod derived_t2_a3_2 {
    use super::*;

}
