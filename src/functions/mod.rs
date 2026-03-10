//! Public functional surface for watchdog runtime tasks.

pub mod inventory;
pub mod monitoring;
pub mod verification;

pub use inventory::{
    generate_safe_client_runner_list, get_all_ipv4, monitor_client_inventory,
    refresh_client_inventory_once,
};
pub use monitoring::{
    CommandStubResult, ProcessStoreHandle, ProcessStoreKind, configure_client_runtime_command,
    configure_www_data_command, monitor_application_states, monitor_runtime_health,
    rebuild_application_stub, reload_application_stub, start_application_stub,
    stop_application_stub, take_process_by_name,
};
pub use verification::{
    persist_shutdown_integrity_manifest, verify_startup_integrity,
};
