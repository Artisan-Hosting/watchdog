use std::io::ErrorKind;

use artisan_middleware::dusa_collection_utils::{
    core::{logger::LogLevel, types::rb::RollingBuffer},
    log,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::definitions::{self, ApplicationStatus, BuildStatus, VerificationEntry};

pub mod proto {
    tonic::include_proto!("artisan.watchdog");
}

use proto::{
    ApplicationStatusList, ApplicationStatusMessage, ApplicationStatusRequest,
    ApplicationStatusResponse, BuildStatusList, BuildStatusMessage, CommandRequest,
    CommandResponse, Empty, NetworkUsageMessage, StdLogEntry, SystemInfo, VerificationEntryList,
    VerificationEntryMessage,
    watchdog_server::{Watchdog, WatchdogServer},
};

pub async fn serve_watchdog(
    system_application_status_store: definitions::SystemApplicationStatusStore,
    client_application_status_store: definitions::ClientApplicationStatusStore,
    build_status_store: definitions::BuildStatusStore,
    verification_status_store: definitions::VerificationStatusStore,
    system_information_store: definitions::SystemInformationStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = definitions::WATCHDOG_SOCKET_PATH;

    if let Err(err) = tokio::fs::remove_file(socket_path).await {
        if err.kind() != ErrorKind::NotFound {
            return Err(Box::new(err));
        }
    }

    let listener = UnixListener::bind(socket_path)?;
    let incoming = UnixListenerStream::new(listener);

    let service = WatchdogService::new(
        system_application_status_store,
        client_application_status_store,
        build_status_store,
        verification_status_store,
        system_information_store,
    );

    log!(
        LogLevel::Info,
        "Starting watchdog gRPC server on Unix socket: {}",
        socket_path
    );

    Server::builder()
        .add_service(WatchdogServer::new(service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

struct WatchdogService {
    system_application_status_store: definitions::SystemApplicationStatusStore,
    client_application_status_store: definitions::ClientApplicationStatusStore,
    build_status_store: definitions::BuildStatusStore,
    verification_status_store: definitions::VerificationStatusStore,
    system_information_store: definitions::SystemInformationStore,
}

impl WatchdogService {
    fn new(
        system_application_status_store: definitions::SystemApplicationStatusStore,
        client_application_status_store: definitions::ClientApplicationStatusStore,
        build_status_store: definitions::BuildStatusStore,
        verification_status_store: definitions::VerificationStatusStore,
        system_information_store: definitions::SystemInformationStore,
    ) -> Self {
        Self {
            system_application_status_store,
            client_application_status_store,
            build_status_store,
            verification_status_store,
            system_information_store,
        }
    }
}

#[tonic::async_trait]
impl Watchdog for WatchdogService {
    async fn list_applications(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ApplicationStatusList>, Status> {
        let mut combined: Vec<(String, ApplicationStatus)> = Vec::new();

        {
            let system_store = self.system_application_status_store.read().await;
            combined.extend(
                system_store
                    .iter()
                    .map(|(name, status)| (name.clone(), status.clone())),
            );
        }

        {
            let client_store = self.client_application_status_store.read().await;
            combined.extend(
                client_store
                    .iter()
                    .map(|(name, status)| (name.clone(), status.clone())),
            );
        }

        combined.sort_by(|a, b| a.0.cmp(&b.0));

        let applications = combined
            .into_iter()
            .map(|(name, status)| application_status_to_proto(name, &status))
            .collect();

        Ok(Response::new(ApplicationStatusList { applications }))
    }

    async fn get_application(
        &self,
        request: Request<ApplicationStatusRequest>,
    ) -> Result<Response<ApplicationStatusResponse>, Status> {
        let name = request.into_inner().name;
        let result = {
            let system_store = self.system_application_status_store.read().await;
            let result = system_store.get(&name).cloned();
            drop(system_store);

            if result.is_some() {
                result
            } else {
                let client_store = self.client_application_status_store.read().await;
                client_store.get(&name).cloned()
            }
        };

        let response = if let Some(status) = result {
            ApplicationStatusResponse {
                found: true,
                status: Some(application_status_to_proto(name, &status)),
            }
        } else {
            ApplicationStatusResponse {
                found: false,
                status: None,
            }
        };

        Ok(Response::new(response))
    }

    async fn list_builds(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<BuildStatusList>, Status> {
        let store = self.build_status_store.read().await;
        let mut entries: Vec<BuildStatus> = store.values().cloned().collect();
        drop(store);

        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let builds = entries.into_iter().map(build_status_to_proto).collect();

        Ok(Response::new(BuildStatusList { builds }))
    }

    async fn list_verifications(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<VerificationEntryList>, Status> {
        let store = self.verification_status_store.read().await;
        let mut entries: Vec<VerificationEntry> = store.clone();
        drop(store);

        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let entries = entries
            .into_iter()
            .map(verification_entry_to_proto)
            .collect();

        Ok(Response::new(VerificationEntryList { entries }))
    }

    async fn get_system_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<SystemInfo>, Status> {
        let info = self.system_information_store.read().await.clone();

        Ok(Response::new(system_info_to_proto(info)))
    }

    async fn execute_command(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        let command = request.into_inner();

        let message = match command.payload {
            Some(payload) => format!("Command received but not yet implemented: {:?}", payload),
            None => "Command payload missing".to_string(),
        };

        log!(LogLevel::Warn, "{}", message);

        Ok(Response::new(CommandResponse {
            accepted: false,
            message,
        }))
    }
}

fn application_status_to_proto(
    name: String,
    status: &ApplicationStatus,
) -> ApplicationStatusMessage {
    ApplicationStatusMessage {
        name,
        status: format!("{:?}", status.status),
        cpu_usage: status.cpu_usage,
        memory_usage: status.memory_usage,
        pid: status.pid,
        last_updated: status.last_updated,
        stdout: rolling_buffer_to_proto_entries(&status.stdout),
        stderr: rolling_buffer_to_proto_entries(&status.stderr),
        network_usage: status.network_usage.as_ref().map(network_usage_to_proto),
    }
}

fn rolling_buffer_to_proto_entries(buffer: &RollingBuffer) -> Vec<StdLogEntry> {
    buffer
        .get_latest_time()
        .into_iter()
        .map(|(timestamp, line)| StdLogEntry { timestamp, line })
        .collect()
}

fn build_status_to_proto(status: BuildStatus) -> BuildStatusMessage {
    let result = match status.status {
        definitions::SimpleStatus::Successful => 1,
        definitions::SimpleStatus::Failed => 2,
    } as i32;

    BuildStatusMessage {
        name: status.name,
        result,
        timestamp: status.timestamp,
        vetted: status.vetted,
    }
}

fn verification_entry_to_proto(entry: VerificationEntry) -> VerificationEntryMessage {
    VerificationEntryMessage {
        name: entry.name,
        path: entry.path.to_string(),
        expected_hash: entry.expected_hash,
        calculated_hash: entry.calculated_hash,
        verified: entry.verified,
        timestamp: entry.timestamp,
    }
}

fn system_info_to_proto(info: definitions::ArtisanSystemInformation) -> SystemInfo {
    SystemInfo {
        identity: info
            .identity
            .as_ref()
            .map(|id| id.id.to_string())
            .unwrap_or_default(),
        system_apps_initialized: info.system_apps_initialized,
        ip_addresses: info.ip_addrs.iter().map(|ip| ip.to_string()).collect(),
        manager_linked: info.manager_linked,
    }
}

fn network_usage_to_proto(
    usage: &artisan_middleware::aggregator::NetworkUsage,
) -> NetworkUsageMessage {
    NetworkUsageMessage {
        rx_bytes: usage.rx_bytes,
        tx_bytes: usage.tx_bytes,
    }
}
