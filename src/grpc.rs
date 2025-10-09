use std::{fmt::Write, io::ErrorKind, time::Duration};

use artisan_middleware::dusa_collection_utils::{
    core::{logger::LogLevel, types::rb::RollingBuffer},
    log,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::{
    definitions::{self, ApplicationStatus, BuildStatus, VerificationEntry},
    functions,
    grpc::proto::command_request::Payload,
};

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
    process_store: definitions::ChildProcessArray,
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
        process_store,
    );

    log!(
        LogLevel::Info,
        "Starting watchdog gRPC server on Unix socket: {}",
        socket_path
    );

    Server::builder()
        .timeout(Duration::from_secs(120))
        .concurrency_limit_per_connection(64)
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
    process_handles: Vec<functions::ProcessStoreHandle>,
}

impl WatchdogService {
    fn new(
        system_application_status_store: definitions::SystemApplicationStatusStore,
        client_application_status_store: definitions::ClientApplicationStatusStore,
        build_status_store: definitions::BuildStatusStore,
        verification_status_store: definitions::VerificationStatusStore,
        system_information_store: definitions::SystemInformationStore,
        process_store: definitions::ChildProcessArray,
    ) -> Self {
        let process_handles = vec![functions::ProcessStoreHandle::system(&process_store)];
        Self {
            system_application_status_store,
            client_application_status_store,
            build_status_store,
            verification_status_store,
            system_information_store,
            process_handles,
        }
    }

    async fn lookup_application_status(
        &self,
        name: &str,
    ) -> Option<(functions::ProcessStoreKind, ApplicationStatus)> {
        {
            let store = self.system_application_status_store.read().await;
            if let Some(status) = store.get(name) {
                return Some((functions::ProcessStoreKind::System, status.clone()));
            }
        }

        {
            let store = self.client_application_status_store.read().await;
            if let Some(status) = store.get(name) {
                return Some((functions::ProcessStoreKind::Client, status.clone()));
            }
        }

        None
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

        let (accepted, message) = match command.payload {
            Some(payload) => match payload {
                Payload::Start(start_command) => {
                    let application = start_command.application;
                    match functions::start_application_stub(&application, &self.process_handles)
                        .await
                    {
                        Ok(result) => (result.accepted, result.message),
                        Err(err) => {
                            log!(
                                LogLevel::Error,
                                "Failed to process start command for {}: {}",
                                application,
                                err.err_mesg
                            );
                            (
                                false,
                                format!(
                                    "Failed to process start command for {}: {}",
                                    application, err.err_mesg
                                ),
                            )
                        }
                    }
                }
                Payload::Stop(stop_command) => {
                    let application = stop_command.application;
                    match functions::stop_application_stub(&application, &self.process_handles)
                        .await
                    {
                        Ok(result) => (result.accepted, result.message),
                        Err(err) => {
                            log!(
                                LogLevel::Error,
                                "Failed to process stop command for {}: {}",
                                application,
                                err.err_mesg
                            );
                            (
                                false,
                                format!(
                                    "Failed to process stop command for {}: {}",
                                    application, err.err_mesg
                                ),
                            )
                        }
                    }
                }
                Payload::Reload(reload_command) => {
                    let application = reload_command.application;
                    match functions::reload_application_stub(&application, &self.process_handles)
                        .await
                    {
                        Ok(result) => (result.accepted, result.message),
                        Err(err) => {
                            log!(
                                LogLevel::Error,
                                "Failed to process reload command for {}: {}",
                                application,
                                err.err_mesg
                            );
                            (
                                false,
                                format!(
                                    "Failed to process reload command for {}: {}",
                                    application, err.err_mesg
                                ),
                            )
                        }
                    }
                }
                Payload::Rebuild(rebuild_command) => {
                    let application = rebuild_command.application;
                    match functions::rebuild_application_stub(&application, &self.process_handles)
                        .await
                    {
                        Ok(result) => (result.accepted, result.message),
                        Err(err) => {
                            log!(
                                LogLevel::Error,
                                "Failed to process rebuild command for {}: {}",
                                application,
                                err.err_mesg
                            );
                            (
                                false,
                                format!(
                                    "Failed to process rebuild command for {}: {}",
                                    application, err.err_mesg
                                ),
                            )
                        }
                    }
                }
                Payload::Status(status_command) => {
                    let application = status_command.application;
                    match self.lookup_application_status(&application).await {
                        Some((store_kind, status)) => {
                            let pid = status
                                .pid
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "n/a".to_string());
                            let mut message = format!(
                                "[status] {application} ({store_kind}) => state={:?}, pid={pid}, cpu={:.2}%, mem={:.2}",
                                status.status, status.cpu_usage, status.memory_usage
                            );
                            if let Some(network) = status.network_usage.as_ref() {
                                let _ = write!(
                                    &mut message,
                                    ", net_rx={}B, net_tx={}B",
                                    network.rx_bytes, network.tx_bytes
                                );
                            }
                            let _ = write!(&mut message, ", last_updated={}", status.last_updated);
                            (true, message)
                        }
                        None => (
                            false,
                            format!(
                                "[status] {application} is not tracked in system or client status stores"
                            ),
                        ),
                    }
                }
                Payload::Info(_info_command) => {
                    let info = self.system_information_store.read().await.clone();
                    let identity = info
                        .identity
                        .as_ref()
                        .map(|id| id.id.to_string())
                        .unwrap_or_else(|| "unassigned".to_string());
                    let ips = if info.ip_addrs.is_empty() {
                        "none".to_string()
                    } else {
                        info.ip_addrs
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<String>>()
                            .join(", ")
                    };
                    let message = format!(
                        "[info] identity={identity}, system_apps_initialized={}, manager_linked={}, ip_addrs=[{ips}]",
                        info.system_apps_initialized, info.manager_linked
                    );
                    (true, message)
                }
                Payload::Set(_set_command) => (false, "Not implemented".to_string()),
                Payload::Get(_get_command) => (false, "Not implemented".to_string()),
            },
            None => (false, "Command payload missing".to_string()),
        };

        log!(LogLevel::Warn, "{}", message);

        Ok(Response::new(CommandResponse { accepted, message }))
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
