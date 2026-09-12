//! gRPC transport layer for watchdog control and telemetry queries.

use std::{fmt::Write, io::ErrorKind, time::Duration};

use artisan_middleware::{
    dusa_collection_utils::{
        core::{logger::LogLevel, types::rb::RollingBuffer},
        log,
    },
    timestamp::current_timestamp,
};
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::{
    definitions::{self, ApplicationStatus, BuildStatus, VerificationEntry},
    functions,
    grpc::proto::command_request::Payload,
    ledger,
};

/// Generated protobuf service/messages.
pub mod proto {
    tonic::include_proto!("artisan.watchdog");
}

use proto::{
    ApplicationStatusList, ApplicationStatusMessage, ApplicationStatusRequest,
    ApplicationStatusResponse, BuildStatusList, BuildStatusMessage, CommandRequest,
    CommandResponse, CurrentLogsRequest, CurrentLogsResponse, Empty, ExpectedAppsList,
    GetConfigFileRequest, GetConfigFileResponse, HistoricalLogRecord as HistoricalLogRecordMessage,
    HistoricalLogsRequest, HistoricalLogsResponse, LogStream, NetworkUsageMessage,
    SecurityTripStatus, SetConfigFileRequest, SetConfigFileResponse, StdLogEntry, SystemInfo,
    UsageQueryRequest, UsageQueryResponse, VerificationEntryList, VerificationEntryMessage,
    VersionInfo, GetConfigField, set_config_value,
    watchdog_server::{Watchdog, WatchdogServer},
};

use crate::functions::config_files;

/// Starts the watchdog gRPC server on the configured Unix socket path.
pub async fn serve_watchdog(
    system_application_status_store: definitions::SystemApplicationStatusStore,
    client_application_status_store: definitions::ClientApplicationStatusStore,
    client_inventory_store: definitions::ClientInventoryStore,
    build_status_store: definitions::BuildStatusStore,
    verification_status_store: definitions::VerificationStatusStore,
    system_information_store: definitions::SystemInformationStore,
    process_store: definitions::ChildProcessArray,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = definitions::WATCHDOG_SOCKET_PATH;

    '_prepare_socket: {
        if let Err(err) = tokio::fs::remove_file(socket_path).await {
            if err.kind() != ErrorKind::NotFound {
                return Err(Box::new(err));
            }
        }
    }

    let incoming = '_bind_socket: {
        // Root-only socket: mask group/other bits during bind (avoids a chmod
        // race), then pin permissions explicitly.
        let previous_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o177));
        let bind_result = UnixListener::bind(socket_path);
        nix::sys::stat::umask(previous_umask);
        let listener = bind_result?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }
        break '_bind_socket UnixListenerStream::new(listener).filter(root_only_connection);
    };

    let service = WatchdogService::new(
        system_application_status_store,
        client_application_status_store,
        client_inventory_store,
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

    '_serve_grpc: {
        let shutdown_signal = async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        };

        Server::builder()
            .timeout(Duration::from_secs(120))
            .concurrency_limit_per_connection(64)
            .add_service(WatchdogServer::new(service))
            .serve_with_incoming_shutdown(incoming, shutdown_signal)
            .await?;
    }

    Ok(())
}

/// SO_PEERCRED gate: only root may talk to the watchdog control socket.
fn root_only_connection(conn: &std::io::Result<tokio::net::UnixStream>) -> bool {
    match conn {
        Ok(stream) => match stream.peer_cred() {
            Ok(cred) if cred.uid() == 0 => true,
            Ok(cred) => {
                log!(
                    LogLevel::Warn,
                    "Rejected watchdog socket connection from uid {}",
                    cred.uid()
                );
                false
            }
            Err(err) => {
                log!(
                    LogLevel::Warn,
                    "Rejected watchdog socket connection; peer credentials unavailable: {}",
                    err
                );
                false
            }
        },
        Err(_) => true,
    }
}

struct WatchdogService {
    system_application_status_store: definitions::SystemApplicationStatusStore,
    client_application_status_store: definitions::ClientApplicationStatusStore,
    client_inventory_store: definitions::ClientInventoryStore,
    build_status_store: definitions::BuildStatusStore,
    verification_status_store: definitions::VerificationStatusStore,
    system_information_store: definitions::SystemInformationStore,
    process_handles: Vec<functions::ProcessStoreHandle>,
}

impl WatchdogService {
    fn new(
        system_application_status_store: definitions::SystemApplicationStatusStore,
        client_application_status_store: definitions::ClientApplicationStatusStore,
        client_inventory_store: definitions::ClientInventoryStore,
        build_status_store: definitions::BuildStatusStore,
        verification_status_store: definitions::VerificationStatusStore,
        system_information_store: definitions::SystemInformationStore,
        process_store: definitions::ChildProcessArray,
    ) -> Self {
        let process_handles = vec![
            functions::ProcessStoreHandle::system(&process_store),
            functions::ProcessStoreHandle::client(&process_store),
        ];
        Self {
            system_application_status_store,
            client_application_status_store,
            client_inventory_store,
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

    /// Re-scans git credentials and reports whether `name` is a known application.
    async fn application_is_expected(&self, name: &str) -> bool {
        if definitions::CRITICAL_APPLICATIONS
            .iter()
            .any(|app| app.ais == name)
        {
            return true;
        }

        if let Err(err) =
            functions::refresh_client_inventory_once(&self.client_inventory_store).await
        {
            log!(
                LogLevel::Warn,
                "Inventory refresh failed; checking cached snapshot: {}",
                err.err_mesg
            );
        }

        let snapshot = self.client_inventory_store.read().await;
        snapshot
            .expected_clients
            .iter()
            .any(|client| client == name)
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

    async fn get_current_logs(
        &self,
        request: Request<CurrentLogsRequest>,
    ) -> Result<Response<CurrentLogsResponse>, Status> {
        let msg = request.into_inner();
        if msg.application.trim().is_empty() {
            return Err(Status::invalid_argument("application is required"));
        }

        let limit = if msg.limit == 0 {
            200usize
        } else {
            msg.limit as usize
        };

        match self.lookup_application_status(&msg.application).await {
            Some((_, status)) => {
                let stdout = tail_proto_entries(status.stdout.get_latest_time(), limit);
                let stderr = tail_proto_entries(status.stderr.get_latest_time(), limit);

                Ok(Response::new(CurrentLogsResponse {
                    found: true,
                    application: msg.application,
                    stdout,
                    stderr,
                    last_updated: status.last_updated,
                }))
            }
            None => Ok(Response::new(CurrentLogsResponse {
                found: false,
                application: msg.application,
                stdout: Vec::new(),
                stderr: Vec::new(),
                last_updated: 0,
            })),
        }
    }

    async fn query_historical_logs(
        &self,
        request: Request<HistoricalLogsRequest>,
    ) -> Result<Response<HistoricalLogsResponse>, Status> {
        let msg = request.into_inner();
        if msg.application.trim().is_empty() {
            return Err(Status::invalid_argument("application is required"));
        }

        let mut start = msg.start;
        let mut end = if msg.end == 0 {
            current_timestamp()
        } else {
            msg.end
        };
        if start == 0 {
            start = end.saturating_sub(86_400);
        }
        if end < start {
            std::mem::swap(&mut start, &mut end);
        }

        let stream_filter = ledger_stream_filter_from_proto(msg.stream);
        let stream = normalize_proto_stream(msg.stream);
        let page = ledger::query_historical_logs(
            &msg.application,
            stream_filter,
            start,
            end,
            msg.cursor,
            msg.limit,
        )
        .await
        .map_err(|err| Status::internal(err.err_mesg.to_string()))?;

        let entries: Vec<HistoricalLogRecordMessage> = page
            .entries
            .into_iter()
            .map(|entry| HistoricalLogRecordMessage {
                id: entry.id,
                application: entry.application,
                stream: proto_stream_from_ledger(entry.stream) as i32,
                timestamp: entry.timestamp,
                line: entry.line,
            })
            .collect();

        Ok(Response::new(HistoricalLogsResponse {
            found: !entries.is_empty(),
            application: msg.application,
            start,
            end,
            stream: stream as i32,
            entries,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
        }))
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

    async fn get_security_trip_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<SecurityTripStatus>, Status> {
        let info = self.system_information_store.read().await.clone();
        Ok(Response::new(security_trip_status_to_proto(info)))
    }

    async fn get_version_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<VersionInfo>, Status> {
        Ok(Response::new(version_info_to_proto()))
    }

    async fn query_usage(
        &self,
        request: Request<UsageQueryRequest>,
    ) -> Result<Response<UsageQueryResponse>, Status> {
        let msg = request.into_inner();
        if msg.application.trim().is_empty() {
            return Err(Status::invalid_argument("application is required"));
        }

        let mut start = msg.start;
        let mut end = if msg.end == 0 {
            current_timestamp()
        } else {
            msg.end
        };

        if start == 0 {
            start = end.saturating_sub(86_400); // default to last 24h
        }

        if end < start {
            std::mem::swap(&mut start, &mut end);
        }

        match ledger::summarize_usage(&msg.application, start, end).await {
            Ok(Some(summary)) => Ok(Response::new(UsageQueryResponse {
                found: true,
                application: summary.application,
                start: summary.start,
                end: summary.end,
                avg_cpu: f64::from(summary.avg_cpu),
                avg_mem: summary.avg_mem,
                peak_mem: summary.peak_mem,
                total_rx: summary.total_rx,
                total_tx: summary.total_tx,
                sample_count: summary.samples,
            })),
            Ok(None) => Ok(Response::new(UsageQueryResponse {
                found: false,
                application: msg.application,
                start,
                end,
                avg_cpu: 0.0,
                avg_mem: 0.0,
                peak_mem: 0.0,
                total_rx: 0,
                total_tx: 0,
                sample_count: 0,
            })),
            Err(err) => Err(Status::internal(err.err_mesg.to_string())),
        }
    }

    async fn list_expected_apps(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ExpectedAppsList>, Status> {
        if let Err(err) =
            functions::refresh_client_inventory_once(&self.client_inventory_store).await
        {
            log!(
                LogLevel::Warn,
                "Expected-apps refresh failed; serving cached inventory: {}",
                err.err_mesg
            );
        }

        let snapshot = self.client_inventory_store.read().await;
        Ok(Response::new(ExpectedAppsList {
            expected: snapshot.expected_clients.clone(),
            safe: snapshot.safe_clients.clone(),
            last_scan: snapshot.last_scan,
        }))
    }

    async fn get_config_file(
        &self,
        request: Request<GetConfigFileRequest>,
    ) -> Result<Response<GetConfigFileResponse>, Status> {
        let msg = request.into_inner();
        let kind = config_files::ConfigFileKind::from_proto(msg.kind)
            .ok_or_else(|| Status::invalid_argument("config file kind is required"))?;
        config_files::validate_ais_name(&msg.application)
            .map_err(|err| Status::invalid_argument(err.err_mesg.to_string()))?;

        if msg.create_if_missing && !self.application_is_expected(&msg.application).await {
            return Err(Status::failed_precondition(format!(
                "{} is not present in git credentials; cannot scaffold its config",
                msg.application
            )));
        }

        let read = config_files::read_config_file_managed(
            &config_files::conf_dir(),
            &msg.application,
            kind,
            msg.create_if_missing,
        )
        .await
        .map_err(|err| Status::internal(err.err_mesg.to_string()))?;

        if read.created {
            if let Err(err) =
                functions::refresh_client_inventory_once(&self.client_inventory_store).await
            {
                log!(
                    LogLevel::Warn,
                    "Inventory refresh failed after scaffolding {}: {}",
                    msg.application,
                    err.err_mesg
                );
            }
        }

        Ok(Response::new(GetConfigFileResponse {
            found: read.found,
            created: read.created,
            path: read.path.display().to_string(),
            content: read.content,
            sha256: read.sha256,
        }))
    }

    async fn set_config_file(
        &self,
        request: Request<SetConfigFileRequest>,
    ) -> Result<Response<SetConfigFileResponse>, Status> {
        let msg = request.into_inner();
        let kind = config_files::ConfigFileKind::from_proto(msg.kind)
            .ok_or_else(|| Status::invalid_argument("config file kind is required"))?;
        config_files::validate_ais_name(&msg.application)
            .map_err(|err| Status::invalid_argument(err.err_mesg.to_string()))?;

        let expected_sha = (!msg.expected_previous_sha256.is_empty())
            .then_some(msg.expected_previous_sha256.as_str());

        match config_files::write_config_file_managed(
            &config_files::conf_dir(),
            &msg.application,
            kind,
            &msg.content,
            expected_sha,
        )
        .await
        {
            Ok(result) => {
                log!(
                    LogLevel::Info,
                    "Config write: app={} file={} backup={}",
                    msg.application,
                    result.path.display(),
                    result.backup_file.as_deref().unwrap_or("none")
                );
                if let Err(err) =
                    functions::refresh_client_inventory_once(&self.client_inventory_store).await
                {
                    log!(
                        LogLevel::Warn,
                        "Inventory refresh failed after config write for {}: {}",
                        msg.application,
                        err.err_mesg
                    );
                }
                Ok(Response::new(SetConfigFileResponse {
                    accepted: true,
                    message: format!("wrote {}", result.path.display()),
                    backup_file: result.backup_file.unwrap_or_default(),
                }))
            }
            Err(err) => Ok(Response::new(SetConfigFileResponse {
                accepted: false,
                message: err.err_mesg.to_string(),
                backup_file: String::new(),
            })),
        }
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
                    match functions::start_application_stub(
                        &application,
                        &self.process_handles,
                        &self.client_inventory_store,
                    )
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
                    let stores = self.process_handles.clone();
                    let build_store = self.build_status_store.clone();
                    let inventory_store = self.client_inventory_store.clone();
                    let queued_application = application.clone();

                    tokio::spawn(async move {
                        match functions::rebuild_application_stub(
                            &application,
                            &stores,
                            &inventory_store,
                        )
                        .await
                        {
                            Ok(result) => {
                                let status = if result.accepted {
                                    definitions::BuildStatus::success(application.clone(), false)
                                } else {
                                    definitions::BuildStatus::failure(application.clone(), false)
                                };
                                {
                                    let mut store = build_store.write().await;
                                    store.insert(application.clone(), status);
                                }
                                if result.accepted {
                                    log!(LogLevel::Info, "{}", result.message);
                                } else {
                                    log!(LogLevel::Warn, "{}", result.message);
                                }
                            }
                            Err(err) => {
                                {
                                    let mut store = build_store.write().await;
                                    store.insert(
                                        application.clone(),
                                        definitions::BuildStatus::failure(
                                            application.clone(),
                                            false,
                                        ),
                                    );
                                }
                                log!(
                                    LogLevel::Error,
                                    "Failed to process rebuild command for {}: {}",
                                    application,
                                    err.err_mesg
                                );
                            }
                        }
                    });

                    (
                        true,
                        format!(
                            "[stub] rebuild command queued for {}; check list_builds for final status",
                            queued_application
                        ),
                    )
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
                                "[status] {application} ({store_kind:?}) => state={:?}, pid={pid}, cpu={:.2}%, mem={:.2}",
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
                        "[info] identity={identity}, system_apps_initialized={}, manager_linked={}, security_tripped={}, security_trip_detected_at={}, security_trip_summary={}, ip_addrs=[{ips}]",
                        info.system_apps_initialized,
                        info.manager_linked,
                        info.security_tripped,
                        info.security_trip_detected_at,
                        info.security_trip_summary
                    );
                    (true, message)
                }
                Payload::Get(get_command) => {
                    let app = &get_command.application;
                    if let Err(err) = config_files::validate_ais_name(app) {
                        (false, format!("Invalid application name: {}", err.err_mesg))
                    } else {
                        let field_enum = proto::GetConfigField::try_from(get_command.field)
                            .ok()
                            .unwrap_or(proto::GetConfigField::Unspecified);
                        if let Some(kind) = get_config_file_kind_for_get(field_enum) {
                            match config_files::read_config_file_managed(
                                &config_files::conf_dir(),
                                app,
                                kind,
                                false,
                            )
                            .await
                            {
                                Ok(read) => {
                                    if !read.found {
                                        (false, "Config file not found".to_string())
                                    } else {
                                        match toml::from_str::<toml::Value>(&read.content) {
                                            Ok(toml_val) => {
                                                if let Some(val) = get_field_from_toml(&toml_val, field_enum) {
                                                    (true, val)
                                                } else {
                                                    (false, "Field not found in configuration".to_string())
                                                }
                                            }
                                            Err(err) => (false, format!("Invalid TOML content: {}", err)),
                                        }
                                    }
                                }
                                Err(err) => (false, format!("Failed to read config file: {}", err.err_mesg)),
                            }
                        } else {
                            (false, "Unsupported or unspecified config field".to_string())
                        }
                    }
                }
                Payload::Set(set_command) => {
                    let app = &set_command.application;
                    if let Err(err) = config_files::validate_ais_name(app) {
                        (false, format!("Invalid application name: {}", err.err_mesg))
                    } else if let Some(ref set_config_value) = set_command.value {
                        if let Some(ref val) = set_config_value.value {
                            if let Some(kind) = get_config_file_kind_for_set(val) {
                                match config_files::read_config_file_managed(
                                    &config_files::conf_dir(),
                                    app,
                                    kind,
                                    true, // Create/scaffold if missing
                                )
                                .await
                                {
                                    Ok(read) => {
                                        match toml::from_str::<toml::Value>(&read.content) {
                                            Ok(mut toml_val) => {
                                                if let Err(err) = set_field_in_toml(&mut toml_val, val) {
                                                    (false, format!("Failed to update field: {}", err))
                                                } else {
                                                    match toml::to_string(&toml_val) {
                                                        Ok(new_content) => {
                                                            match config_files::write_config_file_managed(
                                                                &config_files::conf_dir(),
                                                                app,
                                                                kind,
                                                                &new_content,
                                                                Some(&read.sha256),
                                                            )
                                                            .await
                                                            {
                                                                Ok(_) => {
                                                                    // Gracefully restart application
                                                                    let stop_res = functions::stop_application_stub(app, &self.process_handles).await;
                                                                    let start_res = functions::start_application_stub(
                                                                        app,
                                                                        &self.process_handles,
                                                                        &self.client_inventory_store,
                                                                    )
                                                                    .await;

                                                                    let restart_msg = match (stop_res, start_res) {
                                                                        (Ok(stop), Ok(start)) => {
                                                                            format!("; restart: stopped accepted={} message={}; started accepted={} message={}", stop.accepted, stop.message, start.accepted, start.message)
                                                                        }
                                                                        (Err(stop_err), Ok(start)) => {
                                                                            format!("; restart stop failed: {}; started accepted={} message={}", stop_err.err_mesg, start.accepted, start.message)
                                                                        }
                                                                        (Ok(stop), Err(start_err)) => {
                                                                            format!("; restart: stopped accepted={} message={}; start failed: {}", stop.accepted, stop.message, start_err.err_mesg)
                                                                        }
                                                                        (Err(stop_err), Err(start_err)) => {
                                                                            format!("; restart failed: stop={}, start={}", stop_err.err_mesg, start_err.err_mesg)
                                                                        }
                                                                    };
                                                                    (true, format!("Successfully updated configuration{}", restart_msg))
                                                                }
                                                                Err(err) => (false, format!("Failed to write config file: {}", err.err_mesg)),
                                                            }
                                                        }
                                                        Err(err) => (false, format!("Failed to serialize updated TOML: {}", err)),
                                                    }
                                                }
                                            }
                                            Err(err) => (false, format!("Failed to parse existing TOML: {}", err)),
                                        }
                                    }
                                    Err(err) => (false, format!("Failed to read existing config: {}", err.err_mesg)),
                                }
                            } else {
                                (false, "Unsupported configuration field".to_string())
                            }
                        } else {
                            (false, "No value specified inside SetConfigValue".to_string())
                        }
                    } else {
                        (false, "SetConfigValue is missing".to_string())
                    }
                }
            },
            None => (false, "Command payload missing".to_string()),
        };

        log!(LogLevel::Warn, "{}", message);

        Ok(Response::new(CommandResponse { accepted, message }))
    }

    async fn recalculate_allowed_clients(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CommandResponse>, Status> {
        match functions::refresh_client_inventory_once(&self.client_inventory_store).await {
            Ok(diff) => {
                let safe_clients = {
                    let guard = self.client_inventory_store.read().await;
                    guard.safe_clients.clone()
                };

                functions::seed_placeholder_client_statuses(
                    &self.client_application_status_store,
                    &safe_clients,
                )
                .await;

                let build_status_store = self.build_status_store.clone();
                let client_inventory_store = self.client_inventory_store.clone();
                tokio::spawn(async move {
                    functions::auto_build_safe_clients(
                        &client_inventory_store,
                        &build_status_store,
                        safe_clients,
                        std::time::Duration::from_secs(60),
                    )
                    .await;
                });

                let message = format!(
                    "Recalculated allowed client list: added {} expected, removed {} expected; added {} safe, removed {} safe",
                    diff.expected_added.len(),
                    diff.expected_removed.len(),
                    diff.safe_added.len(),
                    diff.safe_removed.len()
                );
                log!(LogLevel::Info, "{}", message);

                Ok(Response::new(CommandResponse {
                    accepted: true,
                    message,
                }))
            }
            Err(err) => Err(Status::internal(format!(
                "Failed to refresh inventory: {}",
                err.err_mesg
            ))),
        }
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

fn tail_proto_entries(entries: Vec<(u64, String)>, limit: usize) -> Vec<StdLogEntry> {
    let total = entries.len();
    let start_idx = total.saturating_sub(limit);
    entries
        .into_iter()
        .skip(start_idx)
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
        security_tripped: info.security_tripped,
        security_trip_detected_at: info.security_trip_detected_at,
        security_trip_summary: info.security_trip_summary,
    }
}

fn security_trip_status_to_proto(
    info: definitions::ArtisanSystemInformation,
) -> SecurityTripStatus {
    SecurityTripStatus {
        tripped: info.security_tripped,
        detected_at: info.security_trip_detected_at,
        summary: info.security_trip_summary,
    }
}

fn version_info_to_proto() -> VersionInfo {
    VersionInfo {
        watchdog_version: env!("CARGO_PKG_VERSION").to_string(),
        artisan_middleware_version: option_env!("ARTISAN_MIDDLEWARE_VERSION")
            .unwrap_or("unknown")
            .to_string(),
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

fn ledger_stream_filter_from_proto(stream: i32) -> ledger::LogStreamFilter {
    match LogStream::try_from(stream).unwrap_or(LogStream::Unspecified) {
        LogStream::Stdout => ledger::LogStreamFilter::Stdout,
        LogStream::Stderr => ledger::LogStreamFilter::Stderr,
        LogStream::Both | LogStream::Unspecified => ledger::LogStreamFilter::Both,
    }
}

fn normalize_proto_stream(stream: i32) -> LogStream {
    match LogStream::try_from(stream).unwrap_or(LogStream::Unspecified) {
        LogStream::Stdout => LogStream::Stdout,
        LogStream::Stderr => LogStream::Stderr,
        LogStream::Both => LogStream::Both,
        LogStream::Unspecified => LogStream::Both,
    }
}

fn proto_stream_from_ledger(stream: ledger::LogStream) -> LogStream {
    match stream {
        ledger::LogStream::Stdout => LogStream::Stdout,
        ledger::LogStream::Stderr => LogStream::Stderr,
    }
}

fn get_config_file_kind_for_get(field: GetConfigField) -> Option<config_files::ConfigFileKind> {
    match field {
        GetConfigField::BuildCommand
        | GetConfigField::RunCommand
        | GetConfigField::DependenciesCommand
        | GetConfigField::MonitorDirectory
        | GetConfigField::WorkingDirectory
        | GetConfigField::ChangesNeeded
        | GetConfigField::DirScanInterval => Some(config_files::ConfigFileKind::Config),
        GetConfigField::LogLevel
        | GetConfigField::MemoryCap
        | GetConfigField::CpuCap => Some(config_files::ConfigFileKind::Overrides),
        _ => None,
    }
}

fn get_config_file_kind_for_set(val: &set_config_value::Value) -> Option<config_files::ConfigFileKind> {
    match val {
        set_config_value::Value::BuildCommand(_)
        | set_config_value::Value::RunCommand(_)
        | set_config_value::Value::DependenciesCommand(_)
        | set_config_value::Value::MonitorDirectory(_)
        | set_config_value::Value::WorkingDirectory(_)
        | set_config_value::Value::ChangesNeeded(_)
        | set_config_value::Value::DirScanInterval(_) => Some(config_files::ConfigFileKind::Config),
        set_config_value::Value::LogLevel(_)
        | set_config_value::Value::MemoryCap(_)
        | set_config_value::Value::CpuCap(_) => Some(config_files::ConfigFileKind::Overrides),
    }
}

fn get_field_from_toml(value: &toml::Value, field: GetConfigField) -> Option<String> {
    match field {
        GetConfigField::BuildCommand => {
            value.get("app_specific")
                .and_then(|v| v.get("build_command"))
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
        }
        GetConfigField::RunCommand => {
            value.get("app_specific")
                .and_then(|v| v.get("run_command"))
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
        }
        GetConfigField::DependenciesCommand => {
            value.get("app_specific")
                .and_then(|v| v.get("install_command"))
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
        }
        GetConfigField::LogLevel => {
            value.get("log_level")
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
        }
        GetConfigField::MemoryCap => {
            value.get("memory_cap")
                .map(|v| v.to_string())
        }
        GetConfigField::CpuCap => {
            value.get("cpu_cap")
                .map(|v| v.to_string())
        }
        GetConfigField::MonitorDirectory => {
            value.get("app_specific")
                .and_then(|v| v.get("monitor_path"))
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
        }
        GetConfigField::WorkingDirectory => {
            value.get("app_specific")
                .and_then(|v| v.get("project_path"))
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    v => v.to_string(),
                })
        }
        GetConfigField::ChangesNeeded => {
            value.get("app_specific")
                .and_then(|v| v.get("changes_needed"))
                .map(|v| v.to_string())
        }
        GetConfigField::DirScanInterval => {
            value.get("app_specific")
                .and_then(|v| v.get("interval_seconds"))
                .map(|v| v.to_string())
        }
        _ => None,
    }
}

fn set_field_in_toml(value: &mut toml::Value, new_val: &set_config_value::Value) -> Result<(), &'static str> {
    match new_val {
        set_config_value::Value::BuildCommand(cmd) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("build_command".to_string(), toml::Value::String(cmd.clone()));
        }
        set_config_value::Value::RunCommand(cmd) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("run_command".to_string(), toml::Value::String(cmd.clone()));
        }
        set_config_value::Value::DependenciesCommand(cmd) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("install_command".to_string(), toml::Value::String(cmd.clone()));
        }
        set_config_value::Value::LogLevel(lvl) => {
            let root = value.as_table_mut().ok_or("Root is not a table")?;
            root.insert("log_level".to_string(), toml::Value::String(lvl.clone()));
        }
        set_config_value::Value::MemoryCap(cap) => {
            let root = value.as_table_mut().ok_or("Root is not a table")?;
            root.insert("memory_cap".to_string(), toml::Value::Integer(*cap as i64));
        }
        set_config_value::Value::CpuCap(cap) => {
            let root = value.as_table_mut().ok_or("Root is not a table")?;
            root.insert("cpu_cap".to_string(), toml::Value::Integer(*cap as i64));
        }
        set_config_value::Value::MonitorDirectory(dir) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("monitor_path".to_string(), toml::Value::String(dir.clone()));
        }
        set_config_value::Value::WorkingDirectory(dir) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("project_path".to_string(), toml::Value::String(dir.clone()));
        }
        set_config_value::Value::ChangesNeeded(cnt) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("changes_needed".to_string(), toml::Value::Integer(*cnt as i64));
        }
        set_config_value::Value::DirScanInterval(seconds) => {
            let app_specific = value.as_table_mut()
                .ok_or("Root is not a table")?
                .entry("app_specific")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or("app_specific is not a table")?;
            app_specific.insert("interval_seconds".to_string(), toml::Value::Integer(*seconds as i64));
        }
    }
    Ok(())
}
