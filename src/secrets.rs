//! Client for `ais_secretserver`, used solely to fetch (and, on first use,
//! provision) this node's runtime-bundle decryption passphrase (Phase E,
//! E6). Watchdog had no connection to secret-server before this -- and
//! still doesn't manage arbitrary app secrets itself, that stays on the
//! `ais_secretserver` read/write path Portal and the dashboard already use
//! (Phase E, E10); this client's only job is the one per-node passphrase.

pub mod proto {
    tonic::include_proto!("secret_service");
}

use artisan_middleware::dusa_collection_utils::{
    core::{
        errors::{ErrorArrayItem, Errors},
        logger::LogLevel,
    },
    log,
};
use proto::secret_service_client::SecretServiceClient;
use tonic::transport::Channel;

/// Fixed internal address for `ais_secretserver`, reachable from any node in
/// the fleet. `ah.internal` is resolved by our own FreeIPA server and this
/// traffic never leaves the internal network, which is the only reason
/// plaintext gRPC is acceptable here today.
///
/// FIXME(security): this passphrase decrypts every bundle on the node and
/// travels here in the clear. Move this to TLS (or mTLS) once
/// `ais_secretserver` terminates it -- plain HTTP was a deliberate "internal
/// network only, for now" call, not a permanent one. Same gap exists in
/// `generic_runner`'s own secret-server client and the dashboard-backend's
/// `SECRET_GRPC_ADDR`; fixing it here should probably happen alongside those.
pub const SECRET_SERVER_ADDR: &str = "http://secrets.ah.internal:50052";

/// Reserved secret-server keying convention for a per-node passphrase: not a
/// real app, so `runner_id` is a fixed sentinel rather than an `ais_<hex>`
/// name, and `environment_id` is the node's own identity id. No schema
/// change needed -- `ais_secretserver`'s columns are already generic strings.
const NODE_PASSPHRASE_RUNNER_ID: &str = "_node";
const NODE_PASSPHRASE_SECRET_KEY: &str = "bundle_passphrase";
/// 4 * 16 hex chars = 256 bits of entropy.
const PASSPHRASE_WORDS: usize = 4;

/// The exact text sqlx surfaces for "no rows" (see `ais_secretserver`'s
/// `secret::get_secret`, `sqlx::Error::RowNotFound`'s `Display`), which its
/// gRPC handler wraps into a generic `Status::internal` with no distinct
/// not-found code. Matching on it is what lets us tell "doesn't exist yet,
/// safe to provision" apart from a real outage -- fragile, but the
/// alternative (provisioning a fresh passphrase on *any* error) risks
/// orphaning every bundle already encrypted with the real one. A proper
/// not-found status on `ais_secretserver`'s side would let this go away.
const NOT_FOUND_MARKER: &str =
    "no rows returned by a query that expected to return at least one row";

fn rpc_err(context: &str, status: tonic::Status) -> ErrorArrayItem {
    ErrorArrayItem::new(Errors::Network, format!("{context}: {status}"))
}

pub struct SecretClient {
    client: SecretServiceClient<Channel>,
}

impl SecretClient {
    pub async fn connect() -> Result<Self, ErrorArrayItem> {
        let client = SecretServiceClient::connect(SECRET_SERVER_ADDR)
            .await
            .map_err(|err| {
                ErrorArrayItem::new(
                    Errors::Network,
                    format!("Connecting to secret-server at {SECRET_SERVER_ADDR}: {err}"),
                )
            })?;
        Ok(Self { client })
    }

    /// `Ok(None)` means "confirmed absent, safe to provision"; any other
    /// failure is a real error the caller must not paper over.
    async fn get(
        &mut self,
        secret_key: &str,
        environment_id: &str,
    ) -> Result<Option<Vec<u8>>, ErrorArrayItem> {
        let request = proto::GetSecretRequest {
            runner_id: NODE_PASSPHRASE_RUNNER_ID.to_owned(),
            environment_id: environment_id.to_owned(),
            secret_key: secret_key.to_owned(),
            version: 0,
            actor: "watchdog".to_owned(),
        };

        match self.client.get_secret(request).await {
            Ok(response) => Ok(Some(response.into_inner().value)),
            Err(status) if status.message().contains(NOT_FOUND_MARKER) => Ok(None),
            Err(status) => Err(rpc_err("get_secret", status)),
        }
    }

    async fn create(
        &mut self,
        secret_key: &str,
        environment_id: &str,
        value: &str,
    ) -> Result<(), ErrorArrayItem> {
        let request = proto::CreateSecretRequest {
            runner_id: NODE_PASSPHRASE_RUNNER_ID.to_owned(),
            environment_id: environment_id.to_owned(),
            secret_key: secret_key.to_owned(),
            value: value.to_owned(),
            actor: "watchdog".to_owned(),
        };

        let response = self
            .client
            .create_secret(request)
            .await
            .map_err(|status| rpc_err("create_secret", status))?;

        if response.into_inner().success {
            Ok(())
        } else {
            Err(ErrorArrayItem::new(
                Errors::GeneralError,
                "create_secret reported failure",
            ))
        }
    }

    /// Fetches this node's bundle-decryption passphrase, generating and
    /// storing a fresh one on first use. `node_id` scopes the passphrase per
    /// node -- one passphrase decrypts every bundle on that node, not the
    /// whole fleet.
    pub async fn get_or_create_node_passphrase(
        &mut self,
        node_id: u64,
    ) -> Result<String, ErrorArrayItem> {
        let environment_id = node_id.to_string();

        if let Some(bytes) = self.get(NODE_PASSPHRASE_SECRET_KEY, &environment_id).await? {
            return String::from_utf8(bytes).map_err(ErrorArrayItem::from);
        }

        log!(
            LogLevel::Info,
            "No bundle passphrase on record for node {}; provisioning a new one",
            node_id
        );
        let passphrase = generate_passphrase();
        self.create(NODE_PASSPHRASE_SECRET_KEY, &environment_id, &passphrase)
            .await?;
        Ok(passphrase)
    }
}

impl SecretClient {
    /// Fetches every secret currently stored for `runner_id`/`environment_id`,
    /// formatted as `KEY=value\n` lines. Used by migration (Phase E, E7) to
    /// bootstrap an already-configured app's env content from secret-server's
    /// fleet-wide record, rather than only ever looking at whatever happens to
    /// already be on this node's local disk. A value that isn't valid UTF-8
    /// is skipped rather than failing the whole fetch.
    pub async fn get_all_as_env_lines(
        &mut self,
        runner_id: &str,
        environment_id: &str,
    ) -> Result<String, ErrorArrayItem> {
        let request = proto::GetAllSecretsRequest {
            runner_id: runner_id.to_owned(),
            environment_id: environment_id.to_owned(),
            version: 0,
        };

        let response = self
            .client
            .get_all_secrets(request)
            .await
            .map_err(|status| rpc_err("get_all_secrets", status))?
            .into_inner();

        let mut lines = String::new();
        for kv in response.vals {
            match String::from_utf8(kv.value) {
                Ok(value) => lines.push_str(&format!("{}={}\n", kv.key, value)),
                Err(_) => continue,
            }
        }
        Ok(lines)
    }
}

fn generate_passphrase() -> String {
    (0..PASSPHRASE_WORDS)
        .map(|_| format!("{:016x}", rand::random::<u64>()))
        .collect::<Vec<_>>()
        .join("")
}
