//! Client-side half of the platform's internal mutual TLS.
//!
//! The internal gRPC servers (ais_auth, ais_secretserver, RunpodManager,
//! keystore, domain_management) *require* a client certificate signed by the
//! internal CA. This is the matching helper for anything that dials them.
//!
//! This is a vendored file -- the same text lives in every crate that dials an
//! mTLS server, exactly like the `.proto` files did before `ais_proto`, because
//! `artisan_middleware`'s `mtls` module is deliberately tonic-free (each crate
//! pins its own tonic). Keep the copies identical; the canonical source is
//! `ais_proto/mtls_client.rs.tmpl`.
//!
//! Behaviour is chosen by the address scheme, so one binary works in both
//! worlds without a flag:
//!   * `https://host:port` -> mutual TLS. Requires client certificate material;
//!     the server's certificate is verified against the internal CA and
//!     against `server_name` (the leaf certs carry a DNS SAN equal to the
//!     service name the CA tool was given, e.g. `ais_auth`).
//!   * `http://host:port`  -> plaintext. Local development against a server
//!     that is itself running without TLS only; a production mTLS server will
//!     refuse it.
//!
//! No `tracing`/`log` dependency on purpose: errors are returned as `String`
//! for the caller to log with whatever it already uses.

// Vendored into several crates, each of which uses only part of it.
#![allow(dead_code)]

use std::path::PathBuf;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// This process's own client identity plus the CA it trusts.
#[derive(Clone)]
pub struct ClientMtls {
    identity: Identity,
    ca: Certificate,
}

impl ClientMtls {
    /// Loads `MTLS_CERT_PATH` / `MTLS_KEY_PATH` / `MTLS_CA_PATH`, defaulting to
    /// `/opt/artisan/tls/<own_service>.{crt,key}` and `/opt/artisan/tls/ca.crt`
    /// -- same variable names the servers use, but this crate's default layout
    /// lives under `/opt/artisan` alongside the rest of this service's local
    /// software, not `/etc/artisan`.
    pub fn load(own_service: &str) -> Result<Self, String> {
        let dir = PathBuf::from("/opt/artisan/tls");
        let path = |var: &str, default: PathBuf| {
            std::env::var(var).map(PathBuf::from).unwrap_or(default)
        };
        let cert_path = path("MTLS_CERT_PATH", dir.join(format!("{own_service}.crt")));
        let key_path = path("MTLS_KEY_PATH", dir.join(format!("{own_service}.key")));
        let ca_path = path("MTLS_CA_PATH", dir.join("ca.crt"));

        let read = |p: &PathBuf, what: &str| {
            std::fs::read(p).map_err(|e| format!("failed to read {what} at {}: {e}", p.display()))
        };
        Ok(Self {
            identity: Identity::from_pem(read(&cert_path, "client cert")?, read(&key_path, "client key")?),
            ca: Certificate::from_pem(read(&ca_path, "CA cert")?),
        })
    }
}

/// True if `addr` asks for TLS. Lets a caller skip loading certificates at all
/// when it was pointed at a plaintext dev server.
pub fn wants_tls(addr: &str) -> bool {
    addr.starts_with("https://")
}

fn endpoint(addr: &str, server_name: &str, mtls: Option<&ClientMtls>) -> Result<Endpoint, String> {
    let endpoint = Channel::from_shared(addr.to_owned())
        .map_err(|e| format!("invalid gRPC address {addr:?}: {e}"))?;

    if !wants_tls(addr) {
        return Ok(endpoint);
    }

    let mtls = mtls.ok_or_else(|| {
        format!("{addr} is an https:// address but no client certificate was loaded")
    })?;
    let tls = ClientTlsConfig::new()
        .domain_name(server_name.to_owned())
        .ca_certificate(mtls.ca.clone())
        .identity(mtls.identity.clone());

    endpoint
        .tls_config(tls)
        .map_err(|e| format!("invalid TLS config for {addr}: {e}"))
}

/// Builds a lazily-connecting channel to an internal service.
///
/// Must be called from inside a Tokio runtime (`connect_lazy` registers with
/// the reactor). It performs no I/O -- a bad certificate or unreachable server
/// surfaces on the first RPC, as a normal `Status`, never as a panic here.
pub fn internal_channel(
    addr: &str,
    server_name: &str,
    mtls: Option<&ClientMtls>,
) -> Result<Channel, String> {
    Ok(endpoint(addr, server_name, mtls)?.connect_lazy())
}

/// Like [`internal_channel`] but dials now, so an unreachable server or a
/// failed handshake is reported here. For callers that want to fail fast and
/// retry later (a periodic sync loop) rather than discover it per-RPC.
pub async fn connect_internal(
    addr: &str,
    server_name: &str,
    mtls: Option<&ClientMtls>,
) -> Result<Channel, String> {
    endpoint(addr, server_name, mtls)?
        .connect()
        .await
        .map_err(|e| format!("connecting to {addr}: {e}"))
}

/// Loads this process's service credential -- the bearer secret ais_auth issued
/// it via `IssueServiceCredential`, presented to ais_secretserver /
/// RunpodManager in the `service_credential` field.
///
/// Read from the file named by `AIS_SERVICE_CREDENTIAL_FILE` if set (preferred:
/// a `0600` file keeps it out of `/proc/<pid>/environ` and `ps e`), otherwise
/// from `AIS_SERVICE_CREDENTIAL`. Surrounding whitespace is trimmed. It is a
/// secret: callers must not log it, and this crate never does.
///
/// This is the *fallback* path -- prefer [`obtain_service_session`] for a
/// GLOBAL-org platform-infra service (Manager, watchdog, gitmon), which needs
/// no manually-provisioned raw secret at all. This function still matters for
/// org-scoped services and local dev, and as what `obtain_service_session`
/// itself falls back to on any error.
pub fn load_service_credential() -> Result<String, String> {
    let raw = match std::env::var("AIS_SERVICE_CREDENTIAL_FILE") {
        Ok(path) => std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read AIS_SERVICE_CREDENTIAL_FILE {path}: {e}"))?,
        Err(_) => std::env::var("AIS_SERVICE_CREDENTIAL").map_err(|_| {
            "no service credential: set AIS_SERVICE_CREDENTIAL_FILE (or AIS_SERVICE_CREDENTIAL)"
                .to_owned()
        })?,
    };
    let credential = raw.trim().to_owned();
    if credential.is_empty() {
        return Err("the configured service credential is empty".to_owned());
    }
    Ok(credential)
}

/// RBAC Phase 5: `AccountInternal`'s `RequestServiceSession`/
/// `ResolveServiceIdentity`, generated from the same `ais_proto/accounts.proto`
/// ais_auth itself implements. Declared here (not in each crate's own
/// `secrets.rs`-style proto module) so `obtain_service_session` below is
/// fully self-contained.
pub mod account {
    tonic::include_proto!("accounts");
}

/// Default address for `ais_auth`. Matches its gRPC server's own default
/// bind port (`GRPC_ADDR`, `ais_auth/src/main.rs`, `0.0.0.0:50051`).
/// Override with `AIS_AUTH_ADDR`.
const DEFAULT_AIS_AUTH_ADDR: &str = "https://auth.ah.internal:50051";

/// Name in `ais_auth`'s server certificate's SAN (what `mtls_ca_tool issue`
/// was given). Override with `AIS_AUTH_TLS_NAME`.
const DEFAULT_AIS_AUTH_TLS_NAME: &str = "ais_auth";

/// In-process cache for [`obtain_service_session`]: the minted token, when it
/// was minted, and its granted TTL. Re-minted transparently once ~80% of
/// that TTL has elapsed, so a caller never has to think about expiry -- the
/// same "mint once, reuse until near-expiry" shape as `ais_auth`'s own
/// JWT-signing-key cache, just without needing a cold-path lock since this
/// runs on a single connect path per process, not concurrent request
/// handlers.
static SESSION_CACHE: once_cell::sync::Lazy<tokio::sync::Mutex<Option<(String, std::time::Instant, u64)>>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(None));

/// Mints (or reuses a cached, still-fresh) short-lived service session token
/// for `own_service` by calling ais_auth's `RequestServiceSession` over the
/// same mTLS channel [`ClientMtls::load`] already sets up -- the client
/// certificate on that channel *is* the credential; nothing else is sent.
///
/// GLOBAL-org platform-infra services only (v1) -- see
/// `ais_proto/accounts.proto`'s `RequestServiceSession` doc comment. Org-scoped
/// services should use [`load_service_credential`] instead.
pub async fn obtain_service_session(own_service: &str) -> Result<String, String> {
    {
        let cache = SESSION_CACHE.lock().await;
        if let Some((token, minted_at, ttl_secs)) = cache.as_ref() {
            let refresh_at = *minted_at + std::time::Duration::from_secs(ttl_secs * 4 / 5);
            if std::time::Instant::now() < refresh_at {
                return Ok(token.clone());
            }
        }
    }

    let addr = std::env::var("AIS_AUTH_ADDR").unwrap_or_else(|_| DEFAULT_AIS_AUTH_ADDR.to_owned());
    let server_name = std::env::var("AIS_AUTH_TLS_NAME").unwrap_or_else(|_| DEFAULT_AIS_AUTH_TLS_NAME.to_owned());
    let mtls = ClientMtls::load(own_service)?;
    let channel = connect_internal(&addr, &server_name, Some(&mtls)).await?;
    let mut client = account::account_internal_client::AccountInternalClient::new(channel);

    let response = client
        .request_service_session(account::RequestServiceSessionRequest { requested_ttl_secs: 0 })
        .await
        .map_err(|e| format!("RequestServiceSession failed: {e}"))?
        .into_inner();

    let mut cache = SESSION_CACHE.lock().await;
    *cache = Some((
        response.session_token.clone(),
        std::time::Instant::now(),
        response.expires_in.max(1) as u64,
    ));
    Ok(response.session_token)
}
