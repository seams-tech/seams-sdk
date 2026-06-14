#![forbid(unsafe_code)]
//! Local development adapters for Router/A/B signing.
//!
//! This crate may use local database drivers and filesystem-facing binaries.
//! The protocol crate remains transport-neutral and wasm-safe by default.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use ed25519_hss::fixtures::{committed_fixture_corpus, FExpandFixture};
use ed25519_hss::shared::{
    add_le_bytes_mod_2_256, eval_f_expand, public_key_from_base_shares, FExpandOutput,
};
use router_ab_core::{
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    router_transcript_digest_v1, CandidateId, CanonicalWireBytesV1, CorrectnessLevel,
    EncryptedPayloadV1, ExpensiveWorkKindV1, LifecycleScopeV1, LocalDeriverAEndpointV1,
    LocalDeriverBEndpointV1, LocalEnvSnapshotV1, LocalHttpCeremonyResultV1, LocalHttpMethodV1,
    LocalHttpPathV1, LocalHttpRequestV1, LocalInProcessCeremonyResultV1, LocalPersistenceSeedV1,
    LocalPersistenceSqlDialectV1, LocalPersistenceSqlExecutionReceiptV1,
    LocalPersistenceSqlSeedExecutorV1, LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1,
    LocalRouterEndpointV1, LocalRouterRecipientProofBundleResponseV1, LocalSealedRootShareRecordV1,
    LocalServiceRoleV1, LocalServiceStackV1, LocalServiceStartupV1, LocalSigningRootMetadataV1,
    LocalSigningWorkerEndpointV1, LocalSigningWorkerRecipientProofBundleActivationV1,
    LocalTransportEnvelopeV1, LocalTransportRouteV1, PublicRouterRequestV1, RelayerIdentityV1,
    RoleEncryptedEnvelopeV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterTranscriptMetadataV1, SignerIdentityV1, SignerSetV1,
    SigningRootShareStore, WireMessageKindV1, WireMessageV1,
};
use router_ab_core::{OpenedShareKind, PublicDigest32, Role, RootShareEpoch};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    time::Duration,
};

const LOCAL_ED25519_HSS_SPLIT_RELAYER_LABEL_V1: &[u8] =
    b"router-ab-dev/ed25519-hss/split-relayer/v1";
const LOCAL_NORMAL_SIGNING_SMOKE_LABEL_V1: &[u8] = b"router-ab-dev/normal-signing-smoke/v1";
const LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1: &str = "split-epoch-1";

/// Local worker role env key used by the four-process development harness.
pub const LOCAL_WORKER_ROLE_ENV_V1: &str = "ROUTER_AB_LOCAL_WORKER_ROLE";
/// Router public URL env key.
pub const LOCAL_ROUTER_PUBLIC_URL_ENV_V1: &str = "ROUTER_PUBLIC_URL";
/// Deriver A private URL env key.
pub const LOCAL_DERIVER_A_URL_ENV_V1: &str = "DERIVER_A_URL";
/// Deriver B private URL env key.
pub const LOCAL_DERIVER_B_URL_ENV_V1: &str = "DERIVER_B_URL";
/// SigningWorker private URL env key.
pub const LOCAL_SIGNING_WORKER_URL_ENV_V1: &str = "SIGNING_WORKER_URL";
/// Router replay storage path env key.
pub const LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1: &str = "ROUTER_REPLAY_STORAGE_PATH";
/// Router lifecycle storage path env key.
pub const LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1: &str = "ROUTER_LIFECYCLE_STORAGE_PATH";
/// Router project-policy storage path env key.
pub const LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1: &str =
    "ROUTER_PROJECT_POLICY_STORAGE_PATH";
/// Router quota storage path env key.
pub const LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1: &str = "ROUTER_QUOTA_STORAGE_PATH";
/// Router abuse storage path env key.
pub const LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1: &str = "ROUTER_ABUSE_STORAGE_PATH";
/// Deriver A envelope HPKE private-key env key.
pub const LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY";
/// Deriver B envelope HPKE private-key env key.
pub const LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY";
/// Deriver A root-share wire secret env key.
pub const LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1: &str = "DERIVER_A_ROOT_SHARE_WIRE_SECRET";
/// Deriver B root-share wire secret env key.
pub const LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1: &str = "DERIVER_B_ROOT_SHARE_WIRE_SECRET";
/// Deriver A peer signing key env key.
pub const LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1: &str = "DERIVER_A_PEER_SIGNING_KEY";
/// Deriver B peer signing key env key.
pub const LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1: &str = "DERIVER_B_PEER_SIGNING_KEY";
/// Deriver A peer verifying key env key.
pub const LOCAL_DERIVER_A_PEER_VERIFYING_KEY_ENV_V1: &str = "DERIVER_A_PEER_VERIFYING_KEY";
/// Deriver B peer verifying key env key.
pub const LOCAL_DERIVER_B_PEER_VERIFYING_KEY_ENV_V1: &str = "DERIVER_B_PEER_VERIFYING_KEY";
/// Deriver A root-share metadata storage path env key.
pub const LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1: &str =
    "DERIVER_A_ROOT_SHARE_STORAGE_PATH";
/// Deriver B root-share metadata storage path env key.
pub const LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1: &str =
    "DERIVER_B_ROOT_SHARE_STORAGE_PATH";
/// Deriver A sealed root-share storage path env key.
pub const LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1: &str =
    "DERIVER_A_SEALED_ROOT_SHARES_PATH";
/// Deriver B sealed root-share storage path env key.
pub const LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1: &str =
    "DERIVER_B_SEALED_ROOT_SHARES_PATH";
/// SigningWorker relayer-output HPKE private-key env key.
pub const LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY";
/// SigningWorker relayer-output storage path env key.
pub const LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH_ENV_V1: &str =
    "SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH";
/// SigningWorker public identity env key.
pub const LOCAL_SIGNING_WORKER_ID_ENV_V1: &str = "SIGNING_WORKER_ID";
/// SigningWorker key epoch env key.
pub const LOCAL_SIGNING_WORKER_KEY_EPOCH_ENV_V1: &str = "SIGNING_WORKER_KEY_EPOCH";
/// SigningWorker relayer-output HPKE public key env key.
pub const LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1: &str =
    "SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PUBLIC_KEY";
/// Generated Router env file path for local development.
pub const LOCAL_ROUTER_ENV_FILE_V1: &str = ".env.router-ab.router.local";
/// Generated Deriver A env file path for local development.
pub const LOCAL_DERIVER_A_ENV_FILE_V1: &str = ".env.router-ab.deriver-a.local";
/// Generated Deriver B env file path for local development.
pub const LOCAL_DERIVER_B_ENV_FILE_V1: &str = ".env.router-ab.deriver-b.local";
/// Generated SigningWorker env file path for local development.
pub const LOCAL_SIGNING_WORKER_ENV_FILE_V1: &str = ".env.router-ab.signing-worker.local";
/// Local Router state directory.
pub const LOCAL_ROUTER_STATE_DIR_V1: &str = ".router-ab-local/router";
/// Local Deriver A state directory.
pub const LOCAL_DERIVER_A_STATE_DIR_V1: &str = ".router-ab-local/deriver-a";
/// Local Deriver B state directory.
pub const LOCAL_DERIVER_B_STATE_DIR_V1: &str = ".router-ab-local/deriver-b";
/// Local SigningWorker state directory.
pub const LOCAL_SIGNING_WORKER_STATE_DIR_V1: &str = ".router-ab-local/signing-worker";
/// Local worker startup epoch for redacted diagnostics.
pub const LOCAL_WORKER_STARTUP_EPOCH_V1: &str = "local-dev-v1";
/// Local health endpoint path.
pub const LOCAL_WORKER_HEALTH_PATH_V1: &str = "/healthz";
/// Local readiness endpoint path.
pub const LOCAL_WORKER_READY_PATH_V1: &str = "/readyz";
/// Router public setup/export/refresh path mirrored from production.
pub const LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1: &str = "/v1/hss/split-derivation";
/// Router public normal-signing path mirrored from production.
pub const LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1: &str = "/v1/hss/sign";
/// Deriver A private Router-dispatch path mirrored from production.
pub const LOCAL_DERIVER_A_PRIVATE_PATH_V1: &str = "/router-ab/v1/signer-a";
/// Deriver B private Router-dispatch path mirrored from production.
pub const LOCAL_DERIVER_B_PRIVATE_PATH_V1: &str = "/router-ab/v1/signer-b";
/// Deriver A private peer path mirrored from production.
pub const LOCAL_DERIVER_A_PEER_PATH_V1: &str = "/router-ab/v1/signer-a/peer";
/// Deriver B private peer path mirrored from production.
pub const LOCAL_DERIVER_B_PEER_PATH_V1: &str = "/router-ab/v1/signer-b/peer";
/// SigningWorker activation path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1: &str =
    "/router-ab/v1/signing-worker/proof-bundle-activation";
/// SigningWorker normal-signing path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1: &str = "/router-ab/v1/signing-worker/sign";
/// Local HTTP service-binding content type for canonical protocol bytes.
pub const LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1: &str = "application/octet-stream";
/// Local HTTP service-binding content type for Worker-shaped JSON protocol calls.
pub const LOCAL_HTTP_JSON_CONTENT_TYPE_V1: &str = "application/json";
/// Default local HTTP service-binding timeout.
pub const LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1: u64 = 10_000;

const LOCAL_ROUTER_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH_ENV_V1,
];

const LOCAL_DERIVER_A_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH_ENV_V1,
];

const LOCAL_DERIVER_B_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH_ENV_V1,
];

const LOCAL_SIGNING_WORKER_FORBIDDEN_ENV_KEYS_V1: &[&str] = &[
    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1,
    LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
    LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
    LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
    LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
];

/// Router local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalRouterWorkerConfigV1 {
    /// Router public URL.
    pub public_url: String,
    /// Deriver A private URL.
    pub deriver_a_url: String,
    /// Deriver B private URL.
    pub deriver_b_url: String,
    /// SigningWorker private URL.
    pub signing_worker_url: String,
    /// Router replay storage path.
    pub replay_storage_path: String,
    /// Router lifecycle storage path.
    pub lifecycle_storage_path: String,
    /// Router project-policy storage path.
    pub project_policy_storage_path: String,
    /// Router quota storage path.
    pub quota_storage_path: String,
    /// Router abuse storage path.
    pub abuse_storage_path: String,
}

/// Deriver A local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDeriverAWorkerConfigV1 {
    /// Deriver A private URL.
    pub deriver_a_url: String,
    /// Deriver B private URL.
    pub deriver_b_url: String,
    /// Deriver A envelope HPKE private key.
    pub envelope_hpke_private_key: String,
    /// Deriver A root-share wire secret.
    pub root_share_wire_secret: String,
    /// Deriver A peer signing key.
    pub peer_signing_key: String,
    /// Deriver A peer verifying key.
    pub deriver_a_peer_verifying_key: String,
    /// Deriver B peer verifying key.
    pub deriver_b_peer_verifying_key: String,
    /// Deriver A root-share metadata storage path.
    pub root_share_storage_path: String,
    /// Deriver A sealed root-share storage path.
    pub sealed_root_shares_path: String,
}

/// Deriver B local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDeriverBWorkerConfigV1 {
    /// Deriver B private URL.
    pub deriver_b_url: String,
    /// Deriver A private URL.
    pub deriver_a_url: String,
    /// Deriver B envelope HPKE private key.
    pub envelope_hpke_private_key: String,
    /// Deriver B root-share wire secret.
    pub root_share_wire_secret: String,
    /// Deriver B peer signing key.
    pub peer_signing_key: String,
    /// Deriver A peer verifying key.
    pub deriver_a_peer_verifying_key: String,
    /// Deriver B peer verifying key.
    pub deriver_b_peer_verifying_key: String,
    /// Deriver B root-share metadata storage path.
    pub root_share_storage_path: String,
    /// Deriver B sealed root-share storage path.
    pub sealed_root_shares_path: String,
}

/// SigningWorker local worker config after raw env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSigningWorkerConfigV1 {
    /// SigningWorker private URL.
    pub signing_worker_url: String,
    /// SigningWorker public identity.
    pub signing_worker_id: String,
    /// SigningWorker key epoch.
    pub signing_worker_key_epoch: String,
    /// SigningWorker relayer-output HPKE public key.
    pub relayer_output_hpke_public_key: String,
    /// SigningWorker relayer-output HPKE private key.
    pub relayer_output_hpke_private_key: String,
    /// SigningWorker relayer-output storage path.
    pub relayer_output_storage_path: String,
}

/// Redacted local worker health response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalWorkerHealthResponseV1 {
    /// Local worker role.
    pub role: LocalServiceRoleV1,
    /// Stable role label.
    pub role_label: String,
    /// URL this worker is expected to bind.
    pub bind_url: String,
    /// Redacted startup status.
    pub status: String,
    /// Local startup epoch safe for diagnostics.
    pub startup_epoch: String,
    /// Config branch label safe for diagnostics.
    pub config_branch: String,
}

/// Role-specific local worker config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum LocalWorkerRoleConfigV1 {
    /// Router config branch.
    Router(LocalRouterWorkerConfigV1),
    /// Deriver A config branch.
    DeriverA(LocalDeriverAWorkerConfigV1),
    /// Deriver B config branch.
    DeriverB(LocalDeriverBWorkerConfigV1),
    /// SigningWorker config branch.
    SigningWorker(LocalSigningWorkerConfigV1),
}

impl LocalWorkerRoleConfigV1 {
    /// Returns this config's local service role.
    pub fn role(&self) -> LocalServiceRoleV1 {
        match self {
            Self::Router(_) => LocalServiceRoleV1::Router,
            Self::DeriverA(_) => LocalServiceRoleV1::DeriverA,
            Self::DeriverB(_) => LocalServiceRoleV1::DeriverB,
            Self::SigningWorker(_) => LocalServiceRoleV1::SigningWorker,
        }
    }

    /// Returns the configured local URL for this worker.
    pub fn bind_url(&self) -> &str {
        match self {
            Self::Router(config) => &config.public_url,
            Self::DeriverA(config) => &config.deriver_a_url,
            Self::DeriverB(config) => &config.deriver_b_url,
            Self::SigningWorker(config) => &config.signing_worker_url,
        }
    }
}

/// Returns the host:port bind address from one local worker config.
pub fn local_worker_bind_addr_v1(
    config: &LocalWorkerRoleConfigV1,
) -> RouterAbProtocolResult<String> {
    parse_http_bind_addr_v1(config.bind_url())
}

/// Returns known local HTTP paths owned by one worker role.
pub fn local_worker_owned_paths_v1(role: LocalServiceRoleV1) -> &'static [&'static str] {
    match role {
        LocalServiceRoleV1::Router => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1,
            LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1,
        ],
        LocalServiceRoleV1::DeriverA => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_DERIVER_A_PRIVATE_PATH_V1,
            LOCAL_DERIVER_A_PEER_PATH_V1,
        ],
        LocalServiceRoleV1::DeriverB => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_DERIVER_B_PRIVATE_PATH_V1,
            LOCAL_DERIVER_B_PEER_PATH_V1,
        ],
        LocalServiceRoleV1::SigningWorker => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
        ],
    }
}

/// Returns true when a path is owned by the selected local worker role.
pub fn local_worker_owns_path_v1(role: LocalServiceRoleV1, path: &str) -> bool {
    local_worker_owned_paths_v1(role).contains(&path)
}

/// Builds a redacted health response for one local worker config.
pub fn local_worker_health_response_v1(
    config: &LocalWorkerRoleConfigV1,
) -> RouterAbProtocolResult<LocalWorkerHealthResponseV1> {
    let bind_url = config.bind_url();
    require_non_empty("local worker bind URL", bind_url)?;
    Ok(LocalWorkerHealthResponseV1 {
        role: config.role(),
        role_label: config.role().as_str().to_owned(),
        bind_url: bind_url.to_owned(),
        status: "ready".to_owned(),
        startup_epoch: LOCAL_WORKER_STARTUP_EPOCH_V1.to_owned(),
        config_branch: config.role().as_str().to_owned(),
    })
}

/// Builds a redacted health response JSON body for one local worker config.
pub fn local_worker_health_response_json_v1(
    config: &LocalWorkerRoleConfigV1,
) -> RouterAbProtocolResult<String> {
    serde_json::to_string(&local_worker_health_response_v1(config)?).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker health response JSON failed: {error}"),
        )
    })
}

/// Parsed local HTTP service-binding endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHttpServiceBindingEndpointV1 {
    /// Role that owns the target path.
    pub owner: LocalServiceRoleV1,
    /// Full URL requested by the local transport.
    pub url: String,
    /// Host header value.
    pub host_header: String,
    /// Host:port address used by `TcpStream`.
    pub bind_addr: String,
    /// Production-style request path.
    pub path: String,
}

/// Blocking local HTTP client for service-binding parity tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHttpServiceBindingClientV1 {
    timeout: Duration,
}

impl LocalHttpServiceBindingClientV1 {
    /// Creates a local HTTP service-binding client with a non-zero timeout.
    pub fn new(timeout: Duration) -> RouterAbProtocolResult<Self> {
        if timeout.is_zero() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local HTTP service-binding timeout must be non-zero",
            ));
        }
        Ok(Self { timeout })
    }

    /// Posts canonical wire bytes to one checked local service-binding path.
    pub fn post_canonical_wire_bytes_v1(
        &self,
        base_url: &str,
        path: LocalHttpPathV1,
        body: &CanonicalWireBytesV1,
    ) -> RouterAbProtocolResult<CanonicalWireBytesV1> {
        let endpoint = local_http_service_binding_endpoint_v1(base_url, path)?;
        let response_body = self.post_bytes_to_endpoint_v1(
            &endpoint,
            LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1,
            body.as_bytes(),
        )?;
        CanonicalWireBytesV1::new(response_body)
    }

    /// Posts JSON to one checked local service-binding path and parses JSON response.
    pub fn post_json_v1<Request, Response>(
        &self,
        base_url: &str,
        path: LocalHttpPathV1,
        body: &Request,
    ) -> RouterAbProtocolResult<Response>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let endpoint = local_http_service_binding_endpoint_v1(base_url, path)?;
        let request_body = serde_json::to_vec(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local HTTP service-binding JSON request serialization failed: {error}"),
            )
        })?;
        let response_body = self.post_bytes_to_endpoint_v1(
            &endpoint,
            LOCAL_HTTP_JSON_CONTENT_TYPE_V1,
            &request_body,
        )?;
        serde_json::from_slice(&response_body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local HTTP service-binding JSON response parse failed: {error}"),
            )
        })
    }

    fn post_bytes_to_endpoint_v1(
        &self,
        endpoint: &LocalHttpServiceBindingEndpointV1,
        content_type: &str,
        body: &[u8],
    ) -> RouterAbProtocolResult<Vec<u8>> {
        let mut stream = TcpStream::connect(&endpoint.bind_addr).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!(
                    "local HTTP service-binding connect to {} failed: {error}",
                    endpoint.bind_addr
                ),
            )
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    format!("local HTTP service-binding read-timeout setup failed: {error}"),
                )
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    format!("local HTTP service-binding write-timeout setup failed: {error}"),
                )
            })?;

        write!(
            stream,
            "POST {} HTTP/1.1\r\nhost: {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            endpoint.path,
            endpoint.host_header,
            content_type,
            body.len()
        )
        .map_err(map_local_http_io_error_v1)?;
        stream.write_all(body).map_err(map_local_http_io_error_v1)?;
        stream.flush().map_err(map_local_http_io_error_v1)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(map_local_http_io_error_v1)?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(map_local_http_io_error_v1)?;
        let (status, response_body) = split_local_http_response_v1(&response)?;
        if !(200..=299).contains(&status) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("local HTTP service-binding request failed with status {status}"),
            ));
        }
        Ok(response_body)
    }
}

impl Default for LocalHttpServiceBindingClientV1 {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1),
        }
    }
}

/// Returns the production-style path for a checked local transport path.
pub fn local_http_service_binding_path_v1(path: LocalHttpPathV1) -> &'static str {
    match path {
        LocalHttpPathV1::RouterToSignerA => LOCAL_DERIVER_A_PRIVATE_PATH_V1,
        LocalHttpPathV1::RouterToSignerB => LOCAL_DERIVER_B_PRIVATE_PATH_V1,
        LocalHttpPathV1::SignerAToSignerB => LOCAL_DERIVER_B_PEER_PATH_V1,
        LocalHttpPathV1::SignerBToSignerA => LOCAL_DERIVER_A_PEER_PATH_V1,
    }
}

/// Returns the destination role that owns a checked local transport path.
pub fn local_http_service_binding_owner_v1(path: LocalHttpPathV1) -> LocalServiceRoleV1 {
    match path {
        LocalHttpPathV1::RouterToSignerA | LocalHttpPathV1::SignerBToSignerA => {
            LocalServiceRoleV1::DeriverA
        }
        LocalHttpPathV1::RouterToSignerB | LocalHttpPathV1::SignerAToSignerB => {
            LocalServiceRoleV1::DeriverB
        }
    }
}

/// Builds the full production-style local service-binding URL for a base URL.
pub fn local_http_service_binding_url_v1(
    base_url: &str,
    path: LocalHttpPathV1,
) -> RouterAbProtocolResult<String> {
    require_non_empty("local HTTP service-binding base URL", base_url)?;
    let route_path = local_http_service_binding_path_v1(path);
    let base = base_url.trim_end_matches('/');
    Ok(format!("{base}{route_path}"))
}

/// Builds the parsed endpoint used by the blocking local HTTP transport.
pub fn local_http_service_binding_endpoint_v1(
    base_url: &str,
    path: LocalHttpPathV1,
) -> RouterAbProtocolResult<LocalHttpServiceBindingEndpointV1> {
    let url = local_http_service_binding_url_v1(base_url, path)?;
    let parts = parse_http_url_parts_v1(&url)?;
    let owner = local_http_service_binding_owner_v1(path);
    if !local_worker_owns_path_v1(owner, &parts.path) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "local HTTP service-binding path {} is not owned by {}",
                parts.path,
                owner.as_str()
            ),
        ));
    }
    Ok(LocalHttpServiceBindingEndpointV1 {
        owner,
        url,
        host_header: parts.authority.clone(),
        bind_addr: parts.authority,
        path: parts.path,
    })
}

/// Local Durable Object storage scope for the four-process harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDurableObjectScopeV1 {
    /// Router replay and idempotency state.
    RouterReplay,
    /// Router public lifecycle state.
    RouterLifecycle,
    /// Router project-policy state.
    RouterProjectPolicy,
    /// Router quota and request-budget state.
    RouterQuota,
    /// Router abuse-control state.
    RouterAbuse,
    /// Deriver A root-share metadata and sealed-share state.
    DeriverARootShare,
    /// Deriver B root-share metadata and sealed-share state.
    DeriverBRootShare,
    /// SigningWorker activation and active relayer-output state.
    SigningWorkerRelayerOutput,
}

impl LocalDurableObjectScopeV1 {
    /// Returns the stable local storage scope label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouterReplay => "router_replay",
            Self::RouterLifecycle => "router_lifecycle",
            Self::RouterProjectPolicy => "router_project_policy",
            Self::RouterQuota => "router_quota",
            Self::RouterAbuse => "router_abuse",
            Self::DeriverARootShare => "deriver_a_root_share",
            Self::DeriverBRootShare => "deriver_b_root_share",
            Self::SigningWorkerRelayerOutput => "signing_worker_relayer_output",
        }
    }

    /// Returns the worker role that owns this local storage scope.
    pub fn owner(self) -> LocalServiceRoleV1 {
        match self {
            Self::RouterReplay
            | Self::RouterLifecycle
            | Self::RouterProjectPolicy
            | Self::RouterQuota
            | Self::RouterAbuse => LocalServiceRoleV1::Router,
            Self::DeriverARootShare => LocalServiceRoleV1::DeriverA,
            Self::DeriverBRootShare => LocalServiceRoleV1::DeriverB,
            Self::SigningWorkerRelayerOutput => LocalServiceRoleV1::SigningWorker,
        }
    }
}

/// SQLite-backed local Durable Object key/value storage.
#[derive(Debug)]
pub struct LocalDurableObjectSqliteStorageV1<'connection> {
    connection: &'connection Connection,
    scope: LocalDurableObjectScopeV1,
}

impl<'connection> LocalDurableObjectSqliteStorageV1<'connection> {
    /// Creates a role-scoped local Durable Object store.
    pub fn new(
        connection: &'connection Connection,
        scope: LocalDurableObjectScopeV1,
    ) -> RouterAbProtocolResult<Self> {
        ensure_local_durable_object_sqlite_schema_v1(connection)?;
        Ok(Self { connection, scope })
    }

    /// Returns this store's local Durable Object scope.
    pub fn scope(&self) -> LocalDurableObjectScopeV1 {
        self.scope
    }

    /// Returns the worker role that owns this store.
    pub fn owner(&self) -> LocalServiceRoleV1 {
        self.scope.owner()
    }

    /// Stores non-empty bytes under a role-local key.
    pub fn put_bytes(&self, key: &str, value: &[u8]) -> RouterAbProtocolResult<()> {
        require_non_empty("local durable object key", key)?;
        if value.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::EmptyField,
                "local durable object value must not be empty",
            ));
        }
        self.connection
            .execute(
                "
                INSERT INTO local_durable_object_kv (scope, key, value)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value
                ",
                params![self.scope.as_str(), key, value],
            )
            .map_err(map_sqlite_error)?;
        Ok(())
    }

    /// Reads bytes from a role-local key.
    pub fn get_bytes(&self, key: &str) -> RouterAbProtocolResult<Option<Vec<u8>>> {
        require_non_empty("local durable object key", key)?;
        self.connection
            .query_row(
                "SELECT value FROM local_durable_object_kv WHERE scope = ?1 AND key = ?2",
                params![self.scope.as_str(), key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(map_sqlite_error)
    }

    /// Deletes one role-local key and returns whether a row was removed.
    pub fn delete_key(&self, key: &str) -> RouterAbProtocolResult<bool> {
        require_non_empty("local durable object key", key)?;
        let rows = self
            .connection
            .execute(
                "DELETE FROM local_durable_object_kv WHERE scope = ?1 AND key = ?2",
                params![self.scope.as_str(), key],
            )
            .map_err(map_sqlite_error)?;
        Ok(rows > 0)
    }

    /// Lists keys in this role-local store.
    pub fn list_keys(&self) -> RouterAbProtocolResult<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT key FROM local_durable_object_kv WHERE scope = ?1 ORDER BY key")
            .map_err(map_sqlite_error)?;
        let rows = statement
            .query_map(params![self.scope.as_str()], |row| row.get::<_, String>(0))
            .map_err(map_sqlite_error)?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(map_sqlite_error)?);
        }
        Ok(keys)
    }
}

/// One deterministic local Durable Object seed entry.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalDurableObjectSeedEntryV1 {
    /// Scope that owns the seed entry.
    pub scope: LocalDurableObjectScopeV1,
    /// Role-local key.
    pub key: String,
    value: Vec<u8>,
}

impl LocalDurableObjectSeedEntryV1 {
    /// Creates a validated local Durable Object seed entry.
    pub fn new(
        scope: LocalDurableObjectScopeV1,
        key: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> RouterAbProtocolResult<Self> {
        let entry = Self {
            scope,
            key: key.into(),
            value: value.into(),
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Returns the seed value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Validates required seed fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("local durable object seed key", &self.key)?;
        if self.value.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::EmptyField,
                "local durable object seed value must not be empty",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LocalDurableObjectSeedEntryV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalDurableObjectSeedEntryV1")
            .field("scope", &self.scope)
            .field("key", &self.key)
            .field("value_len", &self.value.len())
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Deterministic local Durable Object seed plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDurableObjectSeedPlanV1 {
    /// Entries to write.
    pub entries: Vec<LocalDurableObjectSeedEntryV1>,
}

impl LocalDurableObjectSeedPlanV1 {
    /// Creates a validated local Durable Object seed plan.
    pub fn new(entries: Vec<LocalDurableObjectSeedEntryV1>) -> RouterAbProtocolResult<Self> {
        if entries.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::EmptyField,
                "local durable object seed plan requires at least one entry",
            ));
        }
        for entry in &entries {
            entry.validate()?;
        }
        Ok(Self { entries })
    }
}

/// Redacted receipt from a local Durable Object seed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDurableObjectSeedReceiptV1 {
    /// Number of entries written.
    pub written_entry_count: u32,
    /// Scope labels touched by the seed operation.
    pub scope_labels: Vec<String>,
}

/// Redacted receipt from seeding all local storage parity state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalStorageParitySeedReceiptV1 {
    /// SQL seed receipt for signing-root metadata.
    pub signing_root_metadata: LocalPersistenceSqlExecutionReceiptV1,
    /// Durable Object seed receipt.
    pub durable_objects: LocalDurableObjectSeedReceiptV1,
}

/// Returns the deterministic local Durable Object seed plan used by smoke tests.
pub fn example_local_durable_object_seed_plan_v1(
) -> RouterAbProtocolResult<LocalDurableObjectSeedPlanV1> {
    LocalDurableObjectSeedPlanV1::new(vec![
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterReplay,
            "replay/request/dev",
            br#"{"state":"available"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterLifecycle,
            "lifecycle/dev",
            br#"{"state":"initialized"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterProjectPolicy,
            "project/default",
            br#"{"admission":"allow"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterQuota,
            "quota/default",
            br#"{"remaining":1}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::RouterAbuse,
            "abuse/default",
            br#"{"decision":"allow"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::DeriverARootShare,
            "sealed/share/a",
            b"local-dev-sealed-root-share-a".to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::DeriverBRootShare,
            "sealed/share/b",
            b"local-dev-sealed-root-share-b".to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::SigningWorkerRelayerOutput,
            "activation/dev",
            br#"{"state":"activated"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::SigningWorkerRelayerOutput,
            "active-state/dev",
            br#"{"state":"active"}"#.to_vec(),
        )?,
    ])
}

/// Seeds local Durable Object SQLite storage with deterministic smoke state.
pub fn seed_example_local_durable_object_sqlite_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalDurableObjectSeedReceiptV1> {
    let plan = example_local_durable_object_seed_plan_v1()?;
    seed_local_durable_object_sqlite_v1(connection, &plan)
}

/// Seeds local Durable Object SQLite storage from a validated plan.
pub fn seed_local_durable_object_sqlite_v1(
    connection: &Connection,
    plan: &LocalDurableObjectSeedPlanV1,
) -> RouterAbProtocolResult<LocalDurableObjectSeedReceiptV1> {
    if plan.entries.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            "local durable object seed plan requires at least one entry",
        ));
    }
    let mut scope_labels = Vec::<String>::new();
    for entry in &plan.entries {
        entry.validate()?;
        let store = LocalDurableObjectSqliteStorageV1::new(connection, entry.scope)?;
        store.put_bytes(&entry.key, entry.value())?;
        let scope_label = entry.scope.as_str().to_owned();
        if !scope_labels.contains(&scope_label) {
            scope_labels.push(scope_label);
        }
    }
    let written_entry_count = u32::try_from(plan.entries.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local durable object seed entry count did not fit u32",
        )
    })?;
    Ok(LocalDurableObjectSeedReceiptV1 {
        written_entry_count,
        scope_labels,
    })
}

/// Seeds deterministic signing-root metadata and local Durable Object state.
pub fn seed_example_local_storage_parity_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalStorageParitySeedReceiptV1> {
    Ok(LocalStorageParitySeedReceiptV1 {
        signing_root_metadata: seed_example_local_sqlite_v1(connection)?,
        durable_objects: seed_example_local_durable_object_sqlite_v1(connection)?,
    })
}

/// One generated local env file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEnvMaterializedFileV1 {
    /// Role that owns this env file.
    pub role: LocalServiceRoleV1,
    /// Relative path to write.
    pub path: String,
    /// File contents.
    pub contents: String,
}

/// Files and directories needed by the local Router/A/B dev harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEnvMaterializationPlanV1 {
    /// Directories to create before writing env files.
    pub directories: Vec<String>,
    /// Env files to write.
    pub files: Vec<LocalEnvMaterializedFileV1>,
}

impl LocalEnvMaterializationPlanV1 {
    /// Validates every generated env file parses into the matching role branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_exact_len_v1(
            "local env materialization directories",
            self.directories.len(),
            4,
        )?;
        require_exact_len_v1("local env materialization files", self.files.len(), 4)?;
        for directory in &self.directories {
            require_non_empty("local state directory", directory)?;
        }
        for file in &self.files {
            require_non_empty("local env file path", &file.path)?;
            require_non_empty("local env file contents", &file.contents)?;
            let config = parse_local_worker_role_config_for_role_v1(
                file.role,
                parse_local_env_file_contents_v1(&file.contents)?,
            )?;
            if config.role() != file.role {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "local env materialization produced wrong role branch",
                ));
            }
        }
        Ok(())
    }
}

/// Builds generated local env files and state directories from a caller-provided seed.
pub fn local_env_materialization_plan_v1(
    seed: &[u8],
) -> RouterAbProtocolResult<LocalEnvMaterializationPlanV1> {
    require_non_empty("local env materialization seed", &hex::encode(seed))?;
    let plan = LocalEnvMaterializationPlanV1 {
        directories: vec![
            LOCAL_ROUTER_STATE_DIR_V1.to_owned(),
            LOCAL_DERIVER_A_STATE_DIR_V1.to_owned(),
            LOCAL_DERIVER_B_STATE_DIR_V1.to_owned(),
            LOCAL_SIGNING_WORKER_STATE_DIR_V1.to_owned(),
        ],
        files: vec![
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::Router,
                path: LOCAL_ROUTER_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/router.local.example"),
                    seed,
                )?,
            },
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::DeriverA,
                path: LOCAL_DERIVER_A_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/deriver-a.local.example"),
                    seed,
                )?,
            },
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::DeriverB,
                path: LOCAL_DERIVER_B_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/deriver-b.local.example"),
                    seed,
                )?,
            },
            LocalEnvMaterializedFileV1 {
                role: LocalServiceRoleV1::SigningWorker,
                path: LOCAL_SIGNING_WORKER_ENV_FILE_V1.to_owned(),
                contents: materialize_template_v1(
                    include_str!("../env/signing-worker.local.example"),
                    seed,
                )?,
            },
        ],
    };
    plan.validate()?;
    Ok(plan)
}

/// Parses simple `KEY=value` local env file contents.
pub fn parse_local_env_file_contents_v1(
    contents: &str,
) -> RouterAbProtocolResult<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("local env line {} must use KEY=value", index + 1),
            ));
        };
        entries.push((key.to_owned(), value.to_owned()));
    }
    Ok(entries)
}

/// Parses one local worker role label.
pub fn parse_local_service_role_label_v1(
    label: &str,
) -> RouterAbProtocolResult<LocalServiceRoleV1> {
    match label {
        "router" => Ok(LocalServiceRoleV1::Router),
        "deriver-a" | "deriver_a" => Ok(LocalServiceRoleV1::DeriverA),
        "deriver-b" | "deriver_b" => Ok(LocalServiceRoleV1::DeriverB),
        "signing-worker" | "signing_worker" => Ok(LocalServiceRoleV1::SigningWorker),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("unknown local worker role '{label}'"),
        )),
    }
}

/// Parses raw local worker env entries into one role-specific config branch.
pub fn parse_local_worker_role_config_v1(
    entries: impl IntoIterator<Item = (String, String)>,
) -> RouterAbProtocolResult<LocalWorkerRoleConfigV1> {
    let env = local_env_map_v1(entries)?;
    let role =
        parse_local_service_role_label_v1(&required_env_v1(&env, LOCAL_WORKER_ROLE_ENV_V1)?)?;
    parse_local_worker_role_config_for_role_v1(role, entries_from_env_map_v1(&env))
}

/// Parses raw local worker env entries for a CLI-selected role and checks env role agreement.
pub fn parse_local_worker_role_config_for_role_v1(
    expected_role: LocalServiceRoleV1,
    entries: impl IntoIterator<Item = (String, String)>,
) -> RouterAbProtocolResult<LocalWorkerRoleConfigV1> {
    let env = local_env_map_v1(entries)?;
    let actual_role =
        parse_local_service_role_label_v1(&required_env_v1(&env, LOCAL_WORKER_ROLE_ENV_V1)?)?;
    if actual_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "local worker env role {} does not match selected role {}",
                actual_role.as_str(),
                expected_role.as_str()
            ),
        ));
    }
    match expected_role {
        LocalServiceRoleV1::Router => {
            reject_forbidden_env_keys_v1(&env, LOCAL_ROUTER_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::Router(LocalRouterWorkerConfigV1 {
                public_url: required_env_v1(&env, LOCAL_ROUTER_PUBLIC_URL_ENV_V1)?,
                deriver_a_url: required_env_v1(&env, LOCAL_DERIVER_A_URL_ENV_V1)?,
                deriver_b_url: required_env_v1(&env, LOCAL_DERIVER_B_URL_ENV_V1)?,
                signing_worker_url: required_env_v1(&env, LOCAL_SIGNING_WORKER_URL_ENV_V1)?,
                replay_storage_path: required_env_v1(
                    &env,
                    LOCAL_ROUTER_REPLAY_STORAGE_PATH_ENV_V1,
                )?,
                lifecycle_storage_path: required_env_v1(
                    &env,
                    LOCAL_ROUTER_LIFECYCLE_STORAGE_PATH_ENV_V1,
                )?,
                project_policy_storage_path: required_env_v1(
                    &env,
                    LOCAL_ROUTER_PROJECT_POLICY_STORAGE_PATH_ENV_V1,
                )?,
                quota_storage_path: required_env_v1(&env, LOCAL_ROUTER_QUOTA_STORAGE_PATH_ENV_V1)?,
                abuse_storage_path: required_env_v1(&env, LOCAL_ROUTER_ABUSE_STORAGE_PATH_ENV_V1)?,
            }))
        }
        LocalServiceRoleV1::DeriverA => {
            reject_forbidden_env_keys_v1(&env, LOCAL_DERIVER_A_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::DeriverA(
                LocalDeriverAWorkerConfigV1 {
                    deriver_a_url: required_env_v1(&env, LOCAL_DERIVER_A_URL_ENV_V1)?,
                    deriver_b_url: required_env_v1(&env, LOCAL_DERIVER_B_URL_ENV_V1)?,
                    envelope_hpke_private_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    root_share_wire_secret: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ROOT_SHARE_WIRE_SECRET_ENV_V1,
                    )?,
                    peer_signing_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
                    )?,
                    deriver_a_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    deriver_b_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    root_share_storage_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_ROOT_SHARE_STORAGE_PATH_ENV_V1,
                    )?,
                    sealed_root_shares_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_SEALED_ROOT_SHARES_PATH_ENV_V1,
                    )?,
                },
            ))
        }
        LocalServiceRoleV1::DeriverB => {
            reject_forbidden_env_keys_v1(&env, LOCAL_DERIVER_B_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::DeriverB(
                LocalDeriverBWorkerConfigV1 {
                    deriver_b_url: required_env_v1(&env, LOCAL_DERIVER_B_URL_ENV_V1)?,
                    deriver_a_url: required_env_v1(&env, LOCAL_DERIVER_A_URL_ENV_V1)?,
                    envelope_hpke_private_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    root_share_wire_secret: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ROOT_SHARE_WIRE_SECRET_ENV_V1,
                    )?,
                    peer_signing_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
                    )?,
                    deriver_a_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_A_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    deriver_b_peer_verifying_key: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_PEER_VERIFYING_KEY_ENV_V1,
                    )?,
                    root_share_storage_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_ROOT_SHARE_STORAGE_PATH_ENV_V1,
                    )?,
                    sealed_root_shares_path: required_env_v1(
                        &env,
                        LOCAL_DERIVER_B_SEALED_ROOT_SHARES_PATH_ENV_V1,
                    )?,
                },
            ))
        }
        LocalServiceRoleV1::SigningWorker => {
            reject_forbidden_env_keys_v1(&env, LOCAL_SIGNING_WORKER_FORBIDDEN_ENV_KEYS_V1)?;
            Ok(LocalWorkerRoleConfigV1::SigningWorker(
                LocalSigningWorkerConfigV1 {
                    signing_worker_url: required_env_v1(&env, LOCAL_SIGNING_WORKER_URL_ENV_V1)?,
                    signing_worker_id: required_env_v1(&env, LOCAL_SIGNING_WORKER_ID_ENV_V1)?,
                    signing_worker_key_epoch: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_KEY_EPOCH_ENV_V1,
                    )?,
                    relayer_output_hpke_public_key: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1,
                    )?,
                    relayer_output_hpke_private_key: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    relayer_output_storage_path: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH_ENV_V1,
                    )?,
                },
            ))
        }
    }
}

/// Summary read back from local SQLite after seeding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSqliteSeedSummaryV1 {
    /// Number of signing-root metadata rows.
    pub signing_root_count: u32,
    /// Number of sealed root-share rows.
    pub sealed_share_count: u32,
    /// Signer roles present in sealed-share storage.
    pub signer_roles: Vec<String>,
}

/// Successful signer startup check against local SQLite share storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSqliteSignerStartupCheckV1 {
    /// Signer set that owns the checked root share.
    pub signer_set_id: String,
    /// Signer role checked at startup.
    pub role: Role,
    /// Root-share epoch checked at startup.
    pub root_share_epoch: RootShareEpoch,
    /// Signer id stored with the sealed share.
    pub signer_id: String,
    /// Signer key epoch stored with the sealed share.
    pub signer_key_epoch: String,
    /// Storage key for the sealed share blob.
    pub sealed_share_storage_key: String,
}

/// Public commitment to one role's local HSS relayer-input shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssSplitRelayerRoleCommitmentV1 {
    /// Deriver role that owns this split input share.
    pub role: Role,
    /// SHA-256 commitment to this role's `y_relayer` share.
    pub y_relayer_share_commitment_hex: String,
    /// SHA-256 commitment to this role's `tau_relayer` share.
    pub tau_relayer_share_commitment_hex: String,
}

/// Public parity evidence from the local HSS split-relayer dev adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssSplitRelayerParityReportV1 {
    /// Committed `ed25519-hss` fixture name.
    pub fixture_name: String,
    /// Local split epoch used to derive role-specific relayer-input shares.
    pub split_epoch: String,
    /// Fixture HSS context binding.
    pub context_binding_hex: String,
    /// Public key derived from recipient-opened base shares.
    pub public_key_hex: String,
    /// Product-facing NEAR Ed25519 public key representation.
    pub near_public_key: String,
    /// Commitment to the client-side base share opened by the client role.
    pub x_client_base_commitment_hex: String,
    /// Commitment to the SigningWorker-side base share opened by the worker role.
    pub x_relayer_base_commitment_hex: String,
    /// Deriver A split relayer-input commitments.
    pub deriver_a: LocalEd25519HssSplitRelayerRoleCommitmentV1,
    /// Deriver B split relayer-input commitments.
    pub deriver_b: LocalEd25519HssSplitRelayerRoleCommitmentV1,
}

/// Public commitment to one recipient-opened HSS base share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssRecipientBaseShareCommitmentV1 {
    /// Recipient role allowed to open this base share.
    pub recipient_role: Role,
    /// Opened share kind.
    pub opened_share_kind: OpenedShareKind,
    /// SHA-256 commitment to the recipient-opened base share.
    pub base_share_commitment_hex: String,
}

/// Recipient-scoped local HSS base share output.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssRecipientBaseShareV1 {
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    base_share: [u8; 32],
}

impl LocalEd25519HssRecipientBaseShareV1 {
    /// Creates a recipient-scoped local HSS base share.
    pub fn new(
        recipient_role: Role,
        opened_share_kind: OpenedShareKind,
        base_share: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let share = Self {
            recipient_role,
            opened_share_kind,
            base_share,
        };
        share.validate()?;
        Ok(share)
    }

    /// Validates the recipient/output-kind binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match (self.recipient_role, self.opened_share_kind) {
            (Role::Client, OpenedShareKind::XClientBase)
            | (Role::Relayer, OpenedShareKind::XRelayerBase) => Ok(()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local HSS recipient base share has invalid recipient binding",
            )),
        }
    }

    /// Returns the recipient role.
    pub fn recipient_role(&self) -> Role {
        self.recipient_role
    }

    /// Returns the opened share kind.
    pub fn opened_share_kind(&self) -> OpenedShareKind {
        self.opened_share_kind
    }

    /// Returns public commitment evidence for this recipient output.
    pub fn commitment(&self) -> LocalEd25519HssRecipientBaseShareCommitmentV1 {
        let label = match self.opened_share_kind {
            OpenedShareKind::XClientBase => b"x_client_base".as_slice(),
            OpenedShareKind::XRelayerBase => b"x_relayer_base".as_slice(),
        };
        LocalEd25519HssRecipientBaseShareCommitmentV1 {
            recipient_role: self.recipient_role,
            opened_share_kind: self.opened_share_kind,
            base_share_commitment_hex: commitment_hex_v1(label, &self.base_share),
        }
    }
}

impl fmt::Debug for LocalEd25519HssRecipientBaseShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssRecipientBaseShareV1")
            .field("recipient_role", &self.recipient_role)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("base_share", &"[redacted]")
            .finish()
    }
}

/// Dev-only output of one role-scoped local HSS derivation.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssRoleScopedDerivationOutputV1 {
    /// Committed `ed25519-hss` fixture name.
    pub fixture_name: String,
    /// Local split epoch used for Deriver A/B relayer-input shares.
    pub split_epoch: String,
    /// Client-scoped `x_client_base` output.
    pub client_output: LocalEd25519HssRecipientBaseShareV1,
    /// SigningWorker-scoped `x_relayer_base` output.
    pub signing_worker_output: LocalEd25519HssRecipientBaseShareV1,
    /// Public key derived from the recipient-opened base shares.
    pub public_key_hex: String,
    /// Product-facing NEAR Ed25519 public key representation.
    pub near_public_key: String,
}

impl fmt::Debug for LocalEd25519HssRoleScopedDerivationOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssRoleScopedDerivationOutputV1")
            .field("fixture_name", &self.fixture_name)
            .field("split_epoch", &self.split_epoch)
            .field("client_output", &self.client_output)
            .field("signing_worker_output", &self.signing_worker_output)
            .field("public_key_hex", &self.public_key_hex)
            .field("near_public_key", &self.near_public_key)
            .finish()
    }
}

/// Combined dev harness output for core local Router/A/B and HSS parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRouterAbHssDevCeremonyResultV1 {
    /// Public Router request used for the core local ceremony.
    pub router_request: PublicRouterRequestV1,
    /// Result of the core local Router/Deriver/SigningWorker ceremony.
    pub core_ceremony: LocalInProcessCeremonyResultV1,
    /// HSS recipient-scoped output evidence for the same account public key.
    pub hss_derivation: LocalEd25519HssRoleScopedDerivationOutputV1,
    /// Public HSS parity report for Deriver A/B split relayer shares.
    pub hss_parity: LocalEd25519HssSplitRelayerParityReportV1,
}

/// Combined dev harness output for the typed local HTTP Router/A/B ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRouterAbHssDevHttpCeremonyResultV1 {
    /// Public Router request used for the core local ceremony.
    pub router_request: PublicRouterRequestV1,
    /// Initial Router-to-Deriver A request over the checked local HTTP boundary.
    pub deriver_a_request: LocalHttpRequestV1,
    /// Initial Router-to-Deriver B request over the checked local HTTP boundary.
    pub deriver_b_request: LocalHttpRequestV1,
    /// Result of the typed local HTTP Router/Deriver/SigningWorker ceremony.
    pub core_http_ceremony: LocalHttpCeremonyResultV1,
    /// HSS recipient-scoped output evidence for the same account public key.
    pub hss_derivation: LocalEd25519HssRoleScopedDerivationOutputV1,
    /// Public HSS parity report for Deriver A/B split relayer shares.
    pub hss_parity: LocalEd25519HssSplitRelayerParityReportV1,
}

/// Public local Router setup-smoke request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterSetupSmokeRequestV1 {
    /// Committed Ed25519-HSS fixture name to drive through local Router/A/B.
    pub fixture_name: String,
    /// Local split epoch for role-scoped HSS shares.
    pub split_epoch: String,
}

impl LocalRouterSetupSmokeRequestV1 {
    /// Creates a validated local Router setup-smoke request.
    pub fn new(
        fixture_name: impl Into<String>,
        split_epoch: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            fixture_name: fixture_name.into(),
            split_epoch: split_epoch.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates required smoke request fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("local setup-smoke fixture_name", &self.fixture_name)?;
        require_non_empty("local setup-smoke split_epoch", &self.split_epoch)
    }
}

/// Public local Router setup-smoke response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalRouterSetupSmokeResponseV1 {
    /// Public fixture name used by the smoke request.
    pub fixture_name: String,
    /// Public split epoch used by the smoke request.
    pub split_epoch: String,
    /// Account public key for the fixture.
    pub near_public_key: String,
    /// Raw public key hex for cross-checks.
    pub public_key_hex: String,
    /// Router response carrying only client-output proof bundles.
    pub router_response: LocalRouterRecipientProofBundleResponseV1,
    /// Digest proving the SigningWorker accepted relayer-output activation.
    pub signing_worker_activation_digest_hex: String,
    /// Redacted activation status.
    pub signing_worker_activation_status: String,
}

/// Handles the public local Router setup-smoke request body.
pub fn handle_local_router_setup_smoke_request_v1(
    request: LocalRouterSetupSmokeRequestV1,
) -> RouterAbProtocolResult<LocalRouterSetupSmokeResponseV1> {
    request.validate()?;
    let result = run_example_local_router_ab_hss_dev_http_ceremony_v1(
        &request.fixture_name,
        &request.split_epoch,
    )?;
    result.core_http_ceremony.router_response.validate()?;
    Ok(LocalRouterSetupSmokeResponseV1 {
        fixture_name: request.fixture_name,
        split_epoch: request.split_epoch,
        near_public_key: result.hss_derivation.near_public_key,
        public_key_hex: result.hss_derivation.public_key_hex,
        router_response: result.core_http_ceremony.router_response,
        signing_worker_activation_digest_hex: hex::encode(
            result
                .core_http_ceremony
                .signing_worker_activation_receipt
                .activation_digest
                .as_bytes(),
        ),
        signing_worker_activation_status: "activated".to_owned(),
    })
}

/// Parses and handles a public local Router setup-smoke request JSON body.
pub fn handle_local_router_setup_smoke_request_json_v1(
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    let request =
        serde_json::from_slice::<LocalRouterSetupSmokeRequestV1>(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local Router setup-smoke request JSON parse failed: {error}"),
            )
        })?;
    serde_json::to_string(&handle_local_router_setup_smoke_request_v1(request)?).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local Router setup-smoke response JSON serialization failed: {error}"),
        )
    })
}

/// Redacted receipt from a local Deriver peer-message route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeriverPeerMessageReceiptV1 {
    /// Deriver worker role that accepted the peer message.
    pub receiver_role: LocalServiceRoleV1,
    /// Producing signer role bound inside the peer message.
    pub accepted_from_role: Role,
    /// Stable peer wire-message kind.
    pub peer_message_kind: WireMessageKindV1,
    /// Transcript digest for routing and smoke assertions.
    pub transcript_digest_hex: String,
    /// Number of proof bundles in the peer payload.
    pub proof_bundle_count: usize,
    /// Redacted receipt status.
    pub status: String,
}

/// Parses and validates a Deriver peer-message JSON body for local worker routes.
pub fn handle_local_deriver_peer_message_json_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    let receipt = handle_local_deriver_peer_message_v1(
        receiver_role,
        path,
        serde_json::from_slice::<WireMessageV1>(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local Deriver peer message JSON parse failed: {error}"),
            )
        })?,
    )?;
    serde_json::to_string(&receipt).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local Deriver peer receipt JSON serialization failed: {error}"),
        )
    })
}

/// Validates a Deriver peer message and returns a redacted local receipt.
pub fn handle_local_deriver_peer_message_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    message: WireMessageV1,
) -> RouterAbProtocolResult<LocalDeriverPeerMessageReceiptV1> {
    let (expected_path, expected_kind, expected_from, expected_to) = match receiver_role {
        LocalServiceRoleV1::DeriverA => (
            LOCAL_DERIVER_A_PEER_PATH_V1,
            WireMessageKindV1::SignerBToSignerA,
            Role::SignerB,
            Role::SignerA,
        ),
        LocalServiceRoleV1::DeriverB => (
            LOCAL_DERIVER_B_PEER_PATH_V1,
            WireMessageKindV1::SignerAToSignerB,
            Role::SignerA,
            Role::SignerB,
        ),
        LocalServiceRoleV1::Router | LocalServiceRoleV1::SigningWorker => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "local Deriver peer route requires Deriver A or Deriver B receiver",
            ));
        }
    };
    if path != expected_path {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "{} peer route must be served at {}",
                receiver_role.as_str(),
                expected_path
            ),
        ));
    }
    if message.kind != expected_kind {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "{} peer route expected {} message, received {}",
                receiver_role.as_str(),
                expected_kind.as_str(),
                message.kind.as_str()
            ),
        ));
    }
    let peer_payload = decode_ab_peer_message_payload_v1(message.payload.as_bytes())?;
    let proof_batch = decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)?;
    if peer_payload.transcript_digest != message.transcript_digest
        || proof_batch.transcript_digest != message.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local Deriver peer payload transcript does not match wire message",
        ));
    }
    if peer_payload.from.role != expected_from || peer_payload.to.role != expected_to {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "local Deriver peer message signer direction does not match route",
        ));
    }
    Ok(LocalDeriverPeerMessageReceiptV1 {
        receiver_role,
        accepted_from_role: peer_payload.from.role,
        peer_message_kind: message.kind,
        transcript_digest_hex: hex::encode(message.transcript_digest.as_bytes()),
        proof_bundle_count: proof_batch.proof_bundles.len(),
        status: "accepted".to_owned(),
    })
}

/// Redacted receipt from a local SigningWorker activation route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerActivationRouteReceiptV1 {
    /// Worker role that accepted the activation.
    pub receiver_role: LocalServiceRoleV1,
    /// Accepted opened share kind.
    pub accepted_opened_share_kind: String,
    /// Accepted recipient role.
    pub accepted_recipient_role: Role,
    /// Transcript digest shared by the relayer-output bundles.
    pub transcript_digest_hex: String,
    /// Digest of Deriver A's encrypted relayer-output bundle.
    pub deriver_a_bundle_digest_hex: String,
    /// Digest of Deriver B's encrypted relayer-output bundle.
    pub deriver_b_bundle_digest_hex: String,
    /// Redacted receipt status.
    pub status: String,
}

/// Local normal-signing smoke request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalNormalSigningSmokeRequestV1 {
    /// Request id used for smoke traceability.
    pub request_id: String,
    /// Account id that would be signed for.
    pub account_id: String,
    /// Session id that would resolve active SigningWorker state.
    pub session_id: String,
    /// Hex-encoded payload bytes to sign.
    pub signing_payload_hex: String,
}

impl LocalNormalSigningSmokeRequestV1 {
    /// Validates the smoke request shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal-signing smoke request_id", &self.request_id)?;
        require_non_empty("normal-signing smoke account_id", &self.account_id)?;
        require_non_empty("normal-signing smoke session_id", &self.session_id)?;
        require_non_empty(
            "normal-signing smoke signing_payload_hex",
            &self.signing_payload_hex,
        )?;
        let _ = parse_local_normal_signing_payload_hex_v1(&self.signing_payload_hex)?;
        Ok(())
    }
}

/// Successful local SigningWorker normal-signing smoke response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerNormalSigningSmokeResponseV1 {
    /// Worker role that handled the request.
    pub receiver_role: LocalServiceRoleV1,
    /// Smoke request id.
    pub request_id: String,
    /// Local smoke signing status.
    pub status: String,
    /// Signature scheme used by the local smoke signer.
    pub signature_scheme: String,
    /// Digest of signed payload bytes.
    pub signing_payload_digest_hex: String,
    /// Local smoke signature bytes.
    pub signature_hex: String,
    /// Public key for verifying the local smoke signature.
    pub verifying_key_hex: String,
}

/// Public Router normal-signing smoke response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterNormalSigningSmokeResponseV1 {
    /// Router status.
    pub status: String,
    /// Role the Router forwarded to.
    pub forwarded_to_role: LocalServiceRoleV1,
    /// SigningWorker status.
    pub signing_worker_status: String,
    /// Signature scheme used by the local smoke signer.
    pub signature_scheme: String,
    /// Digest of signed payload bytes.
    pub signing_payload_digest_hex: String,
    /// Local smoke signature bytes.
    pub signature_hex: String,
    /// Public key for verifying the local smoke signature.
    pub verifying_key_hex: String,
    /// Number of Deriver A requests issued on the normal-signing hot path.
    pub deriver_a_request_count: u32,
    /// Number of Deriver B requests issued on the normal-signing hot path.
    pub deriver_b_request_count: u32,
}

/// Raw local HTTP response from a direct JSON POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHttpPostResponseV1 {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Handles the local SigningWorker normal-signing route with a dev-only smoke signer.
pub fn handle_local_signing_worker_normal_signing_smoke_json_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local normal-signing private route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker normal-signing route must be served at {}",
                LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
            ),
        ));
    }
    let request = parse_local_normal_signing_smoke_request_v1(body)?;
    let signing_payload = parse_local_normal_signing_payload_hex_v1(&request.signing_payload_hex)?;
    let signing_payload_digest = local_normal_signing_payload_digest_hex_v1(&signing_payload);
    let signing_key = local_normal_signing_smoke_key_v1(&request);
    let signature = signing_key.sign(&signing_payload);
    serde_json::to_string(&LocalSigningWorkerNormalSigningSmokeResponseV1 {
        receiver_role,
        request_id: request.request_id,
        status: "signed".to_owned(),
        signature_scheme: "local_dev_ed25519_v1".to_owned(),
        signing_payload_digest_hex: signing_payload_digest,
        signature_hex: hex::encode(signature.to_bytes()),
        verifying_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
    })
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker normal-signing response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local Router normal-signing public route by forwarding only to SigningWorker.
pub fn handle_local_router_normal_signing_smoke_request_json_v1(
    signing_worker_url: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    let request = parse_local_normal_signing_smoke_request_v1(body)?;
    let url = format!(
        "{}{}",
        signing_worker_url.trim_end_matches('/'),
        LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
    );
    let response = local_http_post_json_url_v1(
        &url,
        &request,
        Duration::from_millis(LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1),
    )?;
    if response.status != 200 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "local Router normal-signing smoke expected SigningWorker status 200, received {}",
                response.status
            ),
        ));
    }
    let signing_worker =
        serde_json::from_slice::<LocalSigningWorkerNormalSigningSmokeResponseV1>(&response.body)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!(
                        "local SigningWorker normal-signing response JSON parse failed: {error}"
                    ),
                )
            })?;
    serde_json::to_string(&LocalRouterNormalSigningSmokeResponseV1 {
        status: "signed".to_owned(),
        forwarded_to_role: LocalServiceRoleV1::SigningWorker,
        signing_worker_status: signing_worker.status,
        signature_scheme: signing_worker.signature_scheme,
        signing_payload_digest_hex: signing_worker.signing_payload_digest_hex,
        signature_hex: signing_worker.signature_hex,
        verifying_key_hex: signing_worker.verifying_key_hex,
        deriver_a_request_count: 0,
        deriver_b_request_count: 0,
    })
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local Router normal-signing smoke response JSON serialization failed: {error}"
            ),
        )
    })
}

fn parse_local_normal_signing_smoke_request_v1(
    body: &[u8],
) -> RouterAbProtocolResult<LocalNormalSigningSmokeRequestV1> {
    let request =
        serde_json::from_slice::<LocalNormalSigningSmokeRequestV1>(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local normal-signing smoke request JSON parse failed: {error}"),
            )
        })?;
    request.validate()?;
    Ok(request)
}

fn parse_local_normal_signing_payload_hex_v1(value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty("normal-signing smoke signing_payload_hex", value)?;
    if value.len() % 2 != 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "normal-signing smoke signing_payload_hex must contain an even number of hex characters",
        ));
    }
    hex::decode(value).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("normal-signing smoke signing_payload_hex parse failed: {error}"),
        )
    })
}

fn local_normal_signing_payload_digest_hex_v1(signing_payload: &[u8]) -> String {
    hex::encode(Sha256::digest(signing_payload))
}

fn local_normal_signing_smoke_key_v1(request: &LocalNormalSigningSmokeRequestV1) -> SigningKey {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, LOCAL_NORMAL_SIGNING_SMOKE_LABEL_V1);
    push_hash_field_v1(&mut hasher, request.account_id.as_bytes());
    push_hash_field_v1(&mut hasher, request.session_id.as_bytes());
    SigningKey::from_bytes(&hasher.finalize().into())
}

fn local_http_post_json_url_v1<T: Serialize>(
    url: &str,
    body: &T,
    timeout: Duration,
) -> RouterAbProtocolResult<LocalHttpPostResponseV1> {
    if timeout.is_zero() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local HTTP POST timeout must be non-zero",
        ));
    }
    let parts = parse_http_url_parts_v1(url)?;
    let request_body = serde_json::to_vec(body).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local HTTP POST JSON request serialization failed: {error}"),
        )
    })?;
    let mut stream = TcpStream::connect(&parts.authority).map_err(map_local_http_io_error_v1)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(map_local_http_io_error_v1)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(map_local_http_io_error_v1)?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nhost: {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        parts.path,
        parts.authority,
        LOCAL_HTTP_JSON_CONTENT_TYPE_V1,
        request_body.len()
    )
    .map_err(map_local_http_io_error_v1)?;
    stream
        .write_all(&request_body)
        .map_err(map_local_http_io_error_v1)?;
    stream.flush().map_err(map_local_http_io_error_v1)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(map_local_http_io_error_v1)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(map_local_http_io_error_v1)?;
    let (status, body) = split_local_http_response_v1(&response)?;
    Ok(LocalHttpPostResponseV1 { status, body })
}

/// Parses and validates a SigningWorker activation JSON body for local worker routes.
pub fn handle_local_signing_worker_activation_json_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    let activation =
        serde_json::from_slice::<LocalSigningWorkerRecipientProofBundleActivationV1>(body)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("local SigningWorker activation JSON parse failed: {error}"),
                )
            })?;
    serde_json::to_string(&handle_local_signing_worker_activation_v1(
        receiver_role,
        path,
        activation,
    )?)
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local SigningWorker activation receipt JSON serialization failed: {error}"),
        )
    })
}

/// Validates a SigningWorker activation and returns a redacted local receipt.
pub fn handle_local_signing_worker_activation_v1(
    receiver_role: LocalServiceRoleV1,
    path: &str,
    activation: LocalSigningWorkerRecipientProofBundleActivationV1,
) -> RouterAbProtocolResult<LocalSigningWorkerActivationRouteReceiptV1> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local SigningWorker activation route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker activation route must be served at {}",
                LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1
            ),
        ));
    }
    activation.validate()?;
    Ok(LocalSigningWorkerActivationRouteReceiptV1 {
        receiver_role,
        accepted_opened_share_kind: "x_relayer_base".to_owned(),
        accepted_recipient_role: Role::Relayer,
        transcript_digest_hex: hex::encode(
            activation
                .deriver_a_signing_worker_bundle
                .transcript_digest
                .as_bytes(),
        ),
        deriver_a_bundle_digest_hex: hex::encode(
            activation
                .deriver_a_signing_worker_bundle
                .digest()
                .as_bytes(),
        ),
        deriver_b_bundle_digest_hex: hex::encode(
            activation
                .deriver_b_signing_worker_bundle
                .digest()
                .as_bytes(),
        ),
        status: "accepted".to_owned(),
    })
}

/// Role-scoped local HSS relayer-input share held by one Deriver.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssRelayerInputShareV1 {
    role: Role,
    split_epoch: String,
    y_relayer_share: [u8; 32],
    tau_relayer_share: [u8; 32],
}

impl LocalEd25519HssRelayerInputShareV1 {
    /// Creates a role-scoped relayer-input share for the local HSS dev adapter.
    pub fn new(
        role: Role,
        split_epoch: impl Into<String>,
        y_relayer_share: [u8; 32],
        tau_relayer_share: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let share = Self {
            role,
            split_epoch: split_epoch.into(),
            y_relayer_share,
            tau_relayer_share,
        };
        share.validate()?;
        Ok(share)
    }

    /// Validates role and scalar shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_sqlite_signer_role(self.role)?;
        require_non_empty("split_epoch", &self.split_epoch)?;
        canonical_scalar_v1("tau_relayer share", self.tau_relayer_share)?;
        Ok(())
    }

    /// Returns the Deriver role that owns this share.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the local split epoch.
    pub fn split_epoch(&self) -> &str {
        &self.split_epoch
    }

    /// Returns public commitments for this role-scoped share.
    pub fn commitment(&self) -> LocalEd25519HssSplitRelayerRoleCommitmentV1 {
        let role_label = match self.role {
            Role::SignerA => b"deriver-a".as_slice(),
            Role::SignerB => b"deriver-b".as_slice(),
            _ => b"invalid-role".as_slice(),
        };
        LocalEd25519HssSplitRelayerRoleCommitmentV1 {
            role: self.role,
            y_relayer_share_commitment_hex: commitment_hex_v1(
                &[role_label, b"/y_relayer"].concat(),
                &self.y_relayer_share,
            ),
            tau_relayer_share_commitment_hex: commitment_hex_v1(
                &[role_label, b"/tau_relayer"].concat(),
                &self.tau_relayer_share,
            ),
        }
    }
}

impl fmt::Debug for LocalEd25519HssRelayerInputShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssRelayerInputShareV1")
            .field("role", &self.role)
            .field("split_epoch", &self.split_epoch)
            .field("y_relayer_share", &"[redacted]")
            .field("tau_relayer_share", &"[redacted]")
            .finish()
    }
}

struct LocalEd25519HssSplitRelayerInputsV1 {
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
}

/// SQLite executor for protocol-generated local seed statements.
pub struct LocalSqliteSeedExecutorV1<'conn> {
    connection: &'conn Connection,
}

impl<'conn> LocalSqliteSeedExecutorV1<'conn> {
    /// Creates a SQLite seed executor for an existing connection.
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }
}

impl LocalPersistenceSqlSeedExecutorV1 for LocalSqliteSeedExecutorV1<'_> {
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        dialect: LocalPersistenceSqlDialectV1,
        _statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()> {
        if dialect != LocalPersistenceSqlDialectV1::Sqlite {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local SQLite seed executor requires sqlite dialect statements",
            ));
        }
        statement.validate()?;
        let values = statement
            .values
            .iter()
            .map(sqlite_value)
            .collect::<Vec<_>>();
        self.connection
            .execute(&statement.sql, params_from_iter(values.iter()))
            .map_err(map_sqlite_error)?;
        Ok(())
    }
}

/// SQLite-backed local signing-root share store.
pub struct LocalSqliteSigningRootShareStoreV1<'conn> {
    connection: &'conn Connection,
    signer_set_id: String,
}

impl<'conn> LocalSqliteSigningRootShareStoreV1<'conn> {
    /// Creates a local SQLite root-share store for one signer set.
    pub fn new(
        connection: &'conn Connection,
        signer_set_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let store = Self {
            connection,
            signer_set_id: signer_set_id.into(),
        };
        require_non_empty("signer_set_id", &store.signer_set_id)?;
        Ok(store)
    }

    /// Reads the startup metadata required for a role-specific local signer.
    pub fn require_startup_share(
        &self,
        role: Role,
        root_share_epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<LocalSqliteSignerStartupCheckV1> {
        require_sqlite_signer_role(role)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT signer_id, signer_key_epoch, sealed_share_storage_key \
                 FROM local_sealed_root_shares \
                 WHERE signer_set_id = ?1 AND signer_role = ?2 AND root_share_epoch = ?3",
            )
            .map_err(map_sqlite_error)?;
        let row = statement
            .query_row(
                params![
                    self.signer_set_id.as_str(),
                    role.as_str(),
                    root_share_epoch.as_str()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| map_sqlite_missing_share(error, role, root_share_epoch))?;
        Ok(LocalSqliteSignerStartupCheckV1 {
            signer_set_id: self.signer_set_id.clone(),
            role,
            root_share_epoch: root_share_epoch.clone(),
            signer_id: row.0,
            signer_key_epoch: row.1,
            sealed_share_storage_key: row.2,
        })
    }
}

impl SigningRootShareStore for LocalSqliteSigningRootShareStoreV1<'_> {
    fn has_root_share(&self, role: Role, epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool> {
        require_sqlite_signer_role(role)?;
        let count = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM local_sealed_root_shares \
                 WHERE signer_set_id = ?1 AND signer_role = ?2 AND root_share_epoch = ?3",
                params![self.signer_set_id.as_str(), role.as_str(), epoch.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        Ok(count > 0)
    }
}

/// Verifies every committed `ed25519-hss` fixture through the local split-relayer adapter.
pub fn verify_committed_ed25519_hss_split_relayer_fixtures_v1(
) -> RouterAbProtocolResult<Vec<LocalEd25519HssSplitRelayerParityReportV1>> {
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    fixtures
        .iter()
        .map(|fixture| {
            verify_ed25519_hss_split_relayer_fixture_v1(
                fixture,
                LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
            )
        })
        .collect()
}

/// Verifies one committed `ed25519-hss` fixture through split `y_relayer` and `tau_relayer` shares.
pub fn verify_committed_ed25519_hss_split_relayer_fixture_v1(
    fixture_name: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1(
        fixture_name,
        LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
    )
}

/// Verifies one committed `ed25519-hss` fixture through one local split epoch.
pub fn verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    let shares = split_ed25519_hss_relayer_inputs_v1(fixture, split_epoch)?;
    verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        fixture_name,
        shares.deriver_a,
        shares.deriver_b,
    )
}

/// Derives deterministic role-scoped relayer-input shares for one committed HSS fixture.
pub fn derive_committed_ed25519_hss_split_relayer_role_shares_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<(
    LocalEd25519HssRelayerInputShareV1,
    LocalEd25519HssRelayerInputShareV1,
)> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    let split = split_ed25519_hss_relayer_inputs_v1(fixture, split_epoch)?;
    Ok((split.deriver_a, split.deriver_b))
}

/// Verifies one committed HSS fixture from explicit Deriver A/B role-scoped shares.
pub fn verify_committed_ed25519_hss_split_relayer_role_shares_v1(
    fixture_name: &str,
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    require_non_empty("fixture_name", fixture_name)?;
    validate_ed25519_hss_role_share_pair_v1(&deriver_a, &deriver_b)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    verify_ed25519_hss_split_relayer_fixture_with_role_shares_v1(fixture, deriver_a, deriver_b)
}

/// Runs the dev-only role-scoped HSS derivation and returns recipient-scoped outputs.
pub fn evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
    fixture_name: &str,
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssRoleScopedDerivationOutputV1> {
    require_non_empty("fixture_name", fixture_name)?;
    validate_ed25519_hss_role_share_pair_v1(&deriver_a, &deriver_b)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    let expanded = evaluate_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
        fixture, &deriver_a, &deriver_b,
    )?;
    Ok(LocalEd25519HssRoleScopedDerivationOutputV1 {
        fixture_name: fixture.name.clone(),
        split_epoch: deriver_a.split_epoch().to_owned(),
        client_output: LocalEd25519HssRecipientBaseShareV1::new(
            Role::Client,
            OpenedShareKind::XClientBase,
            expanded.output.x_client_base,
        )?,
        signing_worker_output: LocalEd25519HssRecipientBaseShareV1::new(
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
            expanded.output.x_relayer_base,
        )?,
        public_key_hex: hex::encode(expanded.public_key),
        near_public_key: encode_near_ed25519_public_key_v1(expanded.public_key),
    })
}

/// Runs the local Router/Deriver/SigningWorker ceremony and HSS role-scoped parity side by side.
pub fn run_example_local_router_ab_hss_dev_ceremony_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalRouterAbHssDevCeremonyResultV1> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixture = committed_ed25519_hss_fixture_v1(fixture_name)?;
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1(fixture_name, split_epoch)?;
    let hss_derivation = evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        fixture_name,
        deriver_a.clone(),
        deriver_b.clone(),
    )?;
    let hss_parity = verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        fixture_name,
        deriver_a,
        deriver_b,
    )?;
    let router_request = local_router_request_for_hss_fixture_v1(&fixture, &hss_derivation)?;
    let (signer_a_request, signer_b_request) = router_request.to_signer_wire_messages()?;
    let core_ceremony = local_service_stack_v1()?.run_deterministic_ceremony(
        router_request.lifecycle.lifecycle_id.clone(),
        signer_a_request,
        signer_b_request,
    )?;
    Ok(LocalRouterAbHssDevCeremonyResultV1 {
        router_request,
        core_ceremony,
        hss_derivation,
        hss_parity,
    })
}

/// Runs the local Router/Deriver/SigningWorker ceremony through checked local HTTP requests.
pub fn run_example_local_router_ab_hss_dev_http_ceremony_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalRouterAbHssDevHttpCeremonyResultV1> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixture = committed_ed25519_hss_fixture_v1(fixture_name)?;
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1(fixture_name, split_epoch)?;
    let hss_derivation = evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        fixture_name,
        deriver_a.clone(),
        deriver_b.clone(),
    )?;
    let hss_parity = verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        fixture_name,
        deriver_a,
        deriver_b,
    )?;
    let router_request = local_router_request_for_hss_fixture_v1(&fixture, &hss_derivation)?;
    let (signer_a_request, signer_b_request) = router_request.to_signer_wire_messages()?;
    let deriver_a_request = LocalHttpRequestV1::new(
        LocalHttpMethodV1::Post,
        LocalHttpPathV1::RouterToSignerA,
        LocalTransportEnvelopeV1::new(LocalTransportRouteV1::RouterToSignerA, signer_a_request)?,
    )?;
    let deriver_b_request = LocalHttpRequestV1::new(
        LocalHttpMethodV1::Post,
        LocalHttpPathV1::RouterToSignerB,
        LocalTransportEnvelopeV1::new(LocalTransportRouteV1::RouterToSignerB, signer_b_request)?,
    )?;
    let core_http_ceremony = local_service_stack_v1()?.run_deterministic_http_ceremony(
        router_request.lifecycle.lifecycle_id.clone(),
        deriver_a_request.clone(),
        deriver_b_request.clone(),
    )?;
    Ok(LocalRouterAbHssDevHttpCeremonyResultV1 {
        router_request,
        deriver_a_request,
        deriver_b_request,
        core_http_ceremony,
        hss_derivation,
        hss_parity,
    })
}

fn verify_ed25519_hss_split_relayer_fixture_v1(
    fixture: &FExpandFixture,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    let split = split_ed25519_hss_relayer_inputs_v1(fixture, split_epoch)?;
    verify_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
        fixture,
        split.deriver_a,
        split.deriver_b,
    )
}

fn verify_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
    fixture: &FExpandFixture,
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    let expanded = evaluate_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
        fixture, &deriver_a, &deriver_b,
    )?;
    let split_epoch = deriver_a.split_epoch().to_owned();
    Ok(LocalEd25519HssSplitRelayerParityReportV1 {
        fixture_name: fixture.name.clone(),
        split_epoch,
        context_binding_hex: hex::encode(fixture.output.context_binding),
        public_key_hex: hex::encode(expanded.public_key),
        near_public_key: encode_near_ed25519_public_key_v1(expanded.public_key),
        x_client_base_commitment_hex: commitment_hex_v1(
            b"x_client_base",
            &expanded.output.x_client_base,
        ),
        x_relayer_base_commitment_hex: commitment_hex_v1(
            b"x_relayer_base",
            &expanded.output.x_relayer_base,
        ),
        deriver_a: deriver_a.commitment(),
        deriver_b: deriver_b.commitment(),
    })
}

fn committed_ed25519_hss_fixture_v1(fixture_name: &str) -> RouterAbProtocolResult<FExpandFixture> {
    require_non_empty("fixture_name", fixture_name)?;
    committed_fixture_corpus()
        .map_err(map_hss_error)?
        .into_iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })
}

struct LocalEd25519HssExpandedFixtureV1 {
    output: FExpandOutput,
    public_key: [u8; 32],
}

fn evaluate_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
    fixture: &FExpandFixture,
    deriver_a: &LocalEd25519HssRelayerInputShareV1,
    deriver_b: &LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssExpandedFixtureV1> {
    validate_ed25519_hss_role_share_pair_v1(deriver_a, deriver_b)?;
    let y_relayer = add_le_bytes_mod_2_256(deriver_a.y_relayer_share, deriver_b.y_relayer_share);
    let tau_relayer = add_scalar_mod_l(deriver_a.tau_relayer_share, deriver_b.tau_relayer_share)?;
    if y_relayer != fixture.input.y_relayer || tau_relayer != fixture.input.tau_relayer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS relayer inputs failed to reconstruct fixture inputs",
        ));
    }
    let output = eval_f_expand(&ed25519_hss::shared::FExpandInput {
        context: fixture.input.context.clone(),
        y_client: fixture.input.y_client,
        y_relayer,
        tau_client: fixture.input.tau_client,
        tau_relayer,
    })
    .map_err(map_hss_error)?;
    if output != fixture.output {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS relayer expansion did not match committed fixture output",
        ));
    }
    let public_key = public_key_from_base_shares(output.x_client_base, output.x_relayer_base)
        .map_err(map_hss_error)?;
    if public_key != fixture.output.public_key {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS base-share public key did not match committed fixture",
        ));
    }
    Ok(LocalEd25519HssExpandedFixtureV1 { output, public_key })
}

/// Encodes a NEAR Ed25519 public key string from raw 32-byte public key material.
pub fn encode_near_ed25519_public_key_v1(public_key: [u8; 32]) -> String {
    format!("ed25519:{}", bs58::encode(public_key).into_string())
}

/// Ensures local SQLite tables used by file-backed Durable Object storage exist.
pub fn ensure_local_durable_object_sqlite_schema_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<()> {
    connection
        .execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS local_durable_object_kv (
                scope TEXT NOT NULL,
                key TEXT NOT NULL,
                value BLOB NOT NULL CHECK (length(value) > 0),
                PRIMARY KEY (scope, key)
            );
            ",
        )
        .map_err(map_sqlite_error)
}

/// Ensures local SQLite tables used by Router/A/B seed tests exist.
pub fn ensure_local_sqlite_schema_v1(connection: &Connection) -> RouterAbProtocolResult<()> {
    connection
        .execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS local_signing_roots (
                signer_set_id TEXT NOT NULL,
                signing_root_version TEXT NOT NULL,
                root_share_epoch TEXT NOT NULL,
                account_id TEXT NOT NULL,
                PRIMARY KEY (signer_set_id, root_share_epoch)
            );

            CREATE TABLE IF NOT EXISTS local_sealed_root_shares (
                signer_set_id TEXT NOT NULL,
                signer_role TEXT NOT NULL CHECK (signer_role IN ('signer_a', 'signer_b')),
                signer_id TEXT NOT NULL,
                signer_key_epoch TEXT NOT NULL,
                root_share_epoch TEXT NOT NULL,
                sealed_share_storage_key TEXT NOT NULL,
                sealed_share_commitment_hex TEXT NOT NULL CHECK (length(sealed_share_commitment_hex) = 64),
                sealed_share_len INTEGER NOT NULL CHECK (sealed_share_len > 0),
                PRIMARY KEY (signer_set_id, signer_role, root_share_epoch),
                FOREIGN KEY (signer_set_id, root_share_epoch)
                    REFERENCES local_signing_roots (signer_set_id, root_share_epoch)
            );
            ",
        )
        .map_err(map_sqlite_error)
}

/// Seeds local SQLite with a validated Router/A/B persistence seed.
pub fn seed_local_sqlite_v1(
    connection: &Connection,
    seed: &LocalPersistenceSeedV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    ensure_local_sqlite_schema_v1(connection)?;
    let plan = local_persistence_seed_sql_plan_v1(seed, LocalPersistenceSqlDialectV1::Sqlite)?;
    let mut executor = LocalSqliteSeedExecutorV1::new(connection);
    execute_local_persistence_sql_seed_plan_v1(&plan, &mut executor)
}

/// Reads a small verification summary from local SQLite.
pub fn read_local_sqlite_seed_summary_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalSqliteSeedSummaryV1> {
    let signing_root_count =
        query_u32_count(connection, "SELECT COUNT(*) FROM local_signing_roots")?;
    let sealed_share_count =
        query_u32_count(connection, "SELECT COUNT(*) FROM local_sealed_root_shares")?;
    let signer_roles = query_signer_roles(connection)?;
    Ok(LocalSqliteSeedSummaryV1 {
        signing_root_count,
        sealed_share_count,
        signer_roles,
    })
}

/// Creates the deterministic local dev persistence seed used by smoke tests.
pub fn example_local_persistence_seed_v1() -> RouterAbProtocolResult<LocalPersistenceSeedV1> {
    LocalPersistenceSeedV1::new(
        LocalSigningRootMetadataV1::new(
            "signer-set-v1",
            "signing-root-v1",
            root_epoch()?,
            "alice.testnet",
        )?,
        sealed_share_record(Role::SignerA)?,
        sealed_share_record(Role::SignerB)?,
    )
}

/// Seeds local SQLite with the deterministic dev seed.
pub fn seed_example_local_sqlite_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    seed_local_sqlite_v1(connection, &example_local_persistence_seed_v1()?)
}

/// Checks that a local signer can see its role-specific sealed root share.
pub fn require_example_local_sqlite_signer_startup_v1(
    connection: &Connection,
    role: Role,
) -> RouterAbProtocolResult<LocalSqliteSignerStartupCheckV1> {
    let seed = example_local_persistence_seed_v1()?;
    let store = LocalSqliteSigningRootShareStoreV1::new(
        connection,
        seed.root_metadata.signer_set_id.clone(),
    )?;
    store.require_startup_share(role, &seed.root_metadata.root_share_epoch)
}

fn query_u32_count(connection: &Connection, sql: &str) -> RouterAbProtocolResult<u32> {
    let count = connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite_error)?;
    u32::try_from(count).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local SQLite count did not fit u32",
        )
    })
}

fn query_signer_roles(connection: &Connection) -> RouterAbProtocolResult<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT signer_role FROM local_sealed_root_shares ORDER BY signer_role")
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(map_sqlite_error)?;
    let mut roles = Vec::new();
    for row in rows {
        roles.push(row.map_err(map_sqlite_error)?);
    }
    Ok(roles)
}

fn sealed_share_record(role: Role) -> RouterAbProtocolResult<LocalSealedRootShareRecordV1> {
    let (signer, storage_key, commitment_seed) = match role {
        Role::SignerA => (signer_identity(Role::SignerA)?, "sealed/share/a", 0xa1),
        Role::SignerB => (signer_identity(Role::SignerB)?, "sealed/share/b", 0xb1),
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "local dev seed requires signer role",
            ));
        }
    };
    LocalSealedRootShareRecordV1::new(
        "signer-set-v1",
        signer,
        root_epoch()?,
        storage_key,
        digest(commitment_seed),
        33,
    )
}

fn local_router_request_for_hss_fixture_v1(
    fixture: &FExpandFixture,
    hss_derivation: &LocalEd25519HssRoleScopedDerivationOutputV1,
) -> RouterAbProtocolResult<PublicRouterRequestV1> {
    let account_id = fixture.input.context.account_id.clone();
    let account_public_key = hss_derivation.near_public_key.clone();
    let lifecycle = local_lifecycle_scope_v1(&account_id)?;
    let signer_set = signer_set_v1()?;
    let metadata = RouterTranscriptMetadataV1::new(
        "near-testnet",
        account_public_key.clone(),
        "local-router",
        "client",
        "x25519:local-dev-client-ephemeral-public-key",
    )?;
    let transcript_digest = router_transcript_digest_v1(
        &lifecycle,
        &signer_set,
        &metadata,
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_epoch()?,
    )?;
    PublicRouterRequestV1::new(
        "request-nonce-1",
        2_000,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set,
        metadata.network_id,
        account_public_key,
        metadata.router_id,
        metadata.client_id,
        metadata.client_ephemeral_public_key,
        transcript_digest,
        role_envelope_v1(Role::SignerA, 0xa0)?,
        role_envelope_v1(Role::SignerB, 0xb0)?,
    )
}

fn local_lifecycle_scope_v1(account_id: &str) -> RouterAbProtocolResult<LifecycleScopeV1> {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch()?,
        account_id,
        "session-1",
        "signer-set-v1",
        "relayer-a",
    )
}

fn signer_set_v1() -> RouterAbProtocolResult<SignerSetV1> {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        signer_identity(Role::SignerA)?,
        signer_identity(Role::SignerB)?,
        relayer_identity_v1()?,
    )
}

fn relayer_identity_v1() -> RouterAbProtocolResult<RelayerIdentityV1> {
    RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
}

fn role_envelope_v1(role: Role, seed: u8) -> RouterAbProtocolResult<RoleEncryptedEnvelopeV1> {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(2)])?,
    )
}

fn local_service_stack_v1() -> RouterAbProtocolResult<LocalServiceStackV1> {
    LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint_v1()?, router_env_snapshot_v1()?)?,
        LocalServiceStartupV1::deriver_a(
            deriver_a_endpoint_v1()?,
            signer_identity(Role::SignerA)?,
            deriver_a_env_snapshot_v1()?,
        )?,
        LocalServiceStartupV1::deriver_b(
            deriver_b_endpoint_v1()?,
            signer_identity(Role::SignerB)?,
            deriver_b_env_snapshot_v1()?,
        )?,
        LocalServiceStartupV1::signing_worker(
            signing_worker_endpoint_v1()?,
            relayer_identity_v1()?,
            signing_worker_env_snapshot_v1()?,
        )?,
    )
}

fn router_endpoint_v1() -> RouterAbProtocolResult<LocalRouterEndpointV1> {
    LocalRouterEndpointV1::new(
        "http://127.0.0.1:8787",
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8790",
    )
}

fn deriver_a_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverAEndpointV1> {
    LocalDeriverAEndpointV1::new("http://127.0.0.1:8788", "http://127.0.0.1:8789")
}

fn deriver_b_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverBEndpointV1> {
    LocalDeriverBEndpointV1::new("http://127.0.0.1:8789", "http://127.0.0.1:8788")
}

fn signing_worker_endpoint_v1() -> RouterAbProtocolResult<LocalSigningWorkerEndpointV1> {
    LocalSigningWorkerEndpointV1::new("http://127.0.0.1:8790", "local-relayer-output")
}

fn router_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::Router,
        vec![
            "ROUTER_PUBLIC_URL".to_owned(),
            "DERIVER_A_URL".to_owned(),
            "DERIVER_B_URL".to_owned(),
            "SIGNING_WORKER_URL".to_owned(),
        ],
    )
}

fn deriver_a_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverA,
        vec![
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "DERIVER_B_URL".to_owned(),
        ],
    )
}

fn deriver_b_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverB,
        vec![
            "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "DERIVER_A_URL".to_owned(),
        ],
    )
}

fn signing_worker_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SigningWorker,
        vec!["RELAYER_OUTPUT_STORAGE".to_owned()],
    )
}

fn split_ed25519_hss_relayer_inputs_v1(
    fixture: &FExpandFixture,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerInputsV1> {
    let y_relayer_a = deterministic_hss_share_v1(
        b"deriver-a/y_relayer",
        &fixture.name,
        split_epoch,
        fixture.output.context_binding,
    );
    let y_relayer_b = sub_le_bytes_mod_2_256(fixture.input.y_relayer, y_relayer_a);
    let tau_relayer_a = Scalar::from_bytes_mod_order(deterministic_hss_share_v1(
        b"deriver-a/tau_relayer",
        &fixture.name,
        split_epoch,
        fixture.output.context_binding,
    ))
    .to_bytes();
    let tau_relayer_b = sub_scalar_mod_l(fixture.input.tau_relayer, tau_relayer_a)?;
    Ok(LocalEd25519HssSplitRelayerInputsV1 {
        deriver_a: LocalEd25519HssRelayerInputShareV1::new(
            Role::SignerA,
            split_epoch,
            y_relayer_a,
            tau_relayer_a,
        )?,
        deriver_b: LocalEd25519HssRelayerInputShareV1::new(
            Role::SignerB,
            split_epoch,
            y_relayer_b,
            tau_relayer_b,
        )?,
    })
}

fn validate_ed25519_hss_role_share_pair_v1(
    deriver_a: &LocalEd25519HssRelayerInputShareV1,
    deriver_b: &LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<()> {
    deriver_a.validate()?;
    deriver_b.validate()?;
    if deriver_a.role() != Role::SignerA || deriver_b.role() != Role::SignerB {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local HSS role-scoped shares require Deriver A then Deriver B",
        ));
    }
    if deriver_a.split_epoch() != deriver_b.split_epoch() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local HSS role-scoped shares must use one split epoch",
        ));
    }
    Ok(())
}

fn deterministic_hss_share_v1(
    label: &[u8],
    fixture_name: &str,
    split_epoch: &str,
    context_binding: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, LOCAL_ED25519_HSS_SPLIT_RELAYER_LABEL_V1);
    push_hash_field_v1(&mut hasher, label);
    push_hash_field_v1(&mut hasher, fixture_name.as_bytes());
    push_hash_field_v1(&mut hasher, split_epoch.as_bytes());
    push_hash_field_v1(&mut hasher, &context_binding);
    hasher.finalize().into()
}

fn sub_le_bytes_mod_2_256(total: [u8; 32], left: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in 0..32 {
        let difference = total[index] as i16 - left[index] as i16 - borrow;
        if difference < 0 {
            out[index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            out[index] = difference as u8;
            borrow = 0;
        }
    }
    out
}

fn sub_scalar_mod_l(total: [u8; 32], left: [u8; 32]) -> RouterAbProtocolResult<[u8; 32]> {
    let total = canonical_scalar_v1("tau_relayer", total)?;
    let left = Scalar::from_bytes_mod_order(left);
    Ok((total - left).to_bytes())
}

fn add_scalar_mod_l(left: [u8; 32], right: [u8; 32]) -> RouterAbProtocolResult<[u8; 32]> {
    let left = canonical_scalar_v1("tau_relayer left share", left)?;
    let right = canonical_scalar_v1("tau_relayer right share", right)?;
    Ok((left + right).to_bytes())
}

fn canonical_scalar_v1(field: &str, bytes: [u8; 32]) -> RouterAbProtocolResult<Scalar> {
    Scalar::from_canonical_bytes(bytes)
        .into_option()
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{field} must be canonical modulo ed25519 l"),
            )
        })
}

fn commitment_hex_v1(label: &[u8], material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, LOCAL_ED25519_HSS_SPLIT_RELAYER_LABEL_V1);
    push_hash_field_v1(&mut hasher, b"commitment");
    push_hash_field_v1(&mut hasher, label);
    push_hash_field_v1(&mut hasher, material);
    hex::encode(hasher.finalize())
}

fn signer_identity(role: Role) -> RouterAbProtocolResult<SignerIdentityV1> {
    match role {
        Role::SignerA => SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a"),
        Role::SignerB => SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b"),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local dev seed requires signer identity",
        )),
    }
}

fn root_epoch() -> RouterAbProtocolResult<RootShareEpoch> {
    RootShareEpoch::new("epoch-1").map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            error.to_string(),
        )
    })
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn local_env_map_v1(
    entries: impl IntoIterator<Item = (String, String)>,
) -> RouterAbProtocolResult<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for (key, value) in entries {
        require_non_empty("local env key", &key)?;
        if env.insert(key.clone(), value).is_some() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("duplicate local env key {key}"),
            ));
        }
    }
    Ok(env)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalHttpUrlPartsV1 {
    authority: String,
    path: String,
}

fn parse_http_bind_addr_v1(url: &str) -> RouterAbProtocolResult<String> {
    Ok(parse_http_url_parts_v1(url)?.authority)
}

fn parse_http_url_parts_v1(url: &str) -> RouterAbProtocolResult<LocalHttpUrlPartsV1> {
    require_non_empty("local worker bind URL", url)?;
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local worker bind URL must start with http://",
        ));
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    require_non_empty("local worker bind authority", authority)?;
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local worker bind URL must include host:port",
        ));
    };
    require_non_empty("local worker bind host", host)?;
    require_non_empty("local worker bind port", port)?;
    let parsed_port = port.parse::<u16>().map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker bind port is invalid: {error}"),
        )
    })?;
    Ok(LocalHttpUrlPartsV1 {
        authority: format!("{host}:{parsed_port}"),
        path,
    })
}

fn split_local_http_response_v1(response: &[u8]) -> RouterAbProtocolResult<(u16, Vec<u8>)> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            "local HTTP service-binding response missing header terminator",
        ));
    };
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!("local HTTP service-binding response headers are not UTF-8: {error}"),
        )
    })?;
    let status_line = headers.lines().next().unwrap_or_default();
    let mut status_parts = status_line.split_whitespace();
    let protocol = status_parts.next().unwrap_or_default();
    if protocol != "HTTP/1.1" && protocol != "HTTP/1.0" {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            "local HTTP service-binding response has invalid HTTP version",
        ));
    }
    let status = status_parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("local HTTP service-binding response status is invalid: {error}"),
            )
        })?;
    Ok((status, response[header_end + 4..].to_vec()))
}

fn map_local_http_io_error_v1(error: std::io::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
        format!("local HTTP service-binding I/O failed: {error}"),
    )
}

fn materialize_template_v1(template: &str, seed: &[u8]) -> RouterAbProtocolResult<String> {
    require_non_empty("local env materialization template", template)?;
    let replacements = [
        (
            "dev-only-deriver-a-envelope-hpke-private-key",
            "deriver-a-envelope-hpke-private-key",
        ),
        (
            "dev-only-deriver-b-envelope-hpke-private-key",
            "deriver-b-envelope-hpke-private-key",
        ),
        (
            "dev-only-deriver-a-root-share-wire-secret",
            "deriver-a-root-share-wire-secret",
        ),
        (
            "dev-only-deriver-b-root-share-wire-secret",
            "deriver-b-root-share-wire-secret",
        ),
        (
            "dev-only-deriver-a-peer-signing-key",
            "deriver-a-peer-signing-key",
        ),
        (
            "dev-only-deriver-b-peer-signing-key",
            "deriver-b-peer-signing-key",
        ),
        (
            "dev-only-deriver-a-peer-verifying-key",
            "deriver-a-peer-verifying-key",
        ),
        (
            "dev-only-deriver-b-peer-verifying-key",
            "deriver-b-peer-verifying-key",
        ),
        (
            "dev-only-signing-worker-relayer-output-hpke-private-key",
            "signing-worker-relayer-output-hpke-private-key",
        ),
    ];
    let mut contents = template.to_owned();
    for (placeholder, label) in replacements {
        let material = local_generated_secret_v1(label, seed)?;
        contents = contents.replace(placeholder, &material);
    }
    Ok(contents)
}

fn local_generated_secret_v1(label: &str, seed: &[u8]) -> RouterAbProtocolResult<String> {
    require_non_empty("local generated secret label", label)?;
    if seed.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            "local env materialization seed must not be empty",
        ));
    }
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, b"router-ab-dev/local-env-materialization/v1");
    push_hash_field_v1(&mut hasher, label.as_bytes());
    push_hash_field_v1(&mut hasher, seed);
    Ok(format!(
        "dev-only-generated-{label}-{}",
        hex::encode(hasher.finalize())
    ))
}

fn entries_from_env_map_v1(env: &BTreeMap<String, String>) -> Vec<(String, String)> {
    env.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn required_env_v1(
    env: &BTreeMap<String, String>,
    key: &'static str,
) -> RouterAbProtocolResult<String> {
    let value = env.get(key).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("missing local worker env key {key}"),
        )
    })?;
    require_non_empty(key, value)?;
    Ok(value.clone())
}

fn reject_forbidden_env_keys_v1(
    env: &BTreeMap<String, String>,
    forbidden_keys: &[&'static str],
) -> RouterAbProtocolResult<()> {
    for key in forbidden_keys {
        if env.contains_key(*key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!("local worker role cannot receive env key {key}"),
            ));
        }
    }
    Ok(())
}

fn require_exact_len_v1(field: &str, actual: usize, expected: usize) -> RouterAbProtocolResult<()> {
    if actual != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} expected {expected} entries, received {actual}"),
        ));
    }
    Ok(())
}

fn require_sqlite_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "local SQLite root-share store requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn push_hash_field_v1(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn sqlite_value(value: &LocalPersistenceSqlValueV1) -> Value {
    match value {
        LocalPersistenceSqlValueV1::Text(value) => Value::Text(value.clone()),
        LocalPersistenceSqlValueV1::U32(value) => Value::Integer(i64::from(*value)),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local SQLite seed failed: {error}"),
    )
}

fn map_hss_error(error: ed25519_hss::shared::ProtoError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ed25519-hss parity failed: {error}"),
    )
}

fn map_sqlite_missing_share(
    error: rusqlite::Error,
    role: Role,
    epoch: &RootShareEpoch,
) -> RouterAbProtocolError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "local SQLite signer startup missing {} root share for epoch {}",
                role.as_str(),
                epoch.as_str()
            ),
        ),
        other => map_sqlite_error(other),
    }
}
