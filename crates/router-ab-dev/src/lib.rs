#![forbid(unsafe_code)]
//! Local development adapters for Router/A/B signing.
//!
//! This crate may use local database drivers and filesystem-facing binaries.
//! The protocol crate remains transport-neutral and wasm-safe by default.

use base64::Engine;
use curve25519_dalek::scalar::Scalar;
use ecdsa_hss::ECDSA_HSS_PARTICIPANT_IDS;
use ed25519_hss::fixtures::{committed_fixture_corpus, FExpandFixture};
use ed25519_hss::role_signing::{
    create_role_separated_ed25519_client_signature_share_v1,
    finalize_role_separated_ed25519_server_signature_v1, prepare_role_separated_ed25519_round1_v1,
    role_separated_ed25519_client_verifying_share_v1,
    role_separated_ed25519_server_verifying_share_v1, RoleSeparatedEd25519ClientShareRequestV1,
    RoleSeparatedEd25519CommitmentsV1, RoleSeparatedEd25519Round1StateV1,
    RoleSeparatedEd25519ServerFinalizeRequestV1,
};
use ed25519_hss::shared::{
    add_le_bytes_mod_2_256, eval_f_expand, public_key_from_base_shares, FExpandOutput,
};
use rand_core::OsRng;
use router_ab_core::{
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    router_ab_delegate_action_fingerprint_from_canonical_borsh_b64u_v2,
    router_ab_ecdsa_hss_active_state_session_id_v1,
    router_ab_near_transaction_action_fingerprint_from_unsigned_borsh_b64u_v2,
    router_transcript_digest_v1, ActiveSigningWorkerStateV1, CandidateId, CanonicalWireBytesV1,
    CorrectnessLevel, EncryptedPayloadV1, ExpensiveWorkKindV1, LifecycleScopeV1,
    LocalDeriverAEndpointV1, LocalDeriverBEndpointV1, LocalEnvSnapshotV1,
    LocalHttpCeremonyResultV1, LocalHttpMethodV1, LocalHttpPathV1, LocalHttpRequestV1,
    LocalInProcessCeremonyResultV1, LocalPersistenceSeedV1, LocalPersistenceSqlExecutionReceiptV1,
    LocalPersistenceSqlSeedExecutorV1, LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1,
    LocalRouterEndpointV1, LocalSealedRootShareRecordV1, LocalServiceRoleV1, LocalServiceStackV1,
    LocalServiceStartupV1, LocalSigningRootMetadataV1, LocalSigningWorkerEndpointV1,
    LocalSigningWorkerRecipientProofBundleActivationV1, LocalTransportEnvelopeV1,
    LocalTransportRouteV1, NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningResponseV1,
    NormalSigningRound1PrepareResponseV1, NormalSigningScopeV1, NormalSigningSignatureSchemeV1,
    PublicRouterRequestV1, RoleEncryptedEnvelopeV1,
    RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1, RouterAbEcdsaHssEvmDigestSigningRequestV1,
    RouterAbEcdsaHssEvmDigestSigningResponseV1, RouterAbEcdsaHssNormalSigningScopeV1,
    RouterAbEcdsaHssSignatureSchemeV1, RouterAbEd25519NormalSigningFinalizeProtocolV2,
    RouterAbEd25519NormalSigningFinalizeRequestV2, RouterAbEd25519NormalSigningIntentV2,
    RouterAbEd25519NormalSigningPrepareBindingV2, RouterAbEd25519NormalSigningPrepareRequestV2,
    RouterAbEd25519PresignPoolAcceptedEntryV2, RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    RouterAbEd25519PresignPoolPrepareRequestV2, RouterAbEd25519PresignPoolPrepareResponseV2,
    RouterAbEd25519SigningPayloadV2, RouterAbEd25519TwoPartyFrostFinalizeProtocolV2,
    RouterAbNearDelegateActionIntentV1, RouterAbNearNetworkIdV2, RouterAbNearTransactionIntentV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
    RouterTranscriptMetadataV1, ServerIdentityV1, SignerIdentityV1, SignerSetV1,
    SigningRootShareStore, WireMessageKindV1, WireMessageV1,
};
use router_ab_core::{OpenedShareKind, PublicDigest32, Role, RootShareEpoch};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::threshold_ecdsa::threshold_ecdsa_finalize_signature;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

mod local_dev_http;
mod local_ecdsa_hss_pool_store;
mod local_service_http;
mod local_worker_topology;

pub use local_dev_http::{
    local_dev_http_error_body_v1, local_dev_http_handle_request_v1, local_dev_http_route_error_v1,
    read_local_dev_http_request_v1, require_local_dev_internal_service_auth_v1,
    require_local_dev_normal_signing_wallet_session_v2, write_local_dev_http_response_v1,
    LocalDevHttpErrorBodyV1, LocalDevHttpRequestPartsV1, LocalDevHttpTopologyV1,
};
use local_ecdsa_hss_pool_store::{
    local_signing_worker_ecdsa_hss_presignature_pool_store_put_v1,
    local_signing_worker_ecdsa_hss_presignature_pool_store_take_v1,
};
pub use local_service_http::{
    local_http_service_binding_endpoint_v1, local_http_service_binding_owner_v1,
    local_http_service_binding_path_v1, local_http_service_binding_url_v1,
    LocalHttpServiceBindingClientV1, LocalHttpServiceBindingEndpointV1,
};
pub use local_worker_topology::{
    local_worker_bind_addr_v1, local_worker_health_response_json_v1,
    local_worker_health_response_v1, local_worker_owned_paths_v1, local_worker_owns_path_v1,
    LocalWorkerHealthResponseV1,
};

const LOCAL_ED25519_HSS_SPLIT_SERVER_LABEL_V1: &[u8] = b"router-ab-dev/ed25519-hss/split-server/v1";
const LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1: &str = "split-epoch-1";
const LOCAL_NORMAL_SIGNING_ACTIVATION_MS_V1: u64 = 1_700_000_000_000;
const LOCAL_DEV_ACCOUNT_ID_V1: &str = "alice.testnet";

/// Local worker role env key used by the private-worker development harness.
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
/// SigningWorker server-output HPKE private-key env key.
pub const LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY";
/// SigningWorker server-output storage path env key.
pub const LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH";
/// SigningWorker public identity env key.
pub const LOCAL_SIGNING_WORKER_ID_ENV_V1: &str = "SIGNING_WORKER_ID";
/// SigningWorker key epoch env key.
pub const LOCAL_SIGNING_WORKER_KEY_EPOCH_ENV_V1: &str = "SIGNING_WORKER_KEY_EPOCH";
/// SigningWorker server-output HPKE public key env key.
pub const LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY";
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
pub const LOCAL_WORKER_HEALTH_PATH: &str = "/healthz";
/// Local readiness endpoint path.
pub const LOCAL_WORKER_READY_PATH: &str = "/readyz";
/// Router public normal-signing path mirrored from production.
pub const LOCAL_ROUTER_NORMAL_SIGNING_PATH: &str = "/router-ab/ed25519/sign";
/// Router public normal-signing round-1 prepare path mirrored from production.
pub const LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH: &str = "/router-ab/ed25519/sign/prepare";
/// Router public ECDSA-HSS digest-signing prepare path mirrored from production.
pub const LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH: &str = "/router-ab/ecdsa-hss/sign/prepare";
/// Router public ECDSA-HSS digest-signing finalize path mirrored from production.
pub const LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH: &str = "/router-ab/ecdsa-hss/sign";
/// Local private service-auth secret env key shared with the TypeScript relay.
pub const LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_ENV_V1: &str =
    "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET";
/// Local default private service-auth secret used when the env key is unset.
pub const LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1: &str =
    "dev-router-ab-internal-service-auth";
/// Local private service-auth header mirrored from strict Cloudflare.
pub const LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1: &str =
    "x-router-ab-internal-service-auth";
/// Deriver A private Router-dispatch path mirrored from production.
pub const LOCAL_DERIVER_A_PRIVATE_PATH: &str = "/router-ab/signer-a";
/// Deriver B private Router-dispatch path mirrored from production.
pub const LOCAL_DERIVER_B_PRIVATE_PATH: &str = "/router-ab/signer-b";
/// Deriver A private peer path mirrored from production.
pub const LOCAL_DERIVER_A_PEER_PATH: &str = "/router-ab/signer-a/peer";
/// Deriver B private peer path mirrored from production.
pub const LOCAL_DERIVER_B_PEER_PATH: &str = "/router-ab/signer-b/peer";
/// SigningWorker activation path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ACTIVATION_PATH: &str =
    "/router-ab/signing-worker/proof-bundle-activation";
/// SigningWorker normal-signing path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH: &str = "/router-ab/signing-worker/sign";
/// SigningWorker normal-signing round-1 prepare path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH: &str =
    "/router-ab/signing-worker/sign/prepare";
/// SigningWorker Ed25519 presign-pool prepare path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH: &str =
    "/router-ab/signing-worker/sign/presign-pool/prepare";
/// SigningWorker Ed25519 presign-pool-hit finalize path mirrored from production.
pub const LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH: &str =
    "/router-ab/signing-worker/sign/presign-pool";
/// SigningWorker ECDSA-HSS presignature pool-fill path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/presignature-pool/put";
/// SigningWorker ECDSA-HSS digest-signing prepare path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/sign/prepare";
/// SigningWorker ECDSA-HSS digest-signing finalize path mirrored from production.
pub const LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/sign";
/// Local HTTP service-binding content type for canonical protocol bytes.
pub const LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1: &str = "application/octet-stream";
/// Local HTTP service-binding content type for Worker-shaped JSON protocol calls.
pub const LOCAL_HTTP_JSON_CONTENT_TYPE_V1: &str = "application/json";
/// Default local HTTP service-binding timeout.
pub const LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1: u64 = 10_000;

pub fn validate_local_router_wallet_session_authorization_header_v2(
    authorization: Option<&str>,
) -> Result<(), &'static str> {
    let Some(header) = authorization else {
        return Err("local Router normal-signing Wallet Session authorization is missing");
    };
    let Some(token) = header.trim().strip_prefix("Bearer ") else {
        return Err("local Router normal-signing Wallet Session authorization must use Bearer");
    };
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("local Router normal-signing Wallet Session bearer token is invalid");
    }
    let mut segments = token.split('.');
    let Some(header_segment) = segments.next() else {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    };
    let Some(claims_segment) = segments.next() else {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    };
    let Some(signature_segment) = segments.next() else {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    };
    if segments.next().is_some() {
        return Err("local Router normal-signing Wallet Session JWT is invalid");
    }
    for segment in [header_segment, claims_segment, signature_segment] {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("local Router normal-signing Wallet Session JWT is invalid");
        }
    }
    Ok(())
}

/// Returns the local private service-auth secret used between Router and workers.
pub fn local_router_ab_internal_service_auth_secret_v1() -> String {
    std::env::var(LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_ENV_V1)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1.to_owned())
}

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
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
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
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
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
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
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
    /// SigningWorker server-output HPKE public key.
    pub server_output_hpke_public_key: String,
    /// SigningWorker server-output HPKE private key.
    pub server_output_hpke_private_key: String,
    /// SigningWorker server-output storage path.
    pub server_output_storage_path: String,
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

/// Local Durable Object storage scope for the private-worker harness.
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
    /// SigningWorker activation and active server-output state.
    SigningWorkerServerOutput,
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
            Self::SigningWorkerServerOutput => "signing_worker_server_output",
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
            Self::SigningWorkerServerOutput => LocalServiceRoleV1::SigningWorker,
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
            LocalDurableObjectScopeV1::SigningWorkerServerOutput,
            "activation/dev",
            br#"{"state":"activated"}"#.to_vec(),
        )?,
        LocalDurableObjectSeedEntryV1::new(
            LocalDurableObjectScopeV1::SigningWorkerServerOutput,
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
                    server_output_hpke_public_key: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV_V1,
                    )?,
                    server_output_hpke_private_key: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
                    )?,
                    server_output_storage_path: required_env_v1(
                        &env,
                        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1,
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

/// Public commitment to one role's local HSS server-input shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssSplitServerRoleCommitmentV1 {
    /// Deriver role that owns this split input share.
    pub role: Role,
    /// SHA-256 commitment to this role's `y_server` share.
    pub y_server_share_commitment_hex: String,
    /// SHA-256 commitment to this role's `tau_server` share.
    pub tau_server_share_commitment_hex: String,
}

/// Public parity evidence from the local HSS split-server dev adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssSplitServerParityReportV1 {
    /// Committed `ed25519-hss` fixture name.
    pub fixture_name: String,
    /// Local split epoch used to derive role-specific server-input shares.
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
    pub x_server_base_commitment_hex: String,
    /// Deriver A split server-input commitments.
    pub deriver_a: LocalEd25519HssSplitServerRoleCommitmentV1,
    /// Deriver B split server-input commitments.
    pub deriver_b: LocalEd25519HssSplitServerRoleCommitmentV1,
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
            | (Role::Server, OpenedShareKind::XServerBase) => Ok(()),
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
            OpenedShareKind::XServerBase => b"x_server_base".as_slice(),
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
    /// Local split epoch used for Deriver A/B server-input shares.
    pub split_epoch: String,
    /// Client-scoped `x_client_base` output.
    pub client_output: LocalEd25519HssRecipientBaseShareV1,
    /// SigningWorker-scoped `x_server_base` output.
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
    /// Public HSS parity report for Deriver A/B split server shares.
    pub hss_parity: LocalEd25519HssSplitServerParityReportV1,
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
    /// Public HSS parity report for Deriver A/B split server shares.
    pub hss_parity: LocalEd25519HssSplitServerParityReportV1,
}

/// Local SDK server Ed25519 key-store seed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalRouterEd25519KeyStoreSeedV1 {
    pub relayer_key_id: String,
    pub wallet_id: String,
    pub near_account_id: String,
    pub near_ed25519_signing_key_id: String,
    pub rp_id: String,
    pub threshold_session_id: String,
    pub signing_grant_id: String,
    pub public_key: String,
    pub relayer_signing_share_b64u: String,
    pub key_version: String,
    pub threshold_expires_at_ms: u64,
    pub participant_ids: Vec<u32>,
    pub remaining_uses: u32,
    pub recovery_export_capable: bool,
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
            LOCAL_DERIVER_A_PEER_PATH,
            WireMessageKindV1::SignerBToSignerA,
            Role::SignerB,
            Role::SignerA,
        ),
        LocalServiceRoleV1::DeriverB => (
            LOCAL_DERIVER_B_PEER_PATH,
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
    /// Transcript digest shared by the server-output bundles.
    pub transcript_digest_hex: String,
    /// Digest of Deriver A's encrypted server-output bundle.
    pub deriver_a_bundle_digest_hex: String,
    /// Digest of Deriver B's encrypted server-output bundle.
    pub deriver_b_bundle_digest_hex: String,
    /// Redacted receipt status.
    pub status: String,
}

/// Local SigningWorker round-1 nonce record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerRound1RecordV1 {
    /// Active SigningWorker state selected for this signing request.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle.
    pub server_round1_handle: String,
    /// Digest binding the nonce to the exact prepare/finalize context.
    pub round1_binding_digest: PublicDigest32,
    /// Intent digest admitted by Router during prepare.
    pub intent_digest: PublicDigest32,
    /// Signing-payload digest admitted by Router during prepare.
    pub signing_payload_digest: PublicDigest32,
    /// Exact 32-byte digest this nonce material may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Server-owned round-1 nonce material.
    pub round1_state: RoleSeparatedEd25519Round1StateV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Private SigningWorker request to fill the local ECDSA-HSS presignature pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Validates request fields without applying wall-clock expiry.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        decode_base64url_fixed_33_v1("server_big_r33_b64u", &self.server_big_r33_b64u)?;
        decode_base64url_fixed_32_v1("server_k_share32_b64u", &self.server_k_share32_b64u)?;
        decode_base64url_fixed_32_v1("server_sigma_share32_b64u", &self.server_sigma_share32_b64u)?;
        require_positive_unix_ms_v1(
            "ECDSA-HSS presignature pool fill expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates this pool-fill request can be accepted at the supplied timestamp.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_unix_ms_v1("ECDSA-HSS presignature pool fill now_unix_ms", now_unix_ms)?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS presignature pool fill request expired",
            ));
        }
        Ok(())
    }

    fn to_pool_record(
        &self,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1> {
        self.validate_at(now_unix_ms)?;
        LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1::new(
            active_signing_worker_state,
            self.server_presignature_id.clone(),
            self.server_big_r33_b64u.clone(),
            self.server_k_share32_b64u.clone(),
            self.server_sigma_share32_b64u.clone(),
            now_unix_ms,
            self.expires_at_ms,
        )
    }
}

/// Redacted receipt returned by the local ECDSA-HSS presignature pool-fill route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1 {
    /// Active SigningWorker state selected for this pool entry.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id accepted by the route.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Whether the entry was inserted into the one-use pool.
    pub stored: bool,
}

impl LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1 {
    fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty(
            "receipt.server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_base64url_fixed_33_v1("receipt.server_big_r33_b64u", &self.server_big_r33_b64u)?;
        Ok(())
    }
}

/// Local Router admission attached to a private ECDSA-HSS SigningWorker request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterEcdsaHssTrustedAdmissionV1 {
    /// Wallet/account id admitted by Router.
    pub account_id: String,
    /// Active ECDSA-HSS signing session id admitted by Router.
    pub session_id: String,
    /// Canonical request digest admitted by Router.
    pub request_digest: PublicDigest32,
    /// Exact EVM digest admitted for SigningWorker signing.
    pub signing_digest: PublicDigest32,
    /// Admission timestamp in Unix milliseconds.
    pub admitted_at_ms: u64,
    /// Expiry timestamp copied from the admitted request.
    pub expires_at_ms: u64,
}

impl LocalRouterEcdsaHssTrustedAdmissionV1 {
    fn validate_common(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("local ECDSA-HSS admission account_id", &self.account_id)?;
        require_non_empty("local ECDSA-HSS admission session_id", &self.session_id)?;
        require_positive_unix_ms_v1(
            "local ECDSA-HSS admission admitted_at_ms",
            self.admitted_at_ms,
        )?;
        require_positive_unix_ms_v1(
            "local ECDSA-HSS admission expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms <= self.admitted_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS admission expiry must be after admission",
            ));
        }
        Ok(())
    }

    fn validate_for_prepare(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_common()?;
        request.validate()?;
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS prepare admission account_id does not match request scope",
            ));
        }
        if self.session_id
            != router_ab_ecdsa_hss_active_state_session_id_v1(
                &request.scope.ecdsa_threshold_key_id,
                &request.scope.signing_root_id,
                &request.scope.signing_root_version,
                &request.scope.activation_epoch,
            )?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS prepare admission session_id does not match request scope",
            ));
        }
        if self.request_digest != request.request_digest()?
            || self.signing_digest != request.signing_digest()?
            || self.expires_at_ms != request.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS prepare admission does not match request",
            ));
        }
        Ok(())
    }

    fn validate_for_finalize(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_common()?;
        request.validate()?;
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS finalize admission account_id does not match request scope",
            ));
        }
        if self.session_id
            != router_ab_ecdsa_hss_active_state_session_id_v1(
                &request.scope.ecdsa_threshold_key_id,
                &request.scope.signing_root_id,
                &request.scope.signing_root_version,
                &request.scope.activation_epoch,
            )?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS finalize admission session_id does not match request scope",
            ));
        }
        if self.request_digest != request.request_digest()?
            || self.signing_digest != request.signing_digest()?
            || self.expires_at_ms != request.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "local ECDSA-HSS finalize admission does not match request",
            ));
        }
        Ok(())
    }
}

/// Local Router-admitted ECDSA-HSS prepare request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerAdmittedEcdsaHssPrepareRequestV1 {
    /// Typed public ECDSA-HSS prepare request accepted by Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
    /// Trusted local Router admission for this exact request.
    pub trusted_admission: LocalRouterEcdsaHssTrustedAdmissionV1,
}

impl LocalSigningWorkerAdmittedEcdsaHssPrepareRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.trusted_admission.validate_for_prepare(&self.request)
    }
}

/// Local Router-admitted ECDSA-HSS finalize request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerAdmittedEcdsaHssFinalizeRequestV1 {
    /// Typed public ECDSA-HSS finalize request accepted by Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    /// Trusted local Router admission for this exact finalize request.
    pub trusted_admission: LocalRouterEcdsaHssTrustedAdmissionV1,
}

impl LocalSigningWorkerAdmittedEcdsaHssFinalizeRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.trusted_admission.validate_for_finalize(&self.request)
    }
}

/// One-use local ECDSA-HSS presignature pool record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1 {
    /// Active SigningWorker state selected for this pool entry.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Insertion timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl LocalSigningWorkerEcdsaHssPresignaturePoolRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty(
            "ECDSA-HSS pool record server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_base64url_fixed_33_v1(
            "ECDSA-HSS pool record server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS pool record server_k_share32_b64u",
            &self.server_k_share32_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS pool record server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
        )?;
        require_positive_unix_ms_v1("ECDSA-HSS pool record created_at_ms", self.created_at_ms)?;
        require_positive_unix_ms_v1("ECDSA-HSS pool record expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms <= self.created_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "ECDSA-HSS pool record expiry must be after creation",
            ));
        }
        Ok(())
    }

    fn same_pool_identity_and_material(&self, other: &Self) -> bool {
        self.active_signing_worker_state == other.active_signing_worker_state
            && self.server_presignature_id == other.server_presignature_id
            && self.server_big_r33_b64u == other.server_big_r33_b64u
            && self.server_k_share32_b64u == other.server_k_share32_b64u
            && self.server_sigma_share32_b64u == other.server_sigma_share32_b64u
            && self.expires_at_ms == other.expires_at_ms
    }
}

/// One-use local ECDSA-HSS presignature record bound to an exact signing request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerEcdsaHssPresignatureRecordV1 {
    /// Active SigningWorker state selected for this signing request.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id consumed by finalize.
    pub server_presignature_id: String,
    /// Canonical prepare request digest.
    pub request_digest: PublicDigest32,
    /// Exact 32-byte EVM digest this presignature may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Public 32-byte rerandomization entropy both ECDSA parties must use.
    pub rerandomization_entropy32_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Insertion timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl LocalSigningWorkerEcdsaHssPresignatureRecordV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        server_big_r33_b64u: impl Into<String>,
        rerandomization_entropy32_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            request_digest,
            admitted_signing_digest,
            server_big_r33_b64u: server_big_r33_b64u.into(),
            rerandomization_entropy32_b64u: rerandomization_entropy32_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty(
            "ECDSA-HSS prepared record server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_base64url_fixed_33_v1(
            "ECDSA-HSS prepared record server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS prepared record rerandomization_entropy32_b64u",
            &self.rerandomization_entropy32_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS prepared record server_k_share32_b64u",
            &self.server_k_share32_b64u,
        )?;
        decode_base64url_fixed_32_v1(
            "ECDSA-HSS prepared record server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
        )?;
        require_positive_unix_ms_v1(
            "ECDSA-HSS prepared record created_at_ms",
            self.created_at_ms,
        )?;
        require_positive_unix_ms_v1(
            "ECDSA-HSS prepared record expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms <= self.created_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "ECDSA-HSS prepared record expiry must be after creation",
            ));
        }
        Ok(())
    }

    fn validate_for_finalize(
        &self,
        active_signing_worker_state: &ActiveSigningWorkerStateV1,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate_at(now_unix_ms)?;
        if self.active_signing_worker_state != *active_signing_worker_state {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "local ECDSA-HSS prepared record active SigningWorker mismatch",
            ));
        }
        if self.server_presignature_id != request.server_presignature_id
            || self.request_digest != request.prepare_request_digest()?
            || self.admitted_signing_digest != request.signing_digest()?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "local ECDSA-HSS finalize request does not match prepared presignature",
            ));
        }
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "local ECDSA-HSS prepared presignature expired",
            ));
        }
        Ok(())
    }
}

impl LocalSigningWorkerRound1RecordV1 {
    /// Creates a validated local round-1 record.
    pub fn new(
        active_signing_worker: ActiveSigningWorkerStateV1,
        server_round1_handle: impl Into<String>,
        round1_binding_digest: PublicDigest32,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        round1_state: RoleSeparatedEd25519Round1StateV1,
        prepared_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker,
            server_round1_handle: server_round1_handle.into(),
            round1_binding_digest,
            intent_digest,
            signing_payload_digest,
            admitted_signing_digest,
            round1_state,
            prepared_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the stored nonce record.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker.validate()?;
        require_non_empty("local server_round1_handle", &self.server_round1_handle)?;
        self.round1_state
            .validate()
            .map_err(map_hss_normal_signing_error_v1)?;
        if self.prepared_at_ms == 0 || self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "local round-1 timestamps must be greater than zero",
            ));
        }
        if self.expires_at_ms > self.prepared_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "local round-1 expiry must be after prepare time",
        ))
    }
}

impl fmt::Debug for LocalSigningWorkerRound1RecordV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigningWorkerRound1RecordV1")
            .field("active_signing_worker", &self.active_signing_worker)
            .field("server_round1_handle", &self.server_round1_handle)
            .field("round1_binding_digest", &self.round1_binding_digest)
            .field("intent_digest", &self.intent_digest)
            .field("signing_payload_digest", &self.signing_payload_digest)
            .field("admitted_signing_digest", &self.admitted_signing_digest)
            .field("round1_state", &self.round1_state)
            .field("prepared_at_ms", &self.prepared_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Handles the local SigningWorker round-1 prepare route.
pub fn handle_local_signing_worker_normal_signing_round1_prepare_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local normal-signing round-1 prepare route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker normal-signing round-1 prepare route must be served at {}",
                LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH
            ),
        ));
    }
    let private_request = parse_local_json_body_v1::<
        LocalSigningWorkerEd25519PreparePrivateRequestV1,
    >("local normal-signing round-1 prepare private request", body)?;
    private_request.validate()?;
    let request = &private_request.request;
    let prepared_at_ms = local_now_unix_ms_v1()?;
    if prepared_at_ms >= request.expires_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "local normal-signing round-1 prepare request expired",
        ));
    }
    let admission = request.admission_material()?;
    let active_signing_worker = private_request
        .server_material
        .active_signing_worker_state(config, &request.scope)?;
    let material = private_request.server_material.normal_signing_material()?;
    let mut rng = OsRng;
    let round1_state = prepare_role_separated_ed25519_round1_v1(&mut rng)
        .map_err(map_hss_normal_signing_error_v1)?;
    let mut handle_random = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rng, &mut handle_random);
    let server_round1_handle = format!(
        "local-server-round1/{}/{}",
        request.scope.request_id,
        encode_base64url_bytes_v1(&handle_random)
    );
    let server_verifying_share =
        role_separated_ed25519_server_verifying_share_v1(material.x_server_base)
            .map_err(map_hss_normal_signing_error_v1)?;
    let server_commitments =
        local_normal_signing_commitments_wire_from_role_separated_v1(round1_state.commitments)?;
    let round1_binding_digest = request.round1_binding_digest()?;
    let record = LocalSigningWorkerRound1RecordV1::new(
        active_signing_worker.clone(),
        server_round1_handle.clone(),
        round1_binding_digest,
        admission.intent_digest,
        admission.signing_payload_digest,
        admission.admitted_signing_digest,
        round1_state,
        prepared_at_ms,
        request.expires_at_ms,
    )?;
    let response = NormalSigningRound1PrepareResponseV1::new(
        request.scope.clone(),
        admission.signing_payload_digest,
        round1_binding_digest,
        active_signing_worker.signing_worker.clone(),
        server_round1_handle,
        server_commitments,
        encode_base64url_bytes_v1(&server_verifying_share),
        NormalSigningSignatureSchemeV1::Ed25519V1,
        prepared_at_ms,
        request.expires_at_ms,
    )?;
    response.validate_for_v2_prepare_request(request)?;
    local_signing_worker_round1_store_put_v1(record)?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker normal-signing round-1 prepare response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker Ed25519 presign-pool prepare route.
pub fn handle_local_signing_worker_normal_signing_presign_pool_prepare_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local normal-signing presign-pool prepare route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker normal-signing presign-pool prepare route must be served at {}",
                LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH
            ),
        ));
    }
    let private_request =
        parse_local_json_body_v1::<LocalSigningWorkerEd25519PresignPoolPreparePrivateRequestV1>(
            "local normal-signing presign-pool prepare private request",
            body,
        )?;
    private_request.validate()?;
    let request = &private_request.request;
    let prepared_at_ms = local_now_unix_ms_v1()?;
    request.validate_at(prepared_at_ms)?;
    let active_signing_worker = private_request
        .server_material
        .active_signing_worker_state(config, &request.scope)?;
    let material = private_request.server_material.normal_signing_material()?;
    let server_verifying_share =
        role_separated_ed25519_server_verifying_share_v1(material.x_server_base)
            .map_err(map_hss_normal_signing_error_v1)?;
    let server_verifying_share_b64u = encode_base64url_bytes_v1(&server_verifying_share);
    let mut rng = OsRng;
    let mut accepted = Vec::with_capacity(request.client_offers.len());
    let mut records = Vec::with_capacity(request.client_offers.len());
    for offer in &request.client_offers {
        let round1_state = prepare_role_separated_ed25519_round1_v1(&mut rng)
            .map_err(map_hss_normal_signing_error_v1)?;
        let mut handle_random = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rng, &mut handle_random);
        let server_round1_handle = format!(
            "local-server-round1-pool/{}/{}/{}",
            request.generation,
            offer.client_presign_id,
            encode_base64url_bytes_v1(&handle_random)
        );
        let pool_entry_binding_digest = request.pool_entry_binding_digest(offer)?;
        let server_commitments =
            local_normal_signing_commitments_wire_from_role_separated_v1(round1_state.commitments)?;
        let record = LocalSigningWorkerEd25519PresignPoolRecordV1 {
            active_signing_worker: active_signing_worker.clone(),
            scope: request.scope.clone(),
            client_presign_id: offer.client_presign_id.clone(),
            client_nonce_handle: offer.client_nonce_handle.clone(),
            generation: request.generation,
            pool_entry_binding_digest,
            server_round1_handle: server_round1_handle.clone(),
            client_commitments: offer.client_commitments.clone(),
            client_verifying_share_b64u: offer.client_verifying_share_b64u.clone(),
            round1_state,
            server_verifying_share_b64u: server_verifying_share_b64u.clone(),
            prepared_at_ms,
            expires_at_ms: request.expires_at_ms,
        };
        record.validate()?;
        let accepted_entry = RouterAbEd25519PresignPoolAcceptedEntryV2::new(
            offer.client_presign_id.clone(),
            request.generation,
            pool_entry_binding_digest,
            active_signing_worker.signing_worker.clone(),
            server_round1_handle,
            server_commitments,
            server_verifying_share_b64u.clone(),
            NormalSigningSignatureSchemeV1::Ed25519V1,
            prepared_at_ms,
            request.expires_at_ms,
        )?;
        records.push(record);
        accepted.push(accepted_entry);
    }
    for record in records {
        local_signing_worker_ed25519_presign_pool_store_put_v1(record)?;
    }
    let response = RouterAbEd25519PresignPoolPrepareResponseV2::new(
        request.scope.clone(),
        request.generation,
        accepted,
        vec![],
    )?;
    response.validate_for_request(request)?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker normal-signing presign-pool prepare response JSON serialization failed: {error}"
            ),
        )
    })
}

fn local_finalize_normal_signing_response_v1(
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: LocalSigningWorkerNormalSigningMaterialV1,
    round1_state: &RoleSeparatedEd25519Round1StateV1,
    admitted_signing_digest: PublicDigest32,
    prepared_at_ms: u64,
) -> RouterAbProtocolResult<NormalSigningResponseV1> {
    let RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(protocol) =
        &request.protocol;
    let server_commitments =
        decode_local_normal_signing_commitments_v1(&protocol.server_commitments)?;
    if server_commitments != round1_state.commitments {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local normal-signing server commitments do not match stored round-1 material",
        ));
    }
    let output = finalize_role_separated_ed25519_server_signature_v1(
        RoleSeparatedEd25519ServerFinalizeRequestV1 {
            x_server_base: material.x_server_base,
            server_round1: round1_state,
            group_public_key: decode_near_ed25519_public_key_v1(
                "local normal-signing group_public_key",
                &active_signing_worker.account_public_key,
            )?,
            client_commitments: decode_local_normal_signing_commitments_v1(
                &protocol.client_commitments,
            )?,
            server_commitments,
            client_verifying_share: decode_base64url_fixed_32_v1(
                "local normal-signing client_verifying_share_b64u",
                &protocol.client_verifying_share_b64u,
            )?,
            server_verifying_share: decode_base64url_fixed_32_v1(
                "local normal-signing server_verifying_share_b64u",
                &protocol.server_verifying_share_b64u,
            )?,
            client_signature_share: decode_base64url_fixed_32_v1(
                "local normal-signing client_signature_share_b64u",
                &protocol.client_signature_share_b64u,
            )?,
            signing_payload: admitted_signing_digest.as_bytes(),
        },
    )
    .map_err(map_hss_normal_signing_error_v1)?;
    NormalSigningResponseV1::new(
        request.scope.clone(),
        request.signing_payload_digest(),
        active_signing_worker.signing_worker,
        request.protocol.signature_scheme(),
        CanonicalWireBytesV1::new(output.signature.to_vec())?,
        prepared_at_ms + 1,
    )
}

/// Handles the local SigningWorker normal-signing finalize route.
pub fn handle_local_signing_worker_normal_signing_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local normal-signing route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker normal-signing route must be served at {}",
                LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH
            ),
        ));
    }
    let private_request = parse_local_json_body_v1::<
        LocalSigningWorkerEd25519FinalizePrivateRequestV1,
    >("local normal-signing finalize private request", body)?;
    private_request.validate()?;
    let request = &private_request.request;
    let active_signing_worker = private_request
        .server_material
        .active_signing_worker_state(config, &request.scope)?;
    let material = private_request.server_material.normal_signing_material()?;
    let record = local_signing_worker_round1_store_take_v1(
        request.server_round1_handle(),
        request.round1_binding_digest(),
    )?;
    record.validate()?;
    if record.active_signing_worker != active_signing_worker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local normal-signing active SigningWorker state does not match prepared round-1 record",
        ));
    }
    if record.expires_at_ms != request.expires_at_ms
        || record.intent_digest != request.intent_digest()
        || record.signing_payload_digest != request.signing_payload_digest()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local normal-signing v2 finalize request does not match prepared admission",
        ));
    }
    let response = local_finalize_normal_signing_response_v1(
        request,
        active_signing_worker,
        material,
        &record.round1_state,
        record.admitted_signing_digest,
        record.prepared_at_ms,
    )?;
    response.validate_for_v2_finalize_request(request)?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker normal-signing response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker Ed25519 presign-pool-hit finalize route.
pub fn handle_local_signing_worker_normal_signing_presign_pool_hit_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local normal-signing presign-pool-hit route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker normal-signing presign-pool-hit route must be served at {}",
                LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH
            ),
        ));
    }
    let private_request =
        parse_local_json_body_v1::<LocalSigningWorkerEd25519PresignPoolHitPrivateRequestV1>(
            "local normal-signing presign-pool-hit private request",
            body,
        )?;
    private_request.validate()?;
    let pool_hit_request = &private_request.request;
    let now_unix_ms = local_now_unix_ms_v1()?;
    pool_hit_request.validate_at(now_unix_ms)?;
    let active_signing_worker = private_request
        .server_material
        .active_signing_worker_state(config, &pool_hit_request.scope)?;
    let material = private_request.server_material.normal_signing_material()?;
    let pool_entry = local_signing_worker_ed25519_presign_pool_store_take_v1(
        pool_hit_request.server_round1_handle(),
        pool_hit_request.pool_binding.pool_entry_binding_digest,
    )?;
    pool_entry.validate()?;
    let RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(protocol) =
        &pool_hit_request.protocol;
    let expected_server_commitments = local_normal_signing_commitments_wire_from_role_separated_v1(
        pool_entry.round1_state.commitments,
    )?;
    if pool_entry.active_signing_worker != active_signing_worker
        || pool_entry.client_presign_id != pool_hit_request.pool_binding.client_presign_id
        || pool_entry.client_nonce_handle != pool_hit_request.pool_binding.client_nonce_handle
        || pool_entry.generation != pool_hit_request.pool_binding.generation
        || pool_entry.server_round1_handle != pool_hit_request.pool_binding.server_round1_handle
        || pool_entry.pool_entry_binding_digest
            != pool_hit_request.pool_binding.pool_entry_binding_digest
        || pool_entry.client_commitments != protocol.client_commitments
        || pool_entry.client_verifying_share_b64u != protocol.client_verifying_share_b64u
        || expected_server_commitments != protocol.server_commitments
        || pool_entry.server_verifying_share_b64u != protocol.server_verifying_share_b64u
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local presign-pool-hit request does not match prepared pool entry",
        ));
    }
    let normal_request = pool_hit_request.to_normal_finalize_request_v2()?;
    let admission = pool_hit_request.admission_material()?;
    let response = local_finalize_normal_signing_response_v1(
        &normal_request,
        active_signing_worker,
        material,
        &pool_entry.round1_state,
        admission.admitted_signing_digest,
        pool_entry.prepared_at_ms,
    )?;
    response.validate_for_v2_finalize_request(&normal_request)?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker normal-signing presign-pool-hit response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker ECDSA-HSS presignature pool-fill route.
pub fn handle_local_signing_worker_ecdsa_hss_presignature_pool_put_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local ECDSA-HSS presignature pool-fill route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker ECDSA-HSS presignature pool-fill route must be served at {}",
                LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH
            ),
        ));
    }
    let now_unix_ms = local_now_unix_ms_v1()?;
    let request = parse_local_json_body_v1::<LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1>(
        "local ECDSA-HSS presignature pool-fill request",
        body,
    )?;
    request.validate_at(now_unix_ms)?;
    let active_signing_worker_state =
        local_active_ecdsa_hss_signing_worker_state_v1(config, &request.scope)?;
    let record = request.to_pool_record(active_signing_worker_state.clone(), now_unix_ms)?;
    let stored = local_signing_worker_ecdsa_hss_presignature_pool_store_put_v1(record)?;
    let receipt = LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1::new(
        active_signing_worker_state,
        request.server_presignature_id,
        request.server_big_r33_b64u,
        stored,
    )?;
    serde_json::to_string(&receipt).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker ECDSA-HSS presignature pool-fill receipt JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker ECDSA-HSS digest-signing prepare route.
pub fn handle_local_signing_worker_ecdsa_hss_prepare_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local ECDSA-HSS prepare route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker ECDSA-HSS prepare route must be served at {}",
                LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH
            ),
        ));
    }
    let now_unix_ms = local_now_unix_ms_v1()?;
    let admitted = parse_local_json_body_v1::<LocalSigningWorkerAdmittedEcdsaHssPrepareRequestV1>(
        "local admitted ECDSA-HSS prepare request",
        body,
    )?;
    admitted.validate()?;
    let request = admitted.request;
    request.validate_at(now_unix_ms)?;
    let active_signing_worker_state =
        local_active_ecdsa_hss_signing_worker_state_v1(config, &request.scope)?;
    let pool_record = local_signing_worker_ecdsa_hss_presignature_pool_store_take_v1(
        &active_signing_worker_state,
        &request.client_presignature_id,
        now_unix_ms,
    )?;
    let mut rerandomization_entropy32 = [0u8; 32];
    let mut rng = OsRng;
    rand_core::RngCore::fill_bytes(&mut rng, &mut rerandomization_entropy32);
    let rerandomization_entropy32_b64u = encode_base64url_bytes_v1(&rerandomization_entropy32);
    let response = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request,
        pool_record.server_presignature_id.clone(),
        pool_record.server_big_r33_b64u.clone(),
        rerandomization_entropy32_b64u.clone(),
        now_unix_ms,
    )?;
    let prepared_record = LocalSigningWorkerEcdsaHssPresignatureRecordV1::new(
        active_signing_worker_state,
        pool_record.server_presignature_id,
        request.request_digest()?,
        request.signing_digest()?,
        pool_record.server_big_r33_b64u,
        rerandomization_entropy32_b64u,
        pool_record.server_k_share32_b64u,
        pool_record.server_sigma_share32_b64u,
        now_unix_ms,
        request.expires_at_ms,
    )?;
    local_signing_worker_ecdsa_hss_presignature_store_put_v1(prepared_record)?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker ECDSA-HSS prepare response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Handles the local SigningWorker ECDSA-HSS digest-signing finalize route.
pub fn handle_local_signing_worker_ecdsa_hss_finalize_json_v1(
    config: &LocalSigningWorkerConfigV1,
    receiver_role: LocalServiceRoleV1,
    path: &str,
    body: &[u8],
) -> RouterAbProtocolResult<String> {
    if receiver_role != LocalServiceRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local ECDSA-HSS finalize route requires SigningWorker receiver",
        ));
    }
    if path != LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker ECDSA-HSS finalize route must be served at {}",
                LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH
            ),
        ));
    }
    let now_unix_ms = local_now_unix_ms_v1()?;
    let admitted = parse_local_json_body_v1::<LocalSigningWorkerAdmittedEcdsaHssFinalizeRequestV1>(
        "local admitted ECDSA-HSS finalize request",
        body,
    )?;
    admitted.validate()?;
    let request = admitted.request;
    request.validate_at(now_unix_ms)?;
    let active_signing_worker_state =
        local_active_ecdsa_hss_signing_worker_state_v1(config, &request.scope)?;
    let prepare_request_digest = request.prepare_request_digest()?;
    let record = local_signing_worker_ecdsa_hss_presignature_store_take_v1(
        &request.server_presignature_id,
        prepare_request_digest,
    )?;
    record.validate_for_finalize(&active_signing_worker_state, &request, now_unix_ms)?;
    let participant_ids = ECDSA_HSS_PARTICIPANT_IDS.map(u32::from);
    let signature65 = threshold_ecdsa_finalize_signature(
        &participant_ids,
        2,
        &decode_base64url_fixed_33_v1(
            "local ECDSA-HSS threshold_public_key33_b64u",
            &request.scope.public_identity.threshold_public_key33_b64u,
        )?,
        &decode_base64url_fixed_33_v1(
            "local ECDSA-HSS server_big_r33_b64u",
            &record.server_big_r33_b64u,
        )?,
        &decode_base64url_fixed_32_v1(
            "local ECDSA-HSS server_k_share32_b64u",
            &record.server_k_share32_b64u,
        )?,
        &decode_base64url_fixed_32_v1(
            "local ECDSA-HSS server_sigma_share32_b64u",
            &record.server_sigma_share32_b64u,
        )?,
        record.admitted_signing_digest.as_bytes(),
        &decode_base64url_fixed_32_v1(
            "local ECDSA-HSS rerandomization_entropy32_b64u",
            &record.rerandomization_entropy32_b64u,
        )?,
        &request.client_signature_share32()?,
    )
    .map_err(map_signer_core_ecdsa_error_v1)?;
    let response = RouterAbEcdsaHssEvmDigestSigningResponseV1 {
        scope: request.scope.clone(),
        request_id: request.request_id.clone(),
        request_digest: request.request_digest()?,
        signing_digest: request.signing_digest()?,
        signature_scheme: RouterAbEcdsaHssSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
        signature65_b64u: encode_base64url_bytes_v1(&signature65),
    };
    response.validate()?;
    serde_json::to_string(&response).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "local SigningWorker ECDSA-HSS finalize response JSON serialization failed: {error}"
            ),
        )
    })
}

/// Explicit fixture input for local normal-signing smoke helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNormalSigningSmokeFixtureV1 {
    pub fixture_name: String,
    pub split_epoch: String,
    pub account_id: String,
    pub session_id: String,
    pub signing_worker_id: String,
}

impl LocalNormalSigningSmokeFixtureV1 {
    pub fn new(
        fixture_name: impl Into<String>,
        split_epoch: impl Into<String>,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let fixture = Self {
            fixture_name: fixture_name.into(),
            split_epoch: split_epoch.into(),
            account_id: account_id.into(),
            session_id: session_id.into(),
            signing_worker_id: signing_worker_id.into(),
        };
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "local normal-signing smoke fixture_name",
            &self.fixture_name,
        )?;
        require_non_empty("local normal-signing smoke split_epoch", &self.split_epoch)?;
        require_non_empty("local normal-signing smoke account_id", &self.account_id)?;
        require_non_empty("local normal-signing smoke session_id", &self.session_id)?;
        require_non_empty(
            "local normal-signing smoke signing_worker_id",
            &self.signing_worker_id,
        )
    }
}

/// Builds a typed v2 NEAR transaction prepare request for local smoke flows.
pub fn build_local_normal_signing_near_transaction_prepare_request_v2(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    request_id: impl Into<String>,
    unsigned_transaction_borsh: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningPrepareRequestV2> {
    fixture.validate()?;
    let request_id = request_id.into();
    let scope = local_normal_signing_scope_v2(fixture, request_id.clone())?;
    let unsigned_transaction_borsh_b64u = encode_base64url_bytes_v1(unsigned_transaction_borsh);
    let expected_signing_digest_b64u =
        local_normal_signing_expected_digest_b64u_v2(unsigned_transaction_borsh);
    let operation_fingerprint =
        local_normal_signing_operation_fingerprint_v2(&expected_signing_digest_b64u);
    let action_fingerprint =
        router_ab_near_transaction_action_fingerprint_from_unsigned_borsh_b64u_v2(
            &unsigned_transaction_borsh_b64u,
        )?;
    let intent = RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
        operation_id: format!("local-normal-signing/{request_id}"),
        operation_fingerprint: operation_fingerprint.clone(),
        near_account_id: fixture.account_id.clone(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        transactions: vec![RouterAbNearTransactionIntentV1::new(
            "local-router.test.near",
            action_fingerprint,
        )?],
        unsigned_transaction_borsh_b64u: unsigned_transaction_borsh_b64u.clone(),
    };
    let signing_payload = RouterAbEd25519SigningPayloadV2::NearUnsignedTransactionBorshV1 {
        unsigned_transaction_borsh_b64u,
        expected_signing_digest_b64u,
    };
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        scope,
        2_000_000_000_000,
        intent,
        signing_payload,
    )
}

/// Builds a typed v2 NEP-413 prepare request for local smoke flows.
pub fn build_local_normal_signing_nep413_prepare_request_v2(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    request_id: impl Into<String>,
    message: impl Into<String>,
    recipient: impl Into<String>,
    callback_url: Option<String>,
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningPrepareRequestV2> {
    fixture.validate()?;
    let request_id = request_id.into();
    let message = message.into();
    let recipient = recipient.into();
    let scope = local_normal_signing_scope_v2(fixture, request_id.clone())?;
    let nonce_b64u = encode_base64url_bytes_v1(&[0x41; 32]);
    let canonical_message_b64u =
        router_ab_core::router_ab_ed25519_nep413_canonical_message_b64u_v2(
            &message,
            &recipient,
            &nonce_b64u,
            callback_url.as_deref(),
        )?;
    let canonical_message = decode_base64url_bytes_v1(
        "local normal-signing canonical NEP-413 message",
        &canonical_message_b64u,
    )?;
    let expected_signing_digest_b64u =
        local_normal_signing_expected_digest_b64u_v2(&canonical_message);
    let operation_fingerprint =
        local_normal_signing_operation_fingerprint_v2(&expected_signing_digest_b64u);
    let intent = RouterAbEd25519NormalSigningIntentV2::Nep413V1 {
        operation_id: format!("local-normal-signing/{request_id}"),
        operation_fingerprint,
        near_account_id: fixture.account_id.clone(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        recipient,
        message,
        nonce_b64u,
        callback_url,
    };
    let signing_payload = RouterAbEd25519SigningPayloadV2::Nep413MessageV1 {
        canonical_message_b64u,
        expected_signing_digest_b64u,
    };
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        scope,
        2_000_000_000_000,
        intent,
        signing_payload,
    )
}

/// Builds a typed v2 delegate-action prepare request for local smoke flows.
pub fn build_local_normal_signing_delegate_action_prepare_request_v2(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    request_id: impl Into<String>,
    canonical_delegate_borsh: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningPrepareRequestV2> {
    fixture.validate()?;
    let request_id = request_id.into();
    let scope = local_normal_signing_scope_v2(fixture, request_id.clone())?;
    let canonical_delegate_borsh_b64u = encode_base64url_bytes_v1(canonical_delegate_borsh);
    let expected_signing_digest_b64u =
        local_normal_signing_expected_digest_b64u_v2(canonical_delegate_borsh);
    let operation_fingerprint =
        local_normal_signing_operation_fingerprint_v2(&expected_signing_digest_b64u);
    let action_fingerprint = router_ab_delegate_action_fingerprint_from_canonical_borsh_b64u_v2(
        &canonical_delegate_borsh_b64u,
    )?;
    let delegate = RouterAbNearDelegateActionIntentV1::new(
        &fixture.account_id,
        "local-router.test.near",
        "ed25519:11111111111111111111111111111111",
        "7",
        "2000000",
        action_fingerprint,
        canonical_delegate_borsh_b64u.clone(),
    )?;
    let intent = RouterAbEd25519NormalSigningIntentV2::NearDelegateActionV1 {
        operation_id: format!("local-normal-signing/{request_id}"),
        operation_fingerprint,
        near_account_id: fixture.account_id.clone(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        delegate,
    };
    let signing_payload = RouterAbEd25519SigningPayloadV2::NearDelegateActionV1 {
        canonical_delegate_borsh_b64u,
        expected_signing_digest_b64u,
    };
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        scope,
        2_000_000_000_000,
        intent,
        signing_payload,
    )
}

/// Builds the v2 client finalization request for the local role-separated Ed25519 path.
pub fn build_local_normal_signing_finalize_request_v2(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    prepare_request: RouterAbEd25519NormalSigningPrepareRequestV2,
    prepare_response: NormalSigningRound1PrepareResponseV1,
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningFinalizeRequestV2> {
    fixture.validate()?;
    prepare_response.validate_for_v2_prepare_request(&prepare_request)?;
    let admission = prepare_request.admission_material()?;
    let derivation =
        local_normal_signing_smoke_hss_derivation_for_scope_v1(fixture, &prepare_request.scope)?;
    let mut rng = OsRng;
    let client_round1 = prepare_role_separated_ed25519_round1_v1(&mut rng)
        .map_err(map_hss_normal_signing_error_v1)?;
    let client_verifying_share =
        role_separated_ed25519_client_verifying_share_v1(derivation.client_output.base_share)
            .map_err(map_hss_normal_signing_error_v1)?;
    let server_verifying_share = decode_base64url_fixed_32_v1(
        "local normal-signing server_verifying_share_b64u",
        &prepare_response.server_verifying_share_b64u,
    )?;
    let server_commitments =
        decode_local_normal_signing_commitments_v1(&prepare_response.server_commitments)?;
    let client_signature_share = create_role_separated_ed25519_client_signature_share_v1(
        RoleSeparatedEd25519ClientShareRequestV1 {
            x_client_base: derivation.client_output.base_share,
            client_round1: &client_round1,
            group_public_key: decode_near_ed25519_public_key_v1(
                "local normal-signing group public key",
                &derivation.near_public_key,
            )?,
            client_verifying_share,
            server_verifying_share,
            server_commitments,
            signing_payload: admission.admitted_signing_digest.as_bytes(),
        },
    )
    .map_err(map_hss_normal_signing_error_v1)?;
    let client_commitments =
        local_normal_signing_commitments_wire_from_role_separated_v1(client_round1.commitments)?;
    let prepare_binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        prepare_response.server_round1_handle,
        prepare_response.round1_binding_digest,
        admission.intent_digest,
        admission.signing_payload_digest,
    )?;
    let finalize = RouterAbEd25519TwoPartyFrostFinalizeProtocolV2::new(
        client_commitments,
        prepare_response.server_commitments,
        encode_base64url_bytes_v1(&client_verifying_share),
        encode_base64url_bytes_v1(&server_verifying_share),
        encode_base64url_bytes_v1(&client_signature_share),
    )?;
    let request = RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        prepare_request.scope,
        prepare_request.expires_at_ms,
        prepare_binding,
        RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(finalize),
    )?;
    if request.round1_binding_digest() == prepare_response.round1_binding_digest {
        return Ok(request);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "local normal-signing finalize request does not match prepared round-1 binding",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalSigningWorkerNormalSigningMaterialV1 {
    x_server_base: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSigningWorkerEd25519PrivateMaterialV1 {
    pub kind: String,
    pub account_public_key: String,
    pub x_server_base_b64u: String,
    pub signing_worker_material_handle: String,
    pub activated_at_ms: u64,
}

impl LocalSigningWorkerEd25519PrivateMaterialV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "router_ab_ed25519_signing_worker_material_v1" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "local Ed25519 SigningWorker material kind is invalid",
            ));
        }
        decode_near_ed25519_public_key_v1(
            "local Ed25519 SigningWorker material account_public_key",
            &self.account_public_key,
        )?;
        decode_base64url_fixed_32_v1(
            "local Ed25519 SigningWorker material x_server_base_b64u",
            &self.x_server_base_b64u,
        )?;
        require_non_empty(
            "local Ed25519 SigningWorker material handle",
            &self.signing_worker_material_handle,
        )?;
        require_positive_unix_ms_v1(
            "local Ed25519 SigningWorker material activated_at_ms",
            self.activated_at_ms,
        )
    }

    fn active_signing_worker_state(
        &self,
        config: &LocalSigningWorkerConfigV1,
        scope: &NormalSigningScopeV1,
    ) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
        self.validate()?;
        scope.validate()?;
        let state = ActiveSigningWorkerStateV1::new(
            scope.account_id.clone(),
            scope.session_id.clone(),
            self.account_public_key.clone(),
            ServerIdentityV1::new(
                config.signing_worker_id.clone(),
                config.signing_worker_key_epoch.clone(),
                config.server_output_hpke_public_key.clone(),
            )?,
            local_normal_signing_digest_v1(b"activation-transcript"),
            local_normal_signing_digest_v1(b"activation"),
            self.signing_worker_material_handle.clone(),
            self.activated_at_ms,
        )?;
        state.validate_for_scope(scope)?;
        Ok(state)
    }

    fn normal_signing_material(
        &self,
    ) -> RouterAbProtocolResult<LocalSigningWorkerNormalSigningMaterialV1> {
        self.validate()?;
        Ok(LocalSigningWorkerNormalSigningMaterialV1 {
            x_server_base: decode_base64url_fixed_32_v1(
                "local Ed25519 SigningWorker material x_server_base_b64u",
                &self.x_server_base_b64u,
            )?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSigningWorkerEd25519PreparePrivateRequestV1 {
    kind: String,
    request: RouterAbEd25519NormalSigningPrepareRequestV2,
    server_material: LocalSigningWorkerEd25519PrivateMaterialV1,
}

impl LocalSigningWorkerEd25519PreparePrivateRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "router_ab_ed25519_signing_worker_private_request_v1" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "local Ed25519 prepare private request kind is invalid",
            ));
        }
        self.request.validate()?;
        self.server_material.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSigningWorkerEd25519FinalizePrivateRequestV1 {
    kind: String,
    request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    server_material: LocalSigningWorkerEd25519PrivateMaterialV1,
}

impl LocalSigningWorkerEd25519FinalizePrivateRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "router_ab_ed25519_signing_worker_private_request_v1" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "local Ed25519 finalize private request kind is invalid",
            ));
        }
        self.request.validate()?;
        self.server_material.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSigningWorkerEd25519PresignPoolPreparePrivateRequestV1 {
    kind: String,
    request: RouterAbEd25519PresignPoolPrepareRequestV2,
    server_material: LocalSigningWorkerEd25519PrivateMaterialV1,
}

impl LocalSigningWorkerEd25519PresignPoolPreparePrivateRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "router_ab_ed25519_signing_worker_private_request_v1" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "local Ed25519 presign-pool private request kind is invalid",
            ));
        }
        self.request.validate()?;
        self.server_material.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSigningWorkerEd25519PresignPoolHitPrivateRequestV1 {
    kind: String,
    request: RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    server_material: LocalSigningWorkerEd25519PrivateMaterialV1,
}

impl LocalSigningWorkerEd25519PresignPoolHitPrivateRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "router_ab_ed25519_signing_worker_private_request_v1" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "local Ed25519 presign-pool-hit private request kind is invalid",
            ));
        }
        self.request.validate()?;
        self.server_material.validate()
    }
}

fn local_normal_signing_fixture_name_for_scope_v1(
    scope: &NormalSigningScopeV1,
) -> RouterAbProtocolResult<String> {
    scope.validate()?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    if fixtures.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local normal-signing fixture corpus is empty",
        ));
    }
    let selector = local_normal_signing_digest_v1(
        format!(
            "{}:{}:{}",
            scope.account_id, scope.session_id, scope.signing_worker_id
        )
        .as_bytes(),
    );
    let index = usize::from(selector.as_bytes()[0]) % fixtures.len();
    Ok(fixtures[index].name.clone())
}

/// Builds the local normal-signing smoke fixture bound to a request scope.
pub fn local_normal_signing_smoke_fixture_for_scope_v1(
    scope: &NormalSigningScopeV1,
) -> RouterAbProtocolResult<LocalNormalSigningSmokeFixtureV1> {
    scope.validate()?;
    LocalNormalSigningSmokeFixtureV1::new(
        local_normal_signing_fixture_name_for_scope_v1(scope)?,
        LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
        scope.account_id.clone(),
        scope.session_id.clone(),
        scope.signing_worker_id.clone(),
    )
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalSigningWorkerEd25519PresignPoolRecordV1 {
    active_signing_worker: ActiveSigningWorkerStateV1,
    scope: NormalSigningScopeV1,
    client_presign_id: String,
    client_nonce_handle: String,
    generation: u64,
    pool_entry_binding_digest: PublicDigest32,
    server_round1_handle: String,
    client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    client_verifying_share_b64u: String,
    round1_state: RoleSeparatedEd25519Round1StateV1,
    server_verifying_share_b64u: String,
    prepared_at_ms: u64,
    expires_at_ms: u64,
}

impl LocalSigningWorkerEd25519PresignPoolRecordV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker.validate_for_scope(&self.scope)?;
        require_non_empty(
            "local presign-pool client_presign_id",
            &self.client_presign_id,
        )?;
        require_non_empty(
            "local presign-pool client_nonce_handle",
            &self.client_nonce_handle,
        )?;
        require_positive_unix_ms_v1("local presign-pool generation", self.generation)?;
        require_non_empty(
            "local presign-pool server_round1_handle",
            &self.server_round1_handle,
        )?;
        self.client_commitments.validate()?;
        decode_base64url_fixed_32_v1(
            "local presign-pool client_verifying_share_b64u",
            &self.client_verifying_share_b64u,
        )?;
        self.round1_state
            .validate()
            .map_err(map_hss_normal_signing_error_v1)?;
        decode_base64url_fixed_32_v1(
            "local presign-pool server_verifying_share_b64u",
            &self.server_verifying_share_b64u,
        )?;
        require_positive_unix_ms_v1("local presign-pool prepared_at_ms", self.prepared_at_ms)?;
        require_positive_unix_ms_v1("local presign-pool expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms <= self.prepared_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "local presign-pool expiry must be after prepare time",
            ));
        }
        Ok(())
    }
}

fn parse_local_json_body_v1<T>(label: &str, body: &[u8]) -> RouterAbProtocolResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_slice::<T>(body).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} JSON parse failed: {error}"),
        )
    })
}

fn local_active_ecdsa_hss_signing_worker_state_v1(
    config: &LocalSigningWorkerConfigV1,
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    scope.validate()?;
    let signing_worker = ServerIdentityV1::new(
        config.signing_worker_id.clone(),
        config.signing_worker_key_epoch.clone(),
        config.server_output_hpke_public_key.clone(),
    )?;
    if scope.signing_worker != signing_worker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS scope SigningWorker does not match local worker config",
        ));
    }
    let session_id = router_ab_ecdsa_hss_active_state_session_id_v1(
        &scope.ecdsa_threshold_key_id,
        &scope.signing_root_id,
        &scope.signing_root_version,
        &scope.activation_epoch,
    )?;
    let state = ActiveSigningWorkerStateV1::new(
        scope.wallet_id.clone(),
        session_id,
        scope.public_identity.threshold_public_key33_b64u.clone(),
        signing_worker,
        local_ecdsa_hss_digest_v1(b"activation-transcript"),
        local_ecdsa_hss_digest_v1(b"activation"),
        format!(
            "local-ecdsa-hss/{}/{}/{}",
            scope.ecdsa_threshold_key_id, scope.signing_root_version, scope.activation_epoch
        ),
        LOCAL_NORMAL_SIGNING_ACTIVATION_MS_V1,
    )?;
    if state.signing_worker != scope.signing_worker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS active state SigningWorker mismatch",
        ));
    }
    Ok(state)
}

fn local_normal_signing_scope_v2(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    request_id: impl Into<String>,
) -> RouterAbProtocolResult<NormalSigningScopeV1> {
    fixture.validate()?;
    NormalSigningScopeV1::new(
        request_id,
        &fixture.account_id,
        &fixture.session_id,
        &fixture.signing_worker_id,
    )
}

fn local_normal_signing_expected_digest_b64u_v2(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    encode_base64url_bytes_v1(&digest)
}

fn local_normal_signing_operation_fingerprint_v2(expected_signing_digest_b64u: &str) -> String {
    format!("sha256:{expected_signing_digest_b64u}")
}

fn local_normal_signing_smoke_hss_derivation_v1(
    fixture: &LocalNormalSigningSmokeFixtureV1,
) -> RouterAbProtocolResult<LocalEd25519HssRoleScopedDerivationOutputV1> {
    fixture.validate()?;
    let (deriver_a, deriver_b) = derive_committed_ed25519_hss_split_server_role_shares_v1(
        &fixture.fixture_name,
        &fixture.split_epoch,
    )?;
    evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        &fixture.fixture_name,
        deriver_a,
        deriver_b,
    )
}

fn local_normal_signing_smoke_hss_derivation_for_scope_v1(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    scope: &NormalSigningScopeV1,
) -> RouterAbProtocolResult<LocalEd25519HssRoleScopedDerivationOutputV1> {
    fixture.validate()?;
    scope.validate()?;
    if scope.account_id != fixture.account_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            format!(
                "local normal-signing smoke helper supports account {}",
                fixture.account_id
            ),
        ));
    }
    local_normal_signing_smoke_hss_derivation_v1(fixture)
}

/// Builds the local SDK server key-store seed for a normal-signing smoke fixture.
pub fn build_local_router_ed25519_key_store_seed_v1(
    fixture: &LocalNormalSigningSmokeFixtureV1,
    rp_id: impl Into<String>,
    key_version: impl Into<String>,
    signing_grant_id: impl Into<String>,
    threshold_expires_at_ms: u64,
    remaining_uses: u32,
) -> RouterAbProtocolResult<LocalRouterEd25519KeyStoreSeedV1> {
    fixture.validate()?;
    let rp_id = rp_id.into();
    require_non_empty("local Ed25519 seed rp_id", &rp_id)?;
    let key_version = key_version.into();
    require_non_empty("local Ed25519 seed key_version", &key_version)?;
    let signing_grant_id = signing_grant_id.into();
    require_non_empty("local Ed25519 seed signing_grant_id", &signing_grant_id)?;
    require_positive_unix_ms_v1(
        "local Ed25519 seed threshold_expires_at_ms",
        threshold_expires_at_ms,
    )?;
    if remaining_uses == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local Ed25519 seed remaining_uses is required",
        ));
    }
    let derivation = local_normal_signing_smoke_hss_derivation_v1(fixture)?;
    let x_server_base = derivation.signing_worker_output.base_share;
    Ok(LocalRouterEd25519KeyStoreSeedV1 {
        relayer_key_id: derivation.near_public_key.clone(),
        wallet_id: fixture.account_id.clone(),
        near_account_id: fixture.account_id.clone(),
        near_ed25519_signing_key_id: derivation.near_public_key.clone(),
        rp_id,
        threshold_session_id: fixture.session_id.clone(),
        signing_grant_id,
        public_key: derivation.near_public_key,
        relayer_signing_share_b64u: encode_base64url_bytes_v1(&x_server_base),
        key_version,
        threshold_expires_at_ms,
        participant_ids: vec![1, 2],
        remaining_uses,
        recovery_export_capable: true,
    })
}

fn local_normal_signing_digest_v1(label: &[u8]) -> PublicDigest32 {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, b"router-ab-dev/normal-signing/v1");
    push_hash_field_v1(&mut hasher, label);
    PublicDigest32::new(hasher.finalize().into())
}

fn local_ecdsa_hss_digest_v1(label: &[u8]) -> PublicDigest32 {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, b"router-ab-dev/ecdsa-hss/v1");
    push_hash_field_v1(&mut hasher, label);
    PublicDigest32::new(hasher.finalize().into())
}

fn local_now_unix_ms_v1() -> RouterAbProtocolResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("local system clock is before Unix epoch: {error}"),
            )
        })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local Unix timestamp exceeds u64 milliseconds",
        )
    })
}

fn local_signing_worker_round1_store_v1(
) -> &'static Mutex<BTreeMap<String, LocalSigningWorkerRound1RecordV1>> {
    static STORE: OnceLock<Mutex<BTreeMap<String, LocalSigningWorkerRound1RecordV1>>> =
        OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn local_signing_worker_round1_store_put_v1(
    record: LocalSigningWorkerRound1RecordV1,
) -> RouterAbProtocolResult<()> {
    record.validate()?;
    let now_unix_ms = local_now_unix_ms_v1()?;
    let mut store = local_signing_worker_round1_store_v1()
        .lock()
        .map_err(|_| local_round1_store_lock_error_v1())?;
    local_signing_worker_round1_store_cleanup_expired_locked_v1(&mut store, now_unix_ms);
    if store
        .insert(record.server_round1_handle.clone(), record)
        .is_some()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local normal-signing round-1 handle collision",
        ));
    }
    Ok(())
}

fn local_signing_worker_round1_store_cleanup_expired_locked_v1(
    store: &mut BTreeMap<String, LocalSigningWorkerRound1RecordV1>,
    now_unix_ms: u64,
) -> usize {
    let before = store.len();
    store.retain(|_, record| record.expires_at_ms > now_unix_ms);
    before.saturating_sub(store.len())
}

fn local_signing_worker_ed25519_presign_pool_store_v1(
) -> &'static Mutex<BTreeMap<String, LocalSigningWorkerEd25519PresignPoolRecordV1>> {
    static STORE: OnceLock<Mutex<BTreeMap<String, LocalSigningWorkerEd25519PresignPoolRecordV1>>> =
        OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn local_signing_worker_ed25519_presign_pool_store_put_v1(
    record: LocalSigningWorkerEd25519PresignPoolRecordV1,
) -> RouterAbProtocolResult<()> {
    record.validate()?;
    let mut store = local_signing_worker_ed25519_presign_pool_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local Ed25519 presign-pool store lock poisoned",
            )
        })?;
    if store
        .insert(record.server_round1_handle.clone(), record)
        .is_some()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Ed25519 presign-pool handle collision",
        ));
    }
    Ok(())
}

fn local_signing_worker_ed25519_presign_pool_store_take_v1(
    server_round1_handle: &str,
    pool_entry_binding_digest: PublicDigest32,
) -> RouterAbProtocolResult<LocalSigningWorkerEd25519PresignPoolRecordV1> {
    require_non_empty(
        "local Ed25519 presign-pool server_round1_handle",
        server_round1_handle,
    )?;
    let mut store = local_signing_worker_ed25519_presign_pool_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local Ed25519 presign-pool store lock poisoned",
            )
        })?;
    let Some(record) = store.get(server_round1_handle) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Ed25519 presign-pool entry is not prepared",
        ));
    };
    if record.pool_entry_binding_digest != pool_entry_binding_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Ed25519 presign-pool binding digest mismatch",
        ));
    }
    store.remove(server_round1_handle).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local Ed25519 presign-pool entry disappeared before finalization",
        )
    })
}

fn local_signing_worker_ecdsa_hss_presignature_store_v1(
) -> &'static Mutex<BTreeMap<String, LocalSigningWorkerEcdsaHssPresignatureRecordV1>> {
    static STORE: OnceLock<
        Mutex<BTreeMap<String, LocalSigningWorkerEcdsaHssPresignatureRecordV1>>,
    > = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn local_signing_worker_ecdsa_hss_presignature_store_key_v1(
    server_presignature_id: &str,
    request_digest: PublicDigest32,
) -> RouterAbProtocolResult<String> {
    require_non_empty(
        "ECDSA-HSS prepared lookup server_presignature_id",
        server_presignature_id,
    )?;
    Ok(format!(
        "{}:{}",
        server_presignature_id,
        encode_base64url_bytes_v1(request_digest.as_bytes())
    ))
}

fn local_signing_worker_ecdsa_hss_presignature_store_put_v1(
    record: LocalSigningWorkerEcdsaHssPresignatureRecordV1,
) -> RouterAbProtocolResult<()> {
    record.validate()?;
    let key = local_signing_worker_ecdsa_hss_presignature_store_key_v1(
        &record.server_presignature_id,
        record.request_digest,
    )?;
    let mut store = local_signing_worker_ecdsa_hss_presignature_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local ECDSA-HSS prepared presignature store lock poisoned",
            )
        })?;
    if store.insert(key, record).is_some() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS prepared presignature collision",
        ));
    }
    Ok(())
}

fn local_signing_worker_ecdsa_hss_presignature_store_take_v1(
    server_presignature_id: &str,
    request_digest: PublicDigest32,
) -> RouterAbProtocolResult<LocalSigningWorkerEcdsaHssPresignatureRecordV1> {
    let key = local_signing_worker_ecdsa_hss_presignature_store_key_v1(
        server_presignature_id,
        request_digest,
    )?;
    let mut store = local_signing_worker_ecdsa_hss_presignature_store_v1()
        .lock()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local ECDSA-HSS prepared presignature store lock poisoned",
            )
        })?;
    store.remove(&key).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local ECDSA-HSS prepared presignature is not available",
        )
    })
}

fn local_signing_worker_round1_store_take_v1(
    server_round1_handle: &str,
    round1_binding_digest: PublicDigest32,
) -> RouterAbProtocolResult<LocalSigningWorkerRound1RecordV1> {
    require_non_empty("local server_round1_handle", server_round1_handle)?;
    let mut store = local_signing_worker_round1_store_v1()
        .lock()
        .map_err(|_| local_round1_store_lock_error_v1())?;
    let Some(record) = store.get(server_round1_handle) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local normal-signing round-1 handle is not prepared",
        ));
    };
    if local_now_unix_ms_v1()? >= record.expires_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "local normal-signing round-1 handle expired",
        ));
    }
    if record.round1_binding_digest != round1_binding_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local normal-signing round-1 binding digest mismatch",
        ));
    }
    store.remove(server_round1_handle).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "local normal-signing round-1 handle disappeared before finalization",
        )
    })
}

fn local_round1_store_lock_error_v1() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "local normal-signing round-1 store lock poisoned",
    )
}

fn local_normal_signing_commitments_wire_from_role_separated_v1(
    commitments: RoleSeparatedEd25519CommitmentsV1,
) -> RouterAbProtocolResult<NormalSigningEd25519TwoPartyFrostCommitmentsV1> {
    NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
        encode_base64url_bytes_v1(&commitments.hiding),
        encode_base64url_bytes_v1(&commitments.binding),
    )
}

fn decode_local_normal_signing_commitments_v1(
    commitments: &NormalSigningEd25519TwoPartyFrostCommitmentsV1,
) -> RouterAbProtocolResult<RoleSeparatedEd25519CommitmentsV1> {
    RoleSeparatedEd25519CommitmentsV1::new(
        decode_base64url_fixed_32_v1(
            "local normal-signing commitments.hiding",
            &commitments.hiding,
        )?,
        decode_base64url_fixed_32_v1(
            "local normal-signing commitments.binding",
            &commitments.binding,
        )?,
    )
    .map_err(map_hss_normal_signing_error_v1)
}

fn decode_near_ed25519_public_key_v1(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let Some(encoded) = value.strip_prefix("ed25519:") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use ed25519:<base58-public-key> format"),
        ));
    };
    let decoded = bs58::decode(encoded).into_vec().map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} base58 decode failed: {error}"),
        )
    })?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, received {}", bytes.len()),
        )
    })
}

fn encode_base64url_bytes_v1(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_base64url_fixed_32_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, received {}", bytes.len()),
        )
    })
}

fn decode_base64url_fixed_33_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<[u8; 33]> {
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 33 bytes, received {}", bytes.len()),
        )
    })
}

fn decode_base64url_bytes_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field, encoded)?;
    require_no_ascii_whitespace_v1(field, encoded)?;
    if encoded.contains('=') {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url"),
        ));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} base64url decode failed: {error}"),
            )
        })
}

fn require_no_ascii_whitespace_v1(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must not contain ASCII whitespace"),
        ));
    }
    Ok(())
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

fn require_positive_unix_ms_v1(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} must be positive"),
        ));
    }
    Ok(())
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
    if path != LOCAL_SIGNING_WORKER_ACTIVATION_PATH {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "SigningWorker activation route must be served at {}",
                LOCAL_SIGNING_WORKER_ACTIVATION_PATH
            ),
        ));
    }
    activation.validate()?;
    Ok(LocalSigningWorkerActivationRouteReceiptV1 {
        receiver_role,
        accepted_opened_share_kind: "x_server_base".to_owned(),
        accepted_recipient_role: Role::Server,
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

/// Role-scoped local HSS server-input share held by one Deriver.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssServerInputShareV1 {
    role: Role,
    split_epoch: String,
    y_server_share: [u8; 32],
    tau_server_share: [u8; 32],
}

impl LocalEd25519HssServerInputShareV1 {
    /// Creates a role-scoped server-input share for the local HSS dev adapter.
    pub fn new(
        role: Role,
        split_epoch: impl Into<String>,
        y_server_share: [u8; 32],
        tau_server_share: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let share = Self {
            role,
            split_epoch: split_epoch.into(),
            y_server_share,
            tau_server_share,
        };
        share.validate()?;
        Ok(share)
    }

    /// Validates role and scalar shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_sqlite_signer_role(self.role)?;
        require_non_empty("split_epoch", &self.split_epoch)?;
        canonical_scalar_v1("tau_server share", self.tau_server_share)?;
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
    pub fn commitment(&self) -> LocalEd25519HssSplitServerRoleCommitmentV1 {
        let role_label = match self.role {
            Role::SignerA => b"deriver-a".as_slice(),
            Role::SignerB => b"deriver-b".as_slice(),
            _ => b"invalid-role".as_slice(),
        };
        LocalEd25519HssSplitServerRoleCommitmentV1 {
            role: self.role,
            y_server_share_commitment_hex: commitment_hex_v1(
                &[role_label, b"/y_server"].concat(),
                &self.y_server_share,
            ),
            tau_server_share_commitment_hex: commitment_hex_v1(
                &[role_label, b"/tau_server"].concat(),
                &self.tau_server_share,
            ),
        }
    }
}

impl fmt::Debug for LocalEd25519HssServerInputShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssServerInputShareV1")
            .field("role", &self.role)
            .field("split_epoch", &self.split_epoch)
            .field("y_server_share", &"[redacted]")
            .field("tau_server_share", &"[redacted]")
            .finish()
    }
}

struct LocalEd25519HssSplitServerInputsV1 {
    deriver_a: LocalEd25519HssServerInputShareV1,
    deriver_b: LocalEd25519HssServerInputShareV1,
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
        _statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()> {
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

/// Verifies every committed `ed25519-hss` fixture through the local split-server adapter.
pub fn verify_committed_ed25519_hss_split_server_fixtures_v1(
) -> RouterAbProtocolResult<Vec<LocalEd25519HssSplitServerParityReportV1>> {
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    fixtures
        .iter()
        .map(|fixture| {
            verify_ed25519_hss_split_server_fixture_v1(
                fixture,
                LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
            )
        })
        .collect()
}

/// Verifies one committed `ed25519-hss` fixture through split `y_server` and `tau_server` shares.
pub fn verify_committed_ed25519_hss_split_server_fixture_v1(
    fixture_name: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitServerParityReportV1> {
    verify_committed_ed25519_hss_split_server_fixture_at_epoch_v1(
        fixture_name,
        LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
    )
}

/// Verifies one committed `ed25519-hss` fixture through one local split epoch.
pub fn verify_committed_ed25519_hss_split_server_fixture_at_epoch_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitServerParityReportV1> {
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
    let shares = split_ed25519_hss_server_inputs_v1(fixture, split_epoch)?;
    verify_committed_ed25519_hss_split_server_role_shares_v1(
        fixture_name,
        shares.deriver_a,
        shares.deriver_b,
    )
}

/// Derives deterministic role-scoped server-input shares for one committed HSS fixture.
pub fn derive_committed_ed25519_hss_split_server_role_shares_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<(
    LocalEd25519HssServerInputShareV1,
    LocalEd25519HssServerInputShareV1,
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
    let split = split_ed25519_hss_server_inputs_v1(fixture, split_epoch)?;
    Ok((split.deriver_a, split.deriver_b))
}

/// Verifies one committed HSS fixture from explicit Deriver A/B role-scoped shares.
pub fn verify_committed_ed25519_hss_split_server_role_shares_v1(
    fixture_name: &str,
    deriver_a: LocalEd25519HssServerInputShareV1,
    deriver_b: LocalEd25519HssServerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssSplitServerParityReportV1> {
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
    verify_ed25519_hss_split_server_fixture_with_role_shares_v1(fixture, deriver_a, deriver_b)
}

/// Runs the dev-only role-scoped HSS derivation and returns recipient-scoped outputs.
pub fn evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
    fixture_name: &str,
    deriver_a: LocalEd25519HssServerInputShareV1,
    deriver_b: LocalEd25519HssServerInputShareV1,
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
    let expanded = evaluate_ed25519_hss_split_server_fixture_with_role_shares_v1(
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
            Role::Server,
            OpenedShareKind::XServerBase,
            expanded.output.x_server_base,
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
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_server_role_shares_v1(fixture_name, split_epoch)?;
    let hss_derivation = evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        fixture_name,
        deriver_a.clone(),
        deriver_b.clone(),
    )?;
    let hss_parity = verify_committed_ed25519_hss_split_server_role_shares_v1(
        fixture_name,
        deriver_a,
        deriver_b,
    )?;
    let router_request = local_router_request_for_hss_derivation_v1(&hss_derivation)?;
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
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_server_role_shares_v1(fixture_name, split_epoch)?;
    let hss_derivation = evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        fixture_name,
        deriver_a.clone(),
        deriver_b.clone(),
    )?;
    let hss_parity = verify_committed_ed25519_hss_split_server_role_shares_v1(
        fixture_name,
        deriver_a,
        deriver_b,
    )?;
    let router_request = local_router_request_for_hss_derivation_v1(&hss_derivation)?;
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

fn verify_ed25519_hss_split_server_fixture_v1(
    fixture: &FExpandFixture,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitServerParityReportV1> {
    let split = split_ed25519_hss_server_inputs_v1(fixture, split_epoch)?;
    verify_ed25519_hss_split_server_fixture_with_role_shares_v1(
        fixture,
        split.deriver_a,
        split.deriver_b,
    )
}

fn verify_ed25519_hss_split_server_fixture_with_role_shares_v1(
    fixture: &FExpandFixture,
    deriver_a: LocalEd25519HssServerInputShareV1,
    deriver_b: LocalEd25519HssServerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssSplitServerParityReportV1> {
    let expanded = evaluate_ed25519_hss_split_server_fixture_with_role_shares_v1(
        fixture, &deriver_a, &deriver_b,
    )?;
    let split_epoch = deriver_a.split_epoch().to_owned();
    Ok(LocalEd25519HssSplitServerParityReportV1 {
        fixture_name: fixture.name.clone(),
        split_epoch,
        context_binding_hex: hex::encode(fixture.output.context_binding),
        public_key_hex: hex::encode(expanded.public_key),
        near_public_key: encode_near_ed25519_public_key_v1(expanded.public_key),
        x_client_base_commitment_hex: commitment_hex_v1(
            b"x_client_base",
            &expanded.output.x_client_base,
        ),
        x_server_base_commitment_hex: commitment_hex_v1(
            b"x_server_base",
            &expanded.output.x_server_base,
        ),
        deriver_a: deriver_a.commitment(),
        deriver_b: deriver_b.commitment(),
    })
}

struct LocalEd25519HssExpandedFixtureV1 {
    output: FExpandOutput,
    public_key: [u8; 32],
}

fn evaluate_ed25519_hss_split_server_fixture_with_role_shares_v1(
    fixture: &FExpandFixture,
    deriver_a: &LocalEd25519HssServerInputShareV1,
    deriver_b: &LocalEd25519HssServerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssExpandedFixtureV1> {
    validate_ed25519_hss_role_share_pair_v1(deriver_a, deriver_b)?;
    let y_server = add_le_bytes_mod_2_256(deriver_a.y_server_share, deriver_b.y_server_share);
    let tau_server = add_scalar_mod_l(deriver_a.tau_server_share, deriver_b.tau_server_share)?;
    if y_server != fixture.input.y_server || tau_server != fixture.input.tau_server {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS server inputs failed to reconstruct fixture inputs",
        ));
    }
    let output = eval_f_expand(&ed25519_hss::shared::FExpandInput {
        context: fixture.input.context.clone(),
        y_client: fixture.input.y_client,
        y_server,
        tau_client: fixture.input.tau_client,
        tau_server,
    })
    .map_err(map_hss_error)?;
    if output != fixture.output {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS server expansion did not match committed fixture output",
        ));
    }
    let public_key = public_key_from_base_shares(output.x_client_base, output.x_server_base)
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
    let plan = local_persistence_seed_sql_plan_v1(seed)?;
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
            LOCAL_DEV_ACCOUNT_ID_V1,
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

fn local_router_request_for_hss_derivation_v1(
    hss_derivation: &LocalEd25519HssRoleScopedDerivationOutputV1,
) -> RouterAbProtocolResult<PublicRouterRequestV1> {
    let account_public_key = hss_derivation.near_public_key.clone();
    let lifecycle = local_lifecycle_scope_v1(LOCAL_DEV_ACCOUNT_ID_V1)?;
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
        "server-a",
    )
}

fn signer_set_v1() -> RouterAbProtocolResult<SignerSetV1> {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        signer_identity(Role::SignerA)?,
        signer_identity(Role::SignerB)?,
        server_identity_v1()?,
    )
}

fn server_identity_v1() -> RouterAbProtocolResult<ServerIdentityV1> {
    ServerIdentityV1::new(
        "server-a",
        "server-epoch",
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
            server_identity_v1()?,
            signing_worker_env_snapshot_v1()?,
        )?,
    )
}

fn router_endpoint_v1() -> RouterAbProtocolResult<LocalRouterEndpointV1> {
    LocalRouterEndpointV1::new(
        "http://127.0.0.1:9090",
        "http://127.0.0.1:9091",
        "http://127.0.0.1:9092",
        "http://127.0.0.1:9093",
    )
}

fn deriver_a_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverAEndpointV1> {
    LocalDeriverAEndpointV1::new("http://127.0.0.1:9091", "http://127.0.0.1:9092")
}

fn deriver_b_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverBEndpointV1> {
    LocalDeriverBEndpointV1::new("http://127.0.0.1:9092", "http://127.0.0.1:9091")
}

fn signing_worker_endpoint_v1() -> RouterAbProtocolResult<LocalSigningWorkerEndpointV1> {
    LocalSigningWorkerEndpointV1::new("http://127.0.0.1:9093", "local-server-output")
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
        vec!["SERVER_OUTPUT_STORAGE".to_owned()],
    )
}

fn split_ed25519_hss_server_inputs_v1(
    fixture: &FExpandFixture,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitServerInputsV1> {
    let y_server_a = deterministic_hss_share_v1(
        b"deriver-a/y_server",
        &fixture.name,
        split_epoch,
        fixture.output.context_binding,
    );
    let y_server_b = sub_le_bytes_mod_2_256(fixture.input.y_server, y_server_a);
    let tau_server_a = Scalar::from_bytes_mod_order(deterministic_hss_share_v1(
        b"deriver-a/tau_server",
        &fixture.name,
        split_epoch,
        fixture.output.context_binding,
    ))
    .to_bytes();
    let tau_server_b = sub_scalar_mod_l(fixture.input.tau_server, tau_server_a)?;
    Ok(LocalEd25519HssSplitServerInputsV1 {
        deriver_a: LocalEd25519HssServerInputShareV1::new(
            Role::SignerA,
            split_epoch,
            y_server_a,
            tau_server_a,
        )?,
        deriver_b: LocalEd25519HssServerInputShareV1::new(
            Role::SignerB,
            split_epoch,
            y_server_b,
            tau_server_b,
        )?,
    })
}

fn validate_ed25519_hss_role_share_pair_v1(
    deriver_a: &LocalEd25519HssServerInputShareV1,
    deriver_b: &LocalEd25519HssServerInputShareV1,
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
    push_hash_field_v1(&mut hasher, LOCAL_ED25519_HSS_SPLIT_SERVER_LABEL_V1);
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
    let total = canonical_scalar_v1("tau_server", total)?;
    let left = Scalar::from_bytes_mod_order(left);
    Ok((total - left).to_bytes())
}

fn add_scalar_mod_l(left: [u8; 32], right: [u8; 32]) -> RouterAbProtocolResult<[u8; 32]> {
    let left = canonical_scalar_v1("tau_server left share", left)?;
    let right = canonical_scalar_v1("tau_server right share", right)?;
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
    push_hash_field_v1(&mut hasher, LOCAL_ED25519_HSS_SPLIT_SERVER_LABEL_V1);
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
            "dev-only-signing-worker-server-output-hpke-private-key",
            "signing-worker-server-output-hpke-private-key",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn round1_store_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_active_signing_worker_state() -> ActiveSigningWorkerStateV1 {
        ActiveSigningWorkerStateV1::new(
            "alice.testnet",
            "session-1",
            "ed25519:test-public-key",
            ServerIdentityV1::new("signing-worker-1", "epoch-1", "x25519:test-recipient")
                .expect("server identity"),
            digest(0x01),
            digest(0x02),
            "material-handle-1",
            1,
        )
        .expect("active signing worker state")
    }

    fn test_round1_state() -> RoleSeparatedEd25519Round1StateV1 {
        let mut rng = OsRng;
        prepare_role_separated_ed25519_round1_v1(&mut rng).expect("round1 state")
    }

    fn test_round1_record(
        server_round1_handle: &str,
        expires_at_ms: u64,
    ) -> LocalSigningWorkerRound1RecordV1 {
        LocalSigningWorkerRound1RecordV1::new(
            test_active_signing_worker_state(),
            server_round1_handle,
            digest(0x10),
            digest(0x11),
            digest(0x12),
            digest(0x13),
            test_round1_state(),
            1,
            expires_at_ms,
        )
        .expect("round1 record")
    }

    #[test]
    fn local_round1_store_put_cleans_expired_abandoned_records() {
        let _guard = round1_store_test_lock().lock().expect("test lock");
        {
            let mut store = local_signing_worker_round1_store_v1()
                .lock()
                .expect("round1 store lock");
            store.clear();
        }

        local_signing_worker_round1_store_put_v1(test_round1_record(
            "local-server-round1/expired",
            2,
        ))
        .expect("expired record put");
        local_signing_worker_round1_store_put_v1(test_round1_record(
            "local-server-round1/live",
            u64::MAX,
        ))
        .expect("live record put");

        let store = local_signing_worker_round1_store_v1()
            .lock()
            .expect("round1 store lock");
        assert!(!store.contains_key("local-server-round1/expired"));
        assert!(store.contains_key("local-server-round1/live"));
    }

    #[test]
    fn local_round1_store_rejects_expired_take_without_consuming_record() {
        let _guard = round1_store_test_lock().lock().expect("test lock");
        {
            let mut store = local_signing_worker_round1_store_v1()
                .lock()
                .expect("round1 store lock");
            store.clear();
        }

        local_signing_worker_round1_store_put_v1(test_round1_record(
            "local-server-round1/expired-take",
            2,
        ))
        .expect("expired record put");

        let err = local_signing_worker_round1_store_take_v1(
            "local-server-round1/expired-take",
            digest(0x10),
        )
        .expect_err("expired take must fail");
        assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);

        let store = local_signing_worker_round1_store_v1()
            .lock()
            .expect("round1 store lock");
        assert!(store.contains_key("local-server-round1/expired-take"));
    }
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

fn map_hss_normal_signing_error_v1(
    error: ed25519_hss::shared::ProtoError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ed25519-hss normal signing failed: {error}"),
    )
}

fn map_signer_core_ecdsa_error_v1(
    error: signer_core::error::SignerCoreError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ECDSA-HSS signature finalization failed: {error}"),
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
