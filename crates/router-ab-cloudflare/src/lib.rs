#![forbid(unsafe_code)]
//! Cloudflare adapter boundary types for Router/A/B signing.
//!
//! This crate pins role-specific binding and storage-scope rules before the
//! `workers-rs` adapter layer is added.

mod durable_object;
#[cfg(any(
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-signer-a-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-signer-b-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-signing-worker-entrypoint"
    ),
    all(
        feature = "strict-worker-signer-a-entrypoint",
        feature = "strict-worker-signer-b-entrypoint"
    ),
    all(
        feature = "strict-worker-signer-a-entrypoint",
        feature = "strict-worker-signing-worker-entrypoint"
    ),
    all(
        feature = "strict-worker-signer-b-entrypoint",
        feature = "strict-worker-signing-worker-entrypoint"
    ),
))]
compile_error!("enable exactly one strict Worker entrypoint feature");

#[cfg(any(
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]
mod strict_worker;

#[cfg(feature = "workers-rs")]
pub use durable_object::{
    execute_cloudflare_durable_object_call_v1, handle_cloudflare_durable_object_fetch_v1,
    handle_cloudflare_durable_object_worker_request_v1, RouterAbRouterAbuseDurableObject,
    RouterAbRouterLifecycleDurableObject, RouterAbRouterProjectPolicyDurableObject,
    RouterAbRouterQuotaDurableObject, RouterAbRouterReplayDurableObject,
    RouterAbRouterWalletBudgetDurableObject, RouterAbSignerARootShareDurableObject,
    RouterAbSignerBRootShareDurableObject, RouterAbSigningWorkerServerOutputDurableObject,
};
pub use durable_object::{
    handle_cloudflare_durable_object_call_v1, CloudflareActiveSigningWorkerStateLookupV1,
    CloudflareDerivationCeremonyPutReceiptV1, CloudflareDerivationCeremonyStateLabelV1,
    CloudflareDerivationCeremonyV1, CloudflareDurableObjectCallV1,
    CloudflareDurableObjectMemoryStorageV1, CloudflareDurableObjectOperationKindV1,
    CloudflareDurableObjectRequestV1, CloudflareDurableObjectResponseV1,
    CloudflareDurableObjectStorageV1, CloudflareExpiredStateCleanupReportV1,
    CloudflareExpiredStateCleanupRequestV1, CloudflareLifecyclePutReceiptV1,
    CloudflareReplayReserveRequestV1, CloudflareReplayReserveResponseV1,
    CloudflareRootShareLookupRequestV1, CloudflareRootShareRewrapReceiptV1,
    CloudflareRootShareRewrapRequestV1, CloudflareRootShareStartupMetadataV1,
    CloudflareRouterAbuseRecordV1, CloudflareRouterAdmissionStoreRequestV1,
    CloudflareRouterNormalSigningAdmissionStoreRequestV1, CloudflareRouterProjectPolicyRecordV1,
    CloudflareRouterQuotaReservationV1, CloudflareRouterWalletBudgetCurveV1,
    CloudflareRouterWalletBudgetPutGrantRequestV1, CloudflareRouterWalletBudgetReleaseRequestV1,
    CloudflareRouterWalletBudgetReservationIdentityV1,
    CloudflareRouterWalletBudgetReserveRequestV1, CloudflareRouterWalletBudgetSignerBindingV1,
    CloudflareRouterWalletBudgetStatusRequestV1, CloudflareRouterWalletBudgetStatusV1,
    CloudflareSigningWorkerEcdsaPresignatureLookupV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1,
    CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    CloudflareSigningWorkerEd25519PresignPoolLookupV1,
    CloudflareSigningWorkerEd25519PresignPoolPutReceiptV1,
    CloudflareSigningWorkerEd25519PresignPoolRecordV1,
    CloudflareSigningWorkerOutputActivationReceiptV1,
    CloudflareSigningWorkerOutputActivationRecordV1, CloudflareSigningWorkerOutputMaterialLookupV1,
    CloudflareSigningWorkerRound1LookupV1, CloudflareSigningWorkerRound1PutReceiptV1,
    CloudflareSigningWorkerRound1RecordV1, CLOUDFLARE_DURABLE_OBJECT_API_VERSION_V1,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::sign_ab_peer_message_ed25519_authentication_v1;
#[cfg(feature = "workers-rs")]
use router_ab_core::RouterAbEd25519NormalSigningIntentV2;
use router_ab_core::{
    build_mpc_prf_threshold_signer_batch_input_v1,
    combine_mpc_prf_signing_worker_output_from_activation_context_v1,
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    decode_and_validate_signer_envelope_hpke_payload_v1,
    decode_recipient_proof_bundle_ciphertext_v1, decode_recipient_proof_bundle_payload_v1,
    decode_router_to_signer_payload_v1, decode_signer_envelope_hpke_payload_v1,
    decode_signer_input_plaintext_v1, encode_recipient_output_ciphertext_aad_v1,
    encode_recipient_proof_bundle_ciphertext_aad_v1,
    recipient_proof_bundle_wire_message_from_ab_proof_batch_v1,
    router_ab_ecdsa_hss_active_state_session_id_v1, sign_ab_derivation_proof_batch_peer_payload_v1,
    validate_signer_input_plaintext_binding_v1, verify_ab_peer_message_ed25519_signature_v1,
    verify_recipient_proof_bundle_ciphertext_payload_v1, AbDerivationProofBatchPayloadV1,
    AbPeerMessagePayloadV1, AbPeerMessageVerifyingKeyV1, ActiveSigningWorkerStateV1, AuditEventV1,
    AuditSink, CanonicalWireBytesV1, Clock, Csprng, DeriverAEngine, DeriverBEngine,
    EncryptedPayloadV1, ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1,
    ExpensiveWorkKindV1, GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1,
    MpcPrfSigningRootShareWireV1, MpcPrfThresholdSignerBatchOutputV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningResponseV1,
    NormalSigningRound1PrepareResponseV1, NormalSigningScopeV1, NormalSigningSignatureSchemeV1,
    OpenedShareKind, PeerTransport, PublicDigest32, PublicRouterRequestV1,
    RecipientOutputCiphertextV1, RecipientOutputEncryptionAlgorithmV1,
    RecipientOutputEncryptionRequestV1, RecipientOutputEncryptorV1,
    RecipientProofBundleCiphertextV1, RecipientProofBundleEncryptionRequestV1,
    RecipientProofBundleEncryptorV1, RecipientProofBundlePayloadV1, Role, RoleEnvelopeAadV1,
    RootShareEpoch, RouterAbDerivationError, RouterAbEcdsaHssActivationReceiptV1,
    RouterAbEcdsaHssActivationRefreshRequestV1, RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1, RouterAbEcdsaHssEvmDigestSigningRequestV1,
    RouterAbEcdsaHssEvmDigestSigningResponseV1, RouterAbEcdsaHssExplicitExportRequestV1,
    RouterAbEcdsaHssNormalSigningScopeV1, RouterAbEcdsaHssPublicIdentityV1,
    RouterAbEcdsaHssRecoveryRequestV1, RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    RouterAbEcdsaHssStableKeyContextV1, RouterAbEd25519NormalSigningAdmissionMaterialV2,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519PresignPoolAcceptedEntryV2,
    RouterAbEd25519PresignPoolHitFinalizeRequestV2, RouterAbEd25519PresignPoolPrepareRequestV2,
    RouterAbEd25519PresignPoolPrepareResponseV2, RouterAbLifecycleStateV1, RouterToSignerPayloadV1,
    SecretMaterial32, ServerIdentityV1, SignerEnvelopeHpkePayloadV1, SignerIdentityV1,
    SignerInputPlaintextV1, SignerKeyStore, SignerSetV1, SigningRootShareStore,
    SigningWorkerActivationContextV1, WireMessageKindV1, WireMessageV1,
    MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN,
};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use base64::Engine;
use ecdsa_hss::{
    derive_relayer_share_for_client_public, EcdsaHssStableKeyContext, ECDSA_HSS_PARTICIPANT_IDS,
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use ed25519_hss::role_signing::{
    finalize_role_separated_ed25519_server_signature_v1, prepare_role_separated_ed25519_round1_v1,
    role_separated_ed25519_server_verifying_share_v1, RoleSeparatedEd25519CommitmentsV1,
    RoleSeparatedEd25519ServerFinalizeRequestV1,
};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as Sha2Digest, Sha256};
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use signer_core::threshold_ecdsa::threshold_ecdsa_finalize_signature;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public Router endpoint for derivation-time Router/A/B ceremonies.
pub const CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/split-derivation";
/// Well-known public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2: &str =
    "/.well-known/router-ab/keyset";
/// Versioned public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH_V2: &str = "/v2/router-ab/keyset";
/// Public Router endpoint for normal signing through the active SigningWorker.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2: &str =
    "/v2/router-ab/ed25519/sign";
/// Public Router endpoint for preparing normal-signing round-1 material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2: &str =
    "/v2/router-ab/ed25519/sign/prepare";
/// Public Router endpoint for refilling normal-signing Ed25519 presign-pool material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2: &str =
    "/v2/router-ab/ed25519/sign/presign-pool/prepare";
/// Public Router endpoint for ECDSA-HSS Router A/B registration/bootstrap.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/register";
/// Public Router endpoint for ECDSA-HSS Router A/B explicit export.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/ecdsa/export";
/// Public Router endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/recover";
/// Public Router endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/refresh";
/// Public Router endpoint for preparing ECDSA-HSS normal signing.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/sign/prepare";
/// Public Router endpoint for finalizing ECDSA-HSS normal signing.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/ecdsa/sign";
/// Public Router endpoint for reading server-authoritative Wallet Session budget status.
pub const CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1: &str =
    "/session/signing-budget/status";
/// Private Router endpoint for issuing Wallet Session signing-budget grants.
pub const CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/router/wallet-budget/put-grant";

/// Returns the exact configured browser Origin allowed for normal-signing CORS.
pub fn cloudflare_router_normal_signing_cors_allowed_origin_v1(
    configured_origins: Option<&str>,
    request_origin: &str,
) -> Option<String> {
    let configured_origins = configured_origins?;
    let request_origin = request_origin.trim();
    if request_origin.is_empty() {
        return None;
    }
    configured_origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .find(|origin| *origin == request_origin)
        .map(str::to_owned)
}

/// Private Signer A service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-a";
/// Private Signer B service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-b";
/// Private Signer A service-binding endpoint for ECDSA-HSS registration.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/register";
/// Private Signer B service-binding endpoint for ECDSA-HSS registration.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/register";
/// Private Signer A service-binding endpoint for ECDSA-HSS explicit export.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/export";
/// Private Signer B service-binding endpoint for ECDSA-HSS explicit export.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/export";
/// Private Signer A service-binding endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/recover";
/// Private Signer B service-binding endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/recover";
/// Private Signer A service-binding endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/refresh";
/// Private Signer B service-binding endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/refresh";
/// Private Signer A endpoint for direct B-to-A coordination.
pub const CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-a/peer";
/// Private Signer B endpoint for direct A-to-B coordination.
pub const CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-b/peer";
/// Private SigningWorker endpoint for strict SigningWorker proof-bundle activation.
pub const CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1: &str =
    "/router-ab/v1/signing-worker/proof-bundle-activation";
/// Private SigningWorker endpoint for ECDSA-HSS activation.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/activate";
/// Private SigningWorker endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/refresh";
/// Private SigningWorker endpoint for filling the ECDSA-HSS presignature pool.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put";
/// Private SigningWorker endpoint for normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign";
/// Private SigningWorker endpoint for Ed25519 presign-pool-hit normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign/presign-pool";
/// Private SigningWorker endpoint for normal-signing round-1 prepare.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign/prepare";
/// Private SigningWorker endpoint for refilling the Ed25519 normal-signing presign pool.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign/presign-pool/prepare";
/// Private SigningWorker endpoint for ECDSA-HSS normal-signing prepare.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare";
/// Private SigningWorker endpoint for ECDSA-HSS normal-signing finalize.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/sign";

/// Serializes one Cloudflare Service Binding JSON request body.
pub fn cloudflare_service_json_request_body_v1<T: Serialize>(
    request_kind: &str,
    request: &T,
) -> RouterAbProtocolResult<String> {
    require_non_empty("Cloudflare service JSON request kind", request_kind)?;
    serde_json::to_string(request).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{request_kind} serialization failed: {err}"),
        )
    })
}

/// Serializes one Cloudflare Service Binding JSON request body as UTF-8 bytes.
pub fn cloudflare_service_json_request_body_bytes_v1<T: Serialize>(
    request_kind: &str,
    request: &T,
) -> RouterAbProtocolResult<Vec<u8>> {
    Ok(cloudflare_service_json_request_body_v1(request_kind, request)?.into_bytes())
}

#[cfg(feature = "workers-rs")]
fn load_cloudflare_internal_service_auth_token_v1(
    env: &worker::Env,
) -> RouterAbProtocolResult<String> {
    let binding_name = env
        .var(ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV)
        .map_err(|err| {
            worker_binding_error(
                worker_binding_error_code(&err, ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV),
                ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV,
                "text Env",
                err,
            )
        })?
        .to_string();
    let binding_name = binding_name.trim().to_owned();
    require_non_empty(
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV,
        &binding_name,
    )?;
    let secret = env.secret(&binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding_name),
            &binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let token = secret_value.trim().to_owned();
    secret_value.zeroize();
    require_non_empty("Router A/B internal service-auth token", &token)?;
    Ok(token)
}

#[cfg(feature = "workers-rs")]
pub fn set_cloudflare_internal_service_auth_header_v1(
    env: &worker::Env,
    headers: &worker::Headers,
    request_kind: &str,
) -> RouterAbProtocolResult<()> {
    require_non_empty("Cloudflare service-auth request kind", request_kind)?;
    let mut token = load_cloudflare_internal_service_auth_token_v1(env)?;
    let result = headers
        .set(ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1, &token)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{request_kind} service-auth header construction failed: {err}"),
            )
        });
    token.zeroize();
    result
}

#[cfg(feature = "workers-rs")]
pub fn require_cloudflare_internal_service_auth_request_v1(
    request: &worker::Request,
    env: &worker::Env,
) -> RouterAbProtocolResult<()> {
    let mut expected = load_cloudflare_internal_service_auth_token_v1(env)?;
    let presented = request
        .headers()
        .get(ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("Router A/B internal service-auth header read failed: {err}"),
            )
        })?
        .unwrap_or_default();
    let authorized = constant_time_text_eq_v1(&expected, &presented);
    expected.zeroize();
    if authorized {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
        "Router A/B private Worker request is missing valid service auth",
    ))
}

#[cfg(feature = "workers-rs")]
pub fn cloudflare_private_service_auth_error_response_v1(
    err: RouterAbProtocolError,
) -> worker::Result<worker::Response> {
    let status = match err.code() {
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest => 403,
        code => cloudflare_router_error_status(code),
    };
    worker::Response::error(format!("{:?}: {}", err.code(), err.message()), status)
}

#[cfg(feature = "workers-rs")]
fn constant_time_text_eq_v1(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = a.len() ^ b.len();
    let max_len = core::cmp::max(a.len(), b.len());
    for index in 0..max_len {
        let left = a.get(index).copied().unwrap_or_default();
        let right = b.get(index).copied().unwrap_or_default();
        diff |= (left ^ right) as usize;
    }
    diff == 0
}
/// Router replay Durable Object binding env key.
pub const ROUTER_REPLAY_DO_BINDING_ENV: &str = "ROUTER_REPLAY_DO_BINDING";
/// Router replay Durable Object object-name env key.
pub const ROUTER_REPLAY_DO_OBJECT_ENV: &str = "ROUTER_REPLAY_DO_OBJECT";
/// Router replay Durable Object key-prefix env key.
pub const ROUTER_REPLAY_DO_KEY_PREFIX_ENV: &str = "ROUTER_REPLAY_DO_KEY_PREFIX";
/// Router lifecycle Durable Object binding env key.
pub const ROUTER_LIFECYCLE_DO_BINDING_ENV: &str = "ROUTER_LIFECYCLE_DO_BINDING";
/// Router lifecycle Durable Object object-name env key.
pub const ROUTER_LIFECYCLE_DO_OBJECT_ENV: &str = "ROUTER_LIFECYCLE_DO_OBJECT";
/// Router lifecycle Durable Object key-prefix env key.
pub const ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV: &str = "ROUTER_LIFECYCLE_DO_KEY_PREFIX";
/// Router Wallet Session budget Durable Object binding env key.
pub const ROUTER_WALLET_BUDGET_DO_BINDING_ENV: &str = "ROUTER_WALLET_BUDGET_DO_BINDING";
/// Router Wallet Session budget Durable Object object-name env key.
pub const ROUTER_WALLET_BUDGET_DO_OBJECT_ENV: &str = "ROUTER_WALLET_BUDGET_DO_OBJECT";
/// Router Wallet Session budget Durable Object key-prefix env key.
pub const ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV: &str = "ROUTER_WALLET_BUDGET_DO_KEY_PREFIX";
/// Signer A root-share Durable Object binding env key.
pub const SIGNER_A_ROOT_SHARE_DO_BINDING_ENV: &str = "SIGNER_A_ROOT_SHARE_DO_BINDING";
/// Signer A root-share Durable Object object-name env key.
pub const SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV: &str = "SIGNER_A_ROOT_SHARE_DO_OBJECT";
/// Signer A root-share Durable Object key-prefix env key.
pub const SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV: &str = "SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX";
/// SigningWorker server-output Durable Object binding env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING";
/// SigningWorker server-output Durable Object object-name env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT";
/// SigningWorker server-output Durable Object key-prefix env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX";
/// SigningWorker server-output HPKE private-key binding-name env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING";
/// SigningWorker server-output HPKE key epoch env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH";
/// SigningWorker server-output HPKE public key env key.
pub const SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV: &str =
    "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY";
/// Signer B root-share Durable Object binding env key.
pub const SIGNER_B_ROOT_SHARE_DO_BINDING_ENV: &str = "SIGNER_B_ROOT_SHARE_DO_BINDING";
/// Signer B root-share Durable Object object-name env key.
pub const SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV: &str = "SIGNER_B_ROOT_SHARE_DO_OBJECT";
/// Signer B root-share Durable Object key-prefix env key.
pub const SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV: &str = "SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX";
/// Signer A signing-root-share wire Secret binding-name env key.
pub const SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV: &str =
    "SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING";
/// Signer B signing-root-share wire Secret binding-name env key.
pub const SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV: &str =
    "SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING";
/// Signer A peer binding env key.
pub const SIGNER_A_PEER_BINDING_ENV: &str = "SIGNER_A_PEER_BINDING";
/// Signer B peer binding env key.
pub const SIGNER_B_PEER_BINDING_ENV: &str = "SIGNER_B_PEER_BINDING";
/// SigningWorker peer binding env key.
pub const SIGNING_WORKER_PEER_BINDING_ENV: &str = "SIGNING_WORKER_PEER_BINDING";
/// Internal service-auth secret binding-name env key shared by strict private Workers.
pub const ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV: &str =
    "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING";
/// Internal service-auth header required by strict private Workers.
pub const ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1: &str = "x-router-ab-internal-service-auth";
/// Signer A signer-envelope HPKE private-key binding-name env key.
pub const SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Signer A signer-envelope HPKE key epoch env key.
pub const SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str = "SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH";
/// Signer A signer-envelope HPKE public key env key.
pub const SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str = "SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Signer A signer-envelope HPKE key epoch env key.
pub const SIGNER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str =
    "SIGNER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH";
/// Previous Signer A signer-envelope HPKE public key env key.
pub const SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str =
    "SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Signer A signer-envelope HPKE private-key binding-name env key.
pub const SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Signer B signer-envelope HPKE private-key binding-name env key.
pub const SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Signer B signer-envelope HPKE key epoch env key.
pub const SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str = "SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH";
/// Signer B signer-envelope HPKE public key env key.
pub const SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str = "SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Signer B signer-envelope HPKE key epoch env key.
pub const SIGNER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV: &str =
    "SIGNER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH";
/// Previous Signer B signer-envelope HPKE public key env key.
pub const SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV: &str =
    "SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY";
/// Previous Signer B signer-envelope HPKE private-key binding-name env key.
pub const SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV: &str =
    "SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING";
/// Previous signer-envelope HPKE public-key retirement timestamp.
pub const ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV: &str =
    "ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS";
/// Signer A A/B peer-message Ed25519 signing secret binding-name env key.
pub const SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV: &str = "SIGNER_A_PEER_SIGNING_KEY_BINDING";
/// Signer A A/B peer-message Ed25519 signing key epoch env key.
pub const SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV: &str = "SIGNER_A_PEER_SIGNING_KEY_EPOCH";
/// Signer B A/B peer-message Ed25519 signing secret binding-name env key.
pub const SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV: &str = "SIGNER_B_PEER_SIGNING_KEY_BINDING";
/// Signer B A/B peer-message Ed25519 signing key epoch env key.
pub const SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV: &str = "SIGNER_B_PEER_SIGNING_KEY_EPOCH";
/// Signer A A/B peer-message Ed25519 verifying key env key.
pub const SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV: &str = "SIGNER_A_PEER_VERIFYING_KEY_HEX";
/// Signer B A/B peer-message Ed25519 verifying key env key.
pub const SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV: &str = "SIGNER_B_PEER_VERIFYING_KEY_HEX";
/// Router JWT issuer env key.
pub const ROUTER_JWT_ISSUER_ENV: &str = "ROUTER_JWT_ISSUER";
/// Router JWT audience env key.
pub const ROUTER_JWT_AUDIENCE_ENV: &str = "ROUTER_JWT_AUDIENCE";
/// Router JWKS URL env key.
pub const ROUTER_JWT_JWKS_URL_ENV: &str = "ROUTER_JWT_JWKS_URL";
/// Router project-policy Durable Object binding env key.
pub const ROUTER_PROJECT_POLICY_DO_BINDING_ENV: &str = "ROUTER_PROJECT_POLICY_DO_BINDING";
/// Router project-policy Durable Object object-name env key.
pub const ROUTER_PROJECT_POLICY_DO_OBJECT_ENV: &str = "ROUTER_PROJECT_POLICY_DO_OBJECT";
/// Router project-policy Durable Object key-prefix env key.
pub const ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV: &str = "ROUTER_PROJECT_POLICY_DO_KEY_PREFIX";
/// Router quota Durable Object binding env key.
pub const ROUTER_QUOTA_DO_BINDING_ENV: &str = "ROUTER_QUOTA_DO_BINDING";
/// Router quota Durable Object object-name env key.
pub const ROUTER_QUOTA_DO_OBJECT_ENV: &str = "ROUTER_QUOTA_DO_OBJECT";
/// Router quota Durable Object key-prefix env key.
pub const ROUTER_QUOTA_DO_KEY_PREFIX_ENV: &str = "ROUTER_QUOTA_DO_KEY_PREFIX";
/// Router abuse Durable Object binding env key.
pub const ROUTER_ABUSE_DO_BINDING_ENV: &str = "ROUTER_ABUSE_DO_BINDING";
/// Router abuse Durable Object object-name env key.
pub const ROUTER_ABUSE_DO_OBJECT_ENV: &str = "ROUTER_ABUSE_DO_OBJECT";
/// Router abuse Durable Object key-prefix env key.
pub const ROUTER_ABUSE_DO_KEY_PREFIX_ENV: &str = "ROUTER_ABUSE_DO_KEY_PREFIX";
/// Maximum random bytes a single signer-host preload may request.
pub const CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1: usize = 65_536;
/// Versioned text prefix for a role-local MPC PRF signing-root-share wire secret.
pub const CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1: &str = "mpc-prf-root-share-wire-v1:";
/// Versioned text prefix for a role-local signer-envelope HPKE private key.
pub const CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1: &str =
    "hpke-x25519-private-v1:";
/// Versioned text prefix for SigningWorker's server-output HPKE private key.
pub const CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1: &str =
    "hpke-x25519-server-output-private-v1:";

const ROUTER_FORBIDDEN_ENV_KEYS: &[&str] = &[
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
];
const SIGNER_A_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
    ROUTER_WALLET_BUDGET_DO_OBJECT_ENV,
    ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_URL_ENV,
    ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
    ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
    ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
    ROUTER_QUOTA_DO_BINDING_ENV,
    ROUTER_QUOTA_DO_OBJECT_ENV,
    ROUTER_QUOTA_DO_KEY_PREFIX_ENV,
    ROUTER_ABUSE_DO_BINDING_ENV,
    ROUTER_ABUSE_DO_OBJECT_ENV,
    ROUTER_ABUSE_DO_KEY_PREFIX_ENV,
    SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
];
const SIGNER_B_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
    ROUTER_WALLET_BUDGET_DO_OBJECT_ENV,
    ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_URL_ENV,
    ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
    ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
    ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
    ROUTER_QUOTA_DO_BINDING_ENV,
    ROUTER_QUOTA_DO_OBJECT_ENV,
    ROUTER_QUOTA_DO_KEY_PREFIX_ENV,
    ROUTER_ABUSE_DO_BINDING_ENV,
    ROUTER_ABUSE_DO_OBJECT_ENV,
    ROUTER_ABUSE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
];
const SIGNING_WORKER_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
    ROUTER_WALLET_BUDGET_DO_OBJECT_ENV,
    ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
    ROUTER_JWT_ISSUER_ENV,
    ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_JWKS_URL_ENV,
    ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
    ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
    ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
    ROUTER_QUOTA_DO_BINDING_ENV,
    ROUTER_QUOTA_DO_OBJECT_ENV,
    ROUTER_QUOTA_DO_KEY_PREFIX_ENV,
    ROUTER_ABUSE_DO_BINDING_ENV,
    ROUTER_ABUSE_DO_OBJECT_ENV,
    ROUTER_ABUSE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
];

/// Text-reader boundary used before binding descriptors are constructed.
pub trait CloudflareEnvReaderV1 {
    /// Returns a raw environment value if present.
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>>;
}

/// Platform-neutral signer logic behind the Cloudflare transport wrapper.
pub trait CloudflareSignerWireHandlerV1 {
    /// Handles one validated Router-to-signer wire message.
    fn handle_signer_wire_message(
        &self,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<WireMessageV1>;
}

/// Strict proof-bundle signer logic behind the Cloudflare transport wrapper.
pub trait CloudflareSignerRecipientProofBundleWireHandlerV1 {
    /// Handles one validated Router-to-signer message and returns strict proof-bundle delivery.
    fn handle_signer_recipient_proof_bundle_wire_message(
        &self,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1>;
}

/// SigningWorker v2 prepare logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerNormalSigningPrepareHandlerV2 {
    /// Handles one Router-admitted v2 prepare request.
    fn handle_normal_signing_prepare_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningRound1PreparedV1>;
}

/// SigningWorker v2 presign-pool prepare logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerNormalSigningPresignPoolPrepareHandlerV2 {
    /// Handles one Router-admitted v2 presign-pool refill request.
    fn handle_normal_signing_presign_pool_prepare_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2>;
}

/// SigningWorker v2 finalize logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerNormalSigningFinalizeHandlerV2 {
    /// Handles one Router-admitted v2 finalize request.
    fn handle_normal_signing_finalize_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1>;
}

/// SigningWorker ECDSA-HSS finalize logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1 {
    /// Handles one materialized ECDSA-HSS finalize request.
    fn handle_ecdsa_hss_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1>;
}

/// Private SigningWorker request to fill the ECDSA-HSS presignature pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
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

impl CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Creates a validated ECDSA-HSS presignature pool-fill request.
    pub fn new(
        scope: RouterAbEcdsaHssNormalSigningScopeV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            expires_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates request fields without applying wall-clock expiry.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        decode_base64url_fixed_33_v1("server_big_r33_b64u", &self.server_big_r33_b64u)?;
        decode_base64url_fixed_32_v1("server_k_share32_b64u", &self.server_k_share32_b64u)?;
        decode_base64url_fixed_32_v1("server_sigma_share32_b64u", &self.server_sigma_share32_b64u)?;
        require_positive_ms(
            "ECDSA-HSS presignature pool fill expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates this pool-fill request can be accepted at the supplied timestamp.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_ms("ECDSA-HSS presignature pool fill now_unix_ms", now_unix_ms)?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS presignature pool fill request expired",
            ));
        }
        Ok(())
    }

    /// Builds the unbound pool record for the resolved active SigningWorker.
    pub fn to_pool_record(
        &self,
        active_signing_worker: ActiveSigningWorkerStateV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1> {
        self.validate_at(now_unix_ms)?;
        let lookup =
            CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope(
                &self.scope,
            )?;
        lookup.validate_active_state(&active_signing_worker)?;
        CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new(
            active_signing_worker,
            self.server_presignature_id.clone(),
            self.server_big_r33_b64u.clone(),
            self.server_k_share32_b64u.clone(),
            self.server_sigma_share32_b64u.clone(),
            now_unix_ms,
            self.expires_at_ms,
        )
    }
}

/// Router-admitted v2 prepare request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Router-derived v2 normal-signing prepare admission candidate.
    pub admission_candidate: CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2 {
    /// Creates a validated admitted v2 prepare service request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        admission_candidate: CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            admission_candidate,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact v2 prepare request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms(
            "normal-signing v2 prepare expires_at_ms",
            self.expires_at_ms,
        )?;
        self.admission_candidate.validate()?;
        self.trusted_admission.validate()?;
        if self.admission_candidate.account_id != self.scope.account_id
            || self.admission_candidate.threshold_session_id != self.scope.session_id
            || self.admission_candidate.signing_worker_id != self.scope.signing_worker_id
            || self.admission_candidate.request_id != self.scope.request_id
            || self.admission_candidate.expires_at_ms != self.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission does not match request scope",
            ));
        }
        if self.admission_candidate.round1_binding_digest.is_none() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission requires round1 binding digest",
            ));
        }
        if self.trusted_admission.metadata != self.admission_candidate.to_v1_trusted_metadata()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 trusted admission metadata does not match internal admission",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker normal-signing v2 prepare requires accepted Router admission",
        ))
    }

    fn round1_binding_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.admission_candidate
            .round1_binding_digest
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "normal-signing v2 prepare admission requires round1 binding digest",
                )
            })
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2")
            .field("scope", &self.scope)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("admission_candidate", &self.admission_candidate)
            .field("trusted_admission", &self.trusted_admission)
            .finish()
    }
}

/// Router-admitted v2 Ed25519 presign-pool refill request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2 {
    /// Typed public pool-refill request accepted by the Router.
    pub request: RouterAbEd25519PresignPoolPrepareRequestV2,
    /// Normalized Wallet Session that authorized the refill scope.
    pub wallet_session: CloudflareRouterVerifiedWalletSessionV1,
}

impl CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2 {
    /// Creates a validated admitted v2 presign-pool refill service request.
    pub fn new(
        request: RouterAbEd25519PresignPoolPrepareRequestV2,
        wallet_session: CloudflareRouterVerifiedWalletSessionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            wallet_session,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router authentication accepted this exact refill request scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.wallet_session.validate()?;
        if self.wallet_session.expires_at_ms < self.request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before admitted presign-pool refill request",
            ));
        }
        if self.wallet_session.account_id != self.request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "presign-pool refill Wallet Session account_id does not match scope",
            ));
        }
        if self.wallet_session.threshold_session_id != self.request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "presign-pool refill Wallet Session session_id does not match scope",
            ));
        }
        if self.wallet_session.signing_worker_id != self.request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "presign-pool refill Wallet Session signing_worker_id does not match scope",
            ));
        }
        Ok(())
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2")
            .field("request", &self.request)
            .field("wallet_session", &self.wallet_session)
            .finish()
    }
}

/// Router-admitted v2 finalize request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2 {
    /// Typed public finalize request accepted by the Router.
    pub request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2 {
    /// Creates a validated admitted v2 finalize service request.
    pub fn new(
        request: RouterAbEd25519NormalSigningFinalizeRequestV2,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact v2 finalize request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission
            .validate_for_finalize_request_v2(&self.request)?;
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker normal-signing v2 finalize requires accepted Router admission",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2")
            .field("request", &self.request)
            .field("trusted_admission", &self.trusted_admission)
            .finish()
    }
}

/// Router-admitted v2 Ed25519 presign-pool-hit finalize request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2 {
    /// Typed public pool-hit finalize request accepted by the Router.
    pub request: RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    /// Accepted Router store admission decision for the lowered finalize request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2 {
    /// Creates a validated admitted v2 presign-pool-hit finalize service request.
    pub fn new(
        request: RouterAbEd25519PresignPoolHitFinalizeRequestV2,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact pool-hit finalize request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        let lowered = self.request.to_normal_finalize_request_v2()?;
        self.trusted_admission
            .validate_for_finalize_request_v2(&lowered)?;
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker pool-hit finalize requires accepted Router admission",
        ))
    }

    /// Lowers this admitted pool-hit request into the existing normal finalize request.
    pub fn to_normal_finalize_request_v2(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningFinalizeRequestV2> {
        self.validate()?;
        self.request.to_normal_finalize_request_v2()
    }
}

impl core::fmt::Debug
    for CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(
            "CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2",
        )
        .field("request", &self.request)
        .field("trusted_admission", &self.trusted_admission)
        .finish()
    }
}

/// SigningWorker v2 prepare request after active material lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2 {
    /// Router-admitted v2 prepare request.
    pub request: CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
    /// Active SigningWorker state selected by the Router.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active SigningWorker material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2 {
    /// Creates a validated materialized v2 prepare request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        prepared_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            prepared_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded v2 prepare request and active material agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        if self.prepared_at_ms >= self.request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "normal-signing v2 prepare request expired",
            ));
        }
        self.active_signing_worker
            .validate_for_scope(&self.request.scope)?;
        self.material.validate()?;
        require_positive_ms("normal-signing v2 prepared_at_ms", self.prepared_at_ms)?;
        if self.material.transcript_digest
            == self.active_signing_worker.activation_transcript_digest
            && self.material.recipient_identity
                == self.active_signing_worker.signing_worker.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 prepare material does not match active state",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2")
            .field("request", &self.request)
            .field("active_signing_worker", &self.active_signing_worker)
            .field("material", &self.material)
            .field("prepared_at_ms", &self.prepared_at_ms)
            .finish()
    }
}

/// SigningWorker v2 presign-pool refill request after active material lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2 {
    /// Router-admitted v2 presign-pool refill request.
    pub request: CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2,
    /// Active SigningWorker state selected by the Router.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active SigningWorker material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2 {
    /// Creates a validated materialized v2 presign-pool refill request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        prepared_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            prepared_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded v2 presign-pool refill request and active material agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.prepared_at_ms)?;
        self.active_signing_worker
            .validate_for_scope(&self.request.request.scope)?;
        self.material.validate()?;
        require_positive_ms(
            "normal-signing v2 presign-pool prepared_at_ms",
            self.prepared_at_ms,
        )?;
        if self.material.transcript_digest
            == self.active_signing_worker.activation_transcript_digest
            && self.material.recipient_identity
                == self.active_signing_worker.signing_worker.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 presign-pool material does not match active state",
        ))
    }
}

impl core::fmt::Debug
    for CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct(
            "CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2",
        )
        .field("request", &self.request)
        .field("active_signing_worker", &self.active_signing_worker)
        .field("material", &self.material)
        .field("prepared_at_ms", &self.prepared_at_ms)
        .finish()
    }
}

/// SigningWorker v2 finalize request after active material and round-1 lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2 {
    /// Router-admitted v2 finalize request.
    pub request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    /// Active SigningWorker state selected by the Router.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active SigningWorker material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Exact persisted server round-1 nonce state for this finalize request.
    pub server_round1: CloudflareSigningWorkerRound1RecordV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2 {
    /// Creates a validated materialized v2 finalize request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        server_round1: CloudflareSigningWorkerRound1RecordV1,
        signed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            server_round1,
            signed_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded v2 finalize request, active material, and round-1 state agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.signed_at_ms)?;
        self.active_signing_worker
            .validate_for_scope(&self.request.request.scope)?;
        self.material.validate()?;
        self.server_round1.validate()?;
        require_positive_ms("normal-signing v2 signed_at_ms", self.signed_at_ms)?;
        if self.material.transcript_digest
            != self.active_signing_worker.activation_transcript_digest
            || self.material.recipient_identity
                != self.active_signing_worker.signing_worker.server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker v2 finalize material does not match active state",
            ));
        }
        if self.server_round1.active_signing_worker_state == self.active_signing_worker
            && self.server_round1.server_round1_handle
                == self.request.request.server_round1_handle()
            && self.server_round1.round1_binding_digest
                == self.request.request.round1_binding_digest()
            && self.server_round1.expires_at_ms == self.request.request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 round-1 record does not match materialized finalize request",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2")
            .field("request", &self.request)
            .field("active_signing_worker", &self.active_signing_worker)
            .field("material", &self.material)
            .field("server_round1", &self.server_round1)
            .field("signed_at_ms", &self.signed_at_ms)
            .finish()
    }
}

/// Router-admitted ECDSA-HSS normal-signing request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1 {
    /// Typed public ECDSA-HSS normal-signing request accepted by the Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1 {
    /// Creates a validated admitted ECDSA-HSS normal-signing service request.
    pub fn new(
        request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router-admitted ECDSA-HSS normal-signing material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission.validate()?;
        if self.trusted_admission.metadata.account_id != self.request.scope.context.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS trusted admission account_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.auth.session_id()
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&self.request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS trusted admission session_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.intent_digest != self.request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS trusted admission digest does not match request",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker ECDSA-HSS prepare requires accepted Router admission",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1")
            .field("request", &self.request)
            .field("trusted_admission", &self.trusted_admission)
            .finish()
    }
}

/// Router-admitted ECDSA-HSS finalize request sent to SigningWorker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Typed public ECDSA-HSS finalize request accepted by the Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Creates a validated admitted ECDSA-HSS finalize service request.
    pub fn new(
        request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact ECDSA-HSS finalize body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission.validate()?;
        if self.trusted_admission.metadata.account_id != self.request.scope.context.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize trusted admission account_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.auth.session_id()
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&self.request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize trusted admission session_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.intent_digest != self.request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize trusted admission digest does not match request",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker ECDSA-HSS finalize requires accepted Router admission",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1")
            .field("request", &self.request)
            .field("trusted_admission", &self.trusted_admission)
            .finish()
    }
}

/// ECDSA-HSS normal-signing request after active SigningWorker material lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1 {
    /// Router-admitted ECDSA-HSS request.
    pub request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1,
    /// Active SigningWorker state selected for this ECDSA-HSS identity.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active ECDSA-HSS material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Materialization timestamp in Unix milliseconds.
    pub materialized_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1 {
    /// Creates a validated materialized ECDSA-HSS normal-signing request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        materialized_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            materialized_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded ECDSA-HSS request and active material agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.materialized_at_ms)?;
        require_positive_ms(
            "ECDSA-HSS normal-signing materialized_at_ms",
            self.materialized_at_ms,
        )?;
        validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1(
            &self.request.request.scope,
            &self.active_signing_worker,
            &self.material,
        )
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1")
            .field("request", &self.request)
            .field("active_signing_worker", &self.active_signing_worker)
            .field("material", &self.material)
            .field("materialized_at_ms", &self.materialized_at_ms)
            .finish()
    }
}

/// ECDSA-HSS finalize request after active material and one-use presignature lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Router-admitted ECDSA-HSS finalize request.
    pub request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
    /// Active SigningWorker state selected for this ECDSA-HSS identity.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active ECDSA-HSS material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Exact persisted one-use server presignature state for this finalize request.
    pub server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Creates a validated materialized ECDSA-HSS finalize request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
        signed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            server_presignature,
            signed_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded finalize request, active material, and presignature state agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.signed_at_ms)?;
        require_positive_ms("ECDSA-HSS finalize signed_at_ms", self.signed_at_ms)?;
        validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1(
            &self.request.request.scope,
            &self.active_signing_worker,
            &self.material,
        )?;
        let lookup = CloudflareSigningWorkerEcdsaPresignatureLookupV1::new(
            self.active_signing_worker.clone(),
            self.request.request.server_presignature_id.clone(),
            self.request.request.prepare_request_digest()?,
            self.request.request.signing_digest()?,
            self.signed_at_ms,
        )?;
        self.server_presignature.validate_for_lookup(&lookup)
    }

    /// Returns the prepare request identity that the final signature response must bind.
    pub fn prepare_request(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningRequestV1> {
        self.validate()?;
        self.request.request.prepare_request()
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1")
            .field("request", &self.request)
            .field("active_signing_worker", &self.active_signing_worker)
            .field("material", &self.material)
            .field("server_presignature", &self.server_presignature)
            .field("signed_at_ms", &self.signed_at_ms)
            .finish()
    }
}

/// Materializes and handles one Router-admitted ECDSA-HSS finalize request.
pub fn handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1<Handler>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
    server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1>
where
    Handler: CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1,
{
    let materialized = CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1::new(
        request,
        active_signing_worker,
        material,
        server_presignature,
        now_unix_ms,
    )?;
    let prepare_request = materialized.prepare_request()?;
    let response = handler.handle_ecdsa_hss_evm_digest_finalize_request_v1(materialized)?;
    response.validate_for_request(&prepare_request)?;
    Ok(response)
}

/// SigningWorker-produced ECDSA-HSS presignature record plus public prepare response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1 {
    /// Public response returned to the client through Router.
    pub response: RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1,
    /// Private presignature record persisted by the SigningWorker Durable Object.
    pub record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
}

impl CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1 {
    /// Creates a validated ECDSA-HSS prepared bundle.
    pub fn new(
        response: RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1,
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
        request: &CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let prepared = Self { response, record };
        prepared.validate_for_request(request)?;
        Ok(prepared)
    }

    /// Validates the public response and private record bind to a materialized request.
    pub fn validate_for_request(
        &self,
        request: &CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.response
            .validate_for_request(&request.request.request)?;
        self.record.validate()?;
        let request_digest = request.request.request.request_digest()?;
        let signing_digest = request.request.request.signing_digest()?;
        if self.response.prepared_at_ms == request.materialized_at_ms
            && self.response.expires_at_ms == request.request.request.expires_at_ms
            && self.record.active_signing_worker_state == request.active_signing_worker
            && self.record.server_presignature_id == self.response.server_presignature_id
            && self.record.request_digest == request_digest
            && self.record.admitted_signing_digest == signing_digest
            && self.record.server_big_r33_b64u == self.response.server_big_r33_b64u
            && self.record.rerandomization_entropy32_b64u
                == self.response.rerandomization_entropy32_b64u
            && self.record.created_at_ms == request.materialized_at_ms
            && self.record.expires_at_ms == request.request.request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA-HSS prepared record does not match response",
        ))
    }

    /// Validates the Durable Object put receipt matches the prepared record and response.
    pub fn validate_put_receipt(
        &self,
        receipt: &CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1,
    ) -> RouterAbProtocolResult<()> {
        receipt.validate_for_record(&self.record)?;
        if receipt.server_presignature_id == self.response.server_presignature_id
            && receipt.request_digest == self.response.request_digest
            && receipt.admitted_signing_digest == self.response.signing_digest
            && receipt.server_big_r33_b64u == self.response.server_big_r33_b64u
            && receipt.rerandomization_entropy32_b64u
                == self.response.rerandomization_entropy32_b64u
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA-HSS presignature receipt does not match prepare response",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1")
            .field("response", &self.response)
            .field("record", &self.record)
            .finish()
    }
}

/// Builds a production ECDSA-HSS prepare bundle from a reserved unbound presignature.
pub fn prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1(
    request: CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1,
    pool_record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    rerandomization_entropy32_b64u: impl Into<String>,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1> {
    request.validate()?;
    let pool_lookup = CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1::new(
        request.active_signing_worker.clone(),
        request.request.request.client_presignature_id.clone(),
        request.materialized_at_ms,
    )?;
    pool_record.validate_for_lookup(&pool_lookup)?;
    let rerandomization_entropy32_b64u = rerandomization_entropy32_b64u.into();
    let response = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request.request.request,
        pool_record.server_presignature_id.clone(),
        pool_record.server_big_r33_b64u.clone(),
        rerandomization_entropy32_b64u.clone(),
        request.materialized_at_ms,
    )?;
    let record = pool_record.to_request_bound_record(
        request.request.request.request_digest()?,
        request.request.request.signing_digest()?,
        rerandomization_entropy32_b64u,
        request.materialized_at_ms,
        request.request.request.expires_at_ms,
    )?;
    CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1::new(response, record, &request)
}

/// SigningWorker-produced round-1 record plus public prepare response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerNormalSigningRound1PreparedV1 {
    /// Public response returned to the client through Router.
    pub response: NormalSigningRound1PrepareResponseV1,
    /// Private nonce record persisted by the SigningWorker Durable Object.
    pub record: CloudflareSigningWorkerRound1RecordV1,
}

impl CloudflareSigningWorkerNormalSigningRound1PreparedV1 {
    /// Creates a validated prepared v2 round-1 bundle.
    pub fn new_v2(
        response: NormalSigningRound1PrepareResponseV1,
        record: CloudflareSigningWorkerRound1RecordV1,
        request: &CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<Self> {
        let prepared = Self { response, record };
        prepared.validate_for_v2_request(request)?;
        Ok(prepared)
    }

    /// Validates the public response and private record bind to a v2 materialized request.
    pub fn validate_for_v2_request(
        &self,
        request: &CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.response.validate()?;
        self.record.validate()?;
        let round1_binding_digest = request.request.round1_binding_digest()?;
        let expected_commitments =
            cloudflare_normal_signing_commitments_wire_from_role_separated_v1(
                self.record.round1_state.commitments,
            )?;
        let expected_server_verifying_share = role_separated_ed25519_server_verifying_share_v1(
            *request.material.output_material.as_bytes(),
        )
        .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)?;
        if self.response.scope == request.request.scope
            && self.response.signing_payload_digest
                == request.request.admission_candidate.signing_payload_digest
            && self.response.round1_binding_digest == round1_binding_digest
            && self.response.signing_worker == request.active_signing_worker.signing_worker
            && self.response.expires_at_ms == request.request.expires_at_ms
            && self.record.active_signing_worker_state == request.active_signing_worker
            && self.record.server_round1_handle == self.response.server_round1_handle
            && self.record.round1_binding_digest == round1_binding_digest
            && self.record.admitted_signing_digest
                == request.request.admission_candidate.admitted_signing_digest
            && self.record.created_at_ms == request.prepared_at_ms
            && self.record.expires_at_ms == request.request.expires_at_ms
            && self.response.server_commitments == expected_commitments
            && self.response.server_verifying_share_b64u
                == encode_base64url_bytes_v1(&expected_server_verifying_share)
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 round-1 prepared record does not match response",
        ))
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerNormalSigningRound1PreparedV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerNormalSigningRound1PreparedV1")
            .field("response", &self.response)
            .field("record", &self.record)
            .finish()
    }
}

/// SigningWorker-produced Ed25519 presign-pool records plus public refill response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2 {
    /// Public response returned to the client through Router.
    pub response: RouterAbEd25519PresignPoolPrepareResponseV2,
    /// Private unbound nonce records persisted by the SigningWorker Durable Object.
    pub records: Vec<CloudflareSigningWorkerEd25519PresignPoolRecordV1>,
}

impl CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2 {
    /// Creates a validated presign-pool refill bundle.
    pub fn new_v2(
        response: RouterAbEd25519PresignPoolPrepareResponseV2,
        records: Vec<CloudflareSigningWorkerEd25519PresignPoolRecordV1>,
        request: &CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2,
    ) -> RouterAbProtocolResult<Self> {
        let prepared = Self { response, records };
        prepared.validate_for_v2_request(request)?;
        Ok(prepared)
    }

    /// Validates the public response and private records bind to a materialized refill request.
    pub fn validate_for_v2_request(
        &self,
        request: &CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.response
            .validate_for_request(&request.request.request)?;
        if self.response.accepted.len() != self.records.len() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker presign-pool response and record count differ",
            ));
        }
        for accepted in &self.response.accepted {
            let offer = request
                .request
                .request
                .client_offers
                .iter()
                .find(|offer| offer.client_presign_id == accepted.client_presign_id)
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "accepted presign-pool entry has no originating offer",
                    )
                })?;
            let record = self
                .records
                .iter()
                .find(|record| {
                    record.client_presign_id == accepted.client_presign_id
                        && record.server_round1_handle == accepted.server_round1_handle
                })
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "accepted presign-pool entry has no matching durable record",
                    )
                })?;
            record.validate()?;
            let expected_server_commitments =
                cloudflare_normal_signing_commitments_wire_from_role_separated_v1(
                    record.server_round1_state.commitments,
                )?;
            if record.active_signing_worker_state == request.active_signing_worker
                && record.scope == request.request.request.scope
                && record.client_presign_id == offer.client_presign_id
                && record.client_nonce_handle == offer.client_nonce_handle
                && record.generation == request.request.request.generation
                && record.pool_entry_binding_digest
                    == request.request.request.pool_entry_binding_digest(offer)?
                && record.client_commitments == offer.client_commitments
                && record.client_verifying_share_b64u == offer.client_verifying_share_b64u
                && record.created_at_ms == request.prepared_at_ms
                && record.expires_at_ms == request.request.request.expires_at_ms
                && accepted.generation == record.generation
                && accepted.pool_entry_binding_digest == record.pool_entry_binding_digest
                && accepted.signing_worker == request.active_signing_worker.signing_worker
                && accepted.server_commitments == expected_server_commitments
                && accepted.server_verifying_share_b64u == record.server_verifying_share_b64u
                && accepted.prepared_at_ms == request.prepared_at_ms
                && accepted.expires_at_ms == record.expires_at_ms
            {
                continue;
            }
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker presign-pool record does not match accepted response entry",
            ));
        }
        Ok(())
    }
}

impl core::fmt::Debug for CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2")
            .field("response", &self.response)
            .field("records", &self.records)
            .finish()
    }
}

/// Production SigningWorker normal-signing handler for role-separated Ed25519-HSS.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareRoleSeparatedEd25519NormalSigningHandlerV1;

impl CloudflareSigningWorkerNormalSigningPrepareHandlerV2
    for CloudflareRoleSeparatedEd25519NormalSigningHandlerV1
{
    fn handle_normal_signing_prepare_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningRound1PreparedV1> {
        request.validate()?;
        let mut rng = CloudflareSignerProofGetrandomRngV1;
        let round1_state = prepare_role_separated_ed25519_round1_v1(&mut rng)
            .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)?;
        let mut handle_random = [0u8; 16];
        rand_core_06::RngCore::fill_bytes(&mut rng, &mut handle_random);
        let server_round1_handle = format!(
            "server-round1/{}/{}",
            request.request.scope.request_id,
            encode_base64url_bytes_v1(&handle_random)
        );
        let server_verifying_share = role_separated_ed25519_server_verifying_share_v1(
            *request.material.output_material.as_bytes(),
        )
        .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)?;
        let server_commitments = cloudflare_normal_signing_commitments_wire_from_role_separated_v1(
            round1_state.commitments,
        )?;
        let round1_binding_digest = request.request.round1_binding_digest()?;
        let record = CloudflareSigningWorkerRound1RecordV1::new(
            request.active_signing_worker.clone(),
            server_round1_handle.clone(),
            round1_binding_digest,
            request.request.admission_candidate.admitted_signing_digest,
            round1_state,
            request.prepared_at_ms,
            request.request.expires_at_ms,
        )?;
        let response = NormalSigningRound1PrepareResponseV1::new(
            request.request.scope.clone(),
            request.request.admission_candidate.signing_payload_digest,
            round1_binding_digest,
            request.active_signing_worker.signing_worker.clone(),
            server_round1_handle,
            server_commitments,
            encode_base64url_bytes_v1(&server_verifying_share),
            NormalSigningSignatureSchemeV1::Ed25519V1,
            request.prepared_at_ms,
            request.request.expires_at_ms,
        )?;
        CloudflareSigningWorkerNormalSigningRound1PreparedV1::new_v2(response, record, &request)
    }
}

impl CloudflareSigningWorkerNormalSigningPresignPoolPrepareHandlerV2
    for CloudflareRoleSeparatedEd25519NormalSigningHandlerV1
{
    fn handle_normal_signing_presign_pool_prepare_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2> {
        request.validate()?;
        let mut rng = CloudflareSignerProofGetrandomRngV1;
        let server_verifying_share = role_separated_ed25519_server_verifying_share_v1(
            *request.material.output_material.as_bytes(),
        )
        .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)?;
        let server_verifying_share_b64u = encode_base64url_bytes_v1(&server_verifying_share);
        let mut accepted = Vec::with_capacity(request.request.request.client_offers.len());
        let mut records = Vec::with_capacity(request.request.request.client_offers.len());

        for offer in &request.request.request.client_offers {
            let round1_state = prepare_role_separated_ed25519_round1_v1(&mut rng)
                .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)?;
            let mut handle_random = [0u8; 16];
            rand_core_06::RngCore::fill_bytes(&mut rng, &mut handle_random);
            let server_round1_handle = format!(
                "server-round1-pool/{}/{}/{}",
                request.request.request.generation,
                offer.client_presign_id,
                encode_base64url_bytes_v1(&handle_random)
            );
            let pool_entry_binding_digest =
                request.request.request.pool_entry_binding_digest(offer)?;
            let server_commitments =
                cloudflare_normal_signing_commitments_wire_from_role_separated_v1(
                    round1_state.commitments,
                )?;
            let record = CloudflareSigningWorkerEd25519PresignPoolRecordV1::new(
                request.active_signing_worker.clone(),
                request.request.request.scope.clone(),
                offer.client_presign_id.clone(),
                offer.client_nonce_handle.clone(),
                request.request.request.generation,
                pool_entry_binding_digest,
                server_round1_handle.clone(),
                offer.client_commitments.clone(),
                offer.client_verifying_share_b64u.clone(),
                round1_state,
                server_verifying_share_b64u.clone(),
                request.prepared_at_ms,
                request.request.request.expires_at_ms,
            )?;
            let accepted_entry = RouterAbEd25519PresignPoolAcceptedEntryV2::new(
                offer.client_presign_id.clone(),
                request.request.request.generation,
                pool_entry_binding_digest,
                request.active_signing_worker.signing_worker.clone(),
                server_round1_handle,
                server_commitments,
                server_verifying_share_b64u.clone(),
                NormalSigningSignatureSchemeV1::Ed25519V1,
                request.prepared_at_ms,
                request.request.request.expires_at_ms,
            )?;
            records.push(record);
            accepted.push(accepted_entry);
        }

        let response = RouterAbEd25519PresignPoolPrepareResponseV2::new(
            request.request.request.scope.clone(),
            request.request.request.generation,
            accepted,
            vec![],
        )?;
        CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2::new_v2(
            response, records, &request,
        )
    }
}

impl CloudflareSigningWorkerNormalSigningFinalizeHandlerV2
    for CloudflareRoleSeparatedEd25519NormalSigningHandlerV1
{
    fn handle_normal_signing_finalize_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1> {
        request.validate()?;
        let finalize_request = &request.request.request;
        let RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
            protocol,
        ) = &finalize_request.protocol;
        let server_commitments =
            decode_cloudflare_normal_signing_commitments_v1(&protocol.server_commitments)?;
        if server_commitments != request.server_round1.round1_state.commitments {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "normal-signing v2 server commitments do not match stored round-1 material",
            ));
        }
        let output = finalize_role_separated_ed25519_server_signature_v1(
            RoleSeparatedEd25519ServerFinalizeRequestV1 {
                x_server_base: *request.material.output_material.as_bytes(),
                server_round1: &request.server_round1.round1_state,
                group_public_key: decode_cloudflare_near_ed25519_public_key_v1(
                    "active SigningWorker account_public_key",
                    &request.active_signing_worker.account_public_key,
                )?,
                client_commitments: decode_cloudflare_normal_signing_commitments_v1(
                    &protocol.client_commitments,
                )?,
                server_commitments,
                client_verifying_share: decode_base64url_fixed_32_v1(
                    "normal-signing v2 client_verifying_share_b64u",
                    &protocol.client_verifying_share_b64u,
                )?,
                server_verifying_share: decode_base64url_fixed_32_v1(
                    "normal-signing v2 server_verifying_share_b64u",
                    &protocol.server_verifying_share_b64u,
                )?,
                client_signature_share: decode_base64url_fixed_32_v1(
                    "normal-signing v2 client_signature_share_b64u",
                    &protocol.client_signature_share_b64u,
                )?,
                signing_payload: request.server_round1.admitted_signing_digest.as_bytes(),
            },
        )
        .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)?;
        NormalSigningResponseV1::new(
            finalize_request.scope.clone(),
            finalize_request.signing_payload_digest(),
            request.active_signing_worker.signing_worker.clone(),
            finalize_request.protocol.signature_scheme(),
            CanonicalWireBytesV1::new(output.signature.to_vec())?,
            request.signed_at_ms,
        )
    }
}

/// Production SigningWorker finalize handler for ECDSA-HSS EVM digest signing.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1;

impl CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1
    for CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1
{
    fn handle_ecdsa_hss_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1> {
        request.validate()?;
        let prepare_request = request.prepare_request()?;
        let public_key33 = decode_base64url_fixed_33_v1(
            "ECDSA-HSS threshold_public_key33_b64u",
            &prepare_request
                .scope
                .public_identity
                .threshold_public_key33_b64u,
        )?;
        let server_big_r33 = decode_base64url_fixed_33_v1(
            "ECDSA-HSS server_big_r33_b64u",
            &request.server_presignature.server_big_r33_b64u,
        )?;
        let server_k_share32 = decode_base64url_fixed_32_v1(
            "ECDSA-HSS server_k_share32_b64u",
            &request.server_presignature.server_k_share32_b64u,
        )?;
        let server_sigma_share32 = decode_base64url_fixed_32_v1(
            "ECDSA-HSS server_sigma_share32_b64u",
            &request.server_presignature.server_sigma_share32_b64u,
        )?;
        let rerandomization_entropy32 = decode_base64url_fixed_32_v1(
            "ECDSA-HSS rerandomization_entropy32_b64u",
            &request.server_presignature.rerandomization_entropy32_b64u,
        )?;
        let client_signature_share32 = request.request.request.client_signature_share32()?;
        let participant_ids = ECDSA_HSS_PARTICIPANT_IDS.map(u32::from);
        let signature65 = threshold_ecdsa_finalize_signature(
            &participant_ids,
            2,
            &public_key33,
            &server_big_r33,
            &server_k_share32,
            &server_sigma_share32,
            request
                .server_presignature
                .admitted_signing_digest
                .as_bytes(),
            &rerandomization_entropy32,
            &client_signature_share32,
        )
        .map_err(map_cloudflare_signer_core_ecdsa_error_v1)?;
        RouterAbEcdsaHssEvmDigestSigningResponseV1::new_for_request(
            &prepare_request,
            encode_base64url_bytes_v1(&signature65),
        )
    }
}

fn decode_cloudflare_normal_signing_commitments_v1(
    commitments: &NormalSigningEd25519TwoPartyFrostCommitmentsV1,
) -> RouterAbProtocolResult<RoleSeparatedEd25519CommitmentsV1> {
    RoleSeparatedEd25519CommitmentsV1::new(
        decode_base64url_fixed_32_v1("normal-signing commitments.hiding", &commitments.hiding)?,
        decode_base64url_fixed_32_v1("normal-signing commitments.binding", &commitments.binding)?,
    )
    .map_err(map_cloudflare_ed25519_hss_normal_signing_error_v1)
}

fn cloudflare_normal_signing_commitments_wire_from_role_separated_v1(
    commitments: RoleSeparatedEd25519CommitmentsV1,
) -> RouterAbProtocolResult<NormalSigningEd25519TwoPartyFrostCommitmentsV1> {
    NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
        encode_base64url_bytes_v1(&commitments.hiding),
        encode_base64url_bytes_v1(&commitments.binding),
    )
}

fn decode_cloudflare_near_ed25519_public_key_v1(
    field: &str,
    value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let Some(encoded) = value.strip_prefix("ed25519:") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use ed25519:<base58-public-key> format"),
        ));
    };
    let decoded = bs58::decode(encoded).into_vec().map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} base58 decode failed: {err}"),
        )
    })?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, got {}", decoded.len()),
        )
    })?;
    Ok(bytes)
}

fn map_cloudflare_ed25519_hss_normal_signing_error_v1(
    err: ed25519_hss::shared::ProtoError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("role-separated Ed25519-HSS normal signing failed: {err}"),
    )
}

fn map_cloudflare_signer_core_ecdsa_error_v1(err: SignerCoreError) -> RouterAbProtocolError {
    let code = match err.code {
        SignerCoreErrorCode::InvalidInput
        | SignerCoreErrorCode::InvalidLength
        | SignerCoreErrorCode::DecodeError
        | SignerCoreErrorCode::Utf8Error
        | SignerCoreErrorCode::Unsupported => RouterAbProtocolErrorCode::MalformedWirePayload,
        SignerCoreErrorCode::EncodeError
        | SignerCoreErrorCode::HkdfError
        | SignerCoreErrorCode::CryptoError
        | SignerCoreErrorCode::Internal => RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
    };
    RouterAbProtocolError::new(
        code,
        format!("ECDSA-HSS normal signing finalize failed: {}", err.message),
    )
}

/// Cloudflare production recipient-output encryptor using HPKE base mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareHpkeRecipientOutputEncryptorV1;

impl CloudflareHpkeRecipientOutputEncryptorV1 {
    /// Creates the default HPKE recipient-output encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl RecipientOutputEncryptorV1 for CloudflareHpkeRecipientOutputEncryptorV1 {
    fn encrypt_recipient_output_v1(
        &mut self,
        request: RecipientOutputEncryptionRequestV1<'_>,
    ) -> RouterAbProtocolResult<RecipientOutputCiphertextV1> {
        request.validate()?;
        let recipient_public_key =
            parse_cloudflare_hpke_x25519_public_key_v1(request.recipient_encryption_key())?;
        let aad = cloudflare_hpke_recipient_output_aad_v1(&request)?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1,
            &aad,
            request.plaintext().as_bytes(),
        )
        .map_err(map_cloudflare_hpke_error)?;
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        RecipientOutputCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.package_commitment(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

/// Cloudflare production recipient proof-bundle encryptor using HPKE base mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareHpkeRecipientProofBundleEncryptorV1;

impl CloudflareHpkeRecipientProofBundleEncryptorV1 {
    /// Creates the default HPKE recipient proof-bundle encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl RecipientProofBundleEncryptorV1 for CloudflareHpkeRecipientProofBundleEncryptorV1 {
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
        request.validate()?;
        let recipient_public_key =
            parse_cloudflare_hpke_x25519_public_key_v1(request.recipient_encryption_key())?;
        let aad = cloudflare_hpke_recipient_proof_bundle_aad_v1(&request)?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
            &aad,
            request.plaintext(),
        )
        .map_err(map_cloudflare_hpke_error)?;
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

/// Serializable Cloudflare-local secret material. Debug output redacts bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CloudflareSecretMaterial32V1 {
    bytes: [u8; 32],
}

impl CloudflareSecretMaterial32V1 {
    /// Creates a validated 32-byte secret material record.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Creates a serializable record from core secret material.
    pub fn from_secret_material(secret: &SecretMaterial32) -> Self {
        Self::new(*secret.as_bytes())
    }

    /// Returns secret bytes for server-local cryptographic use.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Converts this record back to core secret material.
    pub fn to_secret_material(&self) -> SecretMaterial32 {
        SecretMaterial32::new(self.bytes)
    }
}

impl core::fmt::Debug for CloudflareSecretMaterial32V1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSecretMaterial32V1")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Server-local material opened from encrypted A/B proof bundles.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareServerOutputMaterialRecordV1 {
    /// Transcript digest that produced the server material.
    pub transcript_digest: PublicDigest32,
    /// Opened share kind. Must be `x_server_base`.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role. Must be `server`.
    pub recipient_role: Role,
    /// Server identity that owns the material.
    pub recipient_identity: String,
    /// Server-local output material.
    pub output_material: CloudflareSecretMaterial32V1,
}

impl CloudflareServerOutputMaterialRecordV1 {
    /// Creates a validated server-output material record.
    pub fn new(
        transcript_digest: PublicDigest32,
        opened_share_kind: OpenedShareKind,
        recipient_role: Role,
        recipient_identity: impl Into<String>,
        output_material: CloudflareSecretMaterial32V1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            transcript_digest,
            opened_share_kind,
            recipient_role,
            recipient_identity: recipient_identity.into(),
            output_material,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates this record holds only server output material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "server output material recipient_identity",
            &self.recipient_identity,
        )?;
        if self.opened_share_kind == OpenedShareKind::XServerBase
            && self.recipient_role == Role::Server
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare server output material must be x_server_base for server",
        ))
    }

    /// Validates this material record matches the activation request that opened it.
    pub fn validate_for_activation_request(
        &self,
        request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let selected_server = &request.activation_context.signer_set().selected_server;
        if self.transcript_digest == request.activation_context.transcript_digest()
            && self.recipient_identity == selected_server.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare server output material does not match activation request",
        ))
    }
}

impl core::fmt::Debug for CloudflareServerOutputMaterialRecordV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareServerOutputMaterialRecordV1")
            .field("transcript_digest", &self.transcript_digest)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("recipient_role", &self.recipient_role)
            .field("recipient_identity", &self.recipient_identity)
            .field("output_material", &"[redacted]")
            .finish()
    }
}

/// Opens one Cloudflare HPKE recipient proof-bundle envelope.
pub fn open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
    envelope: &RecipientProofBundleCiphertextV1,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<RecipientProofBundlePayloadV1> {
    envelope.validate()?;
    if envelope.algorithm != RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare recipient proof-bundle opening requires HPKE",
        ));
    }
    let private_key = parse_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
        private_key_bytes,
        &envelope.recipient_encryption_key,
    )?;
    let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
    if ciphertext_and_tag.len() <= CloudflareHpkeKemV1::ENCAPPED_KEY_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare recipient proof-bundle ciphertext is too short",
        ));
    }
    let (encapped_key, ciphertext) =
        ciphertext_and_tag.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
    let encapped_key =
        CloudflareHpkeKemV1::enc_from_bytes(encapped_key).map_err(map_cloudflare_hpke_error)?;
    let aad = encode_recipient_proof_bundle_ciphertext_aad_v1(envelope)?;
    let plaintext = CloudflareHpkeSuiteV1::open_base(
        &encapped_key,
        &private_key,
        CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
        &aad,
        ciphertext,
    )
    .map_err(map_cloudflare_hpke_error)?;
    let payload = decode_recipient_proof_bundle_payload_v1(&plaintext)?;
    verify_recipient_proof_bundle_ciphertext_payload_v1(envelope, &payload)?;
    Ok(payload)
}

/// Opens encrypted server proof bundles into a serializable server-output material record.
pub fn cloudflare_server_output_material_record_from_activation_request_v1(
    request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareServerOutputMaterialRecordV1> {
    request.validate()?;
    let deriver_a_envelope = decode_cloudflare_recipient_proof_bundle_wire_v1(
        "deriver_a_bundle",
        &request.activation.deriver_a_bundle,
        Role::SignerA,
        Role::Server,
        OpenedShareKind::XServerBase,
    )?;
    let deriver_b_envelope = decode_cloudflare_recipient_proof_bundle_wire_v1(
        "deriver_b_server_bundle",
        &request.activation.deriver_b_server_bundle,
        Role::SignerB,
        Role::Server,
        OpenedShareKind::XServerBase,
    )?;
    let deriver_a_payload = open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
        &deriver_a_envelope,
        private_key_bytes,
    )?;
    let deriver_b_payload = open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
        &deriver_b_envelope,
        private_key_bytes,
    )?;
    let output = combine_mpc_prf_signing_worker_output_from_activation_context_v1(
        &request.activation_context,
        deriver_a_payload,
        deriver_b_payload,
    )?;
    let record = CloudflareServerOutputMaterialRecordV1::new(
        output.transcript_digest,
        output.opened_share_kind,
        output.recipient_role,
        output.recipient_identity,
        CloudflareSecretMaterial32V1::from_secret_material(&output.output_material),
    )?;
    record.validate_for_activation_request(request)?;
    Ok(record)
}

/// Seals signer-input plaintext into a production HPKE signer-envelope payload.
pub fn seal_cloudflare_signer_envelope_hpke_payload_v1(
    recipient_key: &CloudflareSignerEnvelopeHpkePublicKeyV1,
    aad: &RoleEnvelopeAadV1,
    plaintext: &[u8],
) -> RouterAbProtocolResult<SignerEnvelopeHpkePayloadV1> {
    recipient_key.validate()?;
    aad.validate()?;
    if aad.recipient.role != recipient_key.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare signer-envelope HPKE recipient key does not match AAD recipient",
        ));
    }
    if plaintext.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer-envelope HPKE plaintext must be non-empty",
        ));
    }
    let recipient_public_key =
        parse_cloudflare_hpke_x25519_public_key_v1(&recipient_key.public_key)?;
    let aad_bytes = aad.canonical_bytes();
    let mut rng = CloudflareHpkeGetrandomRngV1;
    let (encapped_key, ciphertext_and_tag) = CloudflareHpkeSuiteV1::seal_base(
        &mut rng,
        &recipient_public_key,
        CLOUDFLARE_HPKE_SIGNER_ENVELOPE_INFO_V1,
        &aad_bytes,
        plaintext,
    )
    .map_err(map_cloudflare_signer_envelope_hpke_error)?;
    let encapped_key = encapped_key.as_ref().try_into().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer-envelope HPKE encapsulated key must be 32 bytes",
        )
    })?;
    SignerEnvelopeHpkePayloadV1::new(
        recipient_key.role,
        recipient_key.key_epoch.clone(),
        recipient_key.public_key.clone(),
        aad.digest(),
        encapped_key,
        ciphertext_and_tag,
    )
}

/// Opens a production HPKE signer-envelope payload after public metadata validation.
pub fn open_cloudflare_signer_envelope_hpke_payload_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<Vec<u8>> {
    let payload = decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1(
        worker_role,
        message,
        envelope_decrypt_key,
    )?;
    aad.validate()?;
    if aad.digest() != payload.aad_digest || aad.recipient.role != payload.recipient_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer envelope AAD does not match parsed HPKE payload",
        ));
    }
    let private_key = parse_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
        private_key_bytes,
        &envelope_decrypt_key.public_key,
    )?;
    let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(payload.encapped_key())
        .map_err(map_cloudflare_signer_envelope_hpke_error)?;
    CloudflareHpkeSuiteV1::open_base(
        &encapped_key,
        &private_key,
        CLOUDFLARE_HPKE_SIGNER_ENVELOPE_INFO_V1,
        &aad.canonical_bytes(),
        payload.ciphertext_and_tag(),
    )
    .map_err(map_cloudflare_signer_envelope_hpke_error)
}

type CloudflareHpkeSuiteV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;
type CloudflareHpkeKemV1 = DhKemX25519HkdfSha256;

const CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-output/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-proof-bundle/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const CLOUDFLARE_HPKE_SIGNER_ENVELOPE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/signer-envelope/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1: [u8; 12] = [0u8; 12];

struct CloudflareHpkeGetrandomRngV1;

impl RngCore for CloudflareHpkeGetrandomRngV1 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("Cloudflare HPKE recipient-output RNG failed");
    }
}

impl CryptoRng for CloudflareHpkeGetrandomRngV1 {}

struct CloudflareSignerProofGetrandomRngV1;

impl rand_core_06::RngCore for CloudflareSignerProofGetrandomRngV1 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("Cloudflare signer proof RNG failed");
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for CloudflareSignerProofGetrandomRngV1 {}

fn cloudflare_hpke_recipient_output_aad_v1(
    request: &RecipientOutputEncryptionRequestV1<'_>,
) -> RouterAbProtocolResult<Vec<u8>> {
    let placeholder = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        request.recipient_role(),
        request.opened_share_kind(),
        request.recipient_identity(),
        request.recipient_encryption_key(),
        request.transcript_digest(),
        request.package_commitment(),
        CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
        EncryptedPayloadV1::new(vec![0u8])?,
    )?;
    encode_recipient_output_ciphertext_aad_v1(&placeholder)
}

fn cloudflare_hpke_recipient_proof_bundle_aad_v1(
    request: &RecipientProofBundleEncryptionRequestV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    let placeholder = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        request.signer().clone(),
        request.recipient_role(),
        request.opened_share_kind(),
        request.recipient_identity(),
        request.recipient_encryption_key(),
        request.transcript_digest(),
        request.payload_digest(),
        CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
        EncryptedPayloadV1::new(vec![0u8])?,
    )?;
    encode_recipient_proof_bundle_ciphertext_aad_v1(&placeholder)
}

fn parse_cloudflare_hpke_x25519_public_key_v1(
    encoded: &str,
) -> RouterAbProtocolResult<<CloudflareHpkeKemV1 as Kem>::PublicKey> {
    let hex_value = encoded.strip_prefix("x25519:").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must use x25519:<64 lowercase hex chars> encoding",
        )
    })?;
    let public_key_bytes = decode_cloudflare_hpke_x25519_hex_v1(hex_value)?;
    let public_key =
        CloudflareHpkeKemV1::pk_from_bytes(&public_key_bytes).map_err(map_cloudflare_hpke_error)?;
    if CloudflareHpkeKemV1::pk_to_bytes(&public_key) != public_key_bytes {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must be canonical X25519 bytes",
        ));
    }
    Ok(public_key)
}

fn decode_cloudflare_hpke_x25519_hex_v1(hex_value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    if hex_value.len() != 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key hex must be 64 characters",
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] =
            (decode_cloudflare_lower_hex_nibble_v1("HPKE recipient public key", chunk[0])? << 4)
                | decode_cloudflare_lower_hex_nibble_v1("HPKE recipient public key", chunk[1])?;
    }
    Ok(out)
}

fn decode_cloudflare_hpke_private_key_hex_v1(
    field: &'static str,
    hex_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    if hex_value.len() != 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} HPKE private key hex must be 64 characters"),
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (decode_cloudflare_lower_hex_nibble_for_config_v1(field, chunk[0])? << 4)
            | decode_cloudflare_lower_hex_nibble_for_config_v1(field, chunk[1])?;
    }
    Ok(out)
}

/// Encodes signer-envelope HPKE private-key bytes for Cloudflare Secrets.
pub fn encode_cloudflare_signer_envelope_hpke_private_key_secret_v1(
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<String> {
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(private_key_bytes)?;
    let mut out = String::from(CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1);
    push_lower_hex_v1(&mut out, private_key_bytes);
    Ok(out)
}

/// Decodes signer-envelope HPKE private-key bytes from a Cloudflare Secret value.
pub fn decode_cloudflare_signer_envelope_hpke_private_key_secret_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let trimmed = secret_value.trim();
    let hex_value = trimmed
        .strip_prefix(CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare signer-envelope HPKE private key secret has unsupported prefix",
            )
        })?;
    let private_key_bytes =
        decode_cloudflare_hpke_private_key_hex_v1("Cloudflare signer-envelope", hex_value)?;
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(&private_key_bytes)?;
    Ok(private_key_bytes)
}

/// Encodes server-output HPKE private-key bytes for Cloudflare Secrets.
pub fn encode_cloudflare_server_output_hpke_private_key_secret_v1(
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<String> {
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(private_key_bytes)?;
    let mut out = String::from(CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1);
    push_lower_hex_v1(&mut out, private_key_bytes);
    Ok(out)
}

/// Decodes server-output HPKE private-key bytes from a Cloudflare Secret value.
pub fn decode_cloudflare_server_output_hpke_private_key_secret_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let trimmed = secret_value.trim();
    let hex_value = trimmed
        .strip_prefix(CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare server-output HPKE private key secret has unsupported prefix",
            )
        })?;
    let private_key_bytes =
        decode_cloudflare_hpke_private_key_hex_v1("Cloudflare server-output", hex_value)?;
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(&private_key_bytes)?;
    Ok(private_key_bytes)
}

fn validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<()> {
    if private_key_bytes.len() != CloudflareHpkeKemV1::PRIVATE_KEY_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare signer-envelope HPKE private key must be 32 bytes",
        ));
    }
    let private_key = CloudflareHpkeKemV1::sk_from_bytes(private_key_bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare signer-envelope HPKE private key is invalid: {err}"),
        )
    })?;
    drop(private_key);
    Ok(())
}

fn parse_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
    private_key_bytes: &[u8],
    expected_public_key: &str,
) -> RouterAbProtocolResult<<CloudflareHpkeKemV1 as Kem>::PrivateKey> {
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(private_key_bytes)?;
    parse_cloudflare_hpke_x25519_public_key_v1(expected_public_key)?;
    CloudflareHpkeKemV1::sk_from_bytes(private_key_bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare signer-envelope HPKE private key is invalid: {err}"),
        )
    })
}

fn push_lower_hex_v1(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_cloudflare_lower_hex_nibble_v1(
    field: &'static str,
    byte: u8,
) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use lowercase hex"),
        )),
    }
}

fn decode_cloudflare_lower_hex_nibble_for_config_v1(
    field: &'static str,
    byte: u8,
) -> RouterAbProtocolResult<u8> {
    decode_cloudflare_lower_hex_nibble_v1(field, byte).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            err.message().to_owned(),
        )
    })
}

fn map_cloudflare_hpke_error(err: hpke_ng::HpkeError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Cloudflare HPKE recipient-output encryption failed: {err}"),
    )
}

fn map_cloudflare_signer_envelope_hpke_error(err: hpke_ng::HpkeError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Cloudflare signer-envelope HPKE operation failed: {err}"),
    )
}

/// Deterministic map-backed Env reader for tests and local adapter validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEnvMapV1 {
    entries: BTreeMap<String, String>,
}

impl CloudflareEnvMapV1 {
    /// Creates an empty map-backed Env reader.
    pub fn new(entries: Vec<(impl Into<String>, impl Into<String>)>) -> Self {
        let entries = entries
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        Self { entries }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a copy with the supplied entries inserted or replaced.
    pub fn with_overrides(mut self, entries: Vec<(impl Into<String>, impl Into<String>)>) -> Self {
        for (key, value) in entries {
            self.entries.insert(key.into(), value.into());
        }
        self
    }
}

impl CloudflareEnvReaderV1 for CloudflareEnvMapV1 {
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>> {
        Ok(self.entries.get(key).cloned())
    }
}

/// Cloudflare Worker role in the Router/A/B deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareWorkerRoleV1 {
    /// Public Router Worker.
    Router,
    /// Derivation-only Signer A Worker.
    SignerA,
    /// Signer B Worker.
    SignerB,
    /// Dedicated normal-signing worker that owns active SigningWorker output.
    SigningWorker,
}

impl CloudflareWorkerRoleV1 {
    /// Returns the stable role label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::SignerA => "deriver_a",
            Self::SignerB => "deriver_b",
            Self::SigningWorker => "signing_worker",
        }
    }
}

/// Durable Object storage scope for Router/A/B Cloudflare adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum CloudflareDurableObjectScopeV1 {
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
    /// Router Wallet Session signing budget state.
    RouterWalletBudget,
    /// Role-local sealed root-share state.
    SignerRootShare {
        /// Signer role that owns this storage scope.
        role: Role,
    },
    /// Server-output activation state hosted by the SigningWorker.
    ServerOutput {
        /// Worker role that owns server activation state.
        owner_role: CloudflareWorkerRoleV1,
    },
}

impl CloudflareDurableObjectScopeV1 {
    /// Creates a signer root-share scope for Signer A or Signer B.
    pub fn signer_root_share(role: Role) -> RouterAbProtocolResult<Self> {
        require_signer_role(role)?;
        Ok(Self::SignerRootShare { role })
    }

    /// Creates the SigningWorker server-output scope.
    pub fn signing_worker_server_output() -> Self {
        Self::ServerOutput {
            owner_role: CloudflareWorkerRoleV1::SigningWorker,
        }
    }

    /// Validates the scope itself.
    pub fn validate(self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RouterReplay
            | Self::RouterLifecycle
            | Self::RouterProjectPolicy
            | Self::RouterQuota
            | Self::RouterAbuse
            | Self::RouterWalletBudget => Ok(()),
            Self::SignerRootShare { role } => require_signer_role(role),
            Self::ServerOutput { owner_role } => {
                if owner_role == CloudflareWorkerRoleV1::SigningWorker {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidRole,
                        "v1 server-output Durable Object scope must be owned by SigningWorker",
                    ))
                }
            }
        }
    }

    /// Returns whether this scope is visible to a Worker role.
    pub fn is_visible_to(self, worker_role: CloudflareWorkerRoleV1) -> bool {
        match (worker_role, self) {
            (
                CloudflareWorkerRoleV1::Router,
                Self::RouterReplay
                | Self::RouterLifecycle
                | Self::RouterProjectPolicy
                | Self::RouterQuota
                | Self::RouterAbuse
                | Self::RouterWalletBudget,
            ) => true,
            (
                CloudflareWorkerRoleV1::SignerA,
                Self::SignerRootShare {
                    role: Role::SignerA,
                },
            ) => true,
            (
                CloudflareWorkerRoleV1::SignerB,
                Self::SignerRootShare {
                    role: Role::SignerB,
                },
            ) => true,
            (
                CloudflareWorkerRoleV1::SigningWorker,
                Self::ServerOutput {
                    owner_role: CloudflareWorkerRoleV1::SigningWorker,
                },
            ) => true,
            _ => false,
        }
    }
}

/// Durable Object binding descriptor after Cloudflare env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDurableObjectBindingV1 {
    /// Durable Object storage scope.
    pub scope: CloudflareDurableObjectScopeV1,
    /// Cloudflare Env binding name.
    pub binding_name: String,
    /// Durable Object object name.
    pub object_name: String,
    /// Prefix for keys within the Durable Object.
    pub key_prefix: String,
}

impl CloudflareDurableObjectBindingV1 {
    /// Creates a validated Durable Object binding descriptor.
    pub fn new(
        scope: CloudflareDurableObjectScopeV1,
        binding_name: impl Into<String>,
        object_name: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            scope,
            binding_name: binding_name.into(),
            object_name: object_name.into(),
            key_prefix: key_prefix.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates binding fields and storage scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("object_name", &self.object_name)?;
        require_non_empty("key_prefix", &self.key_prefix)
    }

    /// Validates this binding is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.scope.is_visible_to(worker_role) {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} Durable Object scope",
                worker_role.as_str(),
                self.scope
            ),
        ))
    }
}

/// Service Binding or HTTPS peer descriptor after Cloudflare env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflarePeerBindingV1 {
    /// Peer Worker role.
    pub peer_role: CloudflareWorkerRoleV1,
    /// Cloudflare Service Binding name or configured peer endpoint label.
    pub binding_name: String,
}

impl CloudflarePeerBindingV1 {
    /// Creates a validated peer binding descriptor.
    pub fn new(
        peer_role: CloudflareWorkerRoleV1,
        binding_name: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            peer_role,
            binding_name: binding_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates peer binding fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("binding_name", &self.binding_name)
    }
}

/// Role-local signing-root-share wire Secret binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareWireSecretBindingV1 {
    /// Signer role that owns this root-share wire secret.
    pub role: Role,
    /// Cloudflare Secret binding name that contains the root-share wire.
    pub binding_name: String,
}

impl CloudflareRootShareWireSecretBindingV1 {
    /// Creates a validated root-share wire secret descriptor.
    pub fn new(role: Role, binding_name: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            binding_name: binding_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates secret ownership and descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("binding_name", &self.binding_name)
    }

    /// Validates this secret descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (CloudflareWorkerRoleV1::SignerA, Role::SignerA)
                | (CloudflareWorkerRoleV1::SignerB, Role::SignerB)
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} root-share wire secret",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

/// Public signer-envelope HPKE key descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerEnvelopeHpkePublicKeyV1 {
    /// Signer role that owns this public envelope key.
    pub role: Role,
    /// Public decrypt-key epoch used for transcript and rotation binding.
    pub key_epoch: String,
    /// Canonical `x25519:<64 lowercase hex chars>` public key.
    pub public_key: String,
}

impl CloudflareSignerEnvelopeHpkePublicKeyV1 {
    /// Creates a validated signer-envelope HPKE public-key descriptor.
    pub fn new(
        role: Role,
        key_epoch: impl Into<String>,
        public_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let descriptor = Self {
            role,
            key_epoch: key_epoch.into(),
            public_key: public_key.into(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validates signer ownership and canonical public-key encoding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("key_epoch", &self.key_epoch)?;
        parse_cloudflare_hpke_x25519_public_key_v1(&self.public_key)?;
        Ok(())
    }
}

/// Public A/B signer-envelope HPKE key set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerEnvelopeHpkePublicKeySetV1 {
    /// Signer A public envelope key descriptor.
    pub deriver_a: CloudflareSignerEnvelopeHpkePublicKeyV1,
    /// Signer B public envelope key descriptor.
    pub deriver_b: CloudflareSignerEnvelopeHpkePublicKeyV1,
}

impl CloudflareSignerEnvelopeHpkePublicKeySetV1 {
    /// Creates a validated public A/B signer-envelope HPKE key set.
    pub fn new(
        deriver_a: CloudflareSignerEnvelopeHpkePublicKeyV1,
        deriver_b: CloudflareSignerEnvelopeHpkePublicKeyV1,
    ) -> RouterAbProtocolResult<Self> {
        let key_set = Self {
            deriver_a,
            deriver_b,
        };
        key_set.validate()?;
        Ok(key_set)
    }

    /// Validates role assignments and public-key descriptors.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.deriver_a.validate()?;
        self.deriver_b.validate()?;
        if self.deriver_a.role != Role::SignerA {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Signer A HPKE public key descriptor must use Signer A role",
            ));
        }
        if self.deriver_b.role != Role::SignerB {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Signer B HPKE public key descriptor must use Signer B role",
            ));
        }
        Ok(())
    }

    /// Returns the public-key descriptor for one signer role.
    pub fn for_role(
        &self,
        role: Role,
    ) -> RouterAbProtocolResult<&CloudflareSignerEnvelopeHpkePublicKeyV1> {
        match role {
            Role::SignerA => Ok(&self.deriver_a),
            Role::SignerB => Ok(&self.deriver_b),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "signer-envelope HPKE public key set supports only signer roles",
            )),
        }
    }
}

/// Public signer-envelope HPKE keyset with optional previous-epoch overlap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1 {
    /// Current signer-envelope public keys used for new client envelopes.
    pub current: CloudflareSignerEnvelopeHpkePublicKeySetV1,
    /// Previous signer-envelope public keys accepted only during overlap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<CloudflareSignerEnvelopeHpkePublicKeySetV1>,
    /// Millisecond timestamp when the previous keys must stop being accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_retire_at_ms: Option<u64>,
}

impl CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1 {
    /// Creates a current-only signer-envelope HPKE keyset.
    pub fn current_only(
        current: CloudflareSignerEnvelopeHpkePublicKeySetV1,
    ) -> RouterAbProtocolResult<Self> {
        let key_set = Self {
            current,
            previous: None,
            previous_retire_at_ms: None,
        };
        key_set.validate()?;
        Ok(key_set)
    }

    /// Creates a signer-envelope HPKE keyset with previous-epoch overlap.
    pub fn current_and_previous(
        current: CloudflareSignerEnvelopeHpkePublicKeySetV1,
        previous: CloudflareSignerEnvelopeHpkePublicKeySetV1,
        previous_retire_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let key_set = Self {
            current,
            previous: Some(previous),
            previous_retire_at_ms: Some(previous_retire_at_ms),
        };
        key_set.validate()?;
        Ok(key_set)
    }

    /// Validates the current-only or current-plus-previous branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.current.validate()?;
        match (&self.previous, self.previous_retire_at_ms) {
            (None, None) => Ok(()),
            (Some(previous), Some(previous_retire_at_ms)) => {
                previous.validate()?;
                if previous_retire_at_ms == 0 {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidTimeRange,
                        "previous signer-envelope HPKE retirement timestamp must be positive",
                    ));
                }
                require_rotated_hpke_descriptor_v1(
                    "deriver_a",
                    &self.current.deriver_a,
                    &previous.deriver_a,
                )?;
                require_rotated_hpke_descriptor_v1(
                    "deriver_b",
                    &self.current.deriver_b,
                    &previous.deriver_b,
                )?;
                Ok(())
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "previous signer-envelope HPKE keyset and retirement timestamp must be provided together",
            )),
        }
    }

    /// Returns the descriptor accepted for a role/key epoch at one wall-clock time.
    pub fn accepted_for_role_epoch(
        &self,
        role: Role,
        key_epoch: &str,
        now_ms: u64,
    ) -> RouterAbProtocolResult<&CloudflareSignerEnvelopeHpkePublicKeyV1> {
        require_non_empty("key_epoch", key_epoch)?;
        let current = self.current.for_role(role)?;
        if current.key_epoch == key_epoch {
            return Ok(current);
        }
        if let (Some(previous), Some(previous_retire_at_ms)) =
            (&self.previous, self.previous_retire_at_ms)
        {
            let previous_for_role = previous.for_role(role)?;
            if previous_for_role.key_epoch == key_epoch {
                if now_ms <= previous_retire_at_ms {
                    return Ok(previous_for_role);
                }
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ExpiredLocalRequest,
                    "previous signer-envelope HPKE key epoch is retired",
                ));
            }
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "signer-envelope HPKE key epoch is not in the current or previous keyset",
        ))
    }
}

fn require_rotated_hpke_descriptor_v1(
    label: &str,
    current: &CloudflareSignerEnvelopeHpkePublicKeyV1,
    previous: &CloudflareSignerEnvelopeHpkePublicKeyV1,
) -> RouterAbProtocolResult<()> {
    if current.role != previous.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!("{label} previous signer-envelope HPKE role does not match current role"),
        ));
    }
    if current.key_epoch == previous.key_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} previous signer-envelope HPKE key epoch must differ from current"),
        ));
    }
    if current.public_key == previous.public_key {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} previous signer-envelope HPKE public key must differ from current"),
        ));
    }
    Ok(())
}

/// Role-local signer-envelope HPKE private-key binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1 {
    /// Signer role that owns this envelope decrypt key.
    pub role: Role,
    /// Cloudflare Secret binding name that contains the HPKE private key.
    pub binding_name: String,
    /// Public decrypt-key epoch used for transcript and rotation binding.
    pub key_epoch: String,
    /// Public key paired with the private binding.
    pub public_key: String,
}

impl CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1 {
    /// Creates a validated signer-envelope HPKE decrypt-key descriptor.
    pub fn new(
        role: Role,
        binding_name: impl Into<String>,
        key_epoch: impl Into<String>,
        public_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            binding_name: binding_name.into(),
            key_epoch: key_epoch.into(),
            public_key: public_key.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates key ownership, binding name, and public descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("key_epoch", &self.key_epoch)?;
        parse_cloudflare_hpke_x25519_public_key_v1(&self.public_key)?;
        Ok(())
    }

    /// Returns the public descriptor corresponding to this private binding.
    pub fn public_descriptor(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkePublicKeyV1> {
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            self.role,
            self.key_epoch.clone(),
            self.public_key.clone(),
        )
    }

    /// Validates this key descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (CloudflareWorkerRoleV1::SignerA, Role::SignerA)
                | (CloudflareWorkerRoleV1::SignerB, Role::SignerB)
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} signer-envelope HPKE decrypt key",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

/// Role-local signer-envelope HPKE private-key rotation set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
    /// Key used for newly sealed signer envelopes.
    pub current: CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    /// Temporarily accepted previous key during rotation overlap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1>,
    /// Last timestamp at which the previous key is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_retire_at_ms: Option<u64>,
}

impl From<CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1>
    for CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1
{
    fn from(current: CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1) -> Self {
        Self {
            current,
            previous: None,
            previous_retire_at_ms: None,
        }
    }
}

impl CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
    /// Creates a current-only HPKE decrypt-key set.
    pub fn current_only(
        current: CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let set = Self {
            current,
            previous: None,
            previous_retire_at_ms: None,
        };
        set.validate()?;
        Ok(set)
    }

    /// Creates a rotating HPKE decrypt-key set with an accepted previous key.
    pub fn current_and_previous(
        current: CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
        previous: CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
        previous_retire_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let set = Self {
            current,
            previous: Some(previous),
            previous_retire_at_ms: Some(previous_retire_at_ms),
        };
        set.validate()?;
        Ok(set)
    }

    /// Validates role-local rotation shape and key separation.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.current.validate()?;
        match (&self.previous, self.previous_retire_at_ms) {
            (None, None) => Ok(()),
            (Some(previous), Some(retire_at_ms)) => {
                previous.validate()?;
                require_positive_ms(
                    "previous signer-envelope HPKE private-key retire_at_ms",
                    retire_at_ms,
                )?;
                let current = self.current.public_descriptor()?;
                let previous_public = previous.public_descriptor()?;
                require_rotated_hpke_descriptor_v1(
                    "private signer-envelope HPKE",
                    &current,
                    &previous_public,
                )?;
                if self.current.binding_name == previous.binding_name {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "previous signer-envelope HPKE private-key binding must differ from current",
                    ));
                }
                Ok(())
            }
            (None, Some(_)) | (Some(_), None) => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "previous signer-envelope HPKE private-key binding and retire timestamp must be configured together",
            )),
        }
    }

    /// Validates this key set is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        self.current.validate_visible_to(worker_role)?;
        if let Some(previous) = &self.previous {
            previous.validate_visible_to(worker_role)?;
        }
        Ok(())
    }

    /// Selects the decrypt key bound by a signer-envelope HPKE payload.
    pub fn accepted_binding_for_payload(
        &self,
        worker_role: CloudflareWorkerRoleV1,
        payload: &SignerEnvelopeHpkePayloadV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<&CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1> {
        self.validate_visible_to(worker_role)?;
        require_positive_ms("signer-envelope HPKE rotation now_unix_ms", now_unix_ms)?;
        payload.validate()?;
        let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
        if payload.recipient_role != expected_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "signer-envelope HPKE payload recipient does not match Worker role",
            ));
        }
        if signer_envelope_hpke_payload_matches_binding_v1(payload, &self.current) {
            return Ok(&self.current);
        }
        if let (Some(previous), Some(retire_at_ms)) = (&self.previous, self.previous_retire_at_ms) {
            if signer_envelope_hpke_payload_matches_binding_v1(payload, previous) {
                if now_unix_ms > retire_at_ms {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::ExpiredLocalRequest,
                        "previous signer-envelope HPKE key is retired",
                    ));
                }
                return Ok(previous);
            }
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "signer-envelope HPKE payload key is not in the current or previous private keyset",
        ))
    }
}

fn signer_envelope_hpke_payload_matches_binding_v1(
    payload: &SignerEnvelopeHpkePayloadV1,
    binding: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
) -> bool {
    payload.recipient_role == binding.role
        && payload.key_epoch == binding.key_epoch
        && payload.recipient_public_key == binding.public_key
}

/// SigningWorker server-output HPKE decrypt-key binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareServerOutputHpkeDecryptKeyBindingV1 {
    /// Cloudflare Secret binding name that contains the server-output HPKE private key.
    pub binding_name: String,
    /// Public decrypt-key epoch used for server-output rotation binding.
    pub key_epoch: String,
    /// Public key paired with the private binding.
    pub public_key: String,
}

impl CloudflareServerOutputHpkeDecryptKeyBindingV1 {
    /// Creates a validated server-output HPKE decrypt-key descriptor.
    pub fn new(
        binding_name: impl Into<String>,
        key_epoch: impl Into<String>,
        public_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            binding_name: binding_name.into(),
            key_epoch: key_epoch.into(),
            public_key: public_key.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates binding name and public descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("key_epoch", &self.key_epoch)?;
        parse_cloudflare_hpke_x25519_public_key_v1(&self.public_key)?;
        Ok(())
    }

    /// Validates this key descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if worker_role == CloudflareWorkerRoleV1::SigningWorker {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access server-output HPKE decrypt key",
                worker_role.as_str()
            ),
        ))
    }

    /// Validates this decrypt key matches the selected server identity.
    pub fn validate_matches_server(&self, server: &ServerIdentityV1) -> RouterAbProtocolResult<()> {
        self.validate()?;
        server.validate()?;
        if self.key_epoch == server.key_epoch && self.public_key == server.recipient_encryption_key
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "server-output HPKE decrypt key does not match selected server",
        ))
    }
}

/// Role-local A/B peer-message Ed25519 signing secret binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerSigningKeyBindingV1 {
    /// Signer role that owns this peer signing key.
    pub role: Role,
    /// Cloudflare Secret binding name that contains the Ed25519 signing seed.
    pub binding_name: String,
    /// Public signing-key epoch used for signer identity and rotation binding.
    pub key_epoch: String,
}

impl CloudflareSignerPeerSigningKeyBindingV1 {
    /// Creates a validated A/B peer signing-key descriptor.
    pub fn new(
        role: Role,
        binding_name: impl Into<String>,
        key_epoch: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            binding_name: binding_name.into(),
            key_epoch: key_epoch.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates key ownership and public descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("key_epoch", &self.key_epoch)
    }

    /// Validates this key descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (CloudflareWorkerRoleV1::SignerA, Role::SignerA)
                | (CloudflareWorkerRoleV1::SignerB, Role::SignerB)
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} A/B peer signing key",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

/// Public A/B peer-message Ed25519 verifying key bytes for one signer role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeyBytesV1 {
    /// Signer role that owns this verifying key.
    pub role: Role,
    /// Raw Ed25519 verifying key bytes.
    pub verifying_key_bytes: [u8; 32],
}

impl CloudflareSignerPeerVerifyingKeyBytesV1 {
    /// Creates validated role-bound peer verifying key bytes.
    pub fn new(role: Role, verifying_key_bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        let key = Self {
            role,
            verifying_key_bytes,
        };
        key.validate()?;
        Ok(key)
    }

    /// Validates role ownership and Ed25519 key shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        let probe_identity = SignerIdentityV1::new(
            self.role,
            "cloudflare-peer-verifying-key-probe",
            "cloudflare-peer-verifying-key-probe",
        )?;
        AbPeerMessageVerifyingKeyV1::new(probe_identity, self.verifying_key_bytes)?;
        Ok(())
    }

    /// Binds these key bytes to a request signer identity.
    pub fn bind_to_signer(
        &self,
        signer: SignerIdentityV1,
    ) -> RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        self.validate()?;
        signer.validate()?;
        if signer.role != self.role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Cloudflare peer verifying key role differs from signer identity",
            ));
        }
        AbPeerMessageVerifyingKeyV1::new(signer, self.verifying_key_bytes)
    }

    /// Returns this public verifying key as lowercase hex.
    pub fn to_hex_descriptor(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeyHexV1> {
        self.validate()?;
        let mut verifying_key_hex = String::new();
        push_lower_hex_v1(&mut verifying_key_hex, &self.verifying_key_bytes);
        CloudflareSignerPeerVerifyingKeyHexV1::new(self.role, verifying_key_hex)
    }
}

/// Public A/B peer-message Ed25519 verifying key descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeyHexV1 {
    /// Signer role that owns this verifying key.
    pub role: Role,
    /// Raw Ed25519 verifying key bytes encoded as lowercase hex.
    pub verifying_key_hex: String,
}

impl CloudflareSignerPeerVerifyingKeyHexV1 {
    /// Creates a validated public peer verifying-key descriptor.
    pub fn new(role: Role, verifying_key_hex: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let descriptor = Self {
            role,
            verifying_key_hex: verifying_key_hex.into(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validates role ownership and Ed25519 key shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        CloudflareSignerPeerVerifyingKeyBytesV1::new(
            self.role,
            decode_cloudflare_peer_verifying_key_hex_v1(&self.verifying_key_hex)?,
        )?;
        Ok(())
    }
}

/// Public A/B peer-message Ed25519 verifying-key set for discovery responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeyHexSetV1 {
    /// Signer A peer-message verifying key descriptor.
    pub deriver_a: CloudflareSignerPeerVerifyingKeyHexV1,
    /// Signer B peer-message verifying key descriptor.
    pub deriver_b: CloudflareSignerPeerVerifyingKeyHexV1,
}

impl CloudflareSignerPeerVerifyingKeyHexSetV1 {
    /// Creates a validated public A/B verifying-key set descriptor.
    pub fn new(
        deriver_a: CloudflareSignerPeerVerifyingKeyHexV1,
        deriver_b: CloudflareSignerPeerVerifyingKeyHexV1,
    ) -> RouterAbProtocolResult<Self> {
        let set = Self {
            deriver_a,
            deriver_b,
        };
        set.validate()?;
        Ok(set)
    }

    /// Validates role ordering and key descriptors.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.deriver_a.validate()?;
        self.deriver_b.validate()?;
        if self.deriver_a.role != Role::SignerA || self.deriver_b.role != Role::SignerB {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Cloudflare peer verifying-key descriptor roles must be Signer A and Signer B",
            ));
        }
        Ok(())
    }
}

/// Trusted public A/B peer verifying-key set loaded by signer Workers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeySetV1 {
    /// Signer A peer-message verifying key bytes.
    pub deriver_a: CloudflareSignerPeerVerifyingKeyBytesV1,
    /// Signer B peer-message verifying key bytes.
    pub deriver_b: CloudflareSignerPeerVerifyingKeyBytesV1,
}

impl CloudflareSignerPeerVerifyingKeySetV1 {
    /// Creates a validated public A/B verifying-key set.
    pub fn new(
        deriver_a: CloudflareSignerPeerVerifyingKeyBytesV1,
        deriver_b: CloudflareSignerPeerVerifyingKeyBytesV1,
    ) -> RouterAbProtocolResult<Self> {
        let set = Self {
            deriver_a,
            deriver_b,
        };
        set.validate()?;
        Ok(set)
    }

    /// Validates role ordering and key bytes.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.deriver_a.validate()?;
        self.deriver_b.validate()?;
        if self.deriver_a.role != Role::SignerA || self.deriver_b.role != Role::SignerB {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Cloudflare peer verifying-key set roles must be Signer A and Signer B",
            ));
        }
        Ok(())
    }

    /// Binds configured key bytes to a request signer set.
    pub fn to_protocol_keys(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        self.validate()?;
        signer_set.validate()?;
        Ok(vec![
            self.deriver_a.bind_to_signer(signer_set.signer_a.clone())?,
            self.deriver_b.bind_to_signer(signer_set.signer_b.clone())?,
        ])
    }

    /// Returns lowercase-hex public descriptors for discovery responses.
    pub fn to_hex_descriptor_set(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeyHexSetV1> {
        self.validate()?;
        CloudflareSignerPeerVerifyingKeyHexSetV1::new(
            self.deriver_a.to_hex_descriptor()?,
            self.deriver_b.to_hex_descriptor()?,
        )
    }
}

/// Public HPKE key descriptor for Router A/B discovery responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflarePublicHpkeKeyDescriptorV1 {
    /// Public decrypt-key epoch used for rotation binding.
    pub key_epoch: String,
    /// Canonical `x25519:<64 lowercase hex chars>` public key.
    pub public_key: String,
}

impl CloudflarePublicHpkeKeyDescriptorV1 {
    /// Creates a validated public HPKE key descriptor.
    pub fn new(
        key_epoch: impl Into<String>,
        public_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let descriptor = Self {
            key_epoch: key_epoch.into(),
            public_key: public_key.into(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validates the public key epoch and canonical HPKE key encoding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("key_epoch", &self.key_epoch)?;
        parse_cloudflare_hpke_x25519_public_key_v1(&self.public_key)?;
        Ok(())
    }
}

/// Public Router A/B deployment keyset served by the Router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterPublicKeysetV2 {
    /// Wire format version for this discovery document.
    pub keyset_version: String,
    /// Current and optional previous signer-envelope HPKE keys for A/B envelopes.
    pub signer_envelope_hpke: CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1,
    /// Public A/B peer-message verifying keys.
    pub signer_peer_verifying_keys: CloudflareSignerPeerVerifyingKeyHexSetV1,
    /// Public SigningWorker server-output HPKE key.
    pub signing_worker_server_output_hpke: CloudflarePublicHpkeKeyDescriptorV1,
}

impl CloudflareRouterPublicKeysetV2 {
    /// Creates a validated Router public keyset response.
    pub fn new(
        keyset_version: impl Into<String>,
        signer_envelope_hpke: CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1,
        signer_peer_verifying_keys: CloudflareSignerPeerVerifyingKeyHexSetV1,
        signing_worker_server_output_hpke: CloudflarePublicHpkeKeyDescriptorV1,
    ) -> RouterAbProtocolResult<Self> {
        let keyset = Self {
            keyset_version: keyset_version.into(),
            signer_envelope_hpke,
            signer_peer_verifying_keys,
            signing_worker_server_output_hpke,
        };
        keyset.validate()?;
        Ok(keyset)
    }

    /// Validates all public descriptors in the keyset.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("keyset_version", &self.keyset_version)?;
        self.signer_envelope_hpke.validate()?;
        self.signer_peer_verifying_keys.validate()?;
        self.signing_worker_server_output_hpke.validate()?;
        Ok(())
    }
}

/// Router JWT verifier configuration after Env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterJwtVerifierBindingV1 {
    /// Expected JWT issuer.
    pub issuer: String,
    /// Expected JWT audience.
    pub audience: String,
    /// JWKS URL used by the Worker verifier adapter.
    pub jwks_url: String,
}

impl CloudflareRouterJwtVerifierBindingV1 {
    /// Creates validated JWT verifier configuration.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_url: jwks_url.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates JWT verifier configuration fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("jwt issuer", &self.issuer)?;
        require_non_empty("jwt audience", &self.audience)?;
        require_non_empty("jwt jwks_url", &self.jwks_url)
    }
}

/// Router admission-provider storage bindings after Env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionStoreBindingsV1 {
    /// Router project-policy Durable Object.
    pub project_policy: CloudflareDurableObjectBindingV1,
    /// Router quota Durable Object.
    pub quota: CloudflareDurableObjectBindingV1,
    /// Router abuse-control Durable Object.
    pub abuse: CloudflareDurableObjectBindingV1,
}

impl CloudflareRouterAdmissionStoreBindingsV1 {
    /// Creates validated Router admission store bindings.
    pub fn new(
        project_policy: CloudflareDurableObjectBindingV1,
        quota: CloudflareDurableObjectBindingV1,
        abuse: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            project_policy,
            quota,
            abuse,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates all admission store bindings are Router-visible and correctly scoped.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.project_policy,
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            CloudflareWorkerRoleV1::Router,
        )?;
        require_scope(
            &self.quota,
            CloudflareDurableObjectScopeV1::RouterQuota,
            CloudflareWorkerRoleV1::Router,
        )?;
        require_scope(
            &self.abuse,
            CloudflareDurableObjectScopeV1::RouterAbuse,
            CloudflareWorkerRoleV1::Router,
        )
    }

    /// Builds a Router project-policy Durable Object evaluation call.
    pub fn project_policy_evaluate_call(
        &self,
        request: CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.project_policy.clone(),
            CloudflareDurableObjectRequestV1::router_project_policy_evaluate(request)?,
        )
    }

    /// Builds a Router quota Durable Object evaluation call.
    pub fn quota_evaluate_call(
        &self,
        request: CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.quota.clone(),
            CloudflareDurableObjectRequestV1::router_quota_evaluate(request)?,
        )
    }

    /// Builds a Router abuse Durable Object evaluation call.
    pub fn abuse_evaluate_call(
        &self,
        request: CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.abuse.clone(),
            CloudflareDurableObjectRequestV1::router_abuse_evaluate(request)?,
        )
    }

    /// Builds a Router normal-signing project-policy Durable Object call.
    pub fn normal_signing_project_policy_evaluate_call(
        &self,
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.project_policy.clone(),
            CloudflareDurableObjectRequestV1::router_normal_signing_project_policy_evaluate(
                request,
            )?,
        )
    }

    /// Builds a Router normal-signing quota Durable Object call.
    pub fn normal_signing_quota_evaluate_call(
        &self,
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.quota.clone(),
            CloudflareDurableObjectRequestV1::router_normal_signing_quota_evaluate(request)?,
        )
    }

    /// Builds a Router normal-signing abuse Durable Object call.
    pub fn normal_signing_abuse_evaluate_call(
        &self,
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.abuse.clone(),
            CloudflareDurableObjectRequestV1::router_normal_signing_abuse_evaluate(request)?,
        )
    }
}

/// Router admission-provider configuration after Env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionBindingsV1 {
    /// JWT verifier configuration.
    pub jwt: CloudflareRouterJwtVerifierBindingV1,
    /// Admission-provider storage bindings.
    pub stores: CloudflareRouterAdmissionStoreBindingsV1,
}

impl CloudflareRouterAdmissionBindingsV1 {
    /// Creates validated Router admission-provider bindings.
    pub fn new(
        jwt: CloudflareRouterJwtVerifierBindingV1,
        stores: CloudflareRouterAdmissionStoreBindingsV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self { jwt, stores };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Router admission-provider bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.jwt.validate()?;
        self.stores.validate()
    }
}

/// Router-owned Durable Object calls required to evaluate admission stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionStoreCallsV1 {
    /// Project-policy evaluation call.
    pub project_policy: CloudflareDurableObjectCallV1,
    /// Quota evaluation call.
    pub quota: CloudflareDurableObjectCallV1,
    /// Abuse-control evaluation call.
    pub abuse: CloudflareDurableObjectCallV1,
}

impl CloudflareRouterAdmissionStoreCallsV1 {
    /// Creates validated Router admission-store calls.
    pub fn new(
        project_policy: CloudflareDurableObjectCallV1,
        quota: CloudflareDurableObjectCallV1,
        abuse: CloudflareDurableObjectCallV1,
    ) -> RouterAbProtocolResult<Self> {
        let calls = Self {
            project_policy,
            quota,
            abuse,
        };
        calls.validate()?;
        Ok(calls)
    }

    /// Validates role, scope, and operation shape for all admission-store calls.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        validate_admission_store_call_v1(
            "project_policy",
            &self.project_policy,
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            CloudflareDurableObjectOperationKindV1::RouterProjectPolicyEvaluate,
        )?;
        validate_admission_store_call_v1(
            "quota",
            &self.quota,
            CloudflareDurableObjectScopeV1::RouterQuota,
            CloudflareDurableObjectOperationKindV1::RouterQuotaEvaluate,
        )?;
        validate_admission_store_call_v1(
            "abuse",
            &self.abuse,
            CloudflareDurableObjectScopeV1::RouterAbuse,
            CloudflareDurableObjectOperationKindV1::RouterAbuseEvaluate,
        )
    }
}

/// Router-owned Durable Object calls required to evaluate normal-signing admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningAdmissionStoreCallsV1 {
    /// Project-policy evaluation call.
    pub project_policy: CloudflareDurableObjectCallV1,
    /// Quota evaluation call.
    pub quota: CloudflareDurableObjectCallV1,
    /// Abuse-control evaluation call.
    pub abuse: CloudflareDurableObjectCallV1,
}

impl CloudflareRouterNormalSigningAdmissionStoreCallsV1 {
    /// Creates validated normal-signing admission-store calls.
    pub fn new(
        project_policy: CloudflareDurableObjectCallV1,
        quota: CloudflareDurableObjectCallV1,
        abuse: CloudflareDurableObjectCallV1,
    ) -> RouterAbProtocolResult<Self> {
        let calls = Self {
            project_policy,
            quota,
            abuse,
        };
        calls.validate()?;
        Ok(calls)
    }

    /// Validates role, scope, and operation shape for normal-signing store calls.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        validate_admission_store_call_v1(
            "normal_signing_project_policy",
            &self.project_policy,
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            CloudflareDurableObjectOperationKindV1::RouterNormalSigningProjectPolicyEvaluate,
        )?;
        validate_admission_store_call_v1(
            "normal_signing_quota",
            &self.quota,
            CloudflareDurableObjectScopeV1::RouterQuota,
            CloudflareDurableObjectOperationKindV1::RouterNormalSigningQuotaEvaluate,
        )?;
        validate_admission_store_call_v1(
            "normal_signing_abuse",
            &self.abuse,
            CloudflareDurableObjectScopeV1::RouterAbuse,
            CloudflareDurableObjectOperationKindV1::RouterNormalSigningAbuseEvaluate,
        )
    }
}

/// Router Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterBindingsV1 {
    /// Router replay/idempotency Durable Object.
    pub replay: CloudflareDurableObjectBindingV1,
    /// Router public lifecycle Durable Object.
    pub lifecycle: CloudflareDurableObjectBindingV1,
    /// Router Wallet Session budget Durable Object.
    pub wallet_budget: CloudflareDurableObjectBindingV1,
    /// Router-owned admission-provider bindings.
    pub admission: CloudflareRouterAdmissionBindingsV1,
    /// Signer A peer binding.
    pub deriver_a: CloudflarePeerBindingV1,
    /// Signer B peer binding.
    pub deriver_b: CloudflarePeerBindingV1,
    /// SigningWorker peer binding.
    pub signing_worker: CloudflarePeerBindingV1,
}

impl CloudflareRouterBindingsV1 {
    /// Creates validated Router Worker bindings.
    pub fn new(
        replay: CloudflareDurableObjectBindingV1,
        lifecycle: CloudflareDurableObjectBindingV1,
        wallet_budget: CloudflareDurableObjectBindingV1,
        admission: CloudflareRouterAdmissionBindingsV1,
        deriver_a: CloudflarePeerBindingV1,
        deriver_b: CloudflarePeerBindingV1,
        signing_worker: CloudflarePeerBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            replay,
            lifecycle,
            wallet_budget,
            admission,
            deriver_a,
            deriver_b,
            signing_worker,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Router Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.replay,
            CloudflareDurableObjectScopeV1::RouterReplay,
            CloudflareWorkerRoleV1::Router,
        )?;
        require_scope(
            &self.lifecycle,
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            CloudflareWorkerRoleV1::Router,
        )?;
        require_scope(
            &self.wallet_budget,
            CloudflareDurableObjectScopeV1::RouterWalletBudget,
            CloudflareWorkerRoleV1::Router,
        )?;
        self.admission.validate()?;
        require_peer_role(&self.deriver_a, CloudflareWorkerRoleV1::SignerA)?;
        require_peer_role(&self.deriver_b, CloudflareWorkerRoleV1::SignerB)?;
        require_peer_role(&self.signing_worker, CloudflareWorkerRoleV1::SigningWorker)
    }
}

/// Signer A Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerABindingsV1 {
    /// Signer A sealed root-share Durable Object.
    pub root_share: CloudflareDurableObjectBindingV1,
    /// Signer A signing-root-share wire Secret.
    pub root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
    /// Signer A signer-envelope HPKE decrypt keys.
    pub envelope_decrypt_key: CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    /// Signer A A/B peer-message Ed25519 signing key.
    pub peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
    /// Trusted A/B peer-message Ed25519 verifying keys.
    pub peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
    /// Signer B peer binding.
    pub deriver_b: CloudflarePeerBindingV1,
    /// SigningWorker peer binding used by direct activation delivery.
    pub signing_worker: CloudflarePeerBindingV1,
}

impl CloudflareSignerABindingsV1 {
    /// Creates validated Signer A Worker bindings.
    pub fn new(
        root_share: CloudflareDurableObjectBindingV1,
        root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
        envelope_decrypt_key: impl Into<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1>,
        peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
        peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
        deriver_b: CloudflarePeerBindingV1,
        signing_worker: CloudflarePeerBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            root_share,
            root_share_wire_secret,
            envelope_decrypt_key: envelope_decrypt_key.into(),
            peer_signing_key,
            peer_verifying_keys,
            deriver_b,
            signing_worker,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Signer A Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.root_share,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerA,
            },
            CloudflareWorkerRoleV1::SignerA,
        )?;
        self.root_share_wire_secret
            .validate_visible_to(CloudflareWorkerRoleV1::SignerA)?;
        self.envelope_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerA)?;
        self.peer_signing_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerA)?;
        self.peer_verifying_keys.validate()?;
        require_peer_role(&self.deriver_b, CloudflareWorkerRoleV1::SignerB)?;
        require_peer_role(&self.signing_worker, CloudflareWorkerRoleV1::SigningWorker)
    }
}

/// SigningWorker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerBindingsV1 {
    /// SigningWorker server-output Durable Object.
    pub server_output: CloudflareDurableObjectBindingV1,
    /// SigningWorker server-output HPKE decrypt key.
    pub server_output_decrypt_key: CloudflareServerOutputHpkeDecryptKeyBindingV1,
}

impl CloudflareSigningWorkerBindingsV1 {
    /// Creates validated SigningWorker bindings.
    pub fn new(
        server_output: CloudflareDurableObjectBindingV1,
        server_output_decrypt_key: CloudflareServerOutputHpkeDecryptKeyBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            server_output,
            server_output_decrypt_key,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates SigningWorker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.server_output,
            CloudflareDurableObjectScopeV1::signing_worker_server_output(),
            CloudflareWorkerRoleV1::SigningWorker,
        )?;
        self.server_output_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::SigningWorker)
    }
}

/// Signer B Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerBBindingsV1 {
    /// Signer B sealed root-share Durable Object.
    pub root_share: CloudflareDurableObjectBindingV1,
    /// Signer B signing-root-share wire Secret.
    pub root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
    /// Signer B signer-envelope HPKE decrypt keys.
    pub envelope_decrypt_key: CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    /// Signer B A/B peer-message Ed25519 signing key.
    pub peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
    /// Trusted A/B peer-message Ed25519 verifying keys.
    pub peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
    /// Signer A peer binding.
    pub deriver_a: CloudflarePeerBindingV1,
    /// SigningWorker peer binding used by direct activation delivery.
    pub signing_worker: CloudflarePeerBindingV1,
}

impl CloudflareSignerBBindingsV1 {
    /// Creates validated Signer B Worker bindings.
    pub fn new(
        root_share: CloudflareDurableObjectBindingV1,
        root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
        envelope_decrypt_key: impl Into<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1>,
        peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
        peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
        deriver_a: CloudflarePeerBindingV1,
        signing_worker: CloudflarePeerBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            root_share,
            root_share_wire_secret,
            envelope_decrypt_key: envelope_decrypt_key.into(),
            peer_signing_key,
            peer_verifying_keys,
            deriver_a,
            signing_worker,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Signer B Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.root_share,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerB,
            },
            CloudflareWorkerRoleV1::SignerB,
        )?;
        self.root_share_wire_secret
            .validate_visible_to(CloudflareWorkerRoleV1::SignerB)?;
        self.envelope_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerB)?;
        self.peer_signing_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerB)?;
        self.peer_verifying_keys.validate()?;
        require_peer_role(&self.deriver_a, CloudflareWorkerRoleV1::SignerA)?;
        require_peer_role(&self.signing_worker, CloudflareWorkerRoleV1::SigningWorker)
    }
}

/// Role-specific Cloudflare Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "worker_role", rename_all = "snake_case")]
pub enum CloudflareWorkerBindingsV1 {
    /// Router Worker bindings.
    Router {
        /// Router bindings.
        bindings: CloudflareRouterBindingsV1,
    },
    /// Signer A Worker bindings.
    SignerA {
        /// Signer A bindings.
        bindings: CloudflareSignerABindingsV1,
    },
    /// Signer B Worker bindings.
    SignerB {
        /// Signer B bindings.
        bindings: CloudflareSignerBBindingsV1,
    },
    /// SigningWorker bindings.
    SigningWorker {
        /// SigningWorker bindings.
        bindings: CloudflareSigningWorkerBindingsV1,
    },
}

impl CloudflareWorkerBindingsV1 {
    /// Creates a Router Worker startup branch.
    pub fn router(bindings: CloudflareRouterBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::Router { bindings })
    }

    /// Creates a Signer A Worker startup branch.
    pub fn deriver_a(bindings: CloudflareSignerABindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::SignerA { bindings })
    }

    /// Creates a Signer B Worker startup branch.
    pub fn deriver_b(bindings: CloudflareSignerBBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::SignerB { bindings })
    }

    /// Creates a SigningWorker startup branch.
    pub fn signing_worker(
        bindings: CloudflareSigningWorkerBindingsV1,
    ) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::SigningWorker { bindings })
    }

    /// Returns the Worker role.
    pub fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        match self {
            Self::Router { .. } => CloudflareWorkerRoleV1::Router,
            Self::SignerA { .. } => CloudflareWorkerRoleV1::SignerA,
            Self::SignerB { .. } => CloudflareWorkerRoleV1::SignerB,
            Self::SigningWorker { .. } => CloudflareWorkerRoleV1::SigningWorker,
        }
    }
}

/// Thin Router Worker runtime context after Cloudflare startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWorkerRuntimeV1 {
    bindings: CloudflareRouterBindingsV1,
}

/// Thin Deriver A Worker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeriverAWorkerRuntimeV1 {
    bindings: CloudflareSignerABindingsV1,
}

/// Thin Deriver B Worker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeriverBWorkerRuntimeV1 {
    bindings: CloudflareSignerBBindingsV1,
}

/// Thin SigningWorker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRuntimeV1 {
    bindings: CloudflareSigningWorkerBindingsV1,
}

/// Input for loading a synchronous signer host from async Cloudflare resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerHostPreloadInputV1 {
    /// Signer set id whose local root-share metadata must be loaded.
    pub signer_set_id: String,
    /// Root-share epoch to load for the local signer role.
    pub root_share_epoch: RootShareEpoch,
    /// Peer responses already fetched by an adapter-specific A/B coordinator.
    pub peer_responses: Vec<WireMessageV1>,
    /// Trusted signer verifying keys used for A/B peer authentication.
    pub signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
    /// Number of random bytes to preload before entering synchronous core code.
    pub random_bytes_len: usize,
}

impl CloudflareSignerHostPreloadInputV1 {
    /// Creates a validated signer-host preload request.
    pub fn new(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<Self> {
        let input = Self {
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            peer_responses,
            signer_verifying_keys,
            random_bytes_len,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validates preload identity, peer response shape, and random-buffer budget.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        if self.random_bytes_len > CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "signer host random preload length exceeds maximum",
            ));
        }
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for response in &self.peer_responses {
            require_preloaded_peer_response_v1(response)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, response)?;
        }
        Ok(())
    }
}

/// Input for loading a signer host after fetching direct A/B peer responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerHostPeerPreloadInputV1 {
    /// Signer set id whose local root-share metadata must be loaded.
    pub signer_set_id: String,
    /// Root-share epoch to load for the local signer role.
    pub root_share_epoch: RootShareEpoch,
    /// Direct A/B peer requests to execute before entering synchronous core code.
    pub peer_requests: Vec<WireMessageV1>,
    /// Trusted signer verifying keys used for A/B peer authentication.
    pub signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
    /// Number of random bytes to preload before entering synchronous core code.
    pub random_bytes_len: usize,
}

impl CloudflareSignerHostPeerPreloadInputV1 {
    /// Creates a validated signer-host peer preload request.
    pub fn new(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        peer_requests: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<Self> {
        let input = Self {
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            peer_requests,
            signer_verifying_keys,
            random_bytes_len,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validates preload identity, peer request shape, and random-buffer budget.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        if self.random_bytes_len > CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "signer host peer random preload length exceeds maximum",
            ));
        }
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for request in &self.peer_requests {
            require_preloaded_peer_request_v1(request)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, request)?;
        }
        Ok(())
    }
}

/// Role-local root-share wire loaded before synchronous signer execution.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudflarePreloadedRootShareWireV1 {
    /// Signer role that owns the root-share wire.
    pub signer_role: Role,
    /// Root-share epoch for this wire.
    pub root_share_epoch: RootShareEpoch,
    signing_root_share_wire: MpcPrfSigningRootShareWireV1,
}

impl core::fmt::Debug for CloudflarePreloadedRootShareWireV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflarePreloadedRootShareWireV1")
            .field("signer_role", &self.signer_role)
            .field("root_share_epoch", &self.root_share_epoch)
            .field("signing_root_share_wire", &"[redacted]")
            .finish()
    }
}

impl CloudflarePreloadedRootShareWireV1 {
    /// Creates a validated preloaded root-share wire record.
    pub fn new(
        signer_role: Role,
        root_share_epoch: RootShareEpoch,
        signing_root_share_wire: MpcPrfSigningRootShareWireV1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            signer_role,
            root_share_epoch,
            signing_root_share_wire,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the public root-share wire binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.signer_role)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())
    }

    /// Returns a clone of the redacted signer-local root-share wire.
    pub fn signing_root_share_wire(&self) -> MpcPrfSigningRootShareWireV1 {
        self.signing_root_share_wire.clone()
    }
}

/// Decodes a role-local root-share wire secret into a redacted preloaded record.
pub fn decode_cloudflare_root_share_wire_secret_v1(
    metadata: &CloudflareRootShareStartupMetadataV1,
    encoded_secret: &str,
) -> RouterAbProtocolResult<CloudflarePreloadedRootShareWireV1> {
    metadata.validate()?;
    let encoded_secret = encoded_secret.trim();
    let hex_value = encoded_secret
        .strip_prefix(CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare root-share wire secret has an unsupported encoding prefix",
            )
        })?;
    let wire_bytes = decode_cloudflare_root_share_wire_hex_v1(hex_value)?;
    let signing_root_share_wire =
        MpcPrfSigningRootShareWireV1::new(wire_bytes).map_err(map_root_share_to_protocol)?;
    CloudflarePreloadedRootShareWireV1::new(
        metadata.signer_role,
        metadata.root_share_epoch.clone(),
        signing_root_share_wire,
    )
}

/// Validates binding visibility and decodes a role-local root-share wire Secret value.
pub fn decode_and_validate_cloudflare_root_share_wire_secret_v1(
    worker_role: CloudflareWorkerRoleV1,
    binding: &CloudflareRootShareWireSecretBindingV1,
    metadata: &CloudflareRootShareStartupMetadataV1,
    encoded_secret: &str,
) -> RouterAbProtocolResult<CloudflarePreloadedRootShareWireV1> {
    binding.validate_visible_to(worker_role)?;
    metadata.validate()?;
    if binding.role != metadata.signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Cloudflare root-share wire secret binding role does not match startup metadata",
        ));
    }
    decode_cloudflare_root_share_wire_secret_v1(metadata, encoded_secret)
}

fn decode_cloudflare_root_share_wire_hex_v1(hex_value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    let expected_len = MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN * 2;
    if hex_value.len() != expected_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare root-share wire secret hex must be {expected_len} characters"),
        ));
    }
    let mut out = Vec::with_capacity(MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN);
    for chunk in hex_value.as_bytes().chunks_exact(2) {
        out.push(
            (decode_cloudflare_root_share_hex_nibble_v1(chunk[0])? << 4)
                | decode_cloudflare_root_share_hex_nibble_v1(chunk[1])?,
        );
    }
    Ok(out)
}

fn decode_cloudflare_root_share_hex_nibble_v1(byte: u8) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare root-share wire secret must use lowercase hex",
        )),
    }
}

/// Decodes a lowercase-hex Ed25519 peer verifying key.
pub fn decode_cloudflare_peer_verifying_key_hex_v1(
    hex_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let hex_value = hex_value.trim();
    let expected_len = 64;
    if hex_value.len() != expected_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare peer verifying key hex must be 64 characters",
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (decode_cloudflare_peer_verifying_key_hex_nibble_v1(chunk[0])? << 4)
            | decode_cloudflare_peer_verifying_key_hex_nibble_v1(chunk[1])?;
    }
    Ok(out)
}

fn decode_cloudflare_peer_verifying_key_hex_nibble_v1(byte: u8) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare peer verifying key hex must use lowercase hex",
        )),
    }
}

/// Synchronous signer host built from async Cloudflare adapter preload results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflarePreloadedSignerHostV1 {
    /// Worker-local time captured by the adapter.
    pub now_unix_ms: u64,
    /// Role-local root-share startup metadata loaded before engine execution.
    pub root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
    /// Role-local root-share wires loaded before synchronous engine execution.
    #[serde(skip)]
    pub root_share_wires: Vec<CloudflarePreloadedRootShareWireV1>,
    /// Preloaded peer responses available to synchronous engine code.
    pub peer_responses: Vec<WireMessageV1>,
    /// Trusted signer verifying keys available to synchronous engine code.
    pub signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
    /// Random bytes supplied by the adapter before engine execution.
    pub random_bytes: Vec<u8>,
}

impl CloudflarePreloadedSignerHostV1 {
    /// Creates a validated preloaded signer host.
    pub fn new(
        now_unix_ms: u64,
        root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        Self::new_with_root_share_wires(
            now_unix_ms,
            root_share_metadata,
            Vec::new(),
            peer_responses,
            signer_verifying_keys,
            random_bytes,
        )
    }

    /// Creates a validated preloaded signer host with role-local root-share wires.
    pub fn new_with_root_share_wires(
        now_unix_ms: u64,
        root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
        root_share_wires: Vec<CloudflarePreloadedRootShareWireV1>,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let host = Self {
            now_unix_ms,
            root_share_metadata,
            root_share_wires,
            peer_responses,
            signer_verifying_keys,
            random_bytes,
        };
        host.validate()?;
        Ok(host)
    }

    /// Validates preloaded host material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.now_unix_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "preloaded signer host now_unix_ms must be greater than zero",
            ));
        }
        for metadata in &self.root_share_metadata {
            metadata.validate()?;
            require_signer_role(metadata.signer_role)?;
        }
        for wire in &self.root_share_wires {
            wire.validate()?;
            if !self.root_share_metadata.iter().any(|metadata| {
                metadata.signer_role == wire.signer_role
                    && metadata.root_share_epoch == wire.root_share_epoch
            }) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "preloaded root-share wire is missing matching startup metadata",
                ));
            }
        }
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for response in &self.peer_responses {
            require_preloaded_peer_response_v1(response)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, response)?;
        }
        Ok(())
    }

    /// Returns the preloaded role-local signing-root share wire.
    pub fn signing_root_share_wire(
        &self,
        role: Role,
        epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<MpcPrfSigningRootShareWireV1> {
        require_signer_role(role)?;
        require_non_empty("root_share_epoch", epoch.as_str())?;
        self.root_share_wires
            .iter()
            .find(|wire| wire.signer_role == role && &wire.root_share_epoch == epoch)
            .map(CloudflarePreloadedRootShareWireV1::signing_root_share_wire)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} root-share wire",
                        role.as_str()
                    ),
                )
            })
    }

    /// Returns preloaded role-local root-share startup metadata.
    pub fn root_share_startup_metadata(
        &self,
        role: Role,
        epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<&CloudflareRootShareStartupMetadataV1> {
        require_signer_role(role)?;
        require_non_empty("root_share_epoch", epoch.as_str())?;
        self.root_share_metadata
            .iter()
            .find(|metadata| metadata.signer_role == role && &metadata.root_share_epoch == epoch)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} root-share metadata",
                        role.as_str()
                    ),
                )
            })
    }
}

/// Builds a synchronous signer host from already loaded Cloudflare resources.
pub fn build_cloudflare_preloaded_signer_host_v1(
    now_unix_ms: u64,
    expected_role: Role,
    input: CloudflareSignerHostPreloadInputV1,
    root_share_metadata: CloudflareRootShareStartupMetadataV1,
    random_bytes: Vec<u8>,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    require_signer_role(expected_role)?;
    input.validate()?;
    root_share_metadata.validate()?;
    if root_share_metadata.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "preloaded root-share metadata role does not match signer host role",
        ));
    }
    if root_share_metadata.signer_set_id != input.signer_set_id
        || root_share_metadata.root_share_epoch != input.root_share_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded root-share metadata does not match signer host preload input",
        ));
    }
    if random_bytes.len() != input.random_bytes_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded random byte length does not match signer host preload input",
        ));
    }
    CloudflarePreloadedSignerHostV1::new(
        now_unix_ms,
        vec![root_share_metadata],
        input.peer_responses,
        input.signer_verifying_keys,
        random_bytes,
    )
}

/// Builds a synchronous signer host with already unsealed role-local root-share wire.
pub fn build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
    now_unix_ms: u64,
    expected_role: Role,
    input: CloudflareSignerHostPreloadInputV1,
    root_share_metadata: CloudflareRootShareStartupMetadataV1,
    signing_root_share_wire: MpcPrfSigningRootShareWireV1,
    random_bytes: Vec<u8>,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    require_signer_role(expected_role)?;
    input.validate()?;
    root_share_metadata.validate()?;
    let root_share_wire = CloudflarePreloadedRootShareWireV1::new(
        expected_role,
        input.root_share_epoch.clone(),
        signing_root_share_wire,
    )?;
    if root_share_metadata.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "preloaded root-share metadata role does not match signer host role",
        ));
    }
    if root_share_metadata.signer_set_id != input.signer_set_id
        || root_share_metadata.root_share_epoch != input.root_share_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded root-share metadata does not match signer host preload input",
        ));
    }
    if random_bytes.len() != input.random_bytes_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded random byte length does not match signer host preload input",
        ));
    }
    CloudflarePreloadedSignerHostV1::new_with_root_share_wires(
        now_unix_ms,
        vec![root_share_metadata],
        vec![root_share_wire],
        input.peer_responses,
        input.signer_verifying_keys,
        random_bytes,
    )
}

impl Clock for CloudflarePreloadedSignerHostV1 {
    fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms
    }
}

impl Csprng for CloudflarePreloadedSignerHostV1 {
    fn fill_random(&mut self, out: &mut [u8]) -> RouterAbProtocolResult<()> {
        if self.random_bytes.len() < out.len() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "preloaded signer host random buffer is exhausted",
            ));
        }
        out.copy_from_slice(&self.random_bytes[..out.len()]);
        self.random_bytes.drain(..out.len());
        Ok(())
    }
}

impl SignerKeyStore for CloudflarePreloadedSignerHostV1 {
    fn signer_identity(&self, role: Role) -> RouterAbProtocolResult<String> {
        require_signer_role(role)?;
        self.root_share_metadata
            .iter()
            .find(|metadata| metadata.signer_role == role)
            .map(|metadata| metadata.signer_id.clone())
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} identity",
                        role.as_str()
                    ),
                )
            })
    }

    fn signer_verifying_key(
        &self,
        signer: &SignerIdentityV1,
    ) -> RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        require_signer_role(signer.role)?;
        self.signer_verifying_keys
            .iter()
            .find(|key| &key.signer == signer)
            .cloned()
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} verifying key",
                        signer.role.as_str()
                    ),
                )
            })
    }
}

impl SigningRootShareStore for CloudflarePreloadedSignerHostV1 {
    fn has_root_share(&self, role: Role, epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool> {
        require_signer_role(role)?;
        require_non_empty("root_share_epoch", epoch.as_str())?;
        Ok(self
            .root_share_metadata
            .iter()
            .any(|metadata| metadata.signer_role == role && &metadata.root_share_epoch == epoch))
    }
}

impl PeerTransport for CloudflarePreloadedSignerHostV1 {
    fn send_peer_message(&self, message: WireMessageV1) -> RouterAbProtocolResult<WireMessageV1> {
        self.peer_responses
            .iter()
            .find(|response| response.transcript_digest == message.transcript_digest)
            .cloned()
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "preloaded signer host is missing a peer response for the transcript",
                )
            })
    }
}

impl AuditSink for CloudflarePreloadedSignerHostV1 {
    fn record_audit_event(&self, _event: AuditEventV1) -> RouterAbProtocolResult<()> {
        Ok(())
    }
}

/// Auth context already verified by the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "auth", rename_all = "snake_case")]
pub enum CloudflareRouterAuthContextV1 {
    /// Fully authenticated user/session.
    AuthenticatedSession {
        /// Canonical subject id from verified auth.
        subject_id: String,
        /// Canonical session id from verified auth.
        session_id: String,
    },
    /// Pre-auth session allowed only for registration prepare.
    PreAuthSession {
        /// Router-derived pre-auth session id.
        pre_auth_session_id: String,
    },
}

impl CloudflareRouterAuthContextV1 {
    /// Creates a validated authenticated-session context.
    pub fn authenticated_session(
        subject_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::AuthenticatedSession {
            subject_id: subject_id.into(),
            session_id: session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Creates a validated pre-auth session context.
    pub fn pre_auth_session(
        pre_auth_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::PreAuthSession {
            pre_auth_session_id: pre_auth_session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates auth branch identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => {
                require_non_empty("subject_id", subject_id)?;
                require_non_empty("session_id", session_id)
            }
            Self::PreAuthSession {
                pre_auth_session_id,
            } => require_non_empty("pre_auth_session_id", pre_auth_session_id),
        }
    }

    /// Converts trusted Router auth context into a core gate principal.
    pub fn to_gate_principal(&self) -> RouterAbProtocolResult<GatePrincipalV1> {
        self.validate()?;
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => GatePrincipalV1::authenticated_session(subject_id.clone(), session_id.clone()),
            Self::PreAuthSession {
                pre_auth_session_id,
            } => GatePrincipalV1::pre_auth_session(pre_auth_session_id.clone()),
        }
    }

    fn session_id(&self) -> &str {
        match self {
            Self::AuthenticatedSession { session_id, .. } => session_id,
            Self::PreAuthSession {
                pre_auth_session_id,
            } => pre_auth_session_id,
        }
    }
}

/// Router-owned request metadata used to derive gate context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterTrustedRequestMetadataV1 {
    /// Protected work class from verified Router routing.
    pub work_kind: ExpensiveWorkKindV1,
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Router-owned auth context.
    pub auth: CloudflareRouterAuthContextV1,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterTrustedRequestMetadataV1 {
    /// Creates validated trusted request metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        work_kind: ExpensiveWorkKindV1,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        auth: CloudflareRouterAuthContextV1,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            work_kind,
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            auth,
            trusted_source_digest,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates trusted request metadata fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)?;
        self.auth.validate()
    }

    /// Validates trusted metadata matches the normalized public request.
    pub fn validate_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata work kind does not match public request lifecycle",
            ));
        }
        if self.account_id != request.lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata account id does not match public request lifecycle",
            ));
        }
        if self.auth.session_id() != request.lifecycle.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata session id does not match public request lifecycle",
            ));
        }
        if matches!(
            self.auth,
            CloudflareRouterAuthContextV1::PreAuthSession { .. }
        ) && self.work_kind != ExpensiveWorkKindV1::RegistrationPrepare
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "pre-auth Router metadata is allowed only for registration prepare",
            ));
        }
        Ok(())
    }

    /// Builds the core gate context from trusted Router metadata.
    pub fn to_gate_context(&self) -> RouterAbProtocolResult<ExpensiveWorkGateContextV1> {
        self.validate()?;
        ExpensiveWorkGateContextV1::new(
            self.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.auth.to_gate_principal()?,
            self.trusted_source_digest,
        )
    }
}

/// Router-owned metadata for normal-signing admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningTrustedMetadataV1 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Router-owned authenticated-session context.
    pub auth: CloudflareRouterAuthContextV1,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Digest of the canonical user intent authorized by policy.
    pub intent_digest: PublicDigest32,
}

impl CloudflareRouterNormalSigningTrustedMetadataV1 {
    /// Creates validated normal-signing metadata.
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        auth: CloudflareRouterAuthContextV1,
        trusted_source_digest: PublicDigest32,
        intent_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            auth,
            trusted_source_digest,
            intent_digest,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates trusted normal-signing metadata fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal signing org_id", &self.org_id)?;
        require_non_empty("normal signing project_id", &self.project_id)?;
        require_non_empty("normal signing environment", &self.environment)?;
        require_non_empty("normal signing account_id", &self.account_id)?;
        self.auth.validate()?;
        if matches!(
            self.auth,
            CloudflareRouterAuthContextV1::PreAuthSession { .. }
        ) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal signing requires authenticated Router metadata",
            ));
        }
        Ok(())
    }

    /// Validates metadata matches a typed v2 normal-signing finalize request.
    pub fn validate_for_finalize_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted normal-signing account id does not match v2 finalize scope",
            ));
        }
        if self.auth.session_id() != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted normal-signing session id does not match v2 finalize scope",
            ));
        }
        if self.intent_digest != request.intent_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted normal-signing intent digest does not match v2 finalize intent",
            ));
        }
        Ok(())
    }
}

/// Project policy outcome produced by Router-owned policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum CloudflareRouterProjectPolicyV1 {
    /// Project policy allows this work kind.
    Allowed,
    /// Project policy rejects this work kind before signer capacity is used.
    Rejected {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl CloudflareRouterProjectPolicyV1 {
    /// Validates project policy branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::Rejected { retry_after_ms } => {
                require_positive_ms("project policy retry_after_ms", *retry_after_ms)
            }
        }
    }
}

/// Abuse-control outcome produced by Router-owned abuse checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "abuse", rename_all = "snake_case")]
pub enum CloudflareRouterAbuseCheckV1 {
    /// Abuse checks allow the request.
    Allowed,
    /// Request is rate-limited before signer capacity is used.
    RateLimited {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
    /// Abuse policy rejects the request before signer capacity is used.
    Rejected {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl CloudflareRouterAbuseCheckV1 {
    /// Validates abuse-check branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::RateLimited { retry_after_ms } => {
                require_positive_ms("abuse rate-limit retry_after_ms", *retry_after_ms)
            }
            Self::Rejected { retry_after_ms } => {
                require_positive_ms("abuse rejection retry_after_ms", *retry_after_ms)
            }
        }
    }
}

/// Quota and queue outcome produced by Router-owned gate checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "quota", rename_all = "snake_case")]
pub enum CloudflareRouterQuotaCheckV1 {
    /// New expensive work is allowed.
    Accepted {
        /// Router-assigned request id.
        request_id: String,
    },
    /// Existing active lifecycle should be reused.
    ReuseExisting {
        /// Router-assigned request id.
        request_id: String,
        /// Existing lifecycle id.
        existing_lifecycle_id: String,
    },
    /// Short-window quota is saturated.
    ShortWindowSaturated,
    /// Signer queue is saturated.
    SignerQueueSaturated,
}

impl CloudflareRouterQuotaCheckV1 {
    /// Validates quota branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Accepted { request_id } => require_non_empty("request_id", request_id),
            Self::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => {
                require_non_empty("request_id", request_id)?;
                require_non_empty("existing_lifecycle_id", existing_lifecycle_id)
            }
            Self::ShortWindowSaturated | Self::SignerQueueSaturated => Ok(()),
        }
    }
}

/// Trusted Router admission check results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionChecksV1 {
    /// Project policy result.
    pub project_policy: CloudflareRouterProjectPolicyV1,
    /// Abuse-control result.
    pub abuse: CloudflareRouterAbuseCheckV1,
    /// Quota/queue result.
    pub quota: CloudflareRouterQuotaCheckV1,
}

impl CloudflareRouterAdmissionChecksV1 {
    /// Creates validated admission checks.
    pub fn new(
        project_policy: CloudflareRouterProjectPolicyV1,
        abuse: CloudflareRouterAbuseCheckV1,
        quota: CloudflareRouterQuotaCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let checks = Self {
            project_policy,
            abuse,
            quota,
        };
        checks.validate()?;
        Ok(checks)
    }

    /// Validates all trusted check results.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.project_policy.validate()?;
        self.abuse.validate()?;
        self.quota.validate()
    }

    /// Converts check results into the core expensive-work gate decision.
    pub fn to_gate_decision(&self) -> RouterAbProtocolResult<ExpensiveWorkGateDecisionV1> {
        self.validate()?;
        match &self.project_policy {
            CloudflareRouterProjectPolicyV1::Rejected { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    *retry_after_ms,
                );
            }
            CloudflareRouterProjectPolicyV1::Allowed => {}
        }
        match &self.abuse {
            CloudflareRouterAbuseCheckV1::RateLimited { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::RateLimited,
                    *retry_after_ms,
                );
            }
            CloudflareRouterAbuseCheckV1::Rejected { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    *retry_after_ms,
                );
            }
            CloudflareRouterAbuseCheckV1::Allowed => {}
        }
        match &self.quota {
            CloudflareRouterQuotaCheckV1::Accepted { request_id } => {
                ExpensiveWorkGateDecisionV1::accepted(request_id.clone())
            }
            CloudflareRouterQuotaCheckV1::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => ExpensiveWorkGateDecisionV1::reuse_existing(
                request_id.clone(),
                existing_lifecycle_id.clone(),
            ),
            CloudflareRouterQuotaCheckV1::ShortWindowSaturated => Ok(
                ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::ShortWindowSaturated),
            ),
            CloudflareRouterQuotaCheckV1::SignerQueueSaturated => Ok(
                ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::SignerQueueSaturated),
            ),
        }
    }
}

/// Typed output from Router-owned auth, policy, abuse, and quota providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionProviderOutputV1 {
    /// Trusted request metadata derived from auth/session context.
    pub metadata: CloudflareRouterTrustedRequestMetadataV1,
    /// Trusted policy, abuse, and quota results.
    pub checks: CloudflareRouterAdmissionChecksV1,
}

impl CloudflareRouterAdmissionProviderOutputV1 {
    /// Creates validated admission-provider output.
    pub fn new(
        metadata: CloudflareRouterTrustedRequestMetadataV1,
        checks: CloudflareRouterAdmissionChecksV1,
    ) -> RouterAbProtocolResult<Self> {
        let output = Self { metadata, checks };
        output.validate()?;
        Ok(output)
    }

    /// Validates provider output independent of a public request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        self.checks.validate()
    }

    /// Validates provider output against the normalized public request.
    pub fn validate_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.metadata.validate_for_request(request)?;
        self.checks.validate()
    }
}

/// Router-owned boundary for auth, session, policy, abuse, and quota checks.
pub trait CloudflareRouterAdmissionProviderV1 {
    /// Evaluates all server-owned admission checks for a normalized public request.
    fn evaluate_public_request_admission(
        &mut self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1>;
}

/// Already verified JWT/session claims at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterVerifiedJwtClaimsV1 {
    /// Canonical subject id from verified auth.
    pub subject_id: String,
    /// Canonical session id from verified auth.
    pub session_id: String,
    /// Canonical organization id authorized by the session.
    pub org_id: String,
    /// Canonical project id authorized by the session.
    pub project_id: String,
    /// Deployment environment label authorized by the session.
    pub environment: String,
    /// Account, wallet, or root resource id authorized by the session.
    pub account_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterVerifiedJwtClaimsV1 {
    /// Creates validated claims from an already verified JWT/session boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        session_id: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let claims = Self {
            subject_id: subject_id.into(),
            session_id: session_id.into(),
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            trusted_source_digest,
        };
        claims.validate()?;
        Ok(claims)
    }

    /// Validates branch identity and policy-scope fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)
    }

    /// Converts verified claims into trusted Router metadata for this request.
    pub fn to_trusted_metadata(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.validate()?;
        request.validate()?;
        CloudflareRouterTrustedRequestMetadataV1::new(
            request.lifecycle.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session(
                self.subject_id.clone(),
                self.session_id.clone(),
            )?,
            self.trusted_source_digest,
        )
    }
}

/// Wallet Session credential accepted at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareRouterWalletSessionCredentialV1 {
    /// Bearer token supplied by the public normal-signing caller.
    Bearer {
        /// Parsed bearer authorization.
        authorization: CloudflareRouterBearerAuthorizationV1,
    },
}

impl CloudflareRouterWalletSessionCredentialV1 {
    /// Creates a bearer Wallet Session credential.
    pub fn bearer(
        authorization: CloudflareRouterBearerAuthorizationV1,
    ) -> RouterAbProtocolResult<Self> {
        let credential = Self::Bearer { authorization };
        credential.validate()?;
        Ok(credential)
    }

    /// Parses an HTTP Authorization header into a bearer Wallet Session credential.
    pub fn from_bearer_authorization_header(header: &str) -> RouterAbProtocolResult<Self> {
        Self::bearer(CloudflareRouterBearerAuthorizationV1::from_authorization_header(header)?)
    }

    /// Validates credential branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Bearer { authorization } => authorization.validate(),
        }
    }
}

/// Already verified Wallet Session at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterVerifiedWalletSessionV1 {
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Account, wallet, or root resource id authorized by the session.
    pub account_id: String,
    /// Threshold/MPC session id authorized by the Wallet Session.
    pub threshold_session_id: String,
    /// Server-authoritative Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Canonical organization id authorized by the session.
    pub org_id: String,
    /// Canonical project id authorized by the session.
    pub project_id: String,
    /// Deployment environment label authorized by the session.
    pub environment: String,
    /// Wallet authorization level selected by Router policy.
    pub authorization_level: String,
    /// Active SigningWorker id authorized for this session.
    pub signing_worker_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Session expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterVerifiedWalletSessionV1 {
    /// Creates a validated Wallet Session boundary object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        account_id: impl Into<String>,
        threshold_session_id: impl Into<String>,
        signing_grant_id: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        authorization_level: impl Into<String>,
        signing_worker_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let session = Self {
            subject_id: subject_id.into(),
            account_id: account_id.into(),
            threshold_session_id: threshold_session_id.into(),
            signing_grant_id: signing_grant_id.into(),
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            authorization_level: authorization_level.into(),
            signing_worker_id: signing_worker_id.into(),
            trusted_source_digest,
            expires_at_ms,
        };
        session.validate()?;
        Ok(session)
    }

    /// Validates required Wallet Session fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet session subject_id", &self.subject_id)?;
        require_non_empty("wallet session account_id", &self.account_id)?;
        require_non_empty(
            "wallet session threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty("wallet session signing_grant_id", &self.signing_grant_id)?;
        require_non_empty("wallet session org_id", &self.org_id)?;
        require_non_empty("wallet session project_id", &self.project_id)?;
        require_non_empty("wallet session environment", &self.environment)?;
        require_non_empty(
            "wallet session authorization_level",
            &self.authorization_level,
        )?;
        require_non_empty("wallet session signing_worker_id", &self.signing_worker_id)?;
        require_positive_ms("wallet session expires_at_ms", self.expires_at_ms)
    }

    /// Validates the Wallet Session against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_ms("wallet session now_unix_ms", now_unix_ms)?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Wallet Session expired",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a typed normal-signing prepare request.
    pub fn validate_for_normal_signing_prepare_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before normal-signing request",
            ));
        }
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match normal-signing scope",
            ));
        }
        if self.threshold_session_id != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session session_id does not match normal-signing scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match normal-signing scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a typed Ed25519 presign-pool refill request.
    pub fn validate_for_normal_signing_presign_pool_prepare_request_v2(
        &self,
        request: &RouterAbEd25519PresignPoolPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before normal-signing presign-pool refill request",
            ));
        }
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match presign-pool refill scope",
            ));
        }
        if self.threshold_session_id != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session session_id does not match presign-pool refill scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match presign-pool refill scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a typed normal-signing finalize request.
    pub fn validate_for_normal_signing_finalize_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before normal-signing finalize request",
            ));
        }
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match normal-signing finalize scope",
            ));
        }
        if self.threshold_session_id != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session session_id does not match normal-signing finalize scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match normal-signing finalize scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a typed Ed25519 pool-hit finalize request.
    pub fn validate_for_normal_signing_presign_pool_hit_finalize_request_v2(
        &self,
        request: &RouterAbEd25519PresignPoolHitFinalizeRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before normal-signing pool-hit finalize request",
            ));
        }
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match pool-hit finalize scope",
            ));
        }
        if self.threshold_session_id != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session session_id does not match pool-hit finalize scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match pool-hit finalize scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes an ECDSA-HSS digest-signing prepare request.
    pub fn validate_for_ecdsa_hss_evm_digest_signing_request_v1(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before ECDSA-HSS signing request",
            ));
        }
        if self.account_id != request.scope.context.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match ECDSA-HSS signing scope",
            ));
        }
        if self.threshold_session_id
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session session_id does not match ECDSA-HSS signing scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match ECDSA-HSS signing scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes an ECDSA-HSS finalize request.
    pub fn validate_for_ecdsa_hss_evm_digest_finalize_request_v1(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before ECDSA-HSS finalize request",
            ));
        }
        if self.account_id != request.scope.context.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match ECDSA-HSS finalize scope",
            ));
        }
        if self.threshold_session_id
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session session_id does not match ECDSA-HSS finalize scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match ECDSA-HSS finalize scope",
            ));
        }
        Ok(())
    }

    /// Converts a verified Wallet Session and typed request into a prepare admission candidate.
    pub fn to_normal_signing_prepare_admission_candidate_v2(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningPrepareAdmissionCandidateV2> {
        CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
            self,
            request,
            now_unix_ms,
        )
    }
}

/// Wallet Session verifier boundary used by normal-signing v2 admission.
pub trait CloudflareRouterWalletSessionVerifierV1 {
    /// Verifies a Wallet Session credential and returns normalized session data.
    fn verify_wallet_session(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        credential: &CloudflareRouterWalletSessionCredentialV1,
        trusted_source_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedWalletSessionV1>;
}

/// Already verified pre-auth session at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterVerifiedPreAuthSessionV1 {
    /// Router-derived pre-auth session id.
    pub pre_auth_session_id: String,
    /// Canonical organization id assigned by Router policy.
    pub org_id: String,
    /// Canonical project id assigned by Router policy.
    pub project_id: String,
    /// Deployment environment label assigned by Router policy.
    pub environment: String,
    /// Account, wallet, or root resource id assigned by Router policy.
    pub account_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterVerifiedPreAuthSessionV1 {
    /// Creates a validated pre-auth session boundary.
    pub fn new(
        pre_auth_session_id: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let session = Self {
            pre_auth_session_id: pre_auth_session_id.into(),
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            trusted_source_digest,
        };
        session.validate()?;
        Ok(session)
    }

    /// Validates pre-auth identity and policy-scope fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("pre_auth_session_id", &self.pre_auth_session_id)?;
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)
    }

    /// Converts verified pre-auth session data into trusted Router metadata.
    pub fn to_trusted_metadata(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.validate()?;
        request.validate()?;
        CloudflareRouterTrustedRequestMetadataV1::new(
            request.lifecycle.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::pre_auth_session(self.pre_auth_session_id.clone())?,
            self.trusted_source_digest,
        )
    }
}

/// Verified session variants accepted by the Router admission chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareRouterVerifiedSessionV1 {
    /// Claims from a verified JWT/auth session.
    Jwt {
        /// Verified JWT/session claims.
        claims: CloudflareRouterVerifiedJwtClaimsV1,
    },
    /// Router-verified pre-auth session for registration prepare.
    PreAuth {
        /// Verified pre-auth session data.
        session: CloudflareRouterVerifiedPreAuthSessionV1,
    },
}

impl CloudflareRouterVerifiedSessionV1 {
    /// Creates a verified JWT session variant.
    pub fn jwt(claims: CloudflareRouterVerifiedJwtClaimsV1) -> RouterAbProtocolResult<Self> {
        let session = Self::Jwt { claims };
        session.validate()?;
        Ok(session)
    }

    /// Creates a verified pre-auth session variant.
    pub fn pre_auth(
        session: CloudflareRouterVerifiedPreAuthSessionV1,
    ) -> RouterAbProtocolResult<Self> {
        let verified = Self::PreAuth { session };
        verified.validate()?;
        Ok(verified)
    }

    /// Validates the verified session branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Jwt { claims } => claims.validate(),
            Self::PreAuth { session } => session.validate(),
        }
    }

    /// Converts the verified session branch into trusted Router metadata.
    pub fn to_trusted_metadata(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.validate()?;
        match self {
            Self::Jwt { claims } => claims.to_trusted_metadata(request),
            Self::PreAuth { session } => session.to_trusted_metadata(request),
        }
    }
}

/// Router auth/session provider used by the admission chain.
pub trait CloudflareRouterSessionProviderV1 {
    /// Verifies auth/session state and derives trusted Router metadata.
    fn verify_public_request_session(
        &mut self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1>;
}

/// Session provider for claims already verified at the request boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterVerifiedSessionProviderV1 {
    session: CloudflareRouterVerifiedSessionV1,
}

impl CloudflareRouterVerifiedSessionProviderV1 {
    /// Creates a provider from already verified session data.
    pub fn new(session: CloudflareRouterVerifiedSessionV1) -> RouterAbProtocolResult<Self> {
        session.validate()?;
        Ok(Self { session })
    }
}

impl CloudflareRouterSessionProviderV1 for CloudflareRouterVerifiedSessionProviderV1 {
    fn verify_public_request_session(
        &mut self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.session.to_trusted_metadata(request)
    }
}

/// Parsed `Authorization: Bearer ...` token at the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterBearerAuthorizationV1 {
    /// Compact bearer token.
    pub token: String,
}

impl CloudflareRouterBearerAuthorizationV1 {
    /// Creates a validated bearer token.
    pub fn new(token: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let authorization = Self {
            token: token.into(),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Parses an HTTP Authorization header value.
    pub fn from_authorization_header(header: &str) -> RouterAbProtocolResult<Self> {
        let value = header.trim();
        let token = value.strip_prefix("Bearer ").ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router authorization header must use Bearer scheme",
            )
        })?;
        Self::new(token.to_owned())
    }

    /// Validates token shape before verifier-specific parsing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("authorization bearer token", &self.token)?;
        require_no_ascii_whitespace("authorization bearer token", &self.token)
    }
}

/// One Ed25519 public JWT verification key parsed from JWKS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterEd25519JwkV1 {
    /// JWK key id.
    pub key_id: String,
    /// Ed25519 public key bytes.
    pub public_key: [u8; 32],
}

impl CloudflareRouterEd25519JwkV1 {
    /// Creates a validated Ed25519 JWK descriptor.
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> RouterAbProtocolResult<Self> {
        let key = Self {
            key_id: key_id.into(),
            public_key,
        };
        key.validate()?;
        Ok(key)
    }

    /// Validates the key id.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("ed25519 jwk kid", &self.key_id)?;
        require_no_ascii_whitespace("ed25519 jwk kid", &self.key_id)
    }
}

/// EdDSA/Ed25519-only JWT verifier backed by a parsed JWKS document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterEd25519JwksJwtVerifierV1 {
    /// Parsed Ed25519 signing keys indexed by `kid`.
    pub keys: Vec<CloudflareRouterEd25519JwkV1>,
}

impl CloudflareRouterEd25519JwksJwtVerifierV1 {
    /// Parses a JWKS JSON document into an Ed25519-only verifier.
    pub fn from_jwks_json(jwks_json: &str) -> RouterAbProtocolResult<Self> {
        require_non_empty("router jwt jwks json", jwks_json)?;
        let raw: CloudflareRouterRawJwksV1 = serde_json::from_str(jwks_json).map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router JWT JWKS JSON parse failed: {err}"),
            )
        })?;
        let mut keys = Vec::new();
        for raw_key in raw.keys {
            let Some(key) = raw_key.try_into_ed25519_key()? else {
                continue;
            };
            if keys
                .iter()
                .any(|existing: &CloudflareRouterEd25519JwkV1| existing.key_id == key.key_id)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "Router JWT JWKS contains duplicate Ed25519 kid",
                ));
            }
            keys.push(key);
        }
        let verifier = Self { keys };
        verifier.validate()?;
        Ok(verifier)
    }

    /// Creates a verifier from already parsed Ed25519 JWKs.
    pub fn new(keys: Vec<CloudflareRouterEd25519JwkV1>) -> RouterAbProtocolResult<Self> {
        let verifier = Self { keys };
        verifier.validate()?;
        Ok(verifier)
    }

    /// Validates that the verifier has at least one unique key.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.keys.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT JWKS must contain at least one Ed25519 signing key",
            ));
        }
        for key in &self.keys {
            key.validate()?;
        }
        for (index, key) in self.keys.iter().enumerate() {
            if self
                .keys
                .iter()
                .skip(index + 1)
                .any(|other| other.key_id == key.key_id)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "Router JWT verifier keys contain duplicate kid",
                ));
            }
        }
        Ok(())
    }

    fn key_for_id(&self, key_id: &str) -> RouterAbProtocolResult<&CloudflareRouterEd25519JwkV1> {
        require_non_empty("jwt kid", key_id)?;
        self.keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router JWT kid is not present in the configured JWKS",
                )
            })
    }
}

impl CloudflareRouterJwtVerifierV1 for CloudflareRouterEd25519JwksJwtVerifierV1 {
    fn verify_public_request_jwt(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        authorization: &CloudflareRouterBearerAuthorizationV1,
        request: &PublicRouterRequestV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        self.validate()?;
        verifier.validate()?;
        authorization.validate()?;
        request.validate_at(now_unix_ms)?;
        let jwt = CloudflareRouterCompactJwtV1::parse(&authorization.token)?;
        if jwt.header.alg != "EdDSA" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT alg must be EdDSA",
            ));
        }
        let key = self.key_for_id(&jwt.header.kid)?;
        verify_router_ed25519_jwt_signature_v1(&jwt.signing_input, &jwt.signature, key)?;
        jwt.claims.validate_for_router_request(
            verifier,
            request,
            now_unix_ms,
            trusted_source_digest,
        )
    }
}

impl CloudflareRouterWalletSessionVerifierV1 for CloudflareRouterEd25519JwksJwtVerifierV1 {
    fn verify_wallet_session(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        credential: &CloudflareRouterWalletSessionCredentialV1,
        trusted_source_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedWalletSessionV1> {
        self.validate()?;
        verifier.validate()?;
        credential.validate()?;
        require_positive_ms("wallet session now_unix_ms", now_unix_ms)?;
        let CloudflareRouterWalletSessionCredentialV1::Bearer { authorization } = credential;
        authorization.validate()?;
        let jwt = CloudflareRouterCompactJwtV1::parse(&authorization.token)?;
        if jwt.header.alg != "EdDSA" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session JWT alg must be EdDSA",
            ));
        }
        let key = self.key_for_id(&jwt.header.kid)?;
        verify_router_ed25519_jwt_signature_v1(&jwt.signing_input, &jwt.signature, key)?;
        jwt.claims
            .validate_for_wallet_session(verifier, now_unix_ms, trusted_source_digest)
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterRawJwksV1 {
    keys: Vec<CloudflareRouterRawJwkV1>,
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterRawJwkV1 {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    public_use: Option<String>,
    x: Option<String>,
}

impl CloudflareRouterRawJwkV1 {
    fn try_into_ed25519_key(self) -> RouterAbProtocolResult<Option<CloudflareRouterEd25519JwkV1>> {
        if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
            return Ok(None);
        }
        if self.alg.as_deref().is_some_and(|alg| alg != "EdDSA") {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK alg must be EdDSA when present",
            ));
        }
        if self.public_use.as_deref().is_some_and(|use_| use_ != "sig") {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK use must be sig when present",
            ));
        }
        let kid = self.kid.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK must include kid",
            )
        })?;
        let x = self.x.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK must include x coordinate",
            )
        })?;
        let public_key = decode_base64url_fixed_32_v1("Router JWT Ed25519 JWK x", &x)?;
        CloudflareRouterEd25519JwkV1::new(kid, public_key).map(Some)
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtHeaderV1 {
    alg: String,
    kid: String,
}

#[derive(Debug)]
struct CloudflareRouterCompactJwtV1 {
    signing_input: String,
    header: CloudflareRouterJwtHeaderV1,
    claims: CloudflareRouterJwtClaimsPayloadV1,
    signature: [u8; 64],
}

impl CloudflareRouterCompactJwtV1 {
    fn parse(token: &str) -> RouterAbProtocolResult<Self> {
        require_non_empty("router jwt token", token)?;
        require_no_ascii_whitespace("router jwt token", token)?;
        let mut parts = token.split('.');
        let header_segment = parts.next().ok_or_else(router_jwt_segment_error)?;
        let claims_segment = parts.next().ok_or_else(router_jwt_segment_error)?;
        let signature_segment = parts.next().ok_or_else(router_jwt_segment_error)?;
        if parts.next().is_some() {
            return Err(router_jwt_segment_error());
        }
        let header: CloudflareRouterJwtHeaderV1 =
            decode_base64url_json_v1("Router JWT header", header_segment)?;
        let claims: CloudflareRouterJwtClaimsPayloadV1 =
            decode_base64url_json_v1("Router JWT claims", claims_segment)?;
        let signature = decode_base64url_fixed_64_v1("Router JWT signature", signature_segment)?;
        Ok(Self {
            signing_input: format!("{header_segment}.{claims_segment}"),
            header,
            claims,
            signature,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtClaimsPayloadV1 {
    iss: String,
    sub: String,
    aud: CloudflareRouterJwtAudienceV1,
    exp: u64,
    nbf: Option<u64>,
    iat: Option<u64>,
    sid: Option<String>,
    session_id: Option<String>,
    #[serde(rename = "signingGrantId")]
    signing_grant_id: Option<String>,
    org_id: String,
    project_id: String,
    environment: String,
    account_id: String,
    #[serde(rename = "routerAbNormalSigning", default)]
    router_ab_normal_signing: Option<CloudflareRouterJwtNormalSigningWalletSessionClaimsV1>,
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtNormalSigningWalletSessionClaimsV1 {
    #[serde(rename = "authorizationLevel")]
    authorization_level: String,
    #[serde(rename = "signingWorkerId")]
    signing_worker_id: String,
}

impl CloudflareRouterJwtNormalSigningWalletSessionClaimsV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "routerAbNormalSigning.authorizationLevel",
            &self.authorization_level,
        )?;
        require_non_empty(
            "routerAbNormalSigning.signingWorkerId",
            &self.signing_worker_id,
        )
    }
}

impl CloudflareRouterJwtClaimsPayloadV1 {
    fn validate_for_router_request(
        self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        request: &PublicRouterRequestV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        verifier.validate()?;
        request.validate_at(now_unix_ms)?;
        let claims = self.validate_common_for_request_expiry(
            verifier,
            request.expires_at_ms,
            now_unix_ms,
            trusted_source_digest,
        )?;
        claims
            .to_trusted_metadata(request)?
            .validate_for_request(request)?;
        Ok(claims)
    }

    fn validate_for_wallet_session(
        self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedWalletSessionV1> {
        verifier.validate()?;
        if self.iss != verifier.issuer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session issuer does not match verifier config",
            ));
        }
        if !self.aud.contains(&verifier.audience) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session audience does not match verifier config",
            ));
        }
        let exp_ms = unix_seconds_to_millis_v1("wallet session exp", self.exp)?;
        if exp_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router Wallet Session is expired",
            ));
        }
        if let Some(nbf) = self.nbf {
            let nbf_ms = unix_seconds_to_millis_v1("wallet session nbf", nbf)?;
            if nbf_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router Wallet Session is not valid yet",
                ));
            }
        }
        if let Some(iat) = self.iat {
            let iat_ms = unix_seconds_to_millis_v1("wallet session iat", iat)?;
            if iat_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router Wallet Session issued-at time is in the future",
                ));
            }
        }
        let normal_signing = self.router_ab_normal_signing.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires routerAbNormalSigning",
            )
        })?;
        normal_signing.validate()?;
        let session_id = select_router_jwt_session_id_v1(self.sid, self.session_id)?;
        let signing_grant_id = self.signing_grant_id.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires signingGrantId",
            )
        })?;
        CloudflareRouterVerifiedWalletSessionV1::new(
            self.sub,
            self.account_id,
            session_id,
            signing_grant_id,
            self.org_id,
            self.project_id,
            self.environment,
            normal_signing.authorization_level,
            normal_signing.signing_worker_id,
            trusted_source_digest,
            exp_ms,
        )
    }

    fn validate_common_for_request_expiry(
        self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        request_expires_at_ms: u64,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        verifier.validate()?;
        if self.iss != verifier.issuer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT issuer does not match verifier config",
            ));
        }
        if !self.aud.contains(&verifier.audience) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT audience does not match verifier config",
            ));
        }
        let exp_ms = unix_seconds_to_millis_v1("jwt exp", self.exp)?;
        if exp_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router JWT is expired",
            ));
        }
        if exp_ms < request_expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Router JWT expires before the request",
            ));
        }
        if let Some(nbf) = self.nbf {
            let nbf_ms = unix_seconds_to_millis_v1("jwt nbf", nbf)?;
            if nbf_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router JWT is not valid yet",
                ));
            }
        }
        if let Some(iat) = self.iat {
            let iat_ms = unix_seconds_to_millis_v1("jwt iat", iat)?;
            if iat_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router JWT issued-at time is in the future",
                ));
            }
        }
        let session_id = select_router_jwt_session_id_v1(self.sid, self.session_id)?;
        let claims = CloudflareRouterVerifiedJwtClaimsV1::new(
            self.sub,
            session_id,
            self.org_id,
            self.project_id,
            self.environment,
            self.account_id,
            trusted_source_digest,
        )?;
        Ok(claims)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CloudflareRouterJwtAudienceV1 {
    Single(String),
    Many(Vec<String>),
}

impl CloudflareRouterJwtAudienceV1 {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(audience) => audience == expected,
            Self::Many(audiences) => audiences.iter().any(|audience| audience == expected),
        }
    }
}

/// JWT verifier boundary used by the Router session provider.
pub trait CloudflareRouterJwtVerifierV1 {
    /// Verifies a bearer token and returns normalized claims.
    fn verify_public_request_jwt(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        authorization: &CloudflareRouterBearerAuthorizationV1,
        request: &PublicRouterRequestV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1>;
}

/// Session provider backed by a Router JWT verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterJwtSessionProviderV1<Verifier> {
    verifier_binding: CloudflareRouterJwtVerifierBindingV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    now_unix_ms: u64,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
}

impl<Verifier> CloudflareRouterJwtSessionProviderV1<Verifier> {
    /// Creates a JWT-backed session provider from parsed boundary inputs.
    pub fn new(
        verifier_binding: CloudflareRouterJwtVerifierBindingV1,
        authorization: CloudflareRouterBearerAuthorizationV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
        verifier: Verifier,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self {
            verifier_binding,
            authorization,
            now_unix_ms,
            trusted_source_digest,
            verifier,
        };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates provider inputs before verifier execution.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.verifier_binding.validate()?;
        self.authorization.validate()?;
        require_positive_ms("jwt session now_unix_ms", self.now_unix_ms)
    }
}

impl<Verifier> CloudflareRouterSessionProviderV1 for CloudflareRouterJwtSessionProviderV1<Verifier>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    fn verify_public_request_session(
        &mut self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        request.validate()?;
        let claims = self.verifier.verify_public_request_jwt(
            &self.verifier_binding,
            &self.authorization,
            request,
            self.now_unix_ms,
            self.trusted_source_digest,
        )?;
        claims.to_trusted_metadata(request)
    }
}

/// Router project policy provider used by the admission chain.
pub trait CloudflareRouterProjectPolicyProviderV1 {
    /// Evaluates whether a project may run this work kind.
    fn evaluate_project_policy(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1>;
}

/// Project policy provider backed by an explicit allowed-work-kind set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1 {
    allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
    rejected_retry_after_ms: u64,
}

impl CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1 {
    /// Creates a project policy provider from the allowed work-kind set.
    pub fn new(
        allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
        rejected_retry_after_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self {
            allowed_work_kinds,
            rejected_retry_after_ms,
        };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates provider configuration.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_work_kind_set("allowed_work_kinds", &self.allowed_work_kinds)?;
        require_positive_ms(
            "project policy rejected retry_after_ms",
            self.rejected_retry_after_ms,
        )
    }
}

impl CloudflareRouterProjectPolicyProviderV1
    for CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1
{
    fn evaluate_project_policy(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        metadata.validate_for_request(request)?;
        if self
            .allowed_work_kinds
            .iter()
            .any(|work_kind| *work_kind == metadata.work_kind)
        {
            return Ok(CloudflareRouterProjectPolicyV1::Allowed);
        }
        Ok(CloudflareRouterProjectPolicyV1::Rejected {
            retry_after_ms: self.rejected_retry_after_ms,
        })
    }
}

/// Storage adapter for Router project policy decisions.
pub trait CloudflareRouterProjectPolicyStoreV1 {
    /// Reads/evaluates project policy for a trusted request.
    fn evaluate_project_policy_from_store(
        &mut self,
        binding: &CloudflareDurableObjectBindingV1,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1>;
}

/// Project policy provider backed by a Router-owned store binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterStoredProjectPolicyProviderV1<Store> {
    binding: CloudflareDurableObjectBindingV1,
    store: Store,
}

impl<Store> CloudflareRouterStoredProjectPolicyProviderV1<Store> {
    /// Creates a project policy provider using a Router project-policy store.
    pub fn new(
        binding: CloudflareDurableObjectBindingV1,
        store: Store,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self { binding, store };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates the store binding scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.binding,
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            CloudflareWorkerRoleV1::Router,
        )
    }
}

impl<Store> CloudflareRouterProjectPolicyProviderV1
    for CloudflareRouterStoredProjectPolicyProviderV1<Store>
where
    Store: CloudflareRouterProjectPolicyStoreV1,
{
    fn evaluate_project_policy(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        metadata.validate_for_request(request)?;
        self.store
            .evaluate_project_policy_from_store(&self.binding, metadata, request)
    }
}

/// Router abuse-control provider used by the admission chain.
pub trait CloudflareRouterAbuseProviderV1 {
    /// Evaluates source, principal, and request-level abuse controls.
    fn evaluate_abuse(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1>;
}

/// Abuse-control provider backed by a caller-supplied decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterConfiguredAbuseProviderV1 {
    outcome: CloudflareRouterAbuseCheckV1,
}

impl CloudflareRouterConfiguredAbuseProviderV1 {
    /// Creates an abuse provider from a validated decision.
    pub fn new(outcome: CloudflareRouterAbuseCheckV1) -> RouterAbProtocolResult<Self> {
        outcome.validate()?;
        Ok(Self { outcome })
    }
}

impl CloudflareRouterAbuseProviderV1 for CloudflareRouterConfiguredAbuseProviderV1 {
    fn evaluate_abuse(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
        metadata.validate_for_request(request)?;
        Ok(self.outcome.clone())
    }
}

/// Storage adapter for Router abuse-control decisions.
pub trait CloudflareRouterAbuseStoreV1 {
    /// Reads/evaluates abuse-control state for a trusted request.
    fn evaluate_abuse_from_store(
        &mut self,
        binding: &CloudflareDurableObjectBindingV1,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1>;
}

/// Abuse provider backed by a Router-owned store binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterStoredAbuseProviderV1<Store> {
    binding: CloudflareDurableObjectBindingV1,
    store: Store,
}

impl<Store> CloudflareRouterStoredAbuseProviderV1<Store> {
    /// Creates an abuse provider using a Router abuse-control store.
    pub fn new(
        binding: CloudflareDurableObjectBindingV1,
        store: Store,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self { binding, store };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates the store binding scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.binding,
            CloudflareDurableObjectScopeV1::RouterAbuse,
            CloudflareWorkerRoleV1::Router,
        )
    }
}

impl<Store> CloudflareRouterAbuseProviderV1 for CloudflareRouterStoredAbuseProviderV1<Store>
where
    Store: CloudflareRouterAbuseStoreV1,
{
    fn evaluate_abuse(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
        metadata.validate_for_request(request)?;
        self.store
            .evaluate_abuse_from_store(&self.binding, metadata, request)
    }
}

/// Router quota provider used by the admission chain.
pub trait CloudflareRouterQuotaProviderV1 {
    /// Evaluates quota, idempotency reuse, and signer queue capacity.
    fn evaluate_quota(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1>;
}

/// Quota provider backed by a caller-supplied decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterConfiguredQuotaProviderV1 {
    outcome: CloudflareRouterQuotaCheckV1,
}

impl CloudflareRouterConfiguredQuotaProviderV1 {
    /// Creates a quota provider from a validated decision.
    pub fn new(outcome: CloudflareRouterQuotaCheckV1) -> RouterAbProtocolResult<Self> {
        outcome.validate()?;
        Ok(Self { outcome })
    }
}

impl CloudflareRouterQuotaProviderV1 for CloudflareRouterConfiguredQuotaProviderV1 {
    fn evaluate_quota(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
        metadata.validate_for_request(request)?;
        Ok(self.outcome.clone())
    }
}

/// Storage adapter for Router quota decisions.
pub trait CloudflareRouterQuotaStoreV1 {
    /// Reads/evaluates quota state for a trusted request.
    fn evaluate_quota_from_store(
        &mut self,
        binding: &CloudflareDurableObjectBindingV1,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1>;
}

/// Quota provider backed by a Router-owned store binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterStoredQuotaProviderV1<Store> {
    binding: CloudflareDurableObjectBindingV1,
    store: Store,
}

impl<Store> CloudflareRouterStoredQuotaProviderV1<Store> {
    /// Creates a quota provider using a Router quota store.
    pub fn new(
        binding: CloudflareDurableObjectBindingV1,
        store: Store,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self { binding, store };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates the store binding scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.binding,
            CloudflareDurableObjectScopeV1::RouterQuota,
            CloudflareWorkerRoleV1::Router,
        )
    }
}

impl<Store> CloudflareRouterQuotaProviderV1 for CloudflareRouterStoredQuotaProviderV1<Store>
where
    Store: CloudflareRouterQuotaStoreV1,
{
    fn evaluate_quota(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
        metadata.validate_for_request(request)?;
        self.store
            .evaluate_quota_from_store(&self.binding, metadata, request)
    }
}

/// Composite Router provider that wires session, policy, abuse, and quota checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterCompositeAdmissionProviderV1<
    SessionProvider,
    ProjectPolicyProvider,
    AbuseProvider,
    QuotaProvider,
> {
    session: SessionProvider,
    project_policy: ProjectPolicyProvider,
    abuse: AbuseProvider,
    quota: QuotaProvider,
}

impl<SessionProvider, ProjectPolicyProvider, AbuseProvider, QuotaProvider>
    CloudflareRouterCompositeAdmissionProviderV1<
        SessionProvider,
        ProjectPolicyProvider,
        AbuseProvider,
        QuotaProvider,
    >
{
    /// Creates a composite Router admission provider.
    pub fn new(
        session: SessionProvider,
        project_policy: ProjectPolicyProvider,
        abuse: AbuseProvider,
        quota: QuotaProvider,
    ) -> Self {
        Self {
            session,
            project_policy,
            abuse,
            quota,
        }
    }
}

impl<SessionProvider, ProjectPolicyProvider, AbuseProvider, QuotaProvider>
    CloudflareRouterAdmissionProviderV1
    for CloudflareRouterCompositeAdmissionProviderV1<
        SessionProvider,
        ProjectPolicyProvider,
        AbuseProvider,
        QuotaProvider,
    >
where
    SessionProvider: CloudflareRouterSessionProviderV1,
    ProjectPolicyProvider: CloudflareRouterProjectPolicyProviderV1,
    AbuseProvider: CloudflareRouterAbuseProviderV1,
    QuotaProvider: CloudflareRouterQuotaProviderV1,
{
    fn evaluate_public_request_admission(
        &mut self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1> {
        request.validate()?;
        let metadata = self.session.verify_public_request_session(request)?;
        metadata.validate_for_request(request)?;
        let project_policy = self
            .project_policy
            .evaluate_project_policy(&metadata, request)?;
        project_policy.validate()?;
        let abuse = self.abuse.evaluate_abuse(&metadata, request)?;
        abuse.validate()?;
        let quota = self.quota.evaluate_quota(&metadata, request)?;
        quota.validate()?;
        CloudflareRouterAdmissionProviderOutputV1::new(
            metadata,
            CloudflareRouterAdmissionChecksV1::new(project_policy, abuse, quota)?,
        )
    }
}

/// Derives trusted Router admission from a provider-owned admission boundary.
pub fn derive_cloudflare_router_trusted_admission_from_provider_v1(
    request: &PublicRouterRequestV1,
    provider: &mut impl CloudflareRouterAdmissionProviderV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    request.validate()?;
    let output = provider.evaluate_public_request_admission(request)?;
    output.validate_for_request(request)?;
    derive_cloudflare_router_trusted_admission_v1(request, output.metadata, output.checks)
}

/// Derives trusted Router admission from server-owned metadata and checks.
pub fn derive_cloudflare_router_trusted_admission_v1(
    request: &PublicRouterRequestV1,
    metadata: CloudflareRouterTrustedRequestMetadataV1,
    checks: CloudflareRouterAdmissionChecksV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    request.validate()?;
    metadata.validate_for_request(request)?;
    checks.validate()?;
    let admission = CloudflareRouterTrustedAdmissionV1::new(
        metadata.to_gate_context()?,
        checks.to_gate_decision()?,
    )?;
    admission.validate_for_request(request)?;
    Ok(admission)
}

/// Server-derived Router admission data for a public expensive-work request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterTrustedAdmissionV1 {
    /// Trusted Router-owned gate context.
    pub context: ExpensiveWorkGateContextV1,
    /// Trusted Router-owned gate decision.
    pub decision: ExpensiveWorkGateDecisionV1,
}

impl CloudflareRouterTrustedAdmissionV1 {
    /// Creates a validated trusted admission wrapper.
    pub fn new(
        context: ExpensiveWorkGateContextV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self { context, decision };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates the admission wrapper itself.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.decision.validate()
    }

    /// Validates server-derived admission data against the normalized request.
    pub fn validate_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.context.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted admission work kind does not match public request lifecycle",
            ));
        }
        if self.context.resource_id != request.lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted admission resource id does not match public request account",
            ));
        }
        match &self.context.principal {
            GatePrincipalV1::AuthenticatedSession { session_id, .. } => {
                if session_id != &request.lifecycle.session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "trusted authenticated session does not match public request lifecycle",
                    ));
                }
            }
            GatePrincipalV1::PreAuthSession {
                pre_auth_session_id,
            } => {
                if pre_auth_session_id != &request.lifecycle.session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "trusted pre-auth session does not match public request lifecycle",
                    ));
                }
                if self.context.work_kind != ExpensiveWorkKindV1::RegistrationPrepare {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "pre-auth trusted admission is allowed only for registration prepare",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns whether signer forwarding is allowed for this decision.
    pub fn allows_signer_forwarding(&self) -> RouterAbProtocolResult<bool> {
        self.validate()?;
        Ok(matches!(
            self.decision,
            ExpensiveWorkGateDecisionV1::Accepted { .. }
                | ExpensiveWorkGateDecisionV1::ReuseExisting { .. }
        ))
    }

    /// Returns the lifecycle state that the Router should persist.
    pub fn lifecycle_state_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<RouterAbLifecycleStateV1> {
        self.validate_for_request(request)?;
        RouterAbLifecycleStateV1::apply_gate_decision(
            request.lifecycle.clone(),
            self.decision.clone(),
        )
    }
}

/// Server-derived Router admission data for a normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningTrustedAdmissionV1 {
    /// Trusted Router-owned normal-signing metadata.
    pub metadata: CloudflareRouterNormalSigningTrustedMetadataV1,
    /// Trusted Router-owned gate decision.
    pub decision: ExpensiveWorkGateDecisionV1,
}

impl CloudflareRouterNormalSigningTrustedAdmissionV1 {
    /// Creates a validated normal-signing admission wrapper.
    pub fn new(
        metadata: CloudflareRouterNormalSigningTrustedMetadataV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self { metadata, decision };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates the normal-signing admission wrapper itself.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        self.decision.validate()
    }

    /// Validates server-derived admission data against a typed v2 finalize request.
    pub fn validate_for_finalize_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        self.metadata.validate_for_finalize_request_v2(request)
    }

    /// Returns whether SigningWorker forwarding is allowed for this decision.
    pub fn allows_signing_worker_forwarding(&self) -> RouterAbProtocolResult<bool> {
        self.validate()?;
        Ok(matches!(
            self.decision,
            ExpensiveWorkGateDecisionV1::Accepted { .. }
        ))
    }
}

/// Pre-gate Router admission candidate for typed normal-signing v2 prepare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningPrepareAdmissionCandidateV2 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Threshold/MPC session id authorized by the Wallet Session.
    pub threshold_session_id: String,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed normal-signing scope.
    pub request_id: String,
    /// Digest of the canonical typed intent.
    pub intent_digest: PublicDigest32,
    /// Digest of the canonical typed signing payload.
    pub signing_payload_digest: PublicDigest32,
    /// Exact 32-byte digest admitted for the SigningWorker finalizer.
    pub admitted_signing_digest: PublicDigest32,
    /// Prepared round-1 binding digest when the request has reached prepare admission.
    pub round1_binding_digest: Option<PublicDigest32>,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterNormalSigningPrepareAdmissionCandidateV2 {
    /// Creates validated internal normal-signing v2 prepare admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        threshold_session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        round1_binding_digest: Option<PublicDigest32>,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            threshold_session_id: threshold_session_id.into(),
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            intent_digest,
            signing_payload_digest,
            admitted_signing_digest,
            round1_binding_digest,
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds a prepare admission candidate from a verified Wallet Session and typed request.
    pub fn from_prepare_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate_for_normal_signing_prepare_request_v2(request, now_unix_ms)?;
        let material = request.admission_material()?;
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            wallet_session.threshold_session_id.clone(),
            wallet_session.signing_worker_id.clone(),
            request.scope.request_id.clone(),
            material.intent_digest,
            material.signing_payload_digest,
            material.admitted_signing_digest,
            Some(request.round1_binding_digest()?),
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_prepare_request(request)?;
        Ok(admission)
    }

    /// Validates internal admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal-signing v2 org_id", &self.org_id)?;
        require_non_empty("normal-signing v2 project_id", &self.project_id)?;
        require_non_empty("normal-signing v2 environment", &self.environment)?;
        require_non_empty("normal-signing v2 account_id", &self.account_id)?;
        require_non_empty("normal-signing v2 subject_id", &self.subject_id)?;
        require_non_empty(
            "normal-signing v2 threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty(
            "normal-signing v2 signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty("normal-signing v2 request_id", &self.request_id)?;
        require_positive_ms("normal-signing v2 expires_at_ms", self.expires_at_ms)
    }

    /// Returns the v2 digest material carried by this prepare admission candidate.
    pub fn admission_material(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningAdmissionMaterialV2> {
        self.validate()?;
        Ok(RouterAbEd25519NormalSigningAdmissionMaterialV2 {
            intent_digest: self.intent_digest,
            signing_payload_digest: self.signing_payload_digest,
            admitted_signing_digest: self.admitted_signing_digest,
        })
    }

    /// Validates a prepare admission candidate against a typed prepare request.
    pub fn validate_for_prepare_request(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission account_id does not match request scope",
            ));
        }
        if self.threshold_session_id != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission session_id does not match request scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.scope.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission request_id does not match request scope",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission expires_at_ms does not match request",
            ));
        }

        let expected = request.admission_material()?;
        if self.intent_digest != expected.intent_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission intent digest does not match request",
            ));
        }
        if self.signing_payload_digest != expected.signing_payload_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission signing payload digest does not match request",
            ));
        }
        if self.admitted_signing_digest != expected.admitted_signing_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission admitted signing digest does not match request",
            ));
        }

        let Some(round1_binding_digest) = self.round1_binding_digest else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission requires round1 binding digest",
            ));
        };
        if round1_binding_digest != request.round1_binding_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission round1 binding digest does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the candidate to the current v1 admission-store metadata shape.
    pub fn to_v1_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session(
                self.subject_id.clone(),
                self.threshold_session_id.clone(),
            )?,
            self.trusted_source_digest,
            self.intent_digest,
        )
    }

    /// Converts the candidate to the current admission-store request shape.
    pub fn to_v1_prepare_admission_store_request(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreRequestV1> {
        self.validate_for_prepare_request(request)?;
        request.validate_at(now_unix_ms)?;
        require_positive_ms("normal-signing v2 admission-store now_unix_ms", now_unix_ms)?;
        let store_request = CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
            metadata: self.to_v1_trusted_metadata()?,
            request_id: self.request_id.clone(),
            expires_at_ms: self.expires_at_ms,
            now_unix_ms,
            intent_digest: self.intent_digest,
            request_digest: request.round1_binding_digest()?,
        };
        store_request.validate()?;
        Ok(store_request)
    }
}

/// Pre-gate Router admission candidate for typed normal-signing v2 finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Threshold/MPC session id authorized by the Wallet Session.
    pub threshold_session_id: String,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed normal-signing scope.
    pub request_id: String,
    /// Digest of the canonical typed intent admitted during prepare.
    pub intent_digest: PublicDigest32,
    /// Digest of the canonical typed signing payload admitted during prepare.
    pub signing_payload_digest: PublicDigest32,
    /// Prepared round-1 binding digest that finalize must consume.
    pub round1_binding_digest: PublicDigest32,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2 {
    /// Creates validated internal normal-signing v2 finalize admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        threshold_session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
        round1_binding_digest: PublicDigest32,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            threshold_session_id: threshold_session_id.into(),
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            intent_digest,
            signing_payload_digest,
            round1_binding_digest,
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds a finalize admission candidate from a verified Wallet Session and typed request.
    pub fn from_finalize_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate_for_normal_signing_finalize_request_v2(request, now_unix_ms)?;
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            wallet_session.threshold_session_id.clone(),
            wallet_session.signing_worker_id.clone(),
            request.scope.request_id.clone(),
            request.intent_digest(),
            request.signing_payload_digest(),
            request.round1_binding_digest(),
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_finalize_request(request)?;
        Ok(admission)
    }

    /// Validates internal finalize admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal-signing v2 finalize org_id", &self.org_id)?;
        require_non_empty("normal-signing v2 finalize project_id", &self.project_id)?;
        require_non_empty("normal-signing v2 finalize environment", &self.environment)?;
        require_non_empty("normal-signing v2 finalize account_id", &self.account_id)?;
        require_non_empty("normal-signing v2 finalize subject_id", &self.subject_id)?;
        require_non_empty(
            "normal-signing v2 finalize threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty(
            "normal-signing v2 finalize signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty("normal-signing v2 finalize request_id", &self.request_id)?;
        require_positive_ms(
            "normal-signing v2 finalize expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates a finalize admission candidate against a typed finalize request.
    pub fn validate_for_finalize_request(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission account_id does not match request scope",
            ));
        }
        if self.threshold_session_id != request.scope.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission session_id does not match request scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.scope.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission request_id does not match request scope",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission expires_at_ms does not match request",
            ));
        }
        if self.intent_digest != request.intent_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission intent digest does not match request",
            ));
        }
        if self.signing_payload_digest != request.signing_payload_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission signing payload digest does not match request",
            ));
        }
        if self.round1_binding_digest != request.round1_binding_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission round1 binding digest does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the finalize candidate to the current v1 admission-store metadata shape.
    pub fn to_v1_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session(
                self.subject_id.clone(),
                self.threshold_session_id.clone(),
            )?,
            self.trusted_source_digest,
            self.intent_digest,
        )
    }

    /// Converts the finalize candidate to the current admission-store request shape.
    pub fn to_v1_finalize_admission_store_request(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreRequestV1> {
        self.validate_for_finalize_request(request)?;
        request.validate_at(now_unix_ms)?;
        require_positive_ms(
            "normal-signing v2 finalize admission-store now_unix_ms",
            now_unix_ms,
        )?;
        let store_request = CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
            metadata: self.to_v1_trusted_metadata()?,
            request_id: self.request_id.clone(),
            expires_at_ms: self.expires_at_ms,
            now_unix_ms,
            intent_digest: self.intent_digest,
            request_digest: self.round1_binding_digest,
        };
        store_request.validate()?;
        Ok(store_request)
    }
}

/// Pre-gate Router admission candidate for ECDSA-HSS EVM digest prepare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterEcdsaHssEvmDigestPrepareAdmissionCandidateV1 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Wallet id authorized by the Wallet Session.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Threshold/MPC session id authorized by the Wallet Session.
    pub threshold_session_id: String,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed ECDSA-HSS request.
    pub request_id: String,
    /// Client-selected presignature id that must match the SigningWorker server share.
    pub client_presignature_id: String,
    /// Digest of the active ECDSA-HSS normal-signing scope.
    pub scope_digest: PublicDigest32,
    /// Canonical Router-admitted ECDSA-HSS signing request digest.
    pub request_digest: PublicDigest32,
    /// Exact 32-byte EVM digest admitted for SigningWorker finalize.
    pub signing_digest: PublicDigest32,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterEcdsaHssEvmDigestPrepareAdmissionCandidateV1 {
    /// Creates validated internal ECDSA-HSS prepare admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        threshold_session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        client_presignature_id: impl Into<String>,
        scope_digest: PublicDigest32,
        request_digest: PublicDigest32,
        signing_digest: PublicDigest32,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            threshold_session_id: threshold_session_id.into(),
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            client_presignature_id: client_presignature_id.into(),
            scope_digest,
            request_digest,
            signing_digest,
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds an ECDSA-HSS prepare admission candidate from a verified Wallet Session.
    pub fn from_prepare_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session
            .validate_for_ecdsa_hss_evm_digest_signing_request_v1(request, now_unix_ms)?;
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            wallet_session.threshold_session_id.clone(),
            wallet_session.signing_worker_id.clone(),
            request.request_id.clone(),
            request.client_presignature_id.clone(),
            request.scope.scope_digest()?,
            request.request_digest()?,
            request.signing_digest()?,
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_prepare_request(request)?;
        Ok(admission)
    }

    /// Validates internal ECDSA-HSS admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("ECDSA-HSS prepare org_id", &self.org_id)?;
        require_non_empty("ECDSA-HSS prepare project_id", &self.project_id)?;
        require_non_empty("ECDSA-HSS prepare environment", &self.environment)?;
        require_non_empty("ECDSA-HSS prepare account_id", &self.account_id)?;
        require_non_empty("ECDSA-HSS prepare subject_id", &self.subject_id)?;
        require_non_empty(
            "ECDSA-HSS prepare threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty(
            "ECDSA-HSS prepare signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty("ECDSA-HSS prepare request_id", &self.request_id)?;
        require_non_empty(
            "ECDSA-HSS prepare client_presignature_id",
            &self.client_presignature_id,
        )?;
        require_positive_ms("ECDSA-HSS prepare expires_at_ms", self.expires_at_ms)
    }

    /// Validates an ECDSA-HSS prepare admission candidate against a typed request.
    pub fn validate_for_prepare_request(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.context.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission account_id does not match request scope",
            ));
        }
        if self.threshold_session_id
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission session_id does not match request scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission request_id does not match request",
            ));
        }
        if self.client_presignature_id != request.client_presignature_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission presignature id does not match request",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission expires_at_ms does not match request",
            ));
        }
        if self.scope_digest != request.scope.scope_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission scope digest does not match request",
            ));
        }
        if self.request_digest != request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission request digest does not match request",
            ));
        }
        if self.signing_digest != request.signing_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS prepare admission signing digest does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the candidate to the shared normal-signing trusted metadata shape.
    pub fn to_normal_signing_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session(
                self.subject_id.clone(),
                self.threshold_session_id.clone(),
            )?,
            self.trusted_source_digest,
            self.request_digest,
        )
    }

    /// Converts the candidate to the shared normal-signing admission-store shape.
    pub fn to_normal_signing_admission_store_request(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreRequestV1> {
        self.validate_for_prepare_request(request)?;
        request.validate_at(now_unix_ms)?;
        require_positive_ms("ECDSA-HSS prepare admission-store now_unix_ms", now_unix_ms)?;
        let store_request = CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
            metadata: self.to_normal_signing_trusted_metadata()?,
            request_id: self.request_id.clone(),
            expires_at_ms: self.expires_at_ms,
            now_unix_ms,
            intent_digest: self.request_digest,
            request_digest: self.request_digest,
        };
        store_request.validate()?;
        Ok(store_request)
    }
}

/// Pre-gate Router admission candidate for ECDSA-HSS EVM digest finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterEcdsaHssEvmDigestFinalizeAdmissionCandidateV1 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Wallet id authorized by the Wallet Session.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Threshold/MPC session id authorized by the Wallet Session.
    pub threshold_session_id: String,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed ECDSA-HSS finalize request.
    pub request_id: String,
    /// Digest of the active ECDSA-HSS normal-signing scope.
    pub scope_digest: PublicDigest32,
    /// Canonical prepare request digest that the presignature must match.
    pub prepare_request_digest: PublicDigest32,
    /// Canonical finalize request digest admitted by the Router.
    pub finalize_request_digest: PublicDigest32,
    /// Exact 32-byte EVM digest admitted for SigningWorker finalize.
    pub signing_digest: PublicDigest32,
    /// SigningWorker-local presignature id consumed by finalize.
    pub server_presignature_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterEcdsaHssEvmDigestFinalizeAdmissionCandidateV1 {
    /// Creates validated internal ECDSA-HSS finalize admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        threshold_session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        scope_digest: PublicDigest32,
        prepare_request_digest: PublicDigest32,
        finalize_request_digest: PublicDigest32,
        signing_digest: PublicDigest32,
        server_presignature_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            threshold_session_id: threshold_session_id.into(),
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            scope_digest,
            prepare_request_digest,
            finalize_request_digest,
            signing_digest,
            server_presignature_id: server_presignature_id.into(),
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds an ECDSA-HSS finalize admission candidate from a verified Wallet Session.
    pub fn from_finalize_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session
            .validate_for_ecdsa_hss_evm_digest_finalize_request_v1(request, now_unix_ms)?;
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            wallet_session.threshold_session_id.clone(),
            wallet_session.signing_worker_id.clone(),
            request.request_id.clone(),
            request.scope.scope_digest()?,
            request.prepare_request_digest()?,
            request.request_digest()?,
            request.signing_digest()?,
            request.server_presignature_id.clone(),
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_finalize_request(request)?;
        Ok(admission)
    }

    /// Validates internal ECDSA-HSS finalize admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("ECDSA-HSS finalize org_id", &self.org_id)?;
        require_non_empty("ECDSA-HSS finalize project_id", &self.project_id)?;
        require_non_empty("ECDSA-HSS finalize environment", &self.environment)?;
        require_non_empty("ECDSA-HSS finalize account_id", &self.account_id)?;
        require_non_empty("ECDSA-HSS finalize subject_id", &self.subject_id)?;
        require_non_empty(
            "ECDSA-HSS finalize threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty(
            "ECDSA-HSS finalize signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty("ECDSA-HSS finalize request_id", &self.request_id)?;
        require_non_empty(
            "ECDSA-HSS finalize server_presignature_id",
            &self.server_presignature_id,
        )?;
        require_positive_ms("ECDSA-HSS finalize expires_at_ms", self.expires_at_ms)
    }

    /// Validates an ECDSA-HSS finalize admission candidate against a typed request.
    pub fn validate_for_finalize_request(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.context.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission account_id does not match request scope",
            ));
        }
        if self.threshold_session_id
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission session_id does not match request scope",
            ));
        }
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission request_id does not match request",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission expires_at_ms does not match request",
            ));
        }
        if self.scope_digest != request.scope.scope_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission scope digest does not match request",
            ));
        }
        if self.prepare_request_digest != request.prepare_request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission prepare digest does not match request",
            ));
        }
        if self.finalize_request_digest != request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission request digest does not match request",
            ));
        }
        if self.signing_digest != request.signing_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission signing digest does not match request",
            ));
        }
        if self.server_presignature_id != request.server_presignature_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize admission presignature id does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the candidate to the shared normal-signing trusted metadata shape.
    pub fn to_normal_signing_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session(
                self.subject_id.clone(),
                self.threshold_session_id.clone(),
            )?,
            self.trusted_source_digest,
            self.finalize_request_digest,
        )
    }

    /// Converts the candidate to the shared normal-signing admission-store shape.
    pub fn to_normal_signing_admission_store_request(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreRequestV1> {
        self.validate_for_finalize_request(request)?;
        request.validate_at(now_unix_ms)?;
        require_positive_ms(
            "ECDSA-HSS finalize admission-store now_unix_ms",
            now_unix_ms,
        )?;
        let store_request = CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
            metadata: self.to_normal_signing_trusted_metadata()?,
            request_id: self.request_id.clone(),
            expires_at_ms: self.expires_at_ms,
            now_unix_ms,
            intent_digest: self.prepare_request_digest,
            request_digest: self.finalize_request_digest,
        };
        store_request.validate()?;
        Ok(store_request)
    }
}

/// Gate-aware Router work plan after public request normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum CloudflareRouterPublicAdmissionPlanV1 {
    /// Gate accepted or selected an existing lifecycle, so signer forwarding is allowed.
    Forward {
        /// Replay reservation call for the public request nonce.
        replay_reserve_call: CloudflareDurableObjectCallV1,
        /// Public lifecycle persistence call for the requested state.
        lifecycle_requested_put_call: CloudflareDurableObjectCallV1,
        /// Public lifecycle persistence call after gate application.
        lifecycle_put_call: CloudflareDurableObjectCallV1,
        /// Trusted Router-owned gate data.
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
        /// Canonical Router-to-Signer A wire message.
        deriver_a_message: WireMessageV1,
        /// Canonical Router-to-Signer B wire message.
        deriver_b_message: WireMessageV1,
    },
    /// Gate deferred or rejected the request before signer forwarding.
    Stop {
        /// Replay reservation call for the public request nonce.
        replay_reserve_call: CloudflareDurableObjectCallV1,
        /// Public lifecycle persistence call for the requested state.
        lifecycle_requested_put_call: CloudflareDurableObjectCallV1,
        /// Public lifecycle persistence call after gate application.
        lifecycle_put_call: CloudflareDurableObjectCallV1,
        /// Trusted Router-owned gate data.
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
    },
}

impl CloudflareRouterPublicAdmissionPlanV1 {
    /// Validates Router-only storage calls and admission branch consistency.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.replay_reserve_call().validate()?;
        self.lifecycle_requested_put_call().validate()?;
        self.lifecycle_put_call().validate()?;
        self.trusted_admission().validate()?;
        if self.replay_reserve_call().worker_role != CloudflareWorkerRoleV1::Router
            || self.replay_reserve_call().binding.scope
                != CloudflareDurableObjectScopeV1::RouterReplay
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "public Router admission plan replay call must use Router replay scope",
            ));
        }
        if self.lifecycle_put_call().worker_role != CloudflareWorkerRoleV1::Router
            || self.lifecycle_put_call().binding.scope
                != CloudflareDurableObjectScopeV1::RouterLifecycle
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "public Router admission plan lifecycle call must use Router lifecycle scope",
            ));
        }
        if self.lifecycle_requested_put_call().worker_role != CloudflareWorkerRoleV1::Router
            || self.lifecycle_requested_put_call().binding.scope
                != CloudflareDurableObjectScopeV1::RouterLifecycle
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "public Router admission plan requested lifecycle call must use Router lifecycle scope",
            ));
        }
        match self {
            Self::Forward {
                deriver_a_message,
                deriver_b_message,
                trusted_admission,
                ..
            } => {
                if !trusted_admission.allows_signer_forwarding()? {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "public Router admission plan forward branch requires accepted gate decision",
                    ));
                }
                if deriver_a_message.kind != WireMessageKindV1::RouterToSignerA {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan Signer A message has wrong branch",
                    ));
                }
                if deriver_b_message.kind != WireMessageKindV1::RouterToSignerB {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan Signer B message has wrong branch",
                    ));
                }
                if deriver_a_message.transcript_digest != deriver_b_message.transcript_digest {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan signer messages must share transcript digest",
                    ));
                }
                Ok(())
            }
            Self::Stop {
                trusted_admission, ..
            } => {
                if trusted_admission.allows_signer_forwarding()? {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "public Router admission plan stop branch requires defer or reject gate decision",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns the replay reservation call.
    pub fn replay_reserve_call(&self) -> &CloudflareDurableObjectCallV1 {
        match self {
            Self::Forward {
                replay_reserve_call,
                ..
            }
            | Self::Stop {
                replay_reserve_call,
                ..
            } => replay_reserve_call,
        }
    }

    /// Returns the requested lifecycle persistence call.
    pub fn lifecycle_requested_put_call(&self) -> &CloudflareDurableObjectCallV1 {
        match self {
            Self::Forward {
                lifecycle_requested_put_call,
                ..
            }
            | Self::Stop {
                lifecycle_requested_put_call,
                ..
            } => lifecycle_requested_put_call,
        }
    }

    /// Returns the lifecycle persistence call.
    pub fn lifecycle_put_call(&self) -> &CloudflareDurableObjectCallV1 {
        match self {
            Self::Forward {
                lifecycle_put_call, ..
            }
            | Self::Stop {
                lifecycle_put_call, ..
            } => lifecycle_put_call,
        }
    }

    /// Returns trusted admission data.
    pub fn trusted_admission(&self) -> &CloudflareRouterTrustedAdmissionV1 {
        match self {
            Self::Forward {
                trusted_admission, ..
            }
            | Self::Stop {
                trusted_admission, ..
            } => trusted_admission,
        }
    }
}

/// Strict private signer response carrying opaque client and server proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerRecipientProofBundleResponseV1 {
    /// Producing signer role.
    pub signer_role: Role,
    /// Opaque client-delivery proof bundle for `x_client_base`.
    pub client_bundle: WireMessageV1,
    /// Opaque server-delivery proof bundle for `x_server_base`.
    pub server_bundle: WireMessageV1,
}

impl CloudflareSignerRecipientProofBundleResponseV1 {
    /// Creates a validated strict private signer response.
    pub fn new(
        signer_role: Role,
        client_bundle: WireMessageV1,
        server_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            signer_role,
            client_bundle,
            server_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates role, recipient class, and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.signer_role)?;
        let client = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let server = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "server_bundle",
            &self.server_bundle,
            self.signer_role,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        if client.signer != server.signer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer proof-bundle response signer identities must match",
            ));
        }
        if self.client_bundle.transcript_digest != self.server_bundle.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict signer proof-bundle response transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates this signer response against the Router payload that produced it.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let client = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let server = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "server_bundle",
            &self.server_bundle,
            self.signer_role,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let expected_signer =
            expected_cloudflare_signer_identity_for_role_v1(router_payload, self.signer_role)?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "client_bundle",
            &client,
            router_payload,
            expected_signer,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "server_bundle",
            &server,
            router_payload,
            expected_signer,
        )
    }
}

/// Strict private signer response carrying only an opaque client proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerClientRecipientProofBundleResponseV1 {
    /// Producing signer role.
    pub signer_role: Role,
    /// Opaque client-delivery proof bundle for `x_client_base`.
    pub client_bundle: WireMessageV1,
}

impl CloudflareSignerClientRecipientProofBundleResponseV1 {
    /// Creates a validated strict private signer client-output response.
    pub fn new(signer_role: Role, client_bundle: WireMessageV1) -> RouterAbProtocolResult<Self> {
        let response = Self {
            signer_role,
            client_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates role, recipient class, and output material class.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.signer_role)?;
        decode_cloudflare_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        Ok(())
    }

    /// Validates this client-only response against the Router payload that produced it.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let client = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let expected_signer =
            expected_cloudflare_signer_identity_for_role_v1(router_payload, self.signer_role)?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "client_bundle",
            &client,
            router_payload,
            expected_signer,
        )
    }
}

/// Strict public Router response carrying only opaque client proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterRecipientProofBundleResponseV1 {
    /// Replay reservation response from the Router replay Durable Object.
    pub replay: CloudflareReplayReserveResponseV1,
    /// Public lifecycle receipt from the Router lifecycle Durable Object.
    pub lifecycle: CloudflareLifecyclePutReceiptV1,
    /// Signer A opaque client proof bundle.
    pub deriver_a_client_bundle: WireMessageV1,
    /// Signer B opaque client proof bundle.
    pub deriver_b_client_bundle: WireMessageV1,
}

impl CloudflareRouterRecipientProofBundleResponseV1 {
    /// Creates a validated strict public Router response.
    pub fn new(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        deriver_a_client_bundle: WireMessageV1,
        deriver_b_client_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            replay,
            lifecycle,
            deriver_a_client_bundle,
            deriver_b_client_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates replay/lifecycle receipts and opaque client bundle shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.replay.validate()?;
        self.lifecycle.validate()?;
        let deriver_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_a_client_bundle",
            &self.deriver_a_client_bundle,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let deriver_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_b_client_bundle",
            &self.deriver_b_client_bundle,
            Role::SignerB,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        if deriver_a.transcript_digest != deriver_b.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict Router proof-bundle response transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates opaque client bundles against the Router payload that produced them.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let deriver_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_a_client_bundle",
            &self.deriver_a_client_bundle,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let deriver_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_b_client_bundle",
            &self.deriver_b_client_bundle,
            Role::SignerB,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "deriver_a_client_bundle",
            &deriver_a,
            router_payload,
            &router_payload.signer_set().signer_a,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "deriver_b_client_bundle",
            &deriver_b,
            router_payload,
            &router_payload.signer_set().signer_b,
        )
    }
}

/// Strict Signer A activation package for opaque server proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRecipientProofBundleActivationV1 {
    /// Signer A opaque server proof bundle.
    pub deriver_a_bundle: WireMessageV1,
    /// Signer B opaque server proof bundle.
    pub deriver_b_server_bundle: WireMessageV1,
}

impl CloudflareSigningWorkerRecipientProofBundleActivationV1 {
    /// Creates a validated strict SigningWorker activation package.
    pub fn new(
        deriver_a_bundle: WireMessageV1,
        deriver_b_server_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let activation = Self {
            deriver_a_bundle,
            deriver_b_server_bundle,
        };
        activation.validate()?;
        Ok(activation)
    }

    /// Validates opaque server bundle shape and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let deriver_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_a_bundle",
            &self.deriver_a_bundle,
            Role::SignerA,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let deriver_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_b_server_bundle",
            &self.deriver_b_server_bundle,
            Role::SignerB,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        if deriver_a.transcript_digest != deriver_b.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict SigningWorker proof-bundle activation transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates opaque server bundles against the SigningWorker activation context.
    pub fn validate_for_activation_context(
        &self,
        activation_context: &SigningWorkerActivationContextV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        activation_context.validate()?;
        let deriver_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_a_bundle",
            &self.deriver_a_bundle,
            Role::SignerA,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let deriver_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_b_server_bundle",
            &self.deriver_b_server_bundle,
            Role::SignerB,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_activation_context_v1(
            "deriver_a_bundle",
            &deriver_a,
            activation_context,
            &activation_context.signer_set().signer_a,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_activation_context_v1(
            "deriver_b_server_bundle",
            &deriver_b,
            activation_context,
            &activation_context.signer_set().signer_b,
        )
    }

    /// Validates opaque server bundles against the Router payload that produced them.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(router_payload)?;
        self.validate_for_activation_context(&activation_context)
    }
}

/// Direct Deriver-to-SigningWorker activation delivery for one server proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1 {
    /// Public context needed to verify and later aggregate SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Deriver role that produced this SigningWorker-recipient bundle.
    pub deriver_role: Role,
    /// Opaque SigningWorker-delivery proof bundle for `x_server_base`.
    pub signing_worker_bundle: WireMessageV1,
}

impl CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1 {
    /// Creates a validated single-Deriver activation delivery.
    pub fn new(
        activation_context: SigningWorkerActivationContextV1,
        deriver_role: Role,
        signing_worker_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let delivery = Self {
            activation_context,
            deriver_role,
            signing_worker_bundle,
        };
        delivery.validate()?;
        Ok(delivery)
    }

    /// Builds a direct delivery from a validated Deriver response.
    pub fn from_signer_response(
        activation_context: SigningWorkerActivationContextV1,
        response: CloudflareSignerRecipientProofBundleResponseV1,
    ) -> RouterAbProtocolResult<Self> {
        response.validate()?;
        Self::new(
            activation_context,
            response.signer_role,
            response.server_bundle,
        )
    }

    /// Validates this direct delivery against its activation context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.activation_context.validate()?;
        require_signer_role(self.deriver_role)?;
        let envelope = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signing_worker_bundle",
            &self.signing_worker_bundle,
            self.deriver_role,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let expected_signer = match self.deriver_role {
            Role::SignerA => &self.activation_context.signer_set().signer_a,
            Role::SignerB => &self.activation_context.signer_set().signer_b,
            _ => unreachable!("require_signer_role accepted only signer roles"),
        };
        validate_cloudflare_recipient_proof_bundle_envelope_for_activation_context_v1(
            "signing_worker_bundle",
            &envelope,
            &self.activation_context,
            expected_signer,
        )
    }

    /// Returns the transcript digest bound to this activation delivery.
    pub fn transcript_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.validate()?;
        Ok(self.activation_context.transcript_digest())
    }
}

/// Deterministic aggregate of two direct Deriver activation deliveries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1 {
    /// Shared activation context for both Deriver deliveries.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Signer A direct activation delivery.
    pub deriver_a_delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    /// Signer B direct activation delivery.
    pub deriver_b_delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
}

impl CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1 {
    /// Creates a deterministic aggregate from exactly one Signer A and one Signer B delivery.
    pub fn new(
        first: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
        second: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    ) -> RouterAbProtocolResult<Self> {
        first.validate()?;
        second.validate()?;
        let (deriver_a_delivery, deriver_b_delivery) = match (
            first.deriver_role,
            second.deriver_role,
        ) {
            (Role::SignerA, Role::SignerB) => (first, second),
            (Role::SignerB, Role::SignerA) => (second, first),
            (Role::SignerA, Role::SignerA) | (Role::SignerB, Role::SignerB) => {
                return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "direct SigningWorker activation deliveries must include one Signer A and one Signer B bundle",
                    ));
            }
            _ => unreachable!("direct delivery validation accepts only signer roles"),
        };
        if deriver_a_delivery.activation_context != deriver_b_delivery.activation_context {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "direct SigningWorker activation deliveries do not share one activation context",
            ));
        }
        let aggregate = Self {
            activation_context: deriver_a_delivery.activation_context.clone(),
            deriver_a_delivery,
            deriver_b_delivery,
        };
        aggregate.validate()?;
        Ok(aggregate)
    }

    /// Validates the aggregate and both single-Deriver deliveries.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.activation_context.validate()?;
        self.deriver_a_delivery.validate()?;
        self.deriver_b_delivery.validate()?;
        if self.deriver_a_delivery.deriver_role != Role::SignerA
            || self.deriver_b_delivery.deriver_role != Role::SignerB
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "direct SigningWorker activation aggregate has non-canonical Deriver ordering",
            ));
        }
        if self.deriver_a_delivery.activation_context == self.activation_context
            && self.deriver_b_delivery.activation_context == self.activation_context
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "direct SigningWorker activation aggregate context drifted",
        ))
    }

    /// Converts the reconciled direct deliveries into the existing aggregate activation request.
    pub fn to_recipient_proof_bundle_activation_request(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerRecipientProofBundleActivationRequestV1>
    {
        self.validate()?;
        let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
            self.deriver_a_delivery.signing_worker_bundle.clone(),
            self.deriver_b_delivery.signing_worker_bundle.clone(),
        )?;
        let request = CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
            activation_context: self.activation_context.clone(),
            activation,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Pending direct SigningWorker activation delivery stored until the peer Deriver arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "waiting_for", rename_all = "snake_case")]
pub enum CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1 {
    /// Signer A delivery arrived first.
    SignerB {
        /// Signer A direct activation delivery.
        deriver_a_delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    },
    /// Signer B delivery arrived first.
    SignerA {
        /// Signer B direct activation delivery.
        deriver_b_delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    },
}

impl CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1 {
    /// Creates a pending record from the first direct activation delivery.
    pub fn new(
        delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    ) -> RouterAbProtocolResult<Self> {
        delivery.validate()?;
        let record = match delivery.deriver_role {
            Role::SignerA => Self::SignerB {
                deriver_a_delivery: delivery,
            },
            Role::SignerB => Self::SignerA {
                deriver_b_delivery: delivery,
            },
            _ => unreachable!("direct delivery validation accepts only signer roles"),
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the stored first delivery.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::SignerB { deriver_a_delivery } => {
                deriver_a_delivery.validate()?;
                if deriver_a_delivery.deriver_role == Role::SignerA {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "direct activation pending record waiting for Signer B must store Signer A",
                    ))
                }
            }
            Self::SignerA { deriver_b_delivery } => {
                deriver_b_delivery.validate()?;
                if deriver_b_delivery.deriver_role == Role::SignerB {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "direct activation pending record waiting for Signer A must store Signer B",
                    ))
                }
            }
        }
    }

    /// Returns the lifecycle id shared by all deliveries in this pending record.
    pub fn lifecycle_id(&self) -> &str {
        match self {
            Self::SignerB { deriver_a_delivery } => {
                &deriver_a_delivery
                    .activation_context
                    .lifecycle()
                    .lifecycle_id
            }
            Self::SignerA { deriver_b_delivery } => {
                &deriver_b_delivery
                    .activation_context
                    .lifecycle()
                    .lifecycle_id
            }
        }
    }

    /// Returns the transcript digest shared by all deliveries in this pending record.
    pub fn transcript_digest(&self) -> PublicDigest32 {
        match self {
            Self::SignerB { deriver_a_delivery } => {
                deriver_a_delivery.activation_context.transcript_digest()
            }
            Self::SignerA { deriver_b_delivery } => {
                deriver_b_delivery.activation_context.transcript_digest()
            }
        }
    }

    /// Returns the role that has already delivered.
    pub fn received_deriver_role(&self) -> Role {
        match self {
            Self::SignerB { .. } => Role::SignerA,
            Self::SignerA { .. } => Role::SignerB,
        }
    }

    /// Returns the role still needed to complete activation.
    pub fn waiting_for_deriver_role(&self) -> Role {
        match self {
            Self::SignerB { .. } => Role::SignerB,
            Self::SignerA { .. } => Role::SignerA,
        }
    }

    /// Applies another direct delivery and returns either the unchanged pending record or aggregate.
    pub fn apply_delivery(
        &self,
        delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    ) -> RouterAbProtocolResult<
        CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1,
    > {
        self.validate()?;
        delivery.validate()?;
        match self {
            Self::SignerB { deriver_a_delivery } => match delivery.deriver_role {
                Role::SignerA if *deriver_a_delivery == delivery => {
                    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::pending(self.clone())
                }
                Role::SignerA => Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "direct activation Signer A delivery conflicts with stored Signer A delivery",
                )),
                Role::SignerB => {
                    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::ready(
                        CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1::new(
                            deriver_a_delivery.clone(),
                            delivery,
                        )?,
                    )
                }
                _ => unreachable!("direct delivery validation accepts only signer roles"),
            },
            Self::SignerA { deriver_b_delivery } => match delivery.deriver_role {
                Role::SignerB if *deriver_b_delivery == delivery => {
                    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::pending(self.clone())
                }
                Role::SignerB => Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "direct activation Signer B delivery conflicts with stored Signer B delivery",
                )),
                Role::SignerA => {
                    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::ready(
                        CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1::new(
                            delivery,
                            deriver_b_delivery.clone(),
                        )?,
                    )
                }
                _ => unreachable!("direct delivery validation accepts only signer roles"),
            },
        }
    }
}

/// Result of storing one direct SigningWorker activation delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1 {
    /// One Deriver delivery is stored and the peer delivery is still needed.
    Pending {
        /// Stored pending delivery record.
        record: CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
    },
    /// Both Deriver deliveries are present and activation can be applied.
    Ready {
        /// Deterministic aggregate of the two direct deliveries.
        aggregate: CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1,
    },
}

impl CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1 {
    /// Creates a validated pending outcome.
    pub fn pending(
        record: CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let outcome = Self::Pending { record };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Creates a validated ready outcome.
    pub fn ready(
        aggregate: CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1,
    ) -> RouterAbProtocolResult<Self> {
        let outcome = Self::Ready { aggregate };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Validates the outcome branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Pending { record } => record.validate(),
            Self::Ready { aggregate } => aggregate.validate(),
        }
    }

    /// Validates this outcome against the delivery that produced it.
    pub fn validate_for_delivery(
        &self,
        delivery: &CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        delivery.validate()?;
        match self {
            Self::Pending { record } => {
                if record.transcript_digest() == delivery.activation_context.transcript_digest()
                    && (record.received_deriver_role() == delivery.deriver_role
                        || record.waiting_for_deriver_role() == delivery.deriver_role)
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "direct activation pending outcome does not match delivery",
                    ))
                }
            }
            Self::Ready { aggregate } => {
                if aggregate.activation_context == delivery.activation_context
                    && (aggregate.deriver_a_delivery == *delivery
                        || aggregate.deriver_b_delivery == *delivery)
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "direct activation ready outcome does not match delivery",
                    ))
                }
            }
        }
    }
}

/// Private route receipt for one direct SigningWorker activation delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1 {
    /// The peer Deriver delivery has not arrived yet.
    Pending {
        /// Activation lifecycle id.
        lifecycle_id: String,
        /// Activation transcript digest.
        transcript_digest: PublicDigest32,
        /// Deriver role accepted by this request.
        received_deriver_role: Role,
        /// Deriver role still required.
        waiting_for_deriver_role: Role,
    },
    /// The second delivery completed activation.
    Activated {
        /// Generic SigningWorker output activation receipt.
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
}

impl CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1 {
    /// Creates a pending direct activation receipt from a stored pending record.
    pub fn pending(
        record: &CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        record.validate()?;
        let receipt = Self::Pending {
            lifecycle_id: record.lifecycle_id().to_owned(),
            transcript_digest: record.transcript_digest(),
            received_deriver_role: record.received_deriver_role(),
            waiting_for_deriver_role: record.waiting_for_deriver_role(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Creates an activated direct activation receipt.
    pub fn activated(
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self::Activated { receipt };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Pending {
                lifecycle_id,
                received_deriver_role,
                waiting_for_deriver_role,
                ..
            } => {
                require_non_empty("direct activation lifecycle_id", lifecycle_id)?;
                require_signer_role(*received_deriver_role)?;
                require_signer_role(*waiting_for_deriver_role)?;
                if received_deriver_role == waiting_for_deriver_role {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "direct activation pending receipt cannot wait for received role",
                    ));
                }
                Ok(())
            }
            Self::Activated { receipt } => receipt.validate(),
        }
    }
}

/// SigningWorker activation request for strict opaque proof-bundle delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    /// Public context needed to verify and open SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Opaque server proof bundles from Signer A and Signer B.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
}

impl CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    /// Creates a validated SigningWorker activation request from Router public context.
    pub fn new(
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
    ) -> RouterAbProtocolResult<Self> {
        router_payload.require_recipient_role(Role::SignerA)?;
        activation.validate_for_router_payload(&router_payload)?;
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        let request = Self {
            activation_context,
            activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the activation context and opaque server bundles.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.activation_context.validate()?;
        self.activation
            .validate_for_activation_context(&self.activation_context)
    }
}

/// SigningWorker activation request for Router A/B ECDSA-HSS registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssSigningWorkerActivationRequestV1 {
    /// Typed ECDSA-HSS registration/bootstrap request admitted by Router.
    pub registration: RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    /// Public context needed to verify and open SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Opaque SigningWorker proof bundles from Deriver A and Deriver B.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
}

impl CloudflareEcdsaHssSigningWorkerActivationRequestV1 {
    /// Creates a validated ECDSA-HSS activation request from Router public context.
    pub fn new(
        registration: RouterAbEcdsaHssRegistrationBootstrapRequestV1,
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
    ) -> RouterAbProtocolResult<Self> {
        router_payload.require_recipient_role(Role::SignerA)?;
        activation.validate_for_router_payload(&router_payload)?;
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        let request = Self {
            registration,
            activation_context,
            activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates typed ECDSA metadata against the generic Router A/B activation context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.registration.validate()?;
        self.activation_context.validate()?;
        self.activation
            .validate_for_activation_context(&self.activation_context)?;
        let public_request = self.registration.to_public_router_request()?;
        let transcript_metadata = public_request.transcript_metadata()?;
        if self.activation_context.lifecycle != public_request.lifecycle
            || self.activation_context.signer_set != public_request.signer_set
            || self.activation_context.transcript_metadata != transcript_metadata
            || self.activation_context.transcript_digest != public_request.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS activation context does not match registration transcript",
            ));
        }
        Ok(())
    }

    /// Converts this typed ECDSA request into the generic proof-bundle activation body.
    pub fn to_recipient_proof_bundle_activation_request(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerRecipientProofBundleActivationRequestV1>
    {
        self.validate()?;
        let activation = CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
            activation_context: self.activation_context.clone(),
            activation: self.activation.clone(),
        };
        activation.validate()?;
        Ok(activation)
    }
}

/// SigningWorker activation-refresh request for Router A/B ECDSA-HSS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1 {
    /// Typed ECDSA-HSS activation-refresh request admitted by Router.
    pub refresh_request: RouterAbEcdsaHssActivationRefreshRequestV1,
    /// Public context needed to verify and open SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Opaque SigningWorker proof bundles from Deriver A and Deriver B.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
}

impl CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1 {
    /// Creates a validated ECDSA-HSS activation-refresh request from Router public context.
    pub fn new(
        refresh_request: RouterAbEcdsaHssActivationRefreshRequestV1,
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
    ) -> RouterAbProtocolResult<Self> {
        router_payload.require_recipient_role(Role::SignerA)?;
        activation.validate_for_router_payload(&router_payload)?;
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        let request = Self {
            refresh_request,
            activation_context,
            activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates typed refresh metadata against the generic Router A/B activation context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.refresh_request.validate()?;
        self.activation_context.validate()?;
        self.activation
            .validate_for_activation_context(&self.activation_context)?;
        let public_request = self.refresh_request.to_public_router_request()?;
        let transcript_metadata = public_request.transcript_metadata()?;
        if self.activation_context.lifecycle != public_request.lifecycle
            || self.activation_context.signer_set != public_request.signer_set
            || self.activation_context.transcript_metadata != transcript_metadata
            || self.activation_context.transcript_digest != public_request.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS activation-refresh context does not match refresh transcript",
            ));
        }
        Ok(())
    }

    /// Converts this typed refresh into the generic proof-bundle activation body.
    pub fn to_recipient_proof_bundle_activation_request(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerRecipientProofBundleActivationRequestV1>
    {
        self.validate()?;
        let activation = CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
            activation_context: self.activation_context.clone(),
            activation: self.activation.clone(),
        };
        activation.validate()?;
        Ok(activation)
    }
}

/// ECDSA-HSS SigningWorker activation receipt with generic storage evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssSigningWorkerActivationReceiptV1 {
    /// ECDSA-HSS public identity activated for normal signing.
    pub ecdsa_activation: RouterAbEcdsaHssActivationReceiptV1,
    /// Generic SigningWorker output storage receipt.
    pub signing_worker_output: CloudflareSigningWorkerOutputActivationReceiptV1,
}

impl CloudflareEcdsaHssSigningWorkerActivationReceiptV1 {
    /// Creates a validated ECDSA-HSS SigningWorker activation receipt.
    pub fn new(
        ecdsa_activation: RouterAbEcdsaHssActivationReceiptV1,
        signing_worker_output: CloudflareSigningWorkerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            ecdsa_activation,
            signing_worker_output,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates ECDSA public identity and generic output storage consistency.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.ecdsa_activation.validate()?;
        self.signing_worker_output.validate()?;
        if self.ecdsa_activation.signing_worker
            == self
                .signing_worker_output
                .active_signing_worker_state
                .signing_worker
            && self.ecdsa_activation.activation_digest_b64u
                == encode_base64url_bytes_v1(
                    self.signing_worker_output
                        .active_signing_worker_state
                        .activation_digest
                        .as_bytes(),
                )
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS activation receipt does not match SigningWorker output receipt",
        ))
    }
}

/// Returns the public digest of a SigningWorker proof-bundle activation package.
pub fn cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(
    activation: &CloudflareSigningWorkerRecipientProofBundleActivationV1,
) -> RouterAbProtocolResult<PublicDigest32> {
    activation.validate()?;
    let mut hasher = Sha256::new();
    push_hash_field_v1(
        &mut hasher,
        b"router-ab-cloudflare/server-proof-bundle-activation/v1",
    );
    push_hash_field_v1(&mut hasher, activation.deriver_a_bundle.digest().as_bytes());
    push_hash_field_v1(
        &mut hasher,
        activation.deriver_b_server_bundle.digest().as_bytes(),
    );
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(PublicDigest32::new(out))
}

/// Converts a Router A/B ECDSA-HSS context into the ECDSA-HSS crate context.
pub fn cloudflare_ecdsa_hss_stable_key_context_v1(
    context: &RouterAbEcdsaHssStableKeyContextV1,
) -> RouterAbProtocolResult<EcdsaHssStableKeyContext> {
    context.validate()?;
    let ecdsa_context =
        EcdsaHssStableKeyContext::new(*context.context_binding_digest()?.as_bytes());
    ecdsa_context.validate().map_err(map_ecdsa_hss_error_v1)?;
    Ok(ecdsa_context)
}

/// Derives the public ECDSA-HSS identity from opened SigningWorker A/B material.
pub fn cloudflare_ecdsa_hss_public_identity_from_activation_material_v1(
    registration: &RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssPublicIdentityV1> {
    registration.validate()?;
    material.validate()?;
    let public_request = registration.to_public_router_request()?;
    if material.transcript_digest != public_request.transcript_digest
        || material.recipient_identity != registration.signer_set.selected_server.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS activation material does not match registration transcript",
        ));
    }
    let ecdsa_context = cloudflare_ecdsa_hss_stable_key_context_v1(&registration.context)?;
    let client_public_key33 = decode_base64url_fixed_33_v1(
        "ECDSA-HSS registration client_public_key33_b64u",
        &registration.client_public_key33_b64u,
    )?;
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &client_public_key33,
        registration.client_share_retry_counter,
    )
    .map_err(map_ecdsa_hss_error_v1)?;
    RouterAbEcdsaHssPublicIdentityV1::new(
        encode_base64url_bytes_v1(&identity.context_binding32),
        encode_base64url_bytes_v1(&identity.client_public_key33),
        encode_base64url_bytes_v1(&identity.relayer_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_ethereum_address20),
        identity.client_share_retry_counter,
        identity.relayer_share_retry_counter,
    )
}

/// Builds a public ECDSA-HSS activation receipt from opened SigningWorker material.
pub fn cloudflare_ecdsa_hss_activation_receipt_from_material_v1(
    request: &CloudflareEcdsaHssSigningWorkerActivationRequestV1,
    material: &CloudflareServerOutputMaterialRecordV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<RouterAbEcdsaHssActivationReceiptV1> {
    request.validate()?;
    let public_identity = cloudflare_ecdsa_hss_public_identity_from_activation_material_v1(
        &request.registration,
        material,
    )?;
    let selected_worker = request
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    let activation_digest =
        cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(&request.activation)?;
    let receipt = RouterAbEcdsaHssActivationReceiptV1 {
        context: request.registration.context.clone(),
        public_identity,
        signing_worker: selected_worker,
        activation_epoch: request
            .activation_context
            .lifecycle()
            .root_share_epoch
            .as_str()
            .to_owned(),
        activation_digest_b64u: encode_base64url_bytes_v1(activation_digest.as_bytes()),
        activated_at_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Builds a public ECDSA-HSS activation receipt from refreshed SigningWorker material.
pub fn cloudflare_ecdsa_hss_activation_refresh_receipt_from_material_v1(
    request: &CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1,
    material: &CloudflareServerOutputMaterialRecordV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<RouterAbEcdsaHssActivationReceiptV1> {
    request.validate()?;
    let selected_worker = request
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    let scope = RouterAbEcdsaHssNormalSigningScopeV1::new(
        request.refresh_request.context.clone(),
        request.refresh_request.public_identity.clone(),
        selected_worker.clone(),
        request.refresh_request.next_activation_epoch.clone(),
    )?;
    let derived_identity =
        cloudflare_ecdsa_hss_public_identity_from_normal_signing_material_v1(&scope, material)?;
    if derived_identity != request.refresh_request.public_identity {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS refreshed activation material does not match public identity",
        ));
    }
    let activation_digest =
        cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(&request.activation)?;
    let receipt = RouterAbEcdsaHssActivationReceiptV1 {
        context: request.refresh_request.context.clone(),
        public_identity: request.refresh_request.public_identity.clone(),
        signing_worker: selected_worker,
        activation_epoch: request.refresh_request.next_activation_epoch.clone(),
        activation_digest_b64u: encode_base64url_bytes_v1(activation_digest.as_bytes()),
        activated_at_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Builds a normal-signing scope from a validated ECDSA-HSS activation receipt.
pub fn cloudflare_ecdsa_hss_normal_signing_scope_from_activation_receipt_v1(
    receipt: &RouterAbEcdsaHssActivationReceiptV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssNormalSigningScopeV1> {
    receipt.validate()?;
    RouterAbEcdsaHssNormalSigningScopeV1::new(
        receipt.context.clone(),
        receipt.public_identity.clone(),
        receipt.signing_worker.clone(),
        receipt.activation_epoch.clone(),
    )
}

fn cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
) -> RouterAbProtocolResult<String> {
    scope.validate()?;
    router_ab_ecdsa_hss_active_state_session_id_v1(&scope.context, &scope.activation_epoch)
}

/// Derives the ECDSA-HSS identity implied by active SigningWorker material.
pub fn cloudflare_ecdsa_hss_public_identity_from_normal_signing_material_v1(
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssPublicIdentityV1> {
    scope.validate()?;
    material.validate()?;
    if material.recipient_identity != scope.signing_worker.server_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS normal-signing material recipient does not match scope SigningWorker",
        ));
    }
    let ecdsa_context = cloudflare_ecdsa_hss_stable_key_context_v1(&scope.context)?;
    let client_public_key33 = decode_base64url_fixed_33_v1(
        "ECDSA-HSS normal signing client_public_key33_b64u",
        &scope.public_identity.client_public_key33_b64u,
    )?;
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &client_public_key33,
        scope.public_identity.client_share_retry_counter,
    )
    .map_err(map_ecdsa_hss_error_v1)?;
    RouterAbEcdsaHssPublicIdentityV1::new(
        encode_base64url_bytes_v1(&identity.context_binding32),
        encode_base64url_bytes_v1(&identity.client_public_key33),
        encode_base64url_bytes_v1(&identity.relayer_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_ethereum_address20),
        identity.client_share_retry_counter,
        identity.relayer_share_retry_counter,
    )
}

/// Validates that active SigningWorker state and material belong to an ECDSA-HSS scope.
pub fn validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1(
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
    active_signing_worker: &ActiveSigningWorkerStateV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<()> {
    scope.validate()?;
    active_signing_worker.validate()?;
    material.validate()?;
    if active_signing_worker.account_id != scope.context.wallet_id
        || active_signing_worker.session_id
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(scope)?
        || active_signing_worker.signing_worker != scope.signing_worker
        || material.transcript_digest != active_signing_worker.activation_transcript_digest
        || material.recipient_identity != active_signing_worker.signing_worker.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS normal-signing active state does not match scope",
        ));
    }
    let derived_identity =
        cloudflare_ecdsa_hss_public_identity_from_normal_signing_material_v1(scope, material)?;
    if derived_identity == scope.public_identity {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "ECDSA-HSS normal-signing active material does not match public identity",
    ))
}

/// Builds the active SigningWorker state descriptor from a validated activation request.
pub fn cloudflare_active_signing_worker_state_from_activation_request_v1(
    request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    signing_worker_material_handle: impl Into<String>,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    request.validate()?;
    let lifecycle = request.activation_context.lifecycle();
    let selected_server = request
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    ActiveSigningWorkerStateV1::new(
        lifecycle.account_id.clone(),
        lifecycle.session_id.clone(),
        request
            .activation_context
            .transcript_metadata
            .account_public_key
            .clone(),
        selected_server,
        request.activation_context.transcript_digest(),
        cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(&request.activation)?,
        signing_worker_material_handle,
        activated_at_ms,
    )
}

/// Strict Router result after gate handling and Signer A activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterRecipientProofBundleAdmissionResponseV1 {
    /// Request was accepted, signer client bundles were aggregated, and SigningWorker activation ran.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
        /// Signer A activation receipt.
        server_activation: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Gate decision returned to the caller.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterRecipientProofBundleAdmissionResponseV1 {
    /// Creates a forwarded strict Router result.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        server_activation: CloudflareSigningWorkerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response,
            server_activation,
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped strict Router result.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates strict Router response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                server_activation,
            } => {
                response.validate()?;
                server_activation.validate()
            }
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

/// Strict Router result for ECDSA-HSS registration/bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1 {
    /// Request was accepted, client bundles were aggregated, and ECDSA activation ran.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
        /// ECDSA-HSS SigningWorker activation receipt.
        signing_worker_activation: CloudflareEcdsaHssSigningWorkerActivationReceiptV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1 {
    /// Creates a forwarded ECDSA-HSS registration response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        signing_worker_activation: CloudflareEcdsaHssSigningWorkerActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response,
            signing_worker_activation,
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped ECDSA-HSS registration response.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates ECDSA-HSS registration response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                signing_worker_activation,
            } => {
                response.validate()?;
                signing_worker_activation.validate()
            }
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

/// Strict Router result for ECDSA-HSS explicit export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterEcdsaHssExportAdmissionResponseV1 {
    /// Request was accepted and client export bundles were aggregated.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterEcdsaHssExportAdmissionResponseV1 {
    /// Creates a forwarded ECDSA-HSS export response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded { response };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped ECDSA-HSS export response.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates ECDSA-HSS export response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded { response } => response.validate(),
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

/// Strict Router result for ECDSA-HSS recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterEcdsaHssRecoveryAdmissionResponseV1 {
    /// Request was accepted and client recovery bundles were aggregated.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterEcdsaHssRecoveryAdmissionResponseV1 {
    /// Creates a forwarded ECDSA-HSS recovery response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded { response };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped ECDSA-HSS recovery response.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates ECDSA-HSS recovery response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded { response } => response.validate(),
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

/// Strict Router result for ECDSA-HSS activation refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterEcdsaHssActivationRefreshAdmissionResponseV1 {
    /// Request was accepted, client bundles were aggregated, and ECDSA activation refreshed.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
        /// ECDSA-HSS SigningWorker activation-refresh receipt.
        signing_worker_activation: CloudflareEcdsaHssSigningWorkerActivationReceiptV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterEcdsaHssActivationRefreshAdmissionResponseV1 {
    /// Creates a forwarded ECDSA-HSS refresh response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        signing_worker_activation: CloudflareEcdsaHssSigningWorkerActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response,
            signing_worker_activation,
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped ECDSA-HSS refresh response.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates ECDSA-HSS refresh response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                signing_worker_activation,
            } => {
                response.validate()?;
                signing_worker_activation.validate()
            }
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

impl CloudflareRouterWorkerRuntimeV1 {
    /// Creates a Router runtime context from already parsed bindings.
    pub fn new(bindings: CloudflareRouterBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Router startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::Router { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::Router,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router Worker Env parsing returned non-Router bindings",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated Router bindings.
    pub fn bindings(&self) -> &CloudflareRouterBindingsV1 {
        &self.bindings
    }

    /// Returns Router-owned admission bindings.
    pub fn admission_bindings(&self) -> &CloudflareRouterAdmissionBindingsV1 {
        &self.bindings.admission
    }

    /// Builds a Router replay Durable Object call.
    pub fn replay_reserve_call(
        &self,
        request: CloudflareReplayReserveRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.replay.clone(),
            CloudflareDurableObjectRequestV1::router_replay_reserve(request)?,
        )
    }

    /// Builds a Router Wallet Session budget reserve call.
    pub fn wallet_budget_reserve_call(
        &self,
        request: CloudflareRouterWalletBudgetReserveRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.wallet_budget.clone(),
            CloudflareDurableObjectRequestV1::router_wallet_budget_reserve(request)?,
        )
    }

    /// Builds a Router Wallet Session budget grant put call.
    pub fn wallet_budget_put_grant_call(
        &self,
        request: CloudflareRouterWalletBudgetPutGrantRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.wallet_budget.clone(),
            CloudflareDurableObjectRequestV1::router_wallet_budget_put_grant(request)?,
        )
    }

    /// Builds a Router Wallet Session budget validate call.
    pub fn wallet_budget_validate_call(
        &self,
        identity: CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.wallet_budget.clone(),
            CloudflareDurableObjectRequestV1::router_wallet_budget_validate(identity)?,
        )
    }

    /// Builds a Router Wallet Session budget commit call.
    pub fn wallet_budget_commit_call(
        &self,
        identity: CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.wallet_budget.clone(),
            CloudflareDurableObjectRequestV1::router_wallet_budget_commit(identity)?,
        )
    }

    /// Builds a Router Wallet Session budget release call.
    pub fn wallet_budget_release_call(
        &self,
        request: CloudflareRouterWalletBudgetReleaseRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.wallet_budget.clone(),
            CloudflareDurableObjectRequestV1::router_wallet_budget_release(request)?,
        )
    }

    /// Builds a Router Wallet Session budget status call.
    pub fn wallet_budget_status_call(
        &self,
        request: CloudflareRouterWalletBudgetStatusRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.wallet_budget.clone(),
            CloudflareDurableObjectRequestV1::router_wallet_budget_status(request)?,
        )
    }

    /// Builds a Router replay reservation call for a typed normal-signing v2 prepare request.
    pub fn normal_signing_v2_prepare_replay_reserve_call(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        request.validate()?;
        let replay_request = CloudflareReplayReserveRequestV1::new(
            request.scope.request_id.clone(),
            request.round1_binding_digest()?,
            request.expires_at_ms,
        )?;
        self.replay_reserve_call(replay_request)
    }

    /// Builds a Router replay reservation call for a typed ECDSA-HSS prepare request.
    pub fn ecdsa_hss_evm_digest_prepare_replay_reserve_call(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        request.validate()?;
        let replay_request = CloudflareReplayReserveRequestV1::new(
            request.request_id.clone(),
            request.request_digest()?,
            request.expires_at_ms,
        )?;
        self.replay_reserve_call(replay_request)
    }

    /// Builds a Router public-lifecycle Durable Object call.
    pub fn lifecycle_put_public_state_call(
        &self,
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.lifecycle.clone(),
            CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(state)?,
        )
    }

    /// Builds a Cloudflare derivation ceremony Durable Object call.
    pub fn derivation_ceremony_put_state_call(
        &self,
        ceremony: CloudflareDerivationCeremonyV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.lifecycle.clone(),
            CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(ceremony)?,
        )
    }

    /// Validates a public request with trusted admission and builds gate-aware work.
    pub fn public_request_admission_plan_at(
        &self,
        now_unix_ms: u64,
        request: PublicRouterRequestV1,
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionPlanV1> {
        request.validate_at(now_unix_ms)?;
        trusted_admission.validate_for_request(&request)?;
        let replay_request = CloudflareReplayReserveRequestV1::new(
            request.request_nonce.clone(),
            request.router_replay_digest(),
            request.expires_at_ms,
        )?;
        let replay_reserve_call = self.replay_reserve_call(replay_request)?;
        let lifecycle_requested_put_call = self.lifecycle_put_public_state_call(
            RouterAbLifecycleStateV1::requested(request.lifecycle.clone())?,
        )?;
        let lifecycle_put_call = self.lifecycle_put_public_state_call(
            trusted_admission.lifecycle_state_for_request(&request)?,
        )?;
        let plan = if trusted_admission.allows_signer_forwarding()? {
            let (deriver_a_message, deriver_b_message) = request.to_signer_wire_messages()?;
            CloudflareRouterPublicAdmissionPlanV1::Forward {
                replay_reserve_call,
                lifecycle_requested_put_call,
                lifecycle_put_call,
                trusted_admission,
                deriver_a_message,
                deriver_b_message,
            }
        } else {
            CloudflareRouterPublicAdmissionPlanV1::Stop {
                replay_reserve_call,
                lifecycle_requested_put_call,
                lifecycle_put_call,
                trusted_admission,
            }
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Derives trusted admission from a provider and builds gate-aware work.
    pub fn public_request_admission_plan_from_provider_at(
        &self,
        now_unix_ms: u64,
        request: PublicRouterRequestV1,
        provider: &mut impl CloudflareRouterAdmissionProviderV1,
    ) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionPlanV1> {
        let trusted_admission =
            derive_cloudflare_router_trusted_admission_from_provider_v1(&request, provider)?;
        self.public_request_admission_plan_at(now_unix_ms, request, trusted_admission)
    }

    /// Builds Router-owned admission-store calls for already trusted metadata.
    pub fn admission_store_calls_at(
        &self,
        now_unix_ms: u64,
        request: &PublicRouterRequestV1,
        metadata: CloudflareRouterTrustedRequestMetadataV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionStoreCallsV1> {
        request.validate_at(now_unix_ms)?;
        metadata.validate_for_request(request)?;
        let store_request =
            CloudflareRouterAdmissionStoreRequestV1::new(metadata, request, now_unix_ms)?;
        CloudflareRouterAdmissionStoreCallsV1::new(
            self.bindings
                .admission
                .stores
                .project_policy_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .quota_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .abuse_evaluate_call(store_request)?,
        )
    }

    /// Builds Router-owned normal-signing v2 admission-store calls for typed prepare.
    pub fn normal_signing_v2_prepare_admission_store_calls_at(
        &self,
        now_unix_ms: u64,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        admission: &CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreCallsV1> {
        request.validate_at(now_unix_ms)?;
        admission.validate_for_prepare_request(request)?;
        let store_request =
            admission.to_v1_prepare_admission_store_request(request, now_unix_ms)?;
        CloudflareRouterNormalSigningAdmissionStoreCallsV1::new(
            self.bindings
                .admission
                .stores
                .normal_signing_project_policy_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_quota_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_abuse_evaluate_call(store_request)?,
        )
    }

    /// Builds Router-owned normal-signing v2 admission-store calls for typed finalize.
    pub fn normal_signing_v2_finalize_admission_store_calls_at(
        &self,
        now_unix_ms: u64,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        admission: &CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreCallsV1> {
        request.validate_at(now_unix_ms)?;
        admission.validate_for_finalize_request(request)?;
        let store_request =
            admission.to_v1_finalize_admission_store_request(request, now_unix_ms)?;
        CloudflareRouterNormalSigningAdmissionStoreCallsV1::new(
            self.bindings
                .admission
                .stores
                .normal_signing_project_policy_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_quota_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_abuse_evaluate_call(store_request)?,
        )
    }

    /// Builds Router-owned normal-signing admission-store calls for ECDSA-HSS prepare.
    pub fn ecdsa_hss_evm_digest_prepare_admission_store_calls_at(
        &self,
        now_unix_ms: u64,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
        admission: &CloudflareRouterEcdsaHssEvmDigestPrepareAdmissionCandidateV1,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreCallsV1> {
        request.validate_at(now_unix_ms)?;
        admission.validate_for_prepare_request(request)?;
        let store_request =
            admission.to_normal_signing_admission_store_request(request, now_unix_ms)?;
        CloudflareRouterNormalSigningAdmissionStoreCallsV1::new(
            self.bindings
                .admission
                .stores
                .normal_signing_project_policy_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_quota_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_abuse_evaluate_call(store_request)?,
        )
    }

    /// Builds Router-owned normal-signing admission-store calls for ECDSA-HSS finalize.
    pub fn ecdsa_hss_evm_digest_finalize_admission_store_calls_at(
        &self,
        now_unix_ms: u64,
        request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        admission: &CloudflareRouterEcdsaHssEvmDigestFinalizeAdmissionCandidateV1,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningAdmissionStoreCallsV1> {
        request.validate_at(now_unix_ms)?;
        admission.validate_for_finalize_request(request)?;
        let store_request =
            admission.to_normal_signing_admission_store_request(request, now_unix_ms)?;
        CloudflareRouterNormalSigningAdmissionStoreCallsV1::new(
            self.bindings
                .admission
                .stores
                .normal_signing_project_policy_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_quota_evaluate_call(store_request.clone())?,
            self.bindings
                .admission
                .stores
                .normal_signing_abuse_evaluate_call(store_request)?,
        )
    }

    /// Returns the Signer A peer binding used by the Router transport wrapper.
    pub fn deriver_a_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_a
    }

    /// Returns the Signer B peer binding used by the Router transport wrapper.
    pub fn deriver_b_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_b
    }

    /// Returns the SigningWorker peer binding used by activation and normal signing.
    pub fn signing_worker_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signing_worker
    }
}

impl CloudflareDeriverAWorkerRuntimeV1 {
    /// Creates a Deriver A runtime context from parsed bindings.
    pub fn new(bindings: CloudflareSignerABindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Deriver A startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::SignerA { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::SignerA,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Deriver A Worker Env parsing returned wrong binding branch",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated Deriver A bindings.
    pub fn bindings(&self) -> &CloudflareSignerABindingsV1 {
        &self.bindings
    }

    /// Builds a Deriver A root-share presence check call.
    pub fn root_share_has_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerA,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerA,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_has(lookup)?,
        )
    }

    /// Builds a Deriver A root-share startup metadata call.
    pub fn root_share_startup_metadata_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerA,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerA,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)?,
        )
    }

    /// Returns Deriver B peer binding used by direct A/B coordination.
    pub fn deriver_b_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_b
    }

    /// Returns SigningWorker peer binding used by direct activation delivery.
    pub fn signing_worker_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signing_worker
    }

    /// Returns Deriver A's role-local root-share wire Secret descriptor.
    pub fn root_share_wire_secret(&self) -> &CloudflareRootShareWireSecretBindingV1 {
        &self.bindings.root_share_wire_secret
    }

    /// Returns Deriver A's role-local signer-envelope HPKE decrypt-key descriptors.
    pub fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        &self.bindings.envelope_decrypt_key
    }

    /// Returns Deriver A's role-local A/B peer signing-key descriptor.
    pub fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        &self.bindings.peer_signing_key
    }

    /// Returns trusted A/B peer verifying keys bound to a request signer set.
    pub fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        self.bindings
            .peer_verifying_keys
            .to_protocol_keys(signer_set)
    }
}

impl CloudflareSigningWorkerRuntimeV1 {
    /// Creates a SigningWorker runtime context from parsed bindings.
    pub fn new(bindings: CloudflareSigningWorkerBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for SigningWorker startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::SigningWorker { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::SigningWorker,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker Env parsing returned wrong binding branch",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated SigningWorker bindings.
    pub fn bindings(&self) -> &CloudflareSigningWorkerBindingsV1 {
        &self.bindings
    }

    /// Builds a server-output activation call.
    pub fn signing_worker_output_activate_call(
        &self,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_output_activate(
                activation,
                material,
                activated_at_ms,
            )?,
        )
    }

    /// Builds a direct activation delivery persistence call.
    pub fn signing_worker_direct_activation_put_call(
        &self,
        delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_direct_activation_put(delivery)?,
        )
    }

    /// Builds an active SigningWorker-state lookup call.
    pub fn active_signing_worker_state_get_call(
        &self,
        lookup: CloudflareActiveSigningWorkerStateLookupV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_output_active_state_get(lookup)?,
        )
    }

    /// Builds an active SigningWorker material lookup call.
    pub fn signing_worker_output_material_get_call(
        &self,
        lookup: CloudflareSigningWorkerOutputMaterialLookupV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_output_material_get(lookup)?,
        )
    }

    /// Builds a SigningWorker round-1 nonce persistence call.
    pub fn signing_worker_round1_put_call(
        &self,
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_round1_put(record)?,
        )
    }

    /// Builds a SigningWorker round-1 nonce take call.
    pub fn signing_worker_round1_take_call(
        &self,
        lookup: CloudflareSigningWorkerRound1LookupV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_round1_take(lookup)?,
        )
    }

    /// Builds an unbound SigningWorker Ed25519 presign-pool persistence call.
    pub fn signing_worker_ed25519_presign_pool_put_call(
        &self,
        record: CloudflareSigningWorkerEd25519PresignPoolRecordV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_ed25519_presign_pool_put(record)?,
        )
    }

    /// Builds an unbound SigningWorker Ed25519 presign-pool take call.
    pub fn signing_worker_ed25519_presign_pool_take_call(
        &self,
        lookup: CloudflareSigningWorkerEd25519PresignPoolLookupV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_ed25519_presign_pool_take(lookup)?,
        )
    }

    /// Builds a SigningWorker ECDSA presignature persistence call.
    pub fn signing_worker_ecdsa_presignature_put_call(
        &self,
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(record)?,
        )
    }

    /// Builds a SigningWorker ECDSA presignature take call.
    pub fn signing_worker_ecdsa_presignature_take_call(
        &self,
        lookup: CloudflareSigningWorkerEcdsaPresignatureLookupV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_take(lookup)?,
        )
    }

    /// Builds an unbound SigningWorker ECDSA presignature pool persistence call.
    pub fn signing_worker_ecdsa_presignature_pool_put_call(
        &self,
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_pool_put(record)?,
        )
    }

    /// Builds an unbound SigningWorker ECDSA presignature pool take call.
    pub fn signing_worker_ecdsa_presignature_pool_take_call(
        &self,
        lookup: CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            self.bindings.server_output.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_pool_take(lookup)?,
        )
    }

    /// Returns SigningWorker's server-output HPKE decrypt-key descriptor.
    pub fn server_output_decrypt_key(&self) -> &CloudflareServerOutputHpkeDecryptKeyBindingV1 {
        &self.bindings.server_output_decrypt_key
    }
}

impl CloudflareDeriverBWorkerRuntimeV1 {
    /// Creates a Deriver B runtime context from parsed bindings.
    pub fn new(bindings: CloudflareSignerBBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Deriver B startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::SignerB { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::SignerB,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Deriver B Worker Env parsing returned wrong binding branch",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated Deriver B bindings.
    pub fn bindings(&self) -> &CloudflareSignerBBindingsV1 {
        &self.bindings
    }

    /// Builds a Deriver B root-share presence check call.
    pub fn root_share_has_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerB,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerB,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_has(lookup)?,
        )
    }

    /// Builds a Deriver B root-share startup metadata call.
    pub fn root_share_startup_metadata_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerB,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerB,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)?,
        )
    }

    /// Returns Deriver A peer binding used by direct A/B coordination.
    pub fn deriver_a_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_a
    }

    /// Returns SigningWorker peer binding used by direct activation delivery.
    pub fn signing_worker_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signing_worker
    }

    /// Returns Deriver B's role-local root-share wire Secret descriptor.
    pub fn root_share_wire_secret(&self) -> &CloudflareRootShareWireSecretBindingV1 {
        &self.bindings.root_share_wire_secret
    }

    /// Returns Deriver B's role-local signer-envelope HPKE decrypt-key descriptors.
    pub fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        &self.bindings.envelope_decrypt_key
    }

    /// Returns Deriver B's role-local A/B peer signing-key descriptor.
    pub fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        &self.bindings.peer_signing_key
    }

    /// Returns trusted A/B peer verifying keys bound to a request signer set.
    pub fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        self.bindings
            .peer_verifying_keys
            .to_protocol_keys(signer_set)
    }
}

/// Preloads a Deriver A host from real Cloudflare resources.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_deriver_a_host_v1(
    env: &worker::Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    input: CloudflareSignerHostPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let metadata_call = runtime.root_share_startup_metadata_call(
        input.signer_set_id.clone(),
        input.root_share_epoch.clone(),
    )?;
    preload_cloudflare_signer_host_from_metadata_call_v1(
        env,
        metadata_call,
        CloudflareWorkerRoleV1::SignerA,
        Role::SignerA,
        runtime.root_share_wire_secret(),
        input,
    )
    .await
}

/// Preloads a Deriver B host from real Cloudflare resources.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_deriver_b_host_v1(
    env: &worker::Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    input: CloudflareSignerHostPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let metadata_call = runtime.root_share_startup_metadata_call(
        input.signer_set_id.clone(),
        input.root_share_epoch.clone(),
    )?;
    preload_cloudflare_signer_host_from_metadata_call_v1(
        env,
        metadata_call,
        CloudflareWorkerRoleV1::SignerB,
        Role::SignerB,
        runtime.root_share_wire_secret(),
        input,
    )
    .await
}

/// Preloads Signer A host after direct A/B peer requests are executed.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_deriver_a_host_with_peer_requests_v1(
    env: &worker::Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    input: CloudflareSignerHostPeerPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let peer_responses = execute_cloudflare_signer_peer_requests_v1(
        env,
        runtime.deriver_b_peer(),
        &input.peer_requests,
    )
    .await?;
    let host_input = CloudflareSignerHostPreloadInputV1::new(
        input.signer_set_id,
        input.root_share_epoch,
        peer_responses,
        input.signer_verifying_keys,
        input.random_bytes_len,
    )?;
    preload_cloudflare_deriver_a_host_v1(env, runtime, host_input).await
}

/// Preloads Signer B host after direct A/B peer requests are executed.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_deriver_b_host_with_peer_requests_v1(
    env: &worker::Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    input: CloudflareSignerHostPeerPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let peer_responses = execute_cloudflare_signer_peer_requests_v1(
        env,
        runtime.deriver_a_peer(),
        &input.peer_requests,
    )
    .await?;
    let host_input = CloudflareSignerHostPreloadInputV1::new(
        input.signer_set_id,
        input.root_share_epoch,
        peer_responses,
        input.signer_verifying_keys,
        input.random_bytes_len,
    )?;
    preload_cloudflare_deriver_b_host_v1(env, runtime, host_input).await
}

#[cfg(feature = "workers-rs")]
async fn preload_cloudflare_signer_host_from_metadata_call_v1(
    env: &worker::Env,
    metadata_call: CloudflareDurableObjectCallV1,
    worker_role: CloudflareWorkerRoleV1,
    expected_role: Role,
    root_share_wire_secret: &CloudflareRootShareWireSecretBindingV1,
    input: CloudflareSignerHostPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    let metadata_response = execute_cloudflare_durable_object_call_v1(env, &metadata_call).await?;
    let CloudflareDurableObjectResponseV1::RootShareStartupMetadata { metadata } =
        metadata_response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "root-share metadata preload returned wrong Durable Object response branch",
        ));
    };
    let root_share_wire = load_cloudflare_root_share_wire_secret_v1(
        env,
        worker_role,
        root_share_wire_secret,
        &metadata,
    )?;
    let random_bytes = cloudflare_random_bytes_v1(input.random_bytes_len)?;
    build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        cloudflare_now_unix_ms_v1()?,
        expected_role,
        input,
        metadata,
        root_share_wire.signing_root_share_wire(),
        random_bytes,
    )
}

/// Handles a trusted-admission Router request using strict proof-bundle delivery.
#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_router_recipient_proof_bundle_public_request_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: PublicRouterRequestV1,
    trusted_admission: CloudflareRouterTrustedAdmissionV1,
) -> RouterAbProtocolResult<CloudflareRouterRecipientProofBundleAdmissionResponseV1> {
    let public_request_for_derivers = request.clone();
    let plan = runtime.public_request_admission_plan_at(now_unix_ms, request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "public Router request replay reservation already exists",
        ));
    }
    let _requested_lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_requested_put_call())
            .await?;
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_signer_recipient_proof_bundle_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &public_request_for_derivers,
                    deriver_a_message,
                ),
                execute_cloudflare_signer_recipient_proof_bundle_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &public_request_for_derivers,
                    deriver_b_message,
                ),
            );
            let deriver_a_response = deriver_a_result?;
            let deriver_b_response = deriver_b_result?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                replay,
                lifecycle,
                deriver_a_response.client_bundle.clone(),
                deriver_b_response.client_bundle.clone(),
            )?;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            response.validate_for_router_payload(&router_payload)?;
            let activation = CloudflareSigningWorkerRecipientProofBundleActivationRequestV1::new(
                router_payload,
                CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
                    deriver_a_response.server_bundle,
                    deriver_b_response.server_bundle,
                )?,
            )?;
            let server_activation =
                execute_cloudflare_signing_worker_recipient_proof_bundle_activation_service_call_v1(
                    env,
                    runtime.signing_worker_peer(),
                    &activation,
                )
                .await?;
            CloudflareRouterRecipientProofBundleAdmissionResponseV1::forwarded(
                response,
                server_activation,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterRecipientProofBundleAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

/// Derives trusted Router admission by executing Router-owned admission stores.
#[cfg(feature = "workers-rs")]
pub async fn derive_cloudflare_router_trusted_admission_from_worker_stores_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &PublicRouterRequestV1,
    metadata: CloudflareRouterTrustedRequestMetadataV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    metadata.validate_for_request(request)?;
    let calls = runtime.admission_store_calls_at(now_unix_ms, request, metadata.clone())?;
    let (project_policy, quota, abuse) = futures::join!(
        execute_cloudflare_router_project_policy_evaluate_v1(env, &calls.project_policy),
        execute_cloudflare_router_quota_evaluate_v1(env, &calls.quota),
        execute_cloudflare_router_abuse_evaluate_v1(env, &calls.abuse),
    );
    let checks = CloudflareRouterAdmissionChecksV1::new(project_policy?, abuse?, quota?)?;
    derive_cloudflare_router_trusted_admission_v1(request, metadata, checks)
}

/// Derives trusted normal-signing v2 prepare admission by executing Router-owned stores.
#[cfg(feature = "workers-rs")]
pub async fn derive_cloudflare_router_normal_signing_prepare_trusted_admission_from_worker_stores_v2(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    admission: &CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_prepare_request(request)?;
    let calls = runtime.normal_signing_v2_prepare_admission_store_calls_at(
        now_unix_ms,
        request,
        admission,
    )?;
    let (project_policy, quota, abuse) = futures::join!(
        execute_cloudflare_router_normal_signing_project_policy_evaluate_v1(
            env,
            &calls.project_policy
        ),
        execute_cloudflare_router_normal_signing_quota_evaluate_v1(env, &calls.quota),
        execute_cloudflare_router_normal_signing_abuse_evaluate_v1(env, &calls.abuse),
    );
    let checks = CloudflareRouterAdmissionChecksV1::new(project_policy?, abuse?, quota?)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_v1_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted normal-signing v2 finalize admission by executing Router-owned stores.
#[cfg(feature = "workers-rs")]
pub async fn derive_cloudflare_router_normal_signing_finalize_trusted_admission_from_worker_stores_v2(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    admission: &CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_finalize_request(request)?;
    let calls = runtime.normal_signing_v2_finalize_admission_store_calls_at(
        now_unix_ms,
        request,
        admission,
    )?;
    let (project_policy, quota, abuse) = futures::join!(
        execute_cloudflare_router_normal_signing_project_policy_evaluate_v1(
            env,
            &calls.project_policy
        ),
        execute_cloudflare_router_normal_signing_quota_evaluate_v1(env, &calls.quota),
        execute_cloudflare_router_normal_signing_abuse_evaluate_v1(env, &calls.abuse),
    );
    let checks = CloudflareRouterAdmissionChecksV1::new(project_policy?, abuse?, quota?)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_v1_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted ECDSA-HSS prepare admission by executing Router-owned stores.
#[cfg(feature = "workers-rs")]
pub async fn derive_cloudflare_router_ecdsa_hss_evm_digest_prepare_trusted_admission_from_worker_stores_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    admission: &CloudflareRouterEcdsaHssEvmDigestPrepareAdmissionCandidateV1,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_prepare_request(request)?;
    let calls = runtime.ecdsa_hss_evm_digest_prepare_admission_store_calls_at(
        now_unix_ms,
        request,
        admission,
    )?;
    let (project_policy, quota, abuse) = futures::join!(
        execute_cloudflare_router_normal_signing_project_policy_evaluate_v1(
            env,
            &calls.project_policy
        ),
        execute_cloudflare_router_normal_signing_quota_evaluate_v1(env, &calls.quota),
        execute_cloudflare_router_normal_signing_abuse_evaluate_v1(env, &calls.abuse),
    );
    let checks = CloudflareRouterAdmissionChecksV1::new(project_policy?, abuse?, quota?)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_normal_signing_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted ECDSA-HSS finalize admission by executing Router-owned stores.
#[cfg(feature = "workers-rs")]
pub async fn derive_cloudflare_router_ecdsa_hss_evm_digest_finalize_trusted_admission_from_worker_stores_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    admission: &CloudflareRouterEcdsaHssEvmDigestFinalizeAdmissionCandidateV1,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_finalize_request(request)?;
    let calls = runtime.ecdsa_hss_evm_digest_finalize_admission_store_calls_at(
        now_unix_ms,
        request,
        admission,
    )?;
    let (project_policy, quota, abuse) = futures::join!(
        execute_cloudflare_router_normal_signing_project_policy_evaluate_v1(
            env,
            &calls.project_policy
        ),
        execute_cloudflare_router_normal_signing_quota_evaluate_v1(env, &calls.quota),
        execute_cloudflare_router_normal_signing_abuse_evaluate_v1(env, &calls.abuse),
    );
    let checks = CloudflareRouterAdmissionChecksV1::new(project_policy?, abuse?, quota?)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_normal_signing_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted Router admission from a verified JWT plus Router-owned stores.
#[cfg(feature = "workers-rs")]
pub async fn derive_cloudflare_router_trusted_admission_from_worker_jwt_v1<Verifier>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &PublicRouterRequestV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    let mut session = CloudflareRouterJwtSessionProviderV1::new(
        runtime.admission_bindings().jwt.clone(),
        authorization,
        now_unix_ms,
        trusted_source_digest,
        verifier,
    )?;
    let metadata = session.verify_public_request_session(request)?;
    derive_cloudflare_router_trusted_admission_from_worker_stores_v1(
        env,
        runtime,
        now_unix_ms,
        request,
        metadata,
    )
    .await
}

/// Fetches the configured JWKS URL and builds the Ed25519 JWT verifier.
#[cfg(feature = "workers-rs")]
pub async fn load_cloudflare_router_ed25519_jwks_jwt_verifier_v1(
    binding: &CloudflareRouterJwtVerifierBindingV1,
) -> RouterAbProtocolResult<CloudflareRouterEd25519JwksJwtVerifierV1> {
    binding.validate()?;
    let url = worker::Url::parse(&binding.jwks_url).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Router JWT JWKS URL parse failed: {err}"),
        )
    })?;
    let mut response = worker::Fetch::Url(url).send().await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Router JWT JWKS fetch failed: {err}"),
        )
    })?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "Router JWT JWKS fetch returned HTTP {}",
                response.status_code()
            ),
        ));
    }
    let jwks_json = response.text().await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Router JWT JWKS response body read failed: {err}"),
        )
    })?;
    CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
}

/// Parses the strict Router Bearer authorization header.
#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_bearer_authorization_from_request_v1(
    request: &worker::Request,
) -> RouterAbProtocolResult<CloudflareRouterBearerAuthorizationV1> {
    let header = request
        .headers()
        .get("authorization")
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("Router authorization header read failed: {err}"),
            )
        })?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                "Router public request requires Authorization header",
            )
        })?;
    CloudflareRouterBearerAuthorizationV1::from_authorization_header(&header)
}

/// Hashes trusted Cloudflare edge source metadata for admission decisions.
#[cfg(feature = "workers-rs")]
pub fn cloudflare_trusted_source_digest_v1(
    request: &worker::Request,
) -> RouterAbProtocolResult<PublicDigest32> {
    let headers = request.headers();
    let connecting_ip = headers.get("cf-connecting-ip").map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!("cf-connecting-ip header read failed: {err}"),
        )
    })?;
    let ray_id = headers.get("cf-ray").map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!("cf-ray header read failed: {err}"),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"router-ab-cloudflare-trusted-source/v1");
    hash_optional_header_v1(&mut hasher, b"cf-connecting-ip", connecting_ip.as_deref());
    hash_optional_header_v1(&mut hasher, b"cf-ray", ray_id.as_deref());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(PublicDigest32::new(bytes))
}

/// Handles a public Router request whose admission is derived inside the Router Worker.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: PublicRouterRequestV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterRecipientProofBundleAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        env,
        runtime,
        now_unix_ms,
        &request,
        authorization,
        trusted_source_digest,
        verifier,
    )
    .await?;
    handle_cloudflare_router_recipient_proof_bundle_public_request_v1(
        env,
        runtime,
        now_unix_ms,
        request,
        trusted_admission,
    )
    .await
}

#[cfg(feature = "workers-rs")]
fn emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1(
    request: &RouterAbEcdsaHssExplicitExportRequestV1,
    decision: router_ab_core::EcdsaHssExplicitExportAuditDecisionV1,
    reason_code: &str,
) -> RouterAbProtocolResult<()> {
    request.validate()?;
    require_non_empty("ECDSA-HSS export audit reason_code", reason_code)?;
    let request_digest = request.request_digest()?;
    let event = AuditEventV1::EcdsaHssExplicitExportDecision {
        operation: "ecdsa_hss_explicit_key_export".to_owned(),
        request_id: request.export_nonce.clone(),
        request_digest_b64u: encode_base64url_bytes_v1(request_digest.as_bytes()),
        wallet_id: request.context.wallet_id.clone(),
        account_id: request.lifecycle.account_id.clone(),
        session_id: request.lifecycle.session_id.clone(),
        selected_server_id: request.lifecycle.selected_server_id.clone(),
        ecdsa_threshold_key_id: request.context.ecdsa_threshold_key_id.clone(),
        signing_root_id: request.context.signing_root_id.clone(),
        signing_root_version: request.context.signing_root_version.clone(),
        key_purpose: request.context.key_purpose.clone(),
        key_version: request.context.key_version.clone(),
        export_authorization_digest_b64u: request.export_authorization_digest_b64u.clone(),
        decision,
        reason_code: reason_code.to_owned(),
    };
    let serialized = serde_json::to_string(&event).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("ECDSA-HSS export audit event serialization failed: {err}"),
        )
    })?;
    worker::console_log!("router_ab_audit_event_v1={serialized}");
    Ok(())
}

/// Handles an authenticated public Router ECDSA-HSS registration/bootstrap request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let public_request = request.to_public_router_request()?;
    let public_request_for_derivers = public_request.clone();
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        env,
        runtime,
        now_unix_ms,
        &public_request,
        authorization,
        trusted_source_digest,
        verifier,
    )
    .await?;
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "ECDSA-HSS registration replay reservation already exists",
        ));
    }
    let _requested_lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_requested_put_call())
            .await?;
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_a_message,
                ),
                execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_b_message,
                ),
            );
            let deriver_a_response = deriver_a_result?;
            let deriver_b_response = deriver_b_result?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                replay,
                lifecycle,
                deriver_a_response.client_bundle.clone(),
                deriver_b_response.client_bundle.clone(),
            )?;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            response.validate_for_router_payload(&router_payload)?;
            let activation = CloudflareEcdsaHssSigningWorkerActivationRequestV1::new(
                request,
                router_payload,
                CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
                    deriver_a_response.server_bundle,
                    deriver_b_response.server_bundle,
                )?,
            )?;
            let signing_worker_activation =
                execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1(
                    env,
                    runtime.signing_worker_peer(),
                    &activation,
                )
                .await?;
            CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1::forwarded(
                response,
                signing_worker_activation,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

/// Handles an authenticated public Router ECDSA-HSS explicit export request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaHssExplicitExportRequestV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterEcdsaHssExportAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let public_request = request.to_public_router_request()?;
    let public_request_for_derivers = public_request.clone();
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        env,
        runtime,
        now_unix_ms,
        &public_request,
        authorization,
        trusted_source_digest,
        verifier,
    )
    .await?;
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1(
            &request,
            router_ab_core::EcdsaHssExplicitExportAuditDecisionV1::Rejected,
            "replay_reservation_exists",
        )?;
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "ECDSA-HSS export replay reservation already exists",
        ));
    }
    let _requested_lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_requested_put_call())
            .await?;
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_a_message,
                ),
                execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_b_message,
                ),
            );
            let deriver_a_response = match deriver_a_result {
                Ok(response) => response,
                Err(err) => {
                    emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1(
                        &request,
                        router_ab_core::EcdsaHssExplicitExportAuditDecisionV1::Rejected,
                        "deriver_a_export_service_error",
                    )?;
                    return Err(err);
                }
            };
            let deriver_b_response = match deriver_b_result {
                Ok(response) => response,
                Err(err) => {
                    emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1(
                        &request,
                        router_ab_core::EcdsaHssExplicitExportAuditDecisionV1::Rejected,
                        "deriver_b_export_service_error",
                    )?;
                    return Err(err);
                }
            };
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                replay,
                lifecycle,
                deriver_a_response.client_bundle,
                deriver_b_response.client_bundle,
            )?;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            response.validate_for_router_payload(&router_payload)?;
            emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1(
                &request,
                router_ab_core::EcdsaHssExplicitExportAuditDecisionV1::Forwarded,
                "forwarded_client_export_bundles",
            )?;
            CloudflareRouterEcdsaHssExportAdmissionResponseV1::forwarded(response)
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => {
            emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1(
                &request,
                router_ab_core::EcdsaHssExplicitExportAuditDecisionV1::Stopped,
                "router_admission_stopped_export",
            )?;
            CloudflareRouterEcdsaHssExportAdmissionResponseV1::stopped(
                replay,
                lifecycle,
                trusted_admission.decision.clone(),
            )
        }
    }
}

/// Handles an authenticated public Router ECDSA-HSS recovery request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ecdsa_hss_recovery_authenticated_public_request_v1<Verifier>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaHssRecoveryRequestV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterEcdsaHssRecoveryAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let public_request = request.to_public_router_request()?;
    let public_request_for_derivers = public_request.clone();
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        env,
        runtime,
        now_unix_ms,
        &public_request,
        authorization,
        trusted_source_digest,
        verifier,
    )
    .await?;
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "ECDSA-HSS recovery replay reservation already exists",
        ));
    }
    let _requested_lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_requested_put_call())
            .await?;
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_ecdsa_hss_deriver_recovery_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_a_message,
                ),
                execute_cloudflare_ecdsa_hss_deriver_recovery_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_b_message,
                ),
            );
            let deriver_a_response = deriver_a_result?;
            let deriver_b_response = deriver_b_result?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                replay,
                lifecycle,
                deriver_a_response.client_bundle,
                deriver_b_response.client_bundle,
            )?;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            response.validate_for_router_payload(&router_payload)?;
            CloudflareRouterEcdsaHssRecoveryAdmissionResponseV1::forwarded(response)
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterEcdsaHssRecoveryAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

/// Handles an authenticated public Router ECDSA-HSS activation-refresh request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ecdsa_hss_activation_refresh_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaHssActivationRefreshRequestV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterEcdsaHssActivationRefreshAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let public_request = request.to_public_router_request()?;
    let public_request_for_derivers = public_request.clone();
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        env,
        runtime,
        now_unix_ms,
        &public_request,
        authorization,
        trusted_source_digest,
        verifier,
    )
    .await?;
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "ECDSA-HSS activation-refresh replay reservation already exists",
        ));
    }
    let _requested_lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_requested_put_call())
            .await?;
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_ecdsa_hss_deriver_activation_refresh_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_a_message,
                ),
                execute_cloudflare_ecdsa_hss_deriver_activation_refresh_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_b_message,
                ),
            );
            let deriver_a_response = deriver_a_result?;
            let deriver_b_response = deriver_b_result?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                replay,
                lifecycle,
                deriver_a_response.client_bundle.clone(),
                deriver_b_response.client_bundle.clone(),
            )?;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            response.validate_for_router_payload(&router_payload)?;
            let activation = CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1::new(
                request,
                router_payload,
                CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
                    deriver_a_response.server_bundle,
                    deriver_b_response.server_bundle,
                )?,
            )?;
            let signing_worker_activation =
                execute_cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_call_v1(
                    env,
                    runtime.signing_worker_peer(),
                    &activation,
                )
                .await?;
            CloudflareRouterEcdsaHssActivationRefreshAdmissionResponseV1::forwarded(
                response,
                signing_worker_activation,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterEcdsaHssActivationRefreshAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

#[cfg(feature = "workers-rs")]
const CLOUDFLARE_ROUTER_WALLET_BUDGET_SIGNATURE_USES_PER_SIGNING_V1: u32 = 1;
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_ROUTER_WALLET_BUDGET_RESERVATION_TTL_MS_V1: u64 = 10_000;
#[cfg(feature = "workers-rs")]
const ED25519_BUDGET_REQUEST_DIGEST_VERSION_V1: &str = "router_ab_ed25519_budget_request_digest_v1";
#[cfg(feature = "workers-rs")]
const ECDSA_HSS_BUDGET_OPERATION_ID_VERSION_V1: &str = "router_ab_ecdsa_hss_budget_operation_id_v1";

/// Public budget projection attached to strict normal-signing responses.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareRouterWalletBudgetStatusWireV1 {
    /// Remaining committed uses after finalized signatures.
    pub remaining_uses: u32,
    /// Remaining committed uses after finalized signatures.
    pub committed_remaining_uses: u32,
    /// Uses currently reserved by in-flight prepare requests.
    pub reserved_uses: u32,
    /// Uses available for a new reservation now.
    pub available_uses: u32,
    /// Monotonic Durable Object projection version.
    pub projection_version: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

#[cfg(feature = "workers-rs")]
impl CloudflareRouterWalletBudgetStatusWireV1 {
    fn from_status(status: CloudflareRouterWalletBudgetStatusV1) -> RouterAbProtocolResult<Self> {
        status.validate()?;
        Ok(Self {
            remaining_uses: status.committed_remaining_uses,
            committed_remaining_uses: status.committed_remaining_uses,
            reserved_uses: status.reserved_uses,
            available_uses: status.available_uses,
            projection_version: status.projection_version,
            expires_at_ms: status.expires_at_ms,
        })
    }
}

/// Budget metadata required on prepare/finalize split-signing finalize requests.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterWalletBudgetFinalizeMetadataV1 {
    /// Reservation id returned by prepare.
    pub budget_reservation_id: String,
    /// Canonical operation id returned by prepare.
    pub budget_operation_id: String,
}

#[cfg(feature = "workers-rs")]
impl CloudflareRouterWalletBudgetFinalizeMetadataV1 {
    /// Builds validated finalize metadata.
    pub fn new(
        budget_reservation_id: impl Into<String>,
        budget_operation_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            budget_reservation_id: budget_reservation_id.into(),
            budget_operation_id: budget_operation_id.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates required budget metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("budget_reservation_id", &self.budget_reservation_id)?;
        require_non_empty("budget_operation_id", &self.budget_operation_id)
    }
}

/// Prepare response carrying the budget reservation the client must present at finalize.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareRouterWalletBudgetedPrepareResponseV1<T> {
    #[serde(flatten)]
    pub response: T,
    pub budget_reservation_id: String,
    pub budget_operation_id: String,
    pub budget_status: CloudflareRouterWalletBudgetStatusWireV1,
}

#[cfg(feature = "workers-rs")]
impl<T> CloudflareRouterWalletBudgetedPrepareResponseV1<T> {
    fn new(
        response: T,
        budget_reservation_id: impl Into<String>,
        budget_operation_id: impl Into<String>,
        budget_status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            response,
            budget_reservation_id: budget_reservation_id.into(),
            budget_operation_id: budget_operation_id.into(),
            budget_status: CloudflareRouterWalletBudgetStatusWireV1::from_status(budget_status)?,
        };
        response.validate()?;
        Ok(response)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("budget_reservation_id", &self.budget_reservation_id)?;
        require_non_empty("budget_operation_id", &self.budget_operation_id)
    }
}

/// Finalize response carrying the committed budget projection.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloudflareRouterWalletBudgetedFinalizeResponseV1<T> {
    #[serde(flatten)]
    pub response: T,
    pub budget_status: CloudflareRouterWalletBudgetStatusWireV1,
}

#[cfg(feature = "workers-rs")]
impl<T> CloudflareRouterWalletBudgetedFinalizeResponseV1<T> {
    fn new(
        response: T,
        budget_status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        Ok(Self {
            response,
            budget_status: CloudflareRouterWalletBudgetStatusWireV1::from_status(budget_status)?,
        })
    }
}

#[cfg(feature = "workers-rs")]
#[derive(Debug, Deserialize)]
struct CloudflareRouterWalletBudgetStatusPublicRequestV1 {
    #[serde(rename = "signingGrantId")]
    signing_grant_id: Option<String>,
    #[serde(rename = "thresholdSessionId")]
    threshold_session_id: Option<String>,
}

#[cfg(feature = "workers-rs")]
impl CloudflareRouterWalletBudgetStatusPublicRequestV1 {
    fn expected_signing_grant_id(&self) -> String {
        self.signing_grant_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    fn expected_threshold_session_id(&self) -> String {
        self.threshold_session_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_owned()
    }
}

/// Local-compatible budget status response for SDK status polling.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareRouterWalletBudgetStatusPublicResponseV1 {
    pub ok: bool,
    pub signing_grant_id: String,
    pub threshold_session_id: String,
    pub status: String,
    pub committed_remaining_uses: u32,
    pub reserved_uses: u32,
    pub available_uses: u32,
    pub remaining_uses: u32,
    pub expires_at_ms: u64,
    pub projection_version: String,
}

#[cfg(feature = "workers-rs")]
impl CloudflareRouterWalletBudgetStatusPublicResponseV1 {
    fn new(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        budget_status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate()?;
        budget_status.validate()?;
        let status = if budget_status.available_uses > 0 {
            "active"
        } else {
            "exhausted"
        };
        Ok(Self {
            ok: true,
            signing_grant_id: wallet_session.signing_grant_id.clone(),
            threshold_session_id: wallet_session.threshold_session_id.clone(),
            status: status.to_owned(),
            committed_remaining_uses: budget_status.committed_remaining_uses,
            reserved_uses: budget_status.reserved_uses,
            available_uses: budget_status.available_uses,
            remaining_uses: budget_status.available_uses,
            expires_at_ms: budget_status.expires_at_ms,
            projection_version: format!(
                "wallet-budget:{}:{}:{}:{}:{}",
                wallet_session.signing_grant_id,
                budget_status.expires_at_ms,
                budget_status.committed_remaining_uses,
                budget_status.reserved_uses,
                budget_status.available_uses
            ),
        })
    }
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_budgeted_ed25519_finalize_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEd25519NormalSigningFinalizeRequestV2,
    CloudflareRouterWalletBudgetFinalizeMetadataV1,
)> {
    let (value, metadata) =
        strip_cloudflare_router_wallet_budget_finalize_metadata_v1(bytes, "Ed25519 finalize")?;
    let request = serde_json::from_value::<RouterAbEd25519NormalSigningFinalizeRequestV2>(value)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Ed25519 finalize request JSON parse failed: {err}"),
            )
        })?;
    request.validate()?;
    Ok((request, metadata))
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_budgeted_ecdsa_hss_finalize_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    CloudflareRouterWalletBudgetFinalizeMetadataV1,
)> {
    let (value, metadata) =
        strip_cloudflare_router_wallet_budget_finalize_metadata_v1(bytes, "ECDSA-HSS finalize")?;
    let request =
        serde_json::from_value::<RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1>(value)
            .map_err(|err| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("ECDSA-HSS finalize request JSON parse failed: {err}"),
                )
            })?;
    request.validate()?;
    Ok((request, metadata))
}

#[cfg(feature = "workers-rs")]
fn strip_cloudflare_router_wallet_budget_finalize_metadata_v1(
    bytes: &[u8],
    label: &str,
) -> RouterAbProtocolResult<(
    serde_json::Value,
    CloudflareRouterWalletBudgetFinalizeMetadataV1,
)> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} request JSON parse failed: {err}"),
        )
    })?;
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{label} request must be a JSON object"),
            ));
        }
    };
    let budget_reservation_id =
        take_required_json_string_field_v1(&mut object, "budget_reservation_id")?;
    let budget_operation_id =
        take_required_json_string_field_v1(&mut object, "budget_operation_id")?;
    let metadata = CloudflareRouterWalletBudgetFinalizeMetadataV1::new(
        budget_reservation_id,
        budget_operation_id,
    )?;
    Ok((serde_json::Value::Object(object), metadata))
}

#[cfg(feature = "workers-rs")]
fn take_required_json_string_field_v1(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> RouterAbProtocolResult<String> {
    let value = object.remove(field).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} is required"),
        )
    })?;
    match value {
        serde_json::Value::String(value) => {
            require_non_empty(field, &value)?;
            Ok(value)
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be a string"),
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_budget_push_len32_v1(out: &mut Vec<u8>, bytes: &[u8]) -> RouterAbProtocolResult<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "budget digest field is too large",
        )
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn cloudflare_budget_push_field_v1(
    out: &mut Vec<u8>,
    name: &str,
    value: &str,
) -> RouterAbProtocolResult<()> {
    require_non_empty(name, value)?;
    cloudflare_budget_push_len32_v1(out, name.as_bytes())?;
    cloudflare_budget_push_len32_v1(out, value.as_bytes())
}

#[cfg(feature = "workers-rs")]
fn cloudflare_budget_digest_b64u_v1(
    version: &str,
    fields: &[(&str, String)],
) -> RouterAbProtocolResult<String> {
    require_non_empty("budget digest version", version)?;
    let mut out = Vec::new();
    cloudflare_budget_push_len32_v1(&mut out, version.as_bytes())?;
    for (name, value) in fields {
        cloudflare_budget_push_field_v1(&mut out, name, value)?;
    }
    let digest = Sha256::digest(&out);
    Ok(encode_base64url_bytes_v1(&digest))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_operation_id_from_intent_v2(
    intent: &RouterAbEd25519NormalSigningIntentV2,
) -> RouterAbProtocolResult<String> {
    let operation_id = match intent {
        RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 { operation_id, .. }
        | RouterAbEd25519NormalSigningIntentV2::Nep413V1 { operation_id, .. }
        | RouterAbEd25519NormalSigningIntentV2::NearDelegateActionV1 { operation_id, .. } => {
            operation_id.clone()
        }
    };
    require_non_empty("Ed25519 budget operation_id", &operation_id)?;
    Ok(operation_id)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_prepare_budget_operation_id_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
) -> RouterAbProtocolResult<String> {
    request.validate()?;
    cloudflare_router_ed25519_operation_id_from_intent_v2(&request.intent)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_pool_hit_budget_operation_id_v2(
    request: &RouterAbEd25519PresignPoolHitFinalizeRequestV2,
) -> RouterAbProtocolResult<String> {
    request.validate()?;
    cloudflare_router_ed25519_operation_id_from_intent_v2(&request.intent)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_budget_request_digest_v2(
    scope: &NormalSigningScopeV1,
    expires_at_ms: u64,
    signing_payload_digest: PublicDigest32,
    claims_signing_worker_id: &str,
    operation_id: &str,
) -> RouterAbProtocolResult<PublicDigest32> {
    scope.validate()?;
    require_positive_ms("Ed25519 budget expires_at_ms", expires_at_ms)?;
    let digest_b64u = cloudflare_budget_digest_b64u_v1(
        ED25519_BUDGET_REQUEST_DIGEST_VERSION_V1,
        &[
            ("request_id", scope.request_id.clone()),
            ("account_id", scope.account_id.clone()),
            ("session_id", scope.session_id.clone()),
            ("scope_signing_worker_id", scope.signing_worker_id.clone()),
            (
                "claims_signing_worker_id",
                claims_signing_worker_id.to_owned(),
            ),
            ("operation_id", operation_id.to_owned()),
            ("expires_at_ms", expires_at_ms.to_string()),
            (
                "signing_payload_digest",
                encode_base64url_bytes_v1(signing_payload_digest.as_bytes()),
            ),
        ],
    )?;
    decode_public_digest_b64u_v1("Ed25519 budget request digest", &digest_b64u)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_prepare_budget_request_digest_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    operation_id: &str,
    claims_signing_worker_id: &str,
) -> RouterAbProtocolResult<PublicDigest32> {
    request.validate()?;
    cloudflare_router_ed25519_budget_request_digest_v2(
        &request.scope,
        request.expires_at_ms,
        request.admission_material()?.signing_payload_digest,
        claims_signing_worker_id,
        operation_id,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_finalize_budget_request_digest_v2(
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    operation_id: &str,
    claims_signing_worker_id: &str,
) -> RouterAbProtocolResult<PublicDigest32> {
    request.validate()?;
    cloudflare_router_ed25519_budget_request_digest_v2(
        &request.scope,
        request.expires_at_ms,
        request.signing_payload_digest(),
        claims_signing_worker_id,
        operation_id,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_pool_hit_budget_request_digest_v2(
    request: &RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    operation_id: &str,
    claims_signing_worker_id: &str,
) -> RouterAbProtocolResult<PublicDigest32> {
    request.validate()?;
    let material = request.admission_material()?;
    let digest_b64u = cloudflare_budget_digest_b64u_v1(
        ED25519_BUDGET_REQUEST_DIGEST_VERSION_V1,
        &[
            ("request_id", request.scope.request_id.clone()),
            ("account_id", request.scope.account_id.clone()),
            ("session_id", request.scope.session_id.clone()),
            (
                "scope_signing_worker_id",
                request.scope.signing_worker_id.clone(),
            ),
            (
                "claims_signing_worker_id",
                claims_signing_worker_id.to_owned(),
            ),
            ("operation_id", operation_id.to_owned()),
            ("expires_at_ms", request.expires_at_ms.to_string()),
            (
                "signing_payload_digest",
                encode_base64url_bytes_v1(material.signing_payload_digest.as_bytes()),
            ),
            (
                "pool_server_round1_handle",
                request.pool_binding.server_round1_handle.clone(),
            ),
            (
                "pool_entry_binding_digest",
                encode_base64url_bytes_v1(
                    request.pool_binding.pool_entry_binding_digest.as_bytes(),
                ),
            ),
        ],
    )?;
    decode_public_digest_b64u_v1("Ed25519 pool-hit budget request digest", &digest_b64u)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ecdsa_hss_prepare_budget_operation_id_v1(
    request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
) -> RouterAbProtocolResult<String> {
    request.validate()?;
    wallet_session.validate()?;
    cloudflare_router_ecdsa_hss_budget_operation_id_v1(
        &request.scope,
        &request.client_presignature_id,
        request.expires_at_ms,
        &request.signing_digest_b64u,
        wallet_session,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ecdsa_hss_finalize_budget_operation_id_v1(
    request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
) -> RouterAbProtocolResult<String> {
    request.validate()?;
    wallet_session.validate()?;
    cloudflare_router_ecdsa_hss_budget_operation_id_v1(
        &request.scope,
        &request.server_presignature_id,
        request.expires_at_ms,
        &request.signing_digest_b64u,
        wallet_session,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ecdsa_hss_budget_operation_id_v1(
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
    presignature_id: &str,
    expires_at_ms: u64,
    signing_digest_b64u: &str,
    wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
) -> RouterAbProtocolResult<String> {
    scope.validate()?;
    wallet_session.validate()?;
    require_non_empty("ECDSA-HSS budget presignature_id", presignature_id)?;
    let digest = cloudflare_budget_digest_b64u_v1(
        ECDSA_HSS_BUDGET_OPERATION_ID_VERSION_V1,
        &[
            (
                "threshold_session_id",
                wallet_session.threshold_session_id.clone(),
            ),
            ("wallet_id", scope.context.wallet_id.clone()),
            ("rp_id", scope.context.rp_id.clone()),
            (
                "ecdsa_threshold_key_id",
                scope.context.ecdsa_threshold_key_id.clone(),
            ),
            ("signing_root_id", scope.context.signing_root_id.clone()),
            (
                "signing_root_version",
                scope.context.signing_root_version.clone(),
            ),
            ("activation_epoch", scope.activation_epoch.clone()),
            (
                "signing_worker_id",
                wallet_session.signing_worker_id.clone(),
            ),
            (
                "scope_signing_worker_id",
                scope.signing_worker.server_id.clone(),
            ),
            (
                "context_binding_b64u",
                scope.public_identity.context_binding_b64u.clone(),
            ),
            (
                "threshold_public_key33_b64u",
                scope.public_identity.threshold_public_key33_b64u.clone(),
            ),
            ("presignature_id", presignature_id.to_owned()),
            ("expires_at_ms", expires_at_ms.to_string()),
            ("signing_digest_b64u", signing_digest_b64u.to_owned()),
        ],
    )?;
    Ok(format!("router-ab-ecdsa-hss:{digest}"))
}

#[cfg(feature = "workers-rs")]
fn decode_public_digest_b64u_v1(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<PublicDigest32> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} is not valid base64url: {err}"),
            )
        })?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes"),
        )
    })?;
    Ok(PublicDigest32::new(digest))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_wallet_budget_reservation_expires_at_ms_v1(
    now_unix_ms: u64,
    request_expires_at_ms: u64,
    wallet_session_expires_at_ms: u64,
) -> RouterAbProtocolResult<u64> {
    require_positive_ms("budget now_unix_ms", now_unix_ms)?;
    require_positive_ms("budget request_expires_at_ms", request_expires_at_ms)?;
    require_positive_ms(
        "budget wallet_session_expires_at_ms",
        wallet_session_expires_at_ms,
    )?;
    let short_ttl_expires_at_ms = now_unix_ms
        .checked_add(CLOUDFLARE_ROUTER_WALLET_BUDGET_RESERVATION_TTL_MS_V1)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "wallet budget reservation expiry overflowed",
            )
        })?;
    let expires_at_ms = request_expires_at_ms
        .min(wallet_session_expires_at_ms)
        .min(short_ttl_expires_at_ms);
    if now_unix_ms >= expires_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "wallet budget reservation window is already expired",
        ));
    }
    Ok(expires_at_ms)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_wallet_budget_reserve_request_v1(
    wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
    curve: CloudflareRouterWalletBudgetCurveV1,
    operation_id: impl Into<String>,
    request_digest: PublicDigest32,
    request_expires_at_ms: u64,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetReserveRequestV1> {
    wallet_session.validate_at(now_unix_ms)?;
    let request = CloudflareRouterWalletBudgetReserveRequestV1 {
        signing_grant_id: wallet_session.signing_grant_id.clone(),
        curve,
        threshold_session_id: wallet_session.threshold_session_id.clone(),
        signing_worker_id: wallet_session.signing_worker_id.clone(),
        operation_id: operation_id.into(),
        request_digest,
        signature_uses: CLOUDFLARE_ROUTER_WALLET_BUDGET_SIGNATURE_USES_PER_SIGNING_V1,
        expires_at_ms: cloudflare_router_wallet_budget_reservation_expires_at_ms_v1(
            now_unix_ms,
            request_expires_at_ms,
            wallet_session.expires_at_ms,
        )?,
        now_unix_ms,
    };
    request.validate()?;
    Ok(request)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_wallet_budget_identity_v1(
    wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
    metadata: &CloudflareRouterWalletBudgetFinalizeMetadataV1,
    request_digest: PublicDigest32,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetReservationIdentityV1> {
    wallet_session.validate_at(now_unix_ms)?;
    metadata.validate()?;
    CloudflareRouterWalletBudgetReservationIdentityV1::new(
        wallet_session.signing_grant_id.clone(),
        metadata.budget_reservation_id.clone(),
        wallet_session.signing_worker_id.clone(),
        metadata.budget_operation_id.clone(),
        request_digest,
        now_unix_ms,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_wallet_budget_release_request_v1(
    identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetReleaseRequestV1> {
    let request = CloudflareRouterWalletBudgetReleaseRequestV1 {
        signing_grant_id: identity.signing_grant_id.clone(),
        reservation_id: identity.reservation_id.clone(),
        signing_worker_id: identity.signing_worker_id.clone(),
        operation_id: identity.operation_id.clone(),
        request_digest: identity.request_digest,
        now_unix_ms: identity.now_unix_ms,
    };
    request.validate()?;
    Ok(request)
}

#[cfg(feature = "workers-rs")]
async fn reserve_cloudflare_router_wallet_budget_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: CloudflareRouterWalletBudgetReserveRequestV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let call = runtime.wallet_budget_reserve_call(request)?;
    execute_cloudflare_router_wallet_budget_reserve_v1(env, &call).await
}

#[cfg(feature = "workers-rs")]
async fn put_cloudflare_router_wallet_budget_grant_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: CloudflareRouterWalletBudgetPutGrantRequestV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
    let call = runtime.wallet_budget_put_grant_call(request)?;
    execute_cloudflare_router_wallet_budget_put_grant_v1(env, &call).await
}

#[cfg(feature = "workers-rs")]
async fn validate_cloudflare_router_wallet_budget_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    identity: CloudflareRouterWalletBudgetReservationIdentityV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let call = runtime.wallet_budget_validate_call(identity)?;
    execute_cloudflare_router_wallet_budget_validate_v1(env, &call).await
}

#[cfg(feature = "workers-rs")]
async fn commit_cloudflare_router_wallet_budget_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    identity: CloudflareRouterWalletBudgetReservationIdentityV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let call = runtime.wallet_budget_commit_call(identity)?;
    execute_cloudflare_router_wallet_budget_commit_v1(env, &call).await
}

#[cfg(feature = "workers-rs")]
async fn status_cloudflare_router_wallet_budget_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
    wallet_session.validate_at(now_unix_ms)?;
    let request = CloudflareRouterWalletBudgetStatusRequestV1 {
        signing_grant_id: wallet_session.signing_grant_id.clone(),
        now_unix_ms,
    };
    request.validate()?;
    let call = runtime.wallet_budget_status_call(request)?;
    execute_cloudflare_router_wallet_budget_status_v1(env, &call).await
}

#[cfg(feature = "workers-rs")]
async fn release_cloudflare_router_wallet_budget_best_effort_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
) {
    let request = match cloudflare_router_wallet_budget_release_request_v1(identity) {
        Ok(request) => request,
        Err(err) => {
            worker::console_warn!(
                "wallet_budget_release_failed: release request build failed: {:?}: {}",
                err.code(),
                err.message()
            );
            return;
        }
    };
    let call = match runtime.wallet_budget_release_call(request) {
        Ok(call) => call,
        Err(err) => {
            worker::console_warn!(
                "wallet_budget_release_failed: release call build failed: {:?}: {}",
                err.code(),
                err.message()
            );
            return;
        }
    };
    if let Err(err) = execute_cloudflare_router_wallet_budget_release_v1(env, &call).await {
        worker::console_warn!(
            "wallet_budget_release_failed: release call failed: {:?}: {}",
            err.code(),
            err.message()
        );
    }
}

#[cfg(feature = "workers-rs")]
fn require_cloudflare_router_wallet_budget_available_use_v1(
    status: &CloudflareRouterWalletBudgetStatusV1,
) -> RouterAbProtocolResult<()> {
    status.validate()?;
    if status.available_uses >= CLOUDFLARE_ROUTER_WALLET_BUDGET_SIGNATURE_USES_PER_SIGNING_V1 {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidGateDecision,
        "wallet budget exhausted",
    ))
}

/// Handles Router's private Wallet Session budget-grant issuance route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_wallet_budget_put_grant_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B Wallet Budget grant route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B Wallet Budget grant must be served at {}",
                CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH_V1
            ),
            404,
        );
    }
    let mut parsed = match request
        .json::<CloudflareRouterWalletBudgetPutGrantRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B Wallet Budget grant JSON parse failed: {err}"),
                400,
            );
        }
    };
    parsed.now_unix_ms = now_unix_ms;
    let status = match put_cloudflare_router_wallet_budget_grant_v1(env, runtime, parsed).await {
        Ok(status) => status,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    worker::Response::from_json(&status)
}

/// Handles the public Wallet Session budget status route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_wallet_budget_status_authenticated_public_request_v1<
    Verifier,
>(
    request: &mut worker::Request,
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> worker::Result<worker::Response>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B Wallet Budget status route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B Wallet Budget status must be served at {}",
                CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1
            ),
            404,
        );
    }
    let body = match request
        .json::<CloudflareRouterWalletBudgetStatusPublicRequestV1>()
        .await
    {
        Ok(body) => body,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B Wallet Budget status JSON parse failed: {err}"),
                400,
            );
        }
    };
    let wallet_session = match verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    ) {
        Ok(wallet_session) => wallet_session,
        Err(err) => {
            return worker::Response::error(format!("{:?}: {}", err.code(), err.message()), 401);
        }
    };
    let expected_signing_grant_id = body.expected_signing_grant_id();
    if !expected_signing_grant_id.is_empty()
        && expected_signing_grant_id != wallet_session.signing_grant_id
    {
        return worker::Response::from_json(&serde_json::json!({
            "ok": false,
            "code": "wallet_signing_session_mismatch",
            "message": "Signing grant status token does not match requested wallet session",
        }))
        .map(|response| response.with_status(403));
    }
    let expected_threshold_session_id = body.expected_threshold_session_id();
    if !expected_threshold_session_id.is_empty()
        && expected_threshold_session_id != wallet_session.threshold_session_id
    {
        return worker::Response::from_json(&serde_json::json!({
            "ok": false,
            "code": "threshold_session_mismatch",
            "message": "Signing grant status token does not match requested threshold session",
        }))
        .map(|response| response.with_status(403));
    }
    let budget_status =
        match status_cloudflare_router_wallet_budget_v1(env, runtime, &wallet_session, now_unix_ms)
            .await
        {
            Ok(status) => status,
            Err(err)
                if matches!(
                    err.code(),
                    RouterAbProtocolErrorCode::MissingLocalBinding
                        | RouterAbProtocolErrorCode::ForbiddenLocalBinding
                        | RouterAbProtocolErrorCode::ExpiredLocalRequest
                ) =>
            {
                return worker::Response::from_json(&serde_json::json!({
                    "ok": false,
                    "code": "wallet_budget_forbidden",
                    "message": "Wallet Session budget grant is unavailable",
                }))
                .map(|response| response.with_status(403));
            }
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let response = match CloudflareRouterWalletBudgetStatusPublicResponseV1::new(
        &wallet_session,
        budget_status,
    ) {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    worker::Response::from_json(&response)
}

/// Handles an authenticated public Router normal-signing v2 prepare request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningPrepareRequestV2,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<
    CloudflareRouterWalletBudgetedPrepareResponseV1<NormalSigningRound1PrepareResponseV1>,
>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let wallet_session = verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    )?;
    wallet_session.validate_for_normal_signing_prepare_request_v2(&request, now_unix_ms)?;
    let replay_call = runtime.normal_signing_v2_prepare_replay_reserve_call(&request)?;
    let replay = execute_cloudflare_router_replay_reserve_v1(env, &replay_call).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "normal-signing v2 prepare replay reservation already exists",
        ));
    }
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        now_unix_ms,
    )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_prepare_trusted_admission_from_worker_stores_v2(
            env,
            runtime,
            now_unix_ms,
            &request,
            &admission,
        )
        .await?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 prepare Router admission did not allow SigningWorker forwarding",
        ));
    }
    let budget_operation_id = cloudflare_router_ed25519_prepare_budget_operation_id_v2(&request)?;
    let budget_request_digest = cloudflare_router_ed25519_prepare_budget_request_digest_v2(
        &request,
        &budget_operation_id,
        &wallet_session.signing_worker_id,
    )?;
    let budget_reserve_request = cloudflare_router_wallet_budget_reserve_request_v1(
        &wallet_session,
        CloudflareRouterWalletBudgetCurveV1::Ed25519,
        budget_operation_id.clone(),
        budget_request_digest,
        request.expires_at_ms,
        now_unix_ms,
    )?;
    let (budget_reservation_id, budget_status) =
        reserve_cloudflare_router_wallet_budget_v1(env, runtime, budget_reserve_request).await?;
    let budget_identity = CloudflareRouterWalletBudgetReservationIdentityV1::new(
        wallet_session.signing_grant_id.clone(),
        budget_reservation_id.clone(),
        wallet_session.signing_worker_id.clone(),
        budget_operation_id.clone(),
        budget_request_digest,
        now_unix_ms,
    )?;
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2::new(
        request.scope.clone(),
        request.expires_at_ms,
        admission,
        trusted_admission,
    )?;
    let response = match execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            release_cloudflare_router_wallet_budget_best_effort_v1(env, runtime, &budget_identity)
                .await;
            return Err(err);
        }
    };
    CloudflareRouterWalletBudgetedPrepareResponseV1::new(
        response,
        budget_reservation_id,
        budget_operation_id,
        budget_status,
    )
}

/// Handles an authenticated public Router normal-signing v2 presign-pool refill request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_presign_pool_prepare_authenticated_public_request_v2<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519PresignPoolPrepareRequestV2,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolPrepareResponseV2>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let wallet_session = verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    )?;
    wallet_session
        .validate_for_normal_signing_presign_pool_prepare_request_v2(&request, now_unix_ms)?;
    let budget_status =
        status_cloudflare_router_wallet_budget_v1(env, runtime, &wallet_session, now_unix_ms)
            .await?;
    require_cloudflare_router_wallet_budget_available_use_v1(&budget_status)?;
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2::new(
        request,
        wallet_session,
    )?;
    execute_cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

/// Handles an authenticated public Router ECDSA-HSS prepare request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<
    CloudflareRouterWalletBudgetedPrepareResponseV1<
        RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1,
    >,
>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let wallet_session = verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    )?;
    wallet_session.validate_for_ecdsa_hss_evm_digest_signing_request_v1(&request, now_unix_ms)?;
    let replay_call = runtime.ecdsa_hss_evm_digest_prepare_replay_reserve_call(&request)?;
    let replay = execute_cloudflare_router_replay_reserve_v1(env, &replay_call).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "ECDSA-HSS prepare replay reservation already exists",
        ));
    }
    let admission =
        CloudflareRouterEcdsaHssEvmDigestPrepareAdmissionCandidateV1::from_prepare_request(
            &wallet_session,
            &request,
            now_unix_ms,
        )?;
    let trusted_admission =
        derive_cloudflare_router_ecdsa_hss_evm_digest_prepare_trusted_admission_from_worker_stores_v1(
            env,
            runtime,
            now_unix_ms,
            &request,
            &admission,
        )
        .await?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "ECDSA-HSS prepare Router admission did not allow SigningWorker forwarding",
        ));
    }
    let budget_operation_id =
        cloudflare_router_ecdsa_hss_prepare_budget_operation_id_v1(&request, &wallet_session)?;
    let budget_request_digest = request.request_digest()?;
    let budget_reserve_request = cloudflare_router_wallet_budget_reserve_request_v1(
        &wallet_session,
        CloudflareRouterWalletBudgetCurveV1::EcdsaHss,
        budget_operation_id.clone(),
        budget_request_digest,
        request.expires_at_ms,
        now_unix_ms,
    )?;
    let (budget_reservation_id, budget_status) =
        reserve_cloudflare_router_wallet_budget_v1(env, runtime, budget_reserve_request).await?;
    let budget_identity = CloudflareRouterWalletBudgetReservationIdentityV1::new(
        wallet_session.signing_grant_id.clone(),
        budget_reservation_id.clone(),
        wallet_session.signing_worker_id.clone(),
        budget_operation_id.clone(),
        budget_request_digest,
        now_unix_ms,
    )?;
    let admitted = CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1::new(
        request,
        trusted_admission,
    )?;
    let response =
        match execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_call_v1(
            env,
            runtime.signing_worker_peer(),
            admitted,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => {
                release_cloudflare_router_wallet_budget_best_effort_v1(
                    env,
                    runtime,
                    &budget_identity,
                )
                .await;
                return Err(err);
            }
        };
    CloudflareRouterWalletBudgetedPrepareResponseV1::new(
        response,
        budget_reservation_id,
        budget_operation_id,
        budget_status,
    )
}

/// Handles an authenticated public Router ECDSA-HSS finalize request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    budget_metadata: CloudflareRouterWalletBudgetFinalizeMetadataV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<
    CloudflareRouterWalletBudgetedFinalizeResponseV1<RouterAbEcdsaHssEvmDigestSigningResponseV1>,
>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let wallet_session = verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    )?;
    wallet_session.validate_for_ecdsa_hss_evm_digest_finalize_request_v1(&request, now_unix_ms)?;
    budget_metadata.validate()?;
    let expected_budget_operation_id =
        cloudflare_router_ecdsa_hss_finalize_budget_operation_id_v1(&request, &wallet_session)?;
    if budget_metadata.budget_operation_id != expected_budget_operation_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "ECDSA-HSS budget operation identity mismatch",
        ));
    }
    let budget_identity = cloudflare_router_wallet_budget_identity_v1(
        &wallet_session,
        &budget_metadata,
        request.prepare_request_digest()?,
        now_unix_ms,
    )?;
    if let Err(err) =
        validate_cloudflare_router_wallet_budget_v1(env, runtime, budget_identity.clone()).await
    {
        release_cloudflare_router_wallet_budget_best_effort_v1(env, runtime, &budget_identity)
            .await;
        return Err(err);
    }
    let admission =
        CloudflareRouterEcdsaHssEvmDigestFinalizeAdmissionCandidateV1::from_finalize_request(
            &wallet_session,
            &request,
            now_unix_ms,
        )?;
    let trusted_admission =
        derive_cloudflare_router_ecdsa_hss_evm_digest_finalize_trusted_admission_from_worker_stores_v1(
            env,
            runtime,
            now_unix_ms,
            &request,
            &admission,
        )
        .await?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "ECDSA-HSS finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted = CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1::new(
        request,
        trusted_admission,
    )?;
    let response =
        match execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_call_v1(
            env,
            runtime.signing_worker_peer(),
            admitted,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => {
                release_cloudflare_router_wallet_budget_best_effort_v1(
                    env,
                    runtime,
                    &budget_identity,
                )
                .await;
                return Err(err);
            }
        };
    let (_, budget_status) =
        commit_cloudflare_router_wallet_budget_v1(env, runtime, budget_identity).await?;
    CloudflareRouterWalletBudgetedFinalizeResponseV1::new(response, budget_status)
}

/// Handles an authenticated public Router normal-signing v2 finalize request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    budget_metadata: CloudflareRouterWalletBudgetFinalizeMetadataV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetedFinalizeResponseV1<NormalSigningResponseV1>>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let wallet_session = verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    )?;
    wallet_session.validate_for_normal_signing_finalize_request_v2(&request, now_unix_ms)?;
    budget_metadata.validate()?;
    let budget_request_digest = cloudflare_router_ed25519_finalize_budget_request_digest_v2(
        &request,
        &budget_metadata.budget_operation_id,
        &wallet_session.signing_worker_id,
    )?;
    let budget_identity = cloudflare_router_wallet_budget_identity_v1(
        &wallet_session,
        &budget_metadata,
        budget_request_digest,
        now_unix_ms,
    )?;
    if let Err(err) =
        validate_cloudflare_router_wallet_budget_v1(env, runtime, budget_identity.clone()).await
    {
        release_cloudflare_router_wallet_budget_best_effort_v1(env, runtime, &budget_identity)
            .await;
        return Err(err);
    }
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            now_unix_ms,
        )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_finalize_trusted_admission_from_worker_stores_v2(
            env,
            runtime,
            now_unix_ms,
            &request,
            &admission,
        )
        .await?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request,
        trusted_admission,
    )?;
    let response = match execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            release_cloudflare_router_wallet_budget_best_effort_v1(env, runtime, &budget_identity)
                .await;
            return Err(err);
        }
    };
    let (_, budget_status) =
        commit_cloudflare_router_wallet_budget_v1(env, runtime, budget_identity).await?;
    CloudflareRouterWalletBudgetedFinalizeResponseV1::new(response, budget_status)
}

/// Handles an authenticated public Router normal-signing v2 pool-hit finalize request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_presign_pool_hit_finalize_authenticated_public_request_v2<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetedFinalizeResponseV1<NormalSigningResponseV1>>
where
    Verifier: CloudflareRouterWalletSessionVerifierV1,
{
    request.validate_at(now_unix_ms)?;
    let wallet_session = verifier.verify_wallet_session(
        &runtime.admission_bindings().jwt,
        &credential,
        trusted_source_digest,
        now_unix_ms,
    )?;
    wallet_session
        .validate_for_normal_signing_presign_pool_hit_finalize_request_v2(&request, now_unix_ms)?;
    let budget_operation_id = cloudflare_router_ed25519_pool_hit_budget_operation_id_v2(&request)?;
    let budget_request_digest = cloudflare_router_ed25519_pool_hit_budget_request_digest_v2(
        &request,
        &budget_operation_id,
        &wallet_session.signing_worker_id,
    )?;
    let budget_reserve_request = cloudflare_router_wallet_budget_reserve_request_v1(
        &wallet_session,
        CloudflareRouterWalletBudgetCurveV1::Ed25519,
        budget_operation_id.clone(),
        budget_request_digest,
        request.expires_at_ms,
        now_unix_ms,
    )?;
    let (budget_reservation_id, _) =
        reserve_cloudflare_router_wallet_budget_v1(env, runtime, budget_reserve_request).await?;
    let budget_metadata = CloudflareRouterWalletBudgetFinalizeMetadataV1::new(
        budget_reservation_id,
        budget_operation_id,
    )?;
    let budget_identity = cloudflare_router_wallet_budget_identity_v1(
        &wallet_session,
        &budget_metadata,
        budget_request_digest,
        now_unix_ms,
    )?;
    let lowered = request.to_normal_finalize_request_v2()?;
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &lowered,
            now_unix_ms,
        )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_finalize_trusted_admission_from_worker_stores_v2(
            env,
            runtime,
            now_unix_ms,
            &lowered,
            &admission,
        )
        .await?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 pool-hit finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted =
        CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2::new(
            request,
            trusted_admission,
        )?;
    let response = match execute_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            release_cloudflare_router_wallet_budget_best_effort_v1(
                env,
                runtime,
                &budget_identity,
            )
            .await;
            return Err(err);
        }
    };
    let (_, budget_status) =
        commit_cloudflare_router_wallet_budget_v1(env, runtime, budget_identity).await?;
    CloudflareRouterWalletBudgetedFinalizeResponseV1::new(response, budget_status)
}

/// Activates server-output material through SigningWorker's Durable Object binding.
#[cfg(feature = "workers-rs")]
pub async fn activate_cloudflare_signing_worker_server_output_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    let selected_server = activation
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    runtime
        .server_output_decrypt_key()
        .validate_matches_server(&selected_server)?;
    let mut private_key_bytes = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    let material = cloudflare_server_output_material_record_from_activation_request_v1(
        &activation,
        &private_key_bytes,
    );
    private_key_bytes.zeroize();
    let call =
        runtime.signing_worker_output_activate_call(activation, material?, activated_at_ms)?;
    let response = execute_cloudflare_durable_object_call_v1(env, &call).await?;
    require_signing_worker_output_activate_response_v1(&call, response)
}

/// Stores one direct Deriver activation delivery and activates once both roles have arrived.
#[cfg(feature = "workers-rs")]
pub async fn activate_cloudflare_signing_worker_direct_recipient_proof_bundle_delivery_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1> {
    delivery.validate()?;
    let call = runtime.signing_worker_direct_activation_put_call(delivery)?;
    let response = execute_cloudflare_durable_object_call_v1(env, &call).await?;
    let outcome = require_signing_worker_direct_activation_put_response_v1(&call, response)?;
    match outcome {
        CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::Pending {
            record,
        } => CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1::pending(&record),
        CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::Ready {
            aggregate,
        } => {
            let activation = aggregate.to_recipient_proof_bundle_activation_request()?;
            let receipt = activate_cloudflare_signing_worker_server_output_v1(
                env,
                runtime,
                activation,
                activated_at_ms,
            )
            .await?;
            CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1::activated(receipt)
        }
    }
}

/// Activates ECDSA-HSS SigningWorker material through SigningWorker's Durable Object binding.
#[cfg(feature = "workers-rs")]
pub async fn activate_cloudflare_ecdsa_hss_signing_worker_output_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    activation: CloudflareEcdsaHssSigningWorkerActivationRequestV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareEcdsaHssSigningWorkerActivationReceiptV1> {
    activation.validate()?;
    let selected_server = activation
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    runtime
        .server_output_decrypt_key()
        .validate_matches_server(&selected_server)?;
    let generic_activation = activation.to_recipient_proof_bundle_activation_request()?;
    let mut private_key_bytes = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    let material = cloudflare_server_output_material_record_from_activation_request_v1(
        &generic_activation,
        &private_key_bytes,
    );
    private_key_bytes.zeroize();
    let material = material?;
    let ecdsa_receipt = cloudflare_ecdsa_hss_activation_receipt_from_material_v1(
        &activation,
        &material,
        activated_at_ms,
    )?;
    let call = runtime.signing_worker_output_activate_call(
        generic_activation,
        material,
        activated_at_ms,
    )?;
    let response = execute_cloudflare_durable_object_call_v1(env, &call).await?;
    let signing_worker_output =
        require_signing_worker_output_activate_response_v1(&call, response)?;
    CloudflareEcdsaHssSigningWorkerActivationReceiptV1::new(ecdsa_receipt, signing_worker_output)
}

/// Refreshes ECDSA-HSS SigningWorker material through SigningWorker's Durable Object binding.
#[cfg(feature = "workers-rs")]
pub async fn refresh_cloudflare_ecdsa_hss_signing_worker_output_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    activation: CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareEcdsaHssSigningWorkerActivationReceiptV1> {
    activation.validate()?;
    let selected_server = activation
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    runtime
        .server_output_decrypt_key()
        .validate_matches_server(&selected_server)?;
    let generic_activation = activation.to_recipient_proof_bundle_activation_request()?;
    let mut private_key_bytes = load_cloudflare_server_output_hpke_private_key_bytes_v1(
        env,
        runtime.server_output_decrypt_key(),
    )?;
    let material = cloudflare_server_output_material_record_from_activation_request_v1(
        &generic_activation,
        &private_key_bytes,
    );
    private_key_bytes.zeroize();
    let material = material?;
    let ecdsa_receipt = cloudflare_ecdsa_hss_activation_refresh_receipt_from_material_v1(
        &activation,
        &material,
        activated_at_ms,
    )?;
    let call = runtime.signing_worker_output_activate_call(
        generic_activation,
        material,
        activated_at_ms,
    )?;
    let response = execute_cloudflare_durable_object_call_v1(env, &call).await?;
    let signing_worker_output =
        require_signing_worker_output_activate_response_v1(&call, response)?;
    CloudflareEcdsaHssSigningWorkerActivationReceiptV1::new(ecdsa_receipt, signing_worker_output)
}

/// Handles a SigningWorker v2 prepare request after active-state lookup.
pub fn handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2<Handler>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningRound1PreparedV1>
where
    Handler: CloudflareSigningWorkerNormalSigningPrepareHandlerV2,
{
    request.validate()?;
    if now_unix_ms >= request.expires_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "normal-signing v2 prepare request expired",
        ));
    }
    let materialized = CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2::new(
        request,
        active_signing_worker,
        material,
        now_unix_ms,
    )?;
    handler.handle_normal_signing_prepare_request_v2(materialized)
}

/// Handles a SigningWorker v2 presign-pool refill request after active-state lookup.
pub fn handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_request_v2<
    Handler,
>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningPresignPoolPreparedV2>
where
    Handler: CloudflareSigningWorkerNormalSigningPresignPoolPrepareHandlerV2,
{
    request.validate()?;
    request.request.validate_at(now_unix_ms)?;
    let materialized =
        CloudflareSigningWorkerMaterializedNormalSigningPresignPoolPrepareRequestV2::new(
            request,
            active_signing_worker,
            material,
            now_unix_ms,
        )?;
    handler.handle_normal_signing_presign_pool_prepare_request_v2(materialized)
}

/// Handles a SigningWorker v2 finalize request after active-state and round-1 lookup.
pub fn handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2<Handler>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
    server_round1: CloudflareSigningWorkerRound1RecordV1,
) -> RouterAbProtocolResult<NormalSigningResponseV1>
where
    Handler: CloudflareSigningWorkerNormalSigningFinalizeHandlerV2,
{
    request.validate()?;
    request.request.validate_at(now_unix_ms)?;
    let expected_scope = request.request.scope.clone();
    let expected_signing_payload_digest = request.request.signing_payload_digest();
    let expected_signature_scheme = request.request.protocol.signature_scheme();
    let materialized = CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2::new(
        request,
        active_signing_worker,
        material,
        server_round1,
        now_unix_ms,
    )?;
    let response = handler.handle_normal_signing_finalize_request_v2(materialized)?;
    response.validate()?;
    if response.scope == expected_scope
        && response.signing_payload_digest == expected_signing_payload_digest
        && response.signature_scheme == expected_signature_scheme
    {
        return Ok(response);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "normal-signing v2 finalize response does not match admitted request",
    ))
}

/// Handles a SigningWorker v2 presign-pool-hit finalize after active-state and pool claim.
pub fn handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_request_v2<
    Handler,
>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
    pool_record: CloudflareSigningWorkerEd25519PresignPoolRecordV1,
) -> RouterAbProtocolResult<NormalSigningResponseV1>
where
    Handler: CloudflareSigningWorkerNormalSigningFinalizeHandlerV2,
{
    request.validate()?;
    request.request.validate_at(now_unix_ms)?;
    active_signing_worker.validate_for_scope(&request.request.scope)?;
    pool_record.validate()?;
    let protocol = match &request.request.protocol {
        RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
            protocol,
        ) => protocol,
    };
    let expected_server_commitments =
        cloudflare_normal_signing_commitments_wire_from_role_separated_v1(
            pool_record.server_round1_state.commitments,
        )?;
    if pool_record.active_signing_worker_state != active_signing_worker
        || pool_record.client_presign_id != request.request.pool_binding.client_presign_id
        || pool_record.client_nonce_handle != request.request.pool_binding.client_nonce_handle
        || pool_record.generation != request.request.pool_binding.generation
        || pool_record.server_round1_handle != request.request.pool_binding.server_round1_handle
        || pool_record.pool_entry_binding_digest
            != request.request.pool_binding.pool_entry_binding_digest
        || pool_record.client_commitments != protocol.client_commitments
        || pool_record.client_verifying_share_b64u != protocol.client_verifying_share_b64u
        || expected_server_commitments != protocol.server_commitments
        || pool_record.server_verifying_share_b64u != protocol.server_verifying_share_b64u
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker pool-hit finalize material does not match claimed presign-pool record",
        ));
    }
    let lowered = request.to_normal_finalize_request_v2()?;
    let admission_material = request.request.admission_material()?;
    let server_round1 = pool_record.to_request_bound_round1_record(
        &lowered.scope,
        lowered.round1_binding_digest(),
        admission_material.admitted_signing_digest,
        now_unix_ms,
        lowered.expires_at_ms,
    )?;
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        lowered,
        request.trusted_admission,
    )?;
    handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2(
        handler,
        now_unix_ms,
        admitted,
        active_signing_worker,
        material,
        server_round1,
    )
}

/// Validates a private Router-to-signer message for the target Worker role.
pub fn validate_cloudflare_signer_private_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    let expected = expected_signer_private_request_kind_v1(worker_role)?;
    if message.kind != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "{} private signer endpoint expected {} message, received {}",
                worker_role.as_str(),
                expected.as_str(),
                message.kind.as_str()
            ),
        ));
    }
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    if payload.transcript_digest() != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "private signer request payload transcript digest does not match wire message",
        ));
    }
    match (worker_role, payload) {
        (CloudflareWorkerRoleV1::SignerA, RouterToSignerPayloadV1::SignerA { .. })
        | (CloudflareWorkerRoleV1::SignerB, RouterToSignerPayloadV1::SignerB { .. }) => Ok(()),
        (CloudflareWorkerRoleV1::SignerA | CloudflareWorkerRoleV1::SignerB, _) => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "private signer request payload branch does not match Worker role",
            ))
        }
        (CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker, _) => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker has no private signer payload branch",
            ))
        }
    }
}

/// Decodes and validates public signer-envelope HPKE metadata before decryption.
pub fn decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
) -> RouterAbProtocolResult<SignerEnvelopeHpkePayloadV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, message)?;
    envelope_decrypt_key.validate_visible_to(worker_role)?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if envelope_decrypt_key.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Cloudflare signer HPKE envelope key role does not match Worker role",
        ));
    }
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let envelope = &payload.assignment().envelope;
    decode_and_validate_signer_envelope_hpke_payload_v1(
        envelope,
        &envelope_decrypt_key.key_epoch,
        &envelope_decrypt_key.public_key,
    )
}

/// Decodes signer-envelope HPKE metadata and selects the accepted private key.
pub fn decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1<'a>(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_keys: &'a CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<(
    &'a CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    SignerEnvelopeHpkePayloadV1,
)> {
    validate_cloudflare_signer_private_request_v1(worker_role, message)?;
    envelope_decrypt_keys.validate_visible_to(worker_role)?;
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let envelope = &payload.assignment().envelope;
    let hpke_payload = decode_signer_envelope_hpke_payload_v1(envelope.ciphertext.as_bytes())?;
    let binding = envelope_decrypt_keys.accepted_binding_for_payload(
        worker_role,
        &hpke_payload,
        now_unix_ms,
    )?;
    hpke_payload.validate_for_envelope(envelope, &binding.key_epoch, &binding.public_key)?;
    Ok((binding, hpke_payload))
}

/// Strict private signer bootstrap body supplied by Router before envelope decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPrivateBootstrapRequestV1 {
    /// Router-to-signer private wire message.
    pub message: WireMessageV1,
    /// Typed role-envelope AAD used by Router during signer-envelope encryption.
    pub aad: RoleEnvelopeAadV1,
    /// Pre-envelope public request-context digest bound inside signer plaintext.
    pub router_request_digest: PublicDigest32,
}

impl CloudflareSignerPrivateBootstrapRequestV1 {
    /// Creates a validated strict private signer bootstrap body.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        message: WireMessageV1,
        aad: RoleEnvelopeAadV1,
        router_request_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let bootstrap = Self {
            message,
            aad,
            router_request_digest,
        };
        bootstrap.validate_for_worker_role(worker_role)?;
        Ok(bootstrap)
    }

    /// Validates that the typed AAD matches the role-local Router payload.
    pub fn validate_for_worker_role(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        validate_cloudflare_signer_private_request_v1(worker_role, &self.message)?;
        self.aad.validate()?;
        let payload = decode_router_to_signer_payload_v1(self.message.payload.as_bytes())?;
        let assignment = payload.assignment();
        if self.aad.digest() != assignment.envelope.aad_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "strict signer bootstrap AAD digest does not match role envelope",
            ));
        }
        if self.aad.recipient != assignment.signer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer bootstrap AAD recipient does not match assignment signer",
            ));
        }
        if self.aad.signer_set_id != payload.signer_set().signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer bootstrap AAD signer-set id does not match payload",
            ));
        }
        if self.aad.selected_server != payload.signer_set().selected_server {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer bootstrap AAD server does not match signer set",
            ));
        }
        if self.aad.lifecycle_id != payload.lifecycle().lifecycle_id
            || self.aad.work_kind != payload.lifecycle().work_kind
            || self.aad.primitive_request_kind != payload.lifecycle().primitive_request_kind
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "strict signer bootstrap AAD lifecycle scope does not match payload",
            ));
        }
        if self.aad.transcript_digest != payload.transcript_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "strict signer bootstrap AAD transcript digest does not match payload",
            ));
        }
        if self.aad.router_request_digest != self.router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "strict signer bootstrap AAD Router request digest does not match body",
            ));
        }
        Ok(())
    }
}

/// Strict private Deriver request for ECDSA-HSS registration/bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1 {
    /// Typed public registration request admitted by Router.
    pub registration_request: RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
}

impl CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1 {
    /// Creates a validated ECDSA-HSS registration Deriver request.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        registration_request: RouterAbEcdsaHssRegistrationBootstrapRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            registration_request,
            signer_bootstrap,
        };
        request.validate_for_worker_role(worker_role)?;
        Ok(request)
    }

    /// Validates that typed registration metadata matches the Router-to-signer payload.
    pub fn validate_for_worker_role(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.registration_request.validate()?;
        self.signer_bootstrap
            .validate_for_worker_role(worker_role)?;
        let expected_router_request_digest = self
            .registration_request
            .to_public_router_request()?
            .request_context_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "ECDSA-HSS registration bootstrap digest does not match typed registration request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_ecdsa_hss_registration_request_for_router_payload_v1(
            &self.registration_request,
            &router_payload,
        )
    }
}

/// Strict private Deriver request for ECDSA-HSS explicit export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssDeriverExportPrivateRequestV1 {
    /// Typed public export request admitted by Router.
    pub export_request: RouterAbEcdsaHssExplicitExportRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
}

impl CloudflareEcdsaHssDeriverExportPrivateRequestV1 {
    /// Creates a validated ECDSA-HSS export Deriver request.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        export_request: RouterAbEcdsaHssExplicitExportRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            export_request,
            signer_bootstrap,
        };
        request.validate_for_worker_role(worker_role)?;
        Ok(request)
    }

    /// Validates that typed export metadata matches the Router-to-signer payload.
    pub fn validate_for_worker_role(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.export_request.validate()?;
        self.signer_bootstrap
            .validate_for_worker_role(worker_role)?;
        let expected_router_request_digest = self
            .export_request
            .to_public_router_request()?
            .request_context_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "ECDSA-HSS export bootstrap digest does not match typed export request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_ecdsa_hss_export_request_for_router_payload_v1(
            &self.export_request,
            &router_payload,
        )
    }
}

/// Strict private Deriver request for ECDSA-HSS recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1 {
    /// Typed public recovery request admitted by Router.
    pub recovery_request: RouterAbEcdsaHssRecoveryRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
}

impl CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1 {
    /// Creates a validated ECDSA-HSS recovery Deriver request.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        recovery_request: RouterAbEcdsaHssRecoveryRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            recovery_request,
            signer_bootstrap,
        };
        request.validate_for_worker_role(worker_role)?;
        Ok(request)
    }

    /// Validates that typed recovery metadata matches the Router-to-signer payload.
    pub fn validate_for_worker_role(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.recovery_request.validate()?;
        self.signer_bootstrap
            .validate_for_worker_role(worker_role)?;
        let expected_router_request_digest = self
            .recovery_request
            .to_public_router_request()?
            .request_context_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "ECDSA-HSS recovery bootstrap digest does not match typed recovery request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_ecdsa_hss_recovery_request_for_router_payload_v1(
            &self.recovery_request,
            &router_payload,
        )
    }
}

/// Strict private Deriver request for ECDSA-HSS activation refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1 {
    /// Typed public activation-refresh request admitted by Router.
    pub refresh_request: RouterAbEcdsaHssActivationRefreshRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
}

impl CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1 {
    /// Creates a validated ECDSA-HSS activation-refresh Deriver request.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        refresh_request: RouterAbEcdsaHssActivationRefreshRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            refresh_request,
            signer_bootstrap,
        };
        request.validate_for_worker_role(worker_role)?;
        Ok(request)
    }

    /// Validates that typed refresh metadata matches the Router-to-signer payload.
    pub fn validate_for_worker_role(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.refresh_request.validate()?;
        self.signer_bootstrap
            .validate_for_worker_role(worker_role)?;
        let expected_router_request_digest = self
            .refresh_request
            .to_public_router_request()?
            .request_context_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "ECDSA-HSS activation refresh bootstrap digest does not match typed refresh request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_ecdsa_hss_activation_refresh_request_for_router_payload_v1(
            &self.refresh_request,
            &router_payload,
        )
    }
}

/// Reconstructs the strict signer bootstrap body from an admitted public Router request.
pub fn cloudflare_signer_private_bootstrap_from_public_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    public_request: &PublicRouterRequestV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerPrivateBootstrapRequestV1> {
    public_request.validate()?;
    validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
    let signer_role = cloudflare_worker_signer_role_v1(worker_role)?;
    let (expected_a, expected_b) = public_request.to_signer_wire_messages()?;
    let expected_message = match signer_role {
        Role::SignerA => expected_a,
        Role::SignerB => expected_b,
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    };
    if message != expected_message {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "strict signer bootstrap message does not match admitted public Router request",
        ));
    }
    let router_payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let assignment = router_payload.require_recipient_role(signer_role)?;
    let router_request_digest = public_request.request_context_digest()?;
    let aad = RoleEnvelopeAadV1::new(
        router_payload.lifecycle().lifecycle_id.clone(),
        router_payload.lifecycle().work_kind,
        router_payload.signer_set().signer_set_id.clone(),
        assignment.signer.clone(),
        router_payload.signer_set().selected_server.clone(),
        router_payload.transcript_digest(),
        router_request_digest,
        public_request.expires_at_ms,
    )?;
    CloudflareSignerPrivateBootstrapRequestV1::new(worker_role, message, aad, router_request_digest)
}

/// Validates that an ECDSA-HSS registration request owns a Router-to-signer payload.
pub fn validate_cloudflare_ecdsa_hss_registration_request_for_router_payload_v1(
    registration_request: &RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    registration_request.validate()?;
    router_payload.validate()?;
    let public_request = registration_request.to_public_router_request()?;
    let (expected_a, expected_b) = public_request.to_signer_payloads()?;
    let expected = match router_payload.recipient_role() {
        Role::SignerA => expected_a,
        Role::SignerB => expected_b,
        _ => unreachable!("RouterToSignerPayloadV1 targets only signer roles"),
    };
    if router_payload == &expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "ECDSA-HSS registration request does not match Router-to-Deriver payload",
    ))
}

/// Validates that an ECDSA-HSS export request owns a Router-to-signer payload.
pub fn validate_cloudflare_ecdsa_hss_export_request_for_router_payload_v1(
    export_request: &RouterAbEcdsaHssExplicitExportRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    export_request.validate()?;
    router_payload.validate()?;
    let public_request = export_request.to_public_router_request()?;
    let (expected_a, expected_b) = public_request.to_signer_payloads()?;
    let expected = match router_payload.recipient_role() {
        Role::SignerA => expected_a,
        Role::SignerB => expected_b,
        _ => unreachable!("RouterToSignerPayloadV1 targets only signer roles"),
    };
    if router_payload == &expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "ECDSA-HSS export request does not match Router-to-Deriver payload",
    ))
}

/// Validates that an ECDSA-HSS recovery request owns a Router-to-signer payload.
pub fn validate_cloudflare_ecdsa_hss_recovery_request_for_router_payload_v1(
    recovery_request: &RouterAbEcdsaHssRecoveryRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    recovery_request.validate()?;
    router_payload.validate()?;
    let public_request = recovery_request.to_public_router_request()?;
    let (expected_a, expected_b) = public_request.to_signer_payloads()?;
    let expected = match router_payload.recipient_role() {
        Role::SignerA => expected_a,
        Role::SignerB => expected_b,
        _ => unreachable!("RouterToSignerPayloadV1 targets only signer roles"),
    };
    if router_payload == &expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "ECDSA-HSS recovery request does not match Router-to-Deriver payload",
    ))
}

/// Validates that an ECDSA-HSS activation-refresh request owns a Router-to-signer payload.
pub fn validate_cloudflare_ecdsa_hss_activation_refresh_request_for_router_payload_v1(
    refresh_request: &RouterAbEcdsaHssActivationRefreshRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    refresh_request.validate()?;
    router_payload.validate()?;
    let public_request = refresh_request.to_public_router_request()?;
    let (expected_a, expected_b) = public_request.to_signer_payloads()?;
    let expected = match router_payload.recipient_role() {
        Role::SignerA => expected_a,
        Role::SignerB => expected_b,
        _ => unreachable!("RouterToSignerPayloadV1 targets only signer roles"),
    };
    if router_payload == &expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "ECDSA-HSS activation refresh request does not match Router-to-Deriver payload",
    ))
}

/// Public preload coordinates derived from a strict private signer bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerHostPreloadPlanV1 {
    /// Worker role that owns the private signer request.
    pub worker_role: CloudflareWorkerRoleV1,
    /// Signer set id whose local root-share metadata must be loaded.
    pub signer_set_id: String,
    /// Root-share epoch to load for the local signer role.
    pub root_share_epoch: RootShareEpoch,
    /// Local signer identity bound by the Router payload.
    pub local_signer: SignerIdentityV1,
    /// Signer set bound by the Router payload.
    pub signer_set: SignerSetV1,
    /// Transcript digest bound by the Router-to-signer wire message.
    pub transcript_digest: PublicDigest32,
    /// Pre-envelope public request-context digest bound inside signer plaintext.
    pub router_request_digest: PublicDigest32,
}

impl CloudflareSignerHostPreloadPlanV1 {
    /// Creates validated signer-host preload coordinates.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        local_signer: SignerIdentityV1,
        signer_set: SignerSetV1,
        transcript_digest: PublicDigest32,
        router_request_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let plan = Self {
            worker_role,
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            local_signer,
            signer_set,
            transcript_digest,
            router_request_digest,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Derives preload coordinates from a validated strict private bootstrap body.
    pub fn from_private_bootstrap(
        worker_role: CloudflareWorkerRoleV1,
        bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        bootstrap.validate_for_worker_role(worker_role)?;
        let payload = decode_router_to_signer_payload_v1(bootstrap.message.payload.as_bytes())?;
        let local_role = cloudflare_worker_signer_role_v1(worker_role)?;
        let local_signer =
            expected_cloudflare_signer_identity_for_role_v1(&payload, local_role)?.clone();
        Self::new(
            worker_role,
            payload.signer_set().signer_set_id.clone(),
            payload.lifecycle().root_share_epoch.clone(),
            local_signer,
            payload.signer_set().clone(),
            bootstrap.message.transcript_digest,
            bootstrap.router_request_digest,
        )
    }

    /// Validates signer-host preload coordinates.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let expected_role = cloudflare_worker_signer_role_v1(self.worker_role)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        self.local_signer.validate()?;
        self.signer_set.validate()?;
        if self.local_signer.role != expected_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-host preload plan local signer does not match Worker role",
            ));
        }
        if self.signer_set.signer_set_id != self.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-host preload plan signer-set id does not match signer set",
            ));
        }
        let expected_local = match expected_role {
            Role::SignerA => &self.signer_set.signer_a,
            Role::SignerB => &self.signer_set.signer_b,
            _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
        };
        if &self.local_signer != expected_local {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-host preload plan local signer does not match signer-set role",
            ));
        }
        Ok(())
    }

    /// Builds signer-host preload input after the adapter supplies peer material.
    pub fn to_host_preload_input(
        &self,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<CloudflareSignerHostPreloadInputV1> {
        self.validate()?;
        CloudflareSignerHostPreloadInputV1::new(
            self.signer_set_id.clone(),
            self.root_share_epoch.clone(),
            peer_responses,
            signer_verifying_keys,
            random_bytes_len,
        )
    }

    /// Builds signer-host preload input from a trusted public verifying-key set.
    pub fn to_host_preload_input_with_key_set(
        &self,
        peer_responses: Vec<WireMessageV1>,
        peer_verifying_keys: &CloudflareSignerPeerVerifyingKeySetV1,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<CloudflareSignerHostPreloadInputV1> {
        self.validate()?;
        self.to_host_preload_input(
            peer_responses,
            peer_verifying_keys.to_protocol_keys(&self.signer_set)?,
            random_bytes_len,
        )
    }
}

/// Private signer request after envelope decryption and signer-input validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareValidatedSignerPrivateRequestV1 {
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    router_payload: RouterToSignerPayloadV1,
    signer_input: SignerInputPlaintextV1,
}

impl CloudflareValidatedSignerPrivateRequestV1 {
    fn new(
        worker_role: CloudflareWorkerRoleV1,
        message: WireMessageV1,
        router_payload: RouterToSignerPayloadV1,
        signer_input: SignerInputPlaintextV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
        if router_payload.transcript_digest() != message.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "validated signer request payload transcript digest does not match wire message",
            ));
        }
        router_payload.require_recipient_role(cloudflare_worker_signer_role_v1(worker_role)?)?;
        Ok(Self {
            worker_role,
            message,
            router_payload,
            signer_input,
        })
    }

    /// Returns the Cloudflare Worker role handling this request.
    pub fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        self.worker_role
    }

    /// Returns the original private signer wire message.
    pub fn message(&self) -> &WireMessageV1 {
        &self.message
    }

    /// Returns the decoded Router-to-signer payload.
    pub fn router_payload(&self) -> &RouterToSignerPayloadV1 {
        &self.router_payload
    }

    /// Returns the validated signer-input plaintext.
    pub fn signer_input(&self) -> &SignerInputPlaintextV1 {
        &self.signer_input
    }
}

/// Validates decrypted signer plaintext and returns the narrow production handler input.
pub fn validate_cloudflare_signer_private_request_plaintext_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    plaintext_bytes: &[u8],
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<CloudflareValidatedSignerPrivateRequestV1> {
    let signer_input = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        worker_role,
        &message,
        plaintext_bytes,
        router_request_digest,
        root_share_metadata,
    )?;
    let router_payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    CloudflareValidatedSignerPrivateRequestV1::new(
        worker_role,
        message,
        router_payload,
        signer_input,
    )
}

/// Handles a parsed private signer request through a strict proof-bundle handler.
pub fn handle_cloudflare_signer_recipient_proof_bundle_private_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
    let response = handler.handle_signer_recipient_proof_bundle_wire_message(message.clone())?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        &message,
        &response,
    )?;
    Ok(response)
}

/// Evaluates a validated private signer request through the real MPC PRF signer engine.
pub fn evaluate_cloudflare_validated_mpc_prf_batch_output_v1(
    host: &CloudflarePreloadedSignerHostV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
) -> RouterAbProtocolResult<MpcPrfThresholdSignerBatchOutputV1> {
    host.validate()?;
    request.router_payload().validate()?;
    request
        .signer_input()
        .validate()
        .map_err(map_derivation_to_protocol)?;
    let signer_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    if request.signer_input().recipient_role != signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "validated signer input role does not match Worker role",
        ));
    }
    let signing_root_share_wire =
        host.signing_root_share_wire(signer_role, &request.signer_input().root_share_epoch)?;
    let batch_input = build_mpc_prf_threshold_signer_batch_input_v1(
        request.router_payload(),
        request.signer_input(),
        signing_root_share_wire,
    )?;
    let mut proof_rng = CloudflareSignerProofGetrandomRngV1;
    match signer_role {
        Role::SignerA => {
            DeriverAEngine::new().evaluate_mpc_prf_output_batch(batch_input, &mut proof_rng)
        }
        Role::SignerB => {
            DeriverBEngine::new().evaluate_mpc_prf_output_batch(batch_input, &mut proof_rng)
        }
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    }
    .map_err(map_derivation_to_protocol)
}

/// Builds a signed A/B proof-batch peer wire message from a real signer batch output.
pub fn build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
    signing_key_bytes: &[u8; 32],
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    batch_output: MpcPrfThresholdSignerBatchOutputV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    from.validate()?;
    to.validate()?;
    let kind = match (from.role, to.role) {
        (Role::SignerA, Role::SignerB) => WireMessageKindV1::SignerAToSignerB,
        (Role::SignerB, Role::SignerA) => WireMessageKindV1::SignerBToSignerA,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Cloudflare proof-batch peer message requires cross-signer A/B direction",
            ));
        }
    };
    let peer_payload =
        sign_ab_derivation_proof_batch_peer_payload_v1(signing_key_bytes, from, to, batch_output)?;
    WireMessageV1::new(
        kind,
        peer_payload.transcript_digest,
        CanonicalWireBytesV1::new(peer_payload.canonical_bytes())?,
    )
}

/// Verifies an authenticated A/B proof-batch peer message and decodes the proof batch.
pub fn decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
    key_store: &impl SignerKeyStore,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbDerivationProofBatchPayloadV1> {
    let peer_payload = verify_cloudflare_signer_peer_message_authentication_v1(key_store, message)?;
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)
}

/// Builds strict opaque client and server proof bundles from one signer proof batch.
pub fn cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
    router_payload: &RouterToSignerPayloadV1,
    proof_batch: AbDerivationProofBatchPayloadV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    router_payload.validate()?;
    proof_batch.validate()?;
    let signer_role = proof_batch.from.role;
    require_signer_role(signer_role)?;
    let client_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch.clone(),
        OpenedShareKind::XClientBase,
        Role::Client,
        &router_payload.transcript_metadata().client_id,
        &router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        encryptor,
    )?;
    let server_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch,
        OpenedShareKind::XServerBase,
        Role::Server,
        &router_payload.signer_set().selected_server.server_id,
        &router_payload
            .signer_set()
            .selected_server
            .recipient_encryption_key,
        encryptor,
    )?;
    let response = CloudflareSignerRecipientProofBundleResponseV1::new(
        signer_role,
        client_bundle,
        server_bundle,
    )?;
    response.validate_for_router_payload(router_payload)?;
    Ok(response)
}

/// Builds a strict opaque client proof bundle from one signer proof batch.
pub fn cloudflare_client_recipient_proof_bundle_response_from_ab_proof_batch_v1(
    router_payload: &RouterToSignerPayloadV1,
    proof_batch: AbDerivationProofBatchPayloadV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    router_payload.validate()?;
    proof_batch.validate()?;
    let signer_role = proof_batch.from.role;
    require_signer_role(signer_role)?;
    let client_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch,
        OpenedShareKind::XClientBase,
        Role::Client,
        &router_payload.transcript_metadata().client_id,
        &router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        encryptor,
    )?;
    let response =
        CloudflareSignerClientRecipientProofBundleResponseV1::new(signer_role, client_bundle)?;
    response.validate_for_router_payload(router_payload)?;
    Ok(response)
}

/// Handles a decrypt-validated signer request through the strict MPC PRF proof-bundle path.
pub fn handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
    host: &CloudflarePreloadedSignerHostV1,
    peer_signing_key_bytes: &[u8; 32],
    request: &CloudflareValidatedSignerPrivateRequestV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    let local_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    let (local_signer, peer_signer, _) =
        cloudflare_signer_identities_for_request_v1(request, local_role)?;
    let local_output = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(host, request)?;
    let local_peer_message = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        peer_signing_key_bytes,
        local_signer,
        peer_signer,
        local_output,
    )?;
    let local_proof_batch = decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
        host,
        &local_peer_message,
    )?;
    cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
        request.router_payload(),
        local_proof_batch,
        encryptor,
    )
}

/// Handles a decrypt-validated signer request through the client-only proof-bundle path.
pub fn handle_cloudflare_validated_mpc_prf_client_recipient_proof_bundle_signer_request_v1(
    host: &CloudflarePreloadedSignerHostV1,
    peer_signing_key_bytes: &[u8; 32],
    request: &CloudflareValidatedSignerPrivateRequestV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    let local_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    let (local_signer, peer_signer, _) =
        cloudflare_signer_identities_for_request_v1(request, local_role)?;
    let local_output = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(host, request)?;
    let local_peer_message = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        peer_signing_key_bytes,
        local_signer,
        peer_signer,
        local_output,
    )?;
    let local_proof_batch = decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
        host,
        &local_peer_message,
    )?;
    cloudflare_client_recipient_proof_bundle_response_from_ab_proof_batch_v1(
        request.router_payload(),
        local_proof_batch,
        encryptor,
    )
}

/// Validates that a role-local peer signing key can sign for a validated request.
pub fn validate_cloudflare_peer_signing_key_matches_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
) -> RouterAbProtocolResult<SignerIdentityV1> {
    peer_signing_key.validate_visible_to(worker_role)?;
    if request.worker_role() != worker_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "peer signing-key validation Worker role differs from the validated signer request role",
        ));
    }
    let local_role = cloudflare_worker_signer_role_v1(worker_role)?;
    let (local_signer, _, _) = cloudflare_signer_identities_for_request_v1(request, local_role)?;
    if peer_signing_key.role != local_signer.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key role differs from the local signer identity",
        ));
    }
    if peer_signing_key.key_epoch != local_signer.key_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key epoch differs from the local signer identity epoch",
        ));
    }
    Ok(local_signer)
}

/// Decrypts a production signer-envelope HPKE payload through Cloudflare secret bindings.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_cloudflare_signer_envelope_hpke_payload_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    let secret = env
        .secret(&envelope_decrypt_key.binding_name)
        .map_err(|err| {
            worker_binding_error(
                worker_binding_error_code(&err, &envelope_decrypt_key.binding_name),
                &envelope_decrypt_key.binding_name,
                "secret",
                err,
            )
        })?;
    let mut secret_value = secret.to_string();
    let key_result = decode_cloudflare_signer_envelope_hpke_private_key_secret_v1(&secret_value);
    secret_value.zeroize();
    let mut private_key_bytes = key_result?;
    let plaintext = open_cloudflare_signer_envelope_hpke_payload_v1(
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
        &private_key_bytes,
    );
    private_key_bytes.zeroize();
    plaintext
}

/// Decrypts a production signer-envelope HPKE payload through a rotated key set.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_cloudflare_signer_envelope_hpke_payload_with_key_set_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    aad: &RoleEnvelopeAadV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<Vec<u8>> {
    let (envelope_decrypt_key, _) =
        decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
            worker_role,
            message,
            envelope_decrypt_keys,
            now_unix_ms,
        )?;
    decrypt_cloudflare_signer_envelope_hpke_payload_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
    )
    .await
}

#[cfg(feature = "workers-rs")]
fn load_cloudflare_server_output_hpke_private_key_bytes_v1(
    env: &worker::Env,
    binding: &CloudflareServerOutputHpkeDecryptKeyBindingV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    binding.validate_visible_to(CloudflareWorkerRoleV1::SigningWorker)?;
    let secret = env.secret(&binding.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let key = decode_cloudflare_server_output_hpke_private_key_secret_v1(&secret_value);
    secret_value.zeroize();
    key
}

/// Decrypts and validates signer-input plaintext through the production Cloudflare boundary.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_and_validate_cloudflare_signer_input_plaintext_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<SignerInputPlaintextV1> {
    let plaintext_bytes = decrypt_cloudflare_signer_envelope_hpke_payload_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
    )
    .await?;
    decode_and_validate_cloudflare_signer_input_plaintext_v1(
        worker_role,
        message,
        &plaintext_bytes,
        router_request_digest,
        root_share_metadata,
    )
}

/// Decrypts and validates a private signer request for the narrow production handler.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_cloudflare_validated_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareValidatedSignerPrivateRequestV1> {
    let plaintext_bytes = decrypt_cloudflare_signer_envelope_hpke_payload_with_key_set_v1(
        env,
        worker_role,
        &message,
        envelope_decrypt_keys,
        aad,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_signer_private_request_plaintext_v1(
        worker_role,
        message,
        &plaintext_bytes,
        router_request_digest,
        root_share_metadata,
    )
}

/// Decrypts, validates, and handles an MPC PRF private signer request with strict delivery.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    message: WireMessageV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    let request = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_keys,
        aad,
        router_request_digest,
        root_share_metadata,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &request,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
        host,
        &peer_signing_key_bytes,
        &request,
        &mut encryptor,
    );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        request.message(),
        &response,
    )?;
    Ok(response)
}

/// Decrypts, validates, and handles an ECDSA-HSS registration signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_ecdsa_hss_registration_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    request: CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    request.validate_for_worker_role(worker_role)?;
    let CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1 {
        registration_request,
        signer_bootstrap: bootstrap,
    } = request;
    let validated = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_ecdsa_hss_registration_request_for_router_payload_v1(
        &registration_request,
        validated.router_payload(),
    )?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &validated,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
        host,
        &peer_signing_key_bytes,
        &validated,
        &mut encryptor,
    );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
}

/// Decrypts, validates, and handles an ECDSA-HSS export signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    request: CloudflareEcdsaHssDeriverExportPrivateRequestV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    request.validate_for_worker_role(worker_role)?;
    let CloudflareEcdsaHssDeriverExportPrivateRequestV1 {
        export_request,
        signer_bootstrap: bootstrap,
    } = request;
    let validated = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_ecdsa_hss_export_request_for_router_payload_v1(
        &export_request,
        validated.router_payload(),
    )?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &validated,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response =
        handle_cloudflare_validated_mpc_prf_client_recipient_proof_bundle_signer_request_v1(
            host,
            &peer_signing_key_bytes,
            &validated,
            &mut encryptor,
        );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
}

/// Decrypts, validates, and handles an ECDSA-HSS recovery signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_ecdsa_hss_recovery_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    request: CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    request.validate_for_worker_role(worker_role)?;
    let CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1 {
        recovery_request,
        signer_bootstrap: bootstrap,
    } = request;
    let validated = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_ecdsa_hss_recovery_request_for_router_payload_v1(
        &recovery_request,
        validated.router_payload(),
    )?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &validated,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response =
        handle_cloudflare_validated_mpc_prf_client_recipient_proof_bundle_signer_request_v1(
            host,
            &peer_signing_key_bytes,
            &validated,
            &mut encryptor,
        );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
}

/// Decrypts, validates, and handles an ECDSA-HSS activation-refresh signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_ecdsa_hss_activation_refresh_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    request: CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    request.validate_for_worker_role(worker_role)?;
    let CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1 {
        refresh_request,
        signer_bootstrap: bootstrap,
    } = request;
    let validated = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_ecdsa_hss_activation_refresh_request_for_router_payload_v1(
        &refresh_request,
        validated.router_payload(),
    )?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &validated,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
        host,
        &peer_signing_key_bytes,
        &validated,
        &mut encryptor,
    );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
}

/// Decodes and validates post-decryption signer-input plaintext for a signer Worker.
pub fn decode_and_validate_cloudflare_signer_input_plaintext_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    plaintext_bytes: &[u8],
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<SignerInputPlaintextV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, message)?;
    root_share_metadata.validate()?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if root_share_metadata.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Cloudflare signer plaintext metadata role does not match Worker role",
        ));
    }
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let plaintext =
        decode_signer_input_plaintext_v1(plaintext_bytes).map_err(map_derivation_to_protocol)?;
    validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        router_request_digest,
        &root_share_metadata.root_share_epoch,
    )?;
    if plaintext.signer_set_id != root_share_metadata.signer_set_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare signer plaintext signer-set id does not match root metadata",
        ));
    }
    if plaintext.recipient_signer_id != root_share_metadata.signer_id
        || plaintext.recipient_key_epoch != root_share_metadata.signer_key_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare signer plaintext recipient identity does not match root metadata",
        ));
    }
    Ok(plaintext)
}

/// Validates a strict private signer proof-bundle response against the Router-dispatched request.
pub fn validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
    worker_role: CloudflareWorkerRoleV1,
    request: &WireMessageV1,
    response: &CloudflareSignerRecipientProofBundleResponseV1,
) -> RouterAbProtocolResult<()> {
    validate_cloudflare_signer_private_request_v1(worker_role, request)?;
    let router_payload = decode_router_to_signer_payload_v1(request.payload.as_bytes())?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if response.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "strict private signer proof-bundle response signer role does not match Worker role",
        ));
    }
    response.validate_for_router_payload(&router_payload)
}

/// Validates a strict private signer client-output response against the dispatched request.
pub fn validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1(
    worker_role: CloudflareWorkerRoleV1,
    request: &WireMessageV1,
    response: &CloudflareSignerClientRecipientProofBundleResponseV1,
) -> RouterAbProtocolResult<()> {
    validate_cloudflare_signer_private_request_v1(worker_role, request)?;
    let router_payload = decode_router_to_signer_payload_v1(request.payload.as_bytes())?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if response.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "strict private signer client response signer role does not match Worker role",
        ));
    }
    response.validate_for_router_payload(&router_payload)
}

/// Handles a strict Signer A proof-bundle activation request.
pub fn handle_cloudflare_deriver_a_recipient_proof_bundle_activation_request_v1(
    request: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    signing_worker_material_handle: impl Into<String>,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    request.validate()?;
    let active_signing_worker_state =
        cloudflare_active_signing_worker_state_from_activation_request_v1(
            &request,
            signing_worker_material_handle,
            activated_at_ms,
        )?;
    CloudflareSigningWorkerOutputActivationReceiptV1::new(
        request.activation_context.lifecycle().lifecycle_id.clone(),
        request
            .activation_context
            .signer_set()
            .selected_server
            .server_id
            .clone(),
        request.activation_context.transcript_digest(),
        active_signing_worker_state,
        true,
    )
}

/// Validates a direct A/B peer message for the target Worker role.
pub fn validate_cloudflare_signer_peer_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    let expected = expected_signer_peer_request_kind_v1(worker_role)?;
    if message.kind != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "{} peer endpoint expected {} message, received {}",
                worker_role.as_str(),
                expected.as_str(),
                message.kind.as_str()
            ),
        ));
    }
    if message.payload.as_bytes().is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "direct A/B peer request payload must be non-empty",
        ));
    }
    decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
    Ok(())
}

/// Validates a direct A/B peer response against the request and target Worker role.
pub fn validate_cloudflare_signer_peer_response_v1(
    worker_role: CloudflareWorkerRoleV1,
    request: &WireMessageV1,
    response: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    validate_cloudflare_signer_peer_request_v1(worker_role, request)?;
    let expected = expected_signer_peer_response_kind_v1(worker_role)?;
    if response.kind != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} peer endpoint expected {} response, received {}",
                worker_role.as_str(),
                expected.as_str(),
                response.kind.as_str()
            ),
        ));
    }
    if response.transcript_digest != request.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "direct A/B peer response transcript digest does not match request",
        ));
    }
    if response.payload.as_bytes().is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "direct A/B peer response payload must be non-empty",
        ));
    }
    decode_and_validate_cloudflare_signer_peer_message_payload_v1(response)?;
    Ok(())
}

/// Decodes and validates the canonical A/B peer payload inside a wire message.
pub fn decode_and_validate_cloudflare_signer_peer_message_payload_v1(
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    let payload = decode_ab_peer_message_payload_v1(message.payload.as_bytes())?;
    if payload.transcript_digest != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "direct A/B peer payload transcript digest does not match wire message",
        ));
    }
    let (expected_from, expected_to) = match message.kind {
        WireMessageKindV1::SignerAToSignerB => (Role::SignerA, Role::SignerB),
        WireMessageKindV1::SignerBToSignerA => (Role::SignerB, Role::SignerA),
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalRoute,
                "wire message kind is not a direct A/B peer message",
            ));
        }
    };
    if payload.from.role != expected_from || payload.to.role != expected_to {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "direct A/B peer payload signer identities do not match wire direction",
        ));
    }
    Ok(payload)
}

/// Verifies an authenticated direct A/B peer message with trusted signer keys.
pub fn verify_cloudflare_signer_peer_message_authentication_v1(
    key_store: &impl SignerKeyStore,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    let payload = decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
    let verifying_key = key_store.signer_verifying_key(&payload.from)?;
    verify_ab_peer_message_ed25519_signature_v1(&payload, &verifying_key)?;
    Ok(payload)
}

/// Builds and signs one direct A/B peer wire message with the Worker-local Ed25519 key.
#[cfg(feature = "workers-rs")]
pub fn sign_cloudflare_signer_peer_wire_message_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    transcript_digest: PublicDigest32,
    peer_body: CanonicalWireBytesV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    signing_key.validate_visible_to(worker_role)?;
    from.validate()?;
    to.validate()?;
    let local_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if from.role != local_role || signing_key.role != from.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key must match the local sender role",
        ));
    }
    if signing_key.key_epoch != from.key_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key epoch must match the sender identity epoch",
        ));
    }
    let kind = match (from.role, to.role) {
        (Role::SignerA, Role::SignerB) => WireMessageKindV1::SignerAToSignerB,
        (Role::SignerB, Role::SignerA) => WireMessageKindV1::SignerBToSignerA,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Cloudflare peer signing requires a cross-signer A/B direction",
            ));
        }
    };
    let mut signing_key_bytes = load_cloudflare_signer_peer_signing_key_bytes_v1(env, signing_key)?;
    let authentication = sign_ab_peer_message_ed25519_authentication_v1(
        &signing_key_bytes,
        &from,
        &to,
        transcript_digest,
        &peer_body,
    );
    signing_key_bytes.zeroize();
    let payload =
        AbPeerMessagePayloadV1::new(from, to, transcript_digest, peer_body, authentication?)?;
    WireMessageV1::new(
        kind,
        transcript_digest,
        CanonicalWireBytesV1::new(payload.canonical_bytes())?,
    )
}

/// Handles the strict private Signer A service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_a_recipient_proof_bundle_private_fetch_v1(
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
        CloudflareWorkerRoleV1::SignerA,
        CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
        handler,
        request,
    )
    .await
}

/// Handles the strict private Signer B service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_b_recipient_proof_bundle_private_fetch_v1(
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
        CloudflareWorkerRoleV1::SignerB,
        CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1,
        handler,
        request,
    )
    .await
}

/// Handles SigningWorker's strict SigningWorker proof-bundle activation route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B SigningWorker proof-bundle activation route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B SigningWorker proof-bundle activation must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerRecipientProofBundleActivationRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!(
                    "Router A/B SigningWorker proof-bundle activation JSON parse failed: {err}"
                ),
                400,
            );
        }
    };
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    match activate_cloudflare_signing_worker_server_output_v1(env, runtime, parsed, now_unix_ms)
        .await
    {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles SigningWorker's ECDSA-HSS activation route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_ecdsa_hss_signing_worker_activation_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA-HSS SigningWorker activation route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA-HSS SigningWorker activation must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request.json::<serde_json::Value>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B ECDSA-HSS SigningWorker activation JSON parse failed: {err}"),
                400,
            );
        }
    };
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    if let Ok(activation) =
        serde_json::from_value::<CloudflareEcdsaHssSigningWorkerActivationRequestV1>(parsed.clone())
    {
        return match activate_cloudflare_ecdsa_hss_signing_worker_output_v1(
            env,
            runtime,
            activation,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => worker::Response::from_json(&response),
            Err(err) => worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            ),
        };
    }
    let delivery = match serde_json::from_value::<
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    >(parsed)
    {
        Ok(delivery) => delivery,
        Err(err) => {
            return worker::Response::error(
                format!(
                    "Router A/B ECDSA-HSS SigningWorker activation body did not match full activation or direct delivery: {err}"
                ),
                400,
            );
        }
    };
    match activate_cloudflare_signing_worker_direct_recipient_proof_bundle_delivery_v1(
        env,
        runtime,
        delivery,
        now_unix_ms,
    )
    .await
    {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles SigningWorker's ECDSA-HSS activation-refresh route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_ecdsa_hss_signing_worker_activation_refresh_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA-HSS SigningWorker activation-refresh route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA-HSS SigningWorker activation refresh must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!(
                    "Router A/B ECDSA-HSS SigningWorker activation-refresh JSON parse failed: {err}"
                ),
                400,
            );
        }
    };
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    match refresh_cloudflare_ecdsa_hss_signing_worker_output_v1(env, runtime, parsed, now_unix_ms)
        .await
    {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles SigningWorker's private normal-signing round-1 prepare route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1<
    Handler,
>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerNormalSigningPrepareHandlerV2,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B normal-signing round-1 prepare route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B normal-signing round-1 prepare must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B normal-signing round-1 prepare JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let lookup = match CloudflareActiveSigningWorkerStateLookupV1::from_normal_signing_scope(
        &parsed.scope,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_response = match execute_cloudflare_durable_object_call_v1(env, &call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker =
        match require_signing_worker_output_active_state_get_response_v1(&call, active_response) {
            Ok(active_signing_worker) => active_signing_worker,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_lookup =
        match CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone()) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_call = match runtime.signing_worker_output_material_get_call(material_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let material_response =
        match execute_cloudflare_durable_object_call_v1(env, &material_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material = match require_signing_worker_output_material_get_response_v1(
        &material_call,
        material_response,
    ) {
        Ok(material) => material,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let prepared = match handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2(
        handler,
        now_unix_ms,
        parsed,
        active_signing_worker,
        material,
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_call = match runtime.signing_worker_round1_put_call(prepared.record.clone()) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_response = match execute_cloudflare_durable_object_call_v1(env, &put_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_receipt = match require_signing_worker_round1_put_response_v1(&put_call, put_response) {
        Ok(receipt) => receipt,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    if !put_receipt.stored {
        return worker::Response::error(
            "SigningWorker round-1 prepare handle already exists",
            cloudflare_router_error_status(RouterAbProtocolErrorCode::ReplayedLocalRequest),
        );
    }
    worker::Response::from_json(&prepared.response)
}

/// Handles SigningWorker's private normal-signing Ed25519 presign-pool refill route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_fetch_v1<
    Handler,
>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerNormalSigningPresignPoolPrepareHandlerV2,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B normal-signing presign-pool prepare route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B normal-signing presign-pool prepare must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B normal-signing presign-pool prepare JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let lookup = match CloudflareActiveSigningWorkerStateLookupV1::from_normal_signing_scope(
        &parsed.request.scope,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_response = match execute_cloudflare_durable_object_call_v1(env, &call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker =
        match require_signing_worker_output_active_state_get_response_v1(&call, active_response) {
            Ok(active_signing_worker) => active_signing_worker,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_lookup =
        match CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone()) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_call = match runtime.signing_worker_output_material_get_call(material_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let material_response =
        match execute_cloudflare_durable_object_call_v1(env, &material_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material = match require_signing_worker_output_material_get_response_v1(
        &material_call,
        material_response,
    ) {
        Ok(material) => material,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let prepared =
        match handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_request_v2(
            handler,
            now_unix_ms,
            parsed,
            active_signing_worker,
            material,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    for record in &prepared.records {
        let put_call = match runtime.signing_worker_ed25519_presign_pool_put_call(record.clone()) {
            Ok(call) => call,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
        let put_response = match execute_cloudflare_durable_object_call_v1(env, &put_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
        let put_receipt = match require_signing_worker_ed25519_presign_pool_put_response_v1(
            &put_call,
            put_response,
        ) {
            Ok(receipt) => receipt,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
        if !put_receipt.stored {
            return worker::Response::error(
                "SigningWorker Ed25519 presign-pool entry already exists",
                cloudflare_router_error_status(RouterAbProtocolErrorCode::ReplayedLocalRequest),
            );
        }
    }
    worker::Response::from_json(&prepared.response)
}

/// Handles SigningWorker's private normal-signing Ed25519 presign-pool-hit route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_fetch_v1<
    Handler,
>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerNormalSigningFinalizeHandlerV2,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B normal-signing presign-pool-hit route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B normal-signing presign-pool-hit must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B normal-signing presign-pool-hit JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let lookup = match CloudflareActiveSigningWorkerStateLookupV1::from_normal_signing_scope(
        &parsed.request.scope,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_response = match execute_cloudflare_durable_object_call_v1(env, &call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker =
        match require_signing_worker_output_active_state_get_response_v1(&call, active_response) {
            Ok(active_signing_worker) => active_signing_worker,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_lookup =
        match CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone()) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_call = match runtime.signing_worker_output_material_get_call(material_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let material_response =
        match execute_cloudflare_durable_object_call_v1(env, &material_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material = match require_signing_worker_output_material_get_response_v1(
        &material_call,
        material_response,
    ) {
        Ok(material) => material,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_binding = parsed.request.pool_binding.clone();
    let RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(protocol) =
        &parsed.request.protocol;
    let pool_lookup = match CloudflareSigningWorkerEd25519PresignPoolLookupV1::new(
        active_signing_worker.clone(),
        pool_binding.client_presign_id,
        pool_binding.client_nonce_handle,
        pool_binding.generation,
        pool_binding.server_round1_handle,
        pool_binding.pool_entry_binding_digest,
        protocol.client_commitments.clone(),
        protocol.client_verifying_share_b64u.clone(),
        protocol.server_commitments.clone(),
        protocol.server_verifying_share_b64u.clone(),
        now_unix_ms,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_call = match runtime.signing_worker_ed25519_presign_pool_take_call(pool_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_response = match execute_cloudflare_durable_object_call_v1(env, &pool_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_record = match require_signing_worker_ed25519_presign_pool_take_response_v1(
        &pool_call,
        pool_response,
    ) {
        Ok(record) => record,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    match handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_request_v2(
        handler,
        now_unix_ms,
        parsed,
        active_signing_worker,
        material,
        pool_record,
    ) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles SigningWorker's private ECDSA-HSS presignature pool-fill route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_hss_presignature_pool_put_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA-HSS presignature pool fill route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA-HSS presignature pool fill must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B ECDSA-HSS presignature pool fill JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate_at(now_unix_ms) {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let lookup =
        match CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope(
            &parsed.scope,
        ) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let active_call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_response = match execute_cloudflare_durable_object_call_v1(env, &active_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker = match require_signing_worker_output_active_state_get_response_v1(
        &active_call,
        active_response,
    ) {
        Ok(active_signing_worker) => active_signing_worker,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let record = match parsed.to_pool_record(active_signing_worker, now_unix_ms) {
        Ok(record) => record,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_call = match runtime.signing_worker_ecdsa_presignature_pool_put_call(record) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_response = match execute_cloudflare_durable_object_call_v1(env, &put_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let receipt = match require_signing_worker_ecdsa_presignature_pool_put_response_v1(
        &put_call,
        put_response,
    ) {
        Ok(receipt) => receipt,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    worker::Response::from_json(&receipt)
}

/// Handles SigningWorker's production ECDSA-HSS prepare route using the presignature pool.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B ECDSA-HSS prepare route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA-HSS prepare must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B ECDSA-HSS prepare JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let client_presignature_id = parsed.request.client_presignature_id.clone();
    let lookup =
        match CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope(
            &parsed.request.scope,
        ) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_response = match execute_cloudflare_durable_object_call_v1(env, &call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker =
        match require_signing_worker_output_active_state_get_response_v1(&call, active_response) {
            Ok(active_signing_worker) => active_signing_worker,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_lookup =
        match CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone()) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_call = match runtime.signing_worker_output_material_get_call(material_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let material_response =
        match execute_cloudflare_durable_object_call_v1(env, &material_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material = match require_signing_worker_output_material_get_response_v1(
        &material_call,
        material_response,
    ) {
        Ok(material) => material,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let materialized =
        match CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1::new(
            parsed,
            active_signing_worker.clone(),
            material,
            now_unix_ms,
        ) {
            Ok(materialized) => materialized,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let pool_lookup = match CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1::new(
        active_signing_worker,
        client_presignature_id,
        now_unix_ms,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_call = match runtime.signing_worker_ecdsa_presignature_pool_take_call(pool_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_response = match execute_cloudflare_durable_object_call_v1(env, &pool_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let pool_record = match require_signing_worker_ecdsa_presignature_pool_take_response_v1(
        &pool_call,
        pool_response,
    ) {
        Ok(record) => record,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let rerandomization_entropy32_b64u = match cloudflare_random_bytes_v1(32) {
        Ok(bytes) => encode_base64url_bytes_v1(&bytes),
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let prepared = match prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1(
        materialized,
        pool_record,
        rerandomization_entropy32_b64u,
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_call = match runtime.signing_worker_ecdsa_presignature_put_call(prepared.record.clone())
    {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_response = match execute_cloudflare_durable_object_call_v1(env, &put_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_receipt =
        match require_signing_worker_ecdsa_presignature_put_response_v1(&put_call, put_response) {
            Ok(receipt) => receipt,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    if let Err(err) = prepared.validate_put_receipt(&put_receipt) {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    if !put_receipt.stored {
        return worker::Response::error(
            "SigningWorker ECDSA-HSS presignature id already exists",
            cloudflare_router_error_status(RouterAbProtocolErrorCode::ReplayedLocalRequest),
        );
    }
    worker::Response::from_json(&prepared.response)
}

/// Handles SigningWorker's private ECDSA-HSS normal-signing finalize route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_fetch_v1<
    Handler,
>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B ECDSA-HSS finalize route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA-HSS finalize must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B ECDSA-HSS finalize JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let lookup =
        match CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope(
            &parsed.request.scope,
        ) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_response = match execute_cloudflare_durable_object_call_v1(env, &call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker =
        match require_signing_worker_output_active_state_get_response_v1(&call, active_response) {
            Ok(active_signing_worker) => active_signing_worker,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_lookup =
        match CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone()) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_call = match runtime.signing_worker_output_material_get_call(material_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let material_response =
        match execute_cloudflare_durable_object_call_v1(env, &material_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material = match require_signing_worker_output_material_get_response_v1(
        &material_call,
        material_response,
    ) {
        Ok(material) => material,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let prepare_request_digest = match parsed.request.prepare_request_digest() {
        Ok(digest) => digest,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let signing_digest = match parsed.request.signing_digest() {
        Ok(digest) => digest,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let presignature_lookup = match CloudflareSigningWorkerEcdsaPresignatureLookupV1::new(
        active_signing_worker.clone(),
        parsed.request.server_presignature_id.clone(),
        prepare_request_digest,
        signing_digest,
        now_unix_ms,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let presignature_call =
        match runtime.signing_worker_ecdsa_presignature_take_call(presignature_lookup) {
            Ok(call) => call,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let presignature_response =
        match execute_cloudflare_durable_object_call_v1(env, &presignature_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let server_presignature = match require_signing_worker_ecdsa_presignature_take_response_v1(
        &presignature_call,
        presignature_response,
    ) {
        Ok(record) => record,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    match handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1(
        handler,
        now_unix_ms,
        parsed,
        active_signing_worker,
        material,
        server_presignature,
    ) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles SigningWorker's private normal-signing route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_normal_signing_private_fetch_v1<Handler>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerNormalSigningFinalizeHandlerV2,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B normal-signing route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B normal-signing request must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B normal-signing request JSON parse failed: {err}"),
                400,
            );
        }
    };
    if let Err(err) = parsed.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        );
    }
    let lookup = match CloudflareActiveSigningWorkerStateLookupV1::from_normal_signing_scope(
        &parsed.request.scope,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let call = match runtime.active_signing_worker_state_get_call(lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let response = match execute_cloudflare_durable_object_call_v1(env, &call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let active_signing_worker =
        match require_signing_worker_output_active_state_get_response_v1(&call, response) {
            Ok(active_signing_worker) => active_signing_worker,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_lookup =
        match CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone()) {
            Ok(lookup) => lookup,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material_call = match runtime.signing_worker_output_material_get_call(material_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let material_response =
        match execute_cloudflare_durable_object_call_v1(env, &material_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let material = match require_signing_worker_output_material_get_response_v1(
        &material_call,
        material_response,
    ) {
        Ok(material) => material,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let round1_lookup = match CloudflareSigningWorkerRound1LookupV1::new(
        active_signing_worker.clone(),
        parsed.request.server_round1_handle().to_owned(),
        parsed.request.round1_binding_digest(),
        now_unix_ms,
    ) {
        Ok(lookup) => lookup,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let round1_call = match runtime.signing_worker_round1_take_call(round1_lookup) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let round1_response = match execute_cloudflare_durable_object_call_v1(env, &round1_call).await {
        Ok(response) => response,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let server_round1 =
        match require_signing_worker_round1_take_response_v1(&round1_call, round1_response) {
            Ok(record) => record,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    match handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2(
        handler,
        now_unix_ms,
        parsed,
        active_signing_worker,
        material,
        server_round1,
    ) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles the direct Signer A peer coordination route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_a_peer_fetch_v1(
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_peer_fetch_v1(
        CloudflareWorkerRoleV1::SignerA,
        CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1,
        key_store,
        handler,
        request,
    )
    .await
}

/// Handles the direct Signer B peer coordination route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_b_peer_fetch_v1(
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_peer_fetch_v1(
        CloudflareWorkerRoleV1::SignerB,
        CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1,
        key_store,
        handler,
        request,
    )
    .await
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
    worker_role: CloudflareWorkerRoleV1,
    expected_path: &str,
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B strict signer private route requires POST",
            405,
        );
    }
    if request.path() != expected_path {
        return worker::Response::error(
            format!(
                "{} strict private signer request must be served at {}",
                worker_role.as_str(),
                expected_path
            ),
            404,
        );
    }
    let parsed = match request.json::<WireMessageV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B strict signer private request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_signer_recipient_proof_bundle_private_request_v1(
        worker_role,
        handler,
        parsed,
    ) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_signer_peer_fetch_v1(
    worker_role: CloudflareWorkerRoleV1,
    expected_path: &str,
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B signer peer route requires POST", 405);
    }
    if request.path() != expected_path {
        return worker::Response::error(
            format!(
                "{} peer request must be served at {}",
                worker_role.as_str(),
                expected_path
            ),
            404,
        );
    }
    let parsed = match request.json::<WireMessageV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B signer peer request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_signer_peer_request_v1(worker_role, key_store, handler, parsed) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles one parsed direct A/B peer request through a platform-neutral handler.
pub fn handle_cloudflare_signer_peer_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    validate_cloudflare_signer_peer_request_v1(worker_role, &message)?;
    verify_cloudflare_signer_peer_message_authentication_v1(key_store, &message)?;
    let response = handler.handle_signer_wire_message(message.clone())?;
    validate_cloudflare_signer_peer_response_v1(worker_role, &message, &response)?;
    verify_cloudflare_signer_peer_message_authentication_v1(key_store, &response)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_replay_reserve_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareReplayReserveResponseV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_replay_reserve_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_lifecycle_put_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareLifecyclePutReceiptV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_lifecycle_put_response_v1(call, response)
}

/// Executes a Router project-policy Durable Object evaluation call.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_router_project_policy_evaluate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_project_policy_evaluate_response_v1(call, response)
}

/// Executes a Router quota Durable Object evaluation call.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_router_quota_evaluate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_quota_evaluate_response_v1(call, response)
}

/// Executes a Router abuse Durable Object evaluation call.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_router_abuse_evaluate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_abuse_evaluate_response_v1(call, response)
}

/// Executes a Router normal-signing project-policy Durable Object evaluation call.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_router_normal_signing_project_policy_evaluate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_normal_signing_project_policy_evaluate_response_v1(call, response)
}

/// Executes a Router normal-signing quota Durable Object evaluation call.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_router_normal_signing_quota_evaluate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_normal_signing_quota_evaluate_response_v1(call, response)
}

/// Executes a Router normal-signing abuse Durable Object evaluation call.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_router_normal_signing_abuse_evaluate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_normal_signing_abuse_evaluate_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_wallet_budget_put_grant_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_wallet_budget_put_grant_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_wallet_budget_reserve_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_wallet_budget_reserve_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_wallet_budget_validate_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_wallet_budget_validate_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_wallet_budget_commit_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_wallet_budget_commit_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_wallet_budget_release_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_wallet_budget_release_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_wallet_budget_status_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_wallet_budget_status_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
fn require_router_replay_reserve_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareReplayReserveResponseV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterReplayReserve { response } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router replay Durable Object returned wrong response branch",
        ));
    };
    Ok(response)
}

#[cfg(feature = "workers-rs")]
fn require_router_lifecycle_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareLifecyclePutReceiptV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterLifecyclePutPublicState { receipt } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router lifecycle Durable Object returned wrong response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_router_project_policy_evaluate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterProjectPolicyEvaluate { policy } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router project-policy Durable Object returned wrong response branch",
        ));
    };
    Ok(policy)
}

#[cfg(feature = "workers-rs")]
fn require_router_quota_evaluate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterQuotaEvaluate { quota } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router quota Durable Object returned wrong response branch",
        ));
    };
    Ok(quota)
}

#[cfg(feature = "workers-rs")]
fn require_router_abuse_evaluate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterAbuseEvaluate { abuse } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router abuse Durable Object returned wrong response branch",
        ));
    };
    Ok(abuse)
}

#[cfg(feature = "workers-rs")]
fn require_router_normal_signing_project_policy_evaluate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterNormalSigningProjectPolicyEvaluate { policy } =
        response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router normal-signing project-policy Durable Object returned wrong response branch",
        ));
    };
    Ok(policy)
}

#[cfg(feature = "workers-rs")]
fn require_router_normal_signing_quota_evaluate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterNormalSigningQuotaEvaluate { quota } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router normal-signing quota Durable Object returned wrong response branch",
        ));
    };
    Ok(quota)
}

#[cfg(feature = "workers-rs")]
fn require_router_normal_signing_abuse_evaluate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterNormalSigningAbuseEvaluate { abuse } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router normal-signing abuse Durable Object returned wrong response branch",
        ));
    };
    Ok(abuse)
}

#[cfg(feature = "workers-rs")]
fn require_router_wallet_budget_reserve_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetReserved {
        reservation_id,
        status,
    } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router wallet budget Durable Object returned wrong reserve response branch",
        ));
    };
    Ok((reservation_id, status))
}

#[cfg(feature = "workers-rs")]
fn require_router_wallet_budget_validate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetValidated {
        reservation_id,
        status,
    } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router wallet budget Durable Object returned wrong validate response branch",
        ));
    };
    Ok((reservation_id, status))
}

#[cfg(feature = "workers-rs")]
fn require_router_wallet_budget_commit_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetCommitted {
        reservation_id,
        status,
    } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router wallet budget Durable Object returned wrong commit response branch",
        ));
    };
    Ok((reservation_id, status))
}

#[cfg(feature = "workers-rs")]
fn require_router_wallet_budget_release_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<(String, CloudflareRouterWalletBudgetStatusV1)> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetReleased {
        reservation_id,
        status,
    } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router wallet budget Durable Object returned wrong release response branch",
        ));
    };
    Ok((reservation_id, status))
}

#[cfg(feature = "workers-rs")]
fn require_router_wallet_budget_put_grant_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetGrantPut { status } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router wallet budget Durable Object returned wrong put-grant response branch",
        ));
    };
    Ok(status)
}

#[cfg(feature = "workers-rs")]
fn require_router_wallet_budget_status_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetStatus { status } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router wallet budget Durable Object returned wrong status response branch",
        ));
    };
    Ok(status)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_output_activate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerOutputActivate { receipt } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_direct_activation_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1>
{
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerDirectActivationPut { outcome } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong direct activation response branch",
        ));
    };
    Ok(outcome)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_output_active_state_get_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerOutputActiveStateGet {
        active_signing_worker_state,
    } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong active-state response branch",
        ));
    };
    Ok(active_signing_worker_state)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_output_material_get_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareServerOutputMaterialRecordV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerOutputMaterialGet { material } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong material response branch",
        ));
    };
    Ok(material)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_round1_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerRound1PutReceiptV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerRound1Put { receipt } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong round-1 put response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_round1_take_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerRound1RecordV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerRound1Take { record } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong round-1 response branch",
        ));
    };
    Ok(record)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ed25519_presign_pool_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEd25519PresignPoolPutReceiptV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerEd25519PresignPoolPut { receipt } =
        response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong Ed25519 presign-pool put response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ed25519_presign_pool_take_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEd25519PresignPoolRecordV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerEd25519PresignPoolTake { record } =
        response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong Ed25519 presign-pool take response branch",
        ));
    };
    Ok(record)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ecdsa_presignature_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerEcdsaPresignaturePut { receipt } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong ECDSA presignature put response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ecdsa_presignature_take_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignatureRecordV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerEcdsaPresignatureTake { record } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong ECDSA presignature take response branch",
        ));
    };
    Ok(record)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ecdsa_presignature_pool_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerEcdsaPresignaturePoolPut { receipt } =
        response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong ECDSA presignature pool put response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ecdsa_presignature_pool_take_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::SigningWorkerEcdsaPresignaturePoolTake { record } =
        response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output Durable Object returned wrong ECDSA presignature pool take response branch",
        ));
    };
    Ok(record)
}

#[cfg(feature = "workers-rs")]
async fn post_service_json<TReq, TResp>(
    env: &worker::Env,
    binding_name: &str,
    url: &str,
    label: &str,
    request: &TReq,
) -> RouterAbProtocolResult<TResp>
where
    TReq: Serialize,
    TResp: serde::de::DeserializeOwned,
{
    let fetcher = env.service(binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, binding_name),
            binding_name,
            "service",
            err,
        )
    })?;
    let request_body = cloudflare_service_json_request_body_v1(label, request)?;
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{label} header construction failed: {err}"),
            )
        })?;
    set_cloudflare_internal_service_auth_header_v1(env, &headers, label)?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request_for_fetch = worker::Request::new_with_init(url, &init).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} service request construction failed: {err}"),
        )
    })?;
    let mut response = fetcher
        .fetch_request(request_for_fetch)
        .await
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{label} service request failed: {err}"),
            )
        })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} service returned HTTP status {status}"),
        ));
    }
    response.json::<TResp>().await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response JSON parse failed: {err}"),
        )
    })
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signer_recipient_proof_bundle_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    public_request: &PublicRouterRequestV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let label = format!("{} strict service request", peer.peer_role.as_str());
    let response: CloudflareSignerRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_signer_service_url_v1(peer)?,
        &label,
        &bootstrap,
    )
    .await?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    registration_request: &RouterAbEcdsaHssRegistrationBootstrapRequestV1,
    public_request: &PublicRouterRequestV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let private_request = CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1::new(
        peer.peer_role,
        registration_request.clone(),
        signer_bootstrap,
    )?;
    let label = format!(
        "{} ECDSA-HSS registration service request",
        peer.peer_role.as_str()
    );
    let response: CloudflareSignerRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_ecdsa_hss_deriver_registration_service_url_v1(peer)?,
        &label,
        &private_request,
    )
    .await?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    export_request: &RouterAbEcdsaHssExplicitExportRequestV1,
    public_request: &PublicRouterRequestV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let private_request = CloudflareEcdsaHssDeriverExportPrivateRequestV1::new(
        peer.peer_role,
        export_request.clone(),
        signer_bootstrap,
    )?;
    let label = format!(
        "{} ECDSA-HSS export service request",
        peer.peer_role.as_str()
    );
    let response: CloudflareSignerClientRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_ecdsa_hss_deriver_export_service_url_v1(peer)?,
        &label,
        &private_request,
    )
    .await?;
    validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_ecdsa_hss_deriver_recovery_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    recovery_request: &RouterAbEcdsaHssRecoveryRequestV1,
    public_request: &PublicRouterRequestV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let private_request = CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1::new(
        peer.peer_role,
        recovery_request.clone(),
        signer_bootstrap,
    )?;
    let label = format!(
        "{} ECDSA-HSS recovery service request",
        peer.peer_role.as_str()
    );
    let response: CloudflareSignerClientRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_ecdsa_hss_deriver_recovery_service_url_v1(peer)?,
        &label,
        &private_request,
    )
    .await?;
    validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_ecdsa_hss_deriver_activation_refresh_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    refresh_request: &RouterAbEcdsaHssActivationRefreshRequestV1,
    public_request: &PublicRouterRequestV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let private_request = CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1::new(
        peer.peer_role,
        refresh_request.clone(),
        signer_bootstrap,
    )?;
    let label = format!(
        "{} ECDSA-HSS activation-refresh service request",
        peer.peer_role.as_str()
    );
    let response: CloudflareSignerRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_ecdsa_hss_deriver_refresh_service_url_v1(peer)?,
        &label,
        &private_request,
    )
    .await?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signing_worker_recipient_proof_bundle_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict SigningWorker proof-bundle activation must target SigningWorker",
        ));
    }
    request.validate()?;
    let receipt: CloudflareSigningWorkerOutputActivationReceiptV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_signing_worker_recipient_proof_bundle_activation_service_url_v1(peer)?,
        "SigningWorker proof-bundle activation request",
        request,
    )
    .await?;
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareEcdsaHssSigningWorkerActivationRequestV1,
) -> RouterAbProtocolResult<CloudflareEcdsaHssSigningWorkerActivationReceiptV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict ECDSA-HSS SigningWorker activation must target SigningWorker",
        ));
    }
    request.validate()?;
    let receipt: CloudflareEcdsaHssSigningWorkerActivationReceiptV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_ecdsa_hss_signing_worker_activation_service_url_v1(peer)?,
        "ECDSA-HSS SigningWorker activation request",
        request,
    )
    .await?;
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_direct_recipient_proof_bundle_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    delivery: &CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "direct SigningWorker activation delivery must target SigningWorker",
        ));
    }
    delivery.validate()?;
    let receipt: CloudflareSigningWorkerDirectRecipientProofBundleActivationReceiptV1 =
        post_service_json(
            env,
            &peer.binding_name,
            cloudflare_ecdsa_hss_signing_worker_activation_service_url_v1(peer)?,
            "direct SigningWorker activation delivery",
            delivery,
        )
        .await?;
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareEcdsaHssSigningWorkerActivationRefreshRequestV1,
) -> RouterAbProtocolResult<CloudflareEcdsaHssSigningWorkerActivationReceiptV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict ECDSA-HSS SigningWorker activation refresh must target SigningWorker",
        ));
    }
    request.validate()?;
    let receipt: CloudflareEcdsaHssSigningWorkerActivationReceiptV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_url_v1(peer)?,
        "ECDSA-HSS SigningWorker activation-refresh request",
        request,
    )
    .await?;
    receipt.validate()?;
    Ok(receipt)
}

/// Sends one v2 normal-signing finalize request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
) -> RouterAbProtocolResult<NormalSigningResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing v2 finalize must target SigningWorker",
        ));
    }
    request.validate()?;
    let expected_scope = request.request.scope.clone();
    let expected_signing_payload_digest = request.request.signing_payload_digest();
    let expected_signature_scheme = request.request.protocol.signature_scheme();
    let response: NormalSigningResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        &cloudflare_signing_worker_normal_signing_service_url_v1(peer)?,
        "normal-signing v2 finalize",
        &request,
    )
    .await?;
    response.validate()?;
    if response.scope == expected_scope
        && response.signing_payload_digest == expected_signing_payload_digest
        && response.signature_scheme == expected_signature_scheme
    {
        return Ok(response);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "normal-signing v2 finalize response does not match admitted request",
    ))
}

/// Sends one v2 normal-signing pool-hit finalize request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_service_call_v2(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedNormalSigningPresignPoolHitFinalizeRequestV2,
) -> RouterAbProtocolResult<NormalSigningResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing v2 presign-pool-hit finalize must target SigningWorker",
        ));
    }
    request.validate()?;
    let lowered = request.to_normal_finalize_request_v2()?;
    let expected_scope = lowered.scope.clone();
    let expected_signing_payload_digest = lowered.signing_payload_digest();
    let expected_signature_scheme = lowered.protocol.signature_scheme();
    let response: NormalSigningResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        &cloudflare_signing_worker_normal_signing_presign_pool_service_url_v1(peer)?,
        "normal-signing v2 presign-pool-hit finalize",
        &request,
    )
    .await?;
    response.validate()?;
    if response.scope == expected_scope
        && response.signing_payload_digest == expected_signing_payload_digest
        && response.signature_scheme == expected_signature_scheme
    {
        return Ok(response);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "normal-signing v2 presign-pool-hit finalize response does not match admitted request",
    ))
}

/// Sends one v2 normal-signing prepare request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
) -> RouterAbProtocolResult<NormalSigningRound1PrepareResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing v2 prepare must target SigningWorker",
        ));
    }
    request.validate()?;
    let response: NormalSigningRound1PrepareResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        &cloudflare_signing_worker_normal_signing_round1_prepare_service_url_v1(peer)?,
        "normal-signing v2 prepare",
        &request,
    )
    .await?;
    response.validate()?;
    if response.scope == request.scope
        && response.signing_payload_digest == request.admission_candidate.signing_payload_digest
        && response.round1_binding_digest == request.round1_binding_digest()?
        && response.expires_at_ms == request.expires_at_ms
    {
        return Ok(response);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "normal-signing v2 prepare response does not match admitted request",
    ))
}

/// Sends one v2 normal-signing presign-pool refill request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_call_v2(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedNormalSigningPresignPoolPrepareRequestV2,
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolPrepareResponseV2> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing v2 presign-pool prepare must target SigningWorker",
        ));
    }
    request.validate()?;
    let response: RouterAbEd25519PresignPoolPrepareResponseV2 = post_service_json(
        env,
        &peer.binding_name,
        &cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_url_v1(peer)?,
        "normal-signing v2 presign-pool prepare",
        &request,
    )
    .await?;
    response.validate_for_request(&request.request)?;
    Ok(response)
}

/// Sends one ECDSA-HSS normal-signing prepare request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS prepare must target SigningWorker",
        ));
    }
    request.validate()?;
    let response: RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        &cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_url_v1(peer)?,
        "ECDSA-HSS prepare",
        &request,
    )
    .await?;
    response.validate_for_request(&request.request)?;
    Ok(response)
}

/// Sends one ECDSA-HSS normal-signing finalize request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS finalize must target SigningWorker",
        ));
    }
    request.validate()?;
    let prepare_request = request.request.prepare_request()?;
    let response: RouterAbEcdsaHssEvmDigestSigningResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        &cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_url_v1(peer)?,
        "ECDSA-HSS finalize",
        &request,
    )
    .await?;
    response.validate_for_request(&prepare_request)?;
    Ok(response)
}

/// Sends one direct A/B peer message over a Cloudflare Service Binding.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signer_peer_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    peer.validate()?;
    validate_cloudflare_signer_peer_request_v1(peer.peer_role, message)?;
    let label = format!("{} peer request", peer.peer_role.as_str());
    let response: WireMessageV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_signer_peer_service_url_v1(peer)?,
        &label,
        message,
    )
    .await?;
    validate_cloudflare_signer_peer_response_v1(peer.peer_role, message, &response)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signer_peer_requests_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    requests: &[WireMessageV1],
) -> RouterAbProtocolResult<Vec<WireMessageV1>> {
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        responses.push(execute_cloudflare_signer_peer_service_call_v1(env, peer, request).await?);
    }
    Ok(responses)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signer_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router public handler can forward signer work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_ecdsa_hss_deriver_registration_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/register"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/register"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS registration can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_ecdsa_hss_deriver_export_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/export"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/export"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS export can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_ecdsa_hss_deriver_recovery_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/recover"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/recover"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS recovery can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_ecdsa_hss_deriver_refresh_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/refresh"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/refresh"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS activation refresh can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signer_peer_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/peer"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/peer"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "direct A/B peer handler can send peer work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_recipient_proof_bundle_activation_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/proof-bundle-activation"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict SigningWorker proof-bundle activation can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_ecdsa_hss_signing_worker_activation_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/activate"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict ECDSA-HSS SigningWorker activation can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/refresh"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict ECDSA-HSS SigningWorker activation refresh can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_normal_signing_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal signing can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_normal_signing_presign_pool_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign/presign-pool"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing presign-pool finalize can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_normal_signing_round1_prepare_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign/prepare"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing round-1 prepare can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign/presign-pool/prepare"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing presign-pool prepare can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS prepare can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/sign"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS finalize can target only SigningWorker",
        )),
    }
}

/// Parses role-specific Worker bindings from an Env reader.
pub fn parse_cloudflare_worker_bindings_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareWorkerBindingsV1> {
    match worker_role {
        CloudflareWorkerRoleV1::Router => {
            CloudflareWorkerBindingsV1::router(parse_cloudflare_router_bindings_v1(env)?)
        }
        CloudflareWorkerRoleV1::SignerA => {
            CloudflareWorkerBindingsV1::deriver_a(parse_cloudflare_deriver_a_bindings_v1(env)?)
        }
        CloudflareWorkerRoleV1::SignerB => {
            CloudflareWorkerBindingsV1::deriver_b(parse_cloudflare_deriver_b_bindings_v1(env)?)
        }
        CloudflareWorkerRoleV1::SigningWorker => CloudflareWorkerBindingsV1::signing_worker(
            parse_cloudflare_signing_worker_bindings_v1(env)?,
        ),
    }
}

/// Parses Router Worker bindings from an Env reader.
pub fn parse_cloudflare_router_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareRouterBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::Router,
        env,
        ROUTER_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareRouterBindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::RouterReplay,
            ROUTER_REPLAY_DO_BINDING_ENV,
            ROUTER_REPLAY_DO_OBJECT_ENV,
            ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
        )?,
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            ROUTER_LIFECYCLE_DO_BINDING_ENV,
            ROUTER_LIFECYCLE_DO_OBJECT_ENV,
            ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
        )?,
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::RouterWalletBudget,
            ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
            ROUTER_WALLET_BUDGET_DO_OBJECT_ENV,
            ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
        )?,
        parse_cloudflare_router_admission_bindings_v1(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerA,
            SIGNER_A_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerB,
            SIGNER_B_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SigningWorker,
            SIGNING_WORKER_PEER_BINDING_ENV,
        )?,
    )
}

/// Parses Router admission-provider bindings from an Env reader.
pub fn parse_cloudflare_router_admission_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareRouterAdmissionBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::Router,
        env,
        ROUTER_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareRouterAdmissionBindingsV1::new(
        CloudflareRouterJwtVerifierBindingV1::new(
            read_required_env_text(env, ROUTER_JWT_ISSUER_ENV)?,
            read_required_env_text(env, ROUTER_JWT_AUDIENCE_ENV)?,
            read_required_env_text(env, ROUTER_JWT_JWKS_URL_ENV)?,
        )?,
        CloudflareRouterAdmissionStoreBindingsV1::new(
            read_durable_object_binding(
                env,
                CloudflareDurableObjectScopeV1::RouterProjectPolicy,
                ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
                ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
                ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
            )?,
            read_durable_object_binding(
                env,
                CloudflareDurableObjectScopeV1::RouterQuota,
                ROUTER_QUOTA_DO_BINDING_ENV,
                ROUTER_QUOTA_DO_OBJECT_ENV,
                ROUTER_QUOTA_DO_KEY_PREFIX_ENV,
            )?,
            read_durable_object_binding(
                env,
                CloudflareDurableObjectScopeV1::RouterAbuse,
                ROUTER_ABUSE_DO_BINDING_ENV,
                ROUTER_ABUSE_DO_OBJECT_ENV,
                ROUTER_ABUSE_DO_KEY_PREFIX_ENV,
            )?,
        )?,
    )
}

/// Parses public signer-envelope HPKE keys from an Env reader.
pub fn parse_cloudflare_signer_envelope_hpke_public_key_set_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkePublicKeySetV1> {
    CloudflareSignerEnvelopeHpkePublicKeySetV1::new(
        read_signer_envelope_hpke_public_key(
            env,
            Role::SignerA,
            SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
        read_signer_envelope_hpke_public_key(
            env,
            Role::SignerB,
            SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
    )
}

/// Parses current and optional previous signer-envelope HPKE public keys.
pub fn parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1> {
    let current = parse_cloudflare_signer_envelope_hpke_public_key_set_v1(env)?;
    let previous_keys = [
        SIGNER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
        SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        SIGNER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
        SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV,
    ];
    let has_previous = previous_keys
        .iter()
        .map(|key| read_optional_env_text(env, key))
        .collect::<RouterAbProtocolResult<Vec<_>>>()?
        .into_iter()
        .any(|value| value.is_some());
    if !has_previous {
        return CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1::current_only(current);
    }
    let previous = CloudflareSignerEnvelopeHpkePublicKeySetV1::new(
        read_signer_envelope_hpke_public_key(
            env,
            Role::SignerA,
            SIGNER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
        read_signer_envelope_hpke_public_key(
            env,
            Role::SignerB,
            SIGNER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
    )?;
    let previous_retire_at_ms =
        read_required_env_u64(env, ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV)?;
    CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1::current_and_previous(
        current,
        previous,
        previous_retire_at_ms,
    )
}

/// Parses public A/B peer-message verifying keys from an Env reader.
pub fn parse_cloudflare_signer_peer_verifying_key_set_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeySetV1> {
    read_signer_peer_verifying_key_set(env)
}

/// Builds the public Router A/B keyset discovery response from Env.
pub fn build_cloudflare_router_public_keyset_v2(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareRouterPublicKeysetV2> {
    CloudflareRouterPublicKeysetV2::new(
        "router_ab_keyset_v2",
        parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1(env)?,
        parse_cloudflare_signer_peer_verifying_key_set_v1(env)?.to_hex_descriptor_set()?,
        CloudflarePublicHpkeKeyDescriptorV1::new(
            read_required_env_text(env, SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV)?,
            read_required_env_text(env, SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV)?,
        )?,
    )
}

/// Parses the current Worker's role-local signer-envelope HPKE private-key binding.
pub fn parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerA => read_signer_envelope_hpke_decrypt_key_binding(
            env,
            Role::SignerA,
            SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::SignerB => read_signer_envelope_hpke_decrypt_key_binding(
            env,
            Role::SignerB,
            SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker cannot parse a signer-envelope HPKE decrypt key",
            ))
        }
    }
}

/// Parses the current Worker's role-local signer-envelope HPKE private-key rotation set.
pub fn parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1> {
    let current = parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(worker_role, env)?;
    match worker_role {
        CloudflareWorkerRoleV1::SignerA => read_signer_envelope_hpke_decrypt_key_binding_set(
            env,
            current,
            Role::SignerA,
            SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            SIGNER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::SignerB => read_signer_envelope_hpke_decrypt_key_binding_set(
            env,
            current,
            Role::SignerB,
            SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            SIGNER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            SIGNER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker cannot parse a signer-envelope HPKE decrypt-key rotation set",
            ))
        }
    }
}

/// Parses Signer A Worker bindings from an Env reader.
pub fn parse_cloudflare_deriver_a_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerABindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::SignerA,
        env,
        SIGNER_A_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareSignerABindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerA,
            },
            SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
            SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
            SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
        )?,
        read_root_share_wire_secret_binding(
            env,
            Role::SignerA,
            SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        )?,
        parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
            CloudflareWorkerRoleV1::SignerA,
            env,
        )?,
        read_signer_peer_signing_key_binding(
            env,
            Role::SignerA,
            SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
            SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_verifying_key_set(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerB,
            SIGNER_B_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SigningWorker,
            SIGNING_WORKER_PEER_BINDING_ENV,
        )?,
    )
}

/// Parses SigningWorker bindings from an Env reader.
pub fn parse_cloudflare_signing_worker_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::SigningWorker,
        env,
        SIGNING_WORKER_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareSigningWorkerBindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::signing_worker_server_output(),
            SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
        )?,
        read_server_output_hpke_decrypt_key_binding(
            env,
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV,
        )?,
    )
}

/// Parses Signer B Worker bindings from an Env reader.
pub fn parse_cloudflare_deriver_b_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerBBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::SignerB,
        env,
        SIGNER_B_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareSignerBBindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerB,
            },
            SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
            SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
            SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
        )?,
        read_root_share_wire_secret_binding(
            env,
            Role::SignerB,
            SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        )?,
        parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
            CloudflareWorkerRoleV1::SignerB,
            env,
        )?,
        read_signer_peer_signing_key_binding(
            env,
            Role::SignerB,
            SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
            SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_verifying_key_set(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerA,
            SIGNER_A_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SigningWorker,
            SIGNING_WORKER_PEER_BINDING_ENV,
        )?,
    )
}

/// `workers-rs` Env reader for Cloudflare Worker startup parsing.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, Copy)]
pub struct CloudflareWorkerEnvReaderV1<'a> {
    env: &'a worker::Env,
}

#[cfg(feature = "workers-rs")]
impl<'a> CloudflareWorkerEnvReaderV1<'a> {
    /// Creates a reader over a real Cloudflare Worker Env.
    pub fn new(env: &'a worker::Env) -> Self {
        Self { env }
    }
}

#[cfg(feature = "workers-rs")]
impl CloudflareEnvReaderV1 for CloudflareWorkerEnvReaderV1<'_> {
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>> {
        match self.env.var(key) {
            Ok(value) => Ok(Some(value.to_string())),
            Err(err) if worker_binding_is_missing(&err, key) => Ok(None),
            Err(err) => Err(worker_binding_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                key,
                "text Env",
                err,
            )),
        }
    }
}

/// Parses Worker bindings from a real Cloudflare Env and checks runtime bindings exist.
#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_worker_bindings_from_worker_env_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &worker::Env,
) -> RouterAbProtocolResult<CloudflareWorkerBindingsV1> {
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    let bindings = parse_cloudflare_worker_bindings_v1(worker_role, &reader)?;
    validate_cloudflare_worker_env_bindings_v1(env, &bindings)?;
    Ok(bindings)
}

/// Checks the real Worker Env has every Durable Object and service binding required by descriptors.
#[cfg(feature = "workers-rs")]
pub fn validate_cloudflare_worker_env_bindings_v1(
    env: &worker::Env,
    bindings: &CloudflareWorkerBindingsV1,
) -> RouterAbProtocolResult<()> {
    match bindings {
        CloudflareWorkerBindingsV1::Router { bindings } => {
            require_worker_durable_object(env, &bindings.replay)?;
            require_worker_durable_object(env, &bindings.lifecycle)?;
            require_worker_durable_object(env, &bindings.wallet_budget)?;
            require_worker_durable_object(env, &bindings.admission.stores.project_policy)?;
            require_worker_durable_object(env, &bindings.admission.stores.quota)?;
            require_worker_durable_object(env, &bindings.admission.stores.abuse)?;
            require_worker_service(env, &bindings.deriver_a)?;
            require_worker_service(env, &bindings.deriver_b)?;
            require_worker_service(env, &bindings.signing_worker)
        }
        CloudflareWorkerBindingsV1::SignerA { bindings } => {
            require_worker_durable_object(env, &bindings.root_share)?;
            require_worker_root_share_wire_secret(env, &bindings.root_share_wire_secret)?;
            require_worker_hpke_secret_set(env, &bindings.envelope_decrypt_key)?;
            require_worker_peer_signing_secret(env, &bindings.peer_signing_key)?;
            require_worker_service(env, &bindings.deriver_b)?;
            require_worker_service(env, &bindings.signing_worker)
        }
        CloudflareWorkerBindingsV1::SignerB { bindings } => {
            require_worker_durable_object(env, &bindings.root_share)?;
            require_worker_root_share_wire_secret(env, &bindings.root_share_wire_secret)?;
            require_worker_hpke_secret_set(env, &bindings.envelope_decrypt_key)?;
            require_worker_peer_signing_secret(env, &bindings.peer_signing_key)?;
            require_worker_service(env, &bindings.deriver_a)?;
            require_worker_service(env, &bindings.signing_worker)
        }
        CloudflareWorkerBindingsV1::SigningWorker { bindings } => {
            require_worker_durable_object(env, &bindings.server_output)?;
            require_worker_server_output_hpke_secret(env, &bindings.server_output_decrypt_key)
        }
    }
}

/// Expected signer root-share startup check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerStartupCheckV1 {
    /// Worker role being checked.
    pub worker_role: CloudflareWorkerRoleV1,
    /// Signer role expected in storage.
    pub signer_role: Role,
    /// Signer set expected in storage.
    pub signer_set_id: String,
    /// Root-share epoch expected in storage.
    pub root_share_epoch: RootShareEpoch,
    /// Root-share Durable Object binding.
    pub root_share_binding: CloudflareDurableObjectBindingV1,
}

impl CloudflareSignerStartupCheckV1 {
    /// Creates a fail-closed Deriver A startup check descriptor.
    pub fn deriver_a(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        root_share_binding: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        Self::new(
            CloudflareWorkerRoleV1::SignerA,
            Role::SignerA,
            signer_set_id,
            root_share_epoch,
            root_share_binding,
        )
    }

    /// Creates a fail-closed Deriver B startup check descriptor.
    pub fn deriver_b(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        root_share_binding: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        Self::new(
            CloudflareWorkerRoleV1::SignerB,
            Role::SignerB,
            signer_set_id,
            root_share_epoch,
            root_share_binding,
        )
    }

    fn new(
        worker_role: CloudflareWorkerRoleV1,
        signer_role: Role,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        root_share_binding: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let check = Self {
            worker_role,
            signer_role,
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            root_share_binding,
        };
        check.validate()?;
        Ok(check)
    }

    /// Validates the startup check descriptor.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_signer_role(self.signer_role)?;
        require_scope(
            &self.root_share_binding,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: self.signer_role,
            },
            self.worker_role,
        )
    }
}

fn require_scope(
    binding: &CloudflareDurableObjectBindingV1,
    expected_scope: CloudflareDurableObjectScopeV1,
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<()> {
    binding.validate_visible_to(worker_role)?;
    if binding.scope == expected_scope {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "{} Worker expected {:?} Durable Object scope, received {:?}",
            worker_role.as_str(),
            expected_scope,
            binding.scope
        ),
    ))
}

fn validate_admission_store_call_v1(
    name: &str,
    call: &CloudflareDurableObjectCallV1,
    expected_scope: CloudflareDurableObjectScopeV1,
    expected_operation: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<()> {
    call.validate()?;
    require_scope(
        &call.binding,
        expected_scope,
        CloudflareWorkerRoleV1::Router,
    )?;
    if call.operation_kind() == expected_operation {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("{name} admission-store call has wrong operation branch"),
    ))
}

fn decode_base64url_json_v1<T>(field: &str, encoded: &str) -> RouterAbProtocolResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    serde_json::from_slice(&bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} JSON parse failed: {err}"),
        )
    })
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

fn decode_base64url_fixed_64_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<[u8; 64]> {
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 64 bytes, received {}", bytes.len()),
        )
    })
}

fn encode_base64url_bytes_v1(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_base64url_bytes_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field, encoded)?;
    require_no_ascii_whitespace(field, encoded)?;
    if encoded.contains('=') {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url"),
        ));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} base64url decode failed: {err}"),
            )
        })
}

fn map_ecdsa_hss_error_v1(err: ecdsa_hss::EcdsaHssError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("ECDSA-HSS material validation failed: {}", err.message),
    )
}

fn verify_router_ed25519_jwt_signature_v1(
    signing_input: &str,
    signature: &[u8; 64],
    key: &CloudflareRouterEd25519JwkV1,
) -> RouterAbProtocolResult<()> {
    key.validate()?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&key.public_key).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router JWT Ed25519 JWK public key bytes are invalid",
        )
    })?;
    let signature = Ed25519Signature::from_bytes(signature);
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT Ed25519 signature verification failed",
            )
        })
}

fn select_router_jwt_session_id_v1(
    sid: Option<String>,
    session_id: Option<String>,
) -> RouterAbProtocolResult<String> {
    match (sid, session_id) {
        (Some(sid), Some(session_id)) if sid == session_id => Ok(sid),
        (Some(_), Some(_)) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router JWT sid and session_id claims differ",
        )),
        (Some(sid), None) => {
            require_non_empty("jwt sid", &sid)?;
            Ok(sid)
        }
        (None, Some(session_id)) => {
            require_non_empty("jwt session_id", &session_id)?;
            Ok(session_id)
        }
        (None, None) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router JWT must include sid or session_id",
        )),
    }
}

fn unix_seconds_to_millis_v1(field: &str, seconds: u64) -> RouterAbProtocolResult<u64> {
    seconds.checked_mul(1_000).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} seconds overflow milliseconds"),
        )
    })
}

fn router_jwt_segment_error() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        "Router JWT must use compact three-segment serialization",
    )
}

#[cfg(feature = "workers-rs")]
fn hash_optional_header_v1(hasher: &mut Sha256, name: &[u8], value: Option<&str>) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    match value {
        Some(value) => {
            let bytes = value.as_bytes();
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update(0u64.to_be_bytes()),
    }
}

fn require_peer_role(
    peer: &CloudflarePeerBindingV1,
    expected: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<()> {
    peer.validate()?;
    if peer.peer_role == expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "Cloudflare peer binding expected {} role, received {}",
            expected.as_str(),
            peer.peer_role.as_str()
        ),
    ))
}

fn decode_cloudflare_recipient_proof_bundle_wire_v1(
    field: &str,
    message: &WireMessageV1,
    expected_signer_role: Role,
    expected_recipient_role: Role,
    expected_opened_share_kind: OpenedShareKind,
) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
    require_signer_role(expected_signer_role)?;
    if message.kind != WireMessageKindV1::RecipientProofBundle {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} must be a recipient_proof_bundle wire message"),
        ));
    }
    let envelope = decode_recipient_proof_bundle_ciphertext_v1(message.payload.as_bytes())?;
    if envelope.transcript_digest != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match ciphertext envelope"),
        ));
    }
    if envelope.signer.role != expected_signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} proof-bundle signer role is not expected"),
        ));
    }
    if envelope.recipient_role != expected_recipient_role
        || envelope.opened_share_kind != expected_opened_share_kind
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} proof-bundle recipient binding is invalid"),
        ));
    }
    Ok(envelope)
}

fn expected_cloudflare_signer_identity_for_role_v1(
    router_payload: &RouterToSignerPayloadV1,
    role: Role,
) -> RouterAbProtocolResult<&SignerIdentityV1> {
    require_signer_role(role)?;
    match role {
        Role::SignerA => Ok(&router_payload.signer_set().signer_a),
        Role::SignerB => Ok(&router_payload.signer_set().signer_b),
        _ => unreachable!("require_signer_role accepted only signer roles"),
    }
}

fn validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
    field: &str,
    envelope: &RecipientProofBundleCiphertextV1,
    router_payload: &RouterToSignerPayloadV1,
    expected_signer: &SignerIdentityV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    router_payload.validate()?;
    expected_signer.validate()?;
    if envelope.signer != *expected_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} signer identity does not match signer set"),
        ));
    }
    if envelope.transcript_digest != router_payload.transcript_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match Router payload"),
        ));
    }
    match (envelope.recipient_role, envelope.opened_share_kind) {
        (Role::Client, OpenedShareKind::XClientBase) => {
            let metadata = router_payload.transcript_metadata();
            if envelope.recipient_identity != metadata.client_id
                || envelope.recipient_encryption_key != metadata.client_ephemeral_public_key
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} client recipient binding does not match Router payload"),
                ));
            }
        }
        (Role::Server, OpenedShareKind::XServerBase) => {
            let server = &router_payload.signer_set().selected_server;
            if envelope.recipient_identity != server.server_id
                || envelope.recipient_encryption_key != server.recipient_encryption_key
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} server recipient binding does not match Router payload"),
                ));
            }
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{field} recipient proof-bundle binding is invalid"),
            ));
        }
    }
    Ok(())
}

fn validate_cloudflare_recipient_proof_bundle_envelope_for_activation_context_v1(
    field: &str,
    envelope: &RecipientProofBundleCiphertextV1,
    activation_context: &SigningWorkerActivationContextV1,
    expected_signer: &SignerIdentityV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    activation_context.validate()?;
    expected_signer.validate()?;
    if envelope.signer != *expected_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} signer identity does not match activation context"),
        ));
    }
    if envelope.transcript_digest != activation_context.transcript_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match activation context"),
        ));
    }
    if envelope.recipient_role != Role::Server
        || envelope.opened_share_kind != OpenedShareKind::XServerBase
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} SigningWorker activation bundle is not x_server_base"),
        ));
    }
    let selected_worker = &activation_context.signer_set().selected_server;
    if envelope.recipient_identity != selected_worker.server_id
        || envelope.recipient_encryption_key != selected_worker.recipient_encryption_key
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} recipient binding does not match selected SigningWorker"),
        ));
    }
    Ok(())
}

fn require_preloaded_peer_response_v1(message: &WireMessageV1) -> RouterAbProtocolResult<()> {
    match message.kind {
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA
            if !message.payload.as_bytes().is_empty() =>
        {
            decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
            Ok(())
        }
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "preloaded A/B peer response payload must be non-empty",
            ))
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "preloaded signer host peer response must be an A/B peer message, received {}",
                message.kind.as_str()
            ),
        )),
    }
}

fn require_preloaded_peer_request_v1(message: &WireMessageV1) -> RouterAbProtocolResult<()> {
    match message.kind {
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA
            if !message.payload.as_bytes().is_empty() =>
        {
            decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
            Ok(())
        }
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "preloaded A/B peer request payload must be non-empty",
            ))
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "preloaded signer host peer request must be an A/B peer message, received {}",
                message.kind.as_str()
            ),
        )),
    }
}

fn validate_signer_verifying_keys_v1(
    keys: &[AbPeerMessageVerifyingKeyV1],
) -> RouterAbProtocolResult<()> {
    for (index, key) in keys.iter().enumerate() {
        key.validate()?;
        for prior in &keys[..index] {
            if prior.signer == key.signer {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidSignerIdentity,
                    "duplicate A/B peer signer verifying key",
                ));
            }
        }
    }
    Ok(())
}

fn verify_peer_message_authentication_with_keys_v1(
    keys: &[AbPeerMessageVerifyingKeyV1],
    message: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    let payload = decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
    let verifying_key = keys
        .iter()
        .find(|key| key.signer == payload.from)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "preloaded A/B peer message sender has no trusted verifying key",
            )
        })?;
    verify_ab_peer_message_ed25519_signature_v1(&payload, verifying_key)
}

fn expected_signer_private_request_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerA => Ok(WireMessageKindV1::RouterToSignerA),
        CloudflareWorkerRoleV1::SignerB => Ok(WireMessageKindV1::RouterToSignerB),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker has no private signer request kind",
            ))
        }
    }
}

fn cloudflare_worker_signer_role_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<Role> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerA => Ok(Role::SignerA),
        CloudflareWorkerRoleV1::SignerB => Ok(Role::SignerB),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker has no signer plaintext role",
            ))
        }
    }
}

fn cloudflare_signer_identities_for_request_v1(
    request: &CloudflareValidatedSignerPrivateRequestV1,
    local_role: Role,
) -> RouterAbProtocolResult<(SignerIdentityV1, SignerIdentityV1, CloudflareWorkerRoleV1)> {
    require_signer_role(local_role)?;
    let assignment = request
        .router_payload()
        .require_recipient_role(local_role)?;
    let signer_set = request.router_payload().signer_set();
    let (expected_local, peer_signer, peer_worker_role) = match local_role {
        Role::SignerA => (
            signer_set.signer_a.clone(),
            signer_set.signer_b.clone(),
            CloudflareWorkerRoleV1::SignerB,
        ),
        Role::SignerB => (
            signer_set.signer_b.clone(),
            signer_set.signer_a.clone(),
            CloudflareWorkerRoleV1::SignerA,
        ),
        _ => unreachable!("require_signer_role accepted only signer roles"),
    };
    if assignment.signer != expected_local {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "validated signer request assignment does not match signer set role",
        ));
    }
    Ok((assignment.signer.clone(), peer_signer, peer_worker_role))
}

fn expected_signer_peer_request_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerA => Ok(WireMessageKindV1::SignerBToSignerA),
        CloudflareWorkerRoleV1::SignerB => Ok(WireMessageKindV1::SignerAToSignerB),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker has no direct A/B peer request kind",
            ))
        }
    }
}

fn expected_signer_peer_response_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerA => Ok(WireMessageKindV1::SignerAToSignerB),
        CloudflareWorkerRoleV1::SignerB => Ok(WireMessageKindV1::SignerBToSignerA),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker has no direct A/B peer response kind",
            ))
        }
    }
}

fn read_durable_object_binding(
    env: &impl CloudflareEnvReaderV1,
    scope: CloudflareDurableObjectScopeV1,
    binding_name_key: &str,
    object_name_key: &str,
    key_prefix_key: &str,
) -> RouterAbProtocolResult<CloudflareDurableObjectBindingV1> {
    CloudflareDurableObjectBindingV1::new(
        scope,
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, object_name_key)?,
        read_required_env_text(env, key_prefix_key)?,
    )
}

fn read_peer_binding(
    env: &impl CloudflareEnvReaderV1,
    peer_role: CloudflareWorkerRoleV1,
    binding_name_key: &str,
) -> RouterAbProtocolResult<CloudflarePeerBindingV1> {
    CloudflarePeerBindingV1::new(peer_role, read_required_env_text(env, binding_name_key)?)
}

fn read_root_share_wire_secret_binding(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    binding_name_key: &str,
) -> RouterAbProtocolResult<CloudflareRootShareWireSecretBindingV1> {
    CloudflareRootShareWireSecretBindingV1::new(
        role,
        read_required_env_text(env, binding_name_key)?,
    )
}

fn read_signer_envelope_hpke_public_key(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    key_epoch_key: &str,
    public_key_key: &str,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkePublicKeyV1> {
    CloudflareSignerEnvelopeHpkePublicKeyV1::new(
        role,
        read_required_env_text(env, key_epoch_key)?,
        read_required_env_text(env, public_key_key)?,
    )
}

fn read_signer_envelope_hpke_decrypt_key_binding(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    binding_name_key: &str,
    key_epoch_key: &str,
    public_key_key: &str,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1> {
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        role,
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, key_epoch_key)?,
        read_required_env_text(env, public_key_key)?,
    )
}

fn read_signer_envelope_hpke_decrypt_key_binding_set(
    env: &impl CloudflareEnvReaderV1,
    current: CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    role: Role,
    previous_binding_name_key: &str,
    previous_key_epoch_key: &str,
    previous_public_key_key: &str,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1> {
    let previous_keys = [
        previous_binding_name_key,
        previous_key_epoch_key,
        previous_public_key_key,
        ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV,
    ];
    let has_previous = previous_keys
        .iter()
        .map(|key| read_optional_env_text(env, key))
        .collect::<RouterAbProtocolResult<Vec<_>>>()?
        .into_iter()
        .any(|value| value.is_some());
    if !has_previous {
        return CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1::current_only(current);
    }
    let previous = read_signer_envelope_hpke_decrypt_key_binding(
        env,
        role,
        previous_binding_name_key,
        previous_key_epoch_key,
        previous_public_key_key,
    )?;
    let previous_retire_at_ms =
        read_required_env_u64(env, ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV)?;
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1::current_and_previous(
        current,
        previous,
        previous_retire_at_ms,
    )
}

fn read_server_output_hpke_decrypt_key_binding(
    env: &impl CloudflareEnvReaderV1,
    binding_name_key: &str,
    key_epoch_key: &str,
    public_key_key: &str,
) -> RouterAbProtocolResult<CloudflareServerOutputHpkeDecryptKeyBindingV1> {
    CloudflareServerOutputHpkeDecryptKeyBindingV1::new(
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, key_epoch_key)?,
        read_required_env_text(env, public_key_key)?,
    )
}

fn read_signer_peer_signing_key_binding(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    binding_name_key: &str,
    key_epoch_key: &str,
) -> RouterAbProtocolResult<CloudflareSignerPeerSigningKeyBindingV1> {
    CloudflareSignerPeerSigningKeyBindingV1::new(
        role,
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, key_epoch_key)?,
    )
}

fn read_signer_peer_verifying_key_set(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeySetV1> {
    CloudflareSignerPeerVerifyingKeySetV1::new(
        read_signer_peer_verifying_key_bytes(
            env,
            Role::SignerA,
            SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV,
        )?,
        read_signer_peer_verifying_key_bytes(
            env,
            Role::SignerB,
            SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV,
        )?,
    )
}

fn read_signer_peer_verifying_key_bytes(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    key: &str,
) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeyBytesV1> {
    CloudflareSignerPeerVerifyingKeyBytesV1::new(
        role,
        decode_cloudflare_peer_verifying_key_hex_v1(&read_required_env_text(env, key)?)?,
    )
}

fn read_required_env_text(
    env: &impl CloudflareEnvReaderV1,
    key: &str,
) -> RouterAbProtocolResult<String> {
    match env.get_text(key)? {
        Some(value) => {
            let value = value.trim().to_owned();
            require_non_empty(key, &value)?;
            Ok(value)
        }
        None => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Cloudflare Env is missing required key {key}"),
        )),
    }
}

fn read_optional_env_text(
    env: &impl CloudflareEnvReaderV1,
    key: &str,
) -> RouterAbProtocolResult<Option<String>> {
    Ok(env.get_text(key)?.and_then(|value| {
        let value = value.trim().to_owned();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }))
}

fn read_required_env_u64(
    env: &impl CloudflareEnvReaderV1,
    key: &str,
) -> RouterAbProtocolResult<u64> {
    let value = read_required_env_text(env, key)?;
    value.parse::<u64>().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("Cloudflare Env key {key} must be an unsigned integer"),
        )
    })
}

fn reject_forbidden_env_keys(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
    forbidden_keys: &[&str],
) -> RouterAbProtocolResult<()> {
    for key in forbidden_keys {
        if env.get_text(key)?.is_some() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!(
                    "{} Worker cannot receive Cloudflare Env key {key}",
                    worker_role.as_str()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn require_worker_durable_object(
    env: &worker::Env,
    binding: &CloudflareDurableObjectBindingV1,
) -> RouterAbProtocolResult<()> {
    match env.durable_object(&binding.binding_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "Durable Object",
            err,
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn require_worker_service(
    env: &worker::Env,
    binding: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<()> {
    match env.service(&binding.binding_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "service",
            err,
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn require_worker_hpke_secret(
    env: &worker::Env,
    binding: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_hpke_secret_set(
    env: &worker::Env,
    bindings: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
) -> RouterAbProtocolResult<()> {
    require_worker_hpke_secret(env, &bindings.current)?;
    if let Some(previous) = &bindings.previous {
        require_worker_hpke_secret(env, previous)?;
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn require_worker_server_output_hpke_secret(
    env: &worker::Env,
    binding: &CloudflareServerOutputHpkeDecryptKeyBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_root_share_wire_secret(
    env: &worker::Env,
    binding: &CloudflareRootShareWireSecretBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_peer_signing_secret(
    env: &worker::Env,
    binding: &CloudflareSignerPeerSigningKeyBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_secret_binding_name(
    env: &worker::Env,
    binding_name: &str,
) -> RouterAbProtocolResult<()> {
    match env.secret(binding_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(worker_binding_error(
            worker_binding_error_code(&err, binding_name),
            binding_name,
            "secret",
            err,
        )),
    }
}

/// Loads a role-local root-share wire from a Cloudflare Secret binding.
#[cfg(feature = "workers-rs")]
pub fn load_cloudflare_root_share_wire_secret_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    binding: &CloudflareRootShareWireSecretBindingV1,
    metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<CloudflarePreloadedRootShareWireV1> {
    binding.validate_visible_to(worker_role)?;
    let secret = env.secret(&binding.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let record = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        worker_role,
        binding,
        metadata,
        &secret_value,
    );
    secret_value.zeroize();
    record
}

#[cfg(feature = "workers-rs")]
fn load_cloudflare_signer_peer_signing_key_bytes_v1(
    env: &worker::Env,
    binding: &CloudflareSignerPeerSigningKeyBindingV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    binding.validate()?;
    let secret = env.secret(&binding.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let key = decode_cloudflare_signer_peer_signing_key_v1(&secret_value);
    secret_value.zeroize();
    key
}

#[cfg(feature = "workers-rs")]
fn decode_cloudflare_signer_peer_signing_key_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let mut key_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret_value.trim().as_bytes())
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare A/B peer signing key secret must be unpadded base64url",
            ));
        }
    };
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare A/B peer signing key secret must decode to 32 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

#[cfg(feature = "workers-rs")]
fn worker_binding_error_code(err: &worker::Error, binding_name: &str) -> RouterAbProtocolErrorCode {
    if worker_binding_is_missing(err, binding_name) {
        RouterAbProtocolErrorCode::MissingLocalBinding
    } else {
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    }
}

#[cfg(feature = "workers-rs")]
fn worker_binding_error(
    code: RouterAbProtocolErrorCode,
    binding_name: &str,
    binding_kind: &str,
    err: worker::Error,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        code,
        format!("Cloudflare {binding_kind} binding `{binding_name}` failed validation: {err}"),
    )
}

#[cfg(feature = "workers-rs")]
fn worker_binding_is_missing(err: &worker::Error, binding_name: &str) -> bool {
    match err {
        worker::Error::BindingError(name) => name == binding_name,
        worker::Error::JsError(message) | worker::Error::RustError(message) => {
            message == &format!("Env does not contain binding `{binding_name}`")
                || message == &format!("Binding `{binding_name}` is undefined.")
                || message == &format!("no binding found for `{binding_name}`")
        }
        _ => false,
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_error_status(code: RouterAbProtocolErrorCode) -> u16 {
    match code {
        RouterAbProtocolErrorCode::EmptyField
        | RouterAbProtocolErrorCode::InvalidTimeRange
        | RouterAbProtocolErrorCode::InvalidGateDecision
        | RouterAbProtocolErrorCode::InvalidPrepareHandle
        | RouterAbProtocolErrorCode::InvalidRole
        | RouterAbProtocolErrorCode::InvalidSignerIdentity
        | RouterAbProtocolErrorCode::InvalidLifecycleState
        | RouterAbProtocolErrorCode::DowngradeRejected
        | RouterAbProtocolErrorCode::InvalidLocalHttpRequest
        | RouterAbProtocolErrorCode::InvalidLocalRoute
        | RouterAbProtocolErrorCode::MalformedWirePayload
        | RouterAbProtocolErrorCode::UnsupportedVectorVersion => 400,
        RouterAbProtocolErrorCode::ExpiredLocalRequest => 408,
        RouterAbProtocolErrorCode::ReplayedLocalRequest => 409,
        RouterAbProtocolErrorCode::MissingLocalBinding
        | RouterAbProtocolErrorCode::ForbiddenLocalBinding
        | RouterAbProtocolErrorCode::InvalidLocalServiceConfig => 500,
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_now_unix_ms_v1() -> RouterAbProtocolResult<u64> {
    let now = worker::js_sys::Date::now();
    if !now.is_finite() || now <= 0.0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "Cloudflare Worker clock returned invalid Unix milliseconds",
        ));
    }
    Ok(now as u64)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_random_bytes_v1(len: usize) -> RouterAbProtocolResult<Vec<u8>> {
    if len > CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare random preload length exceeds maximum",
        ));
    }
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare random preload failed: {err}"),
        )
    })?;
    Ok(out)
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

fn require_no_ascii_whitespace(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must not contain ASCII whitespace"),
        ));
    }
    Ok(())
}

fn push_hash_field_v1(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn map_derivation_to_protocol(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!(
            "Cloudflare signer plaintext boundary rejected input: {:?}",
            error.code()
        ),
    )
}

fn map_root_share_to_protocol(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "Cloudflare root-share wire boundary rejected input: {:?}",
            error.code()
        ),
    )
}

fn require_positive_ms(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} must be greater than zero"),
        ));
    }
    Ok(())
}

fn require_work_kind_set(
    field: &str,
    values: &[ExpensiveWorkKindV1],
) -> RouterAbProtocolResult<()> {
    if values.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    for (index, value) in values.iter().enumerate() {
        if values.iter().skip(index + 1).any(|other| other == value) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{field} must not contain duplicate work kinds"),
            ));
        }
    }
    Ok(())
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "Cloudflare signer root-share scope requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        decode_recipient_proof_bundle_payload_v1,
        verify_recipient_proof_bundle_ciphertext_payload_v1, AbDerivationProofBatchPayloadV1,
        MpcPrfDleqProofWireV1, MpcPrfPartialBindingV1, MpcPrfPartialProofBundleV1,
        MpcPrfPartialWireV1, MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialV1, MpcPrfSuiteId,
        OpenedShareKind, RecipientProofBundleEncryptionRequestV1, RecipientProofBundlePayloadV1,
        RootShareEpoch, SecretMaterial32, SignerIdentityV1, MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
    };

    #[test]
    fn cloudflare_hpke_recipient_output_encryptor_round_trips() {
        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x42; 32]).expect("recipient keypair derives");
        let recipient_public_key = format!(
            "x25519:{}",
            lower_hex(&CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key))
        );
        let plaintext = SecretMaterial32::new([0x5a; 32]);
        let request = RecipientOutputEncryptionRequestV1::new(
            Role::Client,
            OpenedShareKind::XClientBase,
            "client",
            recipient_public_key,
            digest(0x11),
            digest(0x22),
            &plaintext,
        )
        .expect("recipient output encryption request");
        let mut encryptor = CloudflareHpkeRecipientOutputEncryptorV1::new();
        let envelope = encryptor
            .encrypt_recipient_output_v1(request)
            .expect("hpke recipient output encrypts");

        assert_eq!(
            envelope.algorithm,
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1
        );
        assert_eq!(
            envelope.nonce(),
            &CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1
        );
        let aad = encode_recipient_output_ciphertext_aad_v1(&envelope).expect("hpke aad");
        let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
        let (encapped_key, ciphertext) =
            ciphertext_and_tag.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(encapped_key).expect("encapped key");
        let decrypted = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1,
            &aad,
            ciphertext,
        )
        .expect("hpke recipient output opens");

        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn cloudflare_hpke_recipient_proof_bundle_encryptor_round_trips() {
        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x44; 32]).expect("recipient keypair derives");
        let recipient_public_key = format!(
            "x25519:{}",
            lower_hex(&CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key))
        );
        let payload = sample_recipient_proof_bundle_payload();
        let request = RecipientProofBundleEncryptionRequestV1::new(&payload, recipient_public_key)
            .expect("recipient proof-bundle encryption request");
        let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
        let envelope = encryptor
            .encrypt_recipient_proof_bundle_v1(request)
            .expect("hpke recipient proof bundle encrypts");

        assert_eq!(
            envelope.algorithm,
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1
        );
        assert_eq!(
            envelope.nonce(),
            &CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1
        );
        assert_eq!(envelope.recipient_role, Role::Client);
        assert_eq!(envelope.opened_share_kind, OpenedShareKind::XClientBase);
        assert_eq!(envelope.recipient_identity, "client");
        assert_eq!(envelope.payload_digest, payload.digest());

        let aad =
            encode_recipient_proof_bundle_ciphertext_aad_v1(&envelope).expect("proof bundle aad");
        let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
        let (encapped_key, ciphertext) =
            ciphertext_and_tag.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(encapped_key).expect("encapped key");
        let decrypted = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
            &aad,
            ciphertext,
        )
        .expect("hpke recipient proof bundle opens");
        let decoded = decode_recipient_proof_bundle_payload_v1(&decrypted)
            .expect("proof-bundle payload decodes after HPKE open");

        assert_eq!(decoded, payload);
        verify_recipient_proof_bundle_ciphertext_payload_v1(&envelope, &decoded)
            .expect("proof-bundle envelope matches decrypted payload");
        let recipient_private_key_bytes = CloudflareHpkeKemV1::sk_to_bytes(&recipient_private_key);
        let opened = open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
            &envelope,
            &recipient_private_key_bytes,
        )
        .expect("proof bundle opens through Cloudflare helper");
        assert_eq!(opened, payload);
    }

    #[test]
    fn cloudflare_hpke_recipient_proof_bundle_has_deterministic_seal_vector() {
        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x44; 32]).expect("recipient keypair derives");
        let recipient_public_key_text = format!(
            "x25519:{}",
            lower_hex(&CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key))
        );
        let payload = sample_recipient_proof_bundle_payload();
        let request =
            RecipientProofBundleEncryptionRequestV1::new(&payload, recipient_public_key_text)
                .expect("recipient proof-bundle encryption request");
        let aad = cloudflare_hpke_recipient_proof_bundle_aad_v1(&request).expect("HPKE AAD");
        let mut rng = DeterministicHpkeTestRng::new(0xa5);
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
            &aad,
            request.plaintext(),
        )
        .expect("deterministic HPKE seal");
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        const EXPECTED_CIPHERTEXT_AND_TAG_HEX: &str = concat!(
            "1f2e708b104ceb54ac93c4e807ac5a9b1d3f98ccb4f246ada513b6797b76d33c",
            "5ffdda942753a730080168afee463ac3108e9a4d1832439dcf72738758df8d5c",
            "38d7b8d6bcbdd0a79d51c30b795de0d8c283edf361b32875ad18a5970d80175f",
            "4b90e236700389abcba20540ca0d6924d1c660353fd3e0dc4c68631f56fd14bc",
            "02a111b0106c967f261a5ad44a7a7955d1b23903484accd5bcbae95d7f32d81f",
            "c8697f1f1d6e91bd7a1d7ae758630708309304f70dc22aa16867560f0d9e95d4",
            "a0be1fffdc55037c8495f239a82ce4a070cbcfc709b5703f7345dcb1ed69e714",
            "fc224de9de6249ee85247b35862adea0d6d91a771561a7e816f6e4759f4d5c93",
            "36b59743f86dd5b9d3ab00b43b913f2da23023f01f9c2745ff9135f38a67a3ba",
            "88110a4dab6ad58568d7fc7c6df2634a7a7e0b84744a7ff7810f8737f49c4fc1",
            "45829106819c2bb713bfac1a47a5cf3a68b46145a3bd5c08b4c07158ba243519",
            "33ad6c0a80928dbae32e54d466d7b164e79360a9dd60e2e526094ccf4a25ea3a",
            "2beda19132251de85dc40d8b1ceaf0fa04522381ef0659a8ec10c85d95a1fc98",
            "bbed00b45ae74cf2e598f313648a0333f75b64522165c904d89250b5ef37fdfe",
            "05540aeb8aee7be3ef50c27fd86f188cd2a5d6c7589536b989bb601572df6a47",
            "15bc7dbaa27e09b39947161f5131373d7a5f1248ebf9855c3e3d3a9b2fcbdf60",
            "2061fa605fc493333e545b7b7a152f541cc312d7e44d7f7cafe18fc2bec891",
            "83b7a54db9bdcfc3871883d4f8e71c46f8ba010ef812b7db182640e6cf420",
            "eca205d6beaed924ee6606b714463e4725627cae7d96103c70a1fbe6df33c",
            "4e9d2325633052c652e19c9fc976a2a7aaef175512fe4cf92278de644c106",
            "2acdfb169a3bb271a812f5c2c3947bf08f91a5079daa1710eccfe96bd099f",
            "074baea20e536c1165861fca386a977109050b6e5b45e3d63d014e30a8e87",
            "e1ebb2e67ac6a4814301ed9b1d0a53021c0311c77e2f71d5b5f7f04b",
            "2a2fd827dbb4123849695607c7c9c52699cb500d2",
        );
        assert_eq!(
            lower_hex(&ciphertext_and_tag),
            EXPECTED_CIPHERTEXT_AND_TAG_HEX
        );

        let envelope = RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag).expect("deterministic ciphertext"),
        )
        .expect("deterministic HPKE envelope");
        let recipient_private_key_bytes = CloudflareHpkeKemV1::sk_to_bytes(&recipient_private_key);
        let opened = open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
            &envelope,
            &recipient_private_key_bytes,
        )
        .expect("deterministic HPKE vector opens");

        assert_eq!(opened, payload);
    }

    #[test]
    fn cloudflare_hpke_suite_opens_rfc9180_aes256_base_vector() {
        let info = decode_hex("4f6465206f6e2061204772656369616e2055726e");
        let ikm_r = decode_hex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee");
        let expected_pk_r =
            decode_hex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
        let enc = decode_hex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
        let aad = decode_hex("436f756e742d30");
        let ciphertext = decode_hex(
            "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
        );
        let plaintext = decode_hex("4265617574792069732074727574682c20747275746820626561757479");

        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&ikm_r).expect("recipient keypair derives");
        assert_eq!(
            CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key),
            expected_pk_r
        );

        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(&enc).expect("encapped key");
        let opened = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            &info,
            &aad,
            &ciphertext,
        )
        .expect("RFC 9180 AES-256-GCM base vector opens");
        assert_eq!(opened, plaintext);

        let err = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            &info,
            b"wrong-aad",
            &ciphertext,
        )
        .expect_err("modified AAD must fail");
        assert_eq!(err, hpke_ng::HpkeError::OpenError);
    }

    #[test]
    fn cloudflare_hpke_recipient_output_rejects_uppercase_public_key() {
        let err = parse_cloudflare_hpke_x25519_public_key_v1(
            "x25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .expect_err("uppercase public key hex must fail");

        assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
    }

    #[test]
    fn cloudflare_hpke_recipient_output_rejects_noncanonical_public_key() {
        let (_, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x43; 32]).expect("recipient keypair derives");
        let mut public_key_bytes = CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key);
        public_key_bytes[31] |= 0x80;
        let encoded = format!("x25519:{}", lower_hex(&public_key_bytes));
        let err = parse_cloudflare_hpke_x25519_public_key_v1(&encoded)
            .expect_err("noncanonical public key must fail");

        assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| (decode_hex_nibble(chunk[0]) << 4) | decode_hex_nibble(chunk[1]))
            .collect()
    }

    fn decode_hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("test vector hex must be lowercase"),
        }
    }

    fn digest(seed: u8) -> PublicDigest32 {
        PublicDigest32::new([seed; 32])
    }

    fn sample_recipient_proof_bundle_payload() -> RecipientProofBundlePayloadV1 {
        let transcript_digest = digest(0x77);
        let root_share_epoch = RootShareEpoch::new("epoch-1").expect("root epoch");
        let proof_batch = AbDerivationProofBatchPayloadV1::new(
            signer(Role::SignerA, "signer-a"),
            signer(Role::SignerB, "signer-b"),
            transcript_digest,
            root_share_epoch.clone(),
            vec![sample_mpc_prf_proof_bundle(
                transcript_digest,
                root_share_epoch,
                OpenedShareKind::XClientBase,
                Role::Client,
                "client",
                Role::SignerA,
                "signer-a",
                0x77,
            )],
        )
        .expect("proof batch");
        RecipientProofBundlePayloadV1::new(
            "lifecycle-1",
            signer(Role::SignerA, "signer-a"),
            Role::Client,
            OpenedShareKind::XClientBase,
            "client",
            transcript_digest,
            proof_batch,
        )
        .expect("recipient proof-bundle payload")
    }

    fn signer(role: Role, signer_id: &str) -> SignerIdentityV1 {
        SignerIdentityV1::new(role, signer_id, "key-epoch-1").expect("signer identity")
    }

    #[allow(clippy::too_many_arguments)]
    fn sample_mpc_prf_proof_bundle(
        transcript_digest: PublicDigest32,
        root_share_epoch: RootShareEpoch,
        opened_share_kind: OpenedShareKind,
        recipient_role: Role,
        recipient_identity: &str,
        signer_role: Role,
        signer_identity: &str,
        seed: u8,
    ) -> MpcPrfPartialProofBundleV1 {
        let binding = MpcPrfPartialBindingV1 {
            suite_id: MpcPrfSuiteId::ThresholdPrfRistretto255Sha512,
            transcript_digest,
            root_share_epoch,
            opened_share_kind,
            recipient_role,
            recipient_identity: recipient_identity.to_owned(),
            signer_role,
            signer_identity: signer_identity.to_owned(),
        };
        let signer_partial = MpcPrfSignerPartialV1::new(
            binding,
            MpcPrfPartialWireV1::new(vec![seed; MPC_PRF_PARTIAL_WIRE_V1_LEN])
                .expect("partial wire"),
        )
        .expect("signer partial");
        MpcPrfPartialProofBundleV1::new(
            signer_partial,
            MpcPrfShareCommitmentWireV1::new(vec![
                seed.wrapping_add(1);
                MPC_PRF_COMMITMENT_WIRE_V1_LEN
            ])
            .expect("commitment wire"),
            MpcPrfDleqProofWireV1::new(vec![seed.wrapping_add(2); MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN])
                .expect("DLEQ proof wire"),
        )
        .expect("proof bundle")
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    struct DeterministicHpkeTestRng {
        next: u8,
    }

    impl DeterministicHpkeTestRng {
        fn new(seed: u8) -> Self {
            Self { next: seed }
        }
    }

    impl RngCore for DeterministicHpkeTestRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for byte in dst {
                *byte = self.next;
                self.next = self.next.wrapping_add(0x3d);
            }
        }
    }

    impl CryptoRng for DeterministicHpkeTestRng {}
}
