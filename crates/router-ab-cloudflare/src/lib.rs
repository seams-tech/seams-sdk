#![forbid(unsafe_code)]
//! Cloudflare adapter boundary types for Router/A/B signing.
//!
//! This crate pins role-specific binding and storage-scope rules before the
//! `workers-rs` adapter layer is added.

mod auth;
use base64::Engine;
mod durable_object;
#[cfg(feature = "workers-rs")]
use durable_object::tenant_root_creation::execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1;
#[cfg(feature = "workers-rs")]
mod ecdsa_normal_signing_transport;
mod ecdsa_pool_lifecycle;
pub use ecdsa_pool_lifecycle::*;
mod ed25519_yao_pair_protocol;
pub use ed25519_yao_pair_protocol::*;
#[cfg(feature = "workers-rs")]
mod ed25519_yao_websocket;
#[cfg(feature = "workers-rs")]
pub use ed25519_yao_websocket::*;
#[cfg(feature = "workers-rs")]
mod ed25519_yao_lifecycle;
#[cfg(feature = "workers-rs")]
pub use ed25519_yao_lifecycle::*;
#[cfg(feature = "workers-rs")]
mod ed25519_yao_signing_worker;
#[cfg(feature = "workers-rs")]
pub use ed25519_yao_signing_worker::{
    handle_cloudflare_signing_worker_ed25519_yao_activate_reservation_v1,
    handle_cloudflare_signing_worker_ed25519_yao_deactivate_reservation_v1,
    handle_cloudflare_signing_worker_ed25519_yao_packages_v1,
    handle_cloudflare_signing_worker_ed25519_yao_recovery_promote_v1,
    handle_cloudflare_signing_worker_ed25519_yao_reserve_inactive_source_preserving_v1,
    handle_cloudflare_signing_worker_ed25519_yao_reserve_inactive_v1,
    CloudflareEd25519YaoActivateReservationRequestV1,
    CloudflareEd25519YaoDeactivateReservationRequestV1,
    CloudflareEd25519YaoInactiveReservationRequestV1,
    CloudflareEd25519YaoInactiveReservationResponseV1, CloudflareEd25519YaoPackagePairDeliveryV1,
    CloudflareEd25519YaoRecoveryPromotionRequestV1,
    CloudflareEd25519YaoReservationActivationResponseV1,
    CloudflareEd25519YaoReservationDeactivationResponseV1,
    CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_ACTIVATE_RESERVATION_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DEACTIVATE_RESERVATION_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_PACKAGES_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH,
};
#[cfg(feature = "workers-rs")]
mod ordinary_inactive_signer_material;
#[cfg(feature = "workers-rs")]
pub use ordinary_inactive_signer_material::{
    handle_cloudflare_signing_worker_ecdsa_activate_reservation_v1,
    handle_cloudflare_signing_worker_ecdsa_deactivate_reservation_v1,
    handle_cloudflare_signing_worker_ecdsa_reserve_inactive_source_preserving_v1,
    handle_cloudflare_signing_worker_ecdsa_reserve_inactive_v1,
    CloudflareEcdsaActivateReservationRequestV1, CloudflareEcdsaDeactivateReservationRequestV1,
    CloudflareEcdsaInactiveMaterialReservationRequestV1,
    CloudflareEcdsaInactiveMaterialReservationResponseV1,
    CloudflareEcdsaReservationActivationResponseV1,
    CloudflareEcdsaReservationDeactivationResponseV1,
    CloudflareEcdsaSourcePreservingInactiveMaterialReservationRequestV1,
    CloudflareEcdsaSourcePreservingInactiveMaterialReservationResponseV1,
    CloudflareEcdsaSourcePreservingReservationActivationResponseV1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_ACTIVATE_RESERVATION_PATH,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_DEACTIVATE_RESERVATION_PATH,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_PATH,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH,
};
#[cfg(feature = "workers-rs")]
mod tenant_root_role_d1;
#[cfg(feature = "workers-rs")]
pub use tenant_root_role_d1::*;
// The issuer reads and re-validates Durable Object state, so it is compiled
// exactly where the Durable Object module is.
#[cfg(any(feature = "workers-rs", test))]
mod tenant_root_control_plane;
mod tenant_root_cutover_lifecycle;
mod tenant_root_managed_backup_r2;
mod tenant_root_operational_provider;
#[cfg(feature = "workers-rs")]
pub use tenant_root_control_plane::{
    handle_cloudflare_tenant_root_control_plane_cleanup_command_v1,
    handle_cloudflare_tenant_root_control_plane_create_tenant_root_v1,
    handle_cloudflare_tenant_root_control_plane_refresh_commands_v1,
    handle_cloudflare_tenant_root_control_plane_role_creation_command_v1,
};
#[cfg(any(feature = "workers-rs", test))]
pub use tenant_root_control_plane::{
    CloudflareTenantRootControlPlaneCleanupCommandRequestV1,
    CloudflareTenantRootControlPlaneCleanupCommandResponseV1,
    CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
    CloudflareTenantRootControlPlaneCreateTenantRootResponseV1,
    CloudflareTenantRootControlPlaneRefreshCommandsRequestV1,
    CloudflareTenantRootControlPlaneRefreshCommandsResponseV1,
    CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
    CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1,
    CloudflareTenantRootControlPlaneRoleV1, CloudflareTenantRootCreationStatusV1,
    TENANT_ROOT_CONTROL_PLANE_CLEANUP_COMMAND_REQUEST_MAX_BYTES_V1,
    TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_REQUEST_MAX_BYTES_V1,
    TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_REQUEST_MAX_BYTES_V1,
    TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_REQUEST_MAX_BYTES_V1,
};
#[allow(dead_code)]
mod tenant_root_role_runtime;
#[cfg(feature = "workers-rs")]
mod tenant_root_google_kms;
pub use tenant_root_cutover_lifecycle::*;
#[cfg(feature = "workers-rs")]
use tenant_root_role_runtime::{
    CloudflareDeriverTenantRootCleanupRequestV1, CloudflareDeriverTenantRootCleanupResponseV1,
    CloudflareDeriverTenantRootCreateRoleShareRequestV1,
    CloudflareDeriverTenantRootCreateRoleShareResponseV1,
    CloudflareDeriverTenantRootInitialActivationRequestV1,
    CloudflareDeriverTenantRootInitialActivationResponseV1,
    CloudflareDeriverTenantRootRefreshActivationRequestV1,
    CloudflareDeriverTenantRootRefreshActivationResponseV1,
    CloudflareDeriverTenantRootRefreshRequestV1, CloudflareDeriverTenantRootRefreshResponseV1,
};
mod tenant_root_revision_manifest;
pub use tenant_root_revision_manifest::*;
mod router;
pub use router::*;

#[cfg(feature = "workers-rs")]
mod router_coordinator;
#[cfg(feature = "workers-rs")]
pub use router_coordinator::{
    handle_cloudflare_router_ed25519_yao_execute_private_fetch_v1,
    handle_cloudflare_router_ed25519_yao_lane_execute_private_fetch_v1,
    handle_cloudflare_router_ed25519_yao_recovery_promote_private_fetch_v1,
    handle_cloudflare_router_ed25519_yao_source_preserving_execute_private_fetch_v1,
    CloudflareRouterEd25519YaoLaneExecuteRequestV2,
    CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1,
};
mod signing_worker;
pub use signing_worker::*;
mod env;
pub use env::*;
use env::{
    parse_cloudflare_custody_authority_verifiers_v1,
    parse_cloudflare_operations_incident_verifier_v1,
    parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1,
    parse_cloudflare_tenant_root_creation_grant_authority_verifying_keys_v1,
    parse_cloudflare_tenant_root_creation_role_verifying_keys_v1, DERIVER_A_FORBIDDEN_ENV_KEYS,
    DERIVER_B_FORBIDDEN_ENV_KEYS, ROUTER_FORBIDDEN_ENV_KEYS, SIGNING_WORKER_FORBIDDEN_ENV_KEYS,
};
mod validation;
pub(crate) use validation::{
    require_no_ascii_whitespace, require_non_empty, require_non_empty_vec, require_positive_ms,
};
mod hpke;
#[cfg(feature = "workers-rs")]
use hpke::CloudflareHpkeGetrandomRngV1;
#[cfg(test)]
use hpke::{
    cloudflare_hpke_recipient_proof_bundle_aad_v1, CloudflareHpkeKemV1, CloudflareHpkeSuiteV1,
    CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1, CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1,
    CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
};
pub use hpke::{
    cloudflare_server_output_material_record_from_activation_request_v1,
    decode_cloudflare_server_output_hpke_private_key_secret_v1,
    decode_cloudflare_signer_envelope_hpke_private_key_secret_v1,
    encode_cloudflare_server_output_hpke_private_key_secret_v1,
    encode_cloudflare_signer_envelope_hpke_private_key_secret_v1,
    open_cloudflare_recipient_proof_bundle_hpke_payload_v1,
    open_cloudflare_recipient_proof_bundle_hpke_payload_v2,
    open_cloudflare_signer_envelope_hpke_payload_v1,
    seal_cloudflare_signer_envelope_hpke_payload_v1, CloudflareHpkeRecipientOutputEncryptorV1,
    CloudflareHpkeRecipientProofBundleEncryptorV1, CloudflareSecretMaterial32V1,
    CloudflareServerOutputMaterialRecordV1,
};
#[cfg(feature = "workers-rs")]
pub use hpke::{
    cloudflare_server_output_material_record_from_ecdsa_activation_request_v2,
    cloudflare_server_output_material_record_from_ecdsa_refresh_request_v2,
};
use hpke::{
    parse_cloudflare_hpke_x25519_public_key_v1, push_lower_hex_v1,
    CloudflareSignerProofGetrandomRngV1,
};
pub use router_ab_ecdsa_client_protocol::{
    seal_ecdsa_signing_worker_export_share_v1, EcdsaClientProofBundleDeliveryKindV1,
    EcdsaClientProofBundleDeliveryV1, EcdsaClientProofBundlePairDeliveryV1,
    EcdsaMaterialActivationRefKindV1, EcdsaMaterialActivationRefV1,
    EcdsaSigningWorkerExportShareBindingV1, EcdsaSigningWorkerExportShareEnvelopeV1,
    EcdsaVerifiedClientActivationFactsV1,
};
mod encoding;
#[cfg(feature = "workers-rs")]
use auth::hash_optional_header_v1;
#[cfg(feature = "workers-rs")]
pub use auth::{
    cloudflare_private_service_auth_error_response_v1,
    require_cloudflare_internal_service_auth_request_v1,
    set_cloudflare_internal_service_auth_header_v1,
};
use auth::{
    router_jwt_segment_error, unix_seconds_to_millis_v1, verify_router_ed25519_jwt_signature_v1,
};
use encoding::{
    decode_base64url_bytes_v1, decode_base64url_fixed_32_v1, decode_base64url_fixed_33_v1,
    decode_base64url_fixed_64_v1, decode_base64url_json_v1, encode_base64url_bytes_v1,
};
mod paths;
pub use paths::*;
mod trace_context;
#[cfg(feature = "workers-rs")]
use paths::{
    cloudflare_deriver_peer_service_url, cloudflare_deriver_tenant_root_cleanup_service_url,
    cloudflare_deriver_tenant_root_create_role_share_service_url,
    cloudflare_deriver_tenant_root_initial_activation_service_url,
    cloudflare_deriver_tenant_root_refresh_activation_service_url,
    cloudflare_deriver_tenant_root_refresh_service_url,
    cloudflare_router_ab_ecdsa_derivation_deriver_export_service_url,
    cloudflare_router_ab_ecdsa_derivation_deriver_refresh_service_url,
    cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_url,
    cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_url,
    cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_url,
    cloudflare_router_ab_ecdsa_derivation_signing_worker_export_preflight_service_url,
    cloudflare_router_ab_ecdsa_derivation_signing_worker_export_share_service_url,
    cloudflare_signing_worker_linked_device_ecdsa_finalize_service_url,
    cloudflare_signing_worker_normal_signing_round1_prepare_service_url,
    cloudflare_signing_worker_normal_signing_service_url,
    cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_url,
    cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_url,
    cloudflare_tenant_root_control_plane_cleanup_command_service_url,
    cloudflare_tenant_root_control_plane_create_tenant_root_service_url,
    cloudflare_tenant_root_control_plane_refresh_activation_service_url,
    cloudflare_tenant_root_control_plane_role_creation_command_service_url,
};
pub use trace_context::CloudflareTraceIdV1;
#[cfg(feature = "workers-rs")]
pub use trace_context::{
    parse_cloudflare_trace_id_from_request_v1, set_cloudflare_trace_id_header_v1,
    CLOUDFLARE_TRACE_ID_HEADER_V1,
};
#[cfg(any(
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-deriver-a-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-deriver-b-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-signing-worker-entrypoint"
    ),
    all(
        feature = "strict-worker-deriver-a-entrypoint",
        feature = "strict-worker-deriver-b-entrypoint"
    ),
    all(
        feature = "strict-worker-deriver-a-entrypoint",
        feature = "strict-worker-signing-worker-entrypoint"
    ),
    all(
        feature = "strict-worker-deriver-b-entrypoint",
        feature = "strict-worker-signing-worker-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-tenant-root-control-plane-entrypoint"
    ),
    all(
        feature = "strict-worker-deriver-a-entrypoint",
        feature = "strict-worker-tenant-root-control-plane-entrypoint"
    ),
    all(
        feature = "strict-worker-deriver-b-entrypoint",
        feature = "strict-worker-tenant-root-control-plane-entrypoint"
    ),
    all(
        feature = "strict-worker-signing-worker-entrypoint",
        feature = "strict-worker-tenant-root-control-plane-entrypoint"
    ),
))]
compile_error!("enable exactly one strict Worker entrypoint feature");

#[cfg(any(
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint",
    feature = "strict-worker-tenant-root-control-plane-entrypoint"
))]
mod strict_worker;

#[cfg(feature = "workers-rs")]
pub use durable_object::RouterAbSigningWorkerPresignSessionDurableObject;
pub use durable_object::{
    CloudflareActiveSigningWorkerStateLookupV1, CloudflareEd25519Round1StateV1,
    CloudflareExpiredStateCleanupReportV1, CloudflareExpiredStateCleanupRequestV1,
    CloudflareRootShareStartupMetadataV1, CloudflareSigningWorkerEcdsaPoolAdmissionReceiptV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    CloudflareSigningWorkerOutputActivationReceiptV1,
    CloudflareSigningWorkerOutputActivationRecordV1, CloudflareSigningWorkerOutputMaterialLookupV1,
    CloudflareSigningWorkerPrivateD1RequestV1, CloudflareSigningWorkerPrivateD1ResponseV1,
    CloudflareSigningWorkerRound1LookupV1, CloudflareSigningWorkerRound1PutReceiptV1,
    CloudflareSigningWorkerRound1RecordV1,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::sign_ab_peer_message_ed25519_authentication_v1;
#[cfg(feature = "workers-rs")]
use router_ab_core::RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningResponseV1;
use router_ab_core::{
    combine_mpc_prf_signing_worker_output_from_activation_context_v1,
    decode_ab_peer_message_payload_v1, decode_and_validate_signer_envelope_hpke_payload_v1,
    decode_recipient_proof_bundle_ciphertext_v1, decode_recipient_proof_bundle_payload_v1,
    decode_router_to_signer_payload_v1, decode_signer_envelope_hpke_payload_v1,
    encode_recipient_output_ciphertext_aad_v1, encode_recipient_proof_bundle_ciphertext_aad_v1,
    validate_signer_input_plaintext_binding_v1, verify_ab_peer_message_ed25519_signature_v1,
    verify_recipient_proof_bundle_ciphertext_payload_v1, AbPeerMessagePayloadV1,
    AbPeerMessageVerifyingKeyV1, ActiveSigningWorkerStateV1, AuditEventV1, AuditSink,
    CanonicalWireBytesV1, Clock, Csprng, EcdsaThresholdPrfOuterRequestV2,
    EcdsaThresholdPrfPrivateRequestV2, EcdsaThresholdPrfPurposeV2, EcdsaThresholdPrfRequestV1,
    EncryptedPayloadV1, ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1,
    ExpensiveWorkKindV1, GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1,
    MpcMaterialActivationRefV1, NormalSigningAuthorizationV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningResponseV1,
    NormalSigningRound1PrepareResponseV1, NormalSigningScopeV1, NormalSigningSignatureSchemeV1,
    OpenedShareKind, PeerTransport, PublicDigest32, RecipientOutputCiphertextV1,
    RecipientOutputEncryptionAlgorithmV1, RecipientOutputEncryptionRequestV1,
    RecipientOutputEncryptorV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RecipientProofBundlePayloadV1, Role, RoleEnvelopeAadV1, RootShareEpoch,
    RouterAbDerivationError, RouterAbEcdsaDerivationActivationReceiptV1,
    RouterAbEcdsaDerivationActivationRefreshRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningResponseV1,
    RouterAbEcdsaDerivationExplicitExportRequestV1,
    RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    RouterAbEcdsaDerivationNormalSigningScopeV1, RouterAbEcdsaDerivationPublicIdentityV1,
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    RouterAbEcdsaDerivationStableKeyContextV1, RouterAbEd25519NormalSigningAdmissionMaterialV2,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbLifecycleStateV1,
    RouterRequestPolicyClaimsV1, RouterToSignerPayloadV1, SecretMaterial32, ServerIdentityV1,
    SignerEnvelopeHpkePayloadV1, SignerIdentityV1, SignerInputPlaintextV1, SignerKeyStore,
    SignerSetV1, SigningRootShareStore, SigningWorkerActivationContextV1,
    TenantRootCustodyLineageId, TenantRootDerivationNonceV1, TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1, TenantRootIdentityDigestV1, TenantRootProtocolDigestV1,
    TenantRootSignedActivationReceiptV1, VerifiedTenantRootSignedActivationReceiptV1,
    WireMessageKindV1, WireMessageV1, TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1,
    TENANT_ROOT_MAX_LIFETIME_MS_V1,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::{
    evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2,
    resolve_authoritative_active_tenant_root_pair_binding_v1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoOuterBindingV2, Ed25519YaoPairSessionIdV2, MpcPrfOutputRequestV1,
    MpcPrfStablePartialProofBundleV2, MpcPrfStableRecipientProofBundlePayloadV2,
    MpcPrfStableThresholdSignerInputV2, RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    RouterAbEcdsaDerivationRegistrationPurposeV1, SignerInputQuorumPolicyV1,
    TenantRootActiveRoleBindingV1, TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1,
    TenantRootCustodyBindingV1, TenantRootDeriverIdentitiesV1, TenantRootManagedRestoreRoleV1,
    TwoPartyDeriverRole, VerifiedTenantRootOnlineRoleShareV1,
};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(feature = "workers-rs")]
use zeroize::Zeroize;

use router_ab_ecdsa_derivation::{
    compose_public_identity_from_public_keys, derive_relayer_share_for_client_public,
    ecdsa_lane_client_public_key_from_share32_v1, encode_context, RelayerRoleShare,
    RouterAbEcdsaDerivationStableKeyContext,
};
use sha2::{Digest as Sha2Digest, Sha256};

const SOURCE_PRESERVING_ECDSA_MATERIAL_HANDLE_PREFIX_V1: &str = "source-preserving-ecdsa/";

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

/// Text-reader boundary used before binding descriptors are constructed.
pub trait CloudflareEnvReaderV1 {
    /// Returns a raw environment value if present.
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>>;
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

    /// Returns the retained key/value entries.
    pub const fn entries(&self) -> &BTreeMap<String, String> {
        &self.entries
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
    /// Deriver A Worker.
    DeriverA,
    /// Deriver B Worker.
    DeriverB,
    /// Dedicated normal-signing worker that owns active SigningWorker output.
    SigningWorker,
    /// Internal tenant-root control-plane Worker.
    ///
    /// Sole holder of the R120 issuer private signing key. It validates exact
    /// tenant authorization and authoritative Durable Object lifecycle state,
    /// then constructs and signs canonical one-use commands, capabilities and
    /// receipts. It never receives a scalar, a lane holder share, or Router
    /// authorization configuration, and exposes no raw-payload signing method.
    TenantRootControlPlane,
}

impl CloudflareWorkerRoleV1 {
    /// Returns the stable role label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::DeriverA => "deriver_a",
            Self::DeriverB => "deriver_b",
            Self::SigningWorker => "signing_worker",
            Self::TenantRootControlPlane => "tenant_root_control_plane",
        }
    }
}

/// Binding for the one allowed ephemeral presign rendezvous Durable Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerPresignSessionBindingV1 {
    /// Cloudflare Env binding name.
    pub binding_name: String,
    /// Durable Object object name.
    pub object_name: String,
    /// Prefix for keys within the Durable Object.
    pub key_prefix: String,
}

impl CloudflareSigningWorkerPresignSessionBindingV1 {
    /// Creates a validated presign-session binding descriptor.
    pub fn new(
        binding_name: impl Into<String>,
        object_name: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            binding_name: binding_name.into(),
            object_name: object_name.into(),
            key_prefix: key_prefix.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates binding fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("object_name", &self.object_name)?;
        require_non_empty("key_prefix", &self.key_prefix)
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
    /// Deriver A public envelope key descriptor.
    pub deriver_a: CloudflareSignerEnvelopeHpkePublicKeyV1,
    /// Deriver B public envelope key descriptor.
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
                "Deriver A HPKE public key descriptor must use Deriver A role",
            ));
        }
        if self.deriver_b.role != Role::SignerB {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Deriver B HPKE public key descriptor must use Deriver B role",
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
            (CloudflareWorkerRoleV1::DeriverA, Role::SignerA)
                | (CloudflareWorkerRoleV1::DeriverB, Role::SignerB)
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
            (CloudflareWorkerRoleV1::DeriverA, Role::SignerA)
                | (CloudflareWorkerRoleV1::DeriverB, Role::SignerB)
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
    /// Deriver A peer-message verifying key descriptor.
    pub deriver_a: CloudflareSignerPeerVerifyingKeyHexV1,
    /// Deriver B peer-message verifying key descriptor.
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
                "Cloudflare peer verifying-key descriptor roles must be Deriver A and Deriver B",
            ));
        }
        Ok(())
    }
}

/// Trusted public A/B peer verifying-key set loaded by signer Workers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeySetV1 {
    /// Deriver A peer-message verifying key bytes.
    pub deriver_a: CloudflareSignerPeerVerifyingKeyBytesV1,
    /// Deriver B peer-message verifying key bytes.
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
                "Cloudflare peer verifying-key set roles must be Deriver A and Deriver B",
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
    /// Validated Ed25519 verifier derived from the deployment JWKS.
    pub verifier: CloudflareRouterEd25519JwksJwtVerifierV1,
}

impl CloudflareRouterJwtVerifierBindingV1 {
    /// Creates validated JWT verifier configuration.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_json: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let jwks_json = jwks_json.into();
        let verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)?;
        let binding = Self {
            issuer: issuer.into(),
            audience: audience.into(),
            verifier,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates JWT verifier configuration fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("jwt issuer", &self.issuer)?;
        require_non_empty("jwt audience", &self.audience)?;
        self.verifier.validate()
    }
}

/// Deployment-bound Router project policy parsed from the Worker Env.
///
/// Testnet profiles use the explicit allow-all variant. Production profiles
/// carry the generated identity and work-kind policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudflareRouterProjectPolicyBindingV1 {
    /// No production policy was supplied; the testnet profile remains open.
    AllowAll,
    /// Strict production policy document.
    Configured {
        /// Canonical organization id authorized by this deployment.
        org_id: String,
        /// Canonical project id authorized by this deployment.
        project_id: String,
        /// Deployment environment label authorized by this deployment.
        environment: String,
        /// Expensive work classes admitted by this deployment.
        allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
        /// Whether normal signing is admitted by this deployment.
        allow_normal_signing: bool,
        /// Retry-after duration for policy denials.
        rejected_retry_after_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareRouterProjectPolicyDocumentV1 {
    org_id: String,
    project_id: String,
    environment: String,
    allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
    allow_normal_signing: bool,
    rejected_retry_after_ms: u64,
}

impl CloudflareRouterProjectPolicyBindingV1 {
    fn from_json(json: &str) -> RouterAbProtocolResult<Self> {
        let document: CloudflareRouterProjectPolicyDocumentV1 = serde_json::from_str(json)
            .map_err(|err| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("Router project policy bootstrap JSON parse failed: {err}"),
                )
            })?;
        let policy = Self::Configured {
            org_id: document.org_id,
            project_id: document.project_id,
            environment: document.environment,
            allowed_work_kinds: document.allowed_work_kinds,
            allow_normal_signing: document.allow_normal_signing,
            rejected_retry_after_ms: document.rejected_retry_after_ms,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::AllowAll => Ok(()),
            Self::Configured {
                org_id,
                project_id,
                environment,
                allowed_work_kinds,
                rejected_retry_after_ms,
                ..
            } => {
                require_non_empty("project policy org_id", org_id)?;
                require_non_empty("project policy project_id", project_id)?;
                require_non_empty("project policy environment", environment)?;
                require_work_kind_set("project policy allowed_work_kinds", allowed_work_kinds)?;
                require_positive_ms(
                    "project policy rejected_retry_after_ms",
                    *rejected_retry_after_ms,
                )
            }
        }
    }

    fn policy_for_context(
        &self,
        context: &ExpensiveWorkGateContextV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        self.validate()?;
        context.validate()?;
        request.validate()?;
        self.policy_for_identity_and_work(
            &context.org_id,
            &context.project_id,
            &context.environment,
            context.work_kind,
        )
    }

    fn policy_for_identity_and_work(
        &self,
        org_id_value: &str,
        project_id_value: &str,
        environment_value: &str,
        work_kind: ExpensiveWorkKindV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        match self {
            Self::AllowAll => Ok(CloudflareRouterProjectPolicyV1::Allowed),
            Self::Configured {
                org_id,
                project_id,
                environment,
                allowed_work_kinds,
                rejected_retry_after_ms,
                ..
            } => {
                if org_id_value != org_id
                    || project_id_value != project_id
                    || environment_value != environment
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "Router project policy identity does not match verified request",
                    ));
                }
                if allowed_work_kinds.contains(&work_kind) {
                    Ok(CloudflareRouterProjectPolicyV1::Allowed)
                } else {
                    Ok(CloudflareRouterProjectPolicyV1::Rejected {
                        retry_after_ms: *rejected_retry_after_ms,
                    })
                }
            }
        }
    }

    fn policy_for_yao_work_kind(
        &self,
        work_kind: ExpensiveWorkKindV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        self.validate()?;
        match self {
            Self::AllowAll => self.policy_for_identity_and_work("", "", "", work_kind),
            Self::Configured {
                org_id,
                project_id,
                environment,
                ..
            } => self.policy_for_identity_and_work(org_id, project_id, environment, work_kind),
        }
    }

    fn normal_signing_policy_for_metadata(
        &self,
        metadata: &CloudflareRouterNormalSigningTrustedMetadataV1,
        request_id: &str,
    ) -> RouterAbProtocolResult<ExpensiveWorkGateDecisionV1> {
        self.validate()?;
        metadata.validate()?;
        require_non_empty("normal signing request_id", request_id)?;
        match self {
            Self::AllowAll => ExpensiveWorkGateDecisionV1::accepted(request_id),
            Self::Configured {
                org_id,
                project_id,
                environment,
                allow_normal_signing,
                rejected_retry_after_ms,
                ..
            } => {
                if metadata.org_id != *org_id
                    || metadata.project_id != *project_id
                    || metadata.environment != *environment
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "Router project policy identity does not match normal-signing request",
                    ));
                }
                if *allow_normal_signing {
                    ExpensiveWorkGateDecisionV1::accepted(request_id)
                } else {
                    ExpensiveWorkGateDecisionV1::rejected(
                        GateRejectReasonV1::AbusePolicy,
                        *rejected_retry_after_ms,
                    )
                }
            }
        }
    }
}

/// Router admission-provider configuration after Env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionBindingsV1 {
    /// JWT verifier configuration.
    pub jwt: CloudflareRouterJwtVerifierBindingV1,
    /// Deployment-bound project policy.
    pub project_policy: CloudflareRouterProjectPolicyBindingV1,
}

impl CloudflareRouterAdmissionBindingsV1 {
    /// Creates validated Router admission-provider bindings.
    pub fn new(
        jwt: CloudflareRouterJwtVerifierBindingV1,
        project_policy: CloudflareRouterProjectPolicyBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            jwt,
            project_policy,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Router admission-provider bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.jwt.validate()?;
        self.project_policy.validate()
    }
}

/// Router Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterBindingsV1 {
    /// Router-owned admission-provider bindings.
    pub admission: CloudflareRouterAdmissionBindingsV1,
    /// Deriver A peer binding.
    pub deriver_a: CloudflarePeerBindingV1,
    /// Deriver B peer binding.
    pub deriver_b: CloudflarePeerBindingV1,
    /// SigningWorker peer binding.
    pub signing_worker: CloudflarePeerBindingV1,
    /// Published control-plane issuer verifying keys.
    ///
    /// A signed creation command is verified at this Worker's own boundary, so
    /// the anchor is parsed at startup rather than per request.
    pub issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
}

impl CloudflareRouterBindingsV1 {
    /// Creates validated Router Worker bindings.
    pub fn new(
        admission: CloudflareRouterAdmissionBindingsV1,
        deriver_a: CloudflarePeerBindingV1,
        deriver_b: CloudflarePeerBindingV1,
        signing_worker: CloudflarePeerBindingV1,
        issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            admission,
            deriver_a,
            deriver_b,
            signing_worker,
            issuer_verifying_keys,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Router Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.admission.validate()?;
        require_peer_role(&self.deriver_a, CloudflareWorkerRoleV1::DeriverA)?;
        require_peer_role(&self.deriver_b, CloudflareWorkerRoleV1::DeriverB)?;
        require_peer_role(&self.signing_worker, CloudflareWorkerRoleV1::SigningWorker)?;
        self.issuer_verifying_keys.validate()
    }
}

/// Deriver A Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeriverABindingsV1 {
    /// Deriver A signer-envelope HPKE decrypt keys.
    pub envelope_decrypt_key: CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    /// Deriver A A/B peer-message Ed25519 signing key.
    pub peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
    /// Trusted A/B peer-message Ed25519 verifying keys.
    pub peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
    /// Deriver B peer binding.
    pub deriver_b: CloudflarePeerBindingV1,
    /// Published control-plane issuer verifying keys.
    ///
    /// A signed creation command is verified at this Worker's own boundary, so
    /// the anchor is parsed at startup rather than per request.
    pub issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
}

impl CloudflareDeriverABindingsV1 {
    /// Creates validated Deriver A Worker bindings.
    pub fn new(
        envelope_decrypt_key: impl Into<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1>,
        peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
        peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
        deriver_b: CloudflarePeerBindingV1,
        issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            envelope_decrypt_key: envelope_decrypt_key.into(),
            peer_signing_key,
            peer_verifying_keys,
            deriver_b,
            issuer_verifying_keys,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Deriver A Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.envelope_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::DeriverA)?;
        self.peer_signing_key
            .validate_visible_to(CloudflareWorkerRoleV1::DeriverA)?;
        self.peer_verifying_keys.validate()?;
        require_peer_role(&self.deriver_b, CloudflareWorkerRoleV1::DeriverB)?;
        self.issuer_verifying_keys.validate()
    }
}

/// SigningWorker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerBindingsV1 {
    /// Ephemeral ordered rendezvous for background ECDSA presign generation.
    pub presign_session: CloudflareSigningWorkerPresignSessionBindingV1,
    /// SigningWorker server-output HPKE decrypt key.
    pub server_output_decrypt_key: CloudflareServerOutputHpkeDecryptKeyBindingV1,
}

impl CloudflareSigningWorkerBindingsV1 {
    /// Creates validated SigningWorker bindings.
    pub fn new(
        presign_session: CloudflareSigningWorkerPresignSessionBindingV1,
        server_output_decrypt_key: CloudflareServerOutputHpkeDecryptKeyBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            presign_session,
            server_output_decrypt_key,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates SigningWorker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.presign_session.validate()?;
        self.server_output_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::SigningWorker)
    }
}

/// Deriver B Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeriverBBindingsV1 {
    /// Deriver B signer-envelope HPKE decrypt keys.
    pub envelope_decrypt_key: CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    /// Deriver B A/B peer-message Ed25519 signing key.
    pub peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
    /// Trusted A/B peer-message Ed25519 verifying keys.
    pub peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
    /// Deriver A peer binding.
    pub deriver_a: CloudflarePeerBindingV1,
    /// Published control-plane issuer verifying keys.
    ///
    /// A signed creation command is verified at this Worker's own boundary, so
    /// the anchor is parsed at startup rather than per request.
    pub issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
}

impl CloudflareDeriverBBindingsV1 {
    /// Creates validated Deriver B Worker bindings.
    pub fn new(
        envelope_decrypt_key: impl Into<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1>,
        peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
        peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
        deriver_a: CloudflarePeerBindingV1,
        issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            envelope_decrypt_key: envelope_decrypt_key.into(),
            peer_signing_key,
            peer_verifying_keys,
            deriver_a,
            issuer_verifying_keys,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Deriver B Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.envelope_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::DeriverB)?;
        self.peer_signing_key
            .validate_visible_to(CloudflareWorkerRoleV1::DeriverB)?;
        self.peer_verifying_keys.validate()?;
        require_peer_role(&self.deriver_a, CloudflareWorkerRoleV1::DeriverA)?;
        self.issuer_verifying_keys.validate()
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
    /// Deriver A Worker bindings.
    DeriverA {
        /// Deriver A bindings.
        bindings: CloudflareDeriverABindingsV1,
    },
    /// Deriver B Worker bindings.
    DeriverB {
        /// Deriver B bindings.
        bindings: CloudflareDeriverBBindingsV1,
    },
    /// SigningWorker bindings.
    SigningWorker {
        /// SigningWorker bindings.
        bindings: CloudflareSigningWorkerBindingsV1,
    },
    /// Tenant-root control-plane Worker bindings.
    TenantRootControlPlane {
        /// Control-plane bindings.
        bindings: CloudflareTenantRootControlPlaneBindingsV1,
    },
}

/// Tenant-root control-plane Worker bindings.
///
/// The control plane holds exactly one Secret of its own: the issuer signing
/// key. Its Durable Object and service bindings are resolved per request from
/// Env, as the Router's are, so nothing else is retained here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareTenantRootControlPlaneBindingsV1 {
    /// Issuer signing Secret descriptor (binding name and key ID, never the seed).
    pub issuer_signing_key: CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1,
    /// Published control-plane issuer verifying keys.
    ///
    /// The issuer holds its own published set so it can prove at boot that its
    /// Secret derives the key registered under its active key ID.
    pub issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    /// Authorities trusted to sign a tenant-root creation grant.
    pub grant_authority_verifying_keys: CloudflareTenantRootCreationGrantAuthorityVerifyingKeysV1,
    /// Public verifier for operations incident evidence.
    pub operations_incident_verifier: CloudflareOperationsIncidentVerifierV1,
    /// Separate public custody-authority verifiers for Deriver A and Deriver B.
    pub custody_authority_verifiers: CloudflareCustodyAuthorityVerifiersV1,
    /// Public role signing key ID the issuer names for Deriver A.
    pub deriver_a_signing_key_id: String,
    /// Public role signing key ID the issuer names for Deriver B.
    pub deriver_b_signing_key_id: String,
    /// Deriver A's published verifying key, resolved from the role keyset.
    ///
    /// Resolving at parse time is what proves the configured ID actually exists
    /// under its role; a typo or stale ID cannot reach a ceremony.
    pub deriver_a_verifying_key: [u8; 32],
    /// Deriver B's published verifying key, resolved from the role keyset.
    pub deriver_b_verifying_key: [u8; 32],
}

impl CloudflareTenantRootControlPlaneBindingsV1 {
    /// Creates validated control-plane bindings.
    pub fn new(
        issuer_signing_key: CloudflareTenantRootControlPlaneIssuerSigningKeyBindingV1,
        issuer_verifying_keys: CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
        grant_authority_verifying_keys: CloudflareTenantRootCreationGrantAuthorityVerifyingKeysV1,
        operations_incident_verifier: CloudflareOperationsIncidentVerifierV1,
        custody_authority_verifiers: CloudflareCustodyAuthorityVerifiersV1,
        deriver_a_signing_key_id: String,
        deriver_b_signing_key_id: String,
        deriver_a_verifying_key: [u8; 32],
        deriver_b_verifying_key: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            issuer_signing_key,
            issuer_verifying_keys,
            grant_authority_verifying_keys,
            operations_incident_verifier,
            custody_authority_verifiers,
            deriver_a_signing_key_id,
            deriver_b_signing_key_id,
            deriver_a_verifying_key,
            deriver_b_verifying_key,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates all bindings.
    ///
    /// The active issuer key ID must be present in the published set: an issuer
    /// configured to sign under an unpublished id could never be verified.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.issuer_signing_key.validate()?;
        self.issuer_verifying_keys.validate()?;
        self.grant_authority_verifying_keys.validate()?;
        self.operations_incident_verifier.validate()?;
        self.custody_authority_verifiers.validate()?;
        let operations_verifying_key = self.operations_incident_verifier.verifying_key_bytes();
        if self.custody_authority_verifiers.deriver_a() == &operations_verifying_key
            || self.custody_authority_verifiers.deriver_b() == &operations_verifying_key
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "operations incident and custody authority verifiers must be distinct",
            ));
        }
        // A grant authority key may never double as the issuer key: the issuer
        // could then authorize the tenant creations it goes on to sign.
        for (grant_key_id, grant_key) in self.grant_authority_verifying_keys.keys() {
            if self
                .issuer_verifying_keys
                .keys()
                .values()
                .any(|issuer_key| issuer_key == grant_key)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    format!(
                        "tenant-root creation grant authority {grant_key_id} reuses a control-plane issuer key"
                    ),
                ));
            }
        }
        if self
            .issuer_verifying_keys
            .for_issuer_key_id(self.issuer_signing_key.signing_key_id())
            .is_none()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root control-plane active issuer key ID is not in the published verifying key set",
            ));
        }
        // A ceremony signer must be a Deriver, never the control plane. The IDs
        // themselves were proved to exist under their roles when the bindings
        // were parsed; these keys are what that resolution produced.
        for (signing_key_id, role_key) in [
            (
                self.deriver_a_signing_key_id.as_str(),
                &self.deriver_a_verifying_key,
            ),
            (
                self.deriver_b_signing_key_id.as_str(),
                &self.deriver_b_verifying_key,
            ),
        ] {
            if self
                .issuer_verifying_keys
                .keys()
                .values()
                .any(|key| key == role_key)
                || self
                    .grant_authority_verifying_keys
                    .keys()
                    .values()
                    .any(|key| key == role_key)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    format!(
                        "tenant-root role signing key ID {signing_key_id} reuses a control-plane key"
                    ),
                ));
            }
        }
        if self.deriver_a_signing_key_id == self.deriver_b_signing_key_id
            || self.deriver_a_verifying_key == self.deriver_b_verifying_key
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root role signing keys must be distinct across roles",
            ));
        }
        Ok(())
    }
}

impl CloudflareWorkerBindingsV1 {
    /// Creates a Router Worker startup branch.
    pub fn router(bindings: CloudflareRouterBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::Router { bindings })
    }

    /// Creates a Deriver A Worker startup branch.
    pub fn deriver_a(bindings: CloudflareDeriverABindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::DeriverA { bindings })
    }

    /// Creates a Deriver B Worker startup branch.
    pub fn deriver_b(bindings: CloudflareDeriverBBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::DeriverB { bindings })
    }

    /// Creates a SigningWorker startup branch.
    pub fn signing_worker(
        bindings: CloudflareSigningWorkerBindingsV1,
    ) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::SigningWorker { bindings })
    }

    /// Creates a tenant-root control-plane Worker startup branch.
    pub fn tenant_root_control_plane(
        bindings: CloudflareTenantRootControlPlaneBindingsV1,
    ) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::TenantRootControlPlane { bindings })
    }

    /// Returns the Worker role.
    pub fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        match self {
            Self::Router { .. } => CloudflareWorkerRoleV1::Router,
            Self::DeriverA { .. } => CloudflareWorkerRoleV1::DeriverA,
            Self::DeriverB { .. } => CloudflareWorkerRoleV1::DeriverB,
            Self::SigningWorker { .. } => CloudflareWorkerRoleV1::SigningWorker,
            Self::TenantRootControlPlane { .. } => CloudflareWorkerRoleV1::TenantRootControlPlane,
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
    bindings: CloudflareDeriverABindingsV1,
}

/// Thin Deriver B Worker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDeriverBWorkerRuntimeV1 {
    bindings: CloudflareDeriverBBindingsV1,
}

/// Thin SigningWorker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRuntimeV1 {
    bindings: CloudflareSigningWorkerBindingsV1,
}

/// Thin tenant-root control-plane Worker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareTenantRootControlPlaneRuntimeV1 {
    bindings: CloudflareTenantRootControlPlaneBindingsV1,
}

impl CloudflareTenantRootControlPlaneRuntimeV1 {
    /// Creates a control-plane runtime context from parsed bindings.
    pub fn new(
        bindings: CloudflareTenantRootControlPlaneBindingsV1,
    ) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for control-plane startup.
    ///
    /// Fails closed on any forbidden key, a missing issuer Secret, a binding
    /// name that is not control-plane scoped, or an issuer Secret that does not
    /// derive the public key published under the configured active key ID.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::TenantRootControlPlane { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::TenantRootControlPlane,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root control-plane Env parsing returned wrong binding branch",
            ));
        };
        let runtime = Self::new(bindings)?;
        runtime.require_issuer_key_provenance(env)?;
        Ok(runtime)
    }

    /// Proves at boot that the issuer Secret matches its published active key.
    #[cfg(feature = "workers-rs")]
    fn require_issuer_key_provenance(&self, env: &worker::Env) -> RouterAbProtocolResult<()> {
        let binding = &self.bindings.issuer_signing_key;
        let secret = env.secret(binding.binding_name()).map_err(|err| {
            worker_binding_error(
                worker_binding_error_code(&err, binding.binding_name()),
                binding.binding_name(),
                "secret",
                err,
            )
        })?;
        let mut secret_value = secret.to_string();
        let result =
            crate::env::validate_cloudflare_tenant_root_control_plane_issuer_key_provenance_v1(
                binding,
                &self.bindings.issuer_verifying_keys,
                &secret_value,
            );
        secret_value.zeroize();
        result
    }

    /// Returns validated control-plane bindings.
    pub fn bindings(&self) -> &CloudflareTenantRootControlPlaneBindingsV1 {
        &self.bindings
    }
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
    /// Creates a validated Deriver-host preload request.
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
        if self.random_bytes_len > CLOUDFLARE_DERIVER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflarePreloadedSignerHostV1 {
    /// Worker-local time captured by the adapter.
    pub now_unix_ms: u64,
    /// Role-local root-share startup metadata loaded before engine execution.
    pub root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
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
        let host = Self {
            now_unix_ms,
            root_share_metadata,
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
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for response in &self.peer_responses {
            require_preloaded_peer_response_v1(response)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, response)?;
        }
        Ok(())
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

fn client_proof_bundle_pair_delivery_from_wire_messages_v1(
    signer_a: WireMessageV1,
    signer_b: WireMessageV1,
) -> RouterAbProtocolResult<EcdsaClientProofBundlePairDeliveryV1> {
    let pair = EcdsaClientProofBundlePairDeliveryV1 {
        signer_a: client_proof_bundle_delivery_from_wire_message_v1(signer_a)?,
        signer_b: client_proof_bundle_delivery_from_wire_message_v1(signer_b)?,
    };
    if pair.signer_a.transcript_digest_b64u != pair.signer_b.transcript_digest_b64u {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "strict Router client proof-bundle transcripts must match",
        ));
    }
    Ok(pair)
}

fn client_proof_bundle_delivery_from_wire_message_v1(
    message: WireMessageV1,
) -> RouterAbProtocolResult<EcdsaClientProofBundleDeliveryV1> {
    if message.kind != WireMessageKindV1::RecipientProofBundle {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "strict Router client proof bundle must use recipient_proof_bundle",
        ));
    }
    Ok(EcdsaClientProofBundleDeliveryV1 {
        kind: EcdsaClientProofBundleDeliveryKindV1::RecipientProofBundle,
        transcript_digest_b64u: encode_base64url_bytes_v1(message.transcript_digest.as_bytes()),
        payload_b64u: encode_base64url_bytes_v1(message.payload.as_bytes()),
    })
}

fn client_proof_bundle_delivery_to_wire_message_v1(
    delivery: &EcdsaClientProofBundleDeliveryV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    match delivery.kind {
        EcdsaClientProofBundleDeliveryKindV1::RecipientProofBundle => {}
    }
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        PublicDigest32::new(decode_base64url_fixed_32_v1(
            "client_proof_bundle.transcript_digest_b64u",
            &delivery.transcript_digest_b64u,
        )?),
        CanonicalWireBytesV1::new(decode_base64url_bytes_v1(
            "client_proof_bundle.payload_b64u",
            &delivery.payload_b64u,
        )?)?,
    )
}

/// Strict public Router response carrying client proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareRouterRecipientProofBundleResponseV1 {
    /// Exact Deriver A/B recipient-encrypted client proof bundles.
    pub bundles: EcdsaClientProofBundlePairDeliveryV1,
}

impl CloudflareRouterRecipientProofBundleResponseV1 {
    /// Creates a validated strict public Router response.
    pub fn new(
        deriver_a_client_bundle: WireMessageV1,
        deriver_b_client_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let bundles = client_proof_bundle_pair_delivery_from_wire_messages_v1(
            deriver_a_client_bundle,
            deriver_b_client_bundle,
        )?;
        let response = Self { bundles };
        response.validate()?;
        Ok(response)
    }

    /// Validates the opaque client bundle shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let deriver_a_message =
            client_proof_bundle_delivery_to_wire_message_v1(&self.bundles.signer_a)?;
        let deriver_b_message =
            client_proof_bundle_delivery_to_wire_message_v1(&self.bundles.signer_b)?;
        let deriver_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_a_client_bundle",
            &deriver_a_message,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let deriver_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_b_client_bundle",
            &deriver_b_message,
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
        let deriver_a_message =
            client_proof_bundle_delivery_to_wire_message_v1(&self.bundles.signer_a)?;
        let deriver_b_message =
            client_proof_bundle_delivery_to_wire_message_v1(&self.bundles.signer_b)?;
        let deriver_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_a_client_bundle",
            &deriver_a_message,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let deriver_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "deriver_b_client_bundle",
            &deriver_b_message,
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

/// Strict Deriver A activation package for opaque server proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRecipientProofBundleActivationV1 {
    /// Deriver A opaque server proof bundle.
    pub deriver_a_bundle: WireMessageV1,
    /// Deriver B opaque server proof bundle.
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

/// SigningWorker activation request for strict opaque proof-bundle delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    /// Public context needed to verify and open SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Opaque server proof bundles from Deriver A and Deriver B.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
    /// Canonical exact material activation owned by this SigningWorker.
    pub material_activation: MpcMaterialActivationRefV1,
}

impl CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    /// Creates a validated SigningWorker activation request from Router public context.
    pub fn new(
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
        material_activation: MpcMaterialActivationRefV1,
    ) -> RouterAbProtocolResult<Self> {
        router_payload.require_recipient_role(Role::SignerA)?;
        activation.validate_for_router_payload(&router_payload)?;
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        let request = Self {
            activation_context,
            activation,
            material_activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the activation context and opaque server bundles.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.activation_context.validate()?;
        self.material_activation.validate()?;
        if self.material_activation.material_owner != self.activation_context.lifecycle.account_id
            || self.material_activation.signing_worker
                != self.activation_context.signer_set.selected_server.server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "SigningWorker material activation does not match activation context",
            ));
        }
        self.activation
            .validate_for_activation_context(&self.activation_context)
    }
}

/// Pending SigningWorker activation produced after the Router completes both Deriver calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1 {
    /// Typed Router A/B ECDSA derivation registration/bootstrap request admitted by Router.
    pub registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    /// Digest of the Router-authenticated tenant-root custody binding.
    pub tenant_root_custody_binding_digest: TenantRootProtocolDigestV1,
    /// Public context needed to verify and open SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Opaque SigningWorker proof bundles from Deriver A and Deriver B.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
}

impl CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1 {
    /// Creates a pending activation from Router public context and encrypted server bundles.
    pub fn new(
        registration: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        tenant_root_custody_binding_digest: TenantRootProtocolDigestV1,
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
    ) -> RouterAbProtocolResult<Self> {
        router_payload.require_recipient_role(Role::SignerA)?;
        activation.validate_for_router_payload(&router_payload)?;
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        let request = Self {
            registration,
            tenant_root_custody_binding_digest,
            activation_context,
            activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates registration metadata against the generic Router A/B activation context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.registration.validate()?;
        self.activation_context.validate()?;
        self.activation
            .validate_for_activation_context(&self.activation_context)?;
        let public_request = self.registration.to_threshold_prf_request()?;
        let transcript_metadata = public_request.transcript_metadata()?;
        if self.activation_context.lifecycle != public_request.lifecycle
            || self.activation_context.signer_set != public_request.signer_set
            || self.activation_context.transcript_metadata != transcript_metadata
            || self.activation_context.transcript_digest != public_request.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation activation context does not match registration transcript",
            ));
        }
        Ok(())
    }
}

/// Public Router activation command carrying client facts derived after proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationActivationCommandV1 {
    /// Gateway-owned idempotency identity for this activation.
    pub activation_correlation_id: String,
    /// Router-produced pending activation with encrypted SigningWorker proof bundles.
    pub pending: CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1,
    /// Client public facts produced by the verified `XClientBase` finalizer.
    pub client_activation: EcdsaVerifiedClientActivationFactsV1,
}

impl CloudflareRouterAbEcdsaDerivationActivationCommandV1 {
    /// Creates a validated public Router activation command.
    pub fn new(
        activation_correlation_id: impl Into<String>,
        pending: CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1,
        client_activation: EcdsaVerifiedClientActivationFactsV1,
    ) -> RouterAbProtocolResult<Self> {
        let command = Self {
            activation_correlation_id: activation_correlation_id.into(),
            pending,
            client_activation,
        };
        command.validate()?;
        Ok(command)
    }

    /// Validates client facts against the exact registration request and proof transcript.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "ECDSA activation correlation id",
            &self.activation_correlation_id,
        )?;
        self.pending.validate()?;
        if self.activation_correlation_id != self.pending.activation_context.lifecycle.lifecycle_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA activation correlation id does not match lifecycle id",
            ));
        }
        self.client_activation.validate().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation client activation facts are malformed",
            )
        })?;
        let registration = &self.pending.registration;
        let expected_request_digest =
            encode_base64url_bytes_v1(registration.request_digest()?.as_bytes());
        let public_request = registration.to_threshold_prf_request()?;
        let expected_transcript_digest =
            encode_base64url_bytes_v1(public_request.transcript_digest.as_bytes());
        let expected_context_binding =
            encode_base64url_bytes_v1(registration.context.context_binding_digest()?.as_bytes());
        if self.client_activation.registration_request_digest_b64u != expected_request_digest
            || self.client_activation.proof_transcript_digest_b64u != expected_transcript_digest
            || self.client_activation.context_binding32_b64u != expected_context_binding
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation client activation does not match pending registration",
            ));
        }
        Ok(())
    }

    /// Converts a public command into the private SigningWorker activation request.
    pub fn into_signing_worker_request(
        self,
    ) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1>
    {
        self.validate()?;
        let material_activation =
            cloudflare_router_ab_ecdsa_derivation_material_activation_ref_v1(&self)?;
        CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1::new(
            self.activation_correlation_id,
            self.pending,
            self.client_activation,
            material_activation,
        )
    }
}

/// SigningWorker activation request carrying the Router-minted material reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1 {
    /// Gateway-owned idempotency identity for this activation.
    pub activation_correlation_id: String,
    /// Router-produced pending activation with encrypted SigningWorker proof bundles.
    pub pending: CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1,
    /// Client public facts produced by the verified `XClientBase` finalizer.
    pub client_activation: EcdsaVerifiedClientActivationFactsV1,
    /// Canonical exact material activation for this ECDSA capability.
    pub material_activation: MpcMaterialActivationRefV1,
}

/// Derives the stable Router-owned activation reference for one idempotent activation command.
pub fn cloudflare_router_ab_ecdsa_derivation_material_activation_ref_v1(
    command: &CloudflareRouterAbEcdsaDerivationActivationCommandV1,
) -> RouterAbProtocolResult<MpcMaterialActivationRefV1> {
    command.validate()?;
    let lifecycle = command.pending.activation_context.lifecycle();
    let selected_server = &command
        .pending
        .activation_context
        .signer_set()
        .selected_server;
    let activation_id = router_owned_ecdsa_activation_component_v1(
        b"router-ab-cloudflare/ecdsa-material-activation-id/v1",
        command,
        "ecdsa-activation-v1",
    )?;
    let capability = router_owned_ecdsa_activation_component_v1(
        b"router-ab-cloudflare/ecdsa-material-capability/v1",
        command,
        "ecdsa-capability-v1",
    )?;
    MpcMaterialActivationRefV1::new(
        activation_id,
        capability,
        lifecycle.account_id.clone(),
        command.client_activation.context_binding32_b64u.clone(),
        lifecycle.lifecycle_id.clone(),
        selected_server.server_id.clone(),
    )
}

fn router_owned_ecdsa_activation_component_v1(
    domain: &[u8],
    command: &CloudflareRouterAbEcdsaDerivationActivationCommandV1,
    prefix: &str,
) -> RouterAbProtocolResult<String> {
    let lifecycle = command.pending.activation_context.lifecycle();
    let selected_server = &command
        .pending
        .activation_context
        .signer_set()
        .selected_server;
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, domain);
    push_hash_field_v1(&mut hasher, command.activation_correlation_id.as_bytes());
    push_hash_field_v1(&mut hasher, lifecycle.account_id.as_bytes());
    push_hash_field_v1(
        &mut hasher,
        command
            .client_activation
            .registration_request_digest_b64u
            .as_bytes(),
    );
    push_hash_field_v1(
        &mut hasher,
        command
            .client_activation
            .proof_transcript_digest_b64u
            .as_bytes(),
    );
    push_hash_field_v1(
        &mut hasher,
        command.client_activation.context_binding32_b64u.as_bytes(),
    );
    push_hash_field_v1(&mut hasher, selected_server.server_id.as_bytes());
    let digest = hasher.finalize();
    Ok(format!(
        "{prefix}-{}",
        encode_base64url_bytes_v1(digest.as_slice())
    ))
}

impl CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1 {
    /// Binds verified client facts to one exact pending Router activation.
    pub fn new(
        activation_correlation_id: impl Into<String>,
        pending: CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1,
        client_activation: EcdsaVerifiedClientActivationFactsV1,
        material_activation: MpcMaterialActivationRefV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            activation_correlation_id: activation_correlation_id.into(),
            pending,
            client_activation,
            material_activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates client facts against the exact registration request and proof transcript.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "ECDSA activation correlation id",
            &self.activation_correlation_id,
        )?;
        self.pending.validate()?;
        self.material_activation.validate()?;
        if self.activation_correlation_id != self.pending.activation_context.lifecycle.lifecycle_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA activation correlation id does not match lifecycle id",
            ));
        }
        if self.material_activation.material_owner
            != self.pending.activation_context.lifecycle.account_id
            || self.material_activation.signing_worker
                != self
                    .pending
                    .activation_context
                    .signer_set
                    .selected_server
                    .server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA material activation does not match activation context",
            ));
        }
        self.client_activation.validate().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation client activation facts are malformed",
            )
        })?;
        let registration = &self.pending.registration;
        let expected_request_digest =
            encode_base64url_bytes_v1(registration.request_digest()?.as_bytes());
        let public_request = registration.to_threshold_prf_request()?;
        let expected_transcript_digest =
            encode_base64url_bytes_v1(public_request.transcript_digest.as_bytes());
        let expected_context_binding =
            encode_base64url_bytes_v1(registration.context.context_binding_digest()?.as_bytes());
        if self.client_activation.registration_request_digest_b64u != expected_request_digest
            || self.client_activation.proof_transcript_digest_b64u != expected_transcript_digest
            || self.client_activation.context_binding32_b64u != expected_context_binding
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation client activation does not match pending registration",
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
            activation_context: self.pending.activation_context.clone(),
            activation: self.pending.activation.clone(),
            material_activation: self.material_activation.clone(),
        };
        activation.validate()?;
        Ok(activation)
    }
}

/// SigningWorker activation-refresh request for Router A/B ECDSA derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1 {
    /// Typed Router A/B ECDSA derivation activation-refresh request admitted by Router.
    pub refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1,
    /// Public context needed to verify and open SigningWorker proof bundles.
    pub activation_context: SigningWorkerActivationContextV1,
    /// Opaque SigningWorker proof bundles from Deriver A and Deriver B.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
    /// Canonical exact material activation for the refreshed ECDSA capability.
    pub material_activation: MpcMaterialActivationRefV1,
    /// Digest of the Router-authenticated tenant-root custody binding.
    pub tenant_root_custody_binding_digest: TenantRootProtocolDigestV1,
}

impl CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation activation-refresh request from Router public context.
    pub fn new(
        refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1,
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationV1,
        material_activation: MpcMaterialActivationRefV1,
        tenant_root_custody_binding_digest: TenantRootProtocolDigestV1,
    ) -> RouterAbProtocolResult<Self> {
        router_payload.require_recipient_role(Role::SignerA)?;
        activation.validate_for_router_payload(&router_payload)?;
        let activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        let request = Self {
            refresh_request,
            activation_context,
            activation,
            material_activation,
            tenant_root_custody_binding_digest,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates typed refresh metadata against the generic Router A/B activation context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.refresh_request.validate()?;
        self.material_activation.validate()?;
        if self.material_activation.material_owner != self.activation_context.lifecycle.account_id
            || self.material_activation.signing_worker
                != self.activation_context.signer_set.selected_server.server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA refresh material activation does not match activation context",
            ));
        }
        self.activation_context.validate()?;
        self.activation
            .validate_for_activation_context(&self.activation_context)?;
        let public_request = self.refresh_request.to_threshold_prf_request()?;
        let transcript_metadata = public_request.transcript_metadata()?;
        if self.activation_context.lifecycle != public_request.lifecycle
            || self.activation_context.signer_set != public_request.signer_set
            || self.activation_context.transcript_metadata != transcript_metadata
            || self.activation_context.transcript_digest != public_request.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation activation-refresh context does not match refresh transcript",
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
            material_activation: self.material_activation.clone(),
        };
        activation.validate()?;
        Ok(activation)
    }
}

/// Router A/B ECDSA derivation activation receipt safe to return across the public boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1 {
    /// Router A/B ECDSA derivation public identity activated for normal signing.
    pub ecdsa_activation: RouterAbEcdsaDerivationActivationReceiptV1,
    /// Lifecycle id accepted by the SigningWorker.
    pub lifecycle_id: String,
    /// Public transcript digest accepted by the SigningWorker.
    pub transcript_digest: PublicDigest32,
    /// Whether the SigningWorker committed the activation.
    pub activated: bool,
}

impl CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1 {
    /// Creates a public receipt from server-internal SigningWorker storage evidence.
    pub fn new(
        ecdsa_activation: RouterAbEcdsaDerivationActivationReceiptV1,
        signing_worker_output: CloudflareSigningWorkerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        signing_worker_output.validate()?;
        if ecdsa_activation.signing_worker
            != signing_worker_output
                .active_signing_worker_state
                .signing_worker
            || ecdsa_activation.activation_digest_b64u
                != encode_base64url_bytes_v1(
                    signing_worker_output
                        .active_signing_worker_state
                        .activation_digest
                        .as_bytes(),
                )
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router A/B ECDSA derivation activation does not match SigningWorker storage evidence",
            ));
        }
        let receipt = Self {
            ecdsa_activation,
            lifecycle_id: signing_worker_output.lifecycle_id,
            transcript_digest: signing_worker_output.transcript_digest,
            activated: signing_worker_output.activated,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates the public activation receipt.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.ecdsa_activation.validate()?;
        require_non_empty("activation lifecycle_id", &self.lifecycle_id)?;
        if !self.activated {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation activation was not committed",
            ));
        }
        Ok(())
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

/// Converts a Router A/B ECDSA derivation context into the Router A/B ECDSA derivation crate context.
pub fn cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(
    context: &RouterAbEcdsaDerivationStableKeyContextV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationStableKeyContext> {
    context.validate()?;
    let application_binding_digest = decode_base64url_fixed_32_v1(
        "Router A/B ECDSA derivation application_binding_digest_b64u",
        &context.application_binding_digest_b64u,
    )?;
    let ecdsa_context = RouterAbEcdsaDerivationStableKeyContext::new(application_binding_digest);
    ecdsa_context
        .validate()
        .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    Ok(ecdsa_context)
}

/// Derives the public Router A/B ECDSA derivation identity from opened SigningWorker A/B material.
pub fn cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1(
    registration: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    client_activation: &EcdsaVerifiedClientActivationFactsV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationPublicIdentityV1> {
    registration.validate()?;
    client_activation.validate().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router A/B ECDSA derivation client activation facts are malformed",
        )
    })?;
    material.validate()?;
    let public_request = registration.to_threshold_prf_request()?;
    if material.transcript_digest != public_request.transcript_digest
        || material.recipient_identity != registration.signer_set.selected_server.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B ECDSA derivation activation material does not match registration transcript",
        ));
    }
    let ecdsa_context =
        cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(&registration.context)?;
    let derivation_client_share_public_key33 = decode_base64url_fixed_33_v1(
        "Router A/B ECDSA derivation client activation derivation_client_share_public_key33_b64u",
        &client_activation.derivation_client_share_public_key33_b64u,
    )?;
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &derivation_client_share_public_key33,
        client_activation.client_share_retry_counter,
    )
    .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    RouterAbEcdsaDerivationPublicIdentityV1::new(
        encode_base64url_bytes_v1(&identity.context_binding32),
        encode_base64url_bytes_v1(&identity.derivation_client_share_public_key33),
        encode_base64url_bytes_v1(&identity.relayer_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_ethereum_address20),
        identity.client_share_retry_counter,
        identity.relayer_share_retry_counter,
    )
}

/// Builds a public Router A/B ECDSA derivation activation receipt from opened SigningWorker material.
pub fn cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
    request: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
    material: &CloudflareServerOutputMaterialRecordV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationActivationReceiptV1> {
    request.validate()?;
    let public_identity =
        cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1(
            &request.pending.registration,
            &request.client_activation,
            material,
        )?;
    let selected_worker = request
        .pending
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    let activation_epoch = request
        .pending
        .activation_context
        .lifecycle()
        .root_share_epoch
        .as_str()
        .to_owned();
    let activation_digest = cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(
        &request.pending.activation,
    )?;
    let receipt = RouterAbEcdsaDerivationActivationReceiptV1 {
        context: request.pending.registration.context.clone(),
        public_identity,
        signing_worker: selected_worker,
        material_activation: request.material_activation.clone(),
        activation_epoch,
        activation_digest_b64u: encode_base64url_bytes_v1(activation_digest.as_bytes()),
        activated_at_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Builds a public Router A/B ECDSA derivation activation receipt from refreshed SigningWorker material.
pub fn cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1(
    request: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1,
    material: &CloudflareServerOutputMaterialRecordV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationActivationReceiptV1> {
    request.validate()?;
    let selected_worker = request
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    let derived_identity =
        cloudflare_router_ab_ecdsa_derivation_public_identity_from_material_parts_v1(
            &request.refresh_request.context,
            &request.refresh_request.public_identity,
            &selected_worker,
            material,
            "Router A/B ECDSA derivation refreshed activation material",
        )?;
    if derived_identity != request.refresh_request.public_identity {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B ECDSA derivation refreshed activation material does not match public identity",
        ));
    }
    let activation_digest =
        cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(&request.activation)?;
    let receipt = RouterAbEcdsaDerivationActivationReceiptV1 {
        context: request.refresh_request.context.clone(),
        public_identity: request.refresh_request.public_identity.clone(),
        signing_worker: selected_worker,
        material_activation: request.material_activation.clone(),
        activation_epoch: request.refresh_request.next_activation_epoch.clone(),
        activation_digest_b64u: encode_base64url_bytes_v1(activation_digest.as_bytes()),
        activated_at_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Builds a normal-signing scope from a validated Router A/B ECDSA derivation activation receipt.
pub fn cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
    receipt: &RouterAbEcdsaDerivationActivationReceiptV1,
    wallet_id: impl Into<String>,
    ecdsa_threshold_key_id: impl Into<String>,
    signing_root_id: impl Into<String>,
    signing_root_version: impl Into<String>,
    material_activation: MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationNormalSigningScopeV1> {
    receipt.validate()?;
    RouterAbEcdsaDerivationNormalSigningScopeV1::new(
        wallet_id,
        ecdsa_threshold_key_id,
        signing_root_id,
        signing_root_version,
        receipt.context.clone(),
        receipt.public_identity.clone(),
        receipt.signing_worker.clone(),
        receipt.activation_epoch.clone(),
        material_activation,
    )
}

/// Derives the Router A/B ECDSA derivation identity implied by active SigningWorker material.
pub fn cloudflare_router_ab_ecdsa_derivation_public_identity_from_normal_signing_material_v1(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationPublicIdentityV1> {
    let (_, identity) =
        cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_normal_signing_material_v1(
            scope, material,
        )?;
    Ok(identity)
}

fn cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_normal_signing_material_v1(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<(
    router_ab_ecdsa_derivation::RelayerRoleShare,
    RouterAbEcdsaDerivationPublicIdentityV1,
)> {
    scope.validate()?;
    material.validate()?;
    if material.recipient_identity != scope.signing_worker.server_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B ECDSA derivation normal-signing material recipient does not match SigningWorker",
        ));
    }
    let ecdsa_context =
        cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(&scope.context)?;
    let derivation_client_share_public_key33 = decode_base64url_fixed_33_v1(
        "Router A/B ECDSA derivation normal signing derivation_client_share_public_key33_b64u",
        &scope
            .public_identity
            .derivation_client_share_public_key33_b64u,
    )?;
    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &derivation_client_share_public_key33,
        scope.public_identity.client_share_retry_counter,
    )
    .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    let identity = RouterAbEcdsaDerivationPublicIdentityV1::new(
        encode_base64url_bytes_v1(&identity.context_binding32),
        encode_base64url_bytes_v1(&identity.derivation_client_share_public_key33),
        encode_base64url_bytes_v1(&identity.relayer_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_ethereum_address20),
        identity.client_share_retry_counter,
        identity.relayer_share_retry_counter,
    )?;
    if identity != scope.public_identity {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B ECDSA derivation normal-signing material does not match public identity",
        ));
    }
    Ok((relayer_share, identity))
}

fn cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_source_preserving_material_v1(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<(RelayerRoleShare, RouterAbEcdsaDerivationPublicIdentityV1)> {
    scope.validate()?;
    material.validate()?;
    if material.recipient_identity != scope.signing_worker.server_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B source-preserving ECDSA material recipient does not match SigningWorker",
        ));
    }
    let ecdsa_context =
        cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(&scope.context)?;
    let derivation_client_share_public_key33 = decode_base64url_fixed_33_v1(
        "Router A/B source-preserving ECDSA derivation client public key",
        &scope
            .public_identity
            .derivation_client_share_public_key33_b64u,
    )?;
    let relayer_public_key33 =
        ecdsa_lane_client_public_key_from_share32_v1(*material.output_material.as_bytes())
            .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    let identity = compose_public_identity_from_public_keys(
        &ecdsa_context,
        &derivation_client_share_public_key33,
        scope.public_identity.client_share_retry_counter,
        &relayer_public_key33,
        scope.public_identity.server_share_retry_counter,
    )
    .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    let public_identity = RouterAbEcdsaDerivationPublicIdentityV1::new(
        encode_base64url_bytes_v1(&identity.context_binding32),
        encode_base64url_bytes_v1(&identity.derivation_client_share_public_key33),
        encode_base64url_bytes_v1(&identity.relayer_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_ethereum_address20),
        identity.client_share_retry_counter,
        identity.relayer_share_retry_counter,
    )?;
    if public_identity != scope.public_identity {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B source-preserving ECDSA material does not match public identity",
        ));
    }
    let context_bytes =
        encode_context(&ecdsa_context).map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    let relayer_share = RelayerRoleShare {
        context_bytes,
        context_binding32: identity.context_binding32,
        retry_counter: identity.relayer_share_retry_counter,
        x_relayer32: *material.output_material.as_bytes(),
        relayer_public_key33,
    };
    Ok((relayer_share, public_identity))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_active_material_v1(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    active_signing_worker: &ActiveSigningWorkerStateV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<(RelayerRoleShare, RouterAbEcdsaDerivationPublicIdentityV1)> {
    if active_signing_worker
        .signing_worker_material_handle
        .starts_with(SOURCE_PRESERVING_ECDSA_MATERIAL_HANDLE_PREFIX_V1)
    {
        cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_source_preserving_material_v1(
            scope, material,
        )
    } else {
        cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_normal_signing_material_v1(
            scope, material,
        )
    }
}

fn cloudflare_router_ab_ecdsa_derivation_public_identity_from_material_parts_v1(
    context: &RouterAbEcdsaDerivationStableKeyContextV1,
    public_identity: &RouterAbEcdsaDerivationPublicIdentityV1,
    signing_worker: &ServerIdentityV1,
    material: &CloudflareServerOutputMaterialRecordV1,
    label: &str,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationPublicIdentityV1> {
    context.validate()?;
    public_identity.validate_for_context(context)?;
    signing_worker.validate()?;
    material.validate()?;
    if material.recipient_identity != signing_worker.server_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} recipient does not match SigningWorker"),
        ));
    }
    let ecdsa_context = cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(context)?;
    let derivation_client_share_public_key33 = decode_base64url_fixed_33_v1(
        "Router A/B ECDSA derivation normal signing derivation_client_share_public_key33_b64u",
        &public_identity.derivation_client_share_public_key33_b64u,
    )?;
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &derivation_client_share_public_key33,
        public_identity.client_share_retry_counter,
    )
    .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    RouterAbEcdsaDerivationPublicIdentityV1::new(
        encode_base64url_bytes_v1(&identity.context_binding32),
        encode_base64url_bytes_v1(&identity.derivation_client_share_public_key33),
        encode_base64url_bytes_v1(&identity.relayer_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_public_key33),
        encode_base64url_bytes_v1(&identity.threshold_ethereum_address20),
        identity.client_share_retry_counter,
        identity.relayer_share_retry_counter,
    )
}

/// Validates that active SigningWorker state and material belong to a Router A/B ECDSA derivation scope.
pub fn validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    active_signing_worker: &ActiveSigningWorkerStateV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<()> {
    scope.validate()?;
    active_signing_worker.validate()?;
    material.validate()?;
    if active_signing_worker.account_id != scope.wallet_id
        || active_signing_worker.material_activation != scope.material_activation
        || active_signing_worker.signing_worker != scope.signing_worker
        || material.transcript_digest != active_signing_worker.activation_transcript_digest
        || material.recipient_identity != active_signing_worker.signing_worker.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B ECDSA derivation normal-signing active state does not match scope",
        ));
    }
    let derived_identity = if active_signing_worker
        .signing_worker_material_handle
        .starts_with(SOURCE_PRESERVING_ECDSA_MATERIAL_HANDLE_PREFIX_V1)
    {
        let (_, identity) =
            cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_source_preserving_material_v1(
                scope, material,
            )?;
        identity
    } else {
        cloudflare_router_ab_ecdsa_derivation_public_identity_from_normal_signing_material_v1(
            scope, material,
        )?
    };
    if derived_identity == scope.public_identity {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "Router A/B ECDSA derivation normal-signing active material does not match public identity",
    ))
}

/// Validates direct active lane material against the authoritative linked-device scope.
pub fn validate_cloudflare_linked_device_ecdsa_normal_signing_active_material_v1(
    scope: &RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    active_signing_worker: &ActiveSigningWorkerStateV1,
    material: &CloudflareServerOutputMaterialRecordV1,
) -> RouterAbProtocolResult<()> {
    scope.validate()?;
    active_signing_worker.validate()?;
    material.validate()?;
    let signing_worker = ServerIdentityV1::new(
        scope.signing_worker_participant_id.clone(),
        scope.signing_worker_recipient_key_id.clone(),
        scope.signing_worker_hpke_public_key_b64u.clone(),
    )?;
    let transcript = PublicDigest32::new(decode_base64url_fixed_32_v1(
        "linked ECDSA transcript_hash_b64u",
        &scope.transcript_hash_b64u,
    )?);
    if active_signing_worker.account_id != scope.wallet_id
        || active_signing_worker.material_activation != scope.material_activation
        || active_signing_worker.signing_worker != signing_worker
        || active_signing_worker.activation_transcript_digest != transcript
        || material.transcript_digest != transcript
        || material.recipient_identity != scope.signing_worker_participant_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "linked ECDSA active lane material does not match authoritative scope",
        ));
    }
    let server_public =
        ecdsa_lane_client_public_key_from_share32_v1(*material.output_material.as_bytes())
            .map_err(map_router_ab_ecdsa_derivation_error_v1)?;
    if encode_base64url_bytes_v1(&server_public) == scope.target_server_public_commitment_b64u {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "linked ECDSA server share does not match committed public identity",
    ))
}

/// Builds the active SigningWorker state descriptor from a validated activation request.
pub fn cloudflare_active_signing_worker_state_from_activation_request_v1(
    request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    material_activation: MpcMaterialActivationRefV1,
    signing_worker_material_handle: impl Into<String>,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    request.validate()?;
    material_activation.validate()?;
    let lifecycle = request.activation_context.lifecycle();
    let selected_server = request
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    if material_activation.material_owner != lifecycle.account_id
        || material_activation.signing_worker != selected_server.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "material activation does not match SigningWorker activation context",
        ));
    }
    ActiveSigningWorkerStateV1::new(
        lifecycle.account_id.clone(),
        material_activation,
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

/// Builds an ECDSA active SigningWorker state from the canonical activation ref.
pub fn cloudflare_router_ab_ecdsa_derivation_active_signing_worker_state_from_activation_request_v1(
    request: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
    material_activation: MpcMaterialActivationRefV1,
    signing_worker_material_handle: impl Into<String>,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    request.validate()?;
    material_activation.validate()?;
    let lifecycle = request.pending.activation_context.lifecycle();
    let selected_server = request
        .pending
        .activation_context
        .signer_set()
        .selected_server
        .clone();
    if material_activation.material_owner != lifecycle.account_id
        || material_activation.signing_worker != selected_server.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "ECDSA material activation does not match SigningWorker activation context",
        ));
    }
    ActiveSigningWorkerStateV1::new(
        lifecycle.account_id.clone(),
        material_activation,
        request
            .pending
            .activation_context
            .transcript_metadata
            .account_public_key
            .clone(),
        selected_server,
        request.pending.activation_context.transcript_digest,
        cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(
            &request.pending.activation,
        )?,
        signing_worker_material_handle,
        activated_at_ms,
    )
}

/// Strict Router result for Router A/B ECDSA derivation registration/bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1 {
    /// Request was accepted and both recipient-specific bundle pairs were aggregated.
    Forwarded {
        /// Public client proof-bundle response.
        response: Box<CloudflareRouterRecipientProofBundleResponseV1>,
        /// Server-retained pending activation awaiting verified client facts.
        pending_activation: Box<CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1>,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1 {
    /// Creates a forwarded Router A/B ECDSA derivation registration response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        pending_activation: CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response: Box::new(response),
            pending_activation: Box::new(pending_activation),
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped Router A/B ECDSA derivation registration response.
    pub fn stopped(decision: ExpensiveWorkGateDecisionV1) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped { decision };
        result.validate()?;
        Ok(result)
    }

    /// Validates Router A/B ECDSA derivation registration response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                pending_activation,
            } => {
                response.validate()?;
                pending_activation.validate()
            }
            Self::Stopped { decision } => decision.validate(),
        }
    }
}

/// Strict Router result for Router A/B ECDSA derivation explicit export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationExportAuthorityV1 {
    /// Exact key handle selected by the authenticated Wallet Session.
    pub key_handle: String,
    /// Exact operation authority carried by the authenticated Wallet Session.
    pub authorization: NormalSigningAuthorizationV1,
    /// Exact active normal-signing capability carried by the Wallet Session.
    pub normal_signing_scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
}

impl CloudflareRouterAbEcdsaDerivationExportAuthorityV1 {
    /// Validates the authenticated export authority against its public request.
    pub fn validate_for_request(
        &self,
        request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.normal_signing_scope.validate()?;
        require_non_empty("ECDSA export authority key_handle", &self.key_handle)?;
        self.authorization.validate()?;
        let scope = &self.normal_signing_scope;
        if self.authorization != request.authorization
            || scope.wallet_id != request.lifecycle.account_id
            || scope.context != request.context
            || scope.public_identity != request.public_identity
            || scope.signing_worker != request.signer_set.selected_server
            || scope.activation_epoch != request.lifecycle.root_share_epoch.as_str()
            || scope.material_activation != request.material_activation
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "authenticated ECDSA export authority does not match the requested capability",
            ));
        }
        Ok(())
    }
}

/// Server-private authorization identity forwarded to SigningWorker for one
/// exact ECDSA export redemption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareSigningWorkerEcdsaExportAuthorizationV1 {
    /// Exact reusable Wallet Session identity.
    ReusableWalletSession { wallet_session_id: String },
    /// Verified step-up evidence identity kept off the public request.
    OperationStepUp { evidence_set_digest: String },
}

impl CloudflareSigningWorkerEcdsaExportAuthorizationV1 {
    fn validate_for_public_authorization(
        &self,
        authorization: &NormalSigningAuthorizationV1,
    ) -> RouterAbProtocolResult<()> {
        match (authorization, self) {
            (
                NormalSigningAuthorizationV1::ReusableWalletSession {
                    wallet_session_id: expected,
                },
                Self::ReusableWalletSession { wallet_session_id },
            ) => {
                require_non_empty("ECDSA export private wallet_session_id", wallet_session_id)?;
                if wallet_session_id != expected {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "ECDSA export private Wallet Session identity does not match the public request",
                    ));
                }
                Ok(())
            }
            (
                NormalSigningAuthorizationV1::OperationStepUp,
                Self::OperationStepUp {
                    evidence_set_digest,
                },
            ) => {
                decode_public_digest_b64u_v1(
                    "ECDSA export private evidence_set_digest",
                    evidence_set_digest,
                )?;
                Ok(())
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA export private authorization branch does not match the public request",
            )),
        }
    }

    fn validate_for_request(
        &self,
        request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.validate_for_public_authorization(&request.authorization)
    }

    #[cfg(any(feature = "workers-rs", test))]
    fn binding_authorization_kind(&self) -> &'static str {
        match self {
            Self::ReusableWalletSession { .. } => "reusable_wallet_session",
            Self::OperationStepUp { .. } => "verified_step_up",
        }
    }

    #[cfg(any(feature = "workers-rs", test))]
    fn authorization_id(&self) -> &str {
        match self {
            Self::ReusableWalletSession { wallet_session_id }
            | Self::OperationStepUp {
                evidence_set_digest: wallet_session_id,
            } => wallet_session_id,
        }
    }
}

/// Server-resolved coordinates for one tenant's active derivation root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootCoordinatesV1 {
    /// Canonical tenant identity digest.
    pub identity_digest_b64u: String,
    /// Canonical custody lineage identifier.
    pub custody_lineage_b64u: String,
}

impl CloudflareTenantRootCoordinatesV1 {
    pub fn resolve(
        &self,
    ) -> RouterAbProtocolResult<(TenantRootIdentityDigestV1, TenantRootCustodyLineageId)> {
        let identity_digest_bytes = decode_base64url_fixed_32_v1(
            "tenant-root identity digest",
            &self.identity_digest_b64u,
        )?;
        if encode_base64url_bytes_v1(&identity_digest_bytes) != self.identity_digest_b64u {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "tenant-root identity digest is not canonical base64url",
            ));
        }
        let custody_lineage = TenantRootCustodyLineageId::from_base64url(
            &self.custody_lineage_b64u,
        )
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("tenant-root custody lineage is invalid: {error}"),
            )
        })?;
        Ok((
            TenantRootIdentityDigestV1::from_bytes(identity_digest_bytes),
            custody_lineage,
        ))
    }
}

/// Gateway-admitted explicit-export request and exact Wallet Session capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationExportCommandV1 {
    /// Typed explicit-export request created by the browser ceremony.
    pub request: RouterAbEcdsaDerivationExplicitExportRequestV1,
    /// Exact authority derived from the authenticated ECDSA Wallet Session.
    pub export_authority: CloudflareRouterAbEcdsaDerivationExportAuthorityV1,
    /// Exact active SigningWorker material source selected by Gateway admission.
    pub material_source: CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    /// Server-private authorization identity for SigningWorker redemption.
    pub private_authorization: CloudflareSigningWorkerEcdsaExportAuthorizationV1,
    /// Tenant-root coordinates resolved by the authenticated server boundary.
    pub tenant_root: CloudflareTenantRootCoordinatesV1,
}

impl CloudflareRouterAbEcdsaDerivationExportCommandV1 {
    /// Validates the request and authenticated capability as one command.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.request.validate_at(now_unix_ms)?;
        self.export_authority.validate_for_request(&self.request)?;
        self.material_source
            .validate_for_ecdsa_scope(&self.export_authority.normal_signing_scope)?;
        self.private_authorization
            .validate_for_request(&self.request)?;
        self.tenant_root.resolve()?;
        Ok(())
    }
}

/// Gateway-admitted activation refresh with server-resolved tenant-root coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationActivationRefreshCommandV1 {
    /// Typed activation-refresh request created by the browser ceremony.
    pub refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1,
    /// Tenant-root coordinates resolved by the authenticated server boundary.
    pub tenant_root: CloudflareTenantRootCoordinatesV1,
}

impl CloudflareRouterAbEcdsaDerivationActivationRefreshCommandV1 {
    /// Validates the browser request and server-owned coordinates.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.refresh_request.validate_at(now_unix_ms)?;
        self.tenant_root.resolve()?;
        Ok(())
    }
}

/// Private MPCRouter request for one exact SigningWorker export-share delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaExportShareRequestV1 {
    /// Exact browser export request admitted by MPCRouter.
    pub request: RouterAbEcdsaDerivationExplicitExportRequestV1,
    /// Exact authenticated Wallet Session capability forwarded by Gateway.
    pub export_authority: CloudflareRouterAbEcdsaDerivationExportAuthorityV1,
    /// Exact active SigningWorker material source selected by Gateway admission.
    pub material_source: CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    /// Server-private authorization identity forwarded by Router.
    pub private_authorization: CloudflareSigningWorkerEcdsaExportAuthorizationV1,
}

/// Private request for one exact active additive-lane export share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerLinkedEcdsaExportShareRequestV1 {
    pub scope: RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    pub material_source: CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    pub binding: EcdsaSigningWorkerExportShareBindingV1,
}

impl CloudflareSigningWorkerLinkedEcdsaExportShareRequestV1 {
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        self.material_source
            .validate_for_linked_ecdsa_scope(&self.scope)?;
        self.binding.validate().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "linked ECDSA export-share binding is invalid",
            )
        })?;
        let activation = &self.scope.material_activation;
        let expected = &self.binding;
        if expected.wallet_id != self.scope.wallet_id
            || expected.key_handle != self.scope.wallet_key_id
            || expected.ecdsa_threshold_key_id
                != self.scope.target_capability.ecdsa_threshold_key_id
            || expected.signing_root_id != self.scope.lane_id
            || expected.signing_root_version != self.scope.lane_share_epoch
            || expected.activation_epoch != self.scope.lane_share_epoch
            || expected.signing_worker_id != self.scope.signing_worker_participant_id
            || expected.context_binding_b64u != self.scope.public_identity_digest_b64u
            || expected.threshold_public_key33_b64u != self.scope.threshold_public_key33_b64u
            || expected.authorization_kind != "reusable_wallet_session"
            || expected.material_activation.activation_id != activation.activation_id
            || expected.material_activation.capability != activation.capability
            || expected.material_activation.material_owner != activation.material_owner
            || expected.material_activation.key_binding != activation.key_binding
            || expected.material_activation.lifecycle_binding != activation.lifecycle_binding
            || expected.material_activation.signing_worker != activation.signing_worker
            || expected.expires_at_ms <= now_unix_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "linked ECDSA export-share request changed its admitted lane identity",
            ));
        }
        Ok(())
    }
}

/// No-secret acknowledgement that the requested ECDSA export material is active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaExportPreflightResponseV1 {
    /// Fixed success marker.
    pub ready: bool,
}

impl CloudflareSigningWorkerEcdsaExportShareRequestV1 {
    /// Validates the private request at SigningWorker time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.request.validate_at(now_unix_ms)?;
        self.export_authority.validate_for_request(&self.request)?;
        self.material_source
            .validate_for_ecdsa_scope(&self.export_authority.normal_signing_scope)?;
        self.private_authorization
            .validate_for_request(&self.request)
    }

    #[cfg(feature = "workers-rs")]
    fn export_share_binding(
        &self,
    ) -> RouterAbProtocolResult<EcdsaSigningWorkerExportShareBindingV1> {
        self.export_authority.validate_for_request(&self.request)?;
        self.material_source
            .validate_for_ecdsa_scope(&self.export_authority.normal_signing_scope)?;
        self.private_authorization
            .validate_for_request(&self.request)?;
        let scope = &self.export_authority.normal_signing_scope;
        let threshold_public_key33_b64u = match &self.material_source {
            CloudflareSigningWorkerNormalSigningMaterialSourceV1::RegistrationActivation {
                ..
            } => scope.public_identity.threshold_public_key33_b64u.clone(),
            CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane {
                group_public_key,
                ..
            } => group_public_key.clone(),
        };
        let binding = EcdsaSigningWorkerExportShareBindingV1 {
            wallet_id: scope.wallet_id.clone(),
            key_handle: self.export_authority.key_handle.clone(),
            ecdsa_threshold_key_id: scope.ecdsa_threshold_key_id.clone(),
            signing_root_id: scope.signing_root_id.clone(),
            signing_root_version: scope.signing_root_version.clone(),
            activation_epoch: scope.activation_epoch.clone(),
            signing_worker_id: scope.signing_worker.server_id.clone(),
            context_binding_b64u: scope.public_identity.context_binding_b64u.clone(),
            threshold_public_key33_b64u,
            export_request_digest_b64u: encode_base64url_bytes_v1(
                self.request.request_digest()?.as_bytes(),
            ),
            export_authorization_digest_b64u: self.request.export_authorization_digest_b64u.clone(),
            export_nonce: self.request.export_nonce.clone(),
            authorization_kind: self
                .private_authorization
                .binding_authorization_kind()
                .to_owned(),
            authorization_id: self.private_authorization.authorization_id().to_owned(),
            material_activation: EcdsaMaterialActivationRefV1 {
                kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
                activation_id: scope.material_activation.activation_id.clone(),
                capability: scope.material_activation.capability.clone(),
                material_owner: scope.material_activation.material_owner.clone(),
                key_binding: scope.material_activation.key_binding.clone(),
                lifecycle_binding: scope.material_activation.lifecycle_binding.clone(),
                signing_worker: scope.material_activation.signing_worker.clone(),
            },
            lifecycle_id: self.request.lifecycle.lifecycle_id.clone(),
            recipient_identity: self.request.client_id.clone(),
            recipient_public_key: self.request.client_ephemeral_public_key.clone(),
            expires_at_ms: self.request.expires_at_ms,
        };
        binding.validate().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker ECDSA export-share binding is invalid",
            )
        })?;
        Ok(binding)
    }
}

/// Strict Router result for Router A/B ECDSA derivation explicit export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1 {
    /// Request was accepted and client export bundles were aggregated.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
        /// Exact SigningWorker additive share encrypted to the authorized browser recipient.
        signing_worker_export: EcdsaSigningWorkerExportShareEnvelopeV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1 {
    /// Creates a forwarded Router A/B ECDSA derivation export response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        signing_worker_export: EcdsaSigningWorkerExportShareEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response,
            signing_worker_export,
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped Router A/B ECDSA derivation export response.
    pub fn stopped(decision: ExpensiveWorkGateDecisionV1) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped { decision };
        result.validate()?;
        Ok(result)
    }

    /// Validates Router A/B ECDSA derivation export response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                signing_worker_export,
            } => {
                response.validate()?;
                signing_worker_export.validate().map_err(|_| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "SigningWorker ECDSA export-share envelope is invalid",
                    )
                })
            }
            Self::Stopped { decision } => decision.validate(),
        }
    }
}

/// Strict Router result for Router A/B ECDSA derivation activation refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1 {
    /// Request was accepted, client bundles were aggregated, and ECDSA activation refreshed.
    Forwarded {
        /// Public client proof-bundle response.
        response: Box<CloudflareRouterRecipientProofBundleResponseV1>,
        /// Router A/B ECDSA derivation SigningWorker activation-refresh receipt.
        signing_worker_activation:
            Box<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1>,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Trusted Router-owned gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1 {
    /// Creates a forwarded Router A/B ECDSA derivation refresh response.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        signing_worker_activation: CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response: Box::new(response),
            signing_worker_activation: Box::new(signing_worker_activation),
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped Router A/B ECDSA derivation refresh response.
    pub fn stopped(decision: ExpensiveWorkGateDecisionV1) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped { decision };
        result.validate()?;
        Ok(result)
    }

    /// Validates Router A/B ECDSA derivation refresh response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                signing_worker_activation,
            } => {
                response.validate()?;
                signing_worker_activation.validate()
            }
            Self::Stopped { decision } => decision.validate(),
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

    /// Applies the deployment project policy to a trusted expensive-work admission.
    pub fn apply_project_policy_to_trusted_admission_v1(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
        admission: CloudflareRouterTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
        admission.validate_for_request(request)?;
        let policy = self
            .bindings
            .admission
            .project_policy
            .policy_for_context(&admission.context, request)?;
        let decision = match policy {
            CloudflareRouterProjectPolicyV1::Allowed => admission.decision,
            CloudflareRouterProjectPolicyV1::Rejected { retry_after_ms } => {
                ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    retry_after_ms,
                )?
            }
        };
        CloudflareRouterTrustedAdmissionV1::new(admission.context, decision)
    }

    /// Applies the deployment project policy to a trusted normal-signing admission.
    pub fn apply_project_policy_to_normal_signing_admission_v1(
        &self,
        request_id: &str,
        admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
        admission.validate()?;
        let decision = self
            .bindings
            .admission
            .project_policy
            .normal_signing_policy_for_metadata(&admission.metadata, request_id)?;
        CloudflareRouterNormalSigningTrustedAdmissionV1::new(admission.metadata, decision)
    }

    /// Evaluates the deployment project policy for a validated Yao ceremony.
    pub fn evaluate_project_policy_for_yao_work_kind_v1(
        &self,
        work_kind: ExpensiveWorkKindV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        self.bindings
            .admission
            .project_policy
            .policy_for_yao_work_kind(work_kind)
    }

    /// Validates a public request with trusted admission and builds gate-aware work.
    pub fn public_request_admission_plan_at(
        &self,
        now_unix_ms: u64,
        request: EcdsaThresholdPrfRequestV1,
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionPlanV1> {
        request.validate_at(now_unix_ms)?;
        let trusted_admission =
            self.apply_project_policy_to_trusted_admission_v1(&request, trusted_admission)?;
        trusted_admission.validate_for_request(&request)?;
        let plan = if trusted_admission.allows_signer_forwarding()? {
            let (deriver_a_message, deriver_b_message) = request.to_signer_wire_messages()?;
            CloudflareRouterPublicAdmissionPlanV1::Forward {
                trusted_admission,
                deriver_a_message,
                deriver_b_message,
            }
        } else {
            CloudflareRouterPublicAdmissionPlanV1::Stop { trusted_admission }
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Derives trusted admission from a provider and builds gate-aware work.
    pub fn public_request_admission_plan_from_provider_at(
        &self,
        now_unix_ms: u64,
        request: EcdsaThresholdPrfRequestV1,
        provider: &mut impl CloudflareRouterAdmissionProviderV1,
    ) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionPlanV1> {
        let trusted_admission =
            derive_cloudflare_router_trusted_admission_from_provider_v1(&request, provider)?;
        self.public_request_admission_plan_at(now_unix_ms, request, trusted_admission)
    }

    /// Returns the Deriver A peer binding used by the Router transport wrapper.
    pub fn deriver_a_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_a
    }

    /// Returns the Deriver B peer binding used by the Router transport wrapper.
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
    pub fn new(bindings: CloudflareDeriverABindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Deriver A startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::DeriverA { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::DeriverA,
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
    pub fn bindings(&self) -> &CloudflareDeriverABindingsV1 {
        &self.bindings
    }

    /// Returns Deriver B peer binding used by direct A/B coordination.
    pub fn deriver_b_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_b
    }

    /// Returns Deriver A's role-local signer-envelope HPKE decrypt-key descriptors.
    pub fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        &self.bindings.envelope_decrypt_key
    }

    /// Returns Deriver A's role-local A/B peer signing-key descriptor.
    pub fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        &self.bindings.peer_signing_key
    }

    /// Returns the trusted role-local peer verifying keys for readiness receipts.
    #[cfg(feature = "workers-rs")]
    pub(crate) fn peer_verifying_keys(&self) -> &CloudflareSignerPeerVerifyingKeySetV1 {
        &self.bindings.peer_verifying_keys
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
    pub fn signing_worker_output_activate_request(
        &self,
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1RequestV1> {
        let request = CloudflareSigningWorkerPrivateD1RequestV1::OutputActivate {
            activation,
            material,
            activated_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Builds an active SigningWorker-state lookup call.
    pub fn active_signing_worker_state_get_request(
        &self,
        lookup: CloudflareActiveSigningWorkerStateLookupV1,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1RequestV1> {
        let request = CloudflareSigningWorkerPrivateD1RequestV1::ActiveStateGet { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Builds an active SigningWorker material lookup call.
    pub fn signing_worker_output_material_get_request(
        &self,
        lookup: CloudflareSigningWorkerOutputMaterialLookupV1,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1RequestV1> {
        let request = CloudflareSigningWorkerPrivateD1RequestV1::OutputMaterialGet { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Builds a SigningWorker round-1 nonce persistence call.
    pub fn signing_worker_round1_put_request(
        &self,
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1RequestV1> {
        let request = CloudflareSigningWorkerPrivateD1RequestV1::Round1Put { record };
        request.validate()?;
        Ok(request)
    }

    /// Builds a SigningWorker round-1 nonce take call.
    pub fn signing_worker_round1_take_request(
        &self,
        lookup: CloudflareSigningWorkerRound1LookupV1,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1RequestV1> {
        let request = CloudflareSigningWorkerPrivateD1RequestV1::Round1Take { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Builds one atomic SigningWorker ECDSA pool lifecycle mutation call.
    pub fn signing_worker_ecdsa_pool_mutate_request(
        &self,
        command: CloudflareSigningWorkerEcdsaPoolCommandV1,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1RequestV1> {
        let request = CloudflareSigningWorkerPrivateD1RequestV1::EcdsaPoolMutate { command };
        request.validate()?;
        Ok(request)
    }

    /// Returns SigningWorker's server-output HPKE decrypt-key descriptor.
    pub fn server_output_decrypt_key(&self) -> &CloudflareServerOutputHpkeDecryptKeyBindingV1 {
        &self.bindings.server_output_decrypt_key
    }
}

impl CloudflareDeriverBWorkerRuntimeV1 {
    /// Creates a Deriver B runtime context from parsed bindings.
    pub fn new(bindings: CloudflareDeriverBBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Deriver B startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::DeriverB { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::DeriverB,
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
    pub fn bindings(&self) -> &CloudflareDeriverBBindingsV1 {
        &self.bindings
    }

    /// Returns Deriver A peer binding used by direct A/B coordination.
    pub fn deriver_a_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.deriver_a
    }

    /// Returns Deriver B's role-local signer-envelope HPKE decrypt-key descriptors.
    pub fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        &self.bindings.envelope_decrypt_key
    }

    /// Returns Deriver B's role-local A/B peer signing-key descriptor.
    pub fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        &self.bindings.peer_signing_key
    }

    /// Returns the trusted role-local peer verifying keys for readiness receipts.
    #[cfg(feature = "workers-rs")]
    pub(crate) fn peer_verifying_keys(&self) -> &CloudflareSignerPeerVerifyingKeySetV1 {
        &self.bindings.peer_verifying_keys
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

/// Loads the authenticated Deriver's active tenant-root role share.
///
/// The custody binding is resolved by the authenticated request boundary. D1
/// loads the matching active row, while the Worker role chooses the local
/// role; no selector is accepted from the request body.
#[cfg(feature = "workers-rs")]
pub(crate) async fn load_cloudflare_active_tenant_root_role_share_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    authenticated_custody_binding: &TenantRootCustodyBindingV1,
) -> RouterAbProtocolResult<VerifiedTenantRootOnlineRoleShareV1> {
    let expected_role = match worker_role {
        CloudflareWorkerRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        CloudflareWorkerRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "this Worker has no tenant-root role share",
            ));
        }
    };
    authenticated_custody_binding
        .validate()
        .map_err(map_root_share_to_protocol)?;

    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env).map_err(|error| {
        map_cloudflare_tenant_root_role_store_error_v1("tenant-root role store lookup", error)
    })?;
    let stored = store
        .load_active(authenticated_custody_binding)
        .await
        .map_err(|error| {
            map_cloudflare_tenant_root_role_store_error_v1(
                "tenant-root active role-share lookup",
                error,
            )
        })?;
    let sealed = stored.into_online_role_share_artifact().map_err(|error| {
        map_cloudflare_tenant_root_role_store_error_v1(
            "tenant-root online role-share reconstruction",
            error,
        )
    })?;
    if sealed.binding().role() != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "tenant-root active role-share row does not belong to this Deriver",
        ));
    }

    let mut provider =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)?;
    let opened =
        tenant_root_role_runtime::open_tenant_root_online_role_share_v1(sealed, &mut provider)
            .map_err(map_root_share_to_protocol)?;
    if opened.role() != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "tenant-root online role-share provider returned the wrong Deriver role",
        ));
    }
    Ok(opened)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_allowed_admission_checks_v1(
    request_id: impl Into<String>,
) -> RouterAbProtocolResult<CloudflareRouterAdmissionChecksV1> {
    CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Allowed,
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: request_id.into(),
        },
    )
}

/// Derives trusted Router admission from the locally verified request policy.
#[cfg(feature = "workers-rs")]
pub fn derive_cloudflare_router_trusted_admission_from_signed_policy_v1(
    request: &EcdsaThresholdPrfRequestV1,
    metadata: CloudflareRouterTrustedRequestMetadataV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    metadata.validate_for_request(request)?;
    let checks = cloudflare_router_allowed_admission_checks_v1(&request.request_nonce)?;
    derive_cloudflare_router_trusted_admission_v1(request, metadata, checks)
}

/// Derives trusted normal-signing v2 prepare admission from the verified Wallet Session.
#[cfg(feature = "workers-rs")]
pub fn derive_cloudflare_router_normal_signing_prepare_trusted_admission_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    admission: &CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_prepare_request(request)?;
    let checks = cloudflare_router_allowed_admission_checks_v1(&request.scope.request_id)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_v1_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted normal-signing v2 finalize admission from the verified Wallet Session.
#[cfg(feature = "workers-rs")]
pub fn derive_cloudflare_router_normal_signing_finalize_trusted_admission_v2(
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    admission: &CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_finalize_request(request)?;
    let checks = cloudflare_router_allowed_admission_checks_v1(&request.scope.request_id)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_v1_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted Router A/B ECDSA derivation prepare admission from the verified Wallet Session.
#[cfg(feature = "workers-rs")]
pub fn derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_prepare_trusted_admission_v1(
    request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    admission: &CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_prepare_request(request)?;
    let checks = cloudflare_router_allowed_admission_checks_v1(&request.request_id)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_normal_signing_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted Router A/B ECDSA derivation finalize admission from the verified Wallet Session.
#[cfg(feature = "workers-rs")]
pub fn derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_finalize_trusted_admission_v1(
    request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    admission: &CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    admission.validate_for_finalize_request(request)?;
    let checks = cloudflare_router_allowed_admission_checks_v1(&request.request_id)?;
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission.to_normal_signing_trusted_metadata()?,
        checks.to_gate_decision()?,
    )
}

/// Derives trusted Router admission from a locally verified signed request policy.
#[cfg(feature = "workers-rs")]
pub fn derive_cloudflare_router_trusted_admission_from_worker_jwt_v1<Verifier>(
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: &EcdsaThresholdPrfRequestV1,
    request_policy_digest: PublicDigest32,
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
        request_policy_digest,
        verifier,
    )?;
    let metadata = session.verify_public_request_session(request)?;
    derive_cloudflare_router_trusted_admission_from_signed_policy_v1(request, metadata)
}

/// Builds the Ed25519 JWT verifier from the deployment-bound JWKS document.
#[cfg(feature = "workers-rs")]
pub fn build_cloudflare_router_ed25519_jwks_jwt_verifier_v1(
    binding: &CloudflareRouterJwtVerifierBindingV1,
) -> RouterAbProtocolResult<CloudflareRouterEd25519JwksJwtVerifierV1> {
    binding.validate()?;
    Ok(binding.verifier.clone())
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

#[cfg(feature = "workers-rs")]
fn emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1(
    request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
    decision: router_ab_core::RouterAbEcdsaDerivationExplicitExportAuditDecisionV1,
    reason_code: &str,
) -> RouterAbProtocolResult<()> {
    request.validate()?;
    require_non_empty(
        "Router A/B ECDSA derivation export audit reason_code",
        reason_code,
    )?;
    let request_digest = request.request_digest()?;
    let event = AuditEventV1::RouterAbEcdsaDerivationExplicitExportDecision {
        operation: "router_ab_ecdsa_derivation_explicit_key_export".to_owned(),
        request_id: request.export_nonce.clone(),
        request_digest_b64u: encode_base64url_bytes_v1(request_digest.as_bytes()),
        wallet_id: request.lifecycle.account_id.clone(),
        account_id: request.lifecycle.account_id.clone(),
        session_id: request.lifecycle.session_id.clone(),
        selected_server_id: request.lifecycle.selected_server_id.clone(),
        application_binding_digest_b64u: request.context.application_binding_digest_b64u.clone(),
        export_authorization_digest_b64u: request.export_authorization_digest_b64u.clone(),
        decision,
        reason_code: reason_code.to_owned(),
    };
    let serialized = serde_json::to_string(&event).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Router A/B ECDSA derivation export audit event serialization failed: {err}"),
        )
    })?;
    worker::console_log!("router_ab_audit_event_v1={serialized}");
    Ok(())
}

/// Upper bound on metrics folded in from one role worker's `Server-Timing`.
/// Role headers are internal, but a merged header still grows with every hop,
/// so the fold is bounded rather than trusting the peer to stay terse.
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_ROUTER_ECDSA_MERGED_ROLE_METRIC_LIMIT_V1: usize = 12;

/// Refactor 94B Phase 0. Collects Router-side boundary timings for the strict
/// ECDSA registration legs, so a cold registration stays attributable past the
/// Gateway instead of collapsing into one opaque `ecdsa_respond_router` span.
///
/// Diagnostics only. Every entry is a duration, nothing here feeds a protocol
/// decision, and a clock read that fails contributes zero rather than failing
/// the ceremony. Cloudflare freezes `Date.now()` between I/O, so these spans
/// advance only across an actual service-binding or Durable Object call —
/// which is exactly what they are measuring.
#[cfg(feature = "workers-rs")]
#[derive(Default)]
pub struct CloudflareEcdsaBoundaryTimingV1 {
    entries: Vec<(String, u64)>,
    trace_id: Option<CloudflareTraceIdV1>,
}

#[cfg(feature = "workers-rs")]
impl CloudflareEcdsaBoundaryTimingV1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_trace_id(trace_id: Option<CloudflareTraceIdV1>) -> Self {
        Self {
            entries: Vec::new(),
            trace_id,
        }
    }

    fn trace_id(&self) -> Option<CloudflareTraceIdV1> {
        self.trace_id
    }

    pub(crate) fn now_ms() -> u64 {
        cloudflare_now_unix_ms_v1().unwrap_or_default()
    }

    fn mark(&mut self, name: &str, started_at_ms: u64) {
        let elapsed = Self::now_ms().saturating_sub(started_at_ms);
        self.entries.push((name.to_owned(), elapsed));
    }

    fn push(&mut self, name: &str, duration_ms: u64) {
        self.entries.push((name.to_owned(), duration_ms));
    }

    /// Folds one role worker's own `Server-Timing` into this header, renaming
    /// each metric with the role prefix so the role that produced it stays
    /// visible after the merge. Entries without a finite non-negative `dur`
    /// are dropped, which also discards Cloudflare's descriptive metrics.
    fn merge_role(&mut self, role_prefix: &str, header: Option<String>) {
        let Some(header) = header else {
            return;
        };
        let mut merged = 0usize;
        for entry in header.split(',') {
            if merged >= CLOUDFLARE_ROUTER_ECDSA_MERGED_ROLE_METRIC_LIMIT_V1 {
                return;
            }
            let mut parts = entry.split(';');
            let name = parts.next().map(str::trim).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            for part in parts {
                let Some((key, value)) = part.split_once('=') else {
                    continue;
                };
                if key.trim() != "dur" {
                    continue;
                }
                let Ok(duration) = value.trim().parse::<f64>() else {
                    break;
                };
                if !duration.is_finite() || duration < 0.0 {
                    break;
                }
                self.entries
                    .push((format!("{role_prefix}_{name}"), duration as u64));
                merged += 1;
                break;
            }
        }
    }

    /// Attaches these spans to a response, leaving the header off entirely
    /// when nothing was measured rather than emitting an empty one.
    fn apply_to(&self, response: &worker::Response) -> worker::Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        response
            .headers()
            .set("Server-Timing", &self.server_timing())
    }

    fn server_timing(&self) -> String {
        self.entries
            .iter()
            .map(|(name, duration_ms)| format!("{name};dur={duration_ms}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Handles an authenticated public Router Router A/B ECDSA derivation registration/bootstrap request.
// The eighth parameter is the diagnostics-only span collector; folding it into
// a params struct would churn every caller for something that carries no state.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "workers-rs")]
pub(crate) async fn handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    tenant_root_custody_binding: &CloudflareTenantRootCustodyBindingWireV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
    timing: &mut CloudflareEcdsaBoundaryTimingV1,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    let total_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
    request.validate_at(now_unix_ms)?;
    let tenant_root_custody_binding_digest = tenant_root_custody_binding
        .authenticate_for_registration(env, &request, now_unix_ms)?
        .digest()
        .map_err(map_root_share_to_protocol)?;
    let public_request = request.to_threshold_prf_request()?;
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        runtime,
        now_unix_ms,
        &public_request,
        request.request_digest()?,
        authorization,
        trusted_source_digest,
        verifier,
    )?;
    timing.mark("ecdsa_rt_authorize", total_started_at_ms);
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    let result = match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let derivers_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
            let (deriver_a_result, deriver_b_result) = futures::join!(
                async {
                    let started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
                    let result =
                        execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1(
                            env,
                            runtime.deriver_a_peer(),
                            &request,
                            deriver_a_message,
                            tenant_root_custody_binding,
                            timing.trace_id(),
                        )
                        .await;
                    (
                        result,
                        CloudflareEcdsaBoundaryTimingV1::now_ms().saturating_sub(started_at_ms),
                    )
                },
                async {
                    let started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
                    let result =
                        execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1(
                            env,
                            runtime.deriver_b_peer(),
                            &request,
                            deriver_b_message,
                            tenant_root_custody_binding,
                            timing.trace_id(),
                        )
                        .await;
                    (
                        result,
                        CloudflareEcdsaBoundaryTimingV1::now_ms().saturating_sub(started_at_ms),
                    )
                },
            );
            let (deriver_a_result, deriver_a_elapsed_ms) = deriver_a_result;
            let (deriver_b_result, deriver_b_elapsed_ms) = deriver_b_result;
            timing.push("ecdsa_rt_deriver_a", deriver_a_elapsed_ms);
            timing.push("ecdsa_rt_deriver_b", deriver_b_elapsed_ms);
            timing.mark("ecdsa_rt_derivers", derivers_started_at_ms);
            /* Both role headers are folded in before the `?`s below, so a
            failing deriver still reports where its time went. */
            let deriver_a_response = deriver_a_result;
            let deriver_b_response = deriver_b_result;
            timing.merge_role(
                "ecdsa_a",
                deriver_a_response
                    .as_ref()
                    .ok()
                    .and_then(|response| response.1.clone()),
            );
            timing.merge_role(
                "ecdsa_b",
                deriver_b_response
                    .as_ref()
                    .ok()
                    .and_then(|response| response.1.clone()),
            );
            let deriver_a_response = deriver_a_response?.0;
            let deriver_b_response = deriver_b_response?.0;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                deriver_a_response.client_bundle.clone(),
                deriver_b_response.client_bundle.clone(),
            )?;
            response.validate_for_router_payload(&router_payload)?;
            let pending_activation =
                CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1::new(
                    request.clone(),
                    tenant_root_custody_binding_digest,
                    router_payload,
                    CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
                        deriver_a_response.server_bundle,
                        deriver_b_response.server_bundle,
                    )?,
                )?;
            CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1::forwarded(
                response,
                pending_activation,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1::stopped(
            trusted_admission.decision.clone(),
        ),
    }?;
    timing.mark("ecdsa_rt_total", total_started_at_ms);
    Ok(result)
}

/// Completes strict Router A/B ECDSA registration after the client verifies both proof bundles.
// See the registration handler above: the eighth parameter is span collection.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_activation_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    command: CloudflareRouterAbEcdsaDerivationActivationCommandV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
    timing: &mut CloudflareEcdsaBoundaryTimingV1,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    let total_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
    command.validate()?;
    let public_request = command.pending.registration.to_threshold_prf_request()?;
    let mut session = CloudflareRouterJwtSessionProviderV1::new(
        runtime.admission_bindings().jwt.clone(),
        authorization,
        now_unix_ms,
        trusted_source_digest,
        command.pending.registration.request_digest()?,
        verifier,
    )?;
    session.verify_public_request_session(&public_request)?;
    timing.mark("ecdsa_rt_act_session", total_started_at_ms);
    let request = command.into_signing_worker_request()?;
    let worker_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
    let call =
        execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1(
            env,
            runtime.signing_worker_peer(),
            &request,
            timing.trace_id(),
        )
        .await;
    timing.mark("ecdsa_rt_act_worker", worker_started_at_ms);
    timing.merge_role(
        "ecdsa_sw",
        call.as_ref().ok().and_then(|call| call.1.clone()),
    );
    let receipt = call?.0;
    timing.mark("ecdsa_rt_act_total", total_started_at_ms);
    Ok(receipt)
}

/// Parses one strict second-phase ECDSA registration activation request.
#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_ab_ecdsa_derivation_activation_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationActivationCommandV1> {
    let request: CloudflareRouterAbEcdsaDerivationActivationCommandV1 =
        serde_json::from_slice(bytes).map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router A/B ECDSA derivation activation request JSON parse failed: {err}"),
            )
        })?;
    request.validate()?;
    Ok(request)
}

/// Parses one strict ECDSA activation-refresh request.
#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_ab_ecdsa_derivation_activation_refresh_command_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationActivationRefreshCommandV1> {
    let command: CloudflareRouterAbEcdsaDerivationActivationRefreshCommandV1 =
        serde_json::from_slice(bytes).map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router A/B ECDSA activation-refresh command JSON parse failed: {err}"),
            )
        })?;
    command.refresh_request.validate()?;
    command.tenant_root.resolve()?;
    Ok(command)
}

/// Handles an authenticated public Router Router A/B ECDSA derivation explicit export request.
#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_ab_ecdsa_derivation_export_command_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationExportCommandV1> {
    let command: CloudflareRouterAbEcdsaDerivationExportCommandV1 = serde_json::from_slice(bytes)
        .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Router A/B ECDSA export command JSON parse failed: {error}"),
        )
    })?;
    command.request.validate()?;
    command
        .export_authority
        .validate_for_request(&command.request)?;
    command
        .material_source
        .validate_for_ecdsa_scope(&command.export_authority.normal_signing_scope)?;
    command
        .private_authorization
        .validate_for_request(&command.request)?;
    Ok(command)
}

/// Handles an authenticated public Router Router A/B ECDSA derivation explicit export request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    command: CloudflareRouterAbEcdsaDerivationExportCommandV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    command.validate_at(now_unix_ms)?;
    let CloudflareRouterAbEcdsaDerivationExportCommandV1 {
        request,
        export_authority,
        material_source,
        private_authorization,
        tenant_root,
    } = command;
    let (identity_digest, custody_lineage) = tenant_root.resolve()?;
    let active_receipt = execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
        env,
        identity_digest,
        custody_lineage,
    )
    .await?;
    let tenant_root_custody_binding =
        cloudflare_tenant_root_export_binding_wire_v1(&request, &active_receipt)?;
    let public_request = request.to_threshold_prf_request()?;
    let public_request_for_derivers = public_request.clone();
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        runtime,
        now_unix_ms,
        &public_request,
        request.request_digest()?,
        authorization,
        trusted_source_digest,
        verifier,
    )?;
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let signing_worker_request = CloudflareSigningWorkerEcdsaExportShareRequestV1 {
                request: request.clone(),
                export_authority,
                material_source,
                private_authorization,
            };
            execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_export_preflight_service_call_v1(
                env,
                runtime.signing_worker_peer(),
                &signing_worker_request,
            )
            .await?;
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_a_message,
                    &tenant_root_custody_binding,
                ),
                execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_b_message,
                    &tenant_root_custody_binding,
                ),
            );
            let deriver_a_response = match deriver_a_result {
                Ok(response) => response,
                Err(err) => {
                    emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1(
                        &request,
                        router_ab_core::RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Rejected,
                        "deriver_a_export_service_error",
                    )?;
                    return Err(err);
                }
            };
            let deriver_b_response = match deriver_b_result {
                Ok(response) => response,
                Err(err) => {
                    emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1(
                        &request,
                        router_ab_core::RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Rejected,
                        "deriver_b_export_service_error",
                    )?;
                    return Err(err);
                }
            };
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                deriver_a_response.client_bundle,
                deriver_b_response.client_bundle,
            )?;
            response.validate_for_router_payload(&router_payload)?;
            emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1(
                &request,
                router_ab_core::RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Forwarded,
                "forwarded_client_export_bundles",
            )?;
            let signing_worker_export =
                execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_export_share_service_call_v1(
                    env,
                    runtime.signing_worker_peer(),
                    &signing_worker_request,
                )
                .await?;
            CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1::forwarded(
                response,
                signing_worker_export,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => {
            emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1(
                &request,
                router_ab_core::RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Stopped,
                "router_admission_stopped_export",
            )?;
            CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1::stopped(
                trusted_admission.decision.clone(),
            )
        }
    }
}

/// Handles an authenticated public Router Router A/B ECDSA derivation activation-refresh request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    command: CloudflareRouterAbEcdsaDerivationActivationRefreshCommandV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    trusted_source_digest: PublicDigest32,
    verifier: Verifier,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    command.validate_at(now_unix_ms)?;
    let CloudflareRouterAbEcdsaDerivationActivationRefreshCommandV1 {
        refresh_request: request,
        tenant_root,
    } = command;
    let (identity_digest, custody_lineage) = tenant_root.resolve()?;
    let active_receipt = execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
        env,
        identity_digest,
        custody_lineage,
    )
    .await?;
    let tenant_root_custody_binding =
        cloudflare_tenant_root_refresh_binding_wire_v1(&request, &active_receipt)?;
    let tenant_root_custody_binding_digest = tenant_root_custody_binding
        .authenticate_for_refresh(env, &request, now_unix_ms)?
        .digest()
        .map_err(map_root_share_to_protocol)?;
    let public_request = request.to_threshold_prf_request()?;
    let public_request_for_derivers = public_request.clone();
    let trusted_admission = derive_cloudflare_router_trusted_admission_from_worker_jwt_v1(
        runtime,
        now_unix_ms,
        &public_request,
        request.request_digest()?,
        authorization,
        trusted_source_digest,
        verifier,
    )?;
    let plan =
        runtime.public_request_admission_plan_at(now_unix_ms, public_request, trusted_admission)?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } => {
            let (deriver_a_result, deriver_b_result) = futures::join!(
                execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1(
                    env,
                    runtime.deriver_a_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_a_message,
                    &tenant_root_custody_binding,
                ),
                execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1(
                    env,
                    runtime.deriver_b_peer(),
                    &request,
                    &public_request_for_derivers,
                    deriver_b_message,
                    &tenant_root_custody_binding,
                ),
            );
            let deriver_a_response = deriver_a_result?;
            let deriver_b_response = deriver_b_result?;
            let router_payload =
                decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                deriver_a_response.client_bundle.clone(),
                deriver_b_response.client_bundle.clone(),
            )?;
            response.validate_for_router_payload(&router_payload)?;
            let activation =
                CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1::new(
                    request.clone(),
                    router_payload,
                    CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
                        deriver_a_response.server_bundle,
                        deriver_b_response.server_bundle,
                    )?,
                    request.material_activation.clone(),
                    tenant_root_custody_binding_digest,
                )?;
            let signing_worker_activation =
                execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_call_v1(
                    env,
                    runtime.signing_worker_peer(),
                    &activation,
                )
                .await?;
            CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1::forwarded(
                response,
                signing_worker_activation,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1::stopped(
            trusted_admission.decision.clone(),
        ),
    }
}

/// Durable authorized operation attached by the authorization service to Ed25519 finalize.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareRouterEd25519AuthorizedOperationV1 {
    ReusableWalletSessionAuthorizedOperationV1 {
        authorized_operation_id: String,
        operation_id: String,
        capability_kind: CloudflareRouterEd25519CapabilityKindV1,
        operation_kind: CloudflareRouterEd25519OperationKindV1,
        lane_digest_b64u: String,
        intent_digest_b64u: String,
        display_digest_b64u: String,
        operation_fingerprint_digest: String,
    },
    VerifiedStepUpAuthorizedOperationV1 {
        authorization_session_id: String,
        evidence_set_digest: String,
        authorized_operation_id: String,
        operation_id: String,
        capability_kind: CloudflareRouterEd25519CapabilityKindV1,
        operation_kind: CloudflareRouterEd25519OperationKindV1,
        lane_digest_b64u: String,
        intent_digest_b64u: String,
        display_digest_b64u: String,
        operation_fingerprint_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg(feature = "workers-rs")]
pub enum CloudflareRouterEd25519AcceptedCapabilityBindingV1 {
    ReusableWalletSession {
        /// Exact Wallet Session authorization record used for this operation.
        authorization_id: String,
        wallet_session_id: String,
        quota_id: String,
    },
    /// Wallet Session admission resolved by the trusted Gateway.
    GatewayOwnerWalletSession {
        subject_id: String,
        account_id: String,
        authorization_id: String,
        wallet_session_id: String,
        quota_id: String,
        threshold_session_id: String,
        org_id: String,
        project_id: String,
        environment: String,
        signing_worker_id: String,
        expires_at_ms: u64,
    },
    /// Linked-device Wallet Session admission resolved by the trusted Gateway.
    GatewayLinkedDeviceWalletSession {
        subject_id: String,
        account_id: String,
        authorization_id: String,
        wallet_session_id: String,
        quota_id: String,
        org_id: String,
        project_id: String,
        environment: String,
        signing_worker_id: String,
        expires_at_ms: u64,
        material_source: CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    },
    OperationStepUp {
        authorization_session_id: String,
        org_id: String,
        project_id: String,
        environment: String,
        subject_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(feature = "workers-rs")]
pub struct CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
    pub binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1,
    pub authorized_operation: CloudflareRouterEd25519AuthorizedOperationV1,
}

#[cfg(feature = "workers-rs")]
impl CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
    #[cfg(feature = "workers-rs")]
    fn into_signing_worker_authorized_operation_identity(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerAuthorizedOperationIdentityV1> {
        self.validate()?;
        match (&self.binding, &self.authorized_operation) {
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession {
                    authorization_id,
                    wallet_session_id,
                    ..
                },
                CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                authorization_id: authorization_id.clone(),
                wallet_session_id: wallet_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                    authorization_id,
                    wallet_session_id,
                    ..
                },
                CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                authorization_id: authorization_id.clone(),
                wallet_session_id: wallet_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession {
                    authorization_id,
                    wallet_session_id,
                    ..
                },
                CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                authorization_id: authorization_id.clone(),
                wallet_session_id: wallet_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp {
                    authorization_session_id,
                    ..
                },
                CloudflareRouterEd25519AuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
                authorization_session_id: authorization_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "accepted Ed25519 operation identity branch does not match authorized operation",
            )),
        }
    }

    #[cfg(feature = "workers-rs")]
    fn reusable_authorization_id(&self) -> RouterAbProtocolResult<&str> {
        match &self.binding {
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession {
                authorization_id,
                ..
            }
            | CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                authorization_id,
                ..
            }
            | CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession {
                authorization_id,
                ..
            } => Ok(authorization_id),
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp { .. } => {
                Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Ed25519 operation step-up has no reusable authorization id",
                ))
            }
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.authorized_operation.validate()?;
        match (&self.binding, &self.authorized_operation) {
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession {
                    authorization_id,
                    wallet_session_id,
                    quota_id,
                },
                CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    ..
                },
            ) => {
                require_non_empty("accepted Ed25519 authorization_id", authorization_id)?;
                require_non_empty("accepted Ed25519 wallet_session_id", wallet_session_id)?;
                require_non_empty("accepted Ed25519 quota_id", quota_id)?;
                if authorization_id == wallet_session_id
                    || authorization_id == quota_id
                    || wallet_session_id == quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted Ed25519 authorization, Wallet Session, and quota ids must be pairwise distinct",
                    ));
                }
                Ok(())
            }
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                    subject_id,
                    account_id,
                    authorization_id,
                    wallet_session_id,
                    quota_id,
                    threshold_session_id,
                    org_id,
                    project_id,
                    environment,
                    signing_worker_id,
                    expires_at_ms,
                },
                CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    ..
                },
            ) => {
                require_non_empty("accepted Ed25519 Gateway subject_id", subject_id)?;
                require_non_empty("accepted Ed25519 Gateway account_id", account_id)?;
                require_non_empty("accepted Ed25519 Gateway authorization_id", authorization_id)?;
                require_non_empty("accepted Ed25519 Gateway wallet_session_id", wallet_session_id)?;
                require_non_empty("accepted Ed25519 Gateway quota_id", quota_id)?;
                require_non_empty(
                    "accepted Ed25519 Gateway threshold_session_id",
                    threshold_session_id,
                )?;
                require_non_empty("accepted Ed25519 Gateway org_id", org_id)?;
                require_non_empty("accepted Ed25519 Gateway project_id", project_id)?;
                require_non_empty("accepted Ed25519 Gateway environment", environment)?;
                require_non_empty("accepted Ed25519 Gateway signing_worker_id", signing_worker_id)?;
                require_positive_ms("accepted Ed25519 Gateway expires_at_ms", *expires_at_ms)?;
                if authorization_id == wallet_session_id
                    || authorization_id == quota_id
                    || wallet_session_id == quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted Ed25519 Gateway authorization ids must be pairwise distinct",
                    ));
                }
                Ok(())
            }
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession {
                    subject_id,
                    account_id,
                    authorization_id,
                    wallet_session_id,
                    quota_id,
                    org_id,
                    project_id,
                    environment,
                    signing_worker_id,
                    expires_at_ms,
                    material_source,
                },
                CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    ..
                },
            ) => {
                require_non_empty("accepted Ed25519 linked-device subject_id", subject_id)?;
                require_non_empty("accepted Ed25519 linked-device account_id", account_id)?;
                require_non_empty("accepted Ed25519 linked-device authorization_id", authorization_id)?;
                require_non_empty("accepted Ed25519 linked-device wallet_session_id", wallet_session_id)?;
                require_non_empty("accepted Ed25519 linked-device quota_id", quota_id)?;
                require_non_empty("accepted Ed25519 linked-device org_id", org_id)?;
                require_non_empty("accepted Ed25519 linked-device project_id", project_id)?;
                require_non_empty("accepted Ed25519 linked-device environment", environment)?;
                require_non_empty("accepted Ed25519 linked-device signing_worker_id", signing_worker_id)?;
                require_positive_ms("accepted Ed25519 linked-device expires_at_ms", *expires_at_ms)?;
                if !matches!(
                    material_source,
                    CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane { .. }
                ) {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted Ed25519 linked-device material source must be a rotatable lane",
                    ));
                }
                if authorization_id == wallet_session_id
                    || authorization_id == quota_id
                    || wallet_session_id == quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted Ed25519 linked-device authorization ids must be pairwise distinct",
                    ));
                }
                Ok(())
            }
            (
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp {
                    authorization_session_id,
                    org_id,
                    project_id,
                    environment,
                    subject_id,
                },
                CloudflareRouterEd25519AuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                    authorization_session_id: authorized_operation_session,
                    ..
                },
            ) if authorization_session_id == authorized_operation_session => {
                require_non_empty(
                    "accepted Ed25519 authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty("accepted Ed25519 org_id", org_id)?;
                require_non_empty("accepted Ed25519 project_id", project_id)?;
                require_non_empty("accepted Ed25519 environment", environment)?;
                require_non_empty("accepted Ed25519 subject_id", subject_id)
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "accepted Ed25519 capability binding does not match authorized operation",
            )),
        }
    }

    #[cfg(feature = "workers-rs")]
    fn validate_for_wallet_session(
        &self,
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        match &self.binding {
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession {
                authorization_id,
                wallet_session_id,
                quota_id,
            } => {
                if wallet_session.authorization_id != *authorization_id
                    || wallet_session.wallet_session_id != *wallet_session_id
                    || wallet_session.quota_id != *quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted Ed25519 capability binding does not match Wallet Session",
                    ));
                }
            }
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                authorization_id,
                wallet_session_id,
                quota_id,
                ..
            } => {
                if wallet_session.authorization_id != *authorization_id
                    || wallet_session.wallet_session_id != *wallet_session_id
                    || wallet_session.quota_id != *quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted Ed25519 Gateway binding does not match Wallet Session",
                    ));
                }
            }
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession {
                ..
            } => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "accepted Ed25519 linked-device binding requires trusted Gateway admission",
                ));
            }
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp { .. } => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "accepted Ed25519 step-up session cannot use a Wallet Session credential",
                ));
            }
        }
        Ok(())
    }

    #[cfg(feature = "workers-rs")]
    #[cfg_attr(not(feature = "strict-worker-router-entrypoint"), allow(dead_code))]
    fn gateway_owner_wallet_session_credential(
        &self,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterWalletSessionCredentialV1> {
        self.validate()?;
        let CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
            subject_id,
            account_id,
            authorization_id,
            wallet_session_id,
            quota_id,
            threshold_session_id,
            org_id,
            project_id,
            environment,
            signing_worker_id,
            expires_at_ms,
        } = &self.binding
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Ed25519 Gateway owner Wallet Session admission is required",
            ));
        };
        let wallet_session = CloudflareRouterVerifiedWalletSessionV1::new(
            subject_id.clone(),
            account_id.clone(),
            authorization_id.clone(),
            wallet_session_id.clone(),
            quota_id.clone(),
            threshold_session_id.clone(),
            org_id.clone(),
            project_id.clone(),
            environment.clone(),
            "near-ed25519",
            signing_worker_id.clone(),
            trusted_source_digest,
            *expires_at_ms,
        )?;
        CloudflareRouterWalletSessionCredentialV1::gateway_owner(wallet_session)
    }
}

/// Capability domain admitted by the Ed25519 reusable-session route.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudflareRouterEd25519CapabilityKindV1 {
    #[serde(rename = "near_ed25519_mpc_signing")]
    NearEd25519MpcSigning,
}

/// Supported NEAR operation admitted by the Ed25519 reusable-session route.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudflareRouterEd25519OperationKindV1 {
    #[serde(rename = "near.sign_transaction")]
    SignTransaction,
    #[serde(rename = "near.sign_delegate_action")]
    SignDelegateAction,
    #[serde(rename = "near.sign_nep413_message")]
    SignNep413Message,
}

#[cfg(feature = "workers-rs")]
impl CloudflareRouterEd25519AuthorizedOperationV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let (
            authorization_session_id,
            evidence_set_digest,
            authorized_operation_id,
            operation_id,
            lane_digest_b64u,
            intent_digest_b64u,
            display_digest_b64u,
            operation_fingerprint_digest,
        ) = match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
                ..
            } => (
                None,
                None,
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
            ),
            Self::VerifiedStepUpAuthorizedOperationV1 {
                authorization_session_id,
                evidence_set_digest,
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
                ..
            } => (
                Some(authorization_session_id),
                Some(evidence_set_digest),
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
            ),
        };
        if let Some(value) = authorization_session_id {
            require_non_empty("authorized_operation.authorization_session_id", value)?;
        }
        if let Some(value) = evidence_set_digest {
            decode_public_digest_b64u_v1("authorized_operation.evidence_set_digest", value)?;
        }
        require_non_empty(
            "authorized_operation.authorized_operation_id",
            authorized_operation_id,
        )?;
        require_non_empty("authorized_operation.operation_id", operation_id)?;
        decode_public_digest_b64u_v1("authorized_operation.lane_digest_b64u", lane_digest_b64u)?;
        decode_public_digest_b64u_v1(
            "authorized_operation.intent_digest_b64u",
            intent_digest_b64u,
        )?;
        decode_public_digest_b64u_v1(
            "authorized_operation.display_digest_b64u",
            display_digest_b64u,
        )?;
        decode_public_digest_b64u_v1(
            "authorized_operation.operation_fingerprint_digest",
            operation_fingerprint_digest,
        )?;
        Ok(())
    }

    pub fn validate_for_prepare_request(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let material = request.admission_material()?;
        let intent_digest_b64u = encode_base64url_bytes_v1(material.intent_digest.as_bytes());
        let display_digest_b64u = encode_base64url_bytes_v1(request.display_digest.as_bytes());
        let (authorized_operation_intent, authorized_operation_display) = match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                intent_digest_b64u,
                display_digest_b64u,
                ..
            }
            | Self::VerifiedStepUpAuthorizedOperationV1 {
                intent_digest_b64u,
                display_digest_b64u,
                ..
            } => (intent_digest_b64u, display_digest_b64u),
        };
        if authorized_operation_intent != &intent_digest_b64u
            || authorized_operation_display != &display_digest_b64u
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Ed25519 authorized operation does not match prepare digests",
            ));
        }
        Ok(())
    }

    pub fn validate_for_finalize_request(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        authorization: &CloudflareRouterNormalSigningAuthorizationV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        authorization.validate()?;
        let intent_digest_b64u = match (self, authorization) {
            (
                Self::ReusableWalletSessionAuthorizedOperationV1 {
                    intent_digest_b64u, ..
                },
                CloudflareRouterNormalSigningAuthorizationV2::ReusableWalletSession { .. },
            ) => intent_digest_b64u,
            (
                Self::VerifiedStepUpAuthorizedOperationV1 {
                    authorization_session_id,
                    intent_digest_b64u,
                    ..
                },
                CloudflareRouterNormalSigningAuthorizationV2::OperationStepUp {
                    authorization_session_id: admitted_session_id,
                    ..
                },
            ) if authorization_session_id == admitted_session_id => intent_digest_b64u,
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Ed25519 authorized operation does not match Router admission",
                ));
            }
        };
        let intent_digest = decode_public_digest_b64u_v1(
            "authorized_operation.intent_digest_b64u",
            intent_digest_b64u,
        )?;
        if intent_digest != request.intent_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Ed25519 authorized operation intent does not match finalize request",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "workers-rs")]
    fn into_signing_worker_effect_claim(
        self,
        wallet_session_id: String,
        authorization_id: String,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningEffectClaimV1> {
        self.validate()?;
        match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
                ..
            } => Ok(
                CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession {
                    claim: CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
                        authorization_id,
                        wallet_session_id,
                        authorized_operation_id,
                        operation_id,
                        operation_fingerprint_digest,
                    )?,
                },
            ),
            Self::VerifiedStepUpAuthorizedOperationV1 {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
                ..
            } => Ok(
                CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
                    authorization_session_id,
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                },
            ),
        }
    }

    #[cfg(feature = "workers-rs")]
    fn into_step_up_signing_worker_effect_claim(
        self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningEffectClaimV1> {
        self.validate()?;
        match self {
            Self::VerifiedStepUpAuthorizedOperationV1 {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
                ..
            } => Ok(CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
            }),
            Self::ReusableWalletSessionAuthorizedOperationV1 { .. } => Err(
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Ed25519 reusable Wallet Session authorized operation cannot use the operation step-up admission path",
                ),
            ),
        }
    }
}

/// Gateway authorized operation attached to Router A/B ECDSA finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareRouterEcdsaAuthorizedOperationV1 {
    ReusableWalletSessionAuthorizedOperationV1 {
        authorized_operation_id: String,
        operation_id: String,
        capability_kind: CloudflareRouterEcdsaCapabilityKindV1,
        operation_kind: CloudflareRouterEcdsaOperationKindV1,
        lane_digest_b64u: String,
        intent_digest_b64u: String,
        display_digest_b64u: String,
        operation_fingerprint_digest: String,
    },
    VerifiedStepUpAuthorizedOperationV1 {
        authorization_session_id: String,
        evidence_set_digest: String,
        authorized_operation_id: String,
        operation_id: String,
        capability_kind: CloudflareRouterEcdsaCapabilityKindV1,
        operation_kind: CloudflareRouterEcdsaOperationKindV1,
        lane_digest_b64u: String,
        intent_digest_b64u: String,
        display_digest_b64u: String,
        operation_fingerprint_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareRouterEcdsaAcceptedCapabilityBindingV1 {
    ReusableWalletSession {
        /// Exact Wallet Session authorization record used for this operation.
        authorization_id: String,
        wallet_session_id: String,
        quota_id: String,
    },
    /// Wallet Session admission resolved by the trusted Gateway.
    GatewayOwnerWalletSession {
        subject_id: String,
        account_id: String,
        authorization_id: String,
        wallet_session_id: String,
        quota_id: String,
        threshold_session_id: String,
        org_id: String,
        project_id: String,
        environment: String,
        signing_worker_id: String,
        expires_at_ms: u64,
    },
    OperationStepUp {
        authorization_session_id: String,
        org_id: String,
        project_id: String,
        environment: String,
        subject_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
    pub binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1,
    pub authorized_operation: CloudflareRouterEcdsaAuthorizedOperationV1,
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
impl CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
    fn validate_for_linked_device_ecdsa_finalize_request(
        &self,
        request: &router_ab_core::RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let (
            authorized_operation_id,
            operation_id,
            authorized_operation_intent,
            authorized_operation_lane,
            authorized_operation_display,
        ) = match &self.authorized_operation {
            CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id,
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
                ..
            }
            | CloudflareRouterEcdsaAuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                authorized_operation_id,
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
                ..
            } => (
                authorized_operation_id,
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
            ),
        };
        if authorized_operation_id
            != &format!("linked-ecdsa-authorized-operation:{}", request.request_id)
            || operation_id != &request.operation_id
            || authorized_operation_intent != &request.operation_digests.intent_digest_b64u
            || authorized_operation_lane != &request.operation_digests.lane_digest_b64u
            || authorized_operation_display != &request.operation_digests.display_digest_b64u
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA authorized operation does not match linked finalize digests",
            ));
        }
        let NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } =
            &request.authorization
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "linked ECDSA finalize requires reusable Wallet Session authorization",
            ));
        };
        match &self.binding {
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
                wallet_session_id: admitted_wallet_session_id,
                ..
            } if admitted_wallet_session_id == wallet_session_id => Ok(()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "linked ECDSA capability binding does not match Wallet Session authorization",
            )),
        }
    }

    fn into_signing_worker_authorized_operation_identity(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerAuthorizedOperationIdentityV1> {
        self.validate()?;
        match (&self.binding, &self.authorized_operation) {
            (
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
                    authorization_id,
                    wallet_session_id,
                    ..
                },
                CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                authorization_id: authorization_id.clone(),
                wallet_session_id: wallet_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            (
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                    authorization_id,
                    wallet_session_id,
                    ..
                },
                CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                authorization_id: authorization_id.clone(),
                wallet_session_id: wallet_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            (
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp {
                    authorization_session_id,
                    ..
                },
                CloudflareRouterEcdsaAuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
            ) => Ok(CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
                authorization_session_id: authorization_session_id.clone(),
                authorized_operation_id: authorized_operation_id.clone(),
                operation_id: operation_id.clone(),
                operation_fingerprint_digest: operation_fingerprint_digest.clone(),
            }),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "accepted ECDSA operation identity branch does not match authorized operation",
            )),
        }
    }

    fn reusable_authorization_id(&self) -> RouterAbProtocolResult<&str> {
        match &self.binding {
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
                authorization_id,
                ..
            }
            | CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                authorization_id,
                ..
            } => Ok(authorization_id),
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp { .. } => {
                Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "ECDSA operation step-up has no reusable authorization id",
                ))
            }
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.authorized_operation.validate()?;
        match (&self.binding, &self.authorized_operation) {
            (
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
                    authorization_id,
                    wallet_session_id,
                    quota_id,
                },
                CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    ..
                },
            ) => {
                require_non_empty("accepted ECDSA authorization_id", authorization_id)?;
                require_non_empty("accepted ECDSA wallet_session_id", wallet_session_id)?;
                require_non_empty("accepted ECDSA quota_id", quota_id)?;
                if authorization_id == wallet_session_id
                    || authorization_id == quota_id
                    || wallet_session_id == quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted ECDSA authorization, Wallet Session, and quota ids must be pairwise distinct",
                    ));
                }
                Ok(())
            }
            (
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                    subject_id,
                    account_id,
                    authorization_id,
                    wallet_session_id,
                    quota_id,
                    threshold_session_id,
                    org_id,
                    project_id,
                    environment,
                    signing_worker_id,
                    expires_at_ms,
                },
                CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                    ..
                },
            ) => {
                require_non_empty("accepted ECDSA Gateway subject_id", subject_id)?;
                require_non_empty("accepted ECDSA Gateway account_id", account_id)?;
                require_non_empty("accepted ECDSA Gateway authorization_id", authorization_id)?;
                require_non_empty("accepted ECDSA Gateway wallet_session_id", wallet_session_id)?;
                require_non_empty("accepted ECDSA Gateway quota_id", quota_id)?;
                require_non_empty(
                    "accepted ECDSA Gateway threshold_session_id",
                    threshold_session_id,
                )?;
                require_non_empty("accepted ECDSA Gateway org_id", org_id)?;
                require_non_empty("accepted ECDSA Gateway project_id", project_id)?;
                require_non_empty("accepted ECDSA Gateway environment", environment)?;
                require_non_empty("accepted ECDSA Gateway signing_worker_id", signing_worker_id)?;
                require_positive_ms("accepted ECDSA Gateway expires_at_ms", *expires_at_ms)?;
                if authorization_id == wallet_session_id
                    || authorization_id == quota_id
                    || wallet_session_id == quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted ECDSA Gateway authorization ids must be pairwise distinct",
                    ));
                }
                Ok(())
            }
            (
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp {
                    authorization_session_id,
                    org_id,
                    project_id,
                    environment,
                    subject_id,
                },
                CloudflareRouterEcdsaAuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                    authorization_session_id: authorized_operation_session,
                    ..
                },
            ) if authorization_session_id == authorized_operation_session => {
                require_non_empty(
                    "accepted ECDSA authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty("accepted ECDSA org_id", org_id)?;
                require_non_empty("accepted ECDSA project_id", project_id)?;
                require_non_empty("accepted ECDSA environment", environment)?;
                require_non_empty("accepted ECDSA subject_id", subject_id)
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "accepted ECDSA capability binding does not match authorized operation",
            )),
        }
    }

    fn validate_for_wallet_session(
        &self,
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        match &self.binding {
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
                authorization_id,
                wallet_session_id,
                quota_id,
                ..
            } => {
                if wallet_session.authorization_id != *authorization_id
                    || wallet_session.wallet_session_id != *wallet_session_id
                    || wallet_session.quota_id != *quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted ECDSA capability binding does not match Wallet Session",
                    ));
                }
            }
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                authorization_id,
                wallet_session_id,
                quota_id,
                ..
            } => {
                if wallet_session.authorization_id != *authorization_id
                    || wallet_session.wallet_session_id != *wallet_session_id
                    || wallet_session.quota_id != *quota_id
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted ECDSA Gateway binding does not match Wallet Session",
                    ));
                }
            }
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp { .. } => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "accepted ECDSA step-up session cannot use a Wallet Session credential",
                ));
            }
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "strict-worker-router-entrypoint"), allow(dead_code))]
    fn gateway_owner_wallet_session_credential(
        &self,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterWalletSessionCredentialV1> {
        self.validate()?;
        let CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
            subject_id,
            account_id,
            authorization_id,
            wallet_session_id,
            quota_id,
            threshold_session_id,
            org_id,
            project_id,
            environment,
            signing_worker_id,
            expires_at_ms,
        } = &self.binding
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA Gateway owner Wallet Session admission is required",
            ));
        };
        let wallet_session = CloudflareRouterVerifiedWalletSessionV1::new(
            subject_id.clone(),
            account_id.clone(),
            authorization_id.clone(),
            wallet_session_id.clone(),
            quota_id.clone(),
            threshold_session_id.clone(),
            org_id.clone(),
            project_id.clone(),
            environment.clone(),
            "evm-family",
            signing_worker_id.clone(),
            trusted_source_digest,
            *expires_at_ms,
        )?;
        CloudflareRouterWalletSessionCredentialV1::gateway_owner(wallet_session)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudflareRouterEcdsaCapabilityKindV1 {
    #[serde(rename = "evm_ecdsa_mpc_signing")]
    EvmEcdsaMpcSigning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudflareRouterEcdsaOperationKindV1 {
    #[serde(rename = "evm.sign_transaction")]
    SignTransaction,
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
impl CloudflareRouterEcdsaAuthorizedOperationV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let (
            authorization_session_id,
            evidence_set_digest,
            authorized_operation_id,
            operation_id,
            lane_digest_b64u,
            intent_digest_b64u,
            display_digest_b64u,
            operation_fingerprint_digest,
            capability_kind,
            operation_kind,
        ) = match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
                capability_kind,
                operation_kind,
            } => (
                None,
                None,
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
                capability_kind,
                operation_kind,
            ),
            Self::VerifiedStepUpAuthorizedOperationV1 {
                authorization_session_id,
                evidence_set_digest,
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
                capability_kind,
                operation_kind,
            } => (
                Some(authorization_session_id),
                Some(evidence_set_digest),
                authorized_operation_id,
                operation_id,
                lane_digest_b64u,
                intent_digest_b64u,
                display_digest_b64u,
                operation_fingerprint_digest,
                capability_kind,
                operation_kind,
            ),
        };
        if let Some(value) = authorization_session_id {
            require_non_empty("ECDSA authorized_operation.authorization_session_id", value)?;
        }
        if let Some(value) = evidence_set_digest {
            decode_public_digest_b64u_v1("ECDSA authorized_operation.evidence_set_digest", value)?;
        }
        require_non_empty(
            "ECDSA authorized_operation.authorized_operation_id",
            authorized_operation_id,
        )?;
        require_non_empty("ECDSA authorized_operation.operation_id", operation_id)?;
        decode_public_digest_b64u_v1(
            "ECDSA authorized_operation.lane_digest_b64u",
            lane_digest_b64u,
        )?;
        decode_public_digest_b64u_v1(
            "ECDSA authorized_operation.intent_digest_b64u",
            intent_digest_b64u,
        )?;
        decode_public_digest_b64u_v1(
            "ECDSA authorized_operation.display_digest_b64u",
            display_digest_b64u,
        )?;
        decode_public_digest_b64u_v1(
            "ECDSA authorized_operation.operation_fingerprint_digest",
            operation_fingerprint_digest,
        )?;
        if *capability_kind != CloudflareRouterEcdsaCapabilityKindV1::EvmEcdsaMpcSigning
            || *operation_kind != CloudflareRouterEcdsaOperationKindV1::SignTransaction
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA authorized operation capability or operation kind is invalid",
            ));
        }
        Ok(())
    }

    pub fn validate_for_prepare_request(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let (
            authorized_operation_id,
            authorized_operation_intent,
            authorized_operation_lane,
            authorized_operation_display,
        ) = match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
                ..
            }
            | Self::VerifiedStepUpAuthorizedOperationV1 {
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
                ..
            } => (
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
            ),
        };
        if authorized_operation_id != &request.operation_id
            || authorized_operation_intent != &request.operation_digests.intent_digest_b64u
            || authorized_operation_lane != &request.operation_digests.lane_digest_b64u
            || authorized_operation_display != &request.operation_digests.display_digest_b64u
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA authorized operation does not match prepare digests",
            ));
        }
        match (&request.authorization, self) {
            (
                NormalSigningAuthorizationV1::ReusableWalletSession { .. },
                Self::ReusableWalletSessionAuthorizedOperationV1 { .. },
            ) => Ok(()),
            (
                NormalSigningAuthorizationV1::OperationStepUp,
                Self::VerifiedStepUpAuthorizedOperationV1 { .. },
            ) => Ok(()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA authorized operation branch does not match prepare authorization",
            )),
        }
    }

    pub fn validate_for_finalize_request(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_for_finalize_request_with_session(request, None)
    }

    pub fn validate_for_finalize_request_with_session(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        expected_authorization_session_id: Option<&str>,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let (
            authorized_operation_id,
            authorized_operation_intent,
            authorized_operation_lane,
            authorized_operation_display,
        ) = match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
                ..
            }
            | Self::VerifiedStepUpAuthorizedOperationV1 {
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
                ..
            } => (
                operation_id,
                intent_digest_b64u,
                lane_digest_b64u,
                display_digest_b64u,
            ),
        };
        if authorized_operation_id != &request.operation_id
            || authorized_operation_intent != &request.operation_digests.intent_digest_b64u
            || authorized_operation_lane != &request.operation_digests.lane_digest_b64u
            || authorized_operation_display != &request.operation_digests.display_digest_b64u
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA authorized operation does not match finalize digests",
            ));
        }
        match (&request.authorization, self) {
            (
                NormalSigningAuthorizationV1::ReusableWalletSession { .. },
                Self::ReusableWalletSessionAuthorizedOperationV1 { .. },
            ) => Ok(()),
            (
                NormalSigningAuthorizationV1::OperationStepUp,
                Self::VerifiedStepUpAuthorizedOperationV1 {
                    authorization_session_id,
                    ..
                },
            ) => {
                if let Some(expected) = expected_authorization_session_id {
                    if authorization_session_id != expected {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidGateDecision,
                            "ECDSA authorized operation session does not match Wallet Session",
                        ));
                    }
                }
                Ok(())
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA authorized operation branch does not match finalize authorization",
            )),
        }
    }

    pub fn authorized_operation_id(&self) -> &str {
        match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id,
                ..
            }
            | Self::VerifiedStepUpAuthorizedOperationV1 {
                authorized_operation_id,
                ..
            } => authorized_operation_id,
        }
    }

    fn into_signing_worker_effect_claim(
        self,
        wallet_session_id: String,
        authorization_id: String,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningEffectClaimV1> {
        self.validate()?;
        match self {
            Self::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
                ..
            } => Ok(
                CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession {
                    claim: CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
                        authorization_id,
                        wallet_session_id,
                        authorized_operation_id,
                        operation_id,
                        operation_fingerprint_digest,
                    )?,
                },
            ),
            Self::VerifiedStepUpAuthorizedOperationV1 {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
                ..
            } => Ok(
                CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
                    authorization_session_id,
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                },
            ),
        }
    }

    fn into_step_up_signing_worker_effect_claim(
        self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningEffectClaimV1> {
        self.validate()?;
        match self {
            Self::VerifiedStepUpAuthorizedOperationV1 {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
                ..
            } => Ok(CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
            }),
            Self::ReusableWalletSessionAuthorizedOperationV1 { .. } => Err(
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "ECDSA reusable Wallet Session authorized operation cannot use the operation step-up admission path",
                ),
            ),
        }
    }
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_prepare_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
)> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Router A/B ECDSA derivation prepare request JSON parse failed: {err}"),
        )
    })?;
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation prepare request must be a JSON object",
            ));
        }
    };
    let authorized_operation_value = object.remove("authorized_operation").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "authorized_operation is required",
        )
    })?;
    let authorized_operation = serde_json::from_value::<
        CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    >(authorized_operation_value)
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("ECDSA authorized operation JSON parse failed: {err}"),
        )
    })?;
    authorized_operation.validate()?;
    let request = serde_json::from_value::<RouterAbEcdsaDerivationEvmDigestSigningRequestV1>(
        serde_json::Value::Object(object),
    )
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Router A/B ECDSA derivation prepare request JSON parse failed: {err}"),
        )
    })?;
    request.validate()?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(&request)?;
    Ok((request, authorized_operation))
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_authorized_ed25519_prepare_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEd25519NormalSigningPrepareRequestV2,
    CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
)> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 prepare request JSON parse failed: {err}"),
        )
    })?;
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Ed25519 prepare request must be a JSON object",
            ));
        }
    };
    let authorized_operation_value = object.remove("authorized_operation").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "authorized_operation is required",
        )
    })?;
    let authorized_operation = serde_json::from_value::<
        CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    >(authorized_operation_value)
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 authorized operation JSON parse failed: {err}"),
        )
    })?;
    authorized_operation.validate()?;
    let request = serde_json::from_value::<RouterAbEd25519NormalSigningPrepareRequestV2>(
        serde_json::Value::Object(object),
    )
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 prepare request JSON parse failed: {err}"),
        )
    })?;
    request.validate()?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(&request)?;
    Ok((request, authorized_operation))
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEd25519NormalSigningFinalizeRequestV2,
    CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
)> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 finalize request JSON parse failed: {err}"),
        )
    })?;
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Ed25519 finalize request must be a JSON object",
            ));
        }
    };
    let authorized_operation_value = object.remove("authorized_operation").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "authorized_operation is required",
        )
    })?;
    let authorized_operation = serde_json::from_value::<
        CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    >(authorized_operation_value)
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 authorized operation JSON parse failed: {err}"),
        )
    })?;
    authorized_operation.validate()?;
    let request = serde_json::from_value::<RouterAbEd25519NormalSigningFinalizeRequestV2>(
        serde_json::Value::Object(object),
    )
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 finalize request JSON parse failed: {err}"),
        )
    })?;
    request.validate()?;
    let authorization = match (
        &authorized_operation.binding,
        &authorized_operation.authorized_operation,
    ) {
        (
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession {
                authorization_id,
                wallet_session_id,
                ..
            }
            | CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession {
                authorization_id,
                wallet_session_id,
                ..
            }
            | CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession {
                authorization_id,
                wallet_session_id,
                ..
            },
            CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                ..
            },
        ) => CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
            authorization_id.clone(),
            wallet_session_id.clone(),
        )?,
        (
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp {
                authorization_session_id,
                ..
            },
            CloudflareRouterEd25519AuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                evidence_set_digest,
                ..
            },
        ) => CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
            authorization_session_id.clone(),
            evidence_set_digest.clone(),
        )?,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "accepted Ed25519 capability binding does not match authorized operation",
            ));
        }
    };
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request(&request, &authorization)?;
    Ok((request, authorized_operation))
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
)> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Router A/B ECDSA derivation finalize request JSON parse failed: {err}"),
        )
    })?;
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation finalize request must be a JSON object",
            ));
        }
    };
    let authorized_operation_value = object.remove("authorized_operation").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "authorized_operation is required",
        )
    })?;
    let authorized_operation = serde_json::from_value::<
        CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    >(authorized_operation_value)
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("ECDSA authorized operation JSON parse failed: {err}"),
        )
    })?;
    authorized_operation.validate()?;
    let request =
        serde_json::from_value::<RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1>(
            serde_json::Value::Object(object),
        )
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router A/B ECDSA derivation finalize request JSON parse failed: {err}"),
            )
        })?;
    request.validate()?;
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request_with_session(&request, None)?;
    Ok((request, authorized_operation))
}

pub fn parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareSigningWorkerAdmittedLinkedDeviceEcdsaFinalizeRequestV1> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("linked ECDSA finalize request JSON parse failed: {err}"),
        )
    })?;
    let mut object = match value {
        serde_json::Value::Object(object) => object,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "linked ECDSA finalize request must be a JSON object",
            ));
        }
    };
    let authorized_operation = serde_json::from_value::<
        CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    >(object.remove("authorized_operation").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "linked ECDSA authorized_operation is required",
        )
    })?)
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("linked ECDSA authorized operation JSON parse failed: {err}"),
        )
    })?;
    let material_source = serde_json::from_value::<
        CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    >(object.remove("material_source").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "linked ECDSA material_source is required",
        )
    })?)
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("linked ECDSA material source JSON parse failed: {err}"),
        )
    })?;
    let request = serde_json::from_value::<
        router_ab_core::RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1,
    >(serde_json::Value::Object(object))
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("linked ECDSA finalize request JSON parse failed: {err}"),
        )
    })?;
    CloudflareSigningWorkerAdmittedLinkedDeviceEcdsaFinalizeRequestV1::new(
        request,
        authorized_operation,
        material_source,
    )
}

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

/// Handles an authenticated public Router normal-signing v2 prepare request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningPrepareRequestV2,
    authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<NormalSigningRound1PrepareResponseV1>
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
    authorized_operation.validate_for_wallet_session(&wallet_session)?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(&request)?;
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        now_unix_ms,
    )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.scope.request_id,
        derive_cloudflare_router_normal_signing_prepare_trusted_admission_v2(&request, &admission)?,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 prepare Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2::new(
        request.scope.clone(),
        request.expires_at_ms,
        admission,
        trusted_admission,
    )?;
    execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

#[cfg(feature = "workers-rs")]
struct CloudflareRouterEd25519LinkedDeviceBindingV1<'a> {
    subject_id: &'a str,
    account_id: &'a str,
    authorization_id: &'a str,
    wallet_session_id: &'a str,
    org_id: &'a str,
    project_id: &'a str,
    environment: &'a str,
    signing_worker_id: &'a str,
    expires_at_ms: u64,
    material_source: &'a CloudflareSigningWorkerNormalSigningMaterialSourceV1,
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_linked_device_binding_v1(
    authorized_operation: &CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
) -> RouterAbProtocolResult<CloudflareRouterEd25519LinkedDeviceBindingV1<'_>> {
    authorized_operation.validate()?;
    match (
        &authorized_operation.binding,
        &authorized_operation.authorized_operation,
    ) {
        (
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession {
                subject_id,
                account_id,
                authorization_id,
                wallet_session_id,
                org_id,
                project_id,
                environment,
                signing_worker_id,
                expires_at_ms,
                material_source,
                ..
            },
            CloudflareRouterEd25519AuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                ..
            },
        ) => Ok(CloudflareRouterEd25519LinkedDeviceBindingV1 {
            subject_id,
            account_id,
            authorization_id,
            wallet_session_id,
            org_id,
            project_id,
            environment,
            signing_worker_id,
            expires_at_ms: *expires_at_ms,
            material_source,
        }),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Ed25519 linked-device admission requires a Gateway linked-device Wallet Session binding",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn validate_cloudflare_router_ed25519_linked_device_request_v1(
    account_id: &str,
    signing_worker_id: &str,
    binding_expires_at_ms: u64,
    request_account_id: &str,
    request_signing_worker_id: &str,
    request_expires_at_ms: u64,
) -> RouterAbProtocolResult<()> {
    if request_account_id != account_id || request_signing_worker_id != signing_worker_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Ed25519 linked-device Gateway admission identity does not match the request",
        ));
    }
    if request_expires_at_ms > binding_expires_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Ed25519 linked-device request outlives its Wallet Session",
        ));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_linked_device_prepare_admission_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    authorized_operation: &CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<(
    CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
)> {
    let binding = cloudflare_router_ed25519_linked_device_binding_v1(authorized_operation)?;
    validate_cloudflare_router_ed25519_linked_device_request_v1(
        binding.account_id,
        binding.signing_worker_id,
        binding.expires_at_ms,
        &request.scope.account_id,
        &request.scope.signing_worker_id,
        request.expires_at_ms,
    )?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(request)?;
    let material = request.admission_material()?;
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::new(
        binding.org_id.to_owned(),
        binding.project_id.to_owned(),
        binding.environment.to_owned(),
        binding.account_id.to_owned(),
        binding.subject_id.to_owned(),
        CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
            binding.authorization_id.to_owned(),
            binding.wallet_session_id.to_owned(),
        )?,
        binding.signing_worker_id.to_owned(),
        request.scope.request_id.clone(),
        material.intent_digest,
        material.signing_payload_digest,
        material.admitted_signing_digest,
        Some(request.round1_binding_digest()?),
        trusted_source_digest,
        request.expires_at_ms,
    )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_prepare_trusted_admission_v2(request, &admission)?;
    Ok((admission, trusted_admission))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_linked_device_finalize_admission_v2(
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    authorized_operation: &CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<(
    CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
)> {
    let binding = cloudflare_router_ed25519_linked_device_binding_v1(authorized_operation)?;
    validate_cloudflare_router_ed25519_linked_device_request_v1(
        binding.account_id,
        binding.signing_worker_id,
        binding.expires_at_ms,
        &request.scope.account_id,
        &request.scope.signing_worker_id,
        request.expires_at_ms,
    )?;
    let authorization = CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
        binding.authorization_id.to_owned(),
        binding.wallet_session_id.to_owned(),
    )?;
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request(request, &authorization)?;
    let admission = CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::new(
        binding.org_id.to_owned(),
        binding.project_id.to_owned(),
        binding.environment.to_owned(),
        binding.account_id.to_owned(),
        binding.subject_id.to_owned(),
        authorization,
        binding.signing_worker_id.to_owned(),
        request.scope.request_id.clone(),
        request.intent_digest(),
        request.signing_payload_digest(),
        request.round1_binding_digest(),
        trusted_source_digest,
        request.expires_at_ms,
    )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_finalize_trusted_admission_v2(request, &admission)?;
    Ok((admission, trusted_admission))
}

#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_prepare_internal_linked_device_request_v2(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningPrepareRequestV2,
    authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<NormalSigningRound1PrepareResponseV1> {
    request.validate_at(now_unix_ms)?;
    let material_source =
        cloudflare_router_ed25519_linked_device_binding_v1(&authorized_operation)?
            .material_source
            .clone();
    let (admission, trusted_admission) =
        cloudflare_router_ed25519_linked_device_prepare_admission_v2(
            &request,
            &authorized_operation,
            trusted_source_digest,
        )?;
    material_source.validate_for_normal_scope(&request.scope)?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.scope.request_id,
        trusted_admission,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "linked-device normal-signing prepare admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted =
        CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2::new_with_material_source(
            request.scope.clone(),
            request.expires_at_ms,
            admission,
            trusted_admission,
            material_source,
        )?;
    execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_finalize_internal_linked_device_request_v2(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<NormalSigningResponseV1> {
    request.validate_at(now_unix_ms)?;
    let binding = cloudflare_router_ed25519_linked_device_binding_v1(&authorized_operation)?;
    let authorization_id = binding.authorization_id.to_owned();
    let wallet_session_id = binding.wallet_session_id.to_owned();
    let material_source = binding.material_source.clone();
    let (admission, trusted_admission) =
        cloudflare_router_ed25519_linked_device_finalize_admission_v2(
            &request,
            &authorized_operation,
            trusted_source_digest,
        )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.scope.request_id,
        trusted_admission,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "linked-device normal-signing finalize admission did not allow SigningWorker forwarding",
        ));
    }
    let authorized_operation_identity =
        authorized_operation.into_signing_worker_authorized_operation_identity()?;
    let effect_claim = authorized_operation
        .authorized_operation
        .into_signing_worker_effect_claim(wallet_session_id, authorization_id)?;
    material_source.validate_for_normal_scope(&request.scope)?;
    let admitted =
        CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new_with_material_source(
            request,
            admission,
            trusted_admission,
            authorized_operation_identity,
            effect_claim,
            material_source,
        )?;
    execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_step_up_binding_v1(
    authorized_operation: &CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
) -> RouterAbProtocolResult<(&str, &str, &str, &str, &str, &str)> {
    authorized_operation.validate()?;
    match (
        &authorized_operation.binding,
        &authorized_operation.authorized_operation,
    ) {
        (
            CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp {
                authorization_session_id,
                org_id,
                project_id,
                environment,
                subject_id,
            },
            CloudflareRouterEd25519AuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                evidence_set_digest,
                ..
            },
        ) => Ok((
            authorization_session_id,
            evidence_set_digest,
            org_id,
            project_id,
            environment,
            subject_id,
        )),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Ed25519 reusable Wallet Session authorized operation cannot use the operation step-up admission path",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_step_up_prepare_admission_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    authorized_operation: &CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<(
    CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
)> {
    let (
        authorization_session_id,
        evidence_set_digest,
        org_id,
        project_id,
        environment,
        subject_id,
    ) = cloudflare_router_ed25519_step_up_binding_v1(authorized_operation)?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(request)?;
    let material = request.admission_material()?;
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::new(
        org_id.to_owned(),
        project_id.to_owned(),
        environment.to_owned(),
        request.scope.account_id.clone(),
        subject_id.to_owned(),
        CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
            authorization_session_id.to_owned(),
            evidence_set_digest.to_owned(),
        )?,
        request.scope.signing_worker_id.clone(),
        request.scope.request_id.clone(),
        material.intent_digest,
        material.signing_payload_digest,
        material.admitted_signing_digest,
        Some(request.round1_binding_digest()?),
        trusted_source_digest,
        request.expires_at_ms,
    )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_prepare_trusted_admission_v2(request, &admission)?;
    Ok((admission, trusted_admission))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ed25519_step_up_finalize_admission_v2(
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    authorized_operation: &CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<(
    CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
)> {
    let (
        authorization_session_id,
        evidence_set_digest,
        org_id,
        project_id,
        environment,
        subject_id,
    ) = cloudflare_router_ed25519_step_up_binding_v1(authorized_operation)?;
    let authorization = CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
        authorization_session_id.to_owned(),
        evidence_set_digest.to_owned(),
    )?;
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request(request, &authorization)?;
    let admission = CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::new(
        org_id.to_owned(),
        project_id.to_owned(),
        environment.to_owned(),
        request.scope.account_id.clone(),
        subject_id.to_owned(),
        authorization,
        request.scope.signing_worker_id.clone(),
        request.scope.request_id.clone(),
        request.intent_digest(),
        request.signing_payload_digest(),
        request.round1_binding_digest(),
        trusted_source_digest,
        request.expires_at_ms,
    )?;
    let trusted_admission =
        derive_cloudflare_router_normal_signing_finalize_trusted_admission_v2(request, &admission)?;
    Ok((admission, trusted_admission))
}

#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_prepare_internal_step_up_request_v2(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningPrepareRequestV2,
    authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<NormalSigningRound1PrepareResponseV1> {
    request.validate_at(now_unix_ms)?;
    let (admission, trusted_admission) = cloudflare_router_ed25519_step_up_prepare_admission_v2(
        &request,
        &authorized_operation,
        trusted_source_digest,
    )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.scope.request_id,
        trusted_admission,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 prepare Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2::new(
        request.scope.clone(),
        request.expires_at_ms,
        admission,
        trusted_admission,
    )?;
    execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_normal_signing_finalize_internal_step_up_request_v2(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<NormalSigningResponseV1> {
    request.validate_at(now_unix_ms)?;
    let (admission, trusted_admission) = cloudflare_router_ed25519_step_up_finalize_admission_v2(
        &request,
        &authorized_operation,
        trusted_source_digest,
    )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.scope.request_id,
        trusted_admission,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    let authorized_operation_identity =
        authorized_operation.into_signing_worker_authorized_operation_identity()?;
    let effect_claim = authorized_operation
        .authorized_operation
        .into_step_up_signing_worker_effect_claim()?;
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request,
        admission,
        trusted_admission,
        authorized_operation_identity,
        effect_claim,
    )?;
    execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ab_ecdsa_step_up_binding_v1(
    authorized_operation: &CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
) -> RouterAbProtocolResult<(&str, &str, &str, &str, &str, &str)> {
    authorized_operation.validate()?;
    match (
        &authorized_operation.binding,
        &authorized_operation.authorized_operation,
    ) {
        (
            CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp {
                authorization_session_id,
                org_id,
                project_id,
                environment,
                subject_id,
            },
            CloudflareRouterEcdsaAuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 {
                evidence_set_digest,
                ..
            },
        ) => Ok((
            authorization_session_id,
            evidence_set_digest,
            org_id,
            project_id,
            environment,
            subject_id,
        )),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "ECDSA reusable Wallet Session authorized operation cannot use the operation step-up admission path",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ab_ecdsa_step_up_prepare_admission_v1(
    request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    authorized_operation: &CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    let (
        authorization_session_id,
        evidence_set_digest,
        org_id,
        project_id,
        environment,
        subject_id,
    ) = cloudflare_router_ab_ecdsa_step_up_binding_v1(authorized_operation)?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(request)?;
    let admission = CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1::new(
        org_id.to_owned(),
        project_id.to_owned(),
        environment.to_owned(),
        request.scope.wallet_id.clone(),
        subject_id.to_owned(),
        CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
            authorization_session_id.to_owned(),
            evidence_set_digest.to_owned(),
        )?,
        request.scope.signing_worker.server_id.clone(),
        request.request_id.clone(),
        request.client_presignature_id.clone(),
        request.scope.scope_digest()?,
        request.request_digest()?,
        request.signing_digest()?,
        trusted_source_digest,
        request.expires_at_ms,
    )?;
    derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_prepare_trusted_admission_v1(
        request, &admission,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_ab_ecdsa_step_up_finalize_admission_v1(
    request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    authorized_operation: &CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedAdmissionV1> {
    let (
        authorization_session_id,
        evidence_set_digest,
        org_id,
        project_id,
        environment,
        subject_id,
    ) = cloudflare_router_ab_ecdsa_step_up_binding_v1(authorized_operation)?;
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request_with_session(request, Some(authorization_session_id))?;
    let admission = CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1::new(
        org_id.to_owned(),
        project_id.to_owned(),
        environment.to_owned(),
        request.scope.wallet_id.clone(),
        subject_id.to_owned(),
        CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
            authorization_session_id.to_owned(),
            evidence_set_digest.to_owned(),
        )?,
        request.scope.signing_worker.server_id.clone(),
        request.request_id.clone(),
        request.scope.scope_digest()?,
        request.prepare_request_digest()?,
        request.request_digest()?,
        request.signing_digest()?,
        request.server_presignature_id.clone(),
        trusted_source_digest,
        request.expires_at_ms,
    )?;
    derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_finalize_trusted_admission_v1(
        request, &admission,
    )
}

#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_internal_step_up_request_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1> {
    request.validate_at(now_unix_ms)?;
    let trusted_admission = cloudflare_router_ab_ecdsa_step_up_prepare_admission_v1(
        &request,
        &authorized_operation,
        trusted_source_digest,
    )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.request_id,
        trusted_admission,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Router A/B ECDSA derivation prepare Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            request,
            trusted_admission,
        )?;
    execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_internal_step_up_request_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    trusted_source_digest: PublicDigest32,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1> {
    request.validate_at(now_unix_ms)?;
    let trusted_admission = cloudflare_router_ab_ecdsa_step_up_finalize_admission_v1(
        &request,
        &authorized_operation,
        trusted_source_digest,
    )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.request_id,
        trusted_admission,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Router A/B ECDSA derivation finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    let authorized_operation_identity =
        authorized_operation.into_signing_worker_authorized_operation_identity()?;
    let effect_claim = authorized_operation
        .authorized_operation
        .into_step_up_signing_worker_effect_claim()?;
    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request,
            trusted_admission,
            authorized_operation_identity,
            effect_claim,
        )?;
    execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

/// Handles an authenticated public Router Router A/B ECDSA derivation prepare request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1>
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
    wallet_session.validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1(
        &request,
        now_unix_ms,
    )?;
    authorized_operation.validate_for_wallet_session(&wallet_session)?;
    authorized_operation
        .authorized_operation
        .validate_for_prepare_request(&request)?;
    let admission =
        CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1::from_prepare_request(
            &wallet_session,
            &request,
            now_unix_ms,
        )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.request_id,
        derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_prepare_trusted_admission_v1(
            &request, &admission,
        )?,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Router A/B ECDSA derivation prepare Router admission did not allow SigningWorker forwarding",
        ));
    }
    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            request,
            trusted_admission,
        )?;
    execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

/// Handles an authenticated public Router Router A/B ECDSA derivation finalize request.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1<
    Verifier,
>(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1>
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
    wallet_session.validate_for_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
        &request,
        now_unix_ms,
    )?;
    authorized_operation.validate_for_wallet_session(&wallet_session)?;
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request_with_session(&request, None)?;
    let admission =
        CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1::from_finalize_request(
            &wallet_session,
            &request,
            now_unix_ms,
        )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.request_id,
        derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_finalize_trusted_admission_v1(
            &request, &admission,
        )?,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Router A/B ECDSA derivation finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    let authorized_operation_identity =
        authorized_operation.into_signing_worker_authorized_operation_identity()?;
    let authorization_id = authorized_operation.reusable_authorization_id()?.to_owned();
    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request,
            trusted_admission,
            authorized_operation_identity,
            authorized_operation
                .authorized_operation
                .into_signing_worker_effect_claim(
                    wallet_session.wallet_session_id.clone(),
                    authorization_id,
                )?,
        )?;
    execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
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
    authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    credential: CloudflareRouterWalletSessionCredentialV1,
    trusted_source_digest: PublicDigest32,
    mut verifier: Verifier,
) -> RouterAbProtocolResult<NormalSigningResponseV1>
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
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            now_unix_ms,
        )?;
    let trusted_admission = runtime.apply_project_policy_to_normal_signing_admission_v1(
        &request.scope.request_id,
        derive_cloudflare_router_normal_signing_finalize_trusted_admission_v2(
            &request, &admission,
        )?,
    )?;
    if !trusted_admission.allows_signing_worker_forwarding()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "normal-signing v2 finalize Router admission did not allow SigningWorker forwarding",
        ));
    }
    authorized_operation.validate_for_wallet_session(&wallet_session)?;
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request(&request, &admission.authorization)?;
    let authorized_operation_identity =
        authorized_operation.into_signing_worker_authorized_operation_identity()?;
    let authorization_id = authorized_operation.reusable_authorization_id()?.to_owned();
    let effect_claim = authorized_operation
        .authorized_operation
        .into_signing_worker_effect_claim(
            wallet_session.wallet_session_id.clone(),
            authorization_id,
        )?;
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request,
        admission,
        trusted_admission,
        authorized_operation_identity,
        effect_claim,
    )?;
    execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2(
        env,
        runtime.signing_worker_peer(),
        admitted,
    )
    .await
}

/// Activates server-output material through SigningWorker-private D1.
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
    let call = runtime.signing_worker_output_activate_request(
        activation.clone(),
        material?,
        activated_at_ms,
    )?;
    let response = execute_cloudflare_signing_worker_private_d1_request_v1(env, &call).await?;
    require_signing_worker_output_activate_response_v1(&call, response)
}

/// Activates Router A/B ECDSA derivation SigningWorker material through SigningWorker-private D1.
#[cfg(feature = "workers-rs")]
pub async fn activate_cloudflare_router_ab_ecdsa_derivation_signing_worker_output_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    activation: CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1> {
    activation.validate()?;
    let selected_server = activation
        .pending
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
    let material = cloudflare_server_output_material_record_from_ecdsa_activation_request_v2(
        &activation,
        &private_key_bytes,
    );
    private_key_bytes.zeroize();
    let material = material?;
    let call = runtime.signing_worker_output_activate_request(
        generic_activation,
        material.clone(),
        activated_at_ms,
    )?;
    let response = execute_cloudflare_signing_worker_private_d1_request_v1(env, &call).await?;
    let signing_worker_output =
        require_signing_worker_output_activate_response_v1(&call, response)?;
    let ecdsa_receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        signing_worker_output
            .active_signing_worker_state
            .activated_at_ms,
    )?;
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1::new(
        ecdsa_receipt,
        signing_worker_output,
    )
}

/// Refreshes Router A/B ECDSA derivation SigningWorker material through SigningWorker-private D1.
#[cfg(feature = "workers-rs")]
pub async fn refresh_cloudflare_router_ab_ecdsa_derivation_signing_worker_output_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    activation: CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1> {
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
    let material = cloudflare_server_output_material_record_from_ecdsa_refresh_request_v2(
        &activation,
        &private_key_bytes,
    );
    private_key_bytes.zeroize();
    let material = material?;
    let call = runtime.signing_worker_output_activate_request(
        generic_activation,
        material.clone(),
        activated_at_ms,
    )?;
    let response = execute_cloudflare_signing_worker_private_d1_request_v1(env, &call).await?;
    let signing_worker_output =
        require_signing_worker_output_activate_response_v1(&call, response)?;
    let ecdsa_receipt =
        cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1(
            &activation,
            &material,
            signing_worker_output
                .active_signing_worker_state
                .activated_at_ms,
        )?;
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1::new(
        ecdsa_receipt,
        signing_worker_output,
    )
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
        (CloudflareWorkerRoleV1::DeriverA, RouterToSignerPayloadV1::SignerA { .. })
        | (CloudflareWorkerRoleV1::DeriverB, RouterToSignerPayloadV1::SignerB { .. }) => Ok(()),
        (CloudflareWorkerRoleV1::DeriverA | CloudflareWorkerRoleV1::DeriverB, _) => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "private signer request payload branch does not match Worker role",
            ))
        }
        (
            CloudflareWorkerRoleV1::Router
            | CloudflareWorkerRoleV1::SigningWorker
            | CloudflareWorkerRoleV1::TenantRootControlPlane,
            _,
        ) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker has no private signer payload branch",
        )),
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

/// Parses the exact Gateway-to-Router registration envelope.
///
/// The browser request remains the nested `registration_request`; tenant-root
/// coordinates are supplied by the authenticated server boundary and are
/// converted to typed identifiers before any Router admission work starts.
#[cfg(feature = "workers-rs")]
pub(crate) fn parse_cloudflare_router_ab_ecdsa_derivation_registration_gateway_request_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<(
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    TenantRootIdentityDigestV1,
    TenantRootCustodyLineageId,
)> {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GatewayRequest {
        registration_request: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        tenant_root: CloudflareTenantRootCoordinatesV1,
    }

    let parsed = serde_json::from_slice::<GatewayRequest>(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "Router A/B ECDSA derivation registration Gateway envelope parse failed: {err}"
            ),
        )
    })?;
    parsed.registration_request.validate()?;
    let (identity_digest, custody_lineage) = parsed.tenant_root.resolve()?;
    Ok((
        parsed.registration_request,
        identity_digest,
        custody_lineage,
    ))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_tenant_root_deriver_identities_v1(
    env: &worker::Env,
) -> RouterAbProtocolResult<TenantRootDeriverIdentitiesV1> {
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    parse_cloudflare_tenant_root_creation_role_verifying_keys_v1(&reader)?.deriver_identities()
}

#[cfg(feature = "workers-rs")]
fn derive_cloudflare_tenant_root_registration_scope_v1(
    registration_request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
) -> RouterAbProtocolResult<(
    TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1,
    TenantRootDerivationNonceV1,
)> {
    let request_digest = registration_request.request_digest()?;
    derive_cloudflare_tenant_root_ecdsa_scope_v1(
        request_digest,
        b"seams/router-ab-ecdsa-registration/operation/v1",
        b"seams/router-ab-ecdsa-registration/session/v1",
        b"seams/router-ab-ecdsa-registration/nonce/v1",
    )
}

#[cfg(feature = "workers-rs")]
fn derive_cloudflare_tenant_root_ecdsa_scope_v1(
    request_digest: PublicDigest32,
    operation_domain: &[u8],
    session_domain: &[u8],
    nonce_domain: &[u8],
) -> RouterAbProtocolResult<(
    TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1,
    TenantRootDerivationNonceV1,
)> {
    let derive = |domain: &[u8]| {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(request_digest.as_bytes());
        let mut bytes: [u8; 32] = hasher.finalize().into();
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[0] = 1;
        }
        bytes
    };
    let operation_bytes = derive(operation_domain);
    let operation_id = TenantRootDerivationOperationIdV1::from_bytes(
        operation_bytes[..16]
            .try_into()
            .expect("fixed operation id length"),
    )
    .map_err(map_root_share_to_protocol)?;
    let session_bytes = derive(session_domain);
    let session_id = TenantRootDerivationSessionIdV1::from_bytes(
        session_bytes[..16]
            .try_into()
            .expect("fixed session id length"),
    )
    .map_err(map_root_share_to_protocol)?;
    let nonce = TenantRootDerivationNonceV1::from_bytes(derive(nonce_domain))
        .map_err(map_root_share_to_protocol)?;
    Ok((operation_id, session_id, nonce))
}

#[cfg(feature = "workers-rs")]
fn derive_cloudflare_tenant_root_export_scope_v1(
    export_request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
) -> RouterAbProtocolResult<(
    TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1,
    TenantRootDerivationNonceV1,
)> {
    derive_cloudflare_tenant_root_ecdsa_scope_v1(
        export_request.request_digest()?,
        b"seams/router-ab-ecdsa-export/operation/v1",
        b"seams/router-ab-ecdsa-export/session/v1",
        b"seams/router-ab-ecdsa-export/nonce/v1",
    )
}

#[cfg(feature = "workers-rs")]
fn derive_cloudflare_tenant_root_refresh_scope_v1(
    refresh_request: &RouterAbEcdsaDerivationActivationRefreshRequestV1,
) -> RouterAbProtocolResult<(
    TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1,
    TenantRootDerivationNonceV1,
)> {
    derive_cloudflare_tenant_root_ecdsa_scope_v1(
        refresh_request.request_digest()?,
        b"seams/router-ab-ecdsa-refresh/operation/v1",
        b"seams/router-ab-ecdsa-refresh/session/v1",
        b"seams/router-ab-ecdsa-refresh/nonce/v1",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_tenant_root_registration_binding_wire_v1(
    registration_request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    registration_purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCustodyBindingWireV1> {
    registration_request.validate_for_registration_purpose(registration_purpose)?;
    let (operation_id, session_id, nonce) =
        derive_cloudflare_tenant_root_registration_scope_v1(registration_request)?;
    let expires_at_ms = registration_request.expires_at_ms;
    let issued_at_ms = expires_at_ms
        .saturating_sub(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .max(1);
    CloudflareTenantRootCustodyBindingWireV1::from_verified_activation_receipt(
        activation_receipt,
        operation_id,
        session_id,
        nonce,
        issued_at_ms,
        expires_at_ms,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_tenant_root_export_binding_wire_v1(
    export_request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCustodyBindingWireV1> {
    export_request.validate()?;
    let (operation_id, session_id, nonce) =
        derive_cloudflare_tenant_root_export_scope_v1(export_request)?;
    let issued_at_ms = export_request
        .expires_at_ms
        .saturating_sub(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .max(1);
    CloudflareTenantRootCustodyBindingWireV1::from_verified_activation_receipt(
        activation_receipt,
        operation_id,
        session_id,
        nonce,
        issued_at_ms,
        export_request.expires_at_ms,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_tenant_root_refresh_binding_wire_v1(
    refresh_request: &RouterAbEcdsaDerivationActivationRefreshRequestV1,
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCustodyBindingWireV1> {
    refresh_request.validate()?;
    let (operation_id, session_id, nonce) =
        derive_cloudflare_tenant_root_refresh_scope_v1(refresh_request)?;
    let issued_at_ms = refresh_request
        .expires_at_ms
        .saturating_sub(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .max(1);
    CloudflareTenantRootCustodyBindingWireV1::from_verified_activation_receipt(
        activation_receipt,
        operation_id,
        session_id,
        nonce,
        issued_at_ms,
        refresh_request.expires_at_ms,
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_tenant_root_ed25519_yao_binding_v2(
    env: &worker::Env,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<(
    CloudflareTenantRootCustodyBindingWireV1,
    Ed25519YaoOuterBindingV2,
)> {
    pair_binding.validate()?;
    let pair_digest = pair_binding.pair_digest();
    let operation_bytes = derive_ed25519_yao_tenant_root_scope_bytes_v2(
        b"seams/ed25519-yao/tenant-root-operation/v2",
        pair_digest.as_bytes(),
    );
    let session_bytes = derive_ed25519_yao_tenant_root_scope_bytes_v2(
        b"seams/ed25519-yao/tenant-root-session/v2",
        pair_digest.as_bytes(),
    );
    let nonce_bytes = derive_ed25519_yao_tenant_root_scope_bytes_v2(
        b"seams/ed25519-yao/tenant-root-nonce/v2",
        pair_digest.as_bytes(),
    );
    let mut operation_id_bytes = [0_u8; 16];
    operation_id_bytes.copy_from_slice(&operation_bytes[..16]);
    let operation_id = TenantRootDerivationOperationIdV1::from_bytes(operation_id_bytes)
        .map_err(map_root_share_to_protocol)?;
    let mut session_id_bytes = [0_u8; 16];
    session_id_bytes.copy_from_slice(&session_bytes[..16]);
    let session_id = TenantRootDerivationSessionIdV1::from_bytes(session_id_bytes)
        .map_err(map_root_share_to_protocol)?;
    let nonce =
        TenantRootDerivationNonceV1::from_bytes(nonce_bytes).map_err(map_root_share_to_protocol)?;
    let wire = CloudflareTenantRootCustodyBindingWireV1::from_verified_activation_receipt(
        activation_receipt,
        operation_id,
        session_id,
        nonce,
        issued_at_ms,
        expires_at_ms,
    )?;
    let custody_binding =
        TenantRootCustodyBindingV1::from_verified_activation_receipt_with_stable_context_digest(
            activation_receipt,
            cloudflare_tenant_root_deriver_identities_v1(env)?,
            operation_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            TenantRootProtocolDigestV1::from_bytes(
                pair_binding
                    .binding()
                    .stable_key_context_binding
                    .into_bytes(),
            )
            .map_err(map_root_share_to_protocol)?,
            TenantRootProtocolDigestV1::from_bytes(*pair_digest.as_bytes())
                .map_err(map_root_share_to_protocol)?,
        )
        .map_err(map_root_share_to_protocol)?;
    let custody_digest = custody_binding
        .digest()
        .map_err(map_root_share_to_protocol)?;
    let outer_nonce_digest = derive_ed25519_yao_tenant_root_scope_bytes_v2(
        b"seams/ed25519-yao/outer-nonce/v2",
        custody_digest.as_bytes(),
    );
    let mut outer_nonce = [0_u8; 16];
    outer_nonce.copy_from_slice(&outer_nonce_digest[..16]);
    let outer_binding = Ed25519YaoOuterBindingV2::new(
        Ed25519YaoPairSessionIdV2::new(pair_binding.session())?,
        pair_binding.binding().stable_key_context_binding,
        PublicDigest32::new(*custody_digest.as_bytes()),
        outer_nonce,
        issued_at_ms,
        expires_at_ms,
    )?;
    Ok((wire, outer_binding))
}

#[cfg(feature = "workers-rs")]
fn derive_ed25519_yao_tenant_root_scope_bytes_v2(domain: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(transcript);
    hasher.finalize().into()
}

/// Typed server-only bootstrap after custody-binding comparison.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareAuthenticatedSignerPrivateBootstrapRequestV1 {
    /// Existing validated signer bootstrap body.
    pub bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    /// Authenticated tenant-root custody binding selected by the server boundary.
    pub tenant_root_custody_binding: TenantRootCustodyBindingV1,
}

#[cfg(feature = "workers-rs")]
impl CloudflareAuthenticatedSignerPrivateBootstrapRequestV1 {
    /// Creates a typed bootstrap from an already validated server binding.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
        tenant_root_custody_binding: TenantRootCustodyBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        bootstrap.validate_for_worker_role(worker_role)?;
        tenant_root_custody_binding
            .validate()
            .map_err(map_root_share_to_protocol)?;
        Ok(Self {
            bootstrap,
            tenant_root_custody_binding,
        })
    }

    /// Returns the authenticated binding for the active tenant-root lookup.
    pub const fn tenant_root_custody_binding(&self) -> &TenantRootCustodyBindingV1 {
        &self.tenant_root_custody_binding
    }
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

/// Exact public tenant-root proof and Router-generated operation scope carried
/// over the private Router-to-Deriver registration hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootCustodyBindingWireV1 {
    /// Canonical issuer-signed active-activation receipt bytes.
    pub activation_receipt_b64u: String,
    /// Router-generated derivation operation identifier.
    pub operation_id: TenantRootDerivationOperationIdV1,
    /// Router-generated one-use session identifier.
    pub session_id: TenantRootDerivationSessionIdV1,
    /// Router-generated replay nonce.
    pub nonce: TenantRootDerivationNonceV1,
    /// Router issue time for this private binding.
    pub issued_at_ms: u64,
    /// Router expiry time for this private binding.
    pub expires_at_ms: u64,
}

impl CloudflareTenantRootCustodyBindingWireV1 {
    /// Builds the exact wire from the Router's issuer-verified active receipt.
    pub fn from_verified_activation_receipt(
        activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
        operation_id: TenantRootDerivationOperationIdV1,
        session_id: TenantRootDerivationSessionIdV1,
        nonce: TenantRootDerivationNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let wire = Self {
            activation_receipt_b64u: encode_base64url_bytes_v1(
                activation_receipt.canonical_bytes(),
            ),
            operation_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
        };
        wire.validate()?;
        Ok(wire)
    }

    /// Validates exact receipt encoding and the Router-issued time window.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.validate_transport()?;
        let receipt_bytes = self.activation_receipt_bytes()?;
        TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes).map_err(
            |error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("tenant-root activation receipt wire is invalid: {error}"),
                )
            },
        )?;
        Ok(())
    }

    fn validate_transport(&self) -> RouterAbProtocolResult<()> {
        self.activation_receipt_bytes()?;
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "tenant-root private binding expiry must follow a non-zero issue time",
            ));
        }
        if self.expires_at_ms - self.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "tenant-root private binding lifetime exceeds the frozen maximum window",
            ));
        }
        Ok(())
    }

    /// Returns the canonical activation receipt bytes after validating the wire.
    pub fn activation_receipt_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let bytes = decode_base64url_bytes_v1(
            "tenant-root activation receipt",
            &self.activation_receipt_b64u,
        )?;
        if bytes.len() > TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "tenant-root activation receipt exceeds the accepted wire size",
            ));
        }
        if encode_base64url_bytes_v1(&bytes) != self.activation_receipt_b64u {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "tenant-root activation receipt is not canonical base64url",
            ));
        }
        Ok(bytes)
    }

    #[cfg(feature = "workers-rs")]
    fn verify_activation_receipt(
        &self,
        trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    ) -> RouterAbProtocolResult<VerifiedTenantRootSignedActivationReceiptV1> {
        let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(
            &self.activation_receipt_bytes()?,
        )
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("tenant-root activation receipt wire is invalid: {error}"),
            )
        })?;
        let issuer_key = trusted_issuer_keys
            .for_issuer_key_id(receipt.issuer_key_id())
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    "tenant-root activation receipt issuer is not trusted by this Deriver",
                )
            })?;
        receipt
            .verify_issuer_signature(issuer_key)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    format!(
                        "tenant-root activation receipt signature verification failed: {error}"
                    ),
                )
            })
    }

    #[cfg(feature = "workers-rs")]
    fn authenticate_for_registration(
        &self,
        env: &worker::Env,
        registration_request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<TenantRootCustodyBindingV1> {
        registration_request.validate_at(now_unix_ms)?;
        self.authenticate_for_stable_request(
            env,
            &registration_request.to_threshold_prf_request()?,
            now_unix_ms,
        )
    }

    #[cfg(feature = "workers-rs")]
    fn authenticate_for_export(
        &self,
        env: &worker::Env,
        export_request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<TenantRootCustodyBindingV1> {
        export_request.validate_at(now_unix_ms)?;
        self.authenticate_for_stable_request(
            env,
            &export_request.to_threshold_prf_request()?,
            now_unix_ms,
        )
    }

    #[cfg(feature = "workers-rs")]
    fn authenticate_for_refresh(
        &self,
        env: &worker::Env,
        refresh_request: &RouterAbEcdsaDerivationActivationRefreshRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<TenantRootCustodyBindingV1> {
        refresh_request.validate_at(now_unix_ms)?;
        self.authenticate_for_stable_request(
            env,
            &refresh_request.to_threshold_prf_request()?,
            now_unix_ms,
        )
    }

    #[cfg(feature = "workers-rs")]
    fn authenticate_for_ed25519_yao(
        &self,
        env: &worker::Env,
        pair_binding: &router_ab_core::Ed25519YaoInputPairBindingV1,
        application: &router_ab_core::RouterAbEd25519YaoApplicationBindingFactsV1,
        participant_ids: [u16; 2],
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<TenantRootCustodyBindingV1> {
        self.validate()?;
        pair_binding.validate()?;
        let stable_context =
            router_ab_ed25519_yao::stable_key_derivation_context_v1(application, participant_ids)
                .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("Ed25519 Yao stable context is invalid: {error}"),
                )
            })?;
        if stable_context.binding_digest()
            != pair_binding
                .binding()
                .stable_key_context_binding
                .into_bytes()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Ed25519 Yao stable context does not match the admitted pair",
            ));
        }
        let reader = CloudflareWorkerEnvReaderV1::new(env);
        let issuer_keys =
            parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
        let activation_receipt = self.verify_activation_receipt(&issuer_keys)?;
        let stable_context_digest =
            TenantRootProtocolDigestV1::from_bytes(stable_context.binding_digest())
                .map_err(map_root_share_to_protocol)?;
        let outer_transcript_digest =
            TenantRootProtocolDigestV1::from_bytes(pair_binding.pair_digest().bytes)
                .map_err(map_root_share_to_protocol)?;
        let binding =
            TenantRootCustodyBindingV1::from_verified_activation_receipt_with_stable_context_digest(
                &activation_receipt,
                cloudflare_tenant_root_deriver_identities_v1(env)?,
                self.operation_id,
                self.session_id,
                self.nonce,
                self.issued_at_ms,
                self.expires_at_ms,
                stable_context_digest,
                outer_transcript_digest,
            )
            .map_err(map_root_share_to_protocol)?;
        binding
            .validate_at(now_unix_ms)
            .map_err(map_root_share_to_protocol)?;
        Ok(binding)
    }

    #[cfg(feature = "workers-rs")]
    fn authenticate_for_stable_request(
        &self,
        env: &worker::Env,
        public_request: &EcdsaThresholdPrfRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<TenantRootCustodyBindingV1> {
        self.validate()?;
        public_request.validate_at(now_unix_ms)?;
        let reader = CloudflareWorkerEnvReaderV1::new(env);
        let issuer_keys =
            parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
        let activation_receipt = self.verify_activation_receipt(&issuer_keys)?;
        let stable_context = public_request.stable_tenant_derivation_context()?;
        let transcript_digest = public_request.derivation_transcript_digest()?;
        let outer_transcript_digest =
            TenantRootProtocolDigestV1::from_bytes(*transcript_digest.as_bytes())
                .map_err(map_root_share_to_protocol)?;
        let binding = TenantRootCustodyBindingV1::from_verified_activation_receipt(
            &activation_receipt,
            cloudflare_tenant_root_deriver_identities_v1(env)?,
            self.operation_id,
            self.session_id,
            self.nonce,
            self.issued_at_ms,
            self.expires_at_ms,
            &stable_context,
            outer_transcript_digest,
        )
        .map_err(map_root_share_to_protocol)?;
        binding
            .validate_at(now_unix_ms)
            .map_err(map_root_share_to_protocol)?;
        Ok(binding)
    }
}

/// Strict tenant-root private Deriver request for ECDSA registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1 {
    /// Typed public registration request admitted by Router.
    pub registration_request: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    /// Issuer-verified tenant-root receipt and Router-issued operation scope.
    pub tenant_root_custody_binding: CloudflareTenantRootCustodyBindingWireV1,
}

impl CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation registration Deriver request.
    #[cfg(feature = "workers-rs")]
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        registration_request: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
        tenant_root_custody_binding: CloudflareTenantRootCustodyBindingWireV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            registration_request,
            signer_bootstrap,
            tenant_root_custody_binding,
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
        self.tenant_root_custody_binding.validate_transport()?;
        let expected_router_request_digest = self.registration_request.request_header_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation registration bootstrap digest does not match typed registration request",
            ));
        }
        if self.tenant_root_custody_binding.expires_at_ms < self.registration_request.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "tenant-root private binding expires before the admitted registration request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_router_ab_ecdsa_derivation_registration_request_for_router_payload_v1(
            &self.registration_request,
            &router_payload,
        )
    }

    /// Consumes the public wire after independently authenticating its signed
    /// tenant-root receipt and reconstructing the exact role-local binding.
    #[cfg(feature = "workers-rs")]
    pub(crate) fn into_authenticated_parts(
        self,
        env: &worker::Env,
        worker_role: CloudflareWorkerRoleV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<(
        RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        CloudflareAuthenticatedSignerPrivateBootstrapRequestV1,
        CloudflareTenantRootCustodyBindingWireV1,
    )> {
        self.validate_for_worker_role(worker_role)?;
        let CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1 {
            registration_request,
            signer_bootstrap,
            tenant_root_custody_binding,
        } = self;
        let binding = tenant_root_custody_binding.authenticate_for_registration(
            env,
            &registration_request,
            now_unix_ms,
        )?;
        let authenticated = CloudflareAuthenticatedSignerPrivateBootstrapRequestV1::new(
            worker_role,
            signer_bootstrap,
            binding,
        )?;
        Ok((
            registration_request,
            authenticated,
            tenant_root_custody_binding,
        ))
    }
}

/// Reconstructs a strict registration bootstrap from the admitted ECDSA lifecycle header.
pub fn cloudflare_signer_private_bootstrap_from_ecdsa_derivation_registration_v1(
    worker_role: CloudflareWorkerRoleV1,
    registration_request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerPrivateBootstrapRequestV1> {
    registration_request.validate()?;
    validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
    let public_request = registration_request.to_threshold_prf_request()?;
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
            "strict ECDSA registration bootstrap message does not match admitted request",
        ));
    }
    let aad = registration_request.header().role_aad(signer_role)?;
    let router_request_digest = registration_request.request_header_digest()?;
    let router_payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let assignment = router_payload.require_recipient_role(signer_role)?;
    if assignment.envelope.header_digest != router_request_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "strict ECDSA registration envelope header digest does not match admitted header",
        ));
    }
    CloudflareSignerPrivateBootstrapRequestV1::new(worker_role, message, aad, router_request_digest)
}

/// Strict private Deriver request for Router A/B ECDSA derivation explicit export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1 {
    /// Typed public export request admitted by Router.
    pub export_request: RouterAbEcdsaDerivationExplicitExportRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    /// Issuer-verified tenant-root receipt and Router-issued operation scope.
    pub tenant_root_custody_binding: CloudflareTenantRootCustodyBindingWireV1,
}

impl CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation export Deriver request.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        export_request: RouterAbEcdsaDerivationExplicitExportRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
        tenant_root_custody_binding: CloudflareTenantRootCustodyBindingWireV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            export_request,
            signer_bootstrap,
            tenant_root_custody_binding,
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
        self.tenant_root_custody_binding.validate_transport()?;
        if self.tenant_root_custody_binding.expires_at_ms < self.export_request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "tenant-root private binding expires before the admitted export request",
            ));
        }
        let expected_router_request_digest = self
            .export_request
            .to_threshold_prf_request()?
            .request_context_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation export bootstrap digest does not match typed export request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_router_ab_ecdsa_derivation_export_request_for_router_payload_v1(
            &self.export_request,
            &router_payload,
        )
    }

    /// Consumes the public wire after independently authenticating its signed
    /// tenant-root receipt and reconstructing the exact role-local binding.
    #[cfg(feature = "workers-rs")]
    pub(crate) fn into_authenticated_parts(
        self,
        env: &worker::Env,
        worker_role: CloudflareWorkerRoleV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<(
        RouterAbEcdsaDerivationExplicitExportRequestV1,
        CloudflareAuthenticatedSignerPrivateBootstrapRequestV1,
        CloudflareTenantRootCustodyBindingWireV1,
    )> {
        self.validate_for_worker_role(worker_role)?;
        let CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1 {
            export_request,
            signer_bootstrap,
            tenant_root_custody_binding,
        } = self;
        let binding = tenant_root_custody_binding.authenticate_for_export(
            env,
            &export_request,
            now_unix_ms,
        )?;
        let authenticated = CloudflareAuthenticatedSignerPrivateBootstrapRequestV1::new(
            worker_role,
            signer_bootstrap,
            binding,
        )?;
        Ok((export_request, authenticated, tenant_root_custody_binding))
    }
}

/// Strict private Deriver request for Router A/B ECDSA derivation activation refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1 {
    /// Typed public activation-refresh request admitted by Router.
    pub refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1,
    /// Router-to-Deriver bootstrap body carrying role-envelope AAD.
    pub signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    /// Issuer-verified tenant-root receipt and Router-issued operation scope.
    pub tenant_root_custody_binding: CloudflareTenantRootCustodyBindingWireV1,
}

impl CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation activation-refresh Deriver request.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1,
        signer_bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
        tenant_root_custody_binding: CloudflareTenantRootCustodyBindingWireV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            refresh_request,
            signer_bootstrap,
            tenant_root_custody_binding,
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
        self.tenant_root_custody_binding.validate_transport()?;
        if self.tenant_root_custody_binding.expires_at_ms < self.refresh_request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "tenant-root private binding expires before the admitted refresh request",
            ));
        }
        let expected_router_request_digest = self
            .refresh_request
            .to_threshold_prf_request()?
            .request_context_digest()?;
        if self.signer_bootstrap.router_request_digest != expected_router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation activation refresh bootstrap digest does not match typed refresh request",
            ));
        }
        let router_payload =
            decode_router_to_signer_payload_v1(self.signer_bootstrap.message.payload.as_bytes())?;
        validate_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_for_router_payload_v1(
            &self.refresh_request,
            &router_payload,
        )
    }

    /// Consumes the public wire after independently authenticating its signed
    /// tenant-root receipt and reconstructing the exact role-local binding.
    #[cfg(feature = "workers-rs")]
    pub(crate) fn into_authenticated_parts(
        self,
        env: &worker::Env,
        worker_role: CloudflareWorkerRoleV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<(
        RouterAbEcdsaDerivationActivationRefreshRequestV1,
        CloudflareAuthenticatedSignerPrivateBootstrapRequestV1,
        CloudflareTenantRootCustodyBindingWireV1,
    )> {
        self.validate_for_worker_role(worker_role)?;
        let CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1 {
            refresh_request,
            signer_bootstrap,
            tenant_root_custody_binding,
        } = self;
        let binding = tenant_root_custody_binding.authenticate_for_refresh(
            env,
            &refresh_request,
            now_unix_ms,
        )?;
        let authenticated = CloudflareAuthenticatedSignerPrivateBootstrapRequestV1::new(
            worker_role,
            signer_bootstrap,
            binding,
        )?;
        Ok((refresh_request, authenticated, tenant_root_custody_binding))
    }
}

/// Reconstructs the strict signer bootstrap body from an admitted public Router request.
pub fn cloudflare_signer_private_bootstrap_from_public_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    public_request: &EcdsaThresholdPrfRequestV1,
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

/// Validates that a Router A/B ECDSA derivation registration request owns a Router-to-signer payload.
pub fn validate_cloudflare_router_ab_ecdsa_derivation_registration_request_for_router_payload_v1(
    registration_request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    registration_request.validate()?;
    router_payload.validate()?;
    let public_request = registration_request.to_threshold_prf_request()?;
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
        "Router A/B ECDSA derivation registration request does not match Router-to-Deriver payload",
    ))
}

/// Validates that a Router A/B ECDSA derivation export request owns a Router-to-signer payload.
pub fn validate_cloudflare_router_ab_ecdsa_derivation_export_request_for_router_payload_v1(
    export_request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    export_request.validate()?;
    router_payload.validate()?;
    let public_request = export_request.to_threshold_prf_request()?;
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
        "Router A/B ECDSA derivation export request does not match Router-to-Deriver payload",
    ))
}

/// Validates that a Router A/B ECDSA derivation activation-refresh request owns a Router-to-signer payload.
pub fn validate_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_for_router_payload_v1(
    refresh_request: &RouterAbEcdsaDerivationActivationRefreshRequestV1,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    refresh_request.validate()?;
    router_payload.validate()?;
    let public_request = refresh_request.to_threshold_prf_request()?;
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
        "Router A/B ECDSA derivation activation refresh request does not match Router-to-Deriver payload",
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
    /// Creates validated Deriver-host preload coordinates.
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

    /// Validates Deriver-host preload coordinates.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let expected_role = cloudflare_worker_signer_role_v1(self.worker_role)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        self.local_signer.validate()?;
        self.signer_set.validate()?;
        if self.local_signer.role != expected_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Deriver-host preload plan local signer does not match Worker role",
            ));
        }
        if self.signer_set.signer_set_id != self.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Deriver-host preload plan signer-set id does not match signer set",
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
                "Deriver-host preload plan local signer does not match signer-set role",
            ));
        }
        Ok(())
    }

    /// Builds Deriver-host preload input after the adapter supplies peer material.
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

    /// Builds Deriver-host preload input from a trusted public verifying-key set.
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

/// Builds the V2 stable request from the admitted public envelope and the
/// independently authenticated tenant-root custody scope.
#[cfg(feature = "workers-rs")]
pub(crate) fn build_cloudflare_ecdsa_threshold_prf_outer_request_v2(
    public_request: &EcdsaThresholdPrfRequestV1,
    custody_binding: &TenantRootCustodyBindingV1,
    custody_wire: &CloudflareTenantRootCustodyBindingWireV1,
) -> RouterAbProtocolResult<EcdsaThresholdPrfOuterRequestV2> {
    public_request.validate()?;
    custody_binding
        .validate()
        .map_err(map_root_share_to_protocol)?;
    custody_wire.validate()?;
    let private_request = EcdsaThresholdPrfPrivateRequestV2::new(
        public_request.stable_tenant_derivation_context()?,
        custody_binding
            .digest()
            .map_err(map_root_share_to_protocol)?,
        EcdsaThresholdPrfPurposeV2::XClientBase,
    )?;
    EcdsaThresholdPrfOuterRequestV2::new(
        custody_wire.nonce,
        custody_wire.issued_at_ms,
        custody_wire.expires_at_ms,
        private_request,
        public_request.signer_a_envelope.clone(),
        public_request.signer_b_envelope.clone(),
    )
}

/// Evaluates the two stable tenant-root outputs for one authenticated Deriver request.
#[cfg(feature = "workers-rs")]
pub fn evaluate_cloudflare_authenticated_stable_mpc_prf_outputs_v2(
    host: &CloudflarePreloadedSignerHostV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
    outer_request: &EcdsaThresholdPrfOuterRequestV2,
    custody_binding: &TenantRootCustodyBindingV1,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<(
    MpcPrfStablePartialProofBundleV2,
    MpcPrfStablePartialProofBundleV2,
)> {
    let (signer_role, active_pair) = validate_cloudflare_authenticated_stable_mpc_prf_request_v2(
        host,
        request,
        outer_request,
        custody_binding,
        now_unix_ms,
    )?;
    let expected_share_role = match signer_role {
        Role::SignerA => TwoPartyDeriverRole::DeriverA,
        Role::SignerB => TwoPartyDeriverRole::DeriverB,
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    };
    if verified_share.role() != expected_share_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "tenant-root active role share does not match Deriver Worker role",
        ));
    }
    MpcPrfStableThresholdSignerInputV2::evaluate_x_client_and_x_server_batch_with_threshold_backend_v2(
        outer_request.private_request().stable_context(),
        custody_binding,
        &active_pair,
        verified_share,
        now_unix_ms,
        &mut CloudflareSignerProofGetrandomRngV1,
    )
    .map_err(map_derivation_to_protocol)
}

#[cfg(feature = "workers-rs")]
fn validate_cloudflare_authenticated_stable_mpc_prf_request_v2(
    host: &CloudflarePreloadedSignerHostV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
    outer_request: &EcdsaThresholdPrfOuterRequestV2,
    custody_binding: &TenantRootCustodyBindingV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<(Role, router_ab_core::TenantRootActiveRootPairV1)> {
    host.validate()?;
    request.router_payload().validate()?;
    request
        .signer_input()
        .validate()
        .map_err(map_derivation_to_protocol)?;
    custody_binding
        .validate_at(now_unix_ms)
        .map_err(map_root_share_to_protocol)?;
    outer_request.validate_for_custody(custody_binding, now_unix_ms)?;
    if outer_request.private_request().purpose() != EcdsaThresholdPrfPurposeV2::XClientBase {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "ECDSA registration V2 request must use the fixed client/server purpose pair",
        ));
    }

    let signer_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    if request.signer_input().recipient_role != signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "validated signer input role does not match Worker role",
        ));
    }
    let expected_envelope = match signer_role {
        Role::SignerA => outer_request.signer_a_envelope(),
        Role::SignerB => outer_request.signer_b_envelope(),
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    };
    if expected_envelope != &request.router_payload().assignment().envelope {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "ECDSA threshold-PRF V2 outer request envelope does not match Router payload",
        ));
    }
    let active_pair = cloudflare_active_tenant_root_pair_from_custody_binding_v1(custody_binding)?;
    Ok((signer_role, active_pair))
}

#[cfg(feature = "workers-rs")]
fn evaluate_cloudflare_stable_mpc_prf_output_v2(
    outer_request: &EcdsaThresholdPrfOuterRequestV2,
    custody_binding: &TenantRootCustodyBindingV1,
    active_pair: &router_ab_core::TenantRootActiveRootPairV1,
    signer_role: Role,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    purpose: EcdsaThresholdPrfPurposeV2,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<MpcPrfStablePartialProofBundleV2> {
    let expected_share_role = match signer_role {
        Role::SignerA => TwoPartyDeriverRole::DeriverA,
        Role::SignerB => TwoPartyDeriverRole::DeriverB,
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    };
    if verified_share.role() != expected_share_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "tenant-root active role share does not match Deriver Worker role",
        ));
    }
    let private_request = EcdsaThresholdPrfPrivateRequestV2::new(
        outer_request.private_request().stable_context().clone(),
        outer_request.private_request().custody_binding_digest(),
        purpose,
    )?;
    let input = MpcPrfStableThresholdSignerInputV2::from_private_request(
        &private_request,
        custody_binding,
        active_pair,
        verified_share,
        now_unix_ms,
    )
    .map_err(map_derivation_to_protocol)?;
    evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        input,
        &mut CloudflareSignerProofGetrandomRngV1,
    )
    .map_err(map_derivation_to_protocol)
}

#[cfg(feature = "workers-rs")]
fn evaluate_cloudflare_authenticated_stable_mpc_prf_client_output_v2(
    host: &CloudflarePreloadedSignerHostV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
    outer_request: &EcdsaThresholdPrfOuterRequestV2,
    custody_binding: &TenantRootCustodyBindingV1,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<MpcPrfStablePartialProofBundleV2> {
    let (signer_role, active_pair) = validate_cloudflare_authenticated_stable_mpc_prf_request_v2(
        host,
        request,
        outer_request,
        custody_binding,
        now_unix_ms,
    )?;
    evaluate_cloudflare_stable_mpc_prf_output_v2(
        outer_request,
        custody_binding,
        &active_pair,
        signer_role,
        verified_share,
        EcdsaThresholdPrfPurposeV2::XClientBase,
        now_unix_ms,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_active_tenant_root_pair_from_custody_binding_v1(
    custody_binding: &TenantRootCustodyBindingV1,
) -> RouterAbProtocolResult<router_ab_core::TenantRootActiveRootPairV1> {
    let identity_digest = custody_binding.identity_digest();
    let role_binding = |role, commitment: &router_ab_core::MpcPrfShareCommitmentWireV1| {
        TenantRootActiveRoleBindingV1::new(
            TenantRootActiveRoleRowKeyV1::new(
                identity_digest,
                custody_binding.custody_lineage(),
                custody_binding.epoch(),
                role,
            ),
            commitment.clone(),
            custody_binding.activation_receipt_digest(),
        )
        .map(TenantRootActiveRoleResolutionV1::Active)
        .map_err(map_root_share_to_protocol)
    };
    let deriver_a = role_binding(
        TenantRootManagedRestoreRoleV1::DeriverA,
        custody_binding.commitments().deriver_a(),
    )?;
    let deriver_b = role_binding(
        TenantRootManagedRestoreRoleV1::DeriverB,
        custody_binding.commitments().deriver_b(),
    )?;
    resolve_authoritative_active_tenant_root_pair_binding_v1(
        identity_digest,
        custody_binding,
        &deriver_a,
        &deriver_b,
    )
    .map_err(map_root_share_to_protocol)?
    .require_active()
    .map(Clone::clone)
    .map_err(map_root_share_to_protocol)
}

/// Builds the existing opaque delivery envelope from stable tenant-root proofs.
#[cfg(feature = "workers-rs")]
pub fn cloudflare_recipient_proof_bundle_response_from_stable_outputs_v2(
    router_payload: &RouterToSignerPayloadV1,
    signer: SignerIdentityV1,
    client_output: &MpcPrfStablePartialProofBundleV2,
    server_output: &MpcPrfStablePartialProofBundleV2,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    router_payload.validate()?;
    signer.validate()?;
    let client_bundle = cloudflare_stable_recipient_proof_bundle_wire_message_v2(
        router_payload,
        signer.clone(),
        Role::Client,
        &router_payload.transcript_metadata().client_id,
        &router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        client_output,
        encryptor,
    )?;
    let server_bundle = cloudflare_stable_recipient_proof_bundle_wire_message_v2(
        router_payload,
        signer.clone(),
        Role::Server,
        &router_payload.signer_set().selected_server.server_id,
        &router_payload
            .signer_set()
            .selected_server
            .recipient_encryption_key,
        server_output,
        encryptor,
    )?;
    let response = CloudflareSignerRecipientProofBundleResponseV1::new(
        signer.role,
        client_bundle,
        server_bundle,
    )?;
    response.validate_for_router_payload(router_payload)?;
    Ok(response)
}

/// Builds the existing client-only delivery envelope from one stable tenant-root proof.
#[cfg(feature = "workers-rs")]
pub fn cloudflare_client_recipient_proof_bundle_response_from_stable_output_v2(
    router_payload: &RouterToSignerPayloadV1,
    signer: SignerIdentityV1,
    client_output: &MpcPrfStablePartialProofBundleV2,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    router_payload.validate()?;
    signer.validate()?;
    let client_bundle = cloudflare_stable_recipient_proof_bundle_wire_message_v2(
        router_payload,
        signer.clone(),
        Role::Client,
        &router_payload.transcript_metadata().client_id,
        &router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        client_output,
        encryptor,
    )?;
    let response =
        CloudflareSignerClientRecipientProofBundleResponseV1::new(signer.role, client_bundle)?;
    response.validate_for_router_payload(router_payload)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
fn cloudflare_stable_recipient_proof_bundle_wire_message_v2(
    router_payload: &RouterToSignerPayloadV1,
    signer: SignerIdentityV1,
    recipient_role: Role,
    recipient_identity: &str,
    recipient_encryption_key: &str,
    output: &MpcPrfStablePartialProofBundleV2,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    let payload = MpcPrfStableRecipientProofBundlePayloadV2::from_stable_partial(
        signer,
        recipient_role,
        recipient_identity,
        output,
    )?;
    let request = RecipientProofBundleEncryptionRequestV1::new_stable_v2(
        &payload,
        recipient_encryption_key,
        router_payload.transcript_digest(),
    )?;
    let envelope = encryptor.encrypt_recipient_proof_bundle_v1(request)?;
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        router_payload.transcript_digest(),
        CanonicalWireBytesV1::new(envelope.canonical_bytes()?)?,
    )
}

/// Handles one authenticated registration through the stable tenant-root PRF.
#[cfg(feature = "workers-rs")]
pub fn handle_cloudflare_authenticated_stable_mpc_prf_signer_request_v2(
    host: &CloudflarePreloadedSignerHostV1,
    outer_request: &EcdsaThresholdPrfOuterRequestV2,
    custody_binding: &TenantRootCustodyBindingV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    now_unix_ms: u64,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    let local_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    let (local_signer, _, _) = cloudflare_signer_identities_for_request_v1(request, local_role)?;
    let (client_output, server_output) =
        evaluate_cloudflare_authenticated_stable_mpc_prf_outputs_v2(
            host,
            request,
            outer_request,
            custody_binding,
            verified_share,
            now_unix_ms,
        )?;
    cloudflare_recipient_proof_bundle_response_from_stable_outputs_v2(
        request.router_payload(),
        local_signer,
        &client_output,
        &server_output,
        encryptor,
    )
}

/// Handles one authenticated client-only operation through the stable tenant-root PRF.
#[cfg(feature = "workers-rs")]
pub fn handle_cloudflare_authenticated_stable_mpc_prf_client_signer_request_v2(
    host: &CloudflarePreloadedSignerHostV1,
    outer_request: &EcdsaThresholdPrfOuterRequestV2,
    custody_binding: &TenantRootCustodyBindingV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    now_unix_ms: u64,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    let local_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    let (local_signer, _, _) = cloudflare_signer_identities_for_request_v1(request, local_role)?;
    let client_output = evaluate_cloudflare_authenticated_stable_mpc_prf_client_output_v2(
        host,
        request,
        outer_request,
        custody_binding,
        verified_share,
        now_unix_ms,
    )?;
    cloudflare_client_recipient_proof_bundle_response_from_stable_output_v2(
        request.router_payload(),
        local_signer,
        &client_output,
        encryptor,
    )
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
pub(crate) fn load_cloudflare_server_output_hpke_private_key_bytes_v1(
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

#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
async fn decrypt_cloudflare_validated_ecdsa_derivation_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    expected_plaintext: &RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareValidatedSignerPrivateRequestV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
    root_share_metadata.validate()?;
    expected_plaintext.validate()?;
    let plaintext_bytes = decrypt_cloudflare_signer_envelope_hpke_payload_with_key_set_v1(
        env,
        worker_role,
        &message,
        envelope_decrypt_keys,
        aad,
        now_unix_ms,
    )
    .await?;
    if plaintext_bytes != expected_plaintext.canonical_plaintext_bytes()? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router A/B ECDSA derivation decrypted plaintext does not match the typed ceremony request",
        ));
    }
    let router_payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let signer_role = cloudflare_worker_signer_role_v1(worker_role)?;
    let assignment = router_payload.require_recipient_role(signer_role)?;
    expected_plaintext.validate_for_envelope(&assignment.envelope)?;
    let output_requests = match expected_plaintext.output_kind() {
        router_ab_core::RouterAbEcdsaDerivationOutputKindV1::ClientExport => {
            vec![MpcPrfOutputRequestV1::new(
                OpenedShareKind::XClientBase,
                Role::Client,
                expected_plaintext.common().client_id.clone(),
            )
            .map_err(map_derivation_to_protocol)?]
        }
        router_ab_core::RouterAbEcdsaDerivationOutputKindV1::SigningWorkerActivation => vec![
            MpcPrfOutputRequestV1::new(
                OpenedShareKind::XClientBase,
                Role::Client,
                expected_plaintext.common().client_id.clone(),
            )
            .map_err(map_derivation_to_protocol)?,
            MpcPrfOutputRequestV1::new(
                OpenedShareKind::XServerBase,
                Role::Server,
                router_payload
                    .signer_set()
                    .selected_server
                    .server_id
                    .clone(),
            )
            .map_err(map_derivation_to_protocol)?,
        ],
    };
    let signer_input = SignerInputPlaintextV1::new(
        router_payload.lifecycle().primitive_request_kind,
        router_payload.lifecycle().lifecycle_id.clone(),
        router_payload.signer_set().signer_set_id.clone(),
        SignerInputQuorumPolicyV1::All2,
        signer_role,
        assignment.signer.signer_id.clone(),
        assignment.signer.key_epoch.clone(),
        root_share_metadata.root_share_epoch.clone(),
        router_payload
            .signer_set()
            .selected_server
            .server_id
            .clone(),
        router_payload
            .signer_set()
            .selected_server
            .key_epoch
            .clone(),
        router_payload.transcript_digest(),
        router_request_digest,
        assignment.envelope.aad_digest,
        output_requests,
    )
    .map_err(map_derivation_to_protocol)?;
    validate_signer_input_plaintext_binding_v1(
        &router_payload,
        &signer_input,
        router_request_digest,
        &root_share_metadata.root_share_epoch,
    )?;
    CloudflareValidatedSignerPrivateRequestV1::new(
        worker_role,
        message,
        router_payload,
        signer_input,
    )
}

/// Decrypts, validates, and handles a Router A/B ECDSA derivation registration signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_registration_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    registration_request: RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    tenant_root_custody_binding: TenantRootCustodyBindingV1,
    outer_request: EcdsaThresholdPrfOuterRequestV2,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    registration_request.validate()?;
    bootstrap.validate_for_worker_role(worker_role)?;
    let expected_plaintext =
        RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::registration_for_request(
            &registration_request,
            cloudflare_worker_signer_role_v1(worker_role)?,
            bootstrap.aad.digest(),
        )?;
    let validated = decrypt_cloudflare_validated_ecdsa_derivation_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        &expected_plaintext,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_router_ab_ecdsa_derivation_registration_request_for_router_payload_v1(
        &registration_request,
        validated.router_payload(),
    )?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_authenticated_stable_mpc_prf_signer_request_v2(
        host,
        &outer_request,
        &tenant_root_custody_binding,
        &validated,
        verified_share,
        now_unix_ms,
        &mut encryptor,
    )?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
}

/// Decrypts, validates, and handles a Router A/B ECDSA derivation export signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    export_request: RouterAbEcdsaDerivationExplicitExportRequestV1,
    bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    custody_binding: TenantRootCustodyBindingV1,
    outer_request: EcdsaThresholdPrfOuterRequestV2,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    export_request.validate_at(now_unix_ms)?;
    bootstrap.validate_for_worker_role(worker_role)?;
    let expected_plaintext = RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::export_for_request(
        &export_request,
        cloudflare_worker_signer_role_v1(worker_role)?,
        bootstrap.aad.digest(),
    )?;
    let validated = decrypt_cloudflare_validated_ecdsa_derivation_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        &expected_plaintext,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_router_ab_ecdsa_derivation_export_request_for_router_payload_v1(
        &export_request,
        validated.router_payload(),
    )?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_authenticated_stable_mpc_prf_client_signer_request_v2(
        host,
        &outer_request,
        &custody_binding,
        &validated,
        verified_share,
        now_unix_ms,
        &mut encryptor,
    )?;
    validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
}

/// Decrypts, validates, and handles a Router A/B ECDSA derivation activation-refresh signer request.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    refresh_request: RouterAbEcdsaDerivationActivationRefreshRequestV1,
    bootstrap: CloudflareSignerPrivateBootstrapRequestV1,
    custody_binding: TenantRootCustodyBindingV1,
    outer_request: EcdsaThresholdPrfOuterRequestV2,
    verified_share: VerifiedTenantRootOnlineRoleShareV1,
    envelope_decrypt_keys: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    refresh_request.validate_at(now_unix_ms)?;
    bootstrap.validate_for_worker_role(worker_role)?;
    let expected_plaintext =
        RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::refresh_for_request(
            &refresh_request,
            cloudflare_worker_signer_role_v1(worker_role)?,
            bootstrap.aad.digest(),
        )?;
    let validated = decrypt_cloudflare_validated_ecdsa_derivation_signer_private_request_v1(
        env,
        worker_role,
        bootstrap.message,
        envelope_decrypt_keys,
        &bootstrap.aad,
        bootstrap.router_request_digest,
        root_share_metadata,
        &expected_plaintext,
        now_unix_ms,
    )
    .await?;
    validate_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_for_router_payload_v1(
        &refresh_request,
        validated.router_payload(),
    )?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_authenticated_stable_mpc_prf_signer_request_v2(
        host,
        &outer_request,
        &custody_binding,
        &validated,
        verified_share,
        now_unix_ms,
        &mut encryptor,
    )?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        validated.message(),
        &response,
    )?;
    Ok(response)
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

/// Handles a strict Deriver A proof-bundle activation request.
pub fn handle_cloudflare_deriver_a_recipient_proof_bundle_activation_request_v1(
    request: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    signing_worker_material_handle: impl Into<String>,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    request.validate()?;
    let active_signing_worker_state =
        cloudflare_active_signing_worker_state_from_activation_request_v1(
            &request,
            request.material_activation.clone(),
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
pub fn validate_cloudflare_deriver_peer_request_v1(
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
    decode_and_validate_cloudflare_deriver_peer_message_payload_v1(message)?;
    Ok(())
}

/// Validates a direct A/B peer response against the request and target Worker role.
pub fn validate_cloudflare_deriver_peer_response_v1(
    worker_role: CloudflareWorkerRoleV1,
    request: &WireMessageV1,
    response: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    validate_cloudflare_deriver_peer_request_v1(worker_role, request)?;
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
    decode_and_validate_cloudflare_deriver_peer_message_payload_v1(response)?;
    Ok(())
}

/// Decodes and validates the canonical A/B peer payload inside a wire message.
pub fn decode_and_validate_cloudflare_deriver_peer_message_payload_v1(
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
pub fn verify_cloudflare_deriver_peer_message_authentication_v1(
    key_store: &impl SignerKeyStore,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    let payload = decode_and_validate_cloudflare_deriver_peer_message_payload_v1(message)?;
    let verifying_key = key_store.signer_verifying_key(&payload.from)?;
    verify_ab_peer_message_ed25519_signature_v1(&payload, &verifying_key)?;
    Ok(payload)
}

/// Builds and signs one direct A/B peer wire message with the Worker-local Ed25519 key.
#[cfg(feature = "workers-rs")]
pub fn sign_cloudflare_deriver_peer_wire_message_v1(
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
    let mut signing_key_bytes =
        load_cloudflare_deriver_peer_signing_key_bytes_v1(env, signing_key)?;
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

/// Handles the strict private Deriver A service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_a_recipient_proof_bundle_private_fetch_v1(
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
        CloudflareWorkerRoleV1::DeriverA,
        CLOUDFLARE_DERIVER_A_PRIVATE_REQUEST_PATH,
        handler,
        request,
    )
    .await
}

/// Handles the strict private Deriver B service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_b_recipient_proof_bundle_private_fetch_v1(
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
        CloudflareWorkerRoleV1::DeriverB,
        CLOUDFLARE_DERIVER_B_PRIVATE_REQUEST_PATH,
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
    if request.path() != CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH {
        return worker::Response::error(
            format!(
                "Router A/B SigningWorker proof-bundle activation must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH
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

/// Handles SigningWorker's Router A/B ECDSA derivation activation route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA derivation SigningWorker activation route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA derivation SigningWorker activation must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH
            ),
            404,
        );
    }
    /* Refactor 94B Phase 0. Folded into the Router header under `ecdsa_sw_`. */
    let mut timing = CloudflareEcdsaBoundaryTimingV1::new();
    let total_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
    let activation = match request
        .json::<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1>()
        .await
    {
        Ok(activation) => activation,
        Err(err) => {
            return worker::Response::error(
                format!(
                    "Router A/B ECDSA derivation SigningWorker activation JSON parse failed: {err}"
                ),
                400,
            );
        }
    };
    timing.mark("parse", total_started_at_ms);
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let activate_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
    match activate_cloudflare_router_ab_ecdsa_derivation_signing_worker_output_v1(
        env,
        runtime,
        activation,
        now_unix_ms,
    )
    .await
    {
        Ok(response) => {
            timing.mark("activate", activate_started_at_ms);
            timing.mark("total", total_started_at_ms);
            let response = worker::Response::from_json(&response)?;
            timing.apply_to(&response)?;
            Ok(response)
        }
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles SigningWorker's Router A/B ECDSA derivation activation-refresh route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA derivation SigningWorker activation-refresh route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA derivation SigningWorker activation refresh must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!(
                    "Router A/B ECDSA derivation SigningWorker activation-refresh JSON parse failed: {err}"
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
    match refresh_cloudflare_router_ab_ecdsa_derivation_signing_worker_output_v1(
        env,
        runtime,
        parsed,
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
    if request.path() != CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH {
        return worker::Response::error(
            format!(
                "Router A/B normal-signing round-1 prepare must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH
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
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_normal_signing_material_v1(
            env,
            runtime,
            &parsed.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
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
    let put_call = match runtime.signing_worker_round1_put_request(prepared.record.clone()) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let put_response =
        match execute_cloudflare_signing_worker_private_d1_request_v1(env, &put_call).await {
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

#[cfg(feature = "workers-rs")]
async fn load_cloudflare_signing_worker_active_ecdsa_derivation_material_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
) -> RouterAbProtocolResult<(
    ActiveSigningWorkerStateV1,
    CloudflareServerOutputMaterialRecordV1,
)> {
    match ordinary_inactive_signer_material::load_source_preserving_ecdsa_material_v1(
        env,
        runtime,
        &scope.material_activation,
        &scope.signing_worker,
        &scope
            .public_identity
            .derivation_client_share_public_key33_b64u,
        &scope.public_identity.server_public_key33_b64u,
        &scope.public_identity.threshold_public_key33_b64u,
        &scope.public_identity.ethereum_address20_b64u,
    )
    .await
    {
        Ok(material) => return Ok(material),
        Err(error) if error.code() == RouterAbProtocolErrorCode::MissingLocalBinding => {}
        Err(error) => return Err(error),
    }
    let lookup =
        CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope(
            scope,
        )?;
    let active_call = runtime.active_signing_worker_state_get_request(lookup)?;
    let active_response =
        execute_cloudflare_signing_worker_private_d1_request_v1(env, &active_call).await?;
    let active_signing_worker =
        require_signing_worker_output_active_state_get_response_v1(&active_call, active_response)?;
    let material_lookup =
        CloudflareSigningWorkerOutputMaterialLookupV1::new(active_signing_worker.clone())?;
    let material_call = runtime.signing_worker_output_material_get_request(material_lookup)?;
    let material_response =
        execute_cloudflare_signing_worker_private_d1_request_v1(env, &material_call).await?;
    let material =
        require_signing_worker_output_material_get_response_v1(&material_call, material_response)?;
    validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
        scope,
        &active_signing_worker,
        &material,
    )?;
    Ok((active_signing_worker, material))
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_lane_material_record_v1(
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    signing_worker: &ServerIdentityV1,
    bytes: [u8; 32],
) -> RouterAbProtocolResult<CloudflareServerOutputMaterialRecordV1> {
    let transcript = decode_base64url_fixed_32_v1(
        "lane material identity transcript_hash_b64u",
        &identity.transcript_hash_b64u,
    )?;
    CloudflareServerOutputMaterialRecordV1::new(
        PublicDigest32::new(transcript),
        router_ab_core::OpenedShareKind::XServerBase,
        router_ab_core::Role::Server,
        signing_worker.server_id.clone(),
        CloudflareSecretMaterial32V1::new(bytes),
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_lane_active_state_for_scope_v1(
    scope: &NormalSigningScopeV1,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    group_public_key: &str,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    let identity_digest =
        decode_base64url_fixed_32_v1("lane material identity digest", &identity.digest_b64u()?)?;
    let signing_worker = ServerIdentityV1::new(
        scope.signing_worker_id.clone(),
        "lane-material",
        identity.server_recipient_key_digest_b64u.clone(),
    )?;
    ActiveSigningWorkerStateV1::new(
        scope.account_id.clone(),
        scope.material_activation.clone(),
        group_public_key.to_owned(),
        signing_worker,
        PublicDigest32::new(decode_base64url_fixed_32_v1(
            "lane material identity transcript_hash_b64u",
            &identity.transcript_hash_b64u,
        )?),
        PublicDigest32::new(identity_digest),
        format!("lane-material/{}", identity.target_material_activation_id),
        now_unix_ms,
    )
}

#[cfg(feature = "workers-rs")]
async fn load_cloudflare_signing_worker_normal_signing_material_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    scope: &NormalSigningScopeV1,
    source: &CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    _now_unix_ms: u64,
) -> RouterAbProtocolResult<(
    ActiveSigningWorkerStateV1,
    CloudflareServerOutputMaterialRecordV1,
)> {
    source.validate_for_normal_scope(scope)?;
    match source {
        CloudflareSigningWorkerNormalSigningMaterialSourceV1::RegistrationActivation { lookup } => {
            let call = runtime.active_signing_worker_state_get_request(lookup.clone())?;
            let response =
                execute_cloudflare_signing_worker_private_d1_request_v1(env, &call).await?;
            let active =
                require_signing_worker_output_active_state_get_response_v1(&call, response)?;
            let material_lookup =
                CloudflareSigningWorkerOutputMaterialLookupV1::new(active.clone())?;
            let material_call =
                runtime.signing_worker_output_material_get_request(material_lookup)?;
            let material_response =
                execute_cloudflare_signing_worker_private_d1_request_v1(env, &material_call)
                    .await?;
            let material = require_signing_worker_output_material_get_response_v1(
                &material_call,
                material_response,
            )?;
            Ok((active, material))
        }
        CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane {
            lookup,
            group_public_key,
        } => {
            let (artifact, activated_at_ms) =
                load_cloudflare_signing_worker_normal_signing_lane_material_v1(env, lookup).await?;
            artifact
                .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial)?;
            let bytes = decode_base64url_bytes_v1(
                "lane active server material artifact",
                &artifact.payload_b64u,
            )?;
            let active_bytes = match lookup.identity.key_family {
                CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1 => {
                    let parsed: CloudflareEcdsaLaneActiveServerMaterialV1 =
                        serde_json::from_slice(&bytes).map_err(|_| {
                            RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::MalformedWirePayload,
                                "ECDSA lane active server material is invalid",
                            )
                        })?;
                    parsed.share32()?.to_vec()
                }
                CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519 => {
                    let parsed: CloudflareEd25519LaneActiveServerMaterialV1 =
                        serde_json::from_slice(&bytes).map_err(|_| {
                            RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::MalformedWirePayload,
                                "Ed25519 lane active server material is invalid",
                            )
                        })?;
                    parsed.scalar32()?.to_vec()
                }
            };
            let active_bytes: [u8; 32] = active_bytes.try_into().map_err(|_| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "lane active server material must contain 32 bytes",
                )
            })?;
            let active = cloudflare_signing_worker_lane_active_state_for_scope_v1(
                scope,
                &lookup.identity,
                group_public_key,
                activated_at_ms,
            )?;
            let material = cloudflare_signing_worker_lane_material_record_v1(
                &lookup.identity,
                &active.signing_worker,
                active_bytes,
            )?;
            Ok((active, material))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_lane_active_ecdsa_state_v1(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    let identity_digest =
        decode_base64url_fixed_32_v1("lane material identity digest", &identity.digest_b64u()?)?;
    ActiveSigningWorkerStateV1::new(
        scope.wallet_id.clone(),
        scope.material_activation.clone(),
        "lane-material",
        scope.signing_worker.clone(),
        PublicDigest32::new(decode_base64url_fixed_32_v1(
            "lane material identity transcript_hash_b64u",
            &identity.transcript_hash_b64u,
        )?),
        PublicDigest32::new(identity_digest),
        format!("lane-material/{}", identity.target_material_activation_id),
        now_unix_ms,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_lane_active_linked_ecdsa_state_v1(
    scope: &RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    let identity_digest =
        decode_base64url_fixed_32_v1("lane material identity digest", &identity.digest_b64u()?)?;
    ActiveSigningWorkerStateV1::new(
        scope.wallet_id.clone(),
        scope.material_activation.clone(),
        "lane-material",
        ServerIdentityV1::new(
            scope.signing_worker_participant_id.clone(),
            scope.signing_worker_recipient_key_id.clone(),
            scope.signing_worker_hpke_public_key_b64u.clone(),
        )?,
        PublicDigest32::new(decode_base64url_fixed_32_v1(
            "lane material identity transcript_hash_b64u",
            &identity.transcript_hash_b64u,
        )?),
        PublicDigest32::new(identity_digest),
        format!("lane-material/{}", identity.target_material_activation_id),
        now_unix_ms,
    )
}

#[cfg(feature = "workers-rs")]
async fn load_cloudflare_signing_worker_linked_ecdsa_normal_signing_material_v1(
    env: &worker::Env,
    scope: &RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    source: &CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    _now_unix_ms: u64,
) -> RouterAbProtocolResult<(
    ActiveSigningWorkerStateV1,
    CloudflareServerOutputMaterialRecordV1,
)> {
    source.validate_for_linked_ecdsa_scope(scope)?;
    let CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane { lookup, .. } = source
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "linked ECDSA signing requires rotatable lane material",
        ));
    };
    let (artifact, activated_at_ms) =
        load_cloudflare_signing_worker_normal_signing_lane_material_v1(env, lookup).await?;
    artifact.validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial)?;
    let bytes = decode_base64url_bytes_v1(
        "linked ECDSA lane active server material artifact",
        &artifact.payload_b64u,
    )?;
    let parsed: CloudflareEcdsaLaneActiveServerMaterialV1 = serde_json::from_slice(&bytes)
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "linked ECDSA lane active server material is invalid",
            )
        })?;
    let active = cloudflare_signing_worker_lane_active_linked_ecdsa_state_v1(
        scope,
        &lookup.identity,
        activated_at_ms,
    )?;
    let material = cloudflare_signing_worker_lane_material_record_v1(
        &lookup.identity,
        &active.signing_worker,
        parsed.share32()?,
    )?;
    validate_cloudflare_linked_device_ecdsa_normal_signing_active_material_v1(
        scope, &active, &material,
    )?;
    Ok((active, material))
}

#[cfg(feature = "workers-rs")]
async fn load_cloudflare_signing_worker_ecdsa_normal_signing_material_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    source: &CloudflareSigningWorkerNormalSigningMaterialSourceV1,
    _now_unix_ms: u64,
) -> RouterAbProtocolResult<(
    ActiveSigningWorkerStateV1,
    CloudflareServerOutputMaterialRecordV1,
)> {
    source.validate_for_ecdsa_scope(scope)?;
    match source {
        CloudflareSigningWorkerNormalSigningMaterialSourceV1::RegistrationActivation { .. } => {
            load_cloudflare_signing_worker_active_ecdsa_derivation_material_v1(env, runtime, scope)
                .await
        }
        CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane { lookup, .. } => {
            let (artifact, activated_at_ms) =
                load_cloudflare_signing_worker_normal_signing_lane_material_v1(env, lookup).await?;
            artifact
                .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial)?;
            let bytes = decode_base64url_bytes_v1(
                "ECDSA lane active server material artifact",
                &artifact.payload_b64u,
            )?;
            let parsed: CloudflareEcdsaLaneActiveServerMaterialV1 = serde_json::from_slice(&bytes)
                .map_err(|_| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "ECDSA lane active server material is invalid",
                    )
                })?;
            let active = cloudflare_signing_worker_lane_active_ecdsa_state_v1(
                scope,
                &lookup.identity,
                activated_at_ms,
            )?;
            let material = cloudflare_signing_worker_lane_material_record_v1(
                &lookup.identity,
                &active.signing_worker,
                parsed.share32()?,
            )?;
            validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
                scope, &active, &material,
            )?;
            Ok((active, material))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_presign_error_response_v1(
    error: RouterAbProtocolError,
) -> worker::Result<worker::Response> {
    worker::Response::error(
        format!("{:?}: {}", error.code(), error.message()),
        cloudflare_router_error_status(error.code()),
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_internal_json_request_v1<T: Serialize>(
    path: &str,
    value: &T,
) -> RouterAbProtocolResult<worker::Request> {
    let body = serde_json::to_string(value).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("SigningWorker internal request JSON encoding failed: {error}"),
        )
    })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    worker::Request::new_with_init(&format!("https://signing-worker.internal{path}"), &init)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("SigningWorker internal request construction failed: {error}"),
            )
        })
}

/// Handles SigningWorker's private ECDSA presign-session init route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_presign_session_init_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("SigningWorker ECDSA presign init requires POST", 405);
    }
    if request.path()
        != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_INIT_PATH
    {
        return worker::Response::error("SigningWorker ECDSA presign init route not found", 404);
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerEcdsaPresignSessionInitRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker ECDSA presign init JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_active_ecdsa_derivation_material_v1(
            env,
            runtime,
            &parsed.scope,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let (relayer_share, _) =
        match cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_active_material_v1(
            &parsed.scope,
            &active_signing_worker,
            &material,
        ) {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let do_request = durable_object::CloudflareSigningWorkerEcdsaPresignSessionDoInitRequestV1 {
        request: parsed,
        relayer_share32_b64u: encode_base64url_bytes_v1(&relayer_share.x_relayer32),
    };
    let progress: durable_object::CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1 =
        match durable_object::execute_cloudflare_durable_object_custom_json_call_v1(
            env,
            &runtime.bindings().presign_session,
            CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_INIT_PATH,
            &do_request.request.presign_session_id,
            &do_request,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let durable_object::CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1::Continue {
        presign_session_id,
        stage,
        event,
        outgoing_messages_b64u,
    } = progress
    else {
        return worker::Response::error(
            "SigningWorker ECDSA presign init returned terminal state",
            500,
        );
    };
    worker::Response::from_json(
        &CloudflareSigningWorkerEcdsaPresignSessionProgressV1::Continue {
            presign_session_id,
            stage,
            event,
            outgoing_messages_b64u,
        },
    )
}

/// Handles SigningWorker's private linked-device ECDSA presign-session init
/// route. The linked request is admitted by Gateway before this call and is
/// kept in a dedicated Durable Object session, separate from the owner pool.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_linked_ecdsa_presign_session_init_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "SigningWorker linked ECDSA presign init requires POST",
            405,
        );
    }
    if request.path()
        != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_PRESIGNATURE_SESSION_INIT_PATH
    {
        return worker::Response::error(
            "SigningWorker linked ECDSA presign init route not found",
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionInitRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker linked ECDSA presign init JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_linked_ecdsa_normal_signing_material_v1(
            env,
            &parsed.request.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let do_request =
        durable_object::CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoInitRequestV1 {
            request: parsed,
            active_signing_worker_state: active_signing_worker,
            relayer_share32_b64u: encode_base64url_bytes_v1(material.output_material.as_bytes()),
        };
    let progress = match durable_object::execute_cloudflare_durable_object_custom_json_call_v1(
        env,
        &runtime.bindings().presign_session,
        CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_INIT_PATH,
        &do_request.request.request.client_presignature_id,
        &do_request,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    let durable_object::CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1::Continue {
        presign_session_id,
        stage,
        event,
        outgoing_messages_b64u,
    } = progress
    else {
        return worker::Response::error(
            "SigningWorker linked ECDSA presign init returned terminal state",
            500,
        );
    };
    worker::Response::from_json(
        &CloudflareSigningWorkerEcdsaPresignSessionProgressV1::Continue {
            presign_session_id,
            stage,
            event,
            outgoing_messages_b64u,
        },
    )
}

/// Validates active ECDSA export material without releasing a share.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_export_preflight_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("SigningWorker ECDSA export preflight requires POST", 405);
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PREFLIGHT_PATH
    {
        return worker::Response::error(
            "SigningWorker ECDSA export-preflight route not found",
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerEcdsaExportShareRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker ECDSA export-preflight JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    if let Err(error) = load_cloudflare_signing_worker_ecdsa_normal_signing_material_v1(
        env,
        runtime,
        &parsed.export_authority.normal_signing_scope,
        &parsed.material_source,
        now_unix_ms,
    )
    .await
    {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    worker::Response::from_json(&CloudflareSigningWorkerEcdsaExportPreflightResponseV1 {
        ready: true,
    })
}

/// Delivers the exact active additive share to one authenticated, replay-reserved export recipient.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_export_share_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("SigningWorker ECDSA export share requires POST", 405);
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH {
        return worker::Response::error("SigningWorker ECDSA export-share route not found", 404);
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerEcdsaExportShareRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker ECDSA export-share JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_ecdsa_normal_signing_material_v1(
            env,
            runtime,
            &parsed.export_authority.normal_signing_scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let (relayer_share, _) =
        match cloudflare_router_ab_ecdsa_derivation_relayer_share_and_public_identity_from_active_material_v1(
            &parsed.export_authority.normal_signing_scope,
            &active_signing_worker,
            &material,
        ) {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let binding = match parsed.export_share_binding() {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    let mut seal_seed = [0_u8; 32];
    if getrandom::getrandom(&mut seal_seed).is_err() {
        return worker::Response::error("SigningWorker ECDSA export-share RNG failed", 500);
    }
    let envelope = match seal_ecdsa_signing_worker_export_share_v1(
        binding,
        &relayer_share.x_relayer32,
        seal_seed,
    ) {
        Ok(value) => value,
        Err(_) => {
            return worker::Response::error(
                "SigningWorker ECDSA export-share encryption failed",
                500,
            );
        }
    };
    worker::Response::from_json(&envelope)
}

/// Seals one exact active additive-lane server share to an admitted one-use recipient.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_linked_ecdsa_export_share_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "SigningWorker linked ECDSA export share requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_EXPORT_SHARE_PATH {
        return worker::Response::error(
            "SigningWorker linked ECDSA export-share route not found",
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerLinkedEcdsaExportShareRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker linked ECDSA export-share JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let (_, material) =
        match load_cloudflare_signing_worker_linked_ecdsa_normal_signing_material_v1(
            env,
            &parsed.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let mut seal_seed = [0_u8; 32];
    if getrandom::getrandom(&mut seal_seed).is_err() {
        return worker::Response::error("SigningWorker linked ECDSA export-share RNG failed", 500);
    }
    let envelope = match seal_ecdsa_signing_worker_export_share_v1(
        parsed.binding,
        material.output_material.as_bytes(),
        seal_seed,
    ) {
        Ok(value) => value,
        Err(_) => {
            return worker::Response::error(
                "SigningWorker linked ECDSA export-share encryption failed",
                500,
            );
        }
    };
    worker::Response::from_json(&envelope)
}

/// Handles SigningWorker's private ECDSA presign-session step route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_ecdsa_presign_session_step_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("SigningWorker ECDSA presign step requires POST", 405);
    }
    if request.path()
        != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_STEP_PATH
    {
        return worker::Response::error("SigningWorker ECDSA presign step route not found", 404);
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerEcdsaPresignSessionStepRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker ECDSA presign step JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let progress = match durable_object::execute_cloudflare_durable_object_custom_json_call_v1(
        env,
        &runtime.bindings().presign_session,
        CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_STEP_PATH,
        &parsed.presign_session_id,
        &parsed,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    match progress {
        durable_object::CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1::Continue {
            presign_session_id,
            stage,
            event,
            outgoing_messages_b64u,
        } => worker::Response::from_json(
            &CloudflareSigningWorkerEcdsaPresignSessionProgressV1::Continue {
                presign_session_id,
                stage,
                event,
                outgoing_messages_b64u,
            },
        ),
        durable_object::CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1::Complete {
            pool_put_request,
        } => {
            let presign_session_id = parsed.presign_session_id;
            let server_presignature_id = pool_put_request.server_presignature_id.clone();
            let server_big_r33_b64u = pool_put_request.server_big_r33_b64u.clone();
            let internal_request = match cloudflare_signing_worker_internal_json_request_v1(
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
                &pool_put_request,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return cloudflare_signing_worker_presign_error_response_v1(error);
                }
            };
            let admission = handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1(
                internal_request,
                env,
                runtime,
                now_unix_ms,
            )
            .await?;
            if !(200..=299).contains(&admission.status_code()) {
                return Ok(admission);
            }
            worker::Response::from_json(
                &CloudflareSigningWorkerEcdsaPresignSessionProgressV1::Complete {
                    presign_session_id,
                    server_presignature_id,
                    server_big_r33_b64u,
                    signing_worker_rerandomization_contribution32_b64u: None,
                    prepared_response: None,
                },
            )
        }
    }
}

/// Handles SigningWorker's private linked-device ECDSA presign-session step
/// route. Completion is returned directly to Gateway and is never inserted in
/// the owner presignature pool.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_linked_ecdsa_presign_session_step_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "SigningWorker linked ECDSA presign step requires POST",
            405,
        );
    }
    if request.path()
        != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_PRESIGNATURE_SESSION_STEP_PATH
    {
        return worker::Response::error(
            "SigningWorker linked ECDSA presign step route not found",
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionStepRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker linked ECDSA presign step JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let progress = match durable_object::execute_cloudflare_durable_object_custom_json_call_v1(
        env,
        &runtime.bindings().presign_session,
        CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_STEP_PATH,
        &parsed.request.client_presignature_id,
        &parsed,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    match progress {
        durable_object::CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1::Continue {
            presign_session_id,
            stage,
            event,
            outgoing_messages_b64u,
        } => worker::Response::from_json(
            &CloudflareSigningWorkerEcdsaPresignSessionProgressV1::Continue {
                presign_session_id,
                stage,
                event,
                outgoing_messages_b64u,
            },
        ),
        durable_object::CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1::Complete {
            presign_session_id,
            server_presignature_id,
            server_big_r33_b64u,
            signing_worker_rerandomization_contribution32_b64u,
            prepared_response,
        } => worker::Response::from_json(
            &CloudflareSigningWorkerEcdsaPresignSessionProgressV1::Complete {
                presign_session_id,
                server_presignature_id,
                server_big_r33_b64u,
                signing_worker_rerandomization_contribution32_b64u:
                    Some(signing_worker_rerandomization_contribution32_b64u),
                prepared_response: Some(prepared_response),
            },
        ),
    }
}

/// Handles one linked-device ECDSA finalize request. The completed presignature
/// record is consumed inside the SigningWorker boundary and never serialized
/// into an HTTP response.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_linked_ecdsa_finalize_private_fetch_v1<Handler>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerLinkedDeviceEcdsaFinalizeHandlerV1,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "SigningWorker linked ECDSA finalize route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_PATH {
        return worker::Response::error("SigningWorker linked ECDSA finalize route not found", 404);
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedLinkedDeviceEcdsaFinalizeRequestV1>()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker linked ECDSA finalize JSON parse failed: {error}"),
                400,
            );
        }
    };
    if let Err(error) = parsed.validate() {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    if let Err(error) = parsed.request.validate_at(now_unix_ms) {
        return cloudflare_signing_worker_presign_error_response_v1(error);
    }
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_linked_ecdsa_normal_signing_material_v1(
            env,
            &parsed.request.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    let request_digest = match parsed.request.prepare_request_digest() {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    let signing_digest = match parsed.request.signing_digest() {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    let scope_digest = match parsed.request.scope.scope_digest() {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    let server_presignature = match consume_cloudflare_signing_worker_linked_ecdsa_presignature_v1(
        env,
        runtime,
        parsed.request.server_presignature_id.clone(),
        scope_digest,
        request_digest,
        signing_digest,
        now_unix_ms,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
    };
    let response =
        match handle_cloudflare_signing_worker_linked_device_ecdsa_finalize_private_request_v1(
            handler,
            now_unix_ms,
            parsed,
            active_signing_worker,
            material,
            server_presignature,
        ) {
            Ok(value) => value,
            Err(error) => return cloudflare_signing_worker_presign_error_response_v1(error),
        };
    worker::Response::from_json(&response)
}

/// Consumes one completed linked-device presignature inside the SigningWorker
/// boundary. The record remains private and is passed directly to linked
/// finalize materialization.
#[cfg(feature = "workers-rs")]
pub(crate) async fn consume_cloudflare_signing_worker_linked_ecdsa_presignature_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    server_presignature_id: String,
    scope_digest: PublicDigest32,
    request_digest: PublicDigest32,
    signing_digest: PublicDigest32,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignatureRecordV1> {
    let request =
        durable_object::CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeRequestV1 {
            server_presignature_id,
            scope_digest,
            request_digest,
            signing_digest,
            now_unix_ms,
        };
    let response: durable_object::CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeResponseV1 =
        durable_object::execute_cloudflare_durable_object_custom_json_call_v1(
            env,
            &runtime.bindings().presign_session,
            CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGNATURE_DO_CONSUME_PATH,
            &request.server_presignature_id,
            &request,
        )
        .await?;
    Ok(response.record)
}

/// Handles SigningWorker's private Router A/B ECDSA derivation presignature pool-fill route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA derivation presignature pool fill route requires POST",
            405,
        );
    }
    if request.path()
        != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH
    {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA derivation presignature pool fill must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!(
                    "Router A/B ECDSA derivation presignature pool fill JSON parse failed: {err}"
                ),
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
    let (active_signing_worker, active_material) =
        match load_cloudflare_signing_worker_ecdsa_normal_signing_material_v1(
            env,
            runtime,
            &parsed.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let record = match parsed.to_pool_record(active_signing_worker, &active_material, now_unix_ms) {
        Ok(record) => record,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let mutate_call = match runtime.signing_worker_ecdsa_pool_mutate_request(
        CloudflareSigningWorkerEcdsaPoolCommandV1::PutAvailable {
            material: record.clone(),
        },
    ) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let mutate_response =
        match execute_cloudflare_signing_worker_private_d1_request_v1(env, &mutate_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let outcome =
        match require_signing_worker_ecdsa_pool_mutate_response_v1(&mutate_call, mutate_response) {
            Ok(outcome) => outcome,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Available { stored, .. } = outcome
    else {
        return worker::Response::error(
            "SigningWorker ECDSA pool admission returned the wrong lifecycle outcome",
            cloudflare_router_error_status(RouterAbProtocolErrorCode::InvalidLocalServiceConfig),
        );
    };
    let receipt =
        match CloudflareSigningWorkerEcdsaPoolAdmissionReceiptV1::from_record(&record, stored) {
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

/// Handles SigningWorker's production Router A/B ECDSA derivation prepare route using the presignature pool.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_private_fetch_from_pool_v1(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    now_unix_ms: u64,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA derivation prepare route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA derivation prepare must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B ECDSA derivation prepare JSON parse failed: {err}"),
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
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_ecdsa_normal_signing_material_v1(
            env,
            runtime,
            &parsed.request.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let materialized =
        match CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
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
    let signing_worker_rerandomization_contribution32_b64u = match cloudflare_random_bytes_v1(32) {
        Ok(bytes) => encode_base64url_bytes_v1(&bytes),
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let prepare_request_digest = match materialized.request.request.request_digest() {
        Ok(digest) => digest,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let signing_digest = match materialized.request.request.signing_digest() {
        Ok(digest) => digest,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let reserve_command = CloudflareSigningWorkerEcdsaPoolCommandV1::Reserve {
        scope: materialized.request.request.scope.clone(),
        server_presignature_id: client_presignature_id.clone(),
        expected_revision: 0,
        request_digest: prepare_request_digest,
        admitted_signing_digest: signing_digest,
        signing_worker_rerandomization_contribution32_b64u,
        reserved_at_ms: now_unix_ms,
        request_expires_at_ms: materialized.request.request.expires_at_ms,
    };
    let reserve_call = match runtime.signing_worker_ecdsa_pool_mutate_request(reserve_command) {
        Ok(call) => call,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let reserve_response =
        match execute_cloudflare_signing_worker_private_d1_request_v1(env, &reserve_call).await {
            Ok(response) => response,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let reserve_outcome =
        match require_signing_worker_ecdsa_pool_mutate_response_v1(&reserve_call, reserve_response)
        {
            Ok(outcome) => outcome,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    cloudflare_router_error_status(err.code()),
                );
            }
        };
    let CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Reserved { record } = reserve_outcome
    else {
        return worker::Response::error(
            "SigningWorker ECDSA pool reserve returned the wrong lifecycle outcome",
            cloudflare_router_error_status(RouterAbProtocolErrorCode::InvalidLocalServiceConfig),
        );
    };
    let reserved_material = match record.reserved_material() {
        Ok(material) => material.clone(),
        Err(err) => {
            return burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1(
                env,
                runtime,
                materialized.request.request.scope.clone(),
                client_presignature_id.clone(),
                prepare_request_digest,
                now_unix_ms,
                err,
            )
            .await;
        }
    };
    let response = match RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1::new_for_request(
        &materialized.request.request,
        reserved_material.server_presignature_id.clone(),
        reserved_material.server_big_r33_b64u.clone(),
        reserved_material
            .signing_worker_rerandomization_contribution32_b64u
            .clone(),
        now_unix_ms,
    ) {
        Ok(response) => response,
        Err(err) => {
            return burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1(
                env,
                runtime,
                materialized.request.request.scope.clone(),
                client_presignature_id.clone(),
                prepare_request_digest,
                now_unix_ms,
                err,
            )
            .await;
        }
    };
    let prepared = match CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestPreparedV1::new(
        response,
        reserved_material,
        &materialized,
    ) {
        Ok(prepared) => prepared,
        Err(err) => {
            return burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1(
                env,
                runtime,
                materialized.request.request.scope.clone(),
                client_presignature_id.clone(),
                prepare_request_digest,
                now_unix_ms,
                err,
            )
            .await;
        }
    };
    match worker::Response::from_json(&prepared.response) {
        Ok(response) => Ok(response),
        Err(err) => {
            burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1(
                env,
                runtime,
                materialized.request.request.scope,
                client_presignature_id,
                prepare_request_digest,
                now_unix_ms,
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("SigningWorker ECDSA prepare response encoding failed: {err}"),
                ),
            )
            .await
        }
    }
}

/// Handles SigningWorker's private Router A/B ECDSA derivation normal-signing finalize route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_fetch_v1<
    Handler,
>(
    mut request: worker::Request,
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
) -> worker::Result<worker::Response>
where
    Handler: CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
{
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B ECDSA derivation finalize route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH {
        return worker::Response::error(
            format!(
                "Router A/B ECDSA derivation finalize must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B ECDSA derivation finalize JSON parse failed: {err}"),
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
    match replay_cloudflare_signing_worker_ecdsa_terminal_v1(env, &parsed).await {
        Ok(Some(response_json)) => {
            let response = match serde_json::from_str::<
                RouterAbEcdsaDerivationEvmDigestSigningResponseV1,
            >(&response_json)
            {
                Ok(response) => response,
                Err(error) => {
                    return worker::Response::error(
                        format!("SigningWorker ECDSA terminal response JSON is invalid: {error}"),
                        500,
                    );
                }
            };
            if let Err(error) = response.validate_for_request(&parsed.request) {
                return worker::Response::error(
                    format!("{:?}: {}", error.code(), error.message()),
                    cloudflare_router_error_status(error.code()),
                );
            }
            return worker::Response::from_json(&response);
        }
        Ok(None) => {}
        Err(error) => {
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
    }
    match claim_cloudflare_signing_worker_ecdsa_effect_v1(env, &parsed, now_unix_ms).await {
        Ok(CloudflareSigningWorkerNearEffectClaimV1::Claimed) => {}
        Ok(CloudflareSigningWorkerNearEffectClaimV1::Replay { terminal_json }) => {
            let response = match serde_json::from_str::<
                RouterAbEcdsaDerivationEvmDigestSigningResponseV1,
            >(&terminal_json)
            {
                Ok(response) => response,
                Err(error) => {
                    return worker::Response::error(
                        format!("SigningWorker ECDSA terminal response JSON is invalid: {error}"),
                        500,
                    );
                }
            };
            return worker::Response::from_json(&response);
        }
        Ok(CloudflareSigningWorkerNearEffectClaimV1::InProgress) => {
            let error = RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "SigningWorker ECDSA effect is already in progress",
            );
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
        Err(error) => {
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
    }
    // Resolve the exact active lane material before touching one-use pool state.
    // Revoked or stale lane admissions fail before any private pool mutation.
    let (active_signing_worker, material) =
        match load_cloudflare_signing_worker_ecdsa_normal_signing_material_v1(
            env,
            runtime,
            &parsed.request.scope,
            &parsed.material_source,
            now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
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
    let consume_outcome = match execute_cloudflare_signing_worker_ecdsa_pool_mutation_v1(
        env,
        runtime,
        CloudflareSigningWorkerEcdsaPoolCommandV1::Consume {
            scope: parsed.request.scope.clone(),
            server_presignature_id: parsed.request.server_presignature_id.clone(),
            expected_revision: 1,
            request_digest: prepare_request_digest,
            now_unix_ms,
        },
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let server_presignature = match consume_outcome {
        CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Consumed {
            record: _,
            material,
        } => material,
        CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Burned { .. } => {
            return worker::Response::error(
                "SigningWorker ECDSA reservation was terminally burned before finalization",
                cloudflare_router_error_status(RouterAbProtocolErrorCode::ReplayedLocalRequest),
            );
        }
        _ => {
            return worker::Response::error(
                "SigningWorker ECDSA consume returned the wrong lifecycle outcome",
                cloudflare_router_error_status(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                ),
            );
        }
    };
    let effect_operation_key = match parsed.effect_operation_key() {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
    };
    let effect_request_digest = match parsed.effect_request_digest() {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
    };
    let expected_request = parsed.request.clone();
    let signing_result =
        handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1(
            handler,
            now_unix_ms,
            parsed,
            active_signing_worker,
            material,
            server_presignature,
        );
    match signing_result {
        Ok(response) => {
            if let Err(error) = response.validate_for_request(&expected_request) {
                return worker::Response::error(
                    format!("{:?}: {}", error.code(), error.message()),
                    cloudflare_router_error_status(error.code()),
                );
            }
            let response_json = match serde_json::to_string(&response) {
                Ok(value) => value,
                Err(error) => {
                    return worker::Response::error(
                        format!(
                            "SigningWorker ECDSA terminal response serialization failed: {error}"
                        ),
                        500,
                    );
                }
            };
            match commit_cloudflare_signing_worker_terminal_response_v1(
                env,
                &effect_operation_key,
                effect_request_digest,
                &response_json,
                now_unix_ms,
            )
            .await
            {
                Ok(CloudflareSigningWorkerTerminalResponseCommitV1::Committed)
                | Ok(CloudflareSigningWorkerTerminalResponseCommitV1::Replay { .. }) => {
                    worker::Response::from_json(&response)
                }
                Err(error) => worker::Response::error(
                    format!("{:?}: {}", error.code(), error.message()),
                    cloudflare_router_error_status(error.code()),
                ),
            }
        }
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
fn parse_cloudflare_signing_worker_normal_signing_terminal_v1(
    request: &CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    terminal_json: &str,
) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningTerminalV1> {
    let terminal: CloudflareSigningWorkerNormalSigningTerminalV1 =
        serde_json::from_str(terminal_json).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("SigningWorker terminal outcome JSON is invalid: {error}"),
            )
        })?;
    terminal.validate_for_request(request)?;
    Ok(terminal)
}

#[cfg(feature = "workers-rs")]
async fn execute_claimed_cloudflare_signing_worker_normal_signing_v1<Handler>(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
) -> RouterAbProtocolResult<NormalSigningResponseV1>
where
    Handler: CloudflareSigningWorkerNormalSigningFinalizeHandlerV2,
{
    let (active_signing_worker, material) =
        load_cloudflare_signing_worker_normal_signing_material_v1(
            env,
            runtime,
            &request.request.scope,
            &request.material_source,
            now_unix_ms,
        )
        .await?;
    let round1_lookup = CloudflareSigningWorkerRound1LookupV1::new(
        active_signing_worker.clone(),
        request.request.server_round1_handle().to_owned(),
        request.request.round1_binding_digest(),
        now_unix_ms,
    )?;
    let round1_call = runtime.signing_worker_round1_take_request(round1_lookup)?;
    let round1_response =
        execute_cloudflare_signing_worker_private_d1_request_v1(env, &round1_call).await?;
    let server_round1 =
        require_signing_worker_round1_take_response_v1(&round1_call, round1_response)?;
    handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2(
        handler,
        now_unix_ms,
        request,
        active_signing_worker,
        material,
        server_round1,
    )
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_normal_signing_terminal_response_v1(
    terminal: CloudflareSigningWorkerNormalSigningTerminalV1,
) -> worker::Result<worker::Response> {
    match terminal.into_result() {
        Ok(response) => worker::Response::from_json(&response),
        Err(error) => worker::Response::error(
            format!("{:?}: {}", error.code(), error.message()),
            cloudflare_router_error_status(error.code()),
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
    if request.path() != CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH {
        return worker::Response::error(
            format!(
                "Router A/B normal-signing request must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH
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
    let effect_operation_key = match parsed.effect_operation_key() {
        Ok(value) => value,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    let effect_request_digest = match parsed.effect_request_digest() {
        Ok(value) => value,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                cloudflare_router_error_status(err.code()),
            );
        }
    };
    match replay_cloudflare_signing_worker_near_terminal_v1(env, &parsed).await {
        Ok(Some(terminal_json)) => {
            return match parse_cloudflare_signing_worker_normal_signing_terminal_v1(
                &parsed,
                &terminal_json,
            ) {
                Ok(terminal) => {
                    cloudflare_signing_worker_normal_signing_terminal_response_v1(terminal)
                }
                Err(error) => worker::Response::error(
                    format!("{:?}: {}", error.code(), error.message()),
                    cloudflare_router_error_status(error.code()),
                ),
            };
        }
        Ok(None) => {}
        Err(error) => {
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
    }
    if let Err(error) = parsed.request.validate_at(now_unix_ms) {
        return worker::Response::error(
            format!("{:?}: {}", error.code(), error.message()),
            cloudflare_router_error_status(error.code()),
        );
    }
    match claim_cloudflare_signing_worker_near_effect_v1(env, &parsed, now_unix_ms).await {
        Ok(CloudflareSigningWorkerNearEffectClaimV1::Claimed) => {}
        Ok(CloudflareSigningWorkerNearEffectClaimV1::Replay { terminal_json }) => {
            return match parse_cloudflare_signing_worker_normal_signing_terminal_v1(
                &parsed,
                &terminal_json,
            ) {
                Ok(terminal) => {
                    cloudflare_signing_worker_normal_signing_terminal_response_v1(terminal)
                }
                Err(error) => worker::Response::error(
                    format!("{:?}: {}", error.code(), error.message()),
                    cloudflare_router_error_status(error.code()),
                ),
            };
        }
        Ok(CloudflareSigningWorkerNearEffectClaimV1::InProgress) => {
            let error = RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "SigningWorker normal-signing effect is already in progress",
            );
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
        Err(error) => {
            return worker::Response::error(
                format!("{:?}: {}", error.code(), error.message()),
                cloudflare_router_error_status(error.code()),
            );
        }
    }
    let terminal = CloudflareSigningWorkerNormalSigningTerminalV1::from_result(
        execute_claimed_cloudflare_signing_worker_normal_signing_v1(
            env,
            runtime,
            handler,
            now_unix_ms,
            parsed.clone(),
        )
        .await,
    );
    if let Err(error) = terminal.validate_for_request(&parsed) {
        return worker::Response::error(
            format!("{:?}: {}", error.code(), error.message()),
            cloudflare_router_error_status(error.code()),
        );
    }
    let terminal_json = match serde_json::to_string(&terminal) {
        Ok(value) => value,
        Err(error) => {
            return worker::Response::error(
                format!("SigningWorker terminal outcome serialization failed: {error}"),
                500,
            );
        }
    };
    match commit_cloudflare_signing_worker_terminal_response_v1(
        env,
        &effect_operation_key,
        effect_request_digest,
        &terminal_json,
        now_unix_ms,
    )
    .await
    {
        Ok(CloudflareSigningWorkerTerminalResponseCommitV1::Committed) => {
            cloudflare_signing_worker_normal_signing_terminal_response_v1(terminal)
        }
        Ok(CloudflareSigningWorkerTerminalResponseCommitV1::Replay { response_json }) => {
            match parse_cloudflare_signing_worker_normal_signing_terminal_v1(
                &parsed,
                &response_json,
            ) {
                Ok(terminal) => {
                    cloudflare_signing_worker_normal_signing_terminal_response_v1(terminal)
                }
                Err(error) => worker::Response::error(
                    format!("{:?}: {}", error.code(), error.message()),
                    cloudflare_router_error_status(error.code()),
                ),
            }
        }
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles the direct Deriver A peer coordination route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_a_peer_fetch_v1(
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_deriver_peer_fetch_v1(
        CloudflareWorkerRoleV1::DeriverA,
        CLOUDFLARE_DERIVER_A_PEER_REQUEST_PATH,
        key_store,
        handler,
        request,
    )
    .await
}

/// Handles the direct Deriver B peer coordination route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_deriver_b_peer_fetch_v1(
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_deriver_peer_fetch_v1(
        CloudflareWorkerRoleV1::DeriverB,
        CLOUDFLARE_DERIVER_B_PEER_REQUEST_PATH,
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
async fn handle_cloudflare_deriver_peer_fetch_v1(
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
    match handle_cloudflare_deriver_peer_request_v1(worker_role, key_store, handler, parsed) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles one parsed direct A/B peer request through a platform-neutral handler.
pub fn handle_cloudflare_deriver_peer_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    validate_cloudflare_deriver_peer_request_v1(worker_role, &message)?;
    verify_cloudflare_deriver_peer_message_authentication_v1(key_store, &message)?;
    let response = handler.handle_signer_wire_message(message.clone())?;
    validate_cloudflare_deriver_peer_response_v1(worker_role, &message, &response)?;
    verify_cloudflare_deriver_peer_message_authentication_v1(key_store, &response)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_output_activate_response_v1(
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    response: CloudflareSigningWorkerPrivateD1ResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerOutputActivationReceiptV1> {
    response.validate_for_request(request)?;
    let CloudflareSigningWorkerPrivateD1ResponseV1::OutputActivated { receipt } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned wrong response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_output_active_state_get_response_v1(
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    response: CloudflareSigningWorkerPrivateD1ResponseV1,
) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
    response.validate_for_request(request)?;
    let CloudflareSigningWorkerPrivateD1ResponseV1::ActiveState { active_state } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned wrong active-state response branch",
        ));
    };
    Ok(active_state)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_output_material_get_response_v1(
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    response: CloudflareSigningWorkerPrivateD1ResponseV1,
) -> RouterAbProtocolResult<CloudflareServerOutputMaterialRecordV1> {
    response.validate_for_request(request)?;
    let CloudflareSigningWorkerPrivateD1ResponseV1::OutputMaterial { material } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned wrong material response branch",
        ));
    };
    Ok(material)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_round1_put_response_v1(
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    response: CloudflareSigningWorkerPrivateD1ResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerRound1PutReceiptV1> {
    response.validate_for_request(request)?;
    let CloudflareSigningWorkerPrivateD1ResponseV1::Round1Stored { receipt } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned wrong round-1 put response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_round1_take_response_v1(
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    response: CloudflareSigningWorkerPrivateD1ResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerRound1RecordV1> {
    response.validate_for_request(request)?;
    let CloudflareSigningWorkerPrivateD1ResponseV1::Round1Taken { record } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned wrong round-1 response branch",
        ));
    };
    Ok(record)
}

#[cfg(feature = "workers-rs")]
fn require_signing_worker_ecdsa_pool_mutate_response_v1(
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    response: CloudflareSigningWorkerPrivateD1ResponseV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1> {
    response.validate_for_request(request)?;
    let CloudflareSigningWorkerPrivateD1ResponseV1::EcdsaPoolMutated { outcome } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned wrong ECDSA pool mutation response branch",
        ));
    };
    Ok(outcome)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signing_worker_ecdsa_pool_mutation_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    command: CloudflareSigningWorkerEcdsaPoolCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1> {
    let call = runtime.signing_worker_ecdsa_pool_mutate_request(command)?;
    let response = execute_cloudflare_signing_worker_private_d1_request_v1(env, &call).await?;
    require_signing_worker_ecdsa_pool_mutate_response_v1(&call, response)
}

#[cfg(feature = "workers-rs")]
async fn burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1(
    env: &worker::Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    server_presignature_id: String,
    request_digest: PublicDigest32,
    now_unix_ms: u64,
    failure: RouterAbProtocolError,
) -> worker::Result<worker::Response> {
    let cleanup = execute_cloudflare_signing_worker_ecdsa_pool_mutation_v1(
        env,
        runtime,
        CloudflareSigningWorkerEcdsaPoolCommandV1::DestroyReserved {
            scope,
            server_presignature_id,
            expected_revision: 1,
            request_digest,
            reason: TombstoneReason::Rejected,
            now_unix_ms,
        },
    )
    .await;
    let message = match cleanup {
        Ok(CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Finished { .. }) => {
            format!("{:?}: {}", failure.code(), failure.message())
        }
        Ok(_) => format!(
            "{:?}: {}; reservation cleanup returned the wrong lifecycle outcome",
            failure.code(),
            failure.message()
        ),
        Err(cleanup_error) => format!(
            "{:?}: {}; reservation cleanup failed with {:?}: {}",
            failure.code(),
            failure.message(),
            cleanup_error.code(),
            cleanup_error.message()
        ),
    };
    worker::Response::error(message, cloudflare_router_error_status(failure.code()))
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
    let (response, _server_timing) =
        post_service_json_with_server_timing(env, binding_name, url, label, request, None).await?;
    Ok(response)
}

/// As `post_service_json`, but also returns the peer's own `Server-Timing`
/// header so the Router can fold role-local spans into its own (Refactor 94B
/// Phase 0). The header is diagnostics only and never affects the response.
#[cfg(feature = "workers-rs")]
async fn post_service_json_with_server_timing<TReq, TResp>(
    env: &worker::Env,
    binding_name: &str,
    url: &str,
    label: &str,
    request: &TReq,
    trace_id: Option<CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<(TResp, Option<String>)>
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
    if let Some(trace_id) = trace_id {
        set_cloudflare_trace_id_header_v1(&headers, trace_id)?;
    }
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
        let response_body = response.text().await.map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{label} error response body read failed: {err}"),
            )
        })?;
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{label} service returned HTTP status {status}: {}",
                response_body.trim()
            ),
        ));
    }
    // Read before the body is consumed; a missing header is the normal case.
    let server_timing = response.headers().get("Server-Timing").ok().flatten();
    let parsed = response.json::<TResp>().await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response JSON parse failed: {err}"),
        )
    })?;
    Ok((parsed, server_timing))
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    registration_request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    message: &WireMessageV1,
    tenant_root_custody_binding: &CloudflareTenantRootCustodyBindingWireV1,
    trace_id: Option<CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<(
    CloudflareSignerRecipientProofBundleResponseV1,
    Option<String>,
)> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap =
        cloudflare_signer_private_bootstrap_from_ecdsa_derivation_registration_v1(
            peer.peer_role,
            registration_request,
            message.clone(),
        )?;
    let private_request =
        CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1::new(
            peer.peer_role,
            registration_request.clone(),
            signer_bootstrap,
            tenant_root_custody_binding.clone(),
        )?;
    let label = format!(
        "{} Router A/B ECDSA derivation registration service request",
        peer.peer_role.as_str()
    );
    let (response, server_timing): (CloudflareSignerRecipientProofBundleResponseV1, _) =
        post_service_json_with_server_timing(
            env,
            &peer.binding_name,
            cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_url(peer)?,
            &label,
            &private_request,
            trace_id,
        )
        .await?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok((response, server_timing))
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    export_request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
    public_request: &EcdsaThresholdPrfRequestV1,
    message: &WireMessageV1,
    tenant_root_custody_binding: &CloudflareTenantRootCustodyBindingWireV1,
) -> RouterAbProtocolResult<CloudflareSignerClientRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let private_request = CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1::new(
        peer.peer_role,
        export_request.clone(),
        signer_bootstrap,
        tenant_root_custody_binding.clone(),
    )?;
    let label = format!(
        "{} Router A/B ECDSA derivation export service request",
        peer.peer_role.as_str()
    );
    let response: CloudflareSignerClientRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_router_ab_ecdsa_derivation_deriver_export_service_url(peer)?,
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
async fn execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    refresh_request: &RouterAbEcdsaDerivationActivationRefreshRequestV1,
    public_request: &EcdsaThresholdPrfRequestV1,
    message: &WireMessageV1,
    tenant_root_custody_binding: &CloudflareTenantRootCustodyBindingWireV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let signer_bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        peer.peer_role,
        public_request,
        message.clone(),
    )?;
    let private_request =
        CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1::new(
            peer.peer_role,
            refresh_request.clone(),
            signer_bootstrap,
            tenant_root_custody_binding.clone(),
        )?;
    let label = format!(
        "{} Router A/B ECDSA derivation activation-refresh service request",
        peer.peer_role.as_str()
    );
    let response: CloudflareSignerRecipientProofBundleResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_router_ab_ecdsa_derivation_deriver_refresh_service_url(peer)?,
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
async fn execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
    trace_id: Option<CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<(
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1,
    Option<String>,
)> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict Router A/B ECDSA derivation SigningWorker activation must target SigningWorker",
        ));
    }
    request.validate()?;
    let (receipt, server_timing): (
        CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1,
        _,
    ) = post_service_json_with_server_timing(
        env,
        &peer.binding_name,
        cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_url(peer)?,
        "Router A/B ECDSA derivation SigningWorker activation request",
        request,
        trace_id,
    )
    .await?;
    receipt.validate()?;
    Ok((receipt, server_timing))
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1,
) -> RouterAbProtocolResult<CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict Router A/B ECDSA derivation SigningWorker activation refresh must target SigningWorker",
        ));
    }
    request.validate()?;
    let receipt: CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1 =
        post_service_json(
            env,
            &peer.binding_name,
            cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_url(
                peer,
            )?,
            "Router A/B ECDSA derivation SigningWorker activation-refresh request",
            request,
        )
        .await?;
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_export_share_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareSigningWorkerEcdsaExportShareRequestV1,
) -> RouterAbProtocolResult<EcdsaSigningWorkerExportShareEnvelopeV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict Router A/B ECDSA export-share redemption must target SigningWorker",
        ));
    }
    request
        .export_authority
        .validate_for_request(&request.request)?;
    request
        .material_source
        .validate_for_ecdsa_scope(&request.export_authority.normal_signing_scope)?;
    let envelope: EcdsaSigningWorkerExportShareEnvelopeV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_router_ab_ecdsa_derivation_signing_worker_export_share_service_url(peer)?,
        "Router A/B ECDSA SigningWorker export-share request",
        request,
    )
    .await?;
    envelope.validate().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "SigningWorker returned an invalid ECDSA export-share envelope",
        )
    })?;
    Ok(envelope)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_export_preflight_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareSigningWorkerEcdsaExportShareRequestV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaExportPreflightResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict Router A/B ECDSA export preflight must target SigningWorker",
        ));
    }
    request
        .export_authority
        .validate_for_request(&request.request)?;
    request
        .material_source
        .validate_for_ecdsa_scope(&request.export_authority.normal_signing_scope)?;
    let response: CloudflareSigningWorkerEcdsaExportPreflightResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_router_ab_ecdsa_derivation_signing_worker_export_preflight_service_url(peer)?,
        "Router A/B ECDSA SigningWorker export preflight",
        request,
    )
    .await?;
    if !response.ready {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "SigningWorker rejected active ECDSA export material preflight",
        ));
    }
    Ok(response)
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
        &cloudflare_signing_worker_normal_signing_service_url(peer)?,
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
        &cloudflare_signing_worker_normal_signing_round1_prepare_service_url(peer)?,
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

/// Sends one Router A/B ECDSA derivation normal-signing prepare request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1> {
    let mut transport =
        ecdsa_normal_signing_transport::CloudflareWorkerEcdsaNormalSigningServiceTransportV1::new(
            env,
        );
    ecdsa_normal_signing_transport::execute_cloudflare_router_ab_ecdsa_normal_signing_prepare_with_transport_v1(
        &mut transport,
        peer,
        request,
    )
    .await
}

/// Sends one Router A/B ECDSA derivation normal-signing finalize request from Router to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1> {
    let mut transport =
        ecdsa_normal_signing_transport::CloudflareWorkerEcdsaNormalSigningServiceTransportV1::new(
            env,
        );
    ecdsa_normal_signing_transport::execute_cloudflare_router_ab_ecdsa_normal_signing_finalize_with_transport_v1(
        &mut transport,
        peer,
        request,
    )
    .await
}

/// Sends one admitted linked-device ECDSA finalize request to SigningWorker.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signing_worker_linked_device_ecdsa_finalize_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedLinkedDeviceEcdsaFinalizeRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningResponseV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SigningWorker {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "linked ECDSA finalize must target SigningWorker",
        ));
    }
    request.validate()?;
    let response: RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningResponseV1 =
        post_service_json(
            env,
            &peer.binding_name,
            cloudflare_signing_worker_linked_device_ecdsa_finalize_service_url(peer)?,
            "linked ECDSA finalize",
            &request,
        )
        .await?;
    response.validate_for_request(&request.request)?;
    Ok(response)
}

/// Sends one direct A/B peer message over a Cloudflare Service Binding.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_deriver_peer_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    peer.validate()?;
    validate_cloudflare_deriver_peer_request_v1(peer.peer_role, message)?;
    let label = format!("{} peer request", peer.peer_role.as_str());
    let response: WireMessageV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_deriver_peer_service_url(peer)?,
        &label,
        message,
    )
    .await?;
    validate_cloudflare_deriver_peer_response_v1(peer.peer_role, message, &response)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1: &str = "TENANT_ROOT_CONTROL_PLANE";

/// Sends one tenant-root genesis request to the control-plane Worker.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_tenant_root_control_plane_create_tenant_root_service_call_v1(
    env: &worker::Env,
    request: &CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneCreateTenantRootResponseV1> {
    post_service_json(
        env,
        TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
        cloudflare_tenant_root_control_plane_create_tenant_root_service_url(),
        "tenant-root control-plane genesis request",
        request,
    )
    .await
}

/// Sends one tenant-root role-command request to the control-plane Worker.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_tenant_root_control_plane_role_creation_command_service_call_v1(
    env: &worker::Env,
    request: &CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1> {
    let response: CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1 =
        post_service_json(
            env,
            TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
            cloudflare_tenant_root_control_plane_role_creation_command_service_url(),
            "tenant-root control-plane role-command request",
            request,
        )
        .await?;
    if response.role != request.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root control-plane role-command response names the wrong role",
        ));
    }
    Ok(response)
}

/// Requests both issuer-signed role commands for one tenant-root refresh.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_tenant_root_control_plane_refresh_commands_service_call_v1(
    env: &worker::Env,
    request: &CloudflareTenantRootControlPlaneRefreshCommandsRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRefreshCommandsResponseV1> {
    post_service_json(
        env,
        TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
        cloudflare_tenant_root_control_plane_refresh_commands_service_url(),
        "tenant-root control-plane refresh-command request",
        request,
    )
    .await
}

/// Requests an issuer-signed refresh activation receipt for exact public artifacts.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_tenant_root_control_plane_refresh_activation_service_call_v1(
    env: &worker::Env,
    request: &tenant_root_control_plane::CloudflareTenantRootControlPlaneRefreshActivationRequestV1,
) -> RouterAbProtocolResult<
    tenant_root_control_plane::CloudflareTenantRootControlPlaneRefreshActivationReceiptResponseV1,
> {
    post_service_json(
        env,
        TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
        cloudflare_tenant_root_control_plane_refresh_activation_service_url(),
        "tenant-root control-plane refresh-activation request",
        request,
    )
    .await
}

/// Requests one issuer-authorized cleanup command from the control plane.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_tenant_root_control_plane_cleanup_command_service_call_v1(
    env: &worker::Env,
    request: &CloudflareTenantRootControlPlaneCleanupCommandRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneCleanupCommandResponseV1> {
    post_service_json(
        env,
        TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
        cloudflare_tenant_root_control_plane_cleanup_command_service_url(),
        "tenant-root control-plane cleanup-command request",
        request,
    )
    .await
}

/// Sends one tenant-root role-creation request to the peer Deriver over a
/// Cloudflare Service Binding.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_deriver_tenant_root_create_role_share_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootCreateRoleShareRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootCreateRoleShareResponseV1> {
    peer.validate()?;
    post_service_json(
        env,
        &peer.binding_name,
        cloudflare_deriver_tenant_root_create_role_share_service_url(peer)?,
        "tenant-root role creation peer request",
        request,
    )
    .await
}

/// Executes one role-local tenant-root refresh over a Deriver service binding.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_deriver_tenant_root_refresh_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootRefreshRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshResponseV1> {
    peer.validate()?;
    let response: CloudflareDeriverTenantRootRefreshResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_deriver_tenant_root_refresh_service_url(peer)?,
        "tenant-root role refresh request",
        request,
    )
    .await?;
    let expected_role = match peer.peer_role {
        CloudflareWorkerRoleV1::DeriverA => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverA
        }
        CloudflareWorkerRoleV1::DeriverB => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverB
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh can target only a Deriver",
            ));
        }
    };
    if response.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root refresh response names the wrong role",
        ));
    }
    Ok(response)
}

/// Sends one authorized role-share cleanup to its owning Deriver.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_deriver_tenant_root_cleanup_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootCleanupRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootCleanupResponseV1> {
    peer.validate()?;
    let response: CloudflareDeriverTenantRootCleanupResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_deriver_tenant_root_cleanup_service_url(peer)?,
        "tenant-root cleanup request",
        request,
    )
    .await?;
    let expected_role = match peer.peer_role {
        CloudflareWorkerRoleV1::DeriverA => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverA
        }
        CloudflareWorkerRoleV1::DeriverB => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverB
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root cleanup can target only a Deriver",
            ));
        }
    };
    if response.role() != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root cleanup response names the wrong role",
        ));
    }
    Ok(response)
}

/// Sends one exact control-plane activation receipt to its owning Deriver.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootInitialActivationRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootInitialActivationResponseV1> {
    peer.validate()?;
    let response: CloudflareDeriverTenantRootInitialActivationResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_deriver_tenant_root_initial_activation_service_url(peer)?,
        "tenant-root initial activation request",
        request,
    )
    .await?;
    let expected_role = match peer.peer_role {
        CloudflareWorkerRoleV1::DeriverA => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverA
        }
        CloudflareWorkerRoleV1::DeriverB => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverB
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root initial activation can target only a Deriver",
            ));
        }
    };
    if response.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root initial-activation response names the wrong role",
        ));
    }
    let receipt_bytes = decode_base64url_bytes_v1(
        "tenant-root initial-activation terminal receipt",
        &response.activation_terminal_receipt_b64u,
    )?;
    router_ab_core::TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(map_root_share_to_protocol)?;
    Ok(response)
}

/// Sends one exact control-plane refresh-swap receipt to its owning Deriver.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_deriver_tenant_root_refresh_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootRefreshActivationRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshActivationResponseV1> {
    peer.validate()?;
    let response: CloudflareDeriverTenantRootRefreshActivationResponseV1 = post_service_json(
        env,
        &peer.binding_name,
        cloudflare_deriver_tenant_root_refresh_activation_service_url(peer)?,
        "tenant-root refresh activation request",
        request,
    )
    .await?;
    let expected_role = match peer.peer_role {
        CloudflareWorkerRoleV1::DeriverA => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverA
        }
        CloudflareWorkerRoleV1::DeriverB => {
            tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1::DeriverB
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh activation can target only a Deriver",
            ));
        }
    };
    if response.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root refresh-activation response names the wrong role",
        ));
    }
    let receipt_bytes = decode_base64url_bytes_v1(
        "tenant-root refresh-activation terminal receipt",
        &response.activation_terminal_receipt_b64u,
    )?;
    router_ab_core::TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(map_root_share_to_protocol)?;
    Ok(response)
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
        CloudflareWorkerRoleV1::DeriverA => {
            CloudflareWorkerBindingsV1::deriver_a(parse_cloudflare_deriver_a_bindings_v1(env)?)
        }
        CloudflareWorkerRoleV1::DeriverB => {
            CloudflareWorkerBindingsV1::deriver_b(parse_cloudflare_deriver_b_bindings_v1(env)?)
        }
        CloudflareWorkerRoleV1::SigningWorker => CloudflareWorkerBindingsV1::signing_worker(
            parse_cloudflare_signing_worker_bindings_v1(env)?,
        ),
        CloudflareWorkerRoleV1::TenantRootControlPlane => {
            CloudflareWorkerBindingsV1::tenant_root_control_plane(
                parse_cloudflare_tenant_root_control_plane_bindings_v1(env)?,
            )
        }
    }
}

/// Parses tenant-root control-plane Worker bindings from an Env reader.
pub fn parse_cloudflare_tenant_root_control_plane_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneBindingsV1> {
    // The retained public keyset owns active role selection. Its decoder has
    // already proved each selector resolves under its exact role.
    let role_keys = parse_cloudflare_tenant_root_creation_role_verifying_keys_v1(env)?;
    let identities = role_keys.deriver_identities()?;
    let deriver_a_signing_key_id = identities.deriver_a().to_owned();
    let deriver_b_signing_key_id = identities.deriver_b().to_owned();
    let deriver_a_verifying_key = *role_keys.for_role_and_key_id(
        threshold_prf::TwoPartyDeriverRole::DeriverA,
        &deriver_a_signing_key_id,
    )?;
    let deriver_b_verifying_key = *role_keys.for_role_and_key_id(
        threshold_prf::TwoPartyDeriverRole::DeriverB,
        &deriver_b_signing_key_id,
    )?;
    CloudflareTenantRootControlPlaneBindingsV1::new(
        parse_cloudflare_tenant_root_control_plane_issuer_signing_key_binding_v1(
            CloudflareWorkerRoleV1::TenantRootControlPlane,
            env,
        )?,
        parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(env)?,
        parse_cloudflare_tenant_root_creation_grant_authority_verifying_keys_v1(env)?,
        parse_cloudflare_operations_incident_verifier_v1(env)?,
        parse_cloudflare_custody_authority_verifiers_v1(env)?,
        deriver_a_signing_key_id,
        deriver_b_signing_key_id,
        deriver_a_verifying_key,
        deriver_b_verifying_key,
    )
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
        parse_cloudflare_router_admission_bindings_v1(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::DeriverA,
            DERIVER_A_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::DeriverB,
            DERIVER_B_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SigningWorker,
            SIGNING_WORKER_PEER_BINDING_ENV,
        )?,
        parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(env)?,
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
    let project_policy = match env.get_text(ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV)? {
        Some(json) => {
            let json = json.trim().to_owned();
            require_non_empty(ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV, &json)?;
            CloudflareRouterProjectPolicyBindingV1::from_json(&json)?
        }
        None => CloudflareRouterProjectPolicyBindingV1::AllowAll,
    };
    CloudflareRouterAdmissionBindingsV1::new(
        CloudflareRouterJwtVerifierBindingV1::new(
            read_required_env_text(env, ROUTER_JWT_ISSUER_ENV)?,
            read_required_env_text(env, ROUTER_JWT_AUDIENCE_ENV)?,
            read_required_env_text(env, ROUTER_JWT_JWKS_JSON_ENV)?,
        )?,
        project_policy,
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
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
        read_signer_envelope_hpke_public_key(
            env,
            Role::SignerB,
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
    )
}

/// Parses current and optional previous signer-envelope HPKE public keys.
pub fn parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1> {
    let current = parse_cloudflare_signer_envelope_hpke_public_key_set_v1(env)?;
    let previous_keys = [
        DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
        DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
        DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
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
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        )?,
        read_signer_envelope_hpke_public_key(
            env,
            Role::SignerB,
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
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
pub fn parse_cloudflare_deriver_peer_verifying_key_set_v1(
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
        parse_cloudflare_deriver_peer_verifying_key_set_v1(env)?.to_hex_descriptor_set()?,
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
        CloudflareWorkerRoleV1::DeriverA => read_signer_envelope_hpke_decrypt_key_binding(
            env,
            Role::SignerA,
            DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::DeriverB => read_signer_envelope_hpke_decrypt_key_binding(
            env,
            Role::SignerB,
            DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker cannot parse a signer-envelope HPKE decrypt key",
        )),
    }
}

/// Parses the current Worker's role-local signer-envelope HPKE private-key rotation set.
pub fn parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1> {
    let current = parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(worker_role, env)?;
    match worker_role {
        CloudflareWorkerRoleV1::DeriverA => read_signer_envelope_hpke_decrypt_key_binding_set(
            env,
            current,
            Role::SignerA,
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::DeriverB => read_signer_envelope_hpke_decrypt_key_binding_set(
            env,
            current,
            Role::SignerB,
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
        ),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker cannot parse a signer-envelope HPKE decrypt-key rotation set",
        )),
    }
}

/// Parses Deriver A Worker bindings from an Env reader.
pub fn parse_cloudflare_deriver_a_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareDeriverABindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::DeriverA,
        env,
        DERIVER_A_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareDeriverABindingsV1::new(
        parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
            CloudflareWorkerRoleV1::DeriverA,
            env,
        )?,
        read_signer_peer_signing_key_binding(
            env,
            Role::SignerA,
            DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
            DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_verifying_key_set(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::DeriverB,
            DERIVER_B_PEER_BINDING_ENV,
        )?,
        parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(env)?,
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
        read_signing_worker_presign_session_binding(
            env,
            SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
            SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
            SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV,
        )?,
        read_server_output_hpke_decrypt_key_binding(
            env,
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV,
        )?,
    )
}

/// Parses Deriver B Worker bindings from an Env reader.
pub fn parse_cloudflare_deriver_b_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareDeriverBBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::DeriverB,
        env,
        DERIVER_B_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareDeriverBBindingsV1::new(
        parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
            CloudflareWorkerRoleV1::DeriverB,
            env,
        )?,
        read_signer_peer_signing_key_binding(
            env,
            Role::SignerB,
            DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
            DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_verifying_key_set(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::DeriverA,
            DERIVER_A_PEER_BINDING_ENV,
        )?,
        parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(env)?,
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

/// Checks the real Worker Env has every runtime binding required by descriptors.
#[cfg(feature = "workers-rs")]
pub fn validate_cloudflare_worker_env_bindings_v1(
    env: &worker::Env,
    bindings: &CloudflareWorkerBindingsV1,
) -> RouterAbProtocolResult<()> {
    match bindings {
        CloudflareWorkerBindingsV1::Router { bindings } => {
            require_worker_service(env, &bindings.deriver_a)?;
            require_worker_service(env, &bindings.deriver_b)?;
            require_worker_service(env, &bindings.signing_worker)
        }
        CloudflareWorkerBindingsV1::DeriverA { bindings } => {
            require_worker_hpke_secret_set(env, &bindings.envelope_decrypt_key)?;
            require_worker_peer_signing_secret(env, &bindings.peer_signing_key)?;
            require_worker_service(env, &bindings.deriver_b)
        }
        CloudflareWorkerBindingsV1::DeriverB { bindings } => {
            require_worker_hpke_secret_set(env, &bindings.envelope_decrypt_key)?;
            require_worker_peer_signing_secret(env, &bindings.peer_signing_key)?;
            require_worker_service(env, &bindings.deriver_a)
        }
        CloudflareWorkerBindingsV1::SigningWorker { bindings } => {
            require_worker_durable_object(env, &bindings.presign_session)?;
            require_worker_server_output_hpke_secret(env, &bindings.server_output_decrypt_key)
        }
        CloudflareWorkerBindingsV1::TenantRootControlPlane { bindings } => {
            require_worker_secret_binding_name(env, bindings.issuer_signing_key.binding_name())
        }
    }
}

fn map_router_ab_ecdsa_derivation_error_v1(
    err: router_ab_ecdsa_derivation::RouterAbEcdsaDerivationError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!(
            "Router A/B ECDSA derivation material validation failed: {}",
            err.message
        ),
    )
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
            decode_and_validate_cloudflare_deriver_peer_message_payload_v1(message)?;
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
    let payload = decode_and_validate_cloudflare_deriver_peer_message_payload_v1(message)?;
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
        CloudflareWorkerRoleV1::DeriverA => Ok(WireMessageKindV1::RouterToSignerA),
        CloudflareWorkerRoleV1::DeriverB => Ok(WireMessageKindV1::RouterToSignerB),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker has no private signer request kind",
        )),
    }
}

fn cloudflare_worker_signer_role_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<Role> {
    match worker_role {
        CloudflareWorkerRoleV1::DeriverA => Ok(Role::SignerA),
        CloudflareWorkerRoleV1::DeriverB => Ok(Role::SignerB),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker has no signer plaintext role",
        )),
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
            CloudflareWorkerRoleV1::DeriverB,
        ),
        Role::SignerB => (
            signer_set.signer_b.clone(),
            signer_set.signer_a.clone(),
            CloudflareWorkerRoleV1::DeriverA,
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
        CloudflareWorkerRoleV1::DeriverA => Ok(WireMessageKindV1::SignerBToSignerA),
        CloudflareWorkerRoleV1::DeriverB => Ok(WireMessageKindV1::SignerAToSignerB),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker has no direct A/B peer request kind",
        )),
    }
}

fn expected_signer_peer_response_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::DeriverA => Ok(WireMessageKindV1::SignerAToSignerB),
        CloudflareWorkerRoleV1::DeriverB => Ok(WireMessageKindV1::SignerBToSignerA),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "this Worker has no direct A/B peer response kind",
        )),
    }
}

fn read_signing_worker_presign_session_binding(
    env: &impl CloudflareEnvReaderV1,
    binding_name_key: &str,
    object_name_key: &str,
    key_prefix_key: &str,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPresignSessionBindingV1> {
    CloudflareSigningWorkerPresignSessionBindingV1::new(
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
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
        )?,
        read_signer_peer_verifying_key_bytes(
            env,
            Role::SignerB,
            DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
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
    binding: &CloudflareSigningWorkerPresignSessionBindingV1,
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

#[cfg(feature = "workers-rs")]
fn load_cloudflare_deriver_peer_signing_key_bytes_v1(
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
    let key = decode_cloudflare_deriver_peer_signing_key_v1(&secret_value);
    secret_value.zeroize();
    key
}

#[cfg(feature = "workers-rs")]
fn decode_cloudflare_deriver_peer_signing_key_v1(
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
        | RouterAbProtocolErrorCode::InvalidLocalHttpRequest
        | RouterAbProtocolErrorCode::InvalidLocalRoute
        | RouterAbProtocolErrorCode::MalformedWirePayload
        | RouterAbProtocolErrorCode::UnsupportedVectorVersion => 400,
        RouterAbProtocolErrorCode::ExpiredLocalRequest
        | RouterAbProtocolErrorCode::PairPreparationExpired => 408,
        RouterAbProtocolErrorCode::ReplayedLocalRequest
        | RouterAbProtocolErrorCode::ConflictingPair
        | RouterAbProtocolErrorCode::MissingPairPreparation => 409,
        RouterAbProtocolErrorCode::MissingLocalBinding
        | RouterAbProtocolErrorCode::ForbiddenLocalBinding
        | RouterAbProtocolErrorCode::InvalidLocalServiceConfig => 500,
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_now_unix_ms_v1() -> RouterAbProtocolResult<u64> {
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
    if len > CLOUDFLARE_DERIVER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
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

#[cfg(feature = "workers-rs")]
fn map_cloudflare_tenant_root_role_store_error_v1(
    operation: &'static str,
    error: worker::Error,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("{operation} failed: {error}"),
    )
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
    use hpke_ng::Kem;
    use rand_core::{CryptoRng, RngCore};
    use router_ab_core::{
        decode_recipient_proof_bundle_payload_v1,
        verify_recipient_proof_bundle_ciphertext_payload_v1, EcdsaThresholdPrfProofBatchPayloadV1,
        MpcPrfDleqProofWireV1, MpcPrfPartialBindingV1, MpcPrfPartialProofBundleV1,
        MpcPrfPartialWireV1, MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialV1,
        MpcPrfStableProofBundleWireV2, MpcPrfStableRecipientProofBundlePayloadV2, OpenedShareKind,
        RecipientProofBundleEncryptionRequestV1, RecipientProofBundlePayloadV1, RootShareEpoch,
        SecretMaterial32, SignerIdentityV1, TenantRootProtocolDigestV1,
        MPC_PRF_COMMITMENT_WIRE_V1_LEN, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
        MPC_PRF_PARTIAL_WIRE_V1_LEN,
    };
    use threshold_prf::PrfPurpose;

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
    fn cloudflare_hpke_stable_recipient_proof_bundle_round_trips() {
        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x45; 32]).expect("recipient keypair derives");
        let recipient_public_key = format!(
            "x25519:{}",
            lower_hex(&CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key))
        );
        let payload = MpcPrfStableRecipientProofBundlePayloadV2::new(
            signer(Role::SignerA, "signer-a"),
            Role::Client,
            "client",
            MpcPrfStableProofBundleWireV2::new(
                TenantRootProtocolDigestV1::from_bytes([0x31; 32]).expect("stable context digest"),
                TenantRootProtocolDigestV1::from_bytes([0x32; 32]).expect("custody binding digest"),
                PrfPurpose::RouterAbXClientBaseV1,
                Role::SignerA,
                MpcPrfPartialWireV1::new(fixed_share_wire_bytes(
                    Role::SignerA,
                    0x33,
                    MPC_PRF_PARTIAL_WIRE_V1_LEN,
                ))
                .expect("partial wire"),
                MpcPrfShareCommitmentWireV1::new(fixed_share_wire_bytes(
                    Role::SignerA,
                    0x34,
                    MPC_PRF_COMMITMENT_WIRE_V1_LEN,
                ))
                .expect("commitment wire"),
                MpcPrfDleqProofWireV1::new(vec![0x35; MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN])
                    .expect("proof wire"),
            )
            .expect("stable proof bundle"),
        )
        .expect("stable recipient payload");
        let outer_transcript_digest = digest(0x36);
        let request = RecipientProofBundleEncryptionRequestV1::new_stable_v2(
            &payload,
            recipient_public_key,
            outer_transcript_digest,
        )
        .expect("stable encryption request");
        let envelope = CloudflareHpkeRecipientProofBundleEncryptorV1::new()
            .encrypt_recipient_proof_bundle_v1(request)
            .expect("stable proof bundle encrypts");
        let private_key_bytes = CloudflareHpkeKemV1::sk_to_bytes(&recipient_private_key);
        let opened = open_cloudflare_recipient_proof_bundle_hpke_payload_v2(
            &envelope,
            &private_key_bytes,
            outer_transcript_digest,
        )
        .expect("stable proof bundle opens");

        assert_eq!(opened, payload);
        assert!(open_cloudflare_recipient_proof_bundle_hpke_payload_v2(
            &envelope,
            &private_key_bytes,
            digest(0x37),
        )
        .is_err());
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
            "a0be1fffdc55037c8495f239a82ce4a070cbcfc709b5703f734622b1ed69ed14",
            "fc224de9de6249ee85247b35862adea0d6d91e765c76a3b70be8f764854a5dd2",
            "22ea885ef86dc7aac8a70eb429913222a57c37be10c148249bb630abed09c6c0",
            "a4196d23ce10f98d0fb9990633fa04241f074d800d671a8c85099637a0ec20a2",
            "25dcc961eff9519b18d8c27f3d89c45d06d11b1ba8da326dcd86762197414e1d",
            "35bc6c5ef0fdeef2b96823a31180b164e79360a9dd60e2e526094ccf4a25ea3a",
            "2beda19132251de82ab37afb0eed9f996c7877f180653085dd10e929fcd399eb",
            "f2f604a260e456fbd68ec510629e3935ea472215714ece038b9254d89c5f9ceb",
            "43117d9cfdb97be3ef50c27fd86f188cd2a5d6c7589536b989bb601572df6a47",
            "62cb0acab07966d0f16d426f3e525268143c7e2183efae6030352c905b94bd07",
            "3068930531b6f05f57375663137041267faf7bbaf9501812ca9ba3cad9a6f4f9",
            "9bad2ad7d8b59d8f7fedb1c8bd0a318fcd34798e12b7db182640e6cf420eca20",
            "5d6beaed924ee6606b714463e4725627cae7d96103c70a1fbe6df33c4e9d2325",
            "633052c652e19c9fc976a2a7aaef602265ab43f65a00a63e346962acdfb169a3",
            "bb271a812f5c2c3947bf08f91a5079daa1710ecc86eec5319e0632d7db37536c",
            "1165861fca386a977109050b6e5b45e3d63d014e30a8e87e1ebb2e67ac6a4814",
            "301ed9b1d0a53021c0311c77e2f71d5b5f7f04b2a2fd827d19ce80df21574607",
            "8e24f07ea871b5f783b4ca646fbc",
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

    #[test]
    fn ecdsa_export_private_authorization_matches_public_branch() {
        let evidence_set_digest =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x52; 32]);
        let public_step_up =
            NormalSigningAuthorizationV1::operation_step_up().expect("operation step-up marker");
        let private_step_up = CloudflareSigningWorkerEcdsaExportAuthorizationV1::OperationStepUp {
            evidence_set_digest: evidence_set_digest.clone(),
        };
        private_step_up
            .validate_for_public_authorization(&public_step_up)
            .expect("private evidence binds to operation step-up marker");
        assert_eq!(
            private_step_up.binding_authorization_kind(),
            "verified_step_up"
        );
        assert_eq!(private_step_up.authorization_id(), evidence_set_digest);

        let hostile_branch =
            CloudflareSigningWorkerEcdsaExportAuthorizationV1::ReusableWalletSession {
                wallet_session_id: "wallet-session-1".to_owned(),
            };
        let error = hostile_branch
            .validate_for_public_authorization(&public_step_up)
            .expect_err("reusable private authority must not substitute for step-up");
        assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

        let malformed_digest = CloudflareSigningWorkerEcdsaExportAuthorizationV1::OperationStepUp {
            evidence_set_digest: "malformed".to_owned(),
        };
        let error = malformed_digest
            .validate_for_public_authorization(&public_step_up)
            .expect_err("private evidence digest must be a fixed digest");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
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
        let proof_batch = EcdsaThresholdPrfProofBatchPayloadV1::new(
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

    fn fixed_share_wire_bytes(role: Role, fill: u8, len: usize) -> Vec<u8> {
        let share_id = match role {
            Role::SignerA => 1u16,
            Role::SignerB => 2u16,
            _ => panic!("fixed share wire requires a Deriver role"),
        };
        let mut bytes = vec![fill; len];
        bytes[..2].copy_from_slice(&share_id.to_be_bytes());
        bytes
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
            MpcPrfPartialWireV1::new(fixed_share_wire_bytes(
                signer_role,
                seed,
                MPC_PRF_PARTIAL_WIRE_V1_LEN,
            ))
            .expect("partial wire"),
        )
        .expect("signer partial");
        MpcPrfPartialProofBundleV1::new(
            signer_partial,
            MpcPrfShareCommitmentWireV1::new(fixed_share_wire_bytes(
                signer_role,
                seed.wrapping_add(1),
                MPC_PRF_COMMITMENT_WIRE_V1_LEN,
            ))
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
