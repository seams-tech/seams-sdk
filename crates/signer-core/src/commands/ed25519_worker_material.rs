use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[cfg(feature = "near-crypto")]
use {
    base64ct::{Base64UrlUnpadded, Encoding},
    chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Nonce,
    },
    hkdf::Hkdf,
    serde_json::Value,
    sha2::{Digest, Sha256},
    std::collections::BTreeMap,
    zeroize::Zeroize,
};

#[cfg(feature = "near-crypto")]
use crate::error::{CoreResult, SignerCoreError};

#[cfg(feature = "near-crypto")]
pub const ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE: usize = 12;
#[cfg(feature = "near-crypto")]
pub const ED25519_WORKER_MATERIAL_CHACHA20_KEY_SIZE: usize = 32;
#[cfg(feature = "near-crypto")]
pub const ED25519_WORKER_MATERIAL_KDF_INFO: &[u8] = b"seams-ed25519-worker-material-v1";
#[cfg(feature = "near-crypto")]
pub const ED25519_WORKER_MATERIAL_STORAGE_REF_PREFIX: &str = "ed25519-worker-material-v1:";
#[cfg(feature = "near-crypto")]
const ED25519_WORKER_MATERIAL_PLAINTEXT_PREFIX: &[u8] = b"seams-ed25519-worker-material-v1:";
#[cfg(feature = "near-crypto")]
const ED25519_WORKER_MATERIAL_SHARE_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialFormatVersion")]
pub enum Ed25519WorkerMaterialFormatVersionV1 {
    #[serde(rename = "ed25519_worker_material_v1")]
    #[ts(rename = "ed25519_worker_material_v1")]
    Ed25519WorkerMaterialV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(rename = "Ed25519WorkerMaterialCurve", rename_all = "lowercase")]
pub enum Ed25519WorkerMaterialCurveV1 {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialProtocol")]
pub enum Ed25519WorkerMaterialProtocolV1 {
    #[serde(rename = "router_ab_normal_signing")]
    #[ts(rename = "router_ab_normal_signing")]
    RouterAbNormalSigning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialAeadAlgorithm")]
pub enum Ed25519WorkerMaterialAeadAlgorithmV1 {
    #[serde(rename = "chacha20poly1305")]
    #[ts(rename = "chacha20poly1305")]
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialKdfAlgorithm")]
pub enum Ed25519WorkerMaterialKdfAlgorithmV1 {
    #[serde(rename = "hkdf_sha256")]
    #[ts(rename = "hkdf_sha256")]
    HkdfSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialKeyIdentityKind")]
pub enum Ed25519WorkerMaterialKeyIdentityKindV1 {
    #[serde(rename = "ed25519_worker_material_key_identity_v1")]
    #[ts(rename = "ed25519_worker_material_key_identity_v1")]
    Ed25519WorkerMaterialKeyIdentityV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialBindingKind")]
pub enum Ed25519WorkerMaterialBindingKindV1 {
    #[serde(rename = "ed25519_worker_material_binding_v1")]
    #[ts(rename = "ed25519_worker_material_binding_v1")]
    Ed25519WorkerMaterialBindingV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519WorkerMaterialSessionBindingKind")]
pub enum Ed25519WorkerMaterialSessionBindingKindV1 {
    #[serde(rename = "ed25519_worker_material_session_binding_v1")]
    #[ts(rename = "ed25519_worker_material_session_binding_v1")]
    Ed25519WorkerMaterialSessionBindingV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519SealedWorkerMaterialKind")]
pub enum Ed25519SealedWorkerMaterialKindV1 {
    #[serde(rename = "ed25519_sealed_worker_material_v1")]
    #[ts(rename = "ed25519_sealed_worker_material_v1")]
    Ed25519SealedWorkerMaterialV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519SealedWorkerMaterialAadKind")]
pub enum Ed25519SealedWorkerMaterialAadKindV1 {
    #[serde(rename = "ed25519_sealed_worker_material_aad_v1")]
    #[ts(rename = "ed25519_sealed_worker_material_aad_v1")]
    Ed25519SealedWorkerMaterialAadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519WorkerMaterialKeyIdentity", rename_all = "camelCase")]
pub struct Ed25519WorkerMaterialKeyIdentityV1 {
    pub kind: Ed25519WorkerMaterialKeyIdentityKindV1,
    pub near_account_id: String,
    pub signer_slot: u32,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub relayer_key_id: String,
    pub key_version: String,
    pub material_format_version: Ed25519WorkerMaterialFormatVersionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519WorkerMaterialBinding", rename_all = "camelCase")]
pub struct Ed25519WorkerMaterialBindingV1 {
    pub kind: Ed25519WorkerMaterialBindingKindV1,
    pub curve: Ed25519WorkerMaterialCurveV1,
    pub protocol: Ed25519WorkerMaterialProtocolV1,
    pub near_account_id: String,
    pub signer_slot: u32,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub relayer_key_id: String,
    pub key_version: String,
    pub participant_ids: Vec<u32>,
    pub client_verifying_share_b64u: String,
    pub material_format_version: Ed25519WorkerMaterialFormatVersionV1,
    pub material_key_id: String,
    #[ts(type = "number")]
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "ThresholdRuntimePolicyScope", rename_all = "camelCase")]
pub struct ThresholdRuntimePolicyScopeV1 {
    pub org_id: String,
    pub project_id: String,
    pub env_id: String,
    pub signing_root_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519WorkerMaterialSessionBinding",
    rename_all = "camelCase"
)]
pub struct Ed25519WorkerMaterialSessionBindingV1 {
    pub kind: Ed25519WorkerMaterialSessionBindingKindV1,
    pub material_binding_digest: String,
    pub near_account_id: String,
    pub signer_slot: u32,
    pub threshold_session_id: String,
    pub signing_grant_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub runtime_policy_scope: ThresholdRuntimePolicyScopeV1,
    pub relayer_key_id: String,
    pub key_version: String,
    pub participant_ids: Vec<u32>,
    pub signing_worker_id: String,
    #[ts(type = "number")]
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519WorkerMaterialAead", rename_all = "camelCase")]
pub struct Ed25519WorkerMaterialAeadV1 {
    pub algorithm: Ed25519WorkerMaterialAeadAlgorithmV1,
    pub nonce_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519WorkerMaterialKdf", rename_all = "camelCase")]
pub struct Ed25519WorkerMaterialKdfV1 {
    pub algorithm: Ed25519WorkerMaterialKdfAlgorithmV1,
    pub salt_b64u: String,
    pub info: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519SealedWorkerMaterial", rename_all = "camelCase")]
pub struct Ed25519SealedWorkerMaterialV1 {
    pub kind: Ed25519SealedWorkerMaterialKindV1,
    pub material_format_version: Ed25519WorkerMaterialFormatVersionV1,
    pub material_binding_digest: String,
    pub binding: Ed25519WorkerMaterialBindingV1,
    pub sealed_material_b64u: String,
    pub aead: Ed25519WorkerMaterialAeadV1,
    pub kdf: Ed25519WorkerMaterialKdfV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519SealedWorkerMaterialAad", rename_all = "camelCase")]
pub struct Ed25519SealedWorkerMaterialAadV1 {
    pub kind: Ed25519SealedWorkerMaterialAadKindV1,
    pub material_format_version: Ed25519WorkerMaterialFormatVersionV1,
    pub material_binding_digest: String,
    pub binding: Ed25519WorkerMaterialBindingV1,
    pub aead_algorithm: Ed25519WorkerMaterialAeadAlgorithmV1,
    pub kdf_algorithm: Ed25519WorkerMaterialKdfAlgorithmV1,
    pub kdf_info: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[ts(
    rename = "Ed25519SealedWorkerMaterialTransport",
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum Ed25519SealedWorkerMaterialTransportV1 {
    StorageRef {
        sealed_worker_material_ref: String,
    },
    InlineSealedBlob {
        sealed_worker_material_ref: String,
        sealed_worker_material_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[ts(
    rename = "Ed25519WorkerMaterialCredentialAuthorization",
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum Ed25519WorkerMaterialCredentialAuthorizationV1 {
    PasskeyPrfMaterialAuthorizationHandleV1 {
        handle: String,
        purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
        rp_id: String,
        credential_id_b64u: String,
        material_binding_digest: String,
        #[ts(type = "number")]
        expires_at_ms: u64,
    },
    RecoveryCodeMaterialAuthorizationHandleV1 {
        handle: String,
        purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
        auth_subject_id: String,
        recovery_code_binding_digest: String,
        material_binding_digest: String,
        #[ts(type = "number")]
        expires_at_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(
    rename = "Ed25519WorkerMaterialCredentialAuthorizationPurpose",
    rename_all = "snake_case"
)]
pub enum Ed25519WorkerMaterialCredentialAuthorizationPurposeV1 {
    Seal,
    Unseal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename = "Ed25519WorkerMaterialErrorCode", rename_all = "snake_case")]
pub enum Ed25519WorkerMaterialErrorCodeV1 {
    MaterialRestoreRequired,
    MaterialSealAuthorizationRequired,
    MaterialUnsealAuthorizationRequired,
    MaterialRestoreExpired,
    MaterialBindingMismatch,
    MaterialScopeMismatch,
    MaterialHandleNotLoaded,
    MaterialCorrupt,
    WorkerUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519WorkerMaterialFailure", rename_all = "camelCase")]
pub struct Ed25519WorkerMaterialFailureV1 {
    pub ok: bool,
    pub code: Ed25519WorkerMaterialErrorCodeV1,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519WorkerMaterialStored", rename_all = "camelCase")]
pub struct Ed25519WorkerMaterialStoredV1 {
    pub ok: bool,
    pub material_handle: String,
    pub material_binding_digest: String,
    pub client_verifying_share_b64u: String,
    pub sealed_worker_material_ref: String,
    pub sealed_worker_material_b64u: String,
    pub material_format_version: Ed25519WorkerMaterialFormatVersionV1,
    pub material_key_id: String,
    pub signer_slot: u32,
    pub key_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519ValidateWorkerMaterialSuccess",
    rename_all = "camelCase"
)]
pub struct Ed25519ValidateWorkerMaterialSuccessV1 {
    pub ok: bool,
    pub material_handle: String,
    pub material_binding_digest: String,
    pub client_verifying_share_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519CreateClientPresignFromWorkerMaterialSuccess",
    rename_all = "camelCase"
)]
pub struct Ed25519CreateClientPresignFromWorkerMaterialSuccessV1 {
    pub ok: bool,
    pub presign_nonce_handle: String,
    pub client_commitments_message_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519SignClientPresignFromWorkerMaterialSuccess",
    rename_all = "camelCase"
)]
pub struct Ed25519SignClientPresignFromWorkerMaterialSuccessV1 {
    pub ok: bool,
    pub client_signature_share_message_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519PutSealedWorkerMaterialSuccess",
    rename_all = "camelCase"
)]
pub struct Ed25519PutSealedWorkerMaterialSuccessV1 {
    pub ok: bool,
    pub sealed_worker_material_ref: String,
    pub material_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519ReadSealedWorkerMaterialSuccess",
    rename_all = "camelCase"
)]
pub struct Ed25519ReadSealedWorkerMaterialSuccessV1 {
    pub ok: bool,
    pub sealed_material: Ed25519SealedWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519DeleteSealedWorkerMaterialSuccess",
    rename_all = "camelCase"
)]
pub struct Ed25519DeleteSealedWorkerMaterialSuccessV1 {
    pub ok: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519StoreWorkerMaterialFromHssOutputRequestKind")]
pub enum Ed25519StoreWorkerMaterialFromHssOutputRequestKindV1 {
    #[serde(rename = "ed25519_store_worker_material_from_hss_output_v1")]
    #[ts(rename = "ed25519_store_worker_material_from_hss_output_v1")]
    Ed25519StoreWorkerMaterialFromHssOutputV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[ts(
    rename = "Ed25519HssClientOutputMaskTransport",
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum Ed25519HssClientOutputMaskTransportV1 {
    RustOwnedMaskHandleV1 { client_output_mask_handle: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519StoreWorkerMaterialFromHssOutputRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519StoreWorkerMaterialFromHssOutputRequestV1 {
    pub kind: Ed25519StoreWorkerMaterialFromHssOutputRequestKindV1,
    pub evaluator_driver_state_b64u: String,
    pub client_output_message_b64u: String,
    pub client_output_mask: Ed25519HssClientOutputMaskTransportV1,
    pub material_binding: Ed25519WorkerMaterialBindingV1,
    pub seal_authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519RestoreWorkerMaterialRequestKind")]
pub enum Ed25519RestoreWorkerMaterialRequestKindV1 {
    #[serde(rename = "ed25519_restore_worker_material_v1")]
    #[ts(rename = "ed25519_restore_worker_material_v1")]
    Ed25519RestoreWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519RestoreWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519RestoreWorkerMaterialRequestV1 {
    pub kind: Ed25519RestoreWorkerMaterialRequestKindV1,
    pub sealed_material: Ed25519SealedWorkerMaterialTransportV1,
    pub expected_material_binding: Ed25519WorkerMaterialBindingV1,
    pub unseal_authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519ValidateWorkerMaterialRequestKind")]
pub enum Ed25519ValidateWorkerMaterialRequestKindV1 {
    #[serde(rename = "ed25519_validate_worker_material_v1")]
    #[ts(rename = "ed25519_validate_worker_material_v1")]
    Ed25519ValidateWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519ValidateWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519ValidateWorkerMaterialRequestV1 {
    pub kind: Ed25519ValidateWorkerMaterialRequestKindV1,
    pub material_handle: String,
    pub expected_material_binding: Ed25519WorkerMaterialBindingV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519CreateClientPresignFromWorkerMaterialRequestKind")]
pub enum Ed25519CreateClientPresignFromWorkerMaterialRequestKindV1 {
    #[serde(rename = "ed25519_create_client_presign_from_worker_material_v1")]
    #[ts(rename = "ed25519_create_client_presign_from_worker_material_v1")]
    Ed25519CreateClientPresignFromWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519CreateClientPresignFromWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519CreateClientPresignFromWorkerMaterialRequestV1 {
    pub kind: Ed25519CreateClientPresignFromWorkerMaterialRequestKindV1,
    pub material_handle: String,
    pub expected_material_binding: Ed25519WorkerMaterialBindingV1,
    pub expected_session_binding: Ed25519WorkerMaterialSessionBindingV1,
    pub expected_session_binding_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519SignClientPresignFromWorkerMaterialRequestKind")]
pub enum Ed25519SignClientPresignFromWorkerMaterialRequestKindV1 {
    #[serde(rename = "ed25519_sign_client_presign_from_worker_material_v1")]
    #[ts(rename = "ed25519_sign_client_presign_from_worker_material_v1")]
    Ed25519SignClientPresignFromWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519SignClientPresignFromWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519SignClientPresignFromWorkerMaterialRequestV1 {
    pub kind: Ed25519SignClientPresignFromWorkerMaterialRequestKindV1,
    pub material_handle: String,
    pub expected_material_binding: Ed25519WorkerMaterialBindingV1,
    pub expected_session_binding: Ed25519WorkerMaterialSessionBindingV1,
    pub expected_session_binding_digest: String,
    pub signing_payload_b64u: String,
    pub server_commitments: Ed25519ServerCommitmentsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "Ed25519ServerCommitments", rename_all = "camelCase")]
pub struct Ed25519ServerCommitmentsV1 {
    pub hiding_b64u: String,
    pub binding_b64u: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519PutSealedWorkerMaterialRequestKind")]
pub enum Ed25519PutSealedWorkerMaterialRequestKindV1 {
    #[serde(rename = "put_threshold_ed25519_sealed_worker_material_v1")]
    #[ts(rename = "put_threshold_ed25519_sealed_worker_material_v1")]
    PutThresholdEd25519SealedWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519PutSealedWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519PutSealedWorkerMaterialRequestV1 {
    pub kind: Ed25519PutSealedWorkerMaterialRequestKindV1,
    pub sealed_material: Ed25519SealedWorkerMaterialV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519ReadSealedWorkerMaterialRequestKind")]
pub enum Ed25519ReadSealedWorkerMaterialRequestKindV1 {
    #[serde(rename = "read_threshold_ed25519_sealed_worker_material_v1")]
    #[ts(rename = "read_threshold_ed25519_sealed_worker_material_v1")]
    ReadThresholdEd25519SealedWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519ReadSealedWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519ReadSealedWorkerMaterialRequestV1 {
    pub kind: Ed25519ReadSealedWorkerMaterialRequestKindV1,
    pub sealed_worker_material_ref: String,
    pub expected_material_binding_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "Ed25519DeleteSealedWorkerMaterialRequestKind")]
pub enum Ed25519DeleteSealedWorkerMaterialRequestKindV1 {
    #[serde(rename = "delete_threshold_ed25519_sealed_worker_material_v1")]
    #[ts(rename = "delete_threshold_ed25519_sealed_worker_material_v1")]
    DeleteThresholdEd25519SealedWorkerMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "Ed25519DeleteSealedWorkerMaterialRequest",
    rename_all = "camelCase"
)]
pub struct Ed25519DeleteSealedWorkerMaterialRequestV1 {
    pub kind: Ed25519DeleteSealedWorkerMaterialRequestKindV1,
    pub sealed_worker_material_ref: String,
    pub expected_material_binding_digest: String,
}

#[cfg(feature = "near-crypto")]
fn normalize_canonical_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(normalize_canonical_json_value)
                .collect(),
        ),
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(key, value)| (key, normalize_canonical_json_value(value)))
                .collect();
            let mut normalized = serde_json::Map::new();
            for (key, value) in sorted {
                normalized.insert(key, value);
            }
            Value::Object(normalized)
        }
        scalar => scalar,
    }
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_canonical_json<T: Serialize>(value: &T) -> CoreResult<String> {
    let value = serde_json::to_value(value).map_err(|error| {
        SignerCoreError::encode_error(format!("Failed to encode canonical JSON value: {error}"))
    })?;
    serde_json::to_string(&normalize_canonical_json_value(value)).map_err(|error| {
        SignerCoreError::encode_error(format!("Failed to stringify canonical JSON value: {error}"))
    })
}

#[cfg(feature = "near-crypto")]
fn sha256_b64u(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    Base64UrlUnpadded::encode_string(&digest)
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_digest_b64u<T: Serialize>(value: &T) -> CoreResult<String> {
    let canonical = ed25519_worker_material_canonical_json(value)?;
    Ok(sha256_b64u(canonical.as_bytes()))
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_key_id(
    identity: &Ed25519WorkerMaterialKeyIdentityV1,
) -> CoreResult<String> {
    ed25519_worker_material_digest_b64u(identity)
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_binding_digest(
    binding: &Ed25519WorkerMaterialBindingV1,
) -> CoreResult<String> {
    ed25519_worker_material_digest_b64u(binding)
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_session_binding_digest(
    binding: &Ed25519WorkerMaterialSessionBindingV1,
) -> CoreResult<String> {
    ed25519_worker_material_digest_b64u(binding)
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_aad_bytes(
    aad: &Ed25519SealedWorkerMaterialAadV1,
) -> CoreResult<Vec<u8>> {
    Ok(ed25519_worker_material_canonical_json(aad)?.into_bytes())
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_key_identity_from_binding(
    binding: &Ed25519WorkerMaterialBindingV1,
) -> Ed25519WorkerMaterialKeyIdentityV1 {
    Ed25519WorkerMaterialKeyIdentityV1 {
        kind: Ed25519WorkerMaterialKeyIdentityKindV1::Ed25519WorkerMaterialKeyIdentityV1,
        near_account_id: binding.near_account_id.clone(),
        signer_slot: binding.signer_slot,
        signing_root_id: binding.signing_root_id.clone(),
        signing_root_version: binding.signing_root_version.clone(),
        relayer_key_id: binding.relayer_key_id.clone(),
        key_version: binding.key_version.clone(),
        material_format_version: binding.material_format_version,
    }
}

#[cfg(feature = "near-crypto")]
pub fn validate_ed25519_worker_material_binding(
    binding: &Ed25519WorkerMaterialBindingV1,
) -> CoreResult<String> {
    require_non_empty_string(&binding.near_account_id, "binding.nearAccountId")?;
    require_non_empty_string(&binding.signing_root_id, "binding.signingRootId")?;
    require_non_empty_string(&binding.signing_root_version, "binding.signingRootVersion")?;
    require_non_empty_string(&binding.relayer_key_id, "binding.relayerKeyId")?;
    require_non_empty_string(&binding.key_version, "binding.keyVersion")?;
    require_non_empty_string(
        &binding.client_verifying_share_b64u,
        "binding.clientVerifyingShareB64u",
    )?;
    if binding.signer_slot == 0 {
        return Err(SignerCoreError::invalid_input(
            "binding.signerSlot must be positive",
        ));
    }
    if binding.participant_ids.is_empty() || binding.participant_ids.iter().any(|id| *id == 0) {
        return Err(SignerCoreError::invalid_input(
            "binding.participantIds must be positive",
        ));
    }
    let expected_material_key_id = ed25519_worker_material_key_id(
        &ed25519_worker_material_key_identity_from_binding(binding),
    )?;
    if binding.material_key_id != expected_material_key_id {
        return Err(SignerCoreError::invalid_input(
            "binding.materialKeyId does not match binding identity",
        ));
    }
    ed25519_worker_material_binding_digest(binding)
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_storage_ref(material_binding_digest: &str) -> CoreResult<String> {
    let digest = require_non_empty_string(material_binding_digest, "materialBindingDigest")?;
    Ok(format!(
        "{ED25519_WORKER_MATERIAL_STORAGE_REF_PREFIX}{digest}"
    ))
}

#[cfg(feature = "near-crypto")]
pub fn ed25519_worker_material_aad_for_binding(
    binding: &Ed25519WorkerMaterialBindingV1,
) -> CoreResult<Ed25519SealedWorkerMaterialAadV1> {
    let material_binding_digest = validate_ed25519_worker_material_binding(binding)?;
    Ok(Ed25519SealedWorkerMaterialAadV1 {
        kind: Ed25519SealedWorkerMaterialAadKindV1::Ed25519SealedWorkerMaterialAadV1,
        material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
        material_binding_digest,
        binding: binding.clone(),
        aead_algorithm: Ed25519WorkerMaterialAeadAlgorithmV1::ChaCha20Poly1305,
        kdf_algorithm: Ed25519WorkerMaterialKdfAlgorithmV1::HkdfSha256,
        kdf_info: String::from_utf8_lossy(ED25519_WORKER_MATERIAL_KDF_INFO).to_string(),
    })
}

#[cfg(feature = "near-crypto")]
pub fn encode_ed25519_worker_material_plaintext(x_client_base: &[u8; 32]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(
        ED25519_WORKER_MATERIAL_PLAINTEXT_PREFIX.len() + ED25519_WORKER_MATERIAL_SHARE_SIZE,
    );
    plaintext.extend_from_slice(ED25519_WORKER_MATERIAL_PLAINTEXT_PREFIX);
    plaintext.extend_from_slice(x_client_base);
    plaintext
}

#[cfg(feature = "near-crypto")]
pub fn decode_ed25519_worker_material_plaintext(
    plaintext: &[u8],
) -> CoreResult<[u8; ED25519_WORKER_MATERIAL_SHARE_SIZE]> {
    if plaintext.len()
        != ED25519_WORKER_MATERIAL_PLAINTEXT_PREFIX.len() + ED25519_WORKER_MATERIAL_SHARE_SIZE
    {
        return Err(SignerCoreError::invalid_length(
            "Invalid Ed25519 worker material plaintext length",
        ));
    }
    if !plaintext.starts_with(ED25519_WORKER_MATERIAL_PLAINTEXT_PREFIX) {
        return Err(SignerCoreError::invalid_input(
            "Invalid Ed25519 worker material plaintext prefix",
        ));
    }
    plaintext[ED25519_WORKER_MATERIAL_PLAINTEXT_PREFIX.len()..]
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length("Invalid Ed25519 worker material share"))
}

#[cfg(feature = "near-crypto")]
pub fn seal_ed25519_worker_material_artifact(
    binding: &Ed25519WorkerMaterialBindingV1,
    x_client_base: &[u8; ED25519_WORKER_MATERIAL_SHARE_SIZE],
    unseal_secret: &[u8],
    salt: &[u8],
    nonce: &[u8],
) -> CoreResult<Ed25519SealedWorkerMaterialV1> {
    let material_binding_digest = validate_ed25519_worker_material_binding(binding)?;
    let aad = ed25519_worker_material_aad_for_binding(binding)?;
    let aad_bytes = ed25519_worker_material_aad_bytes(&aad)?;
    let mut plaintext = encode_ed25519_worker_material_plaintext(x_client_base);
    let sealed_material = chacha20poly1305_seal_ed25519_worker_material(
        &plaintext,
        unseal_secret,
        salt,
        nonce,
        &aad_bytes,
    )?;
    plaintext.zeroize();
    Ok(Ed25519SealedWorkerMaterialV1 {
        kind: Ed25519SealedWorkerMaterialKindV1::Ed25519SealedWorkerMaterialV1,
        material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
        material_binding_digest,
        binding: binding.clone(),
        sealed_material_b64u: Base64UrlUnpadded::encode_string(&sealed_material),
        aead: Ed25519WorkerMaterialAeadV1 {
            algorithm: Ed25519WorkerMaterialAeadAlgorithmV1::ChaCha20Poly1305,
            nonce_b64u: Base64UrlUnpadded::encode_string(nonce),
        },
        kdf: Ed25519WorkerMaterialKdfV1 {
            algorithm: Ed25519WorkerMaterialKdfAlgorithmV1::HkdfSha256,
            salt_b64u: Base64UrlUnpadded::encode_string(salt),
            info: String::from_utf8_lossy(ED25519_WORKER_MATERIAL_KDF_INFO).to_string(),
        },
    })
}

#[cfg(feature = "near-crypto")]
pub fn open_ed25519_worker_material_artifact(
    artifact: &Ed25519SealedWorkerMaterialV1,
    expected_binding: &Ed25519WorkerMaterialBindingV1,
    unseal_secret: &[u8],
) -> CoreResult<[u8; ED25519_WORKER_MATERIAL_SHARE_SIZE]> {
    validate_sealed_worker_material_envelope(artifact, expected_binding)?;
    let aad = ed25519_worker_material_aad_for_binding(expected_binding)?;
    let aad_bytes = ed25519_worker_material_aad_bytes(&aad)?;
    let ciphertext = decode_b64u(&artifact.sealed_material_b64u, "sealedMaterialB64u")?;
    let salt = decode_b64u(&artifact.kdf.salt_b64u, "kdf.saltB64u")?;
    let nonce = decode_b64u(&artifact.aead.nonce_b64u, "aead.nonceB64u")?;
    let mut plaintext = chacha20poly1305_open_ed25519_worker_material(
        &ciphertext,
        unseal_secret,
        &salt,
        &nonce,
        &aad_bytes,
    )?;
    let decoded = decode_ed25519_worker_material_plaintext(&plaintext);
    plaintext.zeroize();
    decoded
}

#[cfg(feature = "near-crypto")]
pub fn derive_ed25519_worker_material_seal_key(
    unseal_secret: &[u8],
    salt: &[u8],
) -> CoreResult<[u8; ED25519_WORKER_MATERIAL_CHACHA20_KEY_SIZE]> {
    if unseal_secret.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 worker material unseal secret is empty",
        ));
    }
    if salt.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 worker material seal salt is empty",
        ));
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), unseal_secret);
    let mut key = [0u8; ED25519_WORKER_MATERIAL_CHACHA20_KEY_SIZE];
    hk.expand(ED25519_WORKER_MATERIAL_KDF_INFO, &mut key)
        .map_err(|_| SignerCoreError::hkdf_error("Ed25519 worker material HKDF failed"))?;
    Ok(key)
}

#[cfg(feature = "near-crypto")]
pub fn chacha20poly1305_seal_ed25519_worker_material(
    plaintext: &[u8],
    unseal_secret: &[u8],
    salt: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> CoreResult<Vec<u8>> {
    if nonce.len() != ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE {
        return Err(SignerCoreError::invalid_length(format!(
            "Ed25519 worker material nonce must be {} bytes",
            ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE
        )));
    }
    let mut key = derive_ed25519_worker_material_seal_key(unseal_secret, salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce_array: [u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE] = nonce
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length("Invalid ChaCha20Poly1305 nonce"))?;
    let nonce: Nonce = nonce_array.into();
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("Ed25519 worker material seal failed"))?;
    key.zeroize();
    Ok(encrypted)
}

#[cfg(feature = "near-crypto")]
pub fn chacha20poly1305_open_ed25519_worker_material(
    ciphertext: &[u8],
    unseal_secret: &[u8],
    salt: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> CoreResult<Vec<u8>> {
    if nonce.len() != ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE {
        return Err(SignerCoreError::invalid_length(format!(
            "Ed25519 worker material nonce must be {} bytes",
            ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE
        )));
    }
    let mut key = derive_ed25519_worker_material_seal_key(unseal_secret, salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce_array: [u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE] = nonce
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length("Invalid ChaCha20Poly1305 nonce"))?;
    let nonce: Nonce = nonce_array.into();
    let decrypted = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("Ed25519 worker material open failed"))?;
    key.zeroize();
    Ok(decrypted)
}

#[cfg(feature = "near-crypto")]
fn validate_sealed_worker_material_envelope(
    artifact: &Ed25519SealedWorkerMaterialV1,
    expected_binding: &Ed25519WorkerMaterialBindingV1,
) -> CoreResult<()> {
    let expected_digest = validate_ed25519_worker_material_binding(expected_binding)?;
    if artifact.material_binding_digest != expected_digest {
        return Err(SignerCoreError::invalid_input(
            "sealed material binding digest mismatch",
        ));
    }
    if artifact.binding != *expected_binding {
        return Err(SignerCoreError::invalid_input(
            "sealed material binding payload mismatch",
        ));
    }
    match artifact.aead.algorithm {
        Ed25519WorkerMaterialAeadAlgorithmV1::ChaCha20Poly1305 => {}
    }
    match artifact.kdf.algorithm {
        Ed25519WorkerMaterialKdfAlgorithmV1::HkdfSha256 => {}
    }
    if artifact.kdf.info.as_bytes() != ED25519_WORKER_MATERIAL_KDF_INFO {
        return Err(SignerCoreError::invalid_input(
            "sealed material KDF info mismatch",
        ));
    }
    Ok(())
}

#[cfg(feature = "near-crypto")]
fn decode_b64u(value: &str, field_name: &str) -> CoreResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(value)
        .map_err(|error| SignerCoreError::decode_error(format!("Invalid {field_name}: {error}")))
}

#[cfg(feature = "near-crypto")]
fn require_non_empty_string<'a>(value: &'a str, field_name: &str) -> CoreResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} is required"
        )));
    }
    Ok(trimmed)
}

#[cfg(all(test, feature = "near-crypto"))]
mod tests {
    use super::*;

    fn sample_key_identity() -> Ed25519WorkerMaterialKeyIdentityV1 {
        Ed25519WorkerMaterialKeyIdentityV1 {
            kind: Ed25519WorkerMaterialKeyIdentityKindV1::Ed25519WorkerMaterialKeyIdentityV1,
            near_account_id: "alice.near".to_string(),
            signer_slot: 1,
            signing_root_id: "project:env".to_string(),
            signing_root_version: "v1".to_string(),
            relayer_key_id: "ed25519:relayer".to_string(),
            key_version: "threshold-ed25519-hss-v1".to_string(),
            material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
        }
    }

    fn sample_material_binding() -> Ed25519WorkerMaterialBindingV1 {
        Ed25519WorkerMaterialBindingV1 {
            kind: Ed25519WorkerMaterialBindingKindV1::Ed25519WorkerMaterialBindingV1,
            curve: Ed25519WorkerMaterialCurveV1::Ed25519,
            protocol: Ed25519WorkerMaterialProtocolV1::RouterAbNormalSigning,
            near_account_id: "alice.near".to_string(),
            signer_slot: 1,
            signing_root_id: "project:env".to_string(),
            signing_root_version: "v1".to_string(),
            relayer_key_id: "ed25519:relayer".to_string(),
            key_version: "threshold-ed25519-hss-v1".to_string(),
            participant_ids: vec![1, 2],
            client_verifying_share_b64u: "clientVerifier".to_string(),
            material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
            material_key_id: ed25519_worker_material_key_id(&sample_key_identity()).unwrap(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn sample_aad() -> Ed25519SealedWorkerMaterialAadV1 {
        let binding = sample_material_binding();
        Ed25519SealedWorkerMaterialAadV1 {
            kind: Ed25519SealedWorkerMaterialAadKindV1::Ed25519SealedWorkerMaterialAadV1,
            material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
            material_binding_digest: ed25519_worker_material_binding_digest(&binding).unwrap(),
            binding,
            aead_algorithm: Ed25519WorkerMaterialAeadAlgorithmV1::ChaCha20Poly1305,
            kdf_algorithm: Ed25519WorkerMaterialKdfAlgorithmV1::HkdfSha256,
            kdf_info: "seams-ed25519-worker-material-v1".to_string(),
        }
    }

    fn sample_session_binding() -> Ed25519WorkerMaterialSessionBindingV1 {
        Ed25519WorkerMaterialSessionBindingV1 {
            kind: Ed25519WorkerMaterialSessionBindingKindV1::Ed25519WorkerMaterialSessionBindingV1,
            material_binding_digest: ed25519_worker_material_binding_digest(
                &sample_material_binding(),
            )
            .unwrap(),
            near_account_id: "alice.near".to_string(),
            signer_slot: 1,
            threshold_session_id: "threshold-session".to_string(),
            signing_grant_id: "signing-grant".to_string(),
            signing_root_id: "project:env".to_string(),
            signing_root_version: "v1".to_string(),
            runtime_policy_scope: ThresholdRuntimePolicyScopeV1 {
                org_id: "org".to_string(),
                project_id: "project".to_string(),
                env_id: "env".to_string(),
                signing_root_version: "v1".to_string(),
            },
            relayer_key_id: "ed25519:relayer".to_string(),
            key_version: "threshold-ed25519-hss-v1".to_string(),
            participant_ids: vec![1, 2],
            signing_worker_id: "signing-worker".to_string(),
            expires_at_ms: 1_900_000_000_000,
        }
    }

    #[test]
    fn canonical_json_sorts_object_keys_and_preserves_arrays() {
        let value = serde_json::json!({
            "z": 1,
            "a": {
                "b": 2,
                "a": 1
            },
            "arr": [
                { "y": 2, "x": 1 },
                3
            ]
        });
        let canonical = ed25519_worker_material_canonical_json(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":{"a":1,"b":2},"arr":[{"x":1,"y":2},3],"z":1}"#
        );
    }

    #[test]
    fn worker_material_digest_vectors_match_typescript_canonicalization() {
        let identity = sample_key_identity();
        let binding = sample_material_binding();
        let session_binding = sample_session_binding();
        let aad = sample_aad();
        let canonical = ed25519_worker_material_canonical_json(&identity).unwrap();
        assert_eq!(
            canonical,
            r#"{"keyVersion":"threshold-ed25519-hss-v1","kind":"ed25519_worker_material_key_identity_v1","materialFormatVersion":"ed25519_worker_material_v1","nearAccountId":"alice.near","relayerKeyId":"ed25519:relayer","signerSlot":1,"signingRootId":"project:env","signingRootVersion":"v1"}"#
        );
        assert_eq!(
            ed25519_worker_material_canonical_json(&binding).unwrap(),
            r#"{"clientVerifyingShareB64u":"clientVerifier","createdAtMs":1700000000000,"curve":"ed25519","keyVersion":"threshold-ed25519-hss-v1","kind":"ed25519_worker_material_binding_v1","materialFormatVersion":"ed25519_worker_material_v1","materialKeyId":"68zLDBT7vbB8YBa1ckFElOgOaTGKAF_ZgB3ExApHWEo","nearAccountId":"alice.near","participantIds":[1,2],"protocol":"router_ab_normal_signing","relayerKeyId":"ed25519:relayer","signerSlot":1,"signingRootId":"project:env","signingRootVersion":"v1"}"#
        );
        assert_eq!(
            ed25519_worker_material_canonical_json(&session_binding).unwrap(),
            r#"{"expiresAtMs":1900000000000,"keyVersion":"threshold-ed25519-hss-v1","kind":"ed25519_worker_material_session_binding_v1","materialBindingDigest":"nVj1qAfSRNkAiFqo-AOhidltXdCj5rsvPiVmfxTalZY","nearAccountId":"alice.near","participantIds":[1,2],"relayerKeyId":"ed25519:relayer","runtimePolicyScope":{"envId":"env","orgId":"org","projectId":"project","signingRootVersion":"v1"},"signerSlot":1,"signingGrantId":"signing-grant","signingRootId":"project:env","signingRootVersion":"v1","signingWorkerId":"signing-worker","thresholdSessionId":"threshold-session"}"#
        );
        assert_eq!(
            ed25519_worker_material_canonical_json(&aad).unwrap(),
            r#"{"aeadAlgorithm":"chacha20poly1305","binding":{"clientVerifyingShareB64u":"clientVerifier","createdAtMs":1700000000000,"curve":"ed25519","keyVersion":"threshold-ed25519-hss-v1","kind":"ed25519_worker_material_binding_v1","materialFormatVersion":"ed25519_worker_material_v1","materialKeyId":"68zLDBT7vbB8YBa1ckFElOgOaTGKAF_ZgB3ExApHWEo","nearAccountId":"alice.near","participantIds":[1,2],"protocol":"router_ab_normal_signing","relayerKeyId":"ed25519:relayer","signerSlot":1,"signingRootId":"project:env","signingRootVersion":"v1"},"kdfAlgorithm":"hkdf_sha256","kdfInfo":"seams-ed25519-worker-material-v1","kind":"ed25519_sealed_worker_material_aad_v1","materialBindingDigest":"nVj1qAfSRNkAiFqo-AOhidltXdCj5rsvPiVmfxTalZY","materialFormatVersion":"ed25519_worker_material_v1"}"#
        );
        assert_eq!(
            ed25519_worker_material_key_id(&identity).unwrap(),
            "68zLDBT7vbB8YBa1ckFElOgOaTGKAF_ZgB3ExApHWEo"
        );
        assert_eq!(
            ed25519_worker_material_binding_digest(&binding).unwrap(),
            "nVj1qAfSRNkAiFqo-AOhidltXdCj5rsvPiVmfxTalZY"
        );
        assert_eq!(
            ed25519_worker_material_session_binding_digest(&session_binding).unwrap(),
            "SBCUK9pp4dT3AHPupQgx7MoIQ-RXq3aFKhxbucibB1o"
        );
        assert_eq!(
            ed25519_worker_material_digest_b64u(&aad).unwrap(),
            "2RLqwrXrAy5p30JhaSYf2ncZJJDMpBVN_-LmcSVLyw8"
        );
    }

    #[test]
    fn seal_open_roundtrip_authenticates_aad() {
        let aad = ed25519_worker_material_aad_bytes(&sample_aad()).unwrap();
        let plaintext = b"client-mpc-share-material";
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [7u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];

        let ciphertext =
            chacha20poly1305_seal_ed25519_worker_material(plaintext, secret, salt, &nonce, &aad)
                .unwrap();
        let opened =
            chacha20poly1305_open_ed25519_worker_material(&ciphertext, secret, salt, &nonce, &aad)
                .unwrap();

        assert_eq!(opened, plaintext);

        let wrong_aad = b"wrong aad";
        assert!(chacha20poly1305_open_ed25519_worker_material(
            &ciphertext,
            secret,
            salt,
            &nonce,
            wrong_aad,
        )
        .is_err());
    }

    #[test]
    fn seal_open_rejects_wrong_secret_and_nonce_length() {
        let aad = ed25519_worker_material_aad_bytes(&sample_aad()).unwrap();
        let plaintext = b"client-mpc-share-material";
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [9u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];
        let ciphertext =
            chacha20poly1305_seal_ed25519_worker_material(plaintext, secret, salt, &nonce, &aad)
                .unwrap();

        assert!(chacha20poly1305_open_ed25519_worker_material(
            &ciphertext,
            b"wrong-secret",
            salt,
            &nonce,
            &aad,
        )
        .is_err());
        assert!(chacha20poly1305_seal_ed25519_worker_material(
            plaintext,
            secret,
            salt,
            &[1, 2, 3],
            &aad,
        )
        .is_err());
    }

    #[test]
    fn sealed_worker_material_artifact_roundtrips_fixed_plaintext() {
        let binding = sample_material_binding();
        let x_client_base = [11u8; ED25519_WORKER_MATERIAL_SHARE_SIZE];
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [3u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];

        let artifact =
            seal_ed25519_worker_material_artifact(&binding, &x_client_base, secret, salt, &nonce)
                .unwrap();
        let opened = open_ed25519_worker_material_artifact(&artifact, &binding, secret).unwrap();

        assert_eq!(opened, x_client_base);
        assert_eq!(
            artifact.material_binding_digest,
            ed25519_worker_material_binding_digest(&binding).unwrap()
        );
        assert_eq!(
            ed25519_worker_material_storage_ref(&artifact.material_binding_digest).unwrap(),
            format!(
                "{}{}",
                ED25519_WORKER_MATERIAL_STORAGE_REF_PREFIX, artifact.material_binding_digest
            )
        );
    }

    #[test]
    fn sealed_worker_material_artifact_rejects_wrong_binding_and_corruption() {
        let binding = sample_material_binding();
        let mut wrong_binding = binding.clone();
        wrong_binding.near_account_id = "bob.near".to_string();
        wrong_binding.material_key_id = ed25519_worker_material_key_id(
            &ed25519_worker_material_key_identity_from_binding(&wrong_binding),
        )
        .unwrap();
        let x_client_base = [12u8; ED25519_WORKER_MATERIAL_SHARE_SIZE];
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [4u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];
        let artifact =
            seal_ed25519_worker_material_artifact(&binding, &x_client_base, secret, salt, &nonce)
                .unwrap();

        assert!(open_ed25519_worker_material_artifact(&artifact, &wrong_binding, secret).is_err());

        let mut corrupt = artifact.clone();
        corrupt.sealed_material_b64u.push('A');
        assert!(open_ed25519_worker_material_artifact(&corrupt, &binding, secret).is_err());
    }

    #[test]
    fn sealed_worker_material_artifact_rejects_verifier_and_material_id_mismatch() {
        let binding = sample_material_binding();
        let x_client_base = [14u8; ED25519_WORKER_MATERIAL_SHARE_SIZE];
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [5u8; ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];
        let artifact =
            seal_ed25519_worker_material_artifact(&binding, &x_client_base, secret, salt, &nonce)
                .unwrap();

        let mut wrong_verifier = binding.clone();
        wrong_verifier.client_verifying_share_b64u = "different-client-verifier".to_string();
        assert!(open_ed25519_worker_material_artifact(&artifact, &wrong_verifier, secret).is_err());

        let mut wrong_material_id = binding.clone();
        wrong_material_id.material_key_id =
            ed25519_worker_material_key_id(&Ed25519WorkerMaterialKeyIdentityV1 {
                kind: Ed25519WorkerMaterialKeyIdentityKindV1::Ed25519WorkerMaterialKeyIdentityV1,
                near_account_id: binding.near_account_id.clone(),
                signer_slot: 2,
                signing_root_id: binding.signing_root_id.clone(),
                signing_root_version: binding.signing_root_version.clone(),
                relayer_key_id: binding.relayer_key_id.clone(),
                key_version: binding.key_version.clone(),
                material_format_version: binding.material_format_version,
            })
            .unwrap();
        assert!(
            open_ed25519_worker_material_artifact(&artifact, &wrong_material_id, secret).is_err()
        );
    }

    #[test]
    fn plaintext_decode_rejects_wrong_prefix_and_length() {
        let share = [13u8; ED25519_WORKER_MATERIAL_SHARE_SIZE];
        let encoded = encode_ed25519_worker_material_plaintext(&share);
        assert_eq!(
            decode_ed25519_worker_material_plaintext(&encoded).unwrap(),
            share
        );
        assert!(decode_ed25519_worker_material_plaintext(b"short").is_err());
        let mut wrong_prefix = encoded.clone();
        wrong_prefix[0] ^= 1;
        assert!(decode_ed25519_worker_material_plaintext(&wrong_prefix).is_err());
    }
}
