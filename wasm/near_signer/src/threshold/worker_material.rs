use crate::encoders::{base64_url_decode, base64_url_encode};
#[cfg(feature = "hss-client-exports")]
use crate::threshold::threshold_hss::{
    derive_threshold_ed25519_hss_client_output_mask, open_threshold_ed25519_hss_client_output,
    ThresholdEd25519HssDeriveClientOutputMaskArgs, ThresholdEd25519HssOpenClientOutputArgs,
};
use ed25519_hss::role_signing::{
    create_role_separated_ed25519_client_signature_share_v1,
    prepare_role_separated_ed25519_round1_v1, role_separated_ed25519_client_verifying_share_v1,
    RoleSeparatedEd25519ClientShareRequestV1, RoleSeparatedEd25519CommitmentsV1,
};
use serde::{Deserialize, Serialize};
use signer_core::commands::{
    ed25519_worker_material_key_id, ed25519_worker_material_session_binding_digest,
    ed25519_worker_material_storage_ref, open_ed25519_worker_material_artifact,
    seal_ed25519_worker_material_artifact, validate_ed25519_worker_material_binding,
    Ed25519DeleteSealedWorkerMaterialRequestV1, Ed25519DeleteSealedWorkerMaterialSuccessV1,
    Ed25519HssClientOutputMaskTransportV1, Ed25519PutSealedWorkerMaterialRequestKindV1,
    Ed25519PutSealedWorkerMaterialRequestV1, Ed25519PutSealedWorkerMaterialSuccessV1,
    Ed25519ReadSealedWorkerMaterialRequestV1, Ed25519ReadSealedWorkerMaterialSuccessV1,
    Ed25519RestoreWorkerMaterialRequestV1, Ed25519SealedWorkerMaterialTransportV1,
    Ed25519SealedWorkerMaterialV1, Ed25519WorkerMaterialBindingKindV1,
    Ed25519WorkerMaterialBindingV1, Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    Ed25519WorkerMaterialCredentialAuthorizationV1, Ed25519WorkerMaterialCurveV1,
    Ed25519WorkerMaterialFormatVersionV1, Ed25519WorkerMaterialKeyIdentityKindV1,
    Ed25519WorkerMaterialKeyIdentityV1, Ed25519WorkerMaterialProtocolV1,
    Ed25519WorkerMaterialSessionBindingV1, ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const ED25519_WORKER_MATERIAL_SEAL_SALT_SIZE: usize = 32;
const MATERIAL_AUTHORIZATION_DEFAULT_TTL_MS: u64 = 60_000;
const MATERIAL_AUTHORIZATION_MAX_TTL_MS: u64 = 5 * 60_000;
const MATERIAL_AUTHORIZATION_MAX_USES_V1: u32 = 1;
const HSS_CLIENT_OUTPUT_MASK_DEFAULT_TTL_MS: u64 = 60_000;
const HSS_CLIENT_OUTPUT_MASK_MAX_TTL_MS: u64 = 5 * 60_000;
const HSS_CLIENT_OUTPUT_MASK_USES_V1: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoreWorkerMaterialFromBaseShareRequest {
    material_handle: String,
    x_client_base_b64u: String,
    material_binding: Ed25519WorkerMaterialBindingV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoreWorkerMaterialFromHssOutputRequest {
    evaluator_driver_state_b64u: String,
    client_output_message_b64u: String,
    client_output_mask: Ed25519HssClientOutputMaskTransportV1,
    expected_context_binding_b64u: String,
    near_account_id: String,
    signer_slot: u32,
    signing_root_id: String,
    signing_root_version: String,
    relayer_key_id: String,
    participant_ids: Vec<u32>,
    created_at_ms: u64,
    seal_authorization: Option<Ed25519WorkerMaterialSealAuthorizationV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareHssClientOutputMaskHandleRequest {
    application_binding_digest_b64u: String,
    participant_ids: Vec<u16>,
    context_binding_b64u: String,
    operation: String,
    relayer_key_id: String,
    client_recoverable_secret_b64u: String,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkerMaterialBindingInputWithoutVerifier {
    near_account_id: String,
    signer_slot: u32,
    signing_root_id: String,
    signing_root_version: String,
    relayer_key_id: String,
    participant_ids: Vec<u32>,
    created_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest {
    binding_input: WorkerMaterialBindingInputWithoutVerifier,
    rp_id: String,
    credential_id_b64u: String,
    prf_first_bytes: Vec<u8>,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest {
    binding_input: WorkerMaterialBindingInputWithoutVerifier,
    auth_subject_id: String,
    recovery_code_binding_digest: String,
    recovery_code_secret32: Vec<u8>,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest {
    material_binding_digest: String,
    rp_id: String,
    credential_id_b64u: String,
    prf_first_bytes: Vec<u8>,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest {
    material_binding_digest: String,
    auth_subject_id: String,
    recovery_code_binding_digest: String,
    recovery_code_secret32: Vec<u8>,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum Ed25519WorkerMaterialSealAuthorizationV1 {
    PasskeyPrfMaterialSealAuthorizationHandleV1 {
        handle: String,
        rp_id: String,
        credential_id_b64u: String,
        material_key_id: String,
        expires_at_ms: u64,
    },
    RecoveryCodeMaterialSealAuthorizationHandleV1 {
        handle: String,
        auth_subject_id: String,
        recovery_code_binding_digest: String,
        material_key_id: String,
        expires_at_ms: u64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallPasskeyPrfMaterialAuthorizationRequest {
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    material_binding_digest: String,
    rp_id: String,
    credential_id_b64u: String,
    prf_first_bytes: Vec<u8>,
    expires_at_ms: u64,
    max_uses: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallRecoveryCodeMaterialAuthorizationRequest {
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    material_binding_digest: String,
    auth_subject_id: String,
    recovery_code_binding_digest: String,
    recovery_code_secret32: Vec<u8>,
    expires_at_ms: u64,
    max_uses: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValidateWorkerMaterialRequest {
    material_handle: String,
    expected_material_binding: Ed25519WorkerMaterialBindingV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateClientPresignFromWorkerMaterialRequest {
    client_participant_id: u16,
    relayer_participant_id: u16,
    material_handle: String,
    expected_material_binding: Ed25519WorkerMaterialBindingV1,
    expected_session_binding: Ed25519WorkerMaterialSessionBindingV1,
    expected_session_binding_digest: String,
    group_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignClientPresignFromWorkerMaterialRequest {
    client_participant_id: u16,
    relayer_participant_id: u16,
    material_handle: String,
    expected_material_binding: Ed25519WorkerMaterialBindingV1,
    expected_session_binding: Ed25519WorkerMaterialSessionBindingV1,
    expected_session_binding_digest: String,
    group_public_key: String,
    signing_digest_b64u: String,
    client_nonce_handle_b64u: String,
    client_commitments: signer_core::near_threshold_ed25519::CommitmentsWire,
    relayer_commitments: signer_core::near_threshold_ed25519::CommitmentsWire,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RoleSeparatedNormalSigningClientShareFromWorkerMaterialRequest {
    material_handle: String,
    expected_material_binding: Ed25519WorkerMaterialBindingV1,
    expected_session_binding: Ed25519WorkerMaterialSessionBindingV1,
    expected_session_binding_digest: String,
    group_public_key: String,
    server_verifying_share_b64u: String,
    server_commitments: signer_core::near_threshold_ed25519::CommitmentsWire,
    signing_digest_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BurnClientPresignRequest {
    client_nonce_handle_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerMaterialResult {
    material_handle: String,
    client_verifying_share_b64u: String,
    binding_digest: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerMaterialStoreResult {
    ok: bool,
    material_handle: String,
    material_binding_digest: String,
    sealed_worker_material_ref: String,
    sealed_worker_material_b64u: String,
    client_verifying_share_b64u: String,
    material_format_version: Ed25519WorkerMaterialFormatVersionV1,
    material_key_id: String,
    signer_slot: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientPresignCreateResult {
    client_nonce_handle_b64u: String,
    client_verifying_share_b64u: String,
    client_commitments: signer_core::near_threshold_ed25519::CommitmentsWire,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientPresignSignResult {
    client_signature_share_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleSeparatedNormalSigningClientShareResult {
    client_commitments: signer_core::near_threshold_ed25519::CommitmentsWire,
    client_verifying_share_b64u: String,
    client_signature_share_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientPresignBurnResult {
    burned: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerMaterialRestoreResult {
    ok: bool,
    material_handle: String,
    material_binding_digest: String,
    sealed_worker_material_ref: String,
    sealed_worker_material_b64u: String,
    client_verifying_share_b64u: String,
    material_format_version: Ed25519WorkerMaterialFormatVersionV1,
    material_key_id: String,
    signer_slot: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallMaterialAuthorizationResult {
    ok: bool,
    authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
    remaining_uses: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareWorkerMaterialSealAuthorizationResult {
    ok: bool,
    material_key_id: String,
    seal_authorization: Ed25519WorkerMaterialSealAuthorizationV1,
    remaining_uses: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareWorkerMaterialUnsealAuthorizationResult {
    ok: bool,
    unseal_authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
    remaining_uses: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareHssClientOutputMaskHandleResult {
    ok: bool,
    client_output_mask_handle: String,
    context_binding_b64u: String,
    expires_at_ms: u64,
    remaining_uses: u32,
}

struct StoredWorkerMaterial {
    material_handle: String,
    x_client_base: [u8; 32],
    client_verifying_share_b64u: String,
    binding_digest: String,
    binding: Ed25519WorkerMaterialBindingV1,
}

impl Drop for StoredWorkerMaterial {
    fn drop(&mut self) {
        self.x_client_base.zeroize();
    }
}

struct StoredClientPresignNonce {
    nonce_bytes: Vec<u8>,
}

impl Drop for StoredClientPresignNonce {
    fn drop(&mut self) {
        self.nonce_bytes.zeroize();
    }
}

struct StoredWorkerMaterialCredentialAuthorizationSecret {
    secret: Vec<u8>,
    scope: StoredWorkerMaterialAuthorizationScope,
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    expires_at_ms: u64,
    remaining_uses: u32,
}

struct StoredHssClientOutputMask {
    mask: [u8; 32],
    context_binding_b64u: String,
    expires_at_ms: u64,
    remaining_uses: u32,
}

impl Drop for StoredHssClientOutputMask {
    fn drop(&mut self) {
        self.mask.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StoredWorkerMaterialAuthorizationScope {
    MaterialBindingDigest(String),
    MaterialKeyId(String),
}

impl Drop for StoredWorkerMaterialCredentialAuthorizationSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

thread_local! {
    static WORKER_MATERIAL_BY_HANDLE: RefCell<HashMap<String, StoredWorkerMaterial>> =
        RefCell::new(HashMap::new());
    static CLIENT_PRESIGN_NONCE_BY_HANDLE: RefCell<HashMap<String, StoredClientPresignNonce>> =
        RefCell::new(HashMap::new());
    static SEALED_WORKER_MATERIAL_BY_REF: RefCell<HashMap<String, Ed25519SealedWorkerMaterialV1>> =
        RefCell::new(HashMap::new());
    static WORKER_MATERIAL_AUTHORIZATION_SECRET_BY_HANDLE: RefCell<HashMap<String, StoredWorkerMaterialCredentialAuthorizationSecret>> =
        RefCell::new(HashMap::new());
    static HSS_CLIENT_OUTPUT_MASK_BY_HANDLE: RefCell<HashMap<String, StoredHssClientOutputMask>> =
        RefCell::new(HashMap::new());
}

static CLIENT_PRESIGN_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);
static WORKER_MATERIAL_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);
static MATERIAL_AUTHORIZATION_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);
static HSS_CLIENT_OUTPUT_MASK_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[wasm_bindgen]
pub fn threshold_ed25519_worker_material_store_from_base_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: StoreWorkerMaterialFromBaseShareRequest = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 material store args: {e}")))?;
    let result = store_worker_material_from_base_share(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize stored material: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_worker_material_store_from_hss_output(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: StoreWorkerMaterialFromHssOutputRequest = serde_wasm_bindgen::from_value(args)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 material store-from-HSS args: {e}"
            ))
        })?;
    let result = store_worker_material_from_hss_output(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize stored material: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_prepare_hss_client_output_mask_handle(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: PrepareHssClientOutputMaskHandleRequest = serde_wasm_bindgen::from_value(args)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 HSS client output mask handle args: {e}"
            ))
        })?;
    let result = prepare_hss_client_output_mask_handle(request)?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize Ed25519 HSS client output mask handle: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_prepare_passkey_prf_worker_material_seal_authorization(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest =
        serde_wasm_bindgen::from_value(args).map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 passkey material seal authorization args: {e}"
            ))
        })?;
    let result = prepare_passkey_prf_worker_material_seal_authorization(request)?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize Ed25519 material seal authorization: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_prepare_recovery_code_worker_material_seal_authorization(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest =
        serde_wasm_bindgen::from_value(args).map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 recovery-code material seal authorization args: {e}"
            ))
        })?;
    let result = prepare_recovery_code_worker_material_seal_authorization(request)?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize Ed25519 material seal authorization: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_prepare_passkey_prf_worker_material_unseal_authorization(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest =
        serde_wasm_bindgen::from_value(args).map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 passkey material unseal authorization args: {e}"
            ))
        })?;
    let result = prepare_passkey_prf_worker_material_unseal_authorization(request)?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize Ed25519 material unseal authorization: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_prepare_recovery_code_worker_material_unseal_authorization(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest =
        serde_wasm_bindgen::from_value(args).map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 recovery-code material unseal authorization args: {e}"
            ))
        })?;
    let result = prepare_recovery_code_worker_material_unseal_authorization(request)?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize Ed25519 material unseal authorization: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_worker_material_validate(args: JsValue) -> Result<JsValue, JsValue> {
    let request: ValidateWorkerMaterialRequest = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 material validate args: {e}")))?;
    let result = validate_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize material validation: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_worker_material_restore(args: JsValue) -> Result<JsValue, JsValue> {
    let request: Ed25519RestoreWorkerMaterialRequestV1 = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 material restore args: {e}")))?;
    let result = restore_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize restored material: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_sealed_worker_material_put(args: JsValue) -> Result<JsValue, JsValue> {
    let request: Ed25519PutSealedWorkerMaterialRequestV1 = serde_wasm_bindgen::from_value(args)
        .map_err(|e| {
            JsValue::from_str(&format!("Invalid Ed25519 sealed material put args: {e}"))
        })?;
    let result = put_sealed_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize sealed material ref: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_sealed_worker_material_read(args: JsValue) -> Result<JsValue, JsValue> {
    let request: Ed25519ReadSealedWorkerMaterialRequestV1 = serde_wasm_bindgen::from_value(args)
        .map_err(|e| {
            JsValue::from_str(&format!("Invalid Ed25519 sealed material read args: {e}"))
        })?;
    let result = read_sealed_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize sealed material: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_sealed_worker_material_delete(args: JsValue) -> Result<JsValue, JsValue> {
    let request: Ed25519DeleteSealedWorkerMaterialRequestV1 = serde_wasm_bindgen::from_value(args)
        .map_err(|e| {
            JsValue::from_str(&format!("Invalid Ed25519 sealed material delete args: {e}"))
        })?;
    let result = delete_sealed_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize sealed material delete: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_client_presign_create_from_worker_material(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: CreateClientPresignFromWorkerMaterialRequest =
        serde_wasm_bindgen::from_value(args).map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 presign create-from-material args: {e}"
            ))
        })?;
    let result = create_client_presign_from_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize client presign: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_client_presign_sign_from_worker_material(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: SignClientPresignFromWorkerMaterialRequest = serde_wasm_bindgen::from_value(args)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 presign sign-from-material args: {e}"
            ))
        })?;
    let result = sign_client_presign_from_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize client signature share: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_role_separated_normal_signing_client_share_from_worker_material(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let request: RoleSeparatedNormalSigningClientShareFromWorkerMaterialRequest =
        serde_wasm_bindgen::from_value(args).map_err(|e| {
            JsValue::from_str(&format!(
                "Invalid Ed25519 role-separated normal-signing args: {e}"
            ))
        })?;
    let result = create_role_separated_normal_signing_client_share_from_worker_material(request)?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize role-separated client signature share: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_client_presign_burn(args: JsValue) -> Result<JsValue, JsValue> {
    let request: BurnClientPresignRequest = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 presign burn args: {e}")))?;
    let result = burn_client_presign(request);
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize client presign burn: {e}")))
}

fn store_worker_material_from_base_share(
    request: StoreWorkerMaterialFromBaseShareRequest,
) -> Result<WorkerMaterialResult, JsValue> {
    let material_handle = require_non_empty(request.material_handle, "materialHandle")?;
    let binding_digest = signer_core_result_to_js(validate_ed25519_worker_material_binding(
        &request.material_binding,
    ))?;
    let expected_client_verifying_share_b64u = require_non_empty(
        request.material_binding.client_verifying_share_b64u.clone(),
        "materialBinding.clientVerifyingShareB64u",
    )?;
    let x_client_base = decode_fixed_32(&request.x_client_base_b64u, "xClientBaseB64u")?;
    store_worker_material_from_base_share_bytes(
        material_handle,
        x_client_base,
        expected_client_verifying_share_b64u,
        binding_digest,
        request.material_binding,
    )
}

#[cfg(feature = "hss-client-exports")]
fn prepare_hss_client_output_mask_handle(
    request: PrepareHssClientOutputMaskHandleRequest,
) -> Result<PrepareHssClientOutputMaskHandleResult, JsValue> {
    let context_binding_b64u =
        require_non_empty(request.context_binding_b64u.clone(), "contextBindingB64u")?;
    let stored_context_binding_b64u = context_binding_b64u.clone();
    let output = derive_threshold_ed25519_hss_client_output_mask(
        ThresholdEd25519HssDeriveClientOutputMaskArgs {
            application_binding_digest_b64u: request.application_binding_digest_b64u,
            participant_ids: request.participant_ids,
            context_binding_b64u,
            operation: request.operation,
            relayer_key_id: request.relayer_key_id,
            client_recoverable_secret_b64u: request.client_recoverable_secret_b64u,
        },
    )
    .map_err(|e| JsValue::from_str(&e))?;
    let mask = decode_fixed_32(&output.client_output_mask_b64u, "clientOutputMaskB64u")?;
    let handle = random_hss_client_output_mask_handle()?;
    let (expires_at_ms, remaining_uses) = install_hss_client_output_mask(
        handle.clone(),
        mask,
        stored_context_binding_b64u.clone(),
        request.expires_at_ms,
    )?;
    Ok(PrepareHssClientOutputMaskHandleResult {
        ok: true,
        client_output_mask_handle: handle,
        context_binding_b64u: stored_context_binding_b64u,
        expires_at_ms,
        remaining_uses,
    })
}

#[cfg(not(feature = "hss-client-exports"))]
fn prepare_hss_client_output_mask_handle(
    _request: PrepareHssClientOutputMaskHandleRequest,
) -> Result<PrepareHssClientOutputMaskHandleResult, JsValue> {
    Err(JsValue::from_str(
        "PrepareThresholdEd25519HssClientOutputMaskHandle requires hss-client-exports",
    ))
}

fn store_worker_material_from_hss_output(
    request: StoreWorkerMaterialFromHssOutputRequest,
) -> Result<WorkerMaterialStoreResult, JsValue> {
    let opened = open_hss_client_output_for_worker_material(&request)?;
    let expected_context_binding_b64u = require_non_empty(
        request.expected_context_binding_b64u.clone(),
        "expectedContextBindingB64u",
    )?;
    if opened.context_binding_b64u != expected_context_binding_b64u {
        return Err(JsValue::from_str(
            "Ed25519 HSS client output context binding mismatch",
        ));
    }
    let x_client_base = decode_fixed_32(&opened.x_client_base_b64u, "xClientBaseB64u")?;
    let client_verifying_share = role_separated_ed25519_client_verifying_share_v1(x_client_base)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 worker material: {e}")))?;
    let client_verifying_share_b64u = base64_url_encode(&client_verifying_share);
    let material_binding =
        material_binding_from_hss_store_request(&request, client_verifying_share_b64u.clone())?;
    let binding_digest =
        signer_core_result_to_js(validate_ed25519_worker_material_binding(&material_binding))?;
    let material_format_version = material_binding.material_format_version;
    let material_key_id = material_binding.material_key_id.clone();
    let signer_slot = material_binding.signer_slot;
    let seal_authorization = request.seal_authorization.ok_or_else(|| {
        JsValue::from_str(&material_authorization_error(
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
            "seal authorization missing",
        ))
    })?;
    let mut seal_secret =
        consume_material_seal_authorization_secret(seal_authorization, &material_key_id)?;
    let sealed = seal_and_store_worker_material(
        &material_binding,
        &binding_digest,
        &x_client_base,
        &seal_secret,
    );
    seal_secret.zeroize();
    let (sealed_worker_material_ref, sealed_worker_material_b64u) = sealed?;
    store_worker_material_from_base_share_bytes(
        random_worker_material_handle()?,
        x_client_base,
        client_verifying_share_b64u,
        binding_digest.clone(),
        material_binding,
    )
    .map(|stored| WorkerMaterialStoreResult {
        ok: true,
        material_handle: stored.material_handle,
        material_binding_digest: stored.binding_digest,
        sealed_worker_material_ref,
        sealed_worker_material_b64u,
        client_verifying_share_b64u: stored.client_verifying_share_b64u,
        material_format_version,
        material_key_id,
        signer_slot,
    })
}

fn prepare_passkey_prf_worker_material_seal_authorization(
    request: PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest,
) -> Result<PrepareWorkerMaterialSealAuthorizationResult, JsValue> {
    let material_key_id = material_key_id_from_binding_input(&request.binding_input)?;
    let rp_id = require_non_empty(request.rp_id, "rpId")?;
    let credential_id_b64u = require_non_empty(request.credential_id_b64u, "credentialIdB64u")?;
    let mut secret = require_secret32(request.prf_first_bytes, "prfFirstBytes")?;
    let handle = random_material_authorization_handle("passkey-prf-seal")?;
    let (expires_at_ms, remaining_uses) = install_material_authorization_secret(
        handle.clone(),
        StoredWorkerMaterialAuthorizationScope::MaterialKeyId(material_key_id.clone()),
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        &secret,
        request.expires_at_ms,
        MATERIAL_AUTHORIZATION_MAX_USES_V1,
    )?;
    secret.zeroize();
    Ok(PrepareWorkerMaterialSealAuthorizationResult {
        ok: true,
        material_key_id: material_key_id.clone(),
        seal_authorization:
            Ed25519WorkerMaterialSealAuthorizationV1::PasskeyPrfMaterialSealAuthorizationHandleV1 {
                handle,
                rp_id,
                credential_id_b64u,
                material_key_id,
                expires_at_ms,
            },
        remaining_uses,
    })
}

fn prepare_recovery_code_worker_material_seal_authorization(
    request: PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest,
) -> Result<PrepareWorkerMaterialSealAuthorizationResult, JsValue> {
    let material_key_id = material_key_id_from_binding_input(&request.binding_input)?;
    let auth_subject_id = require_non_empty(request.auth_subject_id, "authSubjectId")?;
    let recovery_code_binding_digest = require_non_empty(
        request.recovery_code_binding_digest,
        "recoveryCodeBindingDigest",
    )?;
    let mut secret = require_secret32(request.recovery_code_secret32, "recoveryCodeSecret32")?;
    let handle = random_material_authorization_handle("recovery-code-seal")?;
    let (expires_at_ms, remaining_uses) = install_material_authorization_secret(
        handle.clone(),
        StoredWorkerMaterialAuthorizationScope::MaterialKeyId(material_key_id.clone()),
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        &secret,
        request.expires_at_ms,
        MATERIAL_AUTHORIZATION_MAX_USES_V1,
    )?;
    secret.zeroize();
    Ok(PrepareWorkerMaterialSealAuthorizationResult {
        ok: true,
        material_key_id: material_key_id.clone(),
        seal_authorization:
            Ed25519WorkerMaterialSealAuthorizationV1::RecoveryCodeMaterialSealAuthorizationHandleV1 {
                handle,
                auth_subject_id,
                recovery_code_binding_digest,
                material_key_id,
                expires_at_ms,
            },
        remaining_uses,
    })
}

fn prepare_passkey_prf_worker_material_unseal_authorization(
    request: PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest,
) -> Result<PrepareWorkerMaterialUnsealAuthorizationResult, JsValue> {
    let result = install_passkey_prf_material_authorization(
        InstallPasskeyPrfMaterialAuthorizationRequest {
            purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
            material_binding_digest: request.material_binding_digest,
            rp_id: request.rp_id,
            credential_id_b64u: request.credential_id_b64u,
            prf_first_bytes: request.prf_first_bytes,
            expires_at_ms: request.expires_at_ms,
            max_uses: MATERIAL_AUTHORIZATION_MAX_USES_V1,
        },
    )?;
    Ok(PrepareWorkerMaterialUnsealAuthorizationResult {
        ok: result.ok,
        unseal_authorization: result.authorization,
        remaining_uses: result.remaining_uses,
    })
}

fn prepare_recovery_code_worker_material_unseal_authorization(
    request: PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest,
) -> Result<PrepareWorkerMaterialUnsealAuthorizationResult, JsValue> {
    let result = install_recovery_code_material_authorization(
        InstallRecoveryCodeMaterialAuthorizationRequest {
            purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
            material_binding_digest: request.material_binding_digest,
            auth_subject_id: request.auth_subject_id,
            recovery_code_binding_digest: request.recovery_code_binding_digest,
            recovery_code_secret32: request.recovery_code_secret32,
            expires_at_ms: request.expires_at_ms,
            max_uses: MATERIAL_AUTHORIZATION_MAX_USES_V1,
        },
    )?;
    Ok(PrepareWorkerMaterialUnsealAuthorizationResult {
        ok: result.ok,
        unseal_authorization: result.authorization,
        remaining_uses: result.remaining_uses,
    })
}

fn install_passkey_prf_material_authorization(
    request: InstallPasskeyPrfMaterialAuthorizationRequest,
) -> Result<InstallMaterialAuthorizationResult, JsValue> {
    require_direct_install_unseal_purpose(&request.purpose)?;
    let material_binding_digest =
        require_non_empty(request.material_binding_digest, "materialBindingDigest")?;
    let rp_id = require_non_empty(request.rp_id, "rpId")?;
    let credential_id_b64u = require_non_empty(request.credential_id_b64u, "credentialIdB64u")?;
    let mut secret = require_secret32(request.prf_first_bytes, "prfFirstBytes")?;
    let handle = random_material_authorization_handle("passkey-prf")?;
    let (expires_at_ms, remaining_uses) = install_material_authorization_secret(
        handle.clone(),
        StoredWorkerMaterialAuthorizationScope::MaterialBindingDigest(
            material_binding_digest.clone(),
        ),
        request.purpose,
        &secret,
        request.expires_at_ms,
        request.max_uses,
    )?;
    secret.zeroize();
    Ok(InstallMaterialAuthorizationResult {
        ok: true,
        authorization:
            Ed25519WorkerMaterialCredentialAuthorizationV1::PasskeyPrfMaterialAuthorizationHandleV1 {
                handle,
                purpose: request.purpose,
                rp_id,
                credential_id_b64u,
                material_binding_digest,
                expires_at_ms,
            },
        remaining_uses,
    })
}

fn install_recovery_code_material_authorization(
    request: InstallRecoveryCodeMaterialAuthorizationRequest,
) -> Result<InstallMaterialAuthorizationResult, JsValue> {
    require_direct_install_unseal_purpose(&request.purpose)?;
    let material_binding_digest =
        require_non_empty(request.material_binding_digest, "materialBindingDigest")?;
    let auth_subject_id = require_non_empty(request.auth_subject_id, "authSubjectId")?;
    let recovery_code_binding_digest = require_non_empty(
        request.recovery_code_binding_digest,
        "recoveryCodeBindingDigest",
    )?;
    let mut secret = require_secret32(request.recovery_code_secret32, "recoveryCodeSecret32")?;
    let handle = random_material_authorization_handle("recovery-code")?;
    let (expires_at_ms, remaining_uses) = install_material_authorization_secret(
        handle.clone(),
        StoredWorkerMaterialAuthorizationScope::MaterialBindingDigest(
            material_binding_digest.clone(),
        ),
        request.purpose,
        &secret,
        request.expires_at_ms,
        request.max_uses,
    )?;
    secret.zeroize();
    Ok(InstallMaterialAuthorizationResult {
        ok: true,
        authorization:
            Ed25519WorkerMaterialCredentialAuthorizationV1::RecoveryCodeMaterialAuthorizationHandleV1 {
                handle,
                purpose: request.purpose,
                auth_subject_id,
                recovery_code_binding_digest,
                material_binding_digest,
                expires_at_ms,
            },
        remaining_uses,
    })
}

fn require_direct_install_unseal_purpose(
    purpose: &Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<(), JsValue> {
    require_direct_install_unseal_purpose_internal(purpose)
        .map_err(|message| JsValue::from_str(&message))
}

fn require_direct_install_unseal_purpose_internal(
    purpose: &Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<(), String> {
    if purpose == &Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal {
        return Ok(());
    }
    Err(material_authorization_error(
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        "direct seal install is disabled; use prepared seal authorization",
    ))
}

fn install_material_authorization_secret(
    handle: String,
    scope: StoredWorkerMaterialAuthorizationScope,
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    secret: &[u8],
    expires_at_ms: u64,
    remaining_uses: u32,
) -> Result<(u64, u32), JsValue> {
    let expires_at_ms = resolve_material_authorization_expires_at_ms(expires_at_ms, purpose)?;
    let remaining_uses = require_v1_material_authorization_max_uses(remaining_uses, purpose)?;
    if expires_at_ms <= now_ms() {
        return Err(JsValue::from_str(&material_authorization_error(
            purpose,
            "material authorization expired",
        )));
    }
    WORKER_MATERIAL_AUTHORIZATION_SECRET_BY_HANDLE.with(|store| {
        store.borrow_mut().insert(
            handle,
            StoredWorkerMaterialCredentialAuthorizationSecret {
                secret: secret.to_vec(),
                scope,
                purpose,
                expires_at_ms,
                remaining_uses,
            },
        );
    });
    Ok((expires_at_ms, remaining_uses))
}

fn install_hss_client_output_mask(
    handle: String,
    mask: [u8; 32],
    context_binding_b64u: String,
    requested_expires_at_ms: u64,
) -> Result<(u64, u32), JsValue> {
    let expires_at_ms = resolve_hss_client_output_mask_expires_at_ms(requested_expires_at_ms)?;
    HSS_CLIENT_OUTPUT_MASK_BY_HANDLE.with(|store| {
        store.borrow_mut().insert(
            handle,
            StoredHssClientOutputMask {
                mask,
                context_binding_b64u,
                expires_at_ms,
                remaining_uses: HSS_CLIENT_OUTPUT_MASK_USES_V1,
            },
        );
    });
    Ok((expires_at_ms, HSS_CLIENT_OUTPUT_MASK_USES_V1))
}

fn store_worker_material_from_base_share_bytes(
    material_handle: String,
    x_client_base: [u8; 32],
    expected_client_verifying_share_b64u: String,
    binding_digest: String,
    binding: Ed25519WorkerMaterialBindingV1,
) -> Result<WorkerMaterialResult, JsValue> {
    let client_verifying_share = role_separated_ed25519_client_verifying_share_v1(x_client_base)
        .map_err(|e| JsValue::from_str(&format!("Invalid Ed25519 worker material: {e}")))?;
    let client_verifying_share_b64u = base64_url_encode(&client_verifying_share);
    if client_verifying_share_b64u != expected_client_verifying_share_b64u {
        return Err(JsValue::from_str(
            "Ed25519 worker material verifying-share binding mismatch",
        ));
    }
    WORKER_MATERIAL_BY_HANDLE.with(|store| {
        store.borrow_mut().insert(
            material_handle.clone(),
            StoredWorkerMaterial {
                material_handle: material_handle.clone(),
                x_client_base,
                client_verifying_share_b64u: client_verifying_share_b64u.clone(),
                binding_digest: binding_digest.clone(),
                binding,
            },
        );
    });
    Ok(WorkerMaterialResult {
        material_handle,
        client_verifying_share_b64u,
        binding_digest,
    })
}

#[cfg(feature = "hss-client-exports")]
fn open_hss_client_output_for_worker_material(
    request: &StoreWorkerMaterialFromHssOutputRequest,
) -> Result<crate::threshold::threshold_hss::ThresholdEd25519HssOpenClientOutputOutput, JsValue> {
    let expected_context_binding_b64u = require_non_empty(
        request.expected_context_binding_b64u.clone(),
        "expectedContextBindingB64u",
    )?;
    let mut client_output_mask =
        take_hss_client_output_mask(&request.client_output_mask, &expected_context_binding_b64u)?;
    let client_output_mask_b64u = base64_url_encode(&client_output_mask);
    client_output_mask.zeroize();
    open_threshold_ed25519_hss_client_output(ThresholdEd25519HssOpenClientOutputArgs {
        evaluator_driver_state_b64u: request.evaluator_driver_state_b64u.clone(),
        client_output_message_b64u: request.client_output_message_b64u.clone(),
        client_output_mask_b64u,
    })
    .map_err(|e| JsValue::from_str(&e))
}

#[cfg(not(feature = "hss-client-exports"))]
fn open_hss_client_output_for_worker_material(
    _request: &StoreWorkerMaterialFromHssOutputRequest,
) -> Result<WorkerMaterialOpenedHssOutput, JsValue> {
    Err(JsValue::from_str(
        "StoreThresholdEd25519WorkerMaterialFromHssOutput requires hss-client-exports",
    ))
}

#[cfg(not(feature = "hss-client-exports"))]
struct WorkerMaterialOpenedHssOutput {
    context_binding_b64u: String,
    x_client_base_b64u: String,
}

fn validate_worker_material(
    request: ValidateWorkerMaterialRequest,
) -> Result<WorkerMaterialResult, JsValue> {
    let material_handle = require_non_empty(request.material_handle, "materialHandle")?;
    with_material(
        &material_handle,
        &request.expected_material_binding,
        |material| {
            Ok(WorkerMaterialResult {
                material_handle: material.material_handle.clone(),
                client_verifying_share_b64u: material.client_verifying_share_b64u.clone(),
                binding_digest: material.binding_digest.clone(),
            })
        },
    )
}

fn restore_worker_material(
    request: Ed25519RestoreWorkerMaterialRequestV1,
) -> Result<WorkerMaterialRestoreResult, JsValue> {
    let expected_binding_digest = signer_core_result_to_js(
        validate_ed25519_worker_material_binding(&request.expected_material_binding),
    )?;
    let sealed_worker_material_ref = sealed_worker_material_ref_from_transport(
        &request.sealed_material,
        "sealedMaterial.sealedWorkerMaterialRef",
    )?;
    let artifact = resolve_sealed_worker_material_transport(
        request.sealed_material,
        &expected_binding_digest,
    )?;
    let sealed_worker_material_b64u = encode_sealed_worker_material_b64u(&artifact)?;
    let mut unseal_secret = consume_material_authorization_secret(
        request.unseal_authorization,
        &expected_binding_digest,
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
    )?;
    let x_client_base = signer_core_result_to_js(open_ed25519_worker_material_artifact(
        &artifact,
        &request.expected_material_binding,
        &unseal_secret,
    ))?;
    unseal_secret.zeroize();
    let expected_client_verifying_share_b64u = require_non_empty(
        request
            .expected_material_binding
            .client_verifying_share_b64u
            .clone(),
        "expectedMaterialBinding.clientVerifyingShareB64u",
    )?;
    let material_format_version = request.expected_material_binding.material_format_version;
    let material_key_id = request.expected_material_binding.material_key_id.clone();
    let signer_slot = request.expected_material_binding.signer_slot;
    let stored = store_worker_material_from_base_share_bytes(
        random_worker_material_handle()?,
        x_client_base,
        expected_client_verifying_share_b64u,
        expected_binding_digest,
        request.expected_material_binding,
    )?;
    Ok(WorkerMaterialRestoreResult {
        ok: true,
        material_handle: stored.material_handle,
        material_binding_digest: stored.binding_digest,
        sealed_worker_material_ref,
        sealed_worker_material_b64u,
        client_verifying_share_b64u: stored.client_verifying_share_b64u,
        material_format_version,
        material_key_id,
        signer_slot,
    })
}

fn put_sealed_worker_material(
    request: Ed25519PutSealedWorkerMaterialRequestV1,
) -> Result<Ed25519PutSealedWorkerMaterialSuccessV1, JsValue> {
    let material_binding_digest = signer_core_result_to_js(
        validate_ed25519_worker_material_binding(&request.sealed_material.binding),
    )?;
    if request.sealed_material.material_binding_digest != material_binding_digest {
        return Err(JsValue::from_str(
            "Ed25519 sealed worker material binding digest mismatch",
        ));
    }
    let sealed_worker_material_ref = signer_core_result_to_js(
        ed25519_worker_material_storage_ref(&material_binding_digest),
    )?;
    SEALED_WORKER_MATERIAL_BY_REF.with(|store| {
        store
            .borrow_mut()
            .insert(sealed_worker_material_ref.clone(), request.sealed_material);
    });
    Ok(Ed25519PutSealedWorkerMaterialSuccessV1 {
        ok: true,
        sealed_worker_material_ref,
        material_binding_digest,
    })
}

fn seal_and_store_worker_material(
    binding: &Ed25519WorkerMaterialBindingV1,
    material_binding_digest: &str,
    x_client_base: &[u8; 32],
    unseal_secret: &[u8],
) -> Result<(String, String), JsValue> {
    let salt =
        random_fixed_bytes::<ED25519_WORKER_MATERIAL_SEAL_SALT_SIZE>("sealed material salt")?;
    let nonce =
        random_fixed_bytes::<ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE>("sealed material nonce")?;
    let sealed_material = signer_core_result_to_js(seal_ed25519_worker_material_artifact(
        binding,
        x_client_base,
        unseal_secret,
        &salt,
        &nonce,
    ))?;
    let sealed_worker_material_b64u = encode_sealed_worker_material_b64u(&sealed_material)?;
    let stored = put_sealed_worker_material(Ed25519PutSealedWorkerMaterialRequestV1 {
        kind:
            Ed25519PutSealedWorkerMaterialRequestKindV1::PutThresholdEd25519SealedWorkerMaterialV1,
        sealed_material,
    })?;
    if stored.material_binding_digest != material_binding_digest {
        return Err(JsValue::from_str(
            "material_scope_mismatch: sealed material digest does not match stored material",
        ));
    }
    Ok((
        stored.sealed_worker_material_ref,
        sealed_worker_material_b64u,
    ))
}

fn encode_sealed_worker_material_b64u(
    sealed_material: &Ed25519SealedWorkerMaterialV1,
) -> Result<String, JsValue> {
    let bytes = serde_json::to_vec(sealed_material).map_err(|e| {
        JsValue::from_str(&format!("Failed to serialize sealed worker material: {e}"))
    })?;
    Ok(base64_url_encode(&bytes))
}

fn read_sealed_worker_material(
    request: Ed25519ReadSealedWorkerMaterialRequestV1,
) -> Result<Ed25519ReadSealedWorkerMaterialSuccessV1, JsValue> {
    let sealed_worker_material_ref = require_non_empty(
        request.sealed_worker_material_ref,
        "sealedWorkerMaterialRef",
    )?;
    let expected_material_binding_digest = require_non_empty(
        request.expected_material_binding_digest,
        "expectedMaterialBindingDigest",
    )?;
    let sealed_material = read_sealed_worker_material_by_ref(
        &sealed_worker_material_ref,
        &expected_material_binding_digest,
    )?;
    Ok(Ed25519ReadSealedWorkerMaterialSuccessV1 {
        ok: true,
        sealed_material,
    })
}

fn delete_sealed_worker_material(
    request: Ed25519DeleteSealedWorkerMaterialRequestV1,
) -> Result<Ed25519DeleteSealedWorkerMaterialSuccessV1, JsValue> {
    let sealed_worker_material_ref = require_non_empty(
        request.sealed_worker_material_ref,
        "sealedWorkerMaterialRef",
    )?;
    let expected_material_binding_digest = require_non_empty(
        request.expected_material_binding_digest,
        "expectedMaterialBindingDigest",
    )?;
    validate_sealed_worker_material_ref(
        &sealed_worker_material_ref,
        &expected_material_binding_digest,
    )?;
    let deleted = SEALED_WORKER_MATERIAL_BY_REF.with(|store| {
        store
            .borrow_mut()
            .remove(&sealed_worker_material_ref)
            .is_some()
    });
    Ok(Ed25519DeleteSealedWorkerMaterialSuccessV1 { ok: true, deleted })
}

fn create_client_presign_from_worker_material(
    request: CreateClientPresignFromWorkerMaterialRequest,
) -> Result<ClientPresignCreateResult, JsValue> {
    validate_create_client_presign_request_scope(&request)?;
    let material_handle = require_non_empty(request.material_handle, "materialHandle")?;
    with_material(
        &material_handle,
        &request.expected_material_binding,
        |material| {
            let key_package = key_package_from_material(
                material,
                &request.group_public_key,
                request.client_participant_id,
                request.relayer_participant_id,
            )?;
            let round1 = signer_core::near_threshold_ed25519::client_round1_commit(&key_package)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let nonce_bytes = round1.nonces.serialize().map_err(|e| {
                JsValue::from_str(&format!("Failed to serialize client nonces: {e}"))
            })?;
            let client_verifying_share_bytes =
                key_package.verifying_share().serialize().map_err(|e| {
                    JsValue::from_str(&format!("Failed to serialize client verifying share: {e}"))
                })?;
            let nonce_handle = next_client_presign_handle();
            CLIENT_PRESIGN_NONCE_BY_HANDLE.with(|store| {
                store.borrow_mut().insert(
                    nonce_handle.clone(),
                    StoredClientPresignNonce { nonce_bytes },
                );
            });
            Ok(ClientPresignCreateResult {
                client_nonce_handle_b64u: nonce_handle,
                client_verifying_share_b64u: base64_url_encode(
                    client_verifying_share_bytes.as_slice(),
                ),
                client_commitments: round1.commitments_wire,
            })
        },
    )
}

fn sign_client_presign_from_worker_material(
    request: SignClientPresignFromWorkerMaterialRequest,
) -> Result<ClientPresignSignResult, JsValue> {
    validate_sign_client_presign_request_scope(&request)?;
    let material_handle = require_non_empty(request.material_handle, "materialHandle")?;
    let client_nonce_handle =
        require_non_empty(request.client_nonce_handle_b64u, "clientNonceHandleB64u")?;
    with_material(
        &material_handle,
        &request.expected_material_binding,
        |material| {
            let nonce_bytes = take_client_presign_nonce(&client_nonce_handle)?;
            let nonces = frost_ed25519::round1::SigningNonces::deserialize(nonce_bytes.as_slice())
                .map_err(|e| JsValue::from_str(&format!("Invalid clientNonceHandleB64u: {e}")))?;
            let signing_digest =
                decode_fixed_32(&request.signing_digest_b64u, "signingDigestB64u")?;
            let (client_id, relayer_id) =
                signer_core::near_threshold_ed25519::validate_threshold_ed25519_participant_ids_2p(
                    Some(request.client_participant_id),
                    Some(request.relayer_participant_id),
                    &[],
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let client_identifier =
                identifier_from_participant_id(client_id, "clientParticipantId")?;
            let relayer_identifier =
                identifier_from_participant_id(relayer_id, "relayerParticipantId")?;
            let key_package = key_package_from_material(
                material,
                &request.group_public_key,
                request.client_participant_id,
                request.relayer_participant_id,
            )?;
            let client_commitments = signer_core::near_threshold_ed25519::commitments_from_wire(
                &request.client_commitments,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let relayer_commitments = signer_core::near_threshold_ed25519::commitments_from_wire(
                &request.relayer_commitments,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let mut commitments_by_id = BTreeMap::new();
            commitments_by_id.insert(client_identifier, client_commitments);
            commitments_by_id.insert(relayer_identifier, relayer_commitments);
            let signing_package = signer_core::near_threshold_ed25519::build_signing_package(
                signing_digest.as_slice(),
                commitments_by_id,
            );
            let client_signature_share =
                signer_core::near_threshold_ed25519::client_round2_signature_share(
                    &signing_package,
                    &nonces,
                    &key_package,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let client_signature_share_b64u =
                signer_core::near_threshold_ed25519::signature_share_to_b64u(
                    &client_signature_share,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(ClientPresignSignResult {
                client_signature_share_b64u,
            })
        },
    )
}

fn create_role_separated_normal_signing_client_share_from_worker_material(
    request: RoleSeparatedNormalSigningClientShareFromWorkerMaterialRequest,
) -> Result<RoleSeparatedNormalSigningClientShareResult, JsValue> {
    validate_role_separated_normal_signing_request_scope(&request)?;
    let material_handle = require_non_empty(request.material_handle, "materialHandle")?;
    with_material(
        &material_handle,
        &request.expected_material_binding,
        |material| {
            let group_public_key =
                signer_core::near_threshold_ed25519::parse_near_public_key_to_bytes(
                    &request.group_public_key,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let server_verifying_share = decode_fixed_32(
                &request.server_verifying_share_b64u,
                "serverVerifyingShareB64u",
            )?;
            let server_commitments =
                role_separated_commitments_from_wire(&request.server_commitments)?;
            let signing_digest =
                decode_fixed_32(&request.signing_digest_b64u, "signingDigestB64u")?;
            let mut rng = frost_ed25519::rand_core::OsRng;
            let client_round1 = prepare_role_separated_ed25519_round1_v1(&mut rng)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let client_verifying_share =
                role_separated_ed25519_client_verifying_share_v1(material.x_client_base)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let client_signature_share = create_role_separated_ed25519_client_signature_share_v1(
                RoleSeparatedEd25519ClientShareRequestV1 {
                    x_client_base: material.x_client_base,
                    client_round1: &client_round1,
                    group_public_key,
                    client_verifying_share,
                    server_verifying_share,
                    server_commitments,
                    signing_payload: &signing_digest,
                },
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(RoleSeparatedNormalSigningClientShareResult {
                client_commitments: role_separated_commitments_to_wire(client_round1.commitments),
                client_verifying_share_b64u: base64_url_encode(&client_verifying_share),
                client_signature_share_b64u: base64_url_encode(&client_signature_share),
            })
        },
    )
}

fn burn_client_presign(request: BurnClientPresignRequest) -> ClientPresignBurnResult {
    let handle = request.client_nonce_handle_b64u.trim().to_string();
    if !handle.is_empty() {
        CLIENT_PRESIGN_NONCE_BY_HANDLE.with(|store| {
            store.borrow_mut().remove(&handle);
        });
    }
    ClientPresignBurnResult { burned: true }
}

fn resolve_sealed_worker_material_transport(
    transport: Ed25519SealedWorkerMaterialTransportV1,
    expected_material_binding_digest: &str,
) -> Result<Ed25519SealedWorkerMaterialV1, JsValue> {
    match transport {
        Ed25519SealedWorkerMaterialTransportV1::StorageRef {
            sealed_worker_material_ref,
        } => read_sealed_worker_material_by_ref(
            &sealed_worker_material_ref,
            expected_material_binding_digest,
        ),
        Ed25519SealedWorkerMaterialTransportV1::InlineSealedBlob {
            sealed_worker_material_ref,
            sealed_worker_material_b64u,
        } => {
            validate_sealed_worker_material_ref(
                &sealed_worker_material_ref,
                expected_material_binding_digest,
            )?;
            let sealed_material = decode_inline_sealed_worker_material(
                &sealed_worker_material_b64u,
                expected_material_binding_digest,
            )?;
            SEALED_WORKER_MATERIAL_BY_REF.with(|store| {
                store
                    .borrow_mut()
                    .insert(sealed_worker_material_ref, sealed_material.clone());
            });
            Ok(sealed_material)
        }
    }
}

fn sealed_worker_material_ref_from_transport(
    transport: &Ed25519SealedWorkerMaterialTransportV1,
    field_name: &str,
) -> Result<String, JsValue> {
    match transport {
        Ed25519SealedWorkerMaterialTransportV1::StorageRef {
            sealed_worker_material_ref,
        }
        | Ed25519SealedWorkerMaterialTransportV1::InlineSealedBlob {
            sealed_worker_material_ref,
            ..
        } => require_non_empty(sealed_worker_material_ref.clone(), field_name),
    }
}

fn read_sealed_worker_material_by_ref(
    sealed_worker_material_ref: &str,
    expected_material_binding_digest: &str,
) -> Result<Ed25519SealedWorkerMaterialV1, JsValue> {
    validate_sealed_worker_material_ref(
        sealed_worker_material_ref,
        expected_material_binding_digest,
    )?;
    SEALED_WORKER_MATERIAL_BY_REF.with(|store| {
        let sealed_material = store
            .borrow()
            .get(sealed_worker_material_ref)
            .cloned()
            .ok_or_else(|| JsValue::from_str("material_restore_required: sealed ref missing"))?;
        if sealed_material.material_binding_digest != expected_material_binding_digest {
            return Err(JsValue::from_str(
                "material_corrupt: sealed material digest mismatch",
            ));
        }
        Ok(sealed_material)
    })
}

fn decode_inline_sealed_worker_material(
    sealed_worker_material_b64u: &str,
    expected_material_binding_digest: &str,
) -> Result<Ed25519SealedWorkerMaterialV1, JsValue> {
    let encoded = require_non_empty(
        sealed_worker_material_b64u.to_string(),
        "sealedWorkerMaterialB64u",
    )?;
    let bytes = base64_url_decode(&encoded)
        .map_err(|e| JsValue::from_str(&format!("material_corrupt: invalid sealed blob: {e}")))?;
    let sealed_material: Ed25519SealedWorkerMaterialV1 = serde_json::from_slice(&bytes)
        .map_err(|e| JsValue::from_str(&format!("material_corrupt: invalid sealed JSON: {e}")))?;
    if sealed_material.material_binding_digest != expected_material_binding_digest {
        return Err(JsValue::from_str(
            "material_corrupt: sealed material digest mismatch",
        ));
    }
    Ok(sealed_material)
}

fn validate_sealed_worker_material_ref(
    sealed_worker_material_ref: &str,
    expected_material_binding_digest: &str,
) -> Result<(), JsValue> {
    let sealed_worker_material_ref = require_non_empty(
        sealed_worker_material_ref.to_string(),
        "sealedWorkerMaterialRef",
    )?;
    let expected_material_binding_digest = require_non_empty(
        expected_material_binding_digest.to_string(),
        "expectedMaterialBindingDigest",
    )?;
    let expected_ref = signer_core_result_to_js(ed25519_worker_material_storage_ref(
        &expected_material_binding_digest,
    ))?;
    if sealed_worker_material_ref != expected_ref {
        return Err(JsValue::from_str(
            "material_scope_mismatch: sealed material ref does not match binding digest",
        ));
    }
    Ok(())
}

fn consume_material_authorization_secret(
    authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
    expected_material_binding_digest: &str,
    expected_purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<Vec<u8>, JsValue> {
    consume_material_authorization_secret_internal(
        authorization,
        expected_material_binding_digest,
        expected_purpose,
    )
    .map_err(|message| JsValue::from_str(&message))
}

fn consume_material_authorization_secret_internal(
    authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
    expected_material_binding_digest: &str,
    expected_purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<Vec<u8>, String> {
    let (handle, source_binding_digest, source_purpose, expires_at_ms) =
        material_authorization_facts(authorization, expected_purpose)?;
    let expected_scope = StoredWorkerMaterialAuthorizationScope::MaterialBindingDigest(
        expected_material_binding_digest.to_string(),
    );
    if source_purpose != expected_purpose {
        return Err(material_authorization_error(
            expected_purpose,
            "authorization purpose mismatch",
        ));
    }
    if source_binding_digest != expected_material_binding_digest {
        return Err(material_authorization_error(
            expected_purpose,
            "authorization binding digest mismatch",
        ));
    }
    consume_material_authorization_secret_by_scope(
        handle,
        expected_scope,
        expected_purpose,
        expires_at_ms,
    )
}

fn consume_material_seal_authorization_secret(
    authorization: Ed25519WorkerMaterialSealAuthorizationV1,
    expected_material_key_id: &str,
) -> Result<Vec<u8>, JsValue> {
    consume_material_seal_authorization_secret_internal(authorization, expected_material_key_id)
        .map_err(|message| JsValue::from_str(&message))
}

fn consume_material_seal_authorization_secret_internal(
    authorization: Ed25519WorkerMaterialSealAuthorizationV1,
    expected_material_key_id: &str,
) -> Result<Vec<u8>, String> {
    let expected_purpose = Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal;
    let (handle, material_key_id, expires_at_ms) =
        material_seal_authorization_facts(authorization)?;
    let material_key_id =
        require_material_authorization_field(material_key_id, "materialKeyId", expected_purpose)?;
    if material_key_id != expected_material_key_id {
        return Err(material_authorization_error(
            expected_purpose,
            "authorization material key id mismatch",
        ));
    }
    consume_material_authorization_secret_by_scope(
        handle,
        StoredWorkerMaterialAuthorizationScope::MaterialKeyId(material_key_id),
        expected_purpose,
        expires_at_ms,
    )
}

fn consume_material_authorization_secret_by_scope(
    handle: String,
    expected_scope: StoredWorkerMaterialAuthorizationScope,
    expected_purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    expires_at_ms: u64,
) -> Result<Vec<u8>, String> {
    if expires_at_ms <= now_ms() {
        return Err(material_authorization_error(
            expected_purpose,
            "authorization expired",
        ));
    }
    WORKER_MATERIAL_AUTHORIZATION_SECRET_BY_HANDLE.with(|store| {
        let mut borrowed = store.borrow_mut();
        let mut entry = borrowed.remove(&handle).ok_or_else(|| {
            material_authorization_error(expected_purpose, "authorization handle missing")
        })?;
        if entry.purpose != expected_purpose {
            return Err(material_authorization_error(
                expected_purpose,
                "stored authorization purpose mismatch",
            ));
        }
        if entry.scope != expected_scope {
            return Err(material_authorization_error(
                expected_purpose,
                "stored authorization scope mismatch",
            ));
        }
        if entry.expires_at_ms <= now_ms() || entry.remaining_uses == 0 {
            return Err(material_authorization_error(
                expected_purpose,
                "authorization unavailable",
            ));
        }
        entry.remaining_uses -= 1;
        let secret = entry.secret.clone();
        if entry.remaining_uses > 0 {
            borrowed.insert(handle, entry);
        }
        Ok(secret)
    })
}

fn material_seal_authorization_facts(
    authorization: Ed25519WorkerMaterialSealAuthorizationV1,
) -> Result<(String, String, u64), String> {
    let expected_purpose = Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal;
    match authorization {
        Ed25519WorkerMaterialSealAuthorizationV1::PasskeyPrfMaterialSealAuthorizationHandleV1 {
            handle,
            material_key_id,
            expires_at_ms,
            ..
        } => Ok((
            require_material_authorization_field(handle, "handle", expected_purpose)?,
            material_key_id,
            expires_at_ms,
        )),
        Ed25519WorkerMaterialSealAuthorizationV1::RecoveryCodeMaterialSealAuthorizationHandleV1 {
            handle,
            material_key_id,
            expires_at_ms,
            ..
        } => Ok((
            require_material_authorization_field(handle, "handle", expected_purpose)?,
            material_key_id,
            expires_at_ms,
        )),
    }
}

fn material_authorization_facts(
    authorization: Ed25519WorkerMaterialCredentialAuthorizationV1,
    expected_purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<
    (
        String,
        String,
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
        u64,
    ),
    String,
> {
    match authorization {
        Ed25519WorkerMaterialCredentialAuthorizationV1::PasskeyPrfMaterialAuthorizationHandleV1 {
            handle,
            purpose,
            material_binding_digest,
            expires_at_ms,
            ..
        } => Ok((
            require_material_authorization_field(handle, "handle", expected_purpose)?,
            require_material_authorization_field(
                material_binding_digest,
                "materialBindingDigest",
                expected_purpose,
            )?,
            purpose,
            expires_at_ms,
        )),
        Ed25519WorkerMaterialCredentialAuthorizationV1::RecoveryCodeMaterialAuthorizationHandleV1 {
            handle,
            purpose,
            material_binding_digest,
            expires_at_ms,
            ..
        } => Ok((
            require_material_authorization_field(handle, "handle", expected_purpose)?,
            require_material_authorization_field(
                material_binding_digest,
                "materialBindingDigest",
                expected_purpose,
            )?,
            purpose,
            expires_at_ms,
        )),
    }
}

fn require_material_authorization_field(
    value: String,
    field: &str,
    expected_purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(material_authorization_error(
            expected_purpose,
            &format!("{field} missing"),
        ));
    }
    Ok(value)
}

fn material_authorization_error(
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
    reason: &str,
) -> String {
    let code = match purpose {
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal => {
            "material_seal_authorization_required"
        }
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal => {
            "material_unseal_authorization_required"
        }
    };
    format!("{code}: {reason}")
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> u64 {
    js_sys::Date::now().max(0.0).floor() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn signer_core_result_to_js<T>(result: signer_core::error::CoreResult<T>) -> Result<T, JsValue> {
    result.map_err(|e| JsValue::from_str(&e.to_string()))
}

fn material_binding_from_hss_store_request(
    request: &StoreWorkerMaterialFromHssOutputRequest,
    client_verifying_share_b64u: String,
) -> Result<Ed25519WorkerMaterialBindingV1, JsValue> {
    if request.created_at_ms == 0 {
        return Err(JsValue::from_str("createdAtMs must be positive"));
    }
    let identity = material_key_identity_from_parts(MaterialKeyIdentityParts {
        near_account_id: request.near_account_id.clone(),
        signer_slot: request.signer_slot,
        signing_root_id: request.signing_root_id.clone(),
        signing_root_version: request.signing_root_version.clone(),
        relayer_key_id: request.relayer_key_id.clone(),
    })?;
    let material_key_id = signer_core_result_to_js(ed25519_worker_material_key_id(&identity))?;
    Ok(Ed25519WorkerMaterialBindingV1 {
        kind: Ed25519WorkerMaterialBindingKindV1::Ed25519WorkerMaterialBindingV1,
        curve: Ed25519WorkerMaterialCurveV1::Ed25519,
        protocol: Ed25519WorkerMaterialProtocolV1::RouterAbNormalSigning,
        near_account_id: identity.near_account_id,
        signer_slot: identity.signer_slot,
        signing_root_id: identity.signing_root_id,
        signing_root_version: identity.signing_root_version,
        relayer_key_id: identity.relayer_key_id,
        participant_ids: require_positive_participant_ids(&request.participant_ids)?,
        client_verifying_share_b64u,
        material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
        material_key_id,
        created_at_ms: request.created_at_ms,
    })
}

struct MaterialKeyIdentityParts {
    near_account_id: String,
    signer_slot: u32,
    signing_root_id: String,
    signing_root_version: String,
    relayer_key_id: String,
}

fn material_key_id_from_binding_input(
    input: &WorkerMaterialBindingInputWithoutVerifier,
) -> Result<String, JsValue> {
    if input.created_at_ms == 0 {
        return Err(JsValue::from_str(
            "bindingInput.createdAtMs must be positive",
        ));
    }
    require_positive_participant_ids(&input.participant_ids)?;
    let identity = material_key_identity_from_parts(MaterialKeyIdentityParts {
        near_account_id: input.near_account_id.clone(),
        signer_slot: input.signer_slot,
        signing_root_id: input.signing_root_id.clone(),
        signing_root_version: input.signing_root_version.clone(),
        relayer_key_id: input.relayer_key_id.clone(),
    })?;
    signer_core_result_to_js(ed25519_worker_material_key_id(&identity))
}

fn material_key_identity_from_parts(
    parts: MaterialKeyIdentityParts,
) -> Result<Ed25519WorkerMaterialKeyIdentityV1, JsValue> {
    Ok(Ed25519WorkerMaterialKeyIdentityV1 {
        kind: Ed25519WorkerMaterialKeyIdentityKindV1::Ed25519WorkerMaterialKeyIdentityV1,
        near_account_id: require_non_empty(parts.near_account_id, "nearAccountId")?,
        signer_slot: require_positive_u32(parts.signer_slot, "signerSlot")?,
        signing_root_id: require_non_empty(parts.signing_root_id, "signingRootId")?,
        signing_root_version: require_non_empty(parts.signing_root_version, "signingRootVersion")?,
        relayer_key_id: require_non_empty(parts.relayer_key_id, "relayerKeyId")?,
        material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
    })
}

fn validate_create_client_presign_request_scope(
    request: &CreateClientPresignFromWorkerMaterialRequest,
) -> Result<String, JsValue> {
    validate_create_client_presign_request_scope_internal(request)
        .map_err(|message| JsValue::from_str(&message))
}

fn validate_create_client_presign_request_scope_internal(
    request: &CreateClientPresignFromWorkerMaterialRequest,
) -> Result<String, String> {
    validate_material_and_session_bindings_internal(
        &request.expected_material_binding,
        &request.expected_session_binding,
        &request.expected_session_binding_digest,
    )
}

fn validate_sign_client_presign_request_scope(
    request: &SignClientPresignFromWorkerMaterialRequest,
) -> Result<String, JsValue> {
    validate_sign_client_presign_request_scope_internal(request)
        .map_err(|message| JsValue::from_str(&message))
}

fn validate_sign_client_presign_request_scope_internal(
    request: &SignClientPresignFromWorkerMaterialRequest,
) -> Result<String, String> {
    validate_material_and_session_bindings_internal(
        &request.expected_material_binding,
        &request.expected_session_binding,
        &request.expected_session_binding_digest,
    )
}

fn validate_role_separated_normal_signing_request_scope(
    request: &RoleSeparatedNormalSigningClientShareFromWorkerMaterialRequest,
) -> Result<String, JsValue> {
    validate_role_separated_normal_signing_request_scope_internal(request)
        .map_err(|message| JsValue::from_str(&message))
}

fn validate_role_separated_normal_signing_request_scope_internal(
    request: &RoleSeparatedNormalSigningClientShareFromWorkerMaterialRequest,
) -> Result<String, String> {
    validate_material_and_session_bindings_internal(
        &request.expected_material_binding,
        &request.expected_session_binding,
        &request.expected_session_binding_digest,
    )
}

fn validate_material_and_session_bindings_internal(
    material_binding: &Ed25519WorkerMaterialBindingV1,
    session_binding: &Ed25519WorkerMaterialSessionBindingV1,
    expected_session_binding_digest: &str,
) -> Result<String, String> {
    let material_binding_digest = validate_ed25519_worker_material_binding(material_binding)
        .map_err(|error| format!("material_binding_mismatch: {}", error))?;
    let session_binding_digest = ed25519_worker_material_session_binding_digest(session_binding)
        .map_err(|error| format!("material_scope_mismatch: {}", error))?;
    require_non_empty_for_session_binding(
        expected_session_binding_digest,
        "expectedSessionBindingDigest",
    )?;
    if session_binding_digest != expected_session_binding_digest {
        return Err("material_scope_mismatch: session binding digest mismatch".to_string());
    }
    if session_binding.material_binding_digest != material_binding_digest {
        return Err(
            "material_scope_mismatch: session binding does not target material binding".to_string(),
        );
    }
    if session_binding.expires_at_ms <= now_ms() {
        return Err("material_scope_mismatch: session binding is expired".to_string());
    }
    if session_binding.near_account_id != material_binding.near_account_id
        || session_binding.signer_slot != material_binding.signer_slot
        || session_binding.signing_root_id != material_binding.signing_root_id
        || session_binding.signing_root_version != material_binding.signing_root_version
        || session_binding.relayer_key_id != material_binding.relayer_key_id
        || session_binding.participant_ids != material_binding.participant_ids
    {
        return Err(
            "material_scope_mismatch: session binding identity does not match material binding"
                .to_string(),
        );
    }
    require_non_empty_for_session_binding(
        &session_binding.threshold_session_id,
        "expectedSessionBinding.thresholdSessionId",
    )?;
    require_non_empty_for_session_binding(
        &session_binding.signing_grant_id,
        "expectedSessionBinding.signingGrantId",
    )?;
    require_non_empty_for_session_binding(
        &session_binding.signing_worker_id,
        "expectedSessionBinding.signingWorkerId",
    )?;
    Ok(material_binding_digest)
}

fn require_non_empty_for_session_binding(value: &str, field_name: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field_name} is required"));
    }
    Ok(())
}

fn with_material<T>(
    material_handle: &str,
    expected_material_binding: &Ed25519WorkerMaterialBindingV1,
    f: impl FnOnce(&StoredWorkerMaterial) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    let expected_binding_digest = signer_core_result_to_js(
        validate_ed25519_worker_material_binding(expected_material_binding),
    )?;
    let expected_client_verifying_share_b64u = require_non_empty(
        expected_material_binding
            .client_verifying_share_b64u
            .clone(),
        "expectedMaterialBinding.clientVerifyingShareB64u",
    )?;
    WORKER_MATERIAL_BY_HANDLE.with(|store| {
        let borrowed = store.borrow();
        let material = borrowed.get(material_handle).ok_or_else(|| {
            JsValue::from_str("Ed25519 worker material handle is not loaded in this worker")
        })?;
        if material.binding_digest != expected_binding_digest {
            return Err(JsValue::from_str(
                "material_binding_mismatch: Ed25519 worker material digest mismatch",
            ));
        }
        if material.binding != *expected_material_binding {
            return Err(JsValue::from_str(
                "material_scope_mismatch: Ed25519 worker material binding payload mismatch",
            ));
        }
        if material.client_verifying_share_b64u != expected_client_verifying_share_b64u {
            return Err(JsValue::from_str(
                "material_binding_mismatch: Ed25519 worker material verifier mismatch",
            ));
        }
        f(material)
    })
}

fn key_package_from_material(
    material: &StoredWorkerMaterial,
    group_public_key: &str,
    client_participant_id: u16,
    relayer_participant_id: u16,
) -> Result<frost_ed25519::keys::KeyPackage, JsValue> {
    let group_public_key_bytes =
        signer_core::near_threshold_ed25519::parse_near_public_key_to_bytes(group_public_key)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (client_id, _relayer_id) =
        signer_core::near_threshold_ed25519::validate_threshold_ed25519_participant_ids_2p(
            Some(client_participant_id),
            Some(relayer_participant_id),
            &[],
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client_identifier = identifier_from_participant_id(client_id, "clientParticipantId")?;
    signer_core::near_threshold_ed25519::key_package_from_signing_share_bytes(
        &material.x_client_base,
        &group_public_key_bytes,
        client_identifier,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn take_client_presign_nonce(handle: &str) -> Result<Vec<u8>, JsValue> {
    CLIENT_PRESIGN_NONCE_BY_HANDLE.with(|store| {
        store
            .borrow_mut()
            .remove(handle)
            .map(|mut nonce| std::mem::take(&mut nonce.nonce_bytes))
            .ok_or_else(|| {
                JsValue::from_str("threshold-ed25519 client presign handle is not available")
            })
    })
}

fn role_separated_commitments_from_wire(
    wire: &signer_core::near_threshold_ed25519::CommitmentsWire,
) -> Result<RoleSeparatedEd25519CommitmentsV1, JsValue> {
    let hiding = decode_fixed_32(&wire.hiding, "serverCommitments.hiding")?;
    let binding = decode_fixed_32(&wire.binding, "serverCommitments.binding")?;
    RoleSeparatedEd25519CommitmentsV1::new(hiding, binding)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn role_separated_commitments_to_wire(
    commitments: RoleSeparatedEd25519CommitmentsV1,
) -> signer_core::near_threshold_ed25519::CommitmentsWire {
    signer_core::near_threshold_ed25519::CommitmentsWire {
        hiding: base64_url_encode(&commitments.hiding),
        binding: base64_url_encode(&commitments.binding),
    }
}

fn decode_fixed_32(value: &str, field_name: &str) -> Result<[u8; 32], JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field_name} must decode to 32 bytes")))
}

fn identifier_from_participant_id(
    participant_id: u16,
    field_name: &str,
) -> Result<frost_ed25519::Identifier, JsValue> {
    participant_id
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("Invalid {field_name}")))
}

fn next_client_presign_handle() -> String {
    let id = CLIENT_PRESIGN_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("ed25519-client-presign:{id}")
}

fn random_worker_material_handle() -> Result<String, JsValue> {
    let id = WORKER_MATERIAL_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let bytes = random_fixed_bytes::<16>("material handle")?;
    Ok(format!(
        "ed25519-worker-material:{id}:{}",
        base64_url_encode(&bytes)
    ))
}

fn random_material_authorization_handle(label: &str) -> Result<String, JsValue> {
    let id = MATERIAL_AUTHORIZATION_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let bytes = random_fixed_bytes::<16>("material authorization handle")?;
    Ok(format!(
        "ed25519-material-authorization:{label}:{id}:{}",
        base64_url_encode(&bytes)
    ))
}

fn random_hss_client_output_mask_handle() -> Result<String, JsValue> {
    let id = HSS_CLIENT_OUTPUT_MASK_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let bytes = random_fixed_bytes::<16>("HSS client output mask handle")?;
    Ok(format!(
        "ed25519-hss-client-output-mask:{id}:{}",
        base64_url_encode(&bytes)
    ))
}

fn random_fixed_bytes<const N: usize>(label: &str) -> Result<[u8; N], JsValue> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate {label}: {e}")))?;
    Ok(bytes)
}

fn take_hss_client_output_mask(
    transport: &Ed25519HssClientOutputMaskTransportV1,
    expected_context_binding_b64u: &str,
) -> Result<[u8; 32], JsValue> {
    match transport {
        Ed25519HssClientOutputMaskTransportV1::RustOwnedMaskHandleV1 {
            client_output_mask_handle,
        } => take_hss_client_output_mask_handle(
            client_output_mask_handle,
            expected_context_binding_b64u,
        ),
    }
}

fn take_hss_client_output_mask_handle(
    handle: &str,
    expected_context_binding_b64u: &str,
) -> Result<[u8; 32], JsValue> {
    let handle = require_non_empty(handle.to_string(), "clientOutputMaskHandle")?;
    HSS_CLIENT_OUTPUT_MASK_BY_HANDLE.with(|store| {
        let mut borrowed = store.borrow_mut();
        let mut entry = borrowed
            .remove(&handle)
            .ok_or_else(|| JsValue::from_str("Ed25519 HSS client output mask handle is missing"))?;
        if entry.expires_at_ms <= now_ms() {
            return Err(JsValue::from_str(
                "Ed25519 HSS client output mask handle expired",
            ));
        }
        if entry.remaining_uses != HSS_CLIENT_OUTPUT_MASK_USES_V1 {
            return Err(JsValue::from_str(
                "Ed25519 HSS client output mask handle exhausted",
            ));
        }
        if entry.context_binding_b64u != expected_context_binding_b64u {
            return Err(JsValue::from_str(
                "Ed25519 HSS client output mask context binding mismatch",
            ));
        }
        entry.remaining_uses = 0;
        Ok(entry.mask)
    })
}

fn require_secret32(mut value: Vec<u8>, field_name: &str) -> Result<Vec<u8>, JsValue> {
    if value.len() != 32 {
        value.zeroize();
        return Err(JsValue::from_str(&format!("{field_name} must be 32 bytes")));
    }
    Ok(value)
}

fn resolve_hss_client_output_mask_expires_at_ms(
    requested_expires_at_ms: u64,
) -> Result<u64, JsValue> {
    let now = now_ms();
    let expires_at_ms = if requested_expires_at_ms == 0 {
        now.saturating_add(HSS_CLIENT_OUTPUT_MASK_DEFAULT_TTL_MS)
    } else {
        requested_expires_at_ms
    };
    if expires_at_ms <= now {
        return Err(JsValue::from_str(
            "Ed25519 HSS client output mask handle expired",
        ));
    }
    if expires_at_ms.saturating_sub(now) > HSS_CLIENT_OUTPUT_MASK_MAX_TTL_MS {
        return Err(JsValue::from_str(
            "Ed25519 HSS client output mask expiry exceeds local capability cap",
        ));
    }
    Ok(expires_at_ms)
}

fn resolve_material_authorization_expires_at_ms(
    requested_expires_at_ms: u64,
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<u64, JsValue> {
    resolve_material_authorization_expires_at_ms_internal(requested_expires_at_ms, purpose)
        .map_err(|message| JsValue::from_str(&message))
}

fn resolve_material_authorization_expires_at_ms_internal(
    requested_expires_at_ms: u64,
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<u64, String> {
    let now = now_ms();
    let expires_at_ms = if requested_expires_at_ms == 0 {
        now.saturating_add(MATERIAL_AUTHORIZATION_DEFAULT_TTL_MS)
    } else {
        requested_expires_at_ms
    };
    if expires_at_ms <= now {
        return Err(material_authorization_error(
            purpose,
            "material authorization expired",
        ));
    }
    if expires_at_ms.saturating_sub(now) > MATERIAL_AUTHORIZATION_MAX_TTL_MS {
        return Err(material_authorization_error(
            purpose,
            "material authorization expiry exceeds local capability cap",
        ));
    }
    Ok(expires_at_ms)
}

fn require_v1_material_authorization_max_uses(
    max_uses: u32,
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<u32, JsValue> {
    require_v1_material_authorization_max_uses_internal(max_uses, purpose)
        .map_err(|message| JsValue::from_str(&message))
}

fn require_v1_material_authorization_max_uses_internal(
    max_uses: u32,
    purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
) -> Result<u32, String> {
    if max_uses != MATERIAL_AUTHORIZATION_MAX_USES_V1 {
        return Err(material_authorization_error(
            purpose,
            "maxUses must be 1 for v1 material authorization",
        ));
    }
    Ok(max_uses)
}

fn require_non_empty(value: String, field_name: &str) -> Result<String, JsValue> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(JsValue::from_str(&format!("{field_name} is required")));
    }
    Ok(trimmed)
}

fn require_positive_u32(value: u32, field_name: &str) -> Result<u32, JsValue> {
    if value == 0 {
        return Err(JsValue::from_str(&format!(
            "{field_name} must be a positive integer"
        )));
    }
    Ok(value)
}

fn require_positive_participant_ids(values: &[u32]) -> Result<Vec<u32>, JsValue> {
    if values.is_empty() || values.iter().any(|value| *value == 0) {
        return Err(JsValue::from_str(
            "participantIds must be positive integers",
        ));
    }
    Ok(values.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar as CurveScalar;
    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    use ed25519_hss::server::ServerEvalOperation;
    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    use ed25519_hss::shared::CanonicalContext;
    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    use serde::Serialize;
    use signer_core::commands::{
        ed25519_worker_material_binding_digest, ed25519_worker_material_key_id,
        seal_ed25519_worker_material_artifact, Ed25519DeleteSealedWorkerMaterialRequestKindV1,
        Ed25519DeleteSealedWorkerMaterialRequestV1, Ed25519PutSealedWorkerMaterialRequestKindV1,
        Ed25519PutSealedWorkerMaterialRequestV1, Ed25519ReadSealedWorkerMaterialRequestKindV1,
        Ed25519ReadSealedWorkerMaterialRequestV1, Ed25519RestoreWorkerMaterialRequestKindV1,
        Ed25519SealedWorkerMaterialKindV1, Ed25519WorkerMaterialAeadAlgorithmV1,
        Ed25519WorkerMaterialBindingKindV1, Ed25519WorkerMaterialBindingV1,
        Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
        Ed25519WorkerMaterialCredentialAuthorizationV1, Ed25519WorkerMaterialCurveV1,
        Ed25519WorkerMaterialFormatVersionV1, Ed25519WorkerMaterialKeyIdentityKindV1,
        Ed25519WorkerMaterialKeyIdentityV1, Ed25519WorkerMaterialProtocolV1,
        Ed25519WorkerMaterialSessionBindingKindV1, Ed25519WorkerMaterialSessionBindingV1,
        ThresholdRuntimePolicyScopeV1,
    };

    fn sample_x_client_base_b64u() -> String {
        base64_url_encode(&CurveScalar::from(7u64).to_bytes())
    }

    fn sample_group_public_key() -> String {
        let point = ED25519_BASEPOINT_POINT * CurveScalar::from(19u64);
        format!(
            "ed25519:{}",
            bs58::encode(point.compress().as_bytes()).into_string()
        )
    }

    fn sample_signing_digest_b64u() -> String {
        base64_url_encode(&[3u8; 32])
    }

    fn invalid_commitments_wire() -> signer_core::near_threshold_ed25519::CommitmentsWire {
        signer_core::near_threshold_ed25519::CommitmentsWire {
            hiding: "invalid-hiding".to_string(),
            binding: "invalid-binding".to_string(),
        }
    }

    fn sample_expected_client_verifying_share_b64u() -> String {
        let x_client_base = CurveScalar::from(7u64).to_bytes();
        let verifying_share =
            role_separated_ed25519_client_verifying_share_v1(x_client_base).unwrap();
        base64_url_encode(&verifying_share)
    }

    fn sample_material_binding() -> Ed25519WorkerMaterialBindingV1 {
        let identity = Ed25519WorkerMaterialKeyIdentityV1 {
            kind: Ed25519WorkerMaterialKeyIdentityKindV1::Ed25519WorkerMaterialKeyIdentityV1,
            near_account_id: "alice.near".to_string(),
            signer_slot: 1,
            signing_root_id: "root".to_string(),
            signing_root_version: "v1".to_string(),
            relayer_key_id: "relayer-key".to_string(),
            material_format_version: Ed25519WorkerMaterialFormatVersionV1::Ed25519WorkerMaterialV1,
        };
        Ed25519WorkerMaterialBindingV1 {
            kind: Ed25519WorkerMaterialBindingKindV1::Ed25519WorkerMaterialBindingV1,
            curve: Ed25519WorkerMaterialCurveV1::Ed25519,
            protocol: Ed25519WorkerMaterialProtocolV1::RouterAbNormalSigning,
            near_account_id: identity.near_account_id.clone(),
            signer_slot: identity.signer_slot,
            signing_root_id: identity.signing_root_id.clone(),
            signing_root_version: identity.signing_root_version.clone(),
            relayer_key_id: identity.relayer_key_id.clone(),
            participant_ids: vec![1, 2],
            client_verifying_share_b64u: sample_expected_client_verifying_share_b64u(),
            material_format_version: identity.material_format_version,
            material_key_id: ed25519_worker_material_key_id(&identity).unwrap(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn sample_session_binding(
        material_binding: &Ed25519WorkerMaterialBindingV1,
    ) -> Ed25519WorkerMaterialSessionBindingV1 {
        Ed25519WorkerMaterialSessionBindingV1 {
            kind: Ed25519WorkerMaterialSessionBindingKindV1::Ed25519WorkerMaterialSessionBindingV1,
            material_binding_digest: ed25519_worker_material_binding_digest(material_binding)
                .unwrap(),
            near_account_id: material_binding.near_account_id.clone(),
            signer_slot: material_binding.signer_slot,
            threshold_session_id: "threshold-session".to_string(),
            signing_grant_id: "signing-grant".to_string(),
            signing_root_id: material_binding.signing_root_id.clone(),
            signing_root_version: material_binding.signing_root_version.clone(),
            runtime_policy_scope: ThresholdRuntimePolicyScopeV1 {
                org_id: "org".to_string(),
                project_id: "project".to_string(),
                env_id: "env".to_string(),
                signing_root_version: material_binding.signing_root_version.clone(),
            },
            relayer_key_id: material_binding.relayer_key_id.clone(),
            participant_ids: material_binding.participant_ids.clone(),
            signing_worker_id: "signing-worker".to_string(),
            expires_at_ms: now_ms() + 60_000,
        }
    }

    fn sample_session_binding_digest(
        session_binding: &Ed25519WorkerMaterialSessionBindingV1,
    ) -> String {
        ed25519_worker_material_session_binding_digest(session_binding).unwrap()
    }

    fn sample_binding_input_without_verifier(
        material_binding: &Ed25519WorkerMaterialBindingV1,
    ) -> WorkerMaterialBindingInputWithoutVerifier {
        WorkerMaterialBindingInputWithoutVerifier {
            near_account_id: material_binding.near_account_id.clone(),
            signer_slot: material_binding.signer_slot,
            signing_root_id: material_binding.signing_root_id.clone(),
            signing_root_version: material_binding.signing_root_version.clone(),
            relayer_key_id: material_binding.relayer_key_id.clone(),
            participant_ids: material_binding.participant_ids.clone(),
            created_at_ms: material_binding.created_at_ms,
        }
    }

    fn store_sample_worker_material(
        material_handle: &str,
        material_binding: Ed25519WorkerMaterialBindingV1,
    ) -> WorkerMaterialResult {
        store_worker_material_from_base_share(StoreWorkerMaterialFromBaseShareRequest {
            material_handle: material_handle.to_string(),
            x_client_base_b64u: sample_x_client_base_b64u(),
            material_binding,
        })
        .unwrap()
    }

    fn install_authorization_secret_for_test(
        handle: &str,
        material_binding_digest: &str,
        purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1,
        secret: &[u8],
    ) {
        install_material_authorization_secret(
            handle.to_string(),
            StoredWorkerMaterialAuthorizationScope::MaterialBindingDigest(
                material_binding_digest.to_string(),
            ),
            purpose,
            secret,
            now_ms() + 60_000,
            1,
        )
        .unwrap();
    }

    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    fn encode_state_blob_for_test<T: Serialize>(value: &T) -> String {
        base64_url_encode(&bincode::serialize(value).unwrap())
    }

    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    fn encode_wire_message_for_test(value: &ed25519_hss::wire::WireMessage) -> String {
        base64_url_encode(&value.bytes)
    }

    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    struct HssWorkerMaterialFixture {
        evaluator_driver_state_b64u: String,
        client_output_message_b64u: String,
        expected_context_binding_b64u: String,
        client_output_mask: [u8; 32],
        client_verifying_share_b64u: String,
    }

    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    fn build_hss_worker_material_fixture() -> HssWorkerMaterialFixture {
        let binding = sample_material_binding();
        let context = CanonicalContext {
            application_binding_digest: [0x42; 32],
            participant_ids: vec![1, 2],
        };
        let prepared = prepare_prime_order_succinct_hss(&context).unwrap();
        let evaluator_driver_state = prepared.evaluator_driver_state();
        let evaluator_driver_state_b64u = encode_state_blob_for_test(&evaluator_driver_state);
        let expected_context_binding_b64u =
            base64_url_encode(&evaluator_driver_state.evaluator_session.context_binding);
        let (_runtime, evaluator_session) = evaluator_driver_state.materialize().unwrap();
        let garbler_session = prepared.garbler_session();
        let client_offer_message = garbler_session.client_ot_offer_message().unwrap();
        let y_client = [11u8; 32];
        let tau_client = [12u8; 32];
        let y_server = [13u8; 32];
        let tau_server = [14u8; 32];
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_offer_message,
                y_client,
                tau_client,
            )
            .unwrap();
        let (server_input_delivery, _server_eval_state) = garbler_session
            .prepare_role_separated_server_input_delivery_message(
                &client_request_message,
                y_server,
                tau_server,
                ServerEvalOperation::Registration,
            )
            .unwrap();
        let client_output_mask = [21u8; 32];
        let shared_runtime = prepared.shared_runtime();
        let staged_evaluator_artifact = evaluator_session
            .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_message(
                &shared_runtime,
                &client_request_message,
                &evaluator_ot_state,
                &server_input_delivery,
                client_output_mask,
            )
            .unwrap();
        let report = shared_runtime
            .finalize_report_from_staged_evaluator_artifact(
                &garbler_session,
                &staged_evaluator_artifact,
            )
            .unwrap();
        let x_client_base = evaluator_session
            .client_output_opener()
            .open_masked(&report.output_delivery.client, client_output_mask)
            .unwrap();
        let client_verifying_share =
            role_separated_ed25519_client_verifying_share_v1(x_client_base).unwrap();

        HssWorkerMaterialFixture {
            evaluator_driver_state_b64u,
            client_output_message_b64u: encode_wire_message_for_test(
                &report.output_delivery.client,
            ),
            expected_context_binding_b64u,
            client_output_mask,
            client_verifying_share_b64u: base64_url_encode(&client_verifying_share),
        }
    }

    #[test]
    fn store_validate_and_presign_roundtrip_keeps_material_in_registry() {
        let material_handle = "test-material".to_string();
        let material_binding = sample_material_binding();
        let binding_digest = ed25519_worker_material_binding_digest(&material_binding).unwrap();
        let session_binding = sample_session_binding(&material_binding);
        let session_binding_digest = sample_session_binding_digest(&session_binding);
        let expected_client_verifying_share_b64u =
            material_binding.client_verifying_share_b64u.clone();
        let stored = store_sample_worker_material(&material_handle, material_binding.clone());
        assert_eq!(stored.material_handle, material_handle);
        assert_eq!(stored.binding_digest, binding_digest);

        let validated = validate_worker_material(ValidateWorkerMaterialRequest {
            material_handle: material_handle.clone(),
            expected_material_binding: material_binding.clone(),
        })
        .unwrap();
        assert_eq!(
            validated.client_verifying_share_b64u,
            expected_client_verifying_share_b64u
        );

        let presign = create_client_presign_from_worker_material(
            CreateClientPresignFromWorkerMaterialRequest {
                client_participant_id: 1,
                relayer_participant_id: 2,
                material_handle,
                expected_material_binding: material_binding,
                expected_session_binding: session_binding,
                expected_session_binding_digest: session_binding_digest,
                group_public_key: sample_group_public_key(),
            },
        )
        .unwrap();
        assert!(presign
            .client_nonce_handle_b64u
            .starts_with("ed25519-client-presign:"));
        assert!(!presign.client_commitments.hiding.is_empty());
        assert!(!presign.client_commitments.binding.is_empty());
    }

    #[cfg(all(feature = "hss-client-exports", feature = "hss-server-exports"))]
    #[test]
    fn store_from_hss_output_opens_output_stores_material_and_sealed_artifact() {
        let fixture = build_hss_worker_material_fixture();
        let material_binding = sample_material_binding();
        let binding_input = sample_binding_input_without_verifier(&material_binding);
        let material_key_id = material_key_id_from_binding_input(&binding_input).unwrap();
        let seal_secret = [31u8; 32];
        let seal_expires_at_ms = now_ms() + 60_000;
        install_material_authorization_secret(
            "test-hss-store-seal-handle".to_string(),
            StoredWorkerMaterialAuthorizationScope::MaterialKeyId(material_key_id),
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
            &seal_secret,
            seal_expires_at_ms,
            MATERIAL_AUTHORIZATION_MAX_USES_V1,
        )
        .unwrap();
        install_hss_client_output_mask(
            "test-hss-output-mask-handle".to_string(),
            fixture.client_output_mask,
            fixture.expected_context_binding_b64u.clone(),
            now_ms() + 60_000,
        )
        .unwrap();

        let stored = store_worker_material_from_hss_output(StoreWorkerMaterialFromHssOutputRequest {
            evaluator_driver_state_b64u: fixture.evaluator_driver_state_b64u,
            client_output_message_b64u: fixture.client_output_message_b64u,
            client_output_mask: Ed25519HssClientOutputMaskTransportV1::RustOwnedMaskHandleV1 {
                client_output_mask_handle: "test-hss-output-mask-handle".to_string(),
            },
            expected_context_binding_b64u: fixture.expected_context_binding_b64u,
            near_account_id: material_binding.near_account_id.clone(),
            signer_slot: material_binding.signer_slot,
            signing_root_id: material_binding.signing_root_id.clone(),
            signing_root_version: material_binding.signing_root_version.clone(),
            relayer_key_id: material_binding.relayer_key_id.clone(),
            participant_ids: material_binding.participant_ids.clone(),
            created_at_ms: material_binding.created_at_ms,
            seal_authorization: Some(
                Ed25519WorkerMaterialSealAuthorizationV1::PasskeyPrfMaterialSealAuthorizationHandleV1 {
                    handle: "test-hss-store-seal-handle".to_string(),
                    rp_id: "example.test".to_string(),
                    credential_id_b64u: "credential".to_string(),
                    material_key_id: material_binding.material_key_id.clone(),
                    expires_at_ms: seal_expires_at_ms,
                },
            ),
        })
        .unwrap();
        let expected_material_binding = Ed25519WorkerMaterialBindingV1 {
            client_verifying_share_b64u: fixture.client_verifying_share_b64u.clone(),
            ..material_binding
        };
        let expected_material_binding_digest =
            ed25519_worker_material_binding_digest(&expected_material_binding).unwrap();

        assert!(stored.ok);
        assert!(stored
            .material_handle
            .starts_with("ed25519-worker-material:"));
        assert_eq!(
            stored.sealed_worker_material_ref,
            signer_core::commands::ed25519_worker_material_storage_ref(
                &expected_material_binding_digest,
            )
            .unwrap()
        );
        assert!(!stored.sealed_worker_material_b64u.is_empty());
        assert_eq!(
            stored.client_verifying_share_b64u,
            fixture.client_verifying_share_b64u
        );
        assert_eq!(
            stored.material_binding_digest,
            expected_material_binding_digest
        );
    }

    #[test]
    fn session_binding_validation_rejects_invalid_scope_before_protocol_messages() {
        let material_binding = sample_material_binding();

        let mut wrong_target_binding = sample_session_binding(&material_binding);
        wrong_target_binding.material_binding_digest = "wrong-material-binding".to_string();
        let wrong_target = validate_material_and_session_bindings_internal(
            &material_binding,
            &wrong_target_binding,
            &sample_session_binding_digest(&wrong_target_binding),
        )
        .unwrap_err();
        assert!(wrong_target.contains("session binding does not target material binding"));

        let mut expired_binding = sample_session_binding(&material_binding);
        expired_binding.expires_at_ms = 1;
        let expired = validate_material_and_session_bindings_internal(
            &material_binding,
            &expired_binding,
            &sample_session_binding_digest(&expired_binding),
        )
        .unwrap_err();
        assert!(expired.contains("session binding is expired"));

        let mut wrong_identity_binding = sample_session_binding(&material_binding);
        wrong_identity_binding.signing_root_version = "wrong-version".to_string();
        let wrong_identity = validate_material_and_session_bindings_internal(
            &material_binding,
            &wrong_identity_binding,
            &sample_session_binding_digest(&wrong_identity_binding),
        )
        .unwrap_err();
        assert!(wrong_identity.contains("session binding identity does not match material binding"));

        let mut missing_worker_binding = sample_session_binding(&material_binding);
        missing_worker_binding.signing_worker_id.clear();
        let missing_worker = validate_material_and_session_bindings_internal(
            &material_binding,
            &missing_worker_binding,
            &sample_session_binding_digest(&missing_worker_binding),
        )
        .unwrap_err();
        assert!(missing_worker.contains("expectedSessionBinding.signingWorkerId"));

        let mut wrong_digest_binding = sample_session_binding(&material_binding);
        wrong_digest_binding.signing_grant_id = "wrong-signing-grant".to_string();
        let wrong_digest = validate_material_and_session_bindings_internal(
            &material_binding,
            &wrong_digest_binding,
            &sample_session_binding_digest(&sample_session_binding(&material_binding)),
        )
        .unwrap_err();
        assert!(wrong_digest.contains("session binding digest mismatch"));
    }

    #[test]
    fn create_presign_rejects_session_binding_digest_mismatch_before_protocol_messages() {
        let material_binding = sample_material_binding();
        let mut session_binding = sample_session_binding(&material_binding);
        let expected_session_binding_digest = sample_session_binding_digest(&session_binding);
        session_binding.signing_grant_id = "wrong-signing-grant".to_string();

        let error = validate_create_client_presign_request_scope_internal(
            &CreateClientPresignFromWorkerMaterialRequest {
                client_participant_id: 1,
                relayer_participant_id: 2,
                material_handle: "test-material-create-mismatch".to_string(),
                expected_material_binding: material_binding,
                expected_session_binding: session_binding,
                expected_session_binding_digest,
                group_public_key: "invalid-group-public-key".to_string(),
            },
        )
        .unwrap_err();

        assert!(error.contains("session binding digest mismatch"));
    }

    #[test]
    fn sign_presign_rejects_session_binding_digest_mismatch_before_protocol_messages() {
        let material_binding = sample_material_binding();
        let session_binding = sample_session_binding(&material_binding);
        let session_binding_digest = sample_session_binding_digest(&session_binding);

        let mut drifted_session_binding = session_binding;
        drifted_session_binding.signing_worker_id = "wrong-signing-worker".to_string();
        let error = validate_sign_client_presign_request_scope_internal(
            &SignClientPresignFromWorkerMaterialRequest {
                client_participant_id: 1,
                relayer_participant_id: 2,
                material_handle: "test-material-sign-mismatch".to_string(),
                expected_material_binding: material_binding,
                expected_session_binding: drifted_session_binding,
                expected_session_binding_digest: session_binding_digest,
                group_public_key: "invalid-group-public-key".to_string(),
                signing_digest_b64u: sample_signing_digest_b64u(),
                client_nonce_handle_b64u: "nonce-handle".to_string(),
                client_commitments: invalid_commitments_wire(),
                relayer_commitments: invalid_commitments_wire(),
            },
        )
        .unwrap_err();

        assert!(error.contains("session binding digest mismatch"));
    }

    #[test]
    fn role_separated_signing_rejects_session_binding_digest_mismatch_before_protocol_messages() {
        let material_binding = sample_material_binding();
        let session_binding = sample_session_binding(&material_binding);
        let session_binding_digest = sample_session_binding_digest(&session_binding);

        let mut drifted_session_binding = session_binding;
        drifted_session_binding.threshold_session_id = "wrong-threshold-session".to_string();
        let error = validate_role_separated_normal_signing_request_scope_internal(
            &RoleSeparatedNormalSigningClientShareFromWorkerMaterialRequest {
                material_handle: "test-material-role-separated-mismatch".to_string(),
                expected_material_binding: material_binding,
                expected_session_binding: drifted_session_binding,
                expected_session_binding_digest: session_binding_digest,
                group_public_key: "invalid-group-public-key".to_string(),
                server_verifying_share_b64u: "invalid-server-share".to_string(),
                server_commitments: invalid_commitments_wire(),
                signing_digest_b64u: sample_signing_digest_b64u(),
            },
        )
        .unwrap_err();

        assert!(error.contains("session binding digest mismatch"));
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn store_rejects_verifying_share_mismatch() {
        let mut material_binding = sample_material_binding();
        material_binding.client_verifying_share_b64u = base64_url_encode(&[1u8; 32]);
        let result =
            store_worker_material_from_base_share(StoreWorkerMaterialFromBaseShareRequest {
                material_handle: "bad-material".to_string(),
                x_client_base_b64u: sample_x_client_base_b64u(),
                material_binding,
            });
        assert!(result.is_err());
    }

    #[test]
    fn sealed_worker_material_put_read_delete_roundtrip() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [8u8; signer_core::commands::ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];
        let x_client_base = CurveScalar::from(7u64).to_bytes();
        let sealed_material =
            seal_ed25519_worker_material_artifact(&binding, &x_client_base, secret, salt, &nonce)
                .unwrap();
        assert!(matches!(
            sealed_material.kind,
            Ed25519SealedWorkerMaterialKindV1::Ed25519SealedWorkerMaterialV1
        ));
        assert!(matches!(
            sealed_material.aead.algorithm,
            Ed25519WorkerMaterialAeadAlgorithmV1::ChaCha20Poly1305
        ));

        let stored =
            put_sealed_worker_material(Ed25519PutSealedWorkerMaterialRequestV1 {
                kind: Ed25519PutSealedWorkerMaterialRequestKindV1::PutThresholdEd25519SealedWorkerMaterialV1,
                sealed_material,
            })
            .unwrap();
        assert_eq!(stored.material_binding_digest, material_binding_digest);

        let read = read_sealed_worker_material(Ed25519ReadSealedWorkerMaterialRequestV1 {
            kind: Ed25519ReadSealedWorkerMaterialRequestKindV1::ReadThresholdEd25519SealedWorkerMaterialV1,
            sealed_worker_material_ref: stored.sealed_worker_material_ref.clone(),
            expected_material_binding_digest: material_binding_digest.clone(),
        })
        .unwrap();
        assert_eq!(
            read.sealed_material.material_binding_digest,
            material_binding_digest
        );

        let deleted = delete_sealed_worker_material(
            Ed25519DeleteSealedWorkerMaterialRequestV1 {
                kind: Ed25519DeleteSealedWorkerMaterialRequestKindV1::DeleteThresholdEd25519SealedWorkerMaterialV1,
                sealed_worker_material_ref: stored.sealed_worker_material_ref,
                expected_material_binding_digest: material_binding_digest,
            },
        )
        .unwrap();
        assert!(deleted.deleted);
    }

    #[test]
    fn restore_loads_sealed_material_into_worker_registry() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let secret = b"passkey-prf-output";
        let salt = b"material-salt";
        let nonce = [9u8; signer_core::commands::ED25519_WORKER_MATERIAL_CHACHA20_NONCE_SIZE];
        let x_client_base = CurveScalar::from(7u64).to_bytes();
        let sealed_material =
            seal_ed25519_worker_material_artifact(&binding, &x_client_base, secret, salt, &nonce)
                .unwrap();
        let stored =
            put_sealed_worker_material(Ed25519PutSealedWorkerMaterialRequestV1 {
                kind: Ed25519PutSealedWorkerMaterialRequestKindV1::PutThresholdEd25519SealedWorkerMaterialV1,
                sealed_material,
            })
            .unwrap();
        install_authorization_secret_for_test(
            "test-prf-handle",
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
            secret,
        );

        let restored = restore_worker_material(Ed25519RestoreWorkerMaterialRequestV1 {
            kind: Ed25519RestoreWorkerMaterialRequestKindV1::Ed25519RestoreWorkerMaterialV1,
            sealed_material: Ed25519SealedWorkerMaterialTransportV1::StorageRef {
                sealed_worker_material_ref: stored.sealed_worker_material_ref.clone(),
            },
            expected_material_binding: binding.clone(),
            unseal_authorization:
                Ed25519WorkerMaterialCredentialAuthorizationV1::PasskeyPrfMaterialAuthorizationHandleV1 {
                handle: "test-prf-handle".to_string(),
                purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                material_binding_digest,
                expires_at_ms: now_ms() + 60_000,
            },
        })
        .unwrap();

        assert_eq!(
            restored.sealed_worker_material_ref,
            stored.sealed_worker_material_ref
        );
        assert_eq!(
            restored.client_verifying_share_b64u,
            binding.client_verifying_share_b64u
        );
        assert!(!restored.material_handle.is_empty());
    }

    #[test]
    fn material_authorization_rejects_wrong_purpose() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let secret = [11u8; 32];
        install_authorization_secret_for_test(
            "test-seal-handle",
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
            &secret,
        );

        let result = consume_material_authorization_secret_internal(
            Ed25519WorkerMaterialCredentialAuthorizationV1::PasskeyPrfMaterialAuthorizationHandleV1 {
                handle: "test-seal-handle".to_string(),
                purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                material_binding_digest,
                expires_at_ms: now_ms() + 60_000,
            },
            &ed25519_worker_material_binding_digest(&binding).unwrap(),
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        );

        let message = result.unwrap_err();
        assert!(message.starts_with("material_unseal_authorization_required:"));
        assert!(message.contains("purpose mismatch"));
    }

    #[test]
    fn material_authorization_defaults_to_short_single_use_handle() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let before = now_ms();
        let result = install_passkey_prf_material_authorization(
            InstallPasskeyPrfMaterialAuthorizationRequest {
                purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
                material_binding_digest: material_binding_digest.clone(),
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                prf_first_bytes: vec![7u8; 32],
                expires_at_ms: 0,
                max_uses: 1,
            },
        )
        .unwrap();

        assert_eq!(result.remaining_uses, 1);
        match result.authorization {
            Ed25519WorkerMaterialCredentialAuthorizationV1::PasskeyPrfMaterialAuthorizationHandleV1 {
                material_binding_digest: actual_digest,
                expires_at_ms,
                ..
            } => {
                assert_eq!(actual_digest, material_binding_digest);
                assert!(expires_at_ms >= before + MATERIAL_AUTHORIZATION_DEFAULT_TTL_MS);
                assert!(
                    expires_at_ms
                        <= before + MATERIAL_AUTHORIZATION_DEFAULT_TTL_MS + 1_000
                );
            }
            _ => panic!("expected passkey authorization"),
        }
    }

    #[test]
    fn prepared_seal_authorization_defaults_to_short_single_use_handle() {
        let binding = sample_material_binding();
        let before = now_ms();
        let result = prepare_passkey_prf_worker_material_seal_authorization(
            PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest {
                binding_input: sample_binding_input_without_verifier(&binding),
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                prf_first_bytes: vec![7u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        assert_eq!(result.material_key_id, binding.material_key_id);
        assert_eq!(result.remaining_uses, 1);
        match result.seal_authorization {
            Ed25519WorkerMaterialSealAuthorizationV1::PasskeyPrfMaterialSealAuthorizationHandleV1 {
                material_key_id,
                expires_at_ms,
                ..
            } => {
                assert_eq!(material_key_id, binding.material_key_id);
                assert!(expires_at_ms >= before + MATERIAL_AUTHORIZATION_DEFAULT_TTL_MS);
                assert!(
                    expires_at_ms
                        <= before + MATERIAL_AUTHORIZATION_DEFAULT_TTL_MS + 1_000
                );
            }
            _ => panic!("expected passkey seal authorization"),
        }
    }

    #[test]
    fn direct_material_authorization_install_rejects_seal_purpose() {
        let message = require_direct_install_unseal_purpose_internal(
            &Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        )
        .unwrap_err();

        assert!(message.starts_with("material_seal_authorization_required:"));
        assert!(message.contains("prepared seal authorization"));
    }

    #[test]
    fn prepared_passkey_unseal_authorization_consumes_by_material_binding_digest() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let result = prepare_passkey_prf_worker_material_unseal_authorization(
            PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest {
                material_binding_digest: material_binding_digest.clone(),
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                prf_first_bytes: vec![8u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        let mismatch = consume_material_authorization_secret_internal(
            result.unseal_authorization.clone(),
            "wrong-binding-digest",
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap_err();
        assert!(mismatch.starts_with("material_unseal_authorization_required:"));
        assert!(mismatch.contains("binding digest mismatch"));

        let secret = consume_material_authorization_secret_internal(
            result.unseal_authorization,
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap();
        assert_eq!(secret, vec![8u8; 32]);
    }

    #[test]
    fn prepared_passkey_unseal_authorization_is_single_use() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let result = prepare_passkey_prf_worker_material_unseal_authorization(
            PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest {
                material_binding_digest: material_binding_digest.clone(),
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                prf_first_bytes: vec![8u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        let secret = consume_material_authorization_secret_internal(
            result.unseal_authorization.clone(),
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap();
        assert_eq!(secret, vec![8u8; 32]);

        let message = consume_material_authorization_secret_internal(
            result.unseal_authorization,
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap_err();
        assert!(message.starts_with("material_unseal_authorization_required:"));
        assert!(message.contains("authorization handle missing"));
    }

    #[test]
    fn prepared_recovery_code_unseal_authorization_consumes_by_material_binding_digest() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let result = prepare_recovery_code_worker_material_unseal_authorization(
            PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest {
                material_binding_digest: material_binding_digest.clone(),
                auth_subject_id: "subject".to_string(),
                recovery_code_binding_digest: "recovery-binding".to_string(),
                recovery_code_secret32: vec![9u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        let mismatch = consume_material_authorization_secret_internal(
            result.unseal_authorization.clone(),
            "wrong-binding-digest",
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap_err();
        assert!(mismatch.starts_with("material_unseal_authorization_required:"));
        assert!(mismatch.contains("binding digest mismatch"));

        let secret = consume_material_authorization_secret_internal(
            result.unseal_authorization,
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap();
        assert_eq!(secret, vec![9u8; 32]);
    }

    #[test]
    fn prepared_unseal_authorization_rejects_expired_handles() {
        let message = resolve_material_authorization_expires_at_ms_internal(
            now_ms().saturating_sub(1),
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap_err();

        assert!(message.starts_with("material_unseal_authorization_required:"));
        assert!(message.contains("material authorization expired"));
    }

    #[test]
    fn prepared_unseal_authorization_rejects_purpose_mismatch() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let result = prepare_passkey_prf_worker_material_unseal_authorization(
            PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest {
                material_binding_digest: material_binding_digest.clone(),
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                prf_first_bytes: vec![8u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        let message = consume_material_authorization_secret_internal(
            result.unseal_authorization,
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        )
        .unwrap_err();
        assert!(message.starts_with("material_seal_authorization_required:"));
        assert!(message.contains("purpose mismatch"));
    }

    #[test]
    fn prepared_passkey_seal_authorization_consumes_by_material_key_id() {
        let binding = sample_material_binding();
        let result = prepare_passkey_prf_worker_material_seal_authorization(
            PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest {
                binding_input: sample_binding_input_without_verifier(&binding),
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                prf_first_bytes: vec![7u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        assert_eq!(result.material_key_id, binding.material_key_id);
        let mismatch = consume_material_seal_authorization_secret_internal(
            result.seal_authorization.clone(),
            "wrong-material-key-id",
        )
        .unwrap_err();
        assert!(mismatch.starts_with("material_seal_authorization_required:"));
        assert!(mismatch.contains("material key id mismatch"));

        let secret = consume_material_seal_authorization_secret_internal(
            result.seal_authorization,
            &binding.material_key_id,
        )
        .unwrap();
        assert_eq!(secret, vec![7u8; 32]);
    }

    #[test]
    fn prepared_recovery_code_seal_authorization_returns_stable_material_key_id() {
        let binding = sample_material_binding();
        let result = prepare_recovery_code_worker_material_seal_authorization(
            PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest {
                binding_input: sample_binding_input_without_verifier(&binding),
                auth_subject_id: "subject".to_string(),
                recovery_code_binding_digest: "recovery-binding".to_string(),
                recovery_code_secret32: vec![9u8; 32],
                expires_at_ms: 0,
            },
        )
        .unwrap();

        assert_eq!(result.material_key_id, binding.material_key_id);
        match result.seal_authorization {
            Ed25519WorkerMaterialSealAuthorizationV1::RecoveryCodeMaterialSealAuthorizationHandleV1 {
                material_key_id,
                auth_subject_id,
                ..
            } => {
                assert_eq!(material_key_id, binding.material_key_id);
                assert_eq!(auth_subject_id, "subject");
            }
            _ => panic!("expected recovery-code seal authorization"),
        }
    }

    #[test]
    fn material_authorization_rejects_multi_use_v1_handles() {
        let unseal_message = require_v1_material_authorization_max_uses_internal(
            2,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
        )
        .unwrap_err();
        assert!(unseal_message.starts_with("material_unseal_authorization_required:"));
        assert!(unseal_message.contains("maxUses must be 1"));

        let seal_message = require_v1_material_authorization_max_uses_internal(
            2,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        )
        .unwrap_err();
        assert!(seal_message.starts_with("material_seal_authorization_required:"));
        assert!(seal_message.contains("maxUses must be 1"));
    }

    #[test]
    fn material_authorization_rejects_expiry_above_local_cap() {
        let message = resolve_material_authorization_expires_at_ms_internal(
            now_ms() + MATERIAL_AUTHORIZATION_MAX_TTL_MS + 60_000,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        )
        .unwrap_err();
        assert!(message.starts_with("material_seal_authorization_required:"));
        assert!(message.contains("exceeds local capability cap"));
    }

    #[test]
    fn material_authorization_rejects_unseal_for_seal() {
        let binding = sample_material_binding();
        let material_binding_digest = ed25519_worker_material_binding_digest(&binding).unwrap();
        let secret = [12u8; 32];
        install_authorization_secret_for_test(
            "test-unseal-handle",
            &material_binding_digest,
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
            &secret,
        );

        let result = consume_material_authorization_secret_internal(
            Ed25519WorkerMaterialCredentialAuthorizationV1::PasskeyPrfMaterialAuthorizationHandleV1 {
                handle: "test-unseal-handle".to_string(),
                purpose: Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Unseal,
                rp_id: "example.test".to_string(),
                credential_id_b64u: "credential".to_string(),
                material_binding_digest,
                expires_at_ms: now_ms() + 60_000,
            },
            &ed25519_worker_material_binding_digest(&binding).unwrap(),
            Ed25519WorkerMaterialCredentialAuthorizationPurposeV1::Seal,
        );

        let message = result.unwrap_err();
        assert!(message.starts_with("material_seal_authorization_required:"));
        assert!(message.contains("purpose mismatch"));
    }
}
