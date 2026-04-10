// === WORKER MESSAGES: REQUEST & RESPONSE TYPES ===
// Enums and message structures for worker communication

use crate::error::ParsePayloadError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// === CLEAN RUST ENUMS WITH NUMERIC CONVERSION ===
// These export to TypeScript as numeric enums and we convert directly from numbers
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRequestType {
    SignTransactionsWithActions,
    ExtractCosePublicKey,
    SignTransactionWithKeyPair,
    SignNep413Message,
    // Delegate action signing (NEP-461)
    SignDelegateAction,
    // Public, deterministic key enrollment helper for threshold mode
    DeriveThresholdEd25519ClientVerifyingShare,
    // Public helper that derives Option A HSS client inputs from PRF + canonical context
    DeriveThresholdEd25519HssClientInputs,
    /// Internal helper to generate a fresh ephemeral Ed25519 keypair.
    GenerateEphemeralNearKeypair,
    PrepareThresholdEd25519HssSession,
    PrepareThresholdEd25519HssClientRequest,
    OpenThresholdEd25519HssClientOutput,
    OpenThresholdEd25519HssSeedOutput,
    BuildThresholdEd25519SeedExportArtifact,
    PrepareThresholdEcdsaHssSession,
    PrepareThresholdEcdsaHssClientRequest,
    FinalizeThresholdEcdsaHssClientRequest,
}

impl From<u32> for WorkerRequestType {
    fn from(value: u32) -> Self {
        match value {
            0 => WorkerRequestType::SignTransactionsWithActions,
            1 => WorkerRequestType::ExtractCosePublicKey,
            2 => WorkerRequestType::SignTransactionWithKeyPair,
            3 => WorkerRequestType::SignNep413Message,
            4 => WorkerRequestType::SignDelegateAction,
            5 => WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare,
            6 => WorkerRequestType::DeriveThresholdEd25519HssClientInputs,
            7 => WorkerRequestType::GenerateEphemeralNearKeypair,
            8 => WorkerRequestType::PrepareThresholdEd25519HssSession,
            9 => WorkerRequestType::PrepareThresholdEd25519HssClientRequest,
            10 => WorkerRequestType::OpenThresholdEd25519HssClientOutput,
            11 => WorkerRequestType::OpenThresholdEd25519HssSeedOutput,
            12 => WorkerRequestType::BuildThresholdEd25519SeedExportArtifact,
            13 => WorkerRequestType::PrepareThresholdEcdsaHssSession,
            14 => WorkerRequestType::PrepareThresholdEcdsaHssClientRequest,
            15 => WorkerRequestType::FinalizeThresholdEcdsaHssClientRequest,
            _ => panic!("Invalid WorkerRequestType value: {}", value),
        }
    }
}
impl WorkerRequestType {
    pub fn name(&self) -> &'static str {
        match self {
            WorkerRequestType::SignTransactionsWithActions => "SIGN_TRANSACTIONS_WITH_ACTIONS",
            WorkerRequestType::SignDelegateAction => "SIGN_DELEGATE_ACTION",
            WorkerRequestType::ExtractCosePublicKey => "EXTRACT_COSE_PUBLIC_KEY",
            WorkerRequestType::SignTransactionWithKeyPair => "SIGN_TRANSACTION_WITH_KEYPAIR",
            WorkerRequestType::SignNep413Message => "SIGN_NEP413_MESSAGE",
            WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare => {
                "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE"
            }
            WorkerRequestType::DeriveThresholdEd25519HssClientInputs => {
                "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS"
            }
            WorkerRequestType::GenerateEphemeralNearKeypair => "GENERATE_EPHEMERAL_NEAR_KEYPAIR",
            WorkerRequestType::PrepareThresholdEd25519HssSession => {
                "PREPARE_THRESHOLD_ED25519_HSS_SESSION"
            }
            WorkerRequestType::PrepareThresholdEd25519HssClientRequest => {
                "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST"
            }
            WorkerRequestType::OpenThresholdEd25519HssClientOutput => {
                "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT"
            }
            WorkerRequestType::OpenThresholdEd25519HssSeedOutput => {
                "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT"
            }
            WorkerRequestType::BuildThresholdEd25519SeedExportArtifact => {
                "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT"
            }
            WorkerRequestType::PrepareThresholdEcdsaHssSession => {
                "PREPARE_THRESHOLD_ECDSA_HSS_SESSION"
            }
            WorkerRequestType::PrepareThresholdEcdsaHssClientRequest => {
                "PREPARE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST"
            }
            WorkerRequestType::FinalizeThresholdEcdsaHssClientRequest => {
                "FINALIZE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST"
            }
        }
    }
}

/// Convert WorkerRequestType enum to readable string for debugging.
/// Used in logs to make numeric enum values human-friendly.
pub fn worker_request_type_name(request_type: WorkerRequestType) -> &'static str {
    match request_type {
        WorkerRequestType::SignTransactionsWithActions => "SIGN_TRANSACTIONS_WITH_ACTIONS",
        WorkerRequestType::SignDelegateAction => "SIGN_DELEGATE_ACTION",
        WorkerRequestType::ExtractCosePublicKey => "EXTRACT_COSE_PUBLIC_KEY",
        WorkerRequestType::SignTransactionWithKeyPair => "SIGN_TRANSACTION_WITH_KEYPAIR",
        WorkerRequestType::SignNep413Message => "SIGN_NEP413_MESSAGE",
        WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare => {
            "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE"
        }
        WorkerRequestType::DeriveThresholdEd25519HssClientInputs => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS"
        }
        WorkerRequestType::GenerateEphemeralNearKeypair => "GENERATE_EPHEMERAL_NEAR_KEYPAIR",
        WorkerRequestType::PrepareThresholdEd25519HssSession => {
            "PREPARE_THRESHOLD_ED25519_HSS_SESSION"
        }
        WorkerRequestType::PrepareThresholdEd25519HssClientRequest => {
            "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST"
        }
        WorkerRequestType::OpenThresholdEd25519HssClientOutput => {
            "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT"
        }
        WorkerRequestType::OpenThresholdEd25519HssSeedOutput => {
            "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT"
        }
        WorkerRequestType::BuildThresholdEd25519SeedExportArtifact => {
            "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT"
        }
        WorkerRequestType::PrepareThresholdEcdsaHssSession => {
            "PREPARE_THRESHOLD_ECDSA_HSS_SESSION"
        }
        WorkerRequestType::PrepareThresholdEcdsaHssClientRequest => {
            "PREPARE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST"
        }
        WorkerRequestType::FinalizeThresholdEcdsaHssClientRequest => {
            "FINALIZE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST"
        }
    }
}

/// Deserialize a typed Rust payload from a raw `JsValue`.
/// Keeps the worker request name in the error so JS callers can surface
/// meaningful `"Invalid payload for <MESSAGE_TYPE>: ..."` messages.
pub fn parse_typed_payload<T: DeserializeOwned>(
    payload: &JsValue,
    request_type: WorkerRequestType,
) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(payload.clone())
        .map_err(|e| ParsePayloadError::new(request_type.name(), e).into())
}

/// Worker response types enum - corresponds to TypeScript WorkerResponseType
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WorkerResponseType {
    // Success responses - one for each request type (kept in the same order)
    SignTransactionsWithActionsSuccess = 0,
    ExtractCosePublicKeySuccess = 1,
    SignTransactionWithKeyPairSuccess = 2,
    SignNep413MessageSuccess = 3,
    SignDelegateActionSuccess = 4,

    // Failure responses - one for each request type (same ordering)
    SignTransactionsWithActionsFailure = 5,
    ExtractCosePublicKeyFailure = 6,
    SignTransactionWithKeyPairFailure = 7,
    SignNep413MessageFailure = 8,
    SignDelegateActionFailure = 9,

    // Progress responses - for real-time updates during operations
    RegistrationProgress = 10,
    RegistrationComplete = 11,
    ExecuteActionsProgress = 12,
    ExecuteActionsComplete = 13,

    // Threshold key enrollment helper
    DeriveThresholdEd25519ClientVerifyingShareSuccess = 14,
    DeriveThresholdEd25519ClientVerifyingShareFailure = 15,
    DeriveThresholdEd25519HssClientInputsSuccess = 16,
    DeriveThresholdEd25519HssClientInputsFailure = 17,
    GenerateEphemeralNearKeypairSuccess = 18,
    GenerateEphemeralNearKeypairFailure = 19,
    PrepareThresholdEd25519HssSessionSuccess = 20,
    PrepareThresholdEd25519HssSessionFailure = 21,
    PrepareThresholdEd25519HssClientRequestSuccess = 22,
    PrepareThresholdEd25519HssClientRequestFailure = 23,
    OpenThresholdEd25519HssClientOutputSuccess = 24,
    OpenThresholdEd25519HssClientOutputFailure = 25,
    OpenThresholdEd25519HssSeedOutputSuccess = 26,
    OpenThresholdEd25519HssSeedOutputFailure = 27,
    BuildThresholdEd25519SeedExportArtifactSuccess = 28,
    BuildThresholdEd25519SeedExportArtifactFailure = 29,
    PrepareThresholdEcdsaHssSessionSuccess = 30,
    PrepareThresholdEcdsaHssSessionFailure = 31,
    PrepareThresholdEcdsaHssClientRequestSuccess = 32,
    PrepareThresholdEcdsaHssClientRequestFailure = 33,
    FinalizeThresholdEcdsaHssClientRequestSuccess = 34,
    FinalizeThresholdEcdsaHssClientRequestFailure = 35,
}
impl From<WorkerResponseType> for u32 {
    fn from(value: WorkerResponseType) -> Self {
        value as u32
    }
}
impl From<u32> for WorkerResponseType {
    fn from(value: u32) -> Self {
        match value {
            // Success responses
            0 => WorkerResponseType::SignTransactionsWithActionsSuccess,
            1 => WorkerResponseType::ExtractCosePublicKeySuccess,
            2 => WorkerResponseType::SignTransactionWithKeyPairSuccess,
            3 => WorkerResponseType::SignNep413MessageSuccess,
            4 => WorkerResponseType::SignDelegateActionSuccess,

            // Failure responses
            5 => WorkerResponseType::SignTransactionsWithActionsFailure,
            6 => WorkerResponseType::ExtractCosePublicKeyFailure,
            7 => WorkerResponseType::SignTransactionWithKeyPairFailure,
            8 => WorkerResponseType::SignNep413MessageFailure,
            9 => WorkerResponseType::SignDelegateActionFailure,

            // Progress responses - for real-time updates during operations
            10 => WorkerResponseType::RegistrationProgress,
            11 => WorkerResponseType::RegistrationComplete,
            12 => WorkerResponseType::ExecuteActionsProgress,
            13 => WorkerResponseType::ExecuteActionsComplete,
            14 => WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareSuccess,
            15 => WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareFailure,
            16 => WorkerResponseType::DeriveThresholdEd25519HssClientInputsSuccess,
            17 => WorkerResponseType::DeriveThresholdEd25519HssClientInputsFailure,
            18 => WorkerResponseType::GenerateEphemeralNearKeypairSuccess,
            19 => WorkerResponseType::GenerateEphemeralNearKeypairFailure,
            20 => WorkerResponseType::PrepareThresholdEd25519HssSessionSuccess,
            21 => WorkerResponseType::PrepareThresholdEd25519HssSessionFailure,
            22 => WorkerResponseType::PrepareThresholdEd25519HssClientRequestSuccess,
            23 => WorkerResponseType::PrepareThresholdEd25519HssClientRequestFailure,
            24 => WorkerResponseType::OpenThresholdEd25519HssClientOutputSuccess,
            25 => WorkerResponseType::OpenThresholdEd25519HssClientOutputFailure,
            26 => WorkerResponseType::OpenThresholdEd25519HssSeedOutputSuccess,
            27 => WorkerResponseType::OpenThresholdEd25519HssSeedOutputFailure,
            28 => WorkerResponseType::BuildThresholdEd25519SeedExportArtifactSuccess,
            29 => WorkerResponseType::BuildThresholdEd25519SeedExportArtifactFailure,
            30 => WorkerResponseType::PrepareThresholdEcdsaHssSessionSuccess,
            31 => WorkerResponseType::PrepareThresholdEcdsaHssSessionFailure,
            32 => WorkerResponseType::PrepareThresholdEcdsaHssClientRequestSuccess,
            33 => WorkerResponseType::PrepareThresholdEcdsaHssClientRequestFailure,
            34 => WorkerResponseType::FinalizeThresholdEcdsaHssClientRequestSuccess,
            35 => WorkerResponseType::FinalizeThresholdEcdsaHssClientRequestFailure,
            _ => panic!("Invalid WorkerResponseType value: {}", value),
        }
    }
}

/// Convert WorkerResponseType enum to readable string for debugging.
/// Used in logs to turn numeric response type values into names.
pub fn worker_response_type_name(response_type: WorkerResponseType) -> &'static str {
    match response_type {
        // Success responses
        WorkerResponseType::SignTransactionsWithActionsSuccess => {
            "SIGN_TRANSACTIONS_WITH_ACTIONS_SUCCESS"
        }
        WorkerResponseType::SignDelegateActionSuccess => "SIGN_DELEGATE_ACTION_SUCCESS",
        WorkerResponseType::ExtractCosePublicKeySuccess => "EXTRACT_COSE_PUBLIC_KEY_SUCCESS",
        WorkerResponseType::SignTransactionWithKeyPairSuccess => {
            "SIGN_TRANSACTION_WITH_KEYPAIR_SUCCESS"
        }
        WorkerResponseType::SignNep413MessageSuccess => "SIGN_NEP413_MESSAGE_SUCCESS",

        // Failure responses
        WorkerResponseType::SignTransactionsWithActionsFailure => {
            "SIGN_TRANSACTIONS_WITH_ACTIONS_FAILURE"
        }
        WorkerResponseType::SignDelegateActionFailure => "SIGN_DELEGATE_ACTION_FAILURE",
        WorkerResponseType::ExtractCosePublicKeyFailure => "EXTRACT_COSE_PUBLIC_KEY_FAILURE",
        WorkerResponseType::SignTransactionWithKeyPairFailure => {
            "SIGN_TRANSACTION_WITH_KEYPAIR_FAILURE"
        }
        WorkerResponseType::SignNep413MessageFailure => "SIGN_NEP413_MESSAGE_FAILURE",

        // Progress responses - for real-time updates during operations
        WorkerResponseType::RegistrationProgress => "REGISTRATION_PROGRESS",
        WorkerResponseType::RegistrationComplete => "REGISTRATION_COMPLETE",
        WorkerResponseType::ExecuteActionsProgress => "EXECUTE_ACTIONS_PROGRESS",
        WorkerResponseType::ExecuteActionsComplete => "EXECUTE_ACTIONS_COMPLETE",
        WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareSuccess => {
            "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE_SUCCESS"
        }
        WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareFailure => {
            "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE_FAILURE"
        }
        WorkerResponseType::DeriveThresholdEd25519HssClientInputsSuccess => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS_SUCCESS"
        }
        WorkerResponseType::DeriveThresholdEd25519HssClientInputsFailure => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS_FAILURE"
        }
        WorkerResponseType::GenerateEphemeralNearKeypairSuccess => {
            "GENERATE_EPHEMERAL_NEAR_KEYPAIR_SUCCESS"
        }
        WorkerResponseType::GenerateEphemeralNearKeypairFailure => {
            "GENERATE_EPHEMERAL_NEAR_KEYPAIR_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEd25519HssSessionSuccess => {
            "PREPARE_THRESHOLD_ED25519_HSS_SESSION_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEd25519HssSessionFailure => {
            "PREPARE_THRESHOLD_ED25519_HSS_SESSION_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEd25519HssClientRequestSuccess => {
            "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEd25519HssClientRequestFailure => {
            "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST_FAILURE"
        }
        WorkerResponseType::OpenThresholdEd25519HssClientOutputSuccess => {
            "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_SUCCESS"
        }
        WorkerResponseType::OpenThresholdEd25519HssClientOutputFailure => {
            "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_FAILURE"
        }
        WorkerResponseType::OpenThresholdEd25519HssSeedOutputSuccess => {
            "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT_SUCCESS"
        }
        WorkerResponseType::OpenThresholdEd25519HssSeedOutputFailure => {
            "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT_FAILURE"
        }
        WorkerResponseType::BuildThresholdEd25519SeedExportArtifactSuccess => {
            "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT_SUCCESS"
        }
        WorkerResponseType::BuildThresholdEd25519SeedExportArtifactFailure => {
            "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEcdsaHssSessionSuccess => {
            "PREPARE_THRESHOLD_ECDSA_HSS_SESSION_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEcdsaHssSessionFailure => {
            "PREPARE_THRESHOLD_ECDSA_HSS_SESSION_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEcdsaHssClientRequestSuccess => {
            "PREPARE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEcdsaHssClientRequestFailure => {
            "PREPARE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST_FAILURE"
        }
        WorkerResponseType::FinalizeThresholdEcdsaHssClientRequestSuccess => {
            "FINALIZE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST_SUCCESS"
        }
        WorkerResponseType::FinalizeThresholdEcdsaHssClientRequestFailure => {
            "FINALIZE_THRESHOLD_ECDSA_HSS_CLIENT_REQUEST_FAILURE"
        }
    }
}

/// Parsed outer worker request envelope (`{ type, payload }`) coming from JS.
/// This:
/// - Accepts either a plain JS object (browser) or a JSON string (Node / server).
/// - Extracts the numeric `type` and converts it to `WorkerRequestType`.
/// - Returns the raw numeric type alongside the `payload` `JsValue`.
///
/// The key design choice here is to *not* use `serde_wasm_bindgen` on the full
/// envelope. `serde_wasm_bindgen::preserve` encodes `JsValue` fields using an
/// internal "magic string" representation, which broke when callers passed
/// plain JS objects as `payload`. By manually reading `type` and `payload`
/// via `Reflect::get`, we avoid that fragile encoding layer entirely.
pub struct SignerWorkerMessage {
    pub request_type: WorkerRequestType,
    pub request_type_raw: u32,
    pub payload: JsValue,
}

pub fn parse_worker_request_envelope(message_val: JsValue) -> Result<SignerWorkerMessage, JsValue> {
    // Support both Object (Browser) and JSON String (Node.js/Server) inputs.
    let message_obj = if message_val.is_string() {
        let json_str = message_val.as_string().unwrap_or_default();
        js_sys::JSON::parse(&json_str).map_err(|e| {
            JsValue::from_str(&format!("Failed to parse JSON string input: {:?}", e))
        })?
    } else {
        message_val
    };

    // Extract type and payload manually to avoid relying on serde_wasm_bindgen
    // to deserialize JsValue fields via its internal "magic string" representation.
    let msg_type_js = js_sys::Reflect::get(&message_obj, &JsValue::from_str("type"))
        .map_err(|e| JsValue::from_str(&format!("Failed to read message.type: {:?}", e)))?;
    let msg_type_num = msg_type_js
        .as_f64()
        .ok_or_else(|| JsValue::from_str("message.type must be a number"))?
        as u32;
    let request_type = WorkerRequestType::from(msg_type_num);

    let payload_js = js_sys::Reflect::get(&message_obj, &JsValue::from_str("payload"))
        .map_err(|e| JsValue::from_str(&format!("Failed to read message.payload: {:?}", e)))?;

    Ok(SignerWorkerMessage {
        request_type,
        request_type_raw: msg_type_num,
        payload: payload_js,
    })
}

/// Main worker response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerResponse {
    #[serde(rename = "type")]
    pub response_type: u32,
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub payload: JsValue,
}
