mod actions;
mod config;
mod cose;
mod crypto;
mod encoders;
mod error;
#[cfg(target_arch = "wasm32")]
mod fetch;
mod handlers;
mod logger;
#[cfg(test)]
mod tests;
mod threshold;
mod transaction;
mod types;

use crate::threshold::threshold_frost::{
    build_threshold_ed25519_seed_export_artifact_from_seed,
    ThresholdEd25519SeedExportArtifactFromSeedArgs,
};
use crate::threshold::threshold_hss::{
    derive_threshold_ed25519_hss_public_key_from_base_shares, open_threshold_ed25519_hss_seed_output,
    ThresholdEd25519HssOpenSeedOutputArgs, ThresholdEd25519HssPublicKeyFromSharesArgs,
};
#[cfg(any(feature = "hss-client-exports", not(feature = "hss-server-exports")))]
use crate::threshold::threshold_hss::{
    evaluate_threshold_ed25519_hss_result, open_threshold_ed25519_hss_client_output,
    prepare_threshold_ed25519_hss_client_request, prepare_threshold_ed25519_hss_session,
    ThresholdEd25519HssEvaluateResultArgs, ThresholdEd25519HssOpenClientOutputArgs,
    ThresholdEd25519HssPrepareClientRequestArgs, ThresholdEd25519HssPrepareSessionArgs,
};
use crate::types::worker_messages::{
    parse_typed_payload, parse_worker_request_envelope, worker_request_type_name,
    worker_response_type_name, SignerWorkerMessage, SignerWorkerResponse, WorkerRequestType,
    WorkerResponseType,
};
use crate::types::*;
use log::debug;
use wasm_bindgen::prelude::*;

pub use handlers::{
    CoseExtractionResult,
    // Delegate Actions
    DelegatePayload,
    DelegateSignResult,
    // Threshold Signing
    DeriveThresholdEd25519ClientVerifyingShareRequest,
    DeriveThresholdEd25519HssClientInputsRequest,
    DeriveThresholdEd25519HssClientInputsResult,
    // Extract Cose Public Key
    ExtractCoseRequest,
    GenerateEphemeralNearKeypairRequest,
    KeyActionResult,
    SignDelegateActionRequest,
    // Sign Nep413 Message
    SignNep413Request,
    SignNep413Result,
    // Sign Transaction With Key Pair
    SignTransactionWithKeyPairRequest,
    // Execute Actions
    SignTransactionsWithActionsRequest,
    TransactionPayload,
};

// Re-export NEAR types for TypeScript usage
pub use types::near::{
    DelegateAction, PublicKey, Signature, SignedDelegate, SignedTransaction, Transaction,
};
// Re-export progress types for auto-generation
pub use types::progress::{
    ProgressMessageType, ProgressStatus, ProgressStep, WorkerProgressMessage,
};
// Re-export WASM-friendly wrapper types for TypeScript usage
pub use types::wasm_to_json::{
    WasmDelegateAction, WasmPublicKey, WasmSignature, WasmSignedDelegate, WasmSignedTransaction,
    WasmTransaction,
};

pub use crate::crypto::WrapKey;

#[wasm_bindgen]
pub fn init_worker() {
    logger::init(config::CURRENT_LOG_LEVEL);
}

/// Alias for init_worker to maintain compatibility with bundlers that auto-generate
/// imports based on the module name (e.g., Rolldown)
#[wasm_bindgen(js_name = "init_wasm_signer_worker")]
pub fn init_wasm_signer_worker() {
    init_worker();
}

// === PROGRESS MESSAGING ===

/// Progress messaging function that sends messages back to main thread
/// Used by handlers to provide real-time updates during long operations
/// Now includes both numeric enum values AND string names for better debugging
pub fn send_progress_message(message_type: u32, step: u32, message: &str, data: JsValue) {
    // Call the TypeScript sendProgressMessage function that was made globally available
    // This replaces the direct postMessage approach
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = sendProgressMessage)]
        fn send_progress_message_js(
            message_type: u32,
            message_type_name: &str,
            step: u32,
            step_name: &str,
            message: &str,
            data: JsValue,
            logs: JsValue,
        );
    }

    // Convert numeric enums back to their string names for debugging
    let message_type_name = match ProgressMessageType::try_from(message_type) {
        Ok(msg_type) => progress_message_type_name(msg_type),
        Err(_) => "UNKNOWN_MESSAGE_TYPE",
    };

    let step_name = match ProgressStep::try_from(step) {
        Ok(step_enum) => progress_step_name(step_enum),
        Err(_) => "unknown-step",
    };

    // Only try to send message in WASM context
    #[cfg(target_arch = "wasm32")]
    {
        let logs = JsValue::from(js_sys::Array::new());
        send_progress_message_js(
            message_type,
            message_type_name,
            step,
            step_name,
            message,
            data,
            logs,
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = data;
        // In non-WASM context (like tests), just log the progress
        println!(
            "Progress: {} ({}) - {} ({}) - {}",
            message_type_name, message_type, step_name, step, message
        );
    }
}

fn require_field(
    field_name: &str,
    value: &Option<String>,
    request_type: WorkerRequestType,
) -> Result<String, JsValue> {
    let trimmed = value.as_deref().unwrap_or("").trim();
    if trimmed.is_empty() {
        return Err(JsValue::from_str(&format!(
            "Missing {} for {}",
            field_name,
            worker_request_type_name(request_type)
        )));
    }
    Ok(trimmed.to_string())
}

fn wrap_key_from_request(
    prf_first_b64u: &Option<String>,
    wrap_key_salt: &Option<String>,
    request_type: WorkerRequestType,
) -> Result<WrapKey, JsValue> {
    let wrap_key_seed = require_field("prfFirstB64u", prf_first_b64u, request_type)?;
    let wrap_key_salt = require_field("wrapKeySalt", wrap_key_salt, request_type)?;
    Ok(WrapKey {
        wrap_key_seed,
        wrap_key_salt,
    })
}

// === MESSAGE HANDLER FUNCTIONS ===

/// Unified message handler for all signer worker operations
/// This replaces the TypeScript-based message dispatching with a Rust-based approach
/// for better type safety and performance
#[wasm_bindgen]
pub async fn handle_signer_message(message_val: JsValue) -> Result<JsValue, JsValue> {
    init_worker();

    // Parse the outer `{ type, payload }` envelope from JS into a strongly
    // typed `WorkerRequestType` and raw `payload` value.
    let SignerWorkerMessage {
        request_type,
        request_type_raw: msg_type_num,
        payload: payload_js,
    } = parse_worker_request_envelope(message_val)?;

    debug!(
        "WASM Worker: Received message type: {} ({})",
        worker_request_type_name(request_type),
        msg_type_num
    );

    // Route message to appropriate handler
    let response_payload = match request_type {
        WorkerRequestType::SignTransactionsWithActions => {
            let request: SignTransactionsWithActionsRequest =
                parse_typed_payload(&payload_js, request_type)?;
            let result = handlers::handle_sign_transactions_with_actions(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::SignDelegateAction => {
            let request: SignDelegateActionRequest =
                parse_typed_payload(&payload_js, request_type)?;
            let result = handlers::handle_sign_delegate_action(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::ExtractCosePublicKey => {
            let request: ExtractCoseRequest = parse_typed_payload(&payload_js, request_type)?;
            let result = handlers::handle_extract_cose_public_key(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        // NOTE: Does not need PRF-derived WrapKey material.
        // The only method that does not require SecureConfirm/WebAuthn material to sign.
        WorkerRequestType::SignTransactionWithKeyPair => {
            let request: SignTransactionWithKeyPairRequest =
                parse_typed_payload(&payload_js, request_type)?;
            let result = handlers::handle_sign_transaction_with_keypair(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::SignNep413Message => {
            let request: SignNep413Request = parse_typed_payload(&payload_js, request_type)?;
            let result = handlers::handle_sign_nep413_message(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare => {
            let request: DeriveThresholdEd25519ClientVerifyingShareRequest =
                parse_typed_payload(&payload_js, request_type)?;
            let wrap_key = wrap_key_from_request(
                &request.prf_first_b64u,
                &request.wrap_key_salt,
                request_type,
            )?;
            let result =
                handlers::handle_threshold_ed25519_derive_client_verifying_share(request, wrap_key)
                    .await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::DeriveThresholdEd25519HssClientInputs => {
            let request: DeriveThresholdEd25519HssClientInputsRequest =
                parse_typed_payload(&payload_js, request_type)?;
            let result =
                handlers::handle_threshold_ed25519_derive_hss_client_inputs(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::GenerateEphemeralNearKeypair => {
            let request: GenerateEphemeralNearKeypairRequest =
                parse_typed_payload(&payload_js, request_type)?;
            let result = handlers::handle_generate_ephemeral_near_keypair(request).await?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::PrepareThresholdEd25519HssSession => {
            #[cfg(any(feature = "hss-client-exports", not(feature = "hss-server-exports")))]
            {
                let request: ThresholdEd25519HssPrepareSessionArgs =
                    parse_typed_payload(&payload_js, request_type)?;
                let result = prepare_threshold_ed25519_hss_session(request)
                    .map_err(|e| JsValue::from_str(&e))?;
                serde_wasm_bindgen::to_value(&result).map_err(|e| {
                    JsValue::from_str(&format!("Failed to serialize result: {:?}", e))
                })?
            }
            #[cfg(not(any(feature = "hss-client-exports", not(feature = "hss-server-exports"))))]
            {
                return Err(JsValue::from_str(
                    "PrepareThresholdEd25519HssSession is not available in the server HSS runtime",
                ));
            }
        }
        WorkerRequestType::PrepareThresholdEd25519HssClientRequest => {
            #[cfg(any(feature = "hss-client-exports", not(feature = "hss-server-exports")))]
            {
                let request: ThresholdEd25519HssPrepareClientRequestArgs =
                    parse_typed_payload(&payload_js, request_type)?;
                let result = prepare_threshold_ed25519_hss_client_request(request)
                    .map_err(|e| JsValue::from_str(&e))?;
                serde_wasm_bindgen::to_value(&result).map_err(|e| {
                    JsValue::from_str(&format!("Failed to serialize result: {:?}", e))
                })?
            }
            #[cfg(not(any(feature = "hss-client-exports", not(feature = "hss-server-exports"))))]
            {
                return Err(JsValue::from_str(
                    "PrepareThresholdEd25519HssClientRequest is not available in the server HSS runtime",
                ));
            }
        }
        WorkerRequestType::EvaluateThresholdEd25519HssResult => {
            #[cfg(any(feature = "hss-client-exports", not(feature = "hss-server-exports")))]
            {
                let request: ThresholdEd25519HssEvaluateResultArgs =
                    parse_typed_payload(&payload_js, request_type)?;
                let result = evaluate_threshold_ed25519_hss_result(request)
                    .map_err(|e| JsValue::from_str(&e))?;
                serde_wasm_bindgen::to_value(&result).map_err(|e| {
                    JsValue::from_str(&format!("Failed to serialize result: {:?}", e))
                })?
            }
            #[cfg(not(any(feature = "hss-client-exports", not(feature = "hss-server-exports"))))]
            {
                return Err(JsValue::from_str(
                    "EvaluateThresholdEd25519HssResult is not available in the server HSS runtime",
                ));
            }
        }
        WorkerRequestType::OpenThresholdEd25519HssClientOutput => {
            #[cfg(any(feature = "hss-client-exports", not(feature = "hss-server-exports")))]
            {
                let request: ThresholdEd25519HssOpenClientOutputArgs =
                    parse_typed_payload(&payload_js, request_type)?;
                let result = open_threshold_ed25519_hss_client_output(request)
                    .map_err(|e| JsValue::from_str(&e))?;
                serde_wasm_bindgen::to_value(&result).map_err(|e| {
                    JsValue::from_str(&format!("Failed to serialize result: {:?}", e))
                })?
            }
            #[cfg(not(any(feature = "hss-client-exports", not(feature = "hss-server-exports"))))]
            {
                return Err(JsValue::from_str(
                    "OpenThresholdEd25519HssClientOutput is not available in the server HSS runtime",
                ));
            }
        }
        WorkerRequestType::OpenThresholdEd25519HssSeedOutput => {
            let request: ThresholdEd25519HssOpenSeedOutputArgs =
                parse_typed_payload(&payload_js, request_type)?;
            let result = open_threshold_ed25519_hss_seed_output(request)
                .map_err(|e| JsValue::from_str(&e))?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::DeriveThresholdEd25519HssPublicKey => {
            let request: ThresholdEd25519HssPublicKeyFromSharesArgs =
                parse_typed_payload(&payload_js, request_type)?;
            let result = derive_threshold_ed25519_hss_public_key_from_base_shares(request)
                .map_err(|e| JsValue::from_str(&e))?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
        WorkerRequestType::BuildThresholdEd25519SeedExportArtifact => {
            let request: ThresholdEd25519SeedExportArtifactFromSeedArgs =
                parse_typed_payload(&payload_js, request_type)?;
            let result = build_threshold_ed25519_seed_export_artifact_from_seed(request)
                .map_err(|e| JsValue::from_str(&e))?;
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {:?}", e)))?
        }
    };

    // At this point, response_payload is the successful JsValue result.
    // Errors would have been propagated early via `?` operator and caught by the TypeScript wrapper.

    // Determine the success response type based on the request type
    let response_type = match request_type {
        WorkerRequestType::SignTransactionsWithActions => {
            WorkerResponseType::SignTransactionsWithActionsSuccess
        }
        WorkerRequestType::SignDelegateAction => WorkerResponseType::SignDelegateActionSuccess,
        WorkerRequestType::ExtractCosePublicKey => WorkerResponseType::ExtractCosePublicKeySuccess,
        WorkerRequestType::SignTransactionWithKeyPair => {
            WorkerResponseType::SignTransactionWithKeyPairSuccess
        }
        WorkerRequestType::SignNep413Message => WorkerResponseType::SignNep413MessageSuccess,
        WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare => {
            WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareSuccess
        }
        WorkerRequestType::DeriveThresholdEd25519HssClientInputs => {
            WorkerResponseType::DeriveThresholdEd25519HssClientInputsSuccess
        }
        WorkerRequestType::GenerateEphemeralNearKeypair => {
            WorkerResponseType::GenerateEphemeralNearKeypairSuccess
        }
        WorkerRequestType::PrepareThresholdEd25519HssSession => {
            WorkerResponseType::PrepareThresholdEd25519HssSessionSuccess
        }
        WorkerRequestType::PrepareThresholdEd25519HssClientRequest => {
            WorkerResponseType::PrepareThresholdEd25519HssClientRequestSuccess
        }
        WorkerRequestType::EvaluateThresholdEd25519HssResult => {
            WorkerResponseType::EvaluateThresholdEd25519HssResultSuccess
        }
        WorkerRequestType::OpenThresholdEd25519HssClientOutput => {
            WorkerResponseType::OpenThresholdEd25519HssClientOutputSuccess
        }
        WorkerRequestType::OpenThresholdEd25519HssSeedOutput => {
            WorkerResponseType::OpenThresholdEd25519HssSeedOutputSuccess
        }
        WorkerRequestType::DeriveThresholdEd25519HssPublicKey => {
            WorkerResponseType::DeriveThresholdEd25519HssPublicKeySuccess
        }
        WorkerRequestType::BuildThresholdEd25519SeedExportArtifact => {
            WorkerResponseType::BuildThresholdEd25519SeedExportArtifactSuccess
        }
    };

    // Debug logging for response type
    debug!(
        "WASM Worker: Determined response type: {} ({})",
        worker_response_type_name(response_type),
        u32::from(response_type)
    );

    // Create the final response
    let response = SignerWorkerResponse {
        response_type: u32::from(response_type),
        payload: response_payload,
    };

    // Return JsValue directly
    serde_wasm_bindgen::to_value(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {:?}", e)))
}
