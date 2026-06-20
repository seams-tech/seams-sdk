// ******************************************************************************
// *                                                                            *
// *                 HANDLER: SIGN TRANSACTION WITH ACTIONS                   *
// *                                                                            *
// ******************************************************************************

use crate::actions::ActionParams;
use crate::threshold::signer_backend::Ed25519SignerBackend;
use crate::transaction::{
    build_actions_from_params, build_transaction_with_actions, calculate_transaction_hash,
    sign_transaction,
};
use crate::types::{
    handlers::{ConfirmationConfig, RpcCallPayload},
    progress::{
        send_completion_message, send_progress_message, ProgressData, ProgressMessageType,
        ProgressStep,
    },
    wasm_to_json::WasmSignedTransaction,
    SignedTransaction, ThresholdSignerConfig,
};
use bs58;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTransactionsWithActionsRequest {
    pub rpc_call: RpcCallPayload,
    pub session_id: String,
    pub created_at: Option<f64>,
    pub threshold: ThresholdSignerConfig,
    pub tx_signing_requests: Vec<TransactionPayload>,
    /// Unified confirmation configuration for controlling the confirmation flow
    pub confirmation_config: Option<ConfirmationConfig>,
    pub intent_digest: Option<String>,
    pub transaction_context: Option<crate::types::handlers::TransactionContext>,
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionPayload {
    pub near_account_id: String,
    pub receiver_id: String,
    pub actions: Vec<ActionParams>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHashes")]
    pub transaction_hashes: Option<Vec<String>>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransactions")]
    pub signed_transactions: Option<Vec<WasmSignedTransaction>>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl TransactionSignResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        success: bool,
        transaction_hashes: Option<Vec<String>>,
        signed_transactions: Option<Vec<WasmSignedTransaction>>,
        logs: Vec<String>,
        error: Option<String>,
    ) -> TransactionSignResult {
        TransactionSignResult {
            success,
            transaction_hashes,
            signed_transactions,
            logs,
            error,
        }
    }

    /// Helper function to create a failed TransactionSignResult
    pub fn failed(logs: Vec<String>, error_msg: String) -> TransactionSignResult {
        TransactionSignResult::new(
            false,
            None, // No transaction hashes
            None, // No signed transactions
            logs,
            Some(error_msg),
        )
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyActionResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHash")]
    pub transaction_hash: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<WasmSignedTransaction>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl KeyActionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        success: bool,
        transaction_hash: Option<String>,
        signed_transaction: Option<WasmSignedTransaction>,
        logs: Vec<String>,
        error: Option<String>,
    ) -> KeyActionResult {
        KeyActionResult {
            success,
            transaction_hash,
            signed_transaction,
            logs,
            error,
        }
    }
}

// ******************************************************************************
// *                           MAIN HANDLER                                   *
// ******************************************************************************

/// **Handles:** `WorkerRequestType::SignTransactionsWithActions`
/// The worker enum name is kept until generated request IDs are renamed, but
/// current signing accepts exactly one NEAR transaction with one or more actions.
///
/// # Arguments
/// * `tx_batch_request` - Contains verification data, decryption parameters, and array of transaction requests
///
/// # Returns
/// * `TransactionSignResult` - Contains success status, transaction hashes, signed transactions, and detailed logs
pub async fn handle_sign_transactions_with_actions(
    tx_batch_request: SignTransactionsWithActionsRequest,
) -> Result<TransactionSignResult, String> {
    if tx_batch_request.tx_signing_requests.len() != 1 {
        return Err(format!(
            "Expected exactly one NEAR transaction but received {}",
            tx_batch_request.tx_signing_requests.len()
        ));
    }

    let mut logs: Vec<String> = Vec::new();
    logs.push("Processing one transaction".to_string());

    // Validate session expiry if created_at is present
    if let Some(created_at) = tx_batch_request.created_at {
        let now = js_sys::Date::now();
        if now - created_at > crate::config::SESSION_MAX_DURATION_MS {
            return Err("Session expired".to_string());
        }
    }

    let tx_request = tx_batch_request
        .tx_signing_requests
        .first()
        .ok_or_else(|| "Expected exactly one NEAR transaction".to_string())?;
    logs.push(format!(
        "Transaction: {} -> {} ({} actions)",
        tx_request.near_account_id,
        tx_request.receiver_id,
        tx_request.actions.len()
    ));
    send_progress_message(
        ProgressMessageType::ExecuteActionsProgress,
        ProgressStep::UserConfirmation,
        "Using pre-confirmed signing session from SecureConfirm flow...",
        Some(&ProgressData::new(1, 4).with_transaction_count(1)),
    );

    let intent_digest = tx_batch_request
        .intent_digest
        .clone()
        .ok_or_else(|| "Missing intent digest from pre-confirmed session".to_string())?;

    let transaction_context = tx_batch_request
        .transaction_context
        .clone()
        .ok_or_else(|| "Missing transaction context from confirmation".to_string())?;

    logs.push(format!(
        "Pre-confirmed session with intent digest {}",
        intent_digest
    ));

    // Step 2: Extract credentials for verification
    logs.push("Extracting credentials for contract verification...".to_string());
    send_progress_message(
        ProgressMessageType::ExecuteActionsProgress,
        ProgressStep::Preparation,
        "Extracting credentials for verification...",
        Some(&ProgressData::new(2, 4)),
    );

    logs.push("Signing transaction in secure WASM context...".to_string());

    send_progress_message(
        ProgressMessageType::ExecuteActionsProgress,
        ProgressStep::TransactionSigningProgress,
        "Signing transaction...",
        Some(&ProgressData::new(4, 4).with_transaction_count(1)),
    );

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct NearTxAuthorizeSigningPayload<'a> {
        kind: &'a str,
        tx_signing_requests: &'a Vec<TransactionPayload>,
        transaction_context: &'a crate::types::handlers::TransactionContext,
    }

    let signing_payload_json = {
        let js_val = serde_wasm_bindgen::to_value(&NearTxAuthorizeSigningPayload {
            kind: "near_tx",
            tx_signing_requests: &tx_batch_request.tx_signing_requests,
            transaction_context: &transaction_context,
        })
        .map_err(|e| format!("Failed to serialize signingPayload: {e}"))?;
        js_sys::JSON::stringify(&js_val)
            .map_err(|e| format!("JSON.stringify signingPayload failed: {:?}", e))?
            .as_string()
            .ok_or_else(|| "JSON.stringify signingPayload did not return a string".to_string())?
    };

    let signer = Ed25519SignerBackend::from_threshold_signer_config(
        &tx_batch_request.rpc_call.near_account_id,
        &transaction_context.near_public_key_str,
        "near_tx",
        tx_batch_request.credential.clone(),
        Some(signing_payload_json),
        &tx_batch_request.threshold,
    )?;

    let transaction_request = tx_batch_request
        .tx_signing_requests
        .into_iter()
        .next()
        .ok_or_else(|| "Expected exactly one NEAR transaction".to_string())?;
    let result = sign_near_transaction_with_actions_impl(
        transaction_request,
        &signer,
        &transaction_context,
        logs,
    )
    .await?;

    // Send completion progress message
    send_completion_message(
        // Mark as terminal success so UIs don't remain "stuck" treating this as in-progress.
        ProgressMessageType::ExecuteActionsComplete,
        ProgressStep::TransactionSigningComplete,
        "Transaction signed successfully",
        Some(
            &ProgressData::new(4, 4)
                .with_success(result.success)
                .with_transaction_count(1)
                .with_logs(result.logs.clone()),
        ),
    );

    Ok(result)
}

/// Internal implementation for one transaction with one or more actions after
/// verification is complete.
///
/// # Arguments
/// * `tx_requests` - Array of transaction payloads to sign
/// * `decryption` - Shared decryption parameters for private key access
/// * `logs` - Existing log entries to append to
///
/// # Returns
/// * `TransactionSignResult` - Contains batch signing results with individual transaction details
async fn sign_near_transaction_with_actions_impl(
    tx_data: TransactionPayload,
    signer: &Ed25519SignerBackend,
    transaction_context: &crate::types::handlers::TransactionContext,
    mut logs: Vec<String>,
) -> Result<TransactionSignResult, String> {
    logs.push("Processing transaction".to_string());
    let public_key_bytes = signer.public_key_bytes()?;
    logs.push("Signer backend initialized successfully".to_string());

    let current_nonce: u64 = transaction_context
        .next_nonce
        .parse()
        .map_err(|e| format!("Invalid nonce: {}", e))?;

    let action_params: Vec<ActionParams> = {
        let params = tx_data.actions.clone();
        logs.push(format!("Transaction: Parsed {} actions", params.len()));
        params
    };

    let actions = match build_actions_from_params(action_params) {
        Ok(actions) => {
            logs.push("Transaction: Actions built successfully".to_string());
            actions
        }
        Err(e) => {
            let error_msg = format!("Transaction: Failed to build actions: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    let transaction = match build_transaction_with_actions(
        &tx_data.near_account_id,
        &tx_data.receiver_id,
        current_nonce,
        &bs58::decode(&transaction_context.tx_block_hash)
            .into_vec()
            .map_err(|e| format!("Invalid block hash: {}", e))?,
        &public_key_bytes,
        actions,
    ) {
        Ok(tx) => {
            logs.push(format!(
                "Transaction: Built successfully (nonce used: {})",
                current_nonce
            ));
            tx
        }
        Err(e) => {
            let error_msg = format!("Transaction: Failed to build transaction: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    let (transaction_hash_to_sign, _size) = transaction.get_hash_and_size();
    let signature_bytes = match signer.sign(&transaction_hash_to_sign.0).await {
        Ok(sig) => sig,
        Err(e) => {
            let error_msg = format!("Transaction: Failed to sign transaction: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    let signed_tx_bytes = match sign_transaction(transaction, &signature_bytes) {
        Ok(bytes) => {
            logs.push("Transaction: Signed successfully".to_string());
            bytes
        }
        Err(e) => {
            let error_msg = format!("Transaction: Failed to serialize signed transaction: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    let transaction_hash = calculate_transaction_hash(&signed_tx_bytes);
    logs.push(format!(
        "Transaction: Hash calculated - {}",
        transaction_hash
    ));

    let signed_tx: SignedTransaction = borsh::from_slice(&signed_tx_bytes).map_err(|e| {
        let error_msg = format!(
            "Transaction: Failed to deserialize SignedTransaction: {}",
            e
        );
        logs.push(error_msg.clone());
        error_msg
    })?;

    logs.push("Transaction signed successfully".to_string());

    Ok(TransactionSignResult::new(
        true,
        Some(vec![transaction_hash]),
        Some(vec![WasmSignedTransaction::from(&signed_tx)]),
        logs,
        None,
    ))
}
