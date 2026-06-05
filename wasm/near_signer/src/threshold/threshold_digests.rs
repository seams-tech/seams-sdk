use crate::actions::ActionParams;
use crate::encoders::{base64_url_decode, base64_url_encode, hash_delegate_action};
use crate::transaction::{build_actions_from_params, build_transaction_with_actions};
use crate::transaction::{calculate_transaction_hash, sign_transaction};
use crate::types::wasm_to_json::{WasmSignedDelegate, WasmSignedTransaction};
use crate::types::{AccountId, DelegateAction, PublicKey, Signature, SignedDelegate, Transaction};
use borsh;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

fn parse_near_public_key_to_bytes(public_key: &str) -> Result<[u8; 32], JsValue> {
    signer_core::near_threshold_ed25519::parse_near_public_key_to_bytes(public_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn parse_near_block_hash_to_bytes(block_hash_b58: &str) -> Result<[u8; 32], JsValue> {
    let decoded = bs58::decode(block_hash_b58.trim())
        .into_vec()
        .map_err(|e| JsValue::from_str(&format!("Invalid block hash base58: {e}")))?;
    if decoded.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "Invalid block hash length: expected 32 bytes, got {}",
            decoded.len()
        )));
    }
    Ok(decoded.as_slice().try_into().expect("checked length above"))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NearTxSigningPayload {
    tx_signing_requests: Vec<NearTxRequest>,
    transaction_context: NearTxContext,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NearTxRequest {
    near_account_id: String,
    receiver_id: String,
    actions: Vec<ActionParams>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NearTxContext {
    near_public_key_str: String,
    next_nonce: String,
    tx_block_hash: String,
}

fn build_near_transactions_from_payload(
    payload: NearTxSigningPayload,
) -> Result<Vec<Transaction>, JsValue> {
    if payload.tx_signing_requests.is_empty() {
        return Err(JsValue::from_str("txSigningRequests must not be empty"));
    }

    let near_public_key_bytes =
        parse_near_public_key_to_bytes(&payload.transaction_context.near_public_key_str)?;
    let block_hash_bytes =
        parse_near_block_hash_to_bytes(&payload.transaction_context.tx_block_hash)?;

    let base_nonce: u64 = payload
        .transaction_context
        .next_nonce
        .trim()
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid transactionContext.nextNonce: {e}")))?;

    let signer_account_id = payload.tx_signing_requests[0]
        .near_account_id
        .trim()
        .to_string();
    if signer_account_id.is_empty() {
        return Err(JsValue::from_str(
            "txSigningRequests[0].nearAccountId is required",
        ));
    }
    for tx in &payload.tx_signing_requests {
        if tx.near_account_id.trim() != signer_account_id {
            return Err(JsValue::from_str(
                "All txSigningRequests[].nearAccountId must match",
            ));
        }
    }

    let mut transactions = Vec::with_capacity(payload.tx_signing_requests.len());
    for (i, tx) in payload.tx_signing_requests.iter().enumerate() {
        let nonce = base_nonce.saturating_add(i as u64);
        let actions = build_actions_from_params(tx.actions.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to build actions: {e}")))?;
        transactions.push(
            build_transaction_with_actions(
                &signer_account_id,
                tx.receiver_id.trim(),
                nonce,
                &block_hash_bytes,
                &near_public_key_bytes,
                actions,
            )
            .map_err(|e| JsValue::from_str(&format!("Failed to build transaction: {e}")))?,
        );
    }
    Ok(transactions)
}

/// Compute the NEAR transaction signing digests (`sha256(borsh(Transaction))`) for the
/// provided batch signing payload (tx list + transaction context).
///
/// Returns a JS Array of Uint8Array (each 32 bytes), one per tx in order.
#[wasm_bindgen]
pub fn threshold_ed25519_compute_near_tx_signing_digests(
    payload: JsValue,
) -> Result<JsValue, JsValue> {
    let payload: NearTxSigningPayload = serde_wasm_bindgen::from_value(payload)
        .map_err(|e| JsValue::from_str(&format!("Invalid near_tx signingPayload: {e}")))?;
    let out = js_sys::Array::new();
    for tx_obj in build_near_transactions_from_payload(payload)?.iter() {
        let (hash, _size) = tx_obj.get_hash_and_size();
        out.push(&js_sys::Uint8Array::from(hash.0.as_slice()));
    }

    Ok(out.into())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NearTxUnsignedBorshOutput {
    unsigned_transaction_borsh_b64u: String,
    signing_digest_b64u: String,
}

/// Build unsigned NEAR transaction borsh bytes and signing digest from the
/// canonical transaction payload used by threshold Ed25519 signing.
#[wasm_bindgen]
pub fn threshold_ed25519_build_near_tx_unsigned_borsh(
    payload: JsValue,
) -> Result<JsValue, JsValue> {
    let payload: NearTxSigningPayload = serde_wasm_bindgen::from_value(payload)
        .map_err(|e| JsValue::from_str(&format!("Invalid near_tx signingPayload: {e}")))?;
    let transactions = build_near_transactions_from_payload(payload)?;
    let out = js_sys::Array::new();
    for tx in transactions.iter() {
        let unsigned_bytes = borsh::to_vec(tx)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize transaction: {e}")))?;
        let (hash, _size) = tx.get_hash_and_size();
        let item = NearTxUnsignedBorshOutput {
            unsigned_transaction_borsh_b64u: base64_url_encode(unsigned_bytes.as_slice()),
            signing_digest_b64u: base64_url_encode(hash.0.as_slice()),
        };
        out.push(&serde_wasm_bindgen::to_value(&item).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to serialize unsigned transaction output: {e}"
            ))
        })?);
    }
    Ok(out.into())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalizeNearTransactionFromSignatureArgs {
    unsigned_transaction_borsh_b64u: String,
    signing_digest_b64u: String,
    signature_b64u: String,
    expected_near_account_id: String,
    expected_signer_public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateNearTransactionArgs {
    unsigned_transaction_borsh_b64u: String,
    signing_digest_b64u: String,
    tx_signing_requests: Vec<NearTxRequest>,
    expected_near_account_id: String,
    expected_signer_public_key: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalizeNearTransactionFromSignatureOutput {
    signed_transaction_borsh_b64u: String,
    transaction_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecodeSignedNearTransactionBorshArgs {
    signed_transaction_borsh_b64u: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodeSignedNearTransactionBorshOutput {
    signed_transaction: WasmSignedTransaction,
    transaction_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateNearTransactionOutput {
    signer_account_id: String,
    signer_public_key: String,
    nonce: String,
}

fn decode_and_validate_near_transaction(
    args: &ValidateNearTransactionArgs,
) -> Result<Transaction, JsValue> {
    let unsigned_bytes = base64_url_decode(args.unsigned_transaction_borsh_b64u.trim())
        .map_err(|e| JsValue::from_str(&format!("Invalid unsignedTransactionBorshB64u: {e}")))?;
    if unsigned_bytes.is_empty() {
        return Err(JsValue::from_str(
            "unsignedTransactionBorshB64u must decode to non-empty bytes",
        ));
    }
    let signing_digest = base64_url_decode(args.signing_digest_b64u.trim())
        .map_err(|e| JsValue::from_str(&format!("Invalid signingDigestB64u: {e}")))?;
    if signing_digest.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "signingDigestB64u must decode to 32 bytes, got {}",
            signing_digest.len()
        )));
    }
    let computed_digest = Sha256::digest(unsigned_bytes.as_slice());
    if computed_digest.as_slice() != signing_digest.as_slice() {
        return Err(JsValue::from_str(
            "signingDigestB64u does not match unsignedTransactionBorshB64u",
        ));
    }
    let transaction: Transaction = borsh::from_slice(unsigned_bytes.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Invalid unsigned NEAR transaction borsh: {e}")))?;
    let expected_near_account_id = args.expected_near_account_id.trim();
    if expected_near_account_id.is_empty() {
        return Err(JsValue::from_str("expectedNearAccountId is required"));
    }
    if transaction.signer_id.0 != expected_near_account_id {
        return Err(JsValue::from_str(
            "unsignedTransactionBorshB64u signer account does not match nearAccountId",
        ));
    }
    let expected_public_key_bytes =
        parse_near_public_key_to_bytes(args.expected_signer_public_key.trim())?;
    if transaction.public_key.key_type != 0
        || transaction.public_key.key_data != expected_public_key_bytes
    {
        return Err(JsValue::from_str(
            "unsignedTransactionBorshB64u signer public key does not match expectedSignerPublicKey",
        ));
    }
    if !args.tx_signing_requests.is_empty() {
        let rebuilt_transactions = build_near_transactions_from_payload(NearTxSigningPayload {
            tx_signing_requests: args.tx_signing_requests.clone(),
            transaction_context: NearTxContext {
                near_public_key_str: args.expected_signer_public_key.trim().to_string(),
                next_nonce: transaction.nonce.to_string(),
                tx_block_hash: bs58::encode(transaction.block_hash.to_vec()).into_string(),
            },
        })?;
        if rebuilt_transactions.len() != 1 {
            return Err(JsValue::from_str(
                "txSigningRequests must contain exactly one NEAR transaction",
            ));
        }
        let rebuilt_unsigned_bytes = borsh::to_vec(&rebuilt_transactions[0]).map_err(|e| {
            JsValue::from_str(&format!("Failed to serialize expected transaction: {e}"))
        })?;
        if rebuilt_unsigned_bytes.as_slice() != unsigned_bytes.as_slice() {
            return Err(JsValue::from_str(
                "unsignedTransactionBorshB64u does not match txSigningRequests",
            ));
        }
    }
    Ok(transaction)
}

#[wasm_bindgen]
pub fn threshold_ed25519_validate_near_tx_unsigned_borsh(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ValidateNearTransactionArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid near tx validation args: {e}")))?;
    let transaction = decode_and_validate_near_transaction(&args)?;
    let output = ValidateNearTransactionOutput {
        signer_account_id: transaction.signer_id.0,
        signer_public_key: format!(
            "ed25519:{}",
            bs58::encode(transaction.public_key.key_data).into_string()
        ),
        nonce: transaction.nonce.to_string(),
    };
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize validated NEAR transaction output: {e}"
        ))
    })
}

/// Attach a verified Ed25519 signature to a serialized NEAR Transaction.
///
/// The digest check binds the caller-provided signature to the exact unsigned
/// transaction bytes before the SignedTransaction is serialized for RPC.
#[wasm_bindgen]
pub fn threshold_ed25519_finalize_near_tx_from_signature(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: FinalizeNearTransactionFromSignatureArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid near tx finalize args: {e}")))?;
    let transaction = decode_and_validate_near_transaction(&ValidateNearTransactionArgs {
        unsigned_transaction_borsh_b64u: args.unsigned_transaction_borsh_b64u,
        signing_digest_b64u: args.signing_digest_b64u,
        tx_signing_requests: Vec::new(),
        expected_near_account_id: args.expected_near_account_id,
        expected_signer_public_key: args.expected_signer_public_key,
    })?;
    let signature_bytes = base64_url_decode(args.signature_b64u.trim())
        .map_err(|e| JsValue::from_str(&format!("Invalid signatureB64u: {e}")))?;
    if signature_bytes.len() != 64 {
        return Err(JsValue::from_str(&format!(
            "signatureB64u must decode to 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut signature64 = [0u8; 64];
    signature64.copy_from_slice(signature_bytes.as_slice());
    let signed_bytes = sign_transaction(transaction, &signature64)
        .map_err(|e| JsValue::from_str(&format!("Failed to build signed transaction: {e}")))?;
    let output = FinalizeNearTransactionFromSignatureOutput {
        signed_transaction_borsh_b64u: base64_url_encode(signed_bytes.as_slice()),
        transaction_hash: calculate_transaction_hash(signed_bytes.as_slice()),
    };
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize finalized NEAR transaction output: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_decode_signed_near_tx_borsh(args: JsValue) -> Result<JsValue, JsValue> {
    let args: DecodeSignedNearTransactionBorshArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid signed near tx decode args: {e}")))?;
    let signed_bytes = base64_url_decode(args.signed_transaction_borsh_b64u.trim())
        .map_err(|e| JsValue::from_str(&format!("Invalid signedTransactionBorshB64u: {e}")))?;
    if signed_bytes.is_empty() {
        return Err(JsValue::from_str(
            "signedTransactionBorshB64u must decode to non-empty bytes",
        ));
    }
    let signed_tx: crate::types::SignedTransaction = borsh::from_slice(signed_bytes.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Invalid signed NEAR transaction borsh: {e}")))?;
    let output = DecodeSignedNearTransactionBorshOutput {
        signed_transaction: WasmSignedTransaction::from(&signed_tx),
        transaction_hash: calculate_transaction_hash(signed_bytes.as_slice()),
    };
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize decoded signed NEAR transaction output: {e}"
        ))
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegateSigningPayload {
    delegate: DelegatePayload,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegatePayload {
    sender_id: String,
    receiver_id: String,
    actions: Vec<ActionParams>,
    nonce: String,
    max_block_height: String,
    public_key: String,
}

fn delegate_action_from_payload(payload: DelegatePayload) -> Result<DelegateAction, JsValue> {
    let sender_id: AccountId = payload
        .sender_id
        .trim()
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid delegate.senderId: {e}")))?;
    let receiver_id: AccountId = payload
        .receiver_id
        .trim()
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid delegate.receiverId: {e}")))?;

    let actions = build_actions_from_params(payload.actions)
        .map_err(|e| JsValue::from_str(&format!("Failed to build delegate actions: {e}")))?;

    let nonce: u64 = payload
        .nonce
        .trim()
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid delegate.nonce: {e}")))?;
    let max_block_height: u64 = payload
        .max_block_height
        .trim()
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid delegate.maxBlockHeight: {e}")))?;

    let pk_bytes = parse_near_public_key_to_bytes(payload.public_key.trim())?;
    let public_key = PublicKey::from_ed25519_bytes(&pk_bytes);

    Ok(DelegateAction {
        sender_id,
        receiver_id,
        actions,
        nonce,
        max_block_height,
        public_key,
    })
}

/// Compute the NEP-461 delegate signing digest (`sha256(encodeDelegateAction(...))`).
/// Returns a 32-byte Uint8Array.
#[wasm_bindgen]
pub fn threshold_ed25519_compute_delegate_signing_digest(
    payload: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let payload: DelegateSigningPayload = serde_wasm_bindgen::from_value(payload)
        .map_err(|e| JsValue::from_str(&format!("Invalid nep461_delegate signingPayload: {e}")))?;
    let delegate_action = delegate_action_from_payload(payload.delegate)?;
    let hash = hash_delegate_action(&delegate_action)
        .map_err(|e| JsValue::from_str(&format!("Failed to hash delegate action: {e}")))?;
    Ok(hash.to_vec())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalizeDelegateFromSignatureArgs {
    delegate: DelegatePayload,
    signing_digest_b64u: String,
    signature_b64u: String,
}

/// Attach a verified Ed25519 signature to a NEP-461 delegate action and return
/// the same WASM-friendly SignedDelegate shape used by the normal signer path.
#[wasm_bindgen]
pub fn threshold_ed25519_finalize_delegate_from_signature(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: FinalizeDelegateFromSignatureArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid delegate finalize args: {e}")))?;
    let delegate_action = delegate_action_from_payload(args.delegate)?;
    let hash = hash_delegate_action(&delegate_action)
        .map_err(|e| JsValue::from_str(&format!("Failed to hash delegate action: {e}")))?;
    let signing_digest = base64_url_decode(args.signing_digest_b64u.trim())
        .map_err(|e| JsValue::from_str(&format!("Invalid signingDigestB64u: {e}")))?;
    if signing_digest.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "signingDigestB64u must decode to 32 bytes, got {}",
            signing_digest.len()
        )));
    }
    if hash.as_slice() != signing_digest.as_slice() {
        return Err(JsValue::from_str(
            "signingDigestB64u does not match delegate action",
        ));
    }

    let signature_bytes = base64_url_decode(args.signature_b64u.trim())
        .map_err(|e| JsValue::from_str(&format!("Invalid signatureB64u: {e}")))?;
    if signature_bytes.len() != 64 {
        return Err(JsValue::from_str(&format!(
            "signatureB64u must decode to 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut signature64 = [0u8; 64];
    signature64.copy_from_slice(signature_bytes.as_slice());
    let signed_delegate = SignedDelegate {
        delegate_action,
        signature: Signature::from_ed25519_bytes(&signature64),
    };
    serde_wasm_bindgen::to_value(&WasmSignedDelegate::from(&signed_delegate)).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize finalized signed delegate: {e}"
        ))
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Nep413SigningPayload {
    message: String,
    recipient: String,
    nonce: String,
    #[serde(default)]
    state: Option<String>,
}

/// Compute the NEP-413 signing digest (sha256(prefix || borsh(payload))).
/// Returns a 32-byte Uint8Array.
#[wasm_bindgen]
pub fn threshold_ed25519_compute_nep413_signing_digest(
    payload: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let payload: Nep413SigningPayload = serde_wasm_bindgen::from_value(payload)
        .map_err(|e| JsValue::from_str(&format!("Invalid nep413 signingPayload: {e}")))?;

    let digest =
        signer_core::near_threshold_ed25519::compute_nep413_signing_digest_from_nonce_base64(
            &payload.message,
            &payload.recipient,
            payload.nonce.trim(),
            payload.state.as_deref(),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(digest.to_vec())
}
