use crate::actions::ActionParams;
use crate::encoders::base64_url_encode;
use crate::handlers::handle_generate_ephemeral_near_keypair::{
    handle_generate_ephemeral_near_keypair, GenerateEphemeralNearKeypairRequest,
};
use crate::handlers::handle_sign_transaction_with_keypair::{
    deserialize_actions_flexible, handle_sign_transaction_with_keypair,
    SignTransactionWithKeyPairRequest,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const EPHEMERAL_NEAR_KEYPAIR_HANDLE_USES: u32 = 1;
const EPHEMERAL_NEAR_KEYPAIR_MAX_TTL_MS: u64 = 15 * 60 * 1000;

thread_local! {
    static EPHEMERAL_NEAR_KEYPAIR_BY_HANDLE: RefCell<BTreeMap<String, StoredEphemeralNearKeypair>> =
        RefCell::new(BTreeMap::new());
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateEphemeralNearKeypairHandleRequest {
    expires_at_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateEphemeralNearKeypairHandleResult {
    public_key: String,
    key_handle: String,
    expires_at_ms: u64,
    remaining_uses: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignTransactionWithEphemeralNearKeypairHandleRequest {
    key_handle: String,
    signer_account_id: String,
    receiver_id: String,
    nonce: String,
    block_hash: String,
    #[serde(deserialize_with = "deserialize_actions_flexible")]
    actions: Vec<ActionParams>,
}

struct StoredEphemeralNearKeypair {
    private_key: String,
    expires_at_ms: u64,
    remaining_uses: u32,
}

impl Drop for StoredEphemeralNearKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[wasm_bindgen]
pub async fn near_ephemeral_keypair_create_handle(args: JsValue) -> Result<JsValue, JsValue> {
    let request: CreateEphemeralNearKeypairHandleRequest =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid ephemeral keypair args: {e}")))?;
    let expires_at_ms = require_bounded_expires_at_ms(request.expires_at_ms)?;
    prune_expired_ephemeral_keypairs();

    let keypair = handle_generate_ephemeral_near_keypair(GenerateEphemeralNearKeypairRequest {})
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    let key_handle = random_ephemeral_keypair_handle()?;
    let stored = StoredEphemeralNearKeypair {
        private_key: keypair.private_key,
        expires_at_ms,
        remaining_uses: EPHEMERAL_NEAR_KEYPAIR_HANDLE_USES,
    };
    EPHEMERAL_NEAR_KEYPAIR_BY_HANDLE.with(|store| {
        store.borrow_mut().insert(key_handle.clone(), stored);
    });

    serde_wasm_bindgen::to_value(&CreateEphemeralNearKeypairHandleResult {
        public_key: keypair.public_key,
        key_handle,
        expires_at_ms,
        remaining_uses: EPHEMERAL_NEAR_KEYPAIR_HANDLE_USES,
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize ephemeral keypair handle: {e}")))
}

#[wasm_bindgen]
pub async fn near_ephemeral_keypair_sign_with_handle(args: JsValue) -> Result<JsValue, JsValue> {
    let request: SignTransactionWithEphemeralNearKeypairHandleRequest =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid ephemeral signing args: {e}")))?;
    let near_private_key = take_ephemeral_near_private_key(&request.key_handle)?;
    let signing_request = SignTransactionWithKeyPairRequest {
        near_private_key,
        signer_account_id: require_non_empty(request.signer_account_id, "signerAccountId")?,
        receiver_id: require_non_empty(request.receiver_id, "receiverId")?,
        nonce: require_non_empty(request.nonce, "nonce")?,
        block_hash: require_non_empty(request.block_hash, "blockHash")?,
        actions: request.actions,
    };
    let result = handle_sign_transaction_with_keypair(signing_request)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize signed transaction: {e}")))
}

fn take_ephemeral_near_private_key(key_handle: &str) -> Result<String, JsValue> {
    let key_handle = require_non_empty(key_handle.to_string(), "keyHandle")?;
    prune_expired_ephemeral_keypairs();
    EPHEMERAL_NEAR_KEYPAIR_BY_HANDLE.with(|store| {
        let maybe_stored = store.borrow_mut().remove(&key_handle);
        match maybe_stored {
            Some(mut stored) => {
                if stored.expires_at_ms <= now_ms() || stored.remaining_uses == 0 {
                    return Err(JsValue::from_str("Ephemeral NEAR keypair handle is expired"));
                }
                Ok(std::mem::take(&mut stored.private_key))
            }
            None => Err(JsValue::from_str(
                "Ephemeral NEAR keypair handle is missing or already used",
            )),
        }
    })
}

fn require_bounded_expires_at_ms(expires_at_ms: u64) -> Result<u64, JsValue> {
    let now = now_ms();
    if expires_at_ms <= now {
        return Err(JsValue::from_str("expiresAtMs must be in the future"));
    }
    if expires_at_ms > now.saturating_add(EPHEMERAL_NEAR_KEYPAIR_MAX_TTL_MS) {
        return Err(JsValue::from_str("expiresAtMs is too far in the future"));
    }
    Ok(expires_at_ms)
}

fn prune_expired_ephemeral_keypairs() {
    let now = now_ms();
    EPHEMERAL_NEAR_KEYPAIR_BY_HANDLE.with(|store| {
        store
            .borrow_mut()
            .retain(|_, stored| stored.expires_at_ms > now && stored.remaining_uses > 0);
    });
}

fn require_non_empty(value: String, field_name: &str) -> Result<String, JsValue> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(JsValue::from_str(&format!("{field_name} is required")));
    }
    Ok(trimmed)
}

fn random_ephemeral_keypair_handle() -> Result<String, JsValue> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate key handle: {e}")))?;
    Ok(format!("near-ephemeral-keypair-{}", base64_url_encode(&bytes)))
}

fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now().max(0.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }
}
