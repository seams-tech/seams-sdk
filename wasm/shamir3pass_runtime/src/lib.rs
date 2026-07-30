use std::cell::RefCell;
use std::collections::HashMap;

use shamir_3_pass::{LockKeyPair, ModpGroup, Shamir3Pass};
use wasm_bindgen::prelude::*;

struct StoredLockKey {
    protocol: Shamir3Pass,
    key_pair: LockKeyPair,
}

#[derive(Default)]
struct LockKeyStore {
    next_handle: u32,
    keys: HashMap<u32, StoredLockKey>,
}

thread_local! {
    static LOCK_KEYS: RefCell<LockKeyStore> = RefCell::new(LockKeyStore::default());
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn protocol_from_group_id(group_id: &str) -> Result<Shamir3Pass, String> {
    let group = match group_id {
        "rfc2409-group1" => ModpGroup::Rfc2409Group1,
        "rfc2409-group2" => ModpGroup::Rfc2409Group2,
        "rfc3526-group14" => ModpGroup::Rfc3526Group14,
        _ => return Err(format!("Unsupported Shamir 3-pass group: {group_id}")),
    };
    Ok(Shamir3Pass::from_group(group))
}

fn insert_key(key: StoredLockKey) -> Result<u32, JsValue> {
    LOCK_KEYS.with(|store| {
        let mut store = store.borrow_mut();
        let handle = store
            .next_handle
            .checked_add(1)
            .ok_or_else(|| js_error("Shamir 3-pass key handle space exhausted"))?;
        store.next_handle = handle;
        store.keys.insert(handle, key);
        Ok(handle)
    })
}

fn with_key<T>(
    handle: u32,
    operation: impl FnOnce(&StoredLockKey) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    LOCK_KEYS.with(|store| {
        let store = store.borrow();
        let key = store
            .keys
            .get(&handle)
            .ok_or_else(|| js_error("Unknown Shamir 3-pass key handle"))?;
        operation(key)
    })
}

#[wasm_bindgen]
pub fn init_shamir3pass_runtime() {}

#[wasm_bindgen]
pub fn shamir3pass_generate_lock_key_handle(group_id: String) -> Result<u32, JsValue> {
    let protocol = protocol_from_group_id(group_id.trim()).map_err(js_error)?;
    let key_pair = protocol
        .generate_lock_key_pair()
        .map_err(|error| js_error(format!("Failed to generate lock key pair: {error}")))?;
    insert_key(StoredLockKey { protocol, key_pair })
}

#[wasm_bindgen]
pub fn shamir3pass_derive_lock_key_handle(
    group_id: String,
    root_secret: Vec<u8>,
    context: Vec<u8>,
) -> Result<u32, JsValue> {
    let protocol = protocol_from_group_id(group_id.trim()).map_err(js_error)?;
    let mut root_secret = root_secret;
    let mut context = context;
    let result = (|| {
        let root: [u8; 32] = root_secret
            .as_slice()
            .try_into()
            .map_err(|_| js_error("rootSecret must contain exactly 32 bytes"))?;
        let key_pair = protocol
            .derive_lock_key_pair(&root, context.as_slice())
            .map_err(|error| js_error(format!("Failed to derive lock key pair: {error}")))?;
        insert_key(StoredLockKey { protocol, key_pair })
    })();
    root_secret.fill(0);
    context.fill(0);
    result
}

#[wasm_bindgen]
pub fn shamir3pass_destroy_lock_key_handle(handle: u32) -> bool {
    LOCK_KEYS.with(|store| store.borrow_mut().keys.remove(&handle).is_some())
}

#[wasm_bindgen]
pub fn shamir3pass_add_lock(handle: u32, ciphertext_b64u: String) -> Result<String, JsValue> {
    with_key(handle, |stored| {
        let value = stored
            .protocol
            .element_from_b64u(ciphertext_b64u.trim())
            .map_err(|error| js_error(format!("Invalid ciphertextB64u: {error}")))?;
        Ok(stored.key_pair.add_lock(&stored.protocol, &value).to_b64u())
    })
}

#[wasm_bindgen]
pub fn shamir3pass_add_lock_bytes(handle: u32, ciphertext: Vec<u8>) -> Result<String, JsValue> {
    let mut ciphertext = ciphertext;
    let result = with_key(handle, |stored| {
        let value = stored
            .protocol
            .element_from_bytes(ciphertext.as_slice())
            .map_err(|error| js_error(format!("Invalid ciphertext: {error}")))?;
        Ok(stored.key_pair.add_lock(&stored.protocol, &value).to_b64u())
    });
    ciphertext.fill(0);
    result
}

#[wasm_bindgen]
pub fn shamir3pass_remove_lock(handle: u32, ciphertext_b64u: String) -> Result<String, JsValue> {
    with_key(handle, |stored| {
        let value = stored
            .protocol
            .element_from_b64u(ciphertext_b64u.trim())
            .map_err(|error| js_error(format!("Invalid ciphertextB64u: {error}")))?;
        Ok(stored
            .key_pair
            .remove_lock(&stored.protocol, &value)
            .to_b64u())
    })
}

#[wasm_bindgen]
pub fn shamir3pass_remove_lock_to_bytes(
    handle: u32,
    ciphertext_b64u: String,
) -> Result<Vec<u8>, JsValue> {
    with_key(handle, |stored| {
        let value = stored
            .protocol
            .element_from_b64u(ciphertext_b64u.trim())
            .map_err(|error| js_error(format!("Invalid ciphertextB64u: {error}")))?;
        Ok(stored
            .key_pair
            .remove_lock(&stored.protocol, &value)
            .to_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_group_ids_are_exhaustive() {
        for group_id in ["rfc2409-group1", "rfc2409-group2", "rfc3526-group14"] {
            assert_eq!(
                protocol_from_group_id(group_id).unwrap().group_id(),
                Some(group_id)
            );
        }
        assert!(protocol_from_group_id("custom").is_err());
    }

    #[test]
    fn upstream_key_pairs_complete_the_three_pass_flow() {
        let protocol = Shamir3Pass::default();
        let client = protocol.generate_lock_key_pair().unwrap();
        let server = protocol
            .derive_lock_key_pair(&[0x42; 32], b"seams/test/server-lock/v1")
            .unwrap();
        let value = protocol.element_from_bytes(&[0x02]).unwrap();

        let client_locked = client.add_lock(&protocol, &value);
        let double_locked = server.add_lock(&protocol, &client_locked);
        let server_locked = client.remove_lock(&protocol, &double_locked);
        let temporary_locked = client.add_lock(&protocol, &server_locked);
        let client_locked = server.remove_lock(&protocol, &temporary_locked);
        let recovered = client.remove_lock(&protocol, &client_locked);

        assert!(recovered == value);
    }
}
