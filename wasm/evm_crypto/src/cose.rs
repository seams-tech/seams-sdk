use wasm_bindgen::prelude::*;

pub fn decode_cose_p256_public_key(cose_public_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    signer_core::webauthn_p256::decode_cose_p256_public_key(&cose_public_key)
        .map(|public_key| public_key.to_vec())
        .map_err(crate::errors::js_core_err)
}
