use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::errors::js_core_err;

pub fn derive_secp256k1_keypair_from_prf_second(
    mut prf_second: Vec<u8>,
    near_account_id: String,
) -> Result<Vec<u8>, JsValue> {
    let result = signer_wasm_core::secp256k1::derive_secp256k1_keypair_from_prf_second(
        prf_second.as_slice(),
        near_account_id.as_str(),
    )
    .map_err(js_core_err);
    prf_second.zeroize();
    result
}

pub fn map_additive_share_to_threshold_signatures_share_2p(
    mut additive_share32: Vec<u8>,
    participant_id: u32,
) -> Result<Vec<u8>, JsValue> {
    let result =
        signer_wasm_core::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
            additive_share32.as_slice(),
            participant_id,
        )
        .map_err(js_core_err);
    additive_share32.zeroize();
    result
}

pub fn validate_secp256k1_public_key_33(public_key33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    signer_wasm_core::secp256k1::validate_secp256k1_public_key_33(public_key33.as_slice())
        .map_err(js_core_err)
}

pub fn add_secp256k1_public_keys_33(left33: Vec<u8>, right33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    signer_wasm_core::secp256k1::add_secp256k1_public_keys_33(
        left33.as_slice(),
        right33.as_slice(),
    )
    .map_err(js_core_err)
}

pub fn secp256k1_private_key_32_to_public_key_33(
    mut private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let result = signer_wasm_core::secp256k1::secp256k1_private_key_32_to_public_key_33(
        private_key32.as_slice(),
    )
    .map_err(js_core_err);
    private_key32.zeroize();
    result
}

pub fn secp256k1_public_key_33_to_ethereum_address_20(
    public_key33: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    signer_wasm_core::secp256k1::secp256k1_public_key_33_to_ethereum_address_20(
        public_key33.as_slice(),
    )
    .map_err(js_core_err)
}

pub fn sha256_bytes(mut input: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let out = Sha256::digest(input.as_slice()).to_vec();
    input.zeroize();
    Ok(out)
}
