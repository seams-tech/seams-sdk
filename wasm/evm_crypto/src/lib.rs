mod codec;
mod cose;
mod derive;
mod eip1559;
mod errors;
mod secp256k1_sign;
mod webauthn_p256;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_evm_crypto() {
    // no-op; reserved for future logger initialization
}

#[wasm_bindgen]
pub fn compute_eip1559_tx_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    eip1559::compute_eip1559_tx_hash(tx)
}

#[wasm_bindgen]
pub fn encode_eip1559_signed_tx_from_signature65(
    tx: JsValue,
    signature65: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    eip1559::encode_eip1559_signed_tx_from_signature65(tx, signature65)
}

#[wasm_bindgen]
pub fn sign_secp256k1_recoverable(
    digest32: Vec<u8>,
    private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    secp256k1_sign::sign_secp256k1_recoverable(digest32, private_key32)
}

#[wasm_bindgen]
pub fn verify_secp256k1_recoverable_signature_against_public_key_33(
    digest32: Vec<u8>,
    signature65: Vec<u8>,
    public_key33: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    secp256k1_sign::verify_secp256k1_recoverable_signature_against_public_key_33(
        digest32,
        signature65,
        public_key33,
    )
}

#[wasm_bindgen]
pub fn derive_secp256k1_keypair_from_prf_second(
    prf_second: Vec<u8>,
    near_account_id: String,
) -> Result<Vec<u8>, JsValue> {
    derive::derive_secp256k1_keypair_from_prf_second(prf_second, near_account_id)
}

#[wasm_bindgen]
pub fn validate_secp256k1_public_key_33(public_key33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    derive::validate_secp256k1_public_key_33(public_key33)
}

#[wasm_bindgen]
pub fn add_secp256k1_public_keys_33(left33: Vec<u8>, right33: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    derive::add_secp256k1_public_keys_33(left33, right33)
}

#[wasm_bindgen]
pub fn secp256k1_private_key_32_to_public_key_33(
    private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    derive::secp256k1_private_key_32_to_public_key_33(private_key32)
}

#[wasm_bindgen]
pub fn secp256k1_public_key_33_to_ethereum_address_20(
    public_key33: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    derive::secp256k1_public_key_33_to_ethereum_address_20(public_key33)
}

#[wasm_bindgen]
pub fn sha256_bytes(input: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    derive::sha256_bytes(input)
}

#[wasm_bindgen]
pub fn build_webauthn_p256_signature(
    challenge32: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
    pub_key_x32: Vec<u8>,
    pub_key_y32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    webauthn_p256::build_webauthn_p256_signature(
        challenge32,
        authenticator_data,
        client_data_json,
        signature_der,
        pub_key_x32,
        pub_key_y32,
    )
}

#[wasm_bindgen]
pub fn decode_cose_p256_public_key(cose_public_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    cose::decode_cose_p256_public_key(cose_public_key)
}
