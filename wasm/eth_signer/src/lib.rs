mod codec;
mod derive;
mod ecdsa_hss;
mod eip1559;
mod errors;
mod secp256k1_sign;
mod threshold;
mod webauthn_p256;

use wasm_bindgen::prelude::*;

pub use threshold::ThresholdEcdsaPresignSession;

#[wasm_bindgen]
pub fn init_eth_signer() {
    // no-op; reserved for future logger initialization
}

#[wasm_bindgen]
pub fn ecdsa_hss_derive_canonical_secret(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::ecdsa_hss_derive_canonical_secret(payload)
}

#[wasm_bindgen]
pub fn ecdsa_hss_derive_additive_shares(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::ecdsa_hss_derive_additive_shares(payload)
}

#[wasm_bindgen]
pub fn ecdsa_hss_bootstrap_non_export_sign(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::ecdsa_hss_bootstrap_non_export_sign(payload)
}

#[wasm_bindgen]
pub fn ecdsa_hss_bootstrap_non_export_sign_full(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::ecdsa_hss_bootstrap_non_export_sign_full(payload)
}

#[wasm_bindgen]
pub fn ecdsa_hss_sign_non_export(payload: JsValue) -> Result<Vec<u8>, JsValue> {
    ecdsa_hss::ecdsa_hss_sign_non_export(payload)
}

#[wasm_bindgen]
pub fn ecdsa_hss_sign_non_export_profiled(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::ecdsa_hss_sign_non_export_profiled(payload)
}

#[wasm_bindgen]
pub fn ecdsa_hss_explicit_export(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::ecdsa_hss_explicit_export(payload)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_prepare_server_session(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::threshold_ecdsa_hss_prepare_server_session(payload)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_prepare_server_ceremony(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::threshold_ecdsa_hss_prepare_server_ceremony(payload)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_finalize_server_report(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::threshold_ecdsa_hss_finalize_server_report(payload)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_open_server_output(payload: JsValue) -> Result<JsValue, JsValue> {
    ecdsa_hss::threshold_ecdsa_hss_open_server_output(payload)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_compute_signature_share(
    participant_ids: Vec<u32>,
    me: u32,
    public_key_sec1: Vec<u8>,
    presign_big_r_sec1: Vec<u8>,
    presign_k_share32: Vec<u8>,
    presign_sigma_share32: Vec<u8>,
    digest32: Vec<u8>,
    entropy32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    threshold::threshold_ecdsa_compute_signature_share(
        participant_ids,
        me,
        public_key_sec1,
        presign_big_r_sec1,
        presign_k_share32,
        presign_sigma_share32,
        digest32,
        entropy32,
    )
}

#[wasm_bindgen]
pub fn threshold_ecdsa_finalize_signature(
    participant_ids: Vec<u32>,
    relayer_id: u32,
    public_key_sec1: Vec<u8>,
    presign_big_r_sec1: Vec<u8>,
    relayer_k_share32: Vec<u8>,
    relayer_sigma_share32: Vec<u8>,
    digest32: Vec<u8>,
    entropy32: Vec<u8>,
    client_signature_share32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    threshold::threshold_ecdsa_finalize_signature(
        participant_ids,
        relayer_id,
        public_key_sec1,
        presign_big_r_sec1,
        relayer_k_share32,
        relayer_sigma_share32,
        digest32,
        entropy32,
        client_signature_share32,
    )
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
pub fn derive_secp256k1_keypair_from_prf_second(
    prf_second: Vec<u8>,
    near_account_id: String,
) -> Result<Vec<u8>, JsValue> {
    derive::derive_secp256k1_keypair_from_prf_second(prf_second, near_account_id)
}

#[wasm_bindgen]
pub fn map_additive_share_to_threshold_signatures_share_2p(
    additive_share32: Vec<u8>,
    participant_id: u32,
) -> Result<Vec<u8>, JsValue> {
    derive::map_additive_share_to_threshold_signatures_share_2p(additive_share32, participant_id)
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
pub fn derive_threshold_secp256k1_relayer_share(
    master_secret: Vec<u8>,
    relayer_key_id: String,
) -> Result<Vec<u8>, JsValue> {
    derive::derive_threshold_secp256k1_relayer_share(master_secret, relayer_key_id)
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
