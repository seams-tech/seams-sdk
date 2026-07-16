#![forbid(unsafe_code)]

use serde::Serialize;
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebauthnErrorWire {
    code: &'static str,
    core_code: &'static str,
    message: String,
}

fn host_code(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "SIGNER_INVALID_INPUT",
        SignerCoreErrorCode::InvalidLength => "SIGNER_INVALID_LENGTH",
        SignerCoreErrorCode::DecodeError => "SIGNER_DECODE_ERROR",
        SignerCoreErrorCode::EncodeError => "SIGNER_ENCODE_ERROR",
        SignerCoreErrorCode::HkdfError => "SIGNER_KDF_ERROR",
        SignerCoreErrorCode::CryptoError => "SIGNER_CRYPTO_ERROR",
        SignerCoreErrorCode::Utf8Error => "SIGNER_UTF8_ERROR",
        SignerCoreErrorCode::Unsupported => "SIGNER_UNSUPPORTED",
        SignerCoreErrorCode::Internal => "SIGNER_INTERNAL",
    }
}

fn core_code(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "InvalidInput",
        SignerCoreErrorCode::InvalidLength => "InvalidLength",
        SignerCoreErrorCode::DecodeError => "DecodeError",
        SignerCoreErrorCode::EncodeError => "EncodeError",
        SignerCoreErrorCode::HkdfError => "HkdfError",
        SignerCoreErrorCode::CryptoError => "CryptoError",
        SignerCoreErrorCode::Utf8Error => "Utf8Error",
        SignerCoreErrorCode::Unsupported => "Unsupported",
        SignerCoreErrorCode::Internal => "Internal",
    }
}

fn js_core_error(error: SignerCoreError) -> JsValue {
    let wire = WebauthnErrorWire {
        code: host_code(error.code),
        core_code: core_code(error.code),
        message: error.message,
    };
    serde_wasm_bindgen::to_value(&wire)
        .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
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
    signer_core::webauthn_p256::build_webauthn_p256_signature(
        challenge32,
        authenticator_data,
        client_data_json,
        signature_der,
        pub_key_x32,
        pub_key_y32,
    )
    .map_err(js_core_error)
}

#[wasm_bindgen]
pub fn decode_cose_p256_public_key(cose_public_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    signer_core::webauthn_p256::decode_cose_p256_public_key(&cose_public_key)
        .map(|public_key| public_key.to_vec())
        .map_err(js_core_error)
}
