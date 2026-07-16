#![forbid(unsafe_code)]

use serde::Serialize;
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CodecErrorWire {
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
    let wire = CodecErrorWire {
        code: host_code(error.code),
        core_code: core_code(error.code),
        message: error.message,
    };
    serde_wasm_bindgen::to_value(&wire)
        .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

fn parse_transaction(tx: JsValue) -> Result<signer_core::eip1559::Eip1559Tx, JsValue> {
    serde_wasm_bindgen::from_value(tx).map_err(|error| {
        js_core_error(SignerCoreError::invalid_input(format!(
            "invalid EIP-1559 transaction: {error}",
        )))
    })
}

#[wasm_bindgen]
pub fn compute_eip1559_tx_hash(tx: JsValue) -> Result<Vec<u8>, JsValue> {
    signer_core::eip1559::compute_eip1559_tx_hash(&parse_transaction(tx)?).map_err(js_core_error)
}

#[wasm_bindgen]
pub fn encode_eip1559_signed_tx_from_signature65(
    tx: JsValue,
    signature65: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    signer_core::eip1559::encode_eip1559_signed_tx_from_signature65(
        &parse_transaction(tx)?,
        &signature65,
    )
    .map_err(js_core_error)
}
