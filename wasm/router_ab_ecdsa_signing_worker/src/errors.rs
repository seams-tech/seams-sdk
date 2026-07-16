use router_ab_ecdsa_derivation::{RouterAbEcdsaDerivationError, RouterAbEcdsaDerivationErrorCode};
use router_ab_ecdsa_presign::session::PresignSessionError;
use serde::Serialize;
use wasm_bindgen::prelude::JsValue;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningWorkerErrorWire {
    code: &'static str,
    core_code: &'static str,
    message: String,
}

fn js_error(code: &'static str, core_code: &'static str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&SigningWorkerErrorWire {
        code,
        core_code,
        message,
    })
    .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

pub fn js_derivation_err(error: RouterAbEcdsaDerivationError) -> JsValue {
    let (code, core_code) = match error.code {
        RouterAbEcdsaDerivationErrorCode::InvalidInput => ("SIGNER_INVALID_INPUT", "InvalidInput"),
        RouterAbEcdsaDerivationErrorCode::InvalidLength => {
            ("SIGNER_INVALID_LENGTH", "InvalidLength")
        }
        RouterAbEcdsaDerivationErrorCode::DecodeError => ("SIGNER_DECODE_ERROR", "DecodeError"),
        RouterAbEcdsaDerivationErrorCode::CryptoError => ("SIGNER_CRYPTO_ERROR", "CryptoError"),
        RouterAbEcdsaDerivationErrorCode::Utf8Error => ("SIGNER_UTF8_ERROR", "Utf8Error"),
        RouterAbEcdsaDerivationErrorCode::Internal => ("SIGNER_INTERNAL", "Internal"),
    };
    js_error(code, core_code, error.message)
}

pub fn js_invalid_input(message: impl core::fmt::Display) -> JsValue {
    js_error("SIGNER_INVALID_INPUT", "InvalidInput", message.to_string())
}

pub fn js_presign_err(error: PresignSessionError) -> JsValue {
    js_error("SIGNER_CRYPTO_ERROR", "CryptoError", error.to_string())
}
