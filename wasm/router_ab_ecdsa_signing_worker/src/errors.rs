use router_ab_ecdsa_derivation::{RouterAbEcdsaDerivationError, RouterAbEcdsaDerivationErrorCode};
use serde::Serialize;
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::JsValue;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningWorkerErrorWire {
    code: String,
    core_code: String,
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

fn core_code_name(code: SignerCoreErrorCode) -> &'static str {
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

fn derivation_core_code(code: RouterAbEcdsaDerivationErrorCode) -> SignerCoreErrorCode {
    match code {
        RouterAbEcdsaDerivationErrorCode::InvalidInput => SignerCoreErrorCode::InvalidInput,
        RouterAbEcdsaDerivationErrorCode::InvalidLength => SignerCoreErrorCode::InvalidLength,
        RouterAbEcdsaDerivationErrorCode::DecodeError => SignerCoreErrorCode::DecodeError,
        RouterAbEcdsaDerivationErrorCode::CryptoError => SignerCoreErrorCode::CryptoError,
        RouterAbEcdsaDerivationErrorCode::Utf8Error => SignerCoreErrorCode::Utf8Error,
        RouterAbEcdsaDerivationErrorCode::Internal => SignerCoreErrorCode::Internal,
    }
}

fn js_error(code: SignerCoreErrorCode, message: String) -> JsValue {
    let wire = SigningWorkerErrorWire {
        code: host_code(code).to_string(),
        core_code: core_code_name(code).to_string(),
        message,
    };
    serde_wasm_bindgen::to_value(&wire)
        .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

pub fn js_core_err(error: SignerCoreError) -> JsValue {
    js_error(error.code, error.message)
}

pub fn js_derivation_err(error: RouterAbEcdsaDerivationError) -> JsValue {
    js_error(derivation_core_code(error.code), error.message)
}

pub fn js_invalid_input(message: impl core::fmt::Display) -> JsValue {
    js_error(SignerCoreErrorCode::InvalidInput, message.to_string())
}
