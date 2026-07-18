use base64ct::{Base64UrlUnpadded, Encoding};
use js_sys::{Object, Reflect};
use serde::Serialize;
use signer_core::ecdsa_role_local_client::command::{
    extract_client_signing_share32_from_ready_state_blob, EcdsaRoleLocalReadyStateBlob,
};
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn prepare_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::PrepareEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::prepare_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn finalize_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::FinalizeEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::finalize_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn open_ecdsa_role_local_signing_share_v1(args: JsValue) -> Result<JsValue, JsValue> {
    let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
        state_blob: base64_url_decode(&get_required_string(&args, "stateBlobB64u")?)
            .map_err(|error| JsValue::from_str(&format!("Invalid stateBlobB64u: {error}")))?,
    };
    let signing_share32 = extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let output = Object::new();
    set_string(
        &output,
        "signingShare32B64u",
        &Base64UrlUnpadded::encode_string(&signing_share32),
    )?;
    Ok(output.into())
}

#[wasm_bindgen]
pub fn build_ecdsa_role_local_export_artifact_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::BuildEcdsaRoleLocalExportArtifactCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::build_ecdsa_role_local_export_artifact_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(input).map_err(|error| format!("Base64 decode error: {error}"))
}

fn get_required_string(value: &JsValue, field_name: &str) -> Result<String, JsValue> {
    let field = Reflect::get(value, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    field
        .as_string()
        .map(|string| string.trim().to_owned())
        .filter(|string| !string.is_empty())
        .ok_or_else(|| JsValue::from_str(&format!("Invalid args: missing {field_name}")))
}

fn set_string(target: &Object, field_name: &str, value: &str) -> Result<(), JsValue> {
    Reflect::set(
        target,
        &JsValue::from_str(field_name),
        &JsValue::from_str(value),
    )
    .map_err(|_| JsValue::from_str(&format!("Failed to serialize field {field_name}")))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerWorkerErrorWire {
    code: String,
    core_code: String,
    message: String,
}

fn command_core_code_name(code: SignerCoreErrorCode) -> &'static str {
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

fn command_host_code(code: SignerCoreErrorCode) -> &'static str {
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

fn js_command_error_with_codes(code: &str, core_code: &str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&SignerWorkerErrorWire {
        code: code.to_owned(),
        core_code: core_code.to_owned(),
        message,
    })
    .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

fn js_signer_core_err(error: SignerCoreError) -> JsValue {
    js_command_error_with_codes(
        command_host_code(error.code),
        command_core_code_name(error.code),
        error.message,
    )
}

fn js_command_invalid_input_err(error: impl core::fmt::Display) -> JsValue {
    js_command_error_with_codes("SIGNER_INVALID_INPUT", "InvalidInput", error.to_string())
}
