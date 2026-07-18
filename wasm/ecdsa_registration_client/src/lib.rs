use base64ct::{Base64UrlUnpadded, Encoding};
use js_sys::{Object, Reflect};
use router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext;
use serde::{Deserialize, Serialize};
use signer_core::commands::{
    Base64UrlEncodingV1, EcdsaClientBootstrapAlgorithmV1, EcdsaClientBootstrapContextV1,
    EcdsaClientBootstrapFactsV1, EcdsaClientBootstrapParticipantsV1, EcdsaPreparePublicFactsV1,
    EcdsaRoleLocalPendingStateBlobV1, PendingStateBlobKindV1, PrepareEcdsaClientBootstrapOutputV1,
    Secp256k1CurveNameV1, SignerCoreProducerV1,
};
use signer_core::ecdsa_role_local_client::command::{
    extract_client_signing_share32_from_ready_state_blob, prepare_ecdsa_client_bootstrap,
    EcdsaRoleLocalReadyStateBlob, PrepareEcdsaClientBootstrapCommand,
};
use signer_core::error::{CoreResult, SignerCoreError, SignerCoreErrorCode};
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
pub fn prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
    input_json: &str,
) -> Result<String, JsValue> {
    let command: PrepareResolvedEmailOtpRootCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = prepare_resolved_email_otp_root_command_v1(command).map_err(js_signer_core_err)?;
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
        &base64_url_encode(&signing_share32),
    )?;
    Ok(output.into())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrepareResolvedEmailOtpRootCommandV1 {
    kind: PrepareResolvedEmailOtpRootCommandKindV1,
    algorithm: EcdsaClientBootstrapAlgorithmV1,
    context: EcdsaClientBootstrapContextV1,
    participants: EcdsaClientBootstrapParticipantsV1,
    resolved_email_otp_root_share32_b64u: String,
}

#[derive(Debug, Deserialize)]
enum PrepareResolvedEmailOtpRootCommandKindV1 {
    #[serde(rename = "prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1")]
    PrepareEcdsaClientBootstrapFromResolvedEmailOtpRootV1,
}

fn prepare_resolved_email_otp_root_command_v1(
    command: PrepareResolvedEmailOtpRootCommandV1,
) -> CoreResult<PrepareEcdsaClientBootstrapOutputV1> {
    match command.kind {
        PrepareResolvedEmailOtpRootCommandKindV1::PrepareEcdsaClientBootstrapFromResolvedEmailOtpRootV1 => {}
    }
    match command.algorithm {
        EcdsaClientBootstrapAlgorithmV1::RouterAbEcdsaDerivationSecp256k1RoleLocalV1 => {}
    }
    validate_resolved_email_otp_root_participants(&command.participants)?;

    let context = RouterAbEcdsaDerivationStableKeyContext::new(decode_fixed_32_core(
        &command.context.application_binding_digest_b64u,
        "context.applicationBindingDigestB64u",
    )?);
    context
        .validate()
        .map_err(|error| SignerCoreError::invalid_input(error.to_string()))?;

    let mut client_root_share32 = decode_fixed_32_core(
        &command.resolved_email_otp_root_share32_b64u,
        "resolvedEmailOtpRootShare32B64u",
    )?;
    let prepared_result = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
        context,
        client_root_share32,
    });
    client_root_share32.fill(0);
    let prepared = prepared_result?;

    Ok(PrepareEcdsaClientBootstrapOutputV1 {
        pending_state_blob: EcdsaRoleLocalPendingStateBlobV1 {
            kind: PendingStateBlobKindV1::EcdsaRoleLocalPendingStateBlobV1,
            curve: Secp256k1CurveNameV1::Secp256k1,
            encoding: Base64UrlEncodingV1::Base64url,
            producer: SignerCoreProducerV1::SignerCore,
            state_blob_b64u: base64_url_encode(&prepared.pending_state_blob.state_blob),
        },
        client_bootstrap: EcdsaClientBootstrapFactsV1 {
            context_binding32_b64u: base64_url_encode(&prepared.client_bootstrap.context_binding32),
            derivation_client_share_public_key33_b64u: base64_url_encode(
                &prepared
                    .client_bootstrap
                    .derivation_client_share_public_key33,
            ),
            client_share_retry_counter: prepared.client_bootstrap.client_share_retry_counter,
            participant_id: prepared.client_bootstrap.participant_id,
        },
        public_facts: EcdsaPreparePublicFactsV1 {
            derivation_client_share_public_key33_b64u: base64_url_encode(
                &prepared.public_facts.derivation_client_share_public_key33,
            ),
            client_verifying_share_b64u: base64_url_encode(
                &prepared.public_facts.client_verifying_share33,
            ),
        },
    })
}

fn validate_resolved_email_otp_root_participants(
    participants: &EcdsaClientBootstrapParticipantsV1,
) -> CoreResult<()> {
    if participants.client_participant_id != 1 {
        return Err(SignerCoreError::invalid_input(
            "participants.clientParticipantId must be 1",
        ));
    }
    if participants.relayer_participant_id != 2 {
        return Err(SignerCoreError::invalid_input(
            "participants.relayerParticipantId must be 2",
        ));
    }
    if participants.participant_ids != [1, 2] {
        return Err(SignerCoreError::invalid_input(
            "participants.participantIds must be [1, 2]",
        ));
    }
    Ok(())
}

fn decode_fixed_32_core(value: &str, field_name: &str) -> CoreResult<[u8; 32]> {
    let mut decoded = base64_url_decode(value)
        .map_err(|error| SignerCoreError::decode_error(format!("{field_name}: {error}")))?;
    if decoded.len() != 32 {
        let len = decoded.len();
        decoded.fill(0);
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must decode to 32 bytes (got {len})"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    decoded.fill(0);
    Ok(out)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(input).map_err(|error| format!("Base64 decode error: {error}"))
}

fn base64_url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
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
