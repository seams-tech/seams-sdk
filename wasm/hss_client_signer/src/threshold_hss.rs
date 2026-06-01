use crate::encoders::{base64_url_decode, base64_url_encode};
use crate::js::{
    get_required_string, get_required_u16_vec, get_required_u32, object, set_string, set_u16_vec,
    set_u32,
};
use ecdsa_hss::EcdsaHssStableKeyContext;
use ed25519_hss::{
    client::{
        output_mask::{
            derive_client_output_mask, ClientOutputMaskContext, ClientOutputMaskOperation,
        },
        ClientDriverState, ClientOtState,
    },
    protocol::prepare_prime_order_succinct_hss_client,
    shared::CanonicalContext,
    wire::{RoleSeparatedServerInputDeliveryPacket, WireMessage},
};
use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use signer_core::commands::{
    Base64UrlEncodingV1, EcdsaClientBootstrapAlgorithmV1, EcdsaClientBootstrapContextV1,
    EcdsaClientBootstrapFactsV1, EcdsaClientBootstrapKeyPurposeV1,
    EcdsaClientBootstrapKeyVersionV1, EcdsaClientBootstrapParticipantsV1,
    EcdsaPreparePublicFactsV1, EcdsaRoleLocalPendingStateBlobV1, PendingStateBlobKindV1,
    PrepareEcdsaClientBootstrapOutputV1, Secp256k1CurveNameV1, SignerCoreProducerV1,
    ThresholdEcdsaChainTargetV1,
};
use signer_core::error::{CoreResult, SignerCoreError, SignerCoreErrorCode};
use signer_core::threshold_ecdsa_hss::{
    extract_client_signing_share32_from_ready_state_blob, finalize_ecdsa_client_bootstrap,
    prepare_ecdsa_client_bootstrap, EcdsaRoleLocalReadyStateBlob,
    FinalizeEcdsaClientBootstrapCommand, PrepareEcdsaClientBootstrapCommand,
    RelayerPublicIdentityInput,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_session(args: JsValue) -> Result<JsValue, JsValue> {
    let context = canonical_context_from_js(&args)?;
    let evaluator_driver_state = prepare_prime_order_succinct_hss_client(&context)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(&out, "signingRootId", &context.org_id)?;
    set_string(&out, "nearAccountId", &context.account_id)?;
    set_string(&out, "keyPurpose", &context.key_purpose)?;
    set_string(&out, "keyVersion", &context.key_version)?;
    set_u16_vec(&out, "participantIds", &context.participant_ids)?;
    set_u32(&out, "derivationVersion", context.derivation_version)?;
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&evaluator_driver_state.evaluator_session.context_binding),
    )?;
    set_string(
        &out,
        "evaluatorDriverStateB64u",
        &encode_state_blob(&evaluator_driver_state, "evaluator state")
            .map_err(|e| JsValue::from_str(&e))?,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_derive_client_output_mask(args: JsValue) -> Result<JsValue, JsValue> {
    let client_recoverable_secret = decode_fixed_32(
        &get_required_string(&args, "clientRecoverableSecretB64u")?,
        "clientRecoverableSecretB64u",
    )?;
    let context = ClientOutputMaskContext {
        canonical_context: canonical_context_from_js(&args)?,
        context_binding: decode_fixed_32(
            &get_required_string(&args, "contextBindingB64u")?,
            "contextBindingB64u",
        )?,
        operation: get_required_string(&args, "operation")?
            .parse::<ClientOutputMaskOperation>()
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        relayer_key_id: get_required_string(&args, "relayerKeyId")?,
    };
    let client_output_mask = derive_client_output_mask(client_recoverable_secret, &context)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "clientOutputMaskB64u",
        &base64_url_encode(&client_output_mask),
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_client_request(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let client_ot_offer_message_b64u = get_required_string(&args, "clientOtOfferMessageB64u")?;
    let y_client_b64u = get_required_string(&args, "yClientB64u")?;
    let tau_client_b64u = get_required_string(&args, "tauClientB64u")?;

    let evaluator_state: ClientDriverState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let (_runtime, evaluator_session) = evaluator_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let offer_message =
        decode_wire_message(&client_ot_offer_message_b64u, "clientOtOfferMessageB64u")?;
    let y_client = decode_fixed_32(&y_client_b64u, "yClientB64u")?;
    let tau_client = decode_fixed_32(&tau_client_b64u, "tauClientB64u")?;
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(&offer_message, y_client, tau_client)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "clientRequestMessageB64u",
        &encode_wire_message(&client_request_message),
    )?;
    set_string(
        &out,
        "evaluatorOtStateB64u",
        &encode_state_blob(&evaluator_ot_state, "evaluator OT state")
            .map_err(|e| JsValue::from_str(&e))?,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let client_request_message_b64u = get_required_string(&args, "clientRequestMessageB64u")?;
    let evaluator_ot_state_b64u = get_required_string(&args, "evaluatorOtStateB64u")?;
    let server_input_delivery_b64u = get_required_string(&args, "serverInputDeliveryB64u")?;
    let client_output_mask = decode_fixed_32(
        &get_required_string(&args, "clientOutputMaskB64u")?,
        "clientOutputMaskB64u",
    )?;

    let evaluator_state: ClientDriverState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let evaluator_ot_state: ClientOtState =
        decode_state_blob(&evaluator_ot_state_b64u, "evaluatorOtStateB64u")?;
    let server_input_delivery: RoleSeparatedServerInputDeliveryPacket =
        decode_state_blob(&server_input_delivery_b64u, "serverInputDeliveryB64u")?;
    let client_request_message =
        decode_wire_message(&client_request_message_b64u, "clientRequestMessageB64u")?;
    let (runtime, evaluator_session) = evaluator_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let artifact = evaluator_session
        .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_message(
            &runtime,
            &client_request_message,
            &evaluator_ot_state,
            &server_input_delivery,
            client_output_mask,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&evaluator_state.evaluator_session.context_binding),
    )?;
    set_string(
        &out,
        "stagedEvaluatorArtifactB64u",
        &encode_state_blob(&artifact, "staged evaluator artifact")
            .map_err(|e| JsValue::from_str(&e))?,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_open_client_output(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let client_output_message_b64u = get_required_string(&args, "clientOutputMessageB64u")?;
    let client_output_mask = decode_fixed_32(
        &get_required_string(&args, "clientOutputMaskB64u")?,
        "clientOutputMaskB64u",
    )?;
    let evaluator_state: ClientDriverState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let (_runtime, evaluator_session) = evaluator_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client_output_message =
        decode_wire_message(&client_output_message_b64u, "clientOutputMessageB64u")?;
    let opener = evaluator_session.client_output_opener();
    let x_client_base = opener
        .open_masked(&client_output_message, client_output_mask)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&evaluator_state.evaluator_session.context_binding),
    )?;
    set_string(&out, "xClientBaseB64u", &base64_url_encode(&x_client_base))?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_open_seed_output(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let seed_output_message_b64u = get_required_string(&args, "seedOutputMessageB64u")?;
    let evaluator_state: ClientDriverState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let (_runtime, evaluator_session) = evaluator_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed_output_message =
        decode_wire_message(&seed_output_message_b64u, "seedOutputMessageB64u")?;
    let canonical_seed = evaluator_session
        .seed_output_opener()
        .open(&seed_output_message)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&evaluator_state.evaluator_session.context_binding),
    )?;
    set_string(
        &out,
        "canonicalSeedB64u",
        &base64_url_encode(&canonical_seed),
    )?;
    Ok(out.into())
}

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
pub fn build_ecdsa_role_local_export_artifact_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::BuildEcdsaRoleLocalExportArtifactCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::build_ecdsa_role_local_export_artifact_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_role_local_finalize_client_bootstrap(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let pending_state_blob = signer_core::threshold_ecdsa_hss::EcdsaRoleLocalPendingStateBlob {
        state_blob: base64_url_decode(&get_required_string(&args, "pendingStateBlobB64u")?)
            .map_err(|e| JsValue::from_str(&format!("Invalid pendingStateBlobB64u: {e}")))?,
    };
    let finalized = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
        pending_state_blob,
        relayer_public_identity: RelayerPublicIdentityInput {
            relayer_key_id: get_required_string(&args, "relayerKeyId")?,
            relayer_public_key33: decode_fixed_33(
                &get_required_string(&args, "relayerPublicKey33B64u")?,
                "relayerPublicKey33B64u",
            )?,
            group_public_key33: decode_fixed_33(
                &get_required_string(&args, "groupPublicKey33B64u")?,
                "groupPublicKey33B64u",
            )?,
            ethereum_address20: decode_ethereum_address20(&get_required_string(
                &args,
                "ethereumAddress",
            )?)?,
            relayer_share_retry_counter: get_optional_u32(&args, "relayerShareRetryCounter")?
                .unwrap_or(0),
        },
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "stateBlobB64u",
        &base64_url_encode(&finalized.ready_state_blob.state_blob),
    )?;
    set_string(
        &out,
        "contextBinding32B64u",
        &base64_url_encode(&finalized.public_facts.context_binding32),
    )?;
    set_string(
        &out,
        "hssClientSharePublicKey33B64u",
        &base64_url_encode(&finalized.public_facts.hss_client_share_public_key33),
    )?;
    set_string(
        &out,
        "clientVerifyingShareB64u",
        &base64_url_encode(&finalized.public_facts.client_verifying_share33),
    )?;
    set_string(
        &out,
        "relayerPublicKey33B64u",
        &base64_url_encode(&finalized.public_facts.relayer_public_key33),
    )?;
    set_string(
        &out,
        "groupPublicKey33B64u",
        &base64_url_encode(&finalized.public_facts.group_public_key33),
    )?;
    set_string(
        &out,
        "ethereumAddress",
        &hex_prefixed(&finalized.public_facts.ethereum_address20),
    )?;
    set_u32(
        &out,
        "clientShareRetryCounter",
        finalized.public_facts.client_share_retry_counter,
    )?;
    set_u32(
        &out,
        "relayerShareRetryCounter",
        finalized.public_facts.relayer_share_retry_counter,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn open_ecdsa_role_local_signing_share_v1(args: JsValue) -> Result<JsValue, JsValue> {
    let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
        state_blob: base64_url_decode(&get_required_string(&args, "stateBlobB64u")?)
            .map_err(|e| JsValue::from_str(&format!("Invalid stateBlobB64u: {e}")))?,
    };
    let signing_share32 = extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let out = object();
    set_string(
        &out,
        "signingShare32B64u",
        &base64_url_encode(&signing_share32),
    )?;
    Ok(out.into())
}

fn canonical_context_from_js(args: &JsValue) -> Result<CanonicalContext, JsValue> {
    Ok(CanonicalContext {
        org_id: get_required_string(args, "signingRootId")?,
        account_id: get_required_string(args, "nearAccountId")?,
        key_purpose: get_required_string(args, "keyPurpose")?,
        key_version: get_required_string(args, "keyVersion")?,
        participant_ids: get_required_u16_vec(args, "participantIds")?,
        derivation_version: get_required_u32(args, "derivationVersion")?,
    })
}

fn decode_state_blob<T: for<'de> Deserialize<'de>>(
    value: &str,
    field_name: &str,
) -> Result<T, JsValue> {
    let bytes = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    bincode::deserialize::<T>(&bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))
}

fn encode_state_blob<T: Serialize>(value: &T, field_name: &str) -> Result<String, String> {
    let bytes =
        bincode::serialize(value).map_err(|e| format!("Failed to serialize {field_name}: {e}"))?;
    Ok(base64_url_encode(&bytes))
}

fn decode_fixed_32(value: &str, field_name: &str) -> Result<[u8; 32], JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field_name} must decode to 32 bytes")))
}

fn decode_fixed_33(value: &str, field_name: &str) -> Result<[u8; 33], JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field_name} must decode to 33 bytes")))
}

fn decode_ethereum_address20(value: &str) -> Result<[u8; 20], JsValue> {
    let text = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if text.len() != 40 {
        return Err(JsValue::from_str("ethereumAddress must be 20 bytes hex"));
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        *byte = u8::from_str_radix(&text[start..start + 2], 16)
            .map_err(|_| JsValue::from_str("ethereumAddress must be hex"))?;
    }
    Ok(out)
}

fn get_optional_u32(args: &JsValue, field_name: &str) -> Result<Option<u32>, JsValue> {
    let value = Reflect::get(args, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let number = value
        .as_f64()
        .ok_or_else(|| JsValue::from_str(&format!("{field_name} must be a number")))?;
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > u32::MAX as f64 {
        return Err(JsValue::from_str(&format!(
            "{field_name} must be a u32 integer"
        )));
    }
    Ok(Some(number as u32))
}

fn hex_prefixed(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
        EcdsaClientBootstrapAlgorithmV1::EcdsaHssSecp256k1RoleLocalV1 => {}
    }
    validate_resolved_email_otp_root_participants(&command.participants)?;
    validate_resolved_email_otp_root_chain_target(&command.context.chain_target)?;

    let context = EcdsaHssStableKeyContext::new(
        require_command_ascii_nonempty(command.context.wallet_id, "context.walletId")?,
        require_command_ascii_nonempty(command.context.rp_id, "context.rpId")?,
        require_command_ascii_nonempty(
            command.context.ecdsa_threshold_key_id,
            "context.ecdsaThresholdKeyId",
        )?,
        require_command_ascii_nonempty(command.context.signing_root_id, "context.signingRootId")?,
        require_command_ascii_nonempty(
            command.context.signing_root_version,
            "context.signingRootVersion",
        )?,
        key_purpose_string(command.context.key_purpose),
        key_version_string(command.context.key_version),
    );
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
            hss_client_share_public_key33_b64u: base64_url_encode(
                &prepared.client_bootstrap.hss_client_share_public_key33,
            ),
            client_share_retry_counter: prepared.client_bootstrap.client_share_retry_counter,
            participant_id: prepared.client_bootstrap.participant_id,
        },
        public_facts: EcdsaPreparePublicFactsV1 {
            hss_client_share_public_key33_b64u: base64_url_encode(
                &prepared.public_facts.hss_client_share_public_key33,
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

fn validate_resolved_email_otp_root_chain_target(
    target: &ThresholdEcdsaChainTargetV1,
) -> CoreResult<()> {
    match target {
        ThresholdEcdsaChainTargetV1::Evm {
            namespace: _,
            chain_id,
            network_slug,
        }
        | ThresholdEcdsaChainTargetV1::Tempo {
            chain_id,
            network_slug,
        } => {
            if *chain_id == 0 {
                return Err(SignerCoreError::invalid_input(
                    "context.chainTarget.chainId must be positive",
                ));
            }
            require_command_ascii_nonempty_ref(network_slug, "context.chainTarget.networkSlug")?;
        }
    }
    Ok(())
}

fn key_purpose_string(value: EcdsaClientBootstrapKeyPurposeV1) -> &'static str {
    match value {
        EcdsaClientBootstrapKeyPurposeV1::EvmSigning => "evm-signing",
    }
}

fn key_version_string(value: EcdsaClientBootstrapKeyVersionV1) -> &'static str {
    match value {
        EcdsaClientBootstrapKeyVersionV1::V1 => "v1",
    }
}

fn require_command_ascii_nonempty(value: String, field_name: &str) -> CoreResult<String> {
    let trimmed = value.trim().to_owned();
    require_command_ascii_nonempty_ref(&trimmed, field_name)?;
    Ok(trimmed)
}

fn require_command_ascii_nonempty_ref(value: &str, field_name: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be ASCII-only"
        )));
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

fn decode_wire_message(value: &str, field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: base64_url_decode(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?,
    })
}

fn encode_wire_message(value: &WireMessage) -> String {
    base64_url_encode(&value.bytes)
}
