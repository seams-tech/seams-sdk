use crate::encoders::{base64_url_decode, base64_url_encode};
use crate::js::{
    get_required_string, get_required_u16_vec, get_required_u32, object, set_string, set_u16_vec,
    set_u32,
};
use ecdsa_hss::{
    derive_client_share, reconstruct_export_key, EcdsaHssStableKeyContext, PublicIdentity,
};
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
use js_sys::{Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use signer_core::threshold_ecdsa_hss::{
    finalize_ecdsa_client_bootstrap, prepare_ecdsa_client_bootstrap,
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
pub fn threshold_ecdsa_hss_role_local_client_bootstrap(args: JsValue) -> Result<JsValue, JsValue> {
    let context = ecdsa_canonical_context_from_js(&args)?;
    let y_client32_le = get_required_client_root_share32(&args)?;
    let client_share = derive_client_share(&context, y_client32_le)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(&out, "walletId", &context.wallet_id)?;
    set_string(&out, "rpId", &context.rp_id)?;
    set_string(&out, "ecdsaThresholdKeyId", &context.ecdsa_threshold_key_id)?;
    set_string(&out, "signingRootId", &context.signing_root_id)?;
    set_string(&out, "signingRootVersion", &context.signing_root_version)?;
    set_string(&out, "keyPurpose", &context.key_purpose)?;
    set_string(&out, "keyVersion", &context.key_version)?;
    set_string(
        &out,
        "contextBinding32B64u",
        &base64_url_encode(&client_share.context_binding32),
    )?;
    set_string(
        &out,
        "clientShare32B64u",
        &base64_url_encode(&client_share.x_client32),
    )?;
    set_string(
        &out,
        "clientPublicKey33B64u",
        &base64_url_encode(&client_share.client_public_key33),
    )?;
    set_u32(&out, "clientShareRetryCounter", client_share.retry_counter)?;
    set_string(
        &out,
        "mappedPrivateShare32B64u",
        &base64_url_encode(&client_share.mapped_client_share32),
    )?;
    set_string(
        &out,
        "verifyingShare33B64u",
        &base64_url_encode(&client_share.client_public_key33),
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_role_local_prepare_client_bootstrap(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let context = ecdsa_canonical_context_from_js(&args)?;
    let client_root_share32 = get_required_client_root_share32(&args)?;
    let prepared = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
        context: context.clone(),
        client_root_share32,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(&out, "walletId", &context.wallet_id)?;
    set_string(&out, "rpId", &context.rp_id)?;
    set_string(&out, "ecdsaThresholdKeyId", &context.ecdsa_threshold_key_id)?;
    set_string(&out, "signingRootId", &context.signing_root_id)?;
    set_string(&out, "signingRootVersion", &context.signing_root_version)?;
    set_string(&out, "keyPurpose", &context.key_purpose)?;
    set_string(&out, "keyVersion", &context.key_version)?;
    set_string(
        &out,
        "pendingStateBlobB64u",
        &base64_url_encode(&prepared.pending_state_blob.state_blob),
    )?;
    set_string(
        &out,
        "contextBinding32B64u",
        &base64_url_encode(&prepared.client_bootstrap.context_binding32),
    )?;
    set_string(
        &out,
        "hssClientSharePublicKey33B64u",
        &base64_url_encode(&prepared.client_bootstrap.hss_client_share_public_key33),
    )?;
    set_string(
        &out,
        "clientVerifyingShareB64u",
        &base64_url_encode(&prepared.public_facts.client_verifying_share33),
    )?;
    set_u32(
        &out,
        "clientShareRetryCounter",
        prepared.client_bootstrap.client_share_retry_counter,
    )?;
    set_u32(
        &out,
        "participantId",
        prepared.client_bootstrap.participant_id,
    )?;
    Ok(out.into())
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
pub fn threshold_ecdsa_hss_role_local_export_artifact(args: JsValue) -> Result<JsValue, JsValue> {
    let context = ecdsa_canonical_context_from_js(&args)?;
    let y_client32_le = get_required_client_root_share32(&args)?;
    let client_share = derive_client_share(&context, y_client32_le)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let server_export_share32 = decode_fixed_32(
        &get_required_string(&args, "serverExportShare32B64u")?,
        "serverExportShare32B64u",
    )?;
    let identity = PublicIdentity {
        context_bytes: client_share.context_bytes.clone(),
        context_binding32: decode_fixed_32(
            &get_required_string(&args, "contextBinding32B64u")?,
            "contextBinding32B64u",
        )?,
        client_public_key33: decode_fixed_33(
            &get_required_string(&args, "clientPublicKey33B64u")?,
            "clientPublicKey33B64u",
        )?,
        relayer_public_key33: decode_fixed_33(
            &get_required_string(&args, "relayerPublicKey33B64u")?,
            "relayerPublicKey33B64u",
        )?,
        threshold_public_key33: decode_fixed_33(
            &get_required_string(&args, "groupPublicKey33B64u")?,
            "groupPublicKey33B64u",
        )?,
        threshold_ethereum_address20: decode_ethereum_address20(&get_required_string(
            &args,
            "ethereumAddress",
        )?)?,
        client_share_retry_counter: get_required_u32(&args, "clientShareRetryCounter")?,
        relayer_share_retry_counter: 0,
    };
    let private_key32 = reconstruct_export_key(&client_share, &server_export_share32, &identity)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "publicKeyHex",
        &hex_prefixed(&identity.threshold_public_key33),
    )?;
    set_string(&out, "privateKeyHex", &hex_prefixed(&private_key32))?;
    set_string(
        &out,
        "ethereumAddress",
        &hex_prefixed(&identity.threshold_ethereum_address20),
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

fn get_required_client_root_share32(args: &JsValue) -> Result<[u8; 32], JsValue> {
    let maybe_bytes = Reflect::get(args, &JsValue::from_str("clientRootShare32"))
        .map_err(|_| JsValue::from_str("Invalid args: missing clientRootShare32"))?;
    if !maybe_bytes.is_undefined() && !maybe_bytes.is_null() {
        if !maybe_bytes.is_instance_of::<Uint8Array>() {
            return Err(JsValue::from_str(
                "Invalid args: clientRootShare32 must be a Uint8Array",
            ));
        }
        let bytes = Uint8Array::new(&maybe_bytes);
        if bytes.length() != 32 {
            return Err(JsValue::from_str(
                "Invalid args: clientRootShare32 must be 32 bytes",
            ));
        }
        let mut out = [0u8; 32];
        bytes.copy_to(&mut out);
        return Ok(out);
    }

    let client_root_share32_b64u = get_required_string(args, "clientRootShare32B64u")?;
    decode_fixed_32(&client_root_share32_b64u, "clientRootShare32B64u")
}

fn ecdsa_canonical_context_from_js(args: &JsValue) -> Result<EcdsaHssStableKeyContext, JsValue> {
    Ok(EcdsaHssStableKeyContext::new(
        get_required_string(args, "walletId")?,
        get_required_string(args, "rpId")?,
        get_required_string(args, "ecdsaThresholdKeyId")?,
        get_required_string(args, "signingRootId")?,
        get_required_string(args, "signingRootVersion")?,
        get_required_string(args, "keyPurpose")?,
        get_required_string(args, "keyVersion")?,
    ))
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

fn decode_wire_message(value: &str, field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: base64_url_decode(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?,
    })
}

fn encode_wire_message(value: &WireMessage) -> String {
    base64_url_encode(&value.bytes)
}
