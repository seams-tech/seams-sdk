use crate::encoders::{base64_url_decode, base64_url_encode};
use crate::js::{
    get_required_string, get_required_u16_vec, get_required_u32, object, set_string, set_u16_vec,
    set_u32,
};
use ecdsa_hss::{encode_context_v1 as encode_ecdsa_context_v1, EcdsaHssStableKeyContextV1};
use ed25519_hss::{
    client::ClientDriverState, protocol::prepare_prime_order_succinct_hss_client,
    shared::CanonicalContext, wire::WireMessage,
};
use js_sys::{Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
pub fn threshold_ed25519_hss_open_client_output(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let client_output_message_b64u = get_required_string(&args, "clientOutputMessageB64u")?;
    let evaluator_state: ClientDriverState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let (_runtime, evaluator_session) = evaluator_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client_output_message =
        decode_wire_message(&client_output_message_b64u, "clientOutputMessageB64u")?;
    let x_client_base = evaluator_session
        .client_output_opener()
        .open(&client_output_message)
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
pub fn threshold_ecdsa_hss_prepare_session(args: JsValue) -> Result<JsValue, JsValue> {
    let context = ecdsa_canonical_context_from_js(&args)?;
    let y_client32_le = get_required_client_root_share32(&args)?;
    let context_binding = ecdsa_context_binding(&context)?;
    let state = ThresholdEcdsaHssClientSessionState {
        wallet_session_user_id: context.wallet_session_user_id,
        subject_id: context.subject_id,
        chain_target: context.chain_target,
        ecdsa_threshold_key_id: context.ecdsa_threshold_key_id,
        signing_root_id: context.signing_root_id,
        signing_root_version: context.signing_root_version,
        key_purpose: context.key_purpose,
        key_version: context.key_version,
        context_binding,
        y_client32_le,
    };

    let out = object();
    set_string(&out, "walletSessionUserId", &state.wallet_session_user_id)?;
    set_string(&out, "subjectId", &state.subject_id)?;
    set_string(&out, "chainTarget", &state.chain_target)?;
    set_string(&out, "ecdsaThresholdKeyId", &state.ecdsa_threshold_key_id)?;
    set_string(&out, "signingRootId", &state.signing_root_id)?;
    set_string(&out, "signingRootVersion", &state.signing_root_version)?;
    set_string(&out, "keyPurpose", &state.key_purpose)?;
    set_string(&out, "keyVersion", &state.key_version)?;
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&state.context_binding),
    )?;
    set_string(
        &out,
        "evaluatorDriverStateB64u",
        &encode_state_blob(&state, "threshold ecdsa hss client session state")
            .map_err(|e| JsValue::from_str(&e))?,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_prepare_client_request(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let server_assist_init_message_b64u =
        get_required_string(&args, "serverAssistInitMessageB64u")?;

    let state: ThresholdEcdsaHssClientSessionState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let expected_client_root_share32 = get_required_client_root_share32(&args)?;
    if expected_client_root_share32 != state.y_client32_le {
        return Err(JsValue::from_str(
            "clientRootShare32 did not match the prepared ECDSA HSS client session",
        ));
    }
    let server_assist_init: ThresholdEcdsaHssServerAssistInitWire = decode_state_blob(
        &server_assist_init_message_b64u,
        "serverAssistInitMessageB64u",
    )?;
    if server_assist_init.context_binding != state.context_binding {
        return Err(JsValue::from_str(
            "serverAssistInitMessageB64u did not match the prepared ECDSA HSS client session",
        ));
    }

    let request = ThresholdEcdsaHssClientEvalRequestWire {
        context_binding: state.context_binding,
        y_client32_le: state.y_client32_le,
    };
    let out = object();
    set_string(
        &out,
        "clientEvalRequestB64u",
        &encode_state_blob(&request, "threshold ecdsa hss client eval request")
            .map_err(|e| JsValue::from_str(&e))?,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_finalize_client_request(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_driver_state_b64u = get_required_string(&args, "evaluatorDriverStateB64u")?;
    let server_eval_response_b64u = get_required_string(&args, "serverEvalResponseB64u")?;
    let state: ThresholdEcdsaHssClientSessionState =
        decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")?;
    let server_eval_response: ThresholdEcdsaHssServerEvalResponseWire =
        decode_state_blob(&server_eval_response_b64u, "serverEvalResponseB64u")?;
    if server_eval_response.context_binding != state.context_binding {
        return Err(JsValue::from_str(
            "serverEvalResponseB64u did not match the prepared ECDSA HSS client session",
        ));
    }

    let finalize = ThresholdEcdsaHssClientFinalizeWire {
        context_binding: state.context_binding,
    };
    let out = object();
    set_string(
        &out,
        "clientEvalFinalizeB64u",
        &encode_state_blob(&finalize, "threshold ecdsa hss client finalize")
            .map_err(|e| JsValue::from_str(&e))?,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssClientSessionState {
    wallet_session_user_id: String,
    subject_id: String,
    chain_target: String,
    ecdsa_threshold_key_id: String,
    signing_root_id: String,
    signing_root_version: String,
    key_purpose: String,
    key_version: String,
    context_binding: [u8; 32],
    y_client32_le: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssServerAssistInitWire {
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssClientEvalRequestWire {
    context_binding: [u8; 32],
    y_client32_le: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssServerEvalResponseWire {
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssClientFinalizeWire {
    context_binding: [u8; 32],
}

fn ecdsa_canonical_context_from_js(args: &JsValue) -> Result<EcdsaHssStableKeyContextV1, JsValue> {
    Ok(EcdsaHssStableKeyContextV1::new(
        get_required_string(args, "walletSessionUserId")?,
        get_required_string(args, "subjectId")?,
        get_required_string(args, "chainTarget")?,
        get_required_string(args, "ecdsaThresholdKeyId")?,
        get_required_string(args, "signingRootId")?,
        get_required_string(args, "signingRootVersion")?,
        get_required_string(args, "keyPurpose")?,
        get_required_string(args, "keyVersion")?,
    ))
}

fn ecdsa_context_binding(context: &EcdsaHssStableKeyContextV1) -> Result<[u8; 32], JsValue> {
    let encoded =
        encode_ecdsa_context_v1(context).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(Sha256::digest(encoded).into())
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

fn decode_wire_message(value: &str, field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: base64_url_decode(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?,
    })
}

fn encode_wire_message(value: &WireMessage) -> String {
    base64_url_encode(&value.bytes)
}
