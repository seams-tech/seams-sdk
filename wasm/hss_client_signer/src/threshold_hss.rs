use crate::encoders::{base64_url_decode, base64_url_encode};
use crate::js::{
    get_required_string, get_required_u16_vec, get_required_u32, object, set_string, set_u16_vec,
    set_u32,
};
use ed25519_hss::{
    client::ClientDriverState,
    protocol::prepare_prime_order_succinct_hss_client,
    shared::CanonicalContext,
    wire::WireMessage,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_session(args: JsValue) -> Result<JsValue, JsValue> {
    let context = canonical_context_from_js(&args)?;
    let evaluator_driver_state =
        prepare_prime_order_succinct_hss_client(&context).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(&out, "orgId", &context.org_id)?;
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

    let evaluator_state: ClientDriverState = decode_state_blob(
        &evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
    )?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| JsValue::from_str(&e.to_string()))?;
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
    let evaluator_state: ClientDriverState = decode_state_blob(
        &evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
    )?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| JsValue::from_str(&e.to_string()))?;
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
    let evaluator_state: ClientDriverState = decode_state_blob(
        &evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
    )?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed_output_message = decode_wire_message(&seed_output_message_b64u, "seedOutputMessageB64u")?;
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
    set_string(&out, "canonicalSeedB64u", &base64_url_encode(&canonical_seed))?;
    Ok(out.into())
}

fn canonical_context_from_js(args: &JsValue) -> Result<CanonicalContext, JsValue> {
    Ok(CanonicalContext {
        org_id: get_required_string(args, "orgId")?,
        account_id: get_required_string(args, "nearAccountId")?,
        key_purpose: get_required_string(args, "keyPurpose")?,
        key_version: get_required_string(args, "keyVersion")?,
        participant_ids: get_required_u16_vec(args, "participantIds")?,
        derivation_version: get_required_u32(args, "derivationVersion")?,
    })
}

fn decode_state_blob<T: for<'de> Deserialize<'de>>(value: &str, field_name: &str) -> Result<T, JsValue> {
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
