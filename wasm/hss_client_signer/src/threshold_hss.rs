use crate::encoders::{base64_url_decode, base64_url_encode};
use ed25519_hss::{
    client::{ClientDriverState, ClientOtState},
    protocol::prepare_prime_order_succinct_hss,
    shared::{public_key_from_base_shares, CanonicalContext},
    wire::WireMessage,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdEd25519HssCanonicalContextArgs {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssPrepareSessionArgs {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssPrepareSessionOutput {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
    context_binding_b64u: String,
    garbler_driver_state_json: String,
    evaluator_driver_state_json: String,
    client_ot_offer_message_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssPrepareClientRequestArgs {
    evaluator_driver_state_json: String,
    client_ot_offer_message_b64u: String,
    y_client_b64u: String,
    tau_client_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssPrepareClientRequestOutput {
    context_binding_b64u: String,
    client_request_message_b64u: String,
    evaluator_ot_state_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssEvaluateResultArgs {
    evaluator_driver_state_json: String,
    client_request_message_b64u: String,
    evaluator_ot_state_json: String,
    server_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssEvaluateResultOutput {
    context_binding_b64u: String,
    evaluation_result_message_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssOpenClientOutputArgs {
    evaluator_driver_state_json: String,
    client_output_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssOpenClientOutputOutput {
    context_binding_b64u: String,
    x_client_base_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssOpenSeedOutputArgs {
    evaluator_driver_state_json: String,
    seed_output_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssOpenSeedOutputOutput {
    context_binding_b64u: String,
    canonical_seed_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssPublicKeyFromSharesArgs {
    x_client_base_b64u: String,
    x_relayer_base_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519HssPublicKeyFromSharesOutput {
    public_key_b64u: String,
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_session(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPrepareSessionArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = prepare_threshold_ed25519_hss_session(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS session output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_client_request(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPrepareClientRequestArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        prepare_threshold_ed25519_hss_client_request(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS client request output: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_evaluate_result(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssEvaluateResultArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = evaluate_threshold_ed25519_hss_result(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS evaluation output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_open_client_output(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssOpenClientOutputArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        open_threshold_ed25519_hss_client_output(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS client output opening: {e}"
        ))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_open_seed_output(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssOpenSeedOutputArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = open_threshold_ed25519_hss_seed_output(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!("Failed to serialize HSS seed output opening: {e}"))
    })
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_public_key_from_base_shares(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPublicKeyFromSharesArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = derive_threshold_ed25519_hss_public_key_from_base_shares(args)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS public key output: {e}")))
}

fn canonical_context_from_args(
    args: ThresholdEd25519HssCanonicalContextArgs,
) -> Result<CanonicalContext, JsValue> {
    let org_id = args.org_id.trim().to_string();
    let near_account_id = args.near_account_id.trim().to_string();
    let key_purpose = args.key_purpose.trim().to_string();
    let key_version = args.key_version.trim().to_string();
    if org_id.is_empty() {
        return Err(JsValue::from_str("Missing orgId"));
    }
    if near_account_id.is_empty() {
        return Err(JsValue::from_str("Missing nearAccountId"));
    }
    if key_purpose.is_empty() {
        return Err(JsValue::from_str("Missing keyPurpose"));
    }
    if key_version.is_empty() {
        return Err(JsValue::from_str("Missing keyVersion"));
    }

    Ok(CanonicalContext {
        org_id,
        account_id: near_account_id,
        key_purpose,
        key_version,
        participant_ids: args.participant_ids,
        derivation_version: args.derivation_version,
    })
}

fn parse_json<T: for<'de> Deserialize<'de>>(value: &str, field_name: &str) -> Result<T, JsValue> {
    serde_json::from_str(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))
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

fn prepare_threshold_ed25519_hss_session(
    args: ThresholdEd25519HssPrepareSessionArgs,
) -> Result<ThresholdEd25519HssPrepareSessionOutput, String> {
    let context = canonical_context_from_args(ThresholdEd25519HssCanonicalContextArgs {
        org_id: args.org_id,
        near_account_id: args.near_account_id,
        key_purpose: args.key_purpose,
        key_version: args.key_version,
        participant_ids: args.participant_ids,
        derivation_version: args.derivation_version,
    })
    .map_err(js_value_to_string)?;
    let session = prepare_prime_order_succinct_hss(&context).map_err(|e| e.to_string())?;
    let garbler_driver_state = session.garbler_driver_state();
    let evaluator_driver_state = session.evaluator_driver_state();
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssPrepareSessionOutput {
        org_id: context.org_id,
        near_account_id: context.account_id,
        key_purpose: context.key_purpose,
        key_version: context.key_version,
        participant_ids: context.participant_ids,
        derivation_version: context.derivation_version,
        context_binding_b64u: base64_url_encode(
            &evaluator_driver_state.evaluator_session.context_binding,
        ),
        garbler_driver_state_json: serde_json::to_string(&garbler_driver_state)
            .map_err(|e| format!("Failed to serialize garbler state: {e}"))?,
        evaluator_driver_state_json: serde_json::to_string(&evaluator_driver_state)
            .map_err(|e| format!("Failed to serialize evaluator state: {e}"))?,
        client_ot_offer_message_b64u: encode_wire_message(&client_ot_offer_message),
    })
}

fn prepare_threshold_ed25519_hss_client_request(
    args: ThresholdEd25519HssPrepareClientRequestArgs,
) -> Result<ThresholdEd25519HssPrepareClientRequestOutput, String> {
    let evaluator_state: ClientDriverState = parse_json(
        &args.evaluator_driver_state_json,
        "evaluatorDriverStateJson",
    )
    .map_err(js_value_to_string)?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
    let offer_message = decode_wire_message(
        &args.client_ot_offer_message_b64u,
        "clientOtOfferMessageB64u",
    )
    .map_err(js_value_to_string)?;
    let y_client =
        decode_fixed_32(&args.y_client_b64u, "yClientB64u").map_err(js_value_to_string)?;
    let tau_client =
        decode_fixed_32(&args.tau_client_b64u, "tauClientB64u").map_err(js_value_to_string)?;
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(&offer_message, y_client, tau_client)
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssPrepareClientRequestOutput {
        context_binding_b64u: base64_url_encode(&evaluator_ot_state.context_binding),
        client_request_message_b64u: encode_wire_message(&client_request_message),
        evaluator_ot_state_json: serde_json::to_string(&evaluator_ot_state)
            .map_err(|e| format!("Failed to serialize evaluator OT state: {e}"))?,
    })
}

fn evaluate_threshold_ed25519_hss_result(
    args: ThresholdEd25519HssEvaluateResultArgs,
) -> Result<ThresholdEd25519HssEvaluateResultOutput, String> {
    let evaluator_state: ClientDriverState = parse_json(
        &args.evaluator_driver_state_json,
        "evaluatorDriverStateJson",
    )
    .map_err(js_value_to_string)?;
    let evaluator_ot_state: ClientOtState =
        parse_json(&args.evaluator_ot_state_json, "evaluatorOtStateJson")
            .map_err(js_value_to_string)?;
    let (runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
    let client_request_message = decode_wire_message(
        &args.client_request_message_b64u,
        "clientRequestMessageB64u",
    )
    .map_err(js_value_to_string)?;
    let server_message = decode_wire_message(&args.server_message_b64u, "serverMessageB64u")
        .map_err(js_value_to_string)?;
    let evaluation_result_message = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message,
            &evaluator_ot_state,
            &server_message,
        )
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssEvaluateResultOutput {
        context_binding_b64u: base64_url_encode(&evaluator_ot_state.context_binding),
        evaluation_result_message_b64u: encode_wire_message(&evaluation_result_message),
    })
}

fn open_threshold_ed25519_hss_client_output(
    args: ThresholdEd25519HssOpenClientOutputArgs,
) -> Result<ThresholdEd25519HssOpenClientOutputOutput, String> {
    let evaluator_state: ClientDriverState = parse_json(
        &args.evaluator_driver_state_json,
        "evaluatorDriverStateJson",
    )
    .map_err(js_value_to_string)?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
    let client_output_message =
        decode_wire_message(&args.client_output_message_b64u, "clientOutputMessageB64u")
            .map_err(js_value_to_string)?;
    let x_client_base = evaluator_session
        .client_output_opener()
        .open(&client_output_message)
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssOpenClientOutputOutput {
        context_binding_b64u: base64_url_encode(&evaluator_state.evaluator_session.context_binding),
        x_client_base_b64u: base64_url_encode(&x_client_base),
    })
}

fn open_threshold_ed25519_hss_seed_output(
    args: ThresholdEd25519HssOpenSeedOutputArgs,
) -> Result<ThresholdEd25519HssOpenSeedOutputOutput, String> {
    let evaluator_state: ClientDriverState = parse_json(
        &args.evaluator_driver_state_json,
        "evaluatorDriverStateJson",
    )
    .map_err(js_value_to_string)?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
    let seed_output_message =
        decode_wire_message(&args.seed_output_message_b64u, "seedOutputMessageB64u")
            .map_err(js_value_to_string)?;
    let canonical_seed = evaluator_session
        .seed_output_opener()
        .open(&seed_output_message)
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssOpenSeedOutputOutput {
        context_binding_b64u: base64_url_encode(&evaluator_state.evaluator_session.context_binding),
        canonical_seed_b64u: base64_url_encode(&canonical_seed),
    })
}

fn derive_threshold_ed25519_hss_public_key_from_base_shares(
    args: ThresholdEd25519HssPublicKeyFromSharesArgs,
) -> Result<ThresholdEd25519HssPublicKeyFromSharesOutput, String> {
    let x_client_base =
        decode_fixed_32(&args.x_client_base_b64u, "xClientBaseB64u").map_err(js_value_to_string)?;
    let x_relayer_base = decode_fixed_32(&args.x_relayer_base_b64u, "xRelayerBaseB64u")
        .map_err(js_value_to_string)?;
    let public_key =
        public_key_from_base_shares(x_client_base, x_relayer_base).map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssPublicKeyFromSharesOutput {
        public_key_b64u: base64_url_encode(&public_key),
    })
}

fn js_value_to_string(value: JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}
