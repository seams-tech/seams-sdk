use crate::encoders::{base64_url_decode, base64_url_encode};
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::client::ClientDriverState;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::client::ClientOtState;
#[cfg(feature = "hss-client-exports")]
use ed25519_hss::protocol::prepare_prime_order_succinct_hss_client;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerDriverState;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::shared::public_key_from_base_shares;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::shared::CanonicalContext;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::wire::{StagedEvaluatorArtifact, WireMessage};
use serde::{Deserialize, Serialize};
use signer_platform_web::near_threshold_ed25519::verifying_share_bytes_from_signing_share_bytes;
use wasm_bindgen::prelude::*;
#[cfg(feature = "hss-server-exports")]
use js_sys::{Object, Reflect};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssCanonicalContextArgs {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssPrepareSessionArgs {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssPrepareSessionOutput {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
    context_binding_b64u: String,
    evaluator_driver_state_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssPrepareClientRequestArgs {
    evaluator_driver_state_b64u: String,
    client_ot_offer_message_b64u: String,
    y_client_b64u: String,
    tau_client_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssPrepareClientRequestOutput {
    context_binding_b64u: String,
    client_request_message_b64u: String,
    evaluator_ot_state_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
pub(crate) struct ThresholdEd25519HssPrepareServerSessionArgs {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
pub(crate) struct ThresholdEd25519HssPrepareServerSessionOutput {
    context_binding_b64u: String,
    evaluator_driver_state_b64u: String,
    garbler_driver_state_b64u: String,
    client_ot_offer_message_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareServerAssistInitArgs {
    garbler_driver_state_b64u: String,
    client_request_message_b64u: String,
    y_relayer_b64u: String,
    tau_relayer_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareServerAssistInitOutput {
    context_binding_b64u: String,
    server_assist_init_message_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssBuildServerOwnedStagedArtifactArgs {
    evaluator_driver_state_b64u: String,
    garbler_driver_state_b64u: String,
    client_request_message_b64u: String,
    evaluator_ot_state_b64u: String,
    y_relayer_b64u: String,
    tau_relayer_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssBuildServerOwnedStagedArtifactOutput {
    context_binding_b64u: String,
    staged_evaluator_artifact_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssFinalizeReportArgs {
    garbler_driver_state_b64u: String,
    staged_evaluator_artifact_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssFinalizeReportOutput {
    context_binding_b64u: String,
    evaluation_report_json: String,
    client_output_message_b64u: String,
    seed_output_message_b64u: String,
    server_output_message_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssOpenClientOutputArgs {
    evaluator_driver_state_b64u: String,
    client_output_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssOpenClientOutputOutput {
    context_binding_b64u: String,
    x_client_base_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssOpenServerOutputArgs {
    garbler_driver_state_b64u: String,
    server_output_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssOpenServerOutputOutput {
    context_binding_b64u: String,
    x_relayer_base_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssOpenSeedOutputArgs {
    evaluator_driver_state_b64u: String,
    seed_output_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssOpenSeedOutputOutput {
    context_binding_b64u: String,
    canonical_seed_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssPublicKeyFromSharesArgs {
    x_client_base_b64u: String,
    x_relayer_base_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssPublicKeyFromSharesOutput {
    public_key_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdEd25519HssVerifyingShareFromSigningShareArgs {
    signing_share_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdEd25519HssVerifyingShareFromSigningShareOutput {
    verifying_share_b64u: String,
}

#[wasm_bindgen]
#[cfg(feature = "hss-client-exports")]
pub fn threshold_ed25519_hss_prepare_session(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPrepareSessionArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = prepare_threshold_ed25519_hss_session(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS session output: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-client-exports")]
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
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_prepare_server_session(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPrepareServerSessionArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        prepare_threshold_ed25519_hss_server_session(args).map_err(|e| JsValue::from_str(&e))?;
    let js_output = Object::new();
    Reflect::set(
        &js_output,
        &JsValue::from_str("contextBindingB64u"),
        &JsValue::from_str(&output.context_binding_b64u),
    )
    .map_err(|_| JsValue::from_str("Failed to set contextBindingB64u"))?;
    Reflect::set(
        &js_output,
        &JsValue::from_str("evaluatorDriverStateB64u"),
        &JsValue::from_str(&output.evaluator_driver_state_b64u),
    )
    .map_err(|_| JsValue::from_str("Failed to set evaluatorDriverStateB64u"))?;
    Reflect::set(
        &js_output,
        &JsValue::from_str("garblerDriverStateB64u"),
        &JsValue::from_str(&output.garbler_driver_state_b64u),
    )
    .map_err(|_| JsValue::from_str("Failed to set garblerDriverStateB64u"))?;
    Reflect::set(
        &js_output,
        &JsValue::from_str("clientOtOfferMessageB64u"),
        &JsValue::from_str(&output.client_ot_offer_message_b64u),
    )
    .map_err(|_| JsValue::from_str("Failed to set clientOtOfferMessageB64u"))?;
    Ok(js_output.into())
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_prepare_server_assist_init(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPrepareServerAssistInitArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let garbler_state: ServerDriverState =
        decode_state_blob(&args.garbler_driver_state_b64u, "garblerDriverStateB64u")
            .map_err(js_value_to_string)?;
    let context_binding = garbler_state.garbler_session.context_binding;
    let (_runtime, garbler_session) = garbler_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client_request_message = decode_wire_message(
        &args.client_request_message_b64u,
        "clientRequestMessageB64u",
    )?;
    let y_relayer = decode_fixed_32(&args.y_relayer_b64u, "yRelayerB64u")?;
    let tau_relayer = decode_fixed_32(&args.tau_relayer_b64u, "tauRelayerB64u")?;
    let (server_assist_init_message, _server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            y_relayer,
            tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssPrepareServerAssistInitOutput {
        context_binding_b64u: base64_url_encode(&context_binding),
        server_assist_init_message_b64u: encode_wire_message(&server_assist_init_message),
    })
    .map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS server assist init output: {e}"
        ))
    })
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_finalize_report(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssFinalizeReportArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let garbler_state: ServerDriverState =
        decode_state_blob(&args.garbler_driver_state_b64u, "garblerDriverStateB64u")
            .map_err(js_value_to_string)?;
    let (runtime, garbler_session) = garbler_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let staged_evaluator_artifact: StagedEvaluatorArtifact = decode_state_blob(
        &args.staged_evaluator_artifact_b64u,
        "stagedEvaluatorArtifactB64u",
    )?;
    let report = runtime
        .finalize_report_from_staged_evaluator_artifact(&garbler_session, &staged_evaluator_artifact)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssFinalizeReportOutput {
        context_binding_b64u: base64_url_encode(&report.artifact.context_binding),
        evaluation_report_json: serde_json::to_string(&report).map_err(|e| {
            JsValue::from_str(&format!("Failed to serialize evaluation report: {e}"))
        })?,
        client_output_message_b64u: encode_wire_message(&report.output_delivery.client),
        seed_output_message_b64u: encode_wire_message(&report.output_delivery.seed),
        server_output_message_b64u: encode_wire_message(&report.output_delivery.server),
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS finalization output: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_build_server_owned_staged_artifact(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssBuildServerOwnedStagedArtifactArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        build_threshold_ed25519_hss_server_owned_staged_artifact(args)
            .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS server-owned staged artifact output: {e}"
        ))
    })
}

#[wasm_bindgen]
#[cfg(feature = "hss-client-exports")]
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
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_open_server_output(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssOpenServerOutputArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let garbler_state: ServerDriverState = decode_state_blob(
        &args.garbler_driver_state_b64u,
        "garblerDriverStateB64u",
    )
    .map_err(js_value_to_string)?;
    let (_runtime, garbler_session) = garbler_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let server_output_message =
        decode_wire_message(&args.server_output_message_b64u, "serverOutputMessageB64u")?;
    let x_relayer_base = garbler_session
        .server_output_opener()
        .open(&server_output_message)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssOpenServerOutputOutput {
        context_binding_b64u: base64_url_encode(&garbler_state.garbler_session.context_binding),
        x_relayer_base_b64u: base64_url_encode(&x_relayer_base),
    })
    .map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS server output opening: {e}"
        ))
    })
}

#[wasm_bindgen]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub fn threshold_ed25519_hss_open_seed_output(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssOpenSeedOutputArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = open_threshold_ed25519_hss_seed_output(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!("Failed to serialize HSS seed output opening: {e}"))
    })
}

#[wasm_bindgen]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
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

#[wasm_bindgen]
pub fn threshold_ed25519_hss_verifying_share_from_signing_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssVerifyingShareFromSigningShareArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let signing_share = decode_fixed_32(&args.signing_share_b64u, "signingShareB64u")?;
    let verifying_share = verifying_share_bytes_from_signing_share_bytes(&signing_share);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssVerifyingShareFromSigningShareOutput {
        verifying_share_b64u: base64_url_encode(&verifying_share),
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize verifying share: {e}")))
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
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

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn decode_state_blob<T: for<'de> Deserialize<'de>>(
    value: &str,
    field_name: &str,
) -> Result<T, JsValue> {
    let bytes = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    bincode::deserialize::<T>(&bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
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

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn decode_wire_message(value: &str, field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: base64_url_decode(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?,
    })
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn encode_wire_message(value: &WireMessage) -> String {
    base64_url_encode(&value.bytes)
}

#[cfg(feature = "hss-client-exports")]
pub(crate) fn prepare_threshold_ed25519_hss_session(
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
    let evaluator_driver_state =
        prepare_prime_order_succinct_hss_client(&context).map_err(|e| e.to_string())?;

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
        evaluator_driver_state_b64u: encode_state_blob(&evaluator_driver_state, "evaluator state")?,
    })
}

#[cfg(feature = "hss-server-exports")]
pub(crate) fn prepare_threshold_ed25519_hss_server_session(
    args: ThresholdEd25519HssPrepareServerSessionArgs,
) -> Result<ThresholdEd25519HssPrepareServerSessionOutput, String> {
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
    let evaluator_driver_state = session.evaluator_driver_state();
    let garbler_driver_state = session.garbler_driver_state();
    let client_ot_offer_message = session
        .garbler_session()
        .client_ot_offer_message()
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssPrepareServerSessionOutput {
        context_binding_b64u: base64_url_encode(
            &garbler_driver_state.garbler_session.context_binding,
        ),
        evaluator_driver_state_b64u: encode_state_blob(
            &evaluator_driver_state,
            "evaluator state",
        )?,
        garbler_driver_state_b64u: encode_state_blob(&garbler_driver_state, "garbler state")?,
        client_ot_offer_message_b64u: encode_wire_message(&client_ot_offer_message),
    })
}

#[cfg(feature = "hss-client-exports")]
pub(crate) fn prepare_threshold_ed25519_hss_client_request(
    args: ThresholdEd25519HssPrepareClientRequestArgs,
) -> Result<ThresholdEd25519HssPrepareClientRequestOutput, String> {
    let evaluator_state: ClientDriverState = decode_state_blob(
        &args.evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
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
        evaluator_ot_state_b64u: encode_state_blob(&evaluator_ot_state, "evaluator OT state")?,
    })
}

#[cfg(feature = "hss-server-exports")]
fn build_threshold_ed25519_hss_server_owned_staged_artifact(
    args: ThresholdEd25519HssBuildServerOwnedStagedArtifactArgs,
) -> Result<ThresholdEd25519HssBuildServerOwnedStagedArtifactOutput, String> {
    let evaluator_state: ClientDriverState = decode_state_blob(
        &args.evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
    )
    .map_err(js_value_to_string)?;
    let garbler_state: ServerDriverState = decode_state_blob(
        &args.garbler_driver_state_b64u,
        "garblerDriverStateB64u",
    )
    .map_err(js_value_to_string)?;
    let evaluator_ot_state: ClientOtState =
        decode_state_blob(&args.evaluator_ot_state_b64u, "evaluatorOtStateB64u")
            .map_err(js_value_to_string)?;
    let client_request_message = decode_wire_message(
        &args.client_request_message_b64u,
        "clientRequestMessageB64u",
    )
    .map_err(js_value_to_string)?;
    let y_relayer = decode_fixed_32(&args.y_relayer_b64u, "yRelayerB64u")
        .map_err(js_value_to_string)?;
    let tau_relayer = decode_fixed_32(&args.tau_relayer_b64u, "tauRelayerB64u")
        .map_err(js_value_to_string)?;
    let (runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
    let (_shared_runtime, garbler_session) =
        garbler_state.materialize().map_err(|e| e.to_string())?;
    let staged_evaluator_artifact = garbler_session
        .build_staged_evaluator_artifact_from_transport_messages(
            &runtime,
            &evaluator_session,
            &evaluator_ot_state,
            &client_request_message,
            y_relayer,
            tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssBuildServerOwnedStagedArtifactOutput {
        context_binding_b64u: base64_url_encode(&evaluator_state.evaluator_session.context_binding),
        staged_evaluator_artifact_b64u: encode_state_blob(
            &staged_evaluator_artifact,
            "staged evaluator artifact",
        )?,
    })
}

#[cfg(feature = "hss-client-exports")]
pub(crate) fn open_threshold_ed25519_hss_client_output(
    args: ThresholdEd25519HssOpenClientOutputArgs,
) -> Result<ThresholdEd25519HssOpenClientOutputOutput, String> {
    let evaluator_state: ClientDriverState = decode_state_blob(
        &args.evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
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

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) fn open_threshold_ed25519_hss_seed_output(
    args: ThresholdEd25519HssOpenSeedOutputArgs,
) -> Result<ThresholdEd25519HssOpenSeedOutputOutput, String> {
    let evaluator_state: ClientDriverState = decode_state_blob(
        &args.evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
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

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) fn derive_threshold_ed25519_hss_public_key_from_base_shares(
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

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn js_value_to_string(value: JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}
