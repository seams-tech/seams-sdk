use crate::encoders::{base64_url_decode, base64_url_encode};
#[cfg(feature = "hss-client-exports")]
use ed25519_hss::client::output_mask::{
    derive_client_output_mask, ClientOutputMaskContext, ClientOutputMaskOperation,
};
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::client::ClientDriverState;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::client::ClientOtState;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
#[cfg(feature = "hss-client-exports")]
use ed25519_hss::protocol::prepare_prime_order_succinct_hss_client;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::protocol::PreparedSession;
use ed25519_hss::role_signing::role_separated_ed25519_client_verifying_share_v1;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::runtime::EvaluateTiming;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerDriverState;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerEvalOperation;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::shared::public_key_from_base_shares;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::shared::CanonicalContext;
#[cfg(feature = "hss-client-exports")]
use ed25519_hss::wire::RoleSeparatedServerInputDeliveryPacket;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::wire::StagedEvaluatorArtifact;
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
use ed25519_hss::wire::WireMessage;
#[cfg(feature = "hss-server-exports")]
use js_sys::{Date, Object, Reflect};
use serde::{Deserialize, Serialize};
use signer_core::near_threshold_ed25519::verifying_share_bytes_from_signing_share_bytes;
#[cfg(feature = "hss-server-exports")]
use std::cell::RefCell;
#[cfg(feature = "hss-server-exports")]
use std::collections::BTreeMap;
#[cfg(feature = "hss-server-exports")]
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_bindgen::prelude::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssCanonicalContextArgs {
    application_binding_digest_b64u: String,
    participant_ids: Vec<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssPrepareSessionArgs {
    application_binding_digest_b64u: String,
    participant_ids: Vec<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssPrepareSessionOutput {
    application_binding_digest_b64u: String,
    participant_ids: Vec<u16>,
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
    client_request_message_b64u: String,
    evaluator_ot_state_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssDeriveClientOutputMaskArgs {
    pub(crate) application_binding_digest_b64u: String,
    pub(crate) participant_ids: Vec<u16>,
    pub(crate) context_binding_b64u: String,
    pub(crate) operation: String,
    pub(crate) relayer_key_id: String,
    pub(crate) client_recoverable_secret_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssDeriveClientOutputMaskOutput {
    pub(crate) client_output_mask_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssBuildClientOwnedStagedArtifactArgs {
    evaluator_driver_state_b64u: String,
    client_request_message_b64u: String,
    evaluator_ot_state_b64u: String,
    server_input_delivery_b64u: String,
    client_output_mask_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssBuildClientOwnedStagedArtifactOutput {
    context_binding_b64u: String,
    staged_evaluator_artifact_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
pub(crate) struct ThresholdEd25519HssPrepareServerSessionArgs {
    application_binding_digest_b64u: String,
    participant_ids: Vec<u16>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
pub(crate) struct ThresholdEd25519HssPrepareServerSessionOutput {
    context_binding_b64u: String,
    evaluator_driver_state_b64u: String,
    garbler_driver_state_b64u: String,
    client_ot_offer_message_b64u: String,
    prepared_session_handle: String,
    timings: ThresholdEd25519HssPrepareServerSessionTimings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareServerSessionTimings {
    prepare_session_ms: f64,
    extract_driver_states_ms: f64,
    client_offer_message_ms: f64,
    cache_prepared_session_ms: f64,
    encode_states_ms: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssBuildServerOwnedStagedArtifactArgs {
    operation: String,
    #[serde(default)]
    prepared_session_handle: String,
    evaluator_driver_state_bytes: Vec<u8>,
    garbler_driver_state_bytes: Vec<u8>,
    client_request_message_bytes: Vec<u8>,
    evaluator_ot_state_bytes: Vec<u8>,
    y_relayer_bytes: Vec<u8>,
    tau_relayer_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareServerCeremonyOutput {
    context_binding_b64u: String,
    staged_evaluator_artifact_handle: String,
    timings: ThresholdEd25519HssPrepareServerCeremonyTimings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryArgs {
    operation: String,
    #[serde(default)]
    prepared_session_handle: String,
    garbler_driver_state_bytes: Vec<u8>,
    client_request_message_bytes: Vec<u8>,
    y_relayer_bytes: Vec<u8>,
    tau_relayer_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryOutput {
    context_binding_b64u: String,
    server_input_delivery_b64u: String,
    timings: ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryTimings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryTimings {
    decode_messages_ms: f64,
    materialize_session_ms: f64,
    prepare_delivery_ms: f64,
    delivery_ot_open_join_ms: f64,
    delivery_server_input_open_ms: f64,
    delivery_server_input_share_ms: f64,
    delivery_server_input_commitment_ms: f64,
    delivery_server_input_transcript_ms: f64,
    delivery_server_input_seal_ms: f64,
    encode_delivery_ms: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareServerCeremonyTimings {
    decode_states_ms: f64,
    decode_messages_ms: f64,
    materialize_runtime_ms: f64,
    materialize_sessions_ms: f64,
    ceremony_core_ms: f64,
    ceremony_ot_open_join_ms: f64,
    ceremony_ot_branch_key_derivation_ms: f64,
    ceremony_ot_branch_decrypt_ms: f64,
    ceremony_ot_point_scalar_reconstruction_ms: f64,
    ceremony_ot_commitment_verification_ms: f64,
    ceremony_server_input_open_ms: f64,
    ceremony_server_input_share_ms: f64,
    ceremony_server_input_commitment_ms: f64,
    ceremony_server_input_transcript_ms: f64,
    ceremony_add_stage_ms: f64,
    ceremony_message_schedule_ms: f64,
    ceremony_round_core_ms: f64,
    ceremony_output_projector_ms: f64,
    ceremony_result_assembly_ms: f64,
    ceremony_output_sealing_finalization_ms: f64,
    encode_artifact_ms: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssFinalizeReportTimings {
    decode_artifact_ms: f64,
    serialized_session_materialize_ms: f64,
    finalize_report_ms: f64,
    encode_report_ms: f64,
}

#[cfg(feature = "hss-server-exports")]
fn ns_to_ms(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}

#[cfg(feature = "hss-server-exports")]
fn ceremony_timing_fields(
    timing: EvaluateTiming,
) -> ThresholdEd25519HssPrepareServerCeremonyTimingFields {
    ThresholdEd25519HssPrepareServerCeremonyTimingFields {
        ceremony_ot_open_join_ms: ns_to_ms(timing.ot_open_join_duration_ns),
        ceremony_ot_branch_key_derivation_ms: ns_to_ms(timing.ot_branch_key_derivation_duration_ns),
        ceremony_ot_branch_decrypt_ms: ns_to_ms(timing.ot_branch_decrypt_duration_ns),
        ceremony_ot_point_scalar_reconstruction_ms: ns_to_ms(
            timing.ot_point_scalar_reconstruction_duration_ns,
        ),
        ceremony_ot_commitment_verification_ms: ns_to_ms(
            timing.ot_commitment_verification_duration_ns,
        ),
        ceremony_server_input_open_ms: ns_to_ms(timing.server_input_open_duration_ns),
        ceremony_server_input_share_ms: ns_to_ms(timing.server_input_share_duration_ns),
        ceremony_server_input_commitment_ms: ns_to_ms(timing.server_input_commitment_duration_ns),
        ceremony_server_input_transcript_ms: ns_to_ms(timing.server_input_transcript_duration_ns),
        ceremony_result_assembly_ms: ns_to_ms(timing.result_assembly_duration_ns),
        ceremony_output_sealing_finalization_ms: ns_to_ms(
            timing.output_sealing_finalization_duration_ns,
        ),
    }
}

#[cfg(feature = "hss-server-exports")]
fn server_input_delivery_timing_fields(timing: EvaluateTiming) -> (f64, f64, f64, f64, f64, f64) {
    (
        ns_to_ms(timing.ot_open_join_duration_ns),
        ns_to_ms(timing.server_input_open_duration_ns),
        ns_to_ms(timing.server_input_share_duration_ns),
        ns_to_ms(timing.server_input_commitment_duration_ns),
        ns_to_ms(timing.server_input_transcript_duration_ns),
        ns_to_ms(timing.server_input_seal_duration_ns),
    )
}

#[derive(Debug, Clone, Copy)]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssPrepareServerCeremonyTimingFields {
    ceremony_ot_open_join_ms: f64,
    ceremony_ot_branch_key_derivation_ms: f64,
    ceremony_ot_branch_decrypt_ms: f64,
    ceremony_ot_point_scalar_reconstruction_ms: f64,
    ceremony_ot_commitment_verification_ms: f64,
    ceremony_server_input_open_ms: f64,
    ceremony_server_input_share_ms: f64,
    ceremony_server_input_commitment_ms: f64,
    ceremony_server_input_transcript_ms: f64,
    ceremony_result_assembly_ms: f64,
    ceremony_output_sealing_finalization_ms: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssFinalizeReportArgs {
    #[serde(default)]
    prepared_session_handle: String,
    garbler_driver_state_bytes: Vec<u8>,
    #[serde(default)]
    staged_evaluator_artifact_handle: String,
    staged_evaluator_artifact_bytes: Vec<u8>,
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
    timings: ThresholdEd25519HssFinalizeReportTimings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssOpenClientOutputArgs {
    pub(crate) evaluator_driver_state_b64u: String,
    pub(crate) client_output_message_b64u: String,
    pub(crate) client_output_mask_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519HssOpenClientOutputOutput {
    pub(crate) context_binding_b64u: String,
    pub(crate) x_client_base_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssOpenServerOutputArgs {
    #[serde(default)]
    prepared_session_handle: String,
    garbler_driver_state_bytes: Vec<u8>,
    server_output_message_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssOpenServerOutputOutput {
    context_binding_b64u: String,
    x_relayer_base_b64u: String,
}

#[cfg(feature = "hss-server-exports")]
thread_local! {
    static PREPARED_SERVER_SESSION_CACHE: RefCell<BTreeMap<String, PreparedSession>> =
        RefCell::new(BTreeMap::new());
}

#[cfg(feature = "hss-server-exports")]
static NEXT_PREPARED_SERVER_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "hss-server-exports")]
thread_local! {
    static STAGED_EVALUATOR_ARTIFACT_CACHE: RefCell<BTreeMap<String, StagedEvaluatorArtifact>> =
        RefCell::new(BTreeMap::new());
}

#[cfg(feature = "hss-server-exports")]
static NEXT_STAGED_EVALUATOR_ARTIFACT_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "hss-server-exports")]
fn cache_prepared_server_session(session: PreparedSession) -> String {
    let id = NEXT_PREPARED_SERVER_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let handle = format!("hss-prepared-{id:016x}");
    PREPARED_SERVER_SESSION_CACHE.with(|cache| {
        cache.borrow_mut().insert(handle.clone(), session);
    });
    handle
}

#[cfg(feature = "hss-server-exports")]
fn with_cached_prepared_server_session<T>(
    handle: &str,
    f: impl FnOnce(&PreparedSession) -> Result<T, String>,
) -> Result<Option<T>, String> {
    let trimmed = handle.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    PREPARED_SERVER_SESSION_CACHE.with(|cache| {
        let borrowed = cache.borrow();
        match borrowed.get(trimmed) {
            Some(session) => f(session).map(Some),
            None => Ok(None),
        }
    })
}

#[cfg(feature = "hss-server-exports")]
fn cache_staged_evaluator_artifact(artifact: StagedEvaluatorArtifact) -> String {
    let id = NEXT_STAGED_EVALUATOR_ARTIFACT_ID.fetch_add(1, Ordering::Relaxed);
    let handle = format!("hss-artifact-{id:016x}");
    STAGED_EVALUATOR_ARTIFACT_CACHE.with(|cache| {
        cache.borrow_mut().insert(handle.clone(), artifact);
    });
    handle
}

#[cfg(feature = "hss-server-exports")]
fn with_cached_staged_evaluator_artifact<T>(
    handle: &str,
    f: impl FnOnce(&StagedEvaluatorArtifact) -> Result<T, String>,
) -> Result<Option<T>, String> {
    let trimmed = handle.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    STAGED_EVALUATOR_ARTIFACT_CACHE.with(|cache| {
        let borrowed = cache.borrow();
        match borrowed.get(trimmed) {
            Some(artifact) => f(artifact).map(Some),
            None => Ok(None),
        }
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
pub(crate) struct ThresholdEd25519HssOpenSeedOutputArgs {
    #[serde(default)]
    prepared_session_handle: String,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShareArgs {
    x_client_base_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShareOutput {
    client_verifying_share_b64u: String,
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
#[cfg(feature = "hss-client-exports")]
pub fn threshold_ed25519_hss_derive_client_output_mask(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssDeriveClientOutputMaskArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        derive_threshold_ed25519_hss_client_output_mask(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS client output mask output: {e}"
        ))
    })
}

#[wasm_bindgen]
#[cfg(feature = "hss-client-exports")]
pub fn threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssBuildClientOwnedStagedArtifactArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = build_threshold_ed25519_hss_client_owned_staged_evaluator_artifact(args)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS client-owned staged artifact output: {e}"
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
    Reflect::set(
        &js_output,
        &JsValue::from_str("preparedSessionHandle"),
        &JsValue::from_str(&output.prepared_session_handle),
    )
    .map_err(|_| JsValue::from_str("Failed to set preparedSessionHandle"))?;
    let timings = serde_wasm_bindgen::to_value(&output.timings).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS prepared server-session timings: {e}"
        ))
    })?;
    Reflect::set(&js_output, &JsValue::from_str("timings"), &timings)
        .map_err(|_| JsValue::from_str("Failed to set timings"))?;
    Ok(js_output.into())
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_release_prepared_server_session(handle: String) {
    let trimmed = handle.trim().to_string();
    if trimmed.is_empty() {
        return;
    }
    PREPARED_SERVER_SESSION_CACHE.with(|cache| {
        cache.borrow_mut().remove(&trimmed);
    });
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_release_staged_evaluator_artifact(handle: String) {
    let trimmed = handle.trim().to_string();
    if trimmed.is_empty() {
        return;
    }
    STAGED_EVALUATOR_ARTIFACT_CACHE.with(|cache| {
        cache.borrow_mut().remove(&trimmed);
    });
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_finalize_report(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssFinalizeReportArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let (report, decode_artifact_ms, serialized_session_materialize_ms, finalize_report_ms) =
        if let Some(report) = with_cached_staged_evaluator_artifact(
            &args.staged_evaluator_artifact_handle,
            |artifact| {
                with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
                    let finalize_report_started = Date::now();
                    session
                        .shared_runtime()
                        .finalize_report_from_staged_evaluator_artifact(
                            &session.garbler_session(),
                            artifact,
                        )
                        .map(|report| {
                            (
                                report,
                                0.0,
                                0.0,
                                (Date::now() - finalize_report_started).max(0.0),
                            )
                        })
                        .map_err(|e| e.to_string())
                })?
                .ok_or_else(|| {
                    "missing prepared-session cache entry for staged evaluator artifact".to_string()
                })
            },
        )
        .map_err(|e| JsValue::from_str(&e))?
        {
            report
        } else {
            let decode_artifact_started = Date::now();
            let staged_evaluator_artifact: StagedEvaluatorArtifact = decode_state_blob_bytes(
                &args.staged_evaluator_artifact_bytes,
                "stagedEvaluatorArtifactBytes",
            )?;
            let decode_artifact_ms = (Date::now() - decode_artifact_started).max(0.0);
            if let Some(report) =
                with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
                    let finalize_report_started = Date::now();
                    session
                        .shared_runtime()
                        .finalize_report_from_staged_evaluator_artifact(
                            &session.garbler_session(),
                            &staged_evaluator_artifact,
                        )
                        .map(|report| {
                            (
                                report,
                                decode_artifact_ms,
                                0.0,
                                (Date::now() - finalize_report_started).max(0.0),
                            )
                        })
                        .map_err(|e| e.to_string())
                })
                .map_err(|e| JsValue::from_str(&e))?
            {
                report
            } else {
                let serialized_session_materialize_started = Date::now();
                let garbler_state: ServerDriverState = decode_state_blob_bytes(
                    &args.garbler_driver_state_bytes,
                    "garblerDriverStateBytes",
                )
                .map_err(js_value_to_string)?;
                let (runtime, garbler_session) = garbler_state
                    .materialize()
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let serialized_session_materialize_ms =
                    (Date::now() - serialized_session_materialize_started).max(0.0);
                let finalize_report_started = Date::now();
                let report = runtime
                    .finalize_report_from_staged_evaluator_artifact(
                        &garbler_session,
                        &staged_evaluator_artifact,
                    )
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
                let finalize_report_ms = (Date::now() - finalize_report_started).max(0.0);
                (
                    report,
                    decode_artifact_ms,
                    serialized_session_materialize_ms,
                    finalize_report_ms,
                )
            }
        };

    let encode_report_started = Date::now();
    let evaluation_report_json = serde_json::to_string(&report)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize evaluation report: {e}")))?;
    let client_output_message_b64u = encode_wire_message(&report.output_delivery.client);
    let seed_output_message_b64u = encode_wire_message(&report.output_delivery.seed);
    let server_output_message_b64u = encode_wire_message(&report.output_delivery.server);
    let encode_report_ms = (Date::now() - encode_report_started).max(0.0);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssFinalizeReportOutput {
        context_binding_b64u: base64_url_encode(&report.artifact.context_binding),
        evaluation_report_json,
        client_output_message_b64u,
        seed_output_message_b64u,
        server_output_message_b64u,
        timings: ThresholdEd25519HssFinalizeReportTimings {
            decode_artifact_ms,
            serialized_session_materialize_ms,
            finalize_report_ms,
            encode_report_ms,
        },
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS finalization output: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_prepare_server_ceremony(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssBuildServerOwnedStagedArtifactArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        prepare_threshold_ed25519_hss_server_ceremony(args).map_err(|e| JsValue::from_str(&e))?;
    let js_output = Object::new();
    Reflect::set(
        &js_output,
        &JsValue::from_str("contextBindingB64u"),
        &JsValue::from_str(&output.context_binding_b64u),
    )
    .map_err(|_| JsValue::from_str("Failed to set contextBindingB64u"))?;
    Reflect::set(
        &js_output,
        &JsValue::from_str("stagedEvaluatorArtifactHandle"),
        &JsValue::from_str(&output.staged_evaluator_artifact_handle),
    )
    .map_err(|_| JsValue::from_str("Failed to set stagedEvaluatorArtifactHandle"))?;
    let timings = serde_wasm_bindgen::to_value(&output.timings).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS server ceremony timings: {e}"
        ))
    })?;
    Reflect::set(&js_output, &JsValue::from_str("timings"), &timings)
        .map_err(|_| JsValue::from_str("Failed to set timings"))?;
    Ok(js_output.into())
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_prepare_role_separated_server_input_delivery(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = prepare_threshold_ed25519_hss_role_separated_server_input_delivery(args)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS role-separated server-input delivery: {e}"
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
    let server_output_message =
        decode_wire_message(&args.server_output_message_b64u, "serverOutputMessageB64u")?;
    let (context_binding, x_relayer_base) = if let Some(output) =
        with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
            let x_relayer_base = session
                .garbler_session()
                .server_output_opener()
                .open(&server_output_message)
                .map_err(|e| e.to_string())?;
            Ok((session.candidate().context_binding, x_relayer_base))
        })
        .map_err(|e| JsValue::from_str(&e))?
    {
        output
    } else {
        let garbler_state: ServerDriverState =
            decode_state_blob_bytes(&args.garbler_driver_state_bytes, "garblerDriverStateBytes")
                .map_err(js_value_to_string)?;
        let (_runtime, garbler_session) = garbler_state
            .materialize()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let x_relayer_base = garbler_session
            .server_output_opener()
            .open(&server_output_message)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        (
            garbler_state.garbler_session.context_binding,
            x_relayer_base,
        )
    };

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssOpenServerOutputOutput {
        context_binding_b64u: base64_url_encode(&context_binding),
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

#[wasm_bindgen]
pub fn threshold_ed25519_role_separated_client_verifying_share_from_base_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShareArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let x_client_base = decode_fixed_32(&args.x_client_base_b64u, "xClientBaseB64u")?;
    let client_verifying_share = role_separated_ed25519_client_verifying_share_v1(x_client_base)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(
        &ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShareOutput {
            client_verifying_share_b64u: base64_url_encode(&client_verifying_share),
        },
    )
    .map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize role-separated client verifying share: {e}"
        ))
    })
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn canonical_context_from_args(
    args: ThresholdEd25519HssCanonicalContextArgs,
) -> Result<CanonicalContext, JsValue> {
    let application_binding_digest_b64u = args.application_binding_digest_b64u.trim();
    if application_binding_digest_b64u.is_empty() {
        return Err(JsValue::from_str("Missing applicationBindingDigestB64u"));
    }
    let application_binding_digest = decode_fixed_32(
        application_binding_digest_b64u,
        "applicationBindingDigestB64u",
    )?;

    Ok(CanonicalContext {
        application_binding_digest,
        participant_ids: args.participant_ids,
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
    let bytes = encode_state_blob_bytes(value, field_name)?;
    Ok(base64_url_encode(&bytes))
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn encode_state_blob_bytes<T: Serialize>(value: &T, field_name: &str) -> Result<Vec<u8>, String> {
    bincode::serialize(value).map_err(|e| format!("Failed to serialize {field_name}: {e}"))
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
#[cfg(feature = "hss-server-exports")]
fn decode_state_blob_bytes<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    field_name: &str,
) -> Result<T, JsValue> {
    bincode::deserialize::<T>(bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))
}

fn decode_fixed_32(value: &str, field_name: &str) -> Result<[u8; 32], JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    decode_fixed_32_bytes(&decoded, field_name)
}

fn decode_fixed_32_bytes(value: &[u8], field_name: &str) -> Result<[u8; 32], JsValue> {
    value
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field_name} must decode to 32 bytes")))
}

#[cfg(feature = "hss-server-exports")]
fn parse_operation(value: &str) -> Result<ServerEvalOperation, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "registration" => Ok(ServerEvalOperation::Registration),
        "txsigning" | "tx_signing" | "sign" => Ok(ServerEvalOperation::TxSigning),
        "linkdevice" | "link_device" => Ok(ServerEvalOperation::LinkDevice),
        "emailrecovery" | "email_recovery" => Ok(ServerEvalOperation::EmailRecovery),
        "warmsessionreconstruction" | "warm_session_reconstruction" => {
            Ok(ServerEvalOperation::WarmSessionReconstruction)
        }
        "export" | "explicitkeyexport" | "explicit_key_export" => {
            Ok(ServerEvalOperation::ExplicitKeyExport)
        }
        other => Err(format!("unknown server ceremony operation {other}")),
    }
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
fn decode_wire_message(value: &str, field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: base64_url_decode(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?,
    })
}

#[cfg(any(feature = "hss-client-exports", feature = "hss-server-exports"))]
#[cfg(feature = "hss-server-exports")]
fn decode_wire_message_bytes(bytes: &[u8], _field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: bytes.to_vec(),
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
        application_binding_digest_b64u: args.application_binding_digest_b64u,
        participant_ids: args.participant_ids,
    })
    .map_err(js_value_to_string)?;
    let evaluator_driver_state =
        prepare_prime_order_succinct_hss_client(&context).map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssPrepareSessionOutput {
        application_binding_digest_b64u: base64_url_encode(&context.application_binding_digest),
        participant_ids: context.participant_ids,
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
        application_binding_digest_b64u: args.application_binding_digest_b64u,
        participant_ids: args.participant_ids,
    })
    .map_err(js_value_to_string)?;
    let prepare_session_started = Date::now();
    let session = prepare_prime_order_succinct_hss(&context).map_err(|e| e.to_string())?;
    let prepare_session_ms = (Date::now() - prepare_session_started).max(0.0);
    let extract_driver_states_started = Date::now();
    let evaluator_driver_state = session.evaluator_driver_state();
    let garbler_driver_state = session.garbler_driver_state();
    let extract_driver_states_ms = (Date::now() - extract_driver_states_started).max(0.0);
    let client_offer_message_started = Date::now();
    let client_ot_offer_message = session
        .garbler_session()
        .client_ot_offer_message()
        .map_err(|e| e.to_string())?;
    let client_offer_message_ms = (Date::now() - client_offer_message_started).max(0.0);
    let cache_prepared_session_started = Date::now();
    let prepared_session_handle = cache_prepared_server_session(session);
    let cache_prepared_session_ms = (Date::now() - cache_prepared_session_started).max(0.0);
    let encode_states_started = Date::now();
    let evaluator_driver_state_b64u =
        encode_state_blob(&evaluator_driver_state, "evaluator state")?;
    let garbler_driver_state_b64u = encode_state_blob(&garbler_driver_state, "garbler state")?;
    let client_ot_offer_message_b64u = encode_wire_message(&client_ot_offer_message);
    let encode_states_ms = (Date::now() - encode_states_started).max(0.0);

    Ok(ThresholdEd25519HssPrepareServerSessionOutput {
        context_binding_b64u: base64_url_encode(
            &garbler_driver_state.garbler_session.context_binding,
        ),
        evaluator_driver_state_b64u,
        garbler_driver_state_b64u,
        client_ot_offer_message_b64u,
        prepared_session_handle,
        timings: ThresholdEd25519HssPrepareServerSessionTimings {
            prepare_session_ms,
            extract_driver_states_ms,
            client_offer_message_ms,
            cache_prepared_session_ms,
            encode_states_ms,
        },
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
        client_request_message_b64u: encode_wire_message(&client_request_message),
        evaluator_ot_state_b64u: encode_state_blob(&evaluator_ot_state, "evaluator OT state")?,
    })
}

#[cfg(feature = "hss-client-exports")]
pub(crate) fn derive_threshold_ed25519_hss_client_output_mask(
    args: ThresholdEd25519HssDeriveClientOutputMaskArgs,
) -> Result<ThresholdEd25519HssDeriveClientOutputMaskOutput, String> {
    let client_recoverable_secret = decode_fixed_32(
        &args.client_recoverable_secret_b64u,
        "clientRecoverableSecretB64u",
    )
    .map_err(js_value_to_string)?;
    let operation = args
        .operation
        .parse::<ClientOutputMaskOperation>()
        .map_err(|e| e.to_string())?;
    let context_binding = decode_fixed_32(&args.context_binding_b64u, "contextBindingB64u")
        .map_err(js_value_to_string)?;
    let canonical_context = canonical_context_from_args(ThresholdEd25519HssCanonicalContextArgs {
        application_binding_digest_b64u: args.application_binding_digest_b64u,
        participant_ids: args.participant_ids,
    })
    .map_err(js_value_to_string)?;
    let client_output_mask = derive_client_output_mask(
        client_recoverable_secret,
        &ClientOutputMaskContext {
            canonical_context,
            context_binding,
            operation,
            server_key_id: args.relayer_key_id.trim().to_string(),
        },
    )
    .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssDeriveClientOutputMaskOutput {
        client_output_mask_b64u: base64_url_encode(&client_output_mask),
    })
}

#[cfg(feature = "hss-client-exports")]
pub(crate) fn build_threshold_ed25519_hss_client_owned_staged_evaluator_artifact(
    args: ThresholdEd25519HssBuildClientOwnedStagedArtifactArgs,
) -> Result<ThresholdEd25519HssBuildClientOwnedStagedArtifactOutput, String> {
    let evaluator_state: ClientDriverState = decode_state_blob(
        &args.evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
    )
    .map_err(js_value_to_string)?;
    let evaluator_ot_state: ClientOtState =
        decode_state_blob(&args.evaluator_ot_state_b64u, "evaluatorOtStateB64u")
            .map_err(js_value_to_string)?;
    let server_input_delivery: RoleSeparatedServerInputDeliveryPacket =
        decode_state_blob(&args.server_input_delivery_b64u, "serverInputDeliveryB64u")
            .map_err(js_value_to_string)?;
    let client_output_mask = decode_fixed_32(&args.client_output_mask_b64u, "clientOutputMaskB64u")
        .map_err(js_value_to_string)?;
    let client_request_message = decode_wire_message(
        &args.client_request_message_b64u,
        "clientRequestMessageB64u",
    )
    .map_err(js_value_to_string)?;
    let (runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
    let artifact = evaluator_session
        .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_message(
            &runtime,
            &client_request_message,
            &evaluator_ot_state,
            &server_input_delivery,
            client_output_mask,
        )
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519HssBuildClientOwnedStagedArtifactOutput {
        context_binding_b64u: base64_url_encode(&evaluator_state.evaluator_session.context_binding),
        staged_evaluator_artifact_b64u: encode_state_blob(&artifact, "staged evaluator artifact")?,
    })
}

#[cfg(feature = "hss-server-exports")]
fn prepare_threshold_ed25519_hss_server_ceremony(
    args: ThresholdEd25519HssBuildServerOwnedStagedArtifactArgs,
) -> Result<ThresholdEd25519HssPrepareServerCeremonyOutput, String> {
    if let Some(output) =
        with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
            let operation = parse_operation(&args.operation)?;
            let decode_states_started = Date::now();
            let evaluator_ot_state: ClientOtState =
                decode_state_blob_bytes(&args.evaluator_ot_state_bytes, "evaluatorOtStateBytes")
                    .map_err(js_value_to_string)?;
            let decode_states_ms = (Date::now() - decode_states_started).max(0.0);

            let decode_messages_started = Date::now();
            let client_request_message = decode_wire_message_bytes(
                &args.client_request_message_bytes,
                "clientRequestMessageBytes",
            )
            .map_err(js_value_to_string)?;
            let y_relayer = decode_fixed_32_bytes(&args.y_relayer_bytes, "yRelayerBytes")
                .map_err(js_value_to_string)?;
            let tau_relayer = decode_fixed_32_bytes(&args.tau_relayer_bytes, "tauRelayerBytes")
                .map_err(js_value_to_string)?;
            let decode_messages_ms = (Date::now() - decode_messages_started).max(0.0);

            let ceremony_core_started = Date::now();
            let (staged_evaluator_artifact, stage_profile, evaluate_timing) = session
                .garbler_session()
                .build_staged_evaluator_artifact_from_transport_messages_profiled_with_pool(
                    &session.shared_runtime(),
                    &session.evaluator_session(),
                    &evaluator_ot_state,
                    &client_request_message,
                    y_relayer,
                    tau_relayer,
                    operation,
                    session.hidden_eval_constants(),
                )
                .map_err(|e| e.to_string())?;
            let ceremony_core_ms = (Date::now() - ceremony_core_started).max(0.0);
            let timing_fields = ceremony_timing_fields(evaluate_timing);

            let encode_artifact_started = Date::now();
            let staged_evaluator_artifact_handle =
                cache_staged_evaluator_artifact(staged_evaluator_artifact);
            let encode_artifact_ms = (Date::now() - encode_artifact_started).max(0.0);

            Ok(ThresholdEd25519HssPrepareServerCeremonyOutput {
                context_binding_b64u: base64_url_encode(&session.candidate().context_binding),
                staged_evaluator_artifact_handle,
                timings: ThresholdEd25519HssPrepareServerCeremonyTimings {
                    decode_states_ms,
                    decode_messages_ms,
                    materialize_runtime_ms: 0.0,
                    materialize_sessions_ms: 0.0,
                    ceremony_core_ms,
                    ceremony_ot_open_join_ms: timing_fields.ceremony_ot_open_join_ms,
                    ceremony_ot_branch_key_derivation_ms: timing_fields
                        .ceremony_ot_branch_key_derivation_ms,
                    ceremony_ot_branch_decrypt_ms: timing_fields.ceremony_ot_branch_decrypt_ms,
                    ceremony_ot_point_scalar_reconstruction_ms: timing_fields
                        .ceremony_ot_point_scalar_reconstruction_ms,
                    ceremony_ot_commitment_verification_ms: timing_fields
                        .ceremony_ot_commitment_verification_ms,
                    ceremony_server_input_open_ms: timing_fields.ceremony_server_input_open_ms,
                    ceremony_server_input_share_ms: timing_fields.ceremony_server_input_share_ms,
                    ceremony_server_input_commitment_ms: timing_fields
                        .ceremony_server_input_commitment_ms,
                    ceremony_server_input_transcript_ms: timing_fields
                        .ceremony_server_input_transcript_ms,
                    ceremony_add_stage_ms: (stage_profile.add_stage_duration_ns as f64)
                        / 1_000_000.0,
                    ceremony_message_schedule_ms: (stage_profile.message_schedule_duration_ns
                        as f64)
                        / 1_000_000.0,
                    ceremony_round_core_ms: (stage_profile.round_core_duration_ns as f64)
                        / 1_000_000.0,
                    ceremony_output_projector_ms: (stage_profile.output_projector_duration_ns
                        as f64)
                        / 1_000_000.0,
                    ceremony_result_assembly_ms: timing_fields.ceremony_result_assembly_ms,
                    ceremony_output_sealing_finalization_ms: timing_fields
                        .ceremony_output_sealing_finalization_ms,
                    encode_artifact_ms,
                },
            })
        })?
    {
        return Ok(output);
    }

    let decode_states_started = Date::now();
    let evaluator_state: ClientDriverState = decode_state_blob_bytes(
        &args.evaluator_driver_state_bytes,
        "evaluatorDriverStateBytes",
    )
    .map_err(js_value_to_string)?;
    let garbler_state: ServerDriverState =
        decode_state_blob_bytes(&args.garbler_driver_state_bytes, "garblerDriverStateBytes")
            .map_err(js_value_to_string)?;
    let evaluator_ot_state: ClientOtState =
        decode_state_blob_bytes(&args.evaluator_ot_state_bytes, "evaluatorOtStateBytes")
            .map_err(js_value_to_string)?;
    let decode_states_ms = (Date::now() - decode_states_started).max(0.0);

    let decode_messages_started = Date::now();
    let client_request_message = decode_wire_message_bytes(
        &args.client_request_message_bytes,
        "clientRequestMessageBytes",
    )
    .map_err(js_value_to_string)?;
    let y_relayer = decode_fixed_32_bytes(&args.y_relayer_bytes, "yRelayerBytes")
        .map_err(js_value_to_string)?;
    let tau_relayer = decode_fixed_32_bytes(&args.tau_relayer_bytes, "tauRelayerBytes")
        .map_err(js_value_to_string)?;
    let decode_messages_ms = (Date::now() - decode_messages_started).max(0.0);
    let operation = parse_operation(&args.operation)?;

    if evaluator_state.runtime != garbler_state.runtime {
        return Err(
            "evaluatorDriverStateBytes and garblerDriverStateBytes do not share the same prepared runtime"
                .to_string(),
        );
    }
    let materialize_runtime_started = Date::now();
    let runtime = evaluator_state
        .runtime
        .materialize()
        .map_err(|e| e.to_string())?;
    let materialize_runtime_ms = (Date::now() - materialize_runtime_started).max(0.0);

    let materialize_sessions_started = Date::now();
    let evaluator_session = evaluator_state
        .evaluator_session
        .materialize()
        .map_err(|e| e.to_string())?;
    let garbler_session = garbler_state
        .garbler_session
        .materialize()
        .map_err(|e| e.to_string())?;
    let materialize_sessions_ms = (Date::now() - materialize_sessions_started).max(0.0);

    let ceremony_core_started = Date::now();
    let (staged_evaluator_artifact, stage_profile, evaluate_timing) = garbler_session
        .build_staged_evaluator_artifact_from_transport_messages_profiled(
            &runtime,
            &evaluator_session,
            &evaluator_ot_state,
            &client_request_message,
            y_relayer,
            tau_relayer,
            operation,
        )
        .map_err(|e| e.to_string())?;
    let ceremony_core_ms = (Date::now() - ceremony_core_started).max(0.0);
    let timing_fields = ceremony_timing_fields(evaluate_timing);

    let encode_artifact_started = Date::now();
    let staged_evaluator_artifact_handle =
        cache_staged_evaluator_artifact(staged_evaluator_artifact);
    let encode_artifact_ms = (Date::now() - encode_artifact_started).max(0.0);

    Ok(ThresholdEd25519HssPrepareServerCeremonyOutput {
        context_binding_b64u: base64_url_encode(&evaluator_state.evaluator_session.context_binding),
        staged_evaluator_artifact_handle,
        timings: ThresholdEd25519HssPrepareServerCeremonyTimings {
            decode_states_ms,
            decode_messages_ms,
            materialize_runtime_ms,
            materialize_sessions_ms,
            ceremony_core_ms,
            ceremony_ot_open_join_ms: timing_fields.ceremony_ot_open_join_ms,
            ceremony_ot_branch_key_derivation_ms: timing_fields
                .ceremony_ot_branch_key_derivation_ms,
            ceremony_ot_branch_decrypt_ms: timing_fields.ceremony_ot_branch_decrypt_ms,
            ceremony_ot_point_scalar_reconstruction_ms: timing_fields
                .ceremony_ot_point_scalar_reconstruction_ms,
            ceremony_ot_commitment_verification_ms: timing_fields
                .ceremony_ot_commitment_verification_ms,
            ceremony_server_input_open_ms: timing_fields.ceremony_server_input_open_ms,
            ceremony_server_input_share_ms: timing_fields.ceremony_server_input_share_ms,
            ceremony_server_input_commitment_ms: timing_fields.ceremony_server_input_commitment_ms,
            ceremony_server_input_transcript_ms: timing_fields.ceremony_server_input_transcript_ms,
            ceremony_add_stage_ms: (stage_profile.add_stage_duration_ns as f64) / 1_000_000.0,
            ceremony_message_schedule_ms: (stage_profile.message_schedule_duration_ns as f64)
                / 1_000_000.0,
            ceremony_round_core_ms: (stage_profile.round_core_duration_ns as f64) / 1_000_000.0,
            ceremony_output_projector_ms: (stage_profile.output_projector_duration_ns as f64)
                / 1_000_000.0,
            ceremony_result_assembly_ms: timing_fields.ceremony_result_assembly_ms,
            ceremony_output_sealing_finalization_ms: timing_fields
                .ceremony_output_sealing_finalization_ms,
            encode_artifact_ms,
        },
    })
}

#[cfg(feature = "hss-server-exports")]
fn prepare_threshold_ed25519_hss_role_separated_server_input_delivery(
    args: ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryArgs,
) -> Result<ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryOutput, String> {
    let operation = parse_operation(&args.operation)?;
    let decode_messages_started = Date::now();
    let client_request_message = decode_wire_message_bytes(
        &args.client_request_message_bytes,
        "clientRequestMessageBytes",
    )
    .map_err(js_value_to_string)?;
    let y_relayer = decode_fixed_32_bytes(&args.y_relayer_bytes, "yRelayerBytes")
        .map_err(js_value_to_string)?;
    let tau_relayer = decode_fixed_32_bytes(&args.tau_relayer_bytes, "tauRelayerBytes")
        .map_err(js_value_to_string)?;
    let decode_messages_ms = (Date::now() - decode_messages_started).max(0.0);

    if let Some(output) =
        with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
            let prepare_delivery_started = Date::now();
            let (delivery, _state, delivery_timing) = session
                .garbler_session()
                .prepare_role_separated_server_input_delivery_message_timed(
                    &client_request_message,
                    y_relayer,
                    tau_relayer,
                    operation,
                )
                .map_err(|e| e.to_string())?;
            let prepare_delivery_ms = (Date::now() - prepare_delivery_started).max(0.0);
            let (
                delivery_ot_open_join_ms,
                delivery_server_input_open_ms,
                delivery_server_input_share_ms,
                delivery_server_input_commitment_ms,
                delivery_server_input_transcript_ms,
                delivery_server_input_seal_ms,
            ) = server_input_delivery_timing_fields(delivery_timing);
            let encode_delivery_started = Date::now();
            let server_input_delivery_b64u =
                encode_state_blob(&delivery, "role-separated server input delivery")?;
            let encode_delivery_ms = (Date::now() - encode_delivery_started).max(0.0);
            Ok(
                ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryOutput {
                    context_binding_b64u: base64_url_encode(&delivery.context_binding),
                    server_input_delivery_b64u,
                    timings: ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryTimings {
                        decode_messages_ms,
                        materialize_session_ms: 0.0,
                        prepare_delivery_ms,
                        delivery_ot_open_join_ms,
                        delivery_server_input_open_ms,
                        delivery_server_input_share_ms,
                        delivery_server_input_commitment_ms,
                        delivery_server_input_transcript_ms,
                        delivery_server_input_seal_ms,
                        encode_delivery_ms,
                    },
                },
            )
        })?
    {
        return Ok(output);
    }

    let materialize_session_started = Date::now();
    let garbler_state: ServerDriverState =
        decode_state_blob_bytes(&args.garbler_driver_state_bytes, "garblerDriverStateBytes")
            .map_err(js_value_to_string)?;
    let (_runtime, garbler_session) = garbler_state.materialize().map_err(|e| e.to_string())?;
    let materialize_session_ms = (Date::now() - materialize_session_started).max(0.0);

    let prepare_delivery_started = Date::now();
    let (delivery, _state, delivery_timing) = garbler_session
        .prepare_role_separated_server_input_delivery_message_timed(
            &client_request_message,
            y_relayer,
            tau_relayer,
            operation,
        )
        .map_err(|e| e.to_string())?;
    let prepare_delivery_ms = (Date::now() - prepare_delivery_started).max(0.0);
    let (
        delivery_ot_open_join_ms,
        delivery_server_input_open_ms,
        delivery_server_input_share_ms,
        delivery_server_input_commitment_ms,
        delivery_server_input_transcript_ms,
        delivery_server_input_seal_ms,
    ) = server_input_delivery_timing_fields(delivery_timing);

    let encode_delivery_started = Date::now();
    let server_input_delivery_b64u =
        encode_state_blob(&delivery, "role-separated server input delivery")?;
    let encode_delivery_ms = (Date::now() - encode_delivery_started).max(0.0);

    Ok(
        ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryOutput {
            context_binding_b64u: base64_url_encode(&delivery.context_binding),
            server_input_delivery_b64u,
            timings: ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryTimings {
                decode_messages_ms,
                materialize_session_ms,
                prepare_delivery_ms,
                delivery_ot_open_join_ms,
                delivery_server_input_open_ms,
                delivery_server_input_share_ms,
                delivery_server_input_commitment_ms,
                delivery_server_input_transcript_ms,
                delivery_server_input_seal_ms,
                encode_delivery_ms,
            },
        },
    )
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
    let client_output_mask = decode_fixed_32(&args.client_output_mask_b64u, "clientOutputMaskB64u")
        .map_err(js_value_to_string)?;
    let opener = evaluator_session.client_output_opener();
    let x_client_base = opener
        .open_masked(&client_output_message, client_output_mask)
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
    let seed_output_message =
        decode_wire_message(&args.seed_output_message_b64u, "seedOutputMessageB64u")
            .map_err(js_value_to_string)?;
    #[cfg(feature = "hss-server-exports")]
    if let Some(output) =
        with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
            let canonical_seed = session
                .evaluator_session()
                .seed_output_opener()
                .open(&seed_output_message)
                .map_err(|e| e.to_string())?;
            Ok((session.candidate().context_binding, canonical_seed))
        })?
    {
        return Ok(ThresholdEd25519HssOpenSeedOutputOutput {
            context_binding_b64u: base64_url_encode(&output.0),
            canonical_seed_b64u: base64_url_encode(&output.1),
        });
    }

    let evaluator_state: ClientDriverState = decode_state_blob(
        &args.evaluator_driver_state_b64u,
        "evaluatorDriverStateB64u",
    )
    .map_err(js_value_to_string)?;
    let (_runtime, evaluator_session) = evaluator_state.materialize().map_err(|e| e.to_string())?;
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
