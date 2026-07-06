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
use ed25519_hss::runtime::flow::{
    advance_server_eval_state_to_output_projection_request_profiled as crate_advance_server_eval_state_to_output_projection_request_profiled,
    advance_server_eval_state_with_advance_context_profiled as crate_advance_server_eval_state_with_advance_context_profiled,
    finalize_advanced_server_eval_state_with_output_projection_profiled as crate_finalize_advanced_server_eval_state_with_output_projection_profiled,
    finalize_server_eval_state_from_add_stage_request_profiled as crate_finalize_server_eval_state_from_add_stage_request_profiled,
    AdvancedServerEvalState, FinalizedServerEvalState, ServerEvalAdvanceTimingsMs,
};
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::runtime::EvaluateTiming;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::runtime::SharedRuntimeFinalizeContext;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerDriverState;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerEvalExecutionState;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerEvalFinalizeOutput;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerEvalOperation;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerEvalState;
#[cfg(feature = "hss-server-exports")]
use ed25519_hss::server::ServerEvalStatus;
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
#[cfg(feature = "hss-server-exports")]
use sha2::{Digest, Sha256};
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
    add_stage_request_message_b64u: String,
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
    server_eval_finalize_output_b64u: String,
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
    server_eval_state_b64u: String,
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
    serialized_session_decode_ms: f64,
    materialize_runtime_ms: f64,
    materialize_evaluator_session_ms: f64,
    materialize_garbler_session_ms: f64,
    advance_add_stage_response_ms: f64,
    advance_message_schedule_rounds_ms: f64,
    advance_round_core_rounds_ms: f64,
    advance_output_projection_ms: f64,
    finalize_report_ms: f64,
    finalize_packet_assembly_ms: f64,
    encode_report_ms: f64,
    open_server_output_ms: f64,
    open_seed_output_ms: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssAdvanceServerEvalStateArgs {
    #[serde(default)]
    prepared_session_handle: String,
    evaluator_driver_state_bytes: Vec<u8>,
    garbler_driver_state_bytes: Vec<u8>,
    server_eval_state_bytes: Vec<u8>,
    add_stage_request_message_bytes: Vec<u8>,
    projection_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssFinalizeAdvancedReportArgs {
    #[serde(default)]
    prepared_session_handle: String,
    evaluator_driver_state_bytes: Vec<u8>,
    garbler_driver_state_bytes: Vec<u8>,
    staged_evaluator_artifact_bytes: Vec<u8>,
    advanced_server_eval_state_bytes: Vec<u8>,
    finalize_context_bytes: Vec<u8>,
    prior_stage_response_message_bytes: Vec<u8>,
    #[serde(default)]
    open_seed_output: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssBoundaryCopyProbeArgs {
    evaluator_driver_state_bytes: Vec<u8>,
    garbler_driver_state_bytes: Vec<u8>,
    #[serde(default)]
    server_eval_state_bytes: Vec<u8>,
    #[serde(default)]
    add_stage_request_message_bytes: Vec<u8>,
    #[serde(default)]
    staged_evaluator_artifact_bytes: Vec<u8>,
    #[serde(default)]
    advanced_server_eval_state_bytes: Vec<u8>,
    #[serde(default)]
    finalize_context_bytes: Vec<u8>,
    #[serde(default)]
    prior_stage_response_message_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssBoundaryCopyProbeOutput {
    total_payload_bytes: usize,
    non_empty_field_count: usize,
    checksum: u8,
    timings: ThresholdEd25519HssBoundaryCopyProbeTimings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssBoundaryCopyProbeTimings {
    decode_args_ms: f64,
    summarize_ms: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssServerEvalStateSizeCensusArgs {
    server_eval_state_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssServerEvalStateSizeCensusOutput {
    total_messagepack_bytes: usize,
    status: String,
    current_stage: String,
    operation: String,
    execution_state_kind: String,
    fields: Vec<ThresholdEd25519HssStateFieldSize>,
    execution_state_fields: Vec<ThresholdEd25519HssStateFieldSize>,
    timings: ThresholdEd25519HssServerEvalStateSizeCensusTimings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssStateFieldSize {
    label: String,
    messagepack_bytes: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssServerEvalStateSizeCensusTimings {
    decode_state_ms: f64,
    summarize_ms: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssAdvanceServerEvalStateOutput {
    context_binding_b64u: String,
    advanced_server_eval_state_b64u: String,
    finalize_context_b64u: String,
    prior_stage_response_message_b64u: String,
    add_stage_request_digest_b64u: String,
    projection_mode: String,
    timings: ThresholdEd25519HssAdvanceServerEvalStateTimings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssAdvanceServerEvalStateTimings {
    decode_state_ms: f64,
    serialized_session_materialize_ms: f64,
    serialized_session_decode_ms: f64,
    materialize_runtime_ms: f64,
    materialize_evaluator_session_ms: f64,
    materialize_garbler_session_ms: f64,
    advance_add_stage_response_ms: f64,
    advance_message_schedule_rounds_ms: f64,
    advance_round_core_rounds_ms: f64,
    advance_output_projection_ms: f64,
    encode_advanced_state_ms: f64,
}

#[cfg(feature = "hss-server-exports")]
type ThresholdEd25519HssServerEvalAdvanceTimings = ServerEvalAdvanceTimingsMs;

#[cfg(feature = "hss-server-exports")]
type ThresholdEd25519HssFinalizedServerEvalState = FinalizedServerEvalState;

#[cfg(feature = "hss-server-exports")]
type ThresholdEd25519HssAdvancedServerEvalState = AdvancedServerEvalState;

#[cfg(feature = "hss-server-exports")]
fn empty_threshold_ed25519_hss_server_eval_advance_timings(
) -> ThresholdEd25519HssServerEvalAdvanceTimings {
    ThresholdEd25519HssServerEvalAdvanceTimings::default()
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssSerializedSessionMaterializeTimings {
    total_ms: f64,
    decode_ms: f64,
    materialize_runtime_ms: f64,
    materialize_evaluator_session_ms: f64,
    materialize_garbler_session_ms: f64,
}

#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssMaterializedSerializedSession {
    runtime: ed25519_hss::runtime::SharedRuntime,
    evaluator_session: ed25519_hss::client::ClientSession,
    garbler_session: ed25519_hss::server::ServerSession,
    timings: ThresholdEd25519HssSerializedSessionMaterializeTimings,
}

#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssMaterializedSerializedAdvanceSession {
    advance_runtime: ed25519_hss::runtime::SharedRuntimeAdvanceMaterial,
    evaluator_session: ed25519_hss::client::ClientSession,
    garbler_session: ed25519_hss::server::ServerSession,
    context_binding: [u8; 32],
    timings: ThresholdEd25519HssSerializedSessionMaterializeTimings,
}

#[cfg(feature = "hss-server-exports")]
fn materialize_threshold_ed25519_hss_serialized_session(
    evaluator_driver_state_bytes: &[u8],
    garbler_driver_state_bytes: &[u8],
) -> Result<ThresholdEd25519HssMaterializedSerializedSession, JsValue> {
    let total_started = Date::now();
    let decode_started = Date::now();
    let evaluator_state: ClientDriverState =
        decode_state_blob_bytes(evaluator_driver_state_bytes, "evaluatorDriverStateBytes")
            .map_err(js_value_to_string)?;
    let garbler_state: ServerDriverState =
        decode_state_blob_bytes(garbler_driver_state_bytes, "garblerDriverStateBytes")
            .map_err(js_value_to_string)?;
    if evaluator_state.runtime != garbler_state.runtime {
        return Err(JsValue::from_str(
            "evaluatorDriverStateBytes and garblerDriverStateBytes do not share the same prepared runtime",
        ));
    }
    let decode_ms = (Date::now() - decode_started).max(0.0);

    let materialize_runtime_started = Date::now();
    let runtime = evaluator_state
        .runtime
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let materialize_runtime_ms = (Date::now() - materialize_runtime_started).max(0.0);

    let materialize_evaluator_session_started = Date::now();
    let evaluator_session = evaluator_state
        .evaluator_session
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let materialize_evaluator_session_ms =
        (Date::now() - materialize_evaluator_session_started).max(0.0);

    let materialize_garbler_session_started = Date::now();
    let garbler_session = garbler_state
        .garbler_session
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let materialize_garbler_session_ms =
        (Date::now() - materialize_garbler_session_started).max(0.0);

    Ok(ThresholdEd25519HssMaterializedSerializedSession {
        runtime,
        evaluator_session,
        garbler_session,
        timings: ThresholdEd25519HssSerializedSessionMaterializeTimings {
            total_ms: (Date::now() - total_started).max(0.0),
            decode_ms,
            materialize_runtime_ms,
            materialize_evaluator_session_ms,
            materialize_garbler_session_ms,
        },
    })
}

#[cfg(feature = "hss-server-exports")]
fn materialize_threshold_ed25519_hss_serialized_advance_session(
    evaluator_driver_state_bytes: &[u8],
    garbler_driver_state_bytes: &[u8],
) -> Result<ThresholdEd25519HssMaterializedSerializedAdvanceSession, JsValue> {
    let total_started = Date::now();
    let decode_started = Date::now();
    let evaluator_state: ClientDriverState =
        decode_state_blob_bytes(evaluator_driver_state_bytes, "evaluatorDriverStateBytes")
            .map_err(js_value_to_string)?;
    let garbler_state: ServerDriverState =
        decode_state_blob_bytes(garbler_driver_state_bytes, "garblerDriverStateBytes")
            .map_err(js_value_to_string)?;
    if evaluator_state.runtime != garbler_state.runtime {
        return Err(JsValue::from_str(
            "evaluatorDriverStateBytes and garblerDriverStateBytes do not share the same prepared runtime",
        ));
    }
    let decode_ms = (Date::now() - decode_started).max(0.0);

    let materialize_runtime_started = Date::now();
    let advance_runtime = garbler_state
        .advance_runtime_material()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let materialize_runtime_ms = (Date::now() - materialize_runtime_started).max(0.0);

    let materialize_evaluator_session_started = Date::now();
    let evaluator_session = evaluator_state
        .evaluator_session
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let materialize_evaluator_session_ms =
        (Date::now() - materialize_evaluator_session_started).max(0.0);

    let materialize_garbler_session_started = Date::now();
    let context_binding = garbler_state.garbler_session.context_binding;
    let garbler_session = garbler_state
        .garbler_session
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let materialize_garbler_session_ms =
        (Date::now() - materialize_garbler_session_started).max(0.0);

    Ok(ThresholdEd25519HssMaterializedSerializedAdvanceSession {
        advance_runtime,
        evaluator_session,
        garbler_session,
        context_binding,
        timings: ThresholdEd25519HssSerializedSessionMaterializeTimings {
            total_ms: (Date::now() - total_started).max(0.0),
            decode_ms,
            materialize_runtime_ms,
            materialize_evaluator_session_ms,
            materialize_garbler_session_ms,
        },
    })
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
    evaluator_driver_state_bytes: Vec<u8>,
    garbler_driver_state_bytes: Vec<u8>,
    #[serde(default)]
    staged_evaluator_artifact_handle: String,
    staged_evaluator_artifact_bytes: Vec<u8>,
    server_eval_state_bytes: Vec<u8>,
    add_stage_request_message_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssFinalizeReportOutput {
    context_binding_b64u: String,
    client_output_message_b64u: String,
    seed_output_message_b64u: String,
    server_output_message_b64u: String,
    x_relayer_base_b64u: Option<String>,
    canonical_seed_b64u: Option<String>,
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
    static STAGED_EVALUATOR_ARTIFACT_CACHE: RefCell<BTreeMap<String, ServerOwnedStagedEvaluatorArtifact>> =
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
struct ServerOwnedStagedEvaluatorArtifact {
    artifact: StagedEvaluatorArtifact,
    server_output: ServerEvalFinalizeOutput,
}

#[cfg(feature = "hss-server-exports")]
fn cache_staged_evaluator_artifact(
    artifact: StagedEvaluatorArtifact,
    server_output: ServerEvalFinalizeOutput,
) -> String {
    let id = NEXT_STAGED_EVALUATOR_ARTIFACT_ID.fetch_add(1, Ordering::Relaxed);
    let handle = format!("hss-artifact-{id:016x}");
    STAGED_EVALUATOR_ARTIFACT_CACHE.with(|cache| {
        cache.borrow_mut().insert(
            handle.clone(),
            ServerOwnedStagedEvaluatorArtifact {
                artifact,
                server_output,
            },
        );
    });
    handle
}

#[cfg(feature = "hss-server-exports")]
fn with_cached_staged_evaluator_artifact<T>(
    handle: &str,
    f: impl FnOnce(&ServerOwnedStagedEvaluatorArtifact) -> Result<T, String>,
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

#[cfg(feature = "hss-server-exports")]
fn advance_server_eval_state_to_output_projection_request(
    runtime: &ed25519_hss::runtime::SharedRuntime,
    garbler_session: &ed25519_hss::server::ServerSession,
    evaluator_session: &ed25519_hss::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
) -> Result<ThresholdEd25519HssAdvancedServerEvalState, JsValue> {
    crate_advance_server_eval_state_to_output_projection_request_profiled(
        runtime,
        garbler_session,
        evaluator_session,
        server_eval_state,
        add_stage_request_message,
        Date::now,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(feature = "hss-server-exports")]
fn advance_server_eval_state_with_advance_context(
    advance_context: &ed25519_hss::runtime::SharedRuntimeAdvanceMaterial,
    garbler_session: &ed25519_hss::server::ServerSession,
    evaluator_session: &ed25519_hss::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
) -> Result<ThresholdEd25519HssAdvancedServerEvalState, JsValue> {
    crate_advance_server_eval_state_with_advance_context_profiled(
        advance_context,
        garbler_session,
        evaluator_session,
        server_eval_state,
        add_stage_request_message,
        Date::now,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(feature = "hss-server-exports")]
fn finalize_advanced_server_eval_state_with_output_projection(
    garbler_session: &ed25519_hss::server::ServerSession,
    evaluator_session: &ed25519_hss::client::ClientSession,
    server_eval_state: &ServerEvalState,
    prior_stage_response_message: &WireMessage,
    projection_mode: &ed25519_hss::wire::OutputProjectionMode,
) -> Result<ThresholdEd25519HssFinalizedServerEvalState, JsValue> {
    crate_finalize_advanced_server_eval_state_with_output_projection_profiled(
        garbler_session,
        evaluator_session,
        server_eval_state,
        prior_stage_response_message,
        projection_mode,
        Date::now,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(feature = "hss-server-exports")]
fn finalize_server_eval_state_from_add_stage_request(
    runtime: &ed25519_hss::runtime::SharedRuntime,
    garbler_session: &ed25519_hss::server::ServerSession,
    evaluator_session: &ed25519_hss::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
    projection_mode: &ed25519_hss::wire::OutputProjectionMode,
) -> Result<ThresholdEd25519HssFinalizedServerEvalState, JsValue> {
    crate_finalize_server_eval_state_from_add_stage_request_profiled(
        runtime,
        garbler_session,
        evaluator_session,
        server_eval_state,
        add_stage_request_message,
        projection_mode,
        Date::now,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(feature = "hss-server-exports")]
fn finalize_or_reuse_threshold_ed25519_hss_server_eval_state(
    garbler_session: &ed25519_hss::server::ServerSession,
    evaluator_session: &ed25519_hss::client::ClientSession,
    server_eval_state: ServerEvalState,
    prior_stage_response_message_bytes: &[u8],
    projection_mode: &ed25519_hss::wire::OutputProjectionMode,
) -> Result<ThresholdEd25519HssFinalizedServerEvalState, JsValue> {
    if server_eval_state.status == ServerEvalStatus::Finalized {
        return Ok(ThresholdEd25519HssFinalizedServerEvalState {
            state: server_eval_state,
            timings: empty_threshold_ed25519_hss_server_eval_advance_timings(),
        });
    }
    let prior_stage_response_message = decode_wire_message_bytes(
        prior_stage_response_message_bytes,
        "priorStageResponseMessageBytes",
    )
    .map_err(js_value_to_string)?;
    finalize_advanced_server_eval_state_with_output_projection(
        garbler_session,
        evaluator_session,
        &server_eval_state,
        &prior_stage_response_message,
        projection_mode,
    )
}

#[cfg(feature = "hss-server-exports")]
fn parse_registration_projection_mode_label(value: &str) -> Result<String, JsValue> {
    match value.trim() {
        "registration_seed_and_output" => Ok("registration_seed_and_output".to_string()),
        "registration_output_only" => Ok("registration_output_only".to_string()),
        _ => Err(JsValue::from_str(
            "Invalid args: unsupported registration projectionMode",
        )),
    }
}

#[cfg(feature = "hss-server-exports")]
fn registration_output_projection_mode_from_label(
    value: &str,
) -> Result<ed25519_hss::wire::OutputProjectionMode, JsValue> {
    parse_registration_projection_mode_label(value)?;
    Ok(ed25519_hss::wire::OutputProjectionMode::trusted_server_projection())
}

#[cfg(feature = "hss-server-exports")]
fn compute_add_stage_request_digest_b64u(message: &WireMessage) -> String {
    let digest = Sha256::digest(&message.bytes);
    base64_url_encode(&digest)
}

#[cfg(feature = "hss-server-exports")]
fn summarize_threshold_ed25519_hss_probe_field(
    bytes: &[u8],
    total_payload_bytes: &mut usize,
    non_empty_field_count: &mut usize,
    checksum: &mut u8,
) {
    *total_payload_bytes += bytes.len();
    if bytes.is_empty() {
        return;
    }
    *non_empty_field_count += 1;
    *checksum ^= bytes[0] ^ bytes[bytes.len() - 1];
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_boundary_copy_probe(args: JsValue) -> Result<JsValue, JsValue> {
    let decode_args_started = Date::now();
    let args: ThresholdEd25519HssBoundaryCopyProbeArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let decode_args_ms = (Date::now() - decode_args_started).max(0.0);

    let summarize_started = Date::now();
    let mut total_payload_bytes = 0usize;
    let mut non_empty_field_count = 0usize;
    let mut checksum = 0u8;
    summarize_threshold_ed25519_hss_probe_field(
        &args.evaluator_driver_state_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.garbler_driver_state_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.server_eval_state_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.add_stage_request_message_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.staged_evaluator_artifact_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.advanced_server_eval_state_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.finalize_context_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    summarize_threshold_ed25519_hss_probe_field(
        &args.prior_stage_response_message_bytes,
        &mut total_payload_bytes,
        &mut non_empty_field_count,
        &mut checksum,
    );
    let summarize_ms = (Date::now() - summarize_started).max(0.0);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssBoundaryCopyProbeOutput {
        total_payload_bytes,
        non_empty_field_count,
        checksum,
        timings: ThresholdEd25519HssBoundaryCopyProbeTimings {
            decode_args_ms,
            summarize_ms,
        },
    })
    .map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS boundary probe output: {e}"
        ))
    })
}

#[cfg(feature = "hss-server-exports")]
fn messagepack_size_of<T: Serialize>(label: &str, value: &T) -> Result<usize, JsValue> {
    rmp_serde::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|e| JsValue::from_str(&format!("Failed to size {label}: {e}")))
}

#[cfg(feature = "hss-server-exports")]
fn push_threshold_ed25519_hss_state_field_size<T: Serialize>(
    fields: &mut Vec<ThresholdEd25519HssStateFieldSize>,
    label: &str,
    value: &T,
) -> Result<(), JsValue> {
    fields.push(ThresholdEd25519HssStateFieldSize {
        label: label.to_string(),
        messagepack_bytes: messagepack_size_of(label, value)?,
    });
    Ok(())
}

#[cfg(feature = "hss-server-exports")]
fn threshold_ed25519_hss_execution_state_size_census(
    execution_state: &Option<ServerEvalExecutionState>,
) -> Result<(String, Vec<ThresholdEd25519HssStateFieldSize>), JsValue> {
    let mut fields = Vec::new();
    match execution_state {
        None => Ok(("none".to_string(), fields)),
        Some(ServerEvalExecutionState::MessageSchedule(state)) => {
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "message_schedule",
                &state.message_schedule,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "projector_inputs",
                &state.projector_inputs,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "client_input_commitment",
                &state.client_input_commitment,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "server_input_commitment",
                &state.server_input_commitment,
            )?;
            Ok(("message_schedule".to_string(), fields))
        }
        Some(ServerEvalExecutionState::RoundCore(state)) => {
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "prior_execution_checkpoint_digest",
                &state.prior_execution_checkpoint_digest,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "round_core",
                &state.round_core,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "projector_inputs",
                &state.projector_inputs,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "client_input_commitment",
                &state.client_input_commitment,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "server_input_commitment",
                &state.server_input_commitment,
            )?;
            Ok(("round_core".to_string(), fields))
        }
        Some(ServerEvalExecutionState::OutputProjection(state)) => {
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "prior_execution_checkpoint_digest",
                &state.prior_execution_checkpoint_digest,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "round_core",
                &state.round_core,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "projector_inputs",
                &state.projector_inputs,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "client_input_commitment",
                &state.client_input_commitment,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "server_input_commitment",
                &state.server_input_commitment,
            )?;
            Ok(("output_projection".to_string(), fields))
        }
        Some(ServerEvalExecutionState::Finalize(state)) => {
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "client_input_commitment",
                &state.client_input_commitment,
            )?;
            push_threshold_ed25519_hss_state_field_size(
                &mut fields,
                "server_input_commitment",
                &state.server_input_commitment,
            )?;
            push_threshold_ed25519_hss_state_field_size(&mut fields, "output", &state.output)?;
            Ok(("finalize".to_string(), fields))
        }
    }
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_server_eval_state_size_census(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssServerEvalStateSizeCensusArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let decode_state_started = Date::now();
    let state: ServerEvalState =
        decode_messagepack_state_blob_bytes(&args.server_eval_state_bytes, "serverEvalStateBytes")?;
    let decode_state_ms = (Date::now() - decode_state_started).max(0.0);

    let summarize_started = Date::now();
    let mut fields = Vec::new();
    push_threshold_ed25519_hss_state_field_size(&mut fields, "handle", &state.handle)?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "context_binding",
        &state.context_binding,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "transcript_id",
        &state.transcript_id,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "current_stage",
        &state.current_stage,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "current_transcript_digest",
        &state.current_transcript_digest,
    )?;
    push_threshold_ed25519_hss_state_field_size(&mut fields, "operation", &state.operation)?;
    push_threshold_ed25519_hss_state_field_size(&mut fields, "status", &state.status)?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "server_input_commitment",
        &state.server_input_commitment,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "ot_transcript",
        &state.ot_transcript,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "last_request_digest",
        &state.last_request_digest,
    )?;
    push_threshold_ed25519_hss_state_field_size(&mut fields, "server_roots", &state.server_roots)?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "server_input_bundles",
        &state.server_input_bundles,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "hidden_eval_program",
        &state.hidden_eval_program,
    )?;
    push_threshold_ed25519_hss_state_field_size(
        &mut fields,
        "execution_state",
        &state.execution_state,
    )?;
    let (execution_state_kind, execution_state_fields) =
        threshold_ed25519_hss_execution_state_size_census(&state.execution_state)?;
    let summarize_ms = (Date::now() - summarize_started).max(0.0);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssServerEvalStateSizeCensusOutput {
        total_messagepack_bytes: args.server_eval_state_bytes.len(),
        status: format!("{:?}", state.status),
        current_stage: format!("{:?}", state.current_stage),
        operation: format!("{:?}", state.operation),
        execution_state_kind,
        fields,
        execution_state_fields,
        timings: ThresholdEd25519HssServerEvalStateSizeCensusTimings {
            decode_state_ms,
            summarize_ms,
        },
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS state census output: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_advance_server_eval_state(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssAdvanceServerEvalStateArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let projection_mode = parse_registration_projection_mode_label(&args.projection_mode)?;
    let output_projection_mode = registration_output_projection_mode_from_label(&projection_mode)?;

    let decode_state_started = Date::now();
    let server_eval_state: ServerEvalState =
        decode_state_blob_bytes(&args.server_eval_state_bytes, "serverEvalStateBytes")?;
    let add_stage_request_message = decode_wire_message_bytes(
        &args.add_stage_request_message_bytes,
        "addStageRequestMessageBytes",
    )
    .map_err(js_value_to_string)?;
    let add_stage_request_digest_b64u =
        compute_add_stage_request_digest_b64u(&add_stage_request_message);
    let decode_state_ms = (Date::now() - decode_state_started).max(0.0);

    let (context_binding, advanced, finalized, finalize_context, session_materialize_timings) =
        if let Some(output) =
            with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
                let advanced = advance_server_eval_state_to_output_projection_request(
                    &session.shared_runtime(),
                    &session.garbler_session(),
                    &session.evaluator_session(),
                    &server_eval_state,
                    &add_stage_request_message,
                )
                .map_err(js_value_to_string)?;
                let finalized = finalize_advanced_server_eval_state_with_output_projection(
                    &session.garbler_session(),
                    &session.evaluator_session(),
                    &advanced.state,
                    &advanced.prior_stage_response_message,
                    &output_projection_mode,
                )
                .map_err(js_value_to_string)?;
                Ok((
                    session.candidate().context_binding,
                    advanced,
                    finalized,
                    session.shared_runtime().finalize_context(),
                    ThresholdEd25519HssSerializedSessionMaterializeTimings::default(),
                ))
            })
            .map_err(|e| JsValue::from_str(&e))?
        {
            output
        } else {
            let materialized = materialize_threshold_ed25519_hss_serialized_advance_session(
                &args.evaluator_driver_state_bytes,
                &args.garbler_driver_state_bytes,
            )?;
            let advanced = advance_server_eval_state_with_advance_context(
                &materialized.advance_runtime,
                &materialized.garbler_session,
                &materialized.evaluator_session,
                &server_eval_state,
                &add_stage_request_message,
            )?;
            let finalized = finalize_advanced_server_eval_state_with_output_projection(
                &materialized.garbler_session,
                &materialized.evaluator_session,
                &advanced.state,
                &advanced.prior_stage_response_message,
                &output_projection_mode,
            )?;
            (
                materialized.context_binding,
                advanced,
                finalized,
                materialized.advance_runtime.finalize_context,
                materialized.timings,
            )
        };

    let encode_advanced_state_started = Date::now();
    let advance_output_projection_ms = finalized.timings.output_projection_ms;
    let mut advanced_server_eval_state = finalized.state;
    advanced_server_eval_state.hidden_eval_program = None;
    let advanced_server_eval_state_b64u =
        encode_messagepack_state_blob(&advanced_server_eval_state, "advancedServerEvalState")
            .map_err(|e| JsValue::from_str(&e))?;
    let finalize_context_b64u = encode_messagepack_state_blob(&finalize_context, "finalizeContext")
        .map_err(|e| JsValue::from_str(&e))?;
    let prior_stage_response_message_b64u =
        encode_wire_message(&advanced.prior_stage_response_message);
    let encode_advanced_state_ms = (Date::now() - encode_advanced_state_started).max(0.0);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssAdvanceServerEvalStateOutput {
        context_binding_b64u: base64_url_encode(&context_binding),
        advanced_server_eval_state_b64u,
        finalize_context_b64u,
        prior_stage_response_message_b64u,
        add_stage_request_digest_b64u,
        projection_mode,
        timings: ThresholdEd25519HssAdvanceServerEvalStateTimings {
            decode_state_ms,
            serialized_session_materialize_ms: session_materialize_timings.total_ms,
            serialized_session_decode_ms: session_materialize_timings.decode_ms,
            materialize_runtime_ms: session_materialize_timings.materialize_runtime_ms,
            materialize_evaluator_session_ms: session_materialize_timings
                .materialize_evaluator_session_ms,
            materialize_garbler_session_ms: session_materialize_timings
                .materialize_garbler_session_ms,
            advance_add_stage_response_ms: advanced.timings.add_stage_response_ms,
            advance_message_schedule_rounds_ms: advanced.timings.message_schedule_rounds_ms,
            advance_round_core_rounds_ms: advanced.timings.round_core_rounds_ms,
            advance_output_projection_ms,
            encode_advanced_state_ms,
        },
    })
    .map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize HSS advance-state output: {e}"
        ))
    })
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_finalize_advanced_report(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssFinalizeAdvancedReportArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let decode_artifact_started = Date::now();
    let staged_evaluator_artifact: StagedEvaluatorArtifact = decode_state_blob_bytes(
        &args.staged_evaluator_artifact_bytes,
        "stagedEvaluatorArtifactBytes",
    )?;
    let advanced_server_eval_state: ServerEvalState = decode_messagepack_state_blob_bytes(
        &args.advanced_server_eval_state_bytes,
        "advancedServerEvalStateBytes",
    )?;
    let finalize_context: SharedRuntimeFinalizeContext =
        decode_messagepack_state_blob_bytes(&args.finalize_context_bytes, "finalizeContextBytes")?;
    let decode_artifact_ms = (Date::now() - decode_artifact_started).max(0.0);

    let (
        report,
        session_materialize_timings,
        advance_timings,
        finalize_report_ms,
        finalize_packet_assembly_ms,
        x_relayer_base_b64u,
        canonical_seed_b64u,
        open_server_output_ms,
        open_seed_output_ms,
    ) = if let Some(report) =
        with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
            let finalize_report_started = Date::now();
            let finalized_server_eval_state =
                finalize_or_reuse_threshold_ed25519_hss_server_eval_state(
                    &session.garbler_session(),
                    &session.evaluator_session(),
                    advanced_server_eval_state.clone(),
                    &args.prior_stage_response_message_bytes,
                    &staged_evaluator_artifact.projection_mode,
                )
                .map_err(js_value_to_string)?;
            let finalize_packet_started = Date::now();
            let (_packet, report) = session
                .garbler_session()
                .prepare_server_finalize_packet_from_staged_evaluator_artifact(
                    &session.shared_runtime(),
                    &finalized_server_eval_state.state,
                    &staged_evaluator_artifact,
                )
                .map_err(|e| e.to_string())?;
            let finalize_packet_assembly_ms = (Date::now() - finalize_packet_started).max(0.0);
            let finalize_report_ms = (Date::now() - finalize_report_started).max(0.0);
            let open_server_output_started = Date::now();
            let x_relayer_base = session
                .garbler_session()
                .server_output_opener()
                .open(&report.output_delivery.server)
                .map_err(|e| e.to_string())?;
            let open_server_output_ms = (Date::now() - open_server_output_started).max(0.0);
            let (canonical_seed_b64u, open_seed_output_ms) = if args.open_seed_output {
                let open_seed_output_started = Date::now();
                let canonical_seed = session
                    .evaluator_session()
                    .seed_output_opener()
                    .open(&report.output_delivery.seed)
                    .map_err(|e| e.to_string())?;
                (
                    Some(base64_url_encode(&canonical_seed)),
                    (Date::now() - open_seed_output_started).max(0.0),
                )
            } else {
                (None, 0.0)
            };
            Ok((
                report,
                ThresholdEd25519HssSerializedSessionMaterializeTimings::default(),
                finalized_server_eval_state.timings,
                finalize_report_ms,
                finalize_packet_assembly_ms,
                Some(base64_url_encode(&x_relayer_base)),
                canonical_seed_b64u,
                open_server_output_ms,
                open_seed_output_ms,
            ))
        })
        .map_err(|e| JsValue::from_str(&e))?
    {
        report
    } else {
        let session_decode_started = Date::now();
        let evaluator_state: ClientDriverState = decode_state_blob_bytes(
            &args.evaluator_driver_state_bytes,
            "evaluatorDriverStateBytes",
        )
        .map_err(js_value_to_string)?;
        let garbler_state: ServerDriverState =
            decode_state_blob_bytes(&args.garbler_driver_state_bytes, "garblerDriverStateBytes")
                .map_err(js_value_to_string)?;
        if evaluator_state.runtime != garbler_state.runtime {
            return Err(JsValue::from_str(
                "evaluatorDriverStateBytes and garblerDriverStateBytes do not share the same prepared runtime",
            ));
        }
        let session_decode_ms = (Date::now() - session_decode_started).max(0.0);
        let finalize_report_started = Date::now();
        if advanced_server_eval_state.status != ServerEvalStatus::Finalized {
            return Err(JsValue::from_str(
                "durable advanced server eval state must be finalized before report assembly",
            ));
        }
        let finalized_server_eval_state = ThresholdEd25519HssFinalizedServerEvalState {
            state: advanced_server_eval_state.clone(),
            timings: empty_threshold_ed25519_hss_server_eval_advance_timings(),
        };
        let finalize_packet_started = Date::now();
        let (_packet, report) = garbler_state
            .garbler_session
            .prepare_server_finalize_packet_from_finalize_context(
                &finalize_context,
                &finalized_server_eval_state.state,
                &staged_evaluator_artifact,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let finalize_packet_assembly_ms = (Date::now() - finalize_packet_started).max(0.0);
        let finalize_report_ms = (Date::now() - finalize_report_started).max(0.0);
        let open_server_output_started = Date::now();
        let x_relayer_base = garbler_state
            .garbler_session
            .server_output_opener()
            .map_err(|e| JsValue::from_str(&e.to_string()))?
            .open(&report.output_delivery.server)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let open_server_output_ms = (Date::now() - open_server_output_started).max(0.0);
        let (canonical_seed_b64u, open_seed_output_ms) = if args.open_seed_output {
            let open_seed_output_started = Date::now();
            let canonical_seed = evaluator_state
                .evaluator_session
                .seed_output_opener()
                .map_err(|e| JsValue::from_str(&e.to_string()))?
                .open(&report.output_delivery.seed)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            (
                Some(base64_url_encode(&canonical_seed)),
                (Date::now() - open_seed_output_started).max(0.0),
            )
        } else {
            (None, 0.0)
        };
        (
            report,
            ThresholdEd25519HssSerializedSessionMaterializeTimings {
                total_ms: session_decode_ms,
                decode_ms: session_decode_ms,
                materialize_runtime_ms: 0.0,
                materialize_evaluator_session_ms: 0.0,
                materialize_garbler_session_ms: 0.0,
            },
            finalized_server_eval_state.timings,
            finalize_report_ms,
            finalize_packet_assembly_ms,
            Some(base64_url_encode(&x_relayer_base)),
            canonical_seed_b64u,
            open_server_output_ms,
            open_seed_output_ms,
        )
    };

    let encode_report_started = Date::now();
    let client_output_message_b64u = encode_wire_message(&report.output_delivery.client);
    let seed_output_message_b64u = encode_wire_message(&report.output_delivery.seed);
    let server_output_message_b64u = encode_wire_message(&report.output_delivery.server);
    let encode_report_ms = (Date::now() - encode_report_started).max(0.0);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssFinalizeReportOutput {
        context_binding_b64u: base64_url_encode(&report.artifact.context_binding),
        client_output_message_b64u,
        seed_output_message_b64u,
        server_output_message_b64u,
        x_relayer_base_b64u,
        canonical_seed_b64u,
        timings: ThresholdEd25519HssFinalizeReportTimings {
            decode_artifact_ms,
            serialized_session_materialize_ms: session_materialize_timings.total_ms,
            serialized_session_decode_ms: session_materialize_timings.decode_ms,
            materialize_runtime_ms: session_materialize_timings.materialize_runtime_ms,
            materialize_evaluator_session_ms: session_materialize_timings
                .materialize_evaluator_session_ms,
            materialize_garbler_session_ms: session_materialize_timings
                .materialize_garbler_session_ms,
            advance_add_stage_response_ms: 0.0,
            advance_message_schedule_rounds_ms: 0.0,
            advance_round_core_rounds_ms: 0.0,
            advance_output_projection_ms: advance_timings.output_projection_ms,
            finalize_report_ms,
            finalize_packet_assembly_ms,
            encode_report_ms,
            open_server_output_ms,
            open_seed_output_ms,
        },
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS finalization output: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_finalize_report(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssFinalizeReportArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let (
        report,
        decode_artifact_ms,
        session_materialize_timings,
        advance_timings,
        finalize_report_ms,
        finalize_packet_assembly_ms,
    ) = if let Some(report) =
        with_cached_staged_evaluator_artifact(&args.staged_evaluator_artifact_handle, |record| {
            with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
                let finalize_report_started = Date::now();
                session
                    .shared_runtime()
                    .finalize_report_from_staged_evaluator_artifact(
                        &session.garbler_session(),
                        &record.artifact,
                        &record.server_output,
                    )
                    .map(|report| {
                        let finalize_report_ms = (Date::now() - finalize_report_started).max(0.0);
                        (
                            report,
                            0.0,
                            ThresholdEd25519HssSerializedSessionMaterializeTimings::default(),
                            empty_threshold_ed25519_hss_server_eval_advance_timings(),
                            finalize_report_ms,
                            finalize_report_ms,
                        )
                    })
                    .map_err(|e| e.to_string())
            })?
            .ok_or_else(|| {
                "missing prepared-session cache entry for staged evaluator artifact".to_string()
            })
        })
        .map_err(|e| JsValue::from_str(&e))?
    {
        report
    } else {
        let decode_artifact_started = Date::now();
        let staged_evaluator_artifact: StagedEvaluatorArtifact = decode_state_blob_bytes(
            &args.staged_evaluator_artifact_bytes,
            "stagedEvaluatorArtifactBytes",
        )?;
        let server_eval_state: ServerEvalState =
            decode_state_blob_bytes(&args.server_eval_state_bytes, "serverEvalStateBytes")?;
        let add_stage_request_message = decode_wire_message_bytes(
            &args.add_stage_request_message_bytes,
            "addStageRequestMessageBytes",
        )
        .map_err(js_value_to_string)?;
        let decode_artifact_ms = (Date::now() - decode_artifact_started).max(0.0);
        if let Some(report) =
            with_cached_prepared_server_session(&args.prepared_session_handle, |session| {
                let finalize_report_started = Date::now();
                let finalized_server_eval_state =
                    finalize_server_eval_state_from_add_stage_request(
                        &session.shared_runtime(),
                        &session.garbler_session(),
                        &session.evaluator_session(),
                        &server_eval_state,
                        &add_stage_request_message,
                        &staged_evaluator_artifact.projection_mode,
                    )
                    .map_err(js_value_to_string)?;
                let finalize_packet_started = Date::now();
                session
                    .garbler_session()
                    .prepare_server_finalize_packet_from_staged_evaluator_artifact(
                        &session.shared_runtime(),
                        &finalized_server_eval_state.state,
                        &staged_evaluator_artifact,
                    )
                    .map(|(_packet, report)| {
                        let finalize_packet_assembly_ms =
                            (Date::now() - finalize_packet_started).max(0.0);
                        (
                            report,
                            decode_artifact_ms,
                            ThresholdEd25519HssSerializedSessionMaterializeTimings::default(),
                            finalized_server_eval_state.timings,
                            (Date::now() - finalize_report_started).max(0.0),
                            finalize_packet_assembly_ms,
                        )
                    })
                    .map_err(|e| e.to_string())
            })
            .map_err(|e| JsValue::from_str(&e))?
        {
            report
        } else {
            let materialized = materialize_threshold_ed25519_hss_serialized_session(
                &args.evaluator_driver_state_bytes,
                &args.garbler_driver_state_bytes,
            )?;
            let finalize_report_started = Date::now();
            let finalized_server_eval_state = finalize_server_eval_state_from_add_stage_request(
                &materialized.runtime,
                &materialized.garbler_session,
                &materialized.evaluator_session,
                &server_eval_state,
                &add_stage_request_message,
                &staged_evaluator_artifact.projection_mode,
            )?;
            let finalize_packet_started = Date::now();
            let (_packet, report) = materialized
                .garbler_session
                .prepare_server_finalize_packet_from_staged_evaluator_artifact(
                    &materialized.runtime,
                    &finalized_server_eval_state.state,
                    &staged_evaluator_artifact,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let finalize_packet_assembly_ms = (Date::now() - finalize_packet_started).max(0.0);
            let finalize_report_ms = (Date::now() - finalize_report_started).max(0.0);
            (
                report,
                decode_artifact_ms,
                materialized.timings,
                finalized_server_eval_state.timings,
                finalize_report_ms,
                finalize_packet_assembly_ms,
            )
        }
    };

    let encode_report_started = Date::now();
    let client_output_message_b64u = encode_wire_message(&report.output_delivery.client);
    let seed_output_message_b64u = encode_wire_message(&report.output_delivery.seed);
    let server_output_message_b64u = encode_wire_message(&report.output_delivery.server);
    let encode_report_ms = (Date::now() - encode_report_started).max(0.0);

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssFinalizeReportOutput {
        context_binding_b64u: base64_url_encode(&report.artifact.context_binding),
        client_output_message_b64u,
        seed_output_message_b64u,
        server_output_message_b64u,
        x_relayer_base_b64u: None,
        canonical_seed_b64u: None,
        timings: ThresholdEd25519HssFinalizeReportTimings {
            decode_artifact_ms,
            serialized_session_materialize_ms: session_materialize_timings.total_ms,
            serialized_session_decode_ms: session_materialize_timings.decode_ms,
            materialize_runtime_ms: session_materialize_timings.materialize_runtime_ms,
            materialize_evaluator_session_ms: session_materialize_timings
                .materialize_evaluator_session_ms,
            materialize_garbler_session_ms: session_materialize_timings
                .materialize_garbler_session_ms,
            advance_add_stage_response_ms: advance_timings.add_stage_response_ms,
            advance_message_schedule_rounds_ms: advance_timings.message_schedule_rounds_ms,
            advance_round_core_rounds_ms: advance_timings.round_core_rounds_ms,
            advance_output_projection_ms: advance_timings.output_projection_ms,
            finalize_report_ms,
            finalize_packet_assembly_ms,
            encode_report_ms,
            open_server_output_ms: 0.0,
            open_seed_output_ms: 0.0,
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
    Reflect::set(
        &js_output,
        &JsValue::from_str("serverEvalFinalizeOutputB64u"),
        &JsValue::from_str(&output.server_eval_finalize_output_b64u),
    )
    .map_err(|_| JsValue::from_str("Failed to set serverEvalFinalizeOutputB64u"))?;
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
        let x_relayer_base = garbler_state
            .garbler_session
            .server_output_opener()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let x_relayer_base = x_relayer_base
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

#[cfg(feature = "hss-server-exports")]
fn encode_messagepack_state_blob<T: Serialize>(
    value: &T,
    field_name: &str,
) -> Result<String, String> {
    let bytes =
        rmp_serde::to_vec(value).map_err(|e| format!("Failed to serialize {field_name}: {e}"))?;
    Ok(base64_url_encode(&bytes))
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

#[cfg(feature = "hss-server-exports")]
fn decode_messagepack_state_blob_bytes<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    field_name: &str,
) -> Result<T, JsValue> {
    rmp_serde::from_slice::<T>(bytes)
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
        "registrationmaterialrestore" | "registration_material_restore" => {
            Ok(ServerEvalOperation::Registration)
        }
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
    let add_stage_request_message = evaluator_session
        .prepare_add_stage_request_message_from_role_separated_delivery(
            &client_request_message,
            &evaluator_ot_state,
            &server_input_delivery,
        )
        .map_err(|e| e.to_string())?;
    let (artifact, _server_output) = evaluator_session
        .build_client_owned_staged_evaluator_artifact_and_server_finalize_output_from_role_separated_delivery_message(
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
        add_stage_request_message_b64u: encode_wire_message(&add_stage_request_message),
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
            let (staged_evaluator_artifact, server_output, stage_profile, evaluate_timing) =
                session
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
            let server_eval_finalize_output_b64u =
                encode_state_blob(&server_output, "server eval finalize output")?;
            let staged_evaluator_artifact_handle =
                cache_staged_evaluator_artifact(staged_evaluator_artifact, server_output);
            let encode_artifact_ms = (Date::now() - encode_artifact_started).max(0.0);

            Ok(ThresholdEd25519HssPrepareServerCeremonyOutput {
                context_binding_b64u: base64_url_encode(&session.candidate().context_binding),
                staged_evaluator_artifact_handle,
                server_eval_finalize_output_b64u,
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
    let (staged_evaluator_artifact, server_output, stage_profile, evaluate_timing) =
        garbler_session
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
    let server_eval_finalize_output_b64u =
        encode_state_blob(&server_output, "server eval finalize output")?;
    let staged_evaluator_artifact_handle =
        cache_staged_evaluator_artifact(staged_evaluator_artifact, server_output);
    let encode_artifact_ms = (Date::now() - encode_artifact_started).max(0.0);

    Ok(ThresholdEd25519HssPrepareServerCeremonyOutput {
        context_binding_b64u: base64_url_encode(&evaluator_state.evaluator_session.context_binding),
        staged_evaluator_artifact_handle,
        server_eval_finalize_output_b64u,
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
            let (delivery, state, delivery_timing) = session
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
            let server_eval_state_b64u = encode_state_blob(&state, "server eval state")?;
            let encode_delivery_ms = (Date::now() - encode_delivery_started).max(0.0);
            Ok(
                ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryOutput {
                    context_binding_b64u: base64_url_encode(&delivery.context_binding),
                    server_input_delivery_b64u,
                    server_eval_state_b64u,
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
    let (delivery, state, delivery_timing) = garbler_session
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
    let server_eval_state_b64u = encode_state_blob(&state, "server eval state")?;
    let encode_delivery_ms = (Date::now() - encode_delivery_started).max(0.0);

    Ok(
        ThresholdEd25519HssPrepareRoleSeparatedServerInputDeliveryOutput {
            context_binding_b64u: base64_url_encode(&delivery.context_binding),
            server_input_delivery_b64u,
            server_eval_state_b64u,
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
    let client_output_message =
        decode_wire_message(&args.client_output_message_b64u, "clientOutputMessageB64u")
            .map_err(js_value_to_string)?;
    let client_output_mask = decode_fixed_32(&args.client_output_mask_b64u, "clientOutputMaskB64u")
        .map_err(js_value_to_string)?;
    let opener = evaluator_state
        .evaluator_session
        .client_output_opener()
        .map_err(|e| e.to_string())?;
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
    let opener = evaluator_state
        .evaluator_session
        .seed_output_opener()
        .map_err(|e| e.to_string())?;
    let canonical_seed = opener
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
