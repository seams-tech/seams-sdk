use std::cell::RefCell;

use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use sha2::{Digest, Sha512};
use wasm_bindgen::prelude::*;

use crate::ddh::hidden_eval_executor::{
    execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool,
    probe_prime_order_ddh_hidden_eval_program_with_pool, DdhHiddenEvalCheckpoint,
    DdhHiddenEvalOperationCounts, DdhHiddenEvalStageOperationCounts,
};
use crate::protocol::{prepare_prime_order_succinct_hss, PreparedSession};
use crate::shared::{
    eval_f_expand, public_key_from_base_shares, CanonicalContext, FExpandInput, ProtoError,
    ProtoResult,
};

const FIXTURE_NAME: &str = "wraparound-seed";

thread_local! {
    static DDH_HIDDEN_EVAL_STATE: RefCell<Option<BrowserDdhHiddenEvalState>> =
        const { RefCell::new(None) };
}

struct BrowserDdhHiddenEvalState {
    input: FExpandInput,
    session: PreparedSession,
    last_total_duration_ns: u128,
}

#[derive(Serialize)]
struct BrowserDdhPrepareReport {
    fixture_name: &'static str,
    artifact_bytes: u64,
    active_window_records: usize,
    total_steps: usize,
    curve_cost_units: u64,
    evaluator_ops: crate::artifact::PrimeOrderEvaluatorOps,
}

#[derive(Serialize)]
struct BrowserDdhDetailedRunReport {
    evaluate_duration_ns: u128,
    ot_open_join_duration_ns: u64,
    ot_branch_key_derivation_duration_ns: u64,
    ot_branch_decrypt_duration_ns: u64,
    ot_point_scalar_reconstruction_duration_ns: u64,
    ot_commitment_verification_duration_ns: u64,
    server_input_open_duration_ns: u64,
    server_input_share_duration_ns: u64,
    server_input_commitment_duration_ns: u64,
    server_input_transcript_duration_ns: u64,
    server_input_seal_duration_ns: u64,
    output_sealing_finalization_duration_ns: u64,
    result_assembly_duration_ns: u64,
    output_materialization_duration_ns: u64,
    output_open_duration_ns: u64,
    public_key_duration_ns: u64,
    total_duration_ns: u128,
    operation_counts: DdhHiddenEvalOperationCounts,
    stage_operation_counts: DdhHiddenEvalStageOperationCounts,
    reference_match: bool,
    output_public_key_hex: String,
    output_x_client_base_hex: String,
}

#[wasm_bindgen]
pub fn reset_prime_order_ddh_hidden_eval() {
    DDH_HIDDEN_EVAL_STATE.with(|state| {
        state.replace(None);
    });
}

#[wasm_bindgen]
pub fn prepare_prime_order_ddh_hidden_eval() -> Result<JsValue, JsValue> {
    let input = browser_benchmark_input();
    let session = prepare_prime_order_succinct_hss(&input.context).map_err(js_error)?;
    let report = BrowserDdhPrepareReport {
        fixture_name: FIXTURE_NAME,
        artifact_bytes: session.artifact_bytes().len() as u64,
        active_window_records: session.hidden_eval_program().active_window_records,
        total_steps: session.execution_program().trace.total_steps,
        curve_cost_units: session.execution_program().trace.estimated_curve_cost_units,
        evaluator_ops: session.execution_program().trace.evaluator_ops.clone(),
    };

    DDH_HIDDEN_EVAL_STATE.with(|state| {
        state.replace(Some(BrowserDdhHiddenEvalState {
            input,
            session,
            last_total_duration_ns: 0,
        }));
    });

    to_js_object(&report)
}

#[wasm_bindgen]
pub fn probe_prime_order_ddh_hidden_eval(stage: &str) -> Result<JsValue, JsValue> {
    with_ddh_state(|state| {
        let checkpoint = parse_checkpoint(stage)?;
        let probe = probe_prime_order_ddh_hidden_eval_program_with_pool(
            state.session.hidden_eval_program(),
            state.session.ddh_backend(),
            state.session.hidden_eval_constants(),
            &state.input,
            checkpoint,
        )?;
        to_js_object_proto(&probe)
    })
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_hidden_run_once_fast() -> Result<(), JsValue> {
    with_ddh_state(|state| {
        let profile =
            execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool(
                state.session.hidden_eval_program(),
                state.session.ddh_backend(),
                state.session.hidden_eval_constants(),
                &state.input,
            )?;
        state.last_total_duration_ns = profile.stage_profile.total_duration_ns;
        Ok(())
    })
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_hidden_run_once() -> Result<JsValue, JsValue> {
    with_ddh_state(|state| {
        detailed_run_report(state).and_then(|report| to_js_object_proto(&report))
    })
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_once() -> Result<JsValue, JsValue> {
    execute_prime_order_ddh_hidden_eval_hidden_run_once()
}

fn with_ddh_state<T>(
    op: impl FnOnce(&mut BrowserDdhHiddenEvalState) -> ProtoResult<T>,
) -> Result<T, JsValue> {
    DDH_HIDDEN_EVAL_STATE.with(|state| {
        let mut borrowed = state.borrow_mut();
        let state = borrowed.as_mut().ok_or_else(|| {
            js_error(ProtoError::InvalidInput(
                "DDH hidden-eval benchmark must be prepared before execution".to_string(),
            ))
        })?;
        op(state).map_err(js_error)
    })
}

fn detailed_run_report(
    state: &mut BrowserDdhHiddenEvalState,
) -> ProtoResult<BrowserDdhDetailedRunReport> {
    let profile = execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool(
        state.session.hidden_eval_program(),
        state.session.ddh_backend(),
        state.session.hidden_eval_constants(),
        &state.input,
    )?;
    let x_client_base = state
        .session
        .evaluator_session()
        .ddh_evaluator
        .decode_client_bit_bundle_array(profile.run.output.client_output.as_bundle())?;
    let garbler_session = state.session.garbler_session();
    let x_relayer_bundle = garbler_session.ddh_garbler.join_share_bundle(
        &profile.run.output.x_relayer_base_left,
        &profile.run.output.x_relayer_base_right,
    )?;
    let x_relayer_base = garbler_session
        .ddh_garbler
        .decode_server_bit_bundle_array(&x_relayer_bundle)?;
    let public_key = public_key_from_base_shares(x_client_base, x_relayer_base)?;
    let reference = eval_f_expand(&state.input)?;
    let reference_match =
        public_key == reference.public_key && x_client_base == reference.x_client_base;
    state.last_total_duration_ns = profile.stage_profile.total_duration_ns;

    Ok(BrowserDdhDetailedRunReport {
        evaluate_duration_ns: profile.stage_profile.total_duration_ns,
        ot_open_join_duration_ns: 0,
        ot_branch_key_derivation_duration_ns: 0,
        ot_branch_decrypt_duration_ns: 0,
        ot_point_scalar_reconstruction_duration_ns: 0,
        ot_commitment_verification_duration_ns: 0,
        server_input_open_duration_ns: 0,
        server_input_share_duration_ns: 0,
        server_input_commitment_duration_ns: 0,
        server_input_transcript_duration_ns: 0,
        server_input_seal_duration_ns: 0,
        output_sealing_finalization_duration_ns: 0,
        result_assembly_duration_ns: 0,
        output_materialization_duration_ns: 0,
        output_open_duration_ns: 0,
        public_key_duration_ns: 0,
        total_duration_ns: profile.stage_profile.total_duration_ns,
        operation_counts: profile.stage_profile.operation_counts,
        stage_operation_counts: profile.stage_profile.stage_operation_counts,
        reference_match,
        output_public_key_hex: hex::encode(public_key),
        output_x_client_base_hex: hex::encode(x_client_base),
    })
}

fn parse_checkpoint(stage: &str) -> ProtoResult<DdhHiddenEvalCheckpoint> {
    match stage {
        "input_sharing" => Ok(DdhHiddenEvalCheckpoint::InputSharing),
        "add_stage" => Ok(DdhHiddenEvalCheckpoint::AddStage),
        "message_schedule" => Ok(DdhHiddenEvalCheckpoint::MessageSchedule),
        "round_core" => Ok(DdhHiddenEvalCheckpoint::RoundCore),
        "output_projector" => Ok(DdhHiddenEvalCheckpoint::OutputProjector),
        other => Err(ProtoError::InvalidInput(format!(
            "unknown DDH hidden-eval benchmark checkpoint: {other}"
        ))),
    }
}

fn browser_benchmark_input() -> FExpandInput {
    FExpandInput {
        context: CanonicalContext {
            org_id: "org.wraparound".to_string(),
            account_id: "wraparound.test.near".to_string(),
            key_purpose: "near-signing".to_string(),
            key_version: "v1-wrap".to_string(),
            participant_ids: vec![2, 1, 2],
            derivation_version: 1,
        },
        y_client: [0xff; 32],
        y_relayer: one_le_u256(),
        tau_client: derive_scalar_bytes("wraparound-seed/tau-client"),
        tau_relayer: derive_scalar_bytes("wraparound-seed/tau-relayer"),
    }
}

fn derive_scalar_bytes(label: &str) -> [u8; 32] {
    let digest = Sha512::digest(format!("succinct-garbling-proto/{label}/scalar"));
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    if scalar == Scalar::ZERO {
        return Scalar::ONE.to_bytes();
    }
    scalar.to_bytes()
}

fn one_le_u256() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = 1;
    out
}

fn to_js_object<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let json = serde_json::to_string(value).map_err(|err| JsValue::from_str(&err.to_string()))?;
    js_sys::JSON::parse(&json)
}

fn to_js_object_proto<T: Serialize>(value: &T) -> ProtoResult<JsValue> {
    let json = serde_json::to_string(value)
        .map_err(|err| ProtoError::Decode(format!("failed to serialize wasm report: {err}")))?;
    js_sys::JSON::parse(&json)
        .map_err(|err| ProtoError::Decode(format!("failed to parse wasm report JSON: {err:?}")))
}

fn js_error(err: ProtoError) -> JsValue {
    JsValue::from_str(&err.to_string())
}
