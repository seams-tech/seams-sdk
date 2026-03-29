use serde::Serialize;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

use crate::ddh_hidden_eval_executor::{DdhHiddenEvalCheckpoint, DdhHiddenEvalProbe};
use crate::fixtures::deterministic_fixture_corpus;
use crate::prime_order_cpu_executor::{
    compile_default_prime_order_cpu_execution_program, execute_prime_order_cpu_execution_program,
    PrimeOrderCpuExecutionProgram,
};
use crate::prime_order_trace::PrimeOrderEvaluatorOps;
use crate::reference::{public_key_from_base_shares, FExpandInput, FExpandOutput};
use crate::succinct_hss::{prepare_prime_order_succinct_hss, PrimeOrderSuccinctHssPreparedSession};

thread_local! {
    static WASM_EXECUTOR_PROGRAM: RefCell<Option<PrimeOrderCpuExecutionProgram>> = const { RefCell::new(None) };
    static WASM_DDH_HIDDEN_EVAL_STATE: RefCell<Option<WasmDdhHiddenEvalPreparedState>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WasmPrimeOrderCpuExecutorPrepared {
    fixture_name: String,
    artifact_bytes: u64,
    total_steps: usize,
    curve_cost_units: u64,
    evaluator_ops: PrimeOrderEvaluatorOps,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WasmPrimeOrderCpuExecutorRun {
    total_steps: usize,
    curve_cost_units: u64,
    evaluator_ops: PrimeOrderEvaluatorOps,
    output_checksum_hex: String,
    final_point_compressed_hex: String,
}

struct WasmDdhHiddenEvalPreparedState {
    input: FExpandInput,
    expected_output: FExpandOutput,
    session: PrimeOrderSuccinctHssPreparedSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WasmDdhHiddenEvalPrepared {
    fixture_name: String,
    artifact_bytes: u64,
    active_window_records: usize,
    total_steps: usize,
    curve_cost_units: u64,
    evaluator_ops: PrimeOrderEvaluatorOps,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WasmDdhHiddenEvalRun {
    total_steps: usize,
    curve_cost_units: u64,
    evaluator_ops: PrimeOrderEvaluatorOps,
    evaluate_duration_ns: u64,
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
    total_duration_ns: u64,
    output_public_key_hex: String,
    output_x_client_base_hex: String,
    reference_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WasmDdhHiddenEvalProbeRun {
    completed_stage: DdhHiddenEvalCheckpoint,
    stage_profile: crate::DdhHiddenEvalStageProfile,
    schedule_word_count: Option<usize>,
    hash_prefix_hex: Option<String>,
}

#[wasm_bindgen]
pub fn prepare_prime_order_cpu_executor() -> Result<JsValue, JsValue> {
    init_wasm_runtime();
    let (fixture_name, program) =
        compile_default_prime_order_cpu_execution_program().map_err(js_error)?;
    let prepared = WasmPrimeOrderCpuExecutorPrepared {
        fixture_name,
        artifact_bytes: program.artifact_bytes,
        total_steps: program.trace.total_steps,
        curve_cost_units: program.trace.estimated_curve_cost_units,
        evaluator_ops: program.trace.evaluator_ops.clone(),
    };
    WASM_EXECUTOR_PROGRAM.with(|slot| {
        *slot.borrow_mut() = Some(program);
    });
    serialize_js_value(&prepared)
}

#[wasm_bindgen]
pub fn execute_prime_order_cpu_executor_once() -> Result<JsValue, JsValue> {
    init_wasm_runtime();
    let run = WASM_EXECUTOR_PROGRAM.with(|slot| {
        let borrowed = slot.borrow();
        let program = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order cpu executor is not prepared"))?;
        let result = execute_prime_order_cpu_execution_program(program).map_err(js_error)?;
        Ok::<_, JsValue>(WasmPrimeOrderCpuExecutorRun {
            total_steps: result.total_steps,
            curve_cost_units: program.trace.estimated_curve_cost_units,
            evaluator_ops: program.trace.evaluator_ops.clone(),
            output_checksum_hex: format!("{:016x}", result.output_checksum),
            final_point_compressed_hex: hex::encode(result.final_point_compressed),
        })
    })?;

    serialize_js_value(&run)
}

#[wasm_bindgen]
pub fn execute_prime_order_cpu_executor_once_fast() -> Result<(), JsValue> {
    init_wasm_runtime();
    WASM_EXECUTOR_PROGRAM.with(|slot| {
        let borrowed = slot.borrow();
        let program = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order cpu executor is not prepared"))?;
        execute_prime_order_cpu_execution_program(program)
            .map(|_| ())
            .map_err(js_error)
    })
}

#[wasm_bindgen]
pub fn reset_prime_order_cpu_executor() {
    WASM_EXECUTOR_PROGRAM.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[wasm_bindgen]
pub fn prepare_prime_order_ddh_hidden_eval() -> Result<JsValue, JsValue> {
    init_wasm_runtime();
    let fixture = deterministic_fixture_corpus()
        .map_err(js_error)?
        .into_iter()
        .next()
        .ok_or_else(|| js_error("fixture corpus is empty"))?;
    let session = prepare_prime_order_succinct_hss(&fixture.input.context).map_err(js_error)?;
    let prepared = WasmDdhHiddenEvalPrepared {
        fixture_name: fixture.name.clone(),
        artifact_bytes: session.artifact_summary().artifact_bytes,
        active_window_records: session.hidden_eval_program().active_window_records,
        total_steps: session.execution_program().trace.total_steps,
        curve_cost_units: session.execution_program().trace.estimated_curve_cost_units,
        evaluator_ops: session.execution_program().trace.evaluator_ops.clone(),
    };
    WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        *slot.borrow_mut() = Some(WasmDdhHiddenEvalPreparedState {
            input: fixture.input,
            expected_output: fixture.output,
            session,
        });
    });
    serialize_js_value(&prepared)
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_once() -> Result<JsValue, JsValue> {
    init_wasm_runtime();
    let run = WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let state = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order DDH hidden eval is not prepared"))?;
        let started_ns = monotonic_now_ns();
        let evaluate_started_ns = started_ns;
        let (report, evaluate_timing) = state
            .session
            .evaluate_with_timing(&state.input)
            .map_err(js_error)?;
        let evaluate_duration_ns = elapsed_ns(evaluate_started_ns);
        let output_openers = state.session.output_openers();
        let output_open_started_ns = monotonic_now_ns();
        let x_client_base = output_openers
            .client
            .open(&report.output_delivery.client)
            .map_err(js_error)?;
        let x_relayer_base = output_openers
            .server
            .open(&report.output_delivery.server)
            .map_err(js_error)?;
        let output_open_duration_ns = elapsed_ns(output_open_started_ns);
        let public_key_started_ns = monotonic_now_ns();
        let public_key =
            public_key_from_base_shares(x_client_base, x_relayer_base).map_err(js_error)?;
        let public_key_duration_ns = elapsed_ns(public_key_started_ns);
        Ok::<_, JsValue>(WasmDdhHiddenEvalRun {
            total_steps: state.session.execution_program().trace.total_steps,
            curve_cost_units: state
                .session
                .execution_program()
                .trace
                .estimated_curve_cost_units,
            evaluator_ops: state
                .session
                .execution_program()
                .trace
                .evaluator_ops
                .clone(),
            evaluate_duration_ns: evaluate_duration_ns as u64,
            ot_open_join_duration_ns: evaluate_timing.ot_open_join_duration_ns,
            ot_branch_key_derivation_duration_ns: evaluate_timing
                .ot_branch_key_derivation_duration_ns,
            ot_branch_decrypt_duration_ns: evaluate_timing.ot_branch_decrypt_duration_ns,
            ot_point_scalar_reconstruction_duration_ns: evaluate_timing
                .ot_point_scalar_reconstruction_duration_ns,
            ot_commitment_verification_duration_ns: evaluate_timing
                .ot_commitment_verification_duration_ns,
            server_input_open_duration_ns: evaluate_timing.server_input_open_duration_ns,
            server_input_share_duration_ns: evaluate_timing.server_input_share_duration_ns,
            server_input_commitment_duration_ns: evaluate_timing
                .server_input_commitment_duration_ns,
            server_input_transcript_duration_ns: evaluate_timing
                .server_input_transcript_duration_ns,
            server_input_seal_duration_ns: evaluate_timing.server_input_seal_duration_ns,
            output_sealing_finalization_duration_ns: evaluate_timing
                .output_sealing_finalization_duration_ns,
            result_assembly_duration_ns: evaluate_timing.result_assembly_duration_ns,
            output_materialization_duration_ns: (output_open_duration_ns + public_key_duration_ns)
                as u64,
            output_open_duration_ns: output_open_duration_ns as u64,
            public_key_duration_ns: public_key_duration_ns as u64,
            total_duration_ns: elapsed_ns(started_ns) as u64,
            output_public_key_hex: hex::encode(public_key),
            output_x_client_base_hex: hex::encode(x_client_base),
            reference_match: x_client_base == state.expected_output.x_client_base
                && public_key == state.expected_output.public_key,
        })
    })?;

    serialize_js_value(&run)
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_once_fast() -> Result<bool, JsValue> {
    init_wasm_runtime();
    WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let state = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order DDH hidden eval is not prepared"))?;
        let run = state
            .session
            .evaluate_hidden_run(&state.input)
            .map_err(js_error)?;
        let (x_client_base, _x_relayer_base, public_key) = state
            .session
            .materialize_hidden_outputs_for_debug(&run.output)
            .map_err(js_error)?;
        Ok::<_, JsValue>(
            x_client_base == state.expected_output.x_client_base
                && public_key == state.expected_output.public_key,
        )
    })
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_hidden_run_once_fast() -> Result<(), JsValue> {
    init_wasm_runtime();
    WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let state = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order DDH hidden eval is not prepared"))?;
        state
            .session
            .evaluate_hidden_run(&state.input)
            .map(|_| ())
            .map_err(js_error)
    })
}

#[wasm_bindgen]
pub fn execute_prime_order_ddh_hidden_eval_hidden_run_once() -> Result<JsValue, JsValue> {
    init_wasm_runtime();
    let run = WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let state = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order DDH hidden eval is not prepared"))?;
        let started_ns = monotonic_now_ns();
        let evaluate_started_ns = started_ns;
        let (hidden_run, evaluate_timing) = state
            .session
            .evaluate_hidden_run_with_timing(&state.input)
            .map_err(js_error)?;
        let evaluate_duration_ns = elapsed_ns(evaluate_started_ns);
        let output_materialization_started_ns = monotonic_now_ns();
        let (x_client_base, _x_relayer_base, public_key) = state
            .session
            .materialize_hidden_outputs_for_debug(&hidden_run.output)
            .map_err(js_error)?;
        let output_materialization_duration_ns =
            elapsed_ns(output_materialization_started_ns) as u64;
        Ok::<_, JsValue>(WasmDdhHiddenEvalRun {
            total_steps: state.session.execution_program().trace.total_steps,
            curve_cost_units: state
                .session
                .execution_program()
                .trace
                .estimated_curve_cost_units,
            evaluator_ops: state
                .session
                .execution_program()
                .trace
                .evaluator_ops
                .clone(),
            evaluate_duration_ns: evaluate_duration_ns as u64,
            ot_open_join_duration_ns: evaluate_timing.ot_open_join_duration_ns,
            ot_branch_key_derivation_duration_ns: evaluate_timing
                .ot_branch_key_derivation_duration_ns,
            ot_branch_decrypt_duration_ns: evaluate_timing.ot_branch_decrypt_duration_ns,
            ot_point_scalar_reconstruction_duration_ns: evaluate_timing
                .ot_point_scalar_reconstruction_duration_ns,
            ot_commitment_verification_duration_ns: evaluate_timing
                .ot_commitment_verification_duration_ns,
            server_input_open_duration_ns: evaluate_timing.server_input_open_duration_ns,
            server_input_share_duration_ns: evaluate_timing.server_input_share_duration_ns,
            server_input_commitment_duration_ns: evaluate_timing
                .server_input_commitment_duration_ns,
            server_input_transcript_duration_ns: evaluate_timing
                .server_input_transcript_duration_ns,
            server_input_seal_duration_ns: evaluate_timing.server_input_seal_duration_ns,
            output_sealing_finalization_duration_ns: 0,
            result_assembly_duration_ns: 0,
            output_materialization_duration_ns,
            output_open_duration_ns: 0,
            public_key_duration_ns: 0,
            total_duration_ns: elapsed_ns(started_ns) as u64,
            output_public_key_hex: hex::encode(public_key),
            output_x_client_base_hex: hex::encode(x_client_base),
            reference_match: x_client_base == state.expected_output.x_client_base
                && public_key == state.expected_output.public_key,
        })
    })?;

    serialize_js_value(&run)
}

#[wasm_bindgen]
pub fn probe_prime_order_ddh_hidden_eval(stage: String) -> Result<JsValue, JsValue> {
    init_wasm_runtime();
    let stop_after = parse_checkpoint(&stage)?;
    let run = WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let state = borrowed
            .as_ref()
            .ok_or_else(|| js_error("prime-order DDH hidden eval is not prepared"))?;
        let probe = state
            .session
            .probe_hidden_eval_for_clear_input(&state.input, stop_after)
            .map_err(js_error)?;
        Ok::<_, JsValue>(probe)
    })?;

    serialize_js_value(&WasmDdhHiddenEvalProbeRun::from_probe(run))
}

#[wasm_bindgen]
pub fn reset_prime_order_ddh_hidden_eval() {
    WASM_DDH_HIDDEN_EVAL_STATE.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn js_error(error: impl ToString) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn serialize_js_value(value: &impl Serialize) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|err| js_error(err.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
fn monotonic_now_ns() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}

#[cfg(target_arch = "wasm32")]
fn monotonic_now_ns() -> u128 {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|performance| (performance.now() * 1_000_000.0) as u128)
        .unwrap_or_else(|| (js_sys::Date::now() * 1_000_000.0) as u128)
}

fn elapsed_ns(started_ns: u128) -> u128 {
    monotonic_now_ns().saturating_sub(started_ns)
}

fn init_wasm_runtime() {
    console_error_panic_hook::set_once();
}

fn parse_checkpoint(value: &str) -> Result<DdhHiddenEvalCheckpoint, JsValue> {
    match value {
        "input_sharing" => Ok(DdhHiddenEvalCheckpoint::InputSharing),
        "add_stage" => Ok(DdhHiddenEvalCheckpoint::AddStage),
        "message_schedule" => Ok(DdhHiddenEvalCheckpoint::MessageSchedule),
        "round_core" => Ok(DdhHiddenEvalCheckpoint::RoundCore),
        "output_projector" => Ok(DdhHiddenEvalCheckpoint::OutputProjector),
        other => Err(js_error(format!("unknown DDH checkpoint: {other}"))),
    }
}

impl WasmDdhHiddenEvalProbeRun {
    fn from_probe(value: DdhHiddenEvalProbe) -> Self {
        Self {
            completed_stage: value.completed_stage,
            stage_profile: value.stage_profile,
            schedule_word_count: value.schedule_word_count,
            hash_prefix_hex: value.hash_prefix_hex,
        }
    }
}
