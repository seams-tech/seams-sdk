use std::collections::BTreeMap;
use std::env;
use std::hint::black_box;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::artifact::PrimeOrderEvaluatorOps;
use crate::benchmark::{ComponentTimingReport, LatencyStats};
use crate::ddh::hidden_eval_executor::{
    prepare_ddh_hidden_eval_constant_pool, probe_prime_order_ddh_hidden_eval_program_with_pool,
};
use crate::ddh::{
    DdhHiddenEvalCheckpoint, DdhHiddenEvalOperationCounts, DdhHiddenEvalStageProfile,
    HiddenEvalInputOwner,
};
use crate::fixtures::{deterministic_fixture_corpus, FExpandFixture};
use crate::protocol::prepare_prime_order_succinct_hss;
use crate::runtime::EvaluateTiming;
use crate::shared::public_key_from_base_shares;
use crate::shared::{ProtoError, ProtoResult};

pub const DDH_HIDDEN_EVAL_BENCHMARK_REPORT_VERSION: &str = "ddh_hidden_eval_benchmark_v1";
pub const DDH_HIDDEN_EVAL_ALLOCATION_PROBE_REPORT_VERSION: &str =
    "ddh_hidden_eval_allocation_probe_v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalBenchmarkConfig {
    pub fixture_name: Option<String>,
    pub primitive_warmup_iterations: u64,
    pub primitive_sample_iterations: u64,
    pub stage_warmup_iterations: u64,
    pub stage_sample_iterations: u64,
    pub sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalBenchmarkConfigRecord {
    pub fixture_name: String,
    pub primitive_warmup_iterations: u64,
    pub primitive_sample_iterations: u64,
    pub stage_warmup_iterations: u64,
    pub stage_sample_iterations: u64,
    pub sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalAllocationProbeConfig {
    pub fixture_name: Option<String>,
    pub warmup_iterations: u64,
    pub sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalAllocationProbeConfigRecord {
    pub fixture_name: String,
    pub warmup_iterations: u64,
    pub sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalBenchmarkMetadata {
    pub generated_at_unix_secs: u64,
    pub host_os: String,
    pub host_arch: String,
    pub logical_cores: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DdhHiddenEvalBenchmarkReport {
    pub report_version: String,
    pub metadata: DdhHiddenEvalBenchmarkMetadata,
    pub fixture_name: String,
    pub artifact_bytes: u64,
    pub active_window_records: usize,
    pub total_steps: usize,
    pub curve_cost_units: u64,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub prepare_duration_ns: u128,
    pub config: DdhHiddenEvalBenchmarkConfigRecord,
    pub primitive_timings: Vec<ComponentTimingReport>,
    pub stage_timings: Vec<ComponentTimingReport>,
    pub substage_timings: Vec<ComponentTimingReport>,
    pub delivery_timings: Vec<ComponentTimingReport>,
    pub operation_counts: DdhHiddenEvalOperationCounts,
    pub reference_match: bool,
    pub output_public_key_hex: String,
    pub output_x_client_base_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalAllocationMeasurement {
    pub allocation_calls: u64,
    pub deallocation_calls: u64,
    pub reallocation_calls: u64,
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    pub live_bytes_before: u64,
    pub live_bytes_after: u64,
    pub live_bytes_delta: i128,
    pub peak_live_bytes_above_start: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalAllocationProbeSample {
    pub sample_index: usize,
    pub operation: String,
    pub measurement: DdhHiddenEvalAllocationMeasurement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalAllocationProbeReport {
    pub report_version: String,
    pub metadata: DdhHiddenEvalBenchmarkMetadata,
    pub fixture_name: String,
    pub config: DdhHiddenEvalAllocationProbeConfigRecord,
    pub samples: Vec<DdhHiddenEvalAllocationProbeSample>,
}

pub trait DdhHiddenEvalAllocationRecorder {
    fn measure<F>(
        &mut self,
        operation: &'static str,
        op: F,
    ) -> ProtoResult<DdhHiddenEvalAllocationMeasurement>
    where
        F: FnOnce() -> ProtoResult<()>;
}

pub fn default_ddh_hidden_eval_benchmark_config() -> DdhHiddenEvalBenchmarkConfig {
    DdhHiddenEvalBenchmarkConfig {
        fixture_name: None,
        primitive_warmup_iterations: 1_000,
        primitive_sample_iterations: 10_000,
        stage_warmup_iterations: 0,
        stage_sample_iterations: 1,
        sample_count: 6,
    }
}

pub fn default_ddh_hidden_eval_allocation_probe_config() -> DdhHiddenEvalAllocationProbeConfig {
    DdhHiddenEvalAllocationProbeConfig {
        fixture_name: None,
        warmup_iterations: 1,
        sample_count: 5,
    }
}

pub fn generate_ddh_hidden_eval_benchmark_report(
    config: &DdhHiddenEvalBenchmarkConfig,
) -> ProtoResult<DdhHiddenEvalBenchmarkReport> {
    let fixture = select_fixture(config.fixture_name.as_deref())?;
    let metadata = capture_benchmark_metadata();

    let prepare_started = Instant::now();
    let session = prepare_prime_order_succinct_hss(&fixture.input.context)?;
    let prepare_duration_ns = prepare_started.elapsed().as_nanos();
    let output_openers = session.output_openers();

    let baseline_report = session.evaluate_for_clear_input_debug(&fixture.input)?;
    let baseline_x_client_base = output_openers
        .client
        .open(&baseline_report.output_delivery.client)?;
    let baseline_x_relayer_base = output_openers
        .server
        .open(&baseline_report.output_delivery.server)?;
    let baseline_public_key =
        public_key_from_base_shares(baseline_x_client_base, baseline_x_relayer_base)?;
    if baseline_x_client_base != fixture.output.x_client_base
        || baseline_x_relayer_base != fixture.output.x_relayer_base
        || baseline_public_key != fixture.output.public_key
    {
        return Err(ProtoError::Decode(
            "baseline DDH delivery-path output does not match frozen fixture".to_string(),
        ));
    }

    let primitive_timings = benchmark_primitives(config, session.ddh_backend())?;

    for _ in 0..config.stage_warmup_iterations {
        let (delivery_report, delivery_timing) =
            session.evaluate_for_clear_input_debug_timed(&fixture.input)?;
        let x_client_base = output_openers
            .client
            .open(&delivery_report.output_delivery.client)?;
        let x_relayer_base = output_openers
            .server
            .open(&delivery_report.output_delivery.server)?;
        let public_key = public_key_from_base_shares(x_client_base, x_relayer_base)?;
        if x_client_base != fixture.output.x_client_base
            || x_relayer_base != fixture.output.x_relayer_base
            || public_key != fixture.output.public_key
        {
            return Err(ProtoError::Decode(
                "warmup DDH delivery-path output does not match frozen fixture".to_string(),
            ));
        }
        let profile = session.profile_hidden_eval_for_clear_input(&fixture.input)?;
        black_box(session.materialize_hidden_outputs_for_debug(&profile.run.output)?);
        black_box(delivery_timing);
    }

    let mut input_sharing_samples = Vec::with_capacity(config.sample_count);
    let mut add_stage_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_samples = Vec::with_capacity(config.sample_count);
    let mut round_core_samples = Vec::with_capacity(config.sample_count);
    let mut round_sigma0_samples = Vec::with_capacity(config.sample_count);
    let mut round_sigma1_samples = Vec::with_capacity(config.sample_count);
    let mut round_ch_samples = Vec::with_capacity(config.sample_count);
    let mut round_maj_samples = Vec::with_capacity(config.sample_count);
    let mut round_state3_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp2_samples = Vec::with_capacity(config.sample_count);
    let mut round_new_a_bits_samples = Vec::with_capacity(config.sample_count);
    let mut round_new_e_bits_samples = Vec::with_capacity(config.sample_count);
    let mut output_projector_samples = Vec::with_capacity(config.sample_count);
    let mut total_samples = Vec::with_capacity(config.sample_count);
    let mut direct_unbucketed_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_total_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_ot_open_join_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_ot_branch_key_derivation_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_ot_branch_decrypt_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_ot_point_scalar_reconstruction_samples =
        Vec::with_capacity(config.sample_count);
    let mut delivery_ot_commitment_verification_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_server_input_open_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_server_input_share_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_server_input_commitment_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_server_input_transcript_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_result_assembly_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_output_sealing_finalization_samples = Vec::with_capacity(config.sample_count);
    let mut delivery_unbucketed_samples = Vec::with_capacity(config.sample_count);
    let mut operation_counts = DdhHiddenEvalOperationCounts::default();

    for _ in 0..config.sample_count {
        let mut input_sharing_total_ns = 0f64;
        let mut add_stage_total_ns = 0f64;
        let mut message_schedule_total_ns = 0f64;
        let mut message_schedule_accumulation_total_ns = 0f64;
        let mut round_core_total_ns = 0f64;
        let mut round_sigma0_total_ns = 0f64;
        let mut round_sigma1_total_ns = 0f64;
        let mut round_ch_total_ns = 0f64;
        let mut round_maj_total_ns = 0f64;
        let mut round_state3_total_ns = 0f64;
        let mut round_temp1_total_ns = 0f64;
        let mut round_temp2_total_ns = 0f64;
        let mut round_new_a_bits_total_ns = 0f64;
        let mut round_new_e_bits_total_ns = 0f64;
        let mut output_projector_total_ns = 0f64;
        let mut total_total_ns = 0f64;
        let mut direct_unbucketed_total_ns = 0f64;
        let mut delivery_total_total_ns = 0f64;
        let mut delivery_ot_open_join_total_ns = 0f64;
        let mut delivery_ot_branch_key_derivation_total_ns = 0f64;
        let mut delivery_ot_branch_decrypt_total_ns = 0f64;
        let mut delivery_ot_point_scalar_reconstruction_total_ns = 0f64;
        let mut delivery_ot_commitment_verification_total_ns = 0f64;
        let mut delivery_server_input_open_total_ns = 0f64;
        let mut delivery_server_input_share_total_ns = 0f64;
        let mut delivery_server_input_commitment_total_ns = 0f64;
        let mut delivery_server_input_transcript_total_ns = 0f64;
        let mut delivery_result_assembly_total_ns = 0f64;
        let mut delivery_output_sealing_finalization_total_ns = 0f64;
        let mut delivery_unbucketed_total_ns = 0f64;

        for _ in 0..config.stage_sample_iterations {
            let profile = session.profile_hidden_eval_for_clear_input(&fixture.input)?;
            let (x_client_base, x_relayer_base, public_key) =
                session.materialize_hidden_outputs_for_debug(&profile.run.output)?;
            if x_client_base != fixture.output.x_client_base
                || x_relayer_base != fixture.output.x_relayer_base
                || public_key != fixture.output.public_key
            {
                return Err(ProtoError::Decode(
                    "sampled DDH hidden-eval output does not match frozen fixture".to_string(),
                ));
            }

            let direct_profile_total_ns = profile.stage_profile.total_duration_ns as f64;
            input_sharing_total_ns += profile.stage_profile.input_sharing_duration_ns as f64;
            add_stage_total_ns += profile.stage_profile.add_stage_duration_ns as f64;
            message_schedule_total_ns += profile.stage_profile.message_schedule_duration_ns as f64;
            message_schedule_accumulation_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_duration_ns
                as f64;
            round_core_total_ns += profile.stage_profile.round_core_duration_ns as f64;
            round_sigma0_total_ns += profile.stage_profile.round_sigma0_duration_ns as f64;
            round_sigma1_total_ns += profile.stage_profile.round_sigma1_duration_ns as f64;
            round_ch_total_ns += profile.stage_profile.round_ch_duration_ns as f64;
            round_maj_total_ns += profile.stage_profile.round_maj_duration_ns as f64;
            round_state3_total_ns += profile.stage_profile.round_state3_duration_ns as f64;
            round_temp1_total_ns += profile.stage_profile.round_temp1_duration_ns as f64;
            round_temp2_total_ns += profile.stage_profile.round_temp2_duration_ns as f64;
            round_new_a_bits_total_ns += profile.stage_profile.round_new_a_bits_duration_ns as f64;
            round_new_e_bits_total_ns += profile.stage_profile.round_new_e_bits_duration_ns as f64;
            output_projector_total_ns += profile.stage_profile.output_projector_duration_ns as f64;
            total_total_ns += direct_profile_total_ns;
            direct_unbucketed_total_ns += direct_executor_unbucketed_ns(&profile.stage_profile);
            operation_counts = profile.stage_profile.operation_counts;

            let delivery_started = Instant::now();
            let (delivery_report, delivery_timing) =
                session.evaluate_for_clear_input_debug_timed(&fixture.input)?;
            let delivery_total_ns = delivery_started.elapsed().as_nanos() as f64;
            let delivery_x_client_base = output_openers
                .client
                .open(&delivery_report.output_delivery.client)?;
            let delivery_x_relayer_base = output_openers
                .server
                .open(&delivery_report.output_delivery.server)?;
            let delivery_public_key =
                public_key_from_base_shares(delivery_x_client_base, delivery_x_relayer_base)?;
            if delivery_x_client_base != fixture.output.x_client_base
                || delivery_x_relayer_base != fixture.output.x_relayer_base
                || delivery_public_key != fixture.output.public_key
            {
                return Err(ProtoError::Decode(
                    "sampled DDH delivery-path output does not match frozen fixture".to_string(),
                ));
            }
            delivery_total_total_ns += delivery_total_ns;
            delivery_ot_open_join_total_ns += delivery_timing.ot_open_join_duration_ns as f64;
            delivery_ot_branch_key_derivation_total_ns +=
                delivery_timing.ot_branch_key_derivation_duration_ns as f64;
            delivery_ot_branch_decrypt_total_ns +=
                delivery_timing.ot_branch_decrypt_duration_ns as f64;
            delivery_ot_point_scalar_reconstruction_total_ns +=
                delivery_timing.ot_point_scalar_reconstruction_duration_ns as f64;
            delivery_ot_commitment_verification_total_ns +=
                delivery_timing.ot_commitment_verification_duration_ns as f64;
            delivery_server_input_open_total_ns +=
                delivery_timing.server_input_open_duration_ns as f64;
            delivery_server_input_share_total_ns +=
                delivery_timing.server_input_share_duration_ns as f64;
            delivery_server_input_commitment_total_ns +=
                delivery_timing.server_input_commitment_duration_ns as f64;
            delivery_server_input_transcript_total_ns +=
                delivery_timing.server_input_transcript_duration_ns as f64;
            delivery_result_assembly_total_ns += delivery_timing.result_assembly_duration_ns as f64;
            delivery_output_sealing_finalization_total_ns +=
                delivery_timing.output_sealing_finalization_duration_ns as f64;
            delivery_unbucketed_total_ns += delivery_unbucketed_ns(
                delivery_total_ns,
                &delivery_timing,
                direct_profile_total_ns,
            );

            black_box((
                x_client_base,
                x_relayer_base,
                public_key,
                delivery_x_client_base,
                delivery_x_relayer_base,
                delivery_public_key,
            ));
        }

        let iterations = config.stage_sample_iterations as f64;
        input_sharing_samples.push(input_sharing_total_ns / iterations);
        add_stage_samples.push(add_stage_total_ns / iterations);
        message_schedule_samples.push(message_schedule_total_ns / iterations);
        message_schedule_accumulation_samples
            .push(message_schedule_accumulation_total_ns / iterations);
        round_core_samples.push(round_core_total_ns / iterations);
        round_sigma0_samples.push(round_sigma0_total_ns / iterations);
        round_sigma1_samples.push(round_sigma1_total_ns / iterations);
        round_ch_samples.push(round_ch_total_ns / iterations);
        round_maj_samples.push(round_maj_total_ns / iterations);
        round_state3_samples.push(round_state3_total_ns / iterations);
        round_temp1_samples.push(round_temp1_total_ns / iterations);
        round_temp2_samples.push(round_temp2_total_ns / iterations);
        round_new_a_bits_samples.push(round_new_a_bits_total_ns / iterations);
        round_new_e_bits_samples.push(round_new_e_bits_total_ns / iterations);
        output_projector_samples.push(output_projector_total_ns / iterations);
        total_samples.push(total_total_ns / iterations);
        direct_unbucketed_samples.push(direct_unbucketed_total_ns / iterations);
        delivery_total_samples.push(delivery_total_total_ns / iterations);
        delivery_ot_open_join_samples.push(delivery_ot_open_join_total_ns / iterations);
        delivery_ot_branch_key_derivation_samples
            .push(delivery_ot_branch_key_derivation_total_ns / iterations);
        delivery_ot_branch_decrypt_samples.push(delivery_ot_branch_decrypt_total_ns / iterations);
        delivery_ot_point_scalar_reconstruction_samples
            .push(delivery_ot_point_scalar_reconstruction_total_ns / iterations);
        delivery_ot_commitment_verification_samples
            .push(delivery_ot_commitment_verification_total_ns / iterations);
        delivery_server_input_open_samples.push(delivery_server_input_open_total_ns / iterations);
        delivery_server_input_share_samples.push(delivery_server_input_share_total_ns / iterations);
        delivery_server_input_commitment_samples
            .push(delivery_server_input_commitment_total_ns / iterations);
        delivery_server_input_transcript_samples
            .push(delivery_server_input_transcript_total_ns / iterations);
        delivery_result_assembly_samples.push(delivery_result_assembly_total_ns / iterations);
        delivery_output_sealing_finalization_samples
            .push(delivery_output_sealing_finalization_total_ns / iterations);
        delivery_unbucketed_samples.push(delivery_unbucketed_total_ns / iterations);
    }

    let stage_timings = vec![
        component_report(
            "input_sharing",
            config.stage_sample_iterations,
            input_sharing_samples,
        ),
        component_report(
            "add_stage",
            config.stage_sample_iterations,
            add_stage_samples,
        ),
        component_report(
            "message_schedule",
            config.stage_sample_iterations,
            message_schedule_samples,
        ),
        component_report(
            "round_core",
            config.stage_sample_iterations,
            round_core_samples,
        ),
        component_report(
            "output_projector",
            config.stage_sample_iterations,
            output_projector_samples,
        ),
        component_report(
            "total_hidden_eval",
            config.stage_sample_iterations,
            total_samples,
        ),
        component_report(
            "direct_executor_unbucketed",
            config.stage_sample_iterations,
            direct_unbucketed_samples,
        ),
    ];
    let substage_timings = vec![
        component_report(
            "message_schedule_accumulation",
            config.stage_sample_iterations,
            message_schedule_accumulation_samples,
        ),
        component_report(
            "round_sigma1",
            config.stage_sample_iterations,
            round_sigma1_samples,
        ),
        component_report(
            "round_sigma0",
            config.stage_sample_iterations,
            round_sigma0_samples,
        ),
        component_report("round_ch", config.stage_sample_iterations, round_ch_samples),
        component_report(
            "round_maj",
            config.stage_sample_iterations,
            round_maj_samples,
        ),
        component_report(
            "round_state3",
            config.stage_sample_iterations,
            round_state3_samples,
        ),
        component_report(
            "round_temp1",
            config.stage_sample_iterations,
            round_temp1_samples,
        ),
        component_report(
            "round_temp2",
            config.stage_sample_iterations,
            round_temp2_samples,
        ),
        component_report(
            "round_new_a_bits",
            config.stage_sample_iterations,
            round_new_a_bits_samples,
        ),
        component_report(
            "round_new_e_bits",
            config.stage_sample_iterations,
            round_new_e_bits_samples,
        ),
    ];
    let delivery_timings = vec![
        component_report(
            "delivery_total",
            config.stage_sample_iterations,
            delivery_total_samples,
        ),
        component_report(
            "delivery_unbucketed",
            config.stage_sample_iterations,
            delivery_unbucketed_samples,
        ),
        component_report(
            "ot_open_join",
            config.stage_sample_iterations,
            delivery_ot_open_join_samples,
        ),
        component_report(
            "ot_branch_key_derivation",
            config.stage_sample_iterations,
            delivery_ot_branch_key_derivation_samples,
        ),
        component_report(
            "ot_branch_decrypt",
            config.stage_sample_iterations,
            delivery_ot_branch_decrypt_samples,
        ),
        component_report(
            "ot_point_scalar_reconstruction",
            config.stage_sample_iterations,
            delivery_ot_point_scalar_reconstruction_samples,
        ),
        component_report(
            "ot_commitment_verification",
            config.stage_sample_iterations,
            delivery_ot_commitment_verification_samples,
        ),
        component_report(
            "server_input_open",
            config.stage_sample_iterations,
            delivery_server_input_open_samples,
        ),
        component_report(
            "server_input_share",
            config.stage_sample_iterations,
            delivery_server_input_share_samples,
        ),
        component_report(
            "server_input_commitment",
            config.stage_sample_iterations,
            delivery_server_input_commitment_samples,
        ),
        component_report(
            "server_input_transcript",
            config.stage_sample_iterations,
            delivery_server_input_transcript_samples,
        ),
        component_report(
            "result_assembly",
            config.stage_sample_iterations,
            delivery_result_assembly_samples,
        ),
        component_report(
            "output_sealing_finalization",
            config.stage_sample_iterations,
            delivery_output_sealing_finalization_samples,
        ),
    ];

    Ok(DdhHiddenEvalBenchmarkReport {
        report_version: DDH_HIDDEN_EVAL_BENCHMARK_REPORT_VERSION.to_string(),
        metadata,
        fixture_name: fixture.name.clone(),
        artifact_bytes: session.artifact_summary().artifact_bytes,
        active_window_records: session.hidden_eval_program().active_window_records,
        total_steps: session.execution_program().trace.total_steps,
        curve_cost_units: session.execution_program().trace.estimated_curve_cost_units,
        evaluator_ops: session.execution_program().trace.evaluator_ops.clone(),
        prepare_duration_ns,
        config: DdhHiddenEvalBenchmarkConfigRecord {
            fixture_name: fixture.name,
            primitive_warmup_iterations: config.primitive_warmup_iterations,
            primitive_sample_iterations: config.primitive_sample_iterations,
            stage_warmup_iterations: config.stage_warmup_iterations,
            stage_sample_iterations: config.stage_sample_iterations,
            sample_count: config.sample_count,
        },
        primitive_timings,
        stage_timings,
        substage_timings,
        delivery_timings,
        operation_counts,
        reference_match: true,
        output_public_key_hex: hex::encode(baseline_public_key),
        output_x_client_base_hex: hex::encode(baseline_x_client_base),
    })
}

pub fn generate_ddh_hidden_eval_allocation_probe_report<R>(
    config: &DdhHiddenEvalAllocationProbeConfig,
    recorder: &mut R,
) -> ProtoResult<DdhHiddenEvalAllocationProbeReport>
where
    R: DdhHiddenEvalAllocationRecorder,
{
    let fixture = select_fixture(config.fixture_name.as_deref())?;
    let metadata = capture_benchmark_metadata();
    let checkpoint_operations = ddh_hidden_eval_allocation_checkpoint_operations();
    let mut samples = Vec::with_capacity(
        config
            .sample_count
            .saturating_mul(3usize.saturating_add(checkpoint_operations.len()))
            .saturating_add(1),
    );

    let mut prepared_session = None;
    let prepare_measurement = recorder.measure("prepare_prime_order_succinct_hss", || {
        prepared_session = Some(prepare_prime_order_succinct_hss(&fixture.input.context)?);
        Ok(())
    })?;
    samples.push(DdhHiddenEvalAllocationProbeSample {
        sample_index: 0,
        operation: "prepare_prime_order_succinct_hss".to_string(),
        measurement: prepare_measurement,
    });

    let session = prepared_session.ok_or_else(|| {
        ProtoError::InvalidInput("allocation probe did not prepare session".to_string())
    })?;
    let output_openers = session.output_openers();
    let checkpoint_constant_pool = prepare_ddh_hidden_eval_constant_pool(session.ddh_backend())?;

    for _ in 0..config.warmup_iterations {
        let profile = session.profile_hidden_eval_for_clear_input(&fixture.input)?;
        black_box(session.materialize_hidden_outputs_for_debug(&profile.run.output)?);
        black_box(session.evaluate_for_clear_input_debug_timed(&fixture.input)?);
    }

    for sample_index in 0..config.sample_count {
        let mut hidden_eval_profile = None;
        let hidden_eval_measurement =
            recorder.measure("profile_hidden_eval_for_clear_input", || {
                hidden_eval_profile =
                    Some(session.profile_hidden_eval_for_clear_input(&fixture.input)?);
                Ok(())
            })?;
        samples.push(DdhHiddenEvalAllocationProbeSample {
            sample_index,
            operation: "profile_hidden_eval_for_clear_input".to_string(),
            measurement: hidden_eval_measurement,
        });

        for (checkpoint, operation) in checkpoint_operations {
            let checkpoint_measurement = recorder.measure(operation, || {
                let probe = probe_prime_order_ddh_hidden_eval_program_with_pool(
                    session.hidden_eval_program(),
                    session.ddh_backend(),
                    &checkpoint_constant_pool,
                    &fixture.input,
                    *checkpoint,
                )?;
                black_box(probe);
                Ok(())
            })?;
            samples.push(DdhHiddenEvalAllocationProbeSample {
                sample_index,
                operation: (*operation).to_string(),
                measurement: checkpoint_measurement,
            });
        }

        let profile = hidden_eval_profile.ok_or_else(|| {
            ProtoError::InvalidInput(
                "allocation probe did not capture hidden-eval profile".to_string(),
            )
        })?;
        let materialize_measurement =
            recorder.measure("materialize_hidden_outputs_for_debug", || {
                let (x_client_base, x_relayer_base, public_key) =
                    session.materialize_hidden_outputs_for_debug(&profile.run.output)?;
                validate_fixture_outputs(
                    &fixture,
                    x_client_base,
                    x_relayer_base,
                    public_key,
                    "allocation probe materialized hidden output",
                )?;
                black_box((x_client_base, x_relayer_base, public_key));
                Ok(())
            })?;
        samples.push(DdhHiddenEvalAllocationProbeSample {
            sample_index,
            operation: "materialize_hidden_outputs_for_debug".to_string(),
            measurement: materialize_measurement,
        });

        let delivery_measurement =
            recorder.measure("evaluate_for_clear_input_debug_timed", || {
                let (delivery_report, delivery_timing) =
                    session.evaluate_for_clear_input_debug_timed(&fixture.input)?;
                let delivery_x_client_base = output_openers
                    .client
                    .open(&delivery_report.output_delivery.client)?;
                let delivery_x_relayer_base = output_openers
                    .server
                    .open(&delivery_report.output_delivery.server)?;
                let delivery_public_key =
                    public_key_from_base_shares(delivery_x_client_base, delivery_x_relayer_base)?;
                validate_fixture_outputs(
                    &fixture,
                    delivery_x_client_base,
                    delivery_x_relayer_base,
                    delivery_public_key,
                    "allocation probe delivery output",
                )?;
                black_box((
                    delivery_report,
                    delivery_timing,
                    delivery_x_client_base,
                    delivery_x_relayer_base,
                    delivery_public_key,
                ));
                Ok(())
            })?;
        samples.push(DdhHiddenEvalAllocationProbeSample {
            sample_index,
            operation: "evaluate_for_clear_input_debug_timed".to_string(),
            measurement: delivery_measurement,
        });
    }

    Ok(DdhHiddenEvalAllocationProbeReport {
        report_version: DDH_HIDDEN_EVAL_ALLOCATION_PROBE_REPORT_VERSION.to_string(),
        metadata,
        fixture_name: fixture.name.clone(),
        config: DdhHiddenEvalAllocationProbeConfigRecord {
            fixture_name: fixture.name,
            warmup_iterations: config.warmup_iterations,
            sample_count: config.sample_count,
        },
        samples,
    })
}

impl DdhHiddenEvalBenchmarkReport {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "ddh hidden eval: fixture={} artifact={}B active_windows={} steps={} curve_cost={} reference_match={} generated_at={} host={}/{} cores={}",
                self.fixture_name,
                self.artifact_bytes,
                self.active_window_records,
                self.total_steps,
                self.curve_cost_units,
                self.reference_match,
                self.metadata.generated_at_unix_secs,
                self.metadata.host_os,
                self.metadata.host_arch,
                self.metadata.logical_cores,
            ),
            format!(
                "prepare: {}ns public_key={} x_client={}",
                self.prepare_duration_ns, self.output_public_key_hex, self.output_x_client_base_hex,
            ),
        ];

        for report in &self.primitive_timings {
            lines.push(format!(
                "primitive {}: mean={:.1}ns median={:.1}ns p95={:.1}ns throughput_mean={:.2} ops/s",
                report.name,
                report.latency_ns_per_op.mean,
                report.latency_ns_per_op.median,
                report.latency_ns_per_op.p95,
                report.throughput_ops_per_sec.mean,
            ));
        }

        for report in &self.stage_timings {
            lines.push(format!(
                "stage {}: mean={:.1}ns median={:.1}ns p95={:.1}ns throughput_mean={:.4} runs/s",
                report.name,
                report.latency_ns_per_op.mean,
                report.latency_ns_per_op.median,
                report.latency_ns_per_op.p95,
                report.throughput_ops_per_sec.mean,
            ));
        }

        for report in &self.delivery_timings {
            lines.push(format!(
                "delivery {}: mean={:.1}ns median={:.1}ns p95={:.1}ns throughput_mean={:.4} runs/s",
                report.name,
                report.latency_ns_per_op.mean,
                report.latency_ns_per_op.median,
                report.latency_ns_per_op.p95,
                report.throughput_ops_per_sec.mean,
            ));
        }

        if self.operation_counts.physical_keyed_digest_derivations > 0
            || self.operation_counts.physical_derived_commitment_hashes > 0
            || self.operation_counts.physical_add_bit_hashes > 0
            || self.operation_counts.physical_mul_material_hashes > 0
            || self.operation_counts.physical_mul_output_seed_hashes > 0
        {
            lines.push(format!(
                "physical hashes: keyed_digest={} derived_commitment={} add_bit={} mul_material={} mul_output_seed={}",
                self.operation_counts.physical_keyed_digest_derivations,
                self.operation_counts.physical_derived_commitment_hashes,
                self.operation_counts.physical_add_bit_hashes,
                self.operation_counts.physical_mul_material_hashes,
                self.operation_counts.physical_mul_output_seed_hashes,
            ));
            lines.push(format!(
                "physical keyed digest domains: eval_xor_local_word={} eval_add_local={} eval_mul_local_material={} eval_mul_local={} phase_a_arith_share_to_bool={} phase_a_bool_to_arith_base={} phase_a_arith_to_bool_zero={} compose_word_from_share_bits={} share_word={} other={}",
                self.operation_counts.physical_keyed_digest_eval_xor_local_word,
                self.operation_counts.physical_keyed_digest_eval_add_local,
                self.operation_counts.physical_keyed_digest_eval_mul_local_material,
                self.operation_counts.physical_keyed_digest_eval_mul_local,
                self.operation_counts.physical_keyed_digest_phase_a_arith_share_to_bool,
                self.operation_counts.physical_keyed_digest_phase_a_bool_to_arith_base,
                self.operation_counts.physical_keyed_digest_phase_a_arith_to_bool_zero,
                self.operation_counts.physical_keyed_digest_compose_word_from_share_bits,
                self.operation_counts.physical_keyed_digest_share_word,
                self.operation_counts.physical_keyed_digest_other,
            ));
            lines.push(format!(
                "physical derived commitment domains: eval_xor_local_word={} eval_add_local={} eval_mul_local_material={} eval_mul_local={} phase_a_arith_share_to_bool={} phase_a_bool_to_arith_base={} phase_a_arith_to_bool_zero={} compose_word_from_share_bits={} share_word={} other={}",
                self.operation_counts.physical_derived_commitment_eval_xor_local_word,
                self.operation_counts.physical_derived_commitment_eval_add_local,
                self.operation_counts.physical_derived_commitment_eval_mul_local_material,
                self.operation_counts.physical_derived_commitment_eval_mul_local,
                self.operation_counts.physical_derived_commitment_phase_a_arith_share_to_bool,
                self.operation_counts.physical_derived_commitment_phase_a_bool_to_arith_base,
                self.operation_counts.physical_derived_commitment_phase_a_arith_to_bool_zero,
                self.operation_counts.physical_derived_commitment_compose_word_from_share_bits,
                self.operation_counts.physical_derived_commitment_share_word,
                self.operation_counts.physical_derived_commitment_other,
            ));
        }

        lines
    }
}

impl DdhHiddenEvalAllocationProbeReport {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "ddh hidden eval allocation probe: fixture={} samples={} warmup={} generated_at={} host={}/{} cores={}",
            self.fixture_name,
            self.config.sample_count,
            self.config.warmup_iterations,
            self.metadata.generated_at_unix_secs,
            self.metadata.host_os,
            self.metadata.host_arch,
            self.metadata.logical_cores,
        )];

        for (operation, samples) in allocation_samples_by_operation(&self.samples) {
            let allocated_bytes = stats_from_samples(
                samples
                    .iter()
                    .map(|sample| sample.allocated_bytes as f64)
                    .collect(),
            );
            let allocation_calls = stats_from_samples(
                samples
                    .iter()
                    .map(|sample| sample.allocation_calls as f64)
                    .collect(),
            );
            let peak_live = stats_from_samples(
                samples
                    .iter()
                    .map(|sample| sample.peak_live_bytes_above_start as f64)
                    .collect(),
            );
            lines.push(format!(
                "allocation {operation}: allocated_bytes median={:.0} p95={:.0} allocation_calls median={:.0} p95={:.0} peak_live_above_start median={:.0} p95={:.0}",
                allocated_bytes.median,
                allocated_bytes.p95,
                allocation_calls.median,
                allocation_calls.p95,
                peak_live.median,
                peak_live.p95,
            ));
        }

        lines
    }
}

fn allocation_samples_by_operation(
    samples: &[DdhHiddenEvalAllocationProbeSample],
) -> BTreeMap<&str, Vec<&DdhHiddenEvalAllocationMeasurement>> {
    let mut grouped = BTreeMap::new();
    for sample in samples {
        grouped
            .entry(sample.operation.as_str())
            .or_insert_with(Vec::new)
            .push(&sample.measurement);
    }
    grouped
}

fn ddh_hidden_eval_allocation_checkpoint_operations(
) -> &'static [(DdhHiddenEvalCheckpoint, &'static str)] {
    &[
        (
            DdhHiddenEvalCheckpoint::InputSharing,
            "probe_checkpoint_input_sharing",
        ),
        (
            DdhHiddenEvalCheckpoint::AddStage,
            "probe_checkpoint_add_stage",
        ),
        (
            DdhHiddenEvalCheckpoint::MessageSchedule,
            "probe_checkpoint_message_schedule",
        ),
        (
            DdhHiddenEvalCheckpoint::RoundCore,
            "probe_checkpoint_round_core",
        ),
        (
            DdhHiddenEvalCheckpoint::OutputProjector,
            "probe_checkpoint_output_projector",
        ),
    ]
}

fn capture_benchmark_metadata() -> DdhHiddenEvalBenchmarkMetadata {
    DdhHiddenEvalBenchmarkMetadata {
        generated_at_unix_secs: unix_timestamp_now(),
        host_os: env::consts::OS.to_string(),
        host_arch: env::consts::ARCH.to_string(),
        logical_cores: thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1),
    }
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn direct_executor_unbucketed_ns(stage_profile: &DdhHiddenEvalStageProfile) -> f64 {
    let accounted_ns = stage_profile
        .input_sharing_duration_ns
        .saturating_add(stage_profile.add_stage_duration_ns)
        .saturating_add(stage_profile.message_schedule_duration_ns)
        .saturating_add(stage_profile.round_core_duration_ns)
        .saturating_add(stage_profile.output_projector_duration_ns);
    stage_profile.total_duration_ns.saturating_sub(accounted_ns) as f64
}

fn validate_fixture_outputs(
    fixture: &FExpandFixture,
    x_client_base: [u8; 32],
    x_relayer_base: [u8; 32],
    public_key: [u8; 32],
    context: &str,
) -> ProtoResult<()> {
    if x_client_base != fixture.output.x_client_base
        || x_relayer_base != fixture.output.x_relayer_base
        || public_key != fixture.output.public_key
    {
        return Err(ProtoError::Decode(format!(
            "{context} does not match frozen fixture"
        )));
    }
    Ok(())
}

fn delivery_unbucketed_ns(
    delivery_total_ns: f64,
    timing: &EvaluateTiming,
    direct_executor_total_ns: f64,
) -> f64 {
    let accounted_ns = timing
        .ot_open_join_duration_ns
        .saturating_add(timing.server_input_open_duration_ns)
        .saturating_add(timing.result_assembly_duration_ns)
        .saturating_add(timing.output_sealing_finalization_duration_ns)
        as f64
        + direct_executor_total_ns;
    (delivery_total_ns - accounted_ns).max(0.0)
}

fn benchmark_primitives(
    config: &DdhHiddenEvalBenchmarkConfig,
    backend: &crate::ddh::DdhHssBackend,
) -> ProtoResult<Vec<ComponentTimingReport>> {
    let left_bit = backend.share_word(HiddenEvalInputOwner::Client, "bench/left_bit", 1, 1)?;
    let right_bit = backend.share_word(HiddenEvalInputOwner::Server, "bench/right_bit", 1, 1)?;
    let left_byte = backend.share_word(HiddenEvalInputOwner::Client, "bench/left_byte", 0x34, 8)?;
    let right_byte =
        backend.share_word(HiddenEvalInputOwner::Server, "bench/right_byte", 0x29, 8)?;
    let bit_mul_material = backend.prepare_mul_material(&left_bit, &right_bit)?;
    let byte_mul_material = backend.prepare_mul_material(&left_byte, &right_byte)?;

    Ok(vec![
        benchmark_operation(
            "share_bit",
            config.primitive_warmup_iterations,
            config.primitive_sample_iterations,
            config.sample_count,
            || {
                black_box(backend.share_word(
                    HiddenEvalInputOwner::Client,
                    "bench/share_bit",
                    1,
                    1,
                )?);
                Ok(())
            },
        )?,
        benchmark_operation(
            "share_byte",
            config.primitive_warmup_iterations,
            config.primitive_sample_iterations,
            config.sample_count,
            || {
                black_box(backend.share_word(
                    HiddenEvalInputOwner::Client,
                    "bench/share_byte",
                    0xabu64,
                    8,
                )?);
                Ok(())
            },
        )?,
        benchmark_operation(
            "eval_add_bit",
            config.primitive_warmup_iterations,
            config.primitive_sample_iterations,
            config.sample_count,
            || {
                black_box(backend.eval_add_mod_2_pow_n(&left_bit, &right_bit)?);
                Ok(())
            },
        )?,
        benchmark_operation(
            "eval_mul_bit",
            config.primitive_warmup_iterations,
            config.primitive_sample_iterations,
            config.sample_count,
            || {
                black_box(backend.eval_mul_mod_2_pow_n(
                    &left_bit,
                    &right_bit,
                    &bit_mul_material,
                )?);
                Ok(())
            },
        )?,
        benchmark_operation(
            "eval_add_byte",
            config.primitive_warmup_iterations,
            config.primitive_sample_iterations,
            config.sample_count,
            || {
                black_box(backend.eval_add_mod_2_pow_n(&left_byte, &right_byte)?);
                Ok(())
            },
        )?,
        benchmark_operation(
            "eval_mul_byte",
            config.primitive_warmup_iterations,
            config.primitive_sample_iterations,
            config.sample_count,
            || {
                black_box(backend.eval_mul_mod_2_pow_n(
                    &left_byte,
                    &right_byte,
                    &byte_mul_material,
                )?);
                Ok(())
            },
        )?,
    ])
}

fn benchmark_operation<F>(
    name: &str,
    warmup_iterations: u64,
    sample_iterations: u64,
    sample_count: usize,
    mut op: F,
) -> ProtoResult<ComponentTimingReport>
where
    F: FnMut() -> ProtoResult<()>,
{
    for _ in 0..warmup_iterations {
        op()?;
    }

    let mut per_op_latencies = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let started = Instant::now();
        for _ in 0..sample_iterations {
            op()?;
        }
        let elapsed = started.elapsed();
        per_op_latencies.push(elapsed.as_nanos() as f64 / sample_iterations as f64);
    }

    Ok(component_report(name, sample_iterations, per_op_latencies))
}

fn component_report(
    name: &str,
    iterations_per_sample: u64,
    per_op_latencies: Vec<f64>,
) -> ComponentTimingReport {
    let throughput_samples = per_op_latencies
        .iter()
        .map(|latency| {
            if *latency > 0.0 {
                1_000_000_000.0 / latency
            } else {
                0.0
            }
        })
        .collect::<Vec<_>>();

    ComponentTimingReport {
        name: name.to_string(),
        sample_count: per_op_latencies.len(),
        iterations_per_sample,
        total_iterations: iterations_per_sample * per_op_latencies.len() as u64,
        latency_ns_per_op: stats_from_samples(per_op_latencies),
        throughput_ops_per_sec: stats_from_samples(throughput_samples),
    }
}

fn stats_from_samples(mut values: Vec<f64>) -> LatencyStats {
    values.sort_by(|left, right| left.partial_cmp(right).expect("samples must be finite"));
    let len = values.len();
    let p95_index = ((len * 95).saturating_sub(1)) / 100;
    let sum: f64 = values.iter().sum();

    LatencyStats {
        min: values[0],
        median: median_of_sorted(&values),
        mean: sum / len as f64,
        p95: values[p95_index],
        max: values[len - 1],
    }
}

fn median_of_sorted(values: &[f64]) -> f64 {
    let len = values.len();
    if len % 2 == 1 {
        values[len / 2]
    } else {
        (values[len / 2 - 1] + values[len / 2]) / 2.0
    }
}

fn select_fixture(name: Option<&str>) -> ProtoResult<FExpandFixture> {
    let fixtures = deterministic_fixture_corpus()?;
    match name {
        Some(fixture_name) => fixtures
            .into_iter()
            .find(|fixture| fixture.name == fixture_name)
            .ok_or_else(|| ProtoError::InvalidInput(format!("unknown fixture: {fixture_name}"))),
        None => fixtures
            .into_iter()
            .next()
            .ok_or_else(|| ProtoError::InvalidInput("fixture corpus is empty".to_string())),
    }
}
