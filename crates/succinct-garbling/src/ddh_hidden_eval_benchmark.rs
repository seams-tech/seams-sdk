use std::hint::black_box;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::benchmark::{ComponentTimingReport, LatencyStats};
use crate::fixtures::{deterministic_fixture_corpus, FExpandFixture};
use crate::hidden_eval::HiddenEvalInputOwner;
use crate::prime_order_trace::PrimeOrderEvaluatorOps;
use crate::reference::public_key_from_base_shares;
use crate::succinct_hss::prepare_prime_order_succinct_hss;
use crate::{ProtoError, ProtoResult};

pub const DDH_HIDDEN_EVAL_BENCHMARK_REPORT_VERSION: &str = "ddh_hidden_eval_benchmark_v0";

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DdhHiddenEvalBenchmarkReport {
    pub report_version: String,
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
    pub reference_match: bool,
    pub output_public_key_hex: String,
    pub output_x_client_base_hex: String,
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

pub fn generate_ddh_hidden_eval_benchmark_report(
    config: &DdhHiddenEvalBenchmarkConfig,
) -> ProtoResult<DdhHiddenEvalBenchmarkReport> {
    let fixture = select_fixture(config.fixture_name.as_deref())?;

    let prepare_started = Instant::now();
    let session = prepare_prime_order_succinct_hss(&fixture.input.context)?;
    let prepare_duration_ns = prepare_started.elapsed().as_nanos();
    let output_openers = session.output_openers();

    let baseline_report = session.evaluate(&fixture.input)?;
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
        let delivery_report = session.evaluate(&fixture.input)?;
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
    }

    let mut input_sharing_samples = Vec::with_capacity(config.sample_count);
    let mut add_stage_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_xor_ab_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_sum_samples = Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_a_xor_carry_samples =
        Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_carry_gate_samples =
        Vec::with_capacity(config.sample_count);
    let mut message_schedule_accumulation_next_carry_samples =
        Vec::with_capacity(config.sample_count);
    let mut round_core_samples = Vec::with_capacity(config.sample_count);
    let mut round_sigma1_samples = Vec::with_capacity(config.sample_count);
    let mut round_ch_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_xor_ab_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_sum_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_a_xor_carry_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_carry_gate_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp1_next_carry_samples = Vec::with_capacity(config.sample_count);
    let mut round_temp2_samples = Vec::with_capacity(config.sample_count);
    let mut output_projector_samples = Vec::with_capacity(config.sample_count);
    let mut total_samples = Vec::with_capacity(config.sample_count);

    for _ in 0..config.sample_count {
        let mut input_sharing_total_ns = 0f64;
        let mut add_stage_total_ns = 0f64;
        let mut message_schedule_total_ns = 0f64;
        let mut message_schedule_accumulation_total_ns = 0f64;
        let mut message_schedule_accumulation_xor_ab_total_ns = 0f64;
        let mut message_schedule_accumulation_sum_total_ns = 0f64;
        let mut message_schedule_accumulation_a_xor_carry_total_ns = 0f64;
        let mut message_schedule_accumulation_carry_gate_total_ns = 0f64;
        let mut message_schedule_accumulation_next_carry_total_ns = 0f64;
        let mut round_core_total_ns = 0f64;
        let mut round_sigma1_total_ns = 0f64;
        let mut round_ch_total_ns = 0f64;
        let mut round_temp1_total_ns = 0f64;
        let mut round_temp1_xor_ab_total_ns = 0f64;
        let mut round_temp1_sum_total_ns = 0f64;
        let mut round_temp1_a_xor_carry_total_ns = 0f64;
        let mut round_temp1_carry_gate_total_ns = 0f64;
        let mut round_temp1_next_carry_total_ns = 0f64;
        let mut round_temp2_total_ns = 0f64;
        let mut output_projector_total_ns = 0f64;
        let mut total_total_ns = 0f64;

        for _ in 0..config.stage_sample_iterations {
            let total_started = Instant::now();
            let delivery_report = session.evaluate(&fixture.input)?;
            let transport_total_ns = total_started.elapsed().as_nanos() as f64;
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
                    "sampled DDH delivery-path output does not match frozen fixture".to_string(),
                ));
            }
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

            input_sharing_total_ns += profile.stage_profile.input_sharing_duration_ns as f64;
            add_stage_total_ns += profile.stage_profile.add_stage_duration_ns as f64;
            message_schedule_total_ns += profile.stage_profile.message_schedule_duration_ns as f64;
            message_schedule_accumulation_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_duration_ns
                as f64;
            message_schedule_accumulation_xor_ab_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_xor_ab_duration_ns
                as f64;
            message_schedule_accumulation_sum_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_sum_duration_ns
                as f64;
            message_schedule_accumulation_a_xor_carry_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_a_xor_carry_duration_ns
                as f64;
            message_schedule_accumulation_carry_gate_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_carry_gate_duration_ns
                as f64;
            message_schedule_accumulation_next_carry_total_ns += profile
                .stage_profile
                .message_schedule_accumulation_next_carry_duration_ns
                as f64;
            round_core_total_ns += profile.stage_profile.round_core_duration_ns as f64;
            round_sigma1_total_ns += profile.stage_profile.round_sigma1_duration_ns as f64;
            round_ch_total_ns += profile.stage_profile.round_ch_duration_ns as f64;
            round_temp1_total_ns += profile.stage_profile.round_temp1_duration_ns as f64;
            round_temp1_xor_ab_total_ns +=
                profile.stage_profile.round_temp1_xor_ab_duration_ns as f64;
            round_temp1_sum_total_ns += profile.stage_profile.round_temp1_sum_duration_ns as f64;
            round_temp1_a_xor_carry_total_ns +=
                profile.stage_profile.round_temp1_a_xor_carry_duration_ns as f64;
            round_temp1_carry_gate_total_ns +=
                profile.stage_profile.round_temp1_carry_gate_duration_ns as f64;
            round_temp1_next_carry_total_ns +=
                profile.stage_profile.round_temp1_next_carry_duration_ns as f64;
            round_temp2_total_ns += profile.stage_profile.round_temp2_duration_ns as f64;
            output_projector_total_ns += profile.stage_profile.output_projector_duration_ns as f64;
            total_total_ns += transport_total_ns;

            black_box((x_client_base, x_relayer_base, public_key));
        }

        let iterations = config.stage_sample_iterations as f64;
        input_sharing_samples.push(input_sharing_total_ns / iterations);
        add_stage_samples.push(add_stage_total_ns / iterations);
        message_schedule_samples.push(message_schedule_total_ns / iterations);
        message_schedule_accumulation_samples
            .push(message_schedule_accumulation_total_ns / iterations);
        message_schedule_accumulation_xor_ab_samples
            .push(message_schedule_accumulation_xor_ab_total_ns / iterations);
        message_schedule_accumulation_sum_samples
            .push(message_schedule_accumulation_sum_total_ns / iterations);
        message_schedule_accumulation_a_xor_carry_samples
            .push(message_schedule_accumulation_a_xor_carry_total_ns / iterations);
        message_schedule_accumulation_carry_gate_samples
            .push(message_schedule_accumulation_carry_gate_total_ns / iterations);
        message_schedule_accumulation_next_carry_samples
            .push(message_schedule_accumulation_next_carry_total_ns / iterations);
        round_core_samples.push(round_core_total_ns / iterations);
        round_sigma1_samples.push(round_sigma1_total_ns / iterations);
        round_ch_samples.push(round_ch_total_ns / iterations);
        round_temp1_samples.push(round_temp1_total_ns / iterations);
        round_temp1_xor_ab_samples.push(round_temp1_xor_ab_total_ns / iterations);
        round_temp1_sum_samples.push(round_temp1_sum_total_ns / iterations);
        round_temp1_a_xor_carry_samples.push(round_temp1_a_xor_carry_total_ns / iterations);
        round_temp1_carry_gate_samples.push(round_temp1_carry_gate_total_ns / iterations);
        round_temp1_next_carry_samples.push(round_temp1_next_carry_total_ns / iterations);
        round_temp2_samples.push(round_temp2_total_ns / iterations);
        output_projector_samples.push(output_projector_total_ns / iterations);
        total_samples.push(total_total_ns / iterations);
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
    ];
    let substage_timings = vec![
        component_report(
            "message_schedule_accumulation",
            config.stage_sample_iterations,
            message_schedule_accumulation_samples,
        ),
        component_report(
            "message_schedule_accumulation_xor_ab",
            config.stage_sample_iterations,
            message_schedule_accumulation_xor_ab_samples,
        ),
        component_report(
            "message_schedule_accumulation_sum",
            config.stage_sample_iterations,
            message_schedule_accumulation_sum_samples,
        ),
        component_report(
            "message_schedule_accumulation_a_xor_carry",
            config.stage_sample_iterations,
            message_schedule_accumulation_a_xor_carry_samples,
        ),
        component_report(
            "message_schedule_accumulation_carry_gate",
            config.stage_sample_iterations,
            message_schedule_accumulation_carry_gate_samples,
        ),
        component_report(
            "message_schedule_accumulation_next_carry",
            config.stage_sample_iterations,
            message_schedule_accumulation_next_carry_samples,
        ),
        component_report(
            "round_sigma1",
            config.stage_sample_iterations,
            round_sigma1_samples,
        ),
        component_report("round_ch", config.stage_sample_iterations, round_ch_samples),
        component_report(
            "round_temp1",
            config.stage_sample_iterations,
            round_temp1_samples,
        ),
        component_report(
            "round_temp1_xor_ab",
            config.stage_sample_iterations,
            round_temp1_xor_ab_samples,
        ),
        component_report(
            "round_temp1_sum",
            config.stage_sample_iterations,
            round_temp1_sum_samples,
        ),
        component_report(
            "round_temp1_a_xor_carry",
            config.stage_sample_iterations,
            round_temp1_a_xor_carry_samples,
        ),
        component_report(
            "round_temp1_carry_gate",
            config.stage_sample_iterations,
            round_temp1_carry_gate_samples,
        ),
        component_report(
            "round_temp1_next_carry",
            config.stage_sample_iterations,
            round_temp1_next_carry_samples,
        ),
        component_report(
            "round_temp2",
            config.stage_sample_iterations,
            round_temp2_samples,
        ),
    ];

    Ok(DdhHiddenEvalBenchmarkReport {
        report_version: DDH_HIDDEN_EVAL_BENCHMARK_REPORT_VERSION.to_string(),
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
        reference_match: true,
        output_public_key_hex: hex::encode(baseline_public_key),
        output_x_client_base_hex: hex::encode(baseline_x_client_base),
    })
}

impl DdhHiddenEvalBenchmarkReport {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "ddh hidden eval: fixture={} artifact={}B active_windows={} steps={} curve_cost={} reference_match={}",
                self.fixture_name,
                self.artifact_bytes,
                self.active_window_records,
                self.total_steps,
                self.curve_cost_units,
                self.reference_match,
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

        lines
    }
}

fn benchmark_primitives(
    config: &DdhHiddenEvalBenchmarkConfig,
    backend: &crate::DdhHssBackend,
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
        .map(|latency| 1_000_000_000.0 / latency)
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
