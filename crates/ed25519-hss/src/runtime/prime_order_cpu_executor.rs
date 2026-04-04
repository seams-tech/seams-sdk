use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::hint::black_box;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::artifact::{
    build_prime_order_execution_trace, PrimeOrderDecodedArtifact, PrimeOrderExecutionStep,
    PrimeOrderWindowRecordClass,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::artifact::{
    decode_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
    PrimeOrderEvaluatorOps,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::candidate::build_fixed_hidden_core_candidate;
#[cfg(not(target_arch = "wasm32"))]
use crate::fixtures::deterministic_fixture_corpus;
use crate::shared::{ProtoError, ProtoResult};

#[cfg(not(target_arch = "wasm32"))]
pub const PRIME_ORDER_CPU_EXECUTOR_BENCHMARK_REPORT_VERSION: &str =
    "prime_order_cpu_executor_benchmark_v0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderCpuExecutionProgram {
    pub artifact_bytes: u64,
    pub trace: crate::artifact::PrimeOrderExecutionTrace,
    pub steps: Vec<PrimeOrderCpuExecutionStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderCpuExecutionStep {
    pub record_index: u16,
    pub bucket_count: usize,
    pub bucket_assignments: Vec<u16>,
    pub window_point_indices: Vec<u16>,
    pub window_table: Vec<EdwardsPoint>,
    pub extra_add_points: Vec<EdwardsPoint>,
    pub dependency_left: Option<usize>,
    pub dependency_right: Option<usize>,
    pub normalization_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderCpuExecutionResult {
    pub total_steps: usize,
    pub output_checksum: u64,
    pub final_point_compressed: [u8; 32],
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderCpuExecutorBenchmarkConfig {
    pub warmup_iterations: u64,
    pub sample_iterations: u64,
    pub sample_count: usize,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrimeOrderCpuExecutorBenchmarkReport {
    pub report_version: String,
    pub fixture_name: String,
    pub artifact_bytes: u64,
    pub total_steps: usize,
    pub curve_cost_units: u64,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub compile_duration_ns: u128,
    pub sample_iterations: u64,
    pub sample_count: usize,
    pub execution_latency_ns: PrimeOrderCpuBenchmarkStats,
    pub throughput_execs_per_sec: PrimeOrderCpuBenchmarkStats,
    pub latency_ns_per_curve_cost_unit: PrimeOrderCpuBenchmarkStats,
    pub output_checksum_hex: String,
    pub final_point_compressed_hex: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrimeOrderCpuBenchmarkStats {
    pub min: f64,
    pub median: f64,
    pub mean: f64,
    pub p95: f64,
    pub max: f64,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn default_prime_order_cpu_executor_benchmark_config() -> PrimeOrderCpuExecutorBenchmarkConfig {
    PrimeOrderCpuExecutorBenchmarkConfig {
        warmup_iterations: 3,
        sample_iterations: 20,
        sample_count: 8,
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn compile_default_prime_order_cpu_execution_program(
) -> ProtoResult<(String, PrimeOrderCpuExecutionProgram)> {
    let fixture = deterministic_fixture_corpus()?
        .into_iter()
        .next()
        .ok_or_else(|| ProtoError::InvalidInput("fixture corpus is empty".to_string()))?;
    let candidate = build_fixed_hidden_core_candidate(&fixture.input.context)?;
    let bytes = materialize_prime_order_size_optimized_bytes(&candidate)?;
    let decoded = decode_prime_order_size_optimized_artifact(&bytes)?;
    let program = compile_prime_order_cpu_execution_program(&decoded)?;
    Ok((
        fixture.name,
        program.with_artifact_bytes(bytes.len() as u64),
    ))
}

pub fn compile_prime_order_cpu_execution_program(
    decoded: &PrimeOrderDecodedArtifact,
) -> ProtoResult<PrimeOrderCpuExecutionProgram> {
    let trace = build_prime_order_execution_trace(decoded)?;
    let trace_steps: Vec<&PrimeOrderExecutionStep> = trace
        .stages
        .iter()
        .flat_map(|stage| stage.steps.iter())
        .collect();

    let mut trace_cursor = 0usize;
    let mut steps = Vec::with_capacity(trace.total_steps);
    let mut message_slots = BTreeMap::<u16, usize>::new();
    let mut round_state_slots = BTreeMap::<u16, usize>::new();

    for record in &decoded.windows.records {
        let is_active = matches!(
            record.class,
            PrimeOrderWindowRecordClass::AddLane
                | PrimeOrderWindowRecordClass::ScheduleDerivedWord
                | PrimeOrderWindowRecordClass::RoundState
                | PrimeOrderWindowRecordClass::OutputProjector
        );
        if !is_active {
            continue;
        }

        let trace_step = trace_steps.get(trace_cursor).ok_or_else(|| {
            ProtoError::Decode("active record count exceeded execution trace length".to_string())
        })?;
        trace_cursor += 1;

        let dependency_left = match record.class {
            PrimeOrderWindowRecordClass::ScheduleDerivedWord => {
                resolve_dependency(record.dependency_left, &message_slots)
            }
            PrimeOrderWindowRecordClass::RoundState => {
                resolve_dependency(record.dependency_left, &round_state_slots)
            }
            _ => None,
        };
        let dependency_right = match record.class {
            PrimeOrderWindowRecordClass::ScheduleDerivedWord => {
                resolve_dependency(record.dependency_right, &message_slots)
            }
            PrimeOrderWindowRecordClass::RoundState => {
                resolve_dependency(record.dependency_right, &round_state_slots)
            }
            _ => None,
        };

        let bucket_count = usize::from(record.bucket_count.max(1));
        let window_table_len = usize::try_from(trace_step.evaluator_ops.recoded_scalar_digits)
            .unwrap_or(usize::MAX)
            .max(1);
        let accumulation_count =
            usize::try_from(trace_step.evaluator_ops.bucket_accumulations).unwrap_or(usize::MAX);
        let extra_add_count = usize::try_from(trace_step.evaluator_ops.accumulator_curve_additions)
            .unwrap_or(usize::MAX);
        let normalization_count =
            usize::try_from(trace_step.evaluator_ops.point_normalizations).unwrap_or(usize::MAX);

        let window_table = (0..window_table_len)
            .map(|ordinal| derive_curve_point(&record.digest, b"window-table", ordinal as u32))
            .collect::<Vec<_>>();
        let bucket_assignments = (0..accumulation_count)
            .map(|ordinal| {
                u16::try_from(derive_index(
                    &record.digest,
                    b"bucket-slot",
                    ordinal as u32,
                    bucket_count,
                ))
                .expect("bucket slot fits into u16")
            })
            .collect::<Vec<_>>();
        let window_point_indices = (0..accumulation_count)
            .map(|ordinal| {
                u16::try_from(derive_index(
                    &record.digest,
                    b"window-point",
                    ordinal as u32,
                    window_table_len,
                ))
                .expect("window point index fits into u16")
            })
            .collect::<Vec<_>>();
        let extra_add_points = (0..extra_add_count)
            .map(|ordinal| derive_curve_point(&record.digest, b"accumulator-add", ordinal as u32))
            .collect::<Vec<_>>();

        let step_idx = steps.len();
        steps.push(PrimeOrderCpuExecutionStep {
            record_index: record.index,
            bucket_count,
            bucket_assignments,
            window_point_indices,
            window_table,
            extra_add_points,
            dependency_left,
            dependency_right,
            normalization_count,
        });

        match record.class {
            PrimeOrderWindowRecordClass::AddLane
            | PrimeOrderWindowRecordClass::ScheduleDerivedWord => {
                message_slots.insert(record.class_value, step_idx);
            }
            PrimeOrderWindowRecordClass::RoundState => {
                round_state_slots.insert(record.class_value, step_idx);
            }
            PrimeOrderWindowRecordClass::RoundConstant
            | PrimeOrderWindowRecordClass::OutputProjector
            | PrimeOrderWindowRecordClass::ContextParticipant => {}
        }
    }

    if trace_cursor != trace_steps.len() {
        return Err(ProtoError::Decode(format!(
            "execution trace contains {} active steps but program compiled {}",
            trace_steps.len(),
            trace_cursor
        )));
    }

    Ok(PrimeOrderCpuExecutionProgram {
        artifact_bytes: decoded.total_bytes,
        trace,
        steps,
    })
}

pub fn execute_prime_order_cpu_execution_program(
    program: &PrimeOrderCpuExecutionProgram,
) -> ProtoResult<PrimeOrderCpuExecutionResult> {
    let mut step_outputs = Vec::with_capacity(program.steps.len());
    let mut final_point = EdwardsPoint::identity();
    let mut output_checksum = 0u64;

    for step in &program.steps {
        let mut buckets = vec![EdwardsPoint::identity(); step.bucket_count];
        for (&bucket_slot, &point_idx) in step
            .bucket_assignments
            .iter()
            .zip(step.window_point_indices.iter())
        {
            let bucket_ref = &mut buckets[usize::from(bucket_slot)];
            let point = &step.window_table[usize::from(point_idx)];
            *bucket_ref = &*bucket_ref + point;
        }

        let mut running = EdwardsPoint::identity();
        let mut acc = EdwardsPoint::identity();
        for bucket in buckets.iter().rev() {
            running = &running + bucket;
            acc = &acc + &running;
        }

        if let Some(dependency_idx) = step.dependency_left {
            if let Some(dependency_point) = step_outputs.get(dependency_idx) {
                acc = &acc + dependency_point;
            }
        }
        if let Some(dependency_idx) = step.dependency_right {
            if let Some(dependency_point) = step_outputs.get(dependency_idx) {
                acc = &acc + dependency_point;
            }
        }
        for point in &step.extra_add_points {
            acc = &acc + point;
        }

        for _ in 0..step.normalization_count {
            let compressed = acc.compress();
            acc = compressed.decompress().ok_or_else(|| {
                ProtoError::Decode("compressed point failed to decompress".to_string())
            })?;
        }

        let compressed = acc.compress().to_bytes();
        output_checksum = output_checksum
            .wrapping_add(u64::from(step.record_index))
            .wrapping_add(u64::from_le_bytes(
                compressed[..8].try_into().expect("slice len"),
            ));
        final_point = &final_point + &acc;
        step_outputs.push(acc);
    }

    let final_point_compressed = final_point.compress().to_bytes();
    output_checksum = output_checksum.wrapping_add(u64::from_le_bytes(
        final_point_compressed[..8]
            .try_into()
            .expect("slice len for checksum"),
    ));

    Ok(PrimeOrderCpuExecutionResult {
        total_steps: program.steps.len(),
        output_checksum,
        final_point_compressed,
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_prime_order_cpu_executor_benchmark_report(
    config: &PrimeOrderCpuExecutorBenchmarkConfig,
) -> ProtoResult<PrimeOrderCpuExecutorBenchmarkReport> {
    let compile_start = Instant::now();
    let (fixture_name, program) = compile_default_prime_order_cpu_execution_program()?;
    let compile_duration_ns = compile_start.elapsed().as_nanos();

    let baseline_result = execute_prime_order_cpu_execution_program(&program)?;

    for _ in 0..config.warmup_iterations {
        black_box(
            execute_prime_order_cpu_execution_program(&program)
                .expect("prime-order cpu executor warmup should succeed"),
        );
    }

    let mut execution_latencies = Vec::with_capacity(config.sample_count);
    let mut execution_throughputs = Vec::with_capacity(config.sample_count);
    let mut ns_per_curve_cost_unit = Vec::with_capacity(config.sample_count);

    for _ in 0..config.sample_count {
        let start = Instant::now();
        for _ in 0..config.sample_iterations {
            let result = execute_prime_order_cpu_execution_program(&program)
                .expect("prime-order cpu executor sample should succeed");
            black_box(result.output_checksum);
        }
        let elapsed = start.elapsed();
        let per_exec_ns = elapsed.as_nanos() as f64 / config.sample_iterations as f64;
        execution_latencies.push(per_exec_ns);
        execution_throughputs.push(config.sample_iterations as f64 / elapsed.as_secs_f64());
        ns_per_curve_cost_unit.push(per_exec_ns / program.trace.estimated_curve_cost_units as f64);
    }

    Ok(PrimeOrderCpuExecutorBenchmarkReport {
        report_version: PRIME_ORDER_CPU_EXECUTOR_BENCHMARK_REPORT_VERSION.to_string(),
        fixture_name,
        artifact_bytes: program.artifact_bytes,
        total_steps: program.trace.total_steps,
        curve_cost_units: program.trace.estimated_curve_cost_units,
        evaluator_ops: program.trace.evaluator_ops.clone(),
        compile_duration_ns,
        sample_iterations: config.sample_iterations,
        sample_count: config.sample_count,
        execution_latency_ns: stats_from_samples(execution_latencies),
        throughput_execs_per_sec: stats_from_samples(execution_throughputs),
        latency_ns_per_curve_cost_unit: stats_from_samples(ns_per_curve_cost_unit),
        output_checksum_hex: format!("{:016x}", baseline_result.output_checksum),
        final_point_compressed_hex: hex::encode(baseline_result.final_point_compressed),
    })
}

#[cfg(not(target_arch = "wasm32"))]
impl PrimeOrderCpuExecutionProgram {
    fn with_artifact_bytes(mut self, artifact_bytes: u64) -> Self {
        self.artifact_bytes = artifact_bytes;
        self
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PrimeOrderCpuExecutorBenchmarkReport {
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "prime-order cpu executor: fixture={} artifact={}B steps={} curve_cost={}",
                self.fixture_name, self.artifact_bytes, self.total_steps, self.curve_cost_units,
            ),
            format!(
                "compile: {}ns checksum={} final_point={}",
                self.compile_duration_ns, self.output_checksum_hex, self.final_point_compressed_hex,
            ),
            format!(
                "execute: mean={:.1}ns median={:.1}ns p95={:.1}ns throughput_mean={:.2} exec/s ns_per_curve_cost_unit_mean={:.6}",
                self.execution_latency_ns.mean,
                self.execution_latency_ns.median,
                self.execution_latency_ns.p95,
                self.throughput_execs_per_sec.mean,
                self.latency_ns_per_curve_cost_unit.mean,
            ),
        ]
    }
}

fn resolve_dependency(slot: Option<u16>, slots: &BTreeMap<u16, usize>) -> Option<usize> {
    slot.and_then(|value| slots.get(&value).copied())
}

fn derive_curve_point(seed: &[u8; 32], label: &[u8], ordinal: u32) -> EdwardsPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"succinct-garbling-proto/prime-order-cpu-executor/point/v0");
    hasher.update(label);
    hasher.update(seed);
    hasher.update(ordinal.to_le_bytes());
    let wide: [u8; 64] = hasher.finalize().into();
    ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order_wide(&wide)
}

fn derive_index(seed: &[u8; 32], label: &[u8], ordinal: u32, modulus: usize) -> usize {
    if modulus <= 1 {
        return 0;
    }

    let mut hasher = Sha512::new();
    hasher.update(b"succinct-garbling-proto/prime-order-cpu-executor/index/v0");
    hasher.update(label);
    hasher.update(seed);
    hasher.update(ordinal.to_le_bytes());
    let digest: [u8; 64] = hasher.finalize().into();
    let value = u64::from_le_bytes(digest[..8].try_into().expect("u64 digest prefix"));
    let modulus_u64 = u64::try_from(modulus).expect("modulus fits into u64");
    usize::try_from(value % modulus_u64).expect("reduced index fits into usize")
}

#[cfg(test)]
mod tests {
    use super::derive_index;
    use sha2::Digest;

    #[test]
    fn derive_index_uses_full_u64_before_reducing() {
        let seed = [0xabu8; 32];
        let label = b"cross-arch-index";
        let ordinal = 7u32;
        let modulus = 7usize;

        let reduced = derive_index(&seed, label, ordinal, modulus);

        let mut hasher = sha2::Sha512::new();
        hasher.update(b"succinct-garbling-proto/prime-order-cpu-executor/index/v0");
        hasher.update(label);
        hasher.update(seed);
        hasher.update(ordinal.to_le_bytes());
        let digest: [u8; 64] = hasher.finalize().into();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("u64 digest prefix"));

        assert_eq!(
            reduced,
            usize::try_from(value % u64::try_from(modulus).expect("modulus to u64"))
                .expect("reduced value fits usize")
        );
        assert_ne!(reduced, (value as u32 as usize) % modulus);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn stats_from_samples(mut values: Vec<f64>) -> PrimeOrderCpuBenchmarkStats {
    values.sort_by(|left, right| left.partial_cmp(right).expect("samples must be finite"));
    let len = values.len();
    let p95_index = ((len * 95).saturating_sub(1)) / 100;
    let sum: f64 = values.iter().sum();

    PrimeOrderCpuBenchmarkStats {
        min: values[0],
        median: median_of_sorted(&values),
        mean: sum / len as f64,
        p95: values[p95_index],
        max: values[len - 1],
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn median_of_sorted(values: &[f64]) -> f64 {
    let len = values.len();
    if len % 2 == 1 {
        values[len / 2]
    } else {
        (values[len / 2 - 1] + values[len / 2]) / 2.0
    }
}
