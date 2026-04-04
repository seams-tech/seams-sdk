use std::cmp;
use std::collections::BTreeSet;
use std::env;
use std::hint::black_box;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::fixtures::deterministic_fixture_corpus;
use crate::shared::ProtoResult;
use crate::shared::{
    add_le_bytes_mod_2_256, derive_output_shares, eval_f_expand, eval_nonlinear_expansion,
    public_key_from_scalar_bytes, reduce_scalar_mod_l, sha512_one_block, FExpandInput,
};

pub const PHASE1_REPORT_VERSION: &str = "phase1_eval_report_v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase1BenchmarkConfig {
    pub warmup_iterations: u64,
    pub sample_iterations: u64,
    pub sample_count: usize,
    pub parallel_total_iterations: u64,
    pub thread_counts: Vec<usize>,
    pub runtime_surface: String,
    pub execution_backend: String,
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase1BenchmarkConfigRecord {
    pub warmup_iterations: u64,
    pub sample_iterations: u64,
    pub sample_count: usize,
    pub parallel_total_iterations: u64,
    pub thread_counts: Vec<usize>,
    pub runtime_surface: String,
    pub execution_backend: String,
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase1BenchmarkReport {
    pub report_version: String,
    pub metadata: BenchmarkMetadata,
    pub config: Phase1BenchmarkConfigRecord,
    pub fixtures: FixtureSetMetadata,
    pub output_widths: OutputWidthReport,
    pub component_timings: Vec<ComponentTimingReport>,
    pub parallel_scaling: Vec<ParallelScalingBenchmark>,
    pub setup_overhead: Vec<SetupOverheadReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkMetadata {
    pub generated_at_unix_secs: u64,
    pub host_os: String,
    pub host_arch: String,
    pub logical_cores: usize,
    pub hostname: Option<String>,
    pub uname: Option<String>,
    pub cpu_model: Option<String>,
    pub runtime_surface: String,
    pub execution_backend: String,
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureSetMetadata {
    pub count: usize,
    pub fixture_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputWidthReport {
    pub nonlinear_core_output_bytes: u64,
    pub client_private_output_bytes: u64,
    pub server_private_output_bytes: u64,
    pub public_output_bytes: u64,
    pub minimal_protocol_output_bytes: u64,
    pub reference_trace_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComponentTimingReport {
    pub name: String,
    pub sample_count: usize,
    pub iterations_per_sample: u64,
    pub total_iterations: u64,
    pub latency_ns_per_op: LatencyStats,
    pub throughput_ops_per_sec: ThroughputStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatencyStats {
    pub min: f64,
    pub median: f64,
    pub mean: f64,
    pub p95: f64,
    pub max: f64,
}

pub type ThroughputStats = LatencyStats;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParallelScalingBenchmark {
    pub workload: String,
    pub points: Vec<ParallelScalingPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParallelScalingPoint {
    pub workers: usize,
    pub total_iterations: u64,
    pub total_duration_ns: u128,
    pub latency_ns_per_op: f64,
    pub throughput_ops_per_sec: f64,
    pub speedup_vs_single_thread: f64,
    pub efficiency_vs_single_thread: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetupOverheadReport {
    pub workload: String,
    pub workers: usize,
    pub cold_start_duration_ns: u128,
    pub warm_batch_duration_ns: u128,
    pub cold_start_fraction_of_warm_batch: f64,
}

pub fn default_phase1_config() -> Phase1BenchmarkConfig {
    let logical_cores = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);

    Phase1BenchmarkConfig {
        warmup_iterations: 1_000,
        sample_iterations: 10_000,
        sample_count: 12,
        parallel_total_iterations: 100_000,
        thread_counts: default_thread_counts_for(logical_cores),
        runtime_surface: "native".to_string(),
        execution_backend: "cpu-only".to_string(),
        device_label: None,
    }
}

pub fn default_thread_counts() -> Vec<usize> {
    let logical_cores = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    default_thread_counts_for(logical_cores)
}

pub fn default_thread_counts_for(logical_cores: usize) -> Vec<usize> {
    let logical_cores = cmp::max(1, logical_cores);
    let mut out = BTreeSet::new();
    out.insert(1usize);

    let mut next = 1usize;
    while next < logical_cores {
        out.insert(next);
        next = next.saturating_mul(2);
    }
    out.insert(logical_cores);

    out.into_iter().collect()
}

pub fn generate_phase1_benchmark_report(
    config: &Phase1BenchmarkConfig,
) -> ProtoResult<Phase1BenchmarkReport> {
    let fixtures = deterministic_fixture_corpus()?;
    let inputs: Vec<FExpandInput> = fixtures
        .iter()
        .map(|fixture| fixture.input.clone())
        .collect();
    let add_inputs: Vec<([u8; 32], [u8; 32])> = fixtures
        .iter()
        .map(|fixture| (fixture.input.y_client, fixture.input.y_relayer))
        .collect();
    let d_inputs: Vec<[u8; 32]> = fixtures.iter().map(|fixture| fixture.output.d).collect();
    let a_bytes_inputs: Vec<[u8; 32]> = fixtures
        .iter()
        .map(|fixture| fixture.output.a_bytes)
        .collect();
    let a_inputs: Vec<[u8; 32]> = fixtures.iter().map(|fixture| fixture.output.a).collect();
    let output_share_inputs: Vec<([u8; 32], [u8; 32], [u8; 32])> = fixtures
        .iter()
        .map(|fixture| {
            (
                fixture.output.a,
                fixture.input.tau_client,
                fixture.input.tau_relayer,
            )
        })
        .collect();

    let component_timings = vec![
        benchmark_component("add_mod_2_256", config, &add_inputs, |(left, right)| {
            black_box(add_le_bytes_mod_2_256(black_box(*left), black_box(*right)));
        }),
        benchmark_component("sha512_one_block", config, &d_inputs, |d| {
            black_box(sha512_one_block(black_box(*d)));
        }),
        benchmark_component("clamp_rfc8032", config, &a_bytes_inputs, |a_bytes| {
            black_box(crate::shared::clamp_rfc8032(black_box(*a_bytes)));
        }),
        benchmark_component("reduce_scalar_mod_l", config, &a_bytes_inputs, |a_bytes| {
            black_box(reduce_scalar_mod_l(black_box(*a_bytes)));
        }),
        benchmark_component("hidden_core_sha512_clamp_reduce", config, &d_inputs, |d| {
            black_box(eval_nonlinear_expansion(black_box(*d)));
        }),
        benchmark_component(
            "output_share_derivation",
            config,
            &output_share_inputs,
            |(a, tau_client, tau_relayer)| {
                black_box(
                    derive_output_shares(
                        black_box(*a),
                        black_box(*tau_client),
                        black_box(*tau_relayer),
                    )
                    .expect("fixture output shares should be valid"),
                );
            },
        ),
        benchmark_component("public_key_mul", config, &a_inputs, |a| {
            black_box(
                public_key_from_scalar_bytes(black_box(*a))
                    .expect("fixture scalar should be valid"),
            );
        }),
        benchmark_component("full_f_expand", config, &inputs, |input| {
            black_box(eval_f_expand(black_box(input)).expect("fixture input should be valid"));
        }),
    ];

    let parallel_scaling = vec![
        benchmark_parallel_scaling(
            "hidden_core_sha512_clamp_reduce",
            &config.thread_counts,
            config.parallel_total_iterations,
            &d_inputs,
            |d| {
                black_box(eval_nonlinear_expansion(black_box(*d)));
            },
        ),
        benchmark_parallel_scaling(
            "full_f_expand",
            &config.thread_counts,
            config.parallel_total_iterations,
            &inputs,
            |input| {
                black_box(eval_f_expand(black_box(input)).expect("fixture input should be valid"));
            },
        ),
    ];

    let setup_overhead = config
        .thread_counts
        .iter()
        .copied()
        .map(|workers| SetupOverheadReport {
            workload: "full_f_expand".to_string(),
            workers,
            cold_start_duration_ns: measure_thread_spawn_overhead(workers).as_nanos(),
            warm_batch_duration_ns: measure_parallel_batch_duration(
                workers,
                config.parallel_total_iterations,
                &inputs,
                &|input| {
                    black_box(
                        eval_f_expand(black_box(input)).expect("fixture input should be valid"),
                    );
                },
            )
            .as_nanos(),
            cold_start_fraction_of_warm_batch: 0.0,
        })
        .map(|mut report| {
            report.cold_start_fraction_of_warm_batch =
                ratio(report.cold_start_duration_ns, report.warm_batch_duration_ns);
            report
        })
        .collect();

    Ok(Phase1BenchmarkReport {
        report_version: PHASE1_REPORT_VERSION.to_string(),
        metadata: BenchmarkMetadata::capture(config),
        config: Phase1BenchmarkConfigRecord::from(config),
        fixtures: FixtureSetMetadata {
            count: fixtures.len(),
            fixture_names: fixtures
                .iter()
                .map(|fixture| fixture.name.clone())
                .collect(),
        },
        output_widths: OutputWidthReport::from_reference_trace(&fixtures[0].output),
        component_timings,
        parallel_scaling,
        setup_overhead,
    })
}

impl Phase1BenchmarkReport {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "phase1 report: backend={} runtime={} cores={}",
            self.metadata.execution_backend,
            self.metadata.runtime_surface,
            self.metadata.logical_cores
        ));
        lines.push(format!(
            "fixtures={} minimal_output={}B reference_trace={}B",
            self.fixtures.count,
            self.output_widths.minimal_protocol_output_bytes,
            self.output_widths.reference_trace_bytes
        ));

        for component in &self.component_timings {
            lines.push(format!(
                "{}: mean={:.1}ns median={:.1}ns p95={:.1}ns throughput_mean={:.0} ops/s",
                component.name,
                component.latency_ns_per_op.mean,
                component.latency_ns_per_op.median,
                component.latency_ns_per_op.p95,
                component.throughput_ops_per_sec.mean,
            ));
        }

        for scaling in &self.parallel_scaling {
            lines.push(format!("parallel scaling: {}", scaling.workload));
            for point in &scaling.points {
                lines.push(format!(
                    "  workers={} latency={:.1}ns throughput={:.0} ops/s speedup={:.2}x efficiency={:.2}",
                    point.workers,
                    point.latency_ns_per_op,
                    point.throughput_ops_per_sec,
                    point.speedup_vs_single_thread,
                    point.efficiency_vs_single_thread,
                ));
            }
        }

        lines
    }
}

impl From<&Phase1BenchmarkConfig> for Phase1BenchmarkConfigRecord {
    fn from(value: &Phase1BenchmarkConfig) -> Self {
        Self {
            warmup_iterations: value.warmup_iterations,
            sample_iterations: value.sample_iterations,
            sample_count: value.sample_count,
            parallel_total_iterations: value.parallel_total_iterations,
            thread_counts: value.thread_counts.clone(),
            runtime_surface: value.runtime_surface.clone(),
            execution_backend: value.execution_backend.clone(),
            device_label: value.device_label.clone(),
        }
    }
}

impl BenchmarkMetadata {
    fn capture(config: &Phase1BenchmarkConfig) -> Self {
        Self {
            generated_at_unix_secs: unix_timestamp_now(),
            host_os: env::consts::OS.to_string(),
            host_arch: env::consts::ARCH.to_string(),
            logical_cores: thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1),
            hostname: capture_command_output("hostname", &[]),
            uname: capture_command_output("uname", &["-srvm"]),
            cpu_model: detect_cpu_model(),
            runtime_surface: config.runtime_surface.clone(),
            execution_backend: config.execution_backend.clone(),
            device_label: config.device_label.clone(),
        }
    }
}

impl OutputWidthReport {
    fn from_reference_trace(output: &crate::shared::FExpandOutput) -> Self {
        let nonlinear_core_output_bytes = output.a.len() as u64;
        let client_private_output_bytes = output.x_client_base.len() as u64;
        let server_private_output_bytes = output.x_relayer_base.len() as u64;
        let public_output_bytes = output.public_key.len() as u64;
        let minimal_protocol_output_bytes =
            client_private_output_bytes + server_private_output_bytes + public_output_bytes;
        let reference_trace_bytes = output.context_binding.len() as u64
            + output.m.len() as u64
            + output.d.len() as u64
            + output.h.len() as u64
            + output.a_bytes.len() as u64
            + output.a.len() as u64
            + output.tau.len() as u64
            + output.x_client_base.len() as u64
            + output.x_relayer_base.len() as u64
            + output.public_key.len() as u64;

        Self {
            nonlinear_core_output_bytes,
            client_private_output_bytes,
            server_private_output_bytes,
            public_output_bytes,
            minimal_protocol_output_bytes,
            reference_trace_bytes,
        }
    }
}

fn benchmark_component<Input: Sync>(
    name: &str,
    config: &Phase1BenchmarkConfig,
    inputs: &[Input],
    f: impl Fn(&Input) + Sync,
) -> ComponentTimingReport {
    run_warmup(config.warmup_iterations, inputs, &f);

    let mut sample_latencies = Vec::with_capacity(config.sample_count);
    let mut sample_throughputs = Vec::with_capacity(config.sample_count);

    for _ in 0..config.sample_count {
        let elapsed = measure_sample(config.sample_iterations, inputs, &f);
        let sample_ns = elapsed.as_nanos() as f64 / config.sample_iterations as f64;
        let sample_ops_per_sec = config.sample_iterations as f64 / elapsed.as_secs_f64();
        sample_latencies.push(sample_ns);
        sample_throughputs.push(sample_ops_per_sec);
    }

    ComponentTimingReport {
        name: name.to_string(),
        sample_count: config.sample_count,
        iterations_per_sample: config.sample_iterations,
        total_iterations: config.sample_iterations * config.sample_count as u64,
        latency_ns_per_op: stats_from_sorted(mut_sorted(sample_latencies)),
        throughput_ops_per_sec: stats_from_sorted(mut_sorted(sample_throughputs)),
    }
}

fn benchmark_parallel_scaling<Input: Sync>(
    workload: &str,
    thread_counts: &[usize],
    total_iterations: u64,
    inputs: &[Input],
    f: impl Fn(&Input) + Sync,
) -> ParallelScalingBenchmark {
    let mut points = Vec::with_capacity(thread_counts.len());
    let mut single_thread_throughput = 0.0;

    for &workers in thread_counts {
        let workers = cmp::max(1, workers);
        let elapsed = measure_parallel_batch_duration(workers, total_iterations, inputs, &f);
        let latency_ns_per_op = elapsed.as_nanos() as f64 / total_iterations as f64;
        let throughput_ops_per_sec = total_iterations as f64 / elapsed.as_secs_f64();

        if workers == 1 {
            single_thread_throughput = throughput_ops_per_sec;
        }

        let speedup = if single_thread_throughput > 0.0 {
            throughput_ops_per_sec / single_thread_throughput
        } else {
            1.0
        };

        points.push(ParallelScalingPoint {
            workers,
            total_iterations,
            total_duration_ns: elapsed.as_nanos(),
            latency_ns_per_op,
            throughput_ops_per_sec,
            speedup_vs_single_thread: speedup,
            efficiency_vs_single_thread: speedup / workers as f64,
        });
    }

    ParallelScalingBenchmark {
        workload: workload.to_string(),
        points,
    }
}

fn run_warmup<Input>(iterations: u64, inputs: &[Input], f: &impl Fn(&Input)) {
    if iterations == 0 {
        return;
    }

    for idx in 0..iterations {
        f(&inputs[idx as usize % inputs.len()]);
    }
}

fn measure_sample<Input>(iterations: u64, inputs: &[Input], f: &impl Fn(&Input)) -> Duration {
    let start = Instant::now();
    for idx in 0..iterations {
        f(&inputs[idx as usize % inputs.len()]);
    }
    start.elapsed()
}

fn measure_parallel_batch_duration<Input: Sync>(
    workers: usize,
    total_iterations: u64,
    inputs: &[Input],
    f: &(impl Fn(&Input) + Sync),
) -> Duration {
    let start = Instant::now();
    thread::scope(|scope| {
        for worker in 0..workers {
            let remainder = (total_iterations % workers as u64) as usize;
            let worker_iterations =
                total_iterations / workers as u64 + u64::from(worker < remainder);
            scope.spawn(move || {
                for idx in 0..worker_iterations {
                    let input_idx = (worker + idx as usize * workers) % inputs.len();
                    f(&inputs[input_idx]);
                }
            });
        }
    });
    start.elapsed()
}

fn measure_thread_spawn_overhead(workers: usize) -> Duration {
    let start = Instant::now();
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                black_box(());
            });
        }
    });
    start.elapsed()
}

fn ratio(numerator: u128, denominator: u128) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

fn mut_sorted(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_by(|left, right| left.partial_cmp(right).expect("samples must be finite"));
    values
}

fn stats_from_sorted(values: Vec<f64>) -> LatencyStats {
    let len = values.len();
    let sum: f64 = values.iter().sum();
    let p95_index = ((len * 95).saturating_sub(1)) / 100;

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

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn capture_command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn detect_cpu_model() -> Option<String> {
    capture_command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
        .or_else(|| {
            capture_command_output("sh", &["-lc", "lscpu | awk -F: '/Model name/ {print $2}'"])
                .map(|value| value.trim().to_string())
        })
        .or_else(|| {
            capture_command_output(
                "sh",
                &["-lc", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-"],
            )
            .map(|value| value.trim().to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::{
        default_thread_counts_for, generate_phase1_benchmark_report, median_of_sorted,
        stats_from_sorted, Phase1BenchmarkConfig,
    };

    #[test]
    fn default_thread_counts_include_powers_of_two_and_max() {
        assert_eq!(default_thread_counts_for(1), vec![1]);
        assert_eq!(default_thread_counts_for(6), vec![1, 2, 4, 6]);
        assert_eq!(default_thread_counts_for(8), vec![1, 2, 4, 8]);
    }

    #[test]
    fn stats_helpers_compute_expected_percentiles() {
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let stats = stats_from_sorted(values.clone());
        assert_eq!(median_of_sorted(&values), 30.0);
        assert_eq!(stats.min, 10.0);
        assert_eq!(stats.median, 30.0);
        assert_eq!(stats.mean, 30.0);
        assert_eq!(stats.p95, 50.0);
        assert_eq!(stats.max, 50.0);
    }

    #[test]
    fn phase1_report_smoke_test() {
        let report = generate_phase1_benchmark_report(&Phase1BenchmarkConfig {
            warmup_iterations: 4,
            sample_iterations: 16,
            sample_count: 3,
            parallel_total_iterations: 32,
            thread_counts: vec![1, 2],
            runtime_surface: "native-test".to_string(),
            execution_backend: "cpu-only".to_string(),
            device_label: Some("test-host".to_string()),
        })
        .expect("phase1 report should generate");

        assert_eq!(report.report_version, super::PHASE1_REPORT_VERSION);
        assert_eq!(report.fixtures.count, 5);
        assert_eq!(report.output_widths.minimal_protocol_output_bytes, 96);
        assert_eq!(report.output_widths.reference_trace_bytes, 352);
        assert_eq!(report.parallel_scaling.len(), 2);
        assert_eq!(report.setup_overhead.len(), 2);
        assert!(report
            .component_timings
            .iter()
            .any(|component| component.name == "full_f_expand"));
    }
}
