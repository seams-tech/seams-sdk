use std::collections::BTreeMap;
use std::fs;
use std::process;

use serde::{Deserialize, Serialize};

mod benchmark_support;

use benchmark_support::native_allocation::NativeAllocationRecorder;
use ed25519_hss::benchmark::{
    default_ddh_hidden_eval_allocation_probe_config, default_ddh_hidden_eval_benchmark_config,
    generate_ddh_hidden_eval_allocation_probe_report, generate_ddh_hidden_eval_benchmark_report,
    ComponentTimingReport, DdhHiddenEvalAllocationMeasurement, DdhHiddenEvalAllocationProbeReport,
    DdhHiddenEvalBenchmarkMetadata,
};

const EMBEDDED_PROFILE_REPORT_VERSION: &str = "ddh_hidden_eval_embedded_profile_v1";

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut timing_config = default_ddh_hidden_eval_benchmark_config();
    timing_config.fixture_name = args.fixture_name.clone();
    timing_config.primitive_warmup_iterations = args.primitive_warmup_iterations;
    timing_config.primitive_sample_iterations = args.primitive_sample_iterations;
    timing_config.stage_warmup_iterations = args.stage_warmup_iterations;
    timing_config.stage_sample_iterations = args.stage_sample_iterations;
    timing_config.sample_count = args.stage_sample_count;

    let mut allocation_config = default_ddh_hidden_eval_allocation_probe_config();
    allocation_config.fixture_name = args.fixture_name;
    allocation_config.warmup_iterations = args.allocation_warmup_iterations;
    allocation_config.sample_count = args.allocation_sample_count;

    let timing =
        generate_ddh_hidden_eval_benchmark_report(&timing_config).expect("hidden-eval benchmark");
    let mut recorder = NativeAllocationRecorder;
    let allocation =
        generate_ddh_hidden_eval_allocation_probe_report(&allocation_config, &mut recorder)
            .expect("hidden-eval allocation benchmark");
    let report = EmbeddedProfileReport::from_reports(timing, allocation);
    let json =
        serde_json::to_string_pretty(&report).expect("serialize hidden-eval embedded profile");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write hidden-eval embedded profile");
        eprintln!("wrote DDH hidden-eval embedded profile to {path}");
    }

    if args.emit_json {
        println!("{json}");
    } else {
        for line in report.summary_lines() {
            println!("{line}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EmbeddedProfileReport {
    report_version: String,
    metadata: DdhHiddenEvalBenchmarkMetadata,
    fixture_name: String,
    reference_match: bool,
    artifact_bytes: u64,
    active_window_records: usize,
    total_steps: usize,
    curve_cost_units: u64,
    config: EmbeddedProfileConfigRecord,
    timing: EmbeddedTimingSummary,
    allocation: EmbeddedAllocationSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EmbeddedProfileConfigRecord {
    primitive_warmup_iterations: u64,
    primitive_sample_iterations: u64,
    stage_warmup_iterations: u64,
    stage_sample_iterations: u64,
    stage_sample_count: usize,
    allocation_warmup_iterations: u64,
    allocation_sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EmbeddedTimingSummary {
    stage_timings: Vec<NamedLatencySummary>,
    substage_timings: Vec<NamedLatencySummary>,
    delivery_timings: Vec<NamedLatencySummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NamedLatencySummary {
    name: String,
    median_ms: f64,
    p95_ms: f64,
    mean_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EmbeddedAllocationSummary {
    operations: Vec<NamedAllocationSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NamedAllocationSummary {
    operation: String,
    allocated_bytes: DistributionSummary,
    allocation_calls: DistributionSummary,
    peak_live_bytes_above_start: DistributionSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DistributionSummary {
    median: f64,
    p95: f64,
    mean: f64,
}

impl EmbeddedProfileReport {
    fn from_reports(
        timing: ed25519_hss::benchmark::DdhHiddenEvalBenchmarkReport,
        allocation: DdhHiddenEvalAllocationProbeReport,
    ) -> Self {
        let config = EmbeddedProfileConfigRecord {
            primitive_warmup_iterations: timing.config.primitive_warmup_iterations,
            primitive_sample_iterations: timing.config.primitive_sample_iterations,
            stage_warmup_iterations: timing.config.stage_warmup_iterations,
            stage_sample_iterations: timing.config.stage_sample_iterations,
            stage_sample_count: timing.config.sample_count,
            allocation_warmup_iterations: allocation.config.warmup_iterations,
            allocation_sample_count: allocation.config.sample_count,
        };
        Self {
            report_version: EMBEDDED_PROFILE_REPORT_VERSION.to_string(),
            metadata: timing.metadata.clone(),
            fixture_name: timing.fixture_name.clone(),
            reference_match: timing.reference_match,
            artifact_bytes: timing.artifact_bytes,
            active_window_records: timing.active_window_records,
            total_steps: timing.total_steps,
            curve_cost_units: timing.curve_cost_units,
            config,
            timing: EmbeddedTimingSummary {
                stage_timings: summarize_timing_reports(&timing.stage_timings),
                substage_timings: summarize_timing_reports(&timing.substage_timings),
                delivery_timings: summarize_timing_reports(&timing.delivery_timings),
            },
            allocation: EmbeddedAllocationSummary {
                operations: summarize_allocation_report(&allocation),
            },
        }
    }

    fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "ddh hidden eval embedded profile: fixture={} artifact={}B active_windows={} steps={} curve_cost={} reference_match={} generated_at={} host={}/{} cores={}",
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
        )];
        for timing in &self.timing.stage_timings {
            lines.push(format!(
                "stage {}: p50={:.3}ms p95={:.3}ms mean={:.3}ms",
                timing.name, timing.median_ms, timing.p95_ms, timing.mean_ms,
            ));
        }
        for timing in &self.timing.substage_timings {
            lines.push(format!(
                "substage {}: p50={:.3}ms p95={:.3}ms mean={:.3}ms",
                timing.name, timing.median_ms, timing.p95_ms, timing.mean_ms,
            ));
        }
        for timing in &self.timing.delivery_timings {
            lines.push(format!(
                "delivery {}: p50={:.3}ms p95={:.3}ms mean={:.3}ms",
                timing.name, timing.median_ms, timing.p95_ms, timing.mean_ms,
            ));
        }
        for allocation in &self.allocation.operations {
            lines.push(format!(
                "allocation {}: allocated_p50={:.0}B allocated_p95={:.0}B calls_p50={:.0} calls_p95={:.0} peak_live_p50={:.0}B peak_live_p95={:.0}B",
                allocation.operation,
                allocation.allocated_bytes.median,
                allocation.allocated_bytes.p95,
                allocation.allocation_calls.median,
                allocation.allocation_calls.p95,
                allocation.peak_live_bytes_above_start.median,
                allocation.peak_live_bytes_above_start.p95,
            ));
        }
        lines
    }
}

fn summarize_timing_reports(reports: &[ComponentTimingReport]) -> Vec<NamedLatencySummary> {
    reports
        .iter()
        .map(|report| NamedLatencySummary {
            name: report.name.clone(),
            median_ms: ns_to_ms(report.latency_ns_per_op.median),
            p95_ms: ns_to_ms(report.latency_ns_per_op.p95),
            mean_ms: ns_to_ms(report.latency_ns_per_op.mean),
        })
        .collect()
}

fn summarize_allocation_report(
    report: &DdhHiddenEvalAllocationProbeReport,
) -> Vec<NamedAllocationSummary> {
    allocation_samples_by_operation(&report.samples)
        .into_iter()
        .map(|(operation, samples)| NamedAllocationSummary {
            operation: operation.to_string(),
            allocated_bytes: summarize_distribution(
                samples
                    .iter()
                    .map(|sample| sample.allocated_bytes as f64)
                    .collect(),
            ),
            allocation_calls: summarize_distribution(
                samples
                    .iter()
                    .map(|sample| sample.allocation_calls as f64)
                    .collect(),
            ),
            peak_live_bytes_above_start: summarize_distribution(
                samples
                    .iter()
                    .map(|sample| sample.peak_live_bytes_above_start as f64)
                    .collect(),
            ),
        })
        .collect()
}

fn allocation_samples_by_operation(
    samples: &[ed25519_hss::benchmark::DdhHiddenEvalAllocationProbeSample],
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

fn summarize_distribution(mut values: Vec<f64>) -> DistributionSummary {
    values.sort_by(|left, right| left.partial_cmp(right).expect("finite benchmark samples"));
    let len = values.len();
    let p95_index = ((len * 95).saturating_sub(1)) / 100;
    let sum = values.iter().sum::<f64>();
    DistributionSummary {
        median: values[len / 2],
        p95: values[p95_index],
        mean: sum / len as f64,
    }
}

fn ns_to_ms(ns: f64) -> f64 {
    ns / 1_000_000.0
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
    primitive_warmup_iterations: u64,
    primitive_sample_iterations: u64,
    stage_warmup_iterations: u64,
    stage_sample_iterations: u64,
    stage_sample_count: usize,
    allocation_warmup_iterations: u64,
    allocation_sample_count: usize,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            primitive_warmup_iterations: 0,
            primitive_sample_iterations: 1,
            stage_warmup_iterations: 1,
            stage_sample_iterations: 1,
            stage_sample_count: 6,
            allocation_warmup_iterations: 1,
            allocation_sample_count: 5,
        };

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--json" => {
                    parsed.emit_json = true;
                    idx += 1;
                }
                "--output" => {
                    parsed.output_path = Some(read_next_value(&args, &mut idx, "--output")?);
                }
                "--fixture" => {
                    parsed.fixture_name = Some(read_next_value(&args, &mut idx, "--fixture")?);
                }
                "--primitive-warmup" => {
                    parsed.primitive_warmup_iterations = parse_u64(
                        &read_next_value(&args, &mut idx, "--primitive-warmup")?,
                        "--primitive-warmup",
                    )?;
                }
                "--primitive-iterations" => {
                    parsed.primitive_sample_iterations = parse_positive_u64(
                        &read_next_value(&args, &mut idx, "--primitive-iterations")?,
                        "--primitive-iterations",
                    )?;
                }
                "--stage-warmup" => {
                    parsed.stage_warmup_iterations = parse_u64(
                        &read_next_value(&args, &mut idx, "--stage-warmup")?,
                        "--stage-warmup",
                    )?;
                }
                "--stage-iterations" => {
                    parsed.stage_sample_iterations = parse_positive_u64(
                        &read_next_value(&args, &mut idx, "--stage-iterations")?,
                        "--stage-iterations",
                    )?;
                }
                "--stage-samples" => {
                    parsed.stage_sample_count = parse_positive_usize(
                        &read_next_value(&args, &mut idx, "--stage-samples")?,
                        "--stage-samples",
                    )?;
                }
                "--allocation-warmup" => {
                    parsed.allocation_warmup_iterations = parse_u64(
                        &read_next_value(&args, &mut idx, "--allocation-warmup")?,
                        "--allocation-warmup",
                    )?;
                }
                "--allocation-samples" => {
                    parsed.allocation_sample_count = parse_positive_usize(
                        &read_next_value(&args, &mut idx, "--allocation-samples")?,
                        "--allocation-samples",
                    )?;
                }
                "--help" | "-h" => return Err(Self::usage()),
                other => return Err(format!("unknown argument: {other}\n\n{}", Self::usage())),
            }
        }

        Ok(parsed)
    }

    fn usage() -> String {
        [
            "Usage: benchmark_ddh_hidden_eval_embedded_profile [options]",
            "",
            "Options:",
            "  --json                         Print the full JSON report",
            "  --output <path>                Write the JSON report to a file",
            "  --fixture <name>               Use a specific deterministic fixture",
            "  --primitive-warmup <n>         Primitive warmup iterations",
            "  --primitive-iterations <n>     Primitive iterations per timed sample",
            "  --stage-warmup <n>             Hidden-eval warmup iterations",
            "  --stage-iterations <n>         Hidden-eval executions per timed sample",
            "  --stage-samples <n>            Number of hidden-eval timing samples",
            "  --allocation-warmup <n>        Allocation warmup iterations",
            "  --allocation-samples <n>       Number of allocation samples",
        ]
        .join("\n")
    }
}

fn read_next_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    if *idx >= args.len() {
        return Err(format!("missing value for {flag}\n\n{}", CliArgs::usage()));
    }
    let value = args[*idx].clone();
    *idx += 1;
    Ok(value)
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_positive_u64(value: &str, flag: &str) -> Result<u64, String> {
    let parsed = parse_u64(value, flag)?;
    if parsed == 0 {
        return Err(format!("{flag} must be greater than 0"));
    }
    Ok(parsed)
}

fn parse_positive_usize(value: &str, flag: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be greater than 0"));
    }
    Ok(parsed)
}
