use std::collections::BTreeMap;
use std::fs;
use std::process;

use serde::{Deserialize, Serialize};

mod benchmark_support;

use benchmark_support::native_allocation::NativeAllocationRecorder;
use ed25519_hss::benchmark::{
    default_ddh_hidden_eval_allocation_probe_config,
    generate_ddh_hidden_eval_allocation_probe_report, DdhHiddenEvalAllocationMeasurement,
    DdhHiddenEvalAllocationProbeReport, DdhHiddenEvalBenchmarkMetadata,
};

const MEMORY_STRESS_REPORT_VERSION: &str = "ddh_hidden_eval_memory_stress_v1";
const HIDDEN_EVAL_OPERATION: &str = "profile_hidden_eval_for_clear_input";
const PREPARE_OPERATION: &str = "prepare_prime_order_succinct_hss";

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut config = default_ddh_hidden_eval_allocation_probe_config();
    config.fixture_name = args.fixture_name;
    config.warmup_iterations = args.warmup_iterations;
    config.sample_count = args.sample_count;

    let mut recorder = NativeAllocationRecorder;
    let allocation = generate_ddh_hidden_eval_allocation_probe_report(&config, &mut recorder)
        .expect("hidden-eval memory stress allocation probe");
    let report = MemoryStressReport::from_allocation_report(allocation, args.budgets);
    let json = serde_json::to_string_pretty(&report).expect("serialize memory stress report");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write memory stress report");
        eprintln!("wrote DDH hidden-eval memory stress report to {path}");
    }

    if args.emit_json {
        println!("{json}");
    } else {
        for line in report.summary_lines() {
            println!("{line}");
        }
    }

    if report.budget_results.iter().any(|result| !result.passed) {
        process::exit(1);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MemoryStressReport {
    report_version: String,
    metadata: DdhHiddenEvalBenchmarkMetadata,
    fixture_name: String,
    config: MemoryStressConfigRecord,
    operations: Vec<OperationMemorySummary>,
    budget_results: Vec<BudgetResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MemoryStressConfigRecord {
    warmup_iterations: u64,
    sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OperationMemorySummary {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetMetric {
    AllocatedBytes,
    AllocationCalls,
    PeakLiveBytesAboveStart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Budget {
    operation: String,
    metric: BudgetMetric,
    max_p95: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BudgetResult {
    operation: String,
    metric: BudgetMetric,
    max_p95: u64,
    observed_p95: f64,
    passed: bool,
}

impl MemoryStressReport {
    fn from_allocation_report(
        report: DdhHiddenEvalAllocationProbeReport,
        budgets: Vec<Budget>,
    ) -> Self {
        let operations = summarize_allocation_report(&report);
        let budget_results = budgets
            .into_iter()
            .map(|budget| evaluate_budget(&operations, budget))
            .collect();
        Self {
            report_version: MEMORY_STRESS_REPORT_VERSION.to_string(),
            metadata: report.metadata,
            fixture_name: report.fixture_name,
            config: MemoryStressConfigRecord {
                warmup_iterations: report.config.warmup_iterations,
                sample_count: report.config.sample_count,
            },
            operations,
            budget_results,
        }
    }

    fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "ddh hidden eval memory stress: fixture={} samples={} warmup={} generated_at={} host={}/{} cores={}",
            self.fixture_name,
            self.config.sample_count,
            self.config.warmup_iterations,
            self.metadata.generated_at_unix_secs,
            self.metadata.host_os,
            self.metadata.host_arch,
            self.metadata.logical_cores,
        )];
        for operation in &self.operations {
            lines.push(format!(
                "operation {}: allocated_p50={:.0}B allocated_p95={:.0}B calls_p50={:.0} calls_p95={:.0} peak_live_p50={:.0}B peak_live_p95={:.0}B",
                operation.operation,
                operation.allocated_bytes.median,
                operation.allocated_bytes.p95,
                operation.allocation_calls.median,
                operation.allocation_calls.p95,
                operation.peak_live_bytes_above_start.median,
                operation.peak_live_bytes_above_start.p95,
            ));
        }
        for result in &self.budget_results {
            lines.push(format!(
                "budget {} {:?}: observed_p95={:.0} max_p95={} {}",
                result.operation,
                result.metric,
                result.observed_p95,
                result.max_p95,
                if result.passed { "pass" } else { "fail" },
            ));
        }
        lines
    }
}

fn summarize_allocation_report(
    report: &DdhHiddenEvalAllocationProbeReport,
) -> Vec<OperationMemorySummary> {
    allocation_samples_by_operation(&report.samples)
        .into_iter()
        .map(|(operation, samples)| OperationMemorySummary {
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

fn evaluate_budget(operations: &[OperationMemorySummary], budget: Budget) -> BudgetResult {
    let observed_p95 = operations
        .iter()
        .find(|operation| operation.operation == budget.operation)
        .map(|operation| match budget.metric {
            BudgetMetric::AllocatedBytes => operation.allocated_bytes.p95,
            BudgetMetric::AllocationCalls => operation.allocation_calls.p95,
            BudgetMetric::PeakLiveBytesAboveStart => operation.peak_live_bytes_above_start.p95,
        })
        .unwrap_or(f64::INFINITY);
    BudgetResult {
        operation: budget.operation,
        metric: budget.metric,
        max_p95: budget.max_p95,
        observed_p95,
        passed: observed_p95 <= budget.max_p95 as f64,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
    warmup_iterations: u64,
    sample_count: usize,
    budgets: Vec<Budget>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            warmup_iterations: 1,
            sample_count: 8,
            budgets: Vec::new(),
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
                "--warmup" => {
                    parsed.warmup_iterations =
                        parse_u64(&read_next_value(&args, &mut idx, "--warmup")?, "--warmup")?;
                }
                "--samples" => {
                    parsed.sample_count = parse_positive_usize(
                        &read_next_value(&args, &mut idx, "--samples")?,
                        "--samples",
                    )?;
                }
                "--max-hidden-eval-allocated-bytes" => {
                    parsed.budgets.push(Budget {
                        operation: HIDDEN_EVAL_OPERATION.to_string(),
                        metric: BudgetMetric::AllocatedBytes,
                        max_p95: parse_u64(
                            &read_next_value(&args, &mut idx, "--max-hidden-eval-allocated-bytes")?,
                            "--max-hidden-eval-allocated-bytes",
                        )?,
                    });
                }
                "--max-hidden-eval-allocation-calls" => {
                    parsed.budgets.push(Budget {
                        operation: HIDDEN_EVAL_OPERATION.to_string(),
                        metric: BudgetMetric::AllocationCalls,
                        max_p95: parse_u64(
                            &read_next_value(
                                &args,
                                &mut idx,
                                "--max-hidden-eval-allocation-calls",
                            )?,
                            "--max-hidden-eval-allocation-calls",
                        )?,
                    });
                }
                "--max-hidden-eval-peak-live-bytes" => {
                    parsed.budgets.push(Budget {
                        operation: HIDDEN_EVAL_OPERATION.to_string(),
                        metric: BudgetMetric::PeakLiveBytesAboveStart,
                        max_p95: parse_u64(
                            &read_next_value(&args, &mut idx, "--max-hidden-eval-peak-live-bytes")?,
                            "--max-hidden-eval-peak-live-bytes",
                        )?,
                    });
                }
                "--max-prepare-allocated-bytes" => {
                    parsed.budgets.push(Budget {
                        operation: PREPARE_OPERATION.to_string(),
                        metric: BudgetMetric::AllocatedBytes,
                        max_p95: parse_u64(
                            &read_next_value(&args, &mut idx, "--max-prepare-allocated-bytes")?,
                            "--max-prepare-allocated-bytes",
                        )?,
                    });
                }
                "--max-prepare-allocation-calls" => {
                    parsed.budgets.push(Budget {
                        operation: PREPARE_OPERATION.to_string(),
                        metric: BudgetMetric::AllocationCalls,
                        max_p95: parse_u64(
                            &read_next_value(&args, &mut idx, "--max-prepare-allocation-calls")?,
                            "--max-prepare-allocation-calls",
                        )?,
                    });
                }
                "--max-prepare-peak-live-bytes" => {
                    parsed.budgets.push(Budget {
                        operation: PREPARE_OPERATION.to_string(),
                        metric: BudgetMetric::PeakLiveBytesAboveStart,
                        max_p95: parse_u64(
                            &read_next_value(&args, &mut idx, "--max-prepare-peak-live-bytes")?,
                            "--max-prepare-peak-live-bytes",
                        )?,
                    });
                }
                "--help" | "-h" => return Err(Self::usage()),
                other => return Err(format!("unknown argument: {other}\n\n{}", Self::usage())),
            }
        }

        Ok(parsed)
    }

    fn usage() -> String {
        [
            "Usage: benchmark_ddh_hidden_eval_memory_stress [options]",
            "",
            "Options:",
            "  --json                                  Print the full JSON report",
            "  --output <path>                         Write the JSON report to a file",
            "  --fixture <name>                        Use a deterministic fixture",
            "  --warmup <n>                            Allocation warmup iterations",
            "  --samples <n>                           Number of allocation samples",
            "  --max-hidden-eval-allocated-bytes <n>   Fail if hidden-eval allocated p95 exceeds n",
            "  --max-hidden-eval-allocation-calls <n>  Fail if hidden-eval allocation-call p95 exceeds n",
            "  --max-hidden-eval-peak-live-bytes <n>   Fail if hidden-eval peak-live p95 exceeds n",
            "  --max-prepare-allocated-bytes <n>       Fail if prepare allocated p95 exceeds n",
            "  --max-prepare-allocation-calls <n>      Fail if prepare allocation-call p95 exceeds n",
            "  --max-prepare-peak-live-bytes <n>       Fail if prepare peak-live p95 exceeds n",
            "  -h, --help                              Show this help",
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

fn parse_positive_usize(value: &str, flag: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be greater than 0"));
    }
    Ok(parsed)
}
