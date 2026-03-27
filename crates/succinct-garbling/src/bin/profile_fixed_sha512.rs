use std::fs;
use std::process;

use succinct_garbling::{default_phase1_config, generate_phase1_benchmark_report};

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut config = default_phase1_config();
    config.warmup_iterations = args.warmup_iterations;
    config.sample_iterations = args.sample_iterations;
    config.sample_count = args.sample_count;
    config.parallel_total_iterations = args.parallel_total_iterations;
    if let Some(thread_counts) = args.thread_counts {
        config.thread_counts = thread_counts;
    }
    if let Some(runtime_surface) = args.runtime_surface {
        config.runtime_surface = runtime_surface;
    }
    if let Some(execution_backend) = args.execution_backend {
        config.execution_backend = execution_backend;
    }
    config.device_label = args.device_label;

    let report = generate_phase1_benchmark_report(&config).expect("phase1 benchmark report");
    let json = report.to_json_pretty().expect("serialize phase1 report");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write phase1 report");
        eprintln!("wrote phase1 report to {path}");
    }

    if args.emit_json {
        println!("{json}");
    } else {
        for line in report.summary_lines() {
            println!("{line}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    warmup_iterations: u64,
    sample_iterations: u64,
    sample_count: usize,
    parallel_total_iterations: u64,
    thread_counts: Option<Vec<usize>>,
    runtime_surface: Option<String>,
    execution_backend: Option<String>,
    device_label: Option<String>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            warmup_iterations: 1_000,
            sample_iterations: 10_000,
            sample_count: 12,
            parallel_total_iterations: 100_000,
            thread_counts: None,
            runtime_surface: None,
            execution_backend: None,
            device_label: None,
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
                "--warmup" => {
                    parsed.warmup_iterations =
                        parse_u64(&read_next_value(&args, &mut idx, "--warmup")?, "--warmup")?;
                }
                "--iterations" => {
                    parsed.sample_iterations = parse_u64(
                        &read_next_value(&args, &mut idx, "--iterations")?,
                        "--iterations",
                    )?;
                }
                "--samples" => {
                    parsed.sample_count =
                        parse_usize(&read_next_value(&args, &mut idx, "--samples")?, "--samples")?;
                }
                "--parallel-iterations" => {
                    parsed.parallel_total_iterations = parse_u64(
                        &read_next_value(&args, &mut idx, "--parallel-iterations")?,
                        "--parallel-iterations",
                    )?;
                }
                "--threads" => {
                    parsed.thread_counts = Some(parse_thread_counts(&read_next_value(
                        &args,
                        &mut idx,
                        "--threads",
                    )?)?);
                }
                "--runtime-surface" => {
                    parsed.runtime_surface =
                        Some(read_next_value(&args, &mut idx, "--runtime-surface")?);
                }
                "--backend" => {
                    parsed.execution_backend = Some(read_next_value(&args, &mut idx, "--backend")?);
                }
                "--device-label" => {
                    parsed.device_label = Some(read_next_value(&args, &mut idx, "--device-label")?);
                }
                "--help" | "-h" => {
                    return Err(Self::usage());
                }
                other => {
                    return Err(format!("unknown argument: {other}\n\n{}", Self::usage()));
                }
            }
        }

        Ok(parsed)
    }

    fn usage() -> String {
        [
            "Usage: profile_fixed_sha512 [options]",
            "",
            "Options:",
            "  --json                         Print the full JSON report",
            "  --output <path>                Write the JSON report to a file",
            "  --warmup <n>                   Warmup iterations per component benchmark",
            "  --iterations <n>               Timed iterations per sample",
            "  --samples <n>                  Number of timed samples per component",
            "  --parallel-iterations <n>      Total iterations for each parallel-scaling run",
            "  --threads <csv>                Worker counts to test, e.g. 1,2,4,8",
            "  --runtime-surface <label>      Metadata label, e.g. native, browser-webgpu",
            "  --backend <label>              Metadata label, e.g. cpu-only, browser-gpu",
            "  --device-label <label>         Optional device label in the report",
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

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_thread_counts(value: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let parsed = parse_usize(part.trim(), "--threads")?;
        if parsed == 0 {
            return Err("--threads values must be positive".to_string());
        }
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
    if out.is_empty() {
        return Err("--threads must contain at least one worker count".to_string());
    }
    out.sort_unstable();
    Ok(out)
}
