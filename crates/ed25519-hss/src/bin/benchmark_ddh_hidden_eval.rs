use std::fs;
use std::process;

use ed25519_hss::{
    default_ddh_hidden_eval_benchmark_config, generate_ddh_hidden_eval_benchmark_report,
};

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut config = default_ddh_hidden_eval_benchmark_config();
    config.fixture_name = args.fixture_name;
    config.primitive_warmup_iterations = args.primitive_warmup_iterations;
    config.primitive_sample_iterations = args.primitive_sample_iterations;
    config.stage_warmup_iterations = args.stage_warmup_iterations;
    config.stage_sample_iterations = args.stage_sample_iterations;
    config.sample_count = args.sample_count;

    let report =
        generate_ddh_hidden_eval_benchmark_report(&config).expect("DDH hidden-eval benchmark");
    let json =
        serde_json::to_string_pretty(&report).expect("serialize DDH hidden-eval benchmark report");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write DDH hidden-eval benchmark report");
        eprintln!("wrote DDH hidden-eval benchmark report to {path}");
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
    fixture_name: Option<String>,
    primitive_warmup_iterations: u64,
    primitive_sample_iterations: u64,
    stage_warmup_iterations: u64,
    stage_sample_iterations: u64,
    sample_count: usize,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            primitive_warmup_iterations: 1_000,
            primitive_sample_iterations: 10_000,
            stage_warmup_iterations: 0,
            stage_sample_iterations: 1,
            sample_count: 6,
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
                    parsed.primitive_sample_iterations = parse_u64(
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
                    parsed.stage_sample_iterations = parse_u64(
                        &read_next_value(&args, &mut idx, "--stage-iterations")?,
                        "--stage-iterations",
                    )?;
                }
                "--samples" => {
                    parsed.sample_count =
                        parse_usize(&read_next_value(&args, &mut idx, "--samples")?, "--samples")?;
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
            "Usage: benchmark_ddh_hidden_eval [options]",
            "",
            "Options:",
            "  --json                            Print the full JSON report",
            "  --output <path>                   Write the JSON report to a file",
            "  --fixture <name>                  Use a specific deterministic fixture",
            "  --primitive-warmup <n>            Primitive warmup iterations",
            "  --primitive-iterations <n>        Primitive iterations per timed sample",
            "  --stage-warmup <n>                Hidden-eval warmup iterations",
            "  --stage-iterations <n>            Hidden-eval executions per timed sample",
            "  --samples <n>                     Number of timed samples",
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
