use std::fs;
use std::process;

mod benchmark_support;

use benchmark_support::native_allocation::NativeAllocationRecorder;
use ed25519_hss::benchmark::{
    default_ddh_hidden_eval_allocation_probe_config,
    generate_ddh_hidden_eval_allocation_probe_report,
};

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
    let report = generate_ddh_hidden_eval_allocation_probe_report(&config, &mut recorder)
        .expect("DDH hidden-eval allocation probe");
    let json =
        serde_json::to_string_pretty(&report).expect("serialize DDH hidden-eval allocation report");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write DDH hidden-eval allocation report");
        eprintln!("wrote DDH hidden-eval allocation report to {path}");
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
    warmup_iterations: u64,
    sample_count: usize,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            warmup_iterations: 1,
            sample_count: 5,
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
                    parsed.sample_count =
                        parse_usize(&read_next_value(&args, &mut idx, "--samples")?, "--samples")?;
                    if parsed.sample_count == 0 {
                        return Err(format!(
                            "--samples must be greater than 0\n\n{}",
                            Self::usage()
                        ));
                    }
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
            "Usage: benchmark_ddh_hidden_eval_alloc [options]",
            "",
            "Options:",
            "  --json                  Print the full JSON report",
            "  --output <path>         Write the JSON report to a file",
            "  --fixture <name>        Use a specific deterministic fixture",
            "  --warmup <n>            Hidden-eval warmup iterations",
            "  --samples <n>           Number of allocation samples",
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
