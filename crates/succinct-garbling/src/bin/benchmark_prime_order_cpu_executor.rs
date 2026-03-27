use std::fs;
use std::process;

use succinct_garbling::{
    default_prime_order_cpu_executor_benchmark_config,
    generate_prime_order_cpu_executor_benchmark_report,
};

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut config = default_prime_order_cpu_executor_benchmark_config();
    config.warmup_iterations = args.warmup_iterations;
    config.sample_iterations = args.sample_iterations;
    config.sample_count = args.sample_count;

    let report =
        generate_prime_order_cpu_executor_benchmark_report(&config).expect("cpu benchmark report");
    let json = report
        .to_json_pretty()
        .expect("serialize cpu benchmark report");

    if let Some(path) = args.output_path {
        fs::write(&path, &json).expect("write cpu benchmark report");
        eprintln!("wrote prime-order cpu executor benchmark report to {path}");
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
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            warmup_iterations: 3,
            sample_iterations: 20,
            sample_count: 8,
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
            "Usage: benchmark_prime_order_cpu_executor [options]",
            "",
            "Options:",
            "  --json                         Print the full JSON report",
            "  --output <path>                Write the JSON report to a file",
            "  --warmup <n>                   Warmup executions before timing",
            "  --iterations <n>               Executions per timed sample",
            "  --samples <n>                  Number of timed samples",
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
