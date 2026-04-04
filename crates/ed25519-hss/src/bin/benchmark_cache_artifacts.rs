use std::fs;
use std::process;

use ed25519_hss::benchmark::{default_cache_benchmark_config, generate_cache_benchmark_report};

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let mut config = default_cache_benchmark_config();
    config.timed_samples = args.samples;
    config.warmup_samples = args.warmups;
    config.cached_gc_baseline_bytes = args.cached_gc_baseline_bytes;
    if let Some(bandwidths) = args.bandwidths_mbps {
        config.bandwidths_mbps = bandwidths;
    }

    let report = generate_cache_benchmark_report(&config).expect("cache benchmark report");
    let rendered = if args.emit_json {
        serde_json::to_string_pretty(&report).expect("cache benchmark json")
    } else {
        report.summary_lines().join("\n")
    };

    if let Some(path) = args.output_path.as_deref() {
        fs::write(path, &rendered).expect("write cache benchmark report");
        eprintln!("wrote cache benchmark report to {path}");
    }

    println!("{rendered}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    samples: usize,
    warmups: usize,
    cached_gc_baseline_bytes: u64,
    bandwidths_mbps: Option<Vec<u64>>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            samples: 8,
            warmups: 1,
            cached_gc_baseline_bytes: 1_200_000,
            bandwidths_mbps: None,
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
                "--samples" => {
                    parsed.samples = read_next_value(&args, &mut idx, "--samples")?
                        .parse::<usize>()
                        .map_err(|_| format!("invalid --samples value\n\n{}", Self::usage()))?;
                }
                "--warmups" => {
                    parsed.warmups = read_next_value(&args, &mut idx, "--warmups")?
                        .parse::<usize>()
                        .map_err(|_| format!("invalid --warmups value\n\n{}", Self::usage()))?;
                }
                "--cached-gc-bytes" => {
                    parsed.cached_gc_baseline_bytes =
                        read_next_value(&args, &mut idx, "--cached-gc-bytes")?
                            .parse::<u64>()
                            .map_err(|_| {
                                format!("invalid --cached-gc-bytes value\n\n{}", Self::usage())
                            })?;
                }
                "--bandwidths-mbps" => {
                    parsed.bandwidths_mbps = Some(parse_csv_u64(&read_next_value(
                        &args,
                        &mut idx,
                        "--bandwidths-mbps",
                    )?)?);
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
            "Usage: benchmark_cache_artifacts [options]",
            "",
            "Options:",
            "  --json                       Print the full JSON report",
            "  --output <path>              Write the rendered report to a file",
            "  --samples <n>                Number of timed cache-read/write samples",
            "  --warmups <n>                Number of warmup samples",
            "  --cached-gc-bytes <n>        Approximate cached-GC one-time artifact size",
            "  --bandwidths-mbps <csv>      Download bandwidth assumptions, e.g. 10,25,50,100",
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

fn parse_csv_u64(value: &str) -> Result<Vec<u64>, String> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let parsed = part
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid csv u64 value: {value}"))?;
        if parsed == 0 {
            return Err("bandwidths must be positive".to_string());
        }
        out.push(parsed);
    }
    if out.is_empty() {
        return Err("bandwidth list must not be empty".to_string());
    }
    Ok(out)
}
