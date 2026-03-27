use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use serde::Serialize;
use succinct_garbling_proto::{
    default_cache_benchmark_config, generate_cache_benchmark_report,
    materialize_cache_benchmark_targets, CandidateBackendFamily,
};

const BROWSER_CACHE_BENCHMARK_BUNDLE_VERSION: &str = "browser_cache_benchmark_bundle_v0";

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

    let output_dir = PathBuf::from(&args.output_dir);
    let targets_dir = output_dir.join("targets");
    let manifests_dir = output_dir.join("manifests");
    fs::create_dir_all(&targets_dir).expect("create targets dir");
    fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let materialized_targets =
        materialize_cache_benchmark_targets(&config).expect("materialize cache benchmark targets");
    let local_file_io_report =
        generate_cache_benchmark_report(&config).expect("cache benchmark report");

    let mut emitted_targets = Vec::with_capacity(materialized_targets.len());
    for target in materialized_targets {
        let bytes_file_name = format!("{}.bin", target.label);
        let bytes_file_path = targets_dir.join(&bytes_file_name);
        fs::write(&bytes_file_path, &target.bytes).expect("write target bytes");

        let manifest_rel_path = if let Some(manifest_json) = target.manifest_json.as_deref() {
            let manifest_file_name = format!("{}.json", target.label);
            let manifest_path = manifests_dir.join(&manifest_file_name);
            fs::write(&manifest_path, manifest_json).expect("write manifest");
            Some(relative_path_string(&output_dir, &manifest_path))
        } else {
            None
        };

        emitted_targets.push(BrowserCacheBenchmarkTargetBundle {
            label: target.label,
            kind: target.kind,
            backend_family: target.backend_family,
            bytes: target.bytes.len() as u64,
            bytes_sha256_hex: hex::encode(target.bytes_sha256),
            manifest_bytes: target.manifest_bytes,
            bytes_path: relative_path_string(&output_dir, &bytes_file_path),
            manifest_path: manifest_rel_path,
        });
    }

    let bundle = BrowserCacheBenchmarkBundle {
        bundle_version: BROWSER_CACHE_BENCHMARK_BUNDLE_VERSION.to_string(),
        warmup_samples: config.warmup_samples,
        timed_samples: config.timed_samples,
        cached_gc_baseline_bytes: config.cached_gc_baseline_bytes,
        bandwidths_mbps: config.bandwidths_mbps.clone(),
        local_file_io_report,
        targets: emitted_targets,
    };

    let bundle_json =
        serde_json::to_string_pretty(&bundle).expect("serialize browser cache benchmark bundle");
    let bundle_path = output_dir.join("bundle.json");
    fs::write(&bundle_path, &bundle_json).expect("write bundle json");

    println!(
        "wrote browser cache benchmark bundle to {}",
        bundle_path.display()
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    output_dir: String,
    samples: usize,
    warmups: usize,
    cached_gc_baseline_bytes: u64,
    bandwidths_mbps: Option<Vec<u64>>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            output_dir: "crates/succinct-garbling-proto/web/generated".to_string(),
            samples: 8,
            warmups: 1,
            cached_gc_baseline_bytes: 1_200_000,
            bandwidths_mbps: None,
        };

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--output-dir" => {
                    parsed.output_dir = read_next_value(&args, &mut idx, "--output-dir")?;
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
            "Usage: emit_browser_cache_benchmark_bundle [options]",
            "",
            "Options:",
            "  --output-dir <path>          Output directory for bundle.json and target files",
            "  --samples <n>                Number of timed cache-read/write samples",
            "  --warmups <n>                Number of warmup samples",
            "  --cached-gc-bytes <n>        Approximate cached-GC one-time artifact size",
            "  --bandwidths-mbps <csv>      Download bandwidth assumptions, e.g. 10,25,50,100",
        ]
        .join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BrowserCacheBenchmarkBundle {
    bundle_version: String,
    warmup_samples: usize,
    timed_samples: usize,
    cached_gc_baseline_bytes: u64,
    bandwidths_mbps: Vec<u64>,
    local_file_io_report: succinct_garbling_proto::CacheBenchmarkReport,
    targets: Vec<BrowserCacheBenchmarkTargetBundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BrowserCacheBenchmarkTargetBundle {
    label: String,
    kind: String,
    backend_family: Option<CandidateBackendFamily>,
    bytes: u64,
    bytes_sha256_hex: String,
    manifest_bytes: u64,
    bytes_path: String,
    manifest_path: Option<String>,
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

fn relative_path_string(base_dir: &Path, path: &Path) -> String {
    path.strip_prefix(base_dir)
        .expect("target under output dir")
        .to_string_lossy()
        .into_owned()
}
