use std::fs;
use std::process;

use ed25519_hss::{
    build_candidate_artifact_stub_with_chunk_size, build_fixed_hidden_core_candidate_for_backend,
    deterministic_fixture_corpus, materialize_candidate_artifact_stub_bytes,
    CandidateBackendFamily,
};

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    let fixture = if let Some(fixture_name) = args.fixture_name.as_deref() {
        fixtures
            .iter()
            .find(|fixture| fixture.name == fixture_name)
            .unwrap_or_else(|| panic!("unknown fixture: {fixture_name}"))
    } else {
        fixtures.first().expect("at least one fixture")
    };

    let candidate =
        build_fixed_hidden_core_candidate_for_backend(&fixture.input.context, args.backend_family)
            .expect("candidate");
    let manifest = build_candidate_artifact_stub_with_chunk_size(&candidate, args.chunk_size_bytes)
        .expect("artifact stub manifest");

    if let Some(path) = args.binary_output_path.as_deref() {
        let artifact_bytes = materialize_candidate_artifact_stub_bytes(&candidate).expect("bytes");
        fs::write(path, artifact_bytes).expect("write artifact bytes");
        eprintln!("wrote artifact bytes to {path}");
    }

    let rendered = if args.emit_json {
        serde_json::to_string_pretty(&manifest).expect("artifact stub json")
    } else {
        manifest.summary_lines().join("\n")
    };

    if let Some(path) = args.manifest_output_path.as_deref() {
        fs::write(path, &rendered).expect("write artifact manifest");
        eprintln!("wrote artifact manifest to {path}");
    }

    println!("{rendered}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    fixture_name: Option<String>,
    backend_family: CandidateBackendFamily,
    chunk_size_bytes: u64,
    binary_output_path: Option<String>,
    manifest_output_path: Option<String>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            fixture_name: None,
            backend_family: CandidateBackendFamily::PrimeOrderSizeOptimized,
            chunk_size_bytes: 4_096,
            binary_output_path: None,
            manifest_output_path: None,
        };

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--json" => {
                    parsed.emit_json = true;
                    idx += 1;
                }
                "--fixture" => {
                    parsed.fixture_name = Some(read_next_value(&args, &mut idx, "--fixture")?);
                }
                "--backend" => {
                    parsed.backend_family =
                        parse_backend_family(&read_next_value(&args, &mut idx, "--backend")?)?;
                }
                "--chunk-size" => {
                    parsed.chunk_size_bytes = read_next_value(&args, &mut idx, "--chunk-size")?
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --chunk-size value\n\n{}", Self::usage()))?;
                }
                "--output-binary" => {
                    parsed.binary_output_path =
                        Some(read_next_value(&args, &mut idx, "--output-binary")?);
                }
                "--output-manifest" => {
                    parsed.manifest_output_path =
                        Some(read_next_value(&args, &mut idx, "--output-manifest")?);
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
            "Usage: emit_candidate_artifact_stub [options]",
            "",
            "Options:",
            "  --json                     Print the artifact manifest as JSON",
            "  --fixture <name>          Use a specific deterministic fixture context",
            "  --backend <name>          prime-order-size-opt | prime-order-compute-opt",
            "  --chunk-size <bytes>      Chunk size for the manifest",
            "  --output-binary <path>    Write the stub artifact bytes to a file",
            "  --output-manifest <path>  Write the rendered manifest to a file",
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

fn parse_backend_family(value: &str) -> Result<CandidateBackendFamily, String> {
    match value {
        "prime-order-size-opt" => Ok(CandidateBackendFamily::PrimeOrderSizeOptimized),
        "prime-order-compute-opt" => Ok(CandidateBackendFamily::PrimeOrderComputeOptimized),
        _ => Err(format!(
            "invalid --backend value: {value}\n\n{}",
            CliArgs::usage()
        )),
    }
}
