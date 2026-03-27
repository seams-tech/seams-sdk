use std::fs;
use std::process;

use succinct_garbling::{
    build_fixed_hidden_core_candidate, build_prime_order_size_optimized_artifact,
    deterministic_fixture_corpus, materialize_prime_order_size_optimized_bytes,
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

    let candidate = build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate");
    let manifest =
        build_prime_order_size_optimized_artifact(&candidate).expect("prime-order manifest");

    if let Some(path) = args.binary_output_path.as_deref() {
        let bytes = materialize_prime_order_size_optimized_bytes(&candidate).expect("bytes");
        fs::write(path, bytes).expect("write artifact bytes");
        eprintln!("wrote prime-order artifact bytes to {path}");
    }

    let rendered = if args.emit_json {
        manifest.to_json_pretty().expect("manifest json")
    } else {
        manifest.summary_lines().join("\n")
    };

    if let Some(path) = args.manifest_output_path.as_deref() {
        fs::write(path, &rendered).expect("write manifest");
        eprintln!("wrote prime-order artifact manifest to {path}");
    }

    println!("{rendered}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    fixture_name: Option<String>,
    binary_output_path: Option<String>,
    manifest_output_path: Option<String>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            fixture_name: None,
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
            "Usage: emit_prime_order_artifact [options]",
            "",
            "Options:",
            "  --json                      Print the manifest as JSON",
            "  --fixture <name>           Use a specific deterministic fixture context",
            "  --output-binary <path>     Write the encoded artifact bytes to a file",
            "  --output-manifest <path>   Write the manifest to a file",
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
