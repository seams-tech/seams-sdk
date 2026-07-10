use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_yao_generator::{
    canonical_lifecycle_continuity_corpus_v1, canonical_vector_corpus_v1,
    differential_vector_corpus_v1, LifecycleContinuityCorpusV1, VectorCorpusV1,
};
use serde::Serialize;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

enum Command {
    Emit {
        output: PathBuf,
    },
    EmitDifferential {
        public_test_seed: [u8; 32],
        cases: usize,
        output: PathBuf,
    },
    EmitLifecycleContinuity {
        output: PathBuf,
    },
    Check {
        input: PathBuf,
    },
    CheckLifecycleContinuity {
        input: PathBuf,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ed25519-yao-vectors: {error}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    match parse_command()? {
        Command::Emit { output } => emit(&output),
        Command::EmitDifferential {
            public_test_seed,
            cases,
            output,
        } => emit_differential(public_test_seed, cases, &output),
        Command::EmitLifecycleContinuity { output } => emit_lifecycle_continuity(&output),
        Command::Check { input } => check(&input),
        Command::CheckLifecycleContinuity { input } => check_lifecycle_continuity(&input),
    }
}

fn parse_command() -> CliResult<Command> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [action, flag, path] if action == "emit" && flag == "--output" => Ok(Command::Emit {
            output: PathBuf::from(path),
        }),
        [action, flag, path] if action == "check" && flag == "--input" => Ok(Command::Check {
            input: PathBuf::from(path),
        }),
        [action, flag, path] if action == "emit-lifecycle-continuity" && flag == "--output" => {
            Ok(Command::EmitLifecycleContinuity {
                output: PathBuf::from(path),
            })
        }
        [action, flag, path] if action == "check-lifecycle-continuity" && flag == "--input" => {
            Ok(Command::CheckLifecycleContinuity {
                input: PathBuf::from(path),
            })
        }
        [action, seed_flag, seed, cases_flag, cases, output_flag, output]
            if action == "emit-differential"
                && seed_flag == "--seed-hex"
                && cases_flag == "--cases"
                && output_flag == "--output" =>
        {
            Ok(Command::EmitDifferential {
                public_test_seed: decode_hex_32(seed)?,
                cases: cases.parse()?,
                output: PathBuf::from(output),
            })
        }
        _ => Err(usage_error()),
    }
}

fn usage_error() -> Box<dyn std::error::Error> {
    "usage: ed25519-yao-vectors emit --output <path> | emit-differential --seed-hex <64-hex-chars> --cases <count> --output <path> | emit-lifecycle-continuity --output <path> | check --input <path> | check-lifecycle-continuity --input <path>".into()
}

fn emit(output: &Path) -> CliResult<()> {
    let corpus = canonical_vector_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} canonical cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_differential(public_test_seed: [u8; 32], cases: usize, output: &Path) -> CliResult<()> {
    let corpus = differential_vector_corpus_v1(public_test_seed, cases)?;
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} deterministic differential cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn emit_lifecycle_continuity(output: &Path) -> CliResult<()> {
    let corpus = canonical_lifecycle_continuity_corpus_v1();
    write_corpus(output, &corpus)?;
    println!(
        "wrote {} lifecycle-continuity cases to {}",
        corpus.cases.len(),
        output.display()
    );
    Ok(())
}

fn write_corpus<T: Serialize>(output: &Path, corpus: &T) -> CliResult<()> {
    let mut encoded = serde_json::to_string_pretty(corpus)?;
    encoded.push('\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, encoded)?;
    Ok(())
}

fn check(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: VectorCorpusV1 = serde_json::from_str(&encoded)?;
    let expected = canonical_vector_corpus_v1();
    if parsed != expected {
        return Err(format!("vector corpus drifted: {}", input.display()).into());
    }
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "vector corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} canonical cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn check_lifecycle_continuity(input: &Path) -> CliResult<()> {
    let encoded = fs::read_to_string(input)?;
    let parsed: LifecycleContinuityCorpusV1 = serde_json::from_str(&encoded)?;
    parsed.validate()?;
    let expected = canonical_lifecycle_continuity_corpus_v1();
    let expected_encoding = format!("{}\n", serde_json::to_string_pretty(&expected)?);
    if encoded != expected_encoding {
        return Err(format!(
            "lifecycle-continuity corpus encoding is noncanonical: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked {} lifecycle-continuity cases in {}",
        parsed.cases.len(),
        input.display()
    );
    Ok(())
}

fn decode_hex_32(value: &str) -> CliResult<[u8; 32]> {
    if value.len() != 64 {
        return Err("public differential seed must contain exactly 64 hex characters".into());
    }

    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "public differential seed contains invalid hex")?;
    }
    Ok(output)
}
