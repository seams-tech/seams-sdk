use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_yao_generator::{canonical_vector_corpus_v1, VectorCorpusV1};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

enum Command {
    Emit { output: PathBuf },
    Check { input: PathBuf },
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
        Command::Check { input } => check(&input),
    }
}

fn parse_command() -> CliResult<Command> {
    let mut arguments = env::args().skip(1);
    let action = arguments.next().ok_or_else(usage_error)?;
    let flag = arguments.next().ok_or_else(usage_error)?;
    let path = arguments.next().ok_or_else(usage_error)?;
    if arguments.next().is_some() {
        return Err(usage_error());
    }

    match (action.as_str(), flag.as_str()) {
        ("emit", "--output") => Ok(Command::Emit {
            output: PathBuf::from(path),
        }),
        ("check", "--input") => Ok(Command::Check {
            input: PathBuf::from(path),
        }),
        _ => Err(usage_error()),
    }
}

fn usage_error() -> Box<dyn std::error::Error> {
    "usage: ed25519-yao-vectors emit --output <path> | check --input <path>".into()
}

fn emit(output: &Path) -> CliResult<()> {
    let corpus = canonical_vector_corpus_v1();
    let mut encoded = serde_json::to_string_pretty(&corpus)?;
    encoded.push('\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, encoded)?;
    println!(
        "wrote {} canonical cases to {}",
        corpus.cases.len(),
        output.display()
    );
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
