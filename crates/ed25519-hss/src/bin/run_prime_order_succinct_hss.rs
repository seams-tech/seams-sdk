use std::fs;
use std::process;

use ed25519_hss::fixtures::{deterministic_fixture_corpus, FExpandFixture};
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let fixture = select_fixture(args.fixture_name.as_deref());
    let report = prepare_prime_order_succinct_hss(&fixture.input.context)
        .and_then(|session| session.evaluate_for_clear_input_debug(&fixture.input))
        .expect("evaluate succinct HSS");
    let rendered = if args.emit_json {
        serde_json::to_string_pretty(&report).expect("serialize succinct HSS report")
    } else {
        report.summary_lines().join("\n")
    };

    if let Some(path) = args.output_path {
        fs::write(&path, &rendered).expect("write succinct HSS report");
        eprintln!("wrote succinct HSS report to {path}");
    }

    println!("{rendered}");
}

fn select_fixture(name: Option<&str>) -> FExpandFixture {
    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    match name {
        Some(fixture_name) => fixtures
            .into_iter()
            .find(|fixture| fixture.name == fixture_name)
            .unwrap_or_else(|| panic!("unknown fixture: {fixture_name}")),
        None => fixtures.into_iter().next().expect("at least one fixture"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
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
            "Usage: run_prime_order_succinct_hss [options]",
            "",
            "Options:",
            "  --json                  Print the full JSON report",
            "  --output <path>         Write the rendered report to a file",
            "  --fixture <name>        Use a specific deterministic fixture",
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
