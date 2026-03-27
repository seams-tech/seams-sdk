use std::fs;
use std::process;

use succinct_garbling::{
    build_fixed_hidden_core_candidate_for_backend, deterministic_fixture_corpus,
    simulate_fixed_hidden_core_candidate_for_backend, CandidateBackendFamily,
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
    let simulation =
        simulate_fixed_hidden_core_candidate_for_backend(&fixture.input, args.backend_family)
            .expect("simulation");

    let rendered = if args.emit_json {
        candidate.to_json_pretty().expect("candidate json")
    } else {
        let mut markdown = candidate.to_markdown();
        markdown.push_str("\n## Oracle Simulation\n\n");
        for line in simulation.summary_lines() {
            markdown.push_str(&format!("- {}\n", line));
        }
        markdown
    };

    if let Some(path) = args.output_path {
        fs::write(&path, &rendered).expect("write candidate note");
        eprintln!("wrote candidate note to {path}");
    }

    println!("{rendered}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
    backend_family: CandidateBackendFamily,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            backend_family: CandidateBackendFamily::PrimeOrderSizeOptimized,
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
                "--backend" => {
                    parsed.backend_family =
                        parse_backend_family(&read_next_value(&args, &mut idx, "--backend")?)?;
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
            "Usage: emit_candidate_note [options]",
            "",
            "Options:",
            "  --json                  Print the candidate as JSON instead of Markdown",
            "  --output <path>         Write the rendered candidate note to a file",
            "  --fixture <name>        Use a specific deterministic fixture context",
            "  --backend <name>        prime-order-size-opt | prime-order-compute-opt | paillier | lattice",
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
        "paillier" => Ok(CandidateBackendFamily::PaillierCompressed),
        "lattice" => Ok(CandidateBackendFamily::LatticeRlwe),
        _ => Err(format!(
            "invalid --backend value: {value}\n\n{}",
            CliArgs::usage()
        )),
    }
}
