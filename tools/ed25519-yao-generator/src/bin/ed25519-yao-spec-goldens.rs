use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_yao_generator::render_fixed_reference_specification_v1;

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

enum Command {
    Render { template: PathBuf, output: PathBuf },
    Check { input: PathBuf },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ed25519-yao-spec-goldens: {error}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    match parse_command()? {
        Command::Render { template, output } => render(&template, &output),
        Command::Check { input } => check(&input),
    }
}

fn parse_command() -> CliResult<Command> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [action, template_flag, template, output_flag, output]
            if action == "render" && template_flag == "--template" && output_flag == "--output" =>
        {
            Ok(Command::Render {
                template: PathBuf::from(template),
                output: PathBuf::from(output),
            })
        }
        [action, input_flag, input] if action == "check" && input_flag == "--input" => {
            Ok(Command::Check {
                input: PathBuf::from(input),
            })
        }
        _ => Err(usage_error()),
    }
}

fn usage_error() -> Box<dyn std::error::Error> {
    "usage: ed25519-yao-spec-goldens render --template <path> --output <path> | check --input <path>"
        .into()
}

fn render(template: &Path, output: &Path) -> CliResult<()> {
    let source = fs::read_to_string(template)?;
    let rendered = render_fixed_reference_specification_v1(&source)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, rendered)?;
    println!(
        "rendered fixed-reference-v1 specification to {}",
        output.display()
    );
    Ok(())
}

fn check(input: &Path) -> CliResult<()> {
    let source = fs::read_to_string(input)?;
    let rendered = render_fixed_reference_specification_v1(&source)?;
    if rendered != source {
        return Err(format!(
            "fixed-reference-v1 generated region drifted: {}",
            input.display()
        )
        .into());
    }
    println!(
        "checked fixed-reference-v1 specification in {}",
        input.display()
    );
    Ok(())
}
