use std::env;
use std::path::Path;

use ed25519_yao_generator::build_provisional_artifact_bundle_v1;

fn usage() -> &'static str {
    "usage: ed25519-yao-circuit-artifacts <emit --output-dir DIR|check --input-dir DIR>"
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(|| usage().to_owned())?;
    let option = arguments.next().ok_or_else(|| usage().to_owned())?;
    let path = arguments.next().ok_or_else(|| usage().to_owned())?;
    if arguments.next().is_some() {
        return Err(usage().to_owned());
    }

    let bundle = build_provisional_artifact_bundle_v1();
    match (command.as_str(), option.as_str()) {
        ("emit", "--output-dir") => {
            bundle
                .emit_to(Path::new(&path))
                .map_err(|error| error.to_string())?;
            println!(
                "emitted provisional Phase 2A artifact bundle {}",
                encode_hex(bundle.digest().expose_public_bytes())
            );
            Ok(())
        }
        ("check", "--input-dir") => {
            bundle
                .check_directory(Path::new(&path))
                .map_err(|error| error.to_string())?;
            println!(
                "checked provisional Phase 2A artifact bundle {}",
                encode_hex(bundle.digest().expose_public_bytes())
            );
            Ok(())
        }
        _ => Err(usage().to_owned()),
    }
}

fn encode_hex(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a String succeeds");
    }
    output
}
