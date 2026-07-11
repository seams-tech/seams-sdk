use std::process::ExitCode;

use ed25519_yao_generator::build_provisional_benchmark_manifest_v1;

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| "summary".to_owned());
    if arguments.next().is_some() {
        eprintln!("usage: ed25519-yao-benchmark-manifest [summary|hex]");
        return ExitCode::FAILURE;
    }
    let manifest = build_provisional_benchmark_manifest_v1();
    match command.as_str() {
        "summary" => println!(
            "bytes={} digest={} bundle_index_bytes={} bundle_index_digest={}",
            manifest.canonical_encoding().len(),
            encode_hex(manifest.digest().as_bytes()),
            manifest.bundle_index_bytes(),
            encode_hex(manifest.bundle_index_digest()),
        ),
        "hex" => println!("{}", encode_hex(manifest.canonical_encoding())),
        _ => {
            eprintln!("usage: ed25519-yao-benchmark-manifest [summary|hex]");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a String succeeds");
    }
    output
}
