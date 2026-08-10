use std::env;
use std::fs;
use std::path::Path;

use ed25519_yao_generator::compile_lane_materialization_v1;

const FILENAME: &str = "lane-materialization.schedule.bin";

fn usage() -> &'static str {
    "usage: ed25519-yao-lane-materialization-schedules emit --output-dir DIR"
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
    let output_dir = arguments.next().ok_or_else(|| usage().to_owned())?;
    if command != "emit" || option != "--output-dir" || arguments.next().is_some() {
        return Err(usage().to_owned());
    }

    let output_dir = Path::new(&output_dir);
    fs::create_dir_all(output_dir).map_err(|error| error.to_string())?;
    let circuit = compile_lane_materialization_v1();
    fs::write(
        output_dir.join(FILENAME),
        circuit.canonical_schedule_encoding(),
    )
    .map_err(|error| error.to_string())?;

    let metrics = circuit.metrics();
    let schedule = circuit.schedule_metrics();
    println!(
        "lane_materialization circuit_digest={} schedule_digest={} inputs={} outputs={} gates={} slots={} and={} xor={} inv={} schedule_bytes={} table_bytes={}",
        encode_hex(circuit.benchmark_component_digest().expose_public_bytes()),
        encode_hex(circuit.benchmark_schedule_digest().expose_public_bytes()),
        metrics.input_wire_count(),
        metrics.output_wire_count(),
        metrics.total_gate_count(),
        schedule.reusable_slot_count(),
        metrics.and_gate_count(),
        metrics.xor_gate_count(),
        metrics.inversion_gate_count(),
        schedule.encoded_schedule_bytes(),
        metrics.and_gate_count() * 32,
    );
    Ok(())
}

fn encode_hex(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String succeeds");
    }
    output
}
