use std::env;
use std::fs;
use std::path::Path;

use ed25519_yao_generator::{
    compile_phase4_private_output_activation_core_v1, compile_phase4_private_output_export_core_v1,
};

const ACTIVATION_FILENAME: &str = "activation-private-output.schedule.bin";
const EXPORT_FILENAME: &str = "export-private-output.schedule.bin";

fn usage() -> &'static str {
    "usage: ed25519-yao-phase4-schedules emit --output-dir DIR"
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
    let activation = compile_phase4_private_output_activation_core_v1();
    let export = compile_phase4_private_output_export_core_v1();
    fs::write(
        output_dir.join(ACTIVATION_FILENAME),
        activation.canonical_schedule_encoding(),
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        output_dir.join(EXPORT_FILENAME),
        export.canonical_schedule_encoding(),
    )
    .map_err(|error| error.to_string())?;

    print_component("activation", &activation);
    print_component("export", &export);
    Ok(())
}

trait Phase4CircuitReport {
    fn circuit_digest(&self) -> [u8; 32];
    fn schedule_digest(&self) -> [u8; 32];
    fn input_count(&self) -> u64;
    fn output_count(&self) -> u64;
    fn gate_count(&self) -> u64;
    fn slot_count(&self) -> u64;
    fn and_count(&self) -> u64;
    fn xor_count(&self) -> u64;
    fn inversion_count(&self) -> u64;
    fn schedule_bytes(&self) -> u64;
}

impl Phase4CircuitReport for ed25519_yao_generator::Phase4PrivateOutputActivationCoreV1 {
    fn circuit_digest(&self) -> [u8; 32] {
        self.benchmark_component_digest().expose_public_bytes()
    }

    fn schedule_digest(&self) -> [u8; 32] {
        self.benchmark_schedule_digest().expose_public_bytes()
    }

    fn input_count(&self) -> u64 {
        self.metrics().input_wire_count()
    }

    fn output_count(&self) -> u64 {
        self.metrics().output_wire_count()
    }

    fn gate_count(&self) -> u64 {
        self.metrics().total_gate_count()
    }

    fn slot_count(&self) -> u64 {
        self.schedule_metrics().reusable_slot_count()
    }

    fn and_count(&self) -> u64 {
        self.metrics().and_gate_count()
    }

    fn xor_count(&self) -> u64 {
        self.metrics().xor_gate_count()
    }

    fn inversion_count(&self) -> u64 {
        self.metrics().inversion_gate_count()
    }

    fn schedule_bytes(&self) -> u64 {
        self.schedule_metrics().encoded_schedule_bytes()
    }
}

impl Phase4CircuitReport for ed25519_yao_generator::Phase4PrivateOutputExportCoreV1 {
    fn circuit_digest(&self) -> [u8; 32] {
        self.benchmark_component_digest().expose_public_bytes()
    }

    fn schedule_digest(&self) -> [u8; 32] {
        self.benchmark_schedule_digest().expose_public_bytes()
    }

    fn input_count(&self) -> u64 {
        self.metrics().input_wire_count()
    }

    fn output_count(&self) -> u64 {
        self.metrics().output_wire_count()
    }

    fn gate_count(&self) -> u64 {
        self.metrics().total_gate_count()
    }

    fn slot_count(&self) -> u64 {
        self.schedule_metrics().reusable_slot_count()
    }

    fn and_count(&self) -> u64 {
        self.metrics().and_gate_count()
    }

    fn xor_count(&self) -> u64 {
        self.metrics().xor_gate_count()
    }

    fn inversion_count(&self) -> u64 {
        self.metrics().inversion_gate_count()
    }

    fn schedule_bytes(&self) -> u64 {
        self.schedule_metrics().encoded_schedule_bytes()
    }
}

fn print_component(name: &str, circuit: &impl Phase4CircuitReport) {
    println!(
        "{name} circuit_digest={} schedule_digest={} inputs={} outputs={} gates={} slots={} and={} xor={} inv={} schedule_bytes={} table_bytes={}",
        encode_hex(circuit.circuit_digest()),
        encode_hex(circuit.schedule_digest()),
        circuit.input_count(),
        circuit.output_count(),
        circuit.gate_count(),
        circuit.slot_count(),
        circuit.and_count(),
        circuit.xor_count(),
        circuit.inversion_count(),
        circuit.schedule_bytes(),
        circuit.and_count() * 32,
    );
}

fn encode_hex(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String succeeds");
    }
    output
}
