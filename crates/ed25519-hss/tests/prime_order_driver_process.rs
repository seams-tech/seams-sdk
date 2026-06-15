use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_hss::{fixtures::committed_fixture_corpus, wire::WireMessage};

fn driver_bin() -> &'static str {
    env!("CARGO_BIN_EXE_prime_order_succinct_hss_driver")
}

fn temp_case_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ed25519-hss-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
    fs::write(path, bytes).expect("write json");
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path).expect("read json");
    serde_json::from_slice(&bytes).expect("decode json")
}

fn run_driver(args: &[&str]) {
    let output = Command::new(driver_bin())
        .args(args)
        .output()
        .expect("run driver");
    if !output.status.success() {
        panic!(
            "driver failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn process_driver_round_trips_ot_messages_without_local_coordinator() {
    let fixture = committed_fixture_corpus()
        .expect("fixture corpus")
        .into_iter()
        .find(|fixture| fixture.name == "wraparound-seed")
        .expect("wraparound fixture");
    let dir = temp_case_dir("driver-smoke");
    let context_path = dir.join("context.json");
    let garbler_state_path = dir.join("garbler_state.json");
    let evaluator_state_path = dir.join("evaluator_state.json");
    let offer_path = dir.join("offer.json");
    let request_path = dir.join("request.json");
    let ot_state_path = dir.join("ot_state.json");
    let server_assist_init_path = dir.join("server_assist_init.json");

    write_json(&context_path, &fixture.input.context);
    run_driver(&[
        "prepare",
        "--context-in",
        context_path.to_str().expect("context path"),
        "--garbler-state-out",
        garbler_state_path.to_str().expect("garbler state path"),
        "--evaluator-state-out",
        evaluator_state_path.to_str().expect("evaluator state path"),
    ]);
    run_driver(&[
        "garbler-offer",
        "--garbler-state-in",
        garbler_state_path.to_str().expect("garbler state path"),
        "--offer-out",
        offer_path.to_str().expect("offer path"),
    ]);
    run_driver(&[
        "evaluator-request",
        "--evaluator-state-in",
        evaluator_state_path.to_str().expect("evaluator state path"),
        "--offer-in",
        offer_path.to_str().expect("offer path"),
        "--y-client-hex",
        &hex::encode(fixture.input.y_client),
        "--tau-client-hex",
        &hex::encode(fixture.input.tau_client),
        "--request-out",
        request_path.to_str().expect("request path"),
        "--ot-state-out",
        ot_state_path.to_str().expect("ot state path"),
    ]);
    run_driver(&[
        "server-assist-init",
        "--garbler-state-in",
        garbler_state_path.to_str().expect("garbler state path"),
        "--request-in",
        request_path.to_str().expect("request path"),
        "--y-server-hex",
        &hex::encode(fixture.input.y_server),
        "--tau-server-hex",
        &hex::encode(fixture.input.tau_server),
        "--server-assist-init-out",
        server_assist_init_path
            .to_str()
            .expect("server assist init path"),
    ]);

    let offer: WireMessage = read_json(&offer_path);
    let request: WireMessage = read_json(&request_path);
    let server_assist_init: WireMessage = read_json(&server_assist_init_path);
    assert!(!offer.bytes.is_empty());
    assert!(!request.bytes.is_empty());
    assert!(!server_assist_init.bytes.is_empty());
}
