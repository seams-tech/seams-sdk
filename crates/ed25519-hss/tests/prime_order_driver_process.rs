use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_hss::{
    committed_fixture_corpus, reference::public_key_from_base_shares,
    PrimeOrderSuccinctHssEvaluationReport, PrimeOrderSuccinctHssEvaluatorDriverState,
    PrimeOrderSuccinctHssGarblerDriverState, PrimeOrderSuccinctHssWireMessage,
};

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
    let server_path = dir.join("server.json");

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
        "garbler-respond",
        "--garbler-state-in",
        garbler_state_path.to_str().expect("garbler state path"),
        "--request-in",
        request_path.to_str().expect("request path"),
        "--y-relayer-hex",
        &hex::encode(fixture.input.y_relayer),
        "--tau-relayer-hex",
        &hex::encode(fixture.input.tau_relayer),
        "--server-out",
        server_path.to_str().expect("server path"),
    ]);

    let offer: PrimeOrderSuccinctHssWireMessage = read_json(&offer_path);
    let request: PrimeOrderSuccinctHssWireMessage = read_json(&request_path);
    let server: PrimeOrderSuccinctHssWireMessage = read_json(&server_path);
    assert!(!offer.bytes.is_empty());
    assert!(!request.bytes.is_empty());
    assert!(!server.bytes.is_empty());
}

#[test]
#[ignore = "process-based end-to-end DDH evaluation is expensive in debug mode"]
fn process_driver_end_to_end_matches_reference_fixture() {
    let fixture = committed_fixture_corpus()
        .expect("fixture corpus")
        .into_iter()
        .find(|fixture| fixture.name == "wraparound-seed")
        .expect("wraparound fixture");
    let dir = temp_case_dir("driver-e2e");
    let context_path = dir.join("context.json");
    let garbler_state_path = dir.join("garbler_state.json");
    let evaluator_state_path = dir.join("evaluator_state.json");
    let offer_path = dir.join("offer.json");
    let request_path = dir.join("request.json");
    let ot_state_path = dir.join("ot_state.json");
    let server_path = dir.join("server.json");
    let evaluation_result_path = dir.join("evaluation_result.json");
    let report_path = dir.join("report.json");

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
        "garbler-respond",
        "--garbler-state-in",
        garbler_state_path.to_str().expect("garbler state path"),
        "--request-in",
        request_path.to_str().expect("request path"),
        "--y-relayer-hex",
        &hex::encode(fixture.input.y_relayer),
        "--tau-relayer-hex",
        &hex::encode(fixture.input.tau_relayer),
        "--server-out",
        server_path.to_str().expect("server path"),
    ]);
    run_driver(&[
        "evaluator-evaluate",
        "--evaluator-state-in",
        evaluator_state_path.to_str().expect("evaluator state path"),
        "--request-in",
        request_path.to_str().expect("request path"),
        "--ot-state-in",
        ot_state_path.to_str().expect("ot state path"),
        "--server-in",
        server_path.to_str().expect("server path"),
        "--evaluation-result-out",
        evaluation_result_path
            .to_str()
            .expect("evaluation result path"),
    ]);
    run_driver(&[
        "garbler-finalize",
        "--garbler-state-in",
        garbler_state_path.to_str().expect("garbler state path"),
        "--evaluation-result-in",
        evaluation_result_path
            .to_str()
            .expect("evaluation result path"),
        "--report-out",
        report_path.to_str().expect("report path"),
    ]);

    let report: PrimeOrderSuccinctHssEvaluationReport = read_json(&report_path);
    let garbler_state: PrimeOrderSuccinctHssGarblerDriverState = read_json(&garbler_state_path);
    let evaluator_state: PrimeOrderSuccinctHssEvaluatorDriverState =
        read_json(&evaluator_state_path);
    let (_runtime, garbler_session) = garbler_state.materialize().expect("garbler runtime");
    let (_runtime, evaluator_session) = evaluator_state.materialize().expect("evaluator runtime");
    let x_client_base = evaluator_session
        .client_output_opener()
        .open(&report.output_delivery.client)
        .expect("open client output");
    let x_relayer_base = garbler_session
        .server_output_opener()
        .open(&report.output_delivery.server)
        .expect("open server output");
    let public_key =
        public_key_from_base_shares(x_client_base, x_relayer_base).expect("public key");

    assert_eq!(x_client_base, fixture.output.x_client_base);
    assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
    assert_eq!(public_key, fixture.output.public_key);
}
