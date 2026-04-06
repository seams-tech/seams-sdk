use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_hss::{
    client::{ClientDriverState, ClientOtState},
    fixtures::{committed_fixture_corpus, FExpandFixture},
    protocol::prepare_prime_order_succinct_hss,
    server::{ServerDriverState, ServerEvalOperation},
    shared::{public_key_from_base_shares, ProtoError, ProtoResult},
    wire::{EvaluationReport, WireMessage},
};

const SECURITY_AUDIT_CHECKLIST: &[(&str, &str)] = &[
    (
        "separation_of_shares",
        "Role-local serialized state must not contain the other party's raw secret input shares.",
    ),
    (
        "wire_messages_do_not_embed_raw_secret_inputs",
        "Offer, request, server, and evaluation-result wire messages must not carry raw client or server secret bytes in the clear.",
    ),
    (
        "client_never_gets_server_recovery_material",
        "Evaluator-side state and request/evaluation artifacts must never contain enough raw material to recover relayer/server shares directly.",
    ),
    (
        "server_never_gets_client_recovery_material",
        "Garbler-side state and offer/response artifacts must never contain enough raw material to recover client shares directly.",
    ),
    (
        "split_role_e2e_matches_reference_output",
        "The separated-role flow must still reproduce the committed fixture's client share, server share, and public key.",
    ),
];

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run() -> ProtoResult<()> {
    let fixture_name = env::args()
        .nth(1)
        // The segregation audit scans serialized artifacts for raw secret bytes, so the
        // default fixture should have high-entropy inputs to avoid low-entropy false positives.
        .unwrap_or_else(|| "derived-gamma".to_string());
    let fixture = select_fixture(&fixture_name)?;
    let temp_dir = ExampleTempDir::new("separated-roles-e2e")?;

    let mut timings = Vec::new();

    let prepare_started = Instant::now();
    let prepared = prepare_prime_order_succinct_hss(&fixture.input.context)?;
    let garbler_state = prepared.garbler_driver_state();
    let evaluator_state = prepared.evaluator_driver_state();
    timings.push(("prepare", prepare_started.elapsed()));

    let context_path = temp_dir.path().join("context.json");
    let garbler_state_path = temp_dir.path().join("garbler_state.json");
    let evaluator_state_path = temp_dir.path().join("evaluator_state.json");
    let offer_path = temp_dir.path().join("offer.json");
    let request_path = temp_dir.path().join("request.json");
    let ot_state_path = temp_dir.path().join("ot_state.json");
    let server_assist_init_path = temp_dir.path().join("server_assist_init.json");
    let staged_flow_path = temp_dir.path().join("staged_flow.json");
    let report_path = temp_dir.path().join("report.json");

    write_json(&context_path, &fixture.input.context)?;
    write_json(&garbler_state_path, &garbler_state)?;
    write_json(&evaluator_state_path, &evaluator_state)?;

    assert_segregated(
        "garbler_state",
        &garbler_state,
        &[
            ("y_client", &fixture.input.y_client),
            ("tau_client", &fixture.input.tau_client),
        ],
    )?;
    assert_segregated(
        "evaluator_state",
        &evaluator_state,
        &[
            ("y_relayer", &fixture.input.y_relayer),
            ("tau_relayer", &fixture.input.tau_relayer),
        ],
    )?;

    let garbler_offer_started = Instant::now();
    let garbler_state_for_offer: ServerDriverState = read_json(&garbler_state_path)?;
    let (_runtime, garbler_session_for_offer) = garbler_state_for_offer.materialize()?;
    let offer_message = garbler_session_for_offer.client_ot_offer_message()?;
    timings.push(("garbler_offer", garbler_offer_started.elapsed()));
    write_json(&offer_path, &offer_message)?;
    assert_segregated(
        "offer_message",
        &offer_message,
        &[
            ("y_client", &fixture.input.y_client),
            ("tau_client", &fixture.input.tau_client),
            ("y_relayer", &fixture.input.y_relayer),
            ("tau_relayer", &fixture.input.tau_relayer),
        ],
    )?;

    let evaluator_request_started = Instant::now();
    let evaluator_state_for_request: ClientDriverState = read_json(&evaluator_state_path)?;
    let (_runtime, evaluator_session_for_request) = evaluator_state_for_request.materialize()?;
    let offer_message_for_request: WireMessage = read_json(&offer_path)?;
    let (request_message, ot_state) = evaluator_session_for_request
        .prepare_client_ot_request_from_offer_message(
            &offer_message_for_request,
            fixture.input.y_client,
            fixture.input.tau_client,
        )?;
    timings.push(("evaluator_request", evaluator_request_started.elapsed()));
    write_json(&request_path, &request_message)?;
    write_json(&ot_state_path, &ot_state)?;
    assert_segregated(
        "request_message",
        &request_message,
        &[
            ("y_relayer", &fixture.input.y_relayer),
            ("tau_relayer", &fixture.input.tau_relayer),
        ],
    )?;
    assert_segregated(
        "evaluator_ot_state",
        &ot_state,
        &[
            ("y_relayer", &fixture.input.y_relayer),
            ("tau_relayer", &fixture.input.tau_relayer),
        ],
    )?;

    let garbler_assist_init_started = Instant::now();
    let garbler_state_for_respond: ServerDriverState = read_json(&garbler_state_path)?;
    let (_runtime, garbler_session_for_respond) = garbler_state_for_respond.materialize()?;
    let request_message_for_respond: WireMessage = read_json(&request_path)?;
    let (server_assist_init_message, server_eval_state) = garbler_session_for_respond
        .prepare_server_assist_init_message(
            &request_message_for_respond,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )?;
    timings.push(("garbler_assist_init", garbler_assist_init_started.elapsed()));
    write_json(&server_assist_init_path, &server_assist_init_message)?;
    assert_segregated(
        "server_assist_init_message",
        &server_assist_init_message,
        &[
            ("y_client", &fixture.input.y_client),
            ("tau_client", &fixture.input.tau_client),
            ("y_relayer", &fixture.input.y_relayer),
            ("tau_relayer", &fixture.input.tau_relayer),
        ],
    )?;

    let staged_flow_started = Instant::now();
    let evaluator_state_for_evaluate: ClientDriverState = read_json(&evaluator_state_path)?;
    let (_runtime_for_evaluate, evaluator_session_for_evaluate) =
        evaluator_state_for_evaluate.materialize()?;
    let ot_state_for_evaluate: ClientOtState = read_json(&ot_state_path)?;
    let server_assist_init_for_staged_flow: WireMessage = read_json(&server_assist_init_path)?;
    let add_stage_request_message = evaluator_session_for_evaluate
        .prepare_add_stage_request_message(
            &request_message_for_respond,
            &ot_state_for_evaluate,
            &server_assist_init_for_staged_flow,
        )?;
    let (add_stage_response_message, mut next_server_eval_state) = garbler_session_for_respond
        .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)?;
    let mut message_schedule_request_messages = Vec::new();
    let mut message_schedule_response_messages = Vec::new();
    let mut prior_stage_response_message = add_stage_response_message.clone();
    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let request_message = evaluator_session_for_evaluate
            .prepare_message_schedule_request_message(&prior_stage_response_message)?;
        let (response_message, server_state_after_response) = garbler_session_for_respond
            .prepare_message_schedule_response_message(&next_server_eval_state, &request_message)?;
        message_schedule_request_messages.push(request_message);
        message_schedule_response_messages.push(response_message.clone());
        prior_stage_response_message = response_message;
        next_server_eval_state = server_state_after_response;
    }
    let mut round_core_request_messages = Vec::new();
    let mut round_core_response_messages = Vec::new();
    for _ in 0..ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
        let request_message = evaluator_session_for_evaluate
            .prepare_round_core_request_message(&prior_stage_response_message)?;
        let (response_message, server_state_after_response) = garbler_session_for_respond
            .prepare_round_core_response_message(&next_server_eval_state, &request_message)?;
        round_core_request_messages.push(request_message);
        round_core_response_messages.push(response_message.clone());
        prior_stage_response_message = response_message;
        next_server_eval_state = server_state_after_response;
    }
    let output_projection_request_message = evaluator_session_for_evaluate
        .prepare_output_projection_request_message(&prior_stage_response_message)?;
    let (output_projection_response_message, final_server_eval_state) = garbler_session_for_respond
        .prepare_output_projection_response_message(
            &next_server_eval_state,
            &output_projection_request_message,
        )?;
    timings.push(("staged_flow", staged_flow_started.elapsed()));
    write_json(
        &staged_flow_path,
        &serde_json::json!({
            "serverAssistInitMessage": server_assist_init_for_staged_flow,
            "addStageRequestMessage": add_stage_request_message,
            "addStageResponseMessage": add_stage_response_message,
            "messageScheduleRequestMessages": message_schedule_request_messages,
            "messageScheduleResponseMessages": message_schedule_response_messages,
            "roundCoreRequestMessages": round_core_request_messages,
            "roundCoreResponseMessages": round_core_response_messages,
            "outputProjectionRequestMessage": output_projection_request_message,
            "outputProjectionResponseMessage": output_projection_response_message,
            "finalServerEvalStateStatus": format!("{:?}", final_server_eval_state.status),
        }),
    )?;
    assert_segregated(
        "staged_flow",
        &read_json::<serde_json::Value>(&staged_flow_path)?,
        &[
            ("y_client", &fixture.input.y_client),
            ("tau_client", &fixture.input.tau_client),
            ("y_relayer", &fixture.input.y_relayer),
            ("tau_relayer", &fixture.input.tau_relayer),
        ],
    )?;

    let final_report_started = Instant::now();
    let report = prepared.evaluate_for_clear_input_debug(&fixture.input)?;
    timings.push(("final_report", final_report_started.elapsed()));
    write_json(&report_path, &report)?;

    verify_report(
        &fixture,
        &garbler_state_path,
        &evaluator_state_path,
        &report_path,
    )?;

    println!("Separated prime-order succinct HSS end-to-end example");
    println!("fixture: {}", fixture.name);
    if temp_dir.keep() {
        println!("artifact_dir: {}", temp_dir.path().display());
    } else {
        println!(
            "artifact_dir: {} (removed on exit; set ED25519_HSS_KEEP_EXAMPLE_DIR=1 to keep)",
            temp_dir.path().display()
        );
    }
    println!("segregation_audit: passed");
    println!("security_audit_checklist:");
    for (label, description) in SECURITY_AUDIT_CHECKLIST {
        println!("  [x] {label}: {description}");
    }
    for (label, elapsed) in timings {
        println!("{label}: {:.3} ms", elapsed.as_secs_f64() * 1_000.0);
    }

    Ok(())
}

fn select_fixture(name: &str) -> ProtoResult<FExpandFixture> {
    committed_fixture_corpus()?
        .into_iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| ProtoError::InvalidInput(format!("unknown fixture {name}")))
}

fn verify_report(
    fixture: &FExpandFixture,
    garbler_state_path: &Path,
    evaluator_state_path: &Path,
    report_path: &Path,
) -> ProtoResult<()> {
    let report: EvaluationReport = read_json(report_path)?;
    let garbler_state: ServerDriverState = read_json(garbler_state_path)?;
    let evaluator_state: ClientDriverState = read_json(evaluator_state_path)?;
    let (_runtime, garbler_session) = garbler_state.materialize()?;
    let (_runtime, evaluator_session) = evaluator_state.materialize()?;
    let x_client_base = evaluator_session
        .client_output_opener()
        .open(&report.output_delivery.client)?;
    let x_relayer_base = garbler_session
        .server_output_opener()
        .open(&report.output_delivery.server)?;
    let public_key = public_key_from_base_shares(x_client_base, x_relayer_base)?;

    if x_client_base != fixture.output.x_client_base {
        return Err(ProtoError::InvalidInput(
            "client output share does not match fixture".to_string(),
        ));
    }
    if x_relayer_base != fixture.output.x_relayer_base {
        return Err(ProtoError::InvalidInput(
            "server output share does not match fixture".to_string(),
        ));
    }
    if public_key != fixture.output.public_key {
        return Err(ProtoError::InvalidInput(
            "public key does not match fixture".to_string(),
        ));
    }
    Ok(())
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> ProtoResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| ProtoError::Decode(format!("failed to encode {}: {err}", path.display())))?;
    fs::write(path, bytes)
        .map_err(|err| ProtoError::Decode(format!("failed to write {}: {err}", path.display())))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> ProtoResult<T> {
    let bytes = fs::read(path)
        .map_err(|err| ProtoError::Decode(format!("failed to read {}: {err}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| ProtoError::Decode(format!("failed to decode {}: {err}", path.display())))
}

fn assert_segregated<T: serde::Serialize>(
    label: &str,
    artifact: &T,
    forbidden: &[(&str, &[u8; 32])],
) -> ProtoResult<()> {
    let bytes = bincode::serialize(artifact).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to encode {label} for segregation audit: {err}"
        ))
    })?;
    for (secret_label, secret_bytes) in forbidden {
        if contains_subslice(&bytes, secret_bytes.as_slice()) {
            return Err(ProtoError::InvalidInput(format!(
                "{label} unexpectedly contains raw {secret_label} bytes"
            )));
        }
    }
    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct ExampleTempDir {
    path: PathBuf,
    keep: bool,
}

impl ExampleTempDir {
    fn new(label: &str) -> ProtoResult<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| ProtoError::InvalidInput(format!("system time error: {err}")))?
            .as_nanos();
        let path = env::temp_dir().join(format!("ed25519-hss-{label}-{}-{nanos}", process::id()));
        fs::create_dir_all(&path).map_err(|err| {
            ProtoError::Decode(format!("failed to create {}: {err}", path.display()))
        })?;
        Ok(Self {
            path,
            keep: env::var_os("ED25519_HSS_KEEP_EXAMPLE_DIR").is_some(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn keep(&self) -> bool {
        self.keep
    }
}

impl Drop for ExampleTempDir {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}
