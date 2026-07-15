use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::{
    canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1,
    canonical_semantic_frame_party_view_vector_corpus_v1,
    parse_canonical_semantic_frame_party_view_vector_corpus_json_v1,
    SEMANTIC_FRAME_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
    SEMANTIC_FRAME_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};

const COMMITTED: &[u8] =
    include_bytes!("../vectors/ed25519-yao-semantic-frame-party-views-v1.json");

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("expected object")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &object(value)[name]
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .map(|item| item.as_str().expect("expected string"))
        .collect()
}

fn corpus() -> Value {
    serde_json::from_slice(COMMITTED).expect("committed semantic-frame corpus")
}

fn cases(value: &Value) -> &[Value] {
    field(value, "cases").as_array().expect("cases array")
}

fn temporary_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock follows Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ed25519-yao-semantic-frame-party-views-{}-{nonce}.json",
        std::process::id()
    ))
}

fn source_vector_path(artifact_kind: &str) -> PathBuf {
    let filename = match artifact_kind {
        "ceremony_context" => "ed25519-yao-ceremony-context-v1.json",
        "input_provenance" => "ed25519-yao-provenance-v1.json",
        "evaluation_input_party_views" => "ed25519-yao-evaluation-input-party-views-v1.json",
        "registration_evaluator_admission" => {
            "ed25519-yao-registration-evaluator-admission-v1.json"
        }
        "recovery_evaluator_admission" => "ed25519-yao-recovery-evaluator-admission-v1.json",
        "refresh_evaluator_admission" => "ed25519-yao-refresh-evaluator-admission-v1.json",
        "export_evaluator_authorization" => "ed25519-yao-export-evaluator-authorization-v1.json",
        "semantic_lifecycle" => "ed25519-yao-semantic-lifecycle-v1.json",
        "output_party_views" => "ed25519-yao-output-party-views-v1.json",
        "activation_delivery" => "ed25519-yao-activation-delivery-v1.json",
        "activation_recipient_party_views" => {
            "ed25519-yao-activation-recipient-party-views-v1.json"
        }
        "export_delivery" => "ed25519-yao-export-delivery-v1.json",
        "recovery_credential_transition" => "ed25519-yao-recovery-credential-transition-v1.json",
        "lifecycle_continuity" => "ed25519-yao-lifecycle-continuity-v1.json",
        "uniform_abort" => "ed25519-yao-uniform-abort-envelope-v1.json",
        "evaluator_abort_party_views" => "ed25519-yao-evaluator-abort-state-party-views-v1.json",
        other => panic!("unknown source artifact {other}"),
    };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(filename)
}

fn contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(actual) => actual == expected,
        Value::Array(values) => values.iter().any(|child| contains_string(child, expected)),
        Value::Object(values) => values
            .values()
            .any(|child| contains_string(child, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn assert_forbidden_keys_absent(value: &Value, forbidden: &[&str]) {
    match value {
        Value::Object(values) => {
            for (key, child) in values {
                assert!(
                    forbidden.iter().all(|fragment| !key.contains(fragment)),
                    "forbidden semantic-frame key {key}"
                );
                assert_forbidden_keys_absent(child, forbidden);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_forbidden_keys_absent(child, forbidden);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn is_allowed_private_value(role: &str, value: &str) -> bool {
    if value.ends_with("_public") {
        return true;
    }
    match role {
        "deriver_a" => value.starts_with("deriver_a_"),
        "deriver_b" => value.starts_with("deriver_b_"),
        "client" => value.starts_with("client_"),
        "signing_worker" => value.starts_with("signing_worker_"),
        "router" => value.starts_with("router_"),
        "observer" | "diagnostics" => false,
        other => panic!("unknown role {other}"),
    }
}

fn assert_monotonic_role_views(case: &Value) {
    let mut prior_values: Vec<BTreeSet<String>> = vec![BTreeSet::new(); 7];
    let mut prior_frames: Vec<BTreeSet<String>> = vec![BTreeSet::new(); 7];
    for step in field(case, "trace_steps").as_array().expect("trace steps") {
        for (index, view) in field(step, "ordered_role_views")
            .as_array()
            .expect("role views")
            .iter()
            .enumerate()
        {
            let role = field(view, "role").as_str().expect("role");
            let values: BTreeSet<String> = strings(field(view, "known_values"))
                .into_iter()
                .map(str::to_owned)
                .collect();
            let frames: BTreeSet<String> = strings(field(view, "observed_frame_classes"))
                .into_iter()
                .map(str::to_owned)
                .collect();
            assert!(prior_values[index].is_subset(&values));
            assert!(prior_frames[index].is_subset(&frames));
            assert!(values
                .iter()
                .all(|value| is_allowed_private_value(role, value)));
            prior_values[index] = values;
            prior_frames[index] = frames;
        }
    }
}

#[test]
fn committed_corpus_is_exact_and_has_eight_ordered_cases() {
    assert_eq!(
        COMMITTED,
        canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1()
    );
    let parsed = parse_canonical_semantic_frame_party_view_vector_corpus_json_v1(COMMITTED)
        .expect("strict canonical corpus");
    assert_eq!(
        parsed.schema(),
        SEMANTIC_FRAME_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(
        parsed.evidence_scope(),
        SEMANTIC_FRAME_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.case_count(), 8);
    assert_eq!(
        canonical_semantic_frame_party_view_vector_corpus_v1().case_count(),
        8
    );
    let value = corpus();
    assert_eq!(
        cases(&value)
            .iter()
            .map(|case| field(case, "case_id").as_str().expect("case id"))
            .collect::<Vec<_>>(),
        [
            "registration_success_worker_activated_v1",
            "recovery_success_worker_activated_v1",
            "refresh_success_worker_activated_v1",
            "export_release_exact_redelivery_v1",
            "registration_evaluator_abort_v1",
            "recovery_evaluator_abort_v1",
            "refresh_evaluator_abort_v1",
            "export_evaluator_abort_v1",
        ]
    );
}

#[test]
fn traces_freeze_state_and_emitted_frame_sequences() {
    let value = corpus();
    let activation_states = [
        "ceremony_admitted",
        "evaluation_inputs_accepted",
        "peer_protocol_in_progress",
        "output_committed",
        "activation_metadata_consumed",
        "recipient_delivery_uncertain",
        "activation_recipients_released",
        "exact_redelivery",
        "signing_worker_activated",
    ];
    let export_states = [
        "ceremony_admitted",
        "evaluation_inputs_accepted",
        "peer_protocol_in_progress",
        "output_committed",
        "recipient_delivery_uncertain",
        "export_released",
        "exact_redelivery",
    ];
    let abort_states = [
        "ceremony_admitted",
        "evaluation_inputs_accepted",
        "peer_protocol_in_progress",
        "evaluator_aborted",
    ];
    for (index, case) in cases(&value).iter().enumerate() {
        let steps = field(case, "trace_steps").as_array().expect("trace steps");
        let actual_states: Vec<_> = steps
            .iter()
            .map(|step| field(step, "delivery_state").as_str().expect("state"))
            .collect();
        let expected: &[&str] = if index < 3 {
            &activation_states
        } else if index == 3 {
            &export_states
        } else {
            &abort_states
        };
        assert_eq!(actual_states, expected);
        assert_eq!(
            strings(field(&steps[0], "emitted_frame_classes")),
            ["client_to_router_evaluation_request"]
        );
        assert_eq!(
            strings(field(&steps[1], "emitted_frame_classes")),
            [
                "router_to_deriver_a_input_delivery",
                "router_to_deriver_b_input_delivery"
            ]
        );
        assert_eq!(
            strings(field(&steps[2], "emitted_frame_classes")),
            [
                "deriver_a_to_deriver_b_peer_protocol",
                "deriver_b_to_deriver_a_peer_protocol"
            ]
        );
        if index < 4 {
            assert_eq!(
                strings(field(&steps[3], "emitted_frame_classes")),
                [
                    "deriver_a_to_router_output_packages",
                    "deriver_b_to_router_output_packages"
                ]
            );
        } else {
            assert!(strings(field(&steps[3], "emitted_frame_classes")).is_empty());
        }
    }
}

#[test]
fn role_knowledge_and_frame_observations_are_cumulative_and_isolated() {
    let value = corpus();
    assert_eq!(
        strings(field(&value, "ordered_roles")),
        [
            "deriver_a",
            "deriver_b",
            "client",
            "signing_worker",
            "router",
            "observer",
            "diagnostics"
        ]
    );
    for case in cases(&value) {
        assert_monotonic_role_views(case);
    }
}

#[test]
fn every_source_reference_resolves_to_the_declared_sibling_corpus() {
    let value = corpus();
    for case in cases(&value) {
        for reference in field(case, "source_references")
            .as_array()
            .expect("source references")
        {
            let artifact_kind = field(reference, "artifact_kind")
                .as_str()
                .expect("artifact kind");
            let source: Value = serde_json::from_slice(
                &fs::read(source_vector_path(artifact_kind)).expect("source vector"),
            )
            .expect("source JSON");
            assert_eq!(field(&source, "schema"), field(reference, "schema"));
            let selector = field(reference, "case_selector")
                .as_str()
                .expect("case selector");
            assert!(contains_string(&source, selector), "missing {selector}");
        }
    }
}

#[test]
fn corruption_retry_nonclaim_and_forbidden_key_boundaries_are_exact() {
    let value = corpus();
    assert_eq!(field(&value, "frame_classes").as_array().unwrap().len(), 11);
    assert_eq!(
        field(&value, "delivery_states").as_array().unwrap().len(),
        11
    );
    assert_eq!(
        field(&value, "corruption_markers")
            .as_array()
            .unwrap()
            .len(),
        10
    );
    assert_eq!(
        strings(field(&value, "interface_shapes")),
        [
            "corrupted_view_input",
            "selected_profile_real_execution",
            "selected_profile_ideal_simulator",
            "selected_profile_security_experiment"
        ]
    );
    let expected_nonclaims = [
        "runtime_frame_encoding_absent",
        "transport_and_endpoint_security_unclaimed",
        "production_role_view_serialization_absent",
        "secret_values_absent",
        "out_of_scope_corruptions_excluded",
        "selected_profile_satisfaction_unclaimed",
        "simulator_and_protocol_security_unclaimed",
        "constant_time_and_erasure_unclaimed",
    ];
    for (index, case) in cases(&value).iter().enumerate() {
        assert_eq!(
            strings(field(case, "explicit_nonclaims")),
            expected_nonclaims
        );
        let policy = field(case, "retry_redelivery_policy");
        if index < 4 {
            assert_eq!(field(policy, "evaluator_retry"), "not_applicable");
            assert!(strings(field(policy, "fresh_identity_requirements")).is_empty());
        } else {
            assert_eq!(field(policy, "evaluator_retry"), "terminal_abort_no_resume");
            assert_eq!(
                strings(field(policy, "fresh_identity_requirements")),
                [
                    "fresh_ceremony_request_identity",
                    "fresh_replay_nonce_identity",
                    "fresh_one_use_execution_identity"
                ]
            );
        }
    }
    assert_forbidden_keys_absent(
        &value,
        &[
            "bytes",
            "hex",
            "size",
            "length",
            "timing",
            "latency",
            "authentication",
            "signature",
            "ciphertext",
            "ticket",
            "durable",
            "transaction",
            "security_profile",
            "profile_negotiation",
            "simulator_output",
            "advantage",
            "proof",
        ],
    );
}

#[test]
fn strict_parser_cli_and_source_visibility_guards_reject_drift() {
    let mut mutated = COMMITTED.to_vec();
    mutated[0] = b'[';
    assert!(parse_canonical_semantic_frame_party_view_vector_corpus_json_v1(&mutated).is_err());
    let mut extra_lf = COMMITTED.to_vec();
    extra_lf.push(b'\n');
    assert!(parse_canonical_semantic_frame_party_view_vector_corpus_json_v1(&extra_lf).is_err());

    let output = temporary_path();
    let binary = env!("CARGO_BIN_EXE_ed25519-yao-vectors");
    let emit = Command::new(binary)
        .args([
            "emit-semantic-frame-party-views",
            "--output",
            output.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run semantic-frame emitter");
    assert!(
        emit.status.success(),
        "{}",
        String::from_utf8_lossy(&emit.stderr)
    );
    assert_eq!(fs::read(&output).expect("emitted corpus"), COMMITTED);
    let check = Command::new(binary)
        .args([
            "check-semantic-frame-party-views",
            "--input",
            output.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run semantic-frame checker");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    fs::remove_file(output).expect("remove emitted corpus");

    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/semantic_delivery_views.rs"),
    )
    .expect("semantic view source");
    assert!(!source.contains("pub fn activation_success_trace_steps_v1"));
    assert!(!source.contains("pub fn evaluator_abort_trace_steps_v1"));
    assert!(!source.contains("derive(Serialize"));
    assert!(!source.contains("derive(Deserialize"));
}
