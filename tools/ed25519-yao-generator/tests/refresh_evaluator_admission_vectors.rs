use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::{
    canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_refresh_evaluator_admission_vector_corpus_v1,
    parse_canonical_refresh_evaluator_admission_vector_corpus_json_v1,
    REFRESH_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
    REFRESH_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1,
};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/ed25519-yao-refresh-evaluator-admission-v1.json")
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock follows Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ed25519-yao-refresh-evaluator-{label}-{}-{nonce}.json",
        std::process::id()
    ))
}

fn assert_forbidden_keys_absent(value: &serde_json::Value, forbidden: &[&str]) {
    match value {
        serde_json::Value::Object(object) => {
            for key in object.keys() {
                assert!(!forbidden.contains(&key.as_str()), "forbidden key {key}");
            }
            for child in object.values() {
                assert_forbidden_keys_absent(child, forbidden);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                assert_forbidden_keys_absent(child, forbidden);
            }
        }
        _ => {}
    }
}

#[test]
fn canonical_corpus_has_one_narrow_refresh_case() {
    let corpus = canonical_refresh_evaluator_admission_vector_corpus_v1();
    assert_eq!(
        corpus.schema(),
        REFRESH_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(corpus.protocol_id(), ed25519_yao::PROTOCOL_ID_STR);
    assert_eq!(
        corpus.evidence_scope(),
        REFRESH_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 1);
}

#[test]
fn committed_corpus_equals_exact_canonical_bytes_and_rejects_drift() {
    let committed = fs::read(corpus_path()).expect("committed corpus");
    let canonical = canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1();
    assert_eq!(committed, canonical);
    parse_canonical_refresh_evaluator_admission_vector_corpus_json_v1(&committed)
        .expect("canonical corpus parses");
    let mut mutated = canonical.clone();
    let index = mutated
        .iter()
        .position(|byte| *byte == b'a')
        .expect("canonical corpus contains ASCII a");
    mutated[index] = b'b';
    assert!(parse_canonical_refresh_evaluator_admission_vector_corpus_json_v1(&mutated).is_err());
    let mut trailing = canonical;
    trailing.push(b'\n');
    assert!(parse_canonical_refresh_evaluator_admission_vector_corpus_json_v1(&trailing).is_err());
}

#[test]
fn corpus_commits_store_transition_output_and_audited_cross_links() {
    let encoded = fs::read(corpus_path()).expect("committed corpus");
    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("valid JSON");
    let case = &value["cases"][0];
    assert_eq!(
        case["case_id"],
        "refresh_admitted_evaluation_output_committed_v1"
    );
    assert_eq!(case["request_kind"], "refresh");
    assert_eq!(
        case["source_references"]["ceremony_context_case_id"],
        "ceremony-refresh-v1"
    );
    assert_eq!(
        case["source_references"]["provenance_case_id"],
        "refresh_provenance_outer_v1"
    );
    assert_eq!(
        case["source_references"]["lifecycle_continuity_case_id"],
        "refresh_opposite_delta_continuity_v1"
    );
    let store = &case["authenticated_store_resolution"];
    assert!(
        store["signing_bytes_hex"]
            .as_str()
            .expect("store signing bytes")
            .len()
            > 512
    );
    assert_eq!(
        store["authority_verifying_key_hex"]
            .as_str()
            .expect("authority key")
            .len(),
        64
    );
    assert_eq!(
        store["authority_signature_hex"]
            .as_str()
            .expect("authority signature")
            .len(),
        128
    );
    assert_eq!(case["admission"]["current_deriver_a_input_state_epoch"], 41);
    assert_eq!(case["admission"]["next_deriver_a"]["input_state_epoch"], 42);
    assert_eq!(case["admission"]["current_deriver_b_input_state_epoch"], 51);
    assert_eq!(case["admission"]["next_deriver_b"]["input_state_epoch"], 53);
    assert_eq!(case["evaluation"]["yao_evaluations"], 1);
    assert_eq!(case["evaluation"]["refresh_delta_contributions"], 2);
    assert_eq!(case["evaluation"]["output_share_samples"], 2);
    assert_eq!(
        case["admission"]["digest_hex"],
        case["evaluation"]["output_committed_evaluation_evidence_digest_hex"]
    );
    assert_eq!(
        case["admission"]["registered_public_key_hex"],
        case["evaluation"]["registered_public_key_hex"]
    );
}

#[test]
fn vector_cli_emits_and_checks_exact_corpus() {
    let binary = env!("CARGO_BIN_EXE_ed25519-yao-vectors");
    let output = temporary_path("emit");
    let emit = Command::new(binary)
        .args([
            "emit-refresh-evaluator-admission",
            "--output",
            output.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run vector emitter");
    assert!(
        emit.status.success(),
        "{}",
        String::from_utf8_lossy(&emit.stderr)
    );
    assert_eq!(
        fs::read(&output).expect("emitted corpus"),
        canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1()
    );
    let check = Command::new(binary)
        .args([
            "check-refresh-evaluator-admission",
            "--input",
            output.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run vector checker");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    fs::remove_file(output).expect("remove emitted corpus");
}

#[test]
fn corpus_freezes_retry_nonclaims_and_forbidden_fields() {
    let canonical = canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1();
    let value: serde_json::Value = serde_json::from_slice(&canonical).expect("valid JSON");
    let case = &value["cases"][0];
    assert_eq!(
        case["admission"]["admission_state"],
        "accepted_terminal_registered_state_frozen"
    );
    assert_eq!(case["evaluation"]["terminal_admission_retained"], true);
    assert_eq!(
        case["evaluation"]["current_registered_state"],
        "unchanged_until_verified_promotion"
    );
    assert_eq!(
        case["retry"]["evaluator_abort_retains_authenticated_current_state"],
        true
    );
    assert_eq!(case["retry"]["evaluator_abort_burns_execution"], true);
    assert_eq!(case["retry"]["retry_requires_fresh_store_resolution"], true);
    let exclusions = case["claim_boundary"]["excluded_claims"]
        .as_array()
        .expect("excluded claims array");
    for required in [
        "opposite_delta_proof_validity",
        "input_opening_consistency",
        "durable_refresh_state_transition",
        "atomic_promotion",
        "profile_security",
        "production_constant_time",
    ] {
        assert!(exclusions.iter().any(|value| value == required));
    }
    let forbidden = [
        "security_profile",
        "proof_hex",
        "private_delta_hex",
        "private_root_hex",
        "seed_output_hex",
        "ciphertext_hex",
        "extension_bag",
        "retry_counter",
    ];
    let declared = case["claim_boundary"]["forbidden_fields"]
        .as_array()
        .expect("forbidden fields array");
    for key in &forbidden {
        assert!(declared.iter().any(|value| value == *key));
    }
    assert_forbidden_keys_absent(case, &forbidden);
}
