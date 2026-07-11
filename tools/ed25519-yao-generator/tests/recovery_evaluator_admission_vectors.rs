use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::{
    canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_recovery_evaluator_admission_vector_corpus_v1,
    parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1,
    RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
    RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1,
};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/ed25519-yao-recovery-evaluator-admission-v1.json")
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock follows Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ed25519-yao-recovery-evaluator-{label}-{}-{nonce}.json",
        std::process::id()
    ))
}

#[test]
fn canonical_corpus_has_one_narrow_recovery_case() {
    let corpus = canonical_recovery_evaluator_admission_vector_corpus_v1();
    assert_eq!(
        corpus.schema(),
        RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(corpus.protocol_id(), ed25519_yao::PROTOCOL_ID_STR);
    assert_eq!(
        corpus.evidence_scope(),
        RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 1);
}

#[test]
fn committed_corpus_equals_exact_canonical_bytes_and_rejects_drift() {
    let committed = fs::read(corpus_path()).expect("committed corpus");
    let canonical = canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1();
    assert_eq!(committed, canonical);
    parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1(&committed)
        .expect("canonical corpus parses");
    let mut mutated = canonical.clone();
    let index = mutated
        .iter()
        .position(|byte| *byte == b'a')
        .expect("canonical corpus contains ASCII a");
    mutated[index] = b'b';
    assert!(parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1(&mutated).is_err());
    let mut trailing = canonical;
    trailing.push(b'\n');
    assert!(parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1(&trailing).is_err());
}

#[test]
fn corpus_commits_store_admission_output_and_cross_links() {
    let encoded = fs::read(corpus_path()).expect("committed corpus");
    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("valid JSON");
    let case = &value["cases"][0];
    assert_eq!(
        case["case_id"],
        "recovery_admitted_evaluation_output_committed_v1"
    );
    assert_eq!(case["request_kind"], "recovery");
    assert_eq!(
        case["source_references"]["ceremony_context_case_id"],
        "ceremony-recovery-v1"
    );
    assert_eq!(
        case["source_references"]["recovery_credential_transition_case_id"],
        "recovery_credential_suspension_promotion_v1"
    );
    assert_eq!(case["authenticated_store_resolution"]["active_state_version"], 9);
    assert_eq!(
        case["authenticated_store_resolution"]["authority_verifying_key_hex"]
            .as_str()
            .expect("authority key")
            .len(),
        64
    );
    assert_eq!(
        case["authenticated_store_resolution"]["authority_signature_hex"]
            .as_str()
            .expect("authority signature")
            .len(),
        128
    );
    assert_eq!(case["evaluation"]["yao_evaluations"], 1);
    assert_eq!(case["evaluation"]["contribution_derivations"], 4);
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
            "emit-recovery-evaluator-admission",
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
        canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1()
    );
    let check = Command::new(binary)
        .args([
            "check-recovery-evaluator-admission",
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
fn corpus_freezes_suspension_retry_and_explicit_nonclaims() {
    let canonical = canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1();
    let value: serde_json::Value = serde_json::from_slice(&canonical).expect("valid JSON");
    let case = &value["cases"][0];
    assert_eq!(
        case["admission"]["admission_state"],
        "accepted_terminal_credential_suspended"
    );
    assert_eq!(case["evaluation"]["terminal_admission_retained"], true);
    assert_eq!(case["evaluation"]["old_credential_state"], "suspended");
    assert_eq!(
        case["retry"]["evaluator_abort_retains_credential_suspension"],
        true
    );
    assert_eq!(case["retry"]["evaluator_abort_burns_execution"], true);
    let exclusions = case["claim_boundary"]["excluded_claims"]
        .as_array()
        .expect("excluded claims array");
    for required in [
        "same_root_proof_validity",
        "input_opening_consistency",
        "durable_suspension",
        "atomic_promotion",
        "profile_security",
        "production_constant_time",
    ] {
        assert!(exclusions.iter().any(|value| value == required));
    }
    for forbidden in [
        "proof_hex",
        "security_profile",
        "seed_output_hex",
        "private_root_hex",
    ] {
        assert!(!case
            .as_object()
            .expect("case object")
            .contains_key(forbidden));
    }
}
