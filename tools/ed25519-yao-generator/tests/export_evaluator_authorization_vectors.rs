use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::{
    canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1,
    canonical_export_evaluator_authorization_vector_corpus_v1,
    parse_canonical_export_evaluator_authorization_vector_corpus_json_v1,
    EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1,
    EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1,
};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/ed25519-yao-export-evaluator-authorization-v1.json")
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock follows Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ed25519-yao-export-evaluator-{label}-{}-{nonce}.json",
        std::process::id()
    ))
}

#[test]
fn canonical_corpus_has_one_narrow_export_case() {
    let corpus = canonical_export_evaluator_authorization_vector_corpus_v1();
    assert_eq!(
        corpus.schema(),
        EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(corpus.protocol_id(), ed25519_yao::PROTOCOL_ID_STR);
    assert_eq!(
        corpus.evidence_scope(),
        EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 1);
}

#[test]
fn committed_corpus_equals_exact_canonical_bytes() {
    let committed = fs::read(corpus_path()).expect("committed corpus");
    assert_eq!(
        committed,
        canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1()
    );
    parse_canonical_export_evaluator_authorization_vector_corpus_json_v1(&committed)
        .expect("canonical corpus parses");
}

#[test]
fn strict_parser_rejects_mutation_and_trailing_bytes() {
    let canonical = canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1();
    let mut mutated = canonical.clone();
    let index = mutated
        .iter()
        .position(|byte| *byte == b'a')
        .expect("canonical corpus contains ASCII a");
    mutated[index] = b'b';
    assert!(
        parse_canonical_export_evaluator_authorization_vector_corpus_json_v1(&mutated).is_err()
    );

    let mut trailing = canonical;
    trailing.push(b'\n');
    assert!(
        parse_canonical_export_evaluator_authorization_vector_corpus_json_v1(&trailing).is_err()
    );
}

#[test]
fn corpus_commits_distinct_signed_roles_and_consumed_release() {
    let encoded = fs::read(corpus_path()).expect("committed corpus");
    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("valid JSON");
    let case = &value["cases"][0];
    assert_eq!(case["request_kind"], "export");
    assert_eq!(case["authorities"]["deriver_a"]["role"], "deriver_a");
    assert_eq!(case["authorities"]["deriver_b"]["role"], "deriver_b");
    assert_ne!(
        case["authorities"]["deriver_a"]["key_digest_hex"],
        case["authorities"]["deriver_b"]["key_digest_hex"]
    );
    assert_ne!(
        case["acceptances"]["deriver_a"]["signature_hex"],
        case["acceptances"]["deriver_b"]["signature_hex"]
    );
    assert_eq!(
        case["evaluation"]["output_committed_authorization_state"],
        "unconsumed"
    );
    assert_eq!(
        case["evaluation"]["released_authorization_state"],
        "consumed"
    );
    assert_eq!(
        case["accepted_pair"]["digest_hex"],
        case["evaluation"]["released_evaluation_evidence_digest_hex"]
    );
}

#[test]
fn vector_cli_emits_and_checks_exact_corpus() {
    let binary = env!("CARGO_BIN_EXE_ed25519-yao-vectors");
    let output = temporary_path("emit");
    let emit = Command::new(binary)
        .args([
            "emit-export-evaluator-authorization",
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
        canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1()
    );
    let check = Command::new(binary)
        .args([
            "check-export-evaluator-authorization",
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
