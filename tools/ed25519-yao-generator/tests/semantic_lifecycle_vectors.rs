use std::collections::BTreeSet;

use ed25519_yao_generator::{
    canonical_semantic_lifecycle_vector_corpus_json_bytes_v1,
    parse_canonical_semantic_lifecycle_vector_corpus_json_v1,
    SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1, SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const COMMITTED_CORPUS: &[u8] = include_bytes!("../vectors/ed25519-yao-semantic-lifecycle-v1.json");
const KDF_CORPUS: &[u8] = include_bytes!("../vectors/ed25519-yao-kdf-v1.json");

fn parsed_corpus() -> Value {
    serde_json::from_slice(COMMITTED_CORPUS).expect("committed semantic lifecycle JSON parses")
}

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("expected JSON object")
}

fn array(value: &Value) -> &[Value] {
    value.as_array().expect("expected JSON array")
}

fn string(value: &Value) -> &str {
    value.as_str().expect("expected JSON string")
}

fn field_string<'a>(value: &'a Value, field: &str) -> &'a str {
    string(&object(value)[field])
}

fn cases(corpus: &Value) -> &[Value] {
    array(&object(corpus)["cases"])
}

fn case_for_kind<'a>(corpus: &'a Value, request_kind: &str) -> &'a Value {
    cases(corpus)
        .iter()
        .find(|case| field_string(case, "request_kind") == request_kind)
        .expect("request-kind case exists")
}

fn vector(case: &Value) -> &Value {
    &object(case)["vector"]
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex length must be even");
    (0..encoded.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("canonical lowercase hex")
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn domain_separated_digest_hex(domain: &[u8], encoding: &[u8]) -> String {
    let mut preimage = lp32(domain);
    preimage.extend_from_slice(&lp32(encoding));
    sha256_hex(&preimage)
}

fn assert_digest_pair(value: &Value, encoding_field: &str, digest_field: &str) {
    let encoding = decode_hex(field_string(value, encoding_field));
    assert_eq!(field_string(value, digest_field), sha256_hex(&encoding));
}

fn lp32(bytes: &[u8]) -> Vec<u8> {
    let length = u32::try_from(bytes.len()).expect("fixture fits LP32");
    let mut encoded = Vec::with_capacity(4 + bytes.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

fn sorted_keys(value: &Value) -> Vec<&str> {
    object(value).keys().map(String::as_str).collect()
}

fn assert_package_set_encoding(request_kind: &str, packages: &Value) {
    let (encoding_domain, digest_domain, descriptor_fields): (&[u8], &[u8], &[&str]) =
        match request_kind {
            "registration" | "recovery" | "refresh" => (
                b"seams/router-ab/ed25519-yao/semantic-package-set/activation/v1",
                b"seams/router-ab/ed25519-yao/semantic-package-set/activation-digest/v1",
                &[
                    "deriver_a_client_descriptor_encoding_hex",
                    "deriver_b_client_descriptor_encoding_hex",
                    "deriver_a_signing_worker_descriptor_encoding_hex",
                    "deriver_b_signing_worker_descriptor_encoding_hex",
                ],
            ),
            "export" => (
                b"seams/router-ab/ed25519-yao/semantic-package-set/export/v1",
                b"seams/router-ab/ed25519-yao/semantic-package-set/export-digest/v1",
                &[
                    "deriver_a_client_descriptor_encoding_hex",
                    "deriver_b_client_descriptor_encoding_hex",
                ],
            ),
            _ => panic!("unsupported artifact branch"),
        };

    let mut expected = lp32(encoding_domain);
    for field in descriptor_fields {
        expected.extend_from_slice(&lp32(&decode_hex(field_string(packages, field))));
    }
    let package_set = decode_hex(field_string(packages, "package_set_encoding_hex"));
    assert_eq!(package_set, expected, "{request_kind} package set");
    assert_eq!(
        field_string(packages, "package_set_digest_sha256_hex"),
        domain_separated_digest_hex(digest_domain, &package_set)
    );
}

fn assert_receipt_digest(request_kind: &str, receipt: &Value) {
    let digest_domain: &[u8] = match request_kind {
        "registration" | "recovery" | "refresh" => {
            b"seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed-digest/v1"
        }
        "export" => b"seams/router-ab/ed25519-yao/semantic-receipt/export-released-digest/v1",
        _ => panic!("unsupported receipt branch"),
    };
    let encoding = decode_hex(field_string(receipt, "receipt_body_encoding_hex"));
    assert_eq!(
        field_string(receipt, "receipt_body_digest_sha256_hex"),
        domain_separated_digest_hex(digest_domain, &encoding)
    );
}

fn output_committed_identity(case: &Value) -> &Value {
    let persistence = &object(vector(case))["persistence"];
    assert_eq!(field_string(persistence, "state"), "output_committed");
    &object(&object(persistence)["projection"])["identity"]
}

fn assert_no_forbidden_keys(value: &Value) {
    const FORBIDDEN: &[&str] = &[
        "synthetic_roots",
        "client_root_hex",
        "deriver_a_root_hex",
        "deriver_b_root_hex",
        "contributions",
        "synthetic_clear_reference_trace",
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_a_hex",
        "tau_b_hex",
        "tau_hex",
        "x_client_base_hex",
        "x_server_base_hex",
        "output_coin_hex",
        "scalar_share_hex",
        "seed_share_hex",
        "ciphertext_bytes_hex",
        "refresh_delta_hex",
        "delta_y_hex",
        "delta_tau_hex",
    ];

    match value {
        Value::Array(values) => {
            for value in values {
                assert_no_forbidden_keys(value);
            }
        }
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(!FORBIDDEN.contains(&key.as_str()), "forbidden key: {key}");
                assert_no_forbidden_keys(value);
            }
        }
        _ => {}
    }
}

#[test]
fn semantic_lifecycle_corpus_matches_committed_exact_bytes_and_strict_parser() {
    let generated = canonical_semantic_lifecycle_vector_corpus_json_bytes_v1();
    assert_eq!(generated, COMMITTED_CORPUS);
    assert!(COMMITTED_CORPUS.ends_with(b"\n"));
    assert!(!COMMITTED_CORPUS[..COMMITTED_CORPUS.len() - 1].contains(&b'\r'));

    let parsed = parse_canonical_semantic_lifecycle_vector_corpus_json_v1(COMMITTED_CORPUS)
        .expect("committed corpus is canonical");
    assert_eq!(parsed.schema(), SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(parsed.protocol_id(), ed25519_yao::PROTOCOL_ID_STR);
    assert_eq!(
        parsed.evidence_scope(),
        SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.case_count(), 5);

    let without_lf = &COMMITTED_CORPUS[..COMMITTED_CORPUS.len() - 1];
    assert!(parse_canonical_semantic_lifecycle_vector_corpus_json_v1(without_lf).is_err());

    let mut crlf = without_lf.to_vec();
    crlf.extend_from_slice(b"\r\n");
    assert!(parse_canonical_semantic_lifecycle_vector_corpus_json_v1(&crlf).is_err());

    let mut appended = COMMITTED_CORPUS.to_vec();
    appended.push(b' ');
    assert!(parse_canonical_semantic_lifecycle_vector_corpus_json_v1(&appended).is_err());

    let mut mutated = COMMITTED_CORPUS.to_vec();
    mutated[0] = b'[';
    assert!(parse_canonical_semantic_lifecycle_vector_corpus_json_v1(&mutated).is_err());
}

#[test]
fn corpus_has_five_fixed_branch_shapes_and_no_runtime_profile_negotiation() {
    let corpus = parsed_corpus();
    assert_eq!(
        field_string(&corpus, "schema"),
        SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(
        field_string(&corpus, "protocol_id"),
        ed25519_yao::PROTOCOL_ID_STR
    );
    assert_eq!(
        field_string(&corpus, "evidence_scope"),
        SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1
    );

    let actual_kinds: Vec<_> = cases(&corpus)
        .iter()
        .map(|case| field_string(case, "request_kind"))
        .collect();
    assert_eq!(
        actual_kinds,
        [
            "registration",
            "activation",
            "recovery",
            "refresh",
            "export"
        ]
    );

    let expected_ids = [
        (
            "registration",
            "registration_semantic_artifacts_output_committed_v1",
        ),
        ("activation", "activation_metadata_control_v1"),
        (
            "recovery",
            "recovery_semantic_artifacts_output_committed_v1",
        ),
        ("refresh", "refresh_semantic_artifacts_output_committed_v1"),
        (
            "export",
            "export_semantic_artifacts_host_reference_receipt_v1",
        ),
    ];
    for (kind, case_id) in expected_ids {
        assert_eq!(
            field_string(vector(case_for_kind(&corpus, kind)), "case_id"),
            case_id
        );
    }

    let activation = vector(case_for_kind(&corpus, "activation"));
    assert_eq!(array(&object(activation)["metadata_consumed"]).len(), 3);
    assert_eq!(array(&object(activation)["rejected_attempts"]).len(), 4);
    let export = vector(case_for_kind(&corpus, "export"));
    assert_eq!(
        field_string(export, "state_effect"),
        "registered_state_retained"
    );

    let serialized = String::from_utf8(COMMITTED_CORPUS.to_vec()).expect("JSON is UTF-8");
    assert!(!serialized.contains("security_profile"));
    assert!(!serialized.contains("profile_negotiation"));
}

#[test]
fn public_encodings_digests_and_package_sets_are_independently_reconstructible() {
    let corpus = parsed_corpus();
    for request_kind in ["registration", "recovery", "refresh", "export"] {
        let artifact = vector(case_for_kind(&corpus, request_kind));
        let ceremony = &object(artifact)["ceremony"];
        assert_digest_pair(
            ceremony,
            "public_request_context_encoding_hex",
            "public_request_context_digest_sha256_hex",
        );
        assert_digest_pair(
            ceremony,
            "authorization_encoding_hex",
            "authorization_digest_sha256_hex",
        );
        assert_digest_pair(
            ceremony,
            "transcript_encoding_hex",
            "transcript_digest_sha256_hex",
        );

        let packages = &object(artifact)["packages"];
        assert_package_set_encoding(request_kind, packages);
        let receipt = &object(artifact)["receipt"];
        assert_receipt_digest(request_kind, receipt);
    }
}

#[test]
fn output_committed_projections_cross_link_every_activation_artifact() {
    let corpus = parsed_corpus();
    let mut registered_public_keys = BTreeSet::new();

    for request_kind in ["registration", "recovery", "refresh"] {
        let case = case_for_kind(&corpus, request_kind);
        let artifact = vector(case);
        let ceremony = &object(artifact)["ceremony"];
        let packages = &object(artifact)["packages"];
        let receipt = &object(artifact)["receipt"];
        let identity = output_committed_identity(case);

        assert_eq!(field_string(identity, "origin_kind"), request_kind);
        assert_eq!(field_string(identity, "origin_request_kind"), request_kind);
        assert_eq!(
            field_string(identity, "origin_request_context_digest_hex"),
            field_string(ceremony, "public_request_context_digest_sha256_hex")
        );
        assert_eq!(
            field_string(identity, "origin_authorization_digest_hex"),
            field_string(ceremony, "authorization_digest_sha256_hex")
        );
        assert_eq!(
            field_string(identity, "origin_transcript_digest_hex"),
            field_string(ceremony, "transcript_digest_sha256_hex")
        );
        assert_eq!(
            field_string(identity, "package_set_digest_hex"),
            field_string(packages, "package_set_digest_sha256_hex")
        );
        assert_eq!(
            field_string(identity, "receipt_digest_hex"),
            field_string(receipt, "receipt_body_digest_sha256_hex")
        );
        registered_public_keys.insert(field_string(identity, "registered_public_key_hex"));
    }

    assert_eq!(registered_public_keys.len(), 1);
    let kdf: Value = serde_json::from_slice(KDF_CORPUS).expect("committed KDF corpus parses");
    let expected_public_key = field_string(
        &object(&cases(&kdf)[0])["synthetic_clear_reference_trace"],
        "public_key_hex",
    );
    assert_eq!(
        registered_public_keys.first().copied(),
        Some(expected_public_key)
    );
    let export_authorization = field_string(
        &object(vector(case_for_kind(&corpus, "export")))["ceremony"],
        "authorization_encoding_hex",
    );
    assert!(export_authorization.contains(registered_public_keys.first().unwrap()));
}

#[test]
fn activation_consumes_metadata_for_all_origins_without_reevaluation() {
    let corpus = parsed_corpus();
    let activation = vector(case_for_kind(&corpus, "activation"));
    let consumed = array(&object(activation)["metadata_consumed"]);
    let expected = [
        (
            "registration",
            "registration_semantic_artifacts_output_committed_v1",
        ),
        (
            "recovery",
            "recovery_semantic_artifacts_output_committed_v1",
        ),
        ("refresh", "refresh_semantic_artifacts_output_committed_v1"),
    ];

    for (entry, (origin_kind, origin_case_id)) in consumed.iter().zip(expected) {
        assert_eq!(field_string(entry, "origin_kind"), origin_kind);
        assert_eq!(field_string(entry, "origin_case_id"), origin_case_id);

        let persistence = &object(entry)["persistence"];
        assert_eq!(field_string(persistence, "state"), "metadata_consumed");
        let projection = &object(persistence)["projection"];
        let committed_identity = &object(&object(projection)["committed"])["identity"];
        assert_eq!(
            committed_identity,
            output_committed_identity(case_for_kind(&corpus, origin_kind))
        );

        let ceremony = &object(entry)["activation_ceremony"];
        assert_eq!(
            field_string(projection, "activation_request_context_digest_hex"),
            field_string(ceremony, "public_request_context_digest_sha256_hex")
        );
        assert_eq!(
            field_string(projection, "activation_authorization_digest_hex"),
            field_string(ceremony, "authorization_digest_sha256_hex")
        );
        assert_eq!(
            field_string(projection, "activation_transcript_digest_hex"),
            field_string(ceremony, "transcript_digest_sha256_hex")
        );

        let zero = object(&object(entry)["zero_reevaluation"]);
        assert_eq!(
            zero.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "contribution_derivations",
                "deriver_a_invocations",
                "deriver_b_invocations",
                "output_share_samples",
                "yao_evaluations",
            ]
        );
        assert!(zero.values().all(|value| value.as_u64() == Some(0)));
    }
}

#[test]
fn every_freshness_rejection_is_uniform_and_preserves_output_committed_state() {
    let corpus = parsed_corpus();
    let activation = vector(case_for_kind(&corpus, "activation"));
    let rejected = array(&object(activation)["rejected_attempts"]);
    let expected_committed = output_committed_identity(case_for_kind(&corpus, "registration"));
    let expected = [
        ("request_id", "request-registration-001", "f1", 30_001, "f2"),
        ("replay_nonce", "activation-new", "11", 30_002, "f3"),
        ("transcript_nonce", "activation-new", "f4", 30_003, "61"),
        (
            "origin_context_and_transcript",
            "request-registration-001",
            "11",
            2_000_001,
            "61",
        ),
    ];

    for (attempt, (class, request_id, replay, expiry, transcript)) in rejected.iter().zip(expected)
    {
        assert_eq!(field_string(attempt, "fixture_class"), class);
        let fresh = &object(attempt)["fresh_fields"];
        assert_eq!(
            sorted_keys(fresh),
            [
                "artifact_suite_digest_hex",
                "authorization_record_digest_hex",
                "replay_nonce_hex",
                "request_expiry",
                "request_id",
                "transcript_nonce_hex",
                "transport_binding_digest_hex",
            ]
        );
        assert_eq!(field_string(fresh, "request_id"), request_id);
        assert_eq!(field_string(fresh, "replay_nonce_hex"), replay.repeat(32));
        assert_eq!(object(fresh)["request_expiry"].as_u64(), Some(expiry));
        assert_eq!(
            field_string(fresh, "transcript_nonce_hex"),
            transcript.repeat(32)
        );
        assert_eq!(
            field_string(fresh, "authorization_record_digest_hex"),
            "b1".repeat(32)
        );
        assert_eq!(
            field_string(fresh, "transport_binding_digest_hex"),
            "b2".repeat(32)
        );
        assert_eq!(
            field_string(fresh, "artifact_suite_digest_hex"),
            "b3".repeat(32)
        );

        let persistence = &object(attempt)["persistence"];
        assert_eq!(field_string(persistence, "state"), "attempt_rejected");
        let projection = &object(persistence)["projection"];
        assert_eq!(
            &object(&object(projection)["before"])["identity"],
            expected_committed
        );
        assert_eq!(
            &object(&object(projection)["after"])["identity"],
            expected_committed
        );
        let abort = &object(projection)["abort"];
        assert_eq!(
            sorted_keys(abort),
            [
                "public_failure_code",
                "public_transcript_digest_hex",
                "request_kind",
                "terminal",
            ]
        );
        assert_eq!(field_string(abort, "request_kind"), "activation");
        assert_eq!(field_string(abort, "public_failure_code"), "rejected");
        assert_eq!(field_string(abort, "terminal"), "aborted");
    }
}

#[test]
fn semantic_lifecycle_corpus_excludes_secret_bearing_fields_and_known_secret_values() {
    let corpus = parsed_corpus();
    assert_no_forbidden_keys(&corpus);

    let kdf: Value = serde_json::from_slice(KDF_CORPUS).expect("committed KDF corpus parses");
    let kdf_case = &cases(&kdf)[0];
    let contributions = object(&object(kdf_case)["contributions"]);
    let semantic_text = String::from_utf8(COMMITTED_CORPUS.to_vec()).expect("JSON is UTF-8");

    for secret in contributions.values().map(string) {
        assert!(
            !semantic_text.contains(secret),
            "raw KDF contribution escaped"
        );
    }
    for field in [
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_a_hex",
        "tau_b_hex",
        "tau_hex",
        "x_client_base_hex",
        "x_server_base_hex",
    ] {
        assert!(
            !semantic_text.contains(field_string(
                &object(kdf_case)["synthetic_clear_reference_trace"],
                field
            )),
            "clear reference secret escaped: {field}"
        );
    }
}
