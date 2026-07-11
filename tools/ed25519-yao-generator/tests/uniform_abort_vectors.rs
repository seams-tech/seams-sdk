use ed25519_yao_generator::{
    canonical_uniform_abort_vector_corpus_json_bytes_v1, canonical_uniform_abort_vector_corpus_v1,
    parse_canonical_uniform_abort_vector_corpus_json_v1, UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1,
    UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::Value;

const COMMITTED: &[u8] = include_bytes!("../vectors/ed25519-yao-uniform-abort-envelope-v1.json");
const CEREMONY: &[u8] = include_bytes!("../vectors/ed25519-yao-ceremony-context-v1.json");

#[test]
fn committed_uniform_abort_corpus_is_exact_and_has_five_closed_cases() {
    assert_eq!(
        canonical_uniform_abort_vector_corpus_json_bytes_v1(),
        COMMITTED
    );
    let corpus = canonical_uniform_abort_vector_corpus_v1();
    assert_eq!(corpus.schema(), UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(corpus.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        corpus.evidence_scope(),
        UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 5);

    let document: Value = serde_json::from_slice(COMMITTED).expect("valid committed JSON");
    let expected = [
        ("registration", "ceremony-registration-v1"),
        ("activation", "ceremony-activation-v1"),
        ("recovery", "ceremony-recovery-v1"),
        ("refresh", "ceremony-refresh-v1"),
        ("export", "ceremony-export-v1"),
    ];
    for (case, (request_kind, source_case_id)) in document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .zip(expected)
    {
        assert_eq!(case["request_kind"], request_kind);
        assert_eq!(case["source_ceremony_case_id"], source_case_id);
        assert_eq!(case["envelope"]["request_kind"], request_kind);
        assert_eq!(case["envelope"]["public_failure_code"], "rejected");
        assert_eq!(case["envelope"]["terminal"], "aborted");
        assert_eq!(case["envelope"].as_object().expect("envelope").len(), 4);
    }
}

#[test]
fn every_abort_transcript_cross_links_the_named_ceremony_case() {
    let aborts: Value = serde_json::from_slice(COMMITTED).expect("valid abort corpus");
    let ceremonies: Value = serde_json::from_slice(CEREMONY).expect("valid ceremony corpus");
    for abort_case in aborts["cases"].as_array().expect("abort cases") {
        let source_id = abort_case["source_ceremony_case_id"]
            .as_str()
            .expect("source id");
        let ceremony_case = ceremonies["cases"]
            .as_array()
            .expect("ceremony cases")
            .iter()
            .find(|case| case["vector"]["case_id"] == source_id)
            .expect("named ceremony case");
        assert_eq!(
            abort_case["envelope"]["public_transcript_digest_hex"],
            ceremony_case["vector"]["expected"]["transcript_digest_sha256_hex"]
        );
    }
}

#[test]
fn abort_envelopes_exclude_private_or_blame_bearing_fields() {
    let encoded = std::str::from_utf8(COMMITTED).expect("UTF-8 corpus");
    for forbidden in [
        "request_context_digest",
        "authorization_digest",
        "deriver_role",
        "suspected_role",
        "private",
        "peer_frame",
        "package_plaintext",
        "contribution",
        "share_hex",
        "seed_hex",
        "scalar_hex",
        "label_hex",
        "mask_hex",
        "ot_",
    ] {
        assert!(!encoded.contains(forbidden), "forbidden field {forbidden}");
    }
}

#[test]
fn strict_parser_rejects_noncanonical_bytes() {
    assert!(parse_canonical_uniform_abort_vector_corpus_json_v1(COMMITTED).is_ok());
    let mut extra_lf = COMMITTED.to_vec();
    extra_lf.push(b'\n');
    assert!(parse_canonical_uniform_abort_vector_corpus_json_v1(&extra_lf).is_err());

    let mut changed = COMMITTED.to_vec();
    let offset = changed
        .windows(b"rejected".len())
        .position(|window| window == b"rejected")
        .expect("rejected code exists");
    changed[offset] = b'R';
    assert!(parse_canonical_uniform_abort_vector_corpus_json_v1(&changed).is_err());
}
