use ed25519_yao_generator::{
    canonical_evaluator_abort_view_vector_corpus_json_bytes_v1,
    canonical_evaluator_abort_view_vector_corpus_v1,
    parse_canonical_evaluator_abort_view_vector_corpus_json_v1,
    EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1, EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::Value;

const COMMITTED: &[u8] =
    include_bytes!("../vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json");

fn committed_json() -> Value {
    serde_json::from_slice(COMMITTED).expect("committed evaluator-abort corpus is JSON")
}

#[test]
fn committed_corpus_is_exact_and_has_four_evaluator_cases() {
    assert_eq!(
        COMMITTED,
        canonical_evaluator_abort_view_vector_corpus_json_bytes_v1()
    );
    let corpus = canonical_evaluator_abort_view_vector_corpus_v1();
    assert_eq!(
        corpus.schema(),
        EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(
        corpus.evidence_scope(),
        EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 4);
    let document = committed_json();
    let kinds = document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| case["request_kind"].as_str().expect("request kind"))
        .collect::<Vec<_>>();
    assert_eq!(kinds, ["registration", "recovery", "refresh", "export"]);
}

#[test]
fn every_persistence_transition_burns_once_and_is_a_state_self_loop() {
    for (index, case) in committed_json()["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .enumerate()
    {
        let kind = case["request_kind"].as_str().expect("request kind");
        let persistence = &case["persistence"];
        assert_eq!(persistence["transition"], "self_loop");
        assert_eq!(persistence["burned_attempt"]["request_kind"], kind);
        assert_eq!(persistence["public_abort"]["request_kind"], kind);
        assert_eq!(
            persistence["burned_attempt"]["transcript_digest_hex"],
            persistence["public_abort"]["public_transcript_digest_hex"]
        );
        assert_eq!(
            persistence["pre_state_class"],
            match index {
                0 => "unregistered",
                1 => "credential_suspended",
                _ => "registered",
            }
        );
        assert_ne!(
            persistence["burned_attempt"]["one_use_execution_id_hex"],
            "00".repeat(32)
        );
    }
}

#[test]
fn all_seven_role_views_are_exactly_the_public_abort() {
    for case in committed_json()["cases"].as_array().expect("cases") {
        let expected = &case["persistence"]["public_abort"];
        let views = case["party_views"].as_object().expect("party views");
        assert_eq!(views.len(), 7);
        for role in [
            "deriver_a",
            "deriver_b",
            "client",
            "signing_worker",
            "router",
            "observer",
            "diagnostics",
        ] {
            assert!(views.contains_key(role), "missing role `{role}`");
        }
        for view in views.values() {
            assert_eq!(view, expected);
        }
    }
}

#[test]
fn strict_parser_rejects_drift_and_views_exclude_private_outputs() {
    parse_canonical_evaluator_abort_view_vector_corpus_json_v1(COMMITTED)
        .expect("committed corpus parses");
    let mut changed = COMMITTED.to_vec();
    changed.push(b' ');
    assert!(parse_canonical_evaluator_abort_view_vector_corpus_json_v1(&changed).is_err());

    let encoded = String::from_utf8(COMMITTED.to_vec()).expect("UTF-8 corpus");
    for forbidden in [
        "seed_share",
        "scalar_share",
        "private_payload",
        "peer_frame",
        "semantic_failure",
        "deriver_blame",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "forbidden field `{forbidden}`"
        );
    }
}
