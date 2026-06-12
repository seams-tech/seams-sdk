use router_ab_core::{
    context_digest_v1, parse_vector_fixture_v1, transcript_digest_v1, vector_case_context_v1,
    vector_case_transcript_v1, DerivationVectorFixtureV1, RouterAbDerivationErrorCode,
};

const FIXTURE_JSON: &str =
    include_str!("../fixtures/derivation/split-derivation-candidates-v1.json");

#[test]
fn parses_committed_vector_fixture_shape() {
    let fixture = parse_vector_fixture_v1(FIXTURE_JSON).expect("fixture should parse");

    assert_eq!(
        fixture.vector_version,
        "router_ab_split_derivation_candidates_v1"
    );
    assert_eq!(fixture.cases.len(), 2);
    for case in &fixture.cases {
        let context = vector_case_context_v1(case).expect("context");
        let transcript = vector_case_transcript_v1(context.clone()).expect("transcript");
        assert_eq!(
            case.expected_context_digest_hex,
            hex::encode(context_digest_v1(&context).expect("context digest").bytes)
        );
        assert_eq!(
            case.expected_transcript_digest_hex,
            hex::encode(
                transcript_digest_v1(&transcript)
                    .expect("transcript digest")
                    .bytes
            )
        );
    }
}

#[test]
fn rejects_unsupported_vector_version() {
    let fixture = DerivationVectorFixtureV1 {
        vector_version: "unknown".to_owned(),
        cases: Vec::new(),
    };

    let err = router_ab_core::validate_vector_fixture_v1(&fixture)
        .expect_err("unsupported version should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::UnsupportedVectorVersion
    );
}
