use ecdsa_hss::fixtures::{
    committed_fixture_corpus, serialized_fixture_corpus, FixtureCorpusFile,
    COMMITTED_FIXTURE_CORPUS_JSON,
};
use ecdsa_hss::{
    derive_additive_shares_v1, derive_canonical_secret_v1, encode_context_v1, RootShareInputsV1,
};

#[test]
fn generated_fixture_json_matches_committed_reference_file() {
    let generated_json =
        serde_json::to_string_pretty(&serialized_fixture_corpus().expect("fixture corpus"))
            .expect("generated fixture corpus json");
    let committed_json = serde_json::to_string_pretty(
        &serde_json::from_str::<FixtureCorpusFile>(COMMITTED_FIXTURE_CORPUS_JSON)
            .expect("parse committed fixture corpus"),
    )
    .expect("normalize committed fixture corpus json");

    assert_eq!(generated_json, committed_json);
}

#[test]
fn committed_vectors_match_reference_derivation() {
    for fixture in committed_fixture_corpus().expect("fixture corpus") {
        let context_bytes = encode_context_v1(&fixture.context).expect("encode context");
        assert_eq!(
            context_bytes, fixture.canonical.context_bytes,
            "fixture {}",
            fixture.name
        );

        let canonical = derive_canonical_secret_v1(
            &RootShareInputsV1::new(fixture.y_client32_le, fixture.y_relayer32_le),
            &fixture.context,
        )
        .expect("canonical derivation");
        assert_eq!(canonical, fixture.canonical, "fixture {}", fixture.name);

        let additive =
            derive_additive_shares_v1(&fixture.canonical.x32, &fixture.context).expect("shares");
        assert_eq!(
            additive, fixture.additive_shares,
            "fixture {}",
            fixture.name
        );
    }
}
