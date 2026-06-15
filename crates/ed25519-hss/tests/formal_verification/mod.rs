use ed25519_dalek::SigningKey;
use ed25519_hss::fixtures::{
    committed_fixture_corpus, serialized_fixture_corpus, FixtureCorpusFile,
    COMMITTED_FIXTURE_CORPUS_JSON,
};
use ed25519_hss::shared::{
    eval_f_expand, public_key_from_base_shares, public_key_from_scalar_bytes,
    recover_a_from_base_shares,
};

#[test]
fn fv_hss_fexp_001_generated_fixture_json_matches_committed_reference_file() {
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
fn fv_hss_fexp_001_committed_vectors_match_clear_spec() {
    for fixture in committed_fixture_corpus().expect("fixture corpus") {
        let output = eval_f_expand(&fixture.input).expect("reference path");
        assert_eq!(output, fixture.output, "fixture {}", fixture.name);

        let signing_key = SigningKey::from_bytes(&fixture.output.d);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            fixture.output.public_key,
            "fixture {}",
            fixture.name
        );
    }
}

#[test]
fn fv_hss_fexp_002_base_share_projection_recovers_signing_scalar() {
    for fixture in committed_fixture_corpus().expect("fixture corpus") {
        let recovered_a =
            recover_a_from_base_shares(fixture.output.x_client_base, fixture.output.x_server_base)
                .expect("recover a from base shares");
        assert_eq!(recovered_a, fixture.output.a, "fixture {}", fixture.name);
    }
}

#[test]
fn fv_hss_fexp_003_public_key_projection_matches_scalar_projection() {
    for fixture in committed_fixture_corpus().expect("fixture corpus") {
        let public_key =
            public_key_from_scalar_bytes(fixture.output.a).expect("public key from scalar");
        assert_eq!(
            public_key, fixture.output.public_key,
            "fixture {}",
            fixture.name
        );

        let public_key_from_outputs =
            public_key_from_base_shares(fixture.output.x_client_base, fixture.output.x_server_base)
                .expect("public key from base shares");
        assert_eq!(
            public_key_from_outputs, fixture.output.public_key,
            "fixture {}",
            fixture.name
        );
    }
}
