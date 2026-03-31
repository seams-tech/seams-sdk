use ed25519_hss::{
    build_fixed_hidden_core_candidate, build_fixed_hidden_core_candidate_for_backend,
    committed_fixture_corpus, deterministic_fixture_corpus, serialized_fixture_corpus,
    simulate_fixed_hidden_core_candidate, ArtifactScope, CandidateBackendFamily, FixtureCorpusFile,
    COMMITTED_FIXTURE_CORPUS_JSON,
};

use crate::support::first_fixture;

#[test]
fn fixture_corpus_round_trips_through_json() {
    let generated = deterministic_fixture_corpus().expect("fixture corpus");
    let json = serde_json::to_string_pretty(&serialized_fixture_corpus().expect("fixture corpus"))
        .expect("fixture corpus json");
    let parsed: FixtureCorpusFile = serde_json::from_str(&json).expect("parse fixture corpus json");

    assert_eq!(
        parsed.to_internal().expect("round-trip fixture corpus"),
        generated
    );
}

#[test]
fn committed_fixture_file_matches_generated_reference() {
    let _generated_json =
        serde_json::to_string_pretty(&serialized_fixture_corpus().expect("fixture corpus"))
            .expect("generated fixture corpus json");
    let _committed_json = serde_json::from_str::<FixtureCorpusFile>(COMMITTED_FIXTURE_CORPUS_JSON)
        .expect("parse committed fixture corpus");
    assert_eq!(
        committed_fixture_corpus().expect("committed fixtures"),
        deterministic_fixture_corpus().expect("generated fixtures"),
    );
}

#[test]
fn candidate_template_is_context_bound_and_fixed_function_only() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");

    assert!(candidate.template.context_bound);
    assert!(candidate.template.fixed_function_only);
    assert!(candidate.template.cross_session_reusable);
    assert_eq!(
        candidate.backend.family,
        CandidateBackendFamily::PrimeOrderSizeOptimized
    );
    assert_eq!(candidate.context_descriptor.org_id, "org.wraparound");
    assert_eq!(
        candidate.context_descriptor.account_id,
        "wraparound.test.near"
    );
    assert_eq!(candidate.context_descriptor.participant_ids, vec![1, 2]);
    assert_eq!(
        candidate
            .artifact_inventory
            .totals
            .known_client_output_bytes,
        32
    );
    assert_eq!(
        candidate
            .artifact_inventory
            .totals
            .known_server_output_bytes,
        32
    );
    assert_eq!(
        candidate
            .artifact_inventory
            .totals
            .known_public_output_bytes,
        32
    );
    assert_eq!(
        candidate
            .artifact_inventory
            .line_items
            .iter()
            .filter(|item| item.scope == ArtifactScope::CrossSessionTemplate)
            .count(),
        4
    );
    assert_eq!(candidate.backend.public_data_bytes, 138_256);
    assert_eq!(
        candidate
            .artifact_inventory
            .totals
            .unknown_encoded_payload_item_count,
        0
    );
}

#[test]
fn candidate_simulation_matches_fixture_corpus() {
    for fixture in deterministic_fixture_corpus().expect("fixture corpus") {
        let simulation =
            simulate_fixed_hidden_core_candidate(&fixture.input).expect("candidate simulate");
        assert_eq!(simulation.output, fixture.output);
        assert_ne!(simulation.client_input_commitment, [0u8; 32]);
        assert_ne!(simulation.server_input_commitment, [0u8; 32]);
        assert_ne!(simulation.run_binding, [0u8; 32]);
    }
}

#[test]
fn candidate_report_serializes_to_json() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let json = serde_json::to_string_pretty(&candidate).expect("candidate json");

    assert!(json.contains("fixed_hidden_core_candidate_v0"));
    assert!(json.contains("succinct_hidden_core_encoding"));
    assert!(json.contains("prime_order_size_optimized"));
}

#[test]
fn backend_variants_have_distinct_estimated_sizes() {
    let fixture = first_fixture();

    let prime_size = build_fixed_hidden_core_candidate_for_backend(
        &fixture.input.context,
        CandidateBackendFamily::PrimeOrderSizeOptimized,
    )
    .expect("prime-order size-optimized");
    let prime_compute = build_fixed_hidden_core_candidate_for_backend(
        &fixture.input.context,
        CandidateBackendFamily::PrimeOrderComputeOptimized,
    )
    .expect("prime-order compute-optimized");

    assert_eq!(prime_size.backend.public_data_bytes, 138_256);
    assert_eq!(prime_compute.backend.public_data_bytes, 5_320_016);
    assert!(prime_size.backend.public_data_bytes < prime_compute.backend.public_data_bytes);
}
