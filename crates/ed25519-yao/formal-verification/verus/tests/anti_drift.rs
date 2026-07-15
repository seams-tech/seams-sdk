use ed25519_yao as production;
use ed25519_yao_generator as generator;
use ed25519_yao_verus as mirror;

fn digest(marker: u8) -> [u8; 32] {
    [marker; 32]
}

#[test]
fn identifiers_and_manifest_domains_match_production() {
    assert_eq!(mirror::PROTOCOL_ID_STR, production::PROTOCOL_ID_STR);
    assert_eq!(
        mirror::ACTIVATION_CIRCUIT_ID_STR,
        production::ACTIVATION_CIRCUIT_ID_STR
    );
    assert_eq!(
        mirror::EXPORT_CIRCUIT_ID_STR,
        production::EXPORT_CIRCUIT_ID_STR
    );
    assert_eq!(
        mirror::ACTIVATION_OUTPUT_SCHEMA_ID_STR,
        production::ACTIVATION_OUTPUT_SCHEMA_ID_STR
    );
    assert_eq!(
        mirror::EXPORT_OUTPUT_SCHEMA_ID_STR,
        production::EXPORT_OUTPUT_SCHEMA_ID_STR
    );
    assert_eq!(
        mirror::DRAFT_MANIFEST_DIGEST_DOMAIN_V1,
        production::DRAFT_MANIFEST_DIGEST_DOMAIN_V1
    );
    assert_eq!(
        mirror::ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE,
        production::ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE
    );
    assert_eq!(
        mirror::EXPORT_DRAFT_MANIFEST_FAMILY_BYTE,
        production::EXPORT_DRAFT_MANIFEST_FAMILY_BYTE
    );
    assert_eq!(
        mirror::ACTIVATION_DRAFT_MANIFEST_PREIMAGE_BYTES,
        production::ACTIVATION_DRAFT_MANIFEST_PREIMAGE_BYTES
    );
    assert_eq!(
        mirror::EXPORT_DRAFT_MANIFEST_PREIMAGE_BYTES,
        production::EXPORT_DRAFT_MANIFEST_PREIMAGE_BYTES
    );
    assert_eq!(
        mirror::PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1,
        generator::provenance::PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1
    );
    assert_eq!(
        mirror::PROVENANCE_PAIR_ENCODING_DOMAIN_V1,
        generator::provenance::PROVENANCE_PAIR_ENCODING_DOMAIN_V1
    );
    assert_eq!(
        mirror::PROVENANCE_REGISTRATION_REQUEST_TAG_V1,
        generator::provenance::PROVENANCE_REGISTRATION_REQUEST_TAG_V1
    );
    assert_eq!(
        mirror::PROVENANCE_ACTIVATION_REQUEST_TAG_V1,
        generator::provenance::PROVENANCE_ACTIVATION_REQUEST_TAG_V1
    );
    assert_eq!(
        mirror::PROVENANCE_RECOVERY_REQUEST_TAG_V1,
        generator::provenance::PROVENANCE_RECOVERY_REQUEST_TAG_V1
    );
    assert_eq!(
        mirror::PROVENANCE_REFRESH_REQUEST_TAG_V1,
        generator::provenance::PROVENANCE_REFRESH_REQUEST_TAG_V1
    );
    assert_eq!(
        mirror::PROVENANCE_EXPORT_REQUEST_TAG_V1,
        generator::provenance::PROVENANCE_EXPORT_REQUEST_TAG_V1
    );
    assert_eq!(
        mirror::PROVENANCE_DERIVER_A_ROLE_TAG_V1,
        generator::provenance::PROVENANCE_DERIVER_A_ROLE_TAG_V1
    );
    assert_eq!(
        mirror::PROVENANCE_DERIVER_B_ROLE_TAG_V1,
        generator::provenance::PROVENANCE_DERIVER_B_ROLE_TAG_V1
    );
}

#[test]
fn clamp_reference_boundary_matches_generator() {
    let cases = [[0u8; 32], [0xffu8; 32], [0x5au8; 32], [0xa5u8; 32]];
    for input in cases {
        assert_eq!(
            mirror::clamp_rfc8032(input),
            generator::clamp_rfc8032(input)
        );
    }
}

#[test]
fn wrapping_add_reference_boundary_matches_generator() {
    let mut one = [0u8; 32];
    one[0] = 1;
    let cases = [
        ([0u8; 32], [0u8; 32]),
        ([0xffu8; 32], one),
        ([0x5au8; 32], [0xa5u8; 32]),
        ([0x81u8; 32], [0x42u8; 32]),
    ];
    for (left, right) in cases {
        assert_eq!(
            mirror::wrapping_add_le_256(left, right),
            generator::wrapping_add_le_256(left, right)
        );
    }
}

#[test]
fn manifest_digest_role_counts_match_production_constructors() {
    let digests = production::ActivationCircuitArtifactDigests::new(
        production::CircuitDigest32::new(digest(1)).expect("circuit digest"),
        production::CompilerDigest32::new(digest(2)).expect("compiler digest"),
        production::SourceIrDigest32::new(digest(3)).expect("source IR digest"),
        production::ScheduleDigest32::new(digest(4)).expect("schedule digest"),
        production::ConstantsDigest32::new(digest(5)).expect("constants digest"),
        production::InputSchemaDigest32::new(digest(6)).expect("input schema digest"),
    );
    let artifact_roles = [
        digests.circuit().into_bytes(),
        digests.compiler().into_bytes(),
        digests.source_ir().into_bytes(),
        digests.schedule().into_bytes(),
        digests.constants().into_bytes(),
        digests.input_schema().into_bytes(),
    ];
    let output_schema = production::ActivationOutputSchema::new(
        production::ActivationOutputSchemaDigest32::new(digest(7)).expect("output schema digest"),
    );

    assert_eq!(artifact_roles.len(), mirror::ARTIFACT_DIGEST_COUNT);
    assert_eq!(artifact_roles.len() + 1, mirror::MANIFEST_DIGEST_SLOT_COUNT);
    assert_eq!(output_schema.digest().into_bytes(), digest(7));
}

#[test]
fn metric_count_and_gate_relation_match_production_validation() {
    let gates = production::GateMetrics::new(10, 20, 2, 32, 5, 4).expect("valid gates");
    let schedule = production::ScheduleMetrics::new(8, 8, 64, 32, 24, 512).expect("valid schedule");
    let metrics =
        production::CircuitMetrics::new_passive_half_gates(gates, schedule).expect("valid metrics");
    let scalar_metrics = [
        metrics.gates().and_gate_count(),
        metrics.gates().xor_gate_count(),
        metrics.gates().inversion_gate_count(),
        metrics.gates().total_gate_count(),
        metrics.gates().circuit_depth(),
        metrics.gates().and_depth(),
        metrics.schedule().input_wire_count(),
        metrics.schedule().output_wire_count(),
        metrics.schedule().wire_count(),
        metrics.schedule().scheduled_gate_count(),
        metrics.schedule().peak_live_wire_count(),
        metrics.schedule().encoded_schedule_bytes(),
        metrics.table_payload_bytes(),
    ];

    assert_eq!(scalar_metrics.len(), mirror::MANIFEST_METRIC_COUNT);
    assert_eq!(
        production::PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE,
        mirror::PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE
    );
    assert_eq!(
        metrics.table_payload_bytes(),
        metrics.gates().and_gate_count() * production::PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE
    );
    assert!(production::ScheduleMetrics::new(8, 8, 8, 32, 8, 512).is_ok());
    assert_eq!(
        mirror::gate_total_is_consistent_runtime(10, 20, 2, 32),
        production::GateMetrics::new(10, 20, 2, 32, 5, 4).is_ok()
    );
    assert_eq!(
        mirror::gate_total_is_consistent_runtime(10, 20, 2, 33),
        production::GateMetrics::new(10, 20, 2, 33, 5, 4).is_ok()
    );
    assert_eq!(
        mirror::gate_total_is_consistent_runtime(u64::MAX, 1, 0, u64::MAX),
        production::GateMetrics::new(u64::MAX, 1, 0, u64::MAX, 1, 1).is_ok()
    );
}

#[test]
fn stable_context_and_vector_domains_match_the_frozen_baseline() {
    assert_eq!(
        generator::STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1,
        b"seams/router-ab/ed25519-yao/stable-key-context/v1"
    );
    assert_eq!(
        generator::STABLE_KEY_DERIVATION_CONTEXT_BINDING_DOMAIN_V1,
        b"seams/router-ab/ed25519-yao/stable-key-context-binding/v1"
    );
    let context =
        generator::StableKeyDerivationContext::new([0x42; 32], 2, 1).expect("golden context");
    assert_eq!(
        context.binding_digest().as_bytes(),
        &[
            0xce, 0x53, 0x05, 0x90, 0x8b, 0x0c, 0x31, 0xbf, 0xe0, 0x90, 0x72, 0xb5, 0x49, 0xcb,
            0x34, 0x9b, 0x0c, 0x90, 0x1f, 0x7d, 0x3f, 0xde, 0x60, 0xc6, 0x3f, 0xa8, 0xe2, 0xdf,
            0xb0, 0x88, 0xa4, 0x2d,
        ]
    );
    assert_eq!(
        generator::canonical_vector_corpus_v1().protocol_id,
        production::PROTOCOL_ID_STR
    );
}
