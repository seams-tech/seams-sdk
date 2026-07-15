use ed25519_yao::{
    ActivationCircuitArtifactDigests, ActivationOutputSchema, ActivationOutputSchemaDigest32,
    CircuitDigest32, CircuitFamily, CircuitMetrics, CompilerDigest32, ConstantsDigest32,
    DraftActivationCircuitManifest, DraftExportCircuitManifest, DraftProtocolManifest,
    ExportCircuitArtifactDigests, ExportOutputSchema, ExportOutputSchemaDigest32, GateMetrics,
    InputSchemaDigest32, MetricField, ScheduleDigest32, ScheduleMetrics, SourceIrDigest32,
    ValidationError, ACTIVATION_CIRCUIT_ID_STR, ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE,
    ACTIVATION_DRAFT_MANIFEST_PREIMAGE_BYTES, ACTIVATION_OUTPUT_SCHEMA_ID_STR,
    DRAFT_MANIFEST_DIGEST_DOMAIN_V1, EXPORT_CIRCUIT_ID_STR, EXPORT_DRAFT_MANIFEST_FAMILY_BYTE,
    EXPORT_DRAFT_MANIFEST_PREIMAGE_BYTES, EXPORT_OUTPUT_SCHEMA_ID_STR,
    PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE, PROTOCOL_ID_STR,
};
use sha2::{Digest, Sha256};

fn circuit_digest(marker: u8) -> CircuitDigest32 {
    CircuitDigest32::new([marker; 32]).expect("nonzero circuit digest")
}

fn compiler_digest(marker: u8) -> CompilerDigest32 {
    CompilerDigest32::new([marker; 32]).expect("nonzero compiler digest")
}

fn source_ir_digest(marker: u8) -> SourceIrDigest32 {
    SourceIrDigest32::new([marker; 32]).expect("nonzero source IR digest")
}

fn schedule_digest(marker: u8) -> ScheduleDigest32 {
    ScheduleDigest32::new([marker; 32]).expect("nonzero schedule digest")
}

fn constants_digest(marker: u8) -> ConstantsDigest32 {
    ConstantsDigest32::new([marker; 32]).expect("nonzero constants digest")
}

fn input_schema_digest(marker: u8) -> InputSchemaDigest32 {
    InputSchemaDigest32::new([marker; 32]).expect("nonzero input-schema digest")
}

fn activation_output_schema(marker: u8) -> ActivationOutputSchema {
    let digest = ActivationOutputSchemaDigest32::new([marker; 32])
        .expect("nonzero activation output-schema digest");
    ActivationOutputSchema::new(digest)
}

fn export_output_schema(marker: u8) -> ExportOutputSchema {
    let digest =
        ExportOutputSchemaDigest32::new([marker; 32]).expect("nonzero export output-schema digest");
    ExportOutputSchema::new(digest)
}

fn activation_artifact_digests(start: u8) -> ActivationCircuitArtifactDigests {
    ActivationCircuitArtifactDigests::new(
        circuit_digest(start),
        compiler_digest(start + 1),
        source_ir_digest(start + 2),
        schedule_digest(start + 3),
        constants_digest(start + 4),
        input_schema_digest(start + 5),
    )
}

fn export_artifact_digests(start: u8) -> ExportCircuitArtifactDigests {
    ExportCircuitArtifactDigests::new(
        circuit_digest(start),
        compiler_digest(start + 1),
        source_ir_digest(start + 2),
        schedule_digest(start + 3),
        constants_digest(start + 4),
        input_schema_digest(start + 5),
    )
}

fn metrics() -> CircuitMetrics {
    metrics_with_depth(5)
}

fn metrics_with_depth(circuit_depth: u64) -> CircuitMetrics {
    metrics_with_depths(circuit_depth, 4)
}

fn metrics_with_depths(circuit_depth: u64, and_depth: u64) -> CircuitMetrics {
    let gates = GateMetrics::new(10, 20, 2, 32, circuit_depth, and_depth).expect("valid gates");
    let schedule = ScheduleMetrics::new(8, 8, 64, 32, 24, 512).expect("valid schedule");
    CircuitMetrics::new_passive_half_gates(gates, schedule).expect("valid circuit metrics")
}

fn activation_manifest() -> DraftActivationCircuitManifest {
    DraftActivationCircuitManifest::new(
        activation_artifact_digests(1),
        activation_output_schema(7),
        metrics(),
    )
}

fn export_manifest() -> DraftExportCircuitManifest {
    DraftExportCircuitManifest::new(
        export_artifact_digests(20),
        export_output_schema(26),
        metrics(),
    )
}

fn append_metrics_preimage(expected: &mut Vec<u8>, metrics: CircuitMetrics) {
    let gates = metrics.gates();
    let schedule = metrics.schedule();
    for value in [
        gates.and_gate_count(),
        gates.xor_gate_count(),
        gates.inversion_gate_count(),
        gates.total_gate_count(),
        gates.circuit_depth(),
        gates.and_depth(),
        schedule.input_wire_count(),
        schedule.output_wire_count(),
        schedule.wire_count(),
        schedule.scheduled_gate_count(),
        schedule.peak_live_wire_count(),
        schedule.encoded_schedule_bytes(),
        metrics.table_payload_bytes(),
    ] {
        expected.extend_from_slice(&value.to_be_bytes());
    }
}

#[test]
fn fixed_identifiers_are_exact_and_family_specific() {
    let activation = activation_manifest();
    let export = DraftExportCircuitManifest::new(
        export_artifact_digests(20),
        export_output_schema(26),
        metrics(),
    );
    let protocol = DraftProtocolManifest::new(activation, export).expect("valid draft manifest");

    assert_eq!(protocol.protocol_id().as_str(), PROTOCOL_ID_STR);
    assert_eq!(PROTOCOL_ID_STR, "router_ab_ed25519_yao_v1");
    assert_eq!(activation.family(), CircuitFamily::Activation);
    assert_eq!(activation.circuit_id().as_str(), ACTIVATION_CIRCUIT_ID_STR);
    assert_eq!(ACTIVATION_CIRCUIT_ID_STR, "ed25519_yao_activation_v1");
    assert_eq!(
        activation.output_schema().id_str(),
        ACTIVATION_OUTPUT_SCHEMA_ID_STR
    );
    assert_eq!(
        ACTIVATION_OUTPUT_SCHEMA_ID_STR,
        "ed25519_yao_activation_output_schema_v1"
    );
    assert_eq!(export.family(), CircuitFamily::Export);
    assert_eq!(export.circuit_id().as_str(), EXPORT_CIRCUIT_ID_STR);
    assert_eq!(EXPORT_CIRCUIT_ID_STR, "ed25519_yao_export_v1");
    assert_eq!(export.output_schema().id_str(), EXPORT_OUTPUT_SCHEMA_ID_STR);
    assert_eq!(
        EXPORT_OUTPUT_SCHEMA_ID_STR,
        "ed25519_yao_export_output_schema_v1"
    );
    assert_eq!(
        DRAFT_MANIFEST_DIGEST_DOMAIN_V1,
        b"seams:router-ab:ed25519-yao:draft-manifest:v1"
    );
    assert_eq!(ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE, 0x01);
    assert_eq!(EXPORT_DRAFT_MANIFEST_FAMILY_BYTE, 0x02);
}

#[test]
fn digest_boundaries_reject_wrong_length_and_zero() {
    assert_eq!(
        CircuitDigest32::try_from_slice(&[1_u8; 31]),
        Err(ValidationError::DigestLength { actual: 31 })
    );
    assert_eq!(
        CompilerDigest32::new([0_u8; 32]),
        Err(ValidationError::ZeroDigest)
    );
    assert_eq!(
        ActivationOutputSchemaDigest32::new([0_u8; 32]),
        Err(ValidationError::ZeroDigest)
    );
    assert_eq!(
        ExportOutputSchemaDigest32::try_from_slice(&[1_u8; 33]),
        Err(ValidationError::DigestLength { actual: 33 })
    );
}

#[test]
fn gate_metrics_reject_zero_mismatch_overflow_and_excess_depth() {
    assert_eq!(
        GateMetrics::new(0, 1, 0, 1, 1, 1),
        Err(ValidationError::ZeroMetric {
            field: MetricField::AndGateCount
        })
    );
    assert_eq!(
        GateMetrics::new(1, 1, 1, 4, 1, 1),
        Err(ValidationError::TotalGateCountMismatch {
            declared: 4,
            computed: 3
        })
    );
    assert_eq!(
        GateMetrics::new(u64::MAX, 1, 0, u64::MAX, 1, 1),
        Err(ValidationError::GateCountOverflow)
    );
    assert_eq!(
        GateMetrics::new(1, 1, 0, 2, 3, 1),
        Err(ValidationError::CircuitDepthExceedsTotalGateCount {
            depth: 3,
            total_gates: 2
        })
    );
    assert_eq!(
        GateMetrics::new(2, 2, 0, 4, 3, 0),
        Err(ValidationError::ZeroMetric {
            field: MetricField::AndDepth
        })
    );
    assert_eq!(
        GateMetrics::new(2, 2, 0, 4, 2, 3),
        Err(ValidationError::AndDepthExceedsCircuitDepth {
            and_depth: 3,
            circuit_depth: 2
        })
    );
    assert_eq!(
        GateMetrics::new(1, 3, 0, 4, 3, 2),
        Err(ValidationError::AndDepthExceedsAndGateCount {
            and_depth: 2,
            and_gate_count: 1
        })
    );
}

#[test]
fn schedule_metrics_reject_impossible_wire_liveness() {
    assert!(ScheduleMetrics::new(8, 8, 8, 32, 8, 512).is_ok());
    assert_eq!(
        ScheduleMetrics::new(8, 7, 7, 32, 7, 512),
        Err(ValidationError::WireCountBelowInputWireCount {
            wire_count: 7,
            input_wire_count: 8
        })
    );
    assert_eq!(
        ScheduleMetrics::new(6, 8, 7, 32, 7, 512),
        Err(ValidationError::OutputWireCountExceedsWireCount {
            output_wire_count: 8,
            wire_count: 7
        })
    );
    assert_eq!(
        ScheduleMetrics::new(8, 8, 64, 32, 65, 512),
        Err(ValidationError::PeakLiveWireCountExceedsWireCount {
            peak_live_wire_count: 65,
            wire_count: 64
        })
    );
}

#[test]
fn circuit_metrics_require_schedule_parity_and_derive_passive_table_bytes() {
    let gates = GateMetrics::new(10, 20, 2, 32, 5, 4).expect("valid gates");
    let schedule = ScheduleMetrics::new(8, 8, 64, 31, 24, 512).expect("valid schedule shape");
    assert_eq!(
        CircuitMetrics::new_passive_half_gates(gates, schedule),
        Err(ValidationError::ScheduledGateCountMismatch {
            scheduled: 31,
            total_gates: 32
        })
    );

    let schedule = ScheduleMetrics::new(8, 8, 64, 32, 24, 512).expect("valid schedule");
    let metrics = CircuitMetrics::new_passive_half_gates(gates, schedule).expect("valid metrics");
    assert_eq!(
        metrics.table_payload_bytes(),
        gates.and_gate_count() * PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE
    );

    let overflowing_and_count = (u64::MAX / PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE) + 1;
    let overflowing_total = overflowing_and_count + 1;
    let overflowing_gates = GateMetrics::new(overflowing_and_count, 1, 0, overflowing_total, 2, 1)
        .expect("gate counts fit before table-byte derivation");
    let overflowing_schedule =
        ScheduleMetrics::new(1, 1, 2, overflowing_total, 1, 1).expect("valid schedule shape");
    assert_eq!(
        CircuitMetrics::new_passive_half_gates(overflowing_gates, overflowing_schedule),
        Err(ValidationError::PassiveHalfGatesTablePayloadOverflow {
            and_gate_count: overflowing_and_count
        })
    );
}

#[test]
fn draft_manifest_digest_regenerates_deterministically() {
    let first = activation_manifest();
    let second = activation_manifest();

    assert_eq!(first.manifest_digest(), second.manifest_digest());
}

#[test]
fn draft_manifest_digest_binds_metrics() {
    let baseline = activation_manifest();
    let changed_depth = DraftActivationCircuitManifest::new(
        activation_artifact_digests(1),
        activation_output_schema(7),
        metrics_with_depth(6),
    );
    let changed_and_depth = DraftActivationCircuitManifest::new(
        activation_artifact_digests(1),
        activation_output_schema(7),
        metrics_with_depths(5, 3),
    );

    assert_ne!(baseline.manifest_digest(), changed_depth.manifest_digest());
    assert_ne!(
        baseline.manifest_digest(),
        changed_and_depth.manifest_digest()
    );
}

#[test]
fn draft_manifest_digest_binds_circuit_and_schedule_digests() {
    let baseline = activation_manifest();
    let baseline_digests = baseline.digests();
    let changed_circuit = DraftActivationCircuitManifest::new(
        ActivationCircuitArtifactDigests::new(
            circuit_digest(90),
            baseline_digests.compiler(),
            baseline_digests.source_ir(),
            baseline_digests.schedule(),
            baseline_digests.constants(),
            baseline_digests.input_schema(),
        ),
        baseline.output_schema(),
        baseline.metrics(),
    );
    let changed_schedule = DraftActivationCircuitManifest::new(
        ActivationCircuitArtifactDigests::new(
            baseline_digests.circuit(),
            baseline_digests.compiler(),
            baseline_digests.source_ir(),
            schedule_digest(91),
            baseline_digests.constants(),
            baseline_digests.input_schema(),
        ),
        baseline.output_schema(),
        baseline.metrics(),
    );

    assert_ne!(
        baseline.manifest_digest(),
        changed_circuit.manifest_digest()
    );
    assert_ne!(
        baseline.manifest_digest(),
        changed_schedule.manifest_digest()
    );
}

#[test]
fn draft_manifest_digest_matches_v1_golden_value() {
    assert_eq!(
        activation_manifest().manifest_digest().into_bytes(),
        [
            0x7a, 0xad, 0x12, 0x5c, 0x10, 0xc2, 0x14, 0xc8, 0x12, 0xf7, 0x77, 0x84, 0xc4, 0x3b,
            0x1b, 0xec, 0x4a, 0x92, 0xfc, 0x76, 0xec, 0x3a, 0x3e, 0xda, 0x85, 0xf2, 0x02, 0xe7,
            0x80, 0xdd, 0x3d, 0x9a,
        ]
    );
}

#[test]
fn proof_facing_preimages_freeze_exact_family_role_and_metric_order() {
    let activation = activation_manifest();
    let activation_digests = activation.digests();
    let mut expected_activation = Vec::new();
    expected_activation.extend_from_slice(DRAFT_MANIFEST_DIGEST_DOMAIN_V1);
    expected_activation.push(ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE);
    expected_activation
        .extend_from_slice(&(ACTIVATION_OUTPUT_SCHEMA_ID_STR.len() as u64).to_be_bytes());
    expected_activation.extend_from_slice(ACTIVATION_OUTPUT_SCHEMA_ID_STR.as_bytes());
    for digest in [
        activation_digests.circuit().into_bytes(),
        activation_digests.compiler().into_bytes(),
        activation_digests.source_ir().into_bytes(),
        activation_digests.schedule().into_bytes(),
        activation_digests.constants().into_bytes(),
        activation_digests.input_schema().into_bytes(),
        activation.output_schema().digest().into_bytes(),
    ] {
        expected_activation.extend_from_slice(&digest);
    }
    append_metrics_preimage(&mut expected_activation, activation.metrics());

    let activation_preimage = activation.canonical_preimage();
    assert_eq!(
        expected_activation.len(),
        ACTIVATION_DRAFT_MANIFEST_PREIMAGE_BYTES
    );
    assert_eq!(
        activation_preimage.as_bytes(),
        expected_activation.as_slice()
    );
    assert_eq!(
        Sha256::digest(activation_preimage.as_bytes()).as_slice(),
        activation.manifest_digest().as_bytes()
    );

    let export = export_manifest();
    let export_digests = export.digests();
    let mut expected_export = Vec::new();
    expected_export.extend_from_slice(DRAFT_MANIFEST_DIGEST_DOMAIN_V1);
    expected_export.push(EXPORT_DRAFT_MANIFEST_FAMILY_BYTE);
    expected_export.extend_from_slice(&(EXPORT_OUTPUT_SCHEMA_ID_STR.len() as u64).to_be_bytes());
    expected_export.extend_from_slice(EXPORT_OUTPUT_SCHEMA_ID_STR.as_bytes());
    for digest in [
        export_digests.circuit().into_bytes(),
        export_digests.compiler().into_bytes(),
        export_digests.source_ir().into_bytes(),
        export_digests.schedule().into_bytes(),
        export_digests.constants().into_bytes(),
        export_digests.input_schema().into_bytes(),
        export.output_schema().digest().into_bytes(),
    ] {
        expected_export.extend_from_slice(&digest);
    }
    append_metrics_preimage(&mut expected_export, export.metrics());

    let export_preimage = export.canonical_preimage();
    assert_eq!(expected_export.len(), EXPORT_DRAFT_MANIFEST_PREIMAGE_BYTES);
    assert_eq!(export_preimage.as_bytes(), expected_export.as_slice());
    assert_eq!(
        Sha256::digest(export_preimage.as_bytes()).as_slice(),
        export.manifest_digest().as_bytes()
    );
}

#[test]
fn draft_protocol_manifest_rejects_cross_family_artifact_reuse() {
    let activation_digests = activation_artifact_digests(1);
    let activation = DraftActivationCircuitManifest::new(
        activation_digests,
        activation_output_schema(7),
        metrics(),
    );

    let duplicate_circuit_export_digests = ExportCircuitArtifactDigests::new(
        activation_digests.circuit(),
        compiler_digest(30),
        source_ir_digest(31),
        schedule_digest(32),
        constants_digest(33),
        input_schema_digest(34),
    );
    let export = DraftExportCircuitManifest::new(
        duplicate_circuit_export_digests,
        export_output_schema(35),
        metrics(),
    );
    assert_eq!(
        DraftProtocolManifest::new(activation, export),
        Err(ValidationError::DuplicateCircuitDigest)
    );

    let duplicate_schedule_export_digests = ExportCircuitArtifactDigests::new(
        circuit_digest(50),
        compiler_digest(51),
        source_ir_digest(52),
        activation_digests.schedule(),
        constants_digest(54),
        input_schema_digest(55),
    );
    let export = DraftExportCircuitManifest::new(
        duplicate_schedule_export_digests,
        export_output_schema(56),
        metrics(),
    );
    assert_eq!(
        DraftProtocolManifest::new(activation, export),
        Err(ValidationError::DuplicateScheduleDigest)
    );

    let activation_output_digest = activation.output_schema().digest().into_bytes();
    let duplicate_output_digest = ExportOutputSchemaDigest32::new(activation_output_digest)
        .expect("nonzero duplicate output-schema digest");
    let export = DraftExportCircuitManifest::new(
        export_artifact_digests(40),
        ExportOutputSchema::new(duplicate_output_digest),
        metrics(),
    );
    assert_eq!(
        DraftProtocolManifest::new(activation, export),
        Err(ValidationError::DuplicateOutputSchemaDigest)
    );
}
