use std::sync::OnceLock;

use ed25519_yao::{CircuitMetrics, GateMetrics, ScheduleMetrics};

use crate::{
    canonical_vector_corpus_v1, differential_vector_corpus_v1, VectorCaseV1, VectorInputsV1,
    MAX_DIFFERENTIAL_VECTOR_CASES_V1,
};

use super::families::{PublicSyntheticActivationCoreOutputsV1, PublicSyntheticExportCoreOutputV1};
use super::{
    compile_provisional_activation_core_v1, compile_provisional_export_core_v1,
    ProvisionalActivationCoreV1, ProvisionalExportCoreV1, PublicSyntheticActivationCoreInputsV1,
    PublicSyntheticDeriverAActivationInputsV1, PublicSyntheticDeriverAExportInputsV1,
    PublicSyntheticDeriverBActivationInputsV1, PublicSyntheticDeriverBExportInputsV1,
    PublicSyntheticExportCoreInputsV1, PublicSyntheticTauFieldV1,
    PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1, PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1,
    PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1, PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1,
};

const SCALAR_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn activation_core() -> &'static ProvisionalActivationCoreV1 {
    static CORE: OnceLock<ProvisionalActivationCoreV1> = OnceLock::new();
    CORE.get_or_init(compile_provisional_activation_core_v1)
}

fn export_core() -> &'static ProvisionalExportCoreV1 {
    static CORE: OnceLock<ProvisionalExportCoreV1> = OnceLock::new();
    CORE.get_or_init(compile_provisional_export_core_v1)
}

fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture hex is lowercase ASCII"),
    }
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "fixture field has 32 bytes");
    let encoded = hex.as_bytes();
    let mut decoded = [0u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = (decode_hex_nibble(encoded[index * 2]) << 4)
            | decode_hex_nibble(encoded[index * 2 + 1]);
    }
    decoded
}

fn arithmetic_reference_inputs(case: &VectorCaseV1) -> &VectorInputsV1 {
    match case {
        VectorCaseV1::Registration(case)
        | VectorCaseV1::Activation(case)
        | VectorCaseV1::Recovery(case)
        | VectorCaseV1::Refresh(case) => &case.inputs,
        VectorCaseV1::Export(case) => &case.reference.inputs,
    }
}

fn activation_inputs(inputs: &VectorInputsV1) -> PublicSyntheticActivationCoreInputsV1 {
    let deriver_a = PublicSyntheticDeriverAActivationInputsV1::new(
        decode_hex_32(&inputs.y_client_a_hex),
        decode_hex_32(&inputs.y_server_a_hex),
        decode_hex_32(&inputs.tau_client_a_hex),
        decode_hex_32(&inputs.tau_server_a_hex),
    )
    .expect("fixture A scalars are canonical");
    let deriver_b = PublicSyntheticDeriverBActivationInputsV1::new(
        decode_hex_32(&inputs.y_client_b_hex),
        decode_hex_32(&inputs.y_server_b_hex),
        decode_hex_32(&inputs.tau_client_b_hex),
        decode_hex_32(&inputs.tau_server_b_hex),
    )
    .expect("fixture B scalars are canonical");
    PublicSyntheticActivationCoreInputsV1::new(deriver_a, deriver_b)
}

fn export_inputs(inputs: &VectorInputsV1) -> PublicSyntheticExportCoreInputsV1 {
    PublicSyntheticExportCoreInputsV1::new(
        PublicSyntheticDeriverAExportInputsV1::new(
            decode_hex_32(&inputs.y_client_a_hex),
            decode_hex_32(&inputs.y_server_a_hex),
        ),
        PublicSyntheticDeriverBExportInputsV1::new(
            decode_hex_32(&inputs.y_client_b_hex),
            decode_hex_32(&inputs.y_server_b_hex),
        ),
    )
}

fn evaluate_activation_component(case: &VectorCaseV1) -> PublicSyntheticActivationCoreOutputsV1 {
    let inputs = arithmetic_reference_inputs(case);
    activation_core().evaluate_public_synthetic(&activation_inputs(inputs))
}

fn evaluate_export_component(case: &VectorCaseV1) -> PublicSyntheticExportCoreOutputV1 {
    let inputs = arithmetic_reference_inputs(case);
    export_core().evaluate_public_synthetic(&export_inputs(inputs))
}

fn assert_activation_component_matches_reference(case: &VectorCaseV1) {
    let trace = case.clear_reference_trace();
    let activation = evaluate_activation_component(case);
    assert_eq!(
        activation.x_client_base(),
        decode_hex_32(&trace.x_client_base_hex)
    );
    assert_eq!(
        activation.x_server_base(),
        decode_hex_32(&trace.x_server_base_hex)
    );
}

fn assert_export_component_matches_reference(case: &VectorCaseV1) {
    let trace = case.clear_reference_trace();
    let export = evaluate_export_component(case);
    assert_eq!(export.seed(), decode_hex_32(&trace.joined_seed_hex));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleCoreInvocationV1 {
    ActivationFamily,
    ZeroEvaluationContinuation,
    ExportFamily,
}

fn evaluate_lifecycle_case(case: &VectorCaseV1) -> LifecycleCoreInvocationV1 {
    match case {
        VectorCaseV1::Registration(_) | VectorCaseV1::Recovery(_) | VectorCaseV1::Refresh(_) => {
            assert_activation_component_matches_reference(case);
            LifecycleCoreInvocationV1::ActivationFamily
        }
        VectorCaseV1::Activation(_) => LifecycleCoreInvocationV1::ZeroEvaluationContinuation,
        VectorCaseV1::Export(_) => {
            assert_export_component_matches_reference(case);
            LifecycleCoreInvocationV1::ExportFamily
        }
    }
}

#[test]
fn provisional_components_match_all_frozen_arithmetic_reference_inputs() {
    for case in canonical_vector_corpus_v1().cases {
        assert_activation_component_matches_reference(&case);
        assert_export_component_matches_reference(&case);
    }
    let differential = differential_vector_corpus_v1([0x5a; 32], MAX_DIFFERENTIAL_VECTOR_CASES_V1)
        .expect("maximum public differential corpus is valid");
    for case in differential.cases {
        assert_activation_component_matches_reference(&case);
        assert_export_component_matches_reference(&case);
    }
}

#[test]
fn lifecycle_request_kinds_invoke_only_the_selected_core() {
    let invocations = canonical_vector_corpus_v1()
        .cases
        .iter()
        .map(evaluate_lifecycle_case)
        .collect::<Vec<_>>();
    assert_eq!(
        invocations,
        [
            LifecycleCoreInvocationV1::ActivationFamily,
            LifecycleCoreInvocationV1::ZeroEvaluationContinuation,
            LifecycleCoreInvocationV1::ActivationFamily,
            LifecycleCoreInvocationV1::ActivationFamily,
            LifecycleCoreInvocationV1::ExportFamily,
        ]
    );
}

fn distinguishable_field(domain: u8) -> [u8; 32] {
    let mut field = [0u8; 32];
    for (index, byte) in field.iter_mut().enumerate() {
        *byte = domain.wrapping_add(index as u8);
    }
    field
}

fn distinguishable_canonical_tau(domain: u8, high_byte: u8) -> [u8; 32] {
    let mut field = distinguishable_field(domain);
    field[31] = high_byte;
    field
}

fn assert_byte_major_lsb0(bits: &[bool], bytes: &[u8]) {
    assert_eq!(bits.len(), bytes.len() * 8);
    for (byte_index, byte) in bytes.iter().copied().enumerate() {
        for bit_index in 0..8 {
            assert_eq!(
                bits[byte_index * 8 + bit_index],
                ((byte >> bit_index) & 1) == 1,
                "byte {byte_index}, bit {bit_index}"
            );
        }
    }
}

#[test]
fn activation_input_projection_fixes_field_byte_and_lsb0_order() {
    let fields = [
        distinguishable_field(0x00),
        distinguishable_field(0x20),
        distinguishable_canonical_tau(0x40, 0x01),
        distinguishable_canonical_tau(0x60, 0x02),
        distinguishable_field(0x80),
        distinguishable_field(0xa0),
        distinguishable_canonical_tau(0xc0, 0x03),
        distinguishable_canonical_tau(0xe0, 0x04),
    ];
    let inputs = PublicSyntheticActivationCoreInputsV1::new(
        PublicSyntheticDeriverAActivationInputsV1::new(fields[0], fields[1], fields[2], fields[3])
            .expect("small distinguishable A tau fields are canonical"),
        PublicSyntheticDeriverBActivationInputsV1::new(fields[4], fields[5], fields[6], fields[7])
            .expect("small distinguishable B tau fields are canonical"),
    );
    let projected = inputs.canonical_input_bytes_v1();
    let expected = fields.concat();
    assert_eq!(projected, expected);
    assert_byte_major_lsb0(&super::families::activation_input_bits(&inputs), &projected);
}

#[test]
fn export_input_projection_fixes_field_byte_and_lsb0_order() {
    let fields = [
        distinguishable_field(0x11),
        distinguishable_field(0x33),
        distinguishable_field(0x55),
        distinguishable_field(0x77),
    ];
    let inputs = PublicSyntheticExportCoreInputsV1::new(
        PublicSyntheticDeriverAExportInputsV1::new(fields[0], fields[1]),
        PublicSyntheticDeriverBExportInputsV1::new(fields[2], fields[3]),
    );
    let projected = inputs.canonical_input_bytes_v1();
    let expected = fields.concat();
    assert_eq!(projected, expected);
    assert_byte_major_lsb0(&super::families::export_input_bits(&inputs), &projected);
}

#[test]
fn activation_boundary_rejects_each_noncanonical_tau_and_schemas_are_disjoint() {
    let zero = [0u8; 32];
    let error = PublicSyntheticDeriverAActivationInputsV1::new(zero, zero, SCALAR_ORDER_LE, zero)
        .err()
        .expect("A client scalar is rejected");
    assert_eq!(error.field(), PublicSyntheticTauFieldV1::DeriverAClient);
    let error = PublicSyntheticDeriverAActivationInputsV1::new(zero, zero, zero, SCALAR_ORDER_LE)
        .err()
        .expect("A server scalar is rejected");
    assert_eq!(error.field(), PublicSyntheticTauFieldV1::DeriverAServer);
    let error = PublicSyntheticDeriverBActivationInputsV1::new(zero, zero, SCALAR_ORDER_LE, zero)
        .err()
        .expect("B client scalar is rejected");
    assert_eq!(error.field(), PublicSyntheticTauFieldV1::DeriverBClient);
    let error = PublicSyntheticDeriverBActivationInputsV1::new(zero, zero, zero, SCALAR_ORDER_LE)
        .err()
        .expect("B server scalar is rejected");
    assert_eq!(error.field(), PublicSyntheticTauFieldV1::DeriverBServer);

    assert!(PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1.contains("canonical-l"));
    assert!(PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1.contains("no-seed"));
    assert!(PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1.contains("no-tau"));
    assert!(PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1.contains("no-scalar"));
}

#[test]
fn provisional_family_artifacts_regenerate_and_metrics_are_frozen() {
    let first_activation = compile_provisional_activation_core_v1();
    let second_activation = compile_provisional_activation_core_v1();
    assert_eq!(
        first_activation.canonical_encoding(),
        second_activation.canonical_encoding()
    );
    assert_eq!(
        first_activation.benchmark_component_digest(),
        second_activation.benchmark_component_digest()
    );
    let first_export = compile_provisional_export_core_v1();
    let second_export = compile_provisional_export_core_v1();
    assert_eq!(
        first_export.canonical_encoding(),
        second_export.canonical_encoding()
    );
    assert_eq!(
        first_export.benchmark_component_digest(),
        second_export.benchmark_component_digest()
    );

    let activation_metrics = first_activation.metrics();
    assert_eq!(activation_metrics.input_wire_count(), 2_048);
    assert_eq!(activation_metrics.output_wire_count(), 512);
    assert_eq!(activation_metrics.wire_count(), 369_288);
    assert_eq!(activation_metrics.and_gate_count(), 62_716);
    assert_eq!(activation_metrics.xor_gate_count(), 294_021);
    assert_eq!(activation_metrics.inversion_gate_count(), 10_503);
    assert_eq!(activation_metrics.total_gate_count(), 367_240);
    assert_eq!(activation_metrics.circuit_depth(), 17_903);
    assert_eq!(activation_metrics.and_depth(), 5_723);
    assert_eq!(activation_metrics.canonical_encoding_bytes(), 3_307_294);
    assert_eq!(
        activation_metrics.and_gate_count() * 32,
        2_006_912,
        "passive Half-Gates table bytes"
    );
    assert!(activation_metrics.and_gate_count() * 32 <= (210 * 1_024 * 1_024) / 100);
    assert_eq!(
        first_activation
            .benchmark_component_digest()
            .expose_public_bytes(),
        [
            0x74, 0x7f, 0xa6, 0xf1, 0x81, 0x5e, 0x3a, 0x0c, 0x70, 0xf0, 0x07, 0x7f, 0xfc, 0x10,
            0x50, 0x88, 0x82, 0xf3, 0x21, 0xad, 0x6e, 0x7b, 0xb4, 0x22, 0xf4, 0xee, 0xf6, 0x95,
            0xa8, 0x53, 0xb5, 0xa5,
        ]
    );

    let export_metrics = first_export.metrics();
    assert_eq!(export_metrics.input_wire_count(), 1_024);
    assert_eq!(export_metrics.output_wire_count(), 256);
    assert_eq!(export_metrics.wire_count(), 5_608);
    assert_eq!(export_metrics.and_gate_count(), 765);
    assert_eq!(export_metrics.xor_gate_count(), 3_819);
    assert_eq!(export_metrics.inversion_gate_count(), 0);
    assert_eq!(export_metrics.total_gate_count(), 4_584);
    assert_eq!(export_metrics.circuit_depth(), 766);
    assert_eq!(export_metrics.and_depth(), 255);
    assert_eq!(export_metrics.canonical_encoding_bytes(), 42_366);
    assert_eq!(export_metrics.and_gate_count() * 32, 24_480);
    assert_eq!(
        first_export
            .benchmark_component_digest()
            .expose_public_bytes(),
        [
            0x3c, 0xc9, 0x56, 0x94, 0xe0, 0x19, 0x66, 0x64, 0x2d, 0xb7, 0xea, 0xed, 0x9d, 0x68,
            0xa4, 0x11, 0x6c, 0x66, 0xbc, 0x4d, 0x72, 0xf1, 0x49, 0x08, 0xd0, 0xd3, 0xb5, 0xe2,
            0x5e, 0xe7, 0x98, 0x38,
        ]
    );
    assert_eq!(first_activation.canonical_encoding()[8], 0x91);
    assert_eq!(first_export.canonical_encoding()[8], 0x92);

    let activation_manifest_metrics = CircuitMetrics::new_passive_half_gates(
        GateMetrics::new(62_716, 294_021, 10_503, 367_240, 17_903, 5_723)
            .expect("activation gate metrics fit the manifest schema"),
        ScheduleMetrics::new(2_048, 512, 369_288, 367_240, 5_761, 2_571_762)
            .expect("activation schedule metrics fit the manifest schema"),
    )
    .expect("activation cross-metrics agree");
    assert_eq!(activation_manifest_metrics.table_payload_bytes(), 2_006_912);

    let export_manifest_metrics = CircuitMetrics::new_passive_half_gates(
        GateMetrics::new(765, 3_819, 0, 4_584, 766, 255)
            .expect("export gate metrics fit the manifest schema"),
        ScheduleMetrics::new(1_024, 256, 5_608, 4_584, 1_025, 32_658)
            .expect("export schedule metrics fit the manifest schema"),
    )
    .expect("export cross-metrics agree");
    assert_eq!(export_manifest_metrics.table_payload_bytes(), 24_480);
}
