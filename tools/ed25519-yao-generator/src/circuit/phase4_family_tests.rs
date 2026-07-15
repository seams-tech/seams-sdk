use std::sync::OnceLock;

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::{
    canonical_vector_corpus_v1, differential_vector_corpus_v1, wrapping_add_le_256, VectorCaseV1,
    VectorInputsV1,
};

use super::phase4_families::{
    phase4_activation_input_bits, phase4_export_input_bits, Phase4PrivateOutputActivationCoreV1,
    Phase4PrivateOutputExportCoreV1,
};
use super::{
    compile_phase4_private_output_activation_core_v1, compile_phase4_private_output_export_core_v1,
    PublicSyntheticDeriverAActivationInputsV1, PublicSyntheticDeriverAExportInputsV1,
    PublicSyntheticDeriverBActivationInputsV1, PublicSyntheticDeriverBExportInputsV1,
    PublicSyntheticPhase4ActivationInputsV1, PublicSyntheticPhase4DeriverAClientScalarCoinV1,
    PublicSyntheticPhase4DeriverAExportSeedCoinV1,
    PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1,
    PublicSyntheticPhase4DeriverBClientScalarCoinV1, PublicSyntheticPhase4DeriverBExportSeedCoinV1,
    PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1, PublicSyntheticPhase4ExportInputsV1,
    PHASE4_PRIVATE_OUTPUT_ACTIVATION_INPUT_SCHEMA_V1,
    PHASE4_PRIVATE_OUTPUT_ACTIVATION_OUTPUT_SCHEMA_V1,
    PHASE4_PRIVATE_OUTPUT_EXPORT_INPUT_SCHEMA_V1, PHASE4_PRIVATE_OUTPUT_EXPORT_OUTPUT_SCHEMA_V1,
};

const SCALAR_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn activation_core() -> &'static Phase4PrivateOutputActivationCoreV1 {
    static CORE: OnceLock<Phase4PrivateOutputActivationCoreV1> = OnceLock::new();
    CORE.get_or_init(compile_phase4_private_output_activation_core_v1)
}

fn export_core() -> &'static Phase4PrivateOutputExportCoreV1 {
    static CORE: OnceLock<Phase4PrivateOutputExportCoreV1> = OnceLock::new();
    CORE.get_or_init(compile_phase4_private_output_export_core_v1)
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

fn scalar_from_bytes(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("circuit scalar output is canonical")
}

fn deterministic_scalar(domain: u8, case_index: u8) -> Scalar {
    let wide: [u8; 64] = Sha512::digest(
        [
            b"ed25519-yao-phase4-private-output-scalar-v1".as_slice(),
            &[domain, case_index],
        ]
        .concat(),
    )
    .into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn deterministic_seed_coin(domain: u8) -> [u8; 32] {
    let digest: [u8; 64] = Sha512::digest(
        [
            b"ed25519-yao-phase4-private-output-seed-v1".as_slice(),
            &[domain],
        ]
        .concat(),
    )
    .into();
    digest[..32]
        .try_into()
        .expect("SHA-512 prefix has 32 bytes")
}

fn wrapping_subtract_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = false;
    for index in 0..32 {
        let (after_right, right_borrow) = left[index].overflowing_sub(right[index]);
        let (after_borrow, carry_borrow) = after_right.overflowing_sub(u8::from(borrow));
        output[index] = after_borrow;
        borrow = right_borrow | carry_borrow;
    }
    output
}

fn activation_inputs(
    inputs: &VectorInputsV1,
    coins: [Scalar; 4],
) -> PublicSyntheticPhase4ActivationInputsV1 {
    PublicSyntheticPhase4ActivationInputsV1::new(
        PublicSyntheticDeriverAActivationInputsV1::new(
            decode_hex_32(&inputs.y_client_a_hex),
            decode_hex_32(&inputs.y_server_a_hex),
            decode_hex_32(&inputs.tau_client_a_hex),
            decode_hex_32(&inputs.tau_server_a_hex),
        )
        .expect("fixture A scalars are canonical"),
        PublicSyntheticPhase4DeriverAClientScalarCoinV1::new(coins[0].to_bytes())
            .expect("A client coin is canonical"),
        PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1::new(coins[1].to_bytes())
            .expect("A SigningWorker coin is canonical"),
        PublicSyntheticDeriverBActivationInputsV1::new(
            decode_hex_32(&inputs.y_client_b_hex),
            decode_hex_32(&inputs.y_server_b_hex),
            decode_hex_32(&inputs.tau_client_b_hex),
            decode_hex_32(&inputs.tau_server_b_hex),
        )
        .expect("fixture B scalars are canonical"),
        PublicSyntheticPhase4DeriverBClientScalarCoinV1::new(coins[2].to_bytes())
            .expect("B client coin is canonical"),
        PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1::new(coins[3].to_bytes())
            .expect("B SigningWorker coin is canonical"),
    )
}

fn export_inputs(
    inputs: &VectorInputsV1,
    coins: [[u8; 32]; 2],
) -> PublicSyntheticPhase4ExportInputsV1 {
    PublicSyntheticPhase4ExportInputsV1::new(
        PublicSyntheticDeriverAExportInputsV1::new(
            decode_hex_32(&inputs.y_client_a_hex),
            decode_hex_32(&inputs.y_server_a_hex),
        ),
        PublicSyntheticPhase4DeriverAExportSeedCoinV1::new(coins[0]),
        PublicSyntheticDeriverBExportInputsV1::new(
            decode_hex_32(&inputs.y_client_b_hex),
            decode_hex_32(&inputs.y_server_b_hex),
        ),
        PublicSyntheticPhase4DeriverBExportSeedCoinV1::new(coins[1]),
    )
}

fn activation_coin_cases() -> Vec<[Scalar; 4]> {
    vec![
        [Scalar::ZERO; 4],
        [-Scalar::ONE, Scalar::ONE, Scalar::ONE, -Scalar::ONE],
        [-Scalar::ONE, -Scalar::ONE, -Scalar::ONE, Scalar::ONE],
        [
            deterministic_scalar(0xa1, 0),
            deterministic_scalar(0xa2, 0),
            deterministic_scalar(0xb1, 0),
            deterministic_scalar(0xb2, 0),
        ],
        [
            deterministic_scalar(0xa1, 1),
            deterministic_scalar(0xa2, 1),
            deterministic_scalar(0xb1, 1),
            deterministic_scalar(0xb2, 1),
        ],
    ]
}

fn export_coin_cases() -> Vec<[[u8; 32]; 2]> {
    let mut one = [0u8; 32];
    one[0] = 1;
    vec![
        [[0u8; 32], [0u8; 32]],
        [[0xff; 32], one],
        [one, [0xff; 32]],
        [deterministic_seed_coin(0xa1), deterministic_seed_coin(0xb2)],
    ]
}

fn test_cases() -> Vec<VectorCaseV1> {
    let mut cases = canonical_vector_corpus_v1().cases;
    let mut differential = differential_vector_corpus_v1([0x6d; 32], 8)
        .expect("eight public differential cases are valid")
        .cases;
    cases.append(&mut differential);
    cases
}

#[test]
fn phase4_activation_joint_coins_reconstruct_both_canonical_base_scalars() {
    for case in test_cases() {
        let reference = case.clear_reference_trace();
        let expected_client = scalar_from_bytes(decode_hex_32(&reference.x_client_base_hex));
        let expected_signing_worker =
            scalar_from_bytes(decode_hex_32(&reference.x_server_base_hex));
        for coins in activation_coin_cases() {
            let inputs = activation_inputs(arithmetic_reference_inputs(&case), coins);
            let outputs = activation_core().evaluate_public_synthetic(&inputs);
            let expected_client_mask = coins[0] + coins[2];
            let expected_signing_worker_mask = coins[1] + coins[3];
            let a_client = scalar_from_bytes(outputs.deriver_a().x_client_share());
            let a_signing_worker = scalar_from_bytes(outputs.deriver_a().x_signing_worker_share());
            let b_client = scalar_from_bytes(outputs.deriver_b().x_client_share());
            let b_signing_worker = scalar_from_bytes(outputs.deriver_b().x_signing_worker_share());

            assert_eq!(a_client, expected_client_mask);
            assert_eq!(a_signing_worker, expected_signing_worker_mask);
            assert_eq!(a_client + b_client, expected_client);
            assert_eq!(a_signing_worker + b_signing_worker, expected_signing_worker);
            assert_eq!(
                activation_core().evaluate_ir_public_synthetic_bytes_v1(&inputs),
                activation_core().evaluate_schedule_public_synthetic_bytes_v1(&inputs)
            );
        }
    }
}

#[test]
fn phase4_export_joint_coins_reconstruct_seed_modulo_two_to_256() {
    for case in test_cases() {
        let reference = case.clear_reference_trace();
        let expected_seed = decode_hex_32(&reference.joined_seed_hex);
        for coins in export_coin_cases() {
            let inputs = export_inputs(arithmetic_reference_inputs(&case), coins);
            let outputs = export_core().evaluate_public_synthetic(&inputs);
            let expected_mask = wrapping_add_le_256(coins[0], coins[1]);
            let a_share = outputs.deriver_a().seed_share();
            let b_share = outputs.deriver_b().seed_share();

            assert_eq!(a_share, expected_mask);
            assert_eq!(
                b_share,
                wrapping_subtract_le_256(expected_seed, expected_mask)
            );
            assert_eq!(wrapping_add_le_256(a_share, b_share), expected_seed);
            assert_eq!(
                export_core().evaluate_ir_public_synthetic_bytes_v1(&inputs),
                export_core().evaluate_schedule_public_synthetic_bytes_v1(&inputs)
            );
        }
    }
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
fn phase4_input_projection_groups_each_roles_coins_and_fixes_lsb0_order() {
    let case = canonical_vector_corpus_v1()
        .cases
        .into_iter()
        .next()
        .expect("canonical corpus is nonempty");
    let vector = arithmetic_reference_inputs(&case);
    let scalar_coins = [
        deterministic_scalar(0xc1, 0),
        deterministic_scalar(0xc2, 0),
        deterministic_scalar(0xd1, 0),
        deterministic_scalar(0xd2, 0),
    ];
    let activation = activation_inputs(vector, scalar_coins);
    let activation_bytes = activation.canonical_input_bytes_v1();
    let expected_activation = [
        decode_hex_32(&vector.y_client_a_hex),
        decode_hex_32(&vector.y_server_a_hex),
        decode_hex_32(&vector.tau_client_a_hex),
        decode_hex_32(&vector.tau_server_a_hex),
        scalar_coins[0].to_bytes(),
        scalar_coins[1].to_bytes(),
        decode_hex_32(&vector.y_client_b_hex),
        decode_hex_32(&vector.y_server_b_hex),
        decode_hex_32(&vector.tau_client_b_hex),
        decode_hex_32(&vector.tau_server_b_hex),
        scalar_coins[2].to_bytes(),
        scalar_coins[3].to_bytes(),
    ]
    .concat();
    assert_eq!(activation_bytes, expected_activation);
    assert_byte_major_lsb0(
        &phase4_activation_input_bits(&activation),
        &activation_bytes,
    );

    let export_coins = [deterministic_seed_coin(0xe1), deterministic_seed_coin(0xe2)];
    let export = export_inputs(vector, export_coins);
    let export_bytes = export.canonical_input_bytes_v1();
    let expected_export = [
        decode_hex_32(&vector.y_client_a_hex),
        decode_hex_32(&vector.y_server_a_hex),
        export_coins[0],
        decode_hex_32(&vector.y_client_b_hex),
        decode_hex_32(&vector.y_server_b_hex),
        export_coins[1],
    ]
    .concat();
    assert_eq!(export_bytes, expected_export);
    assert_byte_major_lsb0(&phase4_export_input_bits(&export), &export_bytes);
}

#[test]
fn phase4_scalar_coin_boundaries_and_component_identities_are_separate() {
    assert!(PublicSyntheticPhase4DeriverAClientScalarCoinV1::new(SCALAR_ORDER_LE).is_err());
    assert!(PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1::new(SCALAR_ORDER_LE).is_err());
    assert!(PublicSyntheticPhase4DeriverBClientScalarCoinV1::new(SCALAR_ORDER_LE).is_err());
    assert!(PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1::new(SCALAR_ORDER_LE).is_err());
    assert!(PHASE4_PRIVATE_OUTPUT_ACTIVATION_INPUT_SCHEMA_V1.contains("joint-coins"));
    assert!(PHASE4_PRIVATE_OUTPUT_ACTIVATION_OUTPUT_SCHEMA_V1.contains("role-separated"));
    assert!(PHASE4_PRIVATE_OUTPUT_EXPORT_INPUT_SCHEMA_V1.contains("joint-coins"));
    assert!(PHASE4_PRIVATE_OUTPUT_EXPORT_OUTPUT_SCHEMA_V1.contains("role-separated"));
    assert_eq!(activation_core().canonical_encoding()[8], 0x93);
    assert_eq!(activation_core().canonical_schedule_encoding()[8], 0x93);
    assert_eq!(export_core().canonical_encoding()[8], 0x94);
    assert_eq!(export_core().canonical_schedule_encoding()[8], 0x94);
}

#[test]
fn phase4_artifacts_regenerate_and_report_exact_metrics() {
    let activation_again = compile_phase4_private_output_activation_core_v1();
    assert_eq!(
        activation_core().canonical_encoding(),
        activation_again.canonical_encoding()
    );
    assert_eq!(
        activation_core().canonical_schedule_encoding(),
        activation_again.canonical_schedule_encoding()
    );
    let export_again = compile_phase4_private_output_export_core_v1();
    assert_eq!(
        export_core().canonical_encoding(),
        export_again.canonical_encoding()
    );
    assert_eq!(
        export_core().canonical_schedule_encoding(),
        export_again.canonical_schedule_encoding()
    );

    let activation_metrics = activation_core().metrics();
    let activation_schedule = activation_core().schedule_metrics();
    let export_metrics = export_core().metrics();
    let export_schedule = export_core().schedule_metrics();
    assert_eq!(activation_metrics.input_wire_count(), 3_072);
    assert_eq!(activation_metrics.output_wire_count(), 1_024);
    assert_eq!(activation_metrics.wire_count(), 385_122);
    assert_eq!(activation_metrics.and_gate_count(), 65_780);
    assert_eq!(activation_metrics.xor_gate_count(), 304_223);
    assert_eq!(activation_metrics.inversion_gate_count(), 12_047);
    assert_eq!(activation_metrics.total_gate_count(), 382_050);
    assert_eq!(activation_metrics.circuit_depth(), 18_673);
    assert_eq!(activation_metrics.and_depth(), 5_980);
    assert_eq!(activation_metrics.canonical_encoding_bytes(), 3_442_632);
    assert_eq!(activation_metrics.and_gate_count() * 32, 2_104_960);
    assert_eq!(activation_schedule.input_wire_count(), 3_072);
    assert_eq!(activation_schedule.output_wire_count(), 1_024);
    assert_eq!(activation_schedule.scheduled_gate_count(), 382_050);
    assert_eq!(activation_schedule.reusable_slot_count(), 6_785);
    assert_eq!(activation_schedule.slot_width_bytes(), 2);
    assert_eq!(activation_schedule.gate_record_width_bytes(), 7);
    assert_eq!(activation_schedule.encoded_schedule_bytes(), 2_676_456);
    assert_eq!(
        activation_core()
            .benchmark_component_digest()
            .expose_public_bytes(),
        [
            0x65, 0xb0, 0x01, 0xc2, 0xf9, 0x4d, 0xe2, 0x7e, 0xe8, 0xcb, 0x9f, 0x0c, 0x07, 0x73,
            0xfb, 0xe5, 0x42, 0x58, 0xce, 0xab, 0x43, 0xd1, 0x83, 0x17, 0x4b, 0xee, 0x71, 0x0e,
            0xe8, 0xaa, 0x54, 0x6d,
        ]
    );
    assert_eq!(
        activation_core()
            .benchmark_schedule_digest()
            .expose_public_bytes(),
        [
            0xfb, 0x04, 0xa1, 0x39, 0xde, 0xc1, 0x5e, 0x9d, 0x52, 0xe4, 0x96, 0xdc, 0x4f, 0xc0,
            0x11, 0xcf, 0x88, 0x5c, 0x8f, 0x3f, 0x6f, 0x2d, 0x18, 0xbf, 0x38, 0x60, 0xe4, 0x60,
            0x71, 0xf0, 0xe6, 0x9a,
        ]
    );
    assert_eq!(export_metrics.input_wire_count(), 1_536);
    assert_eq!(export_metrics.output_wire_count(), 512);
    assert_eq!(export_metrics.wire_count(), 9_436);
    assert_eq!(export_metrics.and_gate_count(), 1_275);
    assert_eq!(export_metrics.xor_gate_count(), 6_365);
    assert_eq!(export_metrics.inversion_gate_count(), 260);
    assert_eq!(export_metrics.total_gate_count(), 7_900);
    assert_eq!(export_metrics.circuit_depth(), 768);
    assert_eq!(export_metrics.and_depth(), 255);
    assert_eq!(export_metrics.canonical_encoding_bytes(), 73_234);
    assert_eq!(export_metrics.and_gate_count() * 32, 40_800);
    assert_eq!(export_schedule.input_wire_count(), 1_536);
    assert_eq!(export_schedule.output_wire_count(), 512);
    assert_eq!(export_schedule.scheduled_gate_count(), 7_900);
    assert_eq!(export_schedule.reusable_slot_count(), 1_537);
    assert_eq!(export_schedule.slot_width_bytes(), 2);
    assert_eq!(export_schedule.gate_record_width_bytes(), 7);
    assert_eq!(export_schedule.encoded_schedule_bytes(), 56_382);
    assert_eq!(
        export_core()
            .benchmark_component_digest()
            .expose_public_bytes(),
        [
            0x31, 0xb0, 0x3d, 0x13, 0xe4, 0x1a, 0x72, 0x83, 0x42, 0xae, 0xdc, 0xe7, 0xaf, 0x40,
            0xf5, 0x40, 0x5d, 0xc5, 0x98, 0xd2, 0x8e, 0x78, 0x4d, 0xe4, 0x4d, 0x80, 0x44, 0xdb,
            0x9c, 0x60, 0x1a, 0x0c,
        ]
    );
    assert_eq!(
        export_core()
            .benchmark_schedule_digest()
            .expose_public_bytes(),
        [
            0x66, 0xdd, 0xc2, 0x0f, 0x84, 0x07, 0xe3, 0x69, 0xb7, 0x4f, 0x2a, 0x21, 0x02, 0x87,
            0xd2, 0x13, 0x1e, 0x78, 0xc7, 0x52, 0x5f, 0x47, 0xfc, 0x82, 0x9c, 0x57, 0xf6, 0x41,
            0x8b, 0x0d, 0x97, 0xd0,
        ]
    );
}
