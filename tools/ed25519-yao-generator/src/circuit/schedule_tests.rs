use super::ir::{CircuitBuilder, CircuitEvalError};
use super::schedule::{encoded_slot_width, CanonicalLivenessScheduleV1, ScheduleEvalErrorV1};
use super::{
    compile_fixed_sha512_32_v1, compile_provisional_activation_core_v1,
    compile_provisional_export_core_v1,
};

fn lsb0_seed_bits(seed: [u8; 32]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(256);
    for byte in seed {
        for bit_index in 0..8 {
            bits.push(((byte >> bit_index) & 1) == 1);
        }
    }
    bits
}

#[test]
fn liveness_reuses_smallest_dead_slot_and_pins_outputs() {
    assert!(encoded_slot_width(0).is_err());
    assert_eq!(encoded_slot_width(0x100).unwrap(), 1);
    assert_eq!(encoded_slot_width(0x101).unwrap(), 2);
    assert_eq!(encoded_slot_width(0x1_0000).unwrap(), 2);
    assert_eq!(encoded_slot_width(0x1_0001).unwrap(), 3);
    assert_eq!(encoded_slot_width(0x100_0000).unwrap(), 3);
    assert_eq!(encoded_slot_width(0x100_0001).unwrap(), 4);

    let mut builder = CircuitBuilder::new(3).expect("three-input builder");
    let inputs = builder.input_bits();
    let kept_output = builder.xor(inputs[0], inputs[1]);
    let temporary = builder.and(inputs[1], inputs[2]);
    let final_output = builder.xor(temporary, inputs[0]);
    let circuit = builder
        .finish_test_circuit(vec![kept_output, final_output])
        .expect("test circuit finalizes");
    let schedule = CanonicalLivenessScheduleV1::derive(&circuit);

    assert_eq!(
        schedule.records().collect::<Vec<_>>(),
        vec![(1, 0, 1, 3), (2, 1, 2, 1), (1, 0, 1, 0)]
    );
    assert_eq!(schedule.output_slots(), [3, 0]);
    assert_eq!(schedule.metrics().input_wire_count(), 3);
    assert_eq!(schedule.metrics().output_wire_count(), 2);
    assert_eq!(schedule.metrics().scheduled_gate_count(), 3);
    assert_eq!(schedule.metrics().reusable_slot_count(), 4);
    assert_eq!(schedule.metrics().slot_width_bytes(), 1);
    assert_eq!(schedule.metrics().gate_record_width_bytes(), 4);
    assert_eq!(schedule.metrics().encoded_schedule_bytes(), 72);
    assert_eq!(&schedule.canonical_encoding()[..8], b"EYAOSC01");
    assert_eq!(schedule.canonical_encoding()[8], 0xff);

    for encoded_input in 0u8..8 {
        let inputs = [
            (encoded_input & 1) != 0,
            (encoded_input & 2) != 0,
            (encoded_input & 4) != 0,
        ];
        assert_eq!(
            schedule.evaluate(&inputs).expect("scheduled inputs match"),
            circuit.evaluate(&inputs).expect("IR inputs match")
        );
    }
    assert!(matches!(
        schedule.evaluate(&[false, true]),
        Err(ScheduleEvalErrorV1::InputCountMismatch {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        circuit.evaluate(&[false, true]),
        Err(CircuitEvalError::InputCountMismatch {
            expected: 3,
            actual: 2
        })
    ));
}

#[test]
fn scheduled_sha_evaluator_matches_unscheduled_ir() {
    let fixed = compile_fixed_sha512_32_v1();
    let mut incremental = [0u8; 32];
    for (index, byte) in incremental.iter_mut().enumerate() {
        *byte = u8::try_from(index).expect("32-byte index fits u8");
    }
    for seed in [[0u8; 32], [0xff; 32], incremental] {
        let input_bits = lsb0_seed_bits(seed);
        assert_eq!(
            fixed
                .schedule
                .evaluate(&input_bits)
                .expect("scheduled SHA inputs match"),
            fixed
                .circuit
                .evaluate(&input_bits)
                .expect("IR SHA inputs match")
        );
    }
}

#[test]
fn fixed_schedule_artifacts_regenerate_with_frozen_metrics() {
    let first_sha = compile_fixed_sha512_32_v1();
    let second_sha = compile_fixed_sha512_32_v1();
    assert_eq!(
        first_sha.canonical_schedule_encoding(),
        second_sha.canonical_schedule_encoding()
    );
    assert_eq!(
        first_sha.benchmark_schedule_digest(),
        second_sha.benchmark_schedule_digest()
    );

    let first_activation = compile_provisional_activation_core_v1();
    let second_activation = compile_provisional_activation_core_v1();
    assert_eq!(
        first_activation.canonical_schedule_encoding(),
        second_activation.canonical_schedule_encoding()
    );
    assert_eq!(
        first_activation.benchmark_schedule_digest(),
        second_activation.benchmark_schedule_digest()
    );

    let first_export = compile_provisional_export_core_v1();
    let second_export = compile_provisional_export_core_v1();
    assert_eq!(
        first_export.canonical_schedule_encoding(),
        second_export.canonical_schedule_encoding()
    );
    assert_eq!(
        first_export.benchmark_schedule_digest(),
        second_export.benchmark_schedule_digest()
    );

    let sha_metrics = first_sha.schedule_metrics();
    assert_eq!(sha_metrics.input_wire_count(), 256);
    assert_eq!(sha_metrics.output_wire_count(), 512);
    assert_eq!(sha_metrics.scheduled_gate_count(), 330_857);
    assert_eq!(sha_metrics.reusable_slot_count(), 4_737);
    assert_eq!(sha_metrics.slot_width_bytes(), 2);
    assert_eq!(sha_metrics.gate_record_width_bytes(), 7);
    assert_eq!(sha_metrics.encoded_schedule_bytes(), 2_317_081);
    assert_eq!(
        first_sha.benchmark_schedule_digest().expose_public_bytes(),
        [
            0x0d, 0x7c, 0x79, 0xa0, 0xab, 0x31, 0xb2, 0xae, 0x04, 0xb9, 0x13, 0x19, 0x35, 0x5b,
            0xb7, 0x9a, 0xef, 0x32, 0xc5, 0xf3, 0xd5, 0xf8, 0x53, 0x2a, 0x3d, 0xb6, 0x32, 0xb1,
            0x21, 0xf6, 0x27, 0xda,
        ]
    );

    let activation_metrics = first_activation.schedule_metrics();
    assert_eq!(activation_metrics.input_wire_count(), 2_048);
    assert_eq!(activation_metrics.output_wire_count(), 512);
    assert_eq!(activation_metrics.scheduled_gate_count(), 367_240);
    assert_eq!(activation_metrics.reusable_slot_count(), 5_761);
    assert_eq!(activation_metrics.slot_width_bytes(), 2);
    assert_eq!(activation_metrics.gate_record_width_bytes(), 7);
    assert_eq!(activation_metrics.encoded_schedule_bytes(), 2_571_762);
    assert_eq!(
        first_activation
            .benchmark_schedule_digest()
            .expose_public_bytes(),
        [
            0xe0, 0xf9, 0xdf, 0xb3, 0xf3, 0xb8, 0x5e, 0xab, 0x28, 0xfb, 0xab, 0x81, 0x78, 0x8e,
            0x0e, 0xfe, 0xa2, 0x5d, 0xac, 0x7c, 0x8d, 0xe2, 0x07, 0xaf, 0x8c, 0xe9, 0xe5, 0x75,
            0x67, 0xc6, 0xad, 0x25,
        ]
    );

    let export_metrics = first_export.schedule_metrics();
    assert_eq!(export_metrics.input_wire_count(), 1_024);
    assert_eq!(export_metrics.output_wire_count(), 256);
    assert_eq!(export_metrics.scheduled_gate_count(), 4_584);
    assert_eq!(export_metrics.reusable_slot_count(), 1_025);
    assert_eq!(export_metrics.slot_width_bytes(), 2);
    assert_eq!(export_metrics.gate_record_width_bytes(), 7);
    assert_eq!(export_metrics.encoded_schedule_bytes(), 32_658);
    assert_eq!(
        first_export
            .benchmark_schedule_digest()
            .expose_public_bytes(),
        [
            0xbb, 0x4b, 0x0b, 0x1d, 0xe8, 0x7b, 0xaa, 0x1b, 0xf7, 0xb1, 0x90, 0xc8, 0xc5, 0x75,
            0x38, 0xa6, 0x73, 0x67, 0x09, 0x14, 0x83, 0xa4, 0xcb, 0x08, 0xab, 0xc1, 0xa2, 0x39,
            0x2f, 0x55, 0xb0, 0x71,
        ]
    );
    assert_eq!(&first_sha.canonical_schedule_encoding()[..8], b"EYAOSC01");
    assert_eq!(first_sha.canonical_schedule_encoding()[8], 0x81);
    assert_eq!(first_activation.canonical_schedule_encoding()[8], 0x91);
    assert_eq!(first_export.canonical_schedule_encoding()[8], 0x92);
}
