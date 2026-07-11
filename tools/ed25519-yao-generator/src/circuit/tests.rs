use std::sync::OnceLock;

use sha2::{Digest, Sha512};

use crate::{canonical_vector_corpus_v1, differential_vector_corpus_v1};

use super::ir::{BuilderBit, CircuitBuilder, Gate};
use super::sha512::fixed_message_words_clear;
use super::{compile_fixed_sha512_32_v1, FixedSha512CircuitV1};

fn fixed_sha512_circuit() -> &'static FixedSha512CircuitV1 {
    static CIRCUIT: OnceLock<FixedSha512CircuitV1> = OnceLock::new();
    CIRCUIT.get_or_init(compile_fixed_sha512_32_v1)
}

fn expected_sha512(seed: [u8; 32]) -> [u8; 64] {
    Sha512::digest(seed).into()
}

fn incremental_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::try_from(index).expect("32-byte index fits u8");
    }
    seed
}

fn single_bit_seed(bit_index: usize) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[bit_index / 8] = 1 << (bit_index % 8);
    seed
}

fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture hex is lowercase ASCII"),
    }
}

fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2, "fixture hex has the expected width");
    let encoded = hex.as_bytes();
    let mut decoded = [0u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = (decode_hex_nibble(encoded[index * 2]) << 4)
            | decode_hex_nibble(encoded[index * 2 + 1]);
    }
    decoded
}

fn assert_corpus_sha512_matches(circuit: &FixedSha512CircuitV1, public_test_seed: [u8; 32]) {
    let mut corpora = vec![canonical_vector_corpus_v1()];
    corpora.push(
        differential_vector_corpus_v1(public_test_seed, 128)
            .expect("public differential corpus is valid"),
    );
    for corpus in corpora {
        for case in corpus.cases {
            let trace = case.clear_reference_trace();
            let seed = decode_hex_array::<32>(&trace.joined_seed_hex);
            let expected = decode_hex_array::<64>(&trace.sha512_digest_hex);
            assert_eq!(circuit.evaluate_public_synthetic_seed(seed), expected);
        }
    }
}

#[test]
fn gate_builder_folds_constants_and_canonicalizes_commutative_inputs() {
    let mut builder = CircuitBuilder::new(2).expect("two-input builder");
    let inputs = builder.input_bits();
    let BuilderBit::Wire(first_wire) = inputs[0] else {
        panic!("input is a wire");
    };
    let BuilderBit::Wire(second_wire) = inputs[1] else {
        panic!("input is a wire");
    };

    assert_eq!(
        builder.xor(inputs[0], BuilderBit::Constant(false)),
        inputs[0]
    );
    assert_eq!(
        builder.and(inputs[1], BuilderBit::Constant(true)),
        inputs[1]
    );
    assert_eq!(
        builder.xor(inputs[0], inputs[0]),
        BuilderBit::Constant(false)
    );

    let xor = builder.xor(inputs[1], inputs[0]);
    let and = builder.and(inputs[1], inputs[0]);
    let inv = builder.inv(inputs[0]);
    assert_eq!(
        builder.gates,
        vec![
            Gate::Xor {
                left: first_wire,
                right: second_wire,
            },
            Gate::And {
                left: first_wire,
                right: second_wire,
            },
            Gate::Inv { input: first_wire },
        ]
    );
    let _dead_gate = builder.xor(inv, and);

    let circuit = builder
        .finish_test_circuit(vec![xor, and, inv])
        .expect("test circuit finalizes");
    assert_eq!(circuit.metrics().total_gate_count(), 3);
    assert_eq!(
        circuit.evaluate(&[false, false]).unwrap(),
        [false, false, true]
    );
    assert_eq!(
        circuit.evaluate(&[false, true]).unwrap(),
        [true, false, true]
    );
    assert_eq!(
        circuit.evaluate(&[true, false]).unwrap(),
        [true, false, false]
    );
    assert_eq!(
        circuit.evaluate(&[true, true]).unwrap(),
        [false, true, false]
    );

    let mut wrong_input_count = CircuitBuilder::new(2).expect("test builder");
    let inputs = wrong_input_count.input_bits();
    let output = wrong_input_count.xor(inputs[0], inputs[1]);
    assert!(matches!(
        wrong_input_count.finish_fixed_sha512_32(vec![output]),
        Err(super::ir::CircuitBuildError::InputSchemaWireCountMismatch)
    ));

    let mut wrong_output_count = CircuitBuilder::new(256).expect("fixed input width");
    let inputs = wrong_output_count.input_bits();
    let output = wrong_output_count.xor(inputs[0], inputs[1]);
    assert!(matches!(
        wrong_output_count.finish_fixed_sha512_32(vec![output]),
        Err(super::ir::CircuitBuildError::OutputSchemaWireCountMismatch)
    ));

    let mut dead_only = CircuitBuilder::new(2).expect("test builder");
    let inputs = dead_only.input_bits();
    let _dead = dead_only.xor(inputs[0], inputs[1]);
    assert!(matches!(
        dead_only.finish_test_circuit(vec![inputs[0]]),
        Err(super::ir::CircuitBuildError::EmptyGates)
    ));
}

#[test]
fn specialized_padding_and_big_endian_word_mapping_are_exact() {
    let seed = incremental_seed();
    let words = fixed_message_words_clear(seed);
    assert_eq!(words[0], 0x0001_0203_0405_0607);
    assert_eq!(words[1], 0x0809_0a0b_0c0d_0e0f);
    assert_eq!(words[2], 0x1011_1213_1415_1617);
    assert_eq!(words[3], 0x1819_1a1b_1c1d_1e1f);
    assert_eq!(words[4], 0x8000_0000_0000_0000);
    assert_eq!(&words[5..15], &[0u64; 10]);
    assert_eq!(words[15], 0x0000_0000_0000_0100);
}

#[test]
fn fixed_sha512_matches_sha2_across_endian_boundaries() {
    let circuit = fixed_sha512_circuit();
    let mut cases = vec![[0u8; 32], [0xffu8; 32], incremental_seed()];
    for bit_index in [0usize, 7, 8, 63, 64, 127, 248, 253, 254, 255] {
        cases.push(single_bit_seed(bit_index));
    }

    for seed in cases {
        assert_eq!(
            circuit.evaluate_public_synthetic_seed(seed),
            expected_sha512(seed),
            "fixed circuit disagrees for seed {seed:02x?}"
        );
    }
    assert_corpus_sha512_matches(circuit, [0x5a; 32]);
}

#[test]
fn fixed_sha512_ir_regenerates_byte_for_byte() {
    let first = compile_fixed_sha512_32_v1();
    let second = compile_fixed_sha512_32_v1();
    assert_eq!(first.canonical_encoding(), second.canonical_encoding());
    assert_eq!(
        first.benchmark_component_digest(),
        second.benchmark_component_digest()
    );
    assert_eq!(first.metrics(), second.metrics());
    assert_eq!(&first.canonical_encoding()[..8], b"EYAOIR01");
    assert_eq!(first.canonical_encoding()[8], 0x81);
    assert_eq!(first.canonical_encoding()[9], 1);
}

#[test]
fn fixed_sha512_metrics_and_digest_are_frozen() {
    let circuit = fixed_sha512_circuit();
    let metrics = circuit.metrics();
    assert_eq!(metrics.input_wire_count(), 256);
    assert_eq!(metrics.output_wire_count(), 512);
    assert_eq!(metrics.wire_count(), 331_113);
    assert_eq!(metrics.and_gate_count(), 54_868);
    assert_eq!(metrics.xor_gate_count(), 269_622);
    assert_eq!(metrics.inversion_gate_count(), 6_367);
    assert_eq!(metrics.total_gate_count(), 330_857);
    assert_eq!(metrics.circuit_depth(), 10_675);
    assert_eq!(metrics.and_depth(), 3_301);
    assert_eq!(metrics.canonical_encoding_bytes(), 2_979_847);
    assert_eq!(
        circuit.benchmark_component_digest().expose_public_bytes(),
        [
            0x11, 0x48, 0x8a, 0xe3, 0xb4, 0x77, 0x22, 0xd4, 0x2d, 0x4f, 0xc7, 0xe2, 0xd0, 0x3f,
            0xa2, 0x68, 0x43, 0x12, 0x88, 0x7a, 0xb9, 0x3c, 0x3c, 0x9a, 0x0b, 0x08, 0x00, 0x21,
            0xb4, 0x68, 0xf5, 0x3b,
        ]
    );
}
