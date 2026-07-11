use sha2::{Digest, Sha256};

use crate::{clamp_rfc8032, wrapping_add_le_256};

use super::add256::wrapping_add_le_256_bits;
use super::clamp::clamp_rfc8032_bits;
use super::ir::{BuilderBit, CircuitBuilder, Gate};

const BYTE_WIDTH: usize = 32;
const BIT_WIDTH: usize = BYTE_WIDTH * 8;

fn byte_major_lsb0_bits(bytes: [u8; BYTE_WIDTH]) -> [bool; BIT_WIDTH] {
    let mut bits = [false; BIT_WIDTH];
    for (byte_index, byte) in bytes.into_iter().enumerate() {
        for bit_index in 0..8 {
            bits[byte_index * 8 + bit_index] = ((byte >> bit_index) & 1) == 1;
        }
    }
    bits
}

fn byte_major_lsb0_bytes(bits: &[bool]) -> [u8; BYTE_WIDTH] {
    assert_eq!(bits.len(), BIT_WIDTH);
    let mut bytes = [0u8; BYTE_WIDTH];
    for (bit_index, bit) in bits.iter().copied().enumerate() {
        if bit {
            bytes[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }
    bytes
}

fn deterministic_bytes(domain: u8, case_index: u8) -> [u8; BYTE_WIDTH] {
    Sha256::digest(
        [
            b"ed25519-yao-circuit-combinator-v1".as_slice(),
            &[domain, case_index],
        ]
        .concat(),
    )
    .into()
}

fn materialize_constant_output(
    builder: &mut CircuitBuilder,
    anchor: BuilderBit,
    value: bool,
) -> BuilderBit {
    let inverted_anchor = builder.inv(anchor);
    let false_wire = builder.and(anchor, inverted_anchor);
    if value {
        builder.inv(false_wire)
    } else {
        false_wire
    }
}

#[test]
fn wrapping_add_le_256_fragment_preserves_inputs_and_matches_clear_oracle() {
    let mut builder = CircuitBuilder::new(512).expect("512-input builder");
    let inputs = builder.input_bits();
    let original_inputs = inputs.clone();
    let left: [BuilderBit; BIT_WIDTH] = inputs[..BIT_WIDTH]
        .try_into()
        .expect("left input has 256 bits");
    let right: [BuilderBit; BIT_WIDTH] = inputs[BIT_WIDTH..]
        .try_into()
        .expect("right input has 256 bits");

    let outputs = wrapping_add_le_256_bits(&mut builder, left, right);

    assert_eq!(inputs, original_inputs);
    assert!(inputs.iter().all(|bit| matches!(bit, BuilderBit::Wire(_))));
    assert!(outputs.iter().all(|bit| matches!(bit, BuilderBit::Wire(_))));
    assert_eq!(builder.gates.len(), 1_528);
    assert_eq!(
        builder
            .gates
            .iter()
            .filter(|gate| matches!(gate, Gate::And { .. }))
            .count(),
        255
    );

    let circuit = builder
        .finish_test_circuit(outputs.to_vec())
        .expect("addition fragment finalizes for evaluation");
    let mut cases = vec![
        ([0u8; BYTE_WIDTH], [0u8; BYTE_WIDTH]),
        ([0xff; BYTE_WIDTH], {
            let mut one = [0u8; BYTE_WIDTH];
            one[0] = 1;
            one
        }),
        ([0xff; BYTE_WIDTH], [0xff; BYTE_WIDTH]),
        (
            {
                let mut low_byte = [0u8; BYTE_WIDTH];
                low_byte[0] = 0xff;
                low_byte
            },
            {
                let mut one = [0u8; BYTE_WIDTH];
                one[0] = 1;
                one
            },
        ),
    ];
    for bit_index in [0usize, 7, 8, 127, 248, 255] {
        let mut left = [0u8; BYTE_WIDTH];
        let mut right = [0u8; BYTE_WIDTH];
        left[bit_index / 8] = 1 << (bit_index % 8);
        right[bit_index / 8] = 1 << (bit_index % 8);
        cases.push((left, right));
    }
    for case_index in 0..16 {
        cases.push((
            deterministic_bytes(0xa1, case_index),
            deterministic_bytes(0xb2, case_index),
        ));
    }

    for (left, right) in cases {
        let left_bits = byte_major_lsb0_bits(left);
        let right_bits = byte_major_lsb0_bits(right);
        let mut circuit_inputs = Vec::with_capacity(512);
        circuit_inputs.extend_from_slice(&left_bits);
        circuit_inputs.extend_from_slice(&right_bits);
        let evaluated = circuit
            .evaluate(&circuit_inputs)
            .expect("addition inputs have the synthesized width");
        assert_eq!(
            byte_major_lsb0_bytes(&evaluated),
            wrapping_add_le_256(left, right),
            "addition disagrees for left={left:02x?}, right={right:02x?}"
        );
    }
}

#[test]
fn rfc8032_clamp_fragment_folds_fixed_bits_and_matches_clear_oracle() {
    let mut builder = CircuitBuilder::new(256).expect("256-input builder");
    let inputs: [BuilderBit; BIT_WIDTH] = builder
        .input_bits()
        .try_into()
        .expect("clamp input has 256 bits");
    let outputs = clamp_rfc8032_bits(inputs);

    assert!(builder.gates.is_empty());
    for bit_index in 0..BIT_WIDTH {
        let expected = match bit_index {
            0..=2 | 255 => BuilderBit::Constant(false),
            254 => BuilderBit::Constant(true),
            _ => inputs[bit_index],
        };
        assert_eq!(outputs[bit_index], expected, "bit {bit_index}");
        if !matches!(bit_index, 0..=2 | 254 | 255) {
            assert!(matches!(outputs[bit_index], BuilderBit::Wire(_)));
        }
    }

    let anchor = inputs[3];
    let materialized_outputs = outputs.map(|output| match output {
        BuilderBit::Constant(value) => materialize_constant_output(&mut builder, anchor, value),
        wire => wire,
    });
    let circuit = builder
        .finish_test_circuit(materialized_outputs.to_vec())
        .expect("clamp fragment finalizes for evaluation");
    let mut cases = vec![[0u8; BYTE_WIDTH], [0xff; BYTE_WIDTH], {
        let mut incremental = [0u8; BYTE_WIDTH];
        for (index, byte) in incremental.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("32-byte index fits u8");
        }
        incremental
    }];
    for case_index in 0..16 {
        cases.push(deterministic_bytes(0xc3, case_index));
    }

    for input in cases {
        let evaluated = circuit
            .evaluate(&byte_major_lsb0_bits(input))
            .expect("clamp input has the synthesized width");
        assert_eq!(
            byte_major_lsb0_bytes(&evaluated),
            clamp_rfc8032(input),
            "clamp disagrees for input={input:02x?}"
        );
    }
}
