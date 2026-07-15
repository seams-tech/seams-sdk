use super::add256::{
    add_le_256_with_final_carry_bits, subtract_le_256_with_final_no_borrow_bits,
    wrapping_add_le_256_bits,
};
use super::ir::{BuilderBit, CircuitBuilder};

const SCALAR_BIT_WIDTH: usize = 256;
const CLAMPED_REDUCTION_ROUNDS: usize = 7;
const ZERO: BuilderBit = BuilderBit::Constant(false);

const SCALAR_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
const NEGATIVE_SCALAR_ORDER_LE: [u8; 32] = [
    0x13, 0x2c, 0x0a, 0xa3, 0xe5, 0x9c, 0xed, 0xa7, 0x29, 0x63, 0x08, 0x5d, 0x21, 0x06, 0x21, 0xeb,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xef,
];

pub(super) fn reduce_clamped_mod_l_bits(
    builder: &mut CircuitBuilder,
    clamped: [BuilderBit; SCALAR_BIT_WIDTH],
) -> [BuilderBit; SCALAR_BIT_WIDTH] {
    let mut reduced = clamped;
    for _ in 0..CLAMPED_REDUCTION_ROUNDS {
        reduced = conditional_subtract_l_bits(builder, reduced);
    }
    reduced
}

/// Both inputs must be canonical scalar encodings.
pub(super) fn add_mod_l_bits(
    builder: &mut CircuitBuilder,
    left: [BuilderBit; SCALAR_BIT_WIDTH],
    right: [BuilderBit; SCALAR_BIT_WIDTH],
) -> [BuilderBit; SCALAR_BIT_WIDTH] {
    let sum = wrapping_add_le_256_bits(builder, left, right);
    conditional_subtract_l_bits(builder, sum)
}

/// Both inputs must be canonical scalar encodings.
pub(super) fn subtract_mod_l_bits(
    builder: &mut CircuitBuilder,
    left: [BuilderBit; SCALAR_BIT_WIDTH],
    right: [BuilderBit; SCALAR_BIT_WIDTH],
) -> [BuilderBit; SCALAR_BIT_WIDTH] {
    let (difference, no_borrow) = subtract_le_256_with_final_no_borrow_bits(builder, left, right);
    let wrapped = wrapping_add_le_256_bits(builder, difference, constant_bits_le(SCALAR_ORDER_LE));
    select_bits(builder, no_borrow, difference, wrapped)
}

fn conditional_subtract_l_bits(
    builder: &mut CircuitBuilder,
    value: [BuilderBit; SCALAR_BIT_WIDTH],
) -> [BuilderBit; SCALAR_BIT_WIDTH] {
    let negative_order = constant_bits_le(NEGATIVE_SCALAR_ORDER_LE);
    let (difference, no_borrow) = add_le_256_with_final_carry_bits(builder, value, negative_order);
    select_bits(builder, no_borrow, difference, value)
}

fn select_bits(
    builder: &mut CircuitBuilder,
    selector: BuilderBit,
    when_true: [BuilderBit; SCALAR_BIT_WIDTH],
    when_false: [BuilderBit; SCALAR_BIT_WIDTH],
) -> [BuilderBit; SCALAR_BIT_WIDTH] {
    let mut selected = [ZERO; SCALAR_BIT_WIDTH];
    for bit_index in 0..SCALAR_BIT_WIDTH {
        let difference = builder.xor(when_false[bit_index], when_true[bit_index]);
        let selected_difference = builder.and(selector, difference);
        selected[bit_index] = builder.xor(when_false[bit_index], selected_difference);
    }
    selected
}

fn constant_bits_le(bytes: [u8; 32]) -> [BuilderBit; SCALAR_BIT_WIDTH] {
    let mut bits = [ZERO; SCALAR_BIT_WIDTH];
    for (byte_index, byte) in bytes.into_iter().enumerate() {
        for bit_index in 0..8 {
            bits[byte_index * 8 + bit_index] = BuilderBit::Constant(((byte >> bit_index) & 1) == 1);
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    use crate::{clamp_rfc8032, wrapping_add_le_256};

    use super::{
        add_mod_l_bits, reduce_clamped_mod_l_bits, subtract_mod_l_bits, CLAMPED_REDUCTION_ROUNDS,
    };
    use crate::circuit::ir::{BuilderBit, CanonicalBooleanCircuitV1, CircuitBuilder};

    const BYTE_WIDTH: usize = 32;
    const BIT_WIDTH: usize = BYTE_WIDTH * 8;
    const SCALAR_ORDER_LE: [u8; BYTE_WIDTH] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

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

    fn builder_bits(input_bits: &[BuilderBit]) -> [BuilderBit; BIT_WIDTH] {
        input_bits.try_into().expect("scalar input has 256 bits")
    }

    fn reduction_circuit() -> CanonicalBooleanCircuitV1 {
        let mut builder = CircuitBuilder::new(256).expect("256-input reduction builder");
        let input = builder_bits(&builder.input_bits());
        let output = reduce_clamped_mod_l_bits(&mut builder, input);
        builder
            .finish_test_circuit(output.to_vec())
            .expect("reduction circuit finalizes")
    }

    fn addition_circuit() -> CanonicalBooleanCircuitV1 {
        let mut builder = CircuitBuilder::new(512).expect("512-input addition builder");
        let inputs = builder.input_bits();
        let left = builder_bits(&inputs[..BIT_WIDTH]);
        let right = builder_bits(&inputs[BIT_WIDTH..]);
        let output = add_mod_l_bits(&mut builder, left, right);
        builder
            .finish_test_circuit(output.to_vec())
            .expect("modular-addition circuit finalizes")
    }

    fn subtraction_circuit() -> CanonicalBooleanCircuitV1 {
        let mut builder = CircuitBuilder::new(512).expect("512-input subtraction builder");
        let inputs = builder.input_bits();
        let left = builder_bits(&inputs[..BIT_WIDTH]);
        let right = builder_bits(&inputs[BIT_WIDTH..]);
        let output = subtract_mod_l_bits(&mut builder, left, right);
        builder
            .finish_test_circuit(output.to_vec())
            .expect("modular-subtraction circuit finalizes")
    }

    fn tau_aggregation_circuit() -> CanonicalBooleanCircuitV1 {
        let mut builder = CircuitBuilder::new(1_024).expect("four-scalar tau builder");
        let inputs = builder.input_bits();
        let client_a = builder_bits(&inputs[..BIT_WIDTH]);
        let server_a = builder_bits(&inputs[BIT_WIDTH..BIT_WIDTH * 2]);
        let client_b = builder_bits(&inputs[BIT_WIDTH * 2..BIT_WIDTH * 3]);
        let server_b = builder_bits(&inputs[BIT_WIDTH * 3..]);
        let tau_a = add_mod_l_bits(&mut builder, client_a, server_a);
        let tau_b = add_mod_l_bits(&mut builder, client_b, server_b);
        let tau = add_mod_l_bits(&mut builder, tau_a, tau_b);
        builder
            .finish_test_circuit(tau.to_vec())
            .expect("tau aggregation circuit finalizes")
    }

    fn evaluate_one(
        circuit: &CanonicalBooleanCircuitV1,
        input: [u8; BYTE_WIDTH],
    ) -> [u8; BYTE_WIDTH] {
        let output = circuit
            .evaluate(&byte_major_lsb0_bits(input))
            .expect("one-scalar circuit input width matches");
        byte_major_lsb0_bytes(&output)
    }

    fn evaluate_many(
        circuit: &CanonicalBooleanCircuitV1,
        inputs: &[[u8; BYTE_WIDTH]],
    ) -> [u8; BYTE_WIDTH] {
        let mut circuit_inputs = Vec::with_capacity(inputs.len() * BIT_WIDTH);
        for input in inputs {
            circuit_inputs.extend_from_slice(&byte_major_lsb0_bits(*input));
        }
        let output = circuit
            .evaluate(&circuit_inputs)
            .expect("multi-scalar circuit input width matches");
        byte_major_lsb0_bytes(&output)
    }

    fn increment_le(mut value: [u8; BYTE_WIDTH]) -> [u8; BYTE_WIDTH] {
        for byte in &mut value {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        value
    }

    fn decrement_le(mut value: [u8; BYTE_WIDTH]) -> [u8; BYTE_WIDTH] {
        for byte in &mut value {
            let (next, borrow) = byte.overflowing_sub(1);
            *byte = next;
            if !borrow {
                break;
            }
        }
        value
    }

    fn scalar_order_multiple(multiplier: u8) -> [u8; BYTE_WIDTH] {
        let mut multiple = [0u8; BYTE_WIDTH];
        for _ in 0..multiplier {
            multiple = wrapping_add_le_256(multiple, SCALAR_ORDER_LE);
        }
        multiple
    }

    fn deterministic_scalar(domain: u8, case_index: u8) -> Scalar {
        let digest: [u8; 64] = Sha512::digest(
            [
                b"ed25519-yao-scalar-circuit-v1".as_slice(),
                &[domain, case_index],
            ]
            .concat(),
        )
        .into();
        Scalar::from_bytes_mod_order_wide(&digest)
    }

    #[test]
    fn seven_round_reduction_matches_dalek_across_clamped_and_order_boundaries() {
        assert_eq!(CLAMPED_REDUCTION_ROUNDS, 7);
        let circuit = reduction_circuit();
        let one = increment_le([0u8; BYTE_WIDTH]);
        let mut cases = vec![
            [0u8; BYTE_WIDTH],
            one,
            decrement_le(SCALAR_ORDER_LE),
            SCALAR_ORDER_LE,
            increment_le(SCALAR_ORDER_LE),
            clamp_rfc8032([0u8; BYTE_WIDTH]),
            clamp_rfc8032([0xff; BYTE_WIDTH]),
        ];
        for multiplier in 1..=7 {
            let multiple = scalar_order_multiple(multiplier);
            cases.push(decrement_le(multiple));
            cases.push(multiple);
            cases.push(increment_le(multiple));
        }
        for case_index in 0..16 {
            cases.push(clamp_rfc8032(
                deterministic_scalar(0xa1, case_index).to_bytes(),
            ));
        }

        for input in cases {
            assert_eq!(
                evaluate_one(&circuit, input),
                Scalar::from_bytes_mod_order(input).to_bytes(),
                "reduction disagrees for input={input:02x?}"
            );
        }
    }

    #[test]
    fn canonical_modular_addition_matches_dalek() {
        let circuit = addition_circuit();
        let zero = Scalar::ZERO;
        let one = Scalar::ONE;
        let minus_one = -Scalar::ONE;
        let mut cases = vec![
            (zero, zero),
            (zero, minus_one),
            (minus_one, one),
            (minus_one, minus_one),
        ];
        for case_index in 0..24 {
            cases.push((
                deterministic_scalar(0xb2, case_index),
                deterministic_scalar(0xc3, case_index),
            ));
        }

        for (left, right) in cases {
            assert_eq!(
                evaluate_many(&circuit, &[left.to_bytes(), right.to_bytes()]),
                (left + right).to_bytes(),
                "modular addition disagrees"
            );
        }
    }

    #[test]
    fn canonical_modular_subtraction_matches_dalek() {
        let circuit = subtraction_circuit();
        let zero = Scalar::ZERO;
        let one = Scalar::ONE;
        let minus_one = -Scalar::ONE;
        let mut cases = vec![
            (zero, zero),
            (zero, one),
            (zero, minus_one),
            (one, zero),
            (one, one),
            (minus_one, zero),
            (minus_one, minus_one),
        ];
        for case_index in 0..24 {
            cases.push((
                deterministic_scalar(0x28, case_index),
                deterministic_scalar(0x39, case_index),
            ));
        }

        for (left, right) in cases {
            assert_eq!(
                evaluate_many(&circuit, &[left.to_bytes(), right.to_bytes()]),
                (left - right).to_bytes(),
                "modular subtraction disagrees"
            );
        }
    }

    #[test]
    fn repeated_modular_addition_aggregates_four_tau_contributions() {
        let circuit = tau_aggregation_circuit();
        let mut cases = vec![
            [Scalar::ZERO, Scalar::ZERO, Scalar::ZERO, Scalar::ZERO],
            [Scalar::ZERO, -Scalar::ONE, Scalar::ONE, Scalar::ONE],
            [-Scalar::ONE, -Scalar::ONE, -Scalar::ONE, -Scalar::ONE],
        ];
        for case_index in 0..16 {
            cases.push([
                deterministic_scalar(0xd4, case_index),
                deterministic_scalar(0xe5, case_index),
                deterministic_scalar(0xf6, case_index),
                deterministic_scalar(0x17, case_index),
            ]);
        }

        for contributions in cases {
            let input_bytes = contributions.map(|scalar| scalar.to_bytes());
            let expected = contributions
                .into_iter()
                .fold(Scalar::ZERO, |sum, contribution| sum + contribution);
            assert_eq!(
                evaluate_many(&circuit, &input_bytes),
                expected.to_bytes(),
                "tau aggregation disagrees"
            );
        }
    }
}
