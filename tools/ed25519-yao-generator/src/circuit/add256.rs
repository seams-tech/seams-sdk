use super::ir::{BuilderBit, CircuitBuilder};

const BIT_WIDTH: usize = 256;
const ZERO: BuilderBit = BuilderBit::Constant(false);

pub(super) fn wrapping_add_le_256_bits(
    builder: &mut CircuitBuilder,
    left: [BuilderBit; BIT_WIDTH],
    right: [BuilderBit; BIT_WIDTH],
) -> [BuilderBit; BIT_WIDTH] {
    add_le_256_bits::<false>(builder, left, right).0
}

pub(super) fn add_le_256_with_final_carry_bits(
    builder: &mut CircuitBuilder,
    left: [BuilderBit; BIT_WIDTH],
    right: [BuilderBit; BIT_WIDTH],
) -> ([BuilderBit; BIT_WIDTH], BuilderBit) {
    add_le_256_bits::<true>(builder, left, right)
}

fn add_le_256_bits<const COMPUTE_FINAL_CARRY: bool>(
    builder: &mut CircuitBuilder,
    left: [BuilderBit; BIT_WIDTH],
    right: [BuilderBit; BIT_WIDTH],
) -> ([BuilderBit; BIT_WIDTH], BuilderBit) {
    let mut output = [ZERO; BIT_WIDTH];
    let mut carry = ZERO;

    for bit_index in 0..BIT_WIDTH {
        let left_xor_right = builder.xor(left[bit_index], right[bit_index]);
        output[bit_index] = builder.xor(left_xor_right, carry);
        if bit_index + 1 < BIT_WIDTH || COMPUTE_FINAL_CARRY {
            carry = next_carry(builder, left[bit_index], right[bit_index], carry);
        }
    }

    (output, carry)
}

fn next_carry(
    builder: &mut CircuitBuilder,
    left: BuilderBit,
    right: BuilderBit,
    carry: BuilderBit,
) -> BuilderBit {
    let left_xor_carry = builder.xor(left, carry);
    let right_xor_carry = builder.xor(right, carry);
    let carry_product = builder.and(left_xor_carry, right_xor_carry);
    builder.xor(carry, carry_product)
}
