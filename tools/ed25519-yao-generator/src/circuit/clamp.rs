use super::ir::BuilderBit;

const BIT_WIDTH: usize = 256;

pub(super) fn clamp_rfc8032_bits(mut input: [BuilderBit; BIT_WIDTH]) -> [BuilderBit; BIT_WIDTH] {
    input[0] = BuilderBit::Constant(false);
    input[1] = BuilderBit::Constant(false);
    input[2] = BuilderBit::Constant(false);
    input[31 * 8 + 6] = BuilderBit::Constant(true);
    input[31 * 8 + 7] = BuilderBit::Constant(false);
    input
}
