use super::ir::{BuilderBit, CanonicalBooleanCircuitV1, CircuitBuilder};
use super::schedule::CanonicalLivenessScheduleV1;

/// Canonical field, byte, and bit traversal for the fixed component.
pub const FIXED_SHA512_32_BIT_ORDER_V1: &str =
    "field-order, then byte-index ascending, then bit-index 0..7 (LSB0)";
/// Canonical input-schema bytes bound into the fixed component encoding.
pub const FIXED_SHA512_32_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/input/v1:seed[32]:byte-major-lsb0";
/// Canonical output-schema bytes bound into the fixed component encoding.
pub const FIXED_SHA512_32_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/output/v1:digest[64]:byte-major-lsb0";

type Word = [BuilderBit; 64];

const ZERO_BIT: BuilderBit = BuilderBit::Constant(false);

const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SHA512_ROUND_CONSTANTS: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub(super) fn compile_fixed_sha512_32() -> CanonicalBooleanCircuitV1 {
    let mut builder = CircuitBuilder::new(256).expect("fixed SHA-512 circuit has inputs");
    let input_bits: [BuilderBit; 256] = builder
        .input_bits()
        .try_into()
        .expect("fixed SHA-512 input has 256 bits");
    let outputs = sha512_fixed_32_bits(&mut builder, input_bits);
    builder
        .finish_fixed_sha512_32(outputs.to_vec())
        .expect("fixed SHA-512 circuit topology is canonical")
}

pub(super) fn sha512_fixed_32_bits(
    builder: &mut CircuitBuilder,
    input_bits: [BuilderBit; 256],
) -> [BuilderBit; 512] {
    let mut schedule = [[ZERO_BIT; 64]; 80];
    initialize_fixed_schedule(&input_bits, &mut schedule);
    extend_schedule(builder, &mut schedule);

    let mut state = initial_state_words();
    let initial_state = state;
    for round in 0..80 {
        state = compress_round(
            builder,
            state,
            schedule[round],
            SHA512_ROUND_CONSTANTS[round],
        );
    }

    let mut digest_words = [[ZERO_BIT; 64]; 8];
    for index in 0..8 {
        digest_words[index] = add_words(builder, initial_state[index], state[index]);
    }
    digest_words_to_byte_major_lsb0(digest_words)
}

pub(super) fn evaluate_fixed_sha512_32(
    schedule: &CanonicalLivenessScheduleV1,
    seed: [u8; 32],
) -> [u8; 64] {
    let input_bits = bytes_to_lsb0_bits(&seed);
    let output_bits = schedule
        .evaluate(&input_bits)
        .expect("fixed 32-byte input has the canonical bit count");
    lsb0_bits_to_64_bytes(&output_bits)
}

fn initialize_fixed_schedule(input_bits: &[BuilderBit], schedule: &mut [Word; 80]) {
    for (word_index, schedule_word) in schedule[..4].iter_mut().enumerate() {
        let byte_base = word_index * 8;
        for (bit_index, output_bit) in schedule_word.iter_mut().enumerate() {
            let source_byte = byte_base + 7 - (bit_index / 8);
            let source_bit = bit_index % 8;
            *output_bit = input_bits[source_byte * 8 + source_bit];
        }
    }
    schedule[4] = constant_word(0x8000_0000_0000_0000);
    schedule[15] = constant_word(256);
}

fn extend_schedule(builder: &mut CircuitBuilder, schedule: &mut [Word; 80]) {
    for index in 16..80 {
        let sigma_one = small_sigma_one(builder, schedule[index - 2]);
        let first = add_words(builder, sigma_one, schedule[index - 7]);
        let sigma_zero = small_sigma_zero(builder, schedule[index - 15]);
        let second = add_words(builder, first, sigma_zero);
        schedule[index] = add_words(builder, second, schedule[index - 16]);
    }
}

fn compress_round(
    builder: &mut CircuitBuilder,
    state: [Word; 8],
    schedule_word: Word,
    round_constant: u64,
) -> [Word; 8] {
    let [a, b, c, d, e, f, g, h] = state;
    let sigma_one = big_sigma_one(builder, e);
    let choice = choose_word(builder, e, f, g);
    let mut temporary_one = add_words(builder, h, sigma_one);
    temporary_one = add_words(builder, temporary_one, choice);
    temporary_one = add_words(builder, temporary_one, constant_word(round_constant));
    temporary_one = add_words(builder, temporary_one, schedule_word);

    let sigma_zero = big_sigma_zero(builder, a);
    let majority = majority_word(builder, a, b, c);
    let temporary_two = add_words(builder, sigma_zero, majority);
    let next_e = add_words(builder, d, temporary_one);
    let next_a = add_words(builder, temporary_one, temporary_two);

    [next_a, a, b, c, next_e, e, f, g]
}

fn initial_state_words() -> [Word; 8] {
    let mut state = [[ZERO_BIT; 64]; 8];
    for index in 0..8 {
        state[index] = constant_word(SHA512_INITIAL_STATE[index]);
    }
    state
}

fn constant_word(value: u64) -> Word {
    let mut word = [ZERO_BIT; 64];
    for (index, bit) in word.iter_mut().enumerate() {
        *bit = BuilderBit::Constant(((value >> index) & 1) == 1);
    }
    word
}

fn add_words(builder: &mut CircuitBuilder, left: Word, right: Word) -> Word {
    let mut output = [ZERO_BIT; 64];
    let mut carry = ZERO_BIT;
    for index in 0..64 {
        let left_xor_right = builder.xor(left[index], right[index]);
        output[index] = builder.xor(left_xor_right, carry);
        if index < 63 {
            let left_xor_carry = builder.xor(left[index], carry);
            let right_xor_carry = builder.xor(right[index], carry);
            let carry_product = builder.and(left_xor_carry, right_xor_carry);
            carry = builder.xor(carry, carry_product);
        }
    }
    output
}

fn choose_word(builder: &mut CircuitBuilder, e: Word, f: Word, g: Word) -> Word {
    let mut output = [ZERO_BIT; 64];
    for index in 0..64 {
        let f_xor_g = builder.xor(f[index], g[index]);
        let selected_difference = builder.and(e[index], f_xor_g);
        output[index] = builder.xor(g[index], selected_difference);
    }
    output
}

fn majority_word(builder: &mut CircuitBuilder, a: Word, b: Word, c: Word) -> Word {
    let mut output = [ZERO_BIT; 64];
    for index in 0..64 {
        let a_xor_c = builder.xor(a[index], c[index]);
        let b_xor_c = builder.xor(b[index], c[index]);
        let product = builder.and(a_xor_c, b_xor_c);
        output[index] = builder.xor(c[index], product);
    }
    output
}

fn big_sigma_zero(builder: &mut CircuitBuilder, word: Word) -> Word {
    xor_three_words(
        builder,
        rotate_right(word, 28),
        rotate_right(word, 34),
        rotate_right(word, 39),
    )
}

fn big_sigma_one(builder: &mut CircuitBuilder, word: Word) -> Word {
    xor_three_words(
        builder,
        rotate_right(word, 14),
        rotate_right(word, 18),
        rotate_right(word, 41),
    )
}

fn small_sigma_zero(builder: &mut CircuitBuilder, word: Word) -> Word {
    xor_three_words(
        builder,
        rotate_right(word, 1),
        rotate_right(word, 8),
        shift_right(word, 7),
    )
}

fn small_sigma_one(builder: &mut CircuitBuilder, word: Word) -> Word {
    xor_three_words(
        builder,
        rotate_right(word, 19),
        rotate_right(word, 61),
        shift_right(word, 6),
    )
}

fn xor_three_words(builder: &mut CircuitBuilder, first: Word, second: Word, third: Word) -> Word {
    let mut output = [ZERO_BIT; 64];
    for index in 0..64 {
        let first_pair = builder.xor(first[index], second[index]);
        output[index] = builder.xor(first_pair, third[index]);
    }
    output
}

fn rotate_right(word: Word, amount: usize) -> Word {
    let mut output = [ZERO_BIT; 64];
    for index in 0..64 {
        output[index] = word[(index + amount) % 64];
    }
    output
}

fn shift_right(word: Word, amount: usize) -> Word {
    let mut output = [ZERO_BIT; 64];
    output[..(64 - amount)].copy_from_slice(&word[amount..]);
    output
}

fn digest_words_to_byte_major_lsb0(words: [Word; 8]) -> [BuilderBit; 512] {
    let mut outputs = [ZERO_BIT; 512];
    let mut output_index = 0usize;
    for word in words {
        for byte_index in 0..8 {
            for bit_index in 0..8 {
                outputs[output_index] = word[(7 - byte_index) * 8 + bit_index];
                output_index += 1;
            }
        }
    }
    outputs
}

fn bytes_to_lsb0_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit_index in 0..8 {
            bits.push(((byte >> bit_index) & 1) == 1);
        }
    }
    bits
}

fn lsb0_bits_to_64_bytes(bits: &[bool]) -> [u8; 64] {
    assert_eq!(bits.len(), 512, "SHA-512 output has 512 bits");
    let mut bytes = [0u8; 64];
    for byte_index in 0..64 {
        for bit_index in 0..8 {
            if bits[byte_index * 8 + bit_index] {
                bytes[byte_index] |= 1 << bit_index;
            }
        }
    }
    bytes
}

#[cfg(test)]
pub(super) fn fixed_message_words_clear(seed: [u8; 32]) -> [u64; 16] {
    let mut words = [0u64; 16];
    for (index, chunk) in seed.chunks_exact(8).enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        words[index] = u64::from_be_bytes(bytes);
    }
    words[4] = 0x8000_0000_0000_0000;
    words[15] = 256;
    words
}
