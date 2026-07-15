use core::fmt;

use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::Aes128;
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod ot;
mod packages;
mod phase4;
#[cfg(feature = "passive-benchmark")]
pub mod phase5_benchmark;
#[cfg(feature = "passive-benchmark")]
mod phase5_process;
#[cfg(feature = "passive-benchmark")]
pub mod phase5_transport;
#[cfg(any(test, feature = "passive-wasm-benchmark"))]
pub mod phase5_wasm_benchmark;
#[cfg(feature = "passive-benchmark")]
mod process_support;
#[doc(hidden)]
#[cfg(any(test, feature = "phase9-role-benchmark", feature = "local-protocol"))]
pub mod role_protocol;
mod role_protocol_support;
mod roles;
mod runtime;
mod schedule;
mod stream;
#[cfg(feature = "passive-benchmark")]
mod stream_io;
#[cfg(test)]
mod stream_kats;
mod stream_runtime;
#[cfg(test)]
mod stream_runtime_tests;

const LABEL_BYTES: usize = 16;
const AND_GATE_BYTES: usize = 2 * LABEL_BYTES;
const FIXED_AES_KEY: [u8; LABEL_BYTES] = [0_u8; LABEL_BYTES];
const GF128_REDUCTION: u8 = 0x87;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct WireValue(u8);

impl WireValue {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const fn from_secret_bit(bit: u8) -> Self {
        Self(bit & 1)
    }

    const fn as_u8(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChoiceBit(u8);

impl From<WireValue> for ChoiceBit {
    fn from(value: WireValue) -> Self {
        Self(value.as_u8())
    }
}

impl ChoiceBit {
    #[cfg(test)]
    const fn as_u8(self) -> u8 {
        self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct WireLabel([u8; LABEL_BYTES]);

impl WireLabel {
    const fn from_secret_bytes(bytes: [u8; LABEL_BYTES]) -> Self {
        Self(bytes)
    }

    const fn selection_bit(&self) -> ChoiceBit {
        ChoiceBit(self.0[LABEL_BYTES - 1] & 1)
    }

    fn xor(&self, other: &Self) -> Self {
        let mut output = [0_u8; LABEL_BYTES];
        let mut index = 0_usize;
        while index < LABEL_BYTES {
            output[index] = self.0[index] ^ other.0[index];
            index += 1;
        }
        Self(output)
    }

    fn duplicate(&self) -> Self {
        Self(self.0)
    }

    fn conditional_xor(&mut self, other: &Self, choice: ChoiceBit) {
        let choice = Choice::from(choice.0);
        let mut index = 0_usize;
        while index < LABEL_BYTES {
            self.0[index] ^= u8::conditional_select(&0, &other.0[index], choice);
            index += 1;
        }
    }

    #[cfg(test)]
    const fn test_bytes(&self) -> &[u8; LABEL_BYTES] {
        &self.0
    }

    #[cfg(test)]
    const fn from_test_bytes(bytes: [u8; LABEL_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for WireLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireLabel([REDACTED])")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct GlobalDelta(WireLabel);

impl GlobalDelta {
    pub(crate) fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; LABEL_BYTES];
        getrandom::getrandom(&mut bytes)?;
        bytes[LABEL_BYTES - 1] |= 1;
        Ok(Self(WireLabel::from_secret_bytes(bytes)))
    }

    const fn label(&self) -> &WireLabel {
        &self.0
    }

    #[cfg(test)]
    fn from_test_bytes(mut bytes: [u8; LABEL_BYTES]) -> Self {
        bytes[LABEL_BYTES - 1] |= 1;
        Self(WireLabel::from_test_bytes(bytes))
    }
}

impl fmt::Debug for GlobalDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GlobalDelta([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionDomain(u64);

impl SessionDomain {
    #[cfg(test)]
    pub(crate) fn random() -> Result<Self, getrandom::Error> {
        loop {
            let mut bytes = [0_u8; 8];
            getrandom::getrandom(&mut bytes)?;
            let value = u64::from_be_bytes(bytes);
            bytes.zeroize();
            if value != 0 {
                return Ok(Self(value));
            }
        }
    }

    pub(super) const fn from_protocol_value(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    #[cfg(test)]
    const fn from_test_value(value: u64) -> Option<Self> {
        Self::from_protocol_value(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateOrdinal(u64);

impl GateOrdinal {
    pub(crate) const fn from_schedule_index(value: u64) -> Option<Self> {
        if value < (1_u64 << 63) {
            Some(Self(value))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfGate {
    Garbler = 0,
    Evaluator = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateTweak([u8; LABEL_BYTES]);

impl GateTweak {
    fn new(domain: SessionDomain, gate_ordinal: GateOrdinal, half: HalfGate) -> Self {
        let encoded_ordinal = (gate_ordinal.0 << 1) | half as u64;
        let mut encoded = [0_u8; LABEL_BYTES];
        encoded[..8].copy_from_slice(&domain.0.to_be_bytes());
        encoded[8..].copy_from_slice(&encoded_ordinal.to_be_bytes());
        Self(encoded)
    }
}

struct FixedAesGarblingHash(Aes128);

impl FixedAesGarblingHash {
    fn new() -> Self {
        Self(Aes128::new(&FIXED_AES_KEY.into()))
    }

    #[cfg(test)]
    fn hash(&self, label: &WireLabel, tweak: GateTweak) -> WireLabel {
        let (mut input, mut block) = prepare_hash_block(label, tweak);
        self.0.encrypt_block(&mut block);
        finish_hash_block(&mut input, &mut block)
    }

    fn hash_two(
        &self,
        first_label: &WireLabel,
        first_tweak: GateTweak,
        second_label: &WireLabel,
        second_tweak: GateTweak,
    ) -> [WireLabel; 2] {
        let (mut first_input, first_block) = prepare_hash_block(first_label, first_tweak);
        let (mut second_input, second_block) = prepare_hash_block(second_label, second_tweak);
        let mut blocks = [first_block, second_block];
        self.0.encrypt_blocks(&mut blocks);
        [
            finish_hash_block(&mut first_input, &mut blocks[0]),
            finish_hash_block(&mut second_input, &mut blocks[1]),
        ]
    }

    fn hash_four(&self, labels: [&WireLabel; 4], tweaks: [GateTweak; 4]) -> [WireLabel; 4] {
        let (mut input_zero, block_zero) = prepare_hash_block(labels[0], tweaks[0]);
        let (mut input_one, block_one) = prepare_hash_block(labels[1], tweaks[1]);
        let (mut input_two, block_two) = prepare_hash_block(labels[2], tweaks[2]);
        let (mut input_three, block_three) = prepare_hash_block(labels[3], tweaks[3]);
        let mut blocks = [block_zero, block_one, block_two, block_three];
        self.0.encrypt_blocks(&mut blocks);
        [
            finish_hash_block(&mut input_zero, &mut blocks[0]),
            finish_hash_block(&mut input_one, &mut blocks[1]),
            finish_hash_block(&mut input_two, &mut blocks[2]),
            finish_hash_block(&mut input_three, &mut blocks[3]),
        ]
    }
}

fn prepare_hash_block(label: &WireLabel, tweak: GateTweak) -> ([u8; LABEL_BYTES], Block<Aes128>) {
    let mut doubled = double_gf128(&label.0);
    let mut input = [0_u8; LABEL_BYTES];
    let mut index = 0_usize;
    while index < LABEL_BYTES {
        input[index] = doubled[index] ^ tweak.0[index];
        index += 1;
    }
    doubled.zeroize();
    (input, input.into())
}

fn finish_hash_block(input: &mut [u8; LABEL_BYTES], block: &mut Block<Aes128>) -> WireLabel {
    let mut output = [0_u8; LABEL_BYTES];
    let mut index = 0_usize;
    while index < LABEL_BYTES {
        output[index] = block[index] ^ input[index];
        index += 1;
    }
    input.zeroize();
    block.as_mut_slice().zeroize();
    WireLabel::from_secret_bytes(output)
}

fn double_gf128(input: &[u8; LABEL_BYTES]) -> [u8; LABEL_BYTES] {
    let carry = input[0] >> 7;
    let mut output = [0_u8; LABEL_BYTES];
    let mut index = 0_usize;
    while index + 1 < LABEL_BYTES {
        output[index] = (input[index] << 1) | (input[index + 1] >> 7);
        index += 1;
    }
    output[LABEL_BYTES - 1] = input[LABEL_BYTES - 1] << 1;
    output[LABEL_BYTES - 1] ^= u8::conditional_select(&0, &GF128_REDUCTION, Choice::from(carry));
    output
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct GarblerWire {
    zero: WireLabel,
}

impl GarblerWire {
    pub(crate) const fn from_zero_label(zero: WireLabel) -> Self {
        Self { zero }
    }

    pub(crate) fn random_batch(count: usize) -> Result<Vec<Self>, getrandom::Error> {
        let byte_count = count
            .checked_mul(LABEL_BYTES)
            .expect("fixed circuit input-label count fits usize");
        let mut bytes = vec![0_u8; byte_count];
        if let Err(error) = getrandom::getrandom(&mut bytes) {
            bytes.zeroize();
            return Err(error);
        }
        let mut wires = Vec::with_capacity(count);
        let mut offset = 0_usize;
        while offset < byte_count {
            let mut label = [0_u8; LABEL_BYTES];
            label.copy_from_slice(&bytes[offset..offset + LABEL_BYTES]);
            wires.push(Self::from_zero_label(WireLabel::from_secret_bytes(label)));
            offset += LABEL_BYTES;
        }
        bytes.zeroize();
        Ok(wires)
    }

    fn active_label(&self, delta: &GlobalDelta, value: WireValue) -> WireLabel {
        let mut active = self.zero.duplicate();
        active.conditional_xor(delta.label(), value.into());
        active
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct EvaluatorWire {
    active: WireLabel,
}

impl EvaluatorWire {
    pub(crate) const fn from_active_label(active: WireLabel) -> Self {
        Self { active }
    }

    pub(super) fn from_secret_bytes(bytes: [u8; LABEL_BYTES]) -> Self {
        Self::from_active_label(WireLabel::from_secret_bytes(bytes))
    }

    pub(super) fn append_secret_bytes(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.active.0);
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct GarbledAndGate {
    garbler_half: WireLabel,
    evaluator_half: WireLabel,
}

impl GarbledAndGate {
    #[cfg(test)]
    pub(crate) fn encode(&self) -> [u8; AND_GATE_BYTES] {
        let mut encoded = [0_u8; AND_GATE_BYTES];
        encoded[..LABEL_BYTES].copy_from_slice(&self.garbler_half.0);
        encoded[LABEL_BYTES..].copy_from_slice(&self.evaluator_half.0);
        encoded
    }

    pub(super) fn append_encoded(&self, encoded: &mut Vec<u8>) {
        encoded.extend_from_slice(&self.garbler_half.0);
        encoded.extend_from_slice(&self.evaluator_half.0);
    }

    pub(crate) fn decode(encoded: &[u8; AND_GATE_BYTES]) -> Self {
        let mut garbler_half = [0_u8; LABEL_BYTES];
        let mut evaluator_half = [0_u8; LABEL_BYTES];
        garbler_half.copy_from_slice(&encoded[..LABEL_BYTES]);
        evaluator_half.copy_from_slice(&encoded[LABEL_BYTES..]);
        Self {
            garbler_half: WireLabel::from_secret_bytes(garbler_half),
            evaluator_half: WireLabel::from_secret_bytes(evaluator_half),
        }
    }
}

pub(crate) struct Garbler {
    hash: FixedAesGarblingHash,
    delta: GlobalDelta,
    domain: SessionDomain,
}

impl Garbler {
    pub(crate) fn new(delta: GlobalDelta, domain: SessionDomain) -> Self {
        Self {
            hash: FixedAesGarblingHash::new(),
            delta,
            domain,
        }
    }

    pub(crate) fn encode(&self, wire: &GarblerWire, value: WireValue) -> EvaluatorWire {
        EvaluatorWire::from_active_label(wire.active_label(&self.delta, value))
    }

    pub(super) fn encoded_pair(
        &self,
        wire: &GarblerWire,
    ) -> ([u8; LABEL_BYTES], [u8; LABEL_BYTES]) {
        (
            wire.active_label(&self.delta, WireValue::ZERO).0,
            wire.active_label(&self.delta, WireValue::ONE).0,
        )
    }

    pub(crate) fn xor(&self, left: &GarblerWire, right: &GarblerWire) -> GarblerWire {
        GarblerWire::from_zero_label(left.zero.xor(&right.zero))
    }

    pub(crate) fn invert(&self, input: &GarblerWire) -> GarblerWire {
        GarblerWire::from_zero_label(input.zero.xor(self.delta.label()))
    }

    pub(crate) fn garble_and(
        &self,
        gate_ordinal: GateOrdinal,
        left: &GarblerWire,
        right: &GarblerWire,
    ) -> (GarblerWire, GarbledAndGate) {
        let garbler_tweak = GateTweak::new(self.domain, gate_ordinal, HalfGate::Garbler);
        let evaluator_tweak = GateTweak::new(self.domain, gate_ordinal, HalfGate::Evaluator);

        let left_one = left.zero.xor(self.delta.label());
        let right_one = right.zero.xor(self.delta.label());
        let [left_hash_zero, left_hash_one, right_hash_zero, right_hash_one] = self.hash.hash_four(
            [&left.zero, &left_one, &right.zero, &right_one],
            [
                garbler_tweak,
                garbler_tweak,
                evaluator_tweak,
                evaluator_tweak,
            ],
        );

        let mut garbler_half = left_hash_zero.xor(&left_hash_one);
        garbler_half.conditional_xor(self.delta.label(), right.zero.selection_bit());

        let mut garbler_output = left_hash_zero;
        garbler_output.conditional_xor(&garbler_half, left.zero.selection_bit());

        let evaluator_half = right_hash_zero.xor(&right_hash_one).xor(&left.zero);
        let evaluator_choice = evaluator_half.xor(&left.zero);
        let mut evaluator_output = right_hash_zero;
        evaluator_output.conditional_xor(&evaluator_choice, right.zero.selection_bit());

        let output = GarblerWire::from_zero_label(garbler_output.xor(&evaluator_output));
        (
            output,
            GarbledAndGate {
                garbler_half,
                evaluator_half,
            },
        )
    }
}

pub(crate) struct Evaluator {
    hash: FixedAesGarblingHash,
    domain: SessionDomain,
}

impl Evaluator {
    pub(crate) fn new(domain: SessionDomain) -> Self {
        Self {
            hash: FixedAesGarblingHash::new(),
            domain,
        }
    }

    pub(crate) fn xor(&self, left: &EvaluatorWire, right: &EvaluatorWire) -> EvaluatorWire {
        EvaluatorWire::from_active_label(left.active.xor(&right.active))
    }

    pub(crate) fn invert(&self, input: &EvaluatorWire) -> EvaluatorWire {
        EvaluatorWire::from_active_label(input.active.duplicate())
    }

    pub(crate) fn evaluate_and(
        &self,
        gate_ordinal: GateOrdinal,
        left: &EvaluatorWire,
        right: &EvaluatorWire,
        table: &GarbledAndGate,
    ) -> EvaluatorWire {
        let garbler_tweak = GateTweak::new(self.domain, gate_ordinal, HalfGate::Garbler);
        let evaluator_tweak = GateTweak::new(self.domain, gate_ordinal, HalfGate::Evaluator);

        let [mut garbler_output, mut evaluator_output] =
            self.hash
                .hash_two(&left.active, garbler_tweak, &right.active, evaluator_tweak);
        garbler_output.conditional_xor(&table.garbler_half, left.active.selection_bit());

        let evaluator_choice = table.evaluator_half.xor(&left.active);
        evaluator_output.conditional_xor(&evaluator_choice, right.active.selection_bit());

        EvaluatorWire::from_active_label(garbler_output.xor(&evaluator_output))
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    const WIRE_VALUES: [WireValue; 2] = [WireValue::ZERO, WireValue::ONE];

    fn wire_value(bit: u8) -> WireValue {
        if bit == 0 {
            WireValue::ZERO
        } else {
            WireValue::ONE
        }
    }

    fn label(marker: u8, selection: WireValue) -> WireLabel {
        let mut bytes = [marker; LABEL_BYTES];
        bytes[LABEL_BYTES - 1] = (marker & 0xfe) | selection.as_u8();
        WireLabel::from_test_bytes(bytes)
    }

    fn next_test_bytes(state: &mut u64) -> [u8; LABEL_BYTES] {
        let mut output = [0_u8; LABEL_BYTES];
        let mut offset = 0_usize;
        while offset < LABEL_BYTES {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            output[offset..offset + 8].copy_from_slice(&state.to_be_bytes());
            offset += 8;
        }
        output
    }

    fn assert_active_label(
        output: &EvaluatorWire,
        zero: &GarblerWire,
        delta: &GlobalDelta,
        value: WireValue,
    ) {
        let expected = zero.active_label(delta, value);
        assert_eq!(output.active.test_bytes(), expected.test_bytes());
    }

    #[test]
    fn labels_are_fixed_size_zeroizing_and_redacted() {
        assert_eq!(size_of::<WireLabel>(), LABEL_BYTES);
        assert!(core::mem::needs_drop::<WireLabel>());
        let mut wire = WireLabel::from_test_bytes([0xa5; LABEL_BYTES]);
        assert_eq!(format!("{wire:?}"), "WireLabel([REDACTED])");
        wire.zeroize();
        assert_eq!(wire.test_bytes(), &[0_u8; LABEL_BYTES]);

        let random = GarblerWire::random_batch(1).expect("OS randomness");
        assert_eq!(random[0].zero.test_bytes().len(), LABEL_BYTES);
    }

    #[test]
    fn delta_and_tweaks_freeze_select_and_uniqueness_rules() {
        let delta = GlobalDelta::from_test_bytes([0x42; LABEL_BYTES]);
        assert_eq!(delta.label().selection_bit().as_u8(), 1);
        let random_delta = GlobalDelta::random().expect("OS randomness");
        assert_eq!(random_delta.label().selection_bit().as_u8(), 1);
        assert_ne!(SessionDomain::random().expect("OS randomness").0, 0);

        let domain = SessionDomain::from_test_value(7).expect("nonzero domain");
        assert!(SessionDomain::from_test_value(0).is_none());
        let ordinal = GateOrdinal::from_schedule_index(9).expect("valid ordinal");
        let next_ordinal = GateOrdinal::from_schedule_index(10).expect("valid ordinal");
        let garbler = GateTweak::new(domain, ordinal, HalfGate::Garbler);
        let evaluator = GateTweak::new(domain, ordinal, HalfGate::Evaluator);
        let next = GateTweak::new(domain, next_ordinal, HalfGate::Garbler);
        assert_ne!(garbler, evaluator);
        assert_ne!(garbler, next);
        assert_eq!(garbler.0, [0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 18]);
        assert!(GateOrdinal::from_schedule_index(1_u64 << 63).is_none());
    }

    #[test]
    fn fixed_aes_hash_has_frozen_known_answer() {
        let hash = FixedAesGarblingHash::new();
        let tweak = GateTweak::new(
            SessionDomain::from_test_value(0x0102_0304_0506_0708).expect("domain"),
            GateOrdinal::from_schedule_index(0x090a_0b0c_0d0e_0f10).expect("ordinal"),
            HalfGate::Evaluator,
        );
        let output = hash.hash(&WireLabel::from_test_bytes([0x11; LABEL_BYTES]), tweak);
        assert_eq!(
            output.test_bytes(),
            &[
                0x12, 0x12, 0x53, 0xf8, 0xa1, 0x1e, 0x35, 0xb1, 0x94, 0x5e, 0x36, 0xf1, 0x08, 0x39,
                0x31, 0x8c,
            ]
        );
    }

    #[test]
    fn free_xor_and_inversion_cover_their_truth_tables() {
        let delta = GlobalDelta::from_test_bytes([0x81; LABEL_BYTES]);
        let domain = SessionDomain::from_test_value(1).expect("domain");
        let garbler = Garbler::new(delta, domain);
        let evaluator = Evaluator::new(domain);
        let left = GarblerWire::from_zero_label(label(0x20, WireValue::ONE));
        let right = GarblerWire::from_zero_label(label(0x40, WireValue::ZERO));
        let xor_output = garbler.xor(&left, &right);

        for left_value in WIRE_VALUES {
            for right_value in WIRE_VALUES {
                let left_active = garbler.encode(&left, left_value);
                let right_active = garbler.encode(&right, right_value);
                let output = evaluator.xor(&left_active, &right_active);
                assert_active_label(
                    &output,
                    &xor_output,
                    &garbler.delta,
                    wire_value(left_value.as_u8() ^ right_value.as_u8()),
                );
            }
        }

        let inverted = garbler.invert(&left);
        for value in WIRE_VALUES {
            let active = garbler.encode(&left, value);
            let output = evaluator.invert(&active);
            assert_active_label(
                &output,
                &inverted,
                &garbler.delta,
                wire_value(value.as_u8() ^ 1),
            );
        }
    }

    #[test]
    fn half_gates_known_answer_freezes_table_and_all_outputs() {
        let delta = GlobalDelta::from_test_bytes([0xd2; LABEL_BYTES]);
        let domain = SessionDomain::from_test_value(0x1020_3040_5060_7080).expect("domain");
        let garbler = Garbler::new(delta, domain);
        let evaluator = Evaluator::new(domain);
        let left = GarblerWire::from_zero_label(label(0x12, WireValue::ONE));
        let right = GarblerWire::from_zero_label(label(0x34, WireValue::ONE));
        let ordinal = GateOrdinal::from_schedule_index(17).expect("ordinal");
        let (output_zero, table) = garbler.garble_and(ordinal, &left, &right);
        assert_eq!(
            output_zero.zero.test_bytes(),
            &[
                0xb1, 0xee, 0xf2, 0x3c, 0xa5, 0xff, 0xa1, 0x38, 0xef, 0xaa, 0x49, 0xb4, 0xb3, 0xfa,
                0x50, 0xdc,
            ]
        );
        let encoded = table.encode();
        assert_eq!(
            encoded,
            [
                0xfb, 0x2f, 0x1f, 0x74, 0x99, 0x72, 0x26, 0x9c, 0xf0, 0x0c, 0x34, 0x86, 0x04, 0xfa,
                0xaa, 0x07, 0x9a, 0x51, 0x90, 0x7b, 0xa1, 0x7c, 0xaf, 0xfc, 0x1d, 0x33, 0xd9, 0xe8,
                0xb0, 0x3d, 0xc1, 0x08,
            ]
        );
        let decoded = GarbledAndGate::decode(&encoded);

        for left_value in WIRE_VALUES {
            for right_value in WIRE_VALUES {
                let left_active = garbler.encode(&left, left_value);
                let right_active = garbler.encode(&right, right_value);
                let output = evaluator.evaluate_and(ordinal, &left_active, &right_active, &decoded);
                assert_active_label(
                    &output,
                    &output_zero,
                    &garbler.delta,
                    wire_value(left_value.as_u8() & right_value.as_u8()),
                );
            }
        }
    }

    #[test]
    fn half_gates_covers_every_permutation_bit_pair_and_randomized_labels() {
        let mut state = 0x8f31_2a4b_09d7_e6c5_u64;
        let mut case = 0_u64;
        while case < 128 {
            let delta = GlobalDelta::from_test_bytes(next_test_bytes(&mut state));
            let domain = SessionDomain::from_test_value(case + 1).expect("domain");
            let garbler = Garbler::new(delta, domain);
            let evaluator = Evaluator::new(domain);
            let left_selection = wire_value((case & 1) as u8);
            let right_selection = wire_value(((case >> 1) & 1) as u8);
            let mut left_bytes = next_test_bytes(&mut state);
            let mut right_bytes = next_test_bytes(&mut state);
            left_bytes[LABEL_BYTES - 1] =
                (left_bytes[LABEL_BYTES - 1] & 0xfe) | left_selection.as_u8();
            right_bytes[LABEL_BYTES - 1] =
                (right_bytes[LABEL_BYTES - 1] & 0xfe) | right_selection.as_u8();
            let left = GarblerWire::from_zero_label(WireLabel::from_test_bytes(left_bytes));
            let right = GarblerWire::from_zero_label(WireLabel::from_test_bytes(right_bytes));
            let ordinal = GateOrdinal::from_schedule_index(case).expect("ordinal");
            let (output_zero, table) = garbler.garble_and(ordinal, &left, &right);

            for left_value in WIRE_VALUES {
                for right_value in WIRE_VALUES {
                    let left_active = garbler.encode(&left, left_value);
                    let right_active = garbler.encode(&right, right_value);
                    let output =
                        evaluator.evaluate_and(ordinal, &left_active, &right_active, &table);
                    assert_active_label(
                        &output,
                        &output_zero,
                        &garbler.delta,
                        wire_value(left_value.as_u8() & right_value.as_u8()),
                    );
                }
            }
            case += 1;
        }
    }
}
