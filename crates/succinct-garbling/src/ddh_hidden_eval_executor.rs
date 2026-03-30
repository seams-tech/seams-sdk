use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ddh_hss::{
    build_local_word_pair_public, eval_add_local_word_pairs_mod_2_pow_n_public,
    eval_mul_local_word_pair_batch_public, eval_mul_local_word_pairs_public,
    local_word_from_shared, local_word_from_transport_public,
    validate_transport_bundle_pair_public, validate_transport_word_pair_public,
    xor_local_bit_from_raw_public, xor_local_word_pairs_public, DdhHssArithmeticBackend,
    DdhHssInputShareBundle, DdhHssLocalWord, DdhHssShareSide, DdhHssSharedWord,
    DdhHssTransportBundle, DdhHssTransportWord,
};
use crate::hidden_eval::{
    HiddenEvalInputOwner, HiddenEvalProgram, HiddenEvalStage, HiddenEvalStageKind,
};
use crate::reference::FExpandInput;
#[cfg(test)]
use crate::DdhHssBackend;
use crate::{ProtoError, ProtoResult};

const SHA512_IV: [u64; 8] = [
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

const ED25519_L_BYTES_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalServerInputBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub left_words: Vec<DdhHssTransportWord>,
    pub right_words: Vec<DdhHssTransportWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalServerInputs {
    pub y_relayer_bits: DdhHiddenEvalServerInputBundle,
    pub tau_relayer_bits: DdhHiddenEvalServerInputBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalInputBundles {
    pub y_client_bits: DdhHssInputShareBundle,
    pub server_inputs: DdhHiddenEvalServerInputs,
    pub tau_client_bits: DdhHssInputShareBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalOutputBundles {
    pub x_client_base: DdhHssInputShareBundle,
    pub x_relayer_base_left: DdhHssTransportBundle,
    pub x_relayer_base_right: DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalRun {
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub output: DdhHiddenEvalOutputBundles,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalStageProfile {
    pub input_sharing_duration_ns: u128,
    pub add_stage_duration_ns: u128,
    pub message_schedule_duration_ns: u128,
    pub message_schedule_accumulation_duration_ns: u128,
    pub message_schedule_accumulation_xor_ab_duration_ns: u128,
    pub message_schedule_accumulation_sum_duration_ns: u128,
    pub message_schedule_accumulation_a_xor_carry_duration_ns: u128,
    pub message_schedule_accumulation_carry_gate_duration_ns: u128,
    pub message_schedule_accumulation_next_carry_duration_ns: u128,
    pub round_core_duration_ns: u128,
    pub round_sigma1_duration_ns: u128,
    pub round_ch_duration_ns: u128,
    pub round_temp1_duration_ns: u128,
    pub round_temp1_xor_ab_duration_ns: u128,
    pub round_temp1_sum_duration_ns: u128,
    pub round_temp1_a_xor_carry_duration_ns: u128,
    pub round_temp1_carry_gate_duration_ns: u128,
    pub round_temp1_next_carry_duration_ns: u128,
    pub round_temp2_duration_ns: u128,
    pub output_projector_duration_ns: u128,
    pub total_duration_ns: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdhHiddenEvalCheckpoint {
    InputSharing,
    AddStage,
    MessageSchedule,
    RoundCore,
    OutputProjector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalProbe {
    pub completed_stage: DdhHiddenEvalCheckpoint,
    pub stage_profile: DdhHiddenEvalStageProfile,
    pub schedule_word_count: Option<usize>,
    pub hash_prefix_hex: Option<String>,
}

impl DdhHiddenEvalServerInputBundle {
    fn from_joint_bundle(bundle: &DdhHssInputShareBundle) -> Self {
        Self {
            owner: bundle.owner,
            label: bundle.label.clone(),
            left_words: bundle
                .words
                .iter()
                .map(|word| DdhHssTransportWord {
                    width_bits: word.width_bits,
                    share_side: DdhHssShareSide::Left,
                    share_word: word.left_word,
                    share_commitment: word.left_commitment,
                    counterparty_commitment: word.right_commitment,
                    provenance_digest: word.provenance_digest,
                })
                .collect(),
            right_words: bundle
                .words
                .iter()
                .map(|word| DdhHssTransportWord {
                    width_bits: word.width_bits,
                    share_side: DdhHssShareSide::Right,
                    share_word: word.right_word,
                    share_commitment: word.right_commitment,
                    counterparty_commitment: word.left_commitment,
                    provenance_digest: word.provenance_digest,
                })
                .collect(),
            commitment: bundle.commitment,
        }
    }
}

impl DdhHiddenEvalServerInputs {
    pub(crate) fn from_joint_bundles(
        y_relayer_bits: &DdhHssInputShareBundle,
        tau_relayer_bits: &DdhHssInputShareBundle,
    ) -> Self {
        Self {
            y_relayer_bits: DdhHiddenEvalServerInputBundle::from_joint_bundle(y_relayer_bits),
            tau_relayer_bits: DdhHiddenEvalServerInputBundle::from_joint_bundle(tau_relayer_bits),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalProfile {
    pub stage_profile: DdhHiddenEvalStageProfile,
    pub run: DdhHiddenEvalRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalBitWordSide {
    share_side: DdhHssShareSide,
    share_blocks: Vec<u64>,
    bit_len: usize,
    commitments: Vec<[u8; 32]>,
    provenance_digests: Vec<[u8; 32]>,
}

impl LocalBitWordSide {
    fn empty(share_side: DdhHssShareSide, len: usize) -> Self {
        Self {
            share_side,
            share_blocks: Vec::with_capacity(len.div_ceil(64)),
            bit_len: 0,
            commitments: Vec::with_capacity(len),
            provenance_digests: Vec::with_capacity(len),
        }
    }

    fn ensure_shape(&self) -> ProtoResult<()> {
        if self.commitments.len() != self.bit_len || self.provenance_digests.len() != self.bit_len {
            return Err(ProtoError::InvalidInput(
                "local bit-vector lengths are inconsistent".to_string(),
            ));
        }
        Ok(())
    }

    fn local_word(&self, idx: usize) -> ProtoResult<DdhHssLocalWord> {
        if idx >= self.bit_len
            || idx >= self.commitments.len()
            || idx >= self.provenance_digests.len()
        {
            return Err(ProtoError::InvalidInput(format!(
                "local bit-vector index {} out of range",
                idx
            )));
        }
        Ok(DdhHssLocalWord {
            width_bits: 1,
            share_side: self.share_side,
            share_word: u64::from(self.share_bit(idx)),
            share_commitment: self.commitments[idx],
            provenance_digest: self.provenance_digests[idx],
        })
    }

    fn push_local_word(&mut self, word: &DdhHssLocalWord) -> ProtoResult<()> {
        if word.share_side != self.share_side || word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(
                "local bit-vector requires width-1 words on the matching side".to_string(),
            ));
        }
        self.push_share_bit((word.share_word as u8) & 1);
        self.commitments.push(word.share_commitment);
        self.provenance_digests.push(word.provenance_digest);
        Ok(())
    }

    fn len(&self) -> usize {
        self.bit_len
    }

    fn share_bit(&self, idx: usize) -> u8 {
        let block = idx / 64;
        let bit = idx % 64;
        ((self.share_blocks[block] >> bit) & 1) as u8
    }

    fn push_share_bit(&mut self, value: u8) {
        let block = self.bit_len / 64;
        let bit = self.bit_len % 64;
        if block == self.share_blocks.len() {
            self.share_blocks.push(0);
        }
        if (value & 1) == 1 {
            self.share_blocks[block] |= 1u64 << bit;
        }
        self.bit_len += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SplitLocalBitWord {
    left: LocalBitWordSide,
    right: LocalBitWordSide,
}

impl SplitLocalBitWord {
    fn from_shared_bits(bits: &[DdhHssSharedWord]) -> ProtoResult<Self> {
        let mut left = empty_local_bit_slice(DdhHssShareSide::Left, bits.len());
        let mut right = empty_local_bit_slice(DdhHssShareSide::Right, bits.len());
        for bit in bits {
            if bit.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "split local word requires width-1 shared bits, got {}",
                    bit.width_bits
                )));
            }
            let left_word = local_word_from_shared(bit, DdhHssShareSide::Left);
            let right_word = local_word_from_shared(bit, DdhHssShareSide::Right);
            left.push_share_bit((left_word.share_word as u8) & 1);
            left.commitments.push(left_word.share_commitment);
            left.provenance_digests.push(left_word.provenance_digest);
            right.push_share_bit((right_word.share_word as u8) & 1);
            right.commitments.push(right_word.share_commitment);
            right.provenance_digests.push(right_word.provenance_digest);
        }
        Self::from_local_sides(left, right)
    }

    fn from_local_sides(left: LocalBitWordSide, right: LocalBitWordSide) -> ProtoResult<Self> {
        left.ensure_shape()?;
        right.ensure_shape()?;
        if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
            return Err(ProtoError::InvalidInput(
                "split local word requires left/right bit-slice pair".to_string(),
            ));
        }
        if left.len() != right.len() {
            return Err(ProtoError::InvalidInput(format!(
                "split local word length mismatch: {} vs {}",
                left.len(),
                right.len()
            )));
        }
        Ok(Self { left, right })
    }

    fn to_shared_bits(&self) -> ProtoResult<Vec<DdhHssSharedWord>> {
        if self.left.len() != self.right.len() {
            return Err(ProtoError::InvalidInput(format!(
                "split local word length mismatch: {} vs {}",
                self.left.len(),
                self.right.len()
            )));
        }
        let mut out = Vec::with_capacity(self.left.len());
        for idx in 0..self.left.len() {
            out.push(DdhHssSharedWord {
                width_bits: 1,
                left_word: u64::from(self.left.share_bit(idx)),
                right_word: u64::from(self.right.share_bit(idx)),
                left_commitment: self.left.commitments[idx],
                right_commitment: self.right.commitments[idx],
                provenance_digest: self.left.provenance_digests[idx],
            });
        }
        Ok(out)
    }

    fn len(&self) -> usize {
        self.left.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SharedHashCoreOutput {
    final_words: Vec<SplitLocalBitWord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageScheduleStageOutput {
    words: Vec<SplitLocalBitWord>,
    accumulation_duration_ns: u128,
    accumulation_add_timing: LocalBitWordAddTiming,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundStagesOutput {
    hash_core: SharedHashCoreOutput,
    sigma1_duration_ns: u128,
    ch_duration_ns: u128,
    temp1_duration_ns: u128,
    temp1_add_timing: LocalBitWordAddTiming,
    temp2_duration_ns: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalBitWordAddTiming {
    xor_ab_duration_ns: u128,
    sum_duration_ns: u128,
    a_xor_carry_duration_ns: u128,
    carry_gate_duration_ns: u128,
    next_carry_duration_ns: u128,
}

impl LocalBitWordAddTiming {
    fn add_assign(&mut self, other: &Self) {
        self.xor_ab_duration_ns = self
            .xor_ab_duration_ns
            .saturating_add(other.xor_ab_duration_ns);
        self.sum_duration_ns = self.sum_duration_ns.saturating_add(other.sum_duration_ns);
        self.a_xor_carry_duration_ns = self
            .a_xor_carry_duration_ns
            .saturating_add(other.a_xor_carry_duration_ns);
        self.carry_gate_duration_ns = self
            .carry_gate_duration_ns
            .saturating_add(other.carry_gate_duration_ns);
        self.next_carry_duration_ns = self
            .next_carry_duration_ns
            .saturating_add(other.next_carry_duration_ns);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalConstantPool {
    zero_left: DdhHssLocalWord,
    zero_right: DdhHssLocalWord,
    one_left: DdhHssLocalWord,
    one_right: DdhHssLocalWord,
    schedule_suffix_words: Vec<SplitLocalBitWord>,
    sha512_iv_words: [SplitLocalBitWord; 8],
    sha512_round_constants: Vec<SplitLocalBitWord>,
}

pub fn prepare_ddh_hidden_eval_constant_pool<B: DdhHssArithmeticBackend>(
    backend: &B,
) -> ProtoResult<DdhHiddenEvalConstantPool> {
    let zero_bit = constant_bit(backend, "shared/zero", false)?;
    let one_bit = constant_bit(backend, "output_projector/mod_l/one", true)?;
    Ok(DdhHiddenEvalConstantPool {
        zero_left: local_word_from_shared(&zero_bit, DdhHssShareSide::Left),
        zero_right: local_word_from_shared(&zero_bit, DdhHssShareSide::Right),
        one_left: local_word_from_shared(&one_bit, DdhHssShareSide::Left),
        one_right: local_word_from_shared(&one_bit, DdhHssShareSide::Right),
        schedule_suffix_words: one_block_schedule_constant_suffix_words_bits(backend)?,
        sha512_iv_words: sha512_iv_words_bits(backend)?,
        sha512_round_constants: sha512_round_constant_words_bits(backend)?,
    })
}

pub fn execute_prime_order_ddh_hidden_eval_program<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    input_bundles: &DdhHiddenEvalInputBundles,
) -> ProtoResult<DdhHiddenEvalRun> {
    let constant_pool = prepare_ddh_hidden_eval_constant_pool(backend)?;
    Ok(
        execute_prime_order_ddh_hidden_eval_program_profiled_with_pool(
            program,
            backend,
            &constant_pool,
            input_bundles,
        )?
        .run,
    )
}

pub fn execute_prime_order_ddh_hidden_eval_program_with_pool<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    input_bundles: &DdhHiddenEvalInputBundles,
) -> ProtoResult<DdhHiddenEvalRun> {
    Ok(
        execute_prime_order_ddh_hidden_eval_program_profiled_with_pool(
            program,
            backend,
            constant_pool,
            input_bundles,
        )?
        .run,
    )
}

pub(crate) fn execute_prime_order_ddh_hidden_eval_program_with_transport_server_inputs_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_left: &DdhHssTransportBundle,
    y_relayer_right: &DdhHssTransportBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_left: &DdhHssTransportBundle,
    tau_relayer_right: &DdhHssTransportBundle,
) -> ProtoResult<DdhHiddenEvalRun> {
    Ok(
        execute_prime_order_ddh_hidden_eval_program_internal_with_transport_server_inputs(
            program,
            backend,
            constant_pool,
            y_client_bits,
            y_relayer_left,
            y_relayer_right,
            tau_client_bits,
            tau_relayer_left,
            tau_relayer_right,
        )?
        .run,
    )
}

pub(crate) fn execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<DdhHiddenEvalRun> {
    Ok(
        execute_prime_order_ddh_hidden_eval_program_internal_with_split_server_inputs(
            program,
            backend,
            constant_pool,
            y_client_bits,
            y_relayer_bits,
            tau_client_bits,
            tau_relayer_bits,
        )?
        .run,
    )
}

pub fn execute_prime_order_ddh_hidden_eval_program_profiled<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    input_bundles: &DdhHiddenEvalInputBundles,
) -> ProtoResult<DdhHiddenEvalProfile> {
    let constant_pool = prepare_ddh_hidden_eval_constant_pool(backend)?;
    execute_prime_order_ddh_hidden_eval_program_profiled_with_pool(
        program,
        backend,
        &constant_pool,
        input_bundles,
    )
}

pub fn execute_prime_order_ddh_hidden_eval_program_profiled_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    input_bundles: &DdhHiddenEvalInputBundles,
) -> ProtoResult<DdhHiddenEvalProfile> {
    let ExecutionUntilOutputProjector { stage_profile, run } =
        execute_prime_order_ddh_hidden_eval_program_internal(
            program,
            backend,
            constant_pool,
            input_bundles,
        )?;
    Ok(DdhHiddenEvalProfile { stage_profile, run })
}

pub fn share_input_bit_bundles_for_clear_input<B: DdhHssArithmeticBackend>(
    backend: &B,
    input: &FExpandInput,
) -> ProtoResult<DdhHiddenEvalInputBundles> {
    let y_relayer_bits = backend.share_input_bit_bundle(
        HiddenEvalInputOwner::Server,
        "y_relayer_bits",
        &input.y_relayer,
    )?;
    let tau_relayer_bits = backend.share_input_bit_bundle(
        HiddenEvalInputOwner::Server,
        "tau_relayer_bits",
        &input.tau_relayer,
    )?;
    Ok(DdhHiddenEvalInputBundles {
        y_client_bits: backend.share_input_bit_bundle(
            HiddenEvalInputOwner::Client,
            "y_client_bits",
            &input.y_client,
        )?,
        server_inputs: DdhHiddenEvalServerInputs::from_joint_bundles(
            &y_relayer_bits,
            &tau_relayer_bits,
        ),
        tau_client_bits: backend.share_input_bit_bundle(
            HiddenEvalInputOwner::Client,
            "tau_client_bits",
            &input.tau_client,
        )?,
    })
}

pub fn execute_prime_order_ddh_hidden_eval_program_for_clear_input<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    input: &FExpandInput,
) -> ProtoResult<DdhHiddenEvalRun> {
    let input_bundles = share_input_bit_bundles_for_clear_input(backend, input)?;
    execute_prime_order_ddh_hidden_eval_program(program, backend, &input_bundles)
}

pub fn execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    input: &FExpandInput,
) -> ProtoResult<DdhHiddenEvalProfile> {
    let constant_pool = prepare_ddh_hidden_eval_constant_pool(backend)?;
    execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool(
        program,
        backend,
        &constant_pool,
        input,
    )
}

pub fn execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    input: &FExpandInput,
) -> ProtoResult<DdhHiddenEvalProfile> {
    let input_bundles = share_input_bit_bundles_for_clear_input(backend, input)?;
    execute_prime_order_ddh_hidden_eval_program_profiled_with_pool(
        program,
        backend,
        constant_pool,
        &input_bundles,
    )
}

pub fn probe_prime_order_ddh_hidden_eval_program<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    input: &FExpandInput,
    stop_after: DdhHiddenEvalCheckpoint,
) -> ProtoResult<DdhHiddenEvalProbe> {
    let constant_pool = prepare_ddh_hidden_eval_constant_pool(backend)?;
    probe_prime_order_ddh_hidden_eval_program_with_pool(
        program,
        backend,
        &constant_pool,
        input,
        stop_after,
    )
}

pub fn probe_prime_order_ddh_hidden_eval_program_with_pool<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    input: &FExpandInput,
    stop_after: DdhHiddenEvalCheckpoint,
) -> ProtoResult<DdhHiddenEvalProbe> {
    ensure_program_shape(program)?;

    let total_started_ns = monotonic_now_ns();
    let input_sharing_started_ns = monotonic_now_ns();
    let input_bundles = share_input_bit_bundles_for_clear_input(backend, input)?;
    validate_input_bit_bundle(
        &input_bundles.y_client_bits,
        HiddenEvalInputOwner::Client,
        "y_client_bits",
    )?;
    validate_server_input_bit_bundle(
        &input_bundles.server_inputs.y_relayer_bits,
        HiddenEvalInputOwner::Server,
        "y_relayer_bits",
    )?;
    validate_input_bit_bundle(
        &input_bundles.tau_client_bits,
        HiddenEvalInputOwner::Client,
        "tau_client_bits",
    )?;
    validate_server_input_bit_bundle(
        &input_bundles.server_inputs.tau_relayer_bits,
        HiddenEvalInputOwner::Server,
        "tau_relayer_bits",
    )?;
    let y_client_bits = input_bundles.y_client_bits.words.clone();
    let tau_client_bits = input_bundles.tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bits)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bits)?;
    let input_sharing_duration_ns = elapsed_ns(input_sharing_started_ns);

    if stop_after == DdhHiddenEvalCheckpoint::InputSharing {
        return Ok(DdhHiddenEvalProbe {
            completed_stage: DdhHiddenEvalCheckpoint::InputSharing,
            stage_profile: DdhHiddenEvalStageProfile {
                input_sharing_duration_ns,
                add_stage_duration_ns: 0,
                message_schedule_duration_ns: 0,
                message_schedule_accumulation_duration_ns: 0,
                message_schedule_accumulation_xor_ab_duration_ns: 0,
                message_schedule_accumulation_sum_duration_ns: 0,
                message_schedule_accumulation_a_xor_carry_duration_ns: 0,
                message_schedule_accumulation_carry_gate_duration_ns: 0,
                message_schedule_accumulation_next_carry_duration_ns: 0,
                round_core_duration_ns: 0,
                round_sigma1_duration_ns: 0,
                round_ch_duration_ns: 0,
                round_temp1_duration_ns: 0,
                round_temp1_xor_ab_duration_ns: 0,
                round_temp1_sum_duration_ns: 0,
                round_temp1_a_xor_carry_duration_ns: 0,
                round_temp1_carry_gate_duration_ns: 0,
                round_temp1_next_carry_duration_ns: 0,
                round_temp2_duration_ns: 0,
                output_projector_duration_ns: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
            },
            schedule_word_count: None,
            hash_prefix_hex: None,
        });
    }

    let add_started_ns = monotonic_now_ns();
    let d_bits = execute_add_stage(
        backend,
        &program.stages[0],
        &y_client_bits_local,
        &input_bundles.server_inputs.y_relayer_bits.left_words,
        &input_bundles.server_inputs.y_relayer_bits.right_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let add_stage_duration_ns = elapsed_ns(add_started_ns);
    if stop_after == DdhHiddenEvalCheckpoint::AddStage {
        return Ok(DdhHiddenEvalProbe {
            completed_stage: DdhHiddenEvalCheckpoint::AddStage,
            stage_profile: DdhHiddenEvalStageProfile {
                input_sharing_duration_ns,
                add_stage_duration_ns,
                message_schedule_duration_ns: 0,
                message_schedule_accumulation_duration_ns: 0,
                message_schedule_accumulation_xor_ab_duration_ns: 0,
                message_schedule_accumulation_sum_duration_ns: 0,
                message_schedule_accumulation_a_xor_carry_duration_ns: 0,
                message_schedule_accumulation_carry_gate_duration_ns: 0,
                message_schedule_accumulation_next_carry_duration_ns: 0,
                round_core_duration_ns: 0,
                round_sigma1_duration_ns: 0,
                round_ch_duration_ns: 0,
                round_temp1_duration_ns: 0,
                round_temp1_xor_ab_duration_ns: 0,
                round_temp1_sum_duration_ns: 0,
                round_temp1_a_xor_carry_duration_ns: 0,
                round_temp1_carry_gate_duration_ns: 0,
                round_temp1_next_carry_duration_ns: 0,
                round_temp2_duration_ns: 0,
                output_projector_duration_ns: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
            },
            schedule_word_count: None,
            hash_prefix_hex: None,
        });
    }

    let schedule_started_ns = monotonic_now_ns();
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let message_schedule_duration_ns = elapsed_ns(schedule_started_ns);
    let message_schedule_accumulation_duration_ns = schedule_output.accumulation_duration_ns;
    let message_schedule_accumulation_add_timing = schedule_output.accumulation_add_timing;
    if stop_after == DdhHiddenEvalCheckpoint::MessageSchedule {
        return Ok(DdhHiddenEvalProbe {
            completed_stage: DdhHiddenEvalCheckpoint::MessageSchedule,
            stage_profile: DdhHiddenEvalStageProfile {
                input_sharing_duration_ns,
                add_stage_duration_ns,
                message_schedule_duration_ns,
                message_schedule_accumulation_duration_ns,
                message_schedule_accumulation_xor_ab_duration_ns:
                    message_schedule_accumulation_add_timing.xor_ab_duration_ns,
                message_schedule_accumulation_sum_duration_ns:
                    message_schedule_accumulation_add_timing.sum_duration_ns,
                message_schedule_accumulation_a_xor_carry_duration_ns:
                    message_schedule_accumulation_add_timing.a_xor_carry_duration_ns,
                message_schedule_accumulation_carry_gate_duration_ns:
                    message_schedule_accumulation_add_timing.carry_gate_duration_ns,
                message_schedule_accumulation_next_carry_duration_ns:
                    message_schedule_accumulation_add_timing.next_carry_duration_ns,
                round_core_duration_ns: 0,
                round_sigma1_duration_ns: 0,
                round_ch_duration_ns: 0,
                round_temp1_duration_ns: 0,
                round_temp1_xor_ab_duration_ns: 0,
                round_temp1_sum_duration_ns: 0,
                round_temp1_a_xor_carry_duration_ns: 0,
                round_temp1_carry_gate_duration_ns: 0,
                round_temp1_next_carry_duration_ns: 0,
                round_temp2_duration_ns: 0,
                output_projector_duration_ns: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
            },
            schedule_word_count: Some(schedule_output.words.len()),
            hash_prefix_hex: None,
        });
    }

    let round_started_ns = monotonic_now_ns();
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let round_core_duration_ns = elapsed_ns(round_started_ns);
    let hash_core = round_output.hash_core;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;
    if stop_after == DdhHiddenEvalCheckpoint::RoundCore {
        return Ok(DdhHiddenEvalProbe {
            completed_stage: DdhHiddenEvalCheckpoint::RoundCore,
            stage_profile: DdhHiddenEvalStageProfile {
                input_sharing_duration_ns,
                add_stage_duration_ns,
                message_schedule_duration_ns,
                message_schedule_accumulation_duration_ns,
                message_schedule_accumulation_xor_ab_duration_ns:
                    message_schedule_accumulation_add_timing.xor_ab_duration_ns,
                message_schedule_accumulation_sum_duration_ns:
                    message_schedule_accumulation_add_timing.sum_duration_ns,
                message_schedule_accumulation_a_xor_carry_duration_ns:
                    message_schedule_accumulation_add_timing.a_xor_carry_duration_ns,
                message_schedule_accumulation_carry_gate_duration_ns:
                    message_schedule_accumulation_add_timing.carry_gate_duration_ns,
                message_schedule_accumulation_next_carry_duration_ns:
                    message_schedule_accumulation_add_timing.next_carry_duration_ns,
                round_core_duration_ns,
                round_sigma1_duration_ns,
                round_ch_duration_ns,
                round_temp1_duration_ns,
                round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
                round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
                round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
                round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
                round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
                round_temp2_duration_ns,
                output_projector_duration_ns: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
            },
            schedule_word_count: Some(schedule_output.words.len()),
            hash_prefix_hex: None,
        });
    }

    let output_started_ns = monotonic_now_ns();
    let _ = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &hash_core.final_words,
        &tau_client_bits_local,
        &input_bundles.server_inputs.tau_relayer_bits.left_words,
        &input_bundles.server_inputs.tau_relayer_bits.right_words,
    )?;
    let output_projector_duration_ns = elapsed_ns(output_started_ns);

    Ok(DdhHiddenEvalProbe {
        completed_stage: DdhHiddenEvalCheckpoint::OutputProjector,
        stage_profile: DdhHiddenEvalStageProfile {
            input_sharing_duration_ns,
            add_stage_duration_ns,
            message_schedule_duration_ns,
            message_schedule_accumulation_duration_ns,
            message_schedule_accumulation_xor_ab_duration_ns:
                message_schedule_accumulation_add_timing.xor_ab_duration_ns,
            message_schedule_accumulation_sum_duration_ns: message_schedule_accumulation_add_timing
                .sum_duration_ns,
            message_schedule_accumulation_a_xor_carry_duration_ns:
                message_schedule_accumulation_add_timing.a_xor_carry_duration_ns,
            message_schedule_accumulation_carry_gate_duration_ns:
                message_schedule_accumulation_add_timing.carry_gate_duration_ns,
            message_schedule_accumulation_next_carry_duration_ns:
                message_schedule_accumulation_add_timing.next_carry_duration_ns,
            round_core_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            output_projector_duration_ns,
            total_duration_ns: elapsed_ns(total_started_ns),
        },
        schedule_word_count: Some(schedule_output.words.len()),
        hash_prefix_hex: None,
    })
}

struct ExecutionUntilOutputProjector {
    stage_profile: DdhHiddenEvalStageProfile,
    run: DdhHiddenEvalRun,
}

fn execute_prime_order_ddh_hidden_eval_program_internal<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    input_bundles: &DdhHiddenEvalInputBundles,
) -> ProtoResult<ExecutionUntilOutputProjector> {
    ensure_program_shape(program)?;
    let total_started_ns = monotonic_now_ns();
    let input_sharing_started_ns = monotonic_now_ns();
    validate_input_bit_bundle(
        &input_bundles.y_client_bits,
        HiddenEvalInputOwner::Client,
        "y_client_bits",
    )?;
    validate_server_input_bit_bundle(
        &input_bundles.server_inputs.y_relayer_bits,
        HiddenEvalInputOwner::Server,
        "y_relayer_bits",
    )?;
    validate_input_bit_bundle(
        &input_bundles.tau_client_bits,
        HiddenEvalInputOwner::Client,
        "tau_client_bits",
    )?;
    validate_server_input_bit_bundle(
        &input_bundles.server_inputs.tau_relayer_bits,
        HiddenEvalInputOwner::Server,
        "tau_relayer_bits",
    )?;

    let client_input_commitment = combine_bundle_commitments(
        backend,
        HiddenEvalInputOwner::Client,
        &[&input_bundles.y_client_bits, &input_bundles.tau_client_bits],
    );
    let server_input_commitment =
        combine_server_input_commitments(backend, &input_bundles.server_inputs);
    let y_client_bits = input_bundles.y_client_bits.words.clone();
    let tau_client_bits = input_bundles.tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bits)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bits)?;
    let input_sharing_duration_ns = elapsed_ns(input_sharing_started_ns);

    let add_started_ns = monotonic_now_ns();
    let d_bits = execute_add_stage(
        backend,
        &program.stages[0],
        &y_client_bits_local,
        &input_bundles.server_inputs.y_relayer_bits.left_words,
        &input_bundles.server_inputs.y_relayer_bits.right_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let add_stage_duration_ns = elapsed_ns(add_started_ns);

    let schedule_started_ns = monotonic_now_ns();
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let message_schedule_duration_ns = elapsed_ns(schedule_started_ns);
    let message_schedule_accumulation_duration_ns = schedule_output.accumulation_duration_ns;
    let message_schedule_accumulation_add_timing = schedule_output.accumulation_add_timing;

    let round_started_ns = monotonic_now_ns();
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let round_core_duration_ns = elapsed_ns(round_started_ns);
    let hash_core = round_output.hash_core;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;

    let output_started_ns = monotonic_now_ns();
    let output = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &hash_core.final_words,
        &tau_client_bits_local,
        &input_bundles.server_inputs.tau_relayer_bits.left_words,
        &input_bundles.server_inputs.tau_relayer_bits.right_words,
    )?;
    let output_projector_duration_ns = elapsed_ns(output_started_ns);

    Ok(ExecutionUntilOutputProjector {
        stage_profile: DdhHiddenEvalStageProfile {
            input_sharing_duration_ns,
            add_stage_duration_ns,
            message_schedule_duration_ns,
            message_schedule_accumulation_duration_ns,
            message_schedule_accumulation_xor_ab_duration_ns:
                message_schedule_accumulation_add_timing.xor_ab_duration_ns,
            message_schedule_accumulation_sum_duration_ns: message_schedule_accumulation_add_timing
                .sum_duration_ns,
            message_schedule_accumulation_a_xor_carry_duration_ns:
                message_schedule_accumulation_add_timing.a_xor_carry_duration_ns,
            message_schedule_accumulation_carry_gate_duration_ns:
                message_schedule_accumulation_add_timing.carry_gate_duration_ns,
            message_schedule_accumulation_next_carry_duration_ns:
                message_schedule_accumulation_add_timing.next_carry_duration_ns,
            round_core_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            output_projector_duration_ns,
            total_duration_ns: elapsed_ns(total_started_ns),
        },
        run: DdhHiddenEvalRun {
            client_input_commitment,
            server_input_commitment,
            output,
        },
    })
}

fn execute_prime_order_ddh_hidden_eval_program_internal_with_split_server_inputs<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<ExecutionUntilOutputProjector> {
    ensure_program_shape(program)?;
    validate_input_bit_bundle(y_client_bits, HiddenEvalInputOwner::Client, "y_client_bits")?;
    validate_server_input_bit_bundle(
        y_relayer_bits,
        HiddenEvalInputOwner::Server,
        "y_relayer_bits",
    )?;
    validate_input_bit_bundle(
        tau_client_bits,
        HiddenEvalInputOwner::Client,
        "tau_client_bits",
    )?;
    validate_server_input_bit_bundle(
        tau_relayer_bits,
        HiddenEvalInputOwner::Server,
        "tau_relayer_bits",
    )?;

    execute_prime_order_ddh_hidden_eval_program_internal_with_split_server_inputs_validated(
        program,
        backend,
        constant_pool,
        y_client_bits,
        y_relayer_bits,
        tau_client_bits,
        tau_relayer_bits,
    )
}

fn execute_prime_order_ddh_hidden_eval_program_internal_with_split_server_inputs_validated<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<ExecutionUntilOutputProjector> {
    let total_started_ns = monotonic_now_ns();
    let input_sharing_started_ns = monotonic_now_ns();

    let client_input_commitment = combine_bundle_commitments(
        backend,
        HiddenEvalInputOwner::Client,
        &[y_client_bits, tau_client_bits],
    );
    let server_input_commitment =
        combine_server_input_bundle_commitments(backend, y_relayer_bits, tau_relayer_bits);
    let y_client_bits = y_client_bits.words.clone();
    let tau_client_bits = tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bits)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bits)?;
    let input_sharing_duration_ns = elapsed_ns(input_sharing_started_ns);

    let add_started_ns = monotonic_now_ns();
    let d_bits = execute_add_stage(
        backend,
        &program.stages[0],
        &y_client_bits_local,
        &y_relayer_bits.left_words,
        &y_relayer_bits.right_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let add_stage_duration_ns = elapsed_ns(add_started_ns);

    let schedule_started_ns = monotonic_now_ns();
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let message_schedule_duration_ns = elapsed_ns(schedule_started_ns);
    let message_schedule_accumulation_duration_ns = schedule_output.accumulation_duration_ns;
    let message_schedule_accumulation_add_timing = schedule_output.accumulation_add_timing;

    let round_started_ns = monotonic_now_ns();
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let round_core_duration_ns = elapsed_ns(round_started_ns);
    let hash_core = round_output.hash_core;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;

    let output_started_ns = monotonic_now_ns();
    let output = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &hash_core.final_words,
        &tau_client_bits_local,
        &tau_relayer_bits.left_words,
        &tau_relayer_bits.right_words,
    )?;
    let output_projector_duration_ns = elapsed_ns(output_started_ns);

    Ok(ExecutionUntilOutputProjector {
        stage_profile: DdhHiddenEvalStageProfile {
            input_sharing_duration_ns,
            add_stage_duration_ns,
            message_schedule_duration_ns,
            message_schedule_accumulation_duration_ns,
            message_schedule_accumulation_xor_ab_duration_ns:
                message_schedule_accumulation_add_timing.xor_ab_duration_ns,
            message_schedule_accumulation_sum_duration_ns: message_schedule_accumulation_add_timing
                .sum_duration_ns,
            message_schedule_accumulation_a_xor_carry_duration_ns:
                message_schedule_accumulation_add_timing.a_xor_carry_duration_ns,
            message_schedule_accumulation_carry_gate_duration_ns:
                message_schedule_accumulation_add_timing.carry_gate_duration_ns,
            message_schedule_accumulation_next_carry_duration_ns:
                message_schedule_accumulation_add_timing.next_carry_duration_ns,
            round_core_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            output_projector_duration_ns,
            total_duration_ns: elapsed_ns(total_started_ns),
        },
        run: DdhHiddenEvalRun {
            client_input_commitment,
            server_input_commitment,
            output,
        },
    })
}

fn execute_prime_order_ddh_hidden_eval_program_internal_with_transport_server_inputs<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_left: &DdhHssTransportBundle,
    y_relayer_right: &DdhHssTransportBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_left: &DdhHssTransportBundle,
    tau_relayer_right: &DdhHssTransportBundle,
) -> ProtoResult<ExecutionUntilOutputProjector> {
    ensure_program_shape(program)?;
    let total_started_ns = monotonic_now_ns();
    let input_sharing_started_ns = monotonic_now_ns();
    validate_input_bit_bundle(y_client_bits, HiddenEvalInputOwner::Client, "y_client_bits")?;
    validate_server_input_transport_bundle_pair(
        backend.evaluation_key(),
        y_relayer_left,
        y_relayer_right,
        HiddenEvalInputOwner::Server,
        "y_relayer_bits",
    )?;
    validate_input_bit_bundle(
        tau_client_bits,
        HiddenEvalInputOwner::Client,
        "tau_client_bits",
    )?;
    validate_server_input_transport_bundle_pair(
        backend.evaluation_key(),
        tau_relayer_left,
        tau_relayer_right,
        HiddenEvalInputOwner::Server,
        "tau_relayer_bits",
    )?;

    let client_input_commitment = combine_bundle_commitments(
        backend,
        HiddenEvalInputOwner::Client,
        &[y_client_bits, tau_client_bits],
    );
    let server_input_commitment =
        combine_server_input_transport_commitments(backend, y_relayer_left, tau_relayer_left);
    let y_client_bits = y_client_bits.words.clone();
    let tau_client_bits = tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bits)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bits)?;
    let input_sharing_duration_ns = elapsed_ns(input_sharing_started_ns);

    let add_started_ns = monotonic_now_ns();
    let d_bits = execute_add_stage(
        backend,
        &program.stages[0],
        &y_client_bits_local,
        &y_relayer_left.words,
        &y_relayer_right.words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let add_stage_duration_ns = elapsed_ns(add_started_ns);

    let schedule_started_ns = monotonic_now_ns();
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let message_schedule_duration_ns = elapsed_ns(schedule_started_ns);
    let message_schedule_accumulation_duration_ns = schedule_output.accumulation_duration_ns;
    let message_schedule_accumulation_add_timing = schedule_output.accumulation_add_timing;

    let round_started_ns = monotonic_now_ns();
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let round_core_duration_ns = elapsed_ns(round_started_ns);
    let hash_core = round_output.hash_core;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;

    let output_started_ns = monotonic_now_ns();
    let output = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &hash_core.final_words,
        &tau_client_bits_local,
        &tau_relayer_left.words,
        &tau_relayer_right.words,
    )?;
    let output_projector_duration_ns = elapsed_ns(output_started_ns);

    Ok(ExecutionUntilOutputProjector {
        stage_profile: DdhHiddenEvalStageProfile {
            input_sharing_duration_ns,
            add_stage_duration_ns,
            message_schedule_duration_ns,
            message_schedule_accumulation_duration_ns,
            message_schedule_accumulation_xor_ab_duration_ns:
                message_schedule_accumulation_add_timing.xor_ab_duration_ns,
            message_schedule_accumulation_sum_duration_ns: message_schedule_accumulation_add_timing
                .sum_duration_ns,
            message_schedule_accumulation_a_xor_carry_duration_ns:
                message_schedule_accumulation_add_timing.a_xor_carry_duration_ns,
            message_schedule_accumulation_carry_gate_duration_ns:
                message_schedule_accumulation_add_timing.carry_gate_duration_ns,
            message_schedule_accumulation_next_carry_duration_ns:
                message_schedule_accumulation_add_timing.next_carry_duration_ns,
            round_core_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            output_projector_duration_ns,
            total_duration_ns: elapsed_ns(total_started_ns),
        },
        run: DdhHiddenEvalRun {
            client_input_commitment,
            server_input_commitment,
            output,
        },
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn monotonic_now_ns() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}

#[cfg(target_arch = "wasm32")]
fn monotonic_now_ns() -> u128 {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|performance| (performance.now() * 1_000_000.0) as u128)
        .unwrap_or(0)
}

fn elapsed_ns(started_ns: u128) -> u128 {
    monotonic_now_ns().saturating_sub(started_ns)
}

fn ensure_program_shape(program: &HiddenEvalProgram) -> ProtoResult<()> {
    if program.stages.len() != 7 {
        return Err(ProtoError::InvalidInput(format!(
            "expected 7 hidden-eval stages, got {}",
            program.stages.len()
        )));
    }
    Ok(())
}

fn execute_add_stage<B: DdhHssArithmeticBackend>(
    backend: &B,
    stage: &HiddenEvalStage,
    left_bits: &SplitLocalBitWord,
    right_left_bits: &[DdhHssTransportWord],
    right_right_bits: &[DdhHssTransportWord],
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    if stage.kind != HiddenEvalStageKind::AddMod2Pow256 {
        return Err(ProtoError::InvalidInput(
            "unexpected add-stage kind".to_string(),
        ));
    }
    if stage.windows.len() != 32 {
        return Err(ProtoError::Decode(format!(
            "add stage must contain 32 byte lanes, got {}",
            stage.windows.len()
        )));
    }
    add_two_local_bit_words_right_transport_bundles(
        backend,
        "add_mod_2pow256",
        left_bits,
        right_left_bits,
        right_right_bits,
        zero_left,
        zero_right,
    )
}

fn execute_message_schedule_stage<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    stage: &HiddenEvalStage,
    d_bits: &SplitLocalBitWord,
) -> ProtoResult<MessageScheduleStageOutput> {
    if stage.kind != HiddenEvalStageKind::MessageSchedule {
        return Err(ProtoError::InvalidInput(
            "unexpected message-schedule stage kind".to_string(),
        ));
    }

    let mut words = initial_one_block_schedule_prefix_local_words(
        d_bits,
        &constant_pool.schedule_suffix_words,
    )?;
    let mut accumulation_duration_ns = 0u128;
    let mut accumulation_add_timing = LocalBitWordAddTiming::default();
    for window in &stage.windows {
        let t = usize::from(window.class_value);
        if t < 16 || t >= 80 {
            return Err(ProtoError::Decode(format!(
                "message-schedule window class_value out of range: {t}"
            )));
        }

        let sigma0 = small_sigma0_local_bits(
            backend,
            &format!("message_schedule/{t}/sigma0"),
            &words[t - 15],
            &constant_pool.zero_left,
            &constant_pool.zero_right,
        )?;
        let sigma1 = small_sigma1_local_bits(
            backend,
            &format!("message_schedule/{t}/sigma1"),
            &words[t - 2],
            &constant_pool.zero_left,
            &constant_pool.zero_right,
        )?;
        let accumulation_started_ns = monotonic_now_ns();
        let (accumulation, add_timing) = add_four_local_bit_words_via_arithmetic_naive(
            backend,
            &format!("message_schedule/{t}"),
            &words[t - 16],
            &sigma0,
            &words[t - 7],
            &sigma1,
            &constant_pool.zero_left,
            &constant_pool.zero_right,
        )?;
        accumulation_duration_ns += elapsed_ns(accumulation_started_ns);
        accumulation_add_timing.add_assign(&add_timing);
        words.push(accumulation);
    }

    if words.len() != 80 {
        return Err(ProtoError::Decode(format!(
            "message schedule must contain 80 words, got {}",
            words.len()
        )));
    }

    Ok(MessageScheduleStageOutput {
        words,
        accumulation_duration_ns,
        accumulation_add_timing,
    })
}

fn execute_round_stages<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    stages: &[HiddenEvalStage],
    schedule: &[SplitLocalBitWord],
) -> ProtoResult<RoundStagesOutput> {
    let iv_words = constant_pool.sha512_iv_words.clone();
    let round_constants = constant_pool.sha512_round_constants.clone();
    let mut state = iv_words.clone();
    let mut sigma1_duration_ns = 0u128;
    let mut ch_duration_ns = 0u128;
    let mut temp1_duration_ns = 0u128;
    let mut temp1_add_timing = LocalBitWordAddTiming::default();
    let mut temp2_duration_ns = 0u128;

    for stage in stages {
        match stage.kind {
            HiddenEvalStageKind::RoundState00To19
            | HiddenEvalStageKind::RoundState20To39
            | HiddenEvalStageKind::RoundState40To59
            | HiddenEvalStageKind::RoundState60To79 => {}
            other => {
                return Err(ProtoError::InvalidInput(format!(
                    "unexpected round-stage kind: {:?}",
                    other
                )));
            }
        }

        for window in &stage.windows {
            let round = usize::from(window.class_value);
            let sigma1_started_ns = monotonic_now_ns();
            let sigma1 =
                big_sigma1_local_bits(backend, &format!("round_core/{round}/sigma1"), &state[4])?;
            sigma1_duration_ns += elapsed_ns(sigma1_started_ns);
            let ch_started_ns = monotonic_now_ns();
            let choose = ch_local_bits(
                backend,
                &format!("round_core/{round}/ch"),
                &state[4],
                &state[5],
                &state[6],
            )?;
            ch_duration_ns += elapsed_ns(ch_started_ns);
            let temp1_started_ns = monotonic_now_ns();
            let (temp1_arith, add_timing) = add_five_local_bit_words_to_arithmetic_naive(
                backend,
                &format!("round_core/{round}/temp1"),
                &state[7],
                &sigma1,
                &choose,
                &round_constants[round],
                &schedule[round],
            )?;
            temp1_duration_ns += elapsed_ns(temp1_started_ns);
            temp1_add_timing.add_assign(&add_timing);
            let sigma0 =
                big_sigma0_local_bits(backend, &format!("round_core/{round}/sigma0"), &state[0])?;
            let majority = maj_local_bits(
                backend,
                &format!("round_core/{round}/maj"),
                &state[0],
                &state[1],
                &state[2],
            )?;
            let temp2_started_ns = monotonic_now_ns();
            let (temp2_arith, _) = add_two_local_bit_words_to_arithmetic_naive(
                backend,
                &format!("round_core/{round}/temp2"),
                &sigma0,
                &majority,
            )?;
            temp2_duration_ns += elapsed_ns(temp2_started_ns);

            let new_a_arith = add_local_arithmetic_word_pairs(
                backend.evaluation_key(),
                &format!("round_core/{round}/new_a"),
                &temp1_arith,
                &temp2_arith,
            )?;
            let new_a = arithmetic_word_pair_to_split_local_bits_naive(
                backend,
                &format!("round_core/{round}/new_a_bits"),
                &new_a_arith,
                &constant_pool.zero_left,
                &constant_pool.zero_right,
            )?;

            let state3_arith = split_local_bits_to_arithmetic_word_pair_naive(
                backend,
                &format!("round_core/{round}/state3"),
                &state[3],
            )?;
            let new_e_arith = add_local_arithmetic_word_pairs(
                backend.evaluation_key(),
                &format!("round_core/{round}/new_e"),
                &state3_arith,
                &temp1_arith,
            )?;
            let new_e = arithmetic_word_pair_to_split_local_bits_naive(
                backend,
                &format!("round_core/{round}/new_e_bits"),
                &new_e_arith,
                &constant_pool.zero_left,
                &constant_pool.zero_right,
            )?;
            let old_a = std::mem::replace(&mut state[0], new_a);
            let old_b = std::mem::replace(&mut state[1], old_a);
            let old_c = std::mem::replace(&mut state[2], old_b);
            state[3] = old_c;
            let old_e = std::mem::replace(&mut state[4], new_e);
            let old_f = std::mem::replace(&mut state[5], old_e);
            let old_g = std::mem::replace(&mut state[6], old_f);
            state[7] = old_g;
        }
    }

    let mut final_words = Vec::with_capacity(8);
    for idx in 0..8 {
        let final_word_bits = add_two_local_bit_words(
            backend,
            &format!("round_core/final/{idx}"),
            &state[idx],
            &iv_words[idx],
            &constant_pool.zero_left,
            &constant_pool.zero_right,
        )?;
        final_words.push(final_word_bits);
    }
    Ok(RoundStagesOutput {
        hash_core: SharedHashCoreOutput { final_words },
        sigma1_duration_ns,
        ch_duration_ns,
        temp1_duration_ns,
        temp1_add_timing,
        temp2_duration_ns,
    })
}

fn execute_output_projector_stage<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    stage: &HiddenEvalStage,
    final_words: &[SplitLocalBitWord],
    tau_client_bits: &SplitLocalBitWord,
    tau_relayer_left_bits: &[DdhHssTransportWord],
    tau_relayer_right_bits: &[DdhHssTransportWord],
) -> ProtoResult<DdhHiddenEvalOutputBundles> {
    if stage.kind != HiddenEvalStageKind::OutputProjector {
        return Err(ProtoError::InvalidInput(
            "unexpected output-projector stage kind".to_string(),
        ));
    }

    let clamped_a_bits = extract_clamped_a_bits_local(
        final_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;
    let reduced_a_bits = reduce_scalar_bits_mod_l_with_constants_local(
        backend,
        "scalar_a",
        &clamped_a_bits,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
        7,
    )?;
    let tau_bits = add_words_bits_mod_l_canonical_inputs_right_transport_bundles_local(
        backend,
        tau_client_bits,
        tau_relayer_left_bits,
        tau_relayer_right_bits,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;
    let x_client_base_bits = add_words_bits_mod_l_canonical_inputs_local(
        backend,
        &reduced_a_bits,
        &tau_bits,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;
    let double_tau_bits = add_words_bits_mod_l_canonical_inputs_local(
        backend,
        &tau_bits,
        &tau_bits,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;
    let x_relayer_base_bits = add_words_bits_mod_l_canonical_inputs_local(
        backend,
        &reduced_a_bits,
        &double_tau_bits,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;

    Ok(DdhHiddenEvalOutputBundles {
        x_client_base: build_hidden_bit_output_bundle(
            backend,
            HiddenEvalInputOwner::Client,
            "x_client_base",
            &x_client_base_bits,
        )?,
        x_relayer_base_left: build_hidden_bit_output_transport_bundle(
            backend,
            HiddenEvalInputOwner::Server,
            "x_relayer_base",
            &x_relayer_base_bits,
            DdhHssShareSide::Left,
        )?,
        x_relayer_base_right: build_hidden_bit_output_transport_bundle(
            backend,
            HiddenEvalInputOwner::Server,
            "x_relayer_base",
            &x_relayer_base_bits,
            DdhHssShareSide::Right,
        )?,
    })
}

#[cfg(test)]
fn reduce_scalar_bits_mod_l(
    backend: &impl DdhHssArithmeticBackend,
    label: &str,
    scalar_bits: &[DdhHssSharedWord],
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let modulus_bits = scalar_modulus_bits(backend, &format!("{label}/reduce_mod_l/modulus"))?;
    let zero = constant_bit(backend, &format!("{label}/reduce_mod_l/zero"), false)?;
    let one = constant_bit(backend, &format!("{label}/reduce_mod_l/one"), true)?;
    reduce_scalar_bits_mod_l_with_constants(
        backend,
        label,
        scalar_bits,
        &modulus_bits,
        &zero,
        &one,
        7,
    )
}

#[cfg(test)]
fn reduce_scalar_bits_mod_l_with_constants<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    scalar_bits: &[DdhHssSharedWord],
    modulus_bits: &[DdhHssSharedWord],
    zero: &DdhHssSharedWord,
    one: &DdhHssSharedWord,
    rounds: usize,
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    if scalar_bits.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "{label} must contain exactly 256 bits, got {}",
            scalar_bits.len()
        )));
    }
    if modulus_bits.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "{label} modulus must contain exactly 256 bits, got {}",
            modulus_bits.len()
        )));
    }

    let mut reduced = scalar_bits.to_vec();
    let mut difference = Vec::with_capacity(reduced.len());
    let mut selected = Vec::with_capacity(reduced.len());
    for round in 0..rounds {
        let borrow = sub_two_words_bits_into(
            backend,
            &format!("{label}/reduce_mod_l/sub/{round}"),
            &reduced,
            modulus_bits,
            zero,
            one,
            &mut difference,
        )?;
        let geq_modulus = backend.eval_add_mod_2_pow_n(&borrow, one)?;
        select_word_bits_into(
            backend,
            &format!("{label}/reduce_mod_l/select/{round}"),
            &geq_modulus,
            &difference,
            &reduced,
            &mut selected,
        )?;
        std::mem::swap(&mut reduced, &mut selected);
    }
    Ok(reduced)
}

fn reduce_scalar_bits_mod_l_with_constants_local<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    scalar_bits: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    one_left: &DdhHssLocalWord,
    one_right: &DdhHssLocalWord,
    rounds: usize,
) -> ProtoResult<SplitLocalBitWord> {
    if scalar_bits.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "{label} must contain exactly 256 bits, got {}",
            scalar_bits.len()
        )));
    }

    let mut reduced = scalar_bits.clone();
    for round in 0..rounds {
        let (difference, borrow_left, borrow_right) = sub_local_bit_words_with_ed25519_l(
            backend,
            &format!("{label}/reduce_mod_l/sub/{round}"),
            &reduced,
            zero_left,
            zero_right,
            one_left,
            one_right,
        )?;
        let (geq_modulus_left, geq_modulus_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            format!("{label}/reduce_mod_l/geq/{round}").as_bytes(),
            &borrow_left,
            &borrow_right,
            one_left,
            one_right,
        )?;
        reduced = select_local_bit_words(
            backend,
            &format!("{label}/reduce_mod_l/select/{round}"),
            &geq_modulus_left,
            &geq_modulus_right,
            &difference,
            &reduced,
        )?;
    }
    Ok(reduced)
}

#[cfg(test)]
fn add_words_bits_mod_l(
    backend: &impl DdhHssArithmeticBackend,
    label: &str,
    left: &[DdhHssSharedWord],
    right: &[DdhHssSharedWord],
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let zero = constant_bit(backend, &format!("{label}/sum/zero"), false)?;
    let sum = add_two_words_bits(backend, &format!("{label}/sum"), left, right, &zero)?;
    reduce_scalar_bits_mod_l(backend, label, &sum)
}

fn add_words_bits_mod_l_canonical_inputs_local<B: DdhHssArithmeticBackend>(
    backend: &B,
    left: &SplitLocalBitWord,
    right: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    one_left: &DdhHssLocalWord,
    one_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    let sum = add_two_local_bit_words(
        backend,
        "reduce_mod_l/canonical/sum",
        left,
        right,
        zero_left,
        zero_right,
    )?;
    let (difference, borrow_left, borrow_right) = sub_local_bit_words_with_ed25519_l(
        backend,
        "reduce_mod_l/canonical/sub",
        &sum,
        zero_left,
        zero_right,
        one_left,
        one_right,
    )?;
    let (geq_modulus_left, geq_modulus_right) = xor_local_word_pairs_public(
        backend.evaluation_key(),
        b"reduce_mod_l/geq",
        &borrow_left,
        &borrow_right,
        one_left,
        one_right,
    )?;
    select_local_bit_words(
        backend,
        "reduce_mod_l/select",
        &geq_modulus_left,
        &geq_modulus_right,
        &difference,
        &sum,
    )
}

fn add_words_bits_mod_l_canonical_inputs_right_transport_bundles_local<
    B: DdhHssArithmeticBackend,
>(
    backend: &B,
    left: &SplitLocalBitWord,
    right_left: &[DdhHssTransportWord],
    right_right: &[DdhHssTransportWord],
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    one_left: &DdhHssLocalWord,
    one_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    let sum = add_two_local_bit_words_right_transport_bundles(
        backend,
        "reduce_mod_l/server_input/sum",
        left,
        right_left,
        right_right,
        zero_left,
        zero_right,
    )?;
    let (difference, borrow_left, borrow_right) = sub_local_bit_words_with_ed25519_l(
        backend,
        "reduce_mod_l/server_input/sub",
        &sum,
        zero_left,
        zero_right,
        one_left,
        one_right,
    )?;
    let (geq_modulus_left, geq_modulus_right) = xor_local_word_pairs_public(
        backend.evaluation_key(),
        b"reduce_mod_l/server_input/geq",
        &borrow_left,
        &borrow_right,
        one_left,
        one_right,
    )?;
    select_local_bit_words(
        backend,
        "reduce_mod_l/select",
        &geq_modulus_left,
        &geq_modulus_right,
        &difference,
        &sum,
    )
}

fn extract_clamped_a_bits_local(
    final_words: &[SplitLocalBitWord],
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    one_left: &DdhHssLocalWord,
    one_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    if final_words.len() < 4 {
        return Err(ProtoError::Decode(format!(
            "output projector requires at least 4 final SHA-512 words, got {}",
            final_words.len()
        )));
    }

    let mut left = empty_local_bit_slice(DdhHssShareSide::Left, 256);
    let mut right = empty_local_bit_slice(DdhHssShareSide::Right, 256);
    for (word_idx, word_bits) in final_words.iter().take(4).enumerate() {
        if word_bits.len() != 64 {
            return Err(ProtoError::Decode(format!(
                "output projector expected 64 split-local bits for SHA-512 word, got {}",
                word_bits.len()
            )));
        }
        for byte_idx in 0..8 {
            let global_byte_idx = word_idx * 8 + byte_idx;
            let start = (7 - byte_idx) * 8;
            for bit_idx in 0..8 {
                let absolute_idx = start + bit_idx;
                let mut left_word = word_bits.left.local_word(absolute_idx)?;
                let mut right_word = word_bits.right.local_word(absolute_idx)?;
                if global_byte_idx == 0 && bit_idx < 3 {
                    left_word = zero_left.clone();
                    right_word = zero_right.clone();
                } else if global_byte_idx == 31 && bit_idx == 6 {
                    left_word = one_left.clone();
                    right_word = one_right.clone();
                } else if global_byte_idx == 31 && bit_idx == 7 {
                    left_word = zero_left.clone();
                    right_word = zero_right.clone();
                }
                left.push_local_word(&left_word)?;
                right.push_local_word(&right_word)?;
            }
        }
    }

    SplitLocalBitWord::from_local_sides(left, right)
}

fn validate_input_bit_bundle(
    bundle: &DdhHssInputShareBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<()> {
    if bundle.owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "input bit bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, bundle.owner
        )));
    }
    if bundle.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "input bit bundle label mismatch: expected {expected_label}, got {}",
            bundle.label
        )));
    }
    if bundle.words.len() != 256 {
        return Err(ProtoError::InvalidInput(format!(
            "input bit bundle {expected_label} must contain 256 bits, got {}",
            bundle.words.len()
        )));
    }
    if bundle.words.iter().any(|word| word.width_bits != 1) {
        return Err(ProtoError::InvalidInput(format!(
            "input bit bundle {expected_label} must contain 1-bit words"
        )));
    }
    Ok(())
}

fn validate_server_input_bit_bundle(
    bundle: &DdhHiddenEvalServerInputBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<()> {
    if bundle.owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, bundle.owner
        )));
    }
    if bundle.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle label mismatch: expected {expected_label}, got {}",
            bundle.label
        )));
    }
    if bundle.left_words.len() != 256 || bundle.right_words.len() != 256 {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle {expected_label} must contain 256 bits, got {} and {}",
            bundle.left_words.len(),
            bundle.right_words.len()
        )));
    }
    if bundle
        .left_words
        .iter()
        .zip(&bundle.right_words)
        .any(|(left_word, right_word)| {
            left_word.width_bits != 1
                || right_word.width_bits != 1
                || left_word.share_side != DdhHssShareSide::Left
                || right_word.share_side != DdhHssShareSide::Right
        })
    {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle {expected_label} must contain 1-bit words"
        )));
    }
    for (left_word, right_word) in bundle.left_words.iter().zip(&bundle.right_words) {
        validate_transport_word_pair_public(
            HiddenEvalInputOwner::Server,
            HiddenEvalInputOwner::Server,
            left_word,
            right_word,
        )?;
    }
    Ok(())
}

fn validate_server_input_transport_bundle_pair(
    evaluation_key: &crate::ddh_hss::DdhHssEvaluationKey,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<()> {
    validate_transport_bundle_pair_public(evaluation_key, left, right)?;
    if left.owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, left.owner
        )));
    }
    if left.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle label mismatch: expected {expected_label}, got {}",
            left.label
        )));
    }
    if left.words.len() != 256 {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle {expected_label} must contain 256 bits, got {}",
            left.words.len()
        )));
    }
    if left
        .words
        .iter()
        .zip(&right.words)
        .any(|(left_word, right_word)| {
            left_word.width_bits != 1
                || right_word.width_bits != 1
                || left_word.share_side != DdhHssShareSide::Left
                || right_word.share_side != DdhHssShareSide::Right
        })
    {
        return Err(ProtoError::InvalidInput(format!(
            "server input bit bundle {expected_label} must contain 1-bit words"
        )));
    }
    Ok(())
}

fn build_hidden_bit_output_bundle<B: DdhHssArithmeticBackend>(
    backend: &B,
    owner: HiddenEvalInputOwner,
    label: &str,
    bits: &SplitLocalBitWord,
) -> ProtoResult<DdhHssInputShareBundle> {
    let words = canonicalize_hidden_bit_output_words(owner, label, bits)?;
    let commitment = backend.input_commitment(owner, label, &words);
    Ok(DdhHssInputShareBundle {
        owner,
        label: label.to_string(),
        words,
        commitment,
    })
}

fn build_hidden_bit_output_transport_bundle<B: DdhHssArithmeticBackend>(
    backend: &B,
    owner: HiddenEvalInputOwner,
    label: &str,
    bits: &SplitLocalBitWord,
    share_side: DdhHssShareSide,
) -> ProtoResult<DdhHssTransportBundle> {
    let canonical_words = canonicalize_hidden_bit_output_words(owner, label, bits)?;
    let commitment = backend.input_commitment(owner, label, &canonical_words);
    let words = canonical_words
        .iter()
        .map(|bit| match share_side {
            DdhHssShareSide::Left => DdhHssTransportWord {
                width_bits: bit.width_bits,
                share_side,
                share_word: bit.left_word,
                share_commitment: bit.left_commitment,
                counterparty_commitment: bit.right_commitment,
                provenance_digest: bit.provenance_digest,
            },
            DdhHssShareSide::Right => DdhHssTransportWord {
                width_bits: bit.width_bits,
                share_side,
                share_word: bit.right_word,
                share_commitment: bit.right_commitment,
                counterparty_commitment: bit.left_commitment,
                provenance_digest: bit.provenance_digest,
            },
        })
        .collect();
    Ok(DdhHssTransportBundle {
        owner,
        label: label.to_string(),
        share_side,
        words,
        commitment,
    })
}

fn canonicalize_hidden_bit_output_words(
    owner: HiddenEvalInputOwner,
    label: &str,
    bits: &SplitLocalBitWord,
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let shared_bits = bits.to_shared_bits()?;
    if shared_bits.len() != 256 {
        return Err(ProtoError::InvalidInput(format!(
            "{label} must contain exactly 256 bits, got {}",
            shared_bits.len()
        )));
    }
    if shared_bits.iter().any(|bit| bit.width_bits != 1) {
        return Err(ProtoError::InvalidInput(format!(
            "{label} must contain only 1-bit words"
        )));
    }
    Ok(shared_bits
        .iter()
        .map(|bit| DdhHssSharedWord {
            width_bits: bit.width_bits,
            left_word: bit.left_word,
            right_word: bit.right_word,
            left_commitment: crate::ddh_hss::commit_word(
                owner,
                b"left",
                bit.left_word,
                &bit.provenance_digest,
            ),
            right_commitment: crate::ddh_hss::commit_word(
                owner,
                b"right",
                bit.right_word,
                &bit.provenance_digest,
            ),
            provenance_digest: bit.provenance_digest,
        })
        .collect())
}

#[cfg(test)]
fn share_input_bits(
    backend: &impl DdhHssArithmeticBackend,
    owner: HiddenEvalInputOwner,
    label: &str,
    input: &[u8],
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let mut bits = Vec::with_capacity(input.len() * 8);
    for (byte_idx, byte) in input.iter().enumerate() {
        for bit_idx in 0..8 {
            bits.push(backend.share_word(
                owner,
                &format!("{label}/{byte_idx}/{bit_idx}"),
                u64::from((byte >> bit_idx) & 1),
                1,
            )?);
        }
    }
    Ok(bits)
}

fn sha512_iv_words_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
) -> ProtoResult<[SplitLocalBitWord; 8]> {
    let mut words = Vec::with_capacity(8);
    for (idx, value) in SHA512_IV.iter().copied().enumerate() {
        words.push(SplitLocalBitWord::from_shared_bits(&constant_word_bits(
            backend,
            &format!("sha512_iv/{idx}"),
            value,
            64,
        )?)?);
    }
    words
        .try_into()
        .map_err(|_| ProtoError::Decode("failed to materialize SHA-512 IV words".to_string()))
}

#[cfg_attr(not(test), allow(dead_code))]
fn scalar_modulus_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let mut modulus_bits = Vec::with_capacity(256);
    for (byte_idx, byte) in ED25519_L_BYTES_LE.iter().copied().enumerate() {
        modulus_bits.extend(constant_byte_bits(
            backend,
            &format!("{label}/{byte_idx}"),
            byte,
        )?);
    }
    Ok(modulus_bits)
}

fn sha512_round_constant_words_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
) -> ProtoResult<Vec<SplitLocalBitWord>> {
    SHA512_ROUND_CONSTANTS
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, value)| {
            SplitLocalBitWord::from_shared_bits(&constant_word_bits(
                backend,
                &format!("sha512_round_constant/{idx}"),
                value,
                64,
            )?)
        })
        .collect()
}

fn initial_one_block_schedule_prefix_local_words(
    d_bits: &SplitLocalBitWord,
    schedule_suffix_words: &[SplitLocalBitWord],
) -> ProtoResult<Vec<SplitLocalBitWord>> {
    if d_bits.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "expected 256 message bits, got {}",
            d_bits.len()
        )));
    }

    let mut words = Vec::with_capacity(16);
    for word_idx in 0..4 {
        let mut left_bits = empty_local_bit_slice(DdhHssShareSide::Left, 64);
        let mut right_bits = empty_local_bit_slice(DdhHssShareSide::Right, 64);
        let byte_start = word_idx * 64;
        for byte_idx in (0..8).rev() {
            let bit_start = byte_start + byte_idx * 8;
            for idx in bit_start..bit_start + 8 {
                left_bits.push_share_bit(d_bits.left.share_bit(idx));
                left_bits.commitments.push(d_bits.left.commitments[idx]);
                left_bits
                    .provenance_digests
                    .push(d_bits.left.provenance_digests[idx]);
                right_bits.push_share_bit(d_bits.right.share_bit(idx));
                right_bits.commitments.push(d_bits.right.commitments[idx]);
                right_bits
                    .provenance_digests
                    .push(d_bits.right.provenance_digests[idx]);
            }
        }
        words.push(SplitLocalBitWord::from_local_sides(left_bits, right_bits)?);
    }
    for word_bits in schedule_suffix_words {
        words.push(word_bits.clone());
    }
    Ok(words)
}

fn one_block_schedule_constant_suffix_words_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
) -> ProtoResult<Vec<SplitLocalBitWord>> {
    const SUFFIX_WORDS: [u64; 12] = [
        0x8000_0000_0000_0000,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        32u64 * 8,
    ];

    SUFFIX_WORDS
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, value)| {
            SplitLocalBitWord::from_shared_bits(&constant_word_bits(
                backend,
                &format!("schedule_suffix/{}", idx + 4),
                value,
                64,
            )?)
        })
        .collect()
}

fn constant_bit<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    value: bool,
) -> ProtoResult<DdhHssSharedWord> {
    backend.share_word(HiddenEvalInputOwner::Derived, label, u64::from(value), 1)
}

#[cfg_attr(not(test), allow(dead_code))]
fn constant_byte_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    value: u8,
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    constant_word_bits(backend, label, u64::from(value), 8)
}

fn constant_word_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    value: u64,
    width_bits: usize,
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let mut bits = Vec::with_capacity(width_bits);
    for bit_idx in 0..width_bits {
        bits.push(constant_bit(
            backend,
            &format!("{label}/{bit_idx}"),
            ((value >> bit_idx) & 1) == 1,
        )?);
    }
    Ok(bits)
}

fn empty_local_bit_slice(share_side: DdhHssShareSide, len: usize) -> LocalBitWordSide {
    LocalBitWordSide::empty(share_side, len)
}

#[derive(Debug, Copy, Clone)]
enum LocalBitTransform {
    Rotate(usize),
    Shift(usize),
}

#[derive(Debug, Copy, Clone)]
struct LocalBitTransformSpec<'a> {
    transform: LocalBitTransform,
    zero: Option<&'a DdhHssLocalWord>,
}

fn transformed_local_bit_parts(
    source: &LocalBitWordSide,
    idx: usize,
    spec: LocalBitTransformSpec<'_>,
) -> ProtoResult<(u8, [u8; 32])> {
    match spec.transform {
        LocalBitTransform::Rotate(offset) => {
            let transformed_idx = (idx + offset) % source.len();
            Ok((
                source.share_bit(transformed_idx),
                source.provenance_digests[transformed_idx],
            ))
        }
        LocalBitTransform::Shift(shift) => {
            let zero = spec.zero.ok_or_else(|| {
                ProtoError::InvalidInput(
                    "shifted local bit transform requires a zero word".to_string(),
                )
            })?;
            if zero.share_side != source.share_side || zero.width_bits != 1 {
                return Err(ProtoError::InvalidInput(
                    "shifted local bit transform requires width-1 zero on the same side"
                        .to_string(),
                ));
            }
            if idx + shift < source.len() {
                Ok((
                    source.share_bit(idx + shift),
                    source.provenance_digests[idx + shift],
                ))
            } else {
                Ok(((zero.share_word as u8) & 1, zero.provenance_digest))
            }
        }
    }
}

fn xor_transformed_local_bit_word_side(
    evaluation_key: &crate::ddh_hss::DdhHssEvaluationKey,
    label: &str,
    source: &LocalBitWordSide,
    transforms: [LocalBitTransformSpec<'_>; 3],
) -> ProtoResult<LocalBitWordSide> {
    source.ensure_shape()?;
    let mut out = empty_local_bit_slice(source.share_side, source.len());
    for idx in 0..source.len() {
        let (first_bit, first_provenance) =
            transformed_local_bit_parts(source, idx, transforms[0])?;
        let (second_bit, second_provenance) =
            transformed_local_bit_parts(source, idx, transforms[1])?;
        let (third_bit, third_provenance) =
            transformed_local_bit_parts(source, idx, transforms[2])?;
        let xor01 = xor_local_bit_from_raw_public(
            evaluation_key,
            format!("{label}/xor01/{idx}").as_bytes(),
            source.share_side,
            first_bit,
            &first_provenance,
            second_bit,
            &second_provenance,
        );
        let xor012 = xor_local_bit_from_raw_public(
            evaluation_key,
            format!("{label}/xor012/{idx}").as_bytes(),
            source.share_side,
            (xor01.share_word as u8) & 1,
            &xor01.provenance_digest,
            third_bit,
            &third_provenance,
        );
        out.push_local_word(&xor012)?;
    }
    Ok(out)
}

fn split_local_bit_word_from_local_word_pairs(
    left_words: &[DdhHssLocalWord],
    right_words: &[DdhHssLocalWord],
) -> ProtoResult<SplitLocalBitWord> {
    if left_words.len() != right_words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "split local word pair vector length mismatch: {} vs {}",
            left_words.len(),
            right_words.len()
        )));
    }
    let mut left = empty_local_bit_slice(DdhHssShareSide::Left, left_words.len());
    let mut right = empty_local_bit_slice(DdhHssShareSide::Right, right_words.len());
    for (left_word, right_word) in left_words.iter().zip(right_words) {
        left.push_local_word(left_word)?;
        right.push_local_word(right_word)?;
    }
    SplitLocalBitWord::from_local_sides(left, right)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalArithmeticWordPair {
    left: DdhHssLocalWord,
    right: DdhHssLocalWord,
}

impl LocalArithmeticWordPair {
    fn new(left: DdhHssLocalWord, right: DdhHssLocalWord) -> ProtoResult<Self> {
        if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
            return Err(ProtoError::InvalidInput(
                "local arithmetic word pair requires left/right shares".to_string(),
            ));
        }
        if left.width_bits != right.width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "local arithmetic word pair width mismatch: {} vs {}",
                left.width_bits, right.width_bits
            )));
        }
        if left.provenance_digest != right.provenance_digest {
            return Err(ProtoError::InvalidInput(
                "local arithmetic word pair provenance mismatch".to_string(),
            ));
        }
        Ok(Self { left, right })
    }
}

fn modulus_for_width(width_bits: u16) -> u128 {
    if width_bits == 64 {
        1u128 << 64
    } else {
        1u128 << u32::from(width_bits)
    }
}

fn reduce_mod_2_pow_n(value: u128, width_bits: u16) -> u64 {
    let reduced = value % modulus_for_width(width_bits);
    reduced as u64
}

fn pack_local_side_share_bits(source: &LocalBitWordSide) -> ProtoResult<u64> {
    source.ensure_shape()?;
    if source.len() > 64 {
        return Err(ProtoError::InvalidInput(format!(
            "bit packing requires width <= 64, got {}",
            source.len()
        )));
    }
    let mut packed = 0u64;
    for idx in 0..source.len() {
        packed |= u64::from(source.share_bit(idx)) << idx;
    }
    Ok(packed)
}

fn one_sided_split_word_from_arithmetic_share(
    evaluation_key: &crate::ddh_hss::DdhHssEvaluationKey,
    label: &str,
    source: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    let width_bits = usize::from(source.width_bits);
    let mut left = empty_local_bit_slice(DdhHssShareSide::Left, width_bits);
    let mut right = empty_local_bit_slice(DdhHssShareSide::Right, width_bits);
    for idx in 0..width_bits {
        let bit = (source.share_word >> idx) & 1;
        let bit_label = format!("{label}/{idx}");
        let (derived_left, derived_right) = match source.share_side {
            DdhHssShareSide::Left => build_local_word_pair_public(
                evaluation_key,
                b"phase-a-arith-to-bool-bit",
                bit_label.as_bytes(),
                1,
                bit,
                0,
                &[&source.provenance_digest, &source.share_commitment],
            ),
            DdhHssShareSide::Right => build_local_word_pair_public(
                evaluation_key,
                b"phase-a-arith-to-bool-bit",
                bit_label.as_bytes(),
                1,
                0,
                bit,
                &[&source.provenance_digest, &source.share_commitment],
            ),
        };
        left.push_local_word(&derived_left)?;
        right.push_local_word(&derived_right)?;
    }
    SplitLocalBitWord::from_local_sides(left, right)
}

fn add_local_arithmetic_word_pairs(
    evaluation_key: &crate::ddh_hss::DdhHssEvaluationKey,
    label: &str,
    left: &LocalArithmeticWordPair,
    right: &LocalArithmeticWordPair,
) -> ProtoResult<LocalArithmeticWordPair> {
    let (out_left, out_right) = eval_add_local_word_pairs_mod_2_pow_n_public(
        evaluation_key,
        label.as_bytes(),
        &left.left,
        &left.right,
        &right.left,
        &right.right,
    )?;
    LocalArithmeticWordPair::new(out_left, out_right)
}

fn split_local_bits_to_arithmetic_word_pair_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    bits: &SplitLocalBitWord,
) -> ProtoResult<LocalArithmeticWordPair> {
    if bits.len() == 0 || bits.len() > 64 {
        return Err(ProtoError::InvalidInput(format!(
            "phase-a word conversion requires width 1..=64, got {}",
            bits.len()
        )));
    }
    let width_bits = u16::try_from(bits.len()).map_err(|_| {
        ProtoError::InvalidInput(format!(
            "phase-a word conversion width does not fit u16: {}",
            bits.len()
        ))
    })?;
    let left_packed = pack_local_side_share_bits(&bits.left)?;
    let mut adjusted_right = pack_local_side_share_bits(&bits.right)?;
    for idx in 0..bits.len() {
        if idx + 1 >= bits.len() {
            continue;
        }
        let cross = u64::from(bits.left.share_bit(idx) & bits.right.share_bit(idx));
        if cross == 0 {
            continue;
        }
        adjusted_right = reduce_mod_2_pow_n(
            modulus_for_width(width_bits) + u128::from(adjusted_right) - (1u128 << (idx + 1)),
            width_bits,
        );
    }
    let mut base_material = Vec::with_capacity(bits.len() * 5);
    for idx in 0..bits.len() {
        base_material.push(bits.left.provenance_digests[idx].as_slice());
        base_material.push(bits.left.commitments[idx].as_slice());
        base_material.push(bits.right.provenance_digests[idx].as_slice());
        base_material.push(bits.right.commitments[idx].as_slice());
    }
    let (base_left, base_right) = build_local_word_pair_public(
        backend.evaluation_key(),
        b"phase-a-bool-to-arith-base",
        label.as_bytes(),
        width_bits,
        left_packed,
        adjusted_right,
        &base_material,
    );
    LocalArithmeticWordPair::new(base_left, base_right)
}

fn arithmetic_word_pair_to_split_local_bits_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: &LocalArithmeticWordPair,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    let left_bits = one_sided_split_word_from_arithmetic_share(
        backend.evaluation_key(),
        &format!("{label}/left"),
        &word.left,
    )?;
    let right_bits = one_sided_split_word_from_arithmetic_share(
        backend.evaluation_key(),
        &format!("{label}/right"),
        &word.right,
    )?;
    add_two_local_bit_words(
        backend,
        &format!("{label}/sum"),
        &left_bits,
        &right_bits,
        zero_left,
        zero_right,
    )
}

fn add_four_local_bit_words_via_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: &SplitLocalBitWord,
    b: &SplitLocalBitWord,
    c: &SplitLocalBitWord,
    d: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<(SplitLocalBitWord, LocalBitWordAddTiming)> {
    let (abcd, timing) = add_four_local_bit_words_to_arithmetic_naive(backend, label, a, b, c, d)?;
    Ok((
        arithmetic_word_pair_to_split_local_bits_naive(
            backend,
            &format!("{label}/out"),
            &abcd,
            zero_left,
            zero_right,
        )?,
        timing,
    ))
}

fn add_two_local_bit_words_to_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: &SplitLocalBitWord,
    b: &SplitLocalBitWord,
) -> ProtoResult<(LocalArithmeticWordPair, LocalBitWordAddTiming)> {
    let a_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/a"), a)?;
    let b_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/b"), b)?;
    Ok((
        add_local_arithmetic_word_pairs(backend.evaluation_key(), label, &a_arith, &b_arith)?,
        LocalBitWordAddTiming::default(),
    ))
}

fn add_four_local_bit_words_to_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: &SplitLocalBitWord,
    b: &SplitLocalBitWord,
    c: &SplitLocalBitWord,
    d: &SplitLocalBitWord,
) -> ProtoResult<(LocalArithmeticWordPair, LocalBitWordAddTiming)> {
    let a_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/a"), a)?;
    let b_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/b"), b)?;
    let c_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/c"), c)?;
    let d_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/d"), d)?;
    let ab = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &format!("{label}/ab"),
        &a_arith,
        &b_arith,
    )?;
    let abc = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &format!("{label}/abc"),
        &ab,
        &c_arith,
    )?;
    let abcd = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &format!("{label}/abcd"),
        &abc,
        &d_arith,
    )?;
    Ok((abcd, LocalBitWordAddTiming::default()))
}

fn add_five_local_bit_words_to_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: &SplitLocalBitWord,
    b: &SplitLocalBitWord,
    c: &SplitLocalBitWord,
    d: &SplitLocalBitWord,
    e: &SplitLocalBitWord,
) -> ProtoResult<(LocalArithmeticWordPair, LocalBitWordAddTiming)> {
    let (abcd, timing) = add_four_local_bit_words_to_arithmetic_naive(backend, label, a, b, c, d)?;
    let e_arith =
        split_local_bits_to_arithmetic_word_pair_naive(backend, &format!("{label}/e"), e)?;
    let abcde = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &format!("{label}/abcde"),
        &abcd,
        &e_arith,
    )?;
    Ok((abcde, timing))
}

fn local_bit_word_side_to_local_words(
    source: &LocalBitWordSide,
) -> ProtoResult<Vec<DdhHssLocalWord>> {
    source.ensure_shape()?;
    let mut out = Vec::with_capacity(source.len());
    for idx in 0..source.len() {
        out.push(source.local_word(idx)?);
    }
    Ok(out)
}

fn mul_local_bit_words_batched(
    evaluation_key: &crate::ddh_hss::DdhHssEvaluationKey,
    label_prefix: &str,
    left: &SplitLocalBitWord,
    right: &SplitLocalBitWord,
) -> ProtoResult<SplitLocalBitWord> {
    let left_left_words = local_bit_word_side_to_local_words(&left.left)?;
    let left_right_words = local_bit_word_side_to_local_words(&left.right)?;
    let right_left_words = local_bit_word_side_to_local_words(&right.left)?;
    let right_right_words = local_bit_word_side_to_local_words(&right.right)?;
    let (out_left, out_right) = eval_mul_local_word_pair_batch_public(
        evaluation_key,
        label_prefix,
        &left_left_words,
        &left_right_words,
        &right_left_words,
        &right_right_words,
    )?;
    split_local_bit_word_from_local_word_pairs(&out_left, &out_right)
}

fn add_two_local_bit_words<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &SplitLocalBitWord,
    right: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    Ok(add_two_local_bit_words_profiled(backend, label, left, right, zero_left, zero_right)?.0)
}

fn add_two_local_bit_words_profiled<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &SplitLocalBitWord,
    right: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<(SplitLocalBitWord, LocalBitWordAddTiming)> {
    if left.len() != right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "word addition requires same-width local bit slices, got {} and {}",
            left.len(),
            right.len()
        )));
    }
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, left.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, left.len());
    let mut carry_left = zero_left.clone();
    let mut carry_right = zero_right.clone();
    let mut timing = LocalBitWordAddTiming::default();
    for idx in 0..left.len() {
        let left_left_word = left.left.local_word(idx)?;
        let left_right_word = left.right.local_word(idx)?;
        let right_left_word = right.left.local_word(idx)?;
        let right_right_word = right.right.local_word(idx)?;
        let xor_ab_label = format!("{label}/xor_ab/{idx}");
        let xor_ab_started_ns = monotonic_now_ns();
        let (xor_ab_left, xor_ab_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            xor_ab_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &right_left_word,
            &right_right_word,
        )?;
        timing.xor_ab_duration_ns = timing
            .xor_ab_duration_ns
            .saturating_add(elapsed_ns(xor_ab_started_ns));
        let sum_label = format!("{label}/sum/{idx}");
        let sum_started_ns = monotonic_now_ns();
        let (sum_left, sum_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            sum_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &carry_left,
            &carry_right,
        )?;
        timing.sum_duration_ns = timing
            .sum_duration_ns
            .saturating_add(elapsed_ns(sum_started_ns));
        let a_xor_carry_label = format!("{label}/a_xor_carry/{idx}");
        let a_xor_carry_started_ns = monotonic_now_ns();
        let (a_xor_carry_left, a_xor_carry_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            a_xor_carry_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &carry_left,
            &carry_right,
        )?;
        timing.a_xor_carry_duration_ns = timing
            .a_xor_carry_duration_ns
            .saturating_add(elapsed_ns(a_xor_carry_started_ns));
        let carry_gate_label = format!("{label}/carry/{idx}");
        let carry_gate_started_ns = monotonic_now_ns();
        let (carry_gate_left, carry_gate_right) = eval_mul_local_word_pairs_public(
            backend.evaluation_key(),
            carry_gate_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &a_xor_carry_left,
            &a_xor_carry_right,
        )?;
        timing.carry_gate_duration_ns = timing
            .carry_gate_duration_ns
            .saturating_add(elapsed_ns(carry_gate_started_ns));
        let next_carry_label = format!("{label}/next_carry/{idx}");
        let next_carry_started_ns = monotonic_now_ns();
        (carry_left, carry_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            next_carry_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &carry_gate_left,
            &carry_gate_right,
        )?;
        timing.next_carry_duration_ns = timing
            .next_carry_duration_ns
            .saturating_add(elapsed_ns(next_carry_started_ns));
        out_left.push_local_word(&sum_left)?;
        out_right.push_local_word(&sum_right)?;
    }
    Ok((
        SplitLocalBitWord::from_local_sides(out_left, out_right)?,
        timing,
    ))
}

fn add_two_local_bit_words_right_transport_bundles<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &SplitLocalBitWord,
    right_left: &[DdhHssTransportWord],
    right_right: &[DdhHssTransportWord],
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    if left.len() != right_left.len() || right_left.len() != right_right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "word addition requires same-width bit slices, got {}, {}, and {}",
            left.len(),
            right_left.len(),
            right_right.len()
        )));
    }
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, left.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, left.len());
    let mut carry_left = zero_left.clone();
    let mut carry_right = zero_right.clone();
    for idx in 0..left.len() {
        validate_transport_word_pair_public(
            HiddenEvalInputOwner::Server,
            HiddenEvalInputOwner::Server,
            &right_left[idx],
            &right_right[idx],
        )?;
        let left_left_word = left.left.local_word(idx)?;
        let left_right_word = left.right.local_word(idx)?;
        let right_left_word = local_word_from_transport_public(&right_left[idx])?;
        let right_right_word = local_word_from_transport_public(&right_right[idx])?;
        let xor_ab_label = format!("{label}/xor_ab/{idx}");
        let (xor_ab_left, xor_ab_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            xor_ab_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &right_left_word,
            &right_right_word,
        )?;
        let sum_label = format!("{label}/sum/{idx}");
        let (sum_left, sum_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            sum_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &carry_left,
            &carry_right,
        )?;
        let a_xor_carry_label = format!("{label}/a_xor_carry/{idx}");
        let (a_xor_carry_left, a_xor_carry_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            a_xor_carry_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &carry_left,
            &carry_right,
        )?;
        let carry_gate_label = format!("{label}/carry/{idx}");
        let (carry_gate_left, carry_gate_right) = eval_mul_local_word_pairs_public(
            backend.evaluation_key(),
            carry_gate_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &a_xor_carry_left,
            &a_xor_carry_right,
        )?;
        let next_carry_label = format!("{label}/next_carry/{idx}");
        (carry_left, carry_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            next_carry_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &carry_gate_left,
            &carry_gate_right,
        )?;
        out_left.push_local_word(&sum_left)?;
        out_right.push_local_word(&sum_right)?;
    }
    SplitLocalBitWord::from_local_sides(out_left, out_right)
}

fn or_local_word_pairs<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> ProtoResult<(DdhHssLocalWord, DdhHssLocalWord)> {
    let (xor_left, xor_right) = xor_local_word_pairs_public(
        backend.evaluation_key(),
        format!("{label}/xor").as_bytes(),
        left_left,
        left_right,
        right_left,
        right_right,
    )?;
    let (and_left, and_right) = eval_mul_local_word_pairs_public(
        backend.evaluation_key(),
        format!("{label}/and").as_bytes(),
        left_left,
        left_right,
        right_left,
        right_right,
    )?;
    xor_local_word_pairs_public(
        backend.evaluation_key(),
        format!("{label}/out").as_bytes(),
        &xor_left,
        &xor_right,
        &and_left,
        &and_right,
    )
}

fn ed25519_l_bit(bit_idx: usize) -> bool {
    ((ED25519_L_BYTES_LE[bit_idx / 8] >> (bit_idx % 8)) & 1) == 1
}

fn sub_local_bit_words_with_ed25519_l<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    one_left: &DdhHssLocalWord,
    one_right: &DdhHssLocalWord,
) -> ProtoResult<(SplitLocalBitWord, DdhHssLocalWord, DdhHssLocalWord)> {
    if left.len() != 256 {
        return Err(ProtoError::InvalidInput(format!(
            "fixed-modulus subtraction requires 256-bit input, got {}",
            left.len()
        )));
    }
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, left.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, left.len());
    let mut borrow_left = zero_left.clone();
    let mut borrow_right = zero_right.clone();
    for idx in 0..left.len() {
        let left_left_word = left.left.local_word(idx)?;
        let left_right_word = left.right.local_word(idx)?;
        let (not_left_left, not_left_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            format!("{label}/not_left/{idx}").as_bytes(),
            &left_left_word,
            &left_right_word,
            one_left,
            one_right,
        )?;
        let (diff_left, diff_right) = if ed25519_l_bit(idx) {
            xor_local_word_pairs_public(
                backend.evaluation_key(),
                format!("{label}/diff_one/{idx}").as_bytes(),
                &not_left_left,
                &not_left_right,
                &borrow_left,
                &borrow_right,
            )?
        } else {
            xor_local_word_pairs_public(
                backend.evaluation_key(),
                format!("{label}/diff_zero/{idx}").as_bytes(),
                &left_left_word,
                &left_right_word,
                &borrow_left,
                &borrow_right,
            )?
        };
        (borrow_left, borrow_right) = if ed25519_l_bit(idx) {
            or_local_word_pairs(
                backend,
                &format!("{label}/borrow_one/{idx}"),
                &not_left_left,
                &not_left_right,
                &borrow_left,
                &borrow_right,
            )?
        } else {
            eval_mul_local_word_pairs_public(
                backend.evaluation_key(),
                format!("{label}/borrow_zero/{idx}").as_bytes(),
                &not_left_left,
                &not_left_right,
                &borrow_left,
                &borrow_right,
            )?
        };
        out_left.push_local_word(&diff_left)?;
        out_right.push_local_word(&diff_right)?;
    }
    Ok((
        SplitLocalBitWord::from_local_sides(out_left, out_right)?,
        borrow_left,
        borrow_right,
    ))
}

fn select_local_bit_words<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    selector_left: &DdhHssLocalWord,
    selector_right: &DdhHssLocalWord,
    when_true: &SplitLocalBitWord,
    when_false: &SplitLocalBitWord,
) -> ProtoResult<SplitLocalBitWord> {
    if when_true.len() != when_false.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width branches, got {} and {}",
            when_true.len(),
            when_false.len()
        )));
    }
    let mut branch_delta_left_words = Vec::with_capacity(when_true.len());
    let mut branch_delta_right_words = Vec::with_capacity(when_true.len());
    let mut false_left_words = Vec::with_capacity(when_true.len());
    let mut false_right_words = Vec::with_capacity(when_true.len());
    for idx in 0..when_true.len() {
        let true_left = when_true.left.local_word(idx)?;
        let true_right = when_true.right.local_word(idx)?;
        let false_left = when_false.left.local_word(idx)?;
        let false_right = when_false.right.local_word(idx)?;
        let branch_delta_label = format!("{label}/branch_delta/{idx}");
        let (branch_delta_left, branch_delta_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            branch_delta_label.as_bytes(),
            &true_left,
            &true_right,
            &false_left,
            &false_right,
        )?;
        branch_delta_left_words.push(branch_delta_left);
        branch_delta_right_words.push(branch_delta_right);
        false_left_words.push(false_left);
        false_right_words.push(false_right);
    }
    let selector_left_words = vec![selector_left.clone(); when_true.len()];
    let selector_right_words = vec![selector_right.clone(); when_true.len()];
    let (gated_delta_left_words, gated_delta_right_words) = eval_mul_local_word_pair_batch_public(
        backend.evaluation_key(),
        &format!("{label}/bit"),
        &selector_left_words,
        &selector_right_words,
        &branch_delta_left_words,
        &branch_delta_right_words,
    )?;
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, when_true.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, when_true.len());
    for idx in 0..when_true.len() {
        let (selected_left, selected_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            format!("{label}/selected/{idx}").as_bytes(),
            &false_left_words[idx],
            &false_right_words[idx],
            &gated_delta_left_words[idx],
            &gated_delta_right_words[idx],
        )?;
        out_left.push_local_word(&selected_left)?;
        out_right.push_local_word(&selected_right)?;
    }
    SplitLocalBitWord::from_local_sides(out_left, out_right)
}

fn small_sigma0_local_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    SplitLocalBitWord::from_local_sides(
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.left,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(1),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(8),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Shift(7),
                    zero: Some(zero_left),
                },
            ],
        )?,
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.right,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(1),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(8),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Shift(7),
                    zero: Some(zero_right),
                },
            ],
        )?,
    )
}

fn small_sigma1_local_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: &SplitLocalBitWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    SplitLocalBitWord::from_local_sides(
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.left,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(19),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(61),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Shift(6),
                    zero: Some(zero_left),
                },
            ],
        )?,
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.right,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(19),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(61),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Shift(6),
                    zero: Some(zero_right),
                },
            ],
        )?,
    )
}

fn big_sigma0_local_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: &SplitLocalBitWord,
) -> ProtoResult<SplitLocalBitWord> {
    SplitLocalBitWord::from_local_sides(
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.left,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(28),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(34),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(39),
                    zero: None,
                },
            ],
        )?,
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.right,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(28),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(34),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(39),
                    zero: None,
                },
            ],
        )?,
    )
}

fn big_sigma1_local_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: &SplitLocalBitWord,
) -> ProtoResult<SplitLocalBitWord> {
    SplitLocalBitWord::from_local_sides(
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.left,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(14),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(18),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(41),
                    zero: None,
                },
            ],
        )?,
        xor_transformed_local_bit_word_side(
            backend.evaluation_key(),
            label,
            &word.right,
            [
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(14),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(18),
                    zero: None,
                },
                LocalBitTransformSpec {
                    transform: LocalBitTransform::Rotate(41),
                    zero: None,
                },
            ],
        )?,
    )
}

fn ch_local_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    x: &SplitLocalBitWord,
    y: &SplitLocalBitWord,
    z: &SplitLocalBitWord,
) -> ProtoResult<SplitLocalBitWord> {
    if x.len() != y.len() || y.len() != z.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width local words, got {}, {}, and {}",
            x.len(),
            y.len(),
            z.len()
        )));
    }
    let mut y_xor_z_left_words = Vec::with_capacity(x.len());
    let mut y_xor_z_right_words = Vec::with_capacity(x.len());
    let mut z_left_words = Vec::with_capacity(x.len());
    let mut z_right_words = Vec::with_capacity(x.len());
    for idx in 0..x.len() {
        let y_left = y.left.local_word(idx)?;
        let y_right = y.right.local_word(idx)?;
        let z_left = z.left.local_word(idx)?;
        let z_right = z.right.local_word(idx)?;
        let yz_label = format!("{label}/yz/{idx}");
        let (y_xor_z_left, y_xor_z_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            yz_label.as_bytes(),
            &y_left,
            &y_right,
            &z_left,
            &z_right,
        )?;
        y_xor_z_left_words.push(y_xor_z_left);
        y_xor_z_right_words.push(y_xor_z_right);
        z_left_words.push(z_left);
        z_right_words.push(z_right);
    }
    let gated = mul_local_bit_words_batched(
        backend.evaluation_key(),
        &format!("{label}/gate"),
        x,
        &split_local_bit_word_from_local_word_pairs(&y_xor_z_left_words, &y_xor_z_right_words)?,
    )?;
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, x.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, x.len());
    for idx in 0..x.len() {
        let (out_word_left, out_word_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            format!("{label}/out/{idx}").as_bytes(),
            &z_left_words[idx],
            &z_right_words[idx],
            &gated.left.local_word(idx)?,
            &gated.right.local_word(idx)?,
        )?;
        out_left.push_local_word(&out_word_left)?;
        out_right.push_local_word(&out_word_right)?;
    }
    SplitLocalBitWord::from_local_sides(out_left, out_right)
}

fn maj_local_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    x: &SplitLocalBitWord,
    y: &SplitLocalBitWord,
    z: &SplitLocalBitWord,
) -> ProtoResult<SplitLocalBitWord> {
    if x.len() != y.len() || y.len() != z.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width local words, got {}, {}, and {}",
            x.len(),
            y.len(),
            z.len()
        )));
    }
    let mut x_xor_y_left_words = Vec::with_capacity(x.len());
    let mut x_xor_y_right_words = Vec::with_capacity(x.len());
    let mut x_xor_z_left_words = Vec::with_capacity(x.len());
    let mut x_xor_z_right_words = Vec::with_capacity(x.len());
    for idx in 0..x.len() {
        let x_left = x.left.local_word(idx)?;
        let x_right = x.right.local_word(idx)?;
        let y_left = y.left.local_word(idx)?;
        let y_right = y.right.local_word(idx)?;
        let z_left = z.left.local_word(idx)?;
        let z_right = z.right.local_word(idx)?;
        let xy_label = format!("{label}/xy/{idx}");
        let (x_xor_y_left, x_xor_y_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            xy_label.as_bytes(),
            &x_left,
            &x_right,
            &y_left,
            &y_right,
        )?;
        let xz_label = format!("{label}/xz/{idx}");
        let (x_xor_z_left, x_xor_z_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            xz_label.as_bytes(),
            &x_left,
            &x_right,
            &z_left,
            &z_right,
        )?;
        x_xor_y_left_words.push(x_xor_y_left);
        x_xor_y_right_words.push(x_xor_y_right);
        x_xor_z_left_words.push(x_xor_z_left);
        x_xor_z_right_words.push(x_xor_z_right);
    }
    let gated = mul_local_bit_words_batched(
        backend.evaluation_key(),
        &format!("{label}/gate"),
        &split_local_bit_word_from_local_word_pairs(&x_xor_y_left_words, &x_xor_y_right_words)?,
        &split_local_bit_word_from_local_word_pairs(&x_xor_z_left_words, &x_xor_z_right_words)?,
    )?;
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, x.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, x.len());
    for idx in 0..x.len() {
        let x_left = x.left.local_word(idx)?;
        let x_right = x.right.local_word(idx)?;
        let (out_word_left, out_word_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            format!("{label}/out/{idx}").as_bytes(),
            &x_left,
            &x_right,
            &gated.left.local_word(idx)?,
            &gated.right.local_word(idx)?,
        )?;
        out_left.push_local_word(&out_word_left)?;
        out_right.push_local_word(&out_word_right)?;
    }
    SplitLocalBitWord::from_local_sides(out_left, out_right)
}

#[cfg(test)]
fn add_two_words_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &[DdhHssSharedWord],
    right: &[DdhHssSharedWord],
    zero: &DdhHssSharedWord,
) -> ProtoResult<Vec<DdhHssSharedWord>> {
    let mut out = Vec::with_capacity(left.len());
    add_two_words_bits_into(backend, label, left, right, zero, &mut out)?;
    Ok(out)
}

#[cfg(test)]
fn add_two_words_bits_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &[DdhHssSharedWord],
    right: &[DdhHssSharedWord],
    zero: &DdhHssSharedWord,
    out: &mut Vec<DdhHssSharedWord>,
) -> ProtoResult<()> {
    if left.len() != right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "word addition requires same-width bit slices, got {} and {}",
            left.len(),
            right.len()
        )));
    }
    let mut carry = zero.clone();
    out.clear();
    out.reserve(left.len().saturating_sub(out.capacity()));
    for idx in 0..left.len() {
        let xor_ab = backend.eval_add_mod_2_pow_n(&left[idx], &right[idx])?;
        let sum = backend.eval_add_mod_2_pow_n(&xor_ab, &carry)?;
        let a_xor_carry = backend.eval_add_mod_2_pow_n(&left[idx], &carry)?;
        let carry_gate = mul_word_bits(
            backend,
            &format!("{label}/carry/{idx}"),
            &xor_ab,
            &a_xor_carry,
        )?;
        let next_carry = backend.eval_add_mod_2_pow_n(&left[idx], &carry_gate)?;
        out.push(sum);
        carry = next_carry;
    }
    Ok(())
}

#[cfg(test)]
fn sub_two_words_bits_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &[DdhHssSharedWord],
    right: &[DdhHssSharedWord],
    zero: &DdhHssSharedWord,
    one: &DdhHssSharedWord,
    out: &mut Vec<DdhHssSharedWord>,
) -> ProtoResult<DdhHssSharedWord> {
    if left.len() != right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "word subtraction requires same-width bit slices, got {} and {}",
            left.len(),
            right.len()
        )));
    }

    let mut borrow = zero.clone();
    out.clear();
    out.reserve(left.len().saturating_sub(out.capacity()));
    for idx in 0..left.len() {
        let xor_ab = backend.eval_add_mod_2_pow_n(&left[idx], &right[idx])?;
        let diff = backend.eval_add_mod_2_pow_n(&xor_ab, &borrow)?;
        let not_left = backend.eval_add_mod_2_pow_n(&left[idx], &one)?;
        let right_or_borrow = or_bit(
            backend,
            &format!("{label}/right_or_borrow/{idx}"),
            &right[idx],
            &borrow,
        )?;
        let need_from_left = mul_word_bits(
            backend,
            &format!("{label}/need_from_left/{idx}"),
            &not_left,
            &right_or_borrow,
        )?;
        let borrow_from_bits = mul_word_bits(
            backend,
            &format!("{label}/borrow_from_bits/{idx}"),
            &right[idx],
            &borrow,
        )?;
        borrow = or_bit(
            backend,
            &format!("{label}/borrow_merge/{idx}"),
            &need_from_left,
            &borrow_from_bits,
        )?;
        out.push(diff);
        let _ = idx;
    }

    Ok(borrow)
}

#[cfg(test)]
fn select_word_bits_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    selector: &DdhHssSharedWord,
    when_true: &[DdhHssSharedWord],
    when_false: &[DdhHssSharedWord],
    out: &mut Vec<DdhHssSharedWord>,
) -> ProtoResult<()> {
    if when_true.len() != when_false.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width branches, got {} and {}",
            when_true.len(),
            when_false.len()
        )));
    }

    out.clear();
    out.reserve(when_true.len().saturating_sub(out.capacity()));
    for (idx, (true_bit, false_bit)) in when_true.iter().zip(when_false.iter()).enumerate() {
        let branch_delta = backend.eval_add_mod_2_pow_n(true_bit, false_bit)?;
        let gated_delta = mul_word_bits(
            backend,
            &format!("{label}/bit/{idx}"),
            selector,
            &branch_delta,
        )?;
        let selected = backend.eval_add_mod_2_pow_n(false_bit, &gated_delta)?;
        let _ = idx;
        out.push(selected);
    }
    Ok(())
}

#[cfg(test)]
fn or_bit<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &DdhHssSharedWord,
    right: &DdhHssSharedWord,
) -> ProtoResult<DdhHssSharedWord> {
    let xor = backend.eval_add_mod_2_pow_n(left, right)?;
    let and = mul_word_bits(backend, &format!("{label}/and"), left, right)?;
    backend.eval_add_mod_2_pow_n(&xor, &and)
}

#[cfg(test)]
fn mul_word_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &DdhHssSharedWord,
    right: &DdhHssSharedWord,
) -> ProtoResult<DdhHssSharedWord> {
    backend.eval_mul_bit(label, left, right)
}

#[cfg(test)]
fn decode_bits_to_fixed_bytes<const N: usize>(
    backend: &DdhHssBackend,
    bits: &[DdhHssSharedWord],
    label: &str,
) -> ProtoResult<[u8; N]> {
    if bits.len() != N * 8 {
        return Err(ProtoError::Decode(format!(
            "{label} must contain exactly {} bits, got {}",
            N * 8,
            bits.len()
        )));
    }
    let mut out = [0u8; N];
    for byte_idx in 0..N {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let bit = backend.decode_word(&bits[byte_idx * 8 + bit_idx]);
            value |= ((bit & 1) as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

fn combine_bundle_commitments(
    backend: &impl DdhHssArithmeticBackend,
    owner: HiddenEvalInputOwner,
    bundles: &[&DdhHssInputShareBundle],
) -> [u8; 32] {
    backend.combined_input_commitment(owner, bundles)
}

fn combine_server_input_commitments(
    backend: &impl DdhHssArithmeticBackend,
    server_inputs: &DdhHiddenEvalServerInputs,
) -> [u8; 32] {
    combine_server_input_bundle_commitments(
        backend,
        &server_inputs.y_relayer_bits,
        &server_inputs.tau_relayer_bits,
    )
}

fn combine_server_input_bundle_commitments(
    backend: &impl DdhHssArithmeticBackend,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
    hasher.update(backend.evaluation_key().key_id);
    hasher.update(b"server");
    for bundle in [y_relayer_bits, tau_relayer_bits] {
        hasher.update(bundle.commitment);
        hasher.update(bundle.label.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn combine_server_input_transport_commitments(
    backend: &impl DdhHssArithmeticBackend,
    y_relayer_left: &DdhHssTransportBundle,
    tau_relayer_left: &DdhHssTransportBundle,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
    hasher.update(backend.evaluation_key().key_id);
    hasher.update(b"server");
    for bundle in [y_relayer_left, tau_relayer_left] {
        hasher.update(bundle.commitment);
        hasher.update(bundle.label.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        add_five_local_bit_words_to_arithmetic_naive, add_words_bits_mod_l,
        arithmetic_word_pair_to_split_local_bits_naive, decode_bits_to_fixed_bytes,
        prepare_ddh_hidden_eval_constant_pool, reduce_scalar_bits_mod_l,
        reduce_scalar_bits_mod_l_with_constants_local, share_input_bits,
        split_local_bits_to_arithmetic_word_pair_naive, SplitLocalBitWord,
    };
    use crate::fixtures::deterministic_fixture_corpus;
    use crate::reference::{derive_output_shares, reduce_scalar_mod_l};
    use crate::succinct_hss::prepare_prime_order_succinct_hss;
    use crate::HiddenEvalInputOwner;

    #[test]
    fn phase_a_naive_conversion_round_trip_matches_original_word() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare DDH session");
        let backend = session.ddh_backend();
        let constant_pool =
            prepare_ddh_hidden_eval_constant_pool(backend).expect("prepare constant pool");
        let shared_bits = share_input_bits(
            backend,
            HiddenEvalInputOwner::Derived,
            "test_phase_a_roundtrip_word",
            &fixture.output.a_bytes,
        )
        .expect("share input bits");
        let decoded_expected_bytes = decode_bits_to_fixed_bytes::<8>(
            backend,
            &shared_bits[..64],
            "test_phase_a_roundtrip_word/expected",
        )
        .expect("decode expected bytes");
        let word_bits =
            SplitLocalBitWord::from_shared_bits(&shared_bits[..64]).expect("split word");
        let mut direct_left = 0u64;
        let mut direct_right = 0u64;
        let mut direct_correction = 0u64;
        for idx in 0..word_bits.len() {
            direct_left |= u64::from(word_bits.left.share_bit(idx)) << idx;
            direct_right |= u64::from(word_bits.right.share_bit(idx)) << idx;
            if idx + 1 < word_bits.len() {
                let cross =
                    u64::from(word_bits.left.share_bit(idx) & word_bits.right.share_bit(idx));
                direct_correction = direct_correction.wrapping_add(cross << (idx + 1));
            }
        }
        let arithmetic = split_local_bits_to_arithmetic_word_pair_naive(
            backend,
            "test_phase_a_roundtrip_word/arith",
            &word_bits,
        )
        .expect("convert to arithmetic");
        let arithmetic_open = arithmetic
            .left
            .share_word
            .wrapping_add(arithmetic.right.share_word);
        let round_tripped = arithmetic_word_pair_to_split_local_bits_naive(
            backend,
            "test_phase_a_roundtrip_word/bool",
            &arithmetic,
            &constant_pool.zero_left,
            &constant_pool.zero_right,
        )
        .expect("convert back to boolean");
        let decoded = u64::from_le_bytes(
            decode_bits_to_fixed_bytes::<8>(
                backend,
                &round_tripped
                    .to_shared_bits()
                    .expect("shared roundtrip bits"),
                "test_phase_a_roundtrip_word/decode",
            )
            .expect("decode roundtrip bits"),
        );
        let expected = u64::from_le_bytes(decoded_expected_bytes);

        assert_eq!(direct_left ^ direct_right, expected);
        assert_eq!(
            direct_left
                .wrapping_add(direct_right)
                .wrapping_sub(direct_correction),
            expected
        );
        assert_eq!(arithmetic_open, expected);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn phase_a_naive_five_word_sum_matches_wrapping_reference() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare DDH session");
        let backend = session.ddh_backend();
        let constant_pool =
            prepare_ddh_hidden_eval_constant_pool(backend).expect("prepare constant pool");
        let inputs = [
            0x0123_4567_89ab_cdefu64,
            0xfedc_ba98_7654_3210u64,
            0x0f0f_f0f0_55aa_cc33u64,
            0x1357_9bdf_2468_ace0u64,
            0x1122_3344_5566_7788u64,
        ];
        let expected = inputs
            .into_iter()
            .fold(0u64, |acc, value| acc.wrapping_add(value));
        let words = inputs
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                let shared_bits = share_input_bits(
                    backend,
                    HiddenEvalInputOwner::Derived,
                    &format!("test_phase_a_five_word_sum/{idx}"),
                    &value.to_le_bytes(),
                )
                .expect("share test input bits");
                SplitLocalBitWord::from_shared_bits(&shared_bits[..64]).expect("split word")
            })
            .collect::<Vec<_>>();

        let (sum_arith, _) = add_five_local_bit_words_to_arithmetic_naive(
            backend,
            "test_phase_a_five_word_sum",
            &words[0],
            &words[1],
            &words[2],
            &words[3],
            &words[4],
        )
        .expect("arithmetic five-word sum");
        let sum = arithmetic_word_pair_to_split_local_bits_naive(
            backend,
            "test_phase_a_five_word_sum/bits",
            &sum_arith,
            &constant_pool.zero_left,
            &constant_pool.zero_right,
        )
        .expect("arithmetic five-word sum bits");
        let decoded = u64::from_le_bytes(
            decode_bits_to_fixed_bytes::<8>(
                backend,
                &sum.to_shared_bits().expect("sum shared bits"),
                "test_phase_a_five_word_sum/decode",
            )
            .expect("decode five-word sum"),
        );

        assert_eq!(decoded, expected);
    }

    #[test]
    fn hidden_scalar_reduction_matches_reference_scalar_mod_l() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare DDH session");
        let clamped_bits = share_input_bits(
            session.ddh_backend(),
            HiddenEvalInputOwner::Derived,
            "test_clamped_a_bytes",
            &fixture.output.a_bytes,
        )
        .expect("share clamped scalar bits");
        let reduced_bits =
            reduce_scalar_bits_mod_l(session.ddh_backend(), "test_reduction", &clamped_bits)
                .expect("reduce scalar bits mod l");
        let reduced =
            decode_bits_to_fixed_bytes::<32>(session.ddh_backend(), &reduced_bits, "reduced")
                .expect("decode reduced scalar");

        assert_eq!(reduced, reduce_scalar_mod_l(fixture.output.a_bytes));
    }

    #[test]
    fn local_hidden_scalar_reduction_matches_reference_scalar_mod_l() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare DDH session");
        let backend = session.ddh_backend();
        let constant_pool =
            prepare_ddh_hidden_eval_constant_pool(backend).expect("prepare constant pool");
        let clamped_bits = share_input_bits(
            backend,
            HiddenEvalInputOwner::Derived,
            "test_local_clamped_a_bytes",
            &fixture.output.a_bytes,
        )
        .expect("share clamped scalar bits");
        let clamped_local =
            SplitLocalBitWord::from_shared_bits(&clamped_bits).expect("split local clamped bits");
        let reduced_local = reduce_scalar_bits_mod_l_with_constants_local(
            backend,
            "test_local_reduction",
            &clamped_local,
            &constant_pool.zero_left,
            &constant_pool.zero_right,
            &constant_pool.one_left,
            &constant_pool.one_right,
            7,
        )
        .expect("reduce local scalar bits mod l");
        let reduced_shared = reduced_local
            .to_shared_bits()
            .expect("recombine reduced local bits");
        let reduced = decode_bits_to_fixed_bytes::<32>(backend, &reduced_shared, "local_reduced")
            .expect("decode reduced scalar");

        assert_eq!(reduced, reduce_scalar_mod_l(fixture.output.a_bytes));
    }

    #[test]
    fn hidden_output_projection_matches_reference_output_shares() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare DDH session");
        let backend = session.ddh_backend();
        let a_bits = share_input_bits(
            backend,
            HiddenEvalInputOwner::Derived,
            "test_scalar_a",
            &fixture.output.a,
        )
        .expect("share reduced scalar a");
        let tau_client_bits = share_input_bits(
            backend,
            HiddenEvalInputOwner::Client,
            "test_tau_client",
            &fixture.input.tau_client,
        )
        .expect("share tau_client bits");
        let tau_relayer_bits = share_input_bits(
            backend,
            HiddenEvalInputOwner::Server,
            "test_tau_relayer",
            &fixture.input.tau_relayer,
        )
        .expect("share tau_relayer bits");

        let tau_bits = add_words_bits_mod_l(
            backend,
            "test_output_projection/tau",
            &tau_client_bits,
            &tau_relayer_bits,
        )
        .expect("compute tau");
        let x_client_bits = add_words_bits_mod_l(
            backend,
            "test_output_projection/x_client",
            &a_bits,
            &tau_bits,
        )
        .expect("compute x_client_base");
        let double_tau_bits = add_words_bits_mod_l(
            backend,
            "test_output_projection/double_tau",
            &tau_bits,
            &tau_bits,
        )
        .expect("compute 2*tau");
        let x_relayer_bits = add_words_bits_mod_l(
            backend,
            "test_output_projection/x_relayer",
            &a_bits,
            &double_tau_bits,
        )
        .expect("compute x_relayer_base");

        let tau = decode_bits_to_fixed_bytes::<32>(backend, &tau_bits, "tau").expect("decode tau");
        let x_client_base =
            decode_bits_to_fixed_bytes::<32>(backend, &x_client_bits, "x_client_base")
                .expect("decode x_client_base");
        let x_relayer_base =
            decode_bits_to_fixed_bytes::<32>(backend, &x_relayer_bits, "x_relayer_base")
                .expect("decode x_relayer_base");
        let expected = derive_output_shares(
            fixture.output.a,
            fixture.input.tau_client,
            fixture.input.tau_relayer,
        )
        .expect("reference output shares");

        assert_eq!(tau, expected.tau);
        assert_eq!(x_client_base, expected.x_client_base);
        assert_eq!(x_relayer_base, expected.x_relayer_base);
    }
}
