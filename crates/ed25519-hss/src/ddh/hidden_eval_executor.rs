use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

use crate::ddh::ddh_hss::{
    build_local_word_pair_public, build_local_word_pair_public_from_extra_material,
    eval_add_cross_share_local_arithmetic_word_bits_secure_public_into,
    eval_add_local_word_pairs_mod_2_pow_n_public, eval_maj_local_bit_pair_batch_raw_public_into,
    eval_mul_local_bit_pair_batch_raw_xor_base_public_into, eval_mul_local_word_pair_batch_public,
    eval_mul_local_word_pairs_core_public, eval_mul_local_word_pairs_public,
    local_word_from_shared, local_word_from_transport_public, materialize_local_word_core,
    reset_physical_hash_counters, take_physical_hash_counters, validate_transport_word_pair_public,
    xor_local_bit_core_from_raw_public, xor_local_bit_pair_core_from_raw_public,
    xor_local_bit_pair_from_raw_public, xor_local_word_core_pairs_materialized_public,
    xor_local_word_core_pairs_public, xor_local_word_pairs_public, DdhHssArithmeticBackend,
    DdhHssInputShareBundle, DdhHssLocalBitSliceView, DdhHssLocalWord, DdhHssLocalWordCore,
    DdhHssPhysicalHashCounters, DdhHssShareSide, DdhHssSharedWord, DdhHssTransportBundle,
    DdhHssTransportWord,
};
use crate::ddh::hidden_eval::{
    HiddenEvalInputOwner, HiddenEvalProgram, HiddenEvalStage, HiddenEvalStageKind,
};
#[cfg(test)]
use crate::ddh::DdhHssBackend;
use crate::shared::FExpandInput;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::ClientOutputValueKind;
use curve25519_dalek::scalar::Scalar;

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
pub struct DdhHiddenEvalClientOutputBundle {
    pub value_kind: ClientOutputValueKind,
    pub bundle: DdhHssInputShareBundle,
}

impl DdhHiddenEvalClientOutputBundle {
    pub fn new(
        value_kind: ClientOutputValueKind,
        bundle: DdhHssInputShareBundle,
    ) -> ProtoResult<Self> {
        if bundle.label != value_kind.bundle_label() {
            return Err(ProtoError::InvalidInput(
                "hidden-eval client output bundle label does not match value kind".to_string(),
            ));
        }
        Ok(Self { value_kind, bundle })
    }

    pub fn unmasked_client_base(bundle: DdhHssInputShareBundle) -> ProtoResult<Self> {
        Self::new(ClientOutputValueKind::UnmaskedClientBase, bundle)
    }

    pub fn as_bundle(&self) -> &DdhHssInputShareBundle {
        &self.bundle
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdhHiddenEvalClientOutputProjection {
    TrustedServerProjection,
    ClientMaskedProjection { client_output_mask: [u8; 32] },
}

impl DdhHiddenEvalClientOutputProjection {
    pub fn trusted_server_projection() -> Self {
        Self::TrustedServerProjection
    }

    pub fn client_masked_projection(client_output_mask: [u8; 32]) -> Self {
        Self::ClientMaskedProjection { client_output_mask }
    }

    pub fn value_kind(self) -> ClientOutputValueKind {
        match self {
            Self::TrustedServerProjection => ClientOutputValueKind::UnmaskedClientBase,
            Self::ClientMaskedProjection { .. } => ClientOutputValueKind::ClientBlindedBase,
        }
    }

    pub fn client_output_mask(self) -> Option<[u8; 32]> {
        match self {
            Self::TrustedServerProjection => None,
            Self::ClientMaskedProjection { client_output_mask } => Some(client_output_mask),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalOutputBundles {
    pub canonical_seed: DdhHssInputShareBundle,
    pub client_output: DdhHiddenEvalClientOutputBundle,
    pub x_relayer_base_left: DdhHssTransportBundle,
    pub x_relayer_base_right: DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalServerOutputBundles {
    pub canonical_seed_commitment: [u8; 32],
    pub x_relayer_base_left: DdhHssTransportBundle,
    pub x_relayer_base_right: DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalRun {
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub output: DdhHiddenEvalOutputBundles,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalCheckpointDigests {
    pub add_stage: [u8; 32],
    pub message_schedule: [u8; 32],
    pub round_core: [u8; 32],
    pub output_projection: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalExecutionTrace {
    pub run: DdhHiddenEvalRun,
    pub checkpoint_digests: DdhHiddenEvalCheckpointDigests,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalMessageScheduleContinuation {
    pub add_stage_digest: [u8; 32],
    pub schedule_words: Vec<Vec<DdhHssSharedWord>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalRoundCoreContinuation {
    pub rounds_completed: u16,
    pub schedule_words: Vec<Vec<DdhHssSharedWord>>,
    pub state_words: Vec<Vec<DdhHssSharedWord>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalProjectorInputs {
    pub add_stage_bits: Vec<DdhHssSharedWord>,
    pub tau_client_bits: Vec<DdhHssSharedWord>,
    pub tau_relayer_left_bits: Vec<DdhHssTransportWord>,
    pub tau_relayer_right_bits: Vec<DdhHssTransportWord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHiddenEvalStagedMaterialization {
    pub add_stage_digest: [u8; 32],
    pub message_schedule: DdhHiddenEvalMessageScheduleContinuation,
    pub projector_inputs: DdhHiddenEvalProjectorInputs,
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
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
    pub round_sigma0_duration_ns: u128,
    pub round_sigma1_duration_ns: u128,
    pub round_ch_duration_ns: u128,
    pub round_maj_duration_ns: u128,
    pub round_state3_duration_ns: u128,
    pub round_temp1_duration_ns: u128,
    pub round_temp1_xor_ab_duration_ns: u128,
    pub round_temp1_sum_duration_ns: u128,
    pub round_temp1_a_xor_carry_duration_ns: u128,
    pub round_temp1_carry_gate_duration_ns: u128,
    pub round_temp1_next_carry_duration_ns: u128,
    pub round_temp2_duration_ns: u128,
    pub round_new_a_bits_duration_ns: u128,
    pub round_new_e_bits_duration_ns: u128,
    pub output_projector_duration_ns: u128,
    pub output_projector_core_duration_ns: u128,
    pub output_projector_clamp_a_duration_ns: u128,
    pub output_projector_reduce_a_duration_ns: u128,
    pub output_projector_tau_duration_ns: u128,
    pub output_projector_mask_share_duration_ns: u128,
    pub output_projector_mask_add_duration_ns: u128,
    pub output_projector_client_base_duration_ns: u128,
    pub output_projector_client_output_duration_ns: u128,
    pub output_projector_tau_double_duration_ns: u128,
    pub output_projector_relayer_output_duration_ns: u128,
    pub output_projector_bundle_build_duration_ns: u128,
    pub output_projector_local_word_materializations: u64,
    pub total_duration_ns: u128,
    #[serde(default)]
    pub operation_counts: DdhHiddenEvalOperationCounts,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OutputProjectorProfile {
    core_duration_ns: u128,
    clamp_a_duration_ns: u128,
    reduce_a_duration_ns: u128,
    tau_duration_ns: u128,
    mask_share_duration_ns: u128,
    mask_add_duration_ns: u128,
    client_base_duration_ns: u128,
    client_output_duration_ns: u128,
    tau_double_duration_ns: u128,
    relayer_output_duration_ns: u128,
    bundle_build_duration_ns: u128,
    local_word_materializations: u64,
}

struct OutputProjectorExecution {
    output: DdhHiddenEvalOutputBundles,
    profile: OutputProjectorProfile,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHiddenEvalOperationCounts {
    pub logical_local_word_materializations: u64,
    pub logical_shared_word_materializations: u64,
    pub logical_transport_word_materializations: u64,
    pub logical_commitment_materializations: u64,
    pub logical_provenance_digest_materializations: u64,
    pub logical_commitment_derivations: u64,
    pub logical_provenance_digest_derivations: u64,
    pub logical_label_writes: u64,
    pub logical_label_format_allocations: u64,
    #[serde(default)]
    pub physical_keyed_digest_derivations: u64,
    #[serde(default)]
    pub physical_keyed_digest_eval_xor_local_word: u64,
    #[serde(default)]
    pub physical_keyed_digest_eval_add_local: u64,
    #[serde(default)]
    pub physical_keyed_digest_eval_mul_local_material: u64,
    #[serde(default)]
    pub physical_keyed_digest_eval_mul_local: u64,
    #[serde(default)]
    pub physical_keyed_digest_phase_a_arith_share_to_bool: u64,
    #[serde(default)]
    pub physical_keyed_digest_phase_a_bool_to_arith_base: u64,
    #[serde(default)]
    pub physical_keyed_digest_phase_a_arith_to_bool_zero: u64,
    #[serde(default)]
    pub physical_keyed_digest_compose_word_from_share_bits: u64,
    #[serde(default)]
    pub physical_keyed_digest_share_word: u64,
    #[serde(default)]
    pub physical_keyed_digest_other: u64,
    #[serde(default)]
    pub physical_derived_commitment_hashes: u64,
    #[serde(default)]
    pub physical_derived_commitment_eval_xor_local_word: u64,
    #[serde(default)]
    pub physical_derived_commitment_eval_add_local: u64,
    #[serde(default)]
    pub physical_derived_commitment_eval_mul_local_material: u64,
    #[serde(default)]
    pub physical_derived_commitment_eval_mul_local: u64,
    #[serde(default)]
    pub physical_derived_commitment_phase_a_arith_share_to_bool: u64,
    #[serde(default)]
    pub physical_derived_commitment_phase_a_bool_to_arith_base: u64,
    #[serde(default)]
    pub physical_derived_commitment_phase_a_arith_to_bool_zero: u64,
    #[serde(default)]
    pub physical_derived_commitment_compose_word_from_share_bits: u64,
    #[serde(default)]
    pub physical_derived_commitment_share_word: u64,
    #[serde(default)]
    pub physical_derived_commitment_other: u64,
    #[serde(default)]
    pub physical_add_bit_hashes: u64,
    #[serde(default)]
    pub physical_mul_material_hashes: u64,
    #[serde(default)]
    pub physical_mul_output_seed_hashes: u64,
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

    fn as_raw_view(&self) -> DdhHssLocalBitSliceView<'_> {
        DdhHssLocalBitSliceView {
            share_side: self.share_side,
            share_blocks: &self.share_blocks,
            bit_len: self.bit_len,
            commitments: &self.commitments,
            provenance_digests: &self.provenance_digests,
        }
    }

    fn push_share_bit(&mut self, value: u8) {
        let block = self.bit_len / 64;
        let bit = self.bit_len % 64;
        if block == self.share_blocks.len() {
            self.share_blocks.push(0);
        }
        self.share_blocks[block] |= u64::from(value & 1) << bit;
        self.bit_len += 1;
    }

    fn reset(&mut self) {
        self.share_blocks.clear();
        self.bit_len = 0;
        self.commitments.clear();
        self.provenance_digests.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoreBitWordSide {
    share_side: DdhHssShareSide,
    share_blocks: Vec<u64>,
    bit_len: usize,
    provenance_digests: Vec<[u8; 32]>,
}

impl CoreBitWordSide {
    fn empty(share_side: DdhHssShareSide, len: usize) -> Self {
        Self {
            share_side,
            share_blocks: Vec::with_capacity(len.div_ceil(64)),
            bit_len: 0,
            provenance_digests: Vec::with_capacity(len),
        }
    }

    fn ensure_shape(&self) -> ProtoResult<()> {
        if self.provenance_digests.len() != self.bit_len {
            return Err(ProtoError::InvalidInput(
                "core bit-vector lengths are inconsistent".to_string(),
            ));
        }
        Ok(())
    }

    fn push_core_word(&mut self, word: &DdhHssLocalWordCore) -> ProtoResult<()> {
        if word.share_side != self.share_side || word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(
                "core bit-vector requires width-1 words on the matching side".to_string(),
            ));
        }
        self.push_share_bit((word.share_word as u8) & 1);
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

    fn materialize_into(
        &self,
        out: &mut LocalBitWordSide,
        provenance_domain: &'static [u8],
    ) -> ProtoResult<()> {
        self.ensure_shape()?;
        out.reset();
        for idx in 0..self.len() {
            let core = DdhHssLocalWordCore {
                width_bits: 1,
                share_side: self.share_side,
                share_word: u64::from(self.share_bit(idx)),
                provenance_digest: self.provenance_digests[idx],
            };
            let word = materialize_local_word_core(&core, provenance_domain);
            out.push_local_word(&word)?;
        }
        Ok(())
    }

    fn push_share_bit(&mut self, value: u8) {
        let block = self.bit_len / 64;
        let bit = self.bit_len % 64;
        if block == self.share_blocks.len() {
            self.share_blocks.push(0);
        }
        self.share_blocks[block] |= u64::from(value & 1) << bit;
        self.bit_len += 1;
    }

    fn reset(&mut self) {
        self.share_blocks.clear();
        self.bit_len = 0;
        self.provenance_digests.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SplitLocalBitWord {
    left: LocalBitWordSide,
    right: LocalBitWordSide,
}

#[derive(Debug, Copy, Clone)]
struct LocalBitWordPairRef<'a> {
    left: &'a LocalBitWordSide,
    right: &'a LocalBitWordSide,
}

impl LocalBitWordPairRef<'_> {
    fn len(&self) -> usize {
        self.left.len()
    }
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

    fn as_pair_ref(&self) -> LocalBitWordPairRef<'_> {
        LocalBitWordPairRef {
            left: &self.left,
            right: &self.right,
        }
    }
}

impl DdhHiddenEvalOperationCounts {
    fn add_physical_hash_counters(&mut self, counters: DdhHssPhysicalHashCounters) {
        self.physical_keyed_digest_derivations = self
            .physical_keyed_digest_derivations
            .saturating_add(counters.keyed_digest_derivations);
        self.physical_keyed_digest_eval_xor_local_word = self
            .physical_keyed_digest_eval_xor_local_word
            .saturating_add(counters.keyed_digest_eval_xor_local_word);
        self.physical_keyed_digest_eval_add_local = self
            .physical_keyed_digest_eval_add_local
            .saturating_add(counters.keyed_digest_eval_add_local);
        self.physical_keyed_digest_eval_mul_local_material = self
            .physical_keyed_digest_eval_mul_local_material
            .saturating_add(counters.keyed_digest_eval_mul_local_material);
        self.physical_keyed_digest_eval_mul_local = self
            .physical_keyed_digest_eval_mul_local
            .saturating_add(counters.keyed_digest_eval_mul_local);
        self.physical_keyed_digest_phase_a_arith_share_to_bool = self
            .physical_keyed_digest_phase_a_arith_share_to_bool
            .saturating_add(counters.keyed_digest_phase_a_arith_share_to_bool);
        self.physical_keyed_digest_phase_a_bool_to_arith_base = self
            .physical_keyed_digest_phase_a_bool_to_arith_base
            .saturating_add(counters.keyed_digest_phase_a_bool_to_arith_base);
        self.physical_keyed_digest_phase_a_arith_to_bool_zero = self
            .physical_keyed_digest_phase_a_arith_to_bool_zero
            .saturating_add(counters.keyed_digest_phase_a_arith_to_bool_zero);
        self.physical_keyed_digest_compose_word_from_share_bits = self
            .physical_keyed_digest_compose_word_from_share_bits
            .saturating_add(counters.keyed_digest_compose_word_from_share_bits);
        self.physical_keyed_digest_share_word = self
            .physical_keyed_digest_share_word
            .saturating_add(counters.keyed_digest_share_word);
        self.physical_keyed_digest_other = self
            .physical_keyed_digest_other
            .saturating_add(counters.keyed_digest_other);
        self.physical_derived_commitment_hashes = self
            .physical_derived_commitment_hashes
            .saturating_add(counters.derived_commitment_hashes);
        self.physical_derived_commitment_eval_xor_local_word = self
            .physical_derived_commitment_eval_xor_local_word
            .saturating_add(counters.derived_commitment_eval_xor_local_word);
        self.physical_derived_commitment_eval_add_local = self
            .physical_derived_commitment_eval_add_local
            .saturating_add(counters.derived_commitment_eval_add_local);
        self.physical_derived_commitment_eval_mul_local_material = self
            .physical_derived_commitment_eval_mul_local_material
            .saturating_add(counters.derived_commitment_eval_mul_local_material);
        self.physical_derived_commitment_eval_mul_local = self
            .physical_derived_commitment_eval_mul_local
            .saturating_add(counters.derived_commitment_eval_mul_local);
        self.physical_derived_commitment_phase_a_arith_share_to_bool = self
            .physical_derived_commitment_phase_a_arith_share_to_bool
            .saturating_add(counters.derived_commitment_phase_a_arith_share_to_bool);
        self.physical_derived_commitment_phase_a_bool_to_arith_base = self
            .physical_derived_commitment_phase_a_bool_to_arith_base
            .saturating_add(counters.derived_commitment_phase_a_bool_to_arith_base);
        self.physical_derived_commitment_phase_a_arith_to_bool_zero = self
            .physical_derived_commitment_phase_a_arith_to_bool_zero
            .saturating_add(counters.derived_commitment_phase_a_arith_to_bool_zero);
        self.physical_derived_commitment_compose_word_from_share_bits = self
            .physical_derived_commitment_compose_word_from_share_bits
            .saturating_add(counters.derived_commitment_compose_word_from_share_bits);
        self.physical_derived_commitment_share_word = self
            .physical_derived_commitment_share_word
            .saturating_add(counters.derived_commitment_share_word);
        self.physical_derived_commitment_other = self
            .physical_derived_commitment_other
            .saturating_add(counters.derived_commitment_other);
        self.physical_add_bit_hashes = self
            .physical_add_bit_hashes
            .saturating_add(counters.add_bit_hashes);
        self.physical_mul_material_hashes = self
            .physical_mul_material_hashes
            .saturating_add(counters.mul_material_hashes);
        self.physical_mul_output_seed_hashes = self
            .physical_mul_output_seed_hashes
            .saturating_add(counters.mul_output_seed_hashes);
    }

    fn add_input_share_bundle(&mut self, bundle: &DdhHssInputShareBundle) {
        self.add_shared_words(bundle.words.len());
        self.logical_commitment_materializations =
            self.logical_commitment_materializations.saturating_add(1);
        self.logical_label_writes = self.logical_label_writes.saturating_add(1);
    }

    fn add_server_input_bundle(&mut self, bundle: &DdhHiddenEvalServerInputBundle) {
        self.add_transport_words(bundle.left_words.len());
        self.add_transport_words(bundle.right_words.len());
        self.logical_commitment_materializations =
            self.logical_commitment_materializations.saturating_add(1);
        self.logical_label_writes = self.logical_label_writes.saturating_add(1);
    }

    fn add_transport_bundle(&mut self, bundle: &DdhHssTransportBundle) {
        self.add_transport_words(bundle.words.len());
        self.logical_commitment_materializations =
            self.logical_commitment_materializations.saturating_add(1);
        self.logical_label_writes = self.logical_label_writes.saturating_add(1);
    }

    fn add_split_local_bit_word(&mut self, word: &SplitLocalBitWord) {
        self.add_local_words(word.left.len());
        self.add_local_words(word.right.len());
    }

    fn add_split_local_bit_words(&mut self, words: &[SplitLocalBitWord]) {
        for word in words {
            self.add_split_local_bit_word(word);
        }
    }

    fn add_hidden_eval_output_bundles(&mut self, output: &DdhHiddenEvalOutputBundles) {
        self.add_input_share_bundle(&output.canonical_seed);
        self.add_input_share_bundle(&output.client_output.bundle);
        self.add_transport_bundle(&output.x_relayer_base_left);
        self.add_transport_bundle(&output.x_relayer_base_right);

        let output_word_count = output
            .canonical_seed
            .words
            .len()
            .saturating_add(output.client_output.bundle.words.len())
            .saturating_add(output.x_relayer_base_left.words.len())
            .saturating_add(output.x_relayer_base_right.words.len());
        let side_commitments = output_word_count.saturating_mul(2) as u64;
        self.logical_commitment_derivations = self
            .logical_commitment_derivations
            .saturating_add(side_commitments);
        self.logical_provenance_digest_derivations = self
            .logical_provenance_digest_derivations
            .saturating_add(output_word_count as u64);
    }

    fn add_stage_label_shape(&mut self, schedule_word_count: usize, round_word_count: usize) {
        // Public-shape label counts estimate executor label assembly without allocator hooks.
        let add_stage_labels = 256u64.saturating_mul(5);
        let schedule_extensions = schedule_word_count.saturating_sub(16) as u64;
        let message_schedule_format_allocations = schedule_extensions.saturating_mul(4);
        let message_schedule_labels = schedule_extensions.saturating_mul(521);
        let round_count = 80u64;
        let round_labels = round_count
            .saturating_mul(281)
            .saturating_add((round_word_count as u64).saturating_mul(2));
        let projector_format_allocations = 9u64;

        self.logical_label_writes = self
            .logical_label_writes
            .saturating_add(add_stage_labels)
            .saturating_add(message_schedule_labels)
            .saturating_add(round_labels);
        self.logical_label_format_allocations = self
            .logical_label_format_allocations
            .saturating_add(message_schedule_format_allocations)
            .saturating_add(projector_format_allocations);
    }

    fn add_local_words(&mut self, count: usize) {
        let count = count as u64;
        self.logical_local_word_materializations = self
            .logical_local_word_materializations
            .saturating_add(count);
        self.logical_commitment_materializations = self
            .logical_commitment_materializations
            .saturating_add(count);
        self.logical_provenance_digest_materializations = self
            .logical_provenance_digest_materializations
            .saturating_add(count);
        self.logical_provenance_digest_derivations = self
            .logical_provenance_digest_derivations
            .saturating_add(count);
    }

    fn add_shared_words(&mut self, count: usize) {
        let count = count as u64;
        self.logical_shared_word_materializations = self
            .logical_shared_word_materializations
            .saturating_add(count);
        self.logical_commitment_materializations = self
            .logical_commitment_materializations
            .saturating_add(count.saturating_mul(2));
        self.logical_provenance_digest_materializations = self
            .logical_provenance_digest_materializations
            .saturating_add(count);
    }

    fn add_transport_words(&mut self, count: usize) {
        let count = count as u64;
        self.logical_transport_word_materializations = self
            .logical_transport_word_materializations
            .saturating_add(count);
        self.logical_commitment_materializations = self
            .logical_commitment_materializations
            .saturating_add(count.saturating_mul(2));
        self.logical_provenance_digest_materializations = self
            .logical_provenance_digest_materializations
            .saturating_add(count);
    }
}

fn count_hidden_eval_operation_shape(
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
    y_client_bits_local: &SplitLocalBitWord,
    tau_client_bits_local: &SplitLocalBitWord,
    d_bits: &SplitLocalBitWord,
    schedule_words: &[SplitLocalBitWord],
    round_final_words: &[SplitLocalBitWord],
    output: &DdhHiddenEvalOutputBundles,
) -> DdhHiddenEvalOperationCounts {
    let mut counts = DdhHiddenEvalOperationCounts::default();
    counts.add_input_share_bundle(y_client_bits);
    counts.add_server_input_bundle(y_relayer_bits);
    counts.add_input_share_bundle(tau_client_bits);
    counts.add_server_input_bundle(tau_relayer_bits);
    counts.add_split_local_bit_word(y_client_bits_local);
    counts.add_split_local_bit_word(tau_client_bits_local);
    counts.add_split_local_bit_word(d_bits);
    counts.add_split_local_bit_words(schedule_words);
    counts.add_split_local_bit_words(round_final_words);
    counts.add_hidden_eval_output_bundles(output);
    counts.add_stage_label_shape(schedule_words.len(), round_final_words.len());
    counts
}

#[derive(Debug, Clone)]
struct RoundKernelBooleanWord {
    left: LocalBitWordSide,
    right: LocalBitWordSide,
}

impl RoundKernelBooleanWord {
    fn empty(len: usize) -> Self {
        Self {
            left: empty_local_bit_slice(DdhHssShareSide::Left, len),
            right: empty_local_bit_slice(DdhHssShareSide::Right, len),
        }
    }

    fn as_pair_ref(&self) -> LocalBitWordPairRef<'_> {
        LocalBitWordPairRef {
            left: &self.left,
            right: &self.right,
        }
    }

    fn reset(&mut self) {
        self.left.reset();
        self.right.reset();
    }
}

#[derive(Debug, Clone)]
struct RoundKernelCoreBooleanWord {
    left: CoreBitWordSide,
    right: CoreBitWordSide,
}

impl RoundKernelCoreBooleanWord {
    fn empty(len: usize) -> Self {
        Self {
            left: CoreBitWordSide::empty(DdhHssShareSide::Left, len),
            right: CoreBitWordSide::empty(DdhHssShareSide::Right, len),
        }
    }

    fn materialize_into(&self, out: &mut RoundKernelBooleanWord) -> ProtoResult<()> {
        self.left.ensure_shape()?;
        self.right.ensure_shape()?;
        if self.left.len() != self.right.len() {
            return Err(ProtoError::InvalidInput(format!(
                "core round word length mismatch: {} vs {}",
                self.left.len(),
                self.right.len()
            )));
        }
        self.left
            .materialize_into(&mut out.left, b"eval-xor-local-word")?;
        self.right
            .materialize_into(&mut out.right, b"eval-xor-local-word")?;
        Ok(())
    }

    fn reset(&mut self) {
        self.left.reset();
        self.right.reset();
    }
}

fn digest_shared_words(label: &[u8], words: &[DdhHssSharedWord]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"prime_order_ddh_hidden_eval_stage_digest_v0");
    hasher.update(label);
    hasher.update((words.len() as u64).to_le_bytes());
    for word in words {
        hasher.update(word.width_bits.to_le_bytes());
        hasher.update(word.left_word.to_le_bytes());
        hasher.update(word.right_word.to_le_bytes());
        hasher.update(word.left_commitment);
        hasher.update(word.right_commitment);
        hasher.update(word.provenance_digest);
    }
    hasher.finalize().into()
}

fn digest_split_local_bit_word(label: &[u8], word: &SplitLocalBitWord) -> ProtoResult<[u8; 32]> {
    Ok(digest_shared_words(label, &word.to_shared_bits()?))
}

fn digest_split_local_bit_words(
    label: &[u8],
    words: &[SplitLocalBitWord],
) -> ProtoResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"prime_order_ddh_hidden_eval_stage_vector_digest_v0");
    hasher.update(label);
    hasher.update((words.len() as u64).to_le_bytes());
    for word in words {
        hasher.update(digest_split_local_bit_word(b"word", word)?);
    }
    Ok(hasher.finalize().into())
}

pub fn compute_output_projection_output_digest(output: &DdhHiddenEvalOutputBundles) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"prime_order_ddh_hidden_eval_output_projection_digest_v0");
    hasher.update(output.canonical_seed.commitment);
    hasher.update(output.client_output.value_kind.domain_tag());
    hasher.update(output.client_output.bundle.commitment);
    hasher.update(output.x_relayer_base_left.commitment);
    hasher.update(output.x_relayer_base_right.commitment);
    hasher.finalize().into()
}

pub fn compute_output_projection_continuation_digest(
    continuation: &DdhHiddenEvalProjectorInputs,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"prime_order_ddh_hidden_eval_output_projection_continuation_digest_v0");
    hasher.update(digest_shared_words(
        b"add_stage_bits",
        &continuation.add_stage_bits,
    ));
    hasher.update(digest_shared_words(
        b"tau_client_bits",
        &continuation.tau_client_bits,
    ));
    for word in &continuation.tau_relayer_left_bits {
        hasher.update(word.width_bits.to_le_bytes());
        hasher.update(match word.share_side {
            DdhHssShareSide::Left => [0u8],
            DdhHssShareSide::Right => [1u8],
        });
        hasher.update(word.share_word.to_le_bytes());
        hasher.update(word.share_commitment);
        hasher.update(word.counterparty_commitment);
        hasher.update(word.provenance_digest);
    }
    for word in &continuation.tau_relayer_right_bits {
        hasher.update(word.width_bits.to_le_bytes());
        hasher.update(match word.share_side {
            DdhHssShareSide::Left => [0u8],
            DdhHssShareSide::Right => [1u8],
        });
        hasher.update(word.share_word.to_le_bytes());
        hasher.update(word.share_commitment);
        hasher.update(word.counterparty_commitment);
        hasher.update(word.provenance_digest);
    }
    hasher.finalize().into()
}

pub fn compute_message_schedule_completed_digest(
    continuation: &DdhHiddenEvalMessageScheduleContinuation,
) -> ProtoResult<[u8; 32]> {
    if continuation.schedule_words.len() <= 16 {
        return Ok(continuation.add_stage_digest);
    }
    let words = continuation
        .schedule_words
        .iter()
        .map(|word| SplitLocalBitWord::from_shared_bits(word))
        .collect::<ProtoResult<Vec<_>>>()?;
    digest_split_local_bit_words(b"message_schedule", &words)
}

pub fn compute_round_core_completed_digest(
    continuation: &DdhHiddenEvalRoundCoreContinuation,
) -> ProtoResult<[u8; 32]> {
    let state_words = continuation
        .state_words
        .iter()
        .map(|word| SplitLocalBitWord::from_shared_bits(word))
        .collect::<ProtoResult<Vec<_>>>()?;
    let mut hasher = Sha256::new();
    hasher.update(b"prime_order_ddh_hidden_eval_round_core_continuation_digest_v1");
    hasher.update(continuation.rounds_completed.to_le_bytes());
    hasher.update((state_words.len() as u64).to_le_bytes());
    for word in &state_words {
        hasher.update(digest_split_local_bit_word(b"state_word", word)?);
    }
    Ok(hasher.finalize().into())
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

#[derive(Debug, Clone)]
struct RoundCoreBooleanScratch {
    sigma0_core: RoundKernelCoreBooleanWord,
    sigma1_core: RoundKernelCoreBooleanWord,
    sigma0: RoundKernelBooleanWord,
    sigma1: RoundKernelBooleanWord,
    choose: RoundKernelBooleanWord,
    majority: RoundKernelBooleanWord,
    operand0: RoundKernelBooleanWord,
}

impl RoundCoreBooleanScratch {
    fn new(word_len: usize) -> Self {
        Self {
            sigma0_core: RoundKernelCoreBooleanWord::empty(word_len),
            sigma1_core: RoundKernelCoreBooleanWord::empty(word_len),
            sigma0: RoundKernelBooleanWord::empty(word_len),
            sigma1: RoundKernelBooleanWord::empty(word_len),
            choose: RoundKernelBooleanWord::empty(word_len),
            majority: RoundKernelBooleanWord::empty(word_len),
            operand0: RoundKernelBooleanWord::empty(word_len),
        }
    }

    fn materialize_sigma0(&mut self) -> ProtoResult<()> {
        self.sigma0_core.materialize_into(&mut self.sigma0)
    }

    fn materialize_sigma1(&mut self) -> ProtoResult<()> {
        self.sigma1_core.materialize_into(&mut self.sigma1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundStagesOutput {
    hash_core: SharedHashCoreOutput,
    sigma0_duration_ns: u128,
    sigma1_duration_ns: u128,
    ch_duration_ns: u128,
    maj_duration_ns: u128,
    state3_duration_ns: u128,
    temp1_duration_ns: u128,
    temp1_add_timing: LocalBitWordAddTiming,
    temp2_duration_ns: u128,
    new_a_bits_duration_ns: u128,
    new_e_bits_duration_ns: u128,
}

struct RoundKernelState {
    a: SplitLocalBitWord,
    b: SplitLocalBitWord,
    c: SplitLocalBitWord,
    d: SplitLocalBitWord,
    e: SplitLocalBitWord,
    f: SplitLocalBitWord,
    g: SplitLocalBitWord,
    h: SplitLocalBitWord,
}

impl RoundKernelState {
    fn from_iv_words(iv_words: &[SplitLocalBitWord; 8]) -> Self {
        Self {
            a: iv_words[0].clone(),
            b: iv_words[1].clone(),
            c: iv_words[2].clone(),
            d: iv_words[3].clone(),
            e: iv_words[4].clone(),
            f: iv_words[5].clone(),
            g: iv_words[6].clone(),
            h: iv_words[7].clone(),
        }
    }

    fn rotate_with_new_words(&mut self, new_a: SplitLocalBitWord, new_e: SplitLocalBitWord) {
        let old_a = std::mem::replace(&mut self.a, new_a);
        let old_b = std::mem::replace(&mut self.b, old_a);
        let old_c = std::mem::replace(&mut self.c, old_b);
        self.d = old_c;

        let old_e = std::mem::replace(&mut self.e, new_e);
        let old_f = std::mem::replace(&mut self.f, old_e);
        let old_g = std::mem::replace(&mut self.g, old_f);
        self.h = old_g;
    }

    fn finalize_with_iv<B: DdhHssArithmeticBackend>(
        &self,
        backend: &B,
        iv_words: &[SplitLocalBitWord; 8],
        zero_left: &DdhHssLocalWord,
        zero_right: &DdhHssLocalWord,
    ) -> ProtoResult<Vec<SplitLocalBitWord>> {
        let current_words = [
            &self.a, &self.b, &self.c, &self.d, &self.e, &self.f, &self.g, &self.h,
        ];
        let mut final_words = Vec::with_capacity(8);
        for idx in 0..8 {
            final_words.push(add_two_local_bit_words(
                backend,
                &format!("round_core/final/{idx}"),
                current_words[idx],
                &iv_words[idx],
                zero_left,
                zero_right,
            )?);
        }
        Ok(final_words)
    }

    fn from_shared_bits(words: &[Vec<DdhHssSharedWord>]) -> ProtoResult<Self> {
        if words.len() != 8 {
            return Err(ProtoError::InvalidInput(format!(
                "round-core state must contain 8 words, got {}",
                words.len()
            )));
        }
        let mut local_words = words
            .iter()
            .map(|word| SplitLocalBitWord::from_shared_bits(word))
            .collect::<ProtoResult<Vec<_>>>()?;
        Ok(Self {
            a: local_words.remove(0),
            b: local_words.remove(0),
            c: local_words.remove(0),
            d: local_words.remove(0),
            e: local_words.remove(0),
            f: local_words.remove(0),
            g: local_words.remove(0),
            h: local_words.remove(0),
        })
    }

    fn to_shared_bits(&self) -> ProtoResult<Vec<Vec<DdhHssSharedWord>>> {
        [
            &self.a, &self.b, &self.c, &self.d, &self.e, &self.f, &self.g, &self.h,
        ]
        .into_iter()
        .map(|word| word.to_shared_bits())
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundKernelArithmeticTemps {
    temp1: LocalArithmeticWordPair,
    temp2: LocalArithmeticWordPair,
    state3: LocalArithmeticWordPair,
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
    let ExecutionUntilOutputProjector {
        stage_profile, run, ..
    } = execute_prime_order_ddh_hidden_eval_program_internal(
        program,
        backend,
        constant_pool,
        input_bundles,
        DdhHiddenEvalCheckpointCapture::Skip,
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
    let y_client_bit_words = input_bundles.y_client_bits.words.clone();
    let tau_client_bit_words = input_bundles.tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bit_words)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bit_words)?;
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
                round_sigma0_duration_ns: 0,
                round_sigma1_duration_ns: 0,
                round_ch_duration_ns: 0,
                round_maj_duration_ns: 0,
                round_state3_duration_ns: 0,
                round_temp1_duration_ns: 0,
                round_temp1_xor_ab_duration_ns: 0,
                round_temp1_sum_duration_ns: 0,
                round_temp1_a_xor_carry_duration_ns: 0,
                round_temp1_carry_gate_duration_ns: 0,
                round_temp1_next_carry_duration_ns: 0,
                round_temp2_duration_ns: 0,
                round_new_a_bits_duration_ns: 0,
                round_new_e_bits_duration_ns: 0,
                output_projector_duration_ns: 0,
                output_projector_core_duration_ns: 0,
                output_projector_clamp_a_duration_ns: 0,
                output_projector_reduce_a_duration_ns: 0,
                output_projector_tau_duration_ns: 0,
                output_projector_mask_share_duration_ns: 0,
                output_projector_mask_add_duration_ns: 0,
                output_projector_client_base_duration_ns: 0,
                output_projector_client_output_duration_ns: 0,
                output_projector_tau_double_duration_ns: 0,
                output_projector_relayer_output_duration_ns: 0,
                output_projector_bundle_build_duration_ns: 0,
                output_projector_local_word_materializations: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
                operation_counts: DdhHiddenEvalOperationCounts::default(),
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
                round_sigma0_duration_ns: 0,
                round_sigma1_duration_ns: 0,
                round_ch_duration_ns: 0,
                round_maj_duration_ns: 0,
                round_state3_duration_ns: 0,
                round_temp1_duration_ns: 0,
                round_temp1_xor_ab_duration_ns: 0,
                round_temp1_sum_duration_ns: 0,
                round_temp1_a_xor_carry_duration_ns: 0,
                round_temp1_carry_gate_duration_ns: 0,
                round_temp1_next_carry_duration_ns: 0,
                round_temp2_duration_ns: 0,
                round_new_a_bits_duration_ns: 0,
                round_new_e_bits_duration_ns: 0,
                output_projector_duration_ns: 0,
                output_projector_core_duration_ns: 0,
                output_projector_clamp_a_duration_ns: 0,
                output_projector_reduce_a_duration_ns: 0,
                output_projector_tau_duration_ns: 0,
                output_projector_mask_share_duration_ns: 0,
                output_projector_mask_add_duration_ns: 0,
                output_projector_client_base_duration_ns: 0,
                output_projector_client_output_duration_ns: 0,
                output_projector_tau_double_duration_ns: 0,
                output_projector_relayer_output_duration_ns: 0,
                output_projector_bundle_build_duration_ns: 0,
                output_projector_local_word_materializations: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
                operation_counts: DdhHiddenEvalOperationCounts::default(),
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
                round_sigma0_duration_ns: 0,
                round_sigma1_duration_ns: 0,
                round_ch_duration_ns: 0,
                round_maj_duration_ns: 0,
                round_state3_duration_ns: 0,
                round_temp1_duration_ns: 0,
                round_temp1_xor_ab_duration_ns: 0,
                round_temp1_sum_duration_ns: 0,
                round_temp1_a_xor_carry_duration_ns: 0,
                round_temp1_carry_gate_duration_ns: 0,
                round_temp1_next_carry_duration_ns: 0,
                round_temp2_duration_ns: 0,
                round_new_a_bits_duration_ns: 0,
                round_new_e_bits_duration_ns: 0,
                output_projector_duration_ns: 0,
                output_projector_core_duration_ns: 0,
                output_projector_clamp_a_duration_ns: 0,
                output_projector_reduce_a_duration_ns: 0,
                output_projector_tau_duration_ns: 0,
                output_projector_mask_share_duration_ns: 0,
                output_projector_mask_add_duration_ns: 0,
                output_projector_client_base_duration_ns: 0,
                output_projector_client_output_duration_ns: 0,
                output_projector_tau_double_duration_ns: 0,
                output_projector_relayer_output_duration_ns: 0,
                output_projector_bundle_build_duration_ns: 0,
                output_projector_local_word_materializations: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
                operation_counts: DdhHiddenEvalOperationCounts::default(),
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
    let round_sigma0_duration_ns = round_output.sigma0_duration_ns;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_maj_duration_ns = round_output.maj_duration_ns;
    let round_state3_duration_ns = round_output.state3_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;
    let round_new_a_bits_duration_ns = round_output.new_a_bits_duration_ns;
    let round_new_e_bits_duration_ns = round_output.new_e_bits_duration_ns;
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
                round_sigma0_duration_ns,
                round_sigma1_duration_ns,
                round_ch_duration_ns,
                round_maj_duration_ns,
                round_state3_duration_ns,
                round_temp1_duration_ns,
                round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
                round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
                round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
                round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
                round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
                round_temp2_duration_ns,
                round_new_a_bits_duration_ns,
                round_new_e_bits_duration_ns,
                output_projector_duration_ns: 0,
                output_projector_core_duration_ns: 0,
                output_projector_clamp_a_duration_ns: 0,
                output_projector_reduce_a_duration_ns: 0,
                output_projector_tau_duration_ns: 0,
                output_projector_mask_share_duration_ns: 0,
                output_projector_mask_add_duration_ns: 0,
                output_projector_client_base_duration_ns: 0,
                output_projector_client_output_duration_ns: 0,
                output_projector_tau_double_duration_ns: 0,
                output_projector_relayer_output_duration_ns: 0,
                output_projector_bundle_build_duration_ns: 0,
                output_projector_local_word_materializations: 0,
                total_duration_ns: elapsed_ns(total_started_ns),
                operation_counts: DdhHiddenEvalOperationCounts::default(),
            },
            schedule_word_count: Some(schedule_output.words.len()),
            hash_prefix_hex: None,
        });
    }

    let output_started_ns = monotonic_now_ns();
    let output_execution = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &d_bits,
        &hash_core.final_words,
        &tau_client_bits_local,
        &input_bundles.server_inputs.tau_relayer_bits.left_words,
        &input_bundles.server_inputs.tau_relayer_bits.right_words,
        DdhHiddenEvalClientOutputProjection::trusted_server_projection(),
    )?;
    let output_projector_profile = output_execution.profile;
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
            round_sigma0_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_maj_duration_ns,
            round_state3_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            round_new_a_bits_duration_ns,
            round_new_e_bits_duration_ns,
            output_projector_duration_ns,
            output_projector_core_duration_ns: output_projector_profile.core_duration_ns,
            output_projector_clamp_a_duration_ns: output_projector_profile.clamp_a_duration_ns,
            output_projector_reduce_a_duration_ns: output_projector_profile.reduce_a_duration_ns,
            output_projector_tau_duration_ns: output_projector_profile.tau_duration_ns,
            output_projector_mask_share_duration_ns: output_projector_profile
                .mask_share_duration_ns,
            output_projector_mask_add_duration_ns: output_projector_profile.mask_add_duration_ns,
            output_projector_client_base_duration_ns: output_projector_profile
                .client_base_duration_ns,
            output_projector_client_output_duration_ns: output_projector_profile
                .client_output_duration_ns,
            output_projector_tau_double_duration_ns: output_projector_profile
                .tau_double_duration_ns,
            output_projector_relayer_output_duration_ns: output_projector_profile
                .relayer_output_duration_ns,
            output_projector_bundle_build_duration_ns: output_projector_profile
                .bundle_build_duration_ns,
            output_projector_local_word_materializations: output_projector_profile
                .local_word_materializations,
            total_duration_ns: elapsed_ns(total_started_ns),
            operation_counts: DdhHiddenEvalOperationCounts::default(),
        },
        schedule_word_count: Some(schedule_output.words.len()),
        hash_prefix_hex: None,
    })
}

struct ExecutionUntilOutputProjector {
    stage_profile: DdhHiddenEvalStageProfile,
    run: DdhHiddenEvalRun,
    checkpoint_digests: DdhHiddenEvalCheckpointResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DdhHiddenEvalCheckpointCapture {
    Skip,
    Capture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DdhHiddenEvalCheckpointResult {
    Skipped,
    Captured(DdhHiddenEvalCheckpointDigests),
}

impl DdhHiddenEvalCheckpointResult {
    fn into_captured(self) -> ProtoResult<DdhHiddenEvalCheckpointDigests> {
        match self {
            Self::Captured(checkpoint_digests) => Ok(checkpoint_digests),
            Self::Skipped => Err(ProtoError::InvalidInput(
                "hidden-eval checkpoints were not captured".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DdhHiddenEvalCheckpointAccumulator {
    mode: DdhHiddenEvalCheckpointCapture,
    add_stage: Option<[u8; 32]>,
    message_schedule: Option<[u8; 32]>,
    round_core: Option<[u8; 32]>,
    output_projection: Option<[u8; 32]>,
}

impl DdhHiddenEvalCheckpointAccumulator {
    fn new(mode: DdhHiddenEvalCheckpointCapture) -> Self {
        Self {
            mode,
            add_stage: None,
            message_schedule: None,
            round_core: None,
            output_projection: None,
        }
    }

    fn record_add_stage(&mut self, d_bits: &SplitLocalBitWord) -> ProtoResult<()> {
        if self.mode == DdhHiddenEvalCheckpointCapture::Capture {
            self.add_stage = Some(digest_split_local_bit_word(b"add_stage", d_bits)?);
        }
        Ok(())
    }

    fn record_message_schedule(&mut self, words: &[SplitLocalBitWord]) -> ProtoResult<()> {
        if self.mode == DdhHiddenEvalCheckpointCapture::Capture {
            self.message_schedule = Some(digest_split_local_bit_words(b"message_schedule", words)?);
        }
        Ok(())
    }

    fn record_round_core(&mut self, words: &[SplitLocalBitWord]) -> ProtoResult<()> {
        if self.mode == DdhHiddenEvalCheckpointCapture::Capture {
            self.round_core = Some(digest_split_local_bit_words(b"round_core", words)?);
        }
        Ok(())
    }

    fn record_output_projection(&mut self, output: &DdhHiddenEvalOutputBundles) {
        if self.mode == DdhHiddenEvalCheckpointCapture::Capture {
            self.output_projection = Some(compute_output_projection_output_digest(output));
        }
    }

    fn finish(self) -> ProtoResult<DdhHiddenEvalCheckpointResult> {
        match self.mode {
            DdhHiddenEvalCheckpointCapture::Skip => Ok(DdhHiddenEvalCheckpointResult::Skipped),
            DdhHiddenEvalCheckpointCapture::Capture => Ok(DdhHiddenEvalCheckpointResult::Captured(
                DdhHiddenEvalCheckpointDigests {
                    add_stage: self.add_stage.ok_or_else(|| {
                        ProtoError::InvalidInput(
                            "hidden-eval add-stage checkpoint was not captured".to_string(),
                        )
                    })?,
                    message_schedule: self.message_schedule.ok_or_else(|| {
                        ProtoError::InvalidInput(
                            "hidden-eval message-schedule checkpoint was not captured".to_string(),
                        )
                    })?,
                    round_core: self.round_core.ok_or_else(|| {
                        ProtoError::InvalidInput(
                            "hidden-eval round-core checkpoint was not captured".to_string(),
                        )
                    })?,
                    output_projection: self.output_projection.ok_or_else(|| {
                        ProtoError::InvalidInput(
                            "hidden-eval output-projection checkpoint was not captured".to_string(),
                        )
                    })?,
                },
            )),
        }
    }
}

fn execute_prime_order_ddh_hidden_eval_program_internal<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    input_bundles: &DdhHiddenEvalInputBundles,
    checkpoint_capture: DdhHiddenEvalCheckpointCapture,
) -> ProtoResult<ExecutionUntilOutputProjector> {
    ensure_program_shape(program)?;
    reset_physical_hash_counters();
    let mut checkpoints = DdhHiddenEvalCheckpointAccumulator::new(checkpoint_capture);
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
    let y_client_bit_words = input_bundles.y_client_bits.words.clone();
    let tau_client_bit_words = input_bundles.tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bit_words)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bit_words)?;
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
    checkpoints.record_add_stage(&d_bits)?;

    let schedule_started_ns = monotonic_now_ns();
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let message_schedule_duration_ns = elapsed_ns(schedule_started_ns);
    let message_schedule_accumulation_duration_ns = schedule_output.accumulation_duration_ns;
    let message_schedule_accumulation_add_timing = schedule_output.accumulation_add_timing;
    checkpoints.record_message_schedule(&schedule_output.words)?;

    let round_started_ns = monotonic_now_ns();
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let round_core_duration_ns = elapsed_ns(round_started_ns);
    let hash_core = round_output.hash_core;
    let round_sigma0_duration_ns = round_output.sigma0_duration_ns;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_maj_duration_ns = round_output.maj_duration_ns;
    let round_state3_duration_ns = round_output.state3_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;
    let round_new_a_bits_duration_ns = round_output.new_a_bits_duration_ns;
    let round_new_e_bits_duration_ns = round_output.new_e_bits_duration_ns;
    checkpoints.record_round_core(&hash_core.final_words)?;

    let output_started_ns = monotonic_now_ns();
    let output_execution = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &d_bits,
        &hash_core.final_words,
        &tau_client_bits_local,
        &input_bundles.server_inputs.tau_relayer_bits.left_words,
        &input_bundles.server_inputs.tau_relayer_bits.right_words,
        DdhHiddenEvalClientOutputProjection::trusted_server_projection(),
    )?;
    let output = output_execution.output;
    let output_projector_profile = output_execution.profile;
    let output_projector_duration_ns = elapsed_ns(output_started_ns);
    checkpoints.record_output_projection(&output);
    let mut operation_counts = count_hidden_eval_operation_shape(
        &input_bundles.y_client_bits,
        &input_bundles.server_inputs.y_relayer_bits,
        &input_bundles.tau_client_bits,
        &input_bundles.server_inputs.tau_relayer_bits,
        &y_client_bits_local,
        &tau_client_bits_local,
        &d_bits,
        &schedule_output.words,
        &hash_core.final_words,
        &output,
    );
    operation_counts.add_physical_hash_counters(take_physical_hash_counters());

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
            round_sigma0_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_maj_duration_ns,
            round_state3_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            round_new_a_bits_duration_ns,
            round_new_e_bits_duration_ns,
            output_projector_duration_ns,
            output_projector_core_duration_ns: output_projector_profile.core_duration_ns,
            output_projector_clamp_a_duration_ns: output_projector_profile.clamp_a_duration_ns,
            output_projector_reduce_a_duration_ns: output_projector_profile.reduce_a_duration_ns,
            output_projector_tau_duration_ns: output_projector_profile.tau_duration_ns,
            output_projector_mask_share_duration_ns: output_projector_profile
                .mask_share_duration_ns,
            output_projector_mask_add_duration_ns: output_projector_profile.mask_add_duration_ns,
            output_projector_client_base_duration_ns: output_projector_profile
                .client_base_duration_ns,
            output_projector_client_output_duration_ns: output_projector_profile
                .client_output_duration_ns,
            output_projector_tau_double_duration_ns: output_projector_profile
                .tau_double_duration_ns,
            output_projector_relayer_output_duration_ns: output_projector_profile
                .relayer_output_duration_ns,
            output_projector_bundle_build_duration_ns: output_projector_profile
                .bundle_build_duration_ns,
            output_projector_local_word_materializations: output_projector_profile
                .local_word_materializations,
            total_duration_ns: elapsed_ns(total_started_ns),
            operation_counts,
        },
        run: DdhHiddenEvalRun {
            client_input_commitment,
            server_input_commitment,
            output,
        },
        checkpoint_digests: checkpoints.finish()?,
    })
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
    client_output_projection: DdhHiddenEvalClientOutputProjection,
    checkpoint_capture: DdhHiddenEvalCheckpointCapture,
) -> ProtoResult<ExecutionUntilOutputProjector> {
    reset_physical_hash_counters();
    let mut checkpoints = DdhHiddenEvalCheckpointAccumulator::new(checkpoint_capture);
    let total_started_ns = monotonic_now_ns();
    let input_sharing_started_ns = monotonic_now_ns();

    let client_input_commitment = combine_bundle_commitments(
        backend,
        HiddenEvalInputOwner::Client,
        &[y_client_bits, tau_client_bits],
    );
    let server_input_commitment =
        combine_server_input_bundle_commitments(backend, y_relayer_bits, tau_relayer_bits);
    let y_client_bit_words = y_client_bits.words.clone();
    let tau_client_bit_words = tau_client_bits.words.clone();
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bit_words)?;
    let tau_client_bits_local = SplitLocalBitWord::from_shared_bits(&tau_client_bit_words)?;
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
    checkpoints.record_add_stage(&d_bits)?;

    let schedule_started_ns = monotonic_now_ns();
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let message_schedule_duration_ns = elapsed_ns(schedule_started_ns);
    let message_schedule_accumulation_duration_ns = schedule_output.accumulation_duration_ns;
    let message_schedule_accumulation_add_timing = schedule_output.accumulation_add_timing;
    checkpoints.record_message_schedule(&schedule_output.words)?;

    let round_started_ns = monotonic_now_ns();
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let round_core_duration_ns = elapsed_ns(round_started_ns);
    let hash_core = round_output.hash_core;
    let round_sigma0_duration_ns = round_output.sigma0_duration_ns;
    let round_sigma1_duration_ns = round_output.sigma1_duration_ns;
    let round_ch_duration_ns = round_output.ch_duration_ns;
    let round_maj_duration_ns = round_output.maj_duration_ns;
    let round_state3_duration_ns = round_output.state3_duration_ns;
    let round_temp1_duration_ns = round_output.temp1_duration_ns;
    let round_temp1_add_timing = round_output.temp1_add_timing;
    let round_temp2_duration_ns = round_output.temp2_duration_ns;
    let round_new_a_bits_duration_ns = round_output.new_a_bits_duration_ns;
    let round_new_e_bits_duration_ns = round_output.new_e_bits_duration_ns;
    checkpoints.record_round_core(&hash_core.final_words)?;

    let output_started_ns = monotonic_now_ns();
    let output_execution = execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &d_bits,
        &hash_core.final_words,
        &tau_client_bits_local,
        &tau_relayer_bits.left_words,
        &tau_relayer_bits.right_words,
        client_output_projection,
    )?;
    let output = output_execution.output;
    let output_projector_profile = output_execution.profile;
    let output_projector_duration_ns = elapsed_ns(output_started_ns);
    checkpoints.record_output_projection(&output);
    let mut operation_counts = count_hidden_eval_operation_shape(
        y_client_bits,
        y_relayer_bits,
        tau_client_bits,
        tau_relayer_bits,
        &y_client_bits_local,
        &tau_client_bits_local,
        &d_bits,
        &schedule_output.words,
        &hash_core.final_words,
        &output,
    );
    operation_counts.add_physical_hash_counters(take_physical_hash_counters());

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
            round_sigma0_duration_ns,
            round_sigma1_duration_ns,
            round_ch_duration_ns,
            round_maj_duration_ns,
            round_state3_duration_ns,
            round_temp1_duration_ns,
            round_temp1_xor_ab_duration_ns: round_temp1_add_timing.xor_ab_duration_ns,
            round_temp1_sum_duration_ns: round_temp1_add_timing.sum_duration_ns,
            round_temp1_a_xor_carry_duration_ns: round_temp1_add_timing.a_xor_carry_duration_ns,
            round_temp1_carry_gate_duration_ns: round_temp1_add_timing.carry_gate_duration_ns,
            round_temp1_next_carry_duration_ns: round_temp1_add_timing.next_carry_duration_ns,
            round_temp2_duration_ns,
            round_new_a_bits_duration_ns,
            round_new_e_bits_duration_ns,
            output_projector_duration_ns,
            output_projector_core_duration_ns: output_projector_profile.core_duration_ns,
            output_projector_clamp_a_duration_ns: output_projector_profile.clamp_a_duration_ns,
            output_projector_reduce_a_duration_ns: output_projector_profile.reduce_a_duration_ns,
            output_projector_tau_duration_ns: output_projector_profile.tau_duration_ns,
            output_projector_mask_share_duration_ns: output_projector_profile
                .mask_share_duration_ns,
            output_projector_mask_add_duration_ns: output_projector_profile.mask_add_duration_ns,
            output_projector_client_base_duration_ns: output_projector_profile
                .client_base_duration_ns,
            output_projector_client_output_duration_ns: output_projector_profile
                .client_output_duration_ns,
            output_projector_tau_double_duration_ns: output_projector_profile
                .tau_double_duration_ns,
            output_projector_relayer_output_duration_ns: output_projector_profile
                .relayer_output_duration_ns,
            output_projector_bundle_build_duration_ns: output_projector_profile
                .bundle_build_duration_ns,
            output_projector_local_word_materializations: output_projector_profile
                .local_word_materializations,
            total_duration_ns: elapsed_ns(total_started_ns),
            operation_counts,
        },
        run: DdhHiddenEvalRun {
            client_input_commitment,
            server_input_commitment,
            output,
        },
        checkpoint_digests: checkpoints.finish()?,
    })
}

pub fn trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<DdhHiddenEvalExecutionTrace> {
    trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_with_pool(
        program,
        backend,
        constant_pool,
        y_client_bits,
        y_relayer_bits,
        tau_client_bits,
        tau_relayer_bits,
        DdhHiddenEvalClientOutputProjection::trusted_server_projection(),
    )
}

pub fn trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
    client_output_projection: DdhHiddenEvalClientOutputProjection,
) -> ProtoResult<DdhHiddenEvalExecutionTrace> {
    let (trace, _) =
        trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool(
            program,
            backend,
            constant_pool,
            y_client_bits,
            y_relayer_bits,
            tau_client_bits,
            tau_relayer_bits,
            client_output_projection,
        )?;
    Ok(trace)
}

pub fn trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
    client_output_projection: DdhHiddenEvalClientOutputProjection,
) -> ProtoResult<(DdhHiddenEvalExecutionTrace, DdhHiddenEvalStageProfile)> {
    let ExecutionUntilOutputProjector {
        run,
        checkpoint_digests,
        stage_profile,
    } = execute_prime_order_ddh_hidden_eval_program_internal_with_split_server_inputs_validated(
        program,
        backend,
        constant_pool,
        y_client_bits,
        y_relayer_bits,
        tau_client_bits,
        tau_relayer_bits,
        client_output_projection,
        DdhHiddenEvalCheckpointCapture::Capture,
    )?;
    let checkpoint_digests = checkpoint_digests.into_captured()?;
    Ok((
        DdhHiddenEvalExecutionTrace {
            run,
            checkpoint_digests,
        },
        stage_profile,
    ))
}

pub fn execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
    client_output_projection: DdhHiddenEvalClientOutputProjection,
) -> ProtoResult<(DdhHiddenEvalRun, DdhHiddenEvalStageProfile)> {
    let ExecutionUntilOutputProjector {
        run, stage_profile, ..
    } = execute_prime_order_ddh_hidden_eval_program_internal_with_split_server_inputs_validated(
        program,
        backend,
        constant_pool,
        y_client_bits,
        y_relayer_bits,
        tau_client_bits,
        tau_relayer_bits,
        client_output_projection,
        DdhHiddenEvalCheckpointCapture::Skip,
    )?;
    Ok((run, stage_profile))
}

pub fn materialize_message_schedule_continuation_with_split_server_inputs_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<DdhHiddenEvalMessageScheduleContinuation> {
    ensure_program_shape(program)?;
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bits.words)?;
    let d_bits = execute_add_stage(
        backend,
        &program.stages[0],
        &y_client_bits_local,
        &y_relayer_bits.left_words,
        &y_relayer_bits.right_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let add_stage_digest = digest_split_local_bit_word(b"add_stage", &d_bits)?;
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let schedule_words = schedule_output
        .words
        .into_iter()
        .map(|word| word.to_shared_bits())
        .collect::<ProtoResult<Vec<_>>>()?;
    let _ = (tau_client_bits, tau_relayer_bits);
    Ok(DdhHiddenEvalMessageScheduleContinuation {
        add_stage_digest,
        schedule_words,
    })
}

pub fn initialize_message_schedule_continuation(
    add_stage_digest: [u8; 32],
    add_stage_bits: &[DdhHssSharedWord],
    constant_pool: &DdhHiddenEvalConstantPool,
) -> ProtoResult<DdhHiddenEvalMessageScheduleContinuation> {
    let d_bits = SplitLocalBitWord::from_shared_bits(add_stage_bits)?;
    let schedule_words = initial_one_block_schedule_prefix_local_words(
        &d_bits,
        &constant_pool.schedule_suffix_words,
    )?
    .into_iter()
    .map(|word| word.to_shared_bits())
    .collect::<ProtoResult<Vec<_>>>()?;
    Ok(DdhHiddenEvalMessageScheduleContinuation {
        add_stage_digest,
        schedule_words,
    })
}

pub fn advance_message_schedule_continuation_with_pool<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    continuation: &DdhHiddenEvalMessageScheduleContinuation,
) -> ProtoResult<DdhHiddenEvalMessageScheduleContinuation> {
    if continuation.schedule_words.len() < 16 || continuation.schedule_words.len() >= 80 {
        return Err(ProtoError::InvalidInput(format!(
            "message-schedule continuation must hold between 16 and 79 words, got {}",
            continuation.schedule_words.len()
        )));
    }
    let mut words = continuation
        .schedule_words
        .iter()
        .map(|word| SplitLocalBitWord::from_shared_bits(word))
        .collect::<ProtoResult<Vec<_>>>()?;
    let t = words.len();
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
    let (accumulation_arith, _) = add_four_local_bit_pairs_to_arithmetic_naive(
        backend,
        &format!("message_schedule/{t}"),
        words[t - 16].as_pair_ref(),
        sigma0.as_pair_ref(),
        words[t - 7].as_pair_ref(),
        sigma1.as_pair_ref(),
    )?;
    let accumulation = arithmetic_word_pair_to_split_local_bits_secure(
        backend,
        &format!("message_schedule/{t}/out"),
        &accumulation_arith,
    )?;
    words.push(accumulation);
    Ok(DdhHiddenEvalMessageScheduleContinuation {
        add_stage_digest: continuation.add_stage_digest,
        schedule_words: words
            .into_iter()
            .map(|word| word.to_shared_bits())
            .collect::<ProtoResult<Vec<_>>>()?,
    })
}

pub fn initialize_round_core_continuation_from_message_schedule_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    message_schedule: &DdhHiddenEvalMessageScheduleContinuation,
) -> ProtoResult<DdhHiddenEvalRoundCoreContinuation> {
    ensure_program_shape(program)?;
    if message_schedule.schedule_words.len() != 80 {
        return Err(ProtoError::InvalidInput(format!(
            "message-schedule continuation must contain 80 words, got {}",
            message_schedule.schedule_words.len()
        )));
    }
    let _ = backend;
    Ok(DdhHiddenEvalRoundCoreContinuation {
        rounds_completed: 0,
        schedule_words: message_schedule.schedule_words.clone(),
        state_words: RoundKernelState::from_iv_words(&constant_pool.sha512_iv_words)
            .to_shared_bits()?,
    })
}

pub fn advance_round_core_continuation_with_pool<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    continuation: &DdhHiddenEvalRoundCoreContinuation,
) -> ProtoResult<DdhHiddenEvalRoundCoreContinuation> {
    if continuation.schedule_words.len() != 80 {
        return Err(ProtoError::InvalidInput(format!(
            "round-core continuation must contain 80 schedule words, got {}",
            continuation.schedule_words.len()
        )));
    }
    let round = usize::from(continuation.rounds_completed);
    if round >= 80 {
        return Err(ProtoError::InvalidInput(
            "round-core continuation has already completed all 80 rounds".to_string(),
        ));
    }
    let schedule_words = continuation
        .schedule_words
        .iter()
        .map(|word| SplitLocalBitWord::from_shared_bits(word))
        .collect::<ProtoResult<Vec<_>>>()?;
    let mut state = RoundKernelState::from_shared_bits(&continuation.state_words)?;
    let mut boolean_scratch = RoundCoreBooleanScratch::new(64);
    let mut round_label = String::with_capacity(40);
    set_round_label(&mut round_label, round, "sigma1");
    big_sigma1_local_bits_core_into(
        backend,
        &round_label,
        state.e.as_pair_ref(),
        &mut boolean_scratch.sigma1_core,
    )?;
    boolean_scratch.materialize_sigma1()?;
    set_round_label(&mut round_label, round, "ch");
    ch_local_bits_into(
        backend,
        &round_label,
        state.e.as_pair_ref(),
        state.f.as_pair_ref(),
        state.g.as_pair_ref(),
        &mut boolean_scratch,
    )?;
    set_round_label(&mut round_label, round, "temp1");
    let (temp1, _) = add_five_local_bit_pairs_to_arithmetic_naive(
        backend,
        &round_label,
        state.h.as_pair_ref(),
        boolean_scratch.sigma1.as_pair_ref(),
        boolean_scratch.choose.as_pair_ref(),
        constant_pool.sha512_round_constants[round].as_pair_ref(),
        schedule_words[round].as_pair_ref(),
    )?;
    set_round_label(&mut round_label, round, "sigma0");
    big_sigma0_local_bits_core_into(
        backend,
        &round_label,
        state.a.as_pair_ref(),
        &mut boolean_scratch.sigma0_core,
    )?;
    boolean_scratch.materialize_sigma0()?;
    set_round_label(&mut round_label, round, "maj");
    maj_local_bits_into(
        backend,
        &round_label,
        state.a.as_pair_ref(),
        state.b.as_pair_ref(),
        state.c.as_pair_ref(),
        &mut boolean_scratch,
    )?;
    set_round_label(&mut round_label, round, "temp2");
    let (temp2, _) = add_two_local_bit_pairs_to_arithmetic_naive(
        backend,
        &round_label,
        boolean_scratch.sigma0.as_pair_ref(),
        boolean_scratch.majority.as_pair_ref(),
    )?;
    set_round_label(&mut round_label, round, "state3");
    let state3 = split_local_bit_pair_to_arithmetic_word_pair_naive(
        backend,
        &round_label,
        state.d.as_pair_ref(),
    )?;
    let arithmetic_temps = RoundKernelArithmeticTemps {
        temp1,
        temp2,
        state3,
    };
    set_round_label(&mut round_label, round, "new_a");
    let new_a_arith = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &round_label,
        &arithmetic_temps.temp1,
        &arithmetic_temps.temp2,
    )?;
    set_round_label(&mut round_label, round, "new_a_bits");
    let new_a =
        arithmetic_word_pair_to_split_local_bits_secure(backend, &round_label, &new_a_arith)?;
    set_round_label(&mut round_label, round, "new_e");
    let new_e_arith = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &round_label,
        &arithmetic_temps.state3,
        &arithmetic_temps.temp1,
    )?;
    set_round_label(&mut round_label, round, "new_e_bits");
    let new_e =
        arithmetic_word_pair_to_split_local_bits_secure(backend, &round_label, &new_e_arith)?;
    state.rotate_with_new_words(new_a, new_e);
    Ok(DdhHiddenEvalRoundCoreContinuation {
        rounds_completed: continuation.rounds_completed.saturating_add(1),
        schedule_words: continuation.schedule_words.clone(),
        state_words: state.to_shared_bits()?,
    })
}

pub fn compute_round_core_continuation_digest(
    continuation: &DdhHiddenEvalRoundCoreContinuation,
) -> ProtoResult<[u8; 32]> {
    compute_round_core_completed_digest(continuation)
}

fn materialize_projector_inputs_from_add_stage_inputs(
    d_bits: &SplitLocalBitWord,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<DdhHiddenEvalProjectorInputs> {
    Ok(DdhHiddenEvalProjectorInputs {
        add_stage_bits: d_bits.to_shared_bits()?,
        tau_client_bits: tau_client_bits.words.clone(),
        tau_relayer_left_bits: tau_relayer_bits.left_words.clone(),
        tau_relayer_right_bits: tau_relayer_bits.right_words.clone(),
    })
}

pub fn materialize_output_bundles_from_continuations_with_pool<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    round_core: &DdhHiddenEvalRoundCoreContinuation,
    projector_inputs: &DdhHiddenEvalProjectorInputs,
) -> ProtoResult<DdhHiddenEvalOutputBundles> {
    ensure_program_shape(program)?;
    let d_bits = SplitLocalBitWord::from_shared_bits(&projector_inputs.add_stage_bits)?;
    let round_state = RoundKernelState::from_shared_bits(&round_core.state_words)?;
    let final_words = round_state.finalize_with_iv(
        backend,
        &constant_pool.sha512_iv_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let tau_client_bits = SplitLocalBitWord::from_shared_bits(&projector_inputs.tau_client_bits)?;
    execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &d_bits,
        &final_words,
        &tau_client_bits,
        &projector_inputs.tau_relayer_left_bits,
        &projector_inputs.tau_relayer_right_bits,
        DdhHiddenEvalClientOutputProjection::trusted_server_projection(),
    )
    .map(|execution| execution.output)
}

pub fn materialize_server_output_bundles_from_continuations_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    round_core: &DdhHiddenEvalRoundCoreContinuation,
    projector_inputs: &DdhHiddenEvalProjectorInputs,
) -> ProtoResult<DdhHiddenEvalServerOutputBundles> {
    ensure_program_shape(program)?;
    let d_bits = SplitLocalBitWord::from_shared_bits(&projector_inputs.add_stage_bits)?;
    let round_state = RoundKernelState::from_shared_bits(&round_core.state_words)?;
    let final_words = round_state.finalize_with_iv(
        backend,
        &constant_pool.sha512_iv_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let tau_client_bits = SplitLocalBitWord::from_shared_bits(&projector_inputs.tau_client_bits)?;
    execute_server_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &d_bits,
        &final_words,
        &tau_client_bits,
        &projector_inputs.tau_relayer_left_bits,
        &projector_inputs.tau_relayer_right_bits,
    )
}

pub fn materialize_output_bundles_from_projector_inputs_with_pool<B: DdhHssArithmeticBackend>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    projector_inputs: &DdhHiddenEvalProjectorInputs,
) -> ProtoResult<DdhHiddenEvalOutputBundles> {
    ensure_program_shape(program)?;
    let d_bits = SplitLocalBitWord::from_shared_bits(&projector_inputs.add_stage_bits)?;
    let schedule_output =
        execute_message_schedule_stage(backend, constant_pool, &program.stages[1], &d_bits)?;
    let round_output = execute_round_stages(
        backend,
        constant_pool,
        &program.stages[2..6],
        &schedule_output.words,
    )?;
    let tau_client_bits = SplitLocalBitWord::from_shared_bits(&projector_inputs.tau_client_bits)?;
    execute_output_projector_stage(
        backend,
        constant_pool,
        &program.stages[6],
        &d_bits,
        &round_output.hash_core.final_words,
        &tau_client_bits,
        &projector_inputs.tau_relayer_left_bits,
        &projector_inputs.tau_relayer_right_bits,
        DdhHiddenEvalClientOutputProjection::trusted_server_projection(),
    )
    .map(|execution| execution.output)
}

pub fn materialize_staged_server_execution_with_split_server_inputs_with_pool<
    B: DdhHssArithmeticBackend,
>(
    program: &HiddenEvalProgram,
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    y_client_bits: &DdhHssInputShareBundle,
    y_relayer_bits: &DdhHiddenEvalServerInputBundle,
    tau_client_bits: &DdhHssInputShareBundle,
    tau_relayer_bits: &DdhHiddenEvalServerInputBundle,
) -> ProtoResult<DdhHiddenEvalStagedMaterialization> {
    ensure_program_shape(program)?;
    let client_input_commitment = combine_bundle_commitments(
        backend,
        HiddenEvalInputOwner::Client,
        &[y_client_bits, tau_client_bits],
    );
    let server_input_commitment =
        combine_server_input_bundle_commitments(backend, y_relayer_bits, tau_relayer_bits);
    let y_client_bits_local = SplitLocalBitWord::from_shared_bits(&y_client_bits.words)?;
    let d_bits = execute_add_stage(
        backend,
        &program.stages[0],
        &y_client_bits_local,
        &y_relayer_bits.left_words,
        &y_relayer_bits.right_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    let add_stage_digest = digest_split_local_bit_word(b"add_stage", &d_bits)?;

    let message_schedule = initialize_message_schedule_continuation(
        add_stage_digest,
        &d_bits.to_shared_bits()?,
        constant_pool,
    )?;

    let projector_inputs = materialize_projector_inputs_from_add_stage_inputs(
        &d_bits,
        tau_client_bits,
        tau_relayer_bits,
    )?;

    Ok(DdhHiddenEvalStagedMaterialization {
        add_stage_digest,
        message_schedule,
        projector_inputs,
        client_input_commitment,
        server_input_commitment,
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
    let window_performance = web_sys::window().and_then(|window| window.performance());
    let global_performance = js_sys::Reflect::get(
        &js_sys::global(),
        &wasm_bindgen::JsValue::from_str("performance"),
    )
    .ok()
    .and_then(|value| value.dyn_into::<web_sys::Performance>().ok());
    window_performance
        .or(global_performance)
        .map(|performance| (performance.now() * 1_000_000.0) as u128)
        .unwrap_or_else(|| (js_sys::Date::now() * 1_000_000.0) as u128)
}

fn elapsed_ns(started_ns: u128) -> u128 {
    monotonic_now_ns().saturating_sub(started_ns)
}

fn set_round_label(buffer: &mut String, round: usize, suffix: &str) {
    buffer.clear();
    write!(buffer, "round_core/{round}/{suffix}").expect("write round label");
}

fn set_indexed_label(buffer: &mut String, label: &str, idx: usize) {
    buffer.clear();
    write!(buffer, "{label}/{idx}").expect("write indexed label");
}

fn set_indexed_child_label(buffer: &mut String, label: &str, child: &str, idx: usize) {
    buffer.clear();
    write!(buffer, "{label}/{child}/{idx}").expect("write indexed child label");
}

fn set_child_label(buffer: &mut String, label: &str, child: &str) {
    buffer.clear();
    write!(buffer, "{label}/{child}").expect("write child label");
}

fn set_reduce_label(buffer: &mut String, label: &str, operation: &str, round: usize) {
    buffer.clear();
    write!(buffer, "{label}/reduce_mod_l/{operation}/{round}").expect("write reduce label");
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
        let (accumulation_arith, add_timing) = add_four_local_bit_pairs_to_arithmetic_naive(
            backend,
            &format!("message_schedule/{t}"),
            words[t - 16].as_pair_ref(),
            sigma0.as_pair_ref(),
            words[t - 7].as_pair_ref(),
            sigma1.as_pair_ref(),
        )?;
        let accumulation = arithmetic_word_pair_to_split_local_bits_secure(
            backend,
            &format!("message_schedule/{t}/out"),
            &accumulation_arith,
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
    let iv_words = &constant_pool.sha512_iv_words;
    let round_constants = &constant_pool.sha512_round_constants;
    let mut state = RoundKernelState::from_iv_words(iv_words);
    let mut sigma0_duration_ns = 0u128;
    let mut sigma1_duration_ns = 0u128;
    let mut ch_duration_ns = 0u128;
    let mut maj_duration_ns = 0u128;
    let mut state3_duration_ns = 0u128;
    let mut temp1_duration_ns = 0u128;
    let mut temp1_add_timing = LocalBitWordAddTiming::default();
    let mut temp2_duration_ns = 0u128;
    let mut new_a_bits_duration_ns = 0u128;
    let mut new_e_bits_duration_ns = 0u128;
    let mut round_label = String::with_capacity(40);
    let mut boolean_scratch = RoundCoreBooleanScratch::new(64);

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
            set_round_label(&mut round_label, round, "sigma1");
            big_sigma1_local_bits_core_into(
                backend,
                &round_label,
                state.e.as_pair_ref(),
                &mut boolean_scratch.sigma1_core,
            )?;
            boolean_scratch.materialize_sigma1()?;
            sigma1_duration_ns += elapsed_ns(sigma1_started_ns);
            let ch_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "ch");
            ch_local_bits_into(
                backend,
                &round_label,
                state.e.as_pair_ref(),
                state.f.as_pair_ref(),
                state.g.as_pair_ref(),
                &mut boolean_scratch,
            )?;
            ch_duration_ns += elapsed_ns(ch_started_ns);
            let temp1_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "temp1");
            let (temp1, add_timing) = add_five_local_bit_pairs_to_arithmetic_naive(
                backend,
                &round_label,
                state.h.as_pair_ref(),
                boolean_scratch.sigma1.as_pair_ref(),
                boolean_scratch.choose.as_pair_ref(),
                round_constants[round].as_pair_ref(),
                schedule[round].as_pair_ref(),
            )?;
            temp1_duration_ns += elapsed_ns(temp1_started_ns);
            temp1_add_timing.add_assign(&add_timing);
            let sigma0_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "sigma0");
            big_sigma0_local_bits_core_into(
                backend,
                &round_label,
                state.a.as_pair_ref(),
                &mut boolean_scratch.sigma0_core,
            )?;
            boolean_scratch.materialize_sigma0()?;
            sigma0_duration_ns += elapsed_ns(sigma0_started_ns);
            let maj_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "maj");
            maj_local_bits_into(
                backend,
                &round_label,
                state.a.as_pair_ref(),
                state.b.as_pair_ref(),
                state.c.as_pair_ref(),
                &mut boolean_scratch,
            )?;
            maj_duration_ns += elapsed_ns(maj_started_ns);
            let temp2_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "temp2");
            let (temp2, _) = add_two_local_bit_pairs_to_arithmetic_naive(
                backend,
                &round_label,
                boolean_scratch.sigma0.as_pair_ref(),
                boolean_scratch.majority.as_pair_ref(),
            )?;
            temp2_duration_ns += elapsed_ns(temp2_started_ns);
            let state3_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "state3");
            let state3 = split_local_bit_pair_to_arithmetic_word_pair_naive(
                backend,
                &round_label,
                state.d.as_pair_ref(),
            )?;
            state3_duration_ns += elapsed_ns(state3_started_ns);
            let arithmetic_temps = RoundKernelArithmeticTemps {
                temp1,
                temp2,
                state3,
            };
            set_round_label(&mut round_label, round, "new_a");
            let new_a_arith = add_local_arithmetic_word_pairs(
                backend.evaluation_key(),
                &round_label,
                &arithmetic_temps.temp1,
                &arithmetic_temps.temp2,
            )?;
            let new_a_bits_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "new_a_bits");
            let new_a = arithmetic_word_pair_to_split_local_bits_secure(
                backend,
                &round_label,
                &new_a_arith,
            )?;
            new_a_bits_duration_ns += elapsed_ns(new_a_bits_started_ns);
            set_round_label(&mut round_label, round, "new_e");
            let new_e_arith = add_local_arithmetic_word_pairs(
                backend.evaluation_key(),
                &round_label,
                &arithmetic_temps.state3,
                &arithmetic_temps.temp1,
            )?;
            let new_e_bits_started_ns = monotonic_now_ns();
            set_round_label(&mut round_label, round, "new_e_bits");
            let new_e = arithmetic_word_pair_to_split_local_bits_secure(
                backend,
                &round_label,
                &new_e_arith,
            )?;
            new_e_bits_duration_ns += elapsed_ns(new_e_bits_started_ns);
            state.rotate_with_new_words(new_a, new_e);
        }
    }

    let final_words = state.finalize_with_iv(
        backend,
        &iv_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
    )?;
    Ok(RoundStagesOutput {
        hash_core: SharedHashCoreOutput { final_words },
        sigma0_duration_ns,
        sigma1_duration_ns,
        ch_duration_ns,
        maj_duration_ns,
        state3_duration_ns,
        temp1_duration_ns,
        temp1_add_timing,
        temp2_duration_ns,
        new_a_bits_duration_ns,
        new_e_bits_duration_ns,
    })
}

fn execute_output_projector_stage<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    stage: &HiddenEvalStage,
    d_bits: &SplitLocalBitWord,
    final_words: &[SplitLocalBitWord],
    tau_client_bits: &SplitLocalBitWord,
    tau_relayer_left_bits: &[DdhHssTransportWord],
    tau_relayer_right_bits: &[DdhHssTransportWord],
    client_output_projection: DdhHiddenEvalClientOutputProjection,
) -> ProtoResult<OutputProjectorExecution> {
    if stage.kind != HiddenEvalStageKind::OutputProjector {
        return Err(ProtoError::InvalidInput(
            "unexpected output-projector stage kind".to_string(),
        ));
    }

    let OutputProjectorCoreBits {
        reduced_a_bits,
        tau_bits,
        profile: core_profile,
    } = compute_output_projector_core_bits(
        backend,
        constant_pool,
        final_words,
        tau_client_bits,
        tau_relayer_left_bits,
        tau_relayer_right_bits,
    )?;
    let mut profile = core_profile;
    let (client_output_bits, x_relayer_base_bits) = match client_output_projection {
        DdhHiddenEvalClientOutputProjection::TrustedServerProjection => {
            let client_base_started_ns = monotonic_now_ns();
            let client_base_bits = add_words_bits_mod_l_canonical_inputs_local(
                backend,
                &reduced_a_bits,
                &tau_bits,
                &constant_pool.zero_left,
                &constant_pool.zero_right,
                &constant_pool.one_left,
                &constant_pool.one_right,
            )?;
            profile.client_base_duration_ns = elapsed_ns(client_base_started_ns);
            profile.local_word_materializations =
                profile.local_word_materializations.saturating_add(
                    split_local_bit_word_materialization_count(&client_base_bits),
                );
            profile.client_output_duration_ns = profile.client_base_duration_ns;
            let relayer_output_started_ns = monotonic_now_ns();
            let relayer_base_bits = add_words_bits_mod_l_canonical_inputs_local(
                backend,
                &client_base_bits,
                &tau_bits,
                &constant_pool.zero_left,
                &constant_pool.zero_right,
                &constant_pool.one_left,
                &constant_pool.one_right,
            )?;
            profile.relayer_output_duration_ns = elapsed_ns(relayer_output_started_ns);
            profile.local_word_materializations =
                profile.local_word_materializations.saturating_add(
                    split_local_bit_word_materialization_count(&relayer_base_bits),
                );
            (client_base_bits, relayer_base_bits)
        }
        DdhHiddenEvalClientOutputProjection::ClientMaskedProjection { client_output_mask } => {
            let canonical_mask = Scalar::from_bytes_mod_order(client_output_mask).to_bytes();
            let mask_share_started_ns = monotonic_now_ns();
            let mask_bundle = backend.share_input_bit_bundle(
                HiddenEvalInputOwner::Client,
                "client_output_mask",
                &canonical_mask,
            )?;
            profile.mask_share_duration_ns = elapsed_ns(mask_share_started_ns);
            let client_base_started_ns = monotonic_now_ns();
            let client_base_bits = add_words_bits_mod_l_canonical_inputs_local(
                backend,
                &reduced_a_bits,
                &tau_bits,
                &constant_pool.zero_left,
                &constant_pool.zero_right,
                &constant_pool.one_left,
                &constant_pool.one_right,
            )?;
            profile.client_base_duration_ns = elapsed_ns(client_base_started_ns);
            profile.local_word_materializations =
                profile.local_word_materializations.saturating_add(
                    split_local_bit_word_materialization_count(&client_base_bits),
                );
            let client_output_started_ns = monotonic_now_ns();
            let client_blinded_bits =
                add_words_bits_mod_l_canonical_inputs_right_shared_bits_local(
                    backend,
                    &client_base_bits,
                    &mask_bundle.words,
                    &constant_pool.zero_left,
                    &constant_pool.zero_right,
                    &constant_pool.one_left,
                    &constant_pool.one_right,
                )?;
            profile.client_output_duration_ns = elapsed_ns(client_output_started_ns);
            profile.local_word_materializations =
                profile.local_word_materializations.saturating_add(
                    split_local_bit_word_materialization_count(&client_blinded_bits),
                );
            let relayer_output_started_ns = monotonic_now_ns();
            let relayer_base_bits = add_words_bits_mod_l_canonical_inputs_local(
                backend,
                &client_base_bits,
                &tau_bits,
                &constant_pool.zero_left,
                &constant_pool.zero_right,
                &constant_pool.one_left,
                &constant_pool.one_right,
            )?;
            profile.relayer_output_duration_ns = elapsed_ns(relayer_output_started_ns);
            profile.local_word_materializations =
                profile.local_word_materializations.saturating_add(
                    split_local_bit_word_materialization_count(&relayer_base_bits),
                );
            (client_blinded_bits, relayer_base_bits)
        }
    };
    let client_output_value_kind = client_output_projection.value_kind();

    let bundle_build_started_ns = monotonic_now_ns();
    let (x_relayer_base_left, x_relayer_base_right) =
        build_hidden_bit_output_transport_bundle_pair(
            backend,
            HiddenEvalInputOwner::Server,
            "x_relayer_base",
            &x_relayer_base_bits,
        )?;
    let output = DdhHiddenEvalOutputBundles {
        canonical_seed: build_hidden_bit_output_bundle(
            backend,
            HiddenEvalInputOwner::Client,
            "canonical_seed",
            d_bits,
        )?,
        client_output: DdhHiddenEvalClientOutputBundle::new(
            client_output_value_kind,
            build_hidden_bit_output_bundle(
                backend,
                HiddenEvalInputOwner::Client,
                client_output_value_kind.bundle_label(),
                &client_output_bits,
            )?,
        )?,
        x_relayer_base_left,
        x_relayer_base_right,
    };
    profile.bundle_build_duration_ns = elapsed_ns(bundle_build_started_ns);

    Ok(OutputProjectorExecution { output, profile })
}

fn split_local_bit_word_materialization_count(word: &SplitLocalBitWord) -> u64 {
    word.left
        .len()
        .saturating_add(word.right.len())
        .try_into()
        .unwrap_or(u64::MAX)
}

fn execute_server_output_projector_stage<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    stage: &HiddenEvalStage,
    d_bits: &SplitLocalBitWord,
    final_words: &[SplitLocalBitWord],
    tau_client_bits: &SplitLocalBitWord,
    tau_relayer_left_bits: &[DdhHssTransportWord],
    tau_relayer_right_bits: &[DdhHssTransportWord],
) -> ProtoResult<DdhHiddenEvalServerOutputBundles> {
    if stage.kind != HiddenEvalStageKind::OutputProjector {
        return Err(ProtoError::InvalidInput(
            "unexpected output-projector stage kind".to_string(),
        ));
    }

    let OutputProjectorCoreBits {
        reduced_a_bits,
        tau_bits,
        profile: _,
    } = compute_output_projector_core_bits(
        backend,
        constant_pool,
        final_words,
        tau_client_bits,
        tau_relayer_left_bits,
        tau_relayer_right_bits,
    )?;
    let two_tau_bits = add_words_bits_mod_l_canonical_inputs_local(
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
        &two_tau_bits,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;
    let (x_relayer_base_left, x_relayer_base_right) =
        build_hidden_bit_output_transport_bundle_pair(
            backend,
            HiddenEvalInputOwner::Server,
            "x_relayer_base",
            &x_relayer_base_bits,
        )?;

    Ok(DdhHiddenEvalServerOutputBundles {
        canonical_seed_commitment: hidden_bit_output_commitment(
            backend,
            HiddenEvalInputOwner::Client,
            "canonical_seed",
            d_bits,
        )?,
        x_relayer_base_left,
        x_relayer_base_right,
    })
}

struct OutputProjectorCoreBits {
    reduced_a_bits: SplitLocalBitWord,
    tau_bits: SplitLocalBitWord,
    profile: OutputProjectorProfile,
}

fn compute_output_projector_core_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    constant_pool: &DdhHiddenEvalConstantPool,
    final_words: &[SplitLocalBitWord],
    tau_client_bits: &SplitLocalBitWord,
    tau_relayer_left_bits: &[DdhHssTransportWord],
    tau_relayer_right_bits: &[DdhHssTransportWord],
) -> ProtoResult<OutputProjectorCoreBits> {
    let core_started_ns = monotonic_now_ns();
    let clamp_started_ns = monotonic_now_ns();
    let clamped_a_bits = extract_clamped_a_bits_local(
        final_words,
        &constant_pool.zero_left,
        &constant_pool.zero_right,
        &constant_pool.one_left,
        &constant_pool.one_right,
    )?;
    let clamp_a_duration_ns = elapsed_ns(clamp_started_ns);
    let reduce_started_ns = monotonic_now_ns();
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
    let reduce_a_duration_ns = elapsed_ns(reduce_started_ns);
    let tau_started_ns = monotonic_now_ns();
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
    let tau_duration_ns = elapsed_ns(tau_started_ns);
    let local_word_materializations = split_local_bit_word_materialization_count(&reduced_a_bits)
        .saturating_add(split_local_bit_word_materialization_count(&tau_bits));
    Ok(OutputProjectorCoreBits {
        reduced_a_bits,
        tau_bits,
        profile: OutputProjectorProfile {
            core_duration_ns: elapsed_ns(core_started_ns),
            clamp_a_duration_ns,
            reduce_a_duration_ns,
            tau_duration_ns,
            local_word_materializations,
            ..OutputProjectorProfile::default()
        },
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
    let mut reduce_label = String::with_capacity(label.len() + 32);
    for round in 0..rounds {
        set_reduce_label(&mut reduce_label, label, "sub", round);
        let (difference, borrow_left, borrow_right) = sub_local_bit_words_with_ed25519_l(
            backend,
            &reduce_label,
            &reduced,
            zero_left,
            zero_right,
            one_left,
            one_right,
        )?;
        set_reduce_label(&mut reduce_label, label, "geq", round);
        let (geq_modulus_left, geq_modulus_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            reduce_label.as_bytes(),
            &borrow_left,
            &borrow_right,
            one_left,
            one_right,
        )?;
        set_reduce_label(&mut reduce_label, label, "select", round);
        reduced = select_local_bit_words(
            backend,
            &reduce_label,
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

fn add_words_bits_mod_l_canonical_inputs_right_shared_bits_local<B: DdhHssArithmeticBackend>(
    backend: &B,
    left: &SplitLocalBitWord,
    right: &[DdhHssSharedWord],
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    one_left: &DdhHssLocalWord,
    one_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    let sum = add_two_local_bit_words_right_shared_bits(
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
                if global_byte_idx == 0 && bit_idx < 3 {
                    left.push_local_word(zero_left)?;
                    right.push_local_word(zero_right)?;
                } else if global_byte_idx == 31 && bit_idx == 6 {
                    left.push_local_word(one_left)?;
                    right.push_local_word(one_right)?;
                } else if global_byte_idx == 31 && bit_idx == 7 {
                    left.push_local_word(zero_left)?;
                    right.push_local_word(zero_right)?;
                } else {
                    let left_word = word_bits.left.local_word(absolute_idx)?;
                    let right_word = word_bits.right.local_word(absolute_idx)?;
                    left.push_local_word(&left_word)?;
                    right.push_local_word(&right_word)?;
                }
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

fn hidden_bit_output_commitment<B: DdhHssArithmeticBackend>(
    backend: &B,
    owner: HiddenEvalInputOwner,
    label: &str,
    bits: &SplitLocalBitWord,
) -> ProtoResult<[u8; 32]> {
    let words = canonicalize_hidden_bit_output_words(owner, label, bits)?;
    Ok(backend.input_commitment(owner, label, &words))
}

fn build_hidden_bit_output_transport_bundle_pair<B: DdhHssArithmeticBackend>(
    backend: &B,
    owner: HiddenEvalInputOwner,
    label: &str,
    bits: &SplitLocalBitWord,
) -> ProtoResult<(DdhHssTransportBundle, DdhHssTransportBundle)> {
    let canonical_words = canonicalize_hidden_bit_output_words(owner, label, bits)?;
    let commitment = backend.input_commitment(owner, label, &canonical_words);
    Ok((
        build_hidden_bit_output_transport_bundle_from_canonical(
            owner,
            label,
            DdhHssShareSide::Left,
            &canonical_words,
            commitment,
        ),
        build_hidden_bit_output_transport_bundle_from_canonical(
            owner,
            label,
            DdhHssShareSide::Right,
            &canonical_words,
            commitment,
        ),
    ))
}

fn build_hidden_bit_output_transport_bundle_from_canonical(
    owner: HiddenEvalInputOwner,
    label: &str,
    share_side: DdhHssShareSide,
    canonical_words: &[DdhHssSharedWord],
    commitment: [u8; 32],
) -> DdhHssTransportBundle {
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
    DdhHssTransportBundle {
        owner,
        label: label.to_string(),
        share_side,
        words,
        commitment,
    }
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
            left_commitment: crate::ddh::ddh_hss::commit_word(
                owner,
                b"left",
                bit.left_word,
                &bit.provenance_digest,
            ),
            right_commitment: crate::ddh::ddh_hss::commit_word(
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

#[cfg(test)]
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

#[cfg(test)]
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

fn local_bit_pair_parts(
    source: LocalBitWordPairRef<'_>,
    idx: usize,
) -> ProtoResult<(u8, u8, [u8; 32])> {
    let left_provenance = source.left.provenance_digests[idx];
    let right_provenance = source.right.provenance_digests[idx];
    if left_provenance != right_provenance {
        return Err(ProtoError::InvalidInput(format!(
            "split local bit pair provenance mismatch at index {idx}"
        )));
    }
    Ok((
        source.left.share_bit(idx),
        source.right.share_bit(idx),
        left_provenance,
    ))
}

fn transformed_local_bit_pair_parts(
    source: LocalBitWordPairRef<'_>,
    idx: usize,
    spec: LocalBitTransformSpec<'_>,
) -> ProtoResult<(u8, u8, [u8; 32])> {
    match spec.transform {
        LocalBitTransform::Rotate(offset) => {
            let transformed_idx = (idx + offset) % source.len();
            local_bit_pair_parts(source, transformed_idx)
        }
        LocalBitTransform::Shift(shift) => {
            let zero = spec.zero.ok_or_else(|| {
                ProtoError::InvalidInput(
                    "shifted local bit transform requires a zero word".to_string(),
                )
            })?;
            if zero.width_bits != 1 {
                return Err(ProtoError::InvalidInput(
                    "shifted local bit transform requires width-1 zero".to_string(),
                ));
            }
            if idx + shift < source.len() {
                local_bit_pair_parts(source, idx + shift)
            } else {
                Ok(((zero.share_word as u8) & 1, 0, zero.provenance_digest))
            }
        }
    }
}

fn xor_transformed_local_bit_word_side_core(
    evaluation_key: &crate::ddh::DdhHssEvaluationKey,
    label: &str,
    source: &LocalBitWordSide,
    transforms: [LocalBitTransformSpec<'_>; 3],
) -> ProtoResult<LocalBitWordSide> {
    source.ensure_shape()?;
    let mut core = CoreBitWordSide::empty(source.share_side, source.len());
    let mut xor_label = String::with_capacity(label.len() + 16);
    for idx in 0..source.len() {
        let (first_bit, first_provenance) =
            transformed_local_bit_parts(source, idx, transforms[0])?;
        let (second_bit, second_provenance) =
            transformed_local_bit_parts(source, idx, transforms[1])?;
        let (third_bit, third_provenance) =
            transformed_local_bit_parts(source, idx, transforms[2])?;
        set_indexed_child_label(&mut xor_label, label, "xor01", idx);
        let xor01 = xor_local_bit_core_from_raw_public(
            evaluation_key,
            xor_label.as_bytes(),
            source.share_side,
            first_bit,
            &first_provenance,
            second_bit,
            &second_provenance,
        );
        set_indexed_child_label(&mut xor_label, label, "xor012", idx);
        let xor012 = xor_local_bit_core_from_raw_public(
            evaluation_key,
            xor_label.as_bytes(),
            source.share_side,
            (xor01.share_word as u8) & 1,
            &xor01.provenance_digest,
            third_bit,
            &third_provenance,
        );
        core.push_core_word(&xor012)?;
    }
    let mut out = empty_local_bit_slice(source.share_side, source.len());
    core.materialize_into(&mut out, b"eval-xor-local-word")?;
    Ok(out)
}

fn xor_transformed_local_bit_word_pair_core_into(
    evaluation_key: &crate::ddh::DdhHssEvaluationKey,
    label: &str,
    source: LocalBitWordPairRef<'_>,
    transforms: [LocalBitTransformSpec<'_>; 3],
    out: &mut RoundKernelCoreBooleanWord,
) -> ProtoResult<()> {
    source.left.ensure_shape()?;
    source.right.ensure_shape()?;
    if source.left.len() != source.right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width local word pair, got {} and {}",
            source.left.len(),
            source.right.len()
        )));
    }
    out.reset();
    let mut xor_label = String::with_capacity(label.len() + 16);
    for idx in 0..source.len() {
        let (first_left, first_right, first_provenance) =
            transformed_local_bit_pair_parts(source, idx, transforms[0])?;
        let (second_left, second_right, second_provenance) =
            transformed_local_bit_pair_parts(source, idx, transforms[1])?;
        let (third_left, third_right, third_provenance) =
            transformed_local_bit_pair_parts(source, idx, transforms[2])?;
        set_indexed_child_label(&mut xor_label, label, "xor01", idx);
        let xor01 = xor_local_bit_pair_core_from_raw_public(
            evaluation_key,
            xor_label.as_bytes(),
            first_left,
            first_right,
            &first_provenance,
            second_left,
            second_right,
            &second_provenance,
        );
        set_indexed_child_label(&mut xor_label, label, "xor012", idx);
        let xor012 = xor_local_bit_pair_core_from_raw_public(
            evaluation_key,
            xor_label.as_bytes(),
            (xor01.0.share_word as u8) & 1,
            (xor01.1.share_word as u8) & 1,
            &xor01.0.provenance_digest,
            third_left,
            third_right,
            &third_provenance,
        );
        out.left.push_core_word(&xor012.0)?;
        out.right.push_core_word(&xor012.1)?;
    }
    Ok(())
}

fn xor_split_local_bit_words_into(
    evaluation_key: &crate::ddh::DdhHssEvaluationKey,
    label: &str,
    left: LocalBitWordPairRef<'_>,
    right: LocalBitWordPairRef<'_>,
    out: &mut RoundKernelBooleanWord,
) -> ProtoResult<()> {
    if left.len() != right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width local words, got {} and {}",
            left.len(),
            right.len()
        )));
    }
    left.left.ensure_shape()?;
    left.right.ensure_shape()?;
    right.left.ensure_shape()?;
    right.right.ensure_shape()?;
    out.reset();
    let mut xor_label = String::with_capacity(label.len() + 8);
    for idx in 0..left.len() {
        let left_parts = local_bit_pair_parts(left, idx)?;
        let right_parts = local_bit_pair_parts(right, idx)?;
        set_indexed_label(&mut xor_label, label, idx);
        let xor_pair = xor_local_bit_pair_from_raw_public(
            evaluation_key,
            xor_label.as_bytes(),
            left_parts.0,
            left_parts.1,
            &left_parts.2,
            right_parts.0,
            right_parts.1,
            &right_parts.2,
        );
        out.left.push_local_word(&xor_pair.0)?;
        out.right.push_local_word(&xor_pair.1)?;
    }
    Ok(())
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

fn bitmask_for_width(width_bits: u16) -> u64 {
    if width_bits == 64 {
        u64::MAX
    } else {
        (1u64 << u32::from(width_bits)) - 1
    }
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

fn add_local_arithmetic_word_pairs(
    evaluation_key: &crate::ddh::DdhHssEvaluationKey,
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

fn split_local_bit_pair_to_arithmetic_word_pair_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    bits: LocalBitWordPairRef<'_>,
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
    let width_mask = bitmask_for_width(width_bits);
    let left_packed = pack_local_side_share_bits(&bits.left)?;
    let mut adjusted_right = pack_local_side_share_bits(&bits.right)?;
    for idx in 0..bits.len() {
        if idx + 1 >= bits.len() {
            continue;
        }
        let cross_mask = 0u64.wrapping_sub(u64::from(
            bits.left.share_bit(idx) & bits.right.share_bit(idx),
        ));
        let delta = (1u64 << (idx + 1)) & cross_mask;
        adjusted_right = adjusted_right.wrapping_sub(delta) & width_mask;
    }
    let base_material = (0..bits.len()).flat_map(|idx| {
        [
            bits.left.provenance_digests[idx].as_slice(),
            bits.left.commitments[idx].as_slice(),
            bits.right.provenance_digests[idx].as_slice(),
            bits.right.commitments[idx].as_slice(),
        ]
    });
    let (base_left, base_right) = build_local_word_pair_public_from_extra_material(
        backend.evaluation_key(),
        b"phase-a-bool-to-arith-base",
        label.as_bytes(),
        width_bits,
        left_packed,
        adjusted_right,
        base_material,
    );
    LocalArithmeticWordPair::new(base_left, base_right)
}

// Secure A2B for executor-local arithmetic pairs: decompose each arithmetic
// share separately, then recombine them through the existing Boolean carry
// gadget so carries stay hidden inside split/local state.
fn arithmetic_word_pair_to_split_local_bits_secure<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: &LocalArithmeticWordPair,
) -> ProtoResult<SplitLocalBitWord> {
    let mut child_label = String::with_capacity(label.len() + 16);
    set_child_label(&mut child_label, label, "zero");
    let (zero_left, zero_right) = build_local_word_pair_public(
        backend.evaluation_key(),
        b"phase-a-arith-to-bool-zero",
        child_label.as_bytes(),
        1,
        0,
        0,
        &[
            &word.left.provenance_digest,
            &word.left.share_commitment,
            &word.right.provenance_digest,
            &word.right.share_commitment,
        ],
    );
    let width = usize::from(word.left.width_bits);
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, width);
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, width);
    set_child_label(&mut child_label, label, "sum");
    eval_add_cross_share_local_arithmetic_word_bits_secure_public_into(
        backend.evaluation_key(),
        &child_label,
        &word.left,
        &word.right,
        &zero_left,
        &zero_right,
        |left, right| {
            out_left.push_local_word(&left)?;
            out_right.push_local_word(&right)?;
            Ok(())
        },
    )?;
    SplitLocalBitWord::from_local_sides(out_left, out_right)
}

fn add_two_local_bit_pairs_to_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: LocalBitWordPairRef<'_>,
    b: LocalBitWordPairRef<'_>,
) -> ProtoResult<(LocalArithmeticWordPair, LocalBitWordAddTiming)> {
    let mut child_label = String::with_capacity(label.len() + 8);
    set_child_label(&mut child_label, label, "a");
    let a_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, a)?;
    set_child_label(&mut child_label, label, "b");
    let b_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, b)?;
    Ok((
        add_local_arithmetic_word_pairs(backend.evaluation_key(), label, &a_arith, &b_arith)?,
        LocalBitWordAddTiming::default(),
    ))
}

fn add_four_local_bit_pairs_to_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: LocalBitWordPairRef<'_>,
    b: LocalBitWordPairRef<'_>,
    c: LocalBitWordPairRef<'_>,
    d: LocalBitWordPairRef<'_>,
) -> ProtoResult<(LocalArithmeticWordPair, LocalBitWordAddTiming)> {
    let mut child_label = String::with_capacity(label.len() + 8);
    set_child_label(&mut child_label, label, "a");
    let a_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, a)?;
    set_child_label(&mut child_label, label, "b");
    let b_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, b)?;
    set_child_label(&mut child_label, label, "c");
    let c_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, c)?;
    set_child_label(&mut child_label, label, "d");
    let d_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, d)?;
    set_child_label(&mut child_label, label, "ab");
    let ab = add_local_arithmetic_word_pairs(
        backend.evaluation_key(),
        &child_label,
        &a_arith,
        &b_arith,
    )?;
    set_child_label(&mut child_label, label, "abc");
    let abc =
        add_local_arithmetic_word_pairs(backend.evaluation_key(), &child_label, &ab, &c_arith)?;
    set_child_label(&mut child_label, label, "abcd");
    let abcd =
        add_local_arithmetic_word_pairs(backend.evaluation_key(), &child_label, &abc, &d_arith)?;
    Ok((abcd, LocalBitWordAddTiming::default()))
}

fn add_five_local_bit_pairs_to_arithmetic_naive<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    a: LocalBitWordPairRef<'_>,
    b: LocalBitWordPairRef<'_>,
    c: LocalBitWordPairRef<'_>,
    d: LocalBitWordPairRef<'_>,
    e: LocalBitWordPairRef<'_>,
) -> ProtoResult<(LocalArithmeticWordPair, LocalBitWordAddTiming)> {
    let (abcd, timing) = add_four_local_bit_pairs_to_arithmetic_naive(backend, label, a, b, c, d)?;
    let mut child_label = String::with_capacity(label.len() + 8);
    set_child_label(&mut child_label, label, "e");
    let e_arith = split_local_bit_pair_to_arithmetic_word_pair_naive(backend, &child_label, e)?;
    set_child_label(&mut child_label, label, "abcde");
    let abcde =
        add_local_arithmetic_word_pairs(backend.evaluation_key(), &child_label, &abcd, &e_arith)?;
    Ok((abcde, timing))
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
    let mut carry_left = DdhHssLocalWordCore::from_local_word(zero_left);
    let mut carry_right = DdhHssLocalWordCore::from_local_word(zero_right);
    let mut timing = LocalBitWordAddTiming::default();
    let mut bit_label = String::with_capacity(label.len() + 32);
    for idx in 0..left.len() {
        let left_left_word = left.left.local_word(idx)?;
        let left_right_word = left.right.local_word(idx)?;
        let right_left_word = right.left.local_word(idx)?;
        let right_right_word = right.right.local_word(idx)?;
        let left_left_core = DdhHssLocalWordCore::from_local_word(&left_left_word);
        let left_right_core = DdhHssLocalWordCore::from_local_word(&left_right_word);
        set_indexed_child_label(&mut bit_label, label, "xor_ab", idx);
        let xor_ab_started_ns = monotonic_now_ns();
        let (xor_ab_left, xor_ab_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &right_left_word,
            &right_right_word,
        )?;
        timing.xor_ab_duration_ns = timing
            .xor_ab_duration_ns
            .saturating_add(elapsed_ns(xor_ab_started_ns));
        let xor_ab_left_core = DdhHssLocalWordCore::from_local_word(&xor_ab_left);
        let xor_ab_right_core = DdhHssLocalWordCore::from_local_word(&xor_ab_right);
        set_indexed_child_label(&mut bit_label, label, "sum", idx);
        let sum_started_ns = monotonic_now_ns();
        let (sum_left, sum_right) = xor_local_word_core_pairs_materialized_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &xor_ab_left_core,
            &xor_ab_right_core,
            &carry_left,
            &carry_right,
        )?;
        timing.sum_duration_ns = timing
            .sum_duration_ns
            .saturating_add(elapsed_ns(sum_started_ns));
        set_indexed_child_label(&mut bit_label, label, "a_xor_carry", idx);
        let a_xor_carry_started_ns = monotonic_now_ns();
        let (a_xor_carry_left, a_xor_carry_right) = xor_local_word_core_pairs_materialized_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_core,
            &left_right_core,
            &carry_left,
            &carry_right,
        )?;
        timing.a_xor_carry_duration_ns = timing
            .a_xor_carry_duration_ns
            .saturating_add(elapsed_ns(a_xor_carry_started_ns));
        set_indexed_child_label(&mut bit_label, label, "carry", idx);
        let carry_gate_started_ns = monotonic_now_ns();
        let (carry_gate_left, carry_gate_right) = eval_mul_local_word_pairs_core_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &a_xor_carry_left,
            &a_xor_carry_right,
        )?;
        timing.carry_gate_duration_ns = timing
            .carry_gate_duration_ns
            .saturating_add(elapsed_ns(carry_gate_started_ns));
        set_indexed_child_label(&mut bit_label, label, "next_carry", idx);
        let next_carry_started_ns = monotonic_now_ns();
        (carry_left, carry_right) = xor_local_word_core_pairs_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_core,
            &left_right_core,
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
    let mut carry_left = DdhHssLocalWordCore::from_local_word(zero_left);
    let mut carry_right = DdhHssLocalWordCore::from_local_word(zero_right);
    let mut bit_label = String::with_capacity(label.len() + 32);
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
        let left_left_core = DdhHssLocalWordCore::from_local_word(&left_left_word);
        let left_right_core = DdhHssLocalWordCore::from_local_word(&left_right_word);
        set_indexed_child_label(&mut bit_label, label, "xor_ab", idx);
        let (xor_ab_left, xor_ab_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &right_left_word,
            &right_right_word,
        )?;
        let xor_ab_left_core = DdhHssLocalWordCore::from_local_word(&xor_ab_left);
        let xor_ab_right_core = DdhHssLocalWordCore::from_local_word(&xor_ab_right);
        set_indexed_child_label(&mut bit_label, label, "sum", idx);
        let (sum_left, sum_right) = xor_local_word_core_pairs_materialized_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &xor_ab_left_core,
            &xor_ab_right_core,
            &carry_left,
            &carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label, "a_xor_carry", idx);
        let (a_xor_carry_left, a_xor_carry_right) = xor_local_word_core_pairs_materialized_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_core,
            &left_right_core,
            &carry_left,
            &carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label, "carry", idx);
        let (carry_gate_left, carry_gate_right) = eval_mul_local_word_pairs_core_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &a_xor_carry_left,
            &a_xor_carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label, "next_carry", idx);
        (carry_left, carry_right) = xor_local_word_core_pairs_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_core,
            &left_right_core,
            &carry_gate_left,
            &carry_gate_right,
        )?;
        out_left.push_local_word(&sum_left)?;
        out_right.push_local_word(&sum_right)?;
    }
    SplitLocalBitWord::from_local_sides(out_left, out_right)
}

fn add_two_local_bit_words_right_shared_bits<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    left: &SplitLocalBitWord,
    right: &[DdhHssSharedWord],
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<SplitLocalBitWord> {
    if left.len() != right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "word addition requires same-width bit slices, got {} and {}",
            left.len(),
            right.len()
        )));
    }
    let mut out_left = empty_local_bit_slice(DdhHssShareSide::Left, left.len());
    let mut out_right = empty_local_bit_slice(DdhHssShareSide::Right, left.len());
    let mut carry_left = DdhHssLocalWordCore::from_local_word(zero_left);
    let mut carry_right = DdhHssLocalWordCore::from_local_word(zero_right);
    let mut bit_label = String::with_capacity(label.len() + 32);
    for (idx, right_word) in right.iter().enumerate() {
        if right_word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "word addition requires width-1 shared bits, got {} at index {idx}",
                right_word.width_bits
            )));
        }
        let left_left_word = left.left.local_word(idx)?;
        let left_right_word = left.right.local_word(idx)?;
        let right_left_word = local_word_from_shared(right_word, DdhHssShareSide::Left);
        let right_right_word = local_word_from_shared(right_word, DdhHssShareSide::Right);
        let left_left_core = DdhHssLocalWordCore::from_local_word(&left_left_word);
        let left_right_core = DdhHssLocalWordCore::from_local_word(&left_right_word);
        set_indexed_child_label(&mut bit_label, label, "xor_ab", idx);
        let (xor_ab_left, xor_ab_right) = xor_local_word_pairs_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_word,
            &left_right_word,
            &right_left_word,
            &right_right_word,
        )?;
        let xor_ab_left_core = DdhHssLocalWordCore::from_local_word(&xor_ab_left);
        let xor_ab_right_core = DdhHssLocalWordCore::from_local_word(&xor_ab_right);
        set_indexed_child_label(&mut bit_label, label, "sum", idx);
        let (sum_left, sum_right) = xor_local_word_core_pairs_materialized_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &xor_ab_left_core,
            &xor_ab_right_core,
            &carry_left,
            &carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label, "a_xor_carry", idx);
        let (a_xor_carry_left, a_xor_carry_right) = xor_local_word_core_pairs_materialized_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_core,
            &left_right_core,
            &carry_left,
            &carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label, "carry", idx);
        let (carry_gate_left, carry_gate_right) = eval_mul_local_word_pairs_core_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &a_xor_carry_left,
            &a_xor_carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label, "next_carry", idx);
        (carry_left, carry_right) = xor_local_word_core_pairs_public(
            backend.evaluation_key(),
            bit_label.as_bytes(),
            &left_left_core,
            &left_right_core,
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
        xor_transformed_local_bit_word_side_core(
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
        xor_transformed_local_bit_word_side_core(
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
        xor_transformed_local_bit_word_side_core(
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
        xor_transformed_local_bit_word_side_core(
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

fn big_sigma0_local_bits_core_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: LocalBitWordPairRef<'_>,
    out: &mut RoundKernelCoreBooleanWord,
) -> ProtoResult<()> {
    xor_transformed_local_bit_word_pair_core_into(
        backend.evaluation_key(),
        label,
        word,
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
        out,
    )?;
    Ok(())
}

fn big_sigma1_local_bits_core_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    word: LocalBitWordPairRef<'_>,
    out: &mut RoundKernelCoreBooleanWord,
) -> ProtoResult<()> {
    xor_transformed_local_bit_word_pair_core_into(
        backend.evaluation_key(),
        label,
        word,
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
        out,
    )?;
    Ok(())
}

fn ch_local_bits_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    x: LocalBitWordPairRef<'_>,
    y: LocalBitWordPairRef<'_>,
    z: LocalBitWordPairRef<'_>,
    scratch: &mut RoundCoreBooleanScratch,
) -> ProtoResult<()> {
    if x.len() != y.len() || y.len() != z.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width local words, got {}, {}, and {}",
            x.len(),
            y.len(),
            z.len()
        )));
    }
    let mut yz_label = String::with_capacity(label.len() + 4);
    set_child_label(&mut yz_label, label, "yz");
    xor_split_local_bit_words_into(
        backend.evaluation_key(),
        &yz_label,
        y,
        z,
        &mut scratch.operand0,
    )?;
    scratch.choose.reset();
    eval_mul_local_bit_pair_batch_raw_xor_base_public_into(
        backend.evaluation_key(),
        label,
        x.left.as_raw_view(),
        x.right.as_raw_view(),
        scratch.operand0.left.as_raw_view(),
        scratch.operand0.right.as_raw_view(),
        z.left.as_raw_view(),
        z.right.as_raw_view(),
        |left, right| {
            scratch.choose.left.push_local_word(&left)?;
            scratch.choose.right.push_local_word(&right)?;
            Ok(())
        },
    )?;
    Ok(())
}

fn maj_local_bits_into<B: DdhHssArithmeticBackend>(
    backend: &B,
    label: &str,
    x: LocalBitWordPairRef<'_>,
    y: LocalBitWordPairRef<'_>,
    z: LocalBitWordPairRef<'_>,
    scratch: &mut RoundCoreBooleanScratch,
) -> ProtoResult<()> {
    if x.len() != y.len() || y.len() != z.len() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} requires same-width local words, got {}, {}, and {}",
            x.len(),
            y.len(),
            z.len()
        )));
    }
    scratch.majority.reset();
    eval_maj_local_bit_pair_batch_raw_public_into(
        backend.evaluation_key(),
        label,
        x.left.as_raw_view(),
        x.right.as_raw_view(),
        y.left.as_raw_view(),
        y.right.as_raw_view(),
        z.left.as_raw_view(),
        z.right.as_raw_view(),
        |left, right| {
            scratch.majority.left.push_local_word(&left)?;
            scratch.majority.right.push_local_word(&right)?;
            Ok(())
        },
    )?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        add_five_local_bit_pairs_to_arithmetic_naive, add_words_bits_mod_l,
        arithmetic_word_pair_to_split_local_bits_secure, decode_bits_to_fixed_bytes,
        prepare_ddh_hidden_eval_constant_pool, reduce_scalar_bits_mod_l,
        reduce_scalar_bits_mod_l_with_constants_local, share_input_bits,
        split_local_bit_pair_to_arithmetic_word_pair_naive, SplitLocalBitWord,
    };
    use crate::ddh::HiddenEvalInputOwner;
    use crate::fixtures::deterministic_fixture_corpus;
    use crate::protocol::prepare_prime_order_succinct_hss;
    use crate::shared::{derive_output_shares, reduce_scalar_mod_l};

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
        let arithmetic = split_local_bit_pair_to_arithmetic_word_pair_naive(
            backend,
            "test_phase_a_roundtrip_word/arith",
            word_bits.as_pair_ref(),
        )
        .expect("convert to arithmetic");
        let arithmetic_open = arithmetic
            .left
            .share_word
            .wrapping_add(arithmetic.right.share_word);
        let round_tripped = arithmetic_word_pair_to_split_local_bits_secure(
            backend,
            "test_phase_a_roundtrip_word/bool",
            &arithmetic,
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

        let (sum_arith, _) = add_five_local_bit_pairs_to_arithmetic_naive(
            backend,
            "test_phase_a_five_word_sum",
            words[0].as_pair_ref(),
            words[1].as_pair_ref(),
            words[2].as_pair_ref(),
            words[3].as_pair_ref(),
            words[4].as_pair_ref(),
        )
        .expect("arithmetic five-word sum");
        let sum = arithmetic_word_pair_to_split_local_bits_secure(
            backend,
            "test_phase_a_five_word_sum/bits",
            &sum_arith,
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
        let x_relayer_bits = add_words_bits_mod_l(
            backend,
            "test_output_projection/x_relayer",
            &x_client_bits,
            &tau_bits,
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
