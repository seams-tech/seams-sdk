use std::fmt::Write as _;
#[cfg(feature = "hss-physical-counters")]
use std::sync::atomic::{AtomicU64, Ordering};

use blake3::Hasher as Blake3Hasher;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ddh::hidden_eval::{
    FixedFunctionHssBackend, HiddenEvalInputOwner, HiddenEvalProgram, HssPrimitiveKind,
};
use crate::shared::{ProtoError, ProtoResult};

pub const DDH_HSS_BACKEND_VERSION: &str = "ddh_hss_backend_v0";

#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_DERIVATIONS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_EVAL_XOR_LOCAL_WORD: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_EVAL_ADD_LOCAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL_MATERIAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_SHARE_TO_BOOL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_PHASE_A_BOOL_TO_ARITH_BASE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_TO_BOOL_ZERO: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_COMPOSE_WORD_FROM_SHARE_BITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_SHARE_WORD: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_KEYED_DIGEST_OTHER: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_HASHES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_EVAL_XOR_LOCAL_WORD: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_EVAL_ADD_LOCAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL_MATERIAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_SHARE_TO_BOOL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_PHASE_A_BOOL_TO_ARITH_BASE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_TO_BOOL_ZERO: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_COMPOSE_WORD_FROM_SHARE_BITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_SHARE_WORD: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_DERIVED_COMMITMENT_OTHER: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_ADD_BIT_HASHES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_MUL_MATERIAL_HASHES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "hss-physical-counters")]
static PHYSICAL_MUL_OUTPUT_SEED_HASHES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssPhysicalHashCounters {
    pub keyed_digest_derivations: u64,
    pub keyed_digest_eval_xor_local_word: u64,
    pub keyed_digest_eval_add_local: u64,
    pub keyed_digest_eval_mul_local_material: u64,
    pub keyed_digest_eval_mul_local: u64,
    pub keyed_digest_phase_a_arith_share_to_bool: u64,
    pub keyed_digest_phase_a_bool_to_arith_base: u64,
    pub keyed_digest_phase_a_arith_to_bool_zero: u64,
    pub keyed_digest_compose_word_from_share_bits: u64,
    pub keyed_digest_share_word: u64,
    pub keyed_digest_other: u64,
    pub derived_commitment_hashes: u64,
    pub derived_commitment_eval_xor_local_word: u64,
    pub derived_commitment_eval_add_local: u64,
    pub derived_commitment_eval_mul_local_material: u64,
    pub derived_commitment_eval_mul_local: u64,
    pub derived_commitment_phase_a_arith_share_to_bool: u64,
    pub derived_commitment_phase_a_bool_to_arith_base: u64,
    pub derived_commitment_phase_a_arith_to_bool_zero: u64,
    pub derived_commitment_compose_word_from_share_bits: u64,
    pub derived_commitment_share_word: u64,
    pub derived_commitment_other: u64,
    pub add_bit_hashes: u64,
    pub mul_material_hashes: u64,
    pub mul_output_seed_hashes: u64,
}

#[cfg(feature = "hss-physical-counters")]
pub(crate) fn reset_physical_hash_counters() {
    PHYSICAL_KEYED_DIGEST_DERIVATIONS.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_EVAL_XOR_LOCAL_WORD.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_EVAL_ADD_LOCAL.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL_MATERIAL.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_SHARE_TO_BOOL.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_PHASE_A_BOOL_TO_ARITH_BASE.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_TO_BOOL_ZERO.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_COMPOSE_WORD_FROM_SHARE_BITS.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_SHARE_WORD.store(0, Ordering::Relaxed);
    PHYSICAL_KEYED_DIGEST_OTHER.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_HASHES.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_EVAL_XOR_LOCAL_WORD.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_EVAL_ADD_LOCAL.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL_MATERIAL.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_SHARE_TO_BOOL.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_PHASE_A_BOOL_TO_ARITH_BASE.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_TO_BOOL_ZERO.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_COMPOSE_WORD_FROM_SHARE_BITS.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_SHARE_WORD.store(0, Ordering::Relaxed);
    PHYSICAL_DERIVED_COMMITMENT_OTHER.store(0, Ordering::Relaxed);
    PHYSICAL_ADD_BIT_HASHES.store(0, Ordering::Relaxed);
    PHYSICAL_MUL_MATERIAL_HASHES.store(0, Ordering::Relaxed);
    PHYSICAL_MUL_OUTPUT_SEED_HASHES.store(0, Ordering::Relaxed);
}

#[cfg(not(feature = "hss-physical-counters"))]
pub(crate) fn reset_physical_hash_counters() {}

#[cfg(feature = "hss-physical-counters")]
pub(crate) fn take_physical_hash_counters() -> DdhHssPhysicalHashCounters {
    DdhHssPhysicalHashCounters {
        keyed_digest_derivations: PHYSICAL_KEYED_DIGEST_DERIVATIONS.swap(0, Ordering::Relaxed),
        keyed_digest_eval_xor_local_word: PHYSICAL_KEYED_DIGEST_EVAL_XOR_LOCAL_WORD
            .swap(0, Ordering::Relaxed),
        keyed_digest_eval_add_local: PHYSICAL_KEYED_DIGEST_EVAL_ADD_LOCAL
            .swap(0, Ordering::Relaxed),
        keyed_digest_eval_mul_local_material: PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL_MATERIAL
            .swap(0, Ordering::Relaxed),
        keyed_digest_eval_mul_local: PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL
            .swap(0, Ordering::Relaxed),
        keyed_digest_phase_a_arith_share_to_bool: PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_SHARE_TO_BOOL
            .swap(0, Ordering::Relaxed),
        keyed_digest_phase_a_bool_to_arith_base: PHYSICAL_KEYED_DIGEST_PHASE_A_BOOL_TO_ARITH_BASE
            .swap(0, Ordering::Relaxed),
        keyed_digest_phase_a_arith_to_bool_zero: PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_TO_BOOL_ZERO
            .swap(0, Ordering::Relaxed),
        keyed_digest_compose_word_from_share_bits:
            PHYSICAL_KEYED_DIGEST_COMPOSE_WORD_FROM_SHARE_BITS.swap(0, Ordering::Relaxed),
        keyed_digest_share_word: PHYSICAL_KEYED_DIGEST_SHARE_WORD.swap(0, Ordering::Relaxed),
        keyed_digest_other: PHYSICAL_KEYED_DIGEST_OTHER.swap(0, Ordering::Relaxed),
        derived_commitment_hashes: PHYSICAL_DERIVED_COMMITMENT_HASHES.swap(0, Ordering::Relaxed),
        derived_commitment_eval_xor_local_word: PHYSICAL_DERIVED_COMMITMENT_EVAL_XOR_LOCAL_WORD
            .swap(0, Ordering::Relaxed),
        derived_commitment_eval_add_local: PHYSICAL_DERIVED_COMMITMENT_EVAL_ADD_LOCAL
            .swap(0, Ordering::Relaxed),
        derived_commitment_eval_mul_local_material:
            PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL_MATERIAL.swap(0, Ordering::Relaxed),
        derived_commitment_eval_mul_local: PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL
            .swap(0, Ordering::Relaxed),
        derived_commitment_phase_a_arith_share_to_bool:
            PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_SHARE_TO_BOOL.swap(0, Ordering::Relaxed),
        derived_commitment_phase_a_bool_to_arith_base:
            PHYSICAL_DERIVED_COMMITMENT_PHASE_A_BOOL_TO_ARITH_BASE.swap(0, Ordering::Relaxed),
        derived_commitment_phase_a_arith_to_bool_zero:
            PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_TO_BOOL_ZERO.swap(0, Ordering::Relaxed),
        derived_commitment_compose_word_from_share_bits:
            PHYSICAL_DERIVED_COMMITMENT_COMPOSE_WORD_FROM_SHARE_BITS.swap(0, Ordering::Relaxed),
        derived_commitment_share_word: PHYSICAL_DERIVED_COMMITMENT_SHARE_WORD
            .swap(0, Ordering::Relaxed),
        derived_commitment_other: PHYSICAL_DERIVED_COMMITMENT_OTHER.swap(0, Ordering::Relaxed),
        add_bit_hashes: PHYSICAL_ADD_BIT_HASHES.swap(0, Ordering::Relaxed),
        mul_material_hashes: PHYSICAL_MUL_MATERIAL_HASHES.swap(0, Ordering::Relaxed),
        mul_output_seed_hashes: PHYSICAL_MUL_OUTPUT_SEED_HASHES.swap(0, Ordering::Relaxed),
    }
}

#[cfg(not(feature = "hss-physical-counters"))]
pub(crate) fn take_physical_hash_counters() -> DdhHssPhysicalHashCounters {
    DdhHssPhysicalHashCounters::default()
}

#[cfg(feature = "hss-physical-counters")]
fn record_physical_keyed_digest_derivation(domain: &'static [u8]) {
    PHYSICAL_KEYED_DIGEST_DERIVATIONS.fetch_add(1, Ordering::Relaxed);
    let counter = match domain {
        b"eval-xor-local-word" => &PHYSICAL_KEYED_DIGEST_EVAL_XOR_LOCAL_WORD,
        b"eval-add-local" => &PHYSICAL_KEYED_DIGEST_EVAL_ADD_LOCAL,
        b"eval-mul-local-material" => &PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL_MATERIAL,
        b"eval-mul-local" => &PHYSICAL_KEYED_DIGEST_EVAL_MUL_LOCAL,
        b"phase-a-arith-share-to-bool" => &PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_SHARE_TO_BOOL,
        b"phase-a-bool-to-arith-base" => &PHYSICAL_KEYED_DIGEST_PHASE_A_BOOL_TO_ARITH_BASE,
        b"phase-a-arith-to-bool-zero" => &PHYSICAL_KEYED_DIGEST_PHASE_A_ARITH_TO_BOOL_ZERO,
        b"compose-word-from-share-bits" | b"compose-word-from-share-bits-public" => {
            &PHYSICAL_KEYED_DIGEST_COMPOSE_WORD_FROM_SHARE_BITS
        }
        b"share-left" | b"share-word" | b"share-left-public" | b"share-word-public" => {
            &PHYSICAL_KEYED_DIGEST_SHARE_WORD
        }
        _ => &PHYSICAL_KEYED_DIGEST_OTHER,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "hss-physical-counters"))]
fn record_physical_keyed_digest_derivation(_domain: &'static [u8]) {}

#[cfg(feature = "hss-physical-counters")]
fn record_physical_derived_commitment_hash(domain: &'static [u8]) {
    PHYSICAL_DERIVED_COMMITMENT_HASHES.fetch_add(1, Ordering::Relaxed);
    let counter = match domain {
        b"eval-xor-local-word" => &PHYSICAL_DERIVED_COMMITMENT_EVAL_XOR_LOCAL_WORD,
        b"eval-add-local" => &PHYSICAL_DERIVED_COMMITMENT_EVAL_ADD_LOCAL,
        b"eval-mul-local-material" => &PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL_MATERIAL,
        b"eval-mul-local" => &PHYSICAL_DERIVED_COMMITMENT_EVAL_MUL_LOCAL,
        b"phase-a-arith-share-to-bool" => &PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_SHARE_TO_BOOL,
        b"phase-a-bool-to-arith-base" => &PHYSICAL_DERIVED_COMMITMENT_PHASE_A_BOOL_TO_ARITH_BASE,
        b"phase-a-arith-to-bool-zero" => &PHYSICAL_DERIVED_COMMITMENT_PHASE_A_ARITH_TO_BOOL_ZERO,
        b"compose-word-from-share-bits" | b"compose-word-from-share-bits-public" => {
            &PHYSICAL_DERIVED_COMMITMENT_COMPOSE_WORD_FROM_SHARE_BITS
        }
        b"share-left" | b"share-word" | b"share-left-public" | b"share-word-public" => {
            &PHYSICAL_DERIVED_COMMITMENT_SHARE_WORD
        }
        _ => &PHYSICAL_DERIVED_COMMITMENT_OTHER,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "hss-physical-counters"))]
fn record_physical_derived_commitment_hash(_domain: &'static [u8]) {}

#[cfg(feature = "hss-physical-counters")]
fn record_physical_add_bit_hash() {
    PHYSICAL_ADD_BIT_HASHES.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "hss-physical-counters"))]
fn record_physical_add_bit_hash() {}

#[cfg(feature = "hss-physical-counters")]
fn record_physical_mul_material_hash() {
    PHYSICAL_MUL_MATERIAL_HASHES.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "hss-physical-counters"))]
fn record_physical_mul_material_hash() {}

#[cfg(feature = "hss-physical-counters")]
fn record_physical_mul_output_seed_hash() {
    PHYSICAL_MUL_OUTPUT_SEED_HASHES.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(feature = "hss-physical-counters"))]
fn record_physical_mul_output_seed_hash() {}

fn set_indexed_label(buffer: &mut String, label_prefix: &str, idx: usize) {
    buffer.clear();
    write!(buffer, "{label_prefix}/{idx}").expect("write indexed label");
}

fn set_indexed_child_label(buffer: &mut String, label_prefix: &str, child: &str, idx: usize) {
    buffer.clear();
    write!(buffer, "{label_prefix}/{child}/{idx}").expect("write indexed child label");
}

fn set_child_label(buffer: &mut String, gate_label: &str, child: &str) {
    buffer.clear();
    write!(buffer, "{gate_label}/{child}").expect("write child label");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssParams {
    pub backend_version: String,
    pub scalar_bits: u16,
    pub generator_compressed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssEvaluationKey {
    pub backend_version: String,
    pub primitive_kind: HssPrimitiveKind,
    pub context_binding: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub program_digest: [u8; 32],
    pub key_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssSharedWord {
    pub width_bits: u16,
    pub left_word: u64,
    pub right_word: u64,
    pub left_commitment: [u8; 32],
    pub right_commitment: [u8; 32],
    pub provenance_digest: [u8; 32],
}

// Production schedule/round-core code should prefer narrower executor-local
// value types over this generic joined-share representation. Keep new usage of
// DdhHssSharedWord focused on trusted simulation, bundle transport, and the
// remaining non-kernel execution slices that are still being ported.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DdhHssDerivedWord {
    pub width_bits: u16,
    pub left_word: u64,
    pub right_word: u64,
    pub left_commitment: [u8; 32],
    pub right_commitment: [u8; 32],
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DdhHssLocalWord {
    pub width_bits: u16,
    pub share_side: DdhHssShareSide,
    pub share_word: u64,
    pub share_commitment: [u8; 32],
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DdhHssLocalWordCore {
    pub width_bits: u16,
    pub share_side: DdhHssShareSide,
    pub share_word: u64,
    pub provenance_digest: [u8; 32],
}

impl DdhHssLocalWordCore {
    pub(crate) fn from_local_word(word: &DdhHssLocalWord) -> Self {
        Self {
            width_bits: word.width_bits,
            share_side: word.share_side,
            share_word: word.share_word,
            provenance_digest: word.provenance_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssInputShareBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssSharedWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdhHssShareSide {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssTransportWord {
    pub width_bits: u16,
    pub share_side: DdhHssShareSide,
    pub share_word: u64,
    pub share_commitment: [u8; 32],
    pub counterparty_commitment: [u8; 32],
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssTransportBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub share_side: DdhHssShareSide,
    pub words: Vec<DdhHssTransportWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdhHssTransportPurpose {
    ServerInput,
    ClientOutput,
    ServerOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssMulMaterial {
    pub width_bits: u16,
    pub triple_a: DdhHssSharedWord,
    pub triple_b: DdhHssSharedWord,
    pub triple_c: DdhHssSharedWord,
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DdhHssLocalMulMaterial {
    pub width_bits: u16,
    pub share_side: DdhHssShareSide,
    pub triple_a: DdhHssLocalWord,
    pub triple_b: DdhHssLocalWord,
    pub triple_c: DdhHssLocalWord,
    pub provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DdhHssLocalMulMaterialCore {
    width_bits: u16,
    share_side: DdhHssShareSide,
    triple_a_word: u64,
    triple_b_word: u64,
    triple_c_word: u64,
    provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DdhHssLocalBitSliceView<'a> {
    pub share_side: DdhHssShareSide,
    pub share_blocks: &'a [u64],
    pub bit_len: usize,
    pub commitments: &'a [[u8; 32]],
    pub provenance_digests: &'a [[u8; 32]],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtEncryptedBranch {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtWordOffer {
    pub width_bits: u16,
    pub sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssOtInputBundleOffer {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtWordOffer>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtRemoteWord {
    pub width_bits: u16,
    pub share_word: u64,
    pub share_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtRemoteBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub share_side: DdhHssShareSide,
    pub words: Vec<DdhHssOtRemoteWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtSenderStateWord {
    pub width_bits: u16,
    pub sender_scalar: [u8; 32],
    pub sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssOtSenderStateBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtSenderStateWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DdhHssPreparedOtSenderStateWord {
    sender_scalar: Scalar,
    sender_self_shared_point: EdwardsPoint,
    zero_branch: DdhHssPreparedOtBranch,
    one_branch: DdhHssPreparedOtBranch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtSelectionWord {
    pub width_bits: u16,
    pub receiver_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssOtSelectionBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtSelectionWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtReceiverStateWord {
    pub width_bits: u16,
    pub selected_branch: u8,
    pub shared_point: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdhHssOtReceiverStateBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtReceiverStateWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtSelectionWordCompact {
    receiver_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtSelectionBundleCompact {
    owner: HiddenEvalInputOwner,
    label: String,
    width_bits: u16,
    words: Vec<DdhHssOtSelectionWordCompact>,
    commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtReceiverStateWordCompact {
    selected_branch: u8,
    shared_point: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtReceiverStateBundleCompact {
    owner: HiddenEvalInputOwner,
    label: String,
    width_bits: u16,
    words: Vec<DdhHssOtReceiverStateWordCompact>,
    commitment: [u8; 32],
}

fn uniform_word_width(widths: impl Iterator<Item = u16>, bundle_name: &str) -> Result<u16, String> {
    let mut widths = widths.peekable();
    let Some(width_bits) = widths.peek().copied() else {
        return Ok(0);
    };
    if widths.any(|candidate| candidate != width_bits) {
        return Err(format!(
            "{bundle_name} serialization requires a uniform width_bits across words"
        ));
    }
    Ok(width_bits)
}

impl Serialize for DdhHssOtSelectionBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let width_bits = uniform_word_width(
            self.words.iter().map(|word| word.width_bits),
            "selection bundle",
        )
        .map_err(serde::ser::Error::custom)?;
        DdhHssOtSelectionBundleCompact {
            owner: self.owner,
            label: self.label.clone(),
            width_bits,
            words: self
                .words
                .iter()
                .map(|word| DdhHssOtSelectionWordCompact {
                    receiver_public: word.receiver_public,
                })
                .collect(),
            commitment: self.commitment,
        }
        .serialize(serializer)
    }
}

impl Serialize for DdhHssOtInputBundleOffer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let width_bits = uniform_word_width(
            self.words.iter().map(|word| word.width_bits),
            "input offer bundle",
        )
        .map_err(serde::ser::Error::custom)?;
        DdhHssOtInputBundleOfferCompact {
            owner: self.owner,
            label: self.label.clone(),
            width_bits,
            words: self
                .words
                .iter()
                .map(|word| DdhHssOtWordOfferCompact {
                    sender_public: word.sender_public,
                })
                .collect(),
            commitment: self.commitment,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DdhHssOtInputBundleOffer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compact = DdhHssOtInputBundleOfferCompact::deserialize(deserializer)?;
        Ok(Self {
            owner: compact.owner,
            label: compact.label,
            words: compact
                .words
                .into_iter()
                .map(|word| DdhHssOtWordOffer {
                    width_bits: compact.width_bits,
                    sender_public: word.sender_public,
                })
                .collect(),
            commitment: compact.commitment,
        })
    }
}

impl<'de> Deserialize<'de> for DdhHssOtSelectionBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compact = DdhHssOtSelectionBundleCompact::deserialize(deserializer)?;
        Ok(Self {
            owner: compact.owner,
            label: compact.label,
            words: compact
                .words
                .into_iter()
                .map(|word| DdhHssOtSelectionWord {
                    width_bits: compact.width_bits,
                    receiver_public: word.receiver_public,
                })
                .collect(),
            commitment: compact.commitment,
        })
    }
}

impl Serialize for DdhHssOtSenderStateBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let width_bits = uniform_word_width(
            self.words.iter().map(|word| word.width_bits),
            "sender state bundle",
        )
        .map_err(serde::ser::Error::custom)?;
        DdhHssOtSenderStateBundleCompact {
            owner: self.owner,
            label: self.label.clone(),
            width_bits,
            words: self
                .words
                .iter()
                .map(|word| DdhHssOtSenderStateWordCompact {
                    sender_scalar: word.sender_scalar,
                    sender_public: word.sender_public,
                })
                .collect(),
            commitment: self.commitment,
        }
        .serialize(serializer)
    }
}

impl Serialize for DdhHssOtReceiverStateBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let width_bits = uniform_word_width(
            self.words.iter().map(|word| word.width_bits),
            "receiver state bundle",
        )
        .map_err(serde::ser::Error::custom)?;
        DdhHssOtReceiverStateBundleCompact {
            owner: self.owner,
            label: self.label.clone(),
            width_bits,
            words: self
                .words
                .iter()
                .map(|word| DdhHssOtReceiverStateWordCompact {
                    selected_branch: word.selected_branch,
                    shared_point: word.shared_point,
                })
                .collect(),
            commitment: self.commitment,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DdhHssOtSenderStateBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compact = DdhHssOtSenderStateBundleCompact::deserialize(deserializer)?;
        Ok(Self {
            owner: compact.owner,
            label: compact.label,
            words: compact
                .words
                .into_iter()
                .map(|word| DdhHssOtSenderStateWord {
                    width_bits: compact.width_bits,
                    sender_scalar: word.sender_scalar,
                    sender_public: word.sender_public,
                })
                .collect(),
            commitment: compact.commitment,
        })
    }
}

impl<'de> Deserialize<'de> for DdhHssOtReceiverStateBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compact = DdhHssOtReceiverStateBundleCompact::deserialize(deserializer)?;
        Ok(Self {
            owner: compact.owner,
            label: compact.label,
            words: compact
                .words
                .into_iter()
                .map(|word| DdhHssOtReceiverStateWord {
                    width_bits: compact.width_bits,
                    selected_branch: word.selected_branch,
                    shared_point: word.shared_point,
                })
                .collect(),
            commitment: compact.commitment,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtResponseWord {
    pub width_bits: u16,
    pub zero_branch: DdhHssOtEncryptedBranch,
    pub one_branch: DdhHssOtEncryptedBranch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtResponseBundle {
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub words: Vec<DdhHssOtResponseWord>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssOtReleasedRemoteBundle {
    pub context_binding: [u8; 32],
    pub owner: HiddenEvalInputOwner,
    pub label: String,
    pub share_side: DdhHssShareSide,
    pub words: Vec<DdhHssOtRemoteWord>,
    pub commitment: [u8; 32],
    pub offer_commitment: [u8; 32],
    pub request_commitment: [u8; 32],
    pub response_commitment: [u8; 32],
    pub transcript_binding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssBackend {
    params: DdhHssParams,
    evaluation_key: DdhHssEvaluationKey,
    secret_seed: DdhHssSecretSeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssPublicState {
    params: DdhHssParams,
    evaluation_key: DdhHssEvaluationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssGarbler {
    backend: DdhHssBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssEvaluator {
    public_state: DdhHssPublicState,
    server_input_transport_key: DdhHssTransportKey,
    client_output_transport_key: DdhHssTransportKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DdhHssOtReconstructTiming {
    pub branch_key_derivation_duration_ns: u64,
    pub branch_decrypt_duration_ns: u64,
    pub point_scalar_reconstruction_duration_ns: u64,
    pub commitment_verification_duration_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdhHssRoleSet {
    pub garbler: DdhHssGarbler,
    pub evaluator: DdhHssEvaluator,
}

pub trait DdhHssArithmeticBackend {
    fn evaluation_key(&self) -> &DdhHssEvaluationKey;
    fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord>;
    fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32];
    fn share_input_bit_bundle(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        let mut words = Vec::with_capacity(input.len() * 8);
        for (byte_idx, byte) in input.iter().enumerate() {
            for bit_idx in 0..8 {
                words.push(self.share_word(
                    owner,
                    &format!("{label}/{byte_idx}/{bit_idx}"),
                    u64::from((byte >> bit_idx) & 1),
                    1,
                )?);
            }
        }
        let commitment = self.input_commitment(owner, label, &words);
        Ok(DdhHssInputShareBundle {
            owner,
            label: label.to_string(),
            words,
            commitment,
        })
    }
    fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32];
    fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord>;
    fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial>;
    fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord>;
    fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        if left.width_bits != 1 || right.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "bit multiplication requires 1-bit operands, got {} and {}",
                left.width_bits, right.width_bits
            )));
        }
        let material = self.prepare_mul_material(left, right)?;
        let _ = label;
        self.eval_mul_mod_2_pow_n(left, right, &material)
    }
    fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DdhHssSecretSeed([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DdhHssTransportKey([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtBranchPayload {
    width_bits: u16,
    share_word: u64,
    share_commitment: [u8; 32],
    counterparty_commitment: [u8; 32],
    provenance_digest: [u8; 32],
}

const DDH_HSS_OT_BRANCH_PAYLOAD_BYTES: usize = 2 + 8 + 32 + 32 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DdhHssPreparedOtBranch {
    aad: [u8; 32],
    plaintext: [u8; DDH_HSS_OT_BRANCH_PAYLOAD_BYTES],
    payload_digest: [u8; 32],
}

pub fn keygen_prime_order_ddh_hss_backend(
    context_binding: [u8; 32],
    candidate_digest: [u8; 32],
    program: &HiddenEvalProgram,
) -> ProtoResult<DdhHssBackend> {
    if program.primitive_kind != HssPrimitiveKind::PrimeOrderDdh {
        return Err(ProtoError::InvalidInput(format!(
            "DDH backend requires prime_order_ddh program, got {:?}",
            program.primitive_kind
        )));
    }

    let program_digest = hash_hidden_eval_program(program)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/keygen/v0");
    transcript.append_message(b"context_binding", &context_binding);
    transcript.append_message(b"candidate_digest", &candidate_digest);
    transcript.append_message(b"program_digest", &program_digest);
    transcript.append_message(b"seed", &seed);

    let mut key_id = [0u8; 32];
    transcript.challenge_bytes(b"key_id", &mut key_id);

    Ok(DdhHssBackend {
        params: DdhHssParams {
            backend_version: DDH_HSS_BACKEND_VERSION.to_string(),
            scalar_bits: 252,
            generator_compressed: ED25519_BASEPOINT_POINT.compress().to_bytes(),
        },
        evaluation_key: DdhHssEvaluationKey {
            backend_version: DDH_HSS_BACKEND_VERSION.to_string(),
            primitive_kind: HssPrimitiveKind::PrimeOrderDdh,
            context_binding,
            candidate_digest,
            program_digest,
            key_id,
        },
        secret_seed: DdhHssSecretSeed(seed),
    })
}

pub fn keygen_prime_order_ddh_hss_roles(
    context_binding: [u8; 32],
    candidate_digest: [u8; 32],
    program: &HiddenEvalProgram,
) -> ProtoResult<DdhHssRoleSet> {
    let backend = keygen_prime_order_ddh_hss_backend(context_binding, candidate_digest, program)?;
    Ok(role_views_for_backend(&backend))
}

pub fn role_views_for_backend(backend: &DdhHssBackend) -> DdhHssRoleSet {
    DdhHssRoleSet {
        garbler: DdhHssGarbler {
            backend: backend.clone(),
        },
        evaluator: DdhHssEvaluator {
            public_state: backend.public_state(),
            server_input_transport_key: DdhHssTransportKey(
                backend.transport_key_for_purpose(DdhHssTransportPurpose::ServerInput.as_str()),
            ),
            client_output_transport_key: DdhHssTransportKey(
                backend.transport_key_for_purpose(DdhHssTransportPurpose::ClientOutput.as_str()),
            ),
        },
    }
}

impl DdhHssBackend {
    pub fn params(&self) -> &DdhHssParams {
        &self.params
    }

    pub fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        &self.evaluation_key
    }

    pub fn public_state(&self) -> DdhHssPublicState {
        DdhHssPublicState {
            params: self.params.clone(),
            evaluation_key: self.evaluation_key.clone(),
        }
    }

    pub fn share_input_bundle(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        let words = self.share_input(owner, label, input)?;
        let commitment = self.input_commitment(owner, label, &words);
        Ok(DdhHssInputShareBundle {
            owner,
            label: label.to_string(),
            words,
            commitment,
        })
    }

    pub fn share_input_bit_bundle(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        let mut words = Vec::with_capacity(input.len() * 8);
        for (byte_idx, byte) in input.iter().enumerate() {
            for bit_idx in 0..8 {
                words.push(self.share_word(
                    owner,
                    &format!("{label}/{byte_idx}/{bit_idx}"),
                    u64::from((byte >> bit_idx) & 1),
                    1,
                )?);
            }
        }
        let commitment = self.input_commitment(owner, label, &words);
        Ok(DdhHssInputShareBundle {
            owner,
            label: label.to_string(),
            words,
            commitment,
        })
    }

    pub fn split_share_bundle(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> (DdhHssTransportBundle, DdhHssTransportBundle) {
        let left = DdhHssTransportBundle {
            owner: bundle.owner,
            label: bundle.label.clone(),
            share_side: DdhHssShareSide::Left,
            words: bundle
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
            commitment: bundle.commitment,
        };
        let right = DdhHssTransportBundle {
            owner: bundle.owner,
            label: bundle.label.clone(),
            share_side: DdhHssShareSide::Right,
            words: bundle
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
        };
        (left, right)
    }

    pub fn prepare_client_input_ot_bundle_offer(
        &self,
        label: &str,
        bit_count: usize,
    ) -> ProtoResult<(
        DdhHssOtInputBundleOffer,
        DdhHssOtRemoteBundle,
        DdhHssOtSenderStateBundle,
    )> {
        if bit_count == 0 {
            return Err(ProtoError::InvalidInput(
                "client input OT offer requires at least one bit".to_string(),
            ));
        }

        let mut offer_words = Vec::with_capacity(bit_count);
        let mut remote_words = Vec::with_capacity(bit_count);
        let mut sender_state_words = Vec::with_capacity(bit_count);
        for bit_idx in 0..bit_count {
            let bit_label = format!("{label}/{bit_idx}");
            let mut wide = [0u8; 64];
            OsRng.fill_bytes(&mut wide);
            let sender_scalar = Scalar::from_bytes_mod_order_wide(&wide);
            let sender_public = (ED25519_BASEPOINT_POINT * sender_scalar)
                .compress()
                .to_bytes();
            let right_word = self.derive_masked_word(
                b"client-input-ot/right-share",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                0,
                1,
                &[],
            );
            let zero_left_word = reduce_word(modulus_for_width(1) - u128::from(right_word), 1);
            let one_left_word = reduce_word(
                u128::from(1u8)
                    .wrapping_add(modulus_for_width(1))
                    .wrapping_sub(u128::from(right_word)),
                1,
            );

            let zero_provenance_digest = self.derive_digest(
                b"client-input-ot/zero-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                zero_left_word,
                right_word,
                &[],
            );
            let one_provenance_digest = self.derive_digest(
                b"client-input-ot/one-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                one_left_word,
                right_word,
                &[],
            );

            let _zero_left_commitment = commit_word(
                HiddenEvalInputOwner::Client,
                b"left",
                zero_left_word,
                &zero_provenance_digest,
            );
            let _one_left_commitment = commit_word(
                HiddenEvalInputOwner::Client,
                b"left",
                one_left_word,
                &one_provenance_digest,
            );
            let right_commitment = commit_word(
                HiddenEvalInputOwner::Client,
                b"right",
                right_word,
                &zero_provenance_digest,
            );

            offer_words.push(DdhHssOtWordOffer {
                width_bits: 1,
                sender_public,
            });
            remote_words.push(DdhHssOtRemoteWord {
                width_bits: 1,
                share_word: right_word,
                share_commitment: right_commitment,
            });
            sender_state_words.push(DdhHssOtSenderStateWord {
                width_bits: 1,
                sender_scalar: sender_scalar.to_bytes(),
                sender_public,
            });
        }

        let offer = DdhHssOtInputBundleOffer {
            owner: HiddenEvalInputOwner::Client,
            label: label.to_string(),
            commitment: ot_offer_bundle_commitment(
                HiddenEvalInputOwner::Client,
                label,
                &offer_words,
            ),
            words: offer_words,
        };
        let remote = DdhHssOtRemoteBundle {
            owner: HiddenEvalInputOwner::Client,
            label: label.to_string(),
            share_side: DdhHssShareSide::Right,
            commitment: ot_remote_bundle_commitment(
                HiddenEvalInputOwner::Client,
                label,
                DdhHssShareSide::Right,
                &remote_words,
            ),
            words: remote_words,
        };
        let sender_state = DdhHssOtSenderStateBundle {
            owner: HiddenEvalInputOwner::Client,
            label: label.to_string(),
            commitment: ot_sender_state_bundle_commitment(
                HiddenEvalInputOwner::Client,
                label,
                &sender_state_words,
            ),
            words: sender_state_words,
        };
        Ok((offer, remote, sender_state))
    }

    pub fn prepare_client_input_ot_request(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        input: &[u8],
    ) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
        prepare_client_input_ot_request_public(offer, input)
    }

    pub fn join_share_bundle(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        join_share_bundle_public(&self.evaluation_key, left, right)
    }

    pub fn join_client_ot_bundle(
        &self,
        expected_context_binding: [u8; 32],
        local: &DdhHssTransportBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        if remote.context_binding != expected_context_binding {
            return Err(ProtoError::InvalidInput(
                "client OT remote-share release context binding is invalid".to_string(),
            ));
        }
        if local.owner != HiddenEvalInputOwner::Client
            || remote.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "client OT bundle join requires client-owned bundles".to_string(),
            ));
        }
        if local.label != remote.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT bundle labels do not match: {} vs {}",
                local.label, remote.label
            )));
        }
        if local.share_side != DdhHssShareSide::Left || remote.share_side != DdhHssShareSide::Right
        {
            return Err(ProtoError::InvalidInput(
                "client OT bundles must be joined in left/right order".to_string(),
            ));
        }
        if local.words.len() != remote.words.len() {
            return Err(ProtoError::InvalidInput(format!(
                "client OT bundle word counts do not match: {} vs {}",
                local.words.len(),
                remote.words.len()
            )));
        }
        if local.commitment
            != transport_bundle_commitment(
                local.owner,
                &local.label,
                local.share_side,
                &local.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT local bundle commitment is invalid".to_string(),
            ));
        }
        if remote.commitment
            != ot_remote_bundle_commitment(
                remote.owner,
                &remote.label,
                remote.share_side,
                &remote.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT remote bundle commitment is invalid".to_string(),
            ));
        }
        let expected_remote_binding = ot_remote_release_transcript_binding(
            remote.context_binding,
            remote.owner,
            &remote.label,
            remote.offer_commitment,
            remote.request_commitment,
            remote.response_commitment,
            remote.commitment,
        );
        if remote.transcript_binding != expected_remote_binding {
            return Err(ProtoError::InvalidInput(
                "client OT remote-share release transcript binding is invalid".to_string(),
            ));
        }

        let mut words = Vec::with_capacity(local.words.len());
        for (left_word, right_word) in local.words.iter().zip(&remote.words) {
            if left_word.width_bits != right_word.width_bits {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT word widths do not match: {} vs {}",
                    left_word.width_bits, right_word.width_bits
                )));
            }
            if left_word.counterparty_commitment != right_word.share_commitment {
                return Err(ProtoError::InvalidInput(
                    "client OT counterparty commitment does not match remote share commitment"
                        .to_string(),
                ));
            }
            let expected_left_commitment = commit_word(
                local.owner,
                b"left",
                left_word.share_word,
                &left_word.provenance_digest,
            );
            if left_word.share_commitment != expected_left_commitment {
                return Err(ProtoError::InvalidInput(
                    "client OT left-share commitment is invalid".to_string(),
                ));
            }
            words.push(DdhHssSharedWord {
                width_bits: left_word.width_bits,
                left_word: left_word.share_word,
                right_word: right_word.share_word,
                left_commitment: left_word.share_commitment,
                right_commitment: right_word.share_commitment,
                provenance_digest: left_word.provenance_digest,
            });
        }

        let commitment = self.input_commitment(HiddenEvalInputOwner::Client, &local.label, &words);
        Ok(DdhHssInputShareBundle {
            owner: HiddenEvalInputOwner::Client,
            label: local.label.clone(),
            words,
            commitment,
        })
    }

    pub fn open_client_input_ot_bundle(
        &self,
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
    ) -> ProtoResult<DdhHssTransportBundle> {
        if response.owner != HiddenEvalInputOwner::Client
            || local_state.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "client OT response opening requires client-owned bundles".to_string(),
            ));
        }
        if response.label != local_state.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response label does not match local state: {} vs {}",
                response.label, local_state.label
            )));
        }
        if response.words.len() != local_state.words.len() {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response word count does not match local state: {} vs {}",
                response.words.len(),
                local_state.words.len()
            )));
        }
        if response.commitment
            != ot_response_bundle_commitment(response.owner, &response.label, &response.words)
        {
            return Err(ProtoError::InvalidInput(
                "client OT response commitment is invalid".to_string(),
            ));
        }
        if local_state.commitment
            != ot_receiver_state_bundle_commitment(
                local_state.owner,
                &local_state.label,
                &local_state.words,
            )
        {
            return Err(ProtoError::InvalidInput(
                "client OT local state commitment is invalid".to_string(),
            ));
        }

        let mut local_words = Vec::with_capacity(response.words.len());
        for (bit_idx, (response_word, state_word)) in
            response.words.iter().zip(&local_state.words).enumerate()
        {
            if response_word.width_bits != 1 || state_word.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT response words must be 1-bit at index {bit_idx}"
                )));
            }
            if state_word.selected_branch > 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT local state branch must be 0 or 1 at index {bit_idx}, got {}",
                    state_word.selected_branch
                )));
            }
            let selected_branch = if state_word.selected_branch == 0 {
                &response_word.zero_branch
            } else {
                &response_word.one_branch
            };
            let key = self.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &response.label,
                bit_idx,
                state_word.selected_branch,
                state_word.shared_point,
            );
            let payload = DdhHssBackend::open_ot_branch_with_key(
                key,
                HiddenEvalInputOwner::Client,
                &response.label,
                bit_idx,
                state_word.selected_branch,
                selected_branch,
            )?;
            local_words.push(DdhHssTransportWord {
                width_bits: 1,
                share_side: DdhHssShareSide::Left,
                share_word: payload.share_word,
                share_commitment: payload.share_commitment,
                counterparty_commitment: payload.counterparty_commitment,
                provenance_digest: payload.provenance_digest,
            });
        }

        Ok(DdhHssTransportBundle {
            owner: HiddenEvalInputOwner::Client,
            label: response.label.clone(),
            share_side: DdhHssShareSide::Left,
            commitment: transport_bundle_commitment(
                HiddenEvalInputOwner::Client,
                &response.label,
                DdhHssShareSide::Left,
                &local_words,
            ),
            words: local_words,
        })
    }

    pub fn seal_transport_message(
        &self,
        purpose: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ProtoResult<([u8; 12], Vec<u8>)> {
        let cipher = ChaCha20Poly1305::new(&self.transport_key_for_purpose(purpose).into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to seal DDH transport message for {purpose}: {err}"
                ))
            })?;
        Ok((nonce, ciphertext))
    }

    pub fn open_transport_message(
        &self,
        purpose: &str,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.transport_key_for_purpose(purpose).into());
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to open DDH transport message for {purpose}: {err}"
                ))
            })
    }

    fn seal_ot_branch_with_key(
        key: [u8; 32],
        owner: HiddenEvalInputOwner,
        label: &str,
        bit_idx: usize,
        branch_bit: u8,
        payload: &DdhHssOtBranchPayload,
    ) -> ProtoResult<DdhHssOtEncryptedBranch> {
        let plaintext = encode_ot_branch_payload(payload);
        let aad = ot_branch_aad(owner, label, bit_idx, branch_bit);
        let payload_digest = Sha256::digest(plaintext);
        let mut payload_digest_array = [0u8; 32];
        payload_digest_array.copy_from_slice(&payload_digest);

        let cipher = ChaCha20Poly1305::new(&key.into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to seal OT branch payload for {label}/{bit_idx}/{branch_bit}: {err}"
                ))
            })?;

        Ok(DdhHssOtEncryptedBranch {
            nonce,
            ciphertext,
            payload_digest: payload_digest_array,
        })
    }

    fn seal_prepared_ot_branch_with_key(
        key: [u8; 32],
        prepared: &DdhHssPreparedOtBranch,
    ) -> ProtoResult<DdhHssOtEncryptedBranch> {
        let cipher = ChaCha20Poly1305::new(&key.into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &prepared.plaintext,
                    aad: &prepared.aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!("failed to seal prepared OT branch payload: {err}"))
            })?;
        Ok(DdhHssOtEncryptedBranch {
            nonce,
            ciphertext,
            payload_digest: prepared.payload_digest,
        })
    }

    fn open_ot_branch_with_key(
        key: [u8; 32],
        owner: HiddenEvalInputOwner,
        label: &str,
        bit_idx: usize,
        branch_bit: u8,
        branch: &DdhHssOtEncryptedBranch,
    ) -> ProtoResult<DdhHssOtBranchPayload> {
        let cipher = ChaCha20Poly1305::new(&key.into());
        let aad = ot_branch_aad(owner, label, bit_idx, branch_bit);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&branch.nonce),
                Payload {
                    msg: branch.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|err| {
                ProtoError::Decode(format!(
                    "failed to open OT branch payload for {label}/{bit_idx}/{branch_bit}: {err}"
                ))
            })?;
        let payload_digest = Sha256::digest(&plaintext);
        if payload_digest.as_slice() != branch.payload_digest.as_slice() {
            return Err(ProtoError::Decode(format!(
                "OT branch payload digest mismatch for {label}/{bit_idx}/{branch_bit}"
            )));
        }
        decode_ot_branch_payload(&plaintext).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to decode OT branch payload for {label}/{bit_idx}/{branch_bit}: {err}"
            ))
        })
    }

    pub fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        let mut transcript =
            Transcript::new(b"succinct-garbling-proto/ddh-hss/input-commitment/v0");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"owner", owner_tag(owner));
        transcript.append_message(b"label", label.as_bytes());
        transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
        for word in words {
            transcript.append_message(b"left_commitment", &word.left_commitment);
            transcript.append_message(b"right_commitment", &word.right_commitment);
            transcript.append_message(b"provenance", &word.provenance_digest);
        }
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"input_commitment", &mut out);
        out
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/run-binding/v0");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"artifact_digest", &artifact_digest);
        transcript.append_message(b"context_binding", &self.evaluation_key.context_binding);
        transcript.append_message(b"candidate_digest", &self.evaluation_key.candidate_digest);
        transcript.append_message(b"client_input_commitment", &client_input_commitment);
        transcript.append_message(b"server_input_commitment", &server_input_commitment);
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"run_binding", &mut out);
        out
    }

    pub fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
        hasher.update(self.evaluation_key.key_id);
        match owner {
            HiddenEvalInputOwner::Client => hasher.update(b"client"),
            HiddenEvalInputOwner::Server => hasher.update(b"server"),
            HiddenEvalInputOwner::Derived => hasher.update(b"derived"),
        }
        for bundle in bundles {
            hasher.update(bundle.commitment);
            hasher.update(bundle.label.as_bytes());
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        if !(1..=64).contains(&width_bits) {
            return Err(ProtoError::InvalidInput(format!(
                "shared word width must be in 1..=64 bits, got {width_bits}"
            )));
        }

        let clear_value = reduce_word(u128::from(value), width_bits);
        let left_word = self.derive_masked_word(
            b"share-left",
            owner,
            label.as_bytes(),
            clear_value,
            width_bits,
            &[],
        );
        let right_word = reduce_word(
            u128::from(clear_value)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(left_word)),
            width_bits,
        );

        Ok(self.build_shared_word(
            b"share-word",
            owner,
            label.as_bytes(),
            width_bits,
            left_word,
            right_word,
            &[],
        ))
    }

    pub(crate) fn decode_word(&self, value: &DdhHssSharedWord) -> u64 {
        reduce_word(
            u128::from(value.left_word) + u128::from(value.right_word),
            value.width_bits,
        )
    }

    pub fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if width_bits == 1 {
            return Ok(eval_add_bit_for_key(self.evaluation_key(), left, right));
        }
        let left_word = reduce_word(
            u128::from(left.left_word) + u128::from(right.left_word),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(left.right_word) + u128::from(right.right_word),
            width_bits,
        );
        Ok(self.build_shared_word(
            b"eval-add",
            HiddenEvalInputOwner::Derived,
            b"add",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &right.left_commitment,
            ],
        ))
    }

    pub fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        let triple_a_clear = self.derive_masked_word(
            b"eval-mul/triple-a",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_b_clear = self.derive_masked_word(
            b"eval-mul/triple-b",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_c_clear = reduce_word(
            u128::from(triple_a_clear) * u128::from(triple_b_clear),
            width_bits,
        );
        let triple_a = self.share_word(
            HiddenEvalInputOwner::Derived,
            "mul/triple_a",
            triple_a_clear,
            width_bits,
        )?;
        let triple_b = self.share_word(
            HiddenEvalInputOwner::Derived,
            "mul/triple_b",
            triple_b_clear,
            width_bits,
        )?;
        let triple_c = self.share_word(
            HiddenEvalInputOwner::Derived,
            "mul/triple_c",
            triple_c_clear,
            width_bits,
        )?;
        let provenance_digest = self.derive_digest(
            b"eval-mul-material",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            triple_a_clear,
            triple_b_clear,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &triple_c.provenance_digest,
            ],
        );
        Ok(DdhHssMulMaterial {
            width_bits,
            triple_a,
            triple_b,
            triple_c,
            provenance_digest,
        })
    }

    pub fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if material.width_bits != width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "multiplication material width does not match operands: {} vs {}",
                material.width_bits, width_bits
            )));
        }
        let d_left = reduce_word(
            u128::from(left.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.left_word)),
            width_bits,
        );
        let d_right = reduce_word(
            u128::from(left.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.right_word)),
            width_bits,
        );
        let e_left = reduce_word(
            u128::from(right.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.left_word)),
            width_bits,
        );
        let e_right = reduce_word(
            u128::from(right.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.right_word)),
            width_bits,
        );
        let d_open = reduce_word(u128::from(d_left) + u128::from(d_right), width_bits);
        let e_open = reduce_word(u128::from(e_left) + u128::from(e_right), width_bits);

        let left_word = reduce_word(
            u128::from(material.triple_c.left_word)
                + (u128::from(d_open) * u128::from(material.triple_b.left_word))
                + (u128::from(e_open) * u128::from(material.triple_a.left_word))
                + (u128::from(d_open) * u128::from(e_open)),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(material.triple_c.right_word)
                + (u128::from(d_open) * u128::from(material.triple_b.right_word))
                + (u128::from(e_open) * u128::from(material.triple_a.right_word)),
            width_bits,
        );

        Ok(self.build_shared_word(
            b"eval-mul",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &material.provenance_digest,
            ],
        ))
    }

    pub fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        eval_mul_bit_for_key(self.evaluation_key(), label.as_bytes(), left, right)
    }

    pub fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        if bits.is_empty() || bits.len() > 64 {
            return Err(ProtoError::InvalidInput(format!(
                "bit composition requires 1..=64 bits, got {}",
                bits.len()
            )));
        }

        let mut left_word = 0u64;
        let mut right_word = 0u64;
        let mut extra_material = Vec::with_capacity(bits.len() * 3);
        for (idx, bit) in bits.iter().enumerate() {
            if bit.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "bit composition requires 1-bit words, got {} at index {}",
                    bit.width_bits, idx
                )));
            }
            left_word |= (bit.left_word & 1) << idx;
            right_word |= (bit.right_word & 1) << idx;
            extra_material.push(bit.provenance_digest.as_slice());
            extra_material.push(bit.left_commitment.as_slice());
            extra_material.push(bit.right_commitment.as_slice());
        }

        Ok(self.build_shared_word(
            b"compose-word-from-share-bits",
            owner,
            label.as_bytes(),
            bits.len() as u16,
            left_word,
            right_word,
            &extra_material,
        ))
    }

    fn build_shared_word(
        &self,
        domain: &'static [u8],
        owner: HiddenEvalInputOwner,
        label: &[u8],
        width_bits: u16,
        left_word: u64,
        right_word: u64,
        extra_material: &[&[u8]],
    ) -> DdhHssSharedWord {
        let provenance_digest = self.derive_digest(
            domain,
            owner,
            label,
            width_bits,
            left_word,
            right_word,
            extra_material,
        );
        let left_commitment = commit_word_for_provenance_domain(
            owner,
            b"left",
            left_word,
            &provenance_digest,
            domain,
        );
        let right_commitment = commit_word_for_provenance_domain(
            owner,
            b"right",
            right_word,
            &provenance_digest,
            domain,
        );

        DdhHssSharedWord {
            width_bits,
            left_word,
            right_word,
            left_commitment,
            right_commitment,
            provenance_digest,
        }
    }

    fn derive_masked_word(
        &self,
        domain: &'static [u8],
        owner: HiddenEvalInputOwner,
        label: &[u8],
        clear_value: u64,
        width_bits: u16,
        extra_material: &[&[u8]],
    ) -> u64 {
        let digest = self.derive_digest(
            domain,
            owner,
            label,
            width_bits,
            clear_value,
            0,
            extra_material,
        );
        let sample = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
        reduce_word(u128::from(sample), width_bits)
    }

    fn derive_digest(
        &self,
        domain: &'static [u8],
        owner: HiddenEvalInputOwner,
        label: &[u8],
        width_bits: u16,
        left_word: u64,
        right_word: u64,
        extra_material: &[&[u8]],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(domain);
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"seed", &self.secret_seed.0);
        transcript.append_message(b"label", label);
        transcript.append_message(b"owner", owner_tag(owner));
        transcript.append_message(b"width_bits", &width_bits.to_le_bytes());
        transcript.append_message(b"left_word", &left_word.to_le_bytes());
        transcript.append_message(b"right_word", &right_word.to_le_bytes());
        for material in extra_material {
            transcript.append_message(b"extra", material);
        }
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"digest", &mut out);
        out
    }

    fn transport_key_for_purpose(&self, purpose: &str) -> [u8; 32] {
        let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/transport-key/v0");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"seed", &self.secret_seed.0);
        transcript.append_message(b"purpose", purpose.as_bytes());
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"transport_key", &mut out);
        out
    }

    fn derive_ot_branch_key_from_point(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bit_idx: usize,
        branch_bit: u8,
        shared_point: [u8; 32],
    ) -> [u8; 32] {
        let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-branch-key/v1");
        transcript.append_message(b"key_id", &self.evaluation_key.key_id);
        transcript.append_message(b"owner", owner_tag(owner));
        transcript.append_message(b"label", label.as_bytes());
        transcript.append_message(b"bit_idx", &(bit_idx as u64).to_le_bytes());
        transcript.append_message(b"branch_bit", &[branch_bit]);
        transcript.append_message(b"shared_point", &shared_point);
        let mut out = [0u8; 32];
        transcript.challenge_bytes(b"ot_branch_key", &mut out);
        out
    }
}

impl DdhHssGarbler {
    pub(crate) fn backend(&self) -> &DdhHssBackend {
        &self.backend
    }

    pub fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        self.backend.evaluation_key()
    }

    pub fn share_server_input_bundle(
        &self,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend
            .share_input_bundle(HiddenEvalInputOwner::Server, label, input)
    }

    pub fn share_server_input_bit_bundle(
        &self,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend
            .share_input_bit_bundle(HiddenEvalInputOwner::Server, label, input)
    }

    pub fn split_share_bundle(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> (DdhHssTransportBundle, DdhHssTransportBundle) {
        self.backend.split_share_bundle(bundle)
    }

    pub fn join_share_bundle(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend.join_share_bundle(left, right)
    }

    pub fn prepare_client_input_ot_bundle_offer(
        &self,
        label: &str,
        bit_count: usize,
    ) -> ProtoResult<(
        DdhHssOtInputBundleOffer,
        DdhHssOtRemoteBundle,
        DdhHssOtSenderStateBundle,
    )> {
        self.backend
            .prepare_client_input_ot_bundle_offer(label, bit_count)
    }

    pub fn validate_client_input_ot_bundle_offer(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        sender_state: &DdhHssOtSenderStateBundle,
        remote: &DdhHssOtRemoteBundle,
    ) -> ProtoResult<()> {
        validate_client_ot_offer_preflight(offer, sender_state, remote)?;

        for (bit_idx, ((word_offer, sender_state_word), remote_word)) in offer
            .words
            .iter()
            .zip(&sender_state.words)
            .zip(&remote.words)
            .enumerate()
        {
            if word_offer.width_bits != 1
                || sender_state_word.width_bits != 1
                || remote_word.width_bits != 1
            {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT words must be 1-bit at index {bit_idx}"
                )));
            }
            let sender_public_point = CompressedEdwardsY(word_offer.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT sender public point is invalid at bit index {bit_idx}"
                    ))
                })?;
            if sender_state_word.sender_public != word_offer.sender_public {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT sender-state public point does not match offer at bit index {bit_idx}"
                )));
            }
            let sender_scalar = Scalar::from_bytes_mod_order(sender_state_word.sender_scalar);
            if sender_public_point != (ED25519_BASEPOINT_POINT * sender_scalar) {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT sender-state scalar does not match offer public point at bit index {bit_idx}"
                )));
            }
        }

        Ok(())
    }

    pub fn resolve_client_input_ot_selection(
        &self,
        context_binding: [u8; 32],
        offer: &DdhHssOtInputBundleOffer,
        sender_state: &DdhHssOtSenderStateBundle,
        remote: &DdhHssOtRemoteBundle,
        request: &DdhHssOtSelectionBundle,
    ) -> ProtoResult<(DdhHssOtResponseBundle, DdhHssOtReleasedRemoteBundle)> {
        validate_client_ot_offer_preflight(offer, sender_state, remote)?;
        self.resolve_client_input_ot_selection_trusted(
            context_binding,
            offer,
            sender_state,
            remote,
            request,
        )
    }

    pub(crate) fn resolve_client_input_ot_selection_trusted(
        &self,
        context_binding: [u8; 32],
        offer: &DdhHssOtInputBundleOffer,
        sender_state: &DdhHssOtSenderStateBundle,
        remote: &DdhHssOtRemoteBundle,
        request: &DdhHssOtSelectionBundle,
    ) -> ProtoResult<(DdhHssOtResponseBundle, DdhHssOtReleasedRemoteBundle)> {
        if request.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(
                "client OT request must be client-owned".to_string(),
            ));
        }
        if request.label != offer.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT request label does not match offer: {} vs {}",
                request.label, offer.label
            )));
        }
        if request.words.len() != offer.words.len() {
            return Err(ProtoError::InvalidInput(format!(
                "client OT request word count does not match offer: {} vs {}",
                request.words.len(),
                offer.words.len()
            )));
        }
        if request.commitment
            != ot_request_bundle_commitment(request.owner, &request.label, &request.words)
        {
            return Err(ProtoError::InvalidInput(
                "client OT request commitment is invalid".to_string(),
            ));
        }

        let mut response_words = Vec::with_capacity(request.words.len());
        for (bit_idx, (((request_word, word_offer), sender_state_word), remote_word)) in request
            .words
            .iter()
            .zip(&offer.words)
            .zip(&sender_state.words)
            .zip(&remote.words)
            .enumerate()
        {
            let bit_label = format!("{}/{bit_idx}", offer.label);
            if request_word.width_bits != 1
                || word_offer.width_bits != 1
                || sender_state_word.width_bits != 1
                || remote_word.width_bits != 1
            {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT request words must be 1-bit at index {bit_idx}"
                )));
            }
            let sender_scalar = Scalar::from_bytes_mod_order(sender_state_word.sender_scalar);
            let sender_public_point = CompressedEdwardsY(word_offer.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT sender public point is invalid at bit index {bit_idx}"
                    ))
                })?;
            let receiver_public_point = CompressedEdwardsY(request_word.receiver_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT receiver public point is invalid at bit index {bit_idx}"
                    ))
                })?;

            let zero_left_word = reduce_word(
                modulus_for_width(1).wrapping_sub(u128::from(remote_word.share_word)),
                1,
            );
            let one_left_word = reduce_word(
                u128::from(1u8)
                    .wrapping_add(modulus_for_width(1))
                    .wrapping_sub(u128::from(remote_word.share_word)),
                1,
            );
            let zero_provenance_digest = self.backend.derive_digest(
                b"client-input-ot/zero-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                zero_left_word,
                remote_word.share_word,
                &[],
            );
            let one_provenance_digest = self.backend.derive_digest(
                b"client-input-ot/one-branch",
                HiddenEvalInputOwner::Client,
                bit_label.as_bytes(),
                1,
                one_left_word,
                remote_word.share_word,
                &[],
            );
            let zero_payload = DdhHssOtBranchPayload {
                width_bits: 1,
                share_word: zero_left_word,
                share_commitment: commit_word(
                    HiddenEvalInputOwner::Client,
                    b"left",
                    zero_left_word,
                    &zero_provenance_digest,
                ),
                counterparty_commitment: remote_word.share_commitment,
                provenance_digest: zero_provenance_digest,
            };
            let one_payload = DdhHssOtBranchPayload {
                width_bits: 1,
                share_word: one_left_word,
                share_commitment: commit_word(
                    HiddenEvalInputOwner::Client,
                    b"left",
                    one_left_word,
                    &one_provenance_digest,
                ),
                counterparty_commitment: remote_word.share_commitment,
                provenance_digest: one_provenance_digest,
            };

            let zero_shared = (receiver_public_point * sender_scalar)
                .compress()
                .to_bytes();
            let one_shared = ((receiver_public_point - sender_public_point) * sender_scalar)
                .compress()
                .to_bytes();
            let zero_key = self.backend.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                0,
                zero_shared,
            );
            let one_key = self.backend.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                1,
                one_shared,
            );
            response_words.push(DdhHssOtResponseWord {
                width_bits: 1,
                zero_branch: DdhHssBackend::seal_ot_branch_with_key(
                    zero_key,
                    HiddenEvalInputOwner::Client,
                    &offer.label,
                    bit_idx,
                    0,
                    &zero_payload,
                )?,
                one_branch: DdhHssBackend::seal_ot_branch_with_key(
                    one_key,
                    HiddenEvalInputOwner::Client,
                    &offer.label,
                    bit_idx,
                    1,
                    &one_payload,
                )?,
            });
        }

        let response_commitment = ot_response_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &response_words,
        );
        let response = DdhHssOtResponseBundle {
            owner: HiddenEvalInputOwner::Client,
            label: offer.label.clone(),
            commitment: response_commitment,
            words: response_words,
        };
        let released_remote = DdhHssOtReleasedRemoteBundle {
            context_binding,
            owner: remote.owner,
            label: remote.label.clone(),
            share_side: remote.share_side,
            words: remote.words.clone(),
            commitment: remote.commitment,
            offer_commitment: offer.commitment,
            request_commitment: request.commitment,
            response_commitment,
            transcript_binding: ot_remote_release_transcript_binding(
                context_binding,
                remote.owner,
                &remote.label,
                offer.commitment,
                request.commitment,
                response_commitment,
                remote.commitment,
            ),
        };
        Ok((response, released_remote))
    }

    pub(crate) fn resolve_client_input_ot_selection_trusted_prepared(
        &self,
        context_binding: [u8; 32],
        offer: &DdhHssOtInputBundleOffer,
        prepared_sender_words: &[DdhHssPreparedOtSenderStateWord],
        remote: &DdhHssOtRemoteBundle,
        request: &DdhHssOtSelectionBundle,
    ) -> ProtoResult<(DdhHssOtResponseBundle, DdhHssOtReleasedRemoteBundle)> {
        if request.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(
                "client OT request must be client-owned".to_string(),
            ));
        }
        if request.label != offer.label || remote.label != offer.label {
            return Err(ProtoError::InvalidInput(format!(
                "client OT prepared request label mismatch: request={} offer={} remote={}",
                request.label, offer.label, remote.label
            )));
        }
        if request.words.len() != offer.words.len()
            || request.words.len() != remote.words.len()
            || request.words.len() != prepared_sender_words.len()
        {
            return Err(ProtoError::InvalidInput(format!(
                "client OT prepared word count mismatch: request={} offer={} remote={} prepared={}",
                request.words.len(),
                offer.words.len(),
                remote.words.len(),
                prepared_sender_words.len()
            )));
        }
        if request.commitment
            != ot_request_bundle_commitment(request.owner, &request.label, &request.words)
        {
            return Err(ProtoError::InvalidInput(
                "client OT request commitment is invalid".to_string(),
            ));
        }

        let mut response_words = Vec::with_capacity(request.words.len());
        for (bit_idx, (((request_word, word_offer), prepared_sender_word), remote_word)) in request
            .words
            .iter()
            .zip(&offer.words)
            .zip(prepared_sender_words)
            .zip(&remote.words)
            .enumerate()
        {
            if request_word.width_bits != 1
                || word_offer.width_bits != 1
                || remote_word.width_bits != 1
            {
                return Err(ProtoError::InvalidInput(format!(
                    "client OT prepared request words must be 1-bit at index {bit_idx}"
                )));
            }
            let receiver_public_point = CompressedEdwardsY(request_word.receiver_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "client OT receiver public point is invalid at bit index {bit_idx}"
                    ))
                })?;

            let zero_shared_point = receiver_public_point * prepared_sender_word.sender_scalar;
            let one_shared_point =
                zero_shared_point - prepared_sender_word.sender_self_shared_point;
            let zero_key = self.backend.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                0,
                zero_shared_point.compress().to_bytes(),
            );
            let one_key = self.backend.derive_ot_branch_key_from_point(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                1,
                one_shared_point.compress().to_bytes(),
            );
            response_words.push(DdhHssOtResponseWord {
                width_bits: 1,
                zero_branch: DdhHssBackend::seal_prepared_ot_branch_with_key(
                    zero_key,
                    &prepared_sender_word.zero_branch,
                )?,
                one_branch: DdhHssBackend::seal_prepared_ot_branch_with_key(
                    one_key,
                    &prepared_sender_word.one_branch,
                )?,
            });
        }

        let response_commitment = ot_response_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &response_words,
        );
        let response = DdhHssOtResponseBundle {
            owner: HiddenEvalInputOwner::Client,
            label: offer.label.clone(),
            commitment: response_commitment,
            words: response_words,
        };
        let released_remote = DdhHssOtReleasedRemoteBundle {
            context_binding,
            owner: remote.owner,
            label: remote.label.clone(),
            share_side: remote.share_side,
            words: remote.words.clone(),
            commitment: remote.commitment,
            offer_commitment: offer.commitment,
            request_commitment: request.commitment,
            response_commitment,
            transcript_binding: ot_remote_release_transcript_binding(
                context_binding,
                remote.owner,
                &remote.label,
                offer.commitment,
                request.commitment,
                response_commitment,
                remote.commitment,
            ),
        };
        Ok((response, released_remote))
    }

    pub fn share_derived_bundle(
        &self,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<DdhHssInputShareBundle> {
        self.backend
            .share_input_bundle(HiddenEvalInputOwner::Derived, label, input)
    }

    pub fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        self.backend.combined_input_commitment(owner, bundles)
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        self.backend.run_binding(
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        )
    }

    pub fn seal_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ProtoResult<([u8; 12], Vec<u8>)> {
        if purpose != DdhHssTransportPurpose::ServerInput
            && purpose != DdhHssTransportPurpose::ServerOutput
        {
            return Err(ProtoError::InvalidInput(format!(
                "garbler cannot seal transport purpose {}",
                purpose.as_str()
            )));
        }
        self.backend
            .seal_transport_message(purpose.as_str(), aad, plaintext)
    }

    pub fn open_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        if purpose != DdhHssTransportPurpose::ServerInput
            && purpose != DdhHssTransportPurpose::ServerOutput
        {
            return Err(ProtoError::InvalidInput(format!(
                "garbler cannot open transport purpose {}",
                purpose.as_str()
            )));
        }
        self.backend
            .open_transport_message(purpose.as_str(), aad, nonce, ciphertext)
    }

    pub(crate) fn decode_server_bundle(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<Vec<u8>> {
        if bundle.owner != HiddenEvalInputOwner::Server {
            return Err(ProtoError::InvalidInput(
                "garbler can only decode server-owned bundles".to_string(),
            ));
        }
        self.backend.decode_words(&bundle.words)
    }

    pub(crate) fn decode_server_bit_bundle_array(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<[u8; 32]> {
        if bundle.owner != HiddenEvalInputOwner::Server {
            return Err(ProtoError::InvalidInput(
                "garbler can only decode server-owned bundles".to_string(),
            ));
        }
        decode_bit_bundle_array(&self.backend, bundle)
    }
}

impl DdhHssEvaluator {
    pub fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        &self.public_state.evaluation_key
    }

    pub fn prepare_client_input_ot_request(
        &self,
        offer: &DdhHssOtInputBundleOffer,
        input: &[u8],
    ) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
        prepare_client_input_ot_request_public(offer, input)
    }

    pub fn open_client_input_ot_bundle(
        &self,
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
    ) -> ProtoResult<DdhHssTransportBundle> {
        open_client_input_ot_bundle_public(&self.public_state.evaluation_key, response, local_state)
    }

    pub fn join_client_ot_bundle(
        &self,
        expected_context_binding: [u8; 32],
        local: &DdhHssTransportBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        join_client_ot_bundle_public(
            &self.public_state.evaluation_key,
            expected_context_binding,
            local,
            remote,
        )
    }

    pub fn reconstruct_client_ot_bundle(
        &self,
        expected_context_binding: [u8; 32],
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        Ok(reconstruct_client_ot_bundle_timed_public(
            &self.public_state.evaluation_key,
            expected_context_binding,
            response,
            local_state,
            remote,
        )?
        .0)
    }

    pub(crate) fn reconstruct_client_ot_bundle_timed(
        &self,
        expected_context_binding: [u8; 32],
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<(DdhHssInputShareBundle, DdhHssOtReconstructTiming)> {
        reconstruct_client_ot_bundle_timed_public(
            &self.public_state.evaluation_key,
            expected_context_binding,
            response,
            local_state,
            remote,
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn reconstruct_client_ot_bundle_timed_trusted(
        &self,
        expected_context_binding: [u8; 32],
        response: &DdhHssOtResponseBundle,
        local_state: &DdhHssOtReceiverStateBundle,
        remote: &DdhHssOtReleasedRemoteBundle,
    ) -> ProtoResult<(DdhHssInputShareBundle, DdhHssOtReconstructTiming)> {
        reconstruct_client_ot_bundle_timed_trusted_public(
            &self.public_state.evaluation_key,
            expected_context_binding,
            response,
            local_state,
            remote,
        )
    }

    pub fn join_share_bundle(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<DdhHssInputShareBundle> {
        join_share_bundle_public(&self.public_state.evaluation_key, left, right)
    }

    pub fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        combined_input_commitment_for_key(&self.public_state.evaluation_key, owner, bundles)
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        run_binding_for_key(
            &self.public_state.evaluation_key,
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        )
    }

    pub fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        share_word_for_key(
            &self.public_state.evaluation_key,
            owner,
            label,
            value,
            width_bits,
        )
    }

    pub fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        input_commitment_for_key(&self.public_state.evaluation_key, owner, label, words)
    }

    pub fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if width_bits == 1 {
            return Ok(eval_add_bit_for_key(
                &self.public_state.evaluation_key,
                left,
                right,
            ));
        }
        let left_word = reduce_word(
            u128::from(left.left_word) + u128::from(right.left_word),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(left.right_word) + u128::from(right.right_word),
            width_bits,
        );
        Ok(build_shared_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-add-public",
            HiddenEvalInputOwner::Derived,
            b"add",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &right.left_commitment,
            ],
        ))
    }

    pub fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        let triple_a_clear = derive_masked_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul/triple-a-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_b_clear = derive_masked_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul/triple-b-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            0,
            width_bits,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
            ],
        );
        let triple_c_clear = reduce_word(
            u128::from(triple_a_clear) * u128::from(triple_b_clear),
            width_bits,
        );
        let triple_a = share_word_for_key(
            &self.public_state.evaluation_key,
            HiddenEvalInputOwner::Derived,
            "mul/triple_a",
            triple_a_clear,
            width_bits,
        )?;
        let triple_b = share_word_for_key(
            &self.public_state.evaluation_key,
            HiddenEvalInputOwner::Derived,
            "mul/triple_b",
            triple_b_clear,
            width_bits,
        )?;
        let triple_c = share_word_for_key(
            &self.public_state.evaluation_key,
            HiddenEvalInputOwner::Derived,
            "mul/triple_c",
            triple_c_clear,
            width_bits,
        )?;
        let provenance_digest = derive_digest_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul-material-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            triple_a_clear,
            triple_b_clear,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &triple_c.provenance_digest,
            ],
        );
        Ok(DdhHssMulMaterial {
            width_bits,
            triple_a,
            triple_b,
            triple_c,
            provenance_digest,
        })
    }

    pub fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        ensure_same_width(left, right)?;
        let width_bits = left.width_bits;
        if material.width_bits != width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "multiplication material width does not match operands: {} vs {}",
                material.width_bits, width_bits
            )));
        }
        let d_left = reduce_word(
            u128::from(left.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.left_word)),
            width_bits,
        );
        let d_right = reduce_word(
            u128::from(left.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_a.right_word)),
            width_bits,
        );
        let e_left = reduce_word(
            u128::from(right.left_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.left_word)),
            width_bits,
        );
        let e_right = reduce_word(
            u128::from(right.right_word)
                .wrapping_add(modulus_for_width(width_bits))
                .wrapping_sub(u128::from(material.triple_b.right_word)),
            width_bits,
        );
        let d_open = reduce_word(u128::from(d_left) + u128::from(d_right), width_bits);
        let e_open = reduce_word(u128::from(e_left) + u128::from(e_right), width_bits);

        let left_word = reduce_word(
            u128::from(material.triple_c.left_word)
                + (u128::from(d_open) * u128::from(material.triple_b.left_word))
                + (u128::from(e_open) * u128::from(material.triple_a.left_word))
                + (u128::from(d_open) * u128::from(e_open)),
            width_bits,
        );
        let right_word = reduce_word(
            u128::from(material.triple_c.right_word)
                + (u128::from(d_open) * u128::from(material.triple_b.right_word))
                + (u128::from(e_open) * u128::from(material.triple_a.right_word)),
            width_bits,
        );

        Ok(build_shared_word_for_key(
            &self.public_state.evaluation_key,
            b"eval-mul-public",
            HiddenEvalInputOwner::Derived,
            b"mul",
            width_bits,
            left_word,
            right_word,
            &[
                &left.provenance_digest,
                &right.provenance_digest,
                &left.left_commitment,
                &left.right_commitment,
                &right.left_commitment,
                &right.right_commitment,
                &material.provenance_digest,
            ],
        ))
    }

    pub fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        eval_mul_bit_for_key(
            &self.public_state.evaluation_key,
            label.as_bytes(),
            left,
            right,
        )
    }

    pub fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        if bits.is_empty() || bits.len() > 64 {
            return Err(ProtoError::InvalidInput(format!(
                "bit composition requires 1..=64 bits, got {}",
                bits.len()
            )));
        }

        let mut left_word = 0u64;
        let mut right_word = 0u64;
        let mut extra_material = Vec::with_capacity(bits.len() * 3);
        for (idx, bit) in bits.iter().enumerate() {
            if bit.width_bits != 1 {
                return Err(ProtoError::InvalidInput(format!(
                    "bit composition requires 1-bit words, got {} at index {}",
                    bit.width_bits, idx
                )));
            }
            left_word |= (bit.left_word & 1) << idx;
            right_word |= (bit.right_word & 1) << idx;
            extra_material.push(bit.provenance_digest.as_slice());
            extra_material.push(bit.left_commitment.as_slice());
            extra_material.push(bit.right_commitment.as_slice());
        }

        Ok(build_shared_word_for_key(
            &self.public_state.evaluation_key,
            b"compose-word-from-share-bits-public",
            owner,
            label.as_bytes(),
            bits.len() as u16,
            left_word,
            right_word,
            &extra_material,
        ))
    }

    pub fn seal_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ProtoResult<([u8; 12], Vec<u8>)> {
        if purpose != DdhHssTransportPurpose::ClientOutput {
            return Err(ProtoError::InvalidInput(format!(
                "evaluator cannot seal transport purpose {}",
                purpose.as_str()
            )));
        }
        seal_transport_message_with_key(
            &self.client_output_transport_key,
            purpose.as_str(),
            aad,
            plaintext,
        )
    }

    pub fn open_message(
        &self,
        purpose: DdhHssTransportPurpose,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        let key = match purpose {
            DdhHssTransportPurpose::ServerInput => &self.server_input_transport_key,
            DdhHssTransportPurpose::ClientOutput => &self.client_output_transport_key,
            DdhHssTransportPurpose::ServerOutput => {
                return Err(ProtoError::InvalidInput(format!(
                    "evaluator cannot open transport purpose {}",
                    purpose.as_str()
                )));
            }
        };
        open_transport_message_with_key(key, purpose.as_str(), aad, nonce, ciphertext)
    }

    pub fn server_input_transport_key(&self) -> &[u8; 32] {
        &self.server_input_transport_key.0
    }

    pub fn client_output_transport_key(&self) -> &[u8; 32] {
        &self.client_output_transport_key.0
    }

    pub fn decode_client_bundle(&self, bundle: &DdhHssInputShareBundle) -> ProtoResult<Vec<u8>> {
        if bundle.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(format!(
                "evaluator can only decode client-owned bundles"
            )));
        }
        decode_words_public(&bundle.words)
    }

    pub fn decode_client_bit_bundle_array(
        &self,
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<[u8; 32]> {
        if bundle.owner != HiddenEvalInputOwner::Client {
            return Err(ProtoError::InvalidInput(
                "evaluator can only decode client-owned bundles".to_string(),
            ));
        }
        decode_bit_bundle_array_public(bundle)
    }
}

impl FixedFunctionHssBackend for DdhHssBackend {
    type SharedValue = DdhHssSharedWord;

    fn primitive_kind(&self) -> HssPrimitiveKind {
        HssPrimitiveKind::PrimeOrderDdh
    }

    fn share_input(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<Vec<Self::SharedValue>> {
        input
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                self.share_word(owner, &format!("{label}/{idx}"), u64::from(*value), 8)
            })
            .collect()
    }

    fn eval_add(
        &self,
        left: &Self::SharedValue,
        right: &Self::SharedValue,
    ) -> ProtoResult<Self::SharedValue> {
        self.eval_add_mod_2_pow_n(left, right)
    }

    fn eval_mul(
        &self,
        left: &Self::SharedValue,
        right: &Self::SharedValue,
    ) -> ProtoResult<Self::SharedValue> {
        let material = self.prepare_mul_material(left, right)?;
        self.eval_mul_mod_2_pow_n(left, right, &material)
    }

    fn decode_words(&self, values: &[Self::SharedValue]) -> ProtoResult<Vec<u8>> {
        let mut out = Vec::new();
        for value in values {
            let word = self.decode_word(value);
            let width_bytes = usize::from((value.width_bits + 7) / 8);
            let bytes = word.to_le_bytes();
            out.extend_from_slice(&bytes[..width_bytes]);
        }
        Ok(out)
    }
}

impl DdhHssArithmeticBackend for DdhHssBackend {
    fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        self.evaluation_key()
    }

    fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::share_word(self, owner, label, value, width_bits)
    }

    fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        DdhHssBackend::input_commitment(self, owner, label, words)
    }

    fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        DdhHssBackend::combined_input_commitment(self, owner, bundles)
    }

    fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::eval_add_mod_2_pow_n(self, left, right)
    }

    fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        DdhHssBackend::prepare_mul_material(self, left, right)
    }

    fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::eval_mul_mod_2_pow_n(self, left, right, material)
    }

    fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::eval_mul_bit(self, label, left, right)
    }

    fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssBackend::compose_word_from_share_bits(self, owner, label, bits)
    }
}

impl DdhHssArithmeticBackend for DdhHssEvaluator {
    fn evaluation_key(&self) -> &DdhHssEvaluationKey {
        self.evaluation_key()
    }

    fn share_word(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        value: u64,
        width_bits: u16,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::share_word(self, owner, label, value, width_bits)
    }

    fn input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        words: &[DdhHssSharedWord],
    ) -> [u8; 32] {
        DdhHssEvaluator::input_commitment(self, owner, label, words)
    }

    fn combined_input_commitment(
        &self,
        owner: HiddenEvalInputOwner,
        bundles: &[&DdhHssInputShareBundle],
    ) -> [u8; 32] {
        DdhHssEvaluator::combined_input_commitment(self, owner, bundles)
    }

    fn eval_add_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::eval_add_mod_2_pow_n(self, left, right)
    }

    fn prepare_mul_material(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssMulMaterial> {
        DdhHssEvaluator::prepare_mul_material(self, left, right)
    }

    fn eval_mul_mod_2_pow_n(
        &self,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
        material: &DdhHssMulMaterial,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::eval_mul_mod_2_pow_n(self, left, right, material)
    }

    fn eval_mul_bit(
        &self,
        label: &str,
        left: &DdhHssSharedWord,
        right: &DdhHssSharedWord,
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::eval_mul_bit(self, label, left, right)
    }

    fn compose_word_from_share_bits(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        bits: &[DdhHssSharedWord],
    ) -> ProtoResult<DdhHssSharedWord> {
        DdhHssEvaluator::compose_word_from_share_bits(self, owner, label, bits)
    }
}

impl DdhHssTransportPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            DdhHssTransportPurpose::ServerInput => "server_input",
            DdhHssTransportPurpose::ClientOutput => "client_output",
            DdhHssTransportPurpose::ServerOutput => "server_output",
        }
    }
}

fn hash_hidden_eval_program(program: &HiddenEvalProgram) -> ProtoResult<[u8; 32]> {
    let encoded = bincode::serialize(program).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize hidden-eval program for digest: {err}"
        ))
    })?;
    let digest = Sha256::digest(encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn ensure_same_width(left: &DdhHssSharedWord, right: &DdhHssSharedWord) -> ProtoResult<()> {
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "shared word widths do not match: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    Ok(())
}

fn modulus_for_width(width_bits: u16) -> u128 {
    if width_bits == 64 {
        u128::from(u64::MAX) + 1
    } else {
        1u128 << width_bits
    }
}

fn reduce_word(value: u128, width_bits: u16) -> u64 {
    let masked = if width_bits == 64 {
        value & u128::from(u64::MAX)
    } else {
        value & ((1u128 << width_bits) - 1)
    };
    masked as u64
}

pub(crate) fn commit_word(
    owner: HiddenEvalInputOwner,
    side_label: &'static [u8],
    word: u64,
    provenance_digest: &[u8; 32],
) -> [u8; 32] {
    commit_word_for_provenance_domain(owner, side_label, word, provenance_digest, b"other")
}

fn commit_word_for_provenance_domain(
    owner: HiddenEvalInputOwner,
    side_label: &'static [u8],
    word: u64,
    provenance_digest: &[u8; 32],
    provenance_domain: &'static [u8],
) -> [u8; 32] {
    match owner {
        HiddenEvalInputOwner::Client | HiddenEvalInputOwner::Server => {
            if word == 0 {
                return curve25519_dalek::edwards::EdwardsPoint::identity()
                    .compress()
                    .to_bytes();
            }
            if word == 1 {
                return ED25519_BASEPOINT_POINT.compress().to_bytes();
            }
            (ED25519_BASEPOINT_POINT * Scalar::from(word))
                .compress()
                .to_bytes()
        }
        HiddenEvalInputOwner::Derived => {
            record_physical_derived_commitment_hash(provenance_domain);
            let mut hasher = Blake3Hasher::new();
            hasher.update(b"succinct-garbling-proto/ddh-hss/derived-commitment/v0");
            hasher.update(side_label);
            hasher.update(&word.to_le_bytes());
            hasher.update(provenance_digest);
            *hasher.finalize().as_bytes()
        }
    }
}

fn owner_tag(owner: HiddenEvalInputOwner) -> &'static [u8] {
    match owner {
        HiddenEvalInputOwner::Client => b"client",
        HiddenEvalInputOwner::Server => b"server",
        HiddenEvalInputOwner::Derived => b"derived",
    }
}

fn input_commitment_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssSharedWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/input-commitment/v0");
    transcript.append_message(b"key_id", &evaluation_key.key_id);
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"left_commitment", &word.left_commitment);
        transcript.append_message(b"right_commitment", &word.right_commitment);
        transcript.append_message(b"provenance", &word.provenance_digest);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"input_commitment", &mut out);
    out
}

fn share_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    label: &str,
    value: u64,
    width_bits: u16,
) -> ProtoResult<DdhHssSharedWord> {
    let (left_word, right_word) = split_clear_word_for_key(
        evaluation_key,
        b"share-left-public",
        owner,
        label.as_bytes(),
        value,
        width_bits,
        &[],
    )?;

    Ok(build_shared_word_for_key(
        evaluation_key,
        b"share-word-public",
        owner,
        label.as_bytes(),
        width_bits,
        left_word,
        right_word,
        &[],
    ))
}

fn split_clear_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    value: u64,
    width_bits: u16,
    extra_material: &[&[u8]],
) -> ProtoResult<(u64, u64)> {
    if !(1..=64).contains(&width_bits) {
        return Err(ProtoError::InvalidInput(format!(
            "shared word width must be in 1..=64 bits, got {width_bits}"
        )));
    }

    let clear_value = reduce_word(u128::from(value), width_bits);
    let left_word = derive_masked_word_for_key(
        evaluation_key,
        domain,
        owner,
        label,
        clear_value,
        width_bits,
        extra_material,
    );
    let right_word = reduce_word(
        u128::from(clear_value)
            .wrapping_add(modulus_for_width(width_bits))
            .wrapping_sub(u128::from(left_word)),
        width_bits,
    );
    Ok((left_word, right_word))
}

fn combined_input_commitment_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    bundles: &[&DdhHssInputShareBundle],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
    hasher.update(&evaluation_key.key_id);
    match owner {
        HiddenEvalInputOwner::Client => hasher.update(b"client"),
        HiddenEvalInputOwner::Server => hasher.update(b"server"),
        HiddenEvalInputOwner::Derived => hasher.update(b"derived"),
    }
    for bundle in bundles {
        hasher.update(bundle.commitment);
        hasher.update(bundle.label.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn run_binding_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    artifact_digest: [u8; 32],
    client_input_commitment: [u8; 32],
    server_input_commitment: [u8; 32],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/run-binding/v0");
    transcript.append_message(b"key_id", &evaluation_key.key_id);
    transcript.append_message(b"artifact_digest", &artifact_digest);
    transcript.append_message(b"context_binding", &evaluation_key.context_binding);
    transcript.append_message(b"candidate_digest", &evaluation_key.candidate_digest);
    transcript.append_message(b"client_input_commitment", &client_input_commitment);
    transcript.append_message(b"server_input_commitment", &server_input_commitment);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"run_binding", &mut out);
    out
}

fn derive_digest_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: &[&[u8]],
) -> [u8; 32] {
    derive_digest_for_key_from_extra_material(
        evaluation_key,
        domain,
        owner,
        label,
        width_bits,
        left_word,
        right_word,
        extra_material.iter().copied(),
    )
}

fn derive_digest_for_key_from_extra_material<'a, I>(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: I,
) -> [u8; 32]
where
    I: IntoIterator<Item = &'a [u8]>,
{
    record_physical_keyed_digest_derivation(domain);
    let mut hasher = Blake3Hasher::new();
    hasher.update(domain);
    hasher.update(&evaluation_key.key_id);
    hasher.update(label);
    hasher.update(owner_tag(owner));
    hasher.update(&width_bits.to_le_bytes());
    hasher.update(&left_word.to_le_bytes());
    hasher.update(&right_word.to_le_bytes());
    for material in extra_material {
        hasher.update(&(material.len() as u64).to_le_bytes());
        hasher.update(material);
    }
    *hasher.finalize().as_bytes()
}

fn derive_masked_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    clear_value: u64,
    width_bits: u16,
    extra_material: &[&[u8]],
) -> u64 {
    let digest = derive_digest_for_key(
        evaluation_key,
        domain,
        owner,
        label,
        width_bits,
        clear_value,
        0,
        extra_material,
    );
    let sample = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
    reduce_word(u128::from(sample), width_bits)
}

fn build_shared_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    owner: HiddenEvalInputOwner,
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: &[&[u8]],
) -> DdhHssSharedWord {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        domain,
        owner,
        label,
        width_bits,
        left_word,
        right_word,
        extra_material,
    );
    let left_commitment =
        commit_word_for_provenance_domain(owner, b"left", left_word, &provenance_digest, domain);
    let right_commitment =
        commit_word_for_provenance_domain(owner, b"right", right_word, &provenance_digest, domain);

    DdhHssSharedWord {
        width_bits,
        left_word,
        right_word,
        left_commitment,
        right_commitment,
        provenance_digest,
    }
}

pub(crate) fn build_local_word_pair_public(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: &[&[u8]],
) -> (DdhHssLocalWord, DdhHssLocalWord) {
    build_local_word_pair_public_from_extra_material(
        evaluation_key,
        domain,
        label,
        width_bits,
        left_word,
        right_word,
        extra_material.iter().copied(),
    )
}

pub(crate) fn build_local_word_pair_public_from_extra_material<'a, I>(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    label: &[u8],
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    extra_material: I,
) -> (DdhHssLocalWord, DdhHssLocalWord)
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let provenance_digest = derive_digest_for_key_from_extra_material(
        evaluation_key,
        domain,
        HiddenEvalInputOwner::Derived,
        label,
        width_bits,
        left_word,
        right_word,
        extra_material,
    );
    (
        DdhHssLocalWord {
            width_bits,
            share_side: DdhHssShareSide::Left,
            share_word: left_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"left",
                left_word,
                &provenance_digest,
                domain,
            ),
            provenance_digest,
        },
        DdhHssLocalWord {
            width_bits,
            share_side: DdhHssShareSide::Right,
            share_word: right_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"right",
                right_word,
                &provenance_digest,
                domain,
            ),
            provenance_digest,
        },
    )
}

#[cfg(test)]
fn derived_word_from_shared(value: &DdhHssSharedWord) -> DdhHssDerivedWord {
    DdhHssDerivedWord {
        width_bits: value.width_bits,
        left_word: value.left_word,
        right_word: value.right_word,
        left_commitment: value.left_commitment,
        right_commitment: value.right_commitment,
        provenance_digest: value.provenance_digest,
    }
}

pub(crate) fn local_word_from_shared(
    value: &DdhHssSharedWord,
    share_side: DdhHssShareSide,
) -> DdhHssLocalWord {
    let (share_word, share_commitment) = match share_side {
        DdhHssShareSide::Left => (value.left_word, value.left_commitment),
        DdhHssShareSide::Right => (value.right_word, value.right_commitment),
    };
    DdhHssLocalWord {
        width_bits: value.width_bits,
        share_side,
        share_word,
        share_commitment,
        provenance_digest: value.provenance_digest,
    }
}

#[cfg(test)]
fn local_word_from_derived_public(
    value: &DdhHssDerivedWord,
    share_side: DdhHssShareSide,
) -> ProtoResult<DdhHssLocalWord> {
    if value.width_bits == 0 || value.width_bits > 64 {
        return Err(ProtoError::InvalidInput(format!(
            "local word requires valid width, got {}",
            value.width_bits
        )));
    }
    let (share_word, share_commitment) = match share_side {
        DdhHssShareSide::Left => (value.left_word, value.left_commitment),
        DdhHssShareSide::Right => (value.right_word, value.right_commitment),
    };
    Ok(DdhHssLocalWord {
        width_bits: value.width_bits,
        share_side,
        share_word,
        share_commitment,
        provenance_digest: value.provenance_digest,
    })
}

pub(crate) fn local_word_from_transport_public(
    value: &DdhHssTransportWord,
) -> ProtoResult<DdhHssLocalWord> {
    if value.width_bits == 0 || value.width_bits > 64 {
        return Err(ProtoError::InvalidInput(format!(
            "local transport word requires valid width, got {}",
            value.width_bits
        )));
    }
    Ok(DdhHssLocalWord {
        width_bits: value.width_bits,
        share_side: value.share_side,
        share_word: value.share_word,
        share_commitment: value.share_commitment,
        provenance_digest: value.provenance_digest,
    })
}

#[cfg(test)]
fn shared_word_from_derived(value: &DdhHssDerivedWord) -> DdhHssSharedWord {
    DdhHssSharedWord {
        width_bits: value.width_bits,
        left_word: value.left_word,
        right_word: value.right_word,
        left_commitment: value.left_commitment,
        right_commitment: value.right_commitment,
        provenance_digest: value.provenance_digest,
    }
}

fn build_local_word_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    label: &[u8],
    width_bits: u16,
    share_side: DdhHssShareSide,
    share_word: u64,
    extra_material: &[&[u8]],
) -> DdhHssLocalWord {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        domain,
        HiddenEvalInputOwner::Derived,
        label,
        width_bits,
        0,
        0,
        extra_material,
    );
    build_local_word_from_provenance(
        width_bits,
        share_side,
        share_word,
        provenance_digest,
        domain,
    )
}

fn build_local_word_core_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    domain: &'static [u8],
    label: &[u8],
    width_bits: u16,
    share_side: DdhHssShareSide,
    share_word: u64,
    extra_material: &[&[u8]],
) -> DdhHssLocalWordCore {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        domain,
        HiddenEvalInputOwner::Derived,
        label,
        width_bits,
        0,
        0,
        extra_material,
    );
    local_word_core_from_provenance(width_bits, share_side, share_word, provenance_digest)
}

fn build_local_word_from_provenance(
    width_bits: u16,
    share_side: DdhHssShareSide,
    share_word: u64,
    provenance_digest: [u8; 32],
    provenance_domain: &'static [u8],
) -> DdhHssLocalWord {
    DdhHssLocalWord {
        width_bits,
        share_side,
        share_word,
        share_commitment: commit_word_for_provenance_domain(
            HiddenEvalInputOwner::Derived,
            match share_side {
                DdhHssShareSide::Left => b"left",
                DdhHssShareSide::Right => b"right",
            },
            share_word,
            &provenance_digest,
            provenance_domain,
        ),
        provenance_digest,
    }
}

fn local_word_core_from_provenance(
    width_bits: u16,
    share_side: DdhHssShareSide,
    share_word: u64,
    provenance_digest: [u8; 32],
) -> DdhHssLocalWordCore {
    DdhHssLocalWordCore {
        width_bits,
        share_side,
        share_word,
        provenance_digest,
    }
}

pub(crate) fn materialize_local_word_core(
    core: &DdhHssLocalWordCore,
    provenance_domain: &'static [u8],
) -> DdhHssLocalWord {
    build_local_word_from_provenance(
        core.width_bits,
        core.share_side,
        core.share_word,
        core.provenance_digest,
        provenance_domain,
    )
}

#[cfg(test)]
fn join_local_word_pair_as_derived(
    left: &DdhHssLocalWord,
    right: &DdhHssLocalWord,
) -> ProtoResult<DdhHssDerivedWord> {
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "local join requires left/right share pair".to_string(),
        ));
    }
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local join width mismatch: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    if left.provenance_digest != right.provenance_digest {
        return Err(ProtoError::InvalidInput(
            "local join provenance mismatch".to_string(),
        ));
    }

    Ok(DdhHssDerivedWord {
        width_bits: left.width_bits,
        left_word: left.share_word,
        right_word: right.share_word,
        left_commitment: left.share_commitment,
        right_commitment: right.share_commitment,
        provenance_digest: left.provenance_digest,
    })
}

pub(crate) fn xor_local_bit_from_raw_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    share_side: DdhHssShareSide,
    left_bit: u8,
    left_provenance_digest: &[u8; 32],
    right_bit: u8,
    right_provenance_digest: &[u8; 32],
) -> DdhHssLocalWord {
    build_local_word_for_key(
        evaluation_key,
        b"eval-xor-local-word",
        label,
        1,
        share_side,
        reduce_word(u128::from(left_bit & 1) + u128::from(right_bit & 1), 1),
        &[left_provenance_digest, right_provenance_digest],
    )
}

pub(crate) fn xor_local_bit_core_from_raw_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    share_side: DdhHssShareSide,
    left_bit: u8,
    left_provenance_digest: &[u8; 32],
    right_bit: u8,
    right_provenance_digest: &[u8; 32],
) -> DdhHssLocalWordCore {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        b"eval-xor-local-word",
        HiddenEvalInputOwner::Derived,
        label,
        1,
        0,
        0,
        &[left_provenance_digest, right_provenance_digest],
    );
    local_word_core_from_provenance(
        1,
        share_side,
        reduce_word(u128::from(left_bit & 1) + u128::from(right_bit & 1), 1),
        provenance_digest,
    )
}

pub(crate) fn xor_local_bit_pair_from_raw_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left_bit: u8,
    left_right_bit: u8,
    left_pair_provenance_digest: &[u8; 32],
    right_left_bit: u8,
    right_right_bit: u8,
    right_pair_provenance_digest: &[u8; 32],
) -> (DdhHssLocalWord, DdhHssLocalWord) {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        b"eval-xor-local-word",
        HiddenEvalInputOwner::Derived,
        label,
        1,
        0,
        0,
        &[left_pair_provenance_digest, right_pair_provenance_digest],
    );
    let left_word = u64::from((left_left_bit ^ right_left_bit) & 1);
    let right_word = u64::from((left_right_bit ^ right_right_bit) & 1);
    (
        DdhHssLocalWord {
            width_bits: 1,
            share_side: DdhHssShareSide::Left,
            share_word: left_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"left",
                left_word,
                &provenance_digest,
                b"eval-xor-local-word",
            ),
            provenance_digest,
        },
        DdhHssLocalWord {
            width_bits: 1,
            share_side: DdhHssShareSide::Right,
            share_word: right_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"right",
                right_word,
                &provenance_digest,
                b"eval-xor-local-word",
            ),
            provenance_digest,
        },
    )
}

pub(crate) fn xor_local_bit_pair_core_from_raw_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left_bit: u8,
    left_right_bit: u8,
    left_pair_provenance_digest: &[u8; 32],
    right_left_bit: u8,
    right_right_bit: u8,
    right_pair_provenance_digest: &[u8; 32],
) -> (DdhHssLocalWordCore, DdhHssLocalWordCore) {
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        b"eval-xor-local-word",
        HiddenEvalInputOwner::Derived,
        label,
        1,
        0,
        0,
        &[left_pair_provenance_digest, right_pair_provenance_digest],
    );
    let left_word = u64::from((left_left_bit ^ right_left_bit) & 1);
    let right_word = u64::from((left_right_bit ^ right_right_bit) & 1);
    (
        local_word_core_from_provenance(1, DdhHssShareSide::Left, left_word, provenance_digest),
        local_word_core_from_provenance(1, DdhHssShareSide::Right, right_word, provenance_digest),
    )
}

pub(crate) fn xor_local_word_pairs_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> ProtoResult<(DdhHssLocalWord, DdhHssLocalWord)> {
    ensure_local_word_pair(left_left, left_right)?;
    ensure_local_word_pair(right_left, right_right)?;
    if left_left.width_bits != right_left.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local xor pair width mismatch: {} vs {}",
            left_left.width_bits, right_left.width_bits
        )));
    }

    let width_bits = left_left.width_bits;
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        b"eval-xor-local-word",
        HiddenEvalInputOwner::Derived,
        label,
        width_bits,
        0,
        0,
        &[&left_left.provenance_digest, &right_left.provenance_digest],
    );
    let left_word = reduce_word(
        u128::from(left_left.share_word) + u128::from(right_left.share_word),
        width_bits,
    );
    let right_word = reduce_word(
        u128::from(left_right.share_word) + u128::from(right_right.share_word),
        width_bits,
    );
    Ok((
        DdhHssLocalWord {
            width_bits,
            share_side: DdhHssShareSide::Left,
            share_word: left_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"left",
                left_word,
                &provenance_digest,
                b"eval-xor-local-word",
            ),
            provenance_digest,
        },
        DdhHssLocalWord {
            width_bits,
            share_side: DdhHssShareSide::Right,
            share_word: right_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"right",
                right_word,
                &provenance_digest,
                b"eval-xor-local-word",
            ),
            provenance_digest,
        },
    ))
}

pub(crate) fn xor_local_word_core_pairs_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left: &DdhHssLocalWordCore,
    left_right: &DdhHssLocalWordCore,
    right_left: &DdhHssLocalWordCore,
    right_right: &DdhHssLocalWordCore,
) -> ProtoResult<(DdhHssLocalWordCore, DdhHssLocalWordCore)> {
    ensure_local_word_core_pair(left_left, left_right)?;
    ensure_local_word_core_pair(right_left, right_right)?;
    if left_left.width_bits != right_left.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local xor core pair width mismatch: {} vs {}",
            left_left.width_bits, right_left.width_bits
        )));
    }

    let width_bits = left_left.width_bits;
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        b"eval-xor-local-word",
        HiddenEvalInputOwner::Derived,
        label,
        width_bits,
        0,
        0,
        &[&left_left.provenance_digest, &right_left.provenance_digest],
    );
    let left_word = reduce_word(
        u128::from(left_left.share_word) + u128::from(right_left.share_word),
        width_bits,
    );
    let right_word = reduce_word(
        u128::from(left_right.share_word) + u128::from(right_right.share_word),
        width_bits,
    );
    Ok((
        local_word_core_from_provenance(
            width_bits,
            DdhHssShareSide::Left,
            left_word,
            provenance_digest,
        ),
        local_word_core_from_provenance(
            width_bits,
            DdhHssShareSide::Right,
            right_word,
            provenance_digest,
        ),
    ))
}

pub(crate) fn xor_local_word_core_pairs_materialized_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left: &DdhHssLocalWordCore,
    left_right: &DdhHssLocalWordCore,
    right_left: &DdhHssLocalWordCore,
    right_right: &DdhHssLocalWordCore,
) -> ProtoResult<(DdhHssLocalWord, DdhHssLocalWord)> {
    let (left_core, right_core) = xor_local_word_core_pairs_public(
        evaluation_key,
        label,
        left_left,
        left_right,
        right_left,
        right_right,
    )?;
    Ok((
        materialize_local_word_core(&left_core, b"eval-xor-local-word"),
        materialize_local_word_core(&right_core, b"eval-xor-local-word"),
    ))
}

#[cfg(test)]
pub(crate) fn eval_add_local_mod_2_pow_n_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left: &DdhHssLocalWord,
    right: &DdhHssLocalWord,
) -> ProtoResult<DdhHssLocalWord> {
    if left.share_side != right.share_side {
        return Err(ProtoError::InvalidInput(format!(
            "local add requires same share side, got {:?} and {:?}",
            left.share_side, right.share_side
        )));
    }
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local add width mismatch: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    Ok(build_local_word_for_key(
        evaluation_key,
        b"eval-add-local",
        label,
        left.width_bits,
        left.share_side,
        reduce_word(
            u128::from(left.share_word) + u128::from(right.share_word),
            left.width_bits,
        ),
        &[
            &left.provenance_digest,
            &right.provenance_digest,
            &left.share_commitment,
            &right.share_commitment,
        ],
    ))
}

pub(crate) fn eval_add_local_word_pairs_mod_2_pow_n_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> ProtoResult<(DdhHssLocalWord, DdhHssLocalWord)> {
    ensure_local_word_pair(left_left, left_right)?;
    ensure_local_word_pair(right_left, right_right)?;
    if left_left.width_bits != right_left.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local add pair width mismatch: {} vs {}",
            left_left.width_bits, right_left.width_bits
        )));
    }

    let width_bits = left_left.width_bits;
    let provenance_digest = derive_digest_for_key(
        evaluation_key,
        b"eval-add-local",
        HiddenEvalInputOwner::Derived,
        label,
        width_bits,
        0,
        0,
        &[
            &left_left.provenance_digest,
            &right_left.provenance_digest,
            &left_left.share_commitment,
            &left_right.share_commitment,
            &right_left.share_commitment,
            &right_right.share_commitment,
        ],
    );
    let left_word = reduce_word(
        u128::from(left_left.share_word) + u128::from(right_left.share_word),
        width_bits,
    );
    let right_word = reduce_word(
        u128::from(left_right.share_word) + u128::from(right_right.share_word),
        width_bits,
    );
    Ok((
        DdhHssLocalWord {
            width_bits,
            share_side: DdhHssShareSide::Left,
            share_word: left_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"left",
                left_word,
                &provenance_digest,
                b"eval-add-local",
            ),
            provenance_digest,
        },
        DdhHssLocalWord {
            width_bits,
            share_side: DdhHssShareSide::Right,
            share_word: right_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"right",
                right_word,
                &provenance_digest,
                b"eval-add-local",
            ),
            provenance_digest,
        },
    ))
}

pub(crate) fn open_local_word_pair_public(
    left: &DdhHssLocalWord,
    right: &DdhHssLocalWord,
) -> ProtoResult<u64> {
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "local open requires left/right share pair".to_string(),
        ));
    }
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local open width mismatch: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    Ok(reduce_word(
        u128::from(left.share_word) + u128::from(right.share_word),
        left.width_bits,
    ))
}

fn ensure_local_word_pair(left: &DdhHssLocalWord, right: &DdhHssLocalWord) -> ProtoResult<()> {
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "local pair requires left/right share pair".to_string(),
        ));
    }
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local pair width mismatch: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    if left.provenance_digest != right.provenance_digest {
        return Err(ProtoError::InvalidInput(
            "local pair provenance mismatch".to_string(),
        ));
    }
    Ok(())
}

fn ensure_local_word_core_pair(
    left: &DdhHssLocalWordCore,
    right: &DdhHssLocalWordCore,
) -> ProtoResult<()> {
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "local core pair requires left/right share pair".to_string(),
        ));
    }
    if left.width_bits != right.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "local core pair width mismatch: {} vs {}",
            left.width_bits, right.width_bits
        )));
    }
    if left.provenance_digest != right.provenance_digest {
        return Err(ProtoError::InvalidInput(
            "local core pair provenance mismatch".to_string(),
        ));
    }
    Ok(())
}

fn local_bit_mul_material_base_hasher(evaluation_key: &DdhHssEvaluationKey) -> Blake3Hasher {
    let mut material_hasher = Blake3Hasher::new();
    material_hasher.update(b"succinct-garbling-proto/ddh-hss/eval-mul-bit/v1");
    material_hasher.update(&evaluation_key.key_id);
    material_hasher.update(owner_tag(HiddenEvalInputOwner::Derived));
    material_hasher.update(&1u16.to_le_bytes());
    material_hasher
}

fn local_bit_slice_view_ensure_shape(view: DdhHssLocalBitSliceView<'_>) -> ProtoResult<()> {
    if view.commitments.len() != view.bit_len || view.provenance_digests.len() != view.bit_len {
        return Err(ProtoError::InvalidInput(
            "raw local bit slice lengths are inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn local_bit_slice_view_share_bit(view: DdhHssLocalBitSliceView<'_>, idx: usize) -> u8 {
    let block = idx / 64;
    let bit = idx % 64;
    ((view.share_blocks[block] >> bit) & 1) as u8
}

fn finalize_local_bit_mul_material_digest(
    material_hasher_base: &Blake3Hasher,
    gate_key: &[u8],
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> [u8; 32] {
    let mut material_hasher = material_hasher_base.clone();
    material_hasher.update(gate_key);
    material_hasher.update(&left_left.provenance_digest);
    material_hasher.update(&right_left.provenance_digest);
    material_hasher.update(&left_left.share_commitment);
    material_hasher.update(&left_right.share_commitment);
    material_hasher.update(&right_left.share_commitment);
    material_hasher.update(&right_right.share_commitment);
    record_physical_mul_material_hash();
    *material_hasher.finalize().as_bytes()
}

fn local_bit_mul_material_from_digest(
    evaluation_key: &DdhHssEvaluationKey,
    left_left: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    material_digest: [u8; 32],
) -> (DdhHssLocalMulMaterial, DdhHssLocalMulMaterial) {
    local_bit_mul_material_from_raw_digest(
        evaluation_key,
        &left_left.provenance_digest,
        &right_left.provenance_digest,
        material_digest,
    )
}

fn local_bit_mul_material_from_raw_digest(
    evaluation_key: &DdhHssEvaluationKey,
    left_provenance_digest: &[u8; 32],
    right_provenance_digest: &[u8; 32],
    material_digest: [u8; 32],
) -> (DdhHssLocalMulMaterial, DdhHssLocalMulMaterial) {
    let triple_a_clear = u64::from(material_digest[0] & 1);
    let triple_b_clear = u64::from(material_digest[1] & 1);
    let triple_a_left = u64::from(material_digest[2] & 1);
    let triple_b_left = u64::from(material_digest[3] & 1);
    let triple_c_left = u64::from(material_digest[4] & 1);
    let triple_a_right = triple_a_clear ^ triple_a_left;
    let triple_b_right = triple_b_clear ^ triple_b_left;
    let triple_c_clear = triple_a_clear & triple_b_clear;
    let triple_c_right = triple_c_clear ^ triple_c_left;
    let triple_a_provenance = derive_digest_for_key(
        evaluation_key,
        b"eval-mul-local-material",
        HiddenEvalInputOwner::Derived,
        b"triple-a",
        1,
        0,
        0,
        &[
            left_provenance_digest,
            right_provenance_digest,
            &material_digest,
        ],
    );
    let triple_b_provenance = derive_digest_for_key(
        evaluation_key,
        b"eval-mul-local-material",
        HiddenEvalInputOwner::Derived,
        b"triple-b",
        1,
        0,
        0,
        &[
            left_provenance_digest,
            right_provenance_digest,
            &material_digest,
        ],
    );
    let triple_c_provenance = derive_digest_for_key(
        evaluation_key,
        b"eval-mul-local-material",
        HiddenEvalInputOwner::Derived,
        b"triple-c",
        1,
        0,
        0,
        &[
            left_provenance_digest,
            right_provenance_digest,
            &material_digest,
        ],
    );

    let build_side = |share_side: DdhHssShareSide,
                      triple_a_share: u64,
                      triple_b_share: u64,
                      triple_c_share: u64|
     -> DdhHssLocalMulMaterial {
        DdhHssLocalMulMaterial {
            width_bits: 1,
            share_side,
            triple_a: build_local_word_from_provenance(
                1,
                share_side,
                triple_a_share,
                triple_a_provenance,
                b"eval-mul-local-material",
            ),
            triple_b: build_local_word_from_provenance(
                1,
                share_side,
                triple_b_share,
                triple_b_provenance,
                b"eval-mul-local-material",
            ),
            triple_c: build_local_word_from_provenance(
                1,
                share_side,
                triple_c_share,
                triple_c_provenance,
                b"eval-mul-local-material",
            ),
            provenance_digest: material_digest,
        }
    };

    (
        build_side(
            DdhHssShareSide::Left,
            triple_a_left,
            triple_b_left,
            triple_c_left,
        ),
        build_side(
            DdhHssShareSide::Right,
            triple_a_right,
            triple_b_right,
            triple_c_right,
        ),
    )
}

fn local_bit_mul_material_core_from_raw_digest(
    material_digest: [u8; 32],
) -> (DdhHssLocalMulMaterialCore, DdhHssLocalMulMaterialCore) {
    let triple_a_clear = u64::from(material_digest[0] & 1);
    let triple_b_clear = u64::from(material_digest[1] & 1);
    let triple_a_left = u64::from(material_digest[2] & 1);
    let triple_b_left = u64::from(material_digest[3] & 1);
    let triple_c_left = u64::from(material_digest[4] & 1);
    let triple_a_right = triple_a_clear ^ triple_a_left;
    let triple_b_right = triple_b_clear ^ triple_b_left;
    let triple_c_clear = triple_a_clear & triple_b_clear;
    let triple_c_right = triple_c_clear ^ triple_c_left;
    let build_side = |share_side: DdhHssShareSide,
                      triple_a_word: u64,
                      triple_b_word: u64,
                      triple_c_word: u64|
     -> DdhHssLocalMulMaterialCore {
        DdhHssLocalMulMaterialCore {
            width_bits: 1,
            share_side,
            triple_a_word,
            triple_b_word,
            triple_c_word,
            provenance_digest: material_digest,
        }
    };
    (
        build_side(
            DdhHssShareSide::Left,
            triple_a_left,
            triple_b_left,
            triple_c_left,
        ),
        build_side(
            DdhHssShareSide::Right,
            triple_a_right,
            triple_b_right,
            triple_c_right,
        ),
    )
}

#[cfg(test)]
fn prepare_local_bit_mul_material_public(
    evaluation_key: &DdhHssEvaluationKey,
    gate_key: &[u8],
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> ProtoResult<(DdhHssLocalMulMaterial, DdhHssLocalMulMaterial)> {
    ensure_local_word_pair(left_left, left_right)?;
    ensure_local_word_pair(right_left, right_right)?;
    if left_left.width_bits != right_left.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "bit multiplication requires same width, got {} and {}",
            left_left.width_bits, right_left.width_bits
        )));
    }
    if left_left.width_bits != 1 {
        return Err(ProtoError::InvalidInput(format!(
            "bit multiplication requires width 1, got {}",
            left_left.width_bits
        )));
    }

    let material_digest = finalize_local_bit_mul_material_digest(
        &local_bit_mul_material_base_hasher(evaluation_key),
        gate_key,
        left_left,
        left_right,
        right_left,
        right_right,
    );
    Ok(local_bit_mul_material_from_digest(
        evaluation_key,
        left_left,
        right_left,
        material_digest,
    ))
}

pub(crate) fn eval_mul_local_word_pair_batch_public(
    evaluation_key: &DdhHssEvaluationKey,
    label_prefix: &str,
    left_left_words: &[DdhHssLocalWord],
    left_right_words: &[DdhHssLocalWord],
    right_left_words: &[DdhHssLocalWord],
    right_right_words: &[DdhHssLocalWord],
) -> ProtoResult<(Vec<DdhHssLocalWord>, Vec<DdhHssLocalWord>)> {
    let len = left_left_words.len();
    if left_right_words.len() != len
        || right_left_words.len() != len
        || right_right_words.len() != len
    {
        return Err(ProtoError::InvalidInput(
            "local mul batch lengths are inconsistent".to_string(),
        ));
    }
    let material_hasher_base = local_bit_mul_material_base_hasher(evaluation_key);
    let mut out_left = Vec::with_capacity(len);
    let mut out_right = Vec::with_capacity(len);
    let mut gate_label = String::with_capacity(label_prefix.len() + 24);
    let mut child_label = String::with_capacity(label_prefix.len() + 26);
    for idx in 0..len {
        let left_left = &left_left_words[idx];
        let left_right = &left_right_words[idx];
        let right_left = &right_left_words[idx];
        let right_right = &right_right_words[idx];
        ensure_local_word_pair(left_left, left_right)?;
        ensure_local_word_pair(right_left, right_right)?;
        if left_left.width_bits != 1
            || right_left.width_bits != 1
            || left_left.width_bits != right_left.width_bits
        {
            return Err(ProtoError::InvalidInput(
                "local mul batch requires width-1 aligned operands".to_string(),
            ));
        }

        set_indexed_label(&mut gate_label, label_prefix, idx);
        let material_digest = finalize_local_bit_mul_material_digest(
            &material_hasher_base,
            gate_label.as_bytes(),
            left_left,
            left_right,
            right_left,
            right_right,
        );
        let (material_left, material_right) = local_bit_mul_material_from_digest(
            evaluation_key,
            left_left,
            right_left,
            material_digest,
        );
        set_child_label(&mut child_label, &gate_label, "d");
        let (d_left, d_right) = eval_add_local_word_pairs_mod_2_pow_n_public(
            evaluation_key,
            child_label.as_bytes(),
            left_left,
            left_right,
            &material_left.triple_a,
            &material_right.triple_a,
        )?;
        set_child_label(&mut child_label, &gate_label, "e");
        let (e_left, e_right) = eval_add_local_word_pairs_mod_2_pow_n_public(
            evaluation_key,
            child_label.as_bytes(),
            right_left,
            right_right,
            &material_left.triple_b,
            &material_right.triple_b,
        )?;
        let d_open = open_local_word_pair_public(&d_left, &d_right)?;
        let e_open = open_local_word_pair_public(&e_left, &e_right)?;
        out_left.push(eval_mul_local_with_open_public(
            evaluation_key,
            gate_label.as_bytes(),
            left_left,
            right_left,
            &material_left,
            d_open,
            e_open,
        )?);
        out_right.push(eval_mul_local_with_open_public(
            evaluation_key,
            gate_label.as_bytes(),
            left_right,
            right_right,
            &material_right,
            d_open,
            e_open,
        )?);
    }
    Ok((out_left, out_right))
}

fn eval_mul_local_bit_pair_batch_raw_public_into<F>(
    evaluation_key: &DdhHssEvaluationKey,
    label_prefix: &str,
    left_left: DdhHssLocalBitSliceView<'_>,
    left_right: DdhHssLocalBitSliceView<'_>,
    right_left: DdhHssLocalBitSliceView<'_>,
    right_right: DdhHssLocalBitSliceView<'_>,
    mut push_pair: F,
) -> ProtoResult<()>
where
    F: FnMut(DdhHssLocalWord, DdhHssLocalWord) -> ProtoResult<()>,
{
    local_bit_slice_view_ensure_shape(left_left)?;
    local_bit_slice_view_ensure_shape(left_right)?;
    local_bit_slice_view_ensure_shape(right_left)?;
    local_bit_slice_view_ensure_shape(right_right)?;
    let len = left_left.bit_len;
    if left_right.bit_len != len || right_left.bit_len != len || right_right.bit_len != len {
        return Err(ProtoError::InvalidInput(
            "raw local mul batch lengths are inconsistent".to_string(),
        ));
    }
    if left_left.share_side != DdhHssShareSide::Left
        || right_left.share_side != DdhHssShareSide::Left
        || left_right.share_side != DdhHssShareSide::Right
        || right_right.share_side != DdhHssShareSide::Right
    {
        return Err(ProtoError::InvalidInput(
            "raw local mul batch requires aligned left/right slice pairs".to_string(),
        ));
    }

    let material_hasher_base = local_bit_mul_material_base_hasher(evaluation_key);
    let mut gate_label = String::with_capacity(label_prefix.len() + 24);
    for idx in 0..len {
        set_indexed_label(&mut gate_label, label_prefix, idx);
        let material_digest = {
            let mut material_hasher = material_hasher_base.clone();
            material_hasher.update(gate_label.as_bytes());
            material_hasher.update(&left_left.provenance_digests[idx]);
            material_hasher.update(&right_left.provenance_digests[idx]);
            material_hasher.update(&left_left.commitments[idx]);
            material_hasher.update(&left_right.commitments[idx]);
            material_hasher.update(&right_left.commitments[idx]);
            material_hasher.update(&right_right.commitments[idx]);
            record_physical_mul_material_hash();
            *material_hasher.finalize().as_bytes()
        };
        let (material_left, material_right) = local_bit_mul_material_from_raw_digest(
            evaluation_key,
            &left_left.provenance_digests[idx],
            &right_left.provenance_digests[idx],
            material_digest,
        );
        let d_open = reduce_word(
            u128::from(local_bit_slice_view_share_bit(left_left, idx))
                + u128::from(material_left.triple_a.share_word)
                + u128::from(local_bit_slice_view_share_bit(left_right, idx))
                + u128::from(material_right.triple_a.share_word),
            1,
        );
        let e_open = reduce_word(
            u128::from(local_bit_slice_view_share_bit(right_left, idx))
                + u128::from(material_left.triple_b.share_word)
                + u128::from(local_bit_slice_view_share_bit(right_right, idx))
                + u128::from(material_right.triple_b.share_word),
            1,
        );
        let d_open_bytes = d_open.to_le_bytes();
        let e_open_bytes = e_open.to_le_bytes();
        let output_provenance = derive_digest_for_key(
            evaluation_key,
            b"eval-mul-local",
            HiddenEvalInputOwner::Derived,
            gate_label.as_bytes(),
            1,
            0,
            0,
            &[
                &left_left.provenance_digests[idx],
                &right_left.provenance_digests[idx],
                &material_digest,
                &d_open_bytes,
                &e_open_bytes,
            ],
        );
        let out_left = build_local_word_from_provenance(
            1,
            DdhHssShareSide::Left,
            reduce_word(
                u128::from(material_left.triple_c.share_word)
                    + (u128::from(d_open) * u128::from(material_left.triple_b.share_word))
                    + (u128::from(e_open) * u128::from(material_left.triple_a.share_word))
                    + (u128::from(d_open) * u128::from(e_open)),
                1,
            ),
            output_provenance,
            b"eval-mul-local",
        );
        let out_right = build_local_word_from_provenance(
            1,
            DdhHssShareSide::Right,
            reduce_word(
                u128::from(material_right.triple_c.share_word)
                    + (u128::from(d_open) * u128::from(material_right.triple_b.share_word))
                    + (u128::from(e_open) * u128::from(material_right.triple_a.share_word)),
                1,
            ),
            output_provenance,
            b"eval-mul-local",
        );
        push_pair(out_left, out_right)?;
    }
    Ok(())
}

pub(crate) fn eval_add_cross_share_local_arithmetic_word_bits_secure_public_into<F>(
    evaluation_key: &DdhHssEvaluationKey,
    label_prefix: &str,
    left_word: &DdhHssLocalWord,
    right_word: &DdhHssLocalWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
    mut push_bit_pair: F,
) -> ProtoResult<()>
where
    F: FnMut(DdhHssLocalWord, DdhHssLocalWord) -> ProtoResult<()>,
{
    let width = validate_cross_share_a2b_inputs(left_word, right_word, zero_left, zero_right)?;
    let mut carry_left = DdhHssLocalWordCore::from_local_word(zero_left);
    let mut carry_right = DdhHssLocalWordCore::from_local_word(zero_right);
    let mut bit_label = String::with_capacity(label_prefix.len() + 32);
    for idx in 0..width {
        let left_bit = (left_word.share_word >> idx) & 1;
        let right_bit = (right_word.share_word >> idx) & 1;
        set_indexed_child_label(&mut bit_label, label_prefix, "left", idx);
        let left_bit_word = build_local_word_core_for_key(
            evaluation_key,
            b"phase-a-arith-share-to-bool",
            bit_label.as_bytes(),
            1,
            DdhHssShareSide::Left,
            left_bit,
            &[
                &left_word.provenance_digest,
                &left_word.share_commitment,
                b"left",
            ],
        );
        set_indexed_child_label(&mut bit_label, label_prefix, "right", idx);
        let right_bit_word = build_local_word_core_for_key(
            evaluation_key,
            b"phase-a-arith-share-to-bool",
            bit_label.as_bytes(),
            1,
            DdhHssShareSide::Right,
            right_bit,
            &[
                &right_word.provenance_digest,
                &right_word.share_commitment,
                b"right",
            ],
        );
        set_indexed_child_label(&mut bit_label, label_prefix, "xor_ab", idx);
        let (xor_ab_left, xor_ab_right) = xor_local_bit_pair_from_raw_public(
            evaluation_key,
            bit_label.as_bytes(),
            (left_bit_word.share_word as u8) & 1,
            0,
            &left_bit_word.provenance_digest,
            0,
            (right_bit_word.share_word as u8) & 1,
            &right_bit_word.provenance_digest,
        );
        set_indexed_child_label(&mut bit_label, label_prefix, "sum", idx);
        let (sum_left, sum_right) = xor_local_bit_pair_from_raw_public(
            evaluation_key,
            bit_label.as_bytes(),
            (xor_ab_left.share_word as u8) & 1,
            (xor_ab_right.share_word as u8) & 1,
            &xor_ab_left.provenance_digest,
            (carry_left.share_word as u8) & 1,
            (carry_right.share_word as u8) & 1,
            &carry_left.provenance_digest,
        );
        set_indexed_child_label(&mut bit_label, label_prefix, "a_xor_carry", idx);
        let (a_xor_carry_left, a_xor_carry_right) = xor_local_bit_pair_from_raw_public(
            evaluation_key,
            bit_label.as_bytes(),
            (left_bit_word.share_word as u8) & 1,
            0,
            &left_bit_word.provenance_digest,
            (carry_left.share_word as u8) & 1,
            (carry_right.share_word as u8) & 1,
            &carry_left.provenance_digest,
        );
        set_indexed_child_label(&mut bit_label, label_prefix, "carry", idx);
        let (carry_gate_left, carry_gate_right) = eval_mul_local_word_pairs_core_public(
            evaluation_key,
            bit_label.as_bytes(),
            &xor_ab_left,
            &xor_ab_right,
            &a_xor_carry_left,
            &a_xor_carry_right,
        )?;
        set_indexed_child_label(&mut bit_label, label_prefix, "next_carry", idx);
        let left_zero_right = local_word_core_from_provenance(
            1,
            DdhHssShareSide::Right,
            0,
            left_bit_word.provenance_digest,
        );
        (carry_left, carry_right) = xor_local_word_core_pairs_public(
            evaluation_key,
            bit_label.as_bytes(),
            &left_bit_word,
            &left_zero_right,
            &carry_gate_left,
            &carry_gate_right,
        )?;
        push_bit_pair(sum_left, sum_right)?;
    }
    Ok(())
}

fn validate_cross_share_a2b_inputs(
    left_word: &DdhHssLocalWord,
    right_word: &DdhHssLocalWord,
    zero_left: &DdhHssLocalWord,
    zero_right: &DdhHssLocalWord,
) -> ProtoResult<usize> {
    if left_word.share_side != DdhHssShareSide::Left
        || right_word.share_side != DdhHssShareSide::Right
    {
        return Err(ProtoError::InvalidInput(
            "secure arithmetic-word A2B requires aligned left/right arithmetic shares".to_string(),
        ));
    }
    if left_word.width_bits != right_word.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "secure arithmetic-word A2B requires same width, got {} and {}",
            left_word.width_bits, right_word.width_bits
        )));
    }
    if zero_left.share_side != DdhHssShareSide::Left
        || zero_right.share_side != DdhHssShareSide::Right
        || zero_left.width_bits != 1
        || zero_right.width_bits != 1
    {
        return Err(ProtoError::InvalidInput(
            "secure arithmetic-word A2B requires width-1 zero left/right pair".to_string(),
        ));
    }
    let width = usize::from(left_word.width_bits);
    if width == 0 || width > 64 {
        return Err(ProtoError::InvalidInput(format!(
            "secure arithmetic-word A2B requires width 1..=64, got {}",
            width
        )));
    }
    Ok(width)
}

pub(crate) fn eval_mul_local_bit_pair_batch_raw_xor_base_public_into<F>(
    evaluation_key: &DdhHssEvaluationKey,
    label_prefix: &str,
    left_left: DdhHssLocalBitSliceView<'_>,
    left_right: DdhHssLocalBitSliceView<'_>,
    right_left: DdhHssLocalBitSliceView<'_>,
    right_right: DdhHssLocalBitSliceView<'_>,
    base_left: DdhHssLocalBitSliceView<'_>,
    base_right: DdhHssLocalBitSliceView<'_>,
    mut push_pair: F,
) -> ProtoResult<()>
where
    F: FnMut(DdhHssLocalWord, DdhHssLocalWord) -> ProtoResult<()>,
{
    local_bit_slice_view_ensure_shape(base_left)?;
    local_bit_slice_view_ensure_shape(base_right)?;
    let len = left_left.bit_len;
    if base_left.bit_len != len || base_right.bit_len != len {
        return Err(ProtoError::InvalidInput(
            "raw local mul xor-base lengths are inconsistent".to_string(),
        ));
    }
    let mut gate_prefix = String::with_capacity(label_prefix.len() + 8);
    set_child_label(&mut gate_prefix, label_prefix, "gate");
    let mut out_label = String::with_capacity(label_prefix.len() + 32);
    let mut idx = 0usize;
    eval_mul_local_bit_pair_batch_raw_public_into(
        evaluation_key,
        &gate_prefix,
        left_left,
        left_right,
        right_left,
        right_right,
        |gated_left, gated_right| {
            set_indexed_child_label(&mut out_label, label_prefix, "out", idx);
            let provenance_digest = derive_digest_for_key(
                evaluation_key,
                b"eval-xor-local-word",
                HiddenEvalInputOwner::Derived,
                out_label.as_bytes(),
                1,
                0,
                0,
                &[
                    &base_left.provenance_digests[idx],
                    &gated_left.provenance_digest,
                ],
            );
            let left_word = reduce_word(
                u128::from(local_bit_slice_view_share_bit(base_left, idx))
                    + u128::from(gated_left.share_word),
                1,
            );
            let right_word = reduce_word(
                u128::from(local_bit_slice_view_share_bit(base_right, idx))
                    + u128::from(gated_right.share_word),
                1,
            );
            let out_left = DdhHssLocalWord {
                width_bits: 1,
                share_side: DdhHssShareSide::Left,
                share_word: left_word,
                share_commitment: commit_word_for_provenance_domain(
                    HiddenEvalInputOwner::Derived,
                    b"left",
                    left_word,
                    &provenance_digest,
                    b"eval-xor-local-word",
                ),
                provenance_digest,
            };
            let out_right = DdhHssLocalWord {
                width_bits: 1,
                share_side: DdhHssShareSide::Right,
                share_word: right_word,
                share_commitment: commit_word_for_provenance_domain(
                    HiddenEvalInputOwner::Derived,
                    b"right",
                    right_word,
                    &provenance_digest,
                    b"eval-xor-local-word",
                ),
                provenance_digest,
            };
            idx = idx.saturating_add(1);
            push_pair(out_left, out_right)
        },
    )?;
    Ok(())
}

pub(crate) fn eval_maj_local_bit_pair_batch_raw_public_into<F>(
    evaluation_key: &DdhHssEvaluationKey,
    label_prefix: &str,
    x_left: DdhHssLocalBitSliceView<'_>,
    x_right: DdhHssLocalBitSliceView<'_>,
    y_left: DdhHssLocalBitSliceView<'_>,
    y_right: DdhHssLocalBitSliceView<'_>,
    z_left: DdhHssLocalBitSliceView<'_>,
    z_right: DdhHssLocalBitSliceView<'_>,
    mut push_pair: F,
) -> ProtoResult<()>
where
    F: FnMut(DdhHssLocalWord, DdhHssLocalWord) -> ProtoResult<()>,
{
    local_bit_slice_view_ensure_shape(x_left)?;
    local_bit_slice_view_ensure_shape(x_right)?;
    local_bit_slice_view_ensure_shape(y_left)?;
    local_bit_slice_view_ensure_shape(y_right)?;
    local_bit_slice_view_ensure_shape(z_left)?;
    local_bit_slice_view_ensure_shape(z_right)?;
    let len = x_left.bit_len;
    if x_right.bit_len != len
        || y_left.bit_len != len
        || y_right.bit_len != len
        || z_left.bit_len != len
        || z_right.bit_len != len
    {
        return Err(ProtoError::InvalidInput(
            "raw majority batch lengths are inconsistent".to_string(),
        ));
    }
    if x_left.share_side != DdhHssShareSide::Left
        || y_left.share_side != DdhHssShareSide::Left
        || z_left.share_side != DdhHssShareSide::Left
        || x_right.share_side != DdhHssShareSide::Right
        || y_right.share_side != DdhHssShareSide::Right
        || z_right.share_side != DdhHssShareSide::Right
    {
        return Err(ProtoError::InvalidInput(
            "raw majority batch requires aligned left/right slice pairs".to_string(),
        ));
    }

    let material_hasher_base = local_bit_mul_material_base_hasher(evaluation_key);
    let mut child_label = String::with_capacity(label_prefix.len() + 32);
    let mut gate_label = String::with_capacity(label_prefix.len() + 32);
    let mut out_label = String::with_capacity(label_prefix.len() + 32);
    for idx in 0..len {
        set_indexed_child_label(&mut child_label, label_prefix, "xy_left", idx);
        let xy_left = xor_local_bit_from_raw_public(
            evaluation_key,
            child_label.as_bytes(),
            DdhHssShareSide::Left,
            local_bit_slice_view_share_bit(x_left, idx),
            &x_left.provenance_digests[idx],
            local_bit_slice_view_share_bit(y_left, idx),
            &y_left.provenance_digests[idx],
        );
        set_indexed_child_label(&mut child_label, label_prefix, "xy_right", idx);
        let xy_right = xor_local_bit_from_raw_public(
            evaluation_key,
            child_label.as_bytes(),
            DdhHssShareSide::Right,
            local_bit_slice_view_share_bit(x_right, idx),
            &x_right.provenance_digests[idx],
            local_bit_slice_view_share_bit(y_right, idx),
            &y_right.provenance_digests[idx],
        );
        set_indexed_child_label(&mut child_label, label_prefix, "xz_left", idx);
        let xz_left = xor_local_bit_from_raw_public(
            evaluation_key,
            child_label.as_bytes(),
            DdhHssShareSide::Left,
            local_bit_slice_view_share_bit(x_left, idx),
            &x_left.provenance_digests[idx],
            local_bit_slice_view_share_bit(z_left, idx),
            &z_left.provenance_digests[idx],
        );
        set_indexed_child_label(&mut child_label, label_prefix, "xz_right", idx);
        let xz_right = xor_local_bit_from_raw_public(
            evaluation_key,
            child_label.as_bytes(),
            DdhHssShareSide::Right,
            local_bit_slice_view_share_bit(x_right, idx),
            &x_right.provenance_digests[idx],
            local_bit_slice_view_share_bit(z_right, idx),
            &z_right.provenance_digests[idx],
        );
        set_indexed_child_label(&mut gate_label, label_prefix, "gate", idx);
        let material_digest = {
            let mut material_hasher = material_hasher_base.clone();
            material_hasher.update(gate_label.as_bytes());
            material_hasher.update(&xy_left.provenance_digest);
            material_hasher.update(&xz_left.provenance_digest);
            material_hasher.update(&xy_left.share_commitment);
            material_hasher.update(&xy_right.share_commitment);
            material_hasher.update(&xz_left.share_commitment);
            material_hasher.update(&xz_right.share_commitment);
            record_physical_mul_material_hash();
            *material_hasher.finalize().as_bytes()
        };
        let (material_left, material_right) = local_bit_mul_material_from_raw_digest(
            evaluation_key,
            &xy_left.provenance_digest,
            &xz_left.provenance_digest,
            material_digest,
        );
        let d_open = reduce_word(
            u128::from(xy_left.share_word)
                + u128::from(material_left.triple_a.share_word)
                + u128::from(xy_right.share_word)
                + u128::from(material_right.triple_a.share_word),
            1,
        );
        let e_open = reduce_word(
            u128::from(xz_left.share_word)
                + u128::from(material_left.triple_b.share_word)
                + u128::from(xz_right.share_word)
                + u128::from(material_right.triple_b.share_word),
            1,
        );
        let gated_left = build_local_word_for_key(
            evaluation_key,
            b"eval-mul-local",
            gate_label.as_bytes(),
            1,
            DdhHssShareSide::Left,
            reduce_word(
                u128::from(material_left.triple_c.share_word)
                    + (u128::from(d_open) * u128::from(material_left.triple_b.share_word))
                    + (u128::from(e_open) * u128::from(material_left.triple_a.share_word))
                    + (u128::from(d_open) * u128::from(e_open)),
                1,
            ),
            &[
                &xy_left.provenance_digest,
                &xz_left.provenance_digest,
                &material_left.provenance_digest,
                &d_open.to_le_bytes(),
                &e_open.to_le_bytes(),
            ],
        );
        let gated_right = build_local_word_for_key(
            evaluation_key,
            b"eval-mul-local",
            gate_label.as_bytes(),
            1,
            DdhHssShareSide::Right,
            reduce_word(
                u128::from(material_right.triple_c.share_word)
                    + (u128::from(d_open) * u128::from(material_right.triple_b.share_word))
                    + (u128::from(e_open) * u128::from(material_right.triple_a.share_word)),
                1,
            ),
            &[
                &xy_right.provenance_digest,
                &xz_right.provenance_digest,
                &material_right.provenance_digest,
                &d_open.to_le_bytes(),
                &e_open.to_le_bytes(),
            ],
        );
        let provenance_digest = derive_digest_for_key(
            evaluation_key,
            b"eval-xor-local-word",
            HiddenEvalInputOwner::Derived,
            {
                set_indexed_child_label(&mut out_label, label_prefix, "out", idx);
                out_label.as_bytes()
            },
            1,
            0,
            0,
            &[
                &x_left.provenance_digests[idx],
                &gated_left.provenance_digest,
            ],
        );
        let left_word = reduce_word(
            u128::from(local_bit_slice_view_share_bit(x_left, idx))
                + u128::from(gated_left.share_word),
            1,
        );
        let right_word = reduce_word(
            u128::from(local_bit_slice_view_share_bit(x_right, idx))
                + u128::from(gated_right.share_word),
            1,
        );
        let out_left = DdhHssLocalWord {
            width_bits: 1,
            share_side: DdhHssShareSide::Left,
            share_word: left_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"left",
                left_word,
                &provenance_digest,
                b"eval-xor-local-word",
            ),
            provenance_digest,
        };
        let out_right = DdhHssLocalWord {
            width_bits: 1,
            share_side: DdhHssShareSide::Right,
            share_word: right_word,
            share_commitment: commit_word_for_provenance_domain(
                HiddenEvalInputOwner::Derived,
                b"right",
                right_word,
                &provenance_digest,
                b"eval-xor-local-word",
            ),
            provenance_digest,
        };
        push_pair(out_left, out_right)?;
    }
    Ok(())
}

#[cfg(test)]
fn eval_mul_bit_derived_local_batch_public(
    evaluation_key: &DdhHssEvaluationKey,
    label_prefix: &str,
    left: &[DdhHssDerivedWord],
    right: &[DdhHssDerivedWord],
) -> ProtoResult<Vec<DdhHssDerivedWord>> {
    if left.len() != right.len() {
        return Err(ProtoError::InvalidInput(format!(
            "bit-mul batch requires same-width slices, got {} and {}",
            left.len(),
            right.len()
        )));
    }

    let mut out = Vec::with_capacity(left.len());
    for (idx, (left_word, right_word)) in left.iter().zip(right.iter()).enumerate() {
        let left_left = local_word_from_derived_public(left_word, DdhHssShareSide::Left)?;
        let left_right = local_word_from_derived_public(left_word, DdhHssShareSide::Right)?;
        let right_left = local_word_from_derived_public(right_word, DdhHssShareSide::Left)?;
        let right_right = local_word_from_derived_public(right_word, DdhHssShareSide::Right)?;

        let gate_label = format!("{label_prefix}/{idx}");
        let (material_left, material_right) = prepare_local_bit_mul_material_public(
            evaluation_key,
            gate_label.as_bytes(),
            &left_left,
            &left_right,
            &right_left,
            &right_right,
        )?;

        let (d_left, d_right) = eval_add_local_word_pairs_mod_2_pow_n_public(
            evaluation_key,
            format!("{gate_label}/d").as_bytes(),
            &left_left,
            &left_right,
            &material_left.triple_a,
            &material_right.triple_a,
        )?;
        let (e_left, e_right) = eval_add_local_word_pairs_mod_2_pow_n_public(
            evaluation_key,
            format!("{gate_label}/e").as_bytes(),
            &right_left,
            &right_right,
            &material_left.triple_b,
            &material_right.triple_b,
        )?;

        let d_open = open_local_word_pair_public(&d_left, &d_right)?;
        let e_open = open_local_word_pair_public(&e_left, &e_right)?;

        let product_left = eval_mul_local_with_open_public(
            evaluation_key,
            gate_label.as_bytes(),
            &left_left,
            &right_left,
            &material_left,
            d_open,
            e_open,
        )?;
        let product_right = eval_mul_local_with_open_public(
            evaluation_key,
            gate_label.as_bytes(),
            &left_right,
            &right_right,
            &material_right,
            d_open,
            e_open,
        )?;
        out.push(join_local_word_pair_as_derived(
            &product_left,
            &product_right,
        )?);
    }

    Ok(out)
}

pub(crate) fn eval_mul_local_word_pairs_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> ProtoResult<(DdhHssLocalWord, DdhHssLocalWord)> {
    let (left_core, right_core) = eval_mul_local_word_pairs_core_public(
        evaluation_key,
        label,
        left_left,
        left_right,
        right_left,
        right_right,
    )?;
    Ok((
        materialize_local_word_core(&left_core, b"eval-mul-local"),
        materialize_local_word_core(&right_core, b"eval-mul-local"),
    ))
}

pub(crate) fn eval_mul_local_word_pairs_core_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left_left: &DdhHssLocalWord,
    left_right: &DdhHssLocalWord,
    right_left: &DdhHssLocalWord,
    right_right: &DdhHssLocalWord,
) -> ProtoResult<(DdhHssLocalWordCore, DdhHssLocalWordCore)> {
    ensure_local_word_pair(left_left, left_right)?;
    ensure_local_word_pair(right_left, right_right)?;
    if left_left.width_bits != right_left.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "bit multiplication requires same width, got {} and {}",
            left_left.width_bits, right_left.width_bits
        )));
    }
    if left_left.width_bits != 1 {
        return Err(ProtoError::InvalidInput(format!(
            "bit multiplication requires width 1, got {}",
            left_left.width_bits
        )));
    }
    let material_digest = finalize_local_bit_mul_material_digest(
        &local_bit_mul_material_base_hasher(evaluation_key),
        label,
        left_left,
        left_right,
        right_left,
        right_right,
    );
    let (material_left, material_right) =
        local_bit_mul_material_core_from_raw_digest(material_digest);
    let d_open = reduce_word(
        u128::from(left_left.share_word)
            + u128::from(material_left.triple_a_word)
            + u128::from(left_right.share_word)
            + u128::from(material_right.triple_a_word),
        1,
    );
    let e_open = reduce_word(
        u128::from(right_left.share_word)
            + u128::from(material_left.triple_b_word)
            + u128::from(right_right.share_word)
            + u128::from(material_right.triple_b_word),
        1,
    );
    let d_open_bytes = d_open.to_le_bytes();
    let e_open_bytes = e_open.to_le_bytes();
    let output_provenance = derive_digest_for_key(
        evaluation_key,
        b"eval-mul-local",
        HiddenEvalInputOwner::Derived,
        label,
        1,
        0,
        0,
        &[
            &left_left.provenance_digest,
            &right_left.provenance_digest,
            &material_digest,
            &d_open_bytes,
            &e_open_bytes,
        ],
    );
    Ok((
        local_word_core_from_provenance(
            1,
            DdhHssShareSide::Left,
            reduce_word(
                u128::from(material_left.triple_c_word)
                    + (u128::from(d_open) * u128::from(material_left.triple_b_word))
                    + (u128::from(e_open) * u128::from(material_left.triple_a_word))
                    + (u128::from(d_open) * u128::from(e_open)),
                1,
            ),
            output_provenance,
        ),
        local_word_core_from_provenance(
            1,
            DdhHssShareSide::Right,
            reduce_word(
                u128::from(material_right.triple_c_word)
                    + (u128::from(d_open) * u128::from(material_right.triple_b_word))
                    + (u128::from(e_open) * u128::from(material_right.triple_a_word)),
                1,
            ),
            output_provenance,
        ),
    ))
}

pub(crate) fn eval_mul_local_with_open_public(
    evaluation_key: &DdhHssEvaluationKey,
    label: &[u8],
    left: &DdhHssLocalWord,
    right: &DdhHssLocalWord,
    material: &DdhHssLocalMulMaterial,
    d_open: u64,
    e_open: u64,
) -> ProtoResult<DdhHssLocalWord> {
    if left.share_side != right.share_side || left.share_side != material.share_side {
        return Err(ProtoError::InvalidInput(
            "local mul requires same-side operands and material".to_string(),
        ));
    }
    if left.width_bits != 1 || right.width_bits != 1 || material.width_bits != 1 {
        return Err(ProtoError::InvalidInput(
            "local bit mul requires width-1 operands and material".to_string(),
        ));
    }
    let public_term = match left.share_side {
        DdhHssShareSide::Left => reduce_word(u128::from(d_open) * u128::from(e_open), 1),
        DdhHssShareSide::Right => 0,
    };
    Ok(build_local_word_for_key(
        evaluation_key,
        b"eval-mul-local",
        label,
        1,
        left.share_side,
        reduce_word(
            u128::from(material.triple_c.share_word)
                + (u128::from(d_open) * u128::from(material.triple_b.share_word))
                + (u128::from(e_open) * u128::from(material.triple_a.share_word))
                + u128::from(public_term),
            1,
        ),
        &[
            &left.provenance_digest,
            &right.provenance_digest,
            &material.provenance_digest,
            &d_open.to_le_bytes(),
            &e_open.to_le_bytes(),
        ],
    ))
}

fn eval_add_bit_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssSharedWord,
    right: &DdhHssSharedWord,
) -> DdhHssSharedWord {
    let left_word = (left.left_word ^ right.left_word) & 1;
    let right_word = (left.right_word ^ right.right_word) & 1;

    let mut hasher = Blake3Hasher::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/eval-add-bit/v0");
    hasher.update(&evaluation_key.key_id);
    hasher.update(&left.provenance_digest);
    hasher.update(&right.provenance_digest);
    hasher.update(&left.left_commitment);
    hasher.update(&right.left_commitment);
    record_physical_add_bit_hash();
    let provenance_digest = *hasher.finalize().as_bytes();

    let left_commitment = commit_word(
        HiddenEvalInputOwner::Derived,
        b"left",
        left_word,
        &provenance_digest,
    );
    let right_commitment = commit_word(
        HiddenEvalInputOwner::Derived,
        b"right",
        right_word,
        &provenance_digest,
    );

    DdhHssSharedWord {
        width_bits: 1,
        left_word,
        right_word,
        left_commitment,
        right_commitment,
        provenance_digest,
    }
}

fn eval_mul_bit_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    gate_key: &[u8],
    left: &DdhHssSharedWord,
    right: &DdhHssSharedWord,
) -> ProtoResult<DdhHssSharedWord> {
    ensure_same_width(left, right)?;
    if left.width_bits != 1 {
        return Err(ProtoError::InvalidInput(format!(
            "bit multiplication requires 1-bit operands, got {}",
            left.width_bits
        )));
    }

    let mut material_hasher = Blake3Hasher::new();
    material_hasher.update(b"succinct-garbling-proto/ddh-hss/eval-mul-bit/v1");
    material_hasher.update(&evaluation_key.key_id);
    material_hasher.update(gate_key);
    material_hasher.update(owner_tag(HiddenEvalInputOwner::Derived));
    material_hasher.update(&1u16.to_le_bytes());
    material_hasher.update(&left.provenance_digest);
    material_hasher.update(&right.provenance_digest);
    material_hasher.update(&left.left_commitment);
    material_hasher.update(&left.right_commitment);
    material_hasher.update(&right.left_commitment);
    material_hasher.update(&right.right_commitment);
    record_physical_mul_material_hash();
    let material_digest = material_hasher.finalize();

    let mut triple_bytes = [0u8; 5];
    triple_bytes.copy_from_slice(&material_digest.as_bytes()[..5]);

    let triple_a_clear = u64::from(triple_bytes[0] & 1);
    let triple_b_clear = u64::from(triple_bytes[1] & 1);
    let triple_a_left = u64::from(triple_bytes[2] & 1);
    let triple_b_left = u64::from(triple_bytes[3] & 1);
    let triple_c_left = u64::from(triple_bytes[4] & 1);

    let triple_a_right = triple_a_clear ^ triple_a_left;
    let triple_b_right = triple_b_clear ^ triple_b_left;
    let triple_c_clear = triple_a_clear & triple_b_clear;
    let triple_c_right = triple_c_clear ^ triple_c_left;

    let mut output_seed_hasher = Blake3Hasher::new();
    output_seed_hasher.update(b"succinct-garbling-proto/ddh-hss/eval-mul-bit-output/v1");
    output_seed_hasher.update(material_digest.as_bytes());
    record_physical_mul_output_seed_hash();
    let output_seed = *output_seed_hasher.finalize().as_bytes();

    let d_left = reduce_word(
        u128::from(left.left_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_a_left)),
        1,
    );
    let d_right = reduce_word(
        u128::from(left.right_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_a_right)),
        1,
    );
    let e_left = reduce_word(
        u128::from(right.left_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_b_left)),
        1,
    );
    let e_right = reduce_word(
        u128::from(right.right_word)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(triple_b_right)),
        1,
    );
    let d_open = reduce_word(u128::from(d_left) + u128::from(d_right), 1);
    let e_open = reduce_word(u128::from(e_left) + u128::from(e_right), 1);

    let left_word = reduce_word(
        u128::from(triple_c_left)
            + (u128::from(d_open) * u128::from(triple_b_left))
            + (u128::from(e_open) * u128::from(triple_a_left))
            + (u128::from(d_open) * u128::from(e_open)),
        1,
    );
    let right_word = reduce_word(
        u128::from(triple_c_right)
            + (u128::from(d_open) * u128::from(triple_b_right))
            + (u128::from(e_open) * u128::from(triple_a_right)),
        1,
    );

    let output_material = [
        &left.provenance_digest[..],
        &right.provenance_digest[..],
        &output_seed[..],
    ];
    Ok(build_shared_word_for_key(
        evaluation_key,
        b"eval-mul-public",
        HiddenEvalInputOwner::Derived,
        b"mul",
        1,
        left_word,
        right_word,
        &output_material,
    ))
}

fn decode_word_public(value: &DdhHssSharedWord) -> u64 {
    reduce_word(
        u128::from(value.left_word) + u128::from(value.right_word),
        value.width_bits,
    )
}

fn decode_words_public(values: &[DdhHssSharedWord]) -> ProtoResult<Vec<u8>> {
    let mut out = Vec::new();
    for value in values {
        let word = decode_word_public(value);
        let width_bytes = usize::from((value.width_bits + 7) / 8);
        let bytes = word.to_le_bytes();
        out.extend_from_slice(&bytes[..width_bytes]);
    }
    Ok(out)
}

fn decode_bit_bundle_array(
    backend: &DdhHssBackend,
    bundle: &DdhHssInputShareBundle,
) -> ProtoResult<[u8; 32]> {
    if bundle.words.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "bit bundle must contain exactly 256 words, got {}",
            bundle.words.len()
        )));
    }
    if bundle.words.iter().any(|word| word.width_bits != 1) {
        return Err(ProtoError::Decode(
            "bit bundle must contain only 1-bit words".to_string(),
        ));
    }

    let mut out = [0u8; 32];
    for byte_idx in 0..32 {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let bit = backend.decode_word(&bundle.words[byte_idx * 8 + bit_idx]);
            value |= ((bit & 1) as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

fn decode_bit_bundle_array_public(bundle: &DdhHssInputShareBundle) -> ProtoResult<[u8; 32]> {
    if bundle.words.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "bit bundle must contain exactly 256 words, got {}",
            bundle.words.len()
        )));
    }
    if bundle.words.iter().any(|word| word.width_bits != 1) {
        return Err(ProtoError::Decode(
            "bit bundle must contain only 1-bit words".to_string(),
        ));
    }

    let mut out = [0u8; 32];
    for byte_idx in 0..32 {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let bit = decode_word_public(&bundle.words[byte_idx * 8 + bit_idx]);
            value |= ((bit & 1) as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

fn prepare_client_input_ot_request_public(
    offer: &DdhHssOtInputBundleOffer,
    input: &[u8],
) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
    let sender_public_points = decode_ot_offer_sender_public_points_public(offer)?;
    prepare_client_input_ot_request_with_sender_public_points_public(
        offer,
        &sender_public_points,
        input,
    )
}

fn decode_ot_offer_sender_public_points_public(
    offer: &DdhHssOtInputBundleOffer,
) -> ProtoResult<Vec<EdwardsPoint>> {
    if offer.owner != HiddenEvalInputOwner::Client {
        return Err(ProtoError::InvalidInput(
            "OT request requires a client-owned offer".to_string(),
        ));
    }
    let mut sender_public_points = Vec::with_capacity(offer.words.len());
    for (bit_idx, word_offer) in offer.words.iter().enumerate() {
        if word_offer.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "OT offer word width must be 1, got {} at index {}",
                word_offer.width_bits, bit_idx
            )));
        }
        sender_public_points.push(
            CompressedEdwardsY(word_offer.sender_public)
                .decompress()
                .ok_or_else(|| {
                    ProtoError::InvalidInput(format!(
                        "OT sender public point is invalid at index {}",
                        bit_idx
                    ))
                })?,
        );
    }
    Ok(sender_public_points)
}

fn prepare_client_input_ot_request_with_sender_public_points_public(
    offer: &DdhHssOtInputBundleOffer,
    sender_public_points: &[EdwardsPoint],
    input: &[u8],
) -> ProtoResult<(DdhHssOtSelectionBundle, DdhHssOtReceiverStateBundle)> {
    if offer.owner != HiddenEvalInputOwner::Client {
        return Err(ProtoError::InvalidInput(
            "OT request requires a client-owned offer".to_string(),
        ));
    }
    let bit_count = input.len() * 8;
    if offer.words.len() != bit_count {
        return Err(ProtoError::InvalidInput(format!(
            "OT offer word count does not match input bit count: {} vs {}",
            offer.words.len(),
            bit_count
        )));
    }
    if sender_public_points.len() != bit_count {
        return Err(ProtoError::InvalidInput(format!(
            "prepared OT sender point count does not match input bit count: {} vs {}",
            sender_public_points.len(),
            bit_count
        )));
    }
    let mut request_words = Vec::with_capacity(bit_count);
    let mut local_state_words = Vec::with_capacity(bit_count);
    let mut random_wide_bytes = vec![0u8; bit_count * 64];
    OsRng.fill_bytes(&mut random_wide_bytes);
    for bit_idx in 0..bit_count {
        let byte_idx = bit_idx / 8;
        let inner_bit_idx = bit_idx % 8;
        let selected_branch = (input[byte_idx] >> inner_bit_idx) & 1;
        let wide_offset = bit_idx * 64;
        let receiver_scalar = Scalar::from_bytes_mod_order_wide(
            random_wide_bytes[wide_offset..wide_offset + 64]
                .try_into()
                .expect("random OT scalar slice has fixed width"),
        );
        let sender_public_point = &sender_public_points[bit_idx];
        let shared_point = (sender_public_point * receiver_scalar)
            .compress()
            .to_bytes();
        let receiver_basepoint = ED25519_BASEPOINT_TABLE * &receiver_scalar;
        let receiver_public_point = if selected_branch == 0 {
            receiver_basepoint
        } else {
            sender_public_point + receiver_basepoint
        };
        request_words.push(DdhHssOtSelectionWord {
            width_bits: 1,
            receiver_public: receiver_public_point.compress().to_bytes(),
        });
        local_state_words.push(DdhHssOtReceiverStateWord {
            width_bits: 1,
            selected_branch,
            shared_point,
        });
    }

    let request = DdhHssOtSelectionBundle {
        owner: HiddenEvalInputOwner::Client,
        label: offer.label.clone(),
        commitment: ot_request_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &request_words,
        ),
        words: request_words,
    };
    let local_state = DdhHssOtReceiverStateBundle {
        owner: HiddenEvalInputOwner::Client,
        label: offer.label.clone(),
        commitment: ot_receiver_state_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &offer.label,
            &local_state_words,
        ),
        words: local_state_words,
    };
    Ok((request, local_state))
}

fn validate_client_ot_offer_preflight(
    offer: &DdhHssOtInputBundleOffer,
    sender_state: &DdhHssOtSenderStateBundle,
    remote: &DdhHssOtRemoteBundle,
) -> ProtoResult<()> {
    if offer.owner != HiddenEvalInputOwner::Client
        || sender_state.owner != HiddenEvalInputOwner::Client
        || remote.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "client OT validation requires client-owned offer, sender state, and remote bundles"
                .to_string(),
        ));
    }
    if offer.label != sender_state.label || offer.label != remote.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT offer label does not match sender state or remote bundle: {}, {}, {}",
            offer.label, sender_state.label, remote.label
        )));
    }
    if remote.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "client OT remote bundle must carry right-side shares".to_string(),
        ));
    }
    if offer.words.len() != remote.words.len() || offer.words.len() != sender_state.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "client OT offer word count does not match sender state / remote bundle: {} vs {} / {}",
            offer.words.len(),
            sender_state.words.len(),
            remote.words.len()
        )));
    }
    if remote.commitment
        != ot_remote_bundle_commitment(
            remote.owner,
            &remote.label,
            remote.share_side,
            &remote.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT remote bundle commitment is invalid".to_string(),
        ));
    }
    if offer.commitment != ot_offer_bundle_commitment(offer.owner, &offer.label, &offer.words) {
        return Err(ProtoError::InvalidInput(
            "client OT offer commitment is invalid".to_string(),
        ));
    }
    if sender_state.commitment
        != ot_sender_state_bundle_commitment(
            sender_state.owner,
            &sender_state.label,
            &sender_state.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT sender-state commitment is invalid".to_string(),
        ));
    }
    Ok(())
}

fn client_ot_branch_payloads(
    backend: &DdhHssBackend,
    bit_label: &[u8],
    remote_word: &DdhHssOtRemoteWord,
) -> (DdhHssOtBranchPayload, DdhHssOtBranchPayload) {
    let zero_left_word = reduce_word(
        modulus_for_width(1).wrapping_sub(u128::from(remote_word.share_word)),
        1,
    );
    let one_left_word = reduce_word(
        u128::from(1u8)
            .wrapping_add(modulus_for_width(1))
            .wrapping_sub(u128::from(remote_word.share_word)),
        1,
    );
    let zero_provenance_digest = backend.derive_digest(
        b"client-input-ot/zero-branch",
        HiddenEvalInputOwner::Client,
        bit_label,
        1,
        zero_left_word,
        remote_word.share_word,
        &[],
    );
    let one_provenance_digest = backend.derive_digest(
        b"client-input-ot/one-branch",
        HiddenEvalInputOwner::Client,
        bit_label,
        1,
        one_left_word,
        remote_word.share_word,
        &[],
    );
    (
        DdhHssOtBranchPayload {
            width_bits: 1,
            share_word: zero_left_word,
            share_commitment: commit_word(
                HiddenEvalInputOwner::Client,
                b"left",
                zero_left_word,
                &zero_provenance_digest,
            ),
            counterparty_commitment: remote_word.share_commitment,
            provenance_digest: zero_provenance_digest,
        },
        DdhHssOtBranchPayload {
            width_bits: 1,
            share_word: one_left_word,
            share_commitment: commit_word(
                HiddenEvalInputOwner::Client,
                b"left",
                one_left_word,
                &one_provenance_digest,
            ),
            counterparty_commitment: remote_word.share_commitment,
            provenance_digest: one_provenance_digest,
        },
    )
}

pub(crate) fn prepare_client_ot_sender_state_words_public(
    backend: &DdhHssBackend,
    offer: &DdhHssOtInputBundleOffer,
    sender_state: &DdhHssOtSenderStateBundle,
    remote: &DdhHssOtRemoteBundle,
) -> ProtoResult<Vec<DdhHssPreparedOtSenderStateWord>> {
    validate_client_ot_offer_preflight(offer, sender_state, remote)?;

    let mut prepared_words = Vec::with_capacity(offer.words.len());
    let mut bit_label = String::with_capacity(offer.label.len() + 32);
    for (bit_idx, ((word_offer, sender_state_word), remote_word)) in offer
        .words
        .iter()
        .zip(&sender_state.words)
        .zip(&remote.words)
        .enumerate()
    {
        if word_offer.width_bits != 1
            || sender_state_word.width_bits != 1
            || remote_word.width_bits != 1
        {
            return Err(ProtoError::InvalidInput(format!(
                "client OT prepared sender words must be 1-bit at index {bit_idx}"
            )));
        }
        let sender_public_point = CompressedEdwardsY(word_offer.sender_public)
            .decompress()
            .ok_or_else(|| {
                ProtoError::InvalidInput(format!(
                    "client OT sender public point is invalid at bit index {bit_idx}"
                ))
            })?;
        if sender_state_word.sender_public != word_offer.sender_public {
            return Err(ProtoError::InvalidInput(format!(
                "client OT sender-state public point does not match offer at bit index {bit_idx}"
            )));
        }
        let sender_scalar = Scalar::from_bytes_mod_order(sender_state_word.sender_scalar);
        if sender_public_point != (ED25519_BASEPOINT_POINT * sender_scalar) {
            return Err(ProtoError::InvalidInput(format!(
                "client OT sender-state scalar does not match offer public point at bit index {bit_idx}"
            )));
        }
        set_indexed_label(&mut bit_label, &offer.label, bit_idx);
        let (zero_payload, one_payload) =
            client_ot_branch_payloads(backend, bit_label.as_bytes(), remote_word);
        prepared_words.push(DdhHssPreparedOtSenderStateWord {
            sender_scalar,
            sender_self_shared_point: sender_public_point * sender_scalar,
            zero_branch: prepare_ot_branch(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                0,
                &zero_payload,
            ),
            one_branch: prepare_ot_branch(
                HiddenEvalInputOwner::Client,
                &offer.label,
                bit_idx,
                1,
                &one_payload,
            ),
        });
    }

    Ok(prepared_words)
}

fn derive_ot_branch_key_from_point_for_key(
    evaluation_key: &DdhHssEvaluationKey,
    owner: HiddenEvalInputOwner,
    label: &str,
    bit_idx: usize,
    branch_bit: u8,
    shared_point: [u8; 32],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-branch-key/v1");
    transcript.append_message(b"key_id", &evaluation_key.key_id);
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"bit_idx", &(bit_idx as u64).to_le_bytes());
    transcript.append_message(b"branch_bit", &[branch_bit]);
    transcript.append_message(b"shared_point", &shared_point);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_branch_key", &mut out);
    out
}

fn open_client_input_ot_bundle_public(
    evaluation_key: &DdhHssEvaluationKey,
    response: &DdhHssOtResponseBundle,
    local_state: &DdhHssOtReceiverStateBundle,
) -> ProtoResult<DdhHssTransportBundle> {
    if response.owner != HiddenEvalInputOwner::Client
        || local_state.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "client OT response opening requires client-owned bundles".to_string(),
        ));
    }
    if response.label != local_state.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT response label does not match local state: {} vs {}",
            response.label, local_state.label
        )));
    }
    if response.words.len() != local_state.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "client OT response word count does not match local state: {} vs {}",
            response.words.len(),
            local_state.words.len()
        )));
    }
    if response.commitment
        != ot_response_bundle_commitment(response.owner, &response.label, &response.words)
    {
        return Err(ProtoError::InvalidInput(
            "client OT response commitment is invalid".to_string(),
        ));
    }
    if local_state.commitment
        != ot_receiver_state_bundle_commitment(
            local_state.owner,
            &local_state.label,
            &local_state.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT local state commitment is invalid".to_string(),
        ));
    }

    let mut local_words = Vec::with_capacity(response.words.len());
    for (bit_idx, (response_word, state_word)) in
        response.words.iter().zip(&local_state.words).enumerate()
    {
        if response_word.width_bits != 1 || state_word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response words must be 1-bit at index {bit_idx}"
            )));
        }
        if state_word.selected_branch > 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT local state branch must be 0 or 1 at index {bit_idx}, got {}",
                state_word.selected_branch
            )));
        }
        let selected_branch = if state_word.selected_branch == 0 {
            &response_word.zero_branch
        } else {
            &response_word.one_branch
        };
        let key = derive_ot_branch_key_from_point_for_key(
            evaluation_key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            state_word.shared_point,
        );
        let payload = DdhHssBackend::open_ot_branch_with_key(
            key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            selected_branch,
        )?;
        local_words.push(DdhHssTransportWord {
            width_bits: 1,
            share_side: DdhHssShareSide::Left,
            share_word: payload.share_word,
            share_commitment: payload.share_commitment,
            counterparty_commitment: payload.counterparty_commitment,
            provenance_digest: payload.provenance_digest,
        });
    }

    Ok(DdhHssTransportBundle {
        owner: HiddenEvalInputOwner::Client,
        label: response.label.clone(),
        share_side: DdhHssShareSide::Left,
        commitment: transport_bundle_commitment(
            HiddenEvalInputOwner::Client,
            &response.label,
            DdhHssShareSide::Left,
            &local_words,
        ),
        words: local_words,
    })
}

fn join_client_ot_bundle_public(
    evaluation_key: &DdhHssEvaluationKey,
    expected_context_binding: [u8; 32],
    local: &DdhHssTransportBundle,
    remote: &DdhHssOtReleasedRemoteBundle,
) -> ProtoResult<DdhHssInputShareBundle> {
    if remote.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release context binding is invalid".to_string(),
        ));
    }
    if local.owner != HiddenEvalInputOwner::Client || remote.owner != HiddenEvalInputOwner::Client {
        return Err(ProtoError::InvalidInput(
            "client OT bundle join requires client-owned bundles".to_string(),
        ));
    }
    if local.label != remote.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT bundle labels do not match: {} vs {}",
            local.label, remote.label
        )));
    }
    if local.share_side != DdhHssShareSide::Left || remote.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "client OT bundles must be joined in left/right order".to_string(),
        ));
    }
    if local.words.len() != remote.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "client OT bundle word counts do not match: {} vs {}",
            local.words.len(),
            remote.words.len()
        )));
    }
    if local.commitment
        != transport_bundle_commitment(local.owner, &local.label, local.share_side, &local.words)
    {
        return Err(ProtoError::InvalidInput(
            "client OT local bundle commitment is invalid".to_string(),
        ));
    }
    if remote.commitment
        != ot_remote_bundle_commitment(
            remote.owner,
            &remote.label,
            remote.share_side,
            &remote.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT remote bundle commitment is invalid".to_string(),
        ));
    }
    let expected_remote_binding = ot_remote_release_transcript_binding(
        remote.context_binding,
        remote.owner,
        &remote.label,
        remote.offer_commitment,
        remote.request_commitment,
        remote.response_commitment,
        remote.commitment,
    );
    if remote.transcript_binding != expected_remote_binding {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release transcript binding is invalid".to_string(),
        ));
    }

    let mut words = Vec::with_capacity(local.words.len());
    for (left_word, right_word) in local.words.iter().zip(&remote.words) {
        if left_word.width_bits != right_word.width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "client OT word widths do not match: {} vs {}",
                left_word.width_bits, right_word.width_bits
            )));
        }
        if left_word.counterparty_commitment != right_word.share_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT counterparty commitment does not match remote share commitment"
                    .to_string(),
            ));
        }
        let expected_left_commitment = commit_word(
            local.owner,
            b"left",
            left_word.share_word,
            &left_word.provenance_digest,
        );
        if left_word.share_commitment != expected_left_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT left-share commitment is invalid".to_string(),
            ));
        }
        words.push(DdhHssSharedWord {
            width_bits: left_word.width_bits,
            left_word: left_word.share_word,
            right_word: right_word.share_word,
            left_commitment: left_word.share_commitment,
            right_commitment: right_word.share_commitment,
            provenance_digest: left_word.provenance_digest,
        });
    }

    let commitment = input_commitment_for_key(
        evaluation_key,
        HiddenEvalInputOwner::Client,
        &local.label,
        &words,
    );
    Ok(DdhHssInputShareBundle {
        owner: HiddenEvalInputOwner::Client,
        label: local.label.clone(),
        words,
        commitment,
    })
}

fn reconstruct_client_ot_bundle_timed_public(
    evaluation_key: &DdhHssEvaluationKey,
    expected_context_binding: [u8; 32],
    response: &DdhHssOtResponseBundle,
    local_state: &DdhHssOtReceiverStateBundle,
    remote: &DdhHssOtReleasedRemoteBundle,
) -> ProtoResult<(DdhHssInputShareBundle, DdhHssOtReconstructTiming)> {
    let mut timing = DdhHssOtReconstructTiming::default();
    let commitment_started = monotonic_now_ns();
    if remote.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release context binding is invalid".to_string(),
        ));
    }
    if response.owner != HiddenEvalInputOwner::Client
        || local_state.owner != HiddenEvalInputOwner::Client
        || remote.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "client OT reconstruction requires client-owned bundles".to_string(),
        ));
    }
    if response.label != local_state.label || response.label != remote.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT reconstruction labels do not match: response={} local={} remote={}",
            response.label, local_state.label, remote.label
        )));
    }
    if remote.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release must carry the right share".to_string(),
        ));
    }
    if response.words.len() != local_state.words.len() || response.words.len() != remote.words.len()
    {
        return Err(ProtoError::InvalidInput(format!(
            "client OT reconstruction word counts do not match: response={} local={} remote={}",
            response.words.len(),
            local_state.words.len(),
            remote.words.len()
        )));
    }
    if response.commitment
        != ot_response_bundle_commitment(response.owner, &response.label, &response.words)
    {
        return Err(ProtoError::InvalidInput(
            "client OT response commitment is invalid".to_string(),
        ));
    }
    if local_state.commitment
        != ot_receiver_state_bundle_commitment(
            local_state.owner,
            &local_state.label,
            &local_state.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT local state commitment is invalid".to_string(),
        ));
    }
    if remote.commitment
        != ot_remote_bundle_commitment(
            remote.owner,
            &remote.label,
            remote.share_side,
            &remote.words,
        )
    {
        return Err(ProtoError::InvalidInput(
            "client OT remote bundle commitment is invalid".to_string(),
        ));
    }
    let expected_remote_binding = ot_remote_release_transcript_binding(
        remote.context_binding,
        remote.owner,
        &remote.label,
        remote.offer_commitment,
        remote.request_commitment,
        remote.response_commitment,
        remote.commitment,
    );
    if remote.transcript_binding != expected_remote_binding {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release transcript binding is invalid".to_string(),
        ));
    }
    timing.commitment_verification_duration_ns = timing
        .commitment_verification_duration_ns
        .saturating_add(elapsed_ns_u64(commitment_started));

    let mut words = Vec::with_capacity(response.words.len());
    for (bit_idx, ((response_word, state_word), right_word)) in response
        .words
        .iter()
        .zip(&local_state.words)
        .zip(&remote.words)
        .enumerate()
    {
        if response_word.width_bits != 1 || state_word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response words must be 1-bit at index {bit_idx}"
            )));
        }
        if state_word.selected_branch > 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT local state branch must be 0 or 1 at index {bit_idx}, got {}",
                state_word.selected_branch
            )));
        }
        let selected_branch = if state_word.selected_branch == 0 {
            &response_word.zero_branch
        } else {
            &response_word.one_branch
        };
        let key_derivation_started = monotonic_now_ns();
        let key = derive_ot_branch_key_from_point_for_key(
            evaluation_key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            state_word.shared_point,
        );
        timing.branch_key_derivation_duration_ns = timing
            .branch_key_derivation_duration_ns
            .saturating_add(elapsed_ns_u64(key_derivation_started));
        let branch_decrypt_started = monotonic_now_ns();
        let payload = DdhHssBackend::open_ot_branch_with_key(
            key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            selected_branch,
        )?;
        timing.branch_decrypt_duration_ns = timing
            .branch_decrypt_duration_ns
            .saturating_add(elapsed_ns_u64(branch_decrypt_started));
        let branch_verify_started = monotonic_now_ns();
        if payload.width_bits != right_word.width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "client OT word widths do not match: {} vs {}",
                payload.width_bits, right_word.width_bits
            )));
        }
        if payload.counterparty_commitment != right_word.share_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT counterparty commitment does not match remote share commitment"
                    .to_string(),
            ));
        }
        let expected_left_commitment = commit_word(
            HiddenEvalInputOwner::Client,
            b"left",
            payload.share_word,
            &payload.provenance_digest,
        );
        if payload.share_commitment != expected_left_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT left-share commitment is invalid".to_string(),
            ));
        }
        timing.commitment_verification_duration_ns = timing
            .commitment_verification_duration_ns
            .saturating_add(elapsed_ns_u64(branch_verify_started));
        words.push(DdhHssSharedWord {
            width_bits: payload.width_bits,
            left_word: payload.share_word,
            right_word: right_word.share_word,
            left_commitment: payload.share_commitment,
            right_commitment: right_word.share_commitment,
            provenance_digest: payload.provenance_digest,
        });
    }

    let final_commitment_started = monotonic_now_ns();
    let commitment = input_commitment_for_key(
        evaluation_key,
        HiddenEvalInputOwner::Client,
        &response.label,
        &words,
    );
    timing.commitment_verification_duration_ns = timing
        .commitment_verification_duration_ns
        .saturating_add(elapsed_ns_u64(final_commitment_started));
    Ok((
        DdhHssInputShareBundle {
            owner: HiddenEvalInputOwner::Client,
            label: response.label.clone(),
            words,
            commitment,
        },
        timing,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
fn reconstruct_client_ot_bundle_timed_trusted_public(
    evaluation_key: &DdhHssEvaluationKey,
    expected_context_binding: [u8; 32],
    response: &DdhHssOtResponseBundle,
    local_state: &DdhHssOtReceiverStateBundle,
    remote: &DdhHssOtReleasedRemoteBundle,
) -> ProtoResult<(DdhHssInputShareBundle, DdhHssOtReconstructTiming)> {
    let mut timing = DdhHssOtReconstructTiming::default();
    if remote.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release context binding is invalid".to_string(),
        ));
    }
    if response.owner != HiddenEvalInputOwner::Client
        || local_state.owner != HiddenEvalInputOwner::Client
        || remote.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "client OT reconstruction requires client-owned bundles".to_string(),
        ));
    }
    if response.label != local_state.label || response.label != remote.label {
        return Err(ProtoError::InvalidInput(format!(
            "client OT reconstruction labels do not match: response={} local={} remote={}",
            response.label, local_state.label, remote.label
        )));
    }
    if remote.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "client OT remote-share release must carry the right share".to_string(),
        ));
    }
    if response.words.len() != local_state.words.len() || response.words.len() != remote.words.len()
    {
        return Err(ProtoError::InvalidInput(format!(
            "client OT reconstruction word counts do not match: response={} local={} remote={}",
            response.words.len(),
            local_state.words.len(),
            remote.words.len()
        )));
    }

    let mut words = Vec::with_capacity(response.words.len());
    for (bit_idx, ((response_word, state_word), right_word)) in response
        .words
        .iter()
        .zip(&local_state.words)
        .zip(&remote.words)
        .enumerate()
    {
        if response_word.width_bits != 1 || state_word.width_bits != 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT response words must be 1-bit at index {bit_idx}"
            )));
        }
        if state_word.selected_branch > 1 {
            return Err(ProtoError::InvalidInput(format!(
                "client OT local state branch must be 0 or 1 at index {bit_idx}, got {}",
                state_word.selected_branch
            )));
        }
        let selected_branch = if state_word.selected_branch == 0 {
            &response_word.zero_branch
        } else {
            &response_word.one_branch
        };
        let key_derivation_started = monotonic_now_ns();
        let key = derive_ot_branch_key_from_point_for_key(
            evaluation_key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            state_word.shared_point,
        );
        timing.branch_key_derivation_duration_ns = timing
            .branch_key_derivation_duration_ns
            .saturating_add(elapsed_ns_u64(key_derivation_started));
        let branch_decrypt_started = monotonic_now_ns();
        let payload = DdhHssBackend::open_ot_branch_with_key(
            key,
            HiddenEvalInputOwner::Client,
            &response.label,
            bit_idx,
            state_word.selected_branch,
            selected_branch,
        )?;
        timing.branch_decrypt_duration_ns = timing
            .branch_decrypt_duration_ns
            .saturating_add(elapsed_ns_u64(branch_decrypt_started));
        let branch_verify_started = monotonic_now_ns();
        if payload.width_bits != right_word.width_bits {
            return Err(ProtoError::InvalidInput(format!(
                "client OT word widths do not match: {} vs {}",
                payload.width_bits, right_word.width_bits
            )));
        }
        if payload.counterparty_commitment != right_word.share_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT counterparty commitment does not match remote share commitment"
                    .to_string(),
            ));
        }
        let expected_left_commitment = commit_word(
            HiddenEvalInputOwner::Client,
            b"left",
            payload.share_word,
            &payload.provenance_digest,
        );
        if payload.share_commitment != expected_left_commitment {
            return Err(ProtoError::InvalidInput(
                "client OT left-share commitment is invalid".to_string(),
            ));
        }
        timing.commitment_verification_duration_ns = timing
            .commitment_verification_duration_ns
            .saturating_add(elapsed_ns_u64(branch_verify_started));
        words.push(DdhHssSharedWord {
            width_bits: payload.width_bits,
            left_word: payload.share_word,
            right_word: right_word.share_word,
            left_commitment: payload.share_commitment,
            right_commitment: right_word.share_commitment,
            provenance_digest: payload.provenance_digest,
        });
    }

    let final_commitment_started = monotonic_now_ns();
    let commitment = input_commitment_for_key(
        evaluation_key,
        HiddenEvalInputOwner::Client,
        &response.label,
        &words,
    );
    timing.commitment_verification_duration_ns = timing
        .commitment_verification_duration_ns
        .saturating_add(elapsed_ns_u64(final_commitment_started));
    Ok((
        DdhHssInputShareBundle {
            owner: HiddenEvalInputOwner::Client,
            label: response.label.clone(),
            words,
            commitment,
        },
        timing,
    ))
}

fn join_share_bundle_public(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<DdhHssInputShareBundle> {
    validate_transport_bundle_pair_public(evaluation_key, left, right)?;

    let mut words = Vec::with_capacity(left.words.len());
    for (left_word, right_word) in left.words.iter().zip(&right.words) {
        words.push(join_transport_word_pair_public(
            left.owner,
            right.owner,
            left_word,
            right_word,
        )?);
    }

    Ok(DdhHssInputShareBundle {
        owner: left.owner,
        label: left.label.clone(),
        words,
        commitment: left.commitment,
    })
}

pub(crate) fn join_transport_word_pair_public(
    left_owner: HiddenEvalInputOwner,
    right_owner: HiddenEvalInputOwner,
    left_word: &DdhHssTransportWord,
    right_word: &DdhHssTransportWord,
) -> ProtoResult<DdhHssSharedWord> {
    validate_transport_word_pair_public(left_owner, right_owner, left_word, right_word)?;

    Ok(DdhHssSharedWord {
        width_bits: left_word.width_bits,
        left_word: left_word.share_word,
        right_word: right_word.share_word,
        left_commitment: left_word.share_commitment,
        right_commitment: right_word.share_commitment,
        provenance_digest: left_word.provenance_digest,
    })
}

pub(crate) fn validate_transport_word_pair_public(
    left_owner: HiddenEvalInputOwner,
    right_owner: HiddenEvalInputOwner,
    left_word: &DdhHssTransportWord,
    right_word: &DdhHssTransportWord,
) -> ProtoResult<()> {
    if left_word.width_bits != right_word.width_bits {
        return Err(ProtoError::InvalidInput(format!(
            "transport word widths do not match: {} vs {}",
            left_word.width_bits, right_word.width_bits
        )));
    }
    if left_word.share_side != DdhHssShareSide::Left
        || right_word.share_side != DdhHssShareSide::Right
    {
        return Err(ProtoError::InvalidInput(
            "transport words must be joined in left/right order".to_string(),
        ));
    }
    if left_word.provenance_digest != right_word.provenance_digest {
        return Err(ProtoError::InvalidInput(
            "transport word provenance digests do not match".to_string(),
        ));
    }

    let expected_left_commitment = commit_word(
        left_owner,
        b"left",
        left_word.share_word,
        &left_word.provenance_digest,
    );
    let expected_right_commitment = commit_word(
        right_owner,
        b"right",
        right_word.share_word,
        &right_word.provenance_digest,
    );
    if left_word.share_commitment != expected_left_commitment
        || right_word.share_commitment != expected_right_commitment
    {
        return Err(ProtoError::InvalidInput(
            "transport word commitments are invalid".to_string(),
        ));
    }
    if left_word.counterparty_commitment != right_word.share_commitment
        || right_word.counterparty_commitment != left_word.share_commitment
    {
        return Err(ProtoError::InvalidInput(
            "transport word counterparty commitments do not match".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_transport_bundle_pair_public(
    evaluation_key: &DdhHssEvaluationKey,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<()> {
    if left.owner != right.owner {
        return Err(ProtoError::InvalidInput(format!(
            "transport bundle owners do not match: {:?} vs {:?}",
            left.owner, right.owner
        )));
    }
    if left.label != right.label {
        return Err(ProtoError::InvalidInput(format!(
            "transport bundle labels do not match: {} vs {}",
            left.label, right.label
        )));
    }
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "transport bundles must be joined in left/right order".to_string(),
        ));
    }
    if left.commitment != right.commitment {
        return Err(ProtoError::InvalidInput(
            "transport bundle commitments do not match".to_string(),
        ));
    }
    if left.words.len() != right.words.len() {
        return Err(ProtoError::InvalidInput(format!(
            "transport bundle word counts do not match: {} vs {}",
            left.words.len(),
            right.words.len()
        )));
    }

    for (left_word, right_word) in left.words.iter().zip(&right.words) {
        let _ = join_transport_word_pair_public(left.owner, right.owner, left_word, right_word)?;
    }

    let joint_words = left
        .words
        .iter()
        .zip(&right.words)
        .map(|(left_word, right_word)| {
            join_transport_word_pair_public(left.owner, right.owner, left_word, right_word)
        })
        .collect::<ProtoResult<Vec<_>>>()?;
    let expected_commitment =
        input_commitment_for_key(evaluation_key, left.owner, &left.label, &joint_words);
    if expected_commitment != left.commitment {
        return Err(ProtoError::InvalidInput(
            "reconstructed input bundle commitment is invalid".to_string(),
        ));
    }

    Ok(())
}

fn seal_transport_message_with_key(
    transport_key: &DdhHssTransportKey,
    purpose: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> ProtoResult<([u8; 12], Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new(&transport_key.0.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|err| {
            ProtoError::Decode(format!(
                "failed to seal DDH transport message for {purpose}: {err}"
            ))
        })?;
    Ok((nonce, ciphertext))
}

fn open_transport_message_with_key(
    transport_key: &DdhHssTransportKey,
    purpose: &str,
    aad: &[u8],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> ProtoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&transport_key.0.into());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|err| {
            ProtoError::Decode(format!(
                "failed to open DDH transport message for {purpose}: {err}"
            ))
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
        .unwrap_or_else(|| (js_sys::Date::now() * 1_000_000.0) as u128)
}

fn elapsed_ns_u64(started_ns: u128) -> u64 {
    monotonic_now_ns()
        .saturating_sub(started_ns)
        .min(u64::MAX as u128) as u64
}

fn transport_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    share_side: DdhHssShareSide,
    words: &[DdhHssTransportWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/transport-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(
        b"share_side",
        match share_side {
            DdhHssShareSide::Left => b"left",
            DdhHssShareSide::Right => b"right",
        },
    );
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"share_word", &word.share_word.to_le_bytes());
        transcript.append_message(b"share_commitment", &word.share_commitment);
        transcript.append_message(b"counterparty_commitment", &word.counterparty_commitment);
        transcript.append_message(b"provenance_digest", &word.provenance_digest);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"transport_bundle_commitment", &mut out);
    out
}

fn ot_branch_aad(
    owner: HiddenEvalInputOwner,
    label: &str,
    bit_idx: usize,
    branch_bit: u8,
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-branch-aad/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"bit_idx", &(bit_idx as u64).to_le_bytes());
    transcript.append_message(b"branch_bit", &[branch_bit]);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_branch_aad", &mut out);
    out
}

fn prepare_ot_branch(
    owner: HiddenEvalInputOwner,
    label: &str,
    bit_idx: usize,
    branch_bit: u8,
    payload: &DdhHssOtBranchPayload,
) -> DdhHssPreparedOtBranch {
    let plaintext = encode_ot_branch_payload(payload);
    let payload_digest = Sha256::digest(plaintext);
    let mut payload_digest_array = [0u8; 32];
    payload_digest_array.copy_from_slice(&payload_digest);
    DdhHssPreparedOtBranch {
        aad: ot_branch_aad(owner, label, bit_idx, branch_bit),
        plaintext,
        payload_digest: payload_digest_array,
    }
}

fn encode_ot_branch_payload(
    payload: &DdhHssOtBranchPayload,
) -> [u8; DDH_HSS_OT_BRANCH_PAYLOAD_BYTES] {
    let mut out = [0u8; DDH_HSS_OT_BRANCH_PAYLOAD_BYTES];
    out[0..2].copy_from_slice(&payload.width_bits.to_le_bytes());
    out[2..10].copy_from_slice(&payload.share_word.to_le_bytes());
    out[10..42].copy_from_slice(&payload.share_commitment);
    out[42..74].copy_from_slice(&payload.counterparty_commitment);
    out[74..106].copy_from_slice(&payload.provenance_digest);
    out
}

fn decode_ot_branch_payload(bytes: &[u8]) -> Result<DdhHssOtBranchPayload, &'static str> {
    if bytes.len() != DDH_HSS_OT_BRANCH_PAYLOAD_BYTES {
        return Err("invalid OT branch payload length");
    }
    let mut share_commitment = [0u8; 32];
    share_commitment.copy_from_slice(&bytes[10..42]);
    let mut counterparty_commitment = [0u8; 32];
    counterparty_commitment.copy_from_slice(&bytes[42..74]);
    let mut provenance_digest = [0u8; 32];
    provenance_digest.copy_from_slice(&bytes[74..106]);
    Ok(DdhHssOtBranchPayload {
        width_bits: u16::from_le_bytes(bytes[0..2].try_into().expect("slice width")),
        share_word: u64::from_le_bytes(bytes[2..10].try_into().expect("slice word")),
        share_commitment,
        counterparty_commitment,
        provenance_digest,
    })
}

fn ot_offer_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtWordOffer],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-offer-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"sender_public", &word.sender_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_offer_bundle_commitment", &mut out);
    out
}

fn ot_remote_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    share_side: DdhHssShareSide,
    words: &[DdhHssOtRemoteWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-remote-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(
        b"share_side",
        match share_side {
            DdhHssShareSide::Left => b"left",
            DdhHssShareSide::Right => b"right",
        },
    );
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"share_word", &word.share_word.to_le_bytes());
        transcript.append_message(b"share_commitment", &word.share_commitment);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_remote_bundle_commitment", &mut out);
    out
}

fn ot_request_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtSelectionWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-request-bundle/v1");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"receiver_public", &word.receiver_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_request_bundle_commitment", &mut out);
    out
}

fn ot_receiver_state_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtReceiverStateWord],
) -> [u8; 32] {
    let mut transcript =
        Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-receiver-state-bundle/v1");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"selected_branch", &[word.selected_branch]);
        transcript.append_message(b"shared_point", &word.shared_point);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_receiver_state_bundle_commitment", &mut out);
    out
}

fn ot_sender_state_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtSenderStateWord],
) -> [u8; 32] {
    let mut transcript =
        Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-sender-state-bundle/v0");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"sender_scalar", &word.sender_scalar);
        transcript.append_message(b"sender_public", &word.sender_public);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_sender_state_bundle_commitment", &mut out);
    out
}

fn ot_response_bundle_commitment(
    owner: HiddenEvalInputOwner,
    label: &str,
    words: &[DdhHssOtResponseWord],
) -> [u8; 32] {
    let mut transcript = Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-response-bundle/v1");
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"word_count", &(words.len() as u64).to_le_bytes());
    for word in words {
        transcript.append_message(b"width_bits", &word.width_bits.to_le_bytes());
        transcript.append_message(b"zero_nonce", &word.zero_branch.nonce);
        transcript.append_message(b"zero_payload_digest", &word.zero_branch.payload_digest);
        transcript.append_message(
            b"zero_ciphertext_len",
            &(word.zero_branch.ciphertext.len() as u64).to_le_bytes(),
        );
        transcript.append_message(b"zero_ciphertext", &word.zero_branch.ciphertext);
        transcript.append_message(b"one_nonce", &word.one_branch.nonce);
        transcript.append_message(b"one_payload_digest", &word.one_branch.payload_digest);
        transcript.append_message(
            b"one_ciphertext_len",
            &(word.one_branch.ciphertext.len() as u64).to_le_bytes(),
        );
        transcript.append_message(b"one_ciphertext", &word.one_branch.ciphertext);
    }
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_response_bundle_commitment", &mut out);
    out
}

fn ot_remote_release_transcript_binding(
    context_binding: [u8; 32],
    owner: HiddenEvalInputOwner,
    label: &str,
    offer_commitment: [u8; 32],
    request_commitment: [u8; 32],
    response_commitment: [u8; 32],
    remote_commitment: [u8; 32],
) -> [u8; 32] {
    let mut transcript =
        Transcript::new(b"succinct-garbling-proto/ddh-hss/ot-remote-release-binding/v0");
    transcript.append_message(b"context_binding", &context_binding);
    transcript.append_message(b"owner", owner_tag(owner));
    transcript.append_message(b"label", label.as_bytes());
    transcript.append_message(b"offer_commitment", &offer_commitment);
    transcript.append_message(b"request_commitment", &request_commitment);
    transcript.append_message(b"response_commitment", &response_commitment);
    transcript.append_message(b"remote_commitment", &remote_commitment);
    let mut out = [0u8; 32];
    transcript.challenge_bytes(b"ot_remote_release_binding", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::{
            decode_prime_order_size_optimized_artifact,
            materialize_prime_order_size_optimized_bytes,
        },
        candidate::build_fixed_hidden_core_candidate,
        ddh::compile_prime_order_hidden_eval_program,
        fixtures::deterministic_fixture_corpus,
    };

    fn test_backend() -> DdhHssBackend {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
        let candidate =
            build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
        let bytes =
            materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
        let decoded =
            decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");
        let program = compile_prime_order_hidden_eval_program(&decoded).expect("hidden-eval IR");
        keygen_prime_order_ddh_hss_backend(
            candidate.context_binding,
            candidate.template.candidate_digest,
            &program,
        )
        .expect("DDH keygen")
    }

    #[test]
    fn local_share_mul_with_open_recombines_to_shared_bit_product() {
        let backend = test_backend();

        for (idx, (left_value, right_value)) in [(0u64, 0u64), (0, 1), (1, 0), (1, 1)]
            .into_iter()
            .enumerate()
        {
            let left = backend
                .share_word(
                    HiddenEvalInputOwner::Client,
                    &format!("local/left/{idx}"),
                    left_value,
                    1,
                )
                .expect("share left");
            let right = backend
                .share_word(
                    HiddenEvalInputOwner::Server,
                    &format!("local/right/{idx}"),
                    right_value,
                    1,
                )
                .expect("share right");
            let left_local_left = local_word_from_shared(&left, DdhHssShareSide::Left);
            let left_local_right = local_word_from_shared(&left, DdhHssShareSide::Right);
            let right_local_left = local_word_from_shared(&right, DdhHssShareSide::Left);
            let right_local_right = local_word_from_shared(&right, DdhHssShareSide::Right);
            let left_derived = derived_word_from_shared(&left);
            let right_derived = derived_word_from_shared(&right);
            let (material_left, material_right) = prepare_local_bit_mul_material_public(
                backend.evaluation_key(),
                format!("local/{idx}/mul").as_bytes(),
                &left_local_left,
                &left_local_right,
                &right_local_left,
                &right_local_right,
            )
            .expect("prepare local mul material");

            assert_eq!(
                join_local_word_pair_as_derived(&left_local_left, &left_local_right)
                    .expect("join left input"),
                left_derived
            );
            assert_eq!(
                join_local_word_pair_as_derived(&right_local_left, &right_local_right)
                    .expect("join right input"),
                right_derived
            );

            let d_label = format!("local/{idx}/d");
            let d_left = eval_add_local_mod_2_pow_n_public(
                backend.evaluation_key(),
                d_label.as_bytes(),
                &left_local_left,
                &material_left.triple_a,
            )
            .expect("left d");
            let d_right = eval_add_local_mod_2_pow_n_public(
                backend.evaluation_key(),
                d_label.as_bytes(),
                &left_local_right,
                &material_right.triple_a,
            )
            .expect("right d");
            let e_label = format!("local/{idx}/e");
            let e_left = eval_add_local_mod_2_pow_n_public(
                backend.evaluation_key(),
                e_label.as_bytes(),
                &right_local_left,
                &material_left.triple_b,
            )
            .expect("left e");
            let e_right = eval_add_local_mod_2_pow_n_public(
                backend.evaluation_key(),
                e_label.as_bytes(),
                &right_local_right,
                &material_right.triple_b,
            )
            .expect("right e");

            let d_open = open_local_word_pair_public(&d_left, &d_right).expect("open d");
            let e_open = open_local_word_pair_public(&e_left, &e_right).expect("open e");

            let mul_label = format!("local/{idx}/mul");
            let product_left = eval_mul_local_with_open_public(
                backend.evaluation_key(),
                mul_label.as_bytes(),
                &left_local_left,
                &right_local_left,
                &material_left,
                d_open,
                e_open,
            )
            .expect("left mul");
            let product_right = eval_mul_local_with_open_public(
                backend.evaluation_key(),
                mul_label.as_bytes(),
                &left_local_right,
                &right_local_right,
                &material_right,
                d_open,
                e_open,
            )
            .expect("right mul");

            let local_product = join_local_word_pair_as_derived(&product_left, &product_right)
                .expect("join local product");
            let expected_product = backend
                .eval_mul_bit(&format!("shared/{idx}/mul"), &left, &right)
                .expect("shared mul");

            assert_eq!(
                backend.decode_word(&shared_word_from_derived(&local_product)),
                left_value & right_value
            );
            assert_eq!(
                backend.decode_word(&shared_word_from_derived(&local_product)),
                backend.decode_word(&expected_product)
            );
            assert_eq!(
                local_product.left_commitment,
                commit_word(
                    HiddenEvalInputOwner::Derived,
                    b"left",
                    local_product.left_word,
                    &local_product.provenance_digest,
                )
            );
            assert_eq!(
                local_product.right_commitment,
                commit_word(
                    HiddenEvalInputOwner::Derived,
                    b"right",
                    local_product.right_word,
                    &local_product.provenance_digest,
                )
            );
        }
    }

    #[test]
    fn local_bit_mul_batch_matches_shared_bit_mul_batch() {
        let backend = test_backend();
        let left_words: Vec<_> = [0u64, 1, 1, 0, 1, 0, 0, 1]
            .into_iter()
            .enumerate()
            .map(|(idx, value)| {
                backend
                    .share_word(
                        HiddenEvalInputOwner::Client,
                        &format!("batch/left/{idx}"),
                        value,
                        1,
                    )
                    .expect("share left")
            })
            .collect();
        let right_words: Vec<_> = [1u64, 1, 0, 0, 1, 1, 0, 0]
            .into_iter()
            .enumerate()
            .map(|(idx, value)| {
                backend
                    .share_word(
                        HiddenEvalInputOwner::Server,
                        &format!("batch/right/{idx}"),
                        value,
                        1,
                    )
                    .expect("share right")
            })
            .collect();
        let left_derived: Vec<_> = left_words.iter().map(derived_word_from_shared).collect();
        let right_derived: Vec<_> = right_words.iter().map(derived_word_from_shared).collect();

        let local_batch = eval_mul_bit_derived_local_batch_public(
            backend.evaluation_key(),
            "batch/mul",
            &left_derived,
            &right_derived,
        )
        .expect("local batch mul");

        let shared_batch: Vec<_> = left_words
            .iter()
            .zip(right_words.iter())
            .enumerate()
            .map(|(idx, (left, right))| {
                backend
                    .eval_mul_bit(&format!("batch/shared/{idx}"), left, right)
                    .expect("shared mul")
            })
            .collect();

        let local_decoded: Vec<_> = local_batch
            .iter()
            .map(|word| backend.decode_word(&shared_word_from_derived(word)))
            .collect();
        let shared_decoded: Vec<_> = shared_batch
            .iter()
            .map(|word| backend.decode_word(word))
            .collect();
        assert_eq!(local_decoded, shared_decoded);
        assert_eq!(local_decoded, vec![0, 1, 0, 0, 1, 0, 0, 0]);
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtWordOfferCompact {
    sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtInputBundleOfferCompact {
    owner: HiddenEvalInputOwner,
    label: String,
    width_bits: u16,
    words: Vec<DdhHssOtWordOfferCompact>,
    commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtSenderStateWordCompact {
    sender_scalar: [u8; 32],
    sender_public: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DdhHssOtSenderStateBundleCompact {
    owner: HiddenEvalInputOwner,
    label: String,
    width_bits: u16,
    words: Vec<DdhHssOtSenderStateWordCompact>,
    commitment: [u8; 32],
}
