use core::fmt;

use k256::{
    elliptic_curve::{bigint::U512, ops::Reduce},
    Scalar, WideBytes,
};
use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::PresignPairContext;
use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proofs::TripleIndex;

use super::{
    ClientBaseRotReceiverOutput, ClientBaseRotSenderOutput, ReceiverKeys, ReceiverOutput,
    SenderKeys, SenderOutput, SigningWorkerBaseRotReceiverOutput, SigningWorkerBaseRotSenderOutput,
    BASE_OT_COUNT, BASE_OT_KEY_SIZE, CHOICE_BYTES, CLIENT_ROLE, SIGNING_WORKER_ROLE,
};

pub mod mta;

pub const EXTENDED_OT_COUNT: usize = 768;
pub const PADDED_OT_COUNT: usize = 1024;
pub const CORRELATION_MESSAGE_SIZE: usize = PADDED_OT_COUNT * 16;
pub const CONSISTENCY_VECTOR_SIZE: usize = 32;
const EXTENDED_CHOICE_BYTES: usize = EXTENDED_OT_COUNT / 8;
const PADDED_CHOICE_BYTES: usize = PADDED_OT_COUNT / 8;
const CONSISTENCY_CHUNKS: usize = PADDED_OT_COUNT / BASE_OT_COUNT;
const PRG_BLOCKS: usize = PADDED_OT_COUNT / 256;
const ROW_WORDS: usize = 2;
const DOUBLE_ROW_WORDS: usize = 4;
const EXTENSION_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/random-ot-extension/v1";
const ROW_PRG_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/random-ot-row-prg/v1";
const OUTPUT_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/random-ot-output/v1";
const ACCEPTANCE_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/random-ot-accept/v1";
const SUITE: &[u8] = b"secp256k1+sha256+sha512";

type SenderValues = [[Scalar; 2]; EXTENDED_OT_COUNT];
type ReceiverValues = [Scalar; EXTENDED_OT_COUNT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionError {
    ContextMismatch,
    TripleIndexMismatch,
    RoleMismatch,
    ConsistencyCheckFailed,
    AcceptanceMismatch,
}

impl fmt::Display for ExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextMismatch => "random OT extension context mismatch",
            Self::TripleIndexMismatch => "random OT extension triple index mismatch",
            Self::RoleMismatch => "random OT extension role mismatch",
            Self::ConsistencyCheckFailed => "random OT extension consistency check failed",
            Self::AcceptanceMismatch => "random OT extension acceptance mismatch",
        })
    }
}

impl std::error::Error for ExtensionError {}

#[derive(Clone, Copy, Zeroize)]
struct BitRow([u64; ROW_WORDS]);

impl BitRow {
    const ZERO: Self = Self([0; ROW_WORDS]);
    const ONES: Self = Self([u64::MAX; ROW_WORDS]);

    fn from_bytes(bytes: &[u8; 16]) -> Self {
        let mut words = [0u64; ROW_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().expect("fixed 8-byte chunk"));
        }
        Self(words)
    }

    fn into_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for (index, word) in self.0.into_iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn bit(&self, index: usize) -> Choice {
        Choice::from(((self.0[index / 64] >> (index % 64)) & 1) as u8)
    }

    fn xor(self, other: Self) -> Self {
        Self([self.0[0] ^ other.0[0], self.0[1] ^ other.0[1]])
    }

    fn and(self, other: Self) -> Self {
        Self([self.0[0] & other.0[0], self.0[1] & other.0[1]])
    }

    fn gf_mul(self, other: Self) -> DoubleBitRow {
        let mut output = [0u64; DOUBLE_ROW_WORDS];
        for bit_index in (0..64).rev() {
            for word_index in 0..ROW_WORDS {
                let bit = Choice::from(((self.0[word_index] >> bit_index) & 1) as u8);
                let selected = Self::conditional_select(&Self::ZERO, &other, bit);
                for other_index in 0..ROW_WORDS {
                    output[word_index + other_index] ^= selected.0[other_index];
                }
            }
            if bit_index != 0 {
                let mut carry = 0u64;
                for word in &mut output {
                    let next = *word >> 63;
                    *word = (*word << 1) | carry;
                    carry = next;
                }
            }
        }
        DoubleBitRow(output)
    }
}

impl ConditionallySelectable for BitRow {
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        Self([
            u64::conditional_select(&left.0[0], &right.0[0], choice),
            u64::conditional_select(&left.0[1], &right.0[1], choice),
        ])
    }
}

#[derive(Clone, Copy, Zeroize)]
struct DoubleBitRow([u64; DOUBLE_ROW_WORDS]);

impl DoubleBitRow {
    const ZERO: Self = Self([0; DOUBLE_ROW_WORDS]);

    fn from_bytes(bytes: &[u8; CONSISTENCY_VECTOR_SIZE]) -> Self {
        let mut words = [0u64; DOUBLE_ROW_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().expect("fixed 8-byte chunk"));
        }
        Self(words)
    }

    fn into_bytes(self) -> [u8; CONSISTENCY_VECTOR_SIZE] {
        let mut bytes = [0u8; CONSISTENCY_VECTOR_SIZE];
        for (index, word) in self.0.into_iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn xor(self, other: Self) -> Self {
        Self([
            self.0[0] ^ other.0[0],
            self.0[1] ^ other.0[1],
            self.0[2] ^ other.0[2],
            self.0[3] ^ other.0[3],
        ])
    }
}

impl ConditionallySelectable for DoubleBitRow {
    fn conditional_select(left: &Self, right: &Self, choice: Choice) -> Self {
        let mut words = [0u64; DOUBLE_ROW_WORDS];
        for ((target, left), right) in words.iter_mut().zip(left.0).zip(right.0) {
            *target = u64::conditional_select(&left, &right, choice);
        }
        Self(words)
    }
}

impl ConstantTimeEq for DoubleBitRow {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut equal = Choice::from(1);
        for (left, right) in self.0.iter().zip(other.0.iter()) {
            equal &= left.ct_eq(right);
        }
        equal
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretMatrix(Box<[BitRow; PADDED_OT_COUNT]>);

impl SecretMatrix {
    fn zero() -> Self {
        Self(Box::new([BitRow::ZERO; PADDED_OT_COUNT]))
    }

    fn from_bytes(bytes: &[u8; CORRELATION_MESSAGE_SIZE]) -> Self {
        let mut matrix = Self::zero();
        for (row, chunk) in matrix.0.iter_mut().zip(bytes.chunks_exact(16)) {
            *row = BitRow::from_bytes(chunk.try_into().expect("fixed 16-byte row"));
        }
        matrix
    }

    fn to_bytes(&self) -> Box<[u8; CORRELATION_MESSAGE_SIZE]> {
        let mut bytes = Box::new([0u8; CORRELATION_MESSAGE_SIZE]);
        for (row, chunk) in self.0.iter().zip(bytes.chunks_exact_mut(16)) {
            chunk.copy_from_slice(&row.into_bytes());
        }
        bytes
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ChoiceBits([u8; PADDED_CHOICE_BYTES]);

impl ChoiceBits {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; PADDED_CHOICE_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn bit(&self, index: usize) -> Choice {
        Choice::from((self.0[index / 8] >> (index % 8)) & 1)
    }

    fn chunk(&self, chunk_index: usize) -> BitRow {
        let start = chunk_index * 16;
        BitRow::from_bytes(
            self.0[start..start + 16]
                .try_into()
                .expect("fixed 16-byte choice chunk"),
        )
    }

    fn output_prefix(&self) -> [u8; EXTENDED_CHOICE_BYTES] {
        let mut choices = [0u8; EXTENDED_CHOICE_BYTES];
        choices.copy_from_slice(&self.0[..EXTENDED_CHOICE_BYTES]);
        choices
    }
}

struct CorrelationMessage {
    context: PresignPairContext,
    triple_index: TripleIndex,
    matrix: SecretMatrix,
}

#[derive(Clone, Copy)]
struct ChallengeMessage {
    context: PresignPairContext,
    triple_index: TripleIndex,
    seed: [u8; 32],
}

struct ConsistencyProof {
    context: PresignPairContext,
    triple_index: TripleIndex,
    small_x: DoubleBitRow,
    small_t: Box<[DoubleBitRow; BASE_OT_COUNT]>,
}

#[derive(Clone, Copy)]
struct AcceptanceMessage {
    context: PresignPairContext,
    triple_index: TripleIndex,
    digest: [u8; 32],
}

struct ReceiverAwaitingChallenge {
    context: PresignPairContext,
    triple_index: TripleIndex,
    extension_sender_role: u8,
    choices: ChoiceBits,
    t0: SecretMatrix,
}

struct ReceiverAwaitingAcceptance {
    context: PresignPairContext,
    triple_index: TripleIndex,
    expected_digest: [u8; 32],
    output: ExtensionReceiverOutput,
}

struct SenderAwaitingProof {
    context: PresignPairContext,
    triple_index: TripleIndex,
    extension_sender_role: u8,
    delta: BitRow,
    q: SecretMatrix,
    challenge_seed: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ExtensionSenderOutput {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    sender_role: u8,
    values: SenderValues,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ExtensionReceiverOutput {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    sender_role: u8,
    choices: [u8; EXTENDED_CHOICE_BYTES],
    values: ReceiverValues,
}

pub struct ClientExtensionReceiverAwaitingChallenge(ReceiverAwaitingChallenge);
pub struct SigningWorkerExtensionReceiverAwaitingChallenge(ReceiverAwaitingChallenge);
pub struct ClientExtensionReceiverAwaitingAcceptance(ReceiverAwaitingAcceptance);
pub struct SigningWorkerExtensionReceiverAwaitingAcceptance(ReceiverAwaitingAcceptance);
pub struct ClientExtensionSenderAwaitingProof(SenderAwaitingProof);
pub struct SigningWorkerExtensionSenderAwaitingProof(SenderAwaitingProof);

pub struct ClientExtensionCorrelationMessage(CorrelationMessage);
pub struct SigningWorkerExtensionCorrelationMessage(CorrelationMessage);
pub struct ClientExtensionChallengeMessage(ChallengeMessage);
pub struct SigningWorkerExtensionChallengeMessage(ChallengeMessage);
pub struct ClientExtensionProofMessage(ConsistencyProof);
pub struct SigningWorkerExtensionProofMessage(ConsistencyProof);
pub struct ClientExtensionAcceptanceMessage(AcceptanceMessage);
pub struct SigningWorkerExtensionAcceptanceMessage(AcceptanceMessage);

#[allow(dead_code)]
pub struct ClientRandomOtSenderOutput(ExtensionSenderOutput);
#[allow(dead_code)]
pub struct SigningWorkerRandomOtSenderOutput(ExtensionSenderOutput);
#[allow(dead_code)]
pub struct ClientRandomOtReceiverOutput(ExtensionReceiverOutput);
#[allow(dead_code)]
pub struct SigningWorkerRandomOtReceiverOutput(ExtensionReceiverOutput);

macro_rules! define_correlation_message {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                matrix: Box<[u8; CORRELATION_MESSAGE_SIZE]>,
            ) -> Self {
                Self(CorrelationMessage {
                    context,
                    triple_index,
                    matrix: SecretMatrix::from_bytes(&matrix),
                })
            }

            pub fn into_parts(
                self,
            ) -> (
                PresignPairContext,
                TripleIndex,
                Box<[u8; CORRELATION_MESSAGE_SIZE]>,
            ) {
                (
                    self.0.context,
                    self.0.triple_index,
                    self.0.matrix.to_bytes(),
                )
            }
        }
    };
}

macro_rules! define_challenge_message {
    ($name:ident) => {
        impl $name {
            pub const fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                seed: [u8; 32],
            ) -> Self {
                Self(ChallengeMessage {
                    context,
                    triple_index,
                    seed,
                })
            }

            pub fn into_parts(self) -> (PresignPairContext, TripleIndex, [u8; 32]) {
                (self.0.context, self.0.triple_index, self.0.seed)
            }
        }
    };
}

macro_rules! define_proof_message {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                small_x: [u8; CONSISTENCY_VECTOR_SIZE],
                small_t: Box<[[u8; CONSISTENCY_VECTOR_SIZE]; BASE_OT_COUNT]>,
            ) -> Self {
                let mut parsed = Box::new([DoubleBitRow::ZERO; BASE_OT_COUNT]);
                for (target, encoded) in parsed.iter_mut().zip(small_t.iter()) {
                    *target = DoubleBitRow::from_bytes(encoded);
                }
                Self(ConsistencyProof {
                    context,
                    triple_index,
                    small_x: DoubleBitRow::from_bytes(&small_x),
                    small_t: parsed,
                })
            }

            pub fn into_parts(
                self,
            ) -> (
                PresignPairContext,
                TripleIndex,
                [u8; CONSISTENCY_VECTOR_SIZE],
                Box<[[u8; CONSISTENCY_VECTOR_SIZE]; BASE_OT_COUNT]>,
            ) {
                let mut encoded = Box::new([[0u8; CONSISTENCY_VECTOR_SIZE]; BASE_OT_COUNT]);
                for (target, row) in encoded.iter_mut().zip(self.0.small_t.iter()) {
                    *target = row.into_bytes();
                }
                (
                    self.0.context,
                    self.0.triple_index,
                    self.0.small_x.into_bytes(),
                    encoded,
                )
            }
        }
    };
}

macro_rules! define_acceptance_message {
    ($name:ident) => {
        impl $name {
            pub const fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                digest: [u8; 32],
            ) -> Self {
                Self(AcceptanceMessage {
                    context,
                    triple_index,
                    digest,
                })
            }

            pub fn into_parts(self) -> (PresignPairContext, TripleIndex, [u8; 32]) {
                (self.0.context, self.0.triple_index, self.0.digest)
            }
        }
    };
}

define_correlation_message!(ClientExtensionCorrelationMessage);
define_correlation_message!(SigningWorkerExtensionCorrelationMessage);
define_challenge_message!(ClientExtensionChallengeMessage);
define_challenge_message!(SigningWorkerExtensionChallengeMessage);
define_proof_message!(ClientExtensionProofMessage);
define_proof_message!(SigningWorkerExtensionProofMessage);
define_acceptance_message!(ClientExtensionAcceptanceMessage);
define_acceptance_message!(SigningWorkerExtensionAcceptanceMessage);

pub fn start_client_extension_receiver(
    base_output: ClientBaseRotSenderOutput,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        ClientExtensionReceiverAwaitingChallenge,
        ClientExtensionCorrelationMessage,
    ),
    ExtensionError,
> {
    let (state, message) = start_receiver(base_output.0, CLIENT_ROLE, rng)?;
    Ok((
        ClientExtensionReceiverAwaitingChallenge(state),
        ClientExtensionCorrelationMessage(message),
    ))
}

pub fn start_signing_worker_extension_receiver(
    base_output: SigningWorkerBaseRotSenderOutput,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerExtensionReceiverAwaitingChallenge,
        SigningWorkerExtensionCorrelationMessage,
    ),
    ExtensionError,
> {
    let (state, message) = start_receiver(base_output.0, SIGNING_WORKER_ROLE, rng)?;
    Ok((
        SigningWorkerExtensionReceiverAwaitingChallenge(state),
        SigningWorkerExtensionCorrelationMessage(message),
    ))
}

pub fn start_client_extension_sender(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    base_output: ClientBaseRotReceiverOutput,
    correlation: SigningWorkerExtensionCorrelationMessage,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        ClientExtensionSenderAwaitingProof,
        ClientExtensionChallengeMessage,
    ),
    ExtensionError,
> {
    let (state, message) = start_sender(
        expected_context,
        expected_triple_index,
        CLIENT_ROLE,
        base_output.0,
        correlation.0,
        rng,
    )?;
    Ok((
        ClientExtensionSenderAwaitingProof(state),
        ClientExtensionChallengeMessage(message),
    ))
}

pub fn start_signing_worker_extension_sender(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    base_output: SigningWorkerBaseRotReceiverOutput,
    correlation: ClientExtensionCorrelationMessage,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerExtensionSenderAwaitingProof,
        SigningWorkerExtensionChallengeMessage,
    ),
    ExtensionError,
> {
    let (state, message) = start_sender(
        expected_context,
        expected_triple_index,
        SIGNING_WORKER_ROLE,
        base_output.0,
        correlation.0,
        rng,
    )?;
    Ok((
        SigningWorkerExtensionSenderAwaitingProof(state),
        SigningWorkerExtensionChallengeMessage(message),
    ))
}

impl ClientExtensionReceiverAwaitingChallenge {
    pub fn receive(
        self,
        challenge: SigningWorkerExtensionChallengeMessage,
    ) -> Result<
        (
            ClientExtensionReceiverAwaitingAcceptance,
            ClientExtensionProofMessage,
        ),
        ExtensionError,
    > {
        let (state, proof) = receive_challenge(self.0, challenge.0)?;
        Ok((
            ClientExtensionReceiverAwaitingAcceptance(state),
            ClientExtensionProofMessage(proof),
        ))
    }
}

impl SigningWorkerExtensionReceiverAwaitingChallenge {
    pub fn receive(
        self,
        challenge: ClientExtensionChallengeMessage,
    ) -> Result<
        (
            SigningWorkerExtensionReceiverAwaitingAcceptance,
            SigningWorkerExtensionProofMessage,
        ),
        ExtensionError,
    > {
        let (state, proof) = receive_challenge(self.0, challenge.0)?;
        Ok((
            SigningWorkerExtensionReceiverAwaitingAcceptance(state),
            SigningWorkerExtensionProofMessage(proof),
        ))
    }
}

impl ClientExtensionSenderAwaitingProof {
    pub fn receive(
        self,
        proof: SigningWorkerExtensionProofMessage,
    ) -> Result<(ClientRandomOtSenderOutput, ClientExtensionAcceptanceMessage), ExtensionError>
    {
        let (output, acceptance) = receive_proof(self.0, proof.0)?;
        Ok((
            ClientRandomOtSenderOutput(output),
            ClientExtensionAcceptanceMessage(acceptance),
        ))
    }
}

impl SigningWorkerExtensionSenderAwaitingProof {
    pub fn receive(
        self,
        proof: ClientExtensionProofMessage,
    ) -> Result<
        (
            SigningWorkerRandomOtSenderOutput,
            SigningWorkerExtensionAcceptanceMessage,
        ),
        ExtensionError,
    > {
        let (output, acceptance) = receive_proof(self.0, proof.0)?;
        Ok((
            SigningWorkerRandomOtSenderOutput(output),
            SigningWorkerExtensionAcceptanceMessage(acceptance),
        ))
    }
}

impl ClientExtensionReceiverAwaitingAcceptance {
    pub fn receive(
        self,
        acceptance: SigningWorkerExtensionAcceptanceMessage,
    ) -> Result<ClientRandomOtReceiverOutput, ExtensionError> {
        receive_acceptance(self.0, acceptance.0).map(ClientRandomOtReceiverOutput)
    }
}

impl SigningWorkerExtensionReceiverAwaitingAcceptance {
    pub fn receive(
        self,
        acceptance: ClientExtensionAcceptanceMessage,
    ) -> Result<SigningWorkerRandomOtReceiverOutput, ExtensionError> {
        receive_acceptance(self.0, acceptance.0).map(SigningWorkerRandomOtReceiverOutput)
    }
}

#[cfg(any(test, feature = "test-utils"))]
macro_rules! define_sender_test_parts {
    ($name:ident) => {
        impl $name {
            pub fn into_test_values(self) -> SenderValues {
                self.0.values
            }
        }
    };
}

#[cfg(any(test, feature = "test-utils"))]
macro_rules! define_receiver_test_parts {
    ($name:ident) => {
        impl $name {
            pub fn into_test_parts(self) -> ([u8; EXTENDED_CHOICE_BYTES], ReceiverValues) {
                (self.0.choices, self.0.values)
            }
        }
    };
}

#[cfg(any(test, feature = "test-utils"))]
define_sender_test_parts!(ClientRandomOtSenderOutput);
#[cfg(any(test, feature = "test-utils"))]
define_sender_test_parts!(SigningWorkerRandomOtSenderOutput);
#[cfg(any(test, feature = "test-utils"))]
define_receiver_test_parts!(ClientRandomOtReceiverOutput);
#[cfg(any(test, feature = "test-utils"))]
define_receiver_test_parts!(SigningWorkerRandomOtReceiverOutput);

fn start_receiver(
    base_output: SenderOutput,
    extension_receiver_role: u8,
    rng: &mut impl CryptoRngCore,
) -> Result<(ReceiverAwaitingChallenge, CorrelationMessage), ExtensionError> {
    if base_output.sender_role != extension_receiver_role {
        return Err(ExtensionError::RoleMismatch);
    }
    let extension_sender_role = opposite_role(extension_receiver_role);
    let choices = ChoiceBits::random(rng);
    let (t0, t1) = expand_pair_keys(
        base_output.context,
        base_output.triple_index,
        extension_sender_role,
        &base_output.keys,
    );
    let mut correlation = SecretMatrix::zero();
    for row_index in 0..PADDED_OT_COUNT {
        let choice_mask =
            BitRow::conditional_select(&BitRow::ZERO, &BitRow::ONES, choices.bit(row_index));
        correlation.0[row_index] = t0.0[row_index].xor(t1.0[row_index]).xor(choice_mask);
    }
    let state = ReceiverAwaitingChallenge {
        context: base_output.context,
        triple_index: base_output.triple_index,
        extension_sender_role,
        choices,
        t0,
    };
    let message = CorrelationMessage {
        context: base_output.context,
        triple_index: base_output.triple_index,
        matrix: correlation,
    };
    Ok((state, message))
}

fn start_sender(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    extension_sender_role: u8,
    base_output: ReceiverOutput,
    correlation: CorrelationMessage,
    rng: &mut impl CryptoRngCore,
) -> Result<(SenderAwaitingProof, ChallengeMessage), ExtensionError> {
    check_binding(
        expected_context,
        expected_triple_index,
        base_output.context,
        base_output.triple_index,
    )?;
    check_binding(
        expected_context,
        expected_triple_index,
        correlation.context,
        correlation.triple_index,
    )?;
    if base_output.sender_role != opposite_role(extension_sender_role) {
        return Err(ExtensionError::RoleMismatch);
    }
    let delta = BitRow::from_bytes(&base_output.choices);
    let t = expand_selected_keys(
        expected_context,
        expected_triple_index,
        extension_sender_role,
        &base_output.choices,
        &base_output.keys,
    );
    let mut q = SecretMatrix::zero();
    for row_index in 0..PADDED_OT_COUNT {
        q.0[row_index] = t.0[row_index].xor(correlation.matrix.0[row_index].and(delta));
    }
    let mut challenge_seed = [0u8; 32];
    rng.fill_bytes(&mut challenge_seed);
    Ok((
        SenderAwaitingProof {
            context: expected_context,
            triple_index: expected_triple_index,
            extension_sender_role,
            delta,
            q,
            challenge_seed,
        },
        ChallengeMessage {
            context: expected_context,
            triple_index: expected_triple_index,
            seed: challenge_seed,
        },
    ))
}

fn receive_challenge(
    state: ReceiverAwaitingChallenge,
    challenge: ChallengeMessage,
) -> Result<(ReceiverAwaitingAcceptance, ConsistencyProof), ExtensionError> {
    check_binding(
        state.context,
        state.triple_index,
        challenge.context,
        challenge.triple_index,
    )?;
    let chi = derive_chi(
        state.context,
        state.triple_index,
        state.extension_sender_role,
        &challenge.seed,
    );
    let mut small_x = DoubleBitRow::ZERO;
    for (chunk_index, chi_row) in chi.iter().enumerate() {
        small_x = small_x.xor(state.choices.chunk(chunk_index).gf_mul(*chi_row));
    }
    let mut small_t = Box::new([DoubleBitRow::ZERO; BASE_OT_COUNT]);
    for (column, target) in small_t.iter_mut().enumerate() {
        for (chunk_index, chi_row) in chi.iter().enumerate() {
            *target = target.xor(column_chunk(&state.t0, chunk_index, column).gf_mul(*chi_row));
        }
    }
    let proof = ConsistencyProof {
        context: state.context,
        triple_index: state.triple_index,
        small_x,
        small_t,
    };
    let expected_digest = acceptance_digest(
        state.context,
        state.triple_index,
        state.extension_sender_role,
        &challenge.seed,
        &proof,
    );
    let output = receiver_output(
        state.context,
        state.triple_index,
        state.extension_sender_role,
        &state.choices,
        &state.t0,
    );
    Ok((
        ReceiverAwaitingAcceptance {
            context: state.context,
            triple_index: state.triple_index,
            expected_digest,
            output,
        },
        proof,
    ))
}

fn receive_proof(
    state: SenderAwaitingProof,
    proof: ConsistencyProof,
) -> Result<(ExtensionSenderOutput, AcceptanceMessage), ExtensionError> {
    check_binding(
        state.context,
        state.triple_index,
        proof.context,
        proof.triple_index,
    )?;
    let chi = derive_chi(
        state.context,
        state.triple_index,
        state.extension_sender_role,
        &state.challenge_seed,
    );
    let mut valid = Choice::from(1);
    for column in 0..BASE_OT_COUNT {
        let mut small_q = DoubleBitRow::ZERO;
        for (chunk_index, chi_row) in chi.iter().enumerate() {
            small_q = small_q.xor(column_chunk(&state.q, chunk_index, column).gf_mul(*chi_row));
        }
        let delta_x = DoubleBitRow::conditional_select(
            &DoubleBitRow::ZERO,
            &proof.small_x,
            state.delta.bit(column),
        );
        valid &= small_q.ct_eq(&proof.small_t[column].xor(delta_x));
    }
    if !bool::from(valid) {
        return Err(ExtensionError::ConsistencyCheckFailed);
    }
    let digest = acceptance_digest(
        state.context,
        state.triple_index,
        state.extension_sender_role,
        &state.challenge_seed,
        &proof,
    );
    let output = sender_output(
        state.context,
        state.triple_index,
        state.extension_sender_role,
        state.delta,
        &state.q,
    );
    Ok((
        output,
        AcceptanceMessage {
            context: state.context,
            triple_index: state.triple_index,
            digest,
        },
    ))
}

fn receive_acceptance(
    state: ReceiverAwaitingAcceptance,
    acceptance: AcceptanceMessage,
) -> Result<ExtensionReceiverOutput, ExtensionError> {
    check_binding(
        state.context,
        state.triple_index,
        acceptance.context,
        acceptance.triple_index,
    )?;
    if !bool::from(state.expected_digest.ct_eq(&acceptance.digest)) {
        return Err(ExtensionError::AcceptanceMismatch);
    }
    Ok(state.output)
}

fn expand_pair_keys(
    context: PresignPairContext,
    triple_index: TripleIndex,
    extension_sender_role: u8,
    keys: &SenderKeys,
) -> (SecretMatrix, SecretMatrix) {
    let mut t0 = SecretMatrix::zero();
    let mut t1 = SecretMatrix::zero();
    for (base_index, key_pair) in keys.iter().enumerate() {
        let expanded0 = expand_key(
            context,
            triple_index,
            extension_sender_role,
            base_index,
            0,
            &key_pair[0],
        );
        let expanded1 = expand_key(
            context,
            triple_index,
            extension_sender_role,
            base_index,
            1,
            &key_pair[1],
        );
        transpose_expanded_row(&mut t0, base_index, &expanded0);
        transpose_expanded_row(&mut t1, base_index, &expanded1);
    }
    (t0, t1)
}

fn expand_selected_keys(
    context: PresignPairContext,
    triple_index: TripleIndex,
    extension_sender_role: u8,
    base_choices: &[u8; CHOICE_BYTES],
    keys: &ReceiverKeys,
) -> SecretMatrix {
    let mut matrix = SecretMatrix::zero();
    for base_index in 0..BASE_OT_COUNT {
        let branch = (base_choices[base_index / 8] >> (base_index % 8)) & 1;
        let expanded = expand_key(
            context,
            triple_index,
            extension_sender_role,
            base_index,
            branch,
            &keys[base_index],
        );
        transpose_expanded_row(&mut matrix, base_index, &expanded);
    }
    matrix
}

fn expand_key(
    context: PresignPairContext,
    triple_index: TripleIndex,
    extension_sender_role: u8,
    base_index: usize,
    branch: u8,
    key: &[u8; BASE_OT_KEY_SIZE],
) -> [u8; PADDED_OT_COUNT / 8] {
    let mut expanded = [0u8; PADDED_OT_COUNT / 8];
    for block in 0..PRG_BLOCKS {
        let mut hasher = Sha256::new();
        absorb_field(&mut hasher, 1, ROW_PRG_DOMAIN);
        absorb_field(&mut hasher, 2, SUITE);
        absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
        absorb_field(&mut hasher, 4, context.pair().as_bytes());
        absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
        absorb_field(&mut hasher, 6, &[extension_sender_role]);
        absorb_field(&mut hasher, 7, &(base_index as u16).to_be_bytes());
        absorb_field(&mut hasher, 8, &[branch]);
        absorb_field(&mut hasher, 9, &(block as u16).to_be_bytes());
        absorb_field(&mut hasher, 16, key);
        let digest: [u8; 32] = hasher.finalize().into();
        expanded[block * 32..(block + 1) * 32].copy_from_slice(&digest);
    }
    expanded
}

fn transpose_expanded_row(
    matrix: &mut SecretMatrix,
    base_index: usize,
    expanded: &[u8; PADDED_OT_COUNT / 8],
) {
    for row_index in 0..PADDED_OT_COUNT {
        let bit = (expanded[row_index / 8] >> (row_index % 8)) & 1;
        matrix.0[row_index].0[base_index / 64] |= u64::from(bit) << (base_index % 64);
    }
}

fn derive_chi(
    context: PresignPairContext,
    triple_index: TripleIndex,
    extension_sender_role: u8,
    seed: &[u8; 32],
) -> [BitRow; CONSISTENCY_CHUNKS] {
    let mut chi = [BitRow::ZERO; CONSISTENCY_CHUNKS];
    for (chunk_index, target) in chi.iter_mut().enumerate() {
        let mut hasher = Sha256::new();
        absorb_field(&mut hasher, 1, EXTENSION_DOMAIN);
        absorb_field(&mut hasher, 2, SUITE);
        absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
        absorb_field(&mut hasher, 4, context.pair().as_bytes());
        absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
        absorb_field(&mut hasher, 6, &[extension_sender_role]);
        absorb_field(&mut hasher, 7, &(chunk_index as u16).to_be_bytes());
        absorb_field(&mut hasher, 16, seed);
        let digest: [u8; 32] = hasher.finalize().into();
        *target = BitRow::from_bytes(
            digest[..16]
                .try_into()
                .expect("SHA-256 contains a 16-byte row"),
        );
    }
    chi
}

fn column_chunk(matrix: &SecretMatrix, chunk_index: usize, column: usize) -> BitRow {
    let mut row = BitRow::ZERO;
    let start = chunk_index * BASE_OT_COUNT;
    for offset in 0..BASE_OT_COUNT {
        let bit = matrix.0[start + offset].bit(column).unwrap_u8();
        row.0[offset / 64] |= u64::from(bit) << (offset % 64);
    }
    row
}

fn sender_output(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    delta: BitRow,
    q: &SecretMatrix,
) -> ExtensionSenderOutput {
    let mut values = [[Scalar::ZERO; 2]; EXTENDED_OT_COUNT];
    for (index, (target, q_row)) in values.iter_mut().zip(q.0.iter()).enumerate() {
        target[0] = hash_row_to_scalar(context, triple_index, sender_role, index, *q_row);
        target[1] = hash_row_to_scalar(context, triple_index, sender_role, index, q_row.xor(delta));
    }
    ExtensionSenderOutput {
        context,
        triple_index,
        sender_role,
        values,
    }
}

fn receiver_output(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    choices: &ChoiceBits,
    t0: &SecretMatrix,
) -> ExtensionReceiverOutput {
    let mut values = [Scalar::ZERO; EXTENDED_OT_COUNT];
    for (index, (target, t0_row)) in values.iter_mut().zip(t0.0.iter()).enumerate() {
        *target = hash_row_to_scalar(context, triple_index, sender_role, index, *t0_row);
    }
    ExtensionReceiverOutput {
        context,
        triple_index,
        sender_role,
        choices: choices.output_prefix(),
        values,
    }
}

fn hash_row_to_scalar(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    index: usize,
    row: BitRow,
) -> Scalar {
    let mut hasher = Sha512::new();
    absorb_field(&mut hasher, 1, OUTPUT_DOMAIN);
    absorb_field(&mut hasher, 2, SUITE);
    absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
    absorb_field(&mut hasher, 4, context.pair().as_bytes());
    absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
    absorb_field(&mut hasher, 6, &[sender_role]);
    absorb_field(&mut hasher, 7, &(index as u16).to_be_bytes());
    absorb_field(&mut hasher, 16, &row.into_bytes());
    let digest: [u8; 64] = hasher.finalize().into();
    let mut wide = WideBytes::default();
    wide.copy_from_slice(&digest);
    <Scalar as Reduce<U512>>::reduce_bytes(&wide)
}

fn acceptance_digest(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    challenge_seed: &[u8; 32],
    proof: &ConsistencyProof,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    absorb_field(&mut hasher, 1, ACCEPTANCE_DOMAIN);
    absorb_field(&mut hasher, 2, SUITE);
    absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
    absorb_field(&mut hasher, 4, context.pair().as_bytes());
    absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
    absorb_field(&mut hasher, 6, &[sender_role]);
    absorb_field(&mut hasher, 16, challenge_seed);
    absorb_field(&mut hasher, 17, &proof.small_x.into_bytes());
    for (index, row) in proof.small_t.iter().enumerate() {
        absorb_field(&mut hasher, 32 + index as u16, &row.into_bytes());
    }
    hasher.finalize().into()
}

fn absorb_field<D: Digest>(hasher: &mut D, tag: u16, value: &[u8]) {
    Digest::update(hasher, tag.to_be_bytes());
    Digest::update(hasher, (value.len() as u32).to_be_bytes());
    Digest::update(hasher, value);
}

fn check_binding(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    actual_context: PresignPairContext,
    actual_triple_index: TripleIndex,
) -> Result<(), ExtensionError> {
    if actual_context != expected_context {
        return Err(ExtensionError::ContextMismatch);
    }
    if actual_triple_index != expected_triple_index {
        return Err(ExtensionError::TripleIndexMismatch);
    }
    Ok(())
}

fn opposite_role(role: u8) -> u8 {
    match role {
        CLIENT_ROLE => SIGNING_WORKER_ROLE,
        SIGNING_WORKER_ROLE => CLIENT_ROLE,
        _ => 0,
    }
}

fn triple_index_byte(index: TripleIndex) -> u8 {
    match index {
        TripleIndex::Zero => 0,
        TripleIndex::One => 1,
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};

    use super::*;
    use crate::triples::base_rot::{
        receive_client_base_rot_sender_hello, receive_signing_worker_base_rot_sender_hello,
        start_client_base_rot_sender, start_signing_worker_base_rot_sender,
    };

    fn binding() -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([0x24; 32]),
            PairContextDigest::new([0x42; 32]),
        )
    }

    fn extended_choice(choices: &[u8; EXTENDED_CHOICE_BYTES], index: usize) -> usize {
        usize::from((choices[index / 8] >> (index % 8)) & 1)
    }

    fn base_outputs_for_client_extension_sender() -> (
        ClientBaseRotReceiverOutput,
        SigningWorkerBaseRotSenderOutput,
    ) {
        let mut base_sender_rng = ChaCha20Rng::from_seed([1; 32]);
        let mut base_receiver_rng = ChaCha20Rng::from_seed([2; 32]);
        let (worker_state, hello) = start_signing_worker_base_rot_sender(
            binding(),
            TripleIndex::Zero,
            &mut base_sender_rng,
        )
        .expect("base sender");
        let (client_output, response) = receive_signing_worker_base_rot_sender_hello(
            binding(),
            TripleIndex::Zero,
            hello,
            &mut base_receiver_rng,
        )
        .expect("base receiver");
        let worker_output = worker_state
            .receive(response)
            .expect("base sender finishes");
        (client_output, worker_output)
    }

    #[test]
    fn corrected_extension_completes_and_correlates_all_outputs() {
        let (client_base, worker_base) = base_outputs_for_client_extension_sender();
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([3; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([4; 32]);
        let (worker_state, correlation) =
            start_signing_worker_extension_receiver(worker_base, &mut extension_receiver_rng)
                .expect("extension receiver");
        let (client_state, challenge) = start_client_extension_sender(
            binding(),
            TripleIndex::Zero,
            client_base,
            correlation,
            &mut extension_sender_rng,
        )
        .expect("extension sender");
        let (worker_accept_state, proof) = worker_state.receive(challenge).expect("proof");
        let (client_output, acceptance) = client_state.receive(proof).expect("proof accepted");
        let worker_output = worker_accept_state
            .receive(acceptance)
            .expect("receiver accepted");
        let sender_values = client_output.into_test_values();
        let (choices, receiver_values) = worker_output.into_test_parts();

        for index in 0..EXTENDED_OT_COUNT {
            assert_eq!(
                receiver_values[index],
                sender_values[index][extended_choice(&choices, index)]
            );
        }
    }

    #[test]
    fn tampered_consistency_proof_aborts_before_sender_output() {
        let (client_base, worker_base) = base_outputs_for_client_extension_sender();
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([5; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([6; 32]);
        let (worker_state, correlation) =
            start_signing_worker_extension_receiver(worker_base, &mut extension_receiver_rng)
                .expect("extension receiver");
        let (client_state, challenge) = start_client_extension_sender(
            binding(),
            TripleIndex::Zero,
            client_base,
            correlation,
            &mut extension_sender_rng,
        )
        .expect("extension sender");
        let (_, proof) = worker_state.receive(challenge).expect("proof");
        let (context, index, small_x, mut small_t) = proof.into_parts();
        small_t[0][0] ^= 1;
        let tampered =
            SigningWorkerExtensionProofMessage::from_parts(context, index, small_x, small_t);
        let result = client_state.receive(tampered);
        assert!(matches!(
            result,
            Err(ExtensionError::ConsistencyCheckFailed)
        ));
    }

    #[test]
    fn tampered_acceptance_keeps_receiver_output_sealed() {
        let (client_base, worker_base) = base_outputs_for_client_extension_sender();
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([13; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([14; 32]);
        let (worker_state, correlation) =
            start_signing_worker_extension_receiver(worker_base, &mut extension_receiver_rng)
                .expect("extension receiver");
        let (client_state, challenge) = start_client_extension_sender(
            binding(),
            TripleIndex::Zero,
            client_base,
            correlation,
            &mut extension_sender_rng,
        )
        .expect("extension sender");
        let (worker_accept_state, proof) = worker_state.receive(challenge).expect("proof");
        let (_, acceptance) = client_state.receive(proof).expect("proof accepted");
        let (context, index, mut digest) = acceptance.into_parts();
        digest[0] ^= 1;
        let tampered = ClientExtensionAcceptanceMessage::from_parts(context, index, digest);
        let result = worker_accept_state.receive(tampered);
        assert!(matches!(result, Err(ExtensionError::AcceptanceMismatch)));
    }

    #[test]
    fn keyed_expansion_changes_for_every_changed_base_key() {
        let (_, worker_base) = base_outputs_for_client_extension_sender();
        for base_index in 0..BASE_OT_COUNT {
            for branch in 0..2 {
                let original = worker_base.0.keys[base_index][branch];
                let mut changed = original;
                changed[0] ^= 1;
                let original_expansion = expand_key(
                    binding(),
                    TripleIndex::Zero,
                    CLIENT_ROLE,
                    base_index,
                    branch as u8,
                    &original,
                );
                let changed_expansion = expand_key(
                    binding(),
                    TripleIndex::Zero,
                    CLIENT_ROLE,
                    base_index,
                    branch as u8,
                    &changed,
                );
                assert_ne!(original_expansion, changed_expansion);
            }
        }
    }

    #[test]
    fn extension_context_substitution_aborts() {
        let (client_base, worker_base) = base_outputs_for_client_extension_sender();
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([7; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([8; 32]);
        let (_, correlation) =
            start_signing_worker_extension_receiver(worker_base, &mut extension_receiver_rng)
                .expect("extension receiver");
        let wrong_context = PresignPairContext::new(
            SigningScopeDigest::new([0x24; 32]),
            PairContextDigest::new([0x99; 32]),
        );
        let result = start_client_extension_sender(
            wrong_context,
            TripleIndex::Zero,
            client_base,
            correlation,
            &mut extension_sender_rng,
        );
        assert!(matches!(result, Err(ExtensionError::ContextMismatch)));
    }

    #[test]
    fn reverse_role_extension_completes() {
        let mut base_sender_rng = ChaCha20Rng::from_seed([9; 32]);
        let mut base_receiver_rng = ChaCha20Rng::from_seed([10; 32]);
        let (client_base_state, hello) =
            start_client_base_rot_sender(binding(), TripleIndex::One, &mut base_sender_rng)
                .expect("base sender");
        let (worker_base_output, response) = receive_client_base_rot_sender_hello(
            binding(),
            TripleIndex::One,
            hello,
            &mut base_receiver_rng,
        )
        .expect("base receiver");
        let client_base_output = client_base_state
            .receive(response)
            .expect("base sender finishes");
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([11; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([12; 32]);
        let (client_state, correlation) =
            start_client_extension_receiver(client_base_output, &mut extension_receiver_rng)
                .expect("extension receiver");
        let (worker_state, challenge) = start_signing_worker_extension_sender(
            binding(),
            TripleIndex::One,
            worker_base_output,
            correlation,
            &mut extension_sender_rng,
        )
        .expect("extension sender");
        let (client_accept_state, proof) = client_state.receive(challenge).expect("proof");
        let (worker_output, acceptance) = worker_state.receive(proof).expect("proof accepted");
        let client_output = client_accept_state
            .receive(acceptance)
            .expect("receiver accepted");
        let sender_values = worker_output.into_test_values();
        let (choices, receiver_values) = client_output.into_test_parts();
        for index in 0..EXTENDED_OT_COUNT {
            assert_eq!(
                receiver_values[index],
                sender_values[index][extended_choice(&choices, index)]
            );
        }
    }
}
