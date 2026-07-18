use core::fmt;

use router_ab_ecdsa_wire::{
    ClientAlphaBetaMessage, ClientEShareMessage, CompressedPointBytes, PairContextDigest,
    PresignPairContext, ScalarBytes, SigningScopeDigest, SigningWorkerAlphaBetaMessage,
    SigningWorkerEShareMessage, COMPRESSED_POINT_SIZE, SCALAR_SIZE,
};

use crate::driver::{
    ClientRound1Message, ClientRound2Message, SigningWorkerRound1Message,
    SigningWorkerRound2Message,
};
use crate::proofs::TripleIndex;
use crate::triples::base_rot::extension::mta::{
    ClientMtaCiphertextMessage, ClientMtaResponseMessage, SigningWorkerMtaCiphertextMessage,
    SigningWorkerMtaResponseMessage, MTA_INSTANCE_COUNT, MTA_OT_COUNT,
};
use crate::triples::base_rot::extension::{
    ClientExtensionAcceptanceMessage, ClientExtensionChallengeMessage,
    ClientExtensionCorrelationMessage, ClientExtensionProofMessage,
    SigningWorkerExtensionAcceptanceMessage, SigningWorkerExtensionChallengeMessage,
    SigningWorkerExtensionCorrelationMessage, SigningWorkerExtensionProofMessage,
    CONSISTENCY_VECTOR_SIZE, CORRELATION_MESSAGE_SIZE,
};
use crate::triples::base_rot::{
    ClientBaseRotReceiverChoices, ClientBaseRotSenderHello, SigningWorkerBaseRotReceiverChoices,
    SigningWorkerBaseRotSenderHello, BASE_OT_COUNT,
};
use crate::triples::finalize::{
    ClientTripleFinalizationMessage, SigningWorkerTripleFinalizationMessage,
    TripleContributionParts,
};
use crate::triples::{
    ClientPolynomialCommitmentMessage, ClientPolynomialOpeningMessage,
    ClientPolynomialShareMessage, SigningWorkerPolynomialCommitmentMessage,
    SigningWorkerPolynomialOpeningMessage, SigningWorkerPolynomialShareMessage,
};

const MAGIC: &[u8; 4] = b"RAEP";
const VERSION: u8 = 1;
const CLIENT_ROLE: u8 = 1;
const SIGNING_WORKER_ROLE: u8 = 2;
const HEADER_SIZE: usize = 12;
const CONTEXT_SIZE: usize = 64;
const ROUND1_PAYLOAD_SIZE: usize = CONTEXT_SIZE + (2 * 32) + COMPRESSED_POINT_SIZE;
const OPENING_SIZE: usize = (5 * COMPRESSED_POINT_SIZE) + 32;
const PRIVATE_SHARE_SIZE: usize = 2 * SCALAR_SIZE;
const ROUND2_PAYLOAD_SIZE: usize = CONTEXT_SIZE
    + (2 * OPENING_SIZE)
    + (2 * PRIVATE_SHARE_SIZE)
    + (BASE_OT_COUNT * COMPRESSED_POINT_SIZE);
const ROUND3_PAYLOAD_SIZE: usize = CONTEXT_SIZE + CORRELATION_MESSAGE_SIZE;
const ROUND4_PAYLOAD_SIZE: usize = CONTEXT_SIZE + 32;
const ROUND5_PAYLOAD_SIZE: usize =
    CONTEXT_SIZE + CONSISTENCY_VECTOR_SIZE + (BASE_OT_COUNT * CONSISTENCY_VECTOR_SIZE);
const ROUND6_PAYLOAD_SIZE: usize = CONTEXT_SIZE + 32;
const ROUND7_PAYLOAD_SIZE: usize =
    CONTEXT_SIZE + (MTA_INSTANCE_COUNT * MTA_OT_COUNT * 2 * SCALAR_SIZE);
const ROUND8_PAYLOAD_SIZE: usize = CONTEXT_SIZE + (4 * SCALAR_SIZE);
const TRIPLE_CONTRIBUTION_SIZE: usize = (7 * COMPRESSED_POINT_SIZE) + (5 * SCALAR_SIZE);
const ROUND9_PAYLOAD_SIZE: usize = CONTEXT_SIZE + (2 * TRIPLE_CONTRIBUTION_SIZE);
const ROUND10_PAYLOAD_SIZE: usize = CONTEXT_SIZE + SCALAR_SIZE;
const ROUND11_PAYLOAD_SIZE: usize = CONTEXT_SIZE + (2 * SCALAR_SIZE);

pub const PRESIGN_PROTOCOL_ID: &str = "seams/router-ab-ecdsa-presign/fixed-2of2/v1";
pub const MAX_PRESIGN_FRAME_SIZE: usize = HEADER_SIZE + ROUND7_PAYLOAD_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignCodecError {
    FrameTooShort,
    InvalidMagic,
    UnsupportedVersion,
    UnexpectedSenderRole,
    UnexpectedRound,
    NonZeroFlags,
    PayloadTooLarge,
    LengthMismatch,
    InvalidMessageBinding,
    InvalidBody,
}

impl fmt::Display for PresignCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FrameTooShort => "presign frame is shorter than its fixed header",
            Self::InvalidMagic => "invalid presign protocol identifier",
            Self::UnsupportedVersion => "unsupported presign protocol version",
            Self::UnexpectedSenderRole => "unexpected presign sender role",
            Self::UnexpectedRound => "unexpected presign round",
            Self::NonZeroFlags => "presign frame flags must be zero",
            Self::PayloadTooLarge => "presign frame exceeds the protocol ceiling",
            Self::LengthMismatch => "presign frame has a non-canonical length",
            Self::InvalidMessageBinding => "presign message has inconsistent fixed bindings",
            Self::InvalidBody => "presign message body is invalid",
        })
    }
}

impl std::error::Error for PresignCodecError {}

pub trait EncodePresignMessage {
    fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError>;
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], PresignCodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(PresignCodecError::InvalidBody)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(PresignCodecError::InvalidBody)?;
        let mut output = [0u8; N];
        output.copy_from_slice(source);
        self.position = end;
        Ok(output)
    }

    fn take_boxed<const N: usize>(&mut self) -> Result<Box<[u8; N]>, PresignCodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(PresignCodecError::InvalidBody)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(PresignCodecError::InvalidBody)?;
        let output: Box<[u8]> = source.to_vec().into_boxed_slice();
        self.position = end;
        output
            .try_into()
            .map_err(|_| PresignCodecError::InvalidBody)
    }
}

fn frame(role: u8, round: u8, payload_size: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(HEADER_SIZE + payload_size);
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.push(role);
    output.push(round);
    output.push(0);
    output.extend_from_slice(&(payload_size as u32).to_be_bytes());
    output
}

fn finish_frame(output: Vec<u8>, payload_size: usize) -> Result<Vec<u8>, PresignCodecError> {
    if output.len() != HEADER_SIZE + payload_size || output.len() > MAX_PRESIGN_FRAME_SIZE {
        return Err(PresignCodecError::LengthMismatch);
    }
    Ok(output)
}

fn decode_frame(
    encoded: &[u8],
    expected_role: u8,
    expected_round: u8,
    expected_payload_size: usize,
) -> Result<Cursor<'_>, PresignCodecError> {
    if encoded.len() < HEADER_SIZE {
        return Err(PresignCodecError::FrameTooShort);
    }
    if &encoded[..4] != MAGIC {
        return Err(PresignCodecError::InvalidMagic);
    }
    if encoded[4] != VERSION {
        return Err(PresignCodecError::UnsupportedVersion);
    }
    if encoded[5] != expected_role {
        return Err(PresignCodecError::UnexpectedSenderRole);
    }
    if encoded[6] != expected_round {
        return Err(PresignCodecError::UnexpectedRound);
    }
    if encoded[7] != 0 {
        return Err(PresignCodecError::NonZeroFlags);
    }
    let payload_size = u32::from_be_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| PresignCodecError::FrameTooShort)?,
    ) as usize;
    if payload_size > ROUND7_PAYLOAD_SIZE || encoded.len() > MAX_PRESIGN_FRAME_SIZE {
        return Err(PresignCodecError::PayloadTooLarge);
    }
    if payload_size != expected_payload_size || encoded.len() != HEADER_SIZE + payload_size {
        return Err(PresignCodecError::LengthMismatch);
    }
    Ok(Cursor::new(&encoded[HEADER_SIZE..]))
}

fn write_context(output: &mut Vec<u8>, context: PresignPairContext) {
    output.extend_from_slice(context.signing_scope().as_bytes());
    output.extend_from_slice(context.pair().as_bytes());
}

fn read_context(cursor: &mut Cursor<'_>) -> Result<PresignPairContext, PresignCodecError> {
    Ok(PresignPairContext::new(
        SigningScopeDigest::new(cursor.take()?),
        PairContextDigest::new(cursor.take()?),
    ))
}

fn write_point(output: &mut Vec<u8>, point: CompressedPointBytes) {
    output.extend_from_slice(point.as_bytes());
}

fn read_point(cursor: &mut Cursor<'_>) -> Result<CompressedPointBytes, PresignCodecError> {
    Ok(CompressedPointBytes::new(cursor.take()?))
}

fn write_scalar(output: &mut Vec<u8>, scalar: ScalarBytes) {
    output.extend_from_slice(&scalar.into_bytes());
}

fn read_scalar(cursor: &mut Cursor<'_>) -> Result<ScalarBytes, PresignCodecError> {
    Ok(ScalarBytes::new(cursor.take()?))
}

fn ensure_binding(
    actual_context: PresignPairContext,
    expected_context: PresignPairContext,
    actual_index: TripleIndex,
    expected_index: TripleIndex,
) -> Result<(), PresignCodecError> {
    if actual_context != expected_context || actual_index != expected_index {
        return Err(PresignCodecError::InvalidMessageBinding);
    }
    Ok(())
}

macro_rules! impl_round1_codec {
    (
        $message:ident,
        $commitment:ident,
        $hello:ident,
        $role:expr,
        $hello_index:expr,
        $decode:ident
    ) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let [commitment_zero, commitment_one] = self.commitments;
                let (context, index_zero, digest_zero) = commitment_zero.into_parts();
                let (context_one, index_one, digest_one) = commitment_one.into_parts();
                let (hello_context, hello_index, hello_point) = self.base_hello.into_parts();
                ensure_binding(context_one, context, index_one, TripleIndex::One)?;
                ensure_binding(context, context, index_zero, TripleIndex::Zero)?;
                ensure_binding(hello_context, context, hello_index, $hello_index)?;
                let mut output = frame($role, 1, ROUND1_PAYLOAD_SIZE);
                write_context(&mut output, context);
                output.extend_from_slice(&digest_zero);
                output.extend_from_slice(&digest_one);
                write_point(&mut output, hello_point);
                finish_frame(output, ROUND1_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 1, ROUND1_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let digest_zero = cursor.take()?;
            let digest_one = cursor.take()?;
            let hello_point = read_point(&mut cursor)?;
            let commitments = [
                <$commitment>::from_parts(context, TripleIndex::Zero, digest_zero),
                <$commitment>::from_parts(context, TripleIndex::One, digest_one),
            ];
            let base_hello = <$hello>::from_parts(context, $hello_index, hello_point)
                .map_err(|_| PresignCodecError::InvalidBody)?;
            Ok($message {
                commitments,
                base_hello,
            })
        }
    };
}

impl_round1_codec!(
    ClientRound1Message,
    ClientPolynomialCommitmentMessage,
    ClientBaseRotSenderHello,
    CLIENT_ROLE,
    TripleIndex::One,
    decode_client_round1
);
impl_round1_codec!(
    SigningWorkerRound1Message,
    SigningWorkerPolynomialCommitmentMessage,
    SigningWorkerBaseRotSenderHello,
    SIGNING_WORKER_ROLE,
    TripleIndex::Zero,
    decode_signing_worker_round1
);

fn write_opening(
    output: &mut Vec<u8>,
    parts: (
        PresignPairContext,
        TripleIndex,
        CompressedPointBytes,
        CompressedPointBytes,
        CompressedPointBytes,
        CompressedPointBytes,
        CompressedPointBytes,
        [u8; 32],
    ),
    context: PresignPairContext,
    index: TripleIndex,
) -> Result<(), PresignCodecError> {
    let (actual_context, actual_index, e0, e1, f0, f1, l0, randomizer) = parts;
    ensure_binding(actual_context, context, actual_index, index)?;
    for point in [e0, e1, f0, f1, l0] {
        write_point(output, point);
    }
    output.extend_from_slice(&randomizer);
    Ok(())
}

fn write_private_share(
    output: &mut Vec<u8>,
    parts: (PresignPairContext, TripleIndex, ScalarBytes, ScalarBytes),
    context: PresignPairContext,
    index: TripleIndex,
) -> Result<(), PresignCodecError> {
    let (actual_context, actual_index, e, f) = parts;
    ensure_binding(actual_context, context, actual_index, index)?;
    write_scalar(output, e);
    write_scalar(output, f);
    Ok(())
}

struct DecodedOpening {
    points: [CompressedPointBytes; 5],
    randomizer: [u8; 32],
}

fn read_opening_parts(cursor: &mut Cursor<'_>) -> Result<DecodedOpening, PresignCodecError> {
    Ok(DecodedOpening {
        points: [
            read_point(cursor)?,
            read_point(cursor)?,
            read_point(cursor)?,
            read_point(cursor)?,
            read_point(cursor)?,
        ],
        randomizer: cursor.take()?,
    })
}

macro_rules! impl_round2_codec {
    (
        $message:ident,
        $opening:ident,
        $share:ident,
        $choices:ident,
        $role:expr,
        $choices_index:expr,
        $decode:ident
    ) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let [opening_zero, opening_one] = self.openings;
                let [share_zero, share_one] = self.private_shares;
                let opening_zero = opening_zero.into_parts();
                let context = opening_zero.0;
                let mut output = frame($role, 2, ROUND2_PAYLOAD_SIZE);
                write_context(&mut output, context);
                write_opening(&mut output, opening_zero, context, TripleIndex::Zero)?;
                write_opening(
                    &mut output,
                    opening_one.into_parts(),
                    context,
                    TripleIndex::One,
                )?;
                write_private_share(
                    &mut output,
                    share_zero.into_parts(),
                    context,
                    TripleIndex::Zero,
                )?;
                write_private_share(
                    &mut output,
                    share_one.into_parts(),
                    context,
                    TripleIndex::One,
                )?;
                let (choices_context, choices_index, choices) = self.base_choices.into_parts();
                ensure_binding(choices_context, context, choices_index, $choices_index)?;
                for point in choices {
                    write_point(&mut output, point);
                }
                finish_frame(output, ROUND2_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 2, ROUND2_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let zero = read_opening_parts(&mut cursor)?;
            let one = read_opening_parts(&mut cursor)?;
            let openings = [
                <$opening>::from_parts(
                    context,
                    TripleIndex::Zero,
                    zero.points[0],
                    zero.points[1],
                    zero.points[2],
                    zero.points[3],
                    zero.points[4],
                    zero.randomizer,
                )
                .map_err(|_| PresignCodecError::InvalidBody)?,
                <$opening>::from_parts(
                    context,
                    TripleIndex::One,
                    one.points[0],
                    one.points[1],
                    one.points[2],
                    one.points[3],
                    one.points[4],
                    one.randomizer,
                )
                .map_err(|_| PresignCodecError::InvalidBody)?,
            ];
            let private_shares = [
                <$share>::from_parts(
                    context,
                    TripleIndex::Zero,
                    read_scalar(&mut cursor)?,
                    read_scalar(&mut cursor)?,
                )
                .map_err(|_| PresignCodecError::InvalidBody)?,
                <$share>::from_parts(
                    context,
                    TripleIndex::One,
                    read_scalar(&mut cursor)?,
                    read_scalar(&mut cursor)?,
                )
                .map_err(|_| PresignCodecError::InvalidBody)?,
            ];
            let mut choices =
                [CompressedPointBytes::new([0; COMPRESSED_POINT_SIZE]); BASE_OT_COUNT];
            for point in &mut choices {
                *point = read_point(&mut cursor)?;
            }
            let base_choices = <$choices>::from_parts(context, $choices_index, choices)
                .map_err(|_| PresignCodecError::InvalidBody)?;
            Ok($message {
                openings,
                private_shares,
                base_choices,
            })
        }
    };
}

impl_round2_codec!(
    ClientRound2Message,
    ClientPolynomialOpeningMessage,
    ClientPolynomialShareMessage,
    ClientBaseRotReceiverChoices,
    CLIENT_ROLE,
    TripleIndex::Zero,
    decode_client_round2
);
impl_round2_codec!(
    SigningWorkerRound2Message,
    SigningWorkerPolynomialOpeningMessage,
    SigningWorkerPolynomialShareMessage,
    SigningWorkerBaseRotReceiverChoices,
    SIGNING_WORKER_ROLE,
    TripleIndex::One,
    decode_signing_worker_round2
);

macro_rules! impl_round3_codec {
    ($message:ty, $role:expr, $index:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, index, matrix) = self.into_parts();
                ensure_binding(context, context, index, $index)?;
                let mut output = frame($role, 3, ROUND3_PAYLOAD_SIZE);
                write_context(&mut output, context);
                output.extend_from_slice(matrix.as_ref());
                finish_frame(output, ROUND3_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 3, ROUND3_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let matrix = cursor.take_boxed()?;
            Ok(<$message>::from_parts(context, $index, matrix))
        }
    };
}

impl_round3_codec!(
    ClientExtensionCorrelationMessage,
    CLIENT_ROLE,
    TripleIndex::One,
    decode_client_round3
);
impl_round3_codec!(
    SigningWorkerExtensionCorrelationMessage,
    SIGNING_WORKER_ROLE,
    TripleIndex::Zero,
    decode_signing_worker_round3
);

macro_rules! impl_context_digest_codec {
    ($message:ty, $role:expr, $round:expr, $index:expr, $payload:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, index, digest) = self.into_parts();
                ensure_binding(context, context, index, $index)?;
                let mut output = frame($role, $round, $payload);
                write_context(&mut output, context);
                output.extend_from_slice(&digest);
                finish_frame(output, $payload)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, $round, $payload)?;
            let context = read_context(&mut cursor)?;
            let digest = cursor.take()?;
            Ok(<$message>::from_parts(context, $index, digest))
        }
    };
}

impl_context_digest_codec!(
    ClientExtensionChallengeMessage,
    CLIENT_ROLE,
    4,
    TripleIndex::Zero,
    ROUND4_PAYLOAD_SIZE,
    decode_client_round4
);
impl_context_digest_codec!(
    SigningWorkerExtensionChallengeMessage,
    SIGNING_WORKER_ROLE,
    4,
    TripleIndex::One,
    ROUND4_PAYLOAD_SIZE,
    decode_signing_worker_round4
);

macro_rules! impl_round5_codec {
    ($message:ty, $role:expr, $index:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, index, small_x, small_t) = self.into_parts();
                ensure_binding(context, context, index, $index)?;
                let mut output = frame($role, 5, ROUND5_PAYLOAD_SIZE);
                write_context(&mut output, context);
                output.extend_from_slice(&small_x);
                for row in small_t.iter() {
                    output.extend_from_slice(row);
                }
                finish_frame(output, ROUND5_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 5, ROUND5_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let small_x = cursor.take()?;
            let mut small_t = Box::new([[0u8; CONSISTENCY_VECTOR_SIZE]; BASE_OT_COUNT]);
            for row in small_t.iter_mut() {
                *row = cursor.take()?;
            }
            Ok(<$message>::from_parts(context, $index, small_x, small_t))
        }
    };
}

impl_round5_codec!(
    ClientExtensionProofMessage,
    CLIENT_ROLE,
    TripleIndex::One,
    decode_client_round5
);
impl_round5_codec!(
    SigningWorkerExtensionProofMessage,
    SIGNING_WORKER_ROLE,
    TripleIndex::Zero,
    decode_signing_worker_round5
);

impl_context_digest_codec!(
    ClientExtensionAcceptanceMessage,
    CLIENT_ROLE,
    6,
    TripleIndex::Zero,
    ROUND6_PAYLOAD_SIZE,
    decode_client_round6
);
impl_context_digest_codec!(
    SigningWorkerExtensionAcceptanceMessage,
    SIGNING_WORKER_ROLE,
    6,
    TripleIndex::One,
    ROUND6_PAYLOAD_SIZE,
    decode_signing_worker_round6
);

macro_rules! impl_round7_codec {
    ($message:ty, $role:expr, $index:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, index, values) = self.into_parts();
                ensure_binding(context, context, index, $index)?;
                let mut output = frame($role, 7, ROUND7_PAYLOAD_SIZE);
                write_context(&mut output, context);
                for instance in values.iter() {
                    for pair in instance {
                        output.extend_from_slice(&pair[0]);
                        output.extend_from_slice(&pair[1]);
                    }
                }
                finish_frame(output, ROUND7_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 7, ROUND7_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let mut values =
                Box::new([[[[0u8; SCALAR_SIZE]; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]);
            for instance in values.iter_mut() {
                for pair in instance {
                    pair[0] = cursor.take()?;
                    pair[1] = cursor.take()?;
                }
            }
            <$message>::from_parts(context, $index, values)
                .map_err(|_| PresignCodecError::InvalidBody)
        }
    };
}

impl_round7_codec!(
    ClientMtaCiphertextMessage,
    CLIENT_ROLE,
    TripleIndex::Zero,
    decode_client_round7
);
impl_round7_codec!(
    SigningWorkerMtaCiphertextMessage,
    SIGNING_WORKER_ROLE,
    TripleIndex::One,
    decode_signing_worker_round7
);

macro_rules! impl_round8_codec {
    ($message:ty, $role:expr, $index:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, index, chi, seeds) = self.into_parts();
                ensure_binding(context, context, index, $index)?;
                let mut output = frame($role, 8, ROUND8_PAYLOAD_SIZE);
                write_context(&mut output, context);
                for scalar in chi {
                    output.extend_from_slice(&scalar);
                }
                for seed in seeds {
                    output.extend_from_slice(&seed);
                }
                finish_frame(output, ROUND8_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 8, ROUND8_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let chi = [cursor.take()?, cursor.take()?];
            let seeds = [cursor.take()?, cursor.take()?];
            <$message>::from_parts(context, $index, chi, seeds)
                .map_err(|_| PresignCodecError::InvalidBody)
        }
    };
}

impl_round8_codec!(
    ClientMtaResponseMessage,
    CLIENT_ROLE,
    TripleIndex::One,
    decode_client_round8
);
impl_round8_codec!(
    SigningWorkerMtaResponseMessage,
    SIGNING_WORKER_ROLE,
    TripleIndex::Zero,
    decode_signing_worker_round8
);

fn write_contribution(output: &mut Vec<u8>, contribution: TripleContributionParts) {
    let (
        big_c,
        e_commit,
        e_response,
        f_commit,
        f_response,
        product0,
        product1,
        product_response,
        multiplication,
        multiplication_proof,
        multiplication_response,
        private_evaluation,
    ) = contribution.into_parts();
    write_point(output, big_c);
    write_point(output, e_commit);
    write_scalar(output, e_response);
    write_point(output, f_commit);
    write_scalar(output, f_response);
    write_point(output, product0);
    write_point(output, product1);
    write_scalar(output, product_response);
    write_point(output, multiplication);
    write_point(output, multiplication_proof);
    write_scalar(output, multiplication_response);
    write_scalar(output, private_evaluation);
}

fn read_contribution(
    cursor: &mut Cursor<'_>,
) -> Result<TripleContributionParts, PresignCodecError> {
    Ok(TripleContributionParts::new(
        read_point(cursor)?,
        read_point(cursor)?,
        read_scalar(cursor)?,
        read_point(cursor)?,
        read_scalar(cursor)?,
        read_point(cursor)?,
        read_point(cursor)?,
        read_scalar(cursor)?,
        read_point(cursor)?,
        read_point(cursor)?,
        read_scalar(cursor)?,
        read_scalar(cursor)?,
    ))
}

macro_rules! impl_round9_codec {
    ($message:ty, $role:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, contributions) = self.into_parts();
                let mut output = frame($role, 9, ROUND9_PAYLOAD_SIZE);
                write_context(&mut output, context);
                for contribution in contributions {
                    write_contribution(&mut output, contribution);
                }
                finish_frame(output, ROUND9_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 9, ROUND9_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            let contributions = [
                read_contribution(&mut cursor)?,
                read_contribution(&mut cursor)?,
            ];
            <$message>::from_parts(context, contributions)
                .map_err(|_| PresignCodecError::InvalidBody)
        }
    };
}

impl_round9_codec!(
    ClientTripleFinalizationMessage,
    CLIENT_ROLE,
    decode_client_round9
);
impl_round9_codec!(
    SigningWorkerTripleFinalizationMessage,
    SIGNING_WORKER_ROLE,
    decode_signing_worker_round9
);

macro_rules! impl_round10_codec {
    ($message:ty, $role:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, scalar) = self.into_parts();
                let mut output = frame($role, 10, ROUND10_PAYLOAD_SIZE);
                write_context(&mut output, context);
                output.extend_from_slice(&scalar);
                finish_frame(output, ROUND10_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 10, ROUND10_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            Ok(<$message>::new(context, read_scalar(&mut cursor)?))
        }
    };
}

impl_round10_codec!(ClientEShareMessage, CLIENT_ROLE, decode_client_round10);
impl_round10_codec!(
    SigningWorkerEShareMessage,
    SIGNING_WORKER_ROLE,
    decode_signing_worker_round10
);

macro_rules! impl_round11_codec {
    ($message:ty, $role:expr, $decode:ident) => {
        impl EncodePresignMessage for $message {
            fn encode_presign_message(self) -> Result<Vec<u8>, PresignCodecError> {
                let (context, alpha, beta) = self.into_parts();
                let mut output = frame($role, 11, ROUND11_PAYLOAD_SIZE);
                write_context(&mut output, context);
                output.extend_from_slice(&alpha);
                output.extend_from_slice(&beta);
                finish_frame(output, ROUND11_PAYLOAD_SIZE)
            }
        }

        pub fn $decode(encoded: &[u8]) -> Result<$message, PresignCodecError> {
            let mut cursor = decode_frame(encoded, $role, 11, ROUND11_PAYLOAD_SIZE)?;
            let context = read_context(&mut cursor)?;
            Ok(<$message>::new(
                context,
                read_scalar(&mut cursor)?,
                read_scalar(&mut cursor)?,
            ))
        }
    };
}

impl_round11_codec!(ClientAlphaBetaMessage, CLIENT_ROLE, decode_client_round11);
impl_round11_codec!(
    SigningWorkerAlphaBetaMessage,
    SIGNING_WORKER_ROLE,
    decode_signing_worker_round11
);

#[cfg(test)]
mod tests {
    use k256::{ProjectivePoint, Scalar};
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng,
    };
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::driver::{start_client_driver, start_signing_worker_driver};
    use crate::AdditiveKeyShare;

    type DecodeProbe = fn(&[u8]) -> Result<(), PresignCodecError>;

    struct CorpusFrame {
        label: &'static str,
        encoded: Vec<u8>,
        decode: DecodeProbe,
    }

    macro_rules! record_round_trip {
        ($corpus:expr, $label:literal, $message:expr, $decode:ident) => {{
            let encoded = $message
                .encode_presign_message()
                .expect(concat!("encode ", $label));
            let decode: DecodeProbe = |bytes| $decode(bytes).map(|_| ());
            $corpus.push(CorpusFrame {
                label: $label,
                encoded: encoded.clone(),
                decode,
            });
            $decode(&encoded).expect(concat!("decode ", $label))
        }};
    }

    fn corpus_digest(corpus: &[CorpusFrame]) -> String {
        let mut hasher = Sha256::new();
        for frame in corpus {
            hasher.update((frame.label.len() as u16).to_be_bytes());
            hasher.update(frame.label.as_bytes());
            hasher.update((frame.encoded.len() as u32).to_be_bytes());
            hasher.update(&frame.encoded);
        }
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn assert_strict_frame_mutations(corpus: &[CorpusFrame]) {
        for frame in corpus {
            for truncated_len in 0..frame.encoded.len() {
                assert!(
                    (frame.decode)(&frame.encoded[..truncated_len]).is_err(),
                    "{} accepted a truncated frame of {truncated_len} bytes",
                    frame.label
                );
            }

            let mut trailing = frame.encoded.clone();
            trailing.push(0);
            assert!(
                (frame.decode)(&trailing).is_err(),
                "{} accepted trailing bytes",
                frame.label
            );

            for (offset, replacement) in [
                (0usize, frame.encoded[0] ^ 1),
                (4, VERSION.wrapping_add(1)),
                (
                    5,
                    if frame.encoded[5] == CLIENT_ROLE {
                        SIGNING_WORKER_ROLE
                    } else {
                        CLIENT_ROLE
                    },
                ),
                (6, 0),
                (7, 1),
            ] {
                let mut mutated = frame.encoded.clone();
                mutated[offset] = replacement;
                assert!(
                    (frame.decode)(&mutated).is_err(),
                    "{} accepted mutated header byte {offset}",
                    frame.label
                );
            }

            let mut oversized = frame.encoded.clone();
            oversized[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(
                (frame.decode)(&oversized).is_err(),
                "{} accepted an oversized declared payload",
                frame.label
            );

            for offset in [
                HEADER_SIZE,
                frame.encoded.len() / 2,
                frame.encoded.len() - 1,
            ] {
                let mut mutated = frame.encoded.clone();
                mutated[offset] ^= 1;
                let _ = (frame.decode)(&mutated);
            }
        }
    }

    fn assert_seeded_frame_fuzz(corpus: &[CorpusFrame]) {
        let mut rng = ChaCha20Rng::from_seed([0xA7; 32]);
        for _ in 0..4_096 {
            let frame = &corpus[(rng.next_u32() as usize) % corpus.len()];
            let mut mutated = frame.encoded.clone();
            match rng.next_u32() % 4 {
                0 => {
                    let offset = (rng.next_u32() as usize) % mutated.len();
                    mutated[offset] ^= 1 << (rng.next_u32() % 8);
                }
                1 => {
                    let new_len = (rng.next_u32() as usize) % mutated.len();
                    mutated.truncate(new_len);
                }
                2 => {
                    let extra_len = 1 + ((rng.next_u32() as usize) % 16);
                    mutated.resize(mutated.len() + extra_len, 0xA5);
                }
                3 => {
                    mutated[8..12].copy_from_slice(&rng.next_u32().to_be_bytes());
                }
                _ => unreachable!("fuzz mutation selector is reduced modulo four"),
            }
            let _ = (frame.decode)(&mutated);
        }
    }

    fn context() -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([0x31; 32]),
            PairContextDigest::new([0x42; 32]),
        )
    }

    fn key_share(value: u64) -> AdditiveKeyShare {
        AdditiveKeyShare::from_bytes(ScalarBytes::new(Scalar::from(value).to_bytes().into()))
            .expect("nonzero key share")
    }

    fn wallet_public_key() -> CompressedPointBytes {
        let point = (ProjectivePoint::GENERATOR * Scalar::from(18u64)).to_affine();
        let encoded = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&point, true);
        let bytes: [u8; COMPRESSED_POINT_SIZE] = encoded
            .as_bytes()
            .try_into()
            .expect("compressed point width");
        CompressedPointBytes::new(bytes)
    }

    #[test]
    fn every_fixed_round_round_trips_and_drives_new_new() {
        let mut client_rng = ChaCha20Rng::from_seed([0x11; 32]);
        let mut worker_rng = ChaCha20Rng::from_seed([0x22; 32]);
        let mut corpus = Vec::with_capacity(22);
        let context = context();
        let key = wallet_public_key();
        let (client, client_round1) =
            start_client_driver(context, key_share(7), key, &mut client_rng).expect("client r1");
        let (worker, worker_round1) =
            start_signing_worker_driver(context, key_share(11), key, &mut worker_rng)
                .expect("worker r1");
        let client_round1 = record_round_trip!(
            corpus,
            "client-round-01",
            client_round1,
            decode_client_round1
        );
        let worker_round1 = record_round_trip!(
            corpus,
            "signing-worker-round-01",
            worker_round1,
            decode_signing_worker_round1
        );

        let (client, client_round2) = client
            .receive(worker_round1, &mut client_rng)
            .expect("client r2");
        let (worker, worker_round2) = worker
            .receive(client_round1, &mut worker_rng)
            .expect("worker r2");
        let client_round2 = record_round_trip!(
            corpus,
            "client-round-02",
            client_round2,
            decode_client_round2
        );
        let worker_round2 = record_round_trip!(
            corpus,
            "signing-worker-round-02",
            worker_round2,
            decode_signing_worker_round2
        );

        let (client, client_round3) = client
            .receive(worker_round2, &mut client_rng)
            .expect("client r3");
        let (worker, worker_round3) = worker
            .receive(client_round2, &mut worker_rng)
            .expect("worker r3");
        let client_round3 = record_round_trip!(
            corpus,
            "client-round-03",
            client_round3,
            decode_client_round3
        );
        let worker_round3 = record_round_trip!(
            corpus,
            "signing-worker-round-03",
            worker_round3,
            decode_signing_worker_round3
        );

        let (client, client_round4) = client
            .receive(worker_round3, &mut client_rng)
            .expect("client r4");
        let (worker, worker_round4) = worker
            .receive(client_round3, &mut worker_rng)
            .expect("worker r4");
        let client_round4 = record_round_trip!(
            corpus,
            "client-round-04",
            client_round4,
            decode_client_round4
        );
        let worker_round4 = record_round_trip!(
            corpus,
            "signing-worker-round-04",
            worker_round4,
            decode_signing_worker_round4
        );

        let (client, client_round5) = client.receive(worker_round4).expect("client r5");
        let (worker, worker_round5) = worker.receive(client_round4).expect("worker r5");
        let client_round5 = record_round_trip!(
            corpus,
            "client-round-05",
            client_round5,
            decode_client_round5
        );
        let worker_round5 = record_round_trip!(
            corpus,
            "signing-worker-round-05",
            worker_round5,
            decode_signing_worker_round5
        );

        let (client, client_round6) = client.receive(worker_round5).expect("client r6");
        let (worker, worker_round6) = worker.receive(client_round5).expect("worker r6");
        let client_round6 = record_round_trip!(
            corpus,
            "client-round-06",
            client_round6,
            decode_client_round6
        );
        let worker_round6 = record_round_trip!(
            corpus,
            "signing-worker-round-06",
            worker_round6,
            decode_signing_worker_round6
        );

        let (client, client_round7) = client
            .receive(worker_round6, &mut client_rng)
            .expect("client r7");
        let (worker, worker_round7) = worker
            .receive(client_round6, &mut worker_rng)
            .expect("worker r7");
        let client_round7 = record_round_trip!(
            corpus,
            "client-round-07",
            client_round7,
            decode_client_round7
        );
        let worker_round7 = record_round_trip!(
            corpus,
            "signing-worker-round-07",
            worker_round7,
            decode_signing_worker_round7
        );

        let (client, client_round8) = client
            .receive(worker_round7, &mut client_rng)
            .expect("client r8");
        let (worker, worker_round8) = worker
            .receive(client_round7, &mut worker_rng)
            .expect("worker r8");
        let client_round8 = record_round_trip!(
            corpus,
            "client-round-08",
            client_round8,
            decode_client_round8
        );
        let worker_round8 = record_round_trip!(
            corpus,
            "signing-worker-round-08",
            worker_round8,
            decode_signing_worker_round8
        );

        let (client, client_round9) = client
            .receive(worker_round8, &mut client_rng)
            .expect("client r9");
        let (worker, worker_round9) = worker
            .receive(client_round8, &mut worker_rng)
            .expect("worker r9");
        let client_round9 = record_round_trip!(
            corpus,
            "client-round-09",
            client_round9,
            decode_client_round9
        );
        let worker_round9 = record_round_trip!(
            corpus,
            "signing-worker-round-09",
            worker_round9,
            decode_signing_worker_round9
        );

        let (client, client_round10) = client.receive(worker_round9).expect("client r10");
        let (worker, worker_round10) = worker.receive(client_round9).expect("worker r10");
        let client_round10 = record_round_trip!(
            corpus,
            "client-round-10",
            client_round10,
            decode_client_round10
        );
        let worker_round10 = record_round_trip!(
            corpus,
            "signing-worker-round-10",
            worker_round10,
            decode_signing_worker_round10
        );

        let (client, client_round11) = client.receive(worker_round10).expect("client r11");
        let (worker, worker_round11) = worker.receive(client_round10).expect("worker r11");
        let client_round11 = record_round_trip!(
            corpus,
            "client-round-11",
            client_round11,
            decode_client_round11
        );
        let worker_round11 = record_round_trip!(
            corpus,
            "signing-worker-round-11",
            worker_round11,
            decode_signing_worker_round11
        );

        let client_output = client.receive(worker_round11).expect("client output");
        let worker_output = worker.receive(client_round11).expect("worker output");
        assert_eq!(client_output.into_parts().0, worker_output.into_parts().0);
        assert_eq!(corpus.len(), 22);
        assert_eq!(
            corpus
                .iter()
                .map(|frame| frame.encoded.len())
                .sum::<usize>(),
            152_826
        );
        assert_eq!(
            corpus_digest(&corpus),
            "16bdcb259e861750250969bb4b9491f4620f0157cdda9a0a4433e6f2b9ed6eac"
        );
        assert_strict_frame_mutations(&corpus);
        assert_seeded_frame_fuzz(&corpus);
    }

    #[test]
    fn header_rejects_role_round_flags_length_and_trailing_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let (_, message) =
            start_client_driver(context(), key_share(7), wallet_public_key(), &mut rng)
                .expect("client r1");
        let encoded = message.encode_presign_message().expect("encode");

        let mut wrong_role = encoded.clone();
        wrong_role[5] = SIGNING_WORKER_ROLE;
        assert_eq!(
            decode_client_round1(&wrong_role).err().expect("wrong role"),
            PresignCodecError::UnexpectedSenderRole
        );

        let mut wrong_round = encoded.clone();
        wrong_round[6] = 2;
        assert_eq!(
            decode_client_round1(&wrong_round)
                .err()
                .expect("wrong round"),
            PresignCodecError::UnexpectedRound
        );

        let mut flags = encoded.clone();
        flags[7] = 1;
        assert_eq!(
            decode_client_round1(&flags).err().expect("nonzero flags"),
            PresignCodecError::NonZeroFlags
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_client_round1(&trailing)
                .err()
                .expect("trailing bytes"),
            PresignCodecError::LengthMismatch
        );
    }
}
