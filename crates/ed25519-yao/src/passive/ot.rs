//! Benchmark-only fresh-base Chou-Orlandi and semi-honest IKNP input transfer.
//!
//! This module is isolated Phase 4 viability code. It has no production
//! conversion, transport, reusable base-OT state, or active-security claim.

#![allow(dead_code)]

use core::{fmt, marker::PhantomData};

use aes::{
    cipher::{Block, BlockEncrypt, KeyInit},
    Aes128,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SECURITY_PARAMETER: usize = 128;
const BASE_CHOICE_BYTES: usize = SECURITY_PARAMETER / 8;
const LABEL_BYTES: usize = 16;
const POINT_BYTES: usize = 32;
const FRAME_HEADER_BYTES: usize = 48;
const FRAME_MAGIC: [u8; 8] = *b"YAOOTB01";
const FRAME_RESERVED_BYTES: usize = 6;
const BASE_OFFER_TYPE: u8 = 1;
const BASE_CHOICES_TYPE: u8 = 2;
const EXTENSION_MATRIX_TYPE: u8 = 3;
const MASKED_PAYLOADS_TYPE: u8 = 4;
const BASE_SEED_DOMAIN: &[u8] = b"seams:ed25519-yao:passive-ot:base-seed:v1";
const LABEL_PAD_DOMAIN: &[u8] = b"seams:ed25519-yao:passive-ot:label-pad:v1";
const ROW_EXPANSION_DOMAIN: [u8; 8] = *b"YAOIKNP1";

/// Failures from the benchmark-only passive OT state machine and wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OtError {
    /// The operating system random source failed.
    Randomness,
    /// A fixed-size input, output, or frame had the wrong length.
    InvalidLength,
    /// The fixed frame magic or reserved bytes were invalid.
    InvalidHeader,
    /// A frame used the wrong fixed message type.
    InvalidMessageType,
    /// A frame was decoded as the wrong fixed circuit family.
    InvalidFamily,
    /// A frame contained the forbidden all-zero session identifier.
    InvalidSession,
    /// A compressed Ristretto point was invalid or the identity.
    InvalidPoint,
    /// A message belonged to a different ceremony session.
    SessionMismatch,
}

impl fmt::Display for OtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "passive benchmark OT failed: {self:?}")
    }
}

impl From<getrandom::Error> for OtError {
    fn from(_: getrandom::Error) -> Self {
        Self::Randomness
    }
}

/// Caller-provided nonzero ceremony domain bound into every OT frame and hash.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub(super) struct OtSessionId([u8; 32]);

impl OtSessionId {
    /// Validates a fixed ceremony domain supplied by the surrounding role protocol.
    pub(super) fn new(bytes: [u8; 32]) -> Result<Self, OtError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(OtError::InvalidSession)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Borrows the exact ceremony-domain bytes for surrounding transcript binding.
    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    fn random_for_test() -> Result<Self, OtError> {
        loop {
            let mut bytes = [0_u8; 32];
            fill_os_random(&mut bytes)?;
            if bytes.iter().any(|byte| *byte != 0) {
                return Self::new(bytes);
            }
            bytes.zeroize();
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, OtError> {
        let encoded: [u8; 32] = bytes.try_into().map_err(|_| OtError::InvalidLength)?;
        Self::new(encoded)
    }
}

impl fmt::Debug for OtSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OtSessionId([REDACTED])")
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed benchmark family shape used by the typed OT states and codecs.
pub(super) trait OtFamily: sealed::Sealed + 'static {
    /// Fixed family byte in every OT frame and hash domain.
    const CODE: u8;
    /// Exact number of evaluator-selected circuit inputs.
    const OT_COUNT: usize;
    /// Exact packed bytes in one IKNP row.
    const ROW_BYTES: usize = Self::OT_COUNT / 8;
    /// Exact bytes in the complete 128-row IKNP correction matrix.
    const MATRIX_BYTES: usize = SECURITY_PARAMETER * Self::ROW_BYTES;
    /// Exact bytes in two masked 16-byte payloads per input.
    const MASKED_PAYLOAD_BYTES: usize = Self::OT_COUNT * 2 * LABEL_BYTES;
}

/// The fixed 1,536-choice activation-family benchmark OT shape.
#[derive(Debug)]
pub(super) struct ActivationOtFamily;

impl sealed::Sealed for ActivationOtFamily {}

impl OtFamily for ActivationOtFamily {
    const CODE: u8 = 1;
    const OT_COUNT: usize = 1_536;
}

/// The fixed 768-choice export-family benchmark OT shape.
#[derive(Debug)]
pub(super) struct ExportOtFamily;

impl sealed::Sealed for ExportOtFamily {}

impl OtFamily for ExportOtFamily {
    const CODE: u8 = 2;
    const OT_COUNT: usize = 768;
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PayloadPair {
    zero: [u8; LABEL_BYTES],
    one: [u8; LABEL_BYTES],
}

/// Exactly one family-sized vector of garbler-owned 16-byte payload pairs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SenderPayloads<F: OtFamily> {
    pairs: Vec<PayloadPair>,
    family: PhantomData<F>,
}

impl<F: OtFamily> SenderPayloads<F> {
    /// Validates the exact family count at the local typed boundary.
    pub(super) fn new(
        mut pairs: Vec<([u8; LABEL_BYTES], [u8; LABEL_BYTES])>,
    ) -> Result<Self, OtError> {
        if pairs.len() != F::OT_COUNT {
            pairs.zeroize();
            return Err(OtError::InvalidLength);
        }
        Ok(Self {
            pairs: pairs
                .into_iter()
                .map(|(zero, one)| PayloadPair { zero, one })
                .collect(),
            family: PhantomData,
        })
    }
}

/// Exactly one family-sized packed vector of evaluator choice bits.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ReceiverChoices<F: OtFamily> {
    bytes: Vec<u8>,
    family: PhantomData<F>,
}

impl<F: OtFamily> ReceiverChoices<F> {
    /// Validates the exact family bit count at the local typed boundary.
    pub(super) fn from_packed_bytes(mut bytes: Vec<u8>) -> Result<Self, OtError> {
        if bytes.len() != F::ROW_BYTES {
            bytes.zeroize();
            return Err(OtError::InvalidLength);
        }
        Ok(Self {
            bytes,
            family: PhantomData,
        })
    }

    fn bit(&self, index: usize) -> u8 {
        (self.bytes[index / 8] >> (index % 8)) & 1
    }
}

/// Family-sized selected evaluator payloads returned by the final OT flight.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SelectedPayloads<F: OtFamily> {
    payloads: Vec<[u8; LABEL_BYTES]>,
    family: PhantomData<F>,
}

impl<F: OtFamily> SelectedPayloads<F> {
    /// Borrows the selected 16-byte payloads in circuit input order.
    pub(super) fn as_slice(&self) -> &[[u8; LABEL_BYTES]] {
        &self.payloads
    }
}

struct DecodedFrame<'a> {
    session: OtSessionId,
    payload: &'a [u8],
}

fn encode_frame<F: OtFamily>(message_type: u8, session: OtSessionId, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    encoded.extend_from_slice(&FRAME_MAGIC);
    encoded.push(message_type);
    encoded.push(F::CODE);
    encoded.extend_from_slice(&[0_u8; FRAME_RESERVED_BYTES]);
    encoded.extend_from_slice(&session.0);
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_frame<F: OtFamily>(
    encoded: &[u8],
    message_type: u8,
    payload_bytes: usize,
) -> Result<DecodedFrame<'_>, OtError> {
    if encoded.len() < FRAME_HEADER_BYTES {
        return Err(OtError::InvalidLength);
    }
    if encoded[..8] != FRAME_MAGIC || encoded[10..16] != [0_u8; FRAME_RESERVED_BYTES] {
        return Err(OtError::InvalidHeader);
    }
    if encoded[8] != message_type {
        return Err(OtError::InvalidMessageType);
    }
    if encoded[9] != F::CODE {
        return Err(OtError::InvalidFamily);
    }
    if encoded.len() != FRAME_HEADER_BYTES + payload_bytes {
        return Err(OtError::InvalidLength);
    }
    Ok(DecodedFrame {
        session: OtSessionId::decode(&encoded[16..48])?,
        payload: &encoded[FRAME_HEADER_BYTES..],
    })
}

fn decode_points(payload: &[u8]) -> Result<Vec<RistrettoPoint>, OtError> {
    if payload.len() != SECURITY_PARAMETER * POINT_BYTES {
        return Err(OtError::InvalidLength);
    }
    let mut points = Vec::with_capacity(SECURITY_PARAMETER);
    let mut offset = 0_usize;
    while offset < payload.len() {
        let encoded: [u8; POINT_BYTES] = payload[offset..offset + POINT_BYTES]
            .try_into()
            .map_err(|_| OtError::InvalidLength)?;
        let point = CompressedRistretto(encoded)
            .decompress()
            .ok_or(OtError::InvalidPoint)?;
        if point.is_identity() {
            return Err(OtError::InvalidPoint);
        }
        points.push(point);
        offset += POINT_BYTES;
    }
    Ok(points)
}

fn encode_points(points: &[RistrettoPoint]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(points.len() * POINT_BYTES);
    for point in points {
        encoded.extend_from_slice(point.compress().as_bytes());
    }
    encoded
}

/// Flight 1: B's 128 fresh Chou-Orlandi base-OT sender points.
pub(super) struct BaseOffer<F: OtFamily> {
    session: OtSessionId,
    points: Vec<RistrettoPoint>,
    family: PhantomData<F>,
}

impl<F: OtFamily> BaseOffer<F> {
    /// Returns the exact fixed wire byte count for this flight.
    pub(super) const fn wire_bytes() -> usize {
        FRAME_HEADER_BYTES + SECURITY_PARAMETER * POINT_BYTES
    }

    /// Encodes the exact binary flight with its family and session binding.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode_frame::<F>(BASE_OFFER_TYPE, self.session, &encode_points(&self.points))
    }

    /// Strictly decodes one exact binary base-offer flight.
    pub(super) fn decode(encoded: &[u8]) -> Result<Self, OtError> {
        let frame = decode_frame::<F>(encoded, BASE_OFFER_TYPE, SECURITY_PARAMETER * POINT_BYTES)?;
        Ok(Self {
            session: frame.session,
            points: decode_points(frame.payload)?,
            family: PhantomData,
        })
    }

    /// Decodes an offer and requires the surrounding ceremony's exact OT domain.
    pub(super) fn decode_for_session(
        encoded: &[u8],
        expected_session: OtSessionId,
    ) -> Result<Self, OtError> {
        let offer = Self::decode(encoded)?;
        if offer.session != expected_session {
            return Err(OtError::SessionMismatch);
        }
        Ok(offer)
    }
}

/// Flight 2: A's 128 fresh Chou-Orlandi base-OT receiver points.
pub(super) struct BaseChoices<F: OtFamily> {
    session: OtSessionId,
    points: Vec<RistrettoPoint>,
    family: PhantomData<F>,
}

impl<F: OtFamily> BaseChoices<F> {
    /// Returns the exact fixed wire byte count for this flight.
    pub(super) const fn wire_bytes() -> usize {
        FRAME_HEADER_BYTES + SECURITY_PARAMETER * POINT_BYTES
    }

    /// Encodes the exact binary flight with its family and session binding.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode_frame::<F>(
            BASE_CHOICES_TYPE,
            self.session,
            &encode_points(&self.points),
        )
    }

    /// Strictly decodes one exact binary base-choice flight.
    pub(super) fn decode(encoded: &[u8]) -> Result<Self, OtError> {
        let frame =
            decode_frame::<F>(encoded, BASE_CHOICES_TYPE, SECURITY_PARAMETER * POINT_BYTES)?;
        Ok(Self {
            session: frame.session,
            points: decode_points(frame.payload)?,
            family: PhantomData,
        })
    }
}

/// Flight 3: B's family-sized IKNP correction matrix.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ExtensionMatrix<F: OtFamily> {
    session: OtSessionId,
    matrix: Vec<u8>,
    family: PhantomData<F>,
}

impl<F: OtFamily> ExtensionMatrix<F> {
    /// Returns the exact fixed wire byte count for this family.
    pub(super) const fn wire_bytes() -> usize {
        FRAME_HEADER_BYTES + F::MATRIX_BYTES
    }

    /// Encodes the exact binary flight with its family and session binding.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode_frame::<F>(EXTENSION_MATRIX_TYPE, self.session, &self.matrix)
    }

    /// Strictly decodes one exact binary extension-matrix flight.
    pub(super) fn decode(encoded: &[u8]) -> Result<Self, OtError> {
        let frame = decode_frame::<F>(encoded, EXTENSION_MATRIX_TYPE, F::MATRIX_BYTES)?;
        Ok(Self {
            session: frame.session,
            matrix: frame.payload.to_vec(),
            family: PhantomData,
        })
    }
}

/// Flight 4: A's two masked 16-byte payloads per evaluator choice.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct MaskedPayloads<F: OtFamily> {
    session: OtSessionId,
    payloads: Vec<u8>,
    family: PhantomData<F>,
}

impl<F: OtFamily> MaskedPayloads<F> {
    /// Returns the exact fixed wire byte count for this family.
    pub(super) const fn wire_bytes() -> usize {
        FRAME_HEADER_BYTES + F::MASKED_PAYLOAD_BYTES
    }

    /// Encodes the exact binary flight with its family and session binding.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode_frame::<F>(MASKED_PAYLOADS_TYPE, self.session, &self.payloads)
    }

    /// Strictly decodes one exact binary masked-payload flight.
    pub(super) fn decode(encoded: &[u8]) -> Result<Self, OtError> {
        let frame = decode_frame::<F>(encoded, MASKED_PAYLOADS_TYPE, F::MASKED_PAYLOAD_BYTES)?;
        Ok(Self {
            session: frame.session,
            payloads: frame.payload.to_vec(),
            family: PhantomData,
        })
    }
}

fn fill_os_random(bytes: &mut [u8]) -> Result<(), OtError> {
    if let Err(error) = getrandom::getrandom(bytes) {
        bytes.zeroize();
        Err(error.into())
    } else {
        Ok(())
    }
}

fn random_nonzero_scalar() -> Result<Scalar, OtError> {
    let mut wide = [0_u8; 64];
    fill_os_random(&mut wide)?;
    let mut scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    let nonzero = Scalar::conditional_select(&scalar, &Scalar::ONE, scalar.ct_eq(&Scalar::ZERO));
    scalar.zeroize();
    Ok(nonzero)
}

fn packed_bit(bytes: &[u8], index: usize) -> u8 {
    (bytes[index / 8] >> (index % 8)) & 1
}

fn derive_base_seed<F: OtFamily>(
    session: OtSessionId,
    base_index: usize,
    branch: u8,
    shared: &RistrettoPoint,
) -> [u8; LABEL_BYTES] {
    let mut hash = Sha256::new();
    hash.update(BASE_SEED_DOMAIN);
    hash.update(session.0);
    hash.update([F::CODE]);
    hash.update((base_index as u16).to_be_bytes());
    hash.update([branch]);
    hash.update(shared.compress().as_bytes());
    let mut digest = hash.finalize();
    let mut seed = [0_u8; LABEL_BYTES];
    seed.copy_from_slice(&digest[..LABEL_BYTES]);
    digest.as_mut_slice().zeroize();
    seed
}

fn expand_row<F: OtFamily>(seed: &[u8; LABEL_BYTES], row_index: usize, row: &mut [u8]) {
    let cipher = Aes128::new(&(*seed).into());
    let block_count = F::ROW_BYTES / LABEL_BYTES;
    let mut block_index = 0_usize;
    while block_index < block_count {
        let mut input = [0_u8; LABEL_BYTES];
        input[..8].copy_from_slice(&ROW_EXPANSION_DOMAIN);
        input[8] = F::CODE;
        input[9..11].copy_from_slice(&(row_index as u16).to_be_bytes());
        input[12..16].copy_from_slice(&(block_index as u32).to_be_bytes());
        let mut block: Block<Aes128> = input.into();
        cipher.encrypt_block(&mut block);
        let offset = block_index * LABEL_BYTES;
        row[offset..offset + LABEL_BYTES].copy_from_slice(&block);
        input.zeroize();
        block.as_mut_slice().zeroize();
        block_index += 1;
    }
}

fn derive_label_pad<F: OtFamily>(
    session: OtSessionId,
    message_index: usize,
    column: &[u8; BASE_CHOICE_BYTES],
) -> [u8; LABEL_BYTES] {
    let mut hash = Sha256::new();
    hash.update(LABEL_PAD_DOMAIN);
    hash.update(session.0);
    hash.update([F::CODE]);
    hash.update((message_index as u32).to_be_bytes());
    hash.update(column);
    let mut digest = hash.finalize();
    let mut pad = [0_u8; LABEL_BYTES];
    pad.copy_from_slice(&digest[..LABEL_BYTES]);
    digest.as_mut_slice().zeroize();
    pad
}

fn matrix_column<F: OtFamily>(matrix: &[u8], message_index: usize) -> [u8; BASE_CHOICE_BYTES] {
    let source_byte = message_index / 8;
    let source_bit = message_index % 8;
    let mut column = [0_u8; BASE_CHOICE_BYTES];
    let mut row_index = 0_usize;
    while row_index < SECURITY_PARAMETER {
        let bit = (matrix[row_index * F::ROW_BYTES + source_byte] >> source_bit) & 1;
        column[row_index / 8] |= bit << (row_index % 8);
        row_index += 1;
    }
    column
}

fn conditional_xor(target: &mut [u8], source: &[u8], choice: u8) {
    let choice = Choice::from(choice);
    let mut index = 0_usize;
    while index < target.len() {
        target[index] ^= u8::conditional_select(&0, &source[index], choice);
        index += 1;
    }
}

fn xor_label(left: &[u8; LABEL_BYTES], right: &[u8; LABEL_BYTES]) -> [u8; LABEL_BYTES] {
    let mut output = [0_u8; LABEL_BYTES];
    let mut index = 0_usize;
    while index < LABEL_BYTES {
        output[index] = left[index] ^ right[index];
        index += 1;
    }
    output
}

fn select_label(
    zero: &[u8; LABEL_BYTES],
    one: &[u8; LABEL_BYTES],
    choice: u8,
) -> [u8; LABEL_BYTES] {
    let choice = Choice::from(choice);
    let mut output = [0_u8; LABEL_BYTES];
    let mut index = 0_usize;
    while index < LABEL_BYTES {
        output[index] = u8::conditional_select(&zero[index], &one[index], choice);
        index += 1;
    }
    output
}

fn base_receiver_response(
    offer: &RistrettoPoint,
    mut scalar: Scalar,
    choice: u8,
) -> (Scalar, RistrettoPoint) {
    let identity = RistrettoPoint::identity();
    let selected_offer = RistrettoPoint::conditional_select(&identity, offer, Choice::from(choice));
    let mut response = RistrettoPoint::mul_base(&scalar) + selected_offer;
    let mut repair = 0_u8;
    while repair < 2 {
        let invalid = response.ct_eq(&identity) | response.ct_eq(offer);
        let scalar_increment = Scalar::conditional_select(&Scalar::ZERO, &Scalar::ONE, invalid);
        let point_increment =
            RistrettoPoint::conditional_select(&identity, &RISTRETTO_BASEPOINT_POINT, invalid);
        scalar += scalar_increment;
        response += point_increment;
        repair += 1;
    }
    (scalar, response)
}

/// Initial one-shot evaluator state for a fresh passive OT ceremony.
pub(super) struct ReceiverStart<F: OtFamily>(PhantomData<F>);

impl<F: OtFamily> ReceiverStart<F> {
    /// Constructs an unstarted family-specific evaluator state.
    pub(super) const fn new() -> Self {
        Self(PhantomData)
    }

    /// Samples fresh base-OT state and emits flight 1.
    pub(super) fn begin_os(
        self,
        session: OtSessionId,
        choices: ReceiverChoices<F>,
    ) -> Result<(ReceiverAwaitBaseChoices<F>, BaseOffer<F>), OtError> {
        let mut scalars = Vec::with_capacity(SECURITY_PARAMETER);
        let mut points = Vec::with_capacity(SECURITY_PARAMETER);
        let mut index = 0_usize;
        while index < SECURITY_PARAMETER {
            let scalar = match random_nonzero_scalar() {
                Ok(scalar) => scalar,
                Err(error) => {
                    scalars.zeroize();
                    return Err(error);
                }
            };
            points.push(RistrettoPoint::mul_base(&scalar));
            scalars.push(scalar);
            index += 1;
        }
        Ok((
            ReceiverAwaitBaseChoices {
                session,
                choices,
                offer_scalars: scalars,
            },
            BaseOffer {
                session,
                points,
                family: PhantomData,
            },
        ))
    }
}

/// Evaluator state that consumes exactly one family-matched flight 2.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ReceiverAwaitBaseChoices<F: OtFamily> {
    session: OtSessionId,
    choices: ReceiverChoices<F>,
    offer_scalars: Vec<Scalar>,
}

impl<F: OtFamily> ReceiverAwaitBaseChoices<F> {
    /// Completes fresh base OTs and emits the family-sized IKNP matrix in flight 3.
    #[allow(clippy::op_ref)]
    pub(super) fn accept(
        mut self,
        message: BaseChoices<F>,
    ) -> Result<(ReceiverAwaitMaskedPayloads<F>, ExtensionMatrix<F>), OtError> {
        if message.session != self.session {
            return Err(OtError::SessionMismatch);
        }
        let mut retained_matrix = vec![0_u8; F::MATRIX_BYTES];
        let mut extension_matrix = vec![0_u8; F::MATRIX_BYTES];
        let mut row_zero = vec![0_u8; F::ROW_BYTES];
        let mut row_one = vec![0_u8; F::ROW_BYTES];
        let mut row_index = 0_usize;
        while row_index < SECURITY_PARAMETER {
            let offer = RistrettoPoint::mul_base(&self.offer_scalars[row_index]);
            let mut shared_zero = &message.points[row_index] * &self.offer_scalars[row_index];
            let mut shared_one =
                (&message.points[row_index] - &offer) * &self.offer_scalars[row_index];
            let mut seed_zero = derive_base_seed::<F>(self.session, row_index, 0, &shared_zero);
            let mut seed_one = derive_base_seed::<F>(self.session, row_index, 1, &shared_one);
            shared_zero.zeroize();
            shared_one.zeroize();
            expand_row::<F>(&seed_zero, row_index, &mut row_zero);
            expand_row::<F>(&seed_one, row_index, &mut row_one);
            seed_zero.zeroize();
            seed_one.zeroize();

            let row_start = row_index * F::ROW_BYTES;
            let row_end = row_start + F::ROW_BYTES;
            retained_matrix[row_start..row_end].copy_from_slice(&row_zero);
            let mut byte_index = 0_usize;
            while byte_index < F::ROW_BYTES {
                extension_matrix[row_start + byte_index] =
                    row_zero[byte_index] ^ row_one[byte_index] ^ self.choices.bytes[byte_index];
                byte_index += 1;
            }
            row_index += 1;
        }
        row_zero.zeroize();
        row_one.zeroize();

        let choice_bytes = core::mem::take(&mut self.choices.bytes);
        let next = ReceiverAwaitMaskedPayloads {
            session: self.session,
            choices: ReceiverChoices {
                bytes: choice_bytes,
                family: PhantomData,
            },
            retained_matrix,
        };
        let flight = ExtensionMatrix {
            session: self.session,
            matrix: extension_matrix,
            family: PhantomData,
        };
        Ok((next, flight))
    }
}

/// Initial one-shot garbler state for a fresh passive OT ceremony.
pub(super) struct SenderStart<F: OtFamily>(PhantomData<F>);

impl<F: OtFamily> SenderStart<F> {
    /// Constructs an unstarted family-specific garbler state.
    pub(super) const fn new() -> Self {
        Self(PhantomData)
    }

    /// Samples fresh base choices and emits flight 2 for one decoded offer.
    #[allow(clippy::op_ref)]
    pub(super) fn begin_os(
        self,
        offer: BaseOffer<F>,
        payloads: SenderPayloads<F>,
    ) -> Result<(SenderAwaitExtension<F>, BaseChoices<F>), OtError> {
        let mut base_choices = [0_u8; BASE_CHOICE_BYTES];
        fill_os_random(&mut base_choices)?;
        let mut chosen_seeds = Vec::with_capacity(SECURITY_PARAMETER);
        let mut response_points = Vec::with_capacity(SECURITY_PARAMETER);
        let mut row_index = 0_usize;
        while row_index < SECURITY_PARAMETER {
            let choice = packed_bit(&base_choices, row_index);
            let scalar = match random_nonzero_scalar() {
                Ok(scalar) => scalar,
                Err(error) => {
                    base_choices.zeroize();
                    chosen_seeds.zeroize();
                    return Err(error);
                }
            };
            let (mut scalar, response) =
                base_receiver_response(&offer.points[row_index], scalar, choice);
            let mut shared = &offer.points[row_index] * &scalar;
            chosen_seeds.push(derive_base_seed::<F>(
                offer.session,
                row_index,
                choice,
                &shared,
            ));
            shared.zeroize();
            response_points.push(response);
            scalar.zeroize();
            row_index += 1;
        }
        Ok((
            SenderAwaitExtension {
                session: offer.session,
                base_choices,
                chosen_seeds,
                payloads,
            },
            BaseChoices {
                session: offer.session,
                points: response_points,
                family: PhantomData,
            },
        ))
    }
}

/// Garbler state that consumes exactly one family-matched flight 3.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SenderAwaitExtension<F: OtFamily> {
    session: OtSessionId,
    base_choices: [u8; BASE_CHOICE_BYTES],
    chosen_seeds: Vec<[u8; LABEL_BYTES]>,
    payloads: SenderPayloads<F>,
}

impl<F: OtFamily> SenderAwaitExtension<F> {
    /// Completes IKNP and emits the two masked labels per input in flight 4.
    pub(super) fn accept(self, message: ExtensionMatrix<F>) -> Result<MaskedPayloads<F>, OtError> {
        if message.session != self.session {
            return Err(OtError::SessionMismatch);
        }
        let mut sender_matrix = vec![0_u8; F::MATRIX_BYTES];
        let mut row_index = 0_usize;
        while row_index < SECURITY_PARAMETER {
            let row_start = row_index * F::ROW_BYTES;
            let row_end = row_start + F::ROW_BYTES;
            let row = &mut sender_matrix[row_start..row_end];
            expand_row::<F>(&self.chosen_seeds[row_index], row_index, row);
            conditional_xor(
                row,
                &message.matrix[row_start..row_end],
                packed_bit(&self.base_choices, row_index),
            );
            row_index += 1;
        }

        let mut encoded = vec![0_u8; F::MASKED_PAYLOAD_BYTES];
        let mut message_index = 0_usize;
        while message_index < F::OT_COUNT {
            let mut column_zero = matrix_column::<F>(&sender_matrix, message_index);
            let mut column_one = column_zero;
            let mut byte_index = 0_usize;
            while byte_index < BASE_CHOICE_BYTES {
                column_one[byte_index] ^= self.base_choices[byte_index];
                byte_index += 1;
            }
            let mut pad_zero = derive_label_pad::<F>(self.session, message_index, &column_zero);
            let mut pad_one = derive_label_pad::<F>(self.session, message_index, &column_one);
            let mut masked_zero = xor_label(&self.payloads.pairs[message_index].zero, &pad_zero);
            let mut masked_one = xor_label(&self.payloads.pairs[message_index].one, &pad_one);
            let offset = message_index * 2 * LABEL_BYTES;
            encoded[offset..offset + LABEL_BYTES].copy_from_slice(&masked_zero);
            encoded[offset + LABEL_BYTES..offset + 2 * LABEL_BYTES].copy_from_slice(&masked_one);
            column_zero.zeroize();
            column_one.zeroize();
            pad_zero.zeroize();
            pad_one.zeroize();
            masked_zero.zeroize();
            masked_one.zeroize();
            message_index += 1;
        }
        sender_matrix.zeroize();
        Ok(MaskedPayloads {
            session: self.session,
            payloads: encoded,
            family: PhantomData,
        })
    }
}

/// Evaluator state that consumes exactly one family-matched flight 4.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ReceiverAwaitMaskedPayloads<F: OtFamily> {
    session: OtSessionId,
    choices: ReceiverChoices<F>,
    retained_matrix: Vec<u8>,
}

impl<F: OtFamily> ReceiverAwaitMaskedPayloads<F> {
    /// Opens exactly the selected payload from every fixed pair.
    pub(super) fn accept(self, message: MaskedPayloads<F>) -> Result<SelectedPayloads<F>, OtError> {
        if message.session != self.session {
            return Err(OtError::SessionMismatch);
        }
        let mut selected = Vec::with_capacity(F::OT_COUNT);
        let mut message_index = 0_usize;
        while message_index < F::OT_COUNT {
            let mut column = matrix_column::<F>(&self.retained_matrix, message_index);
            let mut pad = derive_label_pad::<F>(self.session, message_index, &column);
            let offset = message_index * 2 * LABEL_BYTES;
            let mut zero = [0_u8; LABEL_BYTES];
            let mut one = [0_u8; LABEL_BYTES];
            zero.copy_from_slice(&message.payloads[offset..offset + LABEL_BYTES]);
            one.copy_from_slice(&message.payloads[offset + LABEL_BYTES..offset + 2 * LABEL_BYTES]);
            let mut masked = select_label(&zero, &one, self.choices.bit(message_index));
            let output = xor_label(&masked, &pad);
            selected.push(output);
            column.zeroize();
            pad.zeroize();
            zero.zeroize();
            one.zeroize();
            masked.zeroize();
            message_index += 1;
        }
        Ok(SelectedPayloads {
            payloads: selected,
            family: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum ChoicePattern {
        Zero,
        One,
        Alternating,
        Random,
    }

    fn pattern_bytes<F: OtFamily>(pattern: ChoicePattern) -> Vec<u8> {
        match pattern {
            ChoicePattern::Zero => vec![0_u8; F::ROW_BYTES],
            ChoicePattern::One => vec![0xff_u8; F::ROW_BYTES],
            ChoicePattern::Alternating => vec![0xaa_u8; F::ROW_BYTES],
            ChoicePattern::Random => {
                let mut bytes = vec![0_u8; F::ROW_BYTES];
                getrandom::getrandom(&mut bytes).expect("OS randomness");
                bytes
            }
        }
    }

    fn payload_pair(index: usize) -> ([u8; LABEL_BYTES], [u8; LABEL_BYTES]) {
        let mut zero = [0x35_u8; LABEL_BYTES];
        let mut one = [0xca_u8; LABEL_BYTES];
        zero[..8].copy_from_slice(&(index as u64).to_be_bytes());
        one[..8].copy_from_slice(&(!(index as u64)).to_be_bytes());
        (zero, one)
    }

    fn payloads<F: OtFamily>() -> Vec<([u8; LABEL_BYTES], [u8; LABEL_BYTES])> {
        (0..F::OT_COUNT).map(payload_pair).collect()
    }

    fn run_correctness<F: OtFamily>(pattern: ChoicePattern) {
        let choice_bytes = pattern_bytes::<F>(pattern);
        let expected_pairs = payloads::<F>();
        let choices =
            ReceiverChoices::<F>::from_packed_bytes(choice_bytes.clone()).expect("choices");
        let sender_payloads = SenderPayloads::<F>::new(payloads::<F>()).expect("sender payloads");
        let session = OtSessionId::random_for_test().expect("session");

        let (receiver_base, offer) = ReceiverStart::<F>::new()
            .begin_os(session, choices)
            .expect("receiver start");
        let offer_bytes = offer.encode();
        assert_eq!(offer_bytes.len(), BaseOffer::<F>::wire_bytes());
        assert_eq!(&offer_bytes[16..48], session.as_bytes());
        let decoded_offer = BaseOffer::<F>::decode(&offer_bytes).expect("base offer codec");

        let (sender_extension, base_choices) = SenderStart::<F>::new()
            .begin_os(decoded_offer, sender_payloads)
            .expect("sender start");
        let base_choice_bytes = base_choices.encode();
        assert_eq!(base_choice_bytes.len(), BaseChoices::<F>::wire_bytes());
        assert_eq!(&base_choice_bytes[16..48], session.as_bytes());
        let decoded_base_choices =
            BaseChoices::<F>::decode(&base_choice_bytes).expect("base choices codec");

        let (receiver_payloads, extension) = receiver_base
            .accept(decoded_base_choices)
            .expect("receiver extension");
        let extension_bytes = extension.encode();
        assert_eq!(extension_bytes.len(), ExtensionMatrix::<F>::wire_bytes());
        assert_eq!(&extension_bytes[16..48], session.as_bytes());
        let decoded_extension =
            ExtensionMatrix::<F>::decode(&extension_bytes).expect("extension codec");

        let masked = sender_extension
            .accept(decoded_extension)
            .expect("masked payloads");
        let masked_bytes = masked.encode();
        assert_eq!(masked_bytes.len(), MaskedPayloads::<F>::wire_bytes());
        assert_eq!(&masked_bytes[16..48], session.as_bytes());
        let decoded_masked = MaskedPayloads::<F>::decode(&masked_bytes).expect("masked codec");
        let selected = receiver_payloads
            .accept(decoded_masked)
            .expect("selected payloads");

        assert_eq!(selected.as_slice().len(), F::OT_COUNT);
        let mut index = 0_usize;
        while index < F::OT_COUNT {
            let expected = if packed_bit(&choice_bytes, index) == 0 {
                &expected_pairs[index].0
            } else {
                &expected_pairs[index].1
            };
            assert_eq!(&selected.as_slice()[index], expected);
            index += 1;
        }
    }

    #[test]
    fn all_choice_patterns_work_for_both_fixed_families() {
        run_correctness::<ExportOtFamily>(ChoicePattern::Zero);
        run_correctness::<ExportOtFamily>(ChoicePattern::One);
        run_correctness::<ExportOtFamily>(ChoicePattern::Alternating);
        run_correctness::<ExportOtFamily>(ChoicePattern::Random);
        run_correctness::<ActivationOtFamily>(ChoicePattern::Zero);
        run_correctness::<ActivationOtFamily>(ChoicePattern::One);
        run_correctness::<ActivationOtFamily>(ChoicePattern::Alternating);
        run_correctness::<ActivationOtFamily>(ChoicePattern::Random);
    }

    #[test]
    fn family_shapes_and_flight_bytes_are_exact() {
        assert_eq!(ExportOtFamily::OT_COUNT, 768);
        assert_eq!(ActivationOtFamily::OT_COUNT, 1_536);
        assert_eq!(ExportOtFamily::MATRIX_BYTES, 12 * 1_024);
        assert_eq!(ActivationOtFamily::MATRIX_BYTES, 24 * 1_024);
        assert_eq!(BaseOffer::<ExportOtFamily>::wire_bytes(), 4_144);
        assert_eq!(BaseChoices::<ExportOtFamily>::wire_bytes(), 4_144);
        assert_eq!(ExtensionMatrix::<ExportOtFamily>::wire_bytes(), 12_336);
        assert_eq!(MaskedPayloads::<ExportOtFamily>::wire_bytes(), 24_624);
        assert_eq!(BaseOffer::<ActivationOtFamily>::wire_bytes(), 4_144);
        assert_eq!(BaseChoices::<ActivationOtFamily>::wire_bytes(), 4_144);
        assert_eq!(ExtensionMatrix::<ActivationOtFamily>::wire_bytes(), 24_624);
        assert_eq!(MaskedPayloads::<ActivationOtFamily>::wire_bytes(), 49_200);
        assert_eq!(
            BaseOffer::<ExportOtFamily>::wire_bytes()
                + BaseChoices::<ExportOtFamily>::wire_bytes()
                + ExtensionMatrix::<ExportOtFamily>::wire_bytes()
                + MaskedPayloads::<ExportOtFamily>::wire_bytes(),
            45_248
        );
        assert_eq!(
            BaseOffer::<ActivationOtFamily>::wire_bytes()
                + BaseChoices::<ActivationOtFamily>::wire_bytes()
                + ExtensionMatrix::<ActivationOtFamily>::wire_bytes()
                + MaskedPayloads::<ActivationOtFamily>::wire_bytes(),
            82_112
        );
    }

    #[test]
    fn base_response_repairs_both_forbidden_choice_relations() {
        let sender_scalar = Scalar::from(7_u64);
        let offer = RistrettoPoint::mul_base(&sender_scalar);

        let (mut zero_scalar, zero_response) = base_receiver_response(&offer, sender_scalar, 0);
        assert!(!zero_response.is_identity());
        assert_ne!(zero_response, offer);
        let mut zero_receiver_shared = offer * zero_scalar;
        let mut zero_sender_shared = zero_response * sender_scalar;
        assert_eq!(zero_receiver_shared, zero_sender_shared);

        let (mut one_scalar, one_response) = base_receiver_response(&offer, -sender_scalar, 1);
        assert!(!one_response.is_identity());
        assert_ne!(one_response, offer);
        let mut one_receiver_shared = offer * one_scalar;
        let mut one_sender_shared = (one_response - offer) * sender_scalar;
        assert_eq!(one_receiver_shared, one_sender_shared);

        zero_scalar.zeroize();
        one_scalar.zeroize();
        zero_receiver_shared.zeroize();
        zero_sender_shared.zeroize();
        one_receiver_shared.zeroize();
        one_sender_shared.zeroize();
    }

    fn repeated_base_points() -> Vec<RistrettoPoint> {
        let point = RistrettoPoint::mul_base(&Scalar::ONE);
        vec![point; SECURITY_PARAMETER]
    }

    #[test]
    fn codecs_reject_malformed_frames_points_and_old_sizes() {
        let session = OtSessionId::random_for_test().expect("session");
        let offer = BaseOffer::<ExportOtFamily> {
            session,
            points: repeated_base_points(),
            family: PhantomData,
        };
        let valid_offer = offer.encode();
        assert!(BaseOffer::<ExportOtFamily>::decode(&valid_offer).is_ok());

        let mut truncated = valid_offer.clone();
        truncated.pop();
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&truncated).err(),
            Some(OtError::InvalidLength)
        );

        let mut bad_magic = valid_offer.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&bad_magic).err(),
            Some(OtError::InvalidHeader)
        );

        let mut bad_reserved = valid_offer.clone();
        bad_reserved[10] = 1;
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&bad_reserved).err(),
            Some(OtError::InvalidHeader)
        );

        let mut bad_type = valid_offer.clone();
        bad_type[8] = BASE_CHOICES_TYPE;
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&bad_type).err(),
            Some(OtError::InvalidMessageType)
        );

        let mut zero_session = valid_offer.clone();
        zero_session[16..48].fill(0);
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&zero_session).err(),
            Some(OtError::InvalidSession)
        );

        let mut identity_point = valid_offer.clone();
        identity_point[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + POINT_BYTES].fill(0);
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&identity_point).err(),
            Some(OtError::InvalidPoint)
        );

        let old_export_matrix = vec![0_u8; FRAME_HEADER_BYTES + 8 * 1_024];
        assert_eq!(
            ExtensionMatrix::<ExportOtFamily>::decode(&old_export_matrix).err(),
            Some(OtError::InvalidHeader)
        );
        let extension = ExtensionMatrix::<ExportOtFamily> {
            session,
            matrix: vec![0_u8; ExportOtFamily::MATRIX_BYTES],
            family: PhantomData,
        };
        let mut short_extension = extension.encode();
        short_extension.truncate(FRAME_HEADER_BYTES + 8 * 1_024);
        assert_eq!(
            ExtensionMatrix::<ExportOtFamily>::decode(&short_extension).err(),
            Some(OtError::InvalidLength)
        );

        let masked = MaskedPayloads::<ExportOtFamily> {
            session,
            payloads: vec![0_u8; ExportOtFamily::MASKED_PAYLOAD_BYTES],
            family: PhantomData,
        };
        let mut short_masked = masked.encode();
        short_masked.truncate(FRAME_HEADER_BYTES + 512 * 2 * LABEL_BYTES);
        assert_eq!(
            MaskedPayloads::<ExportOtFamily>::decode(&short_masked).err(),
            Some(OtError::InvalidLength)
        );
    }

    #[test]
    fn codecs_and_states_reject_cross_family_and_cross_session_messages() {
        let session = OtSessionId::new([0x5a; 32]).expect("session");
        let other_session = OtSessionId::new([0xa5; 32]).expect("other session");
        let column = [0x3c_u8; BASE_CHOICE_BYTES];
        assert_ne!(
            derive_label_pad::<ExportOtFamily>(session, 17, &column),
            derive_label_pad::<ExportOtFamily>(other_session, 17, &column)
        );
        assert_ne!(
            derive_label_pad::<ExportOtFamily>(session, 17, &column),
            derive_label_pad::<ActivationOtFamily>(session, 17, &column)
        );
        let activation_offer = BaseOffer::<ActivationOtFamily> {
            session,
            points: repeated_base_points(),
            family: PhantomData,
        };
        assert_eq!(
            BaseOffer::<ExportOtFamily>::decode(&activation_offer.encode()).err(),
            Some(OtError::InvalidFamily)
        );

        let choices = ReceiverChoices::<ExportOtFamily>::from_packed_bytes(vec![
            0_u8;
            ExportOtFamily::ROW_BYTES
        ])
        .expect("choices");
        let (_receiver, offer) = ReceiverStart::<ExportOtFamily>::new()
            .begin_os(session, choices)
            .expect("receiver start");
        assert_eq!(offer.session.as_bytes(), &[0x5a; 32]);
        let encoded_offer = offer.encode();
        assert_eq!(&encoded_offer[16..48], &[0x5a; 32]);
        let offer = BaseOffer::<ExportOtFamily>::decode(&encoded_offer).expect("bound offer");
        assert_eq!(offer.session.as_bytes(), &[0x5a; 32]);
        let sender_payloads =
            SenderPayloads::<ExportOtFamily>::new(payloads::<ExportOtFamily>()).expect("payloads");
        let (sender, _base_choices) = SenderStart::<ExportOtFamily>::new()
            .begin_os(offer, sender_payloads)
            .expect("sender start");
        let wrong_session_extension = ExtensionMatrix::<ExportOtFamily> {
            session: other_session,
            matrix: vec![0_u8; ExportOtFamily::MATRIX_BYTES],
            family: PhantomData,
        };
        assert_eq!(
            sender.accept(wrong_session_extension).err(),
            Some(OtError::SessionMismatch)
        );
    }

    #[test]
    fn typed_boundaries_reject_every_non_family_size() {
        assert_eq!(
            OtSessionId::new([0_u8; 32]).err(),
            Some(OtError::InvalidSession)
        );
        assert_eq!(
            ReceiverChoices::<ExportOtFamily>::from_packed_bytes(vec![0_u8; 64]).err(),
            Some(OtError::InvalidLength)
        );
        assert_eq!(
            ReceiverChoices::<ActivationOtFamily>::from_packed_bytes(vec![0_u8; 128]).err(),
            Some(OtError::InvalidLength)
        );
        assert_eq!(
            SenderPayloads::<ExportOtFamily>::new(vec![
                ([0_u8; LABEL_BYTES], [0_u8; LABEL_BYTES]);
                512
            ])
            .err(),
            Some(OtError::InvalidLength)
        );
        assert_eq!(
            SenderPayloads::<ActivationOtFamily>::new(vec![
                (
                    [0_u8; LABEL_BYTES],
                    [0_u8; LABEL_BYTES]
                );
                1_024
            ])
            .err(),
            Some(OtError::InvalidLength)
        );
    }
}
