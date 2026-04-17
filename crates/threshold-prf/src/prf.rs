use core::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::context::{PrfContext, PrfPurpose};
use crate::error::{ThresholdPrfError, ThresholdPrfResult};
use crate::shamir::{
    exactly_two_shares, lagrange_coefficients_2, SigningRootScalar, SigningRootShare,
    SigningRootShareId, SigningRootShareWireV1,
};

const INPUT_DOMAIN: &[u8] = b"threshold-prf:v1/input";
const OUTPUT_DOMAIN: &[u8] = b"threshold-prf:v1/output";
const PARTIAL_CONTEXT_DOMAIN: &[u8] = b"threshold-prf:v1/partial-context";
const DLEQ_DOMAIN: &[u8] = b"threshold-prf:v1/dleq";
const PRF_PARTIAL_WIRE_V1_LEN: usize = 65;
const SIGNING_ROOT_SHARE_COMMITMENT_WIRE_V1_LEN: usize = 33;
const PRF_DLEQ_PROOF_WIRE_V1_LEN: usize = 64;

/// A 32-byte threshold PRF output.
#[derive(Clone, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrfOutput32([u8; 32]);

impl PartialEq for PrfOutput32 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for PrfOutput32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfOutput32([redacted])")
    }
}

impl PrfOutput32 {
    /// Returns the output bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the output and returns its bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A threshold PRF partial produced by one signing-root share.
#[derive(Clone)]
pub struct PrfPartial {
    id: SigningRootShareId,
    context_tag: [u8; 32],
    point: RistrettoPoint,
}

/// Fixed-width v1 signing-root share commitment `[share_i]G`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigningRootShareCommitmentV1 {
    id: SigningRootShareId,
    point: RistrettoPoint,
}

/// Fixed-width v1 DLEQ proof for one PRF partial.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrfDleqProofV1 {
    challenge: Scalar,
    response: Scalar,
}

/// Partial plus share commitment and DLEQ proof.
#[derive(Clone)]
pub struct PrfPartialProofBundleV1 {
    /// Threshold PRF partial `[share_i]P`.
    pub partial: PrfPartial,
    /// Root-share commitment `[share_i]G`.
    pub commitment: SigningRootShareCommitmentV1,
    /// DLEQ proof that `partial` and `commitment` use the same share scalar.
    pub proof: PrfDleqProofV1,
}

impl fmt::Debug for SigningRootShareCommitmentV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningRootShareCommitmentV1")
            .field("id", &self.id)
            .field("point", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for PrfDleqProofV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfDleqProofV1([redacted])")
    }
}

impl fmt::Debug for PrfPartialProofBundleV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrfPartialProofBundleV1")
            .field("partial", &self.partial)
            .field("commitment", &self.commitment)
            .field("proof", &self.proof)
            .finish()
    }
}

impl SigningRootShareCommitmentV1 {
    /// Serialized commitment length: one share-id byte and 32-byte point.
    pub const LEN: usize = SIGNING_ROOT_SHARE_COMMITMENT_WIRE_V1_LEN;

    /// Creates a commitment from a signing-root share.
    pub fn from_share(share: &SigningRootShare) -> Self {
        Self {
            id: share.id(),
            point: share.value * RISTRETTO_BASEPOINT_POINT,
        }
    }

    /// Parses a commitment from its fixed-width byte encoding.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let id = SigningRootShareId::new(bytes[0])?;
        let point_bytes = bytes[1..]
            .try_into()
            .expect("fixed-width commitment point slice");
        let point = CompressedRistretto(point_bytes)
            .decompress()
            .ok_or(ThresholdPrfError::InvalidCommitmentEncoding)?;
        Ok(Self { id, point })
    }

    /// Parses a commitment from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidCommitmentEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Returns the share id encoded in this commitment.
    pub fn id(&self) -> SigningRootShareId {
        self.id
    }

    /// Returns the compressed commitment point bytes.
    pub fn to_compressed(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Returns the fixed-width commitment bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[0] = self.id.get();
        bytes[1..].copy_from_slice(&self.to_compressed());
        bytes
    }
}

impl PrfDleqProofV1 {
    /// Serialized proof length: 32-byte challenge and 32-byte response.
    pub const LEN: usize = PRF_DLEQ_PROOF_WIRE_V1_LEN;

    /// Parses a DLEQ proof from fixed-width scalar encodings.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let challenge_bytes = bytes[..32]
            .try_into()
            .expect("fixed-width challenge scalar slice");
        let response_bytes = bytes[32..]
            .try_into()
            .expect("fixed-width response scalar slice");
        let challenge = Option::<Scalar>::from(Scalar::from_canonical_bytes(challenge_bytes))
            .ok_or(ThresholdPrfError::InvalidDleqProofEncoding)?;
        let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(response_bytes))
            .ok_or(ThresholdPrfError::InvalidDleqProofEncoding)?;
        Ok(Self {
            challenge,
            response,
        })
    }

    /// Parses a DLEQ proof from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidDleqProofEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Returns the challenge scalar bytes.
    pub fn challenge_bytes(&self) -> [u8; 32] {
        self.challenge.to_bytes()
    }

    /// Returns the response scalar bytes.
    pub fn response_bytes(&self) -> [u8; 32] {
        self.response.to_bytes()
    }

    /// Returns the fixed-width proof bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[..32].copy_from_slice(&self.challenge_bytes());
        bytes[32..].copy_from_slice(&self.response_bytes());
        bytes
    }
}

/// Fixed-width v1 serialized PRF partial for worker-to-worker transport.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrfPartialWireV1 {
    bytes: [u8; PRF_PARTIAL_WIRE_V1_LEN],
}

impl fmt::Debug for PrfPartialWireV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfPartialWireV1([redacted])")
    }
}

impl PrfPartialWireV1 {
    /// Serialized partial length: one share-id byte, 32-byte context tag, and 32-byte point.
    pub const LEN: usize = PRF_PARTIAL_WIRE_V1_LEN;

    /// Creates a wire partial from a validated partial.
    pub fn from_partial(partial: &PrfPartial) -> Self {
        let mut bytes = [0u8; Self::LEN];
        bytes[0] = partial.id().get();
        bytes[1..33].copy_from_slice(partial.context_tag());
        bytes[33..].copy_from_slice(&partial.to_compressed());
        Self { bytes }
    }

    /// Decodes a context-bound PRF partial from its fixed-width wire encoding.
    ///
    /// This is the only public decode path for transported partial bytes. It validates the fixed width,
    /// share ID, context tag, and compressed point before returning a partial
    /// that can be combined for the supplied context.
    pub fn decode(context: &PrfContext, bytes: [u8; Self::LEN]) -> ThresholdPrfResult<PrfPartial> {
        Self::parse_raw_bytes(bytes)?.into_partial(context)
    }

    /// Decodes a context-bound PRF partial from a byte slice.
    ///
    /// This is the only public decode path for transported partial byte slices.
    pub fn decode_slice(context: &PrfContext, bytes: &[u8]) -> ThresholdPrfResult<PrfPartial> {
        Self::parse_raw_slice(bytes)?.into_partial(context)
    }

    fn parse_raw_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        SigningRootShareId::new(bytes[0])?;
        Ok(Self { bytes })
    }

    fn parse_raw_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidPartialEncoding)?;
        Self::parse_raw_bytes(bytes)
    }

    /// Returns the share id encoded in this wire partial.
    pub fn id(&self) -> SigningRootShareId {
        SigningRootShareId::new(self.bytes[0]).expect("validated wire partial share id")
    }

    /// Returns the context tag encoded in this wire partial.
    pub fn context_tag(&self) -> &[u8; 32] {
        self.bytes[1..33]
            .try_into()
            .expect("fixed-width context tag slice")
    }

    /// Returns the compressed point bytes encoded in this wire partial.
    pub fn compressed_point(&self) -> [u8; 32] {
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(&self.bytes[33..]);
        compressed
    }

    fn into_partial(self, context: &PrfContext) -> ThresholdPrfResult<PrfPartial> {
        let expected_context_tag = partial_context_tag(context)?;
        if !bool::from(self.context_tag().ct_eq(&expected_context_tag)) {
            return Err(ThresholdPrfError::ContextMismatch);
        }
        partial_from_validated_wire_point(self.id(), context, self.compressed_point())
    }

    /// Returns the fixed-width wire bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        self.bytes
    }
}

impl fmt::Debug for PrfPartial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrfPartial")
            .field("id", &self.id)
            .field("context_tag", &"[redacted]")
            .field("point", &"[redacted]")
            .finish()
    }
}

impl PrfPartial {
    /// Returns the share id that produced this partial.
    pub fn id(&self) -> SigningRootShareId {
        self.id
    }

    /// Returns the compressed partial point.
    pub fn to_compressed(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Returns the context tag bound to this partial.
    pub fn context_tag(&self) -> &[u8; 32] {
        &self.context_tag
    }
}

fn partial_from_validated_wire_point(
    id: SigningRootShareId,
    context: &PrfContext,
    compressed: [u8; 32],
) -> ThresholdPrfResult<PrfPartial> {
    let context_tag = partial_context_tag(context)?;
    let point = CompressedRistretto(compressed)
        .decompress()
        .ok_or(ThresholdPrfError::InvalidPointEncoding)?;
    Ok(PrfPartial {
        id,
        context_tag,
        point,
    })
}

/// Evaluates the PRF directly from the signing root.
///
/// This is a reference path for tests and vectors. Production signing should
/// use `evaluate_partial` and `combine_partials`.
pub fn evaluate_direct_reference(
    root: &SigningRootScalar,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let p = hash_to_group(context)?;
    output_from_point(&(root.0 * p), context)
}

/// Evaluates one threshold PRF partial from one signing-root share.
pub fn evaluate_partial(
    share: &SigningRootShare,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfPartial> {
    let input_point = hash_to_group(context)?;
    let context_tag = partial_context_tag(context)?;
    Ok(evaluate_partial_with_input(
        share,
        context_tag,
        &input_point,
    ))
}

/// Derives the final PRF output from exactly two signing-root shares.
///
/// This is the canonical single-runtime Option A helper. It performs threshold
/// partial evaluation and combine without reconstructing the signing root. The
/// direct signing-root path remains reference-only for tests, vectors, audits,
/// and recovery checks.
pub fn derive_output_from_signing_root_shares(
    shares: &[SigningRootShare],
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let [left, right] = exactly_two_shares(shares)?;
    let input_point = hash_to_group(context)?;
    let context_tag = partial_context_tag(context)?;
    let partials = [
        evaluate_partial_with_input(left, context_tag, &input_point),
        evaluate_partial_with_input(right, context_tag, &input_point),
    ];
    combine_partials_with_context_tag(&partials, context, &context_tag)
}

/// Derives the final PRF output from exactly two validated signing-root share wires.
///
/// This is the narrow server SDK boundary for one-runtime Option A after sealed
/// share storage has decrypted the shares in memory.
pub fn derive_output_from_signing_root_share_wires(
    share_wires: &[SigningRootShareWireV1],
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    if share_wires.len() != 2 {
        return Err(ThresholdPrfError::InvalidThresholdSubset);
    }
    let shares = [share_wires[0].to_share()?, share_wires[1].to_share()?];
    derive_output_from_signing_root_shares(&shares, context)
}

fn evaluate_partial_with_input(
    share: &SigningRootShare,
    context_tag: [u8; 32],
    input_point: &RistrettoPoint,
) -> PrfPartial {
    PrfPartial {
        id: share.id(),
        context_tag,
        point: share.value * *input_point,
    }
}

/// Evaluates one PRF partial and proves it was produced from the committed share scalar.
pub fn evaluate_partial_with_dleq_proof<R>(
    share: &SigningRootShare,
    context: &PrfContext,
    rng: &mut R,
) -> ThresholdPrfResult<PrfPartialProofBundleV1>
where
    R: RngCore + CryptoRng,
{
    let input_point = hash_to_group(context)?;
    let context_tag = partial_context_tag(context)?;
    let partial = evaluate_partial_with_input(share, context_tag, &input_point);
    let commitment = SigningRootShareCommitmentV1::from_share(share);
    let proof = prove_partial_dleq(share, &commitment, &partial, context, &input_point, rng)?;
    Ok(PrfPartialProofBundleV1 {
        partial,
        commitment,
        proof,
    })
}

/// Verifies that a PRF partial and root-share commitment use the same share scalar.
pub fn verify_partial_dleq_proof(
    commitment: &SigningRootShareCommitmentV1,
    partial: &PrfPartial,
    context: &PrfContext,
    proof: &PrfDleqProofV1,
) -> ThresholdPrfResult<()> {
    if commitment.id != partial.id {
        return Err(ThresholdPrfError::InvalidDleqProof);
    }

    let expected_context_tag = partial_context_tag(context)?;
    reject_context_mismatch(partial, &expected_context_tag)?;

    let input_point = hash_to_group(context)?;
    let nonce_g =
        (proof.response * RISTRETTO_BASEPOINT_POINT) - (proof.challenge * commitment.point);
    let nonce_p = (proof.response * input_point) - (proof.challenge * partial.point);
    let expected = dleq_challenge(
        context,
        &expected_context_tag,
        partial.id,
        &input_point,
        &commitment.point,
        &partial.point,
        &nonce_g,
        &nonce_p,
    )?;

    if bool::from(proof.challenge.to_bytes().ct_eq(&expected.to_bytes())) {
        Ok(())
    } else {
        Err(ThresholdPrfError::InvalidDleqProof)
    }
}

/// Verifies two DLEQ proof bundles and combines their partials into the final output.
///
/// This is the preferred combiner boundary for two-runtime Option B deployments
/// when DLEQ is the chosen partial-authenticity mechanism.
pub fn combine_verified_partials(
    bundles: &[PrfPartialProofBundleV1],
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let [left, right] = exactly_two_proof_bundles(bundles)?;
    verify_partial_dleq_proof(&left.commitment, &left.partial, context, &left.proof)?;
    verify_partial_dleq_proof(&right.commitment, &right.partial, context, &right.proof)?;
    combine_partials_with_context_tag(
        &[left.partial.clone(), right.partial.clone()],
        context,
        &partial_context_tag(context)?,
    )
}

/// Combines exactly two threshold PRF partials into the final output.
pub fn combine_partials(
    partials: &[PrfPartial],
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let expected_context_tag = partial_context_tag(context)?;
    combine_partials_with_context_tag(partials, context, &expected_context_tag)
}

fn exactly_two_proof_bundles(
    bundles: &[PrfPartialProofBundleV1],
) -> ThresholdPrfResult<[&PrfPartialProofBundleV1; 2]> {
    if bundles.len() != 2 {
        return Err(ThresholdPrfError::InvalidThresholdSubset);
    }
    if bundles[0].partial.id == bundles[1].partial.id {
        return Err(ThresholdPrfError::DuplicateShareId);
    }
    Ok([&bundles[0], &bundles[1]])
}

fn combine_partials_with_context_tag(
    partials: &[PrfPartial],
    context: &PrfContext,
    expected_context_tag: &[u8; 32],
) -> ThresholdPrfResult<PrfOutput32> {
    let [left, right] = exactly_two_partials(partials)?;
    reject_context_mismatch(left, expected_context_tag)?;
    reject_context_mismatch(right, expected_context_tag)?;

    let (lambda_left, lambda_right) = lagrange_coefficients_2(left.id, right.id)?;
    let z = (lambda_left * left.point) + (lambda_right * right.point);
    output_from_point(&z, context)
}

fn exactly_two_partials(partials: &[PrfPartial]) -> ThresholdPrfResult<[&PrfPartial; 2]> {
    if partials.len() != 2 {
        return Err(ThresholdPrfError::InvalidThresholdSubset);
    }
    if partials[0].id == partials[1].id {
        return Err(ThresholdPrfError::DuplicateShareId);
    }
    Ok([&partials[0], &partials[1]])
}

fn reject_context_mismatch(partial: &PrfPartial, expected: &[u8; 32]) -> ThresholdPrfResult<()> {
    if bool::from(partial.context_tag.ct_eq(expected)) {
        Ok(())
    } else {
        Err(ThresholdPrfError::ContextMismatch)
    }
}

fn hash_to_group(context: &PrfContext) -> ThresholdPrfResult<RistrettoPoint> {
    let transcript = encode_transcript(INPUT_DOMAIN, context, &[])?;
    Ok(RistrettoPoint::hash_from_bytes::<Sha512>(&transcript))
}

fn partial_context_tag(context: &PrfContext) -> ThresholdPrfResult<[u8; 32]> {
    let transcript = encode_transcript(PARTIAL_CONTEXT_DOMAIN, context, &[])?;
    let digest = Sha512::digest(transcript);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest[..32]);
    Ok(tag)
}

fn output_from_point(
    point: &RistrettoPoint,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let compressed = point.compress();
    let transcript = encode_transcript(OUTPUT_DOMAIN, context, compressed.as_bytes())?;
    let digest = Sha512::digest(transcript);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    if matches!(context.purpose, PrfPurpose::Ed25519HssTauRelayer) {
        let reduced = Scalar::from_bytes_mod_order(out).to_bytes();
        out.zeroize();
        return Ok(PrfOutput32(reduced));
    }
    Ok(PrfOutput32(out))
}

fn prove_partial_dleq<R>(
    share: &SigningRootShare,
    commitment: &SigningRootShareCommitmentV1,
    partial: &PrfPartial,
    context: &PrfContext,
    input_point: &RistrettoPoint,
    rng: &mut R,
) -> ThresholdPrfResult<PrfDleqProofV1>
where
    R: RngCore + CryptoRng,
{
    if commitment.id != share.id() || partial.id != share.id() {
        return Err(ThresholdPrfError::InvalidDleqProof);
    }

    let blind = random_nonzero_dleq_nonce(rng);
    let nonce_g = *blind * RISTRETTO_BASEPOINT_POINT;
    let nonce_p = *blind * *input_point;
    let challenge = dleq_challenge(
        context,
        partial.context_tag(),
        partial.id,
        input_point,
        &commitment.point,
        &partial.point,
        &nonce_g,
        &nonce_p,
    )?;
    let response = *blind + (challenge * share.value);
    Ok(PrfDleqProofV1 {
        challenge,
        response,
    })
}

fn random_nonzero_dleq_nonce<R>(rng: &mut R) -> Zeroizing<Scalar>
where
    R: RngCore + CryptoRng,
{
    loop {
        let candidate = Scalar::random(&mut *rng);
        if !bool::from(candidate.ct_eq(&Scalar::ZERO)) {
            return Zeroizing::new(candidate);
        }
    }
}

fn dleq_challenge(
    context: &PrfContext,
    context_tag: &[u8; 32],
    share_id: SigningRootShareId,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> ThresholdPrfResult<Scalar> {
    let mut transcript = Vec::new();
    push_len16(&mut transcript, DLEQ_DOMAIN)?;
    push_len16(&mut transcript, context.suite_id.as_bytes())?;
    push_len16(&mut transcript, context.purpose.as_bytes())?;
    transcript.extend_from_slice(context_tag);
    transcript.push(share_id.get());
    transcript.extend_from_slice(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    transcript.extend_from_slice(input_point.compress().as_bytes());
    transcript.extend_from_slice(commitment_point.compress().as_bytes());
    transcript.extend_from_slice(partial_point.compress().as_bytes());
    transcript.extend_from_slice(nonce_g.compress().as_bytes());
    transcript.extend_from_slice(nonce_p.compress().as_bytes());

    let digest = Sha512::digest(transcript);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn encode_transcript(
    domain: &[u8],
    context: &PrfContext,
    payload: &[u8],
) -> ThresholdPrfResult<Vec<u8>> {
    let mut out = Vec::new();
    push_len16(&mut out, domain)?;
    push_len16(&mut out, context.suite_id.as_bytes())?;
    push_len16(&mut out, context.purpose.as_bytes())?;
    push_len32(&mut out, &context.context_bytes)?;
    push_len32(&mut out, payload)?;
    Ok(out)
}

fn push_len16(out: &mut Vec<u8>, bytes: &[u8]) -> ThresholdPrfResult<()> {
    let len =
        u16::try_from(bytes.len()).map_err(|_| ThresholdPrfError::TranscriptLengthOverflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) -> ThresholdPrfResult<()> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| ThresholdPrfError::TranscriptLengthOverflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
