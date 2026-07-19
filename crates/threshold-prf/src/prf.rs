use core::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use router_ab_ecdsa_client_protocol::{
    verify_ecdsa_prf_public_dleq_proof_v1, EcdsaClientProtocolError, EcdsaPrfPublicContextV1,
    EcdsaPrfPublicProofBundleV1, EcdsaPrfPurposeV1,
};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::context::{PrfContext, PrfOutputEncoding};
use crate::error::{ThresholdPrfError, ThresholdPrfResult};
use crate::shamir::{
    lagrange_coefficients_for_share_ids, validate_threshold_set_values, SigningRootScalar,
    SigningRootShare, ThresholdPolicy, ThresholdShareId, ValidatedThresholdSet,
};

const INPUT_DOMAIN: &[u8] = b"threshold-prf/input";
const OUTPUT_DOMAIN: &[u8] = b"threshold-prf/output";
const PARTIAL_CONTEXT_DOMAIN: &[u8] = b"threshold-prf/partial-context";
const DLEQ_DOMAIN: &[u8] = b"threshold-prf/dleq";
const PRF_PARTIAL_WIRE_LEN: usize = 66;
const SIGNING_ROOT_SHARE_COMMITMENT_WIRE_LEN: usize = 34;
const PRF_DLEQ_PROOF_WIRE_LEN: usize = 64;

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

/// A canonical threshold PRF partial produced by one signing-root share.
#[derive(Clone)]
pub struct PrfPartial {
    id: ThresholdShareId,
    context_tag: [u8; 32],
    point: RistrettoPoint,
}

/// Fixed-width canonical signing-root share commitment `[share_i]G`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigningRootShareCommitment {
    id: ThresholdShareId,
    point: RistrettoPoint,
}

/// Fixed-width canonical DLEQ proof for one PRF partial.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrfDleqProof {
    challenge: Scalar,
    response: Scalar,
}

/// Canonical partial plus share commitment and DLEQ proof.
#[derive(Clone)]
pub struct PrfPartialProofBundle {
    /// Canonical threshold PRF partial `[share_i]P`.
    pub partial: PrfPartial,
    /// Canonical root-share commitment `[share_i]G`.
    pub commitment: SigningRootShareCommitment,
    /// Canonical DLEQ proof that `partial` and `commitment` use the same share scalar.
    pub proof: PrfDleqProof,
}

impl ValidatedThresholdSet<PrfPartial> {
    /// Validates canonical PRF partials against a threshold policy.
    pub fn from_partials(
        policy: ThresholdPolicy,
        partials: Vec<PrfPartial>,
    ) -> ThresholdPrfResult<Self> {
        validate_threshold_set_values(policy, partials, PrfPartial::id)
    }
}

impl ValidatedThresholdSet<PrfPartialProofBundle> {
    /// Validates canonical PRF proof bundles against a threshold policy.
    pub fn from_proof_bundles(
        policy: ThresholdPolicy,
        bundles: Vec<PrfPartialProofBundle>,
    ) -> ThresholdPrfResult<Self> {
        let set = validate_threshold_set_values(policy, bundles, |bundle| bundle.partial.id())?;
        for bundle in set.values() {
            if bundle.commitment.id() != bundle.partial.id() {
                return Err(ThresholdPrfError::InvalidDleqProof);
            }
        }
        Ok(set)
    }
}

impl fmt::Debug for SigningRootShareCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningRootShareCommitment")
            .field("id", &self.id)
            .field("point", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for PrfDleqProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfDleqProof([redacted])")
    }
}

impl fmt::Debug for PrfPartialProofBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrfPartialProofBundle")
            .field("partial", &self.partial)
            .field("commitment", &self.commitment)
            .field("proof", &self.proof)
            .finish()
    }
}

impl SigningRootShareCommitment {
    /// Serialized canonical commitment length: two share-id bytes and 32-byte point.
    pub const LEN: usize = SIGNING_ROOT_SHARE_COMMITMENT_WIRE_LEN;

    /// Creates a canonical commitment from a signing-root share.
    pub fn from_share(share: &SigningRootShare) -> Self {
        Self {
            id: share.id(),
            point: share.value * RISTRETTO_BASEPOINT_POINT,
        }
    }

    /// Parses a canonical commitment from a share id and compressed point.
    pub fn from_compressed(id: ThresholdShareId, compressed: [u8; 32]) -> ThresholdPrfResult<Self> {
        let point = CompressedRistretto(compressed)
            .decompress()
            .ok_or(ThresholdPrfError::InvalidCommitmentEncoding)?;
        Ok(Self { id, point })
    }

    /// Parses a canonical commitment from its fixed-width byte encoding.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let id = ThresholdShareId::from_u16(u16::from_be_bytes(
            bytes[0..2]
                .try_into()
                .expect("fixed-width canonical commitment share id slice"),
        ))?;
        let point_bytes = bytes[2..]
            .try_into()
            .expect("fixed-width canonical commitment point slice");
        Self::from_compressed(id, point_bytes)
    }

    /// Parses a canonical commitment from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidCommitmentEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Returns the share id encoded in this canonical commitment.
    pub fn id(&self) -> ThresholdShareId {
        self.id
    }

    /// Returns the compressed canonical commitment point bytes.
    pub fn to_compressed(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Returns the fixed-width canonical commitment bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[0..2].copy_from_slice(&self.id.get().get().to_be_bytes());
        bytes[2..].copy_from_slice(&self.to_compressed());
        bytes
    }
}

impl PrfDleqProof {
    /// Serialized canonical proof length: 32-byte challenge and 32-byte response.
    pub const LEN: usize = PRF_DLEQ_PROOF_WIRE_LEN;

    /// Parses a canonical DLEQ proof from fixed-width scalar encodings.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let challenge_bytes = bytes[..32]
            .try_into()
            .expect("fixed-width canonical challenge scalar slice");
        let response_bytes = bytes[32..]
            .try_into()
            .expect("fixed-width canonical response scalar slice");
        let challenge = Option::<Scalar>::from(Scalar::from_canonical_bytes(challenge_bytes))
            .ok_or(ThresholdPrfError::InvalidDleqProofEncoding)?;
        let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(response_bytes))
            .ok_or(ThresholdPrfError::InvalidDleqProofEncoding)?;
        Ok(Self {
            challenge,
            response,
        })
    }

    /// Parses a canonical DLEQ proof from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidDleqProofEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Returns the canonical challenge scalar bytes.
    pub fn challenge_bytes(&self) -> [u8; 32] {
        self.challenge.to_bytes()
    }

    /// Returns the canonical response scalar bytes.
    pub fn response_bytes(&self) -> [u8; 32] {
        self.response.to_bytes()
    }

    /// Returns the fixed-width canonical proof bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[..32].copy_from_slice(&self.challenge_bytes());
        bytes[32..].copy_from_slice(&self.response_bytes());
        bytes
    }
}

/// Fixed-width canonical serialized PRF partial for worker-to-worker transport.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrfPartialWire {
    bytes: [u8; PRF_PARTIAL_WIRE_LEN],
}

impl fmt::Debug for PrfPartialWire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfPartialWire([redacted])")
    }
}

impl PrfPartialWire {
    /// Serialized canonical partial length: two share-id bytes, 32-byte context tag, and 32-byte point.
    pub const LEN: usize = PRF_PARTIAL_WIRE_LEN;

    /// Creates a canonical wire partial from a validated canonical partial.
    pub fn from_partial(partial: &PrfPartial) -> Self {
        let mut bytes = [0u8; Self::LEN];
        bytes[0..2].copy_from_slice(&partial.id().get().get().to_be_bytes());
        bytes[2..34].copy_from_slice(partial.context_tag());
        bytes[34..].copy_from_slice(&partial.to_compressed());
        Self { bytes }
    }

    /// Decodes and validates a fixed-width canonical PRF partial.
    pub fn decode(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let wire = Self { bytes };
        wire.to_partial()?;
        Ok(wire)
    }

    /// Decodes and validates a fixed-width canonical PRF partial byte slice.
    pub fn decode_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidPartialEncoding)?;
        Self::decode(bytes)
    }

    /// Returns the share id encoded in this canonical wire partial.
    pub fn id(&self) -> ThresholdShareId {
        self.parse_id()
            .expect("validated canonical wire partial share id")
    }

    fn parse_id(&self) -> ThresholdPrfResult<ThresholdShareId> {
        ThresholdShareId::from_u16(u16::from_be_bytes(
            self.bytes[0..2]
                .try_into()
                .expect("fixed-width canonical partial share id slice"),
        ))
    }

    /// Returns the context tag encoded in this canonical wire partial.
    pub fn context_tag(&self) -> &[u8; 32] {
        self.bytes[2..34]
            .try_into()
            .expect("fixed-width canonical context tag slice")
    }

    /// Returns the compressed point bytes encoded in this canonical wire partial.
    pub fn compressed_point(&self) -> [u8; 32] {
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(&self.bytes[34..]);
        compressed
    }

    /// Decodes this canonical wire partial into a validated canonical partial value.
    pub fn to_partial(&self) -> ThresholdPrfResult<PrfPartial> {
        PrfPartial::from_compressed(
            self.parse_id()?,
            *self.context_tag(),
            self.compressed_point(),
        )
    }

    /// Returns the fixed-width canonical wire bytes.
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
    /// Creates a canonical partial from validated public fields and a compressed point.
    pub fn from_compressed(
        id: ThresholdShareId,
        context_tag: [u8; 32],
        compressed: [u8; 32],
    ) -> ThresholdPrfResult<Self> {
        let point = CompressedRistretto(compressed)
            .decompress()
            .ok_or(ThresholdPrfError::InvalidPointEncoding)?;
        Ok(Self {
            id,
            context_tag,
            point,
        })
    }

    /// Returns the canonical share id that produced this partial.
    pub fn id(&self) -> ThresholdShareId {
        self.id
    }

    /// Returns the compressed canonical partial point.
    pub fn to_compressed(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Returns the context tag bound to this canonical partial.
    pub fn context_tag(&self) -> &[u8; 32] {
        &self.context_tag
    }
}

/// Evaluates the canonical PRF directly from the signing root.
///
/// This is a reference path for tests, vectors, audits, and recovery checks.
/// Production signing should use `evaluate_partial` and either verified combine
/// for peer partials or `trusted::combine_partials` for local authenticated partials.
pub fn evaluate_direct_reference(
    root: &SigningRootScalar,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let p = hash_to_group(context)?;
    output_from_point(&(root.0 * p), context)
}

/// Evaluates one canonical threshold PRF partial from one canonical signing-root share.
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

/// Evaluates one canonical PRF partial and proves it was produced from the committed share scalar.
pub fn evaluate_partial_with_dleq_proof<R>(
    share: &SigningRootShare,
    context: &PrfContext,
    rng: &mut R,
) -> ThresholdPrfResult<PrfPartialProofBundle>
where
    R: RngCore + CryptoRng,
{
    let input_point = hash_to_group(context)?;
    let context_tag = partial_context_tag(context)?;
    let partial = evaluate_partial_with_input(share, context_tag, &input_point);
    let commitment = SigningRootShareCommitment::from_share(share);
    let proof = prove_partial_dleq(share, &commitment, &partial, context, &input_point, rng)?;
    Ok(PrfPartialProofBundle {
        partial,
        commitment,
        proof,
    })
}

/// Verifies that a canonical PRF partial and root-share commitment use the same share scalar.
pub fn verify_partial_dleq_proof(
    commitment: &SigningRootShareCommitment,
    partial: &PrfPartial,
    context: &PrfContext,
    proof: &PrfDleqProof,
) -> ThresholdPrfResult<()> {
    let public_context = ecdsa_public_context_from_threshold_context(context);
    let public_bundle = EcdsaPrfPublicProofBundleV1 {
        partial_wire: PrfPartialWire::from_partial(partial).to_bytes(),
        commitment_wire: commitment.to_bytes(),
        proof_wire: proof.to_bytes(),
    };
    match verify_ecdsa_prf_public_dleq_proof_v1(&public_context, &public_bundle) {
        Ok(()) => Ok(()),
        Err(EcdsaClientProtocolError::ContextMismatch) => Err(ThresholdPrfError::ContextMismatch),
        Err(
            EcdsaClientProtocolError::InvalidShape
            | EcdsaClientProtocolError::HpkeFailed
            | EcdsaClientProtocolError::InvalidDleqProof,
        ) => Err(ThresholdPrfError::InvalidDleqProof),
    }
}

fn ecdsa_public_context_from_threshold_context(context: &PrfContext) -> EcdsaPrfPublicContextV1 {
    EcdsaPrfPublicContextV1 {
        purpose: ecdsa_public_purpose_from_threshold_purpose(&context.purpose),
        context_bytes: context.context_bytes.clone(),
    }
}

fn ecdsa_public_purpose_from_threshold_purpose(
    purpose: &crate::context::PrfPurpose,
) -> EcdsaPrfPurposeV1 {
    match purpose {
        crate::context::PrfPurpose::RouterAbEcdsaDerivationYServer => EcdsaPrfPurposeV1::YServer,
        crate::context::PrfPurpose::RouterAbXClientBaseV1 => EcdsaPrfPurposeV1::XClientBase,
        crate::context::PrfPurpose::RouterAbXServerBaseV1 => EcdsaPrfPurposeV1::XServerBase,
    }
}

/// Verifies a canonical threshold set of DLEQ proof bundles and combines their partials.
pub fn combine_verified_partials(
    bundles: &ValidatedThresholdSet<PrfPartialProofBundle>,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    for bundle in bundles.values() {
        verify_partial_dleq_proof(&bundle.commitment, &bundle.partial, context, &bundle.proof)?;
    }

    let partials = bundles
        .values()
        .iter()
        .map(|bundle| bundle.partial.clone())
        .collect();
    let partial_set = ValidatedThresholdSet::from_partials(*bundles.policy(), partials)?;
    combine_partials(&partial_set, context)
}

/// Combines a trusted validated canonical threshold partial set into the final PRF output.
///
/// Use `combine_verified_partials` for partials received across a trust boundary.
pub fn combine_partials(
    partials: &ValidatedThresholdSet<PrfPartial>,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let expected_context_tag = partial_context_tag(context)?;
    combine_partials_with_context_tag(partials, context, &expected_context_tag)
}

fn combine_partials_with_context_tag(
    partials: &ValidatedThresholdSet<PrfPartial>,
    context: &PrfContext,
    expected_context_tag: &[u8; 32],
) -> ThresholdPrfResult<PrfOutput32> {
    for partial in partials.values() {
        reject_context_mismatch(partial, expected_context_tag)?;
    }

    let ids = partials
        .values()
        .iter()
        .map(PrfPartial::id)
        .collect::<Vec<_>>();
    let coefficients = lagrange_coefficients_for_share_ids(&ids);
    let mut z = RistrettoPoint::identity();

    for (coefficient, partial) in coefficients.iter().zip(partials.values()) {
        z += *coefficient * partial.point;
    }

    output_from_point(&z, context)
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
    output_from_transcript(transcript, context)
}

fn output_from_transcript(
    transcript: Vec<u8>,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32> {
    let digest = Sha512::digest(transcript);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    match context.purpose.output_encoding() {
        PrfOutputEncoding::Raw32 => Ok(PrfOutput32(out)),
        PrfOutputEncoding::CanonicalEd25519Scalar32 => {
            let reduced = Scalar::from_bytes_mod_order(out).to_bytes();
            out.zeroize();
            Ok(PrfOutput32(reduced))
        }
    }
}

fn prove_partial_dleq<R>(
    share: &SigningRootShare,
    commitment: &SigningRootShareCommitment,
    partial: &PrfPartial,
    context: &PrfContext,
    input_point: &RistrettoPoint,
    rng: &mut R,
) -> ThresholdPrfResult<PrfDleqProof>
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
    Ok(PrfDleqProof {
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
    share_id: ThresholdShareId,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> ThresholdPrfResult<Scalar> {
    let transcript = encode_dleq_challenge_transcript(
        context,
        context_tag,
        share_id,
        input_point,
        commitment_point,
        partial_point,
        nonce_g,
        nonce_p,
    )?;
    let digest = Sha512::digest(transcript);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn encode_dleq_challenge_transcript(
    context: &PrfContext,
    context_tag: &[u8; 32],
    share_id: ThresholdShareId,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> ThresholdPrfResult<Vec<u8>> {
    let mut transcript = Vec::new();
    push_len16(&mut transcript, DLEQ_DOMAIN)?;
    push_len16(&mut transcript, context.suite_id.as_bytes())?;
    push_len16(&mut transcript, context.purpose.as_bytes())?;
    transcript.extend_from_slice(context_tag);
    transcript.extend_from_slice(&share_id.get().get().to_be_bytes());
    transcript.extend_from_slice(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    transcript.extend_from_slice(input_point.compress().as_bytes());
    transcript.extend_from_slice(commitment_point.compress().as_bytes());
    transcript.extend_from_slice(partial_point.compress().as_bytes());
    transcript.extend_from_slice(nonce_g.compress().as_bytes());
    transcript.extend_from_slice(nonce_p.compress().as_bytes());
    Ok(transcript)
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
    out.extend_from_slice(&len16_bytes(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) -> ThresholdPrfResult<()> {
    out.extend_from_slice(&len32_bytes(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(())
}

fn len16_bytes(len: usize) -> ThresholdPrfResult<[u8; 2]> {
    let len = u16::try_from(len).map_err(|_| ThresholdPrfError::TranscriptLengthOverflow)?;
    Ok(len.to_be_bytes())
}

fn len32_bytes(len: usize) -> ThresholdPrfResult<[u8; 4]> {
    let len = u32::try_from(len).map_err(|_| ThresholdPrfError::TranscriptLengthOverflow)?;
    Ok(len.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PrfPurpose;
    use crate::shamir::{generate_signing_root, split_signing_root};
    use crate::suite::SuiteId;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::time::Instant;

    fn fixture_context() -> PrfContext {
        PrfContext::new(
            SuiteId::Ristretto255Sha512,
            PrfPurpose::RouterAbEcdsaDerivationYServer,
            b"ctx",
        )
    }

    fn append_point(out: &mut Vec<u8>, point: &RistrettoPoint) {
        out.extend_from_slice(point.compress().as_bytes());
    }

    #[test]
    fn standard_transcript_fixtures_pin_field_order() {
        let context = fixture_context();

        assert_eq!(
            encode_transcript(INPUT_DOMAIN, &context, &[]).unwrap(),
            b"\x00\x13threshold-prf/input\
              \x00\x21threshold-prf/ristretto255-sha512\
              \x00\x26router-ab-ecdsa-derivation/y-server/v1\
              \x00\x00\x00\x03ctx\
              \x00\x00\x00\x00"
                .to_vec()
        );
        assert_eq!(
            encode_transcript(PARTIAL_CONTEXT_DOMAIN, &context, &[]).unwrap(),
            b"\x00\x1dthreshold-prf/partial-context\
              \x00\x21threshold-prf/ristretto255-sha512\
              \x00\x26router-ab-ecdsa-derivation/y-server/v1\
              \x00\x00\x00\x03ctx\
              \x00\x00\x00\x00"
                .to_vec()
        );
        assert_eq!(
            encode_transcript(OUTPUT_DOMAIN, &context, b"payload").unwrap(),
            b"\x00\x14threshold-prf/output\
              \x00\x21threshold-prf/ristretto255-sha512\
              \x00\x26router-ab-ecdsa-derivation/y-server/v1\
              \x00\x00\x00\x03ctx\
              \x00\x00\x00\x07payload"
                .to_vec()
        );
    }

    #[test]
    fn dleq_transcript_fixture_pins_field_order() {
        let context = fixture_context();
        let context_tag = [0x11u8; 32];
        let share_id = ThresholdShareId::from_u16(2).unwrap();
        let input_point = RISTRETTO_BASEPOINT_POINT;
        let commitment_point = Scalar::from(2u64) * RISTRETTO_BASEPOINT_POINT;
        let partial_point = Scalar::from(3u64) * RISTRETTO_BASEPOINT_POINT;
        let nonce_g = Scalar::from(4u64) * RISTRETTO_BASEPOINT_POINT;
        let nonce_p = Scalar::from(5u64) * RISTRETTO_BASEPOINT_POINT;

        let transcript = encode_dleq_challenge_transcript(
            &context,
            &context_tag,
            share_id,
            &input_point,
            &commitment_point,
            &partial_point,
            &nonce_g,
            &nonce_p,
        )
        .unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"\x00\x12threshold-prf/dleq");
        expected.extend_from_slice(b"\x00\x21threshold-prf/ristretto255-sha512");
        expected.extend_from_slice(b"\x00\x26router-ab-ecdsa-derivation/y-server/v1");
        expected.extend_from_slice(&context_tag);
        expected.extend_from_slice(&2u16.to_be_bytes());
        append_point(&mut expected, &RISTRETTO_BASEPOINT_POINT);
        append_point(&mut expected, &input_point);
        append_point(&mut expected, &commitment_point);
        append_point(&mut expected, &partial_point);
        append_point(&mut expected, &nonce_g);
        append_point(&mut expected, &nonce_p);

        assert_eq!(transcript, expected);
    }

    #[test]
    fn transcript_len16_overflow_is_rejected() {
        let oversized = vec![0u8; usize::from(u16::MAX) + 1];
        assert_eq!(
            encode_transcript(&oversized, &fixture_context(), &[]).unwrap_err(),
            ThresholdPrfError::TranscriptLengthOverflow
        );
        assert_eq!(
            len16_bytes(usize::from(u16::MAX) + 1).unwrap_err(),
            ThresholdPrfError::TranscriptLengthOverflow
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn transcript_len32_overflow_is_rejected() {
        let oversized_len = (u32::MAX as usize) + 1;
        assert_eq!(
            len32_bytes(oversized_len).unwrap_err(),
            ThresholdPrfError::TranscriptLengthOverflow
        );
    }

    #[test]
    #[ignore = "local timing harness; run `just threshold-prf-t-of-n-prep-bench`"]
    fn benchmark_private_prf_eval_combine_prep() {
        let iterations = 1_000;
        let mut root_rng = ChaCha20Rng::from_seed([0x31u8; 32]);
        let root = generate_signing_root(&mut root_rng);
        let policy_2_of_3 = ThresholdPolicy::from_u16s(2, 3).unwrap();
        let policy_3_of_5 = ThresholdPolicy::from_u16s(3, 5).unwrap();
        let context = PrfContext::new(
            SuiteId::Ristretto255Sha512,
            PrfPurpose::RouterAbXServerBaseV1,
            b"benchmark/private-prf-eval-combine-prep/canonical",
        );
        let shares_2_of_3 = split_signing_root(&root, policy_2_of_3, &mut root_rng).unwrap();
        let shares_3_of_5 = split_signing_root(&root, policy_3_of_5, &mut root_rng).unwrap();
        let partials_2_of_3 = ValidatedThresholdSet::from_partials(
            policy_2_of_3,
            vec![
                evaluate_partial(&shares_2_of_3[0], &context).unwrap(),
                evaluate_partial(&shares_2_of_3[2], &context).unwrap(),
            ],
        )
        .unwrap();
        let partials_3_of_5 = ValidatedThresholdSet::from_partials(
            policy_3_of_5,
            vec![
                evaluate_partial(&shares_3_of_5[0], &context).unwrap(),
                evaluate_partial(&shares_3_of_5[2], &context).unwrap(),
                evaluate_partial(&shares_3_of_5[4], &context).unwrap(),
            ],
        )
        .unwrap();
        let mut proof_rng = ChaCha20Rng::from_seed([0x61u8; 32]);
        let proof_bundles_3_of_5 = ValidatedThresholdSet::from_proof_bundles(
            policy_3_of_5,
            vec![
                evaluate_partial_with_dleq_proof(&shares_3_of_5[0], &context, &mut proof_rng)
                    .unwrap(),
                evaluate_partial_with_dleq_proof(&shares_3_of_5[2], &context, &mut proof_rng)
                    .unwrap(),
                evaluate_partial_with_dleq_proof(&shares_3_of_5[4], &context, &mut proof_rng)
                    .unwrap(),
            ],
        )
        .unwrap();

        measure_prf_case("prf_evaluate_partial", iterations, || {
            evaluate_partial(&shares_3_of_5[0], &context)
                .unwrap()
                .to_compressed()[0]
        });
        measure_prf_case("prf_combine_partials_2_of_3", iterations, || {
            combine_partials(&partials_2_of_3, &context)
                .unwrap()
                .as_bytes()[0]
        });
        measure_prf_case("prf_combine_partials_3_of_5", iterations, || {
            combine_partials(&partials_3_of_5, &context)
                .unwrap()
                .as_bytes()[0]
        });
        measure_prf_case("prf_combine_verified_partials_3_of_5", iterations, || {
            combine_verified_partials(&proof_bundles_3_of_5, &context)
                .unwrap()
                .as_bytes()[0]
        });

        let mut fresh_proof_rng = ChaCha20Rng::from_seed([0x71u8; 32]);
        measure_prf_case("prf_evaluate_partial_with_dleq_proof", iterations, || {
            evaluate_partial_with_dleq_proof(&shares_3_of_5[0], &context, &mut fresh_proof_rng)
                .unwrap()
                .proof
                .challenge_bytes()[0]
        });
    }

    fn measure_prf_case<F>(name: &str, iterations: u32, mut run_once: F)
    where
        F: FnMut() -> u8,
    {
        let started_at = Instant::now();
        let mut checksum = 0u8;

        for _ in 0..iterations {
            checksum ^= run_once();
        }

        let elapsed = started_at.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / f64::from(iterations);
        println!("{name}: {ns_per_op:.3} ns/op over {iterations} iterations, checksum {checksum}");
    }
}
