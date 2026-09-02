use core::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ThresholdPrfError, ThresholdPrfResult};
use crate::prf::SigningRootShareCommitment;
use crate::shamir::{SigningRootShare, ThresholdShareId};

const REFRESH_CONTRIBUTION_WIRE_LEN: usize = 36;
const REFRESH_COMMITMENT_WIRE_LEN: usize = 34;
const ROOT_SHARE_KNOWLEDGE_PROOF_WIRE_LEN: usize = 64;

/// One role in the fixed Deriver A/B 2-of-2 tenant-root sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoPartyDeriverRole {
    /// Deriver A, fixed to share id 1.
    DeriverA,
    /// Deriver B, fixed to share id 2.
    DeriverB,
}

/// Generates one non-zero role-local share for distributed tenant-root creation.
pub fn generate_two_party_root_share<R>(role: TwoPartyDeriverRole, rng: &mut R) -> SigningRootShare
where
    R: RngCore + CryptoRng,
{
    SigningRootShare::new_unchecked(role.share_id(), random_nonzero_scalar(rng))
}

impl TwoPartyDeriverRole {
    /// Returns the canonical protocol role label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeriverA => "deriver_a",
            Self::DeriverB => "deriver_b",
        }
    }

    /// Returns the other role in the fixed pair.
    pub const fn peer(self) -> Self {
        match self {
            Self::DeriverA => Self::DeriverB,
            Self::DeriverB => Self::DeriverA,
        }
    }

    /// Returns the role's fixed threshold share id.
    pub fn share_id(self) -> ThresholdShareId {
        ThresholdShareId::from_u16(match self {
            Self::DeriverA => 1,
            Self::DeriverB => 2,
        })
        .expect("fixed two-party refresh share ids are non-zero")
    }

    /// Resolves one fixed role from its threshold share id.
    pub fn from_share_id(id: ThresholdShareId) -> ThresholdPrfResult<Self> {
        match id.get().get() {
            1 => Ok(Self::DeriverA),
            2 => Ok(Self::DeriverB),
            _ => Err(ThresholdPrfError::InvalidRefreshRole),
        }
    }
}

/// One source role's secret non-zero coefficient for a two-party zero sharing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootShareRefreshCoefficient {
    #[zeroize(skip)]
    source: TwoPartyDeriverRole,
    scalar: Scalar,
}

impl fmt::Debug for RootShareRefreshCoefficient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootShareRefreshCoefficient")
            .field("source", &self.source)
            .field("scalar", &"[redacted]")
            .finish()
    }
}

impl RootShareRefreshCoefficient {
    /// Samples a fresh non-zero coefficient from a cryptographic RNG.
    pub fn random<R>(source: TwoPartyDeriverRole, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self {
            source,
            scalar: random_nonzero_scalar(rng),
        }
    }

    /// Parses a fixed coefficient for vectors and deterministic protocol tests.
    pub fn from_canonical_bytes(
        source: TwoPartyDeriverRole,
        bytes: [u8; 32],
    ) -> ThresholdPrfResult<Self> {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(ThresholdPrfError::InvalidScalarEncoding)?;
        reject_zero_scalar(&scalar)?;
        Ok(Self { source, scalar })
    }

    /// Returns the public coefficient commitment for contribution verification.
    pub fn commitment(&self) -> RootShareRefreshCoefficientCommitment {
        RootShareRefreshCoefficientCommitment {
            source: self.source,
            point: self.scalar * RISTRETTO_BASEPOINT_POINT,
        }
    }

    /// Creates the exact secret contribution addressed to one recipient role.
    pub fn contribution_for(
        &self,
        recipient: TwoPartyDeriverRole,
    ) -> RootShareRefreshContributionWire {
        let recipient_x = Scalar::from(u64::from(recipient.share_id().get().get()));
        let contribution = self.scalar * recipient_x;
        RootShareRefreshContributionWire::from_scalar(self.source, recipient, contribution)
    }
}

/// Public commitment to one source role's refresh coefficient.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RootShareRefreshCoefficientCommitment {
    source: TwoPartyDeriverRole,
    point: RistrettoPoint,
}

impl fmt::Debug for RootShareRefreshCoefficientCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootShareRefreshCoefficientCommitment")
            .field("source", &self.source)
            .field("point", &self.point.compress().to_bytes())
            .finish()
    }
}

impl RootShareRefreshCoefficientCommitment {
    /// Fixed commitment wire length: source share id and compressed point.
    pub const LEN: usize = REFRESH_COMMITMENT_WIRE_LEN;

    /// Parses one canonical public coefficient commitment.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let source = parse_role(&bytes[..2])?;
        let point_bytes = bytes[2..]
            .try_into()
            .expect("fixed refresh commitment point slice");
        let point = CompressedRistretto(point_bytes)
            .decompress()
            .ok_or(ThresholdPrfError::InvalidCommitmentEncoding)?;
        if bool::from(point.ct_eq(&RistrettoPoint::identity())) {
            return Err(ThresholdPrfError::InvalidRefreshContribution);
        }
        Ok(Self { source, point })
    }

    /// Parses one canonical public coefficient commitment slice.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidCommitmentEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Returns the fixed source role.
    pub fn source(&self) -> TwoPartyDeriverRole {
        self.source
    }

    /// Returns the canonical fixed-width wire bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0_u8; Self::LEN];
        bytes[..2].copy_from_slice(&self.source.share_id().get().get().to_be_bytes());
        bytes[2..].copy_from_slice(self.point.compress().as_bytes());
        bytes
    }

    /// Verifies and consumes one recipient-specific secret contribution.
    pub fn verify_contribution(
        &self,
        contribution: RootShareRefreshContributionWire,
    ) -> ThresholdPrfResult<VerifiedRootShareRefreshContribution> {
        if contribution.source() != self.source {
            return Err(ThresholdPrfError::InvalidRefreshContribution);
        }
        let scalar = contribution.scalar()?;
        let recipient_x = Scalar::from(u64::from(contribution.recipient().share_id().get().get()));
        let expected = recipient_x * self.point;
        let actual = scalar * RISTRETTO_BASEPOINT_POINT;
        if !bool::from(actual.ct_eq(&expected)) {
            return Err(ThresholdPrfError::InvalidRefreshContribution);
        }
        Ok(VerifiedRootShareRefreshContribution {
            source: contribution.source(),
            recipient: contribution.recipient(),
            scalar,
        })
    }
}

/// Fixed-width secret recipient-specific refresh contribution.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootShareRefreshContributionWire {
    bytes: [u8; REFRESH_CONTRIBUTION_WIRE_LEN],
}

impl fmt::Debug for RootShareRefreshContributionWire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootShareRefreshContributionWire([redacted])")
    }
}

impl RootShareRefreshContributionWire {
    /// Fixed contribution wire length: source id, recipient id, and canonical scalar.
    pub const LEN: usize = REFRESH_CONTRIBUTION_WIRE_LEN;

    fn from_scalar(
        source: TwoPartyDeriverRole,
        recipient: TwoPartyDeriverRole,
        scalar: Scalar,
    ) -> Self {
        let mut bytes = [0_u8; Self::LEN];
        bytes[..2].copy_from_slice(&source.share_id().get().get().to_be_bytes());
        bytes[2..4].copy_from_slice(&recipient.share_id().get().get().to_be_bytes());
        bytes[4..].copy_from_slice(&scalar.to_bytes());
        Self { bytes }
    }

    /// Decodes and validates one fixed-width secret contribution.
    pub fn decode(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let wire = Self { bytes };
        wire.parse_source()?;
        wire.parse_recipient()?;
        let scalar = wire.scalar()?;
        reject_zero_scalar(&scalar)?;
        Ok(wire)
    }

    /// Decodes and validates one secret contribution slice.
    pub fn decode_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidRefreshContribution)?;
        Self::decode(bytes)
    }

    /// Returns the source role encoded into this contribution.
    pub fn source(&self) -> TwoPartyDeriverRole {
        self.parse_source()
            .expect("validated refresh contribution source")
    }

    /// Returns the recipient role encoded into this contribution.
    pub fn recipient(&self) -> TwoPartyDeriverRole {
        self.parse_recipient()
            .expect("validated refresh contribution recipient")
    }

    /// Returns a copy of the exact fixed-width secret wire bytes.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.bytes
    }

    fn parse_source(&self) -> ThresholdPrfResult<TwoPartyDeriverRole> {
        parse_role(&self.bytes[..2])
    }

    fn parse_recipient(&self) -> ThresholdPrfResult<TwoPartyDeriverRole> {
        parse_role(&self.bytes[2..4])
    }

    fn scalar(&self) -> ThresholdPrfResult<Scalar> {
        let bytes = self.bytes[4..]
            .try_into()
            .expect("fixed refresh contribution scalar slice");
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(ThresholdPrfError::InvalidRefreshContribution)
    }
}

/// One recipient-specific contribution after its public commitment verified.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedRootShareRefreshContribution {
    #[zeroize(skip)]
    source: TwoPartyDeriverRole,
    #[zeroize(skip)]
    recipient: TwoPartyDeriverRole,
    scalar: Scalar,
}

impl fmt::Debug for VerifiedRootShareRefreshContribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRootShareRefreshContribution")
            .field("source", &self.source)
            .field("recipient", &self.recipient)
            .field("scalar", &"[redacted]")
            .finish()
    }
}

/// Applies exactly one verified contribution from each source to one current role share.
pub fn apply_two_party_root_share_refresh(
    current: &SigningRootShare,
    first: VerifiedRootShareRefreshContribution,
    second: VerifiedRootShareRefreshContribution,
) -> ThresholdPrfResult<SigningRootShare> {
    let recipient = TwoPartyDeriverRole::from_share_id(current.id())?;
    if first.recipient != recipient
        || second.recipient != recipient
        || first.source == second.source
        || !matches!(
            (first.source, second.source),
            (TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB)
                | (TwoPartyDeriverRole::DeriverB, TwoPartyDeriverRole::DeriverA)
        )
    {
        return Err(ThresholdPrfError::InvalidRefreshContribution);
    }
    let delta = first.scalar + second.scalar;
    if bool::from(delta.ct_eq(&Scalar::ZERO)) {
        return Err(ThresholdPrfError::RefreshNoOp);
    }
    let next = current.value + delta;
    reject_zero_scalar(&next)?;
    Ok(SigningRootShare::new_unchecked(current.id(), next))
}

/// Public commitment to the stable joined root represented by a two-party share pair.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TwoPartyRootCommitment(RistrettoPoint);

impl fmt::Debug for TwoPartyRootCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TwoPartyRootCommitment")
            .field(&self.to_bytes())
            .finish()
    }
}

impl TwoPartyRootCommitment {
    /// Parses a non-identity canonical compressed Ristretto commitment.
    pub fn from_bytes(bytes: [u8; 32]) -> ThresholdPrfResult<Self> {
        let point = CompressedRistretto(bytes)
            .decompress()
            .ok_or(ThresholdPrfError::InvalidRootCommitment)?;
        if bool::from(point.ct_eq(&RistrettoPoint::identity())) {
            return Err(ThresholdPrfError::InvalidRootCommitment);
        }
        Ok(Self(point))
    }

    /// Returns the canonical compressed Ristretto commitment bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

/// Exact Deriver A/B public share commitments for one tenant-root epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwoPartyRootShareCommitments {
    deriver_a: SigningRootShareCommitment,
    deriver_b: SigningRootShareCommitment,
    root: TwoPartyRootCommitment,
}

impl TwoPartyRootShareCommitments {
    /// Creates one exact non-zero A/B commitment pair and its joined root commitment.
    pub fn new(
        deriver_a: SigningRootShareCommitment,
        deriver_b: SigningRootShareCommitment,
    ) -> ThresholdPrfResult<Self> {
        require_commitment_role(&deriver_a, TwoPartyDeriverRole::DeriverA)?;
        require_commitment_role(&deriver_b, TwoPartyDeriverRole::DeriverB)?;
        require_non_identity_point(&deriver_a.point())?;
        require_non_identity_point(&deriver_b.point())?;
        if bool::from(deriver_a.point().ct_eq(&deriver_b.point())) {
            return Err(ThresholdPrfError::InvalidRootCommitment);
        }
        let root_point = (Scalar::from(2_u64) * deriver_a.point()) - deriver_b.point();
        let root = TwoPartyRootCommitment::from_bytes(root_point.compress().to_bytes())?;
        Ok(Self {
            deriver_a,
            deriver_b,
            root,
        })
    }

    /// Builds an exact A/B public commitment pair from role-local secret shares.
    pub fn from_shares(
        deriver_a: &SigningRootShare,
        deriver_b: &SigningRootShare,
    ) -> ThresholdPrfResult<Self> {
        Self::new(
            SigningRootShareCommitment::from_share(deriver_a),
            SigningRootShareCommitment::from_share(deriver_b),
        )
    }

    /// Returns the stable joined public root commitment.
    pub fn root(&self) -> TwoPartyRootCommitment {
        self.root
    }

    /// Returns Deriver A's public share commitment.
    pub fn deriver_a(&self) -> SigningRootShareCommitment {
        self.deriver_a
    }

    /// Returns Deriver B's public share commitment.
    pub fn deriver_b(&self) -> SigningRootShareCommitment {
        self.deriver_b
    }
}

/// Derives the next public A/B commitments from two ordered refresh coefficients.
pub fn derive_two_party_root_share_refresh_commitments(
    current: &TwoPartyRootShareCommitments,
    deriver_a_coefficient: RootShareRefreshCoefficientCommitment,
    deriver_b_coefficient: RootShareRefreshCoefficientCommitment,
) -> ThresholdPrfResult<TwoPartyRootShareCommitments> {
    if deriver_a_coefficient.source != TwoPartyDeriverRole::DeriverA
        || deriver_b_coefficient.source != TwoPartyDeriverRole::DeriverB
    {
        return Err(ThresholdPrfError::InvalidRefreshRole);
    }
    let delta = deriver_a_coefficient.point + deriver_b_coefficient.point;
    if bool::from(delta.ct_eq(&RistrettoPoint::identity())) {
        return Err(ThresholdPrfError::RefreshNoOp);
    }
    let next_deriver_a = SigningRootShareCommitment::from_compressed(
        TwoPartyDeriverRole::DeriverA.share_id(),
        (current.deriver_a.point() + delta).compress().to_bytes(),
    )?;
    let next_deriver_b = SigningRootShareCommitment::from_compressed(
        TwoPartyDeriverRole::DeriverB.share_id(),
        (current.deriver_b.point() + (Scalar::from(2_u64) * delta))
            .compress()
            .to_bytes(),
    )?;
    let next = TwoPartyRootShareCommitments::new(next_deriver_a, next_deriver_b)?;
    verify_two_party_root_share_refresh(current, &next)?;
    Ok(next)
}

/// Verifies that both shares changed and the exact joined root commitment stayed fixed.
pub fn verify_two_party_root_share_refresh(
    current: &TwoPartyRootShareCommitments,
    next: &TwoPartyRootShareCommitments,
) -> ThresholdPrfResult<()> {
    let delta_a = next.deriver_a.point() - current.deriver_a.point();
    let delta_b = next.deriver_b.point() - current.deriver_b.point();
    if bool::from(delta_a.ct_eq(&RistrettoPoint::identity()))
        || bool::from(delta_b.ct_eq(&RistrettoPoint::identity()))
    {
        return Err(ThresholdPrfError::RefreshNoOp);
    }
    if !bool::from((Scalar::from(2_u64) * delta_a).ct_eq(&delta_b))
        || !bool::from(current.root.0.ct_eq(&next.root.0))
    {
        return Err(ThresholdPrfError::RefreshContinuityMismatch);
    }
    Ok(())
}

/// Fixed-width Schnorr proof that one role knows its committed root-share scalar.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RootShareKnowledgeProof {
    nonce_commitment: RistrettoPoint,
    response: Scalar,
}

impl fmt::Debug for RootShareKnowledgeProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootShareKnowledgeProof([redacted])")
    }
}

impl RootShareKnowledgeProof {
    /// Fixed proof wire length: compressed nonce commitment and canonical response scalar.
    pub const LEN: usize = ROOT_SHARE_KNOWLEDGE_PROOF_WIRE_LEN;

    /// Parses one canonical fixed-width knowledge proof.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let nonce_bytes = bytes[..32]
            .try_into()
            .expect("fixed knowledge-proof nonce slice");
        let response_bytes = bytes[32..]
            .try_into()
            .expect("fixed knowledge-proof response slice");
        let nonce_commitment = CompressedRistretto(nonce_bytes)
            .decompress()
            .ok_or(ThresholdPrfError::InvalidKnowledgeProofEncoding)?;
        require_non_identity_point(&nonce_commitment)
            .map_err(|_| ThresholdPrfError::InvalidKnowledgeProofEncoding)?;
        let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(response_bytes))
            .ok_or(ThresholdPrfError::InvalidKnowledgeProofEncoding)?;
        Ok(Self {
            nonce_commitment,
            response,
        })
    }

    /// Parses one canonical fixed-width knowledge-proof slice.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidKnowledgeProofEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Returns the canonical fixed-width proof bytes.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut bytes = [0_u8; Self::LEN];
        bytes[..32].copy_from_slice(self.nonce_commitment.compress().as_bytes());
        bytes[32..].copy_from_slice(&self.response.to_bytes());
        bytes
    }
}

/// Proves knowledge of one non-zero root-share scalar under canonical transcript bytes.
pub fn prove_root_share_knowledge<R>(
    share: &SigningRootShare,
    canonical_transcript: &[u8],
    rng: &mut R,
) -> ThresholdPrfResult<RootShareKnowledgeProof>
where
    R: RngCore + CryptoRng,
{
    if canonical_transcript.is_empty() {
        return Err(ThresholdPrfError::InvalidKnowledgeProof);
    }
    let commitment = SigningRootShareCommitment::from_share(share);
    require_non_identity_point(&commitment.point())?;
    loop {
        let nonce = Zeroizing::new(random_nonzero_scalar(rng));
        let nonce_commitment = *nonce * RISTRETTO_BASEPOINT_POINT;
        let challenge = knowledge_challenge(canonical_transcript, &commitment, &nonce_commitment);
        if bool::from(challenge.ct_eq(&Scalar::ZERO)) {
            continue;
        }
        return Ok(RootShareKnowledgeProof {
            nonce_commitment,
            response: *nonce + (challenge * share.value),
        });
    }
}

/// Verifies one root-share knowledge proof against exact canonical transcript bytes.
pub fn verify_root_share_knowledge(
    commitment: &SigningRootShareCommitment,
    canonical_transcript: &[u8],
    proof: &RootShareKnowledgeProof,
) -> ThresholdPrfResult<()> {
    if canonical_transcript.is_empty() {
        return Err(ThresholdPrfError::InvalidKnowledgeProof);
    }
    require_non_identity_point(&commitment.point())?;
    require_non_identity_point(&proof.nonce_commitment)?;
    let challenge = knowledge_challenge(canonical_transcript, commitment, &proof.nonce_commitment);
    if bool::from(challenge.ct_eq(&Scalar::ZERO)) {
        return Err(ThresholdPrfError::InvalidKnowledgeProof);
    }
    let actual = proof.response * RISTRETTO_BASEPOINT_POINT;
    let expected = proof.nonce_commitment + (challenge * commitment.point());
    if bool::from(actual.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(ThresholdPrfError::InvalidKnowledgeProof)
    }
}

fn knowledge_challenge(
    canonical_transcript: &[u8],
    commitment: &SigningRootShareCommitment,
    nonce_commitment: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(canonical_transcript);
    hasher.update(commitment.to_compressed());
    hasher.update(nonce_commitment.compress().as_bytes());
    let digest = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn require_commitment_role(
    commitment: &SigningRootShareCommitment,
    role: TwoPartyDeriverRole,
) -> ThresholdPrfResult<()> {
    if commitment.id() == role.share_id() {
        Ok(())
    } else {
        Err(ThresholdPrfError::InvalidRefreshRole)
    }
}

fn require_non_identity_point(point: &RistrettoPoint) -> ThresholdPrfResult<()> {
    if bool::from(point.ct_eq(&RistrettoPoint::identity())) {
        Err(ThresholdPrfError::InvalidRootCommitment)
    } else {
        Ok(())
    }
}

fn random_nonzero_scalar<R>(rng: &mut R) -> Scalar
where
    R: RngCore + CryptoRng,
{
    loop {
        let scalar = Scalar::random(&mut *rng);
        if !bool::from(scalar.ct_eq(&Scalar::ZERO)) {
            return scalar;
        }
    }
}

fn reject_zero_scalar(scalar: &Scalar) -> ThresholdPrfResult<()> {
    if bool::from(scalar.ct_eq(&Scalar::ZERO)) {
        Err(ThresholdPrfError::ZeroScalar)
    } else {
        Ok(())
    }
}

fn parse_role(bytes: &[u8]) -> ThresholdPrfResult<TwoPartyDeriverRole> {
    let raw = u16::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidRefreshRole)?,
    );
    TwoPartyDeriverRole::from_share_id(ThresholdShareId::from_u16(raw)?)
}
