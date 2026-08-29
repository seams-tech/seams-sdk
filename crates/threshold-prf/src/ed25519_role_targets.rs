use core::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::context::{PrfContext, PrfPurpose};
use crate::error::{ThresholdPrfError, ThresholdPrfResult};
use crate::prf::{
    combine_partials, evaluate_partial, evaluate_partial_with_dleq_proof,
    verify_partial_dleq_proof, PrfDleqProof, PrfPartial, PrfPartialProofBundle, PrfPartialWire,
    SigningRootShareCommitment,
};
use crate::shamir::{SigningRootShare, ThresholdPolicy, ValidatedThresholdSet};
use crate::suite::SuiteId;

const DERIVER_A_SHARE_ID: u16 = 1;
const DERIVER_B_SHARE_ID: u16 = 2;
const ROLE_TARGET_PROOF_BUNDLE_LEN: usize =
    PrfPartialWire::LEN + SigningRootShareCommitment::LEN + PrfDleqProof::LEN;

/// Deriver A's prepared local A-target partial.
pub struct PreparedEd25519DeriverATargetV1 {
    local_partial: Zeroizing<[u8; PrfPartialWire::LEN]>,
    context: PrfContext,
    expected_peer_commitment: SigningRootShareCommitment,
}

impl fmt::Debug for PreparedEd25519DeriverATargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedEd25519DeriverATargetV1([redacted])")
    }
}

/// Deriver B's prepared local B-target partial.
pub struct PreparedEd25519DeriverBTargetV1 {
    local_partial: Zeroizing<[u8; PrfPartialWire::LEN]>,
    context: PrfContext,
    expected_peer_commitment: SigningRootShareCommitment,
}

impl fmt::Debug for PreparedEd25519DeriverBTargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedEd25519DeriverBTargetV1([redacted])")
    }
}

/// Exact A-to-B proof bundle for Deriver B's role-targeted PRF output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519DeriverAToBTargetProofBundleV1([u8; ROLE_TARGET_PROOF_BUNDLE_LEN]);

impl fmt::Debug for Ed25519DeriverAToBTargetProofBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519DeriverAToBTargetProofBundleV1([redacted])")
    }
}

impl Ed25519DeriverAToBTargetProofBundleV1 {
    /// Fixed plaintext length before recipient encryption.
    pub const LEN: usize = ROLE_TARGET_PROOF_BUNDLE_LEN;

    /// Parses the exact A-to-B bundle and rejects any other source share.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let wire = decode_role_target_bundle_wire(bytes, DERIVER_A_SHARE_ID)?;
        Ok(Self(wire))
    }

    /// Returns the exact plaintext bytes for recipient encryption.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// Exact B-to-A proof bundle for Deriver A's role-targeted PRF output.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519DeriverBToATargetProofBundleV1([u8; ROLE_TARGET_PROOF_BUNDLE_LEN]);

impl fmt::Debug for Ed25519DeriverBToATargetProofBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519DeriverBToATargetProofBundleV1([redacted])")
    }
}

impl Ed25519DeriverBToATargetProofBundleV1 {
    /// Fixed plaintext length before recipient encryption.
    pub const LEN: usize = ROLE_TARGET_PROOF_BUNDLE_LEN;

    /// Parses the exact B-to-A bundle and rejects any other source share.
    pub fn from_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let wire = decode_role_target_bundle_wire(bytes, DERIVER_B_SHARE_ID)?;
        Ok(Self(wire))
    }

    /// Returns the exact plaintext bytes for recipient encryption.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// A-target threshold-PRF root that only Deriver A can obtain from the typed protocol.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519DeriverAThresholdPrfRootV1([u8; 32]);

impl fmt::Debug for Ed25519DeriverAThresholdPrfRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519DeriverAThresholdPrfRootV1([redacted])")
    }
}

impl Ed25519DeriverAThresholdPrfRootV1 {
    /// Consumes the capability for the existing Deriver A contribution KDF.
    pub fn into_secret_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

/// B-target threshold-PRF root that only Deriver B can obtain from the typed protocol.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519DeriverBThresholdPrfRootV1([u8; 32]);

impl fmt::Debug for Ed25519DeriverBThresholdPrfRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519DeriverBThresholdPrfRootV1([redacted])")
    }
}

impl Ed25519DeriverBThresholdPrfRootV1 {
    /// Consumes the capability for the existing Deriver B contribution KDF.
    pub fn into_secret_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

/// Prepares Deriver A's local A-target partial and its exact A-to-B B-target proof.
pub fn prepare_ed25519_deriver_a_target_v1<R>(
    share: &SigningRootShare,
    expected_deriver_b_commitment: SigningRootShareCommitment,
    stable_context_bytes: &[u8],
    rng: &mut R,
) -> ThresholdPrfResult<(
    PreparedEd25519DeriverATargetV1,
    Ed25519DeriverAToBTargetProofBundleV1,
)>
where
    R: RngCore + CryptoRng,
{
    require_share_id(share, DERIVER_A_SHARE_ID)?;
    require_commitment_id(&expected_deriver_b_commitment, DERIVER_B_SHARE_ID)?;
    let local_context = role_target_context(
        PrfPurpose::Ed25519DeriverAContributionRoot,
        stable_context_bytes,
    );
    let outgoing_context = role_target_context(
        PrfPurpose::Ed25519DeriverBContributionRoot,
        stable_context_bytes,
    );
    let local_partial = evaluate_partial(share, &local_context)?;
    let outgoing = evaluate_partial_with_dleq_proof(share, &outgoing_context, rng)?;
    Ok((
        PreparedEd25519DeriverATargetV1 {
            local_partial: Zeroizing::new(PrfPartialWire::from_partial(&local_partial).to_bytes()),
            context: local_context,
            expected_peer_commitment: expected_deriver_b_commitment,
        },
        Ed25519DeriverAToBTargetProofBundleV1(encode_role_target_bundle(&outgoing)),
    ))
}

/// Prepares Deriver B's local B-target partial and its exact B-to-A A-target proof.
pub fn prepare_ed25519_deriver_b_target_v1<R>(
    share: &SigningRootShare,
    expected_deriver_a_commitment: SigningRootShareCommitment,
    stable_context_bytes: &[u8],
    rng: &mut R,
) -> ThresholdPrfResult<(
    PreparedEd25519DeriverBTargetV1,
    Ed25519DeriverBToATargetProofBundleV1,
)>
where
    R: RngCore + CryptoRng,
{
    require_share_id(share, DERIVER_B_SHARE_ID)?;
    require_commitment_id(&expected_deriver_a_commitment, DERIVER_A_SHARE_ID)?;
    let local_context = role_target_context(
        PrfPurpose::Ed25519DeriverBContributionRoot,
        stable_context_bytes,
    );
    let outgoing_context = role_target_context(
        PrfPurpose::Ed25519DeriverAContributionRoot,
        stable_context_bytes,
    );
    let local_partial = evaluate_partial(share, &local_context)?;
    let outgoing = evaluate_partial_with_dleq_proof(share, &outgoing_context, rng)?;
    Ok((
        PreparedEd25519DeriverBTargetV1 {
            local_partial: Zeroizing::new(PrfPartialWire::from_partial(&local_partial).to_bytes()),
            context: local_context,
            expected_peer_commitment: expected_deriver_a_commitment,
        },
        Ed25519DeriverBToATargetProofBundleV1(encode_role_target_bundle(&outgoing)),
    ))
}

/// Verifies B's A-target proof and completes only Deriver A's target output.
pub fn complete_ed25519_deriver_a_target_v1(
    prepared: PreparedEd25519DeriverATargetV1,
    incoming: &Ed25519DeriverBToATargetProofBundleV1,
) -> ThresholdPrfResult<Ed25519DeriverAThresholdPrfRootV1> {
    complete_role_target(
        &prepared.local_partial,
        &prepared.context,
        &prepared.expected_peer_commitment,
        &incoming.0,
        DERIVER_B_SHARE_ID,
    )
    .map(Ed25519DeriverAThresholdPrfRootV1)
}

/// Verifies A's B-target proof and completes only Deriver B's target output.
pub fn complete_ed25519_deriver_b_target_v1(
    prepared: PreparedEd25519DeriverBTargetV1,
    incoming: &Ed25519DeriverAToBTargetProofBundleV1,
) -> ThresholdPrfResult<Ed25519DeriverBThresholdPrfRootV1> {
    complete_role_target(
        &prepared.local_partial,
        &prepared.context,
        &prepared.expected_peer_commitment,
        &incoming.0,
        DERIVER_A_SHARE_ID,
    )
    .map(Ed25519DeriverBThresholdPrfRootV1)
}

fn role_target_context(purpose: PrfPurpose, stable_context_bytes: &[u8]) -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        stable_context_bytes.to_vec(),
    )
}

fn require_share_id(share: &SigningRootShare, expected_id: u16) -> ThresholdPrfResult<()> {
    if share.id().get().get() == expected_id {
        Ok(())
    } else {
        Err(ThresholdPrfError::InvalidShareId)
    }
}

fn require_commitment_id(
    commitment: &SigningRootShareCommitment,
    expected_id: u16,
) -> ThresholdPrfResult<()> {
    if commitment.id().get().get() == expected_id {
        Ok(())
    } else {
        Err(ThresholdPrfError::InvalidShareId)
    }
}

fn encode_role_target_bundle(bundle: &PrfPartialProofBundle) -> [u8; ROLE_TARGET_PROOF_BUNDLE_LEN] {
    let mut bytes = [0_u8; ROLE_TARGET_PROOF_BUNDLE_LEN];
    let partial_end = PrfPartialWire::LEN;
    let commitment_end = partial_end + SigningRootShareCommitment::LEN;
    bytes[..partial_end].copy_from_slice(&PrfPartialWire::from_partial(&bundle.partial).to_bytes());
    bytes[partial_end..commitment_end].copy_from_slice(&bundle.commitment.to_bytes());
    bytes[commitment_end..].copy_from_slice(&bundle.proof.to_bytes());
    bytes
}

fn decode_role_target_bundle_wire(
    bytes: &[u8],
    expected_source_share_id: u16,
) -> ThresholdPrfResult<[u8; ROLE_TARGET_PROOF_BUNDLE_LEN]> {
    let wire: [u8; ROLE_TARGET_PROOF_BUNDLE_LEN] = bytes
        .try_into()
        .map_err(|_| ThresholdPrfError::InvalidPartialEncoding)?;
    let (partial, commitment, _) = decode_role_target_bundle(&wire)?;
    if partial.id().get().get() != expected_source_share_id
        || commitment.id().get().get() != expected_source_share_id
    {
        return Err(ThresholdPrfError::InvalidShareId);
    }
    Ok(wire)
}

fn decode_role_target_bundle(
    bytes: &[u8; ROLE_TARGET_PROOF_BUNDLE_LEN],
) -> ThresholdPrfResult<(PrfPartial, SigningRootShareCommitment, PrfDleqProof)> {
    let partial_end = PrfPartialWire::LEN;
    let commitment_end = partial_end + SigningRootShareCommitment::LEN;
    let partial = PrfPartialWire::decode_slice(&bytes[..partial_end])?.to_partial()?;
    let commitment = SigningRootShareCommitment::from_slice(&bytes[partial_end..commitment_end])?;
    let proof = PrfDleqProof::from_slice(&bytes[commitment_end..])?;
    Ok((partial, commitment, proof))
}

fn complete_role_target(
    local_partial_wire: &[u8; PrfPartialWire::LEN],
    context: &PrfContext,
    expected_peer_commitment: &SigningRootShareCommitment,
    incoming: &[u8; ROLE_TARGET_PROOF_BUNDLE_LEN],
    expected_peer_share_id: u16,
) -> ThresholdPrfResult<[u8; 32]> {
    let (peer_partial, peer_commitment, peer_proof) = decode_role_target_bundle(incoming)?;
    if peer_partial.id().get().get() != expected_peer_share_id
        || peer_commitment != *expected_peer_commitment
    {
        return Err(ThresholdPrfError::InvalidDleqProof);
    }
    verify_partial_dleq_proof(&peer_commitment, &peer_partial, context, &peer_proof)?;
    let local_partial = PrfPartialWire::decode(*local_partial_wire)?.to_partial()?;
    let policy = ThresholdPolicy::from_u16s(2, 2)?;
    let partials = ValidatedThresholdSet::from_partials(policy, vec![local_partial, peer_partial])?;
    combine_partials(&partials, context).map(|output| output.into_bytes())
}
