use core::fmt;

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use threshold_prf::{
    generate_two_party_root_share, SigningRootShare, SigningRootShareCommitment,
    SigningRootShareWire, TwoPartyDeriverRole,
};

use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCeremonyContextV1, TenantRootShareInstallationEvidenceV1,
    TenantRootShareInstallationTranscriptV1, TenantRootSignedCreationCommitmentV1,
    TenantRootSignedShareInstallationEvidenceV1, VerifiedTenantRootCreationCommitmentPairV1,
    VerifiedTenantRootCreationCommitmentV1, VerifiedTenantRootRoleCreationCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};

/// One role's in-memory initial-creation attempt before the A/B commitment pair is available.
///
/// This token is deliberately neither cloneable nor serializable. Dropping it burns the
/// sampled share because no persistent state is created by this module.
pub struct PendingTenantRootInitialRoleAttemptV1 {
    command: VerifiedTenantRootRoleCreationCommandV1,
    commitment: VerifiedTenantRootCreationCommitmentV1,
    share: SigningRootShare,
    role_verifying_key: [u8; 32],
}

impl fmt::Debug for PendingTenantRootInitialRoleAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTenantRootInitialRoleAttemptV1")
            .field("command", &self.command)
            .field("commitment", &self.commitment)
            .field("share", &"[redacted]")
            .field("role_verifying_key", &self.role_verifying_key)
            .finish()
    }
}

impl PendingTenantRootInitialRoleAttemptV1 {
    /// Samples, commits, signs, and self-verifies one role's initial share attempt.
    pub fn new<R>(
        command: VerifiedTenantRootRoleCreationCommandV1,
        context: TenantRootCeremonyContextV1,
        role_signing_key_bytes: &[u8; 32],
        expected_role_verifying_key_bytes: &[u8; 32],
        now_ms: u64,
        rng: &mut R,
    ) -> RouterAbDerivationResult<Self>
    where
        R: RngCore + CryptoRng,
    {
        validate_command_context(&command, &context)?;
        command.require_fresh(now_ms)?;
        let role = command.role();
        require_role_signing_key_matches(
            role_signing_key_bytes,
            expected_role_verifying_key_bytes,
        )?;
        let share = generate_two_party_root_share(role, rng);
        let commitment = SigningRootShareCommitment::from_share(&share);
        let transcript =
            super::TenantRootCreationCommitmentTranscriptV1::new(context, role, commitment)?;
        let signed =
            TenantRootSignedCreationCommitmentV1::sign(transcript, role_signing_key_bytes)?;
        let commitment_bytes = signed.canonical_bytes()?;
        let decoded_commitment =
            TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&commitment_bytes)?;
        let verified_commitment = decoded_commitment.verify_strict(
            signed.transcript().context(),
            role,
            signed.transcript().context().signing_key_id(role),
            expected_role_verifying_key_bytes,
        )?;
        Ok(Self {
            command,
            commitment: verified_commitment,
            share,
            role_verifying_key: *expected_role_verifying_key_bytes,
        })
    }

    /// Returns the exact role selected by the issuer command.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.commitment.role()
    }

    /// Returns the exact verified signed commitment token for Router rendezvous.
    pub const fn commitment(&self) -> &VerifiedTenantRootCreationCommitmentV1 {
        &self.commitment
    }

    /// Returns the exact signed commitment wire bytes for Router rendezvous.
    pub fn commitment_bytes(&self) -> &[u8] {
        self.commitment.canonical_bytes()
    }

    /// Proves, signs, and self-verifies this role's share against one exact A/B pair.
    pub fn finalize<R>(
        self,
        verified_pair: VerifiedTenantRootCreationCommitmentPairV1,
        role_signing_key_bytes: &[u8; 32],
        rng: &mut R,
    ) -> RouterAbDerivationResult<VerifiedTenantRootInitialRoleAttemptV1>
    where
        R: RngCore + CryptoRng,
    {
        let PendingTenantRootInitialRoleAttemptV1 {
            command,
            commitment,
            share,
            role_verifying_key,
        } = self;
        require_role_signing_key_matches(role_signing_key_bytes, &role_verifying_key)?;
        let role = commitment.role();
        let pair_commitment = commitment_for_role(&verified_pair, role);
        if commitment.context() != verified_pair.context()
            || commitment.canonical_bytes() != pair_commitment.canonical_bytes()
        {
            return Err(malformed(
                "tenant-root initial role attempt does not match its verified commitment pair",
            ));
        }
        let peer_commitment = commitment_for_role(&verified_pair, role.peer()).commitment();
        let transcript = TenantRootShareInstallationTranscriptV1::new(
            commitment.context().clone(),
            role,
            commitment.commitment(),
            peer_commitment,
        )?;
        let transcript_bytes = transcript.canonical_bytes()?;
        let proof = threshold_prf::prove_root_share_knowledge(&share, &transcript_bytes, rng)
            .map_err(|_| verification_failed("tenant-root initial role share proof failed"))?;
        let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof)?;
        let signed_evidence =
            TenantRootSignedShareInstallationEvidenceV1::sign(evidence, role_signing_key_bytes)?;
        let evidence_bytes = signed_evidence.canonical_bytes()?;
        let verified_evidence =
            TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
                &evidence_bytes,
                &role_verifying_key,
            )?;
        Ok(VerifiedTenantRootInitialRoleAttemptV1 {
            command,
            share_wire: SigningRootShareWire::from_share(&share),
            evidence: verified_evidence,
        })
    }
}

/// Fully verified initial-creation role output ready for sealing and persistence by an adapter.
///
/// The token has no public constructor and is deliberately neither cloneable nor serializable.
pub struct VerifiedTenantRootInitialRoleAttemptV1 {
    command: VerifiedTenantRootRoleCreationCommandV1,
    share_wire: SigningRootShareWire,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
}

impl fmt::Debug for VerifiedTenantRootInitialRoleAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootInitialRoleAttemptV1")
            .field("command", &self.command)
            .field("share_wire", &"[redacted]")
            .field("evidence", &self.evidence)
            .finish()
    }
}

impl VerifiedTenantRootInitialRoleAttemptV1 {
    /// Consumes the verified token into the exact sealer/handler inputs.
    pub fn into_parts(
        self,
    ) -> (
        VerifiedTenantRootRoleCreationCommandV1,
        SigningRootShareWire,
        VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    ) {
        (self.command, self.share_wire, self.evidence)
    }
}

fn validate_command_context(
    command: &VerifiedTenantRootRoleCreationCommandV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbDerivationResult<()> {
    context.validate()?;
    if command.creation_context_digest() != context.digest()?
        || command.identity_digest() != context.identity_digest()
        || command.custody_lineage() != context.custody_lineage()
    {
        return Err(malformed(
            "tenant-root initial role command does not match its creation context",
        ));
    }
    Ok(())
}

fn require_role_signing_key_matches(
    role_signing_key_bytes: &[u8; 32],
    expected_role_verifying_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<()> {
    let derived_verifying_key_bytes = SigningKey::from_bytes(role_signing_key_bytes)
        .verifying_key()
        .to_bytes();
    if derived_verifying_key_bytes != *expected_role_verifying_key_bytes {
        return Err(verification_failed(
            "tenant-root initial role signing key does not match its trusted verifying key",
        ));
    }
    Ok(())
}

fn commitment_for_role(
    pair: &VerifiedTenantRootCreationCommitmentPairV1,
    role: TwoPartyDeriverRole,
) -> &VerifiedTenantRootCreationCommitmentV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => pair.deriver_a(),
        TwoPartyDeriverRole::DeriverB => pair.deriver_b(),
    }
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn verification_failed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}
