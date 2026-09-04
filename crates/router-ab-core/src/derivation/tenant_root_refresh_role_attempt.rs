use core::fmt;

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use threshold_prf::{
    apply_two_party_root_share_refresh, derive_two_party_root_share_refresh_commitments,
    prove_root_share_knowledge, RootShareRefreshCoefficient, RootShareRefreshCoefficientCommitment,
    RootShareRefreshContributionWire, SigningRootShare, SigningRootShareCommitment,
    SigningRootShareWire, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
};
use zeroize::Zeroizing;

use super::{
    MpcPrfShareCommitmentWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootActiveRoleBindingV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootEpochCommitmentsV1, TenantRootManagedRestoreRoleV1,
    TenantRootRefreshCommitmentTranscriptV1, TenantRootRefreshHpkePublicKeyV1,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootRefreshCommitmentPairV1, VerifiedTenantRootRefreshCommitmentV1,
    VerifiedTenantRootRoleRefreshCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};

/// One role's in-memory refresh attempt before the A/B contribution pair is available.
///
/// This token owns the current share, refresh coefficient, and role signing key. It is
/// deliberately neither cloneable nor serializable; dropping it burns the request-local
/// secret material without creating persistent state.
pub struct PendingTenantRootRefreshRoleAttemptV1 {
    command: VerifiedTenantRootRoleRefreshCommandV1,
    commitment: VerifiedTenantRootRefreshCommitmentV1,
    share: SigningRootShare,
    coefficient: RootShareRefreshCoefficient,
    role_signing_key: Zeroizing<[u8; 32]>,
    role_verifying_key: [u8; 32],
}

impl fmt::Debug for PendingTenantRootRefreshRoleAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTenantRootRefreshRoleAttemptV1")
            .field("command", &self.command)
            .field("commitment", &self.commitment)
            .field("share", &"[redacted]")
            .field("coefficient", &"[redacted]")
            .field("role_signing_key", &"[redacted]")
            .field("role_verifying_key", &self.role_verifying_key)
            .finish()
    }
}

impl PendingTenantRootRefreshRoleAttemptV1 {
    /// Samples, commits, signs, and self-verifies one role's refresh coefficient.
    #[allow(clippy::too_many_arguments)]
    pub fn new<R>(
        command: VerifiedTenantRootRoleRefreshCommandV1,
        refresh_context: TenantRootCeremonyContextV1,
        active_binding: TenantRootActiveRoleBindingV1,
        opened_share: SigningRootShare,
        role_signing_key_bytes: &[u8; 32],
        expected_role_verifying_key_bytes: &[u8; 32],
        recipient_key_id: impl Into<String>,
        recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
        now_ms: u64,
        rng: &mut R,
    ) -> RouterAbDerivationResult<Self>
    where
        R: RngCore + CryptoRng,
    {
        validate_command_context(&command, &refresh_context)?;
        command.require_fresh(now_ms)?;
        let role = command.role();
        validate_active_binding(&command, &active_binding, role)?;
        validate_opened_share(&active_binding, role, &opened_share)?;
        require_role_signing_key_matches(
            role_signing_key_bytes,
            expected_role_verifying_key_bytes,
        )?;

        let coefficient = RootShareRefreshCoefficient::random(role, rng);
        let expected_context = refresh_context.clone();
        let transcript = TenantRootRefreshCommitmentTranscriptV1::new(
            refresh_context,
            coefficient.commitment(),
            recipient_key_id,
            recipient_public_key,
        )?;
        let signed = TenantRootSignedRefreshCommitmentV1::sign(transcript, role_signing_key_bytes)?;
        let commitment_bytes = signed.canonical_bytes()?;
        let decoded_commitment =
            TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&commitment_bytes)?;
        let verified_commitment = decoded_commitment.verify_strict(
            &expected_context,
            role,
            expected_context.signing_key_id(role),
            expected_role_verifying_key_bytes,
        )?;

        Ok(Self {
            command,
            commitment: verified_commitment,
            share: opened_share,
            coefficient,
            role_signing_key: Zeroizing::new(*role_signing_key_bytes),
            role_verifying_key: *expected_role_verifying_key_bytes,
        })
    }

    /// Returns the exact role selected by the issuer command.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.command.role()
    }

    /// Returns the verified public command retained by this live attempt.
    pub const fn command(&self) -> &VerifiedTenantRootRoleRefreshCommandV1 {
        &self.command
    }

    /// Returns the exact verified local refresh commitment token.
    pub const fn commitment(&self) -> &VerifiedTenantRootRefreshCommitmentV1 {
        &self.commitment
    }

    /// Returns the exact signed local refresh commitment wire bytes for Router rendezvous.
    pub fn commitment_bytes(&self) -> &[u8] {
        self.commitment.canonical_bytes()
    }

    /// Returns the local coefficient contribution addressed to the peer role.
    pub fn contribution_for_peer(&self) -> RootShareRefreshContributionWire {
        self.coefficient.contribution_for(self.role().peer())
    }

    /// Applies both role contributions and returns the verified next-epoch role output.
    pub fn finalize<R>(
        self,
        verified_pair: VerifiedTenantRootRefreshCommitmentPairV1,
        peer_contribution: RootShareRefreshContributionWire,
        rng: &mut R,
    ) -> RouterAbDerivationResult<VerifiedTenantRootRefreshRoleAttemptV1>
    where
        R: RngCore + CryptoRng,
    {
        let PendingTenantRootRefreshRoleAttemptV1 {
            command,
            commitment,
            share,
            coefficient,
            role_signing_key,
            role_verifying_key,
        } = self;
        let role = command.role();
        let context = commitment.transcript().context();
        validate_verified_pair(&verified_pair, context, &commitment, role)?;

        let current_commitments = current_commitments_from_command(&command)?;
        let local_coefficient_commitment = coefficient.commitment();
        let pair_local_coefficient_commitment = commitment_for_role(&verified_pair, role)
            .transcript()
            .commitment();
        if pair_local_coefficient_commitment != local_coefficient_commitment {
            return Err(malformed(
                "tenant-root refresh role attempt coefficient does not match its verified commitment",
            ));
        }
        let peer_coefficient_commitment = commitment_for_role(&verified_pair, role.peer())
            .transcript()
            .commitment();
        let own_contribution = local_coefficient_commitment
            .verify_contribution(coefficient.contribution_for(role))
            .map_err(|_| {
                verification_failed(
                    "tenant-root refresh role attempt local contribution proof failed",
                )
            })?;
        let peer_contribution = peer_coefficient_commitment
            .verify_contribution(peer_contribution)
            .map_err(|_| {
                verification_failed(
                    "tenant-root refresh role attempt peer contribution proof failed",
                )
            })?;
        let next_share =
            apply_two_party_root_share_refresh(&share, own_contribution, peer_contribution)
                .map_err(|_| {
                    verification_failed("tenant-root refresh role share derivation failed")
                })?;

        let next_commitments = derive_two_party_root_share_refresh_commitments(
            &current_commitments,
            coefficient_commitment_for_role(&verified_pair, TwoPartyDeriverRole::DeriverA),
            coefficient_commitment_for_role(&verified_pair, TwoPartyDeriverRole::DeriverB),
        )
        .map_err(|_| {
            verification_failed("tenant-root refresh next public commitments are invalid")
        })?;
        let expected_local_commitment = next_commitment_for_role(&next_commitments, role);
        if SigningRootShareCommitment::from_share(&next_share) != expected_local_commitment {
            return Err(verification_failed(
                "tenant-root refreshed share does not match its predicted commitment",
            ));
        }
        let transcript = TenantRootShareInstallationTranscriptV1::new(
            context.clone(),
            role,
            expected_local_commitment,
            next_commitment_for_role(&next_commitments, role.peer()),
        )?;
        let transcript_bytes = transcript.canonical_bytes()?;
        let proof = prove_root_share_knowledge(&next_share, &transcript_bytes, rng)
            .map_err(|_| verification_failed("tenant-root refreshed role share proof failed"))?;
        let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof)?;
        let signed_evidence =
            TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &role_signing_key)?;
        let evidence_bytes = signed_evidence.canonical_bytes()?;
        let verified_evidence =
            TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
                &evidence_bytes,
                &role_verifying_key,
            )?;
        Ok(VerifiedTenantRootRefreshRoleAttemptV1 {
            command,
            share_wire: SigningRootShareWire::from_share(&next_share),
            evidence: verified_evidence,
        })
    }
}

/// Fully verified refresh role output ready for online sealing and persistence by an adapter.
///
/// The token has no public constructor and is deliberately neither cloneable nor serializable.
pub struct VerifiedTenantRootRefreshRoleAttemptV1 {
    command: VerifiedTenantRootRoleRefreshCommandV1,
    share_wire: SigningRootShareWire,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
}

impl fmt::Debug for VerifiedTenantRootRefreshRoleAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRefreshRoleAttemptV1")
            .field("command", &self.command)
            .field("share_wire", &"[redacted]")
            .field("evidence", &self.evidence)
            .finish()
    }
}

impl VerifiedTenantRootRefreshRoleAttemptV1 {
    /// Consumes the verified token into the exact sealer/handler inputs.
    pub fn into_parts(
        self,
    ) -> (
        VerifiedTenantRootRoleRefreshCommandV1,
        SigningRootShareWire,
        VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    ) {
        (self.command, self.share_wire, self.evidence)
    }
}

fn validate_command_context(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbDerivationResult<()> {
    context.validate()?;
    let TenantRootCeremonyEpochsV1::Refresh { current, next } = context.epochs() else {
        return Err(malformed(
            "tenant-root refresh role attempt requires a refresh ceremony context",
        ));
    };
    if command.refresh_context_digest() != context.digest()?
        || command.identity_digest() != context.identity_digest()
        || command.custody_lineage() != context.custody_lineage()
        || command.current_epoch() != current
        || command.next_epoch() != next
    {
        return Err(malformed(
            "tenant-root refresh role command does not match its refresh context",
        ));
    }
    Ok(())
}

fn validate_active_binding(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active_binding: &TenantRootActiveRoleBindingV1,
    role: TwoPartyDeriverRole,
) -> RouterAbDerivationResult<()> {
    if managed_role(active_binding.role()) != role
        || active_binding.identity_digest() != command.identity_digest()
        || active_binding.custody_lineage() != command.custody_lineage()
        || active_binding.epoch() != command.current_epoch()
        || active_binding.activation_receipt_digest() != command.active_activation_receipt_digest()
        || active_binding.share_commitment() != local_active_commitment(command, role)
    {
        return Err(malformed(
            "tenant-root refresh role active binding does not match its verified command",
        ));
    }
    Ok(())
}

fn validate_opened_share(
    active_binding: &TenantRootActiveRoleBindingV1,
    role: TwoPartyDeriverRole,
    opened_share: &SigningRootShare,
) -> RouterAbDerivationResult<()> {
    if TwoPartyDeriverRole::from_share_id(opened_share.id())
        .map_err(|_| malformed("tenant-root refresh opened share has an invalid role"))?
        != role
    {
        return Err(malformed(
            "tenant-root refresh opened share role does not match its command",
        ));
    }
    let opened_commitment = SigningRootShareCommitment::from_share(opened_share).to_bytes();
    let expected_commitment = active_binding.share_commitment().as_bytes();
    if opened_commitment.len() != expected_commitment.len()
        || !bool::from(expected_commitment.ct_eq(opened_commitment.as_ref()))
    {
        return Err(verification_failed(
            "tenant-root refresh opened share does not match its active commitment",
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
            "tenant-root refresh role signing key does not match its trusted verifying key",
        ));
    }
    Ok(())
}

fn validate_verified_pair(
    pair: &VerifiedTenantRootRefreshCommitmentPairV1,
    context: &TenantRootCeremonyContextV1,
    local_commitment: &VerifiedTenantRootRefreshCommitmentV1,
    role: TwoPartyDeriverRole,
) -> RouterAbDerivationResult<()> {
    if pair.context() != context {
        return Err(malformed(
            "tenant-root refresh role attempt pair context does not match its command",
        ));
    }
    let pair_local = commitment_for_role(pair, role);
    if pair_local.transcript().context() != context
        || pair_local.canonical_bytes() != local_commitment.canonical_bytes()
    {
        return Err(malformed(
            "tenant-root refresh role attempt does not match its verified commitment pair",
        ));
    }
    Ok(())
}

fn current_commitments_from_command(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbDerivationResult<TwoPartyRootShareCommitments> {
    let commitments = TenantRootEpochCommitmentsV1::new(
        command.deriver_a_share_commitment().clone(),
        command.deriver_b_share_commitment().clone(),
    )?;
    let pair = commitments.threshold_pair()?;
    if pair.root().to_bytes() != *command.active_root_commitment() {
        return Err(malformed(
            "tenant-root refresh command active root commitment does not match its role commitments",
        ));
    }
    Ok(pair)
}

fn managed_role(role: TenantRootManagedRestoreRoleV1) -> TwoPartyDeriverRole {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        TenantRootManagedRestoreRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

fn local_active_commitment(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    role: TwoPartyDeriverRole,
) -> &MpcPrfShareCommitmentWireV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => command.deriver_a_share_commitment(),
        TwoPartyDeriverRole::DeriverB => command.deriver_b_share_commitment(),
    }
}

fn commitment_for_role(
    pair: &VerifiedTenantRootRefreshCommitmentPairV1,
    role: TwoPartyDeriverRole,
) -> &VerifiedTenantRootRefreshCommitmentV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => pair.deriver_a(),
        TwoPartyDeriverRole::DeriverB => pair.deriver_b(),
    }
}

fn coefficient_commitment_for_role(
    pair: &VerifiedTenantRootRefreshCommitmentPairV1,
    role: TwoPartyDeriverRole,
) -> RootShareRefreshCoefficientCommitment {
    commitment_for_role(pair, role).transcript().commitment()
}

fn next_commitment_for_role(
    pair: &TwoPartyRootShareCommitments,
    role: TwoPartyDeriverRole,
) -> SigningRootShareCommitment {
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
