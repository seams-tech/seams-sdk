use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use threshold_prf::{
    verify_root_share_knowledge, verify_two_party_root_share_refresh, RootShareKnowledgeProof,
    SigningRootShareCommitment, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
};

use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootShareEpoch,
};

const TENANT_ROOT_CREATE_DOMAIN_V1: &[u8] = b"tenant_root_create_v1";
const TENANT_ROOT_REFRESH_DOMAIN_V1: &[u8] = b"tenant_root_refresh_v1";
const TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1: u64 = 60_000;
const TENANT_ROOT_SESSION_ID_LEN: usize = 16;
const TENANT_ROOT_NONCE_LEN: usize = 32;

/// Random one-use identifier for a tenant-root creation or refresh ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootCeremonySessionIdV1([u8; TENANT_ROOT_SESSION_ID_LEN]);

impl TenantRootCeremonySessionIdV1 {
    /// Parses one exact non-zero 128-bit session identifier.
    pub fn from_bytes(bytes: [u8; TENANT_ROOT_SESSION_ID_LEN]) -> RouterAbDerivationResult<Self> {
        require_nonzero_bytes(&bytes, "tenant-root ceremony session id must be non-zero")?;
        Ok(Self(bytes))
    }

    /// Samples one fresh non-zero session identifier.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_SESSION_ID_LEN];
            rng.fill_bytes(&mut bytes);
            if let Ok(session) = Self::from_bytes(bytes) {
                return session;
            }
        }
    }

    /// Returns the exact session bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_SESSION_ID_LEN] {
        &self.0
    }
}

/// Random replay nonce for one tenant-root ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootCeremonyNonceV1([u8; TENANT_ROOT_NONCE_LEN]);

impl TenantRootCeremonyNonceV1 {
    /// Parses one exact non-zero 32-byte nonce.
    pub fn from_bytes(bytes: [u8; TENANT_ROOT_NONCE_LEN]) -> RouterAbDerivationResult<Self> {
        require_nonzero_bytes(&bytes, "tenant-root ceremony nonce must be non-zero")?;
        Ok(Self(bytes))
    }

    /// Samples one fresh non-zero ceremony nonce.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_NONCE_LEN];
            rng.fill_bytes(&mut bytes);
            if let Ok(nonce) = Self::from_bytes(bytes) {
                return nonce;
            }
        }
    }

    /// Returns the exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_NONCE_LEN] {
        &self.0
    }
}

/// Exact epoch branch for one tenant-root ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRootCeremonyEpochsV1 {
    /// Initial creation installs epoch 1 in an empty lineage.
    Create {
        /// First epoch installed in the lineage.
        next: TenantRootShareEpoch,
    },
    /// Refresh advances one active epoch by exactly one.
    Refresh {
        /// Currently active epoch.
        current: TenantRootShareEpoch,
        /// Exact next epoch.
        next: TenantRootShareEpoch,
    },
}

impl TenantRootCeremonyEpochsV1 {
    /// Creates the only valid initial-creation epoch branch.
    pub const fn create() -> Self {
        Self::Create {
            next: TenantRootShareEpoch::INITIAL,
        }
    }

    /// Creates an exact one-step refresh branch.
    pub fn refresh(
        current: TenantRootShareEpoch,
        next: TenantRootShareEpoch,
    ) -> RouterAbDerivationResult<Self> {
        if current.next()? != next {
            return Err(malformed(
                "tenant-root refresh next epoch must advance by exactly one",
            ));
        }
        Ok(Self::Refresh { current, next })
    }

    /// Returns the ceremony operation label.
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Refresh { .. } => "refresh",
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::Create { .. } => TENANT_ROOT_CREATE_DOMAIN_V1,
            Self::Refresh { .. } => TENANT_ROOT_REFRESH_DOMAIN_V1,
        }
    }
}

/// Immutable public facts shared by every message in one tenant-root ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootCeremonyContextV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epochs: TenantRootCeremonyEpochsV1,
    session_id: TenantRootCeremonySessionIdV1,
    nonce: TenantRootCeremonyNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    deriver_a_signing_key_id: String,
    deriver_b_signing_key_id: String,
}

impl TenantRootCeremonyContextV1 {
    /// Creates and validates one exact public ceremony context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        epochs: TenantRootCeremonyEpochsV1,
        session_id: TenantRootCeremonySessionIdV1,
        nonce: TenantRootCeremonyNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        deriver_a_signing_key_id: impl Into<String>,
        deriver_b_signing_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let context = Self {
            identity_digest,
            custody_lineage,
            epochs,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            deriver_a_signing_key_id: deriver_a_signing_key_id.into(),
            deriver_b_signing_key_id: deriver_b_signing_key_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates required key identities and the strict time interval.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_nonempty_key_id("deriver A signing key id", &self.deriver_a_signing_key_id)?;
        require_nonempty_key_id("deriver B signing key id", &self.deriver_b_signing_key_id)?;
        if self.deriver_a_signing_key_id == self.deriver_b_signing_key_id {
            return Err(malformed(
                "tenant-root Deriver signing key ids must be distinct",
            ));
        }
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(malformed(
                "tenant-root ceremony expiry must follow a non-zero issue time",
            ));
        }
        match self.epochs {
            TenantRootCeremonyEpochsV1::Create { next }
                if next != TenantRootShareEpoch::INITIAL =>
            {
                Err(malformed("tenant-root creation must install epoch 1"))
            }
            TenantRootCeremonyEpochsV1::Refresh { current, next } if current.next()? != next => {
                Err(malformed(
                    "tenant-root refresh next epoch must advance by exactly one",
                ))
            }
            _ => Ok(()),
        }
    }

    /// Applies the frozen 60-second peer clock-skew allowance.
    pub fn validate_at(&self, peer_now_ms: u64) -> RouterAbDerivationResult<()> {
        self.validate()?;
        let latest_acceptable_issue = peer_now_ms.saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1);
        let latest_acceptable_now = self
            .expires_at_ms
            .saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1);
        if self.issued_at_ms > latest_acceptable_issue || peer_now_ms > latest_acceptable_now {
            return Err(malformed(
                "tenant-root ceremony is outside the allowed clock-skew window",
            ));
        }
        Ok(())
    }

    /// Returns the canonical shared context bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        self.append_transcript_prefix(&mut bytes)?;
        self.append_transcript_suffix(&mut bytes)?;
        Ok(bytes)
    }

    pub(crate) fn append_transcript_prefix(
        &self,
        bytes: &mut Vec<u8>,
    ) -> RouterAbDerivationResult<()> {
        self.validate()?;
        push_len32(bytes, self.epochs.domain())?;
        push_len32(bytes, self.epochs.operation().as_bytes())?;
        push_len32(bytes, self.identity_digest.as_bytes())?;
        push_len32(bytes, self.custody_lineage.as_bytes())?;
        match self.epochs {
            TenantRootCeremonyEpochsV1::Create { next } => {
                push_u64_field(bytes, next.get().get())?;
            }
            TenantRootCeremonyEpochsV1::Refresh { current, next } => {
                push_u64_field(bytes, current.get().get())?;
                push_u64_field(bytes, next.get().get())?;
            }
        }
        push_len32(bytes, self.session_id.as_bytes())?;
        Ok(())
    }

    pub(crate) fn append_transcript_suffix(
        &self,
        bytes: &mut Vec<u8>,
    ) -> RouterAbDerivationResult<()> {
        push_len32(bytes, self.nonce.as_bytes())?;
        push_u64_field(bytes, self.issued_at_ms)?;
        push_u64_field(bytes, self.expires_at_ms)?;
        push_len32(bytes, self.deriver_a_signing_key_id.as_bytes())?;
        push_len32(bytes, self.deriver_b_signing_key_id.as_bytes())?;
        Ok(())
    }

    /// Returns the ceremony epoch branch.
    pub const fn epochs(&self) -> TenantRootCeremonyEpochsV1 {
        self.epochs
    }

    /// Returns the source role's exact signing-key identifier.
    pub fn signing_key_id(&self, role: TwoPartyDeriverRole) -> &str {
        match role {
            TwoPartyDeriverRole::DeriverA => &self.deriver_a_signing_key_id,
            TwoPartyDeriverRole::DeriverB => &self.deriver_b_signing_key_id,
        }
    }
}

/// Public transcript for one role's newly installed share and knowledge proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootShareInstallationTranscriptV1 {
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    commitment: SigningRootShareCommitment,
    peer_commitment: SigningRootShareCommitment,
}

impl TenantRootShareInstallationTranscriptV1 {
    /// Creates one role-exact installation transcript.
    pub fn new(
        context: TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        commitment: SigningRootShareCommitment,
        peer_commitment: SigningRootShareCommitment,
    ) -> RouterAbDerivationResult<Self> {
        require_commitment_role(&commitment, role)?;
        require_commitment_role(&peer_commitment, role.peer())?;
        Ok(Self {
            context,
            role,
            commitment,
            peer_commitment,
        })
    }

    /// Returns the exact transcript bytes used by the Schnorr proof.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.context.append_transcript_prefix(&mut bytes)?;
        push_len32(&mut bytes, self.role.as_str().as_bytes())?;
        push_u16_field(&mut bytes, self.role.share_id().get().get())?;
        push_len32(&mut bytes, &self.commitment.to_compressed())?;
        push_len32(&mut bytes, &self.peer_commitment.to_compressed())?;
        self.context.append_transcript_suffix(&mut bytes)?;
        Ok(bytes)
    }

    /// Returns the shared ceremony context.
    pub const fn context(&self) -> &TenantRootCeremonyContextV1 {
        &self.context
    }

    /// Returns the role proved by this transcript.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the role-local share commitment.
    pub const fn commitment(&self) -> SigningRootShareCommitment {
        self.commitment
    }

    /// Returns the peer share commitment.
    pub const fn peer_commitment(&self) -> SigningRootShareCommitment {
        self.peer_commitment
    }

    /// Returns a public SHA-256 transcript digest.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        Ok(TenantRootProtocolDigestV1(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }
}

/// One role's transcript-bound public share-installation proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootShareInstallationEvidenceV1 {
    transcript: TenantRootShareInstallationTranscriptV1,
    proof: RootShareKnowledgeProof,
}

/// Installation evidence authenticated by the exact issuing Deriver role key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantRootShareInstallationEvidenceV1 {
    evidence: TenantRootShareInstallationEvidenceV1,
}

impl VerifiedTenantRootShareInstallationEvidenceV1 {
    pub(super) fn from_authenticated(evidence: TenantRootShareInstallationEvidenceV1) -> Self {
        Self { evidence }
    }

    const fn evidence(&self) -> &TenantRootShareInstallationEvidenceV1 {
        &self.evidence
    }
}

impl TenantRootShareInstallationEvidenceV1 {
    /// Creates and verifies one exact installation evidence object.
    pub fn new(
        transcript: TenantRootShareInstallationTranscriptV1,
        proof: RootShareKnowledgeProof,
    ) -> RouterAbDerivationResult<Self> {
        let evidence = Self { transcript, proof };
        evidence.verify()?;
        Ok(evidence)
    }

    /// Verifies the role's proof against the exact installation transcript.
    pub fn verify(&self) -> RouterAbDerivationResult<()> {
        verify_root_share_knowledge(
            &self.transcript.commitment,
            &self.transcript.canonical_bytes()?,
            &self.proof,
        )
        .map_err(|_| verification_failed("tenant-root share knowledge proof failed"))
    }

    /// Returns the exact public transcript.
    pub const fn transcript(&self) -> &TenantRootShareInstallationTranscriptV1 {
        &self.transcript
    }

    /// Returns the fixed-width proof.
    pub const fn proof(&self) -> RootShareKnowledgeProof {
        self.proof
    }
}

/// Public digest for one exact tenant-root protocol transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootProtocolDigestV1([u8; 32]);

impl TenantRootProtocolDigestV1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the digest and returns its bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Verifies the exact A/B evidence for initial tenant-root creation.
pub fn verify_tenant_root_creation_evidence_v1(
    deriver_a: &VerifiedTenantRootShareInstallationEvidenceV1,
    deriver_b: &VerifiedTenantRootShareInstallationEvidenceV1,
) -> RouterAbDerivationResult<TwoPartyRootShareCommitments> {
    let deriver_a = deriver_a.evidence();
    let deriver_b = deriver_b.evidence();
    verify_evidence_pair(deriver_a, deriver_b)?;
    if !matches!(
        deriver_a.transcript.context.epochs,
        TenantRootCeremonyEpochsV1::Create { .. }
    ) {
        return Err(malformed(
            "tenant-root creation evidence requires the create epoch branch",
        ));
    }
    TwoPartyRootShareCommitments::new(
        deriver_a.transcript.commitment,
        deriver_b.transcript.commitment,
    )
    .map_err(|_| verification_failed("tenant-root creation commitment pair is invalid"))
}

/// Verifies exact A/B installation evidence and stable-root continuity for refresh.
pub fn verify_tenant_root_refresh_evidence_v1(
    current: &TwoPartyRootShareCommitments,
    deriver_a: &VerifiedTenantRootShareInstallationEvidenceV1,
    deriver_b: &VerifiedTenantRootShareInstallationEvidenceV1,
) -> RouterAbDerivationResult<TwoPartyRootShareCommitments> {
    let deriver_a = deriver_a.evidence();
    let deriver_b = deriver_b.evidence();
    verify_evidence_pair(deriver_a, deriver_b)?;
    if !matches!(
        deriver_a.transcript.context.epochs,
        TenantRootCeremonyEpochsV1::Refresh { .. }
    ) {
        return Err(malformed(
            "tenant-root refresh evidence requires the refresh epoch branch",
        ));
    }
    let next = TwoPartyRootShareCommitments::new(
        deriver_a.transcript.commitment,
        deriver_b.transcript.commitment,
    )
    .map_err(|_| verification_failed("tenant-root refresh commitment pair is invalid"))?;
    verify_two_party_root_share_refresh(current, &next)
        .map_err(|_| verification_failed("tenant-root refresh changed the public root"))?;
    Ok(next)
}

fn verify_evidence_pair(
    deriver_a: &TenantRootShareInstallationEvidenceV1,
    deriver_b: &TenantRootShareInstallationEvidenceV1,
) -> RouterAbDerivationResult<()> {
    if deriver_a.transcript.role != TwoPartyDeriverRole::DeriverA
        || deriver_b.transcript.role != TwoPartyDeriverRole::DeriverB
        || deriver_a.transcript.context != deriver_b.transcript.context
        || deriver_a.transcript.peer_commitment != deriver_b.transcript.commitment
        || deriver_b.transcript.peer_commitment != deriver_a.transcript.commitment
    {
        return Err(malformed(
            "tenant-root installation evidence does not form one exact A/B ceremony",
        ));
    }
    deriver_a.verify()?;
    deriver_b.verify()
}

fn require_commitment_role(
    commitment: &SigningRootShareCommitment,
    role: TwoPartyDeriverRole,
) -> RouterAbDerivationResult<()> {
    if commitment.id() == role.share_id() {
        Ok(())
    } else {
        Err(malformed(
            "tenant-root share commitment does not match its Deriver role",
        ))
    }
}

fn require_nonzero_bytes(bytes: &[u8], message: &'static str) -> RouterAbDerivationResult<()> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(malformed(message))
    } else {
        Ok(())
    }
}

fn require_nonempty_key_id(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root role signing key id is too long"))?;
    Ok(())
}

fn push_len32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root protocol field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn push_u16_field(out: &mut Vec<u8>, value: u16) -> RouterAbDerivationResult<()> {
    push_len32(out, &value.to_be_bytes())
}

fn push_u64_field(out: &mut Vec<u8>, value: u64) -> RouterAbDerivationResult<()> {
    push_len32(out, &value.to_be_bytes())
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
