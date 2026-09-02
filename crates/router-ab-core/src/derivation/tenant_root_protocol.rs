use rand_core::{CryptoRng, RngCore};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use threshold_prf::{
    verify_root_share_knowledge, verify_two_party_root_share_refresh, RootShareKnowledgeProof,
    SigningRootShareCommitment, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
};

use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootShareEpoch, TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_CREATE_DOMAIN_V1: &[u8] = b"tenant_root_create_v1";
const TENANT_ROOT_REFRESH_DOMAIN_V1: &[u8] = b"tenant_root_refresh_v1";
const TENANT_ROOT_SESSION_ID_LEN: usize = 16;
const TENANT_ROOT_NONCE_LEN: usize = 32;
const TENANT_ROOT_CEREMONY_CONTEXT_MAX_WIRE_BYTES_V1: usize = 4 * 1024;
const TENANT_ROOT_CEREMONY_CONTEXT_MAX_IDENTIFIER_BYTES_V1: usize = 256;

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
        require_tenant_root_identifier("deriver A signing key id", &self.deriver_a_signing_key_id)?;
        require_tenant_root_identifier("deriver B signing key id", &self.deriver_b_signing_key_id)?;
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
        if self.expires_at_ms - self.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
            return Err(malformed(
                "tenant-root ceremony lifetime exceeds the frozen maximum window",
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

    /// Parses one exact canonical shared ceremony context wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_CEREMONY_CONTEXT_MAX_WIRE_BYTES_V1 {
            return Err(malformed(
                "tenant-root ceremony context wire length is invalid",
            ));
        }
        let mut decoder = TenantRootWireDecoderV1::new(bytes);
        let domain = decoder.field("tenant-root ceremony context domain")?;
        let operation = decoder.field("tenant-root ceremony context operation")?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root ceremony context identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root ceremony context custody lineage")?,
        )?;
        let epochs = match (domain, operation) {
            (TENANT_ROOT_CREATE_DOMAIN_V1, b"create") => {
                if decoder.u64_field("tenant-root ceremony context next epoch")?
                    != TenantRootShareEpoch::INITIAL.get().get()
                {
                    return Err(malformed(
                        "tenant-root ceremony context creation epoch is invalid",
                    ));
                }
                TenantRootCeremonyEpochsV1::create()
            }
            (TENANT_ROOT_REFRESH_DOMAIN_V1, b"refresh") => {
                let current = TenantRootShareEpoch::new(
                    decoder.u64_field("tenant-root ceremony context current epoch")?,
                )?;
                let next = TenantRootShareEpoch::new(
                    decoder.u64_field("tenant-root ceremony context next epoch")?,
                )?;
                TenantRootCeremonyEpochsV1::refresh(current, next)?
            }
            _ => {
                return Err(malformed(
                    "tenant-root ceremony context domain or operation is invalid",
                ));
            }
        };
        let session_id = TenantRootCeremonySessionIdV1::from_bytes(
            decoder.fixed_field::<TENANT_ROOT_SESSION_ID_LEN>(
                "tenant-root ceremony context session id",
            )?,
        )?;
        let nonce = TenantRootCeremonyNonceV1::from_bytes(
            decoder.fixed_field::<TENANT_ROOT_NONCE_LEN>("tenant-root ceremony context nonce")?,
        )?;
        let issued_at_ms = decoder.u64_field("tenant-root ceremony context issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root ceremony context expiry")?;
        let deriver_a_signing_key_id = decoder.text_field(
            "tenant-root ceremony context Deriver A signing key id",
            TENANT_ROOT_CEREMONY_CONTEXT_MAX_IDENTIFIER_BYTES_V1,
        )?;
        let deriver_b_signing_key_id = decoder.text_field(
            "tenant-root ceremony context Deriver B signing key id",
            TENANT_ROOT_CEREMONY_CONTEXT_MAX_IDENTIFIER_BYTES_V1,
        )?;
        decoder.finish()?;
        let context = Self::new(
            identity_digest,
            custody_lineage,
            epochs,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            deriver_a_signing_key_id,
            deriver_b_signing_key_id,
        )?;
        if context.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root ceremony context wire is not canonical",
            ));
        }
        Ok(context)
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

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the ceremony issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the ceremony expiry.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the one-use ceremony session identifier.
    pub const fn session_id(&self) -> TenantRootCeremonySessionIdV1 {
        self.session_id
    }

    /// Returns the one-use ceremony replay nonce.
    pub const fn nonce(&self) -> TenantRootCeremonyNonceV1 {
        self.nonce
    }

    /// Returns a public digest of the exact ceremony context.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
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
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
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

    /// Returns the authenticated role's exact public installation transcript.
    pub const fn transcript(&self) -> &TenantRootShareInstallationTranscriptV1 {
        self.evidence.transcript()
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantRootProtocolDigestV1([u8; 32]);

impl TenantRootProtocolDigestV1 {
    /// Parses exact public digest bytes and rejects the all-zero digest.
    pub fn from_bytes(bytes: [u8; 32]) -> RouterAbDerivationResult<Self> {
        require_nonzero_bytes(&bytes, "tenant-root protocol digest must be non-zero")?;
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the digest and returns its bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl<'de> Deserialize<'de> for TenantRootProtocolDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(D::Error::custom)
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

pub(crate) struct TenantRootWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TenantRootWireDecoderV1<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root wire offset overflow"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root wire field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte tenant-root wire field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root wire field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root wire field is truncated"))?;
        self.offset = value_end;
        if value.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                format!("{name} is required"),
            ));
        }
        Ok(value)
    }

    pub(crate) fn require_field(&mut self, expected: &[u8]) -> RouterAbDerivationResult<()> {
        if self.field("tenant-root wire domain")? != expected {
            return Err(malformed("tenant-root wire domain is invalid"));
        }
        Ok(())
    }

    pub(crate) fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root wire fixed field length is invalid"))
    }

    pub(crate) fn u64_field(&mut self, name: &'static str) -> RouterAbDerivationResult<u64> {
        Ok(u64::from_be_bytes(self.fixed_field::<8>(name)?))
    }

    pub(crate) fn text_field(
        &mut self,
        name: &'static str,
        max_bytes: usize,
    ) -> RouterAbDerivationResult<String> {
        let bytes = self.field(name)?;
        if bytes.len() > max_bytes {
            return Err(malformed("tenant-root wire text field is too long"));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root wire text field is invalid UTF-8"))
    }

    pub(crate) fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root wire role")?;
        let share_id = self.fixed_field::<2>("tenant-root wire role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed("tenant-root wire role encoding is invalid")),
        }
    }

    pub(crate) fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed("tenant-root wire has trailing bytes"));
        }
        Ok(())
    }
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
