use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core::{CryptoRng as CryptoRng06, RngCore as RngCore06};
use rand_core_09::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{
    apply_two_party_root_share_refresh, prove_root_share_knowledge, verify_root_share_knowledge,
    verify_two_party_root_share_refresh, RootShareKnowledgeProof, RootShareRefreshCoefficient,
    RootShareRefreshCoefficientCommitment, RootShareRefreshContributionWire, SigningRootShare,
    SigningRootShareCommitment, SigningRootShareWire, TwoPartyDeriverRole, TwoPartyRootCommitment,
    TwoPartyRootShareCommitments, VerifiedRootShareRefreshContribution,
};
use zeroize::{Zeroize, Zeroizing};

use super::x25519_canonical::is_canonical_nonzero_x25519_encoding;
use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootActiveRefreshV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootIdentityV1,
    TenantRootProtocolDigestV1, TenantRootRecoveryRecipientFingerprintV1,
    TenantRootRecoveryRecipientPublicKeyV1, TenantRootRecoverySetId, TenantRootShareEpoch,
};

const RECOVERY_RESHARE_CONTEXT_DOMAIN_V1: &[u8] = b"tenant_root_recovery_reshare_v1";
const RECOVERY_RESHARE_COMMITMENT_DOMAIN_V1: &[u8] = b"tenant_root_recovery_reshare_commitment_v1";
const RECOVERY_RESHARE_CONTRIBUTION_AAD_DOMAIN_V1: &[u8] =
    b"tenant_root_recovery_reshare_contribution_aad_v1";
const RECOVERY_RESHARE_CONTRIBUTION_ENVELOPE_DOMAIN_V1: &[u8] =
    b"tenant_root_recovery_reshare_contribution_envelope_v1";
const RECOVERY_RESHARE_INSTALLATION_DOMAIN_V1: &[u8] =
    b"tenant_root_recovery_reshare_installation_v1";
const RECOVERY_RESHARE_EVIDENCE_DOMAIN_V1: &[u8] = b"tenant_root_recovery_reshare_evidence_v1";
const RECOVERY_RESHARE_ROLE_AUTHENTICATION_DOMAIN_V1: &[u8] =
    b"tenant_root_recovery_reshare_role_authentication_v1";
const RECOVERY_RESHARE_HPKE_INFO_V1: &[u8] =
    b"seams/tenant-root-recovery-reshare/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const RECOVERY_RESHARE_HPKE_KEY_LEN: usize = 32;
const RECOVERY_RESHARE_HPKE_TAG_LEN: usize = 16;
const RECOVERY_RESHARE_CONTRIBUTION_CIPHERTEXT_LEN: usize =
    RootShareRefreshContributionWire::LEN + RECOVERY_RESHARE_HPKE_TAG_LEN;
const TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1: u64 = 60_000;

type TenantRootRecoveryReshareHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

/// Immutable public facts shared by every message in one dedicated recovery reshare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryReshareContextV1 {
    identity: TenantRootIdentityV1,
    identity_digest: TenantRootIdentityDigestV1,
    source_custody_lineage: TenantRootCustodyLineageId,
    active_epoch: TenantRootShareEpoch,
    active_commitments: TwoPartyRootShareCommitments,
    recovery_set_id: TenantRootRecoverySetId,
    recipient_a: TenantRootRecoveryRecipientPublicKeyV1,
    recipient_b: TenantRootRecoveryRecipientPublicKeyV1,
    session_id: TenantRootCeremonySessionIdV1,
    nonce: TenantRootCeremonyNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    deriver_a_signing_key_id: String,
    deriver_b_signing_key_id: String,
}

impl TenantRootRecoveryReshareContextV1 {
    /// Creates one recovery-only context from the authoritative active lifecycle state.
    #[allow(clippy::too_many_arguments)]
    pub fn from_active(
        active: &TenantRootActiveRefreshV1,
        recovery_set_id: TenantRootRecoverySetId,
        recipient_a: TenantRootRecoveryRecipientPublicKeyV1,
        recipient_b: TenantRootRecoveryRecipientPublicKeyV1,
        session_id: TenantRootCeremonySessionIdV1,
        nonce: TenantRootCeremonyNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        deriver_a_signing_key_id: impl Into<String>,
        deriver_b_signing_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let commitments = active.current().verified().commitments();
        let active_commitments = TwoPartyRootShareCommitments::new(
            SigningRootShareCommitment::from_slice(commitments.deriver_a().as_bytes())
                .map_err(|_| malformed("tenant-root active Deriver A commitment is invalid"))?,
            SigningRootShareCommitment::from_slice(commitments.deriver_b().as_bytes())
                .map_err(|_| malformed("tenant-root active Deriver B commitment is invalid"))?,
        )
        .map_err(|_| malformed("tenant-root active commitment pair is invalid"))?;
        if active_commitments.root().to_bytes() != *commitments.root_commitment() {
            return Err(malformed(
                "tenant-root active commitment pair does not match its stable root",
            ));
        }
        let context = Self {
            identity: active.identity().clone(),
            identity_digest: active.identity().digest()?,
            source_custody_lineage: active.custody_lineage(),
            active_epoch: active.current().epoch(),
            active_commitments,
            recovery_set_id,
            recipient_a,
            recipient_b,
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

    /// Validates the exact identity, recipient, commitment, key, and lifetime bindings.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.identity.digest()? != self.identity_digest {
            return Err(malformed(
                "tenant-root recovery reshare identity digest does not match identity",
            ));
        }
        if self.recipient_a.fingerprint() == self.recipient_b.fingerprint() {
            return Err(malformed(
                "tenant-root recovery reshare recipient fingerprints must differ",
            ));
        }
        require_key_id(
            "tenant-root recovery reshare Deriver A signing key id",
            &self.deriver_a_signing_key_id,
        )?;
        require_key_id(
            "tenant-root recovery reshare Deriver B signing key id",
            &self.deriver_b_signing_key_id,
        )?;
        if self.deriver_a_signing_key_id == self.deriver_b_signing_key_id {
            return Err(malformed(
                "tenant-root recovery reshare Deriver signing key ids must differ",
            ));
        }
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(malformed(
                "tenant-root recovery reshare expiry must follow a non-zero issue time",
            ));
        }
        TwoPartyRootShareCommitments::new(
            self.active_commitments.deriver_a(),
            self.active_commitments.deriver_b(),
        )
        .map_err(|_| malformed("tenant-root recovery reshare active commitments are invalid"))?;
        Ok(())
    }

    /// Applies the frozen 60-second peer clock-skew allowance.
    pub fn validate_at(&self, peer_now_ms: u64) -> RouterAbDerivationResult<()> {
        self.validate()?;
        if self.issued_at_ms > peer_now_ms.saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1)
            || peer_now_ms
                > self
                    .expires_at_ms
                    .saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1)
        {
            return Err(malformed(
                "tenant-root recovery reshare is outside the allowed clock-skew window",
            ));
        }
        Ok(())
    }

    /// Returns the exact canonical recovery-reshare context bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_field(&mut bytes, RECOVERY_RESHARE_CONTEXT_DOMAIN_V1)?;
        push_field(&mut bytes, self.identity_digest.as_bytes())?;
        push_field(&mut bytes, self.source_custody_lineage.as_bytes())?;
        push_field(&mut bytes, &self.active_epoch.get().get().to_be_bytes())?;
        push_field(&mut bytes, &self.active_commitments.deriver_a().to_bytes())?;
        push_field(&mut bytes, &self.active_commitments.deriver_b().to_bytes())?;
        push_field(&mut bytes, &self.active_commitments.root().to_bytes())?;
        push_field(&mut bytes, self.recovery_set_id.as_bytes())?;
        push_field(&mut bytes, self.recipient_a.fingerprint().as_bytes())?;
        push_field(&mut bytes, self.recipient_b.fingerprint().as_bytes())?;
        push_field(&mut bytes, self.session_id.as_bytes())?;
        push_field(&mut bytes, self.nonce.as_bytes())?;
        push_field(&mut bytes, &self.issued_at_ms.to_be_bytes())?;
        push_field(&mut bytes, &self.expires_at_ms.to_be_bytes())?;
        push_field(&mut bytes, self.deriver_a_signing_key_id.as_bytes())?;
        push_field(&mut bytes, self.deriver_b_signing_key_id.as_bytes())?;
        Ok(bytes)
    }

    /// Returns the SHA-256 digest of the exact public context.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        Ok(TenantRootProtocolDigestV1::from_bytes(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    /// Returns the server-resolved tenant-root identity.
    pub const fn identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the exact identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the source custody lineage.
    pub const fn source_custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.source_custody_lineage
    }

    /// Returns the source operational epoch without making it a recovery epoch.
    pub const fn active_epoch(&self) -> TenantRootShareEpoch {
        self.active_epoch
    }

    /// Returns the stable public root commitment.
    pub fn stable_root_commitment(&self) -> TwoPartyRootCommitment {
        self.active_commitments.root()
    }

    /// Returns the dedicated recovery-set identifier.
    pub const fn recovery_set_id(&self) -> TenantRootRecoverySetId {
        self.recovery_set_id
    }

    /// Returns one role's final recovery-package recipient.
    pub const fn recovery_recipient_public_key(
        &self,
        role: TwoPartyDeriverRole,
    ) -> TenantRootRecoveryRecipientPublicKeyV1 {
        match role {
            TwoPartyDeriverRole::DeriverA => self.recipient_a,
            TwoPartyDeriverRole::DeriverB => self.recipient_b,
        }
    }

    /// Returns one role's final recovery-package recipient fingerprint.
    pub fn recovery_recipient_fingerprint(
        &self,
        role: TwoPartyDeriverRole,
    ) -> TenantRootRecoveryRecipientFingerprintV1 {
        self.recovery_recipient_public_key(role).fingerprint()
    }

    /// Returns one role's exact active public share commitment.
    pub fn active_share_commitment(&self, role: TwoPartyDeriverRole) -> SigningRootShareCommitment {
        match role {
            TwoPartyDeriverRole::DeriverA => self.active_commitments.deriver_a(),
            TwoPartyDeriverRole::DeriverB => self.active_commitments.deriver_b(),
        }
    }

    /// Returns one role's exact signing-key identifier.
    pub fn signing_key_id(&self, role: TwoPartyDeriverRole) -> &str {
        match role {
            TwoPartyDeriverRole::DeriverA => &self.deriver_a_signing_key_id,
            TwoPartyDeriverRole::DeriverB => &self.deriver_b_signing_key_id,
        }
    }
}

/// A role-authenticated public recovery coefficient commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedRecoveryReshareCommitmentV1 {
    context_digest: TenantRootProtocolDigestV1,
    commitment: RootShareRefreshCoefficientCommitment,
    authentication: TenantRootRecoveryReshareRoleAuthenticationV1,
}

impl TenantRootSignedRecoveryReshareCommitmentV1 {
    /// Signs one role's fresh non-zero coefficient commitment.
    pub fn sign(
        context: &TenantRootRecoveryReshareContextV1,
        coefficient: &RootShareRefreshCoefficient,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let commitment = coefficient.commitment();
        let context_digest = context.digest()?;
        let payload = commitment_transcript(context, commitment)?;
        let authentication = TenantRootRecoveryReshareRoleAuthenticationV1::sign(
            context,
            commitment.source(),
            &payload,
            signing_key_bytes,
        )?;
        Ok(Self {
            context_digest,
            commitment,
            authentication,
        })
    }

    /// Verifies the exact context and source signature, yielding a commit-stage capability.
    pub fn verify(
        &self,
        context: &TenantRootRecoveryReshareContextV1,
        verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootRecoveryReshareCommitmentV1> {
        if self.context_digest != context.digest()? {
            return Err(malformed(
                "tenant-root recovery reshare commitment context does not match",
            ));
        }
        let payload = commitment_transcript(context, self.commitment)?;
        self.authentication.verify(
            context,
            self.commitment.source(),
            &payload,
            verifying_key_bytes,
        )?;
        Ok(VerifiedTenantRootRecoveryReshareCommitmentV1 {
            context_digest: self.context_digest,
            commitment: self.commitment,
        })
    }

    /// Returns the signed coefficient commitment.
    pub const fn commitment(&self) -> RootShareRefreshCoefficientCommitment {
        self.commitment
    }
}

/// Verified commit-stage capability required before contribution encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantRootRecoveryReshareCommitmentV1 {
    context_digest: TenantRootProtocolDigestV1,
    commitment: RootShareRefreshCoefficientCommitment,
}

impl VerifiedTenantRootRecoveryReshareCommitmentV1 {
    /// Returns the source role.
    pub fn source(&self) -> TwoPartyDeriverRole {
        self.commitment.source()
    }

    /// Returns the verified coefficient commitment.
    pub const fn commitment(&self) -> RootShareRefreshCoefficientCommitment {
        self.commitment
    }
}

/// Validated X25519 public key for one role's one-use reshare contribution receiver.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryReshareHpkePublicKeyV1([u8; RECOVERY_RESHARE_HPKE_KEY_LEN]);

impl fmt::Debug for TenantRootRecoveryReshareHpkePublicKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRecoveryReshareHpkePublicKeyV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl TenantRootRecoveryReshareHpkePublicKeyV1 {
    /// Parses one canonical non-zero X25519 public key.
    pub fn from_bytes(
        bytes: [u8; RECOVERY_RESHARE_HPKE_KEY_LEN],
    ) -> RouterAbDerivationResult<Self> {
        if !is_canonical_nonzero_x25519_encoding(&bytes)
            || DhKemX25519HkdfSha256::pk_from_bytes(&bytes).is_err()
        {
            return Err(malformed(
                "tenant-root recovery reshare HPKE public key is invalid",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact public key bytes.
    pub const fn as_bytes(&self) -> &[u8; RECOVERY_RESHARE_HPKE_KEY_LEN] {
        &self.0
    }
}

/// One-use HPKE keypair retained only by its target Deriver.
pub struct TenantRootRecoveryReshareHpkeKeypairV1 {
    private_key: Zeroizing<[u8; RECOVERY_RESHARE_HPKE_KEY_LEN]>,
    public_key: TenantRootRecoveryReshareHpkePublicKeyV1,
}

impl fmt::Debug for TenantRootRecoveryReshareHpkeKeypairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRecoveryReshareHpkeKeypairV1")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl TenantRootRecoveryReshareHpkeKeypairV1 {
    /// Deterministically derives a one-use keypair from platform-provided secret IKM.
    pub fn derive_from_ikm(ikm: [u8; 32]) -> RouterAbDerivationResult<Self> {
        let mut ikm = Zeroizing::new(ikm);
        if bool::from(ikm.as_ref().ct_eq(&[0_u8; 32])) {
            return Err(malformed(
                "tenant-root recovery reshare HPKE IKM must be non-zero",
            ));
        }
        let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(ikm.as_ref())
            .map_err(|_| malformed("tenant-root recovery reshare HPKE key derivation failed"))?;
        let private_key_bytes = Zeroizing::new(DhKemX25519HkdfSha256::sk_to_bytes(&private_key));
        let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
        let mut private_key32 = Zeroizing::new([0_u8; RECOVERY_RESHARE_HPKE_KEY_LEN]);
        private_key32.copy_from_slice(private_key_bytes.as_ref());
        let public_key32 = public_key_bytes.as_slice().try_into().map_err(|_| {
            malformed("tenant-root recovery reshare HPKE public key length is invalid")
        })?;
        ikm.zeroize();
        Ok(Self {
            private_key: private_key32,
            public_key: TenantRootRecoveryReshareHpkePublicKeyV1::from_bytes(public_key32)?,
        })
    }

    /// Returns the one-use public recipient key.
    pub const fn public_key(&self) -> TenantRootRecoveryReshareHpkePublicKeyV1 {
        self.public_key
    }
}

/// Source-signed and recipient-encrypted recovery reshare contribution.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootSignedRecoveryReshareContributionV1 {
    context_digest: TenantRootProtocolDigestV1,
    source: TwoPartyDeriverRole,
    recipient: TwoPartyDeriverRole,
    coefficient_commitment: RootShareRefreshCoefficientCommitment,
    recipient_key_id: String,
    recipient_public_key: TenantRootRecoveryReshareHpkePublicKeyV1,
    encapsulated_key: [u8; RECOVERY_RESHARE_HPKE_KEY_LEN],
    ciphertext: [u8; RECOVERY_RESHARE_CONTRIBUTION_CIPHERTEXT_LEN],
    authentication: TenantRootRecoveryReshareRoleAuthenticationV1,
}

impl fmt::Debug for TenantRootSignedRecoveryReshareContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootSignedRecoveryReshareContributionV1")
            .field("context_digest", &self.context_digest)
            .field("source", &self.source)
            .field("recipient", &self.recipient)
            .field("coefficient_commitment", &self.coefficient_commitment)
            .field("recipient_key_id", &self.recipient_key_id)
            .field("recipient_public_key", &self.recipient_public_key)
            .field("encapsulated_key", &hex::encode(self.encapsulated_key))
            .field("ciphertext", &"[redacted]")
            .field("authentication", &self.authentication)
            .finish()
    }
}

impl TenantRootSignedRecoveryReshareContributionV1 {
    /// Encrypts and signs one exact peer contribution after the commit stage.
    #[allow(clippy::too_many_arguments)]
    pub fn seal<R>(
        context: &TenantRootRecoveryReshareContextV1,
        coefficient: &RootShareRefreshCoefficient,
        verified_commitment: &VerifiedTenantRootRecoveryReshareCommitmentV1,
        recipient_key_id: impl Into<String>,
        recipient_public_key: TenantRootRecoveryReshareHpkePublicKeyV1,
        rng: &mut R,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self>
    where
        R: RngCore + CryptoRng,
    {
        require_verified_commitment(context, coefficient, verified_commitment)?;
        let source = verified_commitment.source();
        let recipient = source.peer();
        let recipient_key_id = recipient_key_id.into();
        require_key_id(
            "tenant-root recovery reshare HPKE recipient key id",
            &recipient_key_id,
        )?;
        let aad = contribution_aad(
            context,
            source,
            recipient,
            verified_commitment.commitment(),
            &recipient_key_id,
            recipient_public_key,
        )?;
        let plaintext = Zeroizing::new(coefficient.contribution_for(recipient).to_bytes());
        let hpke_public_key = DhKemX25519HkdfSha256::pk_from_bytes(recipient_public_key.as_bytes())
            .map_err(|_| malformed("tenant-root recovery reshare HPKE public key is invalid"))?;
        let (encapsulated_key, ciphertext) = TenantRootRecoveryReshareHpkeV1::seal_base(
            rng,
            &hpke_public_key,
            RECOVERY_RESHARE_HPKE_INFO_V1,
            &aad,
            plaintext.as_ref(),
        )
        .map_err(|_| {
            verification_failed("tenant-root recovery reshare contribution encryption failed")
        })?;
        let encapsulated_key = encapsulated_key.as_ref().try_into().map_err(|_| {
            malformed("tenant-root recovery reshare HPKE encapsulated key length is invalid")
        })?;
        if !is_canonical_nonzero_x25519_encoding(&encapsulated_key) {
            return Err(malformed(
                "tenant-root recovery reshare HPKE encapsulated key is not canonical",
            ));
        }
        let ciphertext = ciphertext.try_into().map_err(|_| {
            malformed("tenant-root recovery reshare HPKE ciphertext length is invalid")
        })?;
        let context_digest = context.digest()?;
        let payload = contribution_envelope(
            context_digest,
            source,
            recipient,
            verified_commitment.commitment(),
            &recipient_key_id,
            recipient_public_key,
            &encapsulated_key,
            &ciphertext,
        )?;
        let authentication = TenantRootRecoveryReshareRoleAuthenticationV1::sign(
            context,
            source,
            &payload,
            signing_key_bytes,
        )?;
        Ok(Self {
            context_digest,
            source,
            recipient,
            coefficient_commitment: verified_commitment.commitment(),
            recipient_key_id,
            recipient_public_key,
            encapsulated_key,
            ciphertext,
            authentication,
        })
    }

    /// Verifies, decrypts, and checks one peer contribution against its signed commitment.
    pub fn verify_and_open(
        &self,
        context: &TenantRootRecoveryReshareContextV1,
        verified_commitment: &VerifiedTenantRootRecoveryReshareCommitmentV1,
        recipient_key_id: &str,
        recipient: &TenantRootRecoveryReshareHpkeKeypairV1,
        source_verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootRecoveryReshareContributionV1> {
        if self.context_digest != context.digest()?
            || verified_commitment.context_digest != self.context_digest
            || self.source != verified_commitment.source()
            || self.recipient != self.source.peer()
            || self.coefficient_commitment != verified_commitment.commitment()
            || self.recipient_key_id != recipient_key_id
            || self.recipient_public_key != recipient.public_key()
        {
            return Err(malformed(
                "tenant-root recovery reshare contribution binding does not match",
            ));
        }
        let payload = contribution_envelope(
            self.context_digest,
            self.source,
            self.recipient,
            self.coefficient_commitment,
            &self.recipient_key_id,
            self.recipient_public_key,
            &self.encapsulated_key,
            &self.ciphertext,
        )?;
        self.authentication
            .verify(context, self.source, &payload, source_verifying_key_bytes)?;
        let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient.private_key.as_ref())
            .map_err(|_| malformed("tenant-root recovery reshare HPKE private key is invalid"))?;
        if !is_canonical_nonzero_x25519_encoding(&self.encapsulated_key) {
            return Err(malformed(
                "tenant-root recovery reshare HPKE encapsulated key is not canonical",
            ));
        }
        let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(&self.encapsulated_key)
            .map_err(|_| {
                malformed("tenant-root recovery reshare HPKE encapsulated key is invalid")
            })?;
        let aad = contribution_aad(
            context,
            self.source,
            self.recipient,
            self.coefficient_commitment,
            &self.recipient_key_id,
            self.recipient_public_key,
        )?;
        let plaintext = Zeroizing::new(
            TenantRootRecoveryReshareHpkeV1::open_base(
                &encapsulated_key,
                &private_key,
                RECOVERY_RESHARE_HPKE_INFO_V1,
                &aad,
                &self.ciphertext,
            )
            .map_err(|_| {
                verification_failed("tenant-root recovery reshare contribution decryption failed")
            })?,
        );
        let contribution =
            RootShareRefreshContributionWire::decode_slice(&plaintext).map_err(|_| {
                verification_failed(
                    "tenant-root recovery reshare contribution plaintext is invalid",
                )
            })?;
        let verified = self
            .coefficient_commitment
            .verify_contribution(contribution)
            .map_err(|_| {
                verification_failed("tenant-root recovery reshare contribution proof failed")
            })?;
        Ok(VerifiedTenantRootRecoveryReshareContributionV1 {
            context_digest: self.context_digest,
            inner: verified,
        })
    }

    /// Returns the fixed source role.
    pub const fn source(&self) -> TwoPartyDeriverRole {
        self.source
    }

    /// Returns the fixed peer recipient role.
    pub const fn recipient(&self) -> TwoPartyDeriverRole {
        self.recipient
    }
}

/// A signed and commitment-verified peer contribution bound to one recovery context.
pub struct VerifiedTenantRootRecoveryReshareContributionV1 {
    context_digest: TenantRootProtocolDigestV1,
    inner: VerifiedRootShareRefreshContribution,
}

impl fmt::Debug for VerifiedTenantRootRecoveryReshareContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRecoveryReshareContributionV1")
            .field("context_digest", &self.context_digest)
            .field("inner", &self.inner)
            .finish()
    }
}

/// One role's zeroizing recovery share before the public A/B evidence pair verifies.
pub struct PendingTenantRootRecoveryShareV1 {
    context_digest: TenantRootProtocolDigestV1,
    role: TwoPartyDeriverRole,
    share: SigningRootShare,
    commitment: SigningRootShareCommitment,
}

impl fmt::Debug for PendingTenantRootRecoveryShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTenantRootRecoveryShareV1")
            .field("context_digest", &self.context_digest)
            .field("role", &self.role)
            .field("share", &"[redacted]")
            .field("commitment", &self.commitment)
            .finish()
    }
}

impl PendingTenantRootRecoveryShareV1 {
    /// Applies both verified source contributions to exactly one role-local active share.
    pub fn derive(
        context: &TenantRootRecoveryReshareContextV1,
        active_share: &SigningRootShare,
        own_coefficient: &RootShareRefreshCoefficient,
        own_commitment: &VerifiedTenantRootRecoveryReshareCommitmentV1,
        peer_contribution: VerifiedTenantRootRecoveryReshareContributionV1,
    ) -> RouterAbDerivationResult<Self> {
        let role = TwoPartyDeriverRole::from_share_id(active_share.id())
            .map_err(|_| malformed("tenant-root recovery reshare active share role is invalid"))?;
        if !share_commitments_equal(
            SigningRootShareCommitment::from_share(active_share),
            context.active_share_commitment(role),
        ) {
            return Err(verification_failed(
                "tenant-root recovery reshare active share does not match active commitment",
            ));
        }
        require_verified_commitment(context, own_coefficient, own_commitment)?;
        if own_commitment.source() != role
            || peer_contribution.context_digest != context.digest()?
        {
            return Err(malformed(
                "tenant-root recovery reshare local and peer roles do not match",
            ));
        }
        let own_contribution = own_commitment
            .commitment()
            .verify_contribution(own_coefficient.contribution_for(role))
            .map_err(|_| {
                verification_failed("tenant-root recovery reshare local contribution proof failed")
            })?;
        let share = apply_two_party_root_share_refresh(
            active_share,
            own_contribution,
            peer_contribution.inner,
        )
        .map_err(|_| {
            verification_failed("tenant-root dedicated recovery share derivation failed")
        })?;
        let commitment = SigningRootShareCommitment::from_share(&share);
        if share_commitments_equal(commitment, context.active_share_commitment(role)) {
            return Err(verification_failed(
                "tenant-root dedicated recovery share must differ from the operational share",
            ));
        }
        Ok(Self {
            context_digest: context.digest()?,
            role,
            share,
            commitment,
        })
    }

    /// Proves knowledge of this role's dedicated share against both public commitments.
    pub fn prove<R>(
        &self,
        context: &TenantRootRecoveryReshareContextV1,
        peer_commitment: SigningRootShareCommitment,
        rng: &mut R,
    ) -> RouterAbDerivationResult<TenantRootRecoveryShareInstallationEvidenceV1>
    where
        R: RngCore06 + CryptoRng06,
    {
        let transcript =
            installation_transcript(context, self.role, self.commitment, peer_commitment)?;
        if self.context_digest != context.digest()? {
            return Err(malformed(
                "tenant-root recovery share does not match installation context",
            ));
        }
        let proof = prove_root_share_knowledge(&self.share, &transcript, rng).map_err(|_| {
            verification_failed("tenant-root recovery share knowledge proof failed")
        })?;
        Ok(TenantRootRecoveryShareInstallationEvidenceV1 {
            context_digest: self.context_digest,
            role: self.role,
            commitment: self.commitment,
            peer_commitment,
            proof,
        })
    }

    /// Converts the pending secret into a packageable capability after pair verification.
    pub fn finalize(
        self,
        verified_pair: &VerifiedTenantRootRecoveryResharePairV1,
    ) -> RouterAbDerivationResult<VerifiedTenantRootRecoveryShareV1> {
        if self.context_digest != verified_pair.context.digest()?
            || self.commitment != verified_pair.commitment(self.role)
        {
            return Err(malformed(
                "tenant-root pending recovery share does not match verified pair",
            ));
        }
        Ok(VerifiedTenantRootRecoveryShareV1 {
            role: self.role,
            share_wire: SigningRootShareWire::from_share(&self.share),
            identity_digest: verified_pair.context.identity_digest(),
            source_custody_lineage: verified_pair.context.source_custody_lineage(),
            recovery_set_id: verified_pair.context.recovery_set_id(),
            recipient_fingerprint: verified_pair
                .context
                .recovery_recipient_fingerprint(self.role),
            stable_root_commitment: verified_pair.context.stable_root_commitment(),
            recovery_share_commitment: self.commitment,
            deriver_signing_key_id: verified_pair.context.signing_key_id(self.role).to_owned(),
        })
    }

    /// Returns this pending share's public commitment.
    pub const fn commitment(&self) -> SigningRootShareCommitment {
        self.commitment
    }
}

/// Public knowledge proof for one role's dedicated recovery share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryShareInstallationEvidenceV1 {
    context_digest: TenantRootProtocolDigestV1,
    role: TwoPartyDeriverRole,
    commitment: SigningRootShareCommitment,
    peer_commitment: SigningRootShareCommitment,
    proof: RootShareKnowledgeProof,
}

impl TenantRootRecoveryShareInstallationEvidenceV1 {
    /// Returns this evidence's fixed role.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns this role's recovery-share commitment.
    pub const fn commitment(&self) -> SigningRootShareCommitment {
        self.commitment
    }

    /// Returns the peer recovery-share commitment.
    pub const fn peer_commitment(&self) -> SigningRootShareCommitment {
        self.peer_commitment
    }

    fn verify(&self, context: &TenantRootRecoveryReshareContextV1) -> RouterAbDerivationResult<()> {
        if self.context_digest != context.digest()?
            || self.commitment.id() != self.role.share_id()
            || self.peer_commitment.id() != self.role.peer().share_id()
        {
            return Err(malformed(
                "tenant-root recovery share evidence binding does not match",
            ));
        }
        verify_root_share_knowledge(
            &self.commitment,
            &installation_transcript(context, self.role, self.commitment, self.peer_commitment)?,
            &self.proof,
        )
        .map_err(|_| {
            verification_failed("tenant-root recovery share knowledge proof verification failed")
        })
    }

    fn canonical_bytes(
        &self,
        context: &TenantRootRecoveryReshareContextV1,
    ) -> RouterAbDerivationResult<Vec<u8>> {
        self.verify(context)?;
        let mut bytes = Vec::new();
        push_field(&mut bytes, RECOVERY_RESHARE_EVIDENCE_DOMAIN_V1)?;
        push_field(
            &mut bytes,
            &installation_transcript(context, self.role, self.commitment, self.peer_commitment)?,
        )?;
        push_field(&mut bytes, &self.proof.to_bytes())?;
        Ok(bytes)
    }
}

/// Role-signed knowledge proof for one dedicated recovery share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedRecoveryShareInstallationEvidenceV1 {
    evidence: TenantRootRecoveryShareInstallationEvidenceV1,
    authentication: TenantRootRecoveryReshareRoleAuthenticationV1,
}

impl TenantRootSignedRecoveryShareInstallationEvidenceV1 {
    /// Signs an already verified recovery-share knowledge proof.
    pub fn sign(
        context: &TenantRootRecoveryReshareContextV1,
        evidence: TenantRootRecoveryShareInstallationEvidenceV1,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let payload = evidence.canonical_bytes(context)?;
        let authentication = TenantRootRecoveryReshareRoleAuthenticationV1::sign(
            context,
            evidence.role,
            &payload,
            signing_key_bytes,
        )?;
        Ok(Self {
            evidence,
            authentication,
        })
    }

    fn verify(
        &self,
        context: &TenantRootRecoveryReshareContextV1,
        verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<()> {
        self.evidence.verify(context)?;
        self.authentication.verify(
            context,
            self.evidence.role,
            &self.evidence.canonical_bytes(context)?,
            verifying_key_bytes,
        )
    }

    /// Returns the public installation evidence.
    pub const fn evidence(&self) -> &TenantRootRecoveryShareInstallationEvidenceV1 {
        &self.evidence
    }
}

/// Public verified A/B recovery sharing and its authoritative recovery context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantRootRecoveryResharePairV1 {
    context: TenantRootRecoveryReshareContextV1,
    commitments: TwoPartyRootShareCommitments,
}

impl VerifiedTenantRootRecoveryResharePairV1 {
    /// Verifies both role signatures, knowledge proofs, freshness, and stable-root continuity.
    pub fn verify(
        context: &TenantRootRecoveryReshareContextV1,
        deriver_a: &TenantRootSignedRecoveryShareInstallationEvidenceV1,
        deriver_b: &TenantRootSignedRecoveryShareInstallationEvidenceV1,
        deriver_a_verifying_key_bytes: &[u8; 32],
        deriver_b_verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        deriver_a.verify(context, deriver_a_verifying_key_bytes)?;
        deriver_b.verify(context, deriver_b_verifying_key_bytes)?;
        let evidence_a = deriver_a.evidence();
        let evidence_b = deriver_b.evidence();
        if evidence_a.role != TwoPartyDeriverRole::DeriverA
            || evidence_b.role != TwoPartyDeriverRole::DeriverB
            || evidence_a.peer_commitment != evidence_b.commitment
            || evidence_b.peer_commitment != evidence_a.commitment
        {
            return Err(malformed(
                "tenant-root recovery reshare evidence pair is not exact A/B",
            ));
        }
        let commitments =
            TwoPartyRootShareCommitments::new(evidence_a.commitment, evidence_b.commitment)
                .map_err(|_| malformed("tenant-root recovery reshare commitments are invalid"))?;
        verify_two_party_root_share_refresh(&context.active_commitments, &commitments).map_err(
            |_| {
                verification_failed(
                    "tenant-root recovery reshare does not preserve the stable root",
                )
            },
        )?;
        Ok(Self {
            context: context.clone(),
            commitments,
        })
    }

    /// Returns the authoritative recovery context.
    pub const fn context(&self) -> &TenantRootRecoveryReshareContextV1 {
        &self.context
    }

    /// Returns one role's verified recovery-share commitment.
    pub fn commitment(&self, role: TwoPartyDeriverRole) -> SigningRootShareCommitment {
        match role {
            TwoPartyDeriverRole::DeriverA => self.commitments.deriver_a(),
            TwoPartyDeriverRole::DeriverB => self.commitments.deriver_b(),
        }
    }

    /// Returns the stable public root commitment.
    pub fn stable_root_commitment(&self) -> TwoPartyRootCommitment {
        self.commitments.root()
    }
}

/// One role-local dedicated recovery share proven against the verified A/B reshare.
pub struct VerifiedTenantRootRecoveryShareV1 {
    role: TwoPartyDeriverRole,
    share_wire: SigningRootShareWire,
    identity_digest: TenantRootIdentityDigestV1,
    source_custody_lineage: TenantRootCustodyLineageId,
    recovery_set_id: TenantRootRecoverySetId,
    recipient_fingerprint: TenantRootRecoveryRecipientFingerprintV1,
    stable_root_commitment: TwoPartyRootCommitment,
    recovery_share_commitment: SigningRootShareCommitment,
    deriver_signing_key_id: String,
}

impl fmt::Debug for VerifiedTenantRootRecoveryShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRecoveryShareV1")
            .field("role", &self.role)
            .field("share_wire", &"[redacted]")
            .field("identity_digest", &self.identity_digest)
            .field("source_custody_lineage", &self.source_custody_lineage)
            .field("recovery_set_id", &self.recovery_set_id)
            .field("recipient_fingerprint", &self.recipient_fingerprint)
            .field("stable_root_commitment", &self.stable_root_commitment)
            .field("recovery_share_commitment", &self.recovery_share_commitment)
            .field("deriver_signing_key_id", &self.deriver_signing_key_id)
            .finish()
    }
}

impl VerifiedTenantRootRecoveryShareV1 {
    /// Returns the exact role.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn tenant_root_identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the source custody lineage.
    pub const fn source_custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.source_custody_lineage
    }

    /// Returns the dedicated recovery-set identifier.
    pub const fn recovery_set_id(&self) -> TenantRootRecoverySetId {
        self.recovery_set_id
    }

    /// Returns the role-specific recovery recipient fingerprint.
    pub const fn recipient_fingerprint(&self) -> TenantRootRecoveryRecipientFingerprintV1 {
        self.recipient_fingerprint
    }

    /// Returns the stable public root commitment.
    pub const fn stable_root_commitment(&self) -> TwoPartyRootCommitment {
        self.stable_root_commitment
    }

    /// Returns this role's dedicated recovery-share commitment.
    pub const fn recovery_share_commitment(&self) -> SigningRootShareCommitment {
        self.recovery_share_commitment
    }

    /// Returns this role's signing-key identifier.
    pub fn deriver_signing_key_id(&self) -> &str {
        &self.deriver_signing_key_id
    }

    pub(super) const fn share_wire(&self) -> &SigningRootShareWire {
        &self.share_wire
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TenantRootRecoveryReshareRoleAuthenticationV1 {
    role: TwoPartyDeriverRole,
    signing_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootRecoveryReshareRoleAuthenticationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRecoveryReshareRoleAuthenticationV1")
            .field("role", &self.role)
            .field("signing_key_id", &self.signing_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl TenantRootRecoveryReshareRoleAuthenticationV1 {
    fn sign(
        context: &TenantRootRecoveryReshareContextV1,
        role: TwoPartyDeriverRole,
        payload: &[u8],
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let signing_key_id = context.signing_key_id(role).to_owned();
        let signature = SigningKey::from_bytes(signing_key_bytes)
            .sign(&role_authentication_input(role, &signing_key_id, payload)?)
            .to_bytes();
        Ok(Self {
            role,
            signing_key_id,
            signature,
        })
    }

    fn verify(
        &self,
        context: &TenantRootRecoveryReshareContextV1,
        role: TwoPartyDeriverRole,
        payload: &[u8],
        verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<()> {
        if self.role != role || self.signing_key_id != context.signing_key_id(role) {
            return Err(malformed(
                "tenant-root recovery reshare role authentication does not match context",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|_| malformed("tenant-root recovery reshare role verifying key is invalid"))?;
        verifying_key
            .verify_strict(
                &role_authentication_input(role, &self.signing_key_id, payload)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| verification_failed("tenant-root recovery reshare role signature failed"))
    }
}

fn require_verified_commitment(
    context: &TenantRootRecoveryReshareContextV1,
    coefficient: &RootShareRefreshCoefficient,
    verified: &VerifiedTenantRootRecoveryReshareCommitmentV1,
) -> RouterAbDerivationResult<()> {
    if verified.context_digest != context.digest()?
        || !refresh_commitments_equal(coefficient.commitment(), verified.commitment)
    {
        return Err(malformed(
            "tenant-root recovery reshare coefficient does not match verified commitment",
        ));
    }
    Ok(())
}

fn commitment_transcript(
    context: &TenantRootRecoveryReshareContextV1,
    commitment: RootShareRefreshCoefficientCommitment,
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_field(&mut bytes, RECOVERY_RESHARE_COMMITMENT_DOMAIN_V1)?;
    push_field(&mut bytes, &context.canonical_bytes()?)?;
    push_role(&mut bytes, commitment.source())?;
    push_field(&mut bytes, &commitment.to_bytes())?;
    Ok(bytes)
}

fn contribution_aad(
    context: &TenantRootRecoveryReshareContextV1,
    source: TwoPartyDeriverRole,
    recipient: TwoPartyDeriverRole,
    commitment: RootShareRefreshCoefficientCommitment,
    recipient_key_id: &str,
    recipient_public_key: TenantRootRecoveryReshareHpkePublicKeyV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    if recipient != source.peer() || commitment.source() != source {
        return Err(malformed(
            "tenant-root recovery reshare contribution roles are invalid",
        ));
    }
    require_key_id(
        "tenant-root recovery reshare HPKE recipient key id",
        recipient_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, RECOVERY_RESHARE_CONTRIBUTION_AAD_DOMAIN_V1)?;
    push_field(&mut bytes, &context.canonical_bytes()?)?;
    push_role(&mut bytes, source)?;
    push_role(&mut bytes, recipient)?;
    push_field(&mut bytes, &commitment.to_bytes())?;
    push_field(&mut bytes, recipient_key_id.as_bytes())?;
    push_field(&mut bytes, recipient_public_key.as_bytes())?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn contribution_envelope(
    context_digest: TenantRootProtocolDigestV1,
    source: TwoPartyDeriverRole,
    recipient: TwoPartyDeriverRole,
    commitment: RootShareRefreshCoefficientCommitment,
    recipient_key_id: &str,
    recipient_public_key: TenantRootRecoveryReshareHpkePublicKeyV1,
    encapsulated_key: &[u8; RECOVERY_RESHARE_HPKE_KEY_LEN],
    ciphertext: &[u8; RECOVERY_RESHARE_CONTRIBUTION_CIPHERTEXT_LEN],
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_field(&mut bytes, RECOVERY_RESHARE_CONTRIBUTION_ENVELOPE_DOMAIN_V1)?;
    push_field(&mut bytes, context_digest.as_bytes())?;
    push_role(&mut bytes, source)?;
    push_role(&mut bytes, recipient)?;
    push_field(&mut bytes, &commitment.to_bytes())?;
    push_field(&mut bytes, recipient_key_id.as_bytes())?;
    push_field(&mut bytes, recipient_public_key.as_bytes())?;
    push_field(&mut bytes, encapsulated_key)?;
    push_field(&mut bytes, ciphertext)?;
    Ok(bytes)
}

fn installation_transcript(
    context: &TenantRootRecoveryReshareContextV1,
    role: TwoPartyDeriverRole,
    commitment: SigningRootShareCommitment,
    peer_commitment: SigningRootShareCommitment,
) -> RouterAbDerivationResult<Vec<u8>> {
    if commitment.id() != role.share_id() || peer_commitment.id() != role.peer().share_id() {
        return Err(malformed(
            "tenant-root recovery reshare installation commitments do not match roles",
        ));
    }
    let mut bytes = Vec::new();
    push_field(&mut bytes, RECOVERY_RESHARE_INSTALLATION_DOMAIN_V1)?;
    push_field(&mut bytes, &context.canonical_bytes()?)?;
    push_role(&mut bytes, role)?;
    push_field(&mut bytes, &commitment.to_bytes())?;
    push_field(&mut bytes, &peer_commitment.to_bytes())?;
    Ok(bytes)
}

fn role_authentication_input(
    role: TwoPartyDeriverRole,
    signing_key_id: &str,
    payload: &[u8],
) -> RouterAbDerivationResult<Vec<u8>> {
    require_key_id(
        "tenant-root recovery reshare role signing key id",
        signing_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, RECOVERY_RESHARE_ROLE_AUTHENTICATION_DOMAIN_V1)?;
    push_role(&mut bytes, role)?;
    push_field(&mut bytes, signing_key_id.as_bytes())?;
    push_field(&mut bytes, payload)?;
    Ok(bytes)
}

fn require_key_id(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    u32::try_from(value.len()).map_err(|_| malformed("tenant-root recovery key id is too long"))?;
    Ok(())
}

fn push_role(bytes: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    push_field(bytes, role.as_str().as_bytes())?;
    push_field(bytes, &role.share_id().get().get().to_be_bytes())
}

fn share_commitments_equal(
    left: SigningRootShareCommitment,
    right: SigningRootShareCommitment,
) -> bool {
    bool::from(left.to_bytes().ct_eq(&right.to_bytes()))
}

fn refresh_commitments_equal(
    left: RootShareRefreshCoefficientCommitment,
    right: RootShareRefreshCoefficientCommitment,
) -> bool {
    bool::from(left.to_bytes().ct_eq(&right.to_bytes()))
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root recovery transcript field is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
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
