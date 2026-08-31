use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{
    RootShareRefreshCoefficientCommitment, RootShareRefreshContributionWire, TwoPartyDeriverRole,
};
use zeroize::{Zeroize, Zeroizing};

use super::x25519_canonical::is_canonical_nonzero_x25519_encoding;
use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootShareInstallationEvidenceV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
};

const REFRESH_COMMITMENT_DOMAIN_V1: &[u8] = b"tenant_root_refresh_commitment_v1";
const REFRESH_CONTRIBUTION_AAD_DOMAIN_V1: &[u8] = b"tenant_root_refresh_contribution_aad_v1";
const REFRESH_CONTRIBUTION_ENVELOPE_DOMAIN_V1: &[u8] =
    b"tenant_root_refresh_contribution_envelope_v1";
const SIGNED_REFRESH_CONTRIBUTION_DOMAIN_V1: &[u8] = b"tenant_root_signed_refresh_contribution_v1";
const SHARE_INSTALLATION_EVIDENCE_DOMAIN_V1: &[u8] = b"tenant_root_share_installation_evidence_v1";
const ROLE_AUTHENTICATION_DOMAIN_V1: &[u8] = b"tenant_root_role_authentication_v1";
const REFRESH_CONTRIBUTION_HPKE_INFO_V1: &[u8] =
    b"seams/tenant-root-refresh/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const HPKE_KEY_LEN: usize = 32;
const HPKE_TAG_LEN: usize = 16;
const REFRESH_CONTRIBUTION_CIPHERTEXT_LEN: usize =
    RootShareRefreshContributionWire::LEN + HPKE_TAG_LEN;
const MAX_REFRESH_CONTRIBUTION_WIRE_BYTES_V1: usize = 4 * 1024;
const MAX_ROLE_KEY_ID_BYTES_V1: usize = 1024;

type TenantRootRefreshHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

/// Signed public commitment sent before either role reveals a refresh contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRefreshCommitmentTranscriptV1 {
    context: TenantRootCeremonyContextV1,
    commitment: RootShareRefreshCoefficientCommitment,
}

impl TenantRootRefreshCommitmentTranscriptV1 {
    /// Creates one refresh-only, source-bound commitment transcript.
    pub fn new(
        context: TenantRootCeremonyContextV1,
        commitment: RootShareRefreshCoefficientCommitment,
    ) -> RouterAbDerivationResult<Self> {
        require_refresh_context(&context)?;
        Ok(Self {
            context,
            commitment,
        })
    }

    /// Returns the exact signed commitment bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        push_len32(&mut bytes, REFRESH_COMMITMENT_DOMAIN_V1)?;
        self.context.append_transcript_prefix(&mut bytes)?;
        push_role(&mut bytes, self.source())?;
        push_len32(&mut bytes, &self.commitment.to_bytes())?;
        self.context.append_transcript_suffix(&mut bytes)?;
        Ok(bytes)
    }

    /// Returns the shared ceremony context.
    pub const fn context(&self) -> &TenantRootCeremonyContextV1 {
        &self.context
    }

    /// Returns the role that sampled the committed refresh coefficient.
    pub fn source(&self) -> TwoPartyDeriverRole {
        self.commitment.source()
    }

    /// Returns the source-bound coefficient commitment.
    pub const fn commitment(&self) -> RootShareRefreshCoefficientCommitment {
        self.commitment
    }
}

/// A role-authenticated refresh coefficient commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedRefreshCommitmentV1 {
    transcript: TenantRootRefreshCommitmentTranscriptV1,
    authentication: TenantRootRoleAuthenticationV1,
}

impl TenantRootSignedRefreshCommitmentV1 {
    /// Signs the exact commitment transcript with the source role's Ed25519 key.
    pub fn sign(
        transcript: TenantRootRefreshCommitmentTranscriptV1,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let authentication = TenantRootRoleAuthenticationV1::sign(
            transcript.context(),
            transcript.source(),
            &transcript.canonical_bytes()?,
            signing_key_bytes,
        )?;
        Ok(Self {
            transcript,
            authentication,
        })
    }

    /// Verifies the source signature and returns a capability accepted by contribution sealing.
    pub fn verify(
        &self,
        verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootRefreshCommitmentV1> {
        self.authentication.verify(
            self.transcript.context(),
            self.transcript.source(),
            &self.transcript.canonical_bytes()?,
            verifying_key_bytes,
        )?;
        Ok(VerifiedTenantRootRefreshCommitmentV1 {
            transcript: self.transcript.clone(),
        })
    }

    /// Returns the exact public commitment transcript.
    pub const fn transcript(&self) -> &TenantRootRefreshCommitmentTranscriptV1 {
        &self.transcript
    }
}

/// Verified commit-stage capability required before a contribution can be encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantRootRefreshCommitmentV1 {
    transcript: TenantRootRefreshCommitmentTranscriptV1,
}

impl VerifiedTenantRootRefreshCommitmentV1 {
    /// Returns the verified commitment transcript.
    pub const fn transcript(&self) -> &TenantRootRefreshCommitmentTranscriptV1 {
        &self.transcript
    }
}

/// Both role-authenticated commitments required before either contribution is sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantRootRefreshCommitmentPairV1 {
    deriver_a: VerifiedTenantRootRefreshCommitmentV1,
    deriver_b: VerifiedTenantRootRefreshCommitmentV1,
}

impl VerifiedTenantRootRefreshCommitmentPairV1 {
    /// Creates the fixed A/B commit barrier for one exact refresh ceremony.
    pub fn new(
        deriver_a: VerifiedTenantRootRefreshCommitmentV1,
        deriver_b: VerifiedTenantRootRefreshCommitmentV1,
    ) -> RouterAbDerivationResult<Self> {
        if deriver_a.transcript().source() != TwoPartyDeriverRole::DeriverA
            || deriver_b.transcript().source() != TwoPartyDeriverRole::DeriverB
        {
            return Err(malformed(
                "tenant-root refresh commitment pair has invalid role ordering",
            ));
        }
        if deriver_a.transcript().context() != deriver_b.transcript().context() {
            return Err(malformed(
                "tenant-root refresh commitment pair has mismatched ceremony contexts",
            ));
        }
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    fn commitment_for(&self, source: TwoPartyDeriverRole) -> VerifiedTenantRootRefreshCommitmentV1 {
        match source {
            TwoPartyDeriverRole::DeriverA => self.deriver_a.clone(),
            TwoPartyDeriverRole::DeriverB => self.deriver_b.clone(),
        }
    }
}

/// Exact authenticated data for one recipient-specific encrypted refresh contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRefreshContributionAadV1 {
    verified_commitment: VerifiedTenantRootRefreshCommitmentV1,
    recipient_key_id: String,
    recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
}

impl TenantRootRefreshContributionAadV1 {
    /// Builds Deriver A's contribution to Deriver B after the two-role commit barrier.
    pub fn deriver_a_to_b(
        verified_commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
        recipient_key_id: impl Into<String>,
        recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
    ) -> RouterAbDerivationResult<Self> {
        Self::new(
            verified_commitments,
            TwoPartyDeriverRole::DeriverA,
            recipient_key_id,
            recipient_public_key,
        )
    }

    /// Builds Deriver B's contribution to Deriver A after the two-role commit barrier.
    pub fn deriver_b_to_a(
        verified_commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
        recipient_key_id: impl Into<String>,
        recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
    ) -> RouterAbDerivationResult<Self> {
        Self::new(
            verified_commitments,
            TwoPartyDeriverRole::DeriverB,
            recipient_key_id,
            recipient_public_key,
        )
    }

    fn new(
        verified_commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
        source: TwoPartyDeriverRole,
        recipient_key_id: impl Into<String>,
        recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
    ) -> RouterAbDerivationResult<Self> {
        let aad = Self {
            verified_commitment: verified_commitments.commitment_for(source),
            recipient_key_id: recipient_key_id.into(),
            recipient_public_key,
        };
        require_key_id(
            "tenant-root refresh HPKE recipient key id",
            &aad.recipient_key_id,
        )?;
        Ok(aad)
    }

    /// Returns the exact HPKE authenticated-data bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        push_len32(&mut bytes, REFRESH_CONTRIBUTION_AAD_DOMAIN_V1)?;
        self.context().append_transcript_prefix(&mut bytes)?;
        push_role(&mut bytes, self.source())?;
        push_role(&mut bytes, self.recipient())?;
        push_len32(
            &mut bytes,
            &self
                .verified_commitment
                .transcript()
                .commitment()
                .to_bytes(),
        )?;
        push_len32(&mut bytes, self.recipient_key_id.as_bytes())?;
        push_len32(&mut bytes, self.recipient_public_key.as_bytes())?;
        self.context().append_transcript_suffix(&mut bytes)?;
        Ok(bytes)
    }

    /// Returns a public digest of the exact authenticated data.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootRefreshContributionAadDigestV1> {
        Ok(TenantRootRefreshContributionAadDigestV1(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    /// Returns the role that sampled the contribution.
    pub fn source(&self) -> TwoPartyDeriverRole {
        self.verified_commitment.transcript().source()
    }

    /// Returns the fixed peer recipient role.
    pub fn recipient(&self) -> TwoPartyDeriverRole {
        self.source().peer()
    }

    /// Returns the shared ceremony context.
    pub const fn context(&self) -> &TenantRootCeremonyContextV1 {
        self.verified_commitment.transcript().context()
    }

    /// Returns the exact recipient HPKE key identifier.
    pub fn recipient_key_id(&self) -> &str {
        &self.recipient_key_id
    }

    /// Returns the exact recipient HPKE public key.
    pub const fn recipient_public_key(&self) -> TenantRootRefreshHpkePublicKeyV1 {
        self.recipient_public_key
    }

    /// Returns the verified source coefficient commitment.
    pub const fn coefficient_commitment(&self) -> RootShareRefreshCoefficientCommitment {
        self.verified_commitment.transcript().commitment()
    }
}

/// Public SHA-256 digest of exact refresh-contribution authenticated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRefreshContributionAadDigestV1([u8; 32]);

impl TenantRootRefreshContributionAadDigestV1 {
    /// Returns the digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Validated X25519 public key for one role's one-use refresh recipient.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRefreshHpkePublicKeyV1([u8; HPKE_KEY_LEN]);

impl fmt::Debug for TenantRootRefreshHpkePublicKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRefreshHpkePublicKeyV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl TenantRootRefreshHpkePublicKeyV1 {
    /// Parses one exact non-zero X25519 public key.
    pub fn from_bytes(bytes: [u8; HPKE_KEY_LEN]) -> RouterAbDerivationResult<Self> {
        if !is_canonical_nonzero_x25519_encoding(&bytes)
            || DhKemX25519HkdfSha256::pk_from_bytes(&bytes).is_err()
        {
            return Err(malformed("tenant-root refresh HPKE public key is invalid"));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact public key bytes.
    pub const fn as_bytes(&self) -> &[u8; HPKE_KEY_LEN] {
        &self.0
    }
}

/// One-use HPKE recipient keypair retained inside its target Deriver boundary.
pub struct TenantRootRefreshHpkeKeypairV1 {
    private_key: Zeroizing<[u8; HPKE_KEY_LEN]>,
    public_key: TenantRootRefreshHpkePublicKeyV1,
}

impl fmt::Debug for TenantRootRefreshHpkeKeypairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRefreshHpkeKeypairV1")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl TenantRootRefreshHpkeKeypairV1 {
    /// Deterministically derives a one-use keypair from platform-provided secret IKM.
    pub fn derive_from_ikm(ikm: [u8; 32]) -> RouterAbDerivationResult<Self> {
        let mut ikm = Zeroizing::new(ikm);
        if bool::from(ikm.as_ref().ct_eq(&[0_u8; 32])) {
            return Err(malformed("tenant-root refresh HPKE IKM must be non-zero"));
        }
        let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(ikm.as_ref())
            .map_err(|_| malformed("tenant-root refresh HPKE key derivation failed"))?;
        let private_key_bytes = Zeroizing::new(DhKemX25519HkdfSha256::sk_to_bytes(&private_key));
        let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
        let mut private_key32 = Zeroizing::new([0_u8; HPKE_KEY_LEN]);
        private_key32.copy_from_slice(private_key_bytes.as_ref());
        let public_key32: [u8; HPKE_KEY_LEN] = public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| malformed("tenant-root refresh HPKE public key length is invalid"))?;
        ikm.zeroize();
        Ok(Self {
            private_key: private_key32,
            public_key: TenantRootRefreshHpkePublicKeyV1::from_bytes(public_key32)?,
        })
    }

    /// Returns the one-use public recipient key.
    pub const fn public_key(&self) -> TenantRootRefreshHpkePublicKeyV1 {
        self.public_key
    }
}

/// Fixed-shape HPKE envelope for one source's secret refresh contribution.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootEncryptedRefreshContributionV1 {
    source: TwoPartyDeriverRole,
    recipient: TwoPartyDeriverRole,
    aad_digest: TenantRootRefreshContributionAadDigestV1,
    coefficient_commitment: RootShareRefreshCoefficientCommitment,
    recipient_key_id: String,
    recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
    encapsulated_key: [u8; HPKE_KEY_LEN],
    ciphertext: [u8; REFRESH_CONTRIBUTION_CIPHERTEXT_LEN],
}

impl fmt::Debug for TenantRootEncryptedRefreshContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootEncryptedRefreshContributionV1")
            .field("source", &self.source)
            .field("recipient", &self.recipient)
            .field("aad_digest", &hex::encode(self.aad_digest.0))
            .field("coefficient_commitment", &self.coefficient_commitment)
            .field("recipient_key_id", &self.recipient_key_id)
            .field("recipient_public_key", &self.recipient_public_key)
            .field("encapsulated_key", &hex::encode(self.encapsulated_key))
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

impl TenantRootEncryptedRefreshContributionV1 {
    /// Returns canonical bytes covered by the source role signature.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        push_len32(&mut bytes, REFRESH_CONTRIBUTION_ENVELOPE_DOMAIN_V1)?;
        push_role(&mut bytes, self.source)?;
        push_role(&mut bytes, self.recipient)?;
        push_len32(&mut bytes, self.aad_digest.as_bytes())?;
        push_len32(&mut bytes, &self.coefficient_commitment.to_bytes())?;
        push_len32(&mut bytes, self.recipient_key_id.as_bytes())?;
        push_len32(&mut bytes, self.recipient_public_key.as_bytes())?;
        push_len32(&mut bytes, &self.encapsulated_key)?;
        push_len32(&mut bytes, &self.ciphertext)?;
        Ok(bytes)
    }

    /// Parses the exact canonical encrypted contribution wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_REFRESH_CONTRIBUTION_WIRE_BYTES_V1 {
            return Err(malformed(
                "tenant-root encrypted refresh contribution wire length is invalid",
            ));
        }
        let mut decoder = RefreshWireDecoderV1::new(bytes);
        decoder.require_field(REFRESH_CONTRIBUTION_ENVELOPE_DOMAIN_V1)?;
        let source = decoder.role()?;
        let recipient = decoder.role()?;
        if source == recipient {
            return Err(malformed(
                "tenant-root encrypted refresh contribution roles must be distinct",
            ));
        }
        let aad_digest = TenantRootRefreshContributionAadDigestV1(
            decoder.fixed_field::<32>("tenant-root refresh AAD digest")?,
        );
        let coefficient_commitment =
            RootShareRefreshCoefficientCommitment::from_bytes(decoder.fixed_field::<{
                RootShareRefreshCoefficientCommitment::LEN
            }>(
                "tenant-root refresh coefficient commitment",
            )?)
            .map_err(|_| malformed("tenant-root refresh coefficient commitment is invalid"))?;
        if coefficient_commitment.source() != source {
            return Err(malformed(
                "tenant-root refresh coefficient commitment source is invalid",
            ));
        }
        let recipient_key_id = decoder.text_field(
            "tenant-root refresh recipient key id",
            MAX_ROLE_KEY_ID_BYTES_V1,
        )?;
        require_key_id("tenant-root refresh recipient key id", &recipient_key_id)?;
        let recipient_public_key = TenantRootRefreshHpkePublicKeyV1::from_bytes(
            decoder.fixed_field::<HPKE_KEY_LEN>("tenant-root refresh recipient public key")?,
        )?;
        let encapsulated_key =
            decoder.fixed_field::<HPKE_KEY_LEN>("tenant-root refresh encapsulated key")?;
        if !is_canonical_nonzero_x25519_encoding(&encapsulated_key)
            || DhKemX25519HkdfSha256::enc_from_bytes(&encapsulated_key).is_err()
        {
            return Err(malformed(
                "tenant-root refresh HPKE encapsulated key is invalid",
            ));
        }
        let ciphertext = decoder
            .fixed_field::<REFRESH_CONTRIBUTION_CIPHERTEXT_LEN>("tenant-root refresh ciphertext")?;
        decoder.finish()?;
        Ok(Self {
            source,
            recipient,
            aad_digest,
            coefficient_commitment,
            recipient_key_id,
            recipient_public_key,
            encapsulated_key,
            ciphertext,
        })
    }

    /// Returns the source role.
    pub const fn source(&self) -> TwoPartyDeriverRole {
        self.source
    }

    /// Returns the recipient role.
    pub const fn recipient(&self) -> TwoPartyDeriverRole {
        self.recipient
    }

    /// Returns the public AAD digest.
    pub const fn aad_digest(&self) -> TenantRootRefreshContributionAadDigestV1 {
        self.aad_digest
    }

    fn validate_against_aad(
        &self,
        aad: &TenantRootRefreshContributionAadV1,
    ) -> RouterAbDerivationResult<()> {
        if self.source != aad.source()
            || self.recipient != aad.recipient()
            || self.aad_digest != aad.digest()?
            || self.coefficient_commitment != aad.coefficient_commitment()
            || self.recipient_key_id != aad.recipient_key_id()
            || self.recipient_public_key != aad.recipient_public_key()
        {
            return Err(malformed(
                "tenant-root encrypted refresh contribution does not match its authenticated data",
            ));
        }
        Ok(())
    }
}

/// Encrypts one source-bound contribution to the exact peer recipient.
pub fn seal_tenant_root_refresh_contribution_v1<R>(
    aad: &TenantRootRefreshContributionAadV1,
    contribution: &RootShareRefreshContributionWire,
    rng: &mut R,
) -> RouterAbDerivationResult<TenantRootEncryptedRefreshContributionV1>
where
    R: RngCore + CryptoRng,
{
    if contribution.source() != aad.source() || contribution.recipient() != aad.recipient() {
        return Err(malformed(
            "tenant-root refresh contribution role binding does not match authenticated data",
        ));
    }
    let recipient_key = DhKemX25519HkdfSha256::pk_from_bytes(aad.recipient_public_key().as_bytes())
        .map_err(|_| malformed("tenant-root refresh HPKE public key is invalid"))?;
    let authenticated_data = aad.canonical_bytes()?;
    let plaintext = Zeroizing::new(contribution.to_bytes());
    let (encapsulated_key, ciphertext) = TenantRootRefreshHpkeV1::seal_base(
        rng,
        &recipient_key,
        REFRESH_CONTRIBUTION_HPKE_INFO_V1,
        &authenticated_data,
        plaintext.as_ref(),
    )
    .map_err(|_| verification_failed("tenant-root refresh contribution encryption failed"))?;
    let encapsulated_key: [u8; HPKE_KEY_LEN] = encapsulated_key
        .as_ref()
        .try_into()
        .map_err(|_| malformed("tenant-root refresh HPKE encapsulated key length is invalid"))?;
    if !is_canonical_nonzero_x25519_encoding(&encapsulated_key) {
        return Err(malformed(
            "tenant-root refresh HPKE encapsulated key is not canonical",
        ));
    }
    let ciphertext: [u8; REFRESH_CONTRIBUTION_CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| malformed("tenant-root refresh HPKE ciphertext length is invalid"))?;
    Ok(TenantRootEncryptedRefreshContributionV1 {
        source: aad.source(),
        recipient: aad.recipient(),
        aad_digest: aad.digest()?,
        coefficient_commitment: aad.coefficient_commitment(),
        recipient_key_id: aad.recipient_key_id().to_owned(),
        recipient_public_key: aad.recipient_public_key(),
        encapsulated_key,
        ciphertext,
    })
}

/// Opens and parses one exact recipient-bound refresh contribution.
pub fn open_tenant_root_refresh_contribution_v1(
    aad: &TenantRootRefreshContributionAadV1,
    envelope: &TenantRootEncryptedRefreshContributionV1,
    recipient: &TenantRootRefreshHpkeKeypairV1,
) -> RouterAbDerivationResult<RootShareRefreshContributionWire> {
    envelope.validate_against_aad(aad)?;
    if recipient.public_key() != aad.recipient_public_key() {
        return Err(malformed(
            "tenant-root refresh HPKE private recipient does not match authenticated data",
        ));
    }
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient.private_key.as_ref())
        .map_err(|_| malformed("tenant-root refresh HPKE private key is invalid"))?;
    if !is_canonical_nonzero_x25519_encoding(&envelope.encapsulated_key) {
        return Err(malformed(
            "tenant-root refresh HPKE encapsulated key is not canonical",
        ));
    }
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(&envelope.encapsulated_key)
        .map_err(|_| malformed("tenant-root refresh HPKE encapsulated key is invalid"))?;
    let plaintext = Zeroizing::new(
        TenantRootRefreshHpkeV1::open_base(
            &encapsulated_key,
            &private_key,
            REFRESH_CONTRIBUTION_HPKE_INFO_V1,
            &aad.canonical_bytes()?,
            &envelope.ciphertext,
        )
        .map_err(|_| verification_failed("tenant-root refresh contribution decryption failed"))?,
    );
    if plaintext.len() != RootShareRefreshContributionWire::LEN {
        return Err(malformed(
            "tenant-root refresh contribution plaintext length is invalid",
        ));
    }
    let mut contribution_bytes = Zeroizing::new([0_u8; RootShareRefreshContributionWire::LEN]);
    contribution_bytes.copy_from_slice(&plaintext);
    RootShareRefreshContributionWire::decode(*contribution_bytes)
        .map_err(|_| verification_failed("tenant-root refresh contribution plaintext is invalid"))
}

/// Source-signed encrypted contribution for peer delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedRefreshContributionV1 {
    envelope: TenantRootEncryptedRefreshContributionV1,
    authentication: TenantRootRoleAuthenticationV1,
}

impl TenantRootSignedRefreshContributionV1 {
    /// Signs an encrypted contribution after exact AAD validation.
    pub fn sign(
        aad: &TenantRootRefreshContributionAadV1,
        envelope: TenantRootEncryptedRefreshContributionV1,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        envelope.validate_against_aad(aad)?;
        let authentication = TenantRootRoleAuthenticationV1::sign(
            aad.context(),
            envelope.source(),
            &envelope.canonical_bytes()?,
            signing_key_bytes,
        )?;
        Ok(Self {
            envelope,
            authentication,
        })
    }

    /// Verifies the source signature, opens the envelope, and parses the contribution.
    pub fn verify_and_open(
        &self,
        aad: &TenantRootRefreshContributionAadV1,
        verifying_key_bytes: &[u8; 32],
        recipient: &TenantRootRefreshHpkeKeypairV1,
    ) -> RouterAbDerivationResult<RootShareRefreshContributionWire> {
        self.envelope.validate_against_aad(aad)?;
        self.authentication.verify(
            aad.context(),
            self.envelope.source(),
            &self.envelope.canonical_bytes()?,
            verifying_key_bytes,
        )?;
        open_tenant_root_refresh_contribution_v1(aad, &self.envelope, recipient)
    }

    /// Returns the exact signed encrypted-contribution wire bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        push_len32(&mut bytes, SIGNED_REFRESH_CONTRIBUTION_DOMAIN_V1)?;
        push_len32(&mut bytes, &self.envelope.canonical_bytes()?)?;
        push_role(&mut bytes, self.authentication.role)?;
        push_len32(&mut bytes, self.authentication.signing_key_id.as_bytes())?;
        push_len32(&mut bytes, &self.authentication.signature)?;
        if bytes.len() > MAX_REFRESH_CONTRIBUTION_WIRE_BYTES_V1 {
            return Err(malformed(
                "tenant-root signed refresh contribution wire is too long",
            ));
        }
        Ok(bytes)
    }

    /// Parses one exact signed encrypted contribution before verification.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_REFRESH_CONTRIBUTION_WIRE_BYTES_V1 {
            return Err(malformed(
                "tenant-root signed refresh contribution wire length is invalid",
            ));
        }
        let mut decoder = RefreshWireDecoderV1::new(bytes);
        decoder.require_field(SIGNED_REFRESH_CONTRIBUTION_DOMAIN_V1)?;
        let envelope = TenantRootEncryptedRefreshContributionV1::decode_canonical_bytes(
            decoder.field("tenant-root encrypted refresh contribution")?,
        )?;
        let role = decoder.role()?;
        if role != envelope.source() {
            return Err(malformed(
                "tenant-root signed refresh contribution authentication role is invalid",
            ));
        }
        let signing_key_id = decoder.text_field(
            "tenant-root refresh role signing key id",
            MAX_ROLE_KEY_ID_BYTES_V1,
        )?;
        require_key_id("tenant-root refresh role signing key id", &signing_key_id)?;
        let signature = decoder.fixed_field::<64>("tenant-root refresh role signature")?;
        decoder.finish()?;
        Ok(Self {
            envelope,
            authentication: TenantRootRoleAuthenticationV1 {
                role,
                signing_key_id,
                signature,
            },
        })
    }

    /// Returns the encrypted envelope.
    pub const fn envelope(&self) -> &TenantRootEncryptedRefreshContributionV1 {
        &self.envelope
    }
}

/// Source-signed share-installation proof for creation or refresh activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedShareInstallationEvidenceV1 {
    evidence: TenantRootShareInstallationEvidenceV1,
    authentication: TenantRootRoleAuthenticationV1,
}

impl TenantRootSignedShareInstallationEvidenceV1 {
    /// Signs an already verified installation proof with the installing role's key.
    pub fn sign(
        evidence: TenantRootShareInstallationEvidenceV1,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        evidence.verify()?;
        let authentication = TenantRootRoleAuthenticationV1::sign(
            evidence.transcript().context(),
            evidence.transcript().role(),
            &installation_evidence_canonical_bytes(&evidence)?,
            signing_key_bytes,
        )?;
        Ok(Self {
            evidence,
            authentication,
        })
    }

    /// Verifies the installation proof and its issuing role signature.
    pub fn verify(
        &self,
        verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootShareInstallationEvidenceV1> {
        self.evidence.verify()?;
        self.authentication.verify(
            self.evidence.transcript().context(),
            self.evidence.transcript().role(),
            &installation_evidence_canonical_bytes(&self.evidence)?,
            verifying_key_bytes,
        )?;
        Ok(
            VerifiedTenantRootShareInstallationEvidenceV1::from_authenticated(
                self.evidence.clone(),
            ),
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TenantRootRoleAuthenticationV1 {
    role: TwoPartyDeriverRole,
    signing_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootRoleAuthenticationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRoleAuthenticationV1")
            .field("role", &self.role)
            .field("signing_key_id", &self.signing_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl TenantRootRoleAuthenticationV1 {
    fn sign(
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        payload: &[u8],
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let signing_key_id = context.signing_key_id(role).to_owned();
        let input = role_authentication_input(&signing_key_id, role, payload)?;
        let signature = SigningKey::from_bytes(signing_key_bytes)
            .sign(&input)
            .to_bytes();
        Ok(Self {
            role,
            signing_key_id,
            signature,
        })
    }

    fn verify(
        &self,
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        payload: &[u8],
        verifying_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<()> {
        if self.role != role || self.signing_key_id != context.signing_key_id(role) {
            return Err(malformed(
                "tenant-root role authentication does not match the ceremony context",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|_| malformed("tenant-root role verifying key is invalid"))?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(
                &role_authentication_input(&self.signing_key_id, role, payload)?,
                &signature,
            )
            .map_err(|_| verification_failed("tenant-root role signature verification failed"))
    }
}

fn installation_evidence_canonical_bytes(
    evidence: &TenantRootShareInstallationEvidenceV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_len32(&mut bytes, SHARE_INSTALLATION_EVIDENCE_DOMAIN_V1)?;
    push_len32(&mut bytes, &evidence.transcript().canonical_bytes()?)?;
    push_len32(&mut bytes, &evidence.proof().to_bytes())?;
    Ok(bytes)
}

fn role_authentication_input(
    signing_key_id: &str,
    role: TwoPartyDeriverRole,
    payload: &[u8],
) -> RouterAbDerivationResult<Vec<u8>> {
    require_key_id("tenant-root role signing key id", signing_key_id)?;
    let mut bytes = Vec::new();
    push_len32(&mut bytes, ROLE_AUTHENTICATION_DOMAIN_V1)?;
    push_role(&mut bytes, role)?;
    push_len32(&mut bytes, signing_key_id.as_bytes())?;
    push_len32(&mut bytes, payload)?;
    Ok(bytes)
}

fn require_refresh_context(context: &TenantRootCeremonyContextV1) -> RouterAbDerivationResult<()> {
    context.validate()?;
    if !matches!(context.epochs(), TenantRootCeremonyEpochsV1::Refresh { .. }) {
        return Err(malformed(
            "tenant-root refresh transport requires the refresh epoch branch",
        ));
    }
    Ok(())
}

fn require_key_id(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    if value.len() > MAX_ROLE_KEY_ID_BYTES_V1 {
        return Err(malformed("tenant-root protocol key id is too long"));
    }
    Ok(())
}

struct RefreshWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RefreshWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root refresh wire offset overflow"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root refresh wire field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte refresh wire field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root refresh wire field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root refresh wire field is truncated"))?;
        self.offset = value_end;
        if value.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                format!("{name} is required"),
            ));
        }
        Ok(value)
    }

    fn require_field(&mut self, expected: &[u8]) -> RouterAbDerivationResult<()> {
        if self.field("tenant-root refresh wire domain")? != expected {
            return Err(malformed("tenant-root refresh wire domain is invalid"));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root refresh wire fixed field length is invalid"))
    }

    fn text_field(
        &mut self,
        name: &'static str,
        max_bytes: usize,
    ) -> RouterAbDerivationResult<String> {
        let bytes = self.field(name)?;
        if bytes.len() > max_bytes {
            return Err(malformed("tenant-root refresh wire text field is too long"));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root refresh wire text field is invalid UTF-8"))
    }

    fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root refresh role")?;
        let share_id = self.fixed_field::<2>("tenant-root refresh role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed("tenant-root refresh role encoding is invalid")),
        }
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed("tenant-root refresh wire has trailing bytes"));
        }
        Ok(())
    }
}

fn push_role(out: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    push_len32(out, role.as_str().as_bytes())?;
    push_len32(out, &role.share_id().get().get().to_be_bytes())
}

fn push_len32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root protocol field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
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
