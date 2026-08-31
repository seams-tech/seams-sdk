use core::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{CryptoRng, RngCore};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{
    SigningRootShareCommitment, SigningRootShareWire, ThresholdShareId, TwoPartyDeriverRole,
    TwoPartyRootCommitment, TwoPartyRootShareCommitments,
};
use zeroize::{Zeroize, Zeroizing};

use super::x25519_canonical::is_canonical_nonzero_x25519_encoding;
use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootIdentityV1,
    VerifiedTenantRootRecoveryResharePairV1, VerifiedTenantRootRecoveryShareV1,
};

const TENANT_ROOT_RECOVERY_SET_ID_BYTES: usize = 16;
const TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES: usize = 32;
const TENANT_ROOT_RECOVERY_RECIPIENT_FINGERPRINT_BYTES: usize = 32;
const TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES: usize = 64;
const TENANT_ROOT_RECOVERY_PACKAGE_MAGIC: &[u8; 8] = b"SEAMSRB1";
const TENANT_ROOT_RECOVERY_PACKAGE_DOMAIN_V1: &[u8] = b"seams/tenant-root-recovery-package/v1";
const TENANT_ROOT_RECOVERY_PACKAGE_HPKE_INFO_V1: &[u8] =
    b"seams/tenant-root-recovery-package/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const TENANT_ROOT_RECOVERY_MANIFEST_DOMAIN_V1: &[u8] = b"seams/tenant-root-recovery-manifest/v1";
const TENANT_ROOT_RECOVERY_DESCRIPTOR_FORMAT_V1: &str = "tenant_root_recovery_descriptor_v1";
const TENANT_ROOT_RECOVERY_PACKAGE_FORMAT_V1: &str = "tenant_root_recovery_package_v1";
const TENANT_ROOT_RECOVERY_MANIFEST_FORMAT_V1: &str = "tenant_root_recovery_manifest_v1";
const TENANT_ROOT_RECOVERY_HPKE_SUITE_V1: &str = "hpke_x25519_hkdf_sha256_aes256gcm_v1";
const TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1: usize = 16 * 1024;
const TENANT_ROOT_RECOVERY_MANIFEST_MAX_BYTES_V1: usize = 128 * 1024;
const TENANT_ROOT_RECOVERY_SHARE_WIRE_BYTES: usize = SigningRootShareWire::LEN;
const TENANT_ROOT_RECOVERY_HPKE_TAG_BYTES: usize = 16;
const TENANT_ROOT_RECOVERY_PACKAGE_CIPHERTEXT_BYTES: usize =
    TENANT_ROOT_RECOVERY_SHARE_WIRE_BYTES + TENANT_ROOT_RECOVERY_HPKE_TAG_BYTES;

type TenantRootRecoveryHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

/// Maximum encoded size of one tenant-root recovery package.
pub const TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES: usize = TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1;

/// Maximum encoded size of one tenant-root recovery manifest.
pub const TENANT_ROOT_RECOVERY_MANIFEST_MAX_BYTES: usize =
    TENANT_ROOT_RECOVERY_MANIFEST_MAX_BYTES_V1;

/// MIME type of a tenant-root recovery package.
pub const TENANT_ROOT_RECOVERY_PACKAGE_MIME_TYPE: &str =
    "application/vnd.seams.tenant-root-recovery-package.v1";

/// MIME type of a tenant-root recovery manifest.
pub const TENANT_ROOT_RECOVERY_MANIFEST_MIME_TYPE: &str =
    "application/vnd.seams.tenant-root-recovery-manifest.v1+json";

/// Random identifier for one tenant-controlled recovery sharing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoverySetId([u8; TENANT_ROOT_RECOVERY_SET_ID_BYTES]);

impl fmt::Debug for TenantRootRecoverySetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRecoverySetId")
            .field(&self.to_base64url())
            .finish()
    }
}

impl TenantRootRecoverySetId {
    /// Parses one exact non-zero 128-bit recovery-set identifier.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_RECOVERY_SET_ID_BYTES],
    ) -> RouterAbDerivationResult<Self> {
        require_nonzero_bytes(&bytes, "tenant root recovery set id must be non-zero")?;
        Ok(Self(bytes))
    }

    /// Samples one fresh non-zero recovery-set identifier.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_RECOVERY_SET_ID_BYTES];
            rng.fill_bytes(&mut bytes);
            if let Ok(value) = Self::from_bytes(bytes) {
                return value;
            }
        }
    }

    /// Parses the exact unpadded base64url boundary encoding.
    pub fn from_base64url(value: &str) -> RouterAbDerivationResult<Self> {
        let mut bytes = [0_u8; TENANT_ROOT_RECOVERY_SET_ID_BYTES];
        let decoded = Base64UrlUnpadded::decode(value, &mut bytes)
            .map_err(|_| malformed("tenant root recovery set id is invalid base64url"))?;
        if decoded.len() != TENANT_ROOT_RECOVERY_SET_ID_BYTES
            || Base64UrlUnpadded::encode_string(decoded) != value
        {
            return Err(malformed(
                "tenant root recovery set id is not canonical base64url",
            ));
        }
        Self::from_bytes(bytes)
    }

    /// Returns the exact unpadded base64url boundary encoding.
    pub fn to_base64url(self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }

    /// Returns the exact identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_RECOVERY_SET_ID_BYTES] {
        &self.0
    }

    /// Returns a copy of the exact identifier bytes.
    pub const fn into_bytes(self) -> [u8; TENANT_ROOT_RECOVERY_SET_ID_BYTES] {
        self.0
    }
}

impl Serialize for TenantRootRecoverySetId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for TenantRootRecoverySetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_base64url(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Validated X25519 public key for one role's tenant recovery recipient.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryRecipientPublicKeyV1([u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES]);

impl fmt::Debug for TenantRootRecoveryRecipientPublicKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRecoveryRecipientPublicKeyV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl TenantRootRecoveryRecipientPublicKeyV1 {
    /// Parses one exact non-zero X25519 public key.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES],
    ) -> RouterAbDerivationResult<Self> {
        if !is_canonical_nonzero_x25519_encoding(&bytes)
            || DhKemX25519HkdfSha256::pk_from_bytes(&bytes).is_err()
        {
            return Err(malformed(
                "tenant root recovery recipient public key is invalid",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact X25519 public key bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES] {
        &self.0
    }

    /// Returns the SHA-256 fingerprint of the exact public key bytes.
    pub fn fingerprint(&self) -> TenantRootRecoveryRecipientFingerprintV1 {
        TenantRootRecoveryRecipientFingerprintV1(Sha256::digest(self.0).into())
    }
}

impl Serialize for TenantRootRecoveryRecipientPublicKeyV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_base64url(&self.0))
    }
}

impl<'de> Deserialize<'de> for TenantRootRecoveryRecipientPublicKeyV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = decode_base64url_fixed(&value, "recipient public key")
            .map_err(serde::de::Error::custom)?;
        Self::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

/// SHA-256 fingerprint of one tenant recovery recipient public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryRecipientFingerprintV1(
    [u8; TENANT_ROOT_RECOVERY_RECIPIENT_FINGERPRINT_BYTES],
);

impl fmt::Debug for TenantRootRecoveryRecipientFingerprintV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRecoveryRecipientFingerprintV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl TenantRootRecoveryRecipientFingerprintV1 {
    /// Parses one exact 32-byte recipient fingerprint.
    pub fn from_bytes(bytes: [u8; TENANT_ROOT_RECOVERY_RECIPIENT_FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact fingerprint bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_RECOVERY_RECIPIENT_FINGERPRINT_BYTES] {
        &self.0
    }

    /// Returns a copy of the exact fingerprint bytes.
    pub const fn into_bytes(self) -> [u8; TENANT_ROOT_RECOVERY_RECIPIENT_FINGERPRINT_BYTES] {
        self.0
    }
}

impl Serialize for TenantRootRecoveryRecipientFingerprintV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_base64url(&self.0))
    }
}

impl<'de> Deserialize<'de> for TenantRootRecoveryRecipientFingerprintV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = decode_base64url_fixed(&value, "recipient fingerprint")
            .map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// X25519 recipient keypair retained only in a role-local boundary.
pub struct TenantRootRecoveryRecipientKeypairV1 {
    private_key: Zeroizing<[u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES]>,
    public_key: TenantRootRecoveryRecipientPublicKeyV1,
}

impl fmt::Debug for TenantRootRecoveryRecipientKeypairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRecoveryRecipientKeypairV1")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl TenantRootRecoveryRecipientKeypairV1 {
    /// Deterministically derives one recipient keypair from platform-provided secret IKM.
    pub fn derive_from_ikm(
        ikm: [u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES],
    ) -> RouterAbDerivationResult<Self> {
        let mut ikm = Zeroizing::new(ikm);
        if bool::from(
            ikm.as_ref()
                .ct_eq(&[0_u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES]),
        ) {
            return Err(malformed(
                "tenant root recovery recipient IKM must be non-zero",
            ));
        }
        let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(ikm.as_ref())
            .map_err(|_| malformed("tenant root recovery recipient key derivation failed"))?;
        let private_key_bytes = Zeroizing::new(DhKemX25519HkdfSha256::sk_to_bytes(&private_key));
        let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
        let mut private_key32 = Zeroizing::new([0_u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES]);
        private_key32.copy_from_slice(private_key_bytes.as_ref());
        let public_key: [u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES] =
            public_key_bytes.as_slice().try_into().map_err(|_| {
                malformed("tenant root recovery recipient public key length is invalid")
            })?;
        ikm.zeroize();
        Ok(Self {
            private_key: private_key32,
            public_key: TenantRootRecoveryRecipientPublicKeyV1::from_bytes(public_key)?,
        })
    }

    /// Returns the public key corresponding to the private recipient key.
    pub const fn public_key(&self) -> TenantRootRecoveryRecipientPublicKeyV1 {
        self.public_key
    }

    /// Returns the public-key fingerprint corresponding to the private recipient key.
    pub fn fingerprint(&self) -> TenantRootRecoveryRecipientFingerprintV1 {
        self.public_key.fingerprint()
    }

    pub(super) fn private_key_bytes(&self) -> &[u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES] {
        &self.private_key
    }
}

/// Public SHA-256 digest of one canonical recovery descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryDescriptorDigestV1([u8; 32]);

impl TenantRootRecoveryDescriptorDigestV1 {
    /// Parses one exact descriptor digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a copy of the exact digest bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Public SHA-256 digest of one complete recovery package file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryPackageDigestV1([u8; 32]);

impl TenantRootRecoveryPackageDigestV1 {
    /// Parses one exact package digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a copy of the exact digest bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One role's public recipient and recovery-share metadata in a descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryRoleDescriptorV1 {
    role: TwoPartyDeriverRole,
    share_id: ThresholdShareId,
    recipient_public_key: TenantRootRecoveryRecipientPublicKeyV1,
    recipient_fingerprint: TenantRootRecoveryRecipientFingerprintV1,
    recovery_share_commitment: SigningRootShareCommitment,
    deriver_signing_key_id: String,
}

impl TenantRootRecoveryRoleDescriptorV1 {
    /// Returns the fixed role.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the fixed role share identifier.
    pub const fn share_id(&self) -> ThresholdShareId {
        self.share_id
    }

    /// Returns the recipient public key.
    pub const fn recipient_public_key(&self) -> TenantRootRecoveryRecipientPublicKeyV1 {
        self.recipient_public_key
    }

    /// Returns the recipient public-key fingerprint.
    pub const fn recipient_fingerprint(&self) -> TenantRootRecoveryRecipientFingerprintV1 {
        self.recipient_fingerprint
    }

    /// Returns the role's recovery-share commitment.
    pub const fn recovery_share_commitment(&self) -> SigningRootShareCommitment {
        self.recovery_share_commitment
    }

    /// Returns the Deriver signing-key identifier.
    pub fn deriver_signing_key_id(&self) -> &str {
        &self.deriver_signing_key_id
    }
}

/// Public descriptor binding one tenant recovery set and both role recipients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryDescriptorV1 {
    identity: TenantRootIdentityV1,
    identity_digest: TenantRootIdentityDigestV1,
    source_custody_lineage: TenantRootCustodyLineageId,
    recovery_set_id: TenantRootRecoverySetId,
    creation_time: String,
    stable_root_commitment: TwoPartyRootCommitment,
    deriver_a: TenantRootRecoveryRoleDescriptorV1,
    deriver_b: TenantRootRecoveryRoleDescriptorV1,
}

impl TenantRootRecoveryDescriptorV1 {
    /// Builds a descriptor only from a verified dedicated recovery resharing.
    pub fn from_verified_reshare(
        verified: &VerifiedTenantRootRecoveryResharePairV1,
        creation_time: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let context = verified.context();
        Self::new(
            context.identity().clone(),
            context.source_custody_lineage(),
            context.recovery_set_id(),
            creation_time,
            verified.stable_root_commitment(),
            context.recovery_recipient_public_key(TwoPartyDeriverRole::DeriverA),
            context.recovery_recipient_public_key(TwoPartyDeriverRole::DeriverB),
            verified.commitment(TwoPartyDeriverRole::DeriverA),
            verified.commitment(TwoPartyDeriverRole::DeriverB),
            context.signing_key_id(TwoPartyDeriverRole::DeriverA),
            context.signing_key_id(TwoPartyDeriverRole::DeriverB),
        )
    }

    /// Creates one exact descriptor and checks stable-root commitment continuity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: TenantRootIdentityV1,
        source_custody_lineage: TenantRootCustodyLineageId,
        recovery_set_id: TenantRootRecoverySetId,
        creation_time: impl Into<String>,
        stable_root_commitment: TwoPartyRootCommitment,
        recipient_a: TenantRootRecoveryRecipientPublicKeyV1,
        recipient_b: TenantRootRecoveryRecipientPublicKeyV1,
        recovery_share_commitment_a: SigningRootShareCommitment,
        recovery_share_commitment_b: SigningRootShareCommitment,
        deriver_a_signing_key_id: impl Into<String>,
        deriver_b_signing_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let identity_digest = identity.digest()?;
        let deriver_a = role_descriptor(
            TwoPartyDeriverRole::DeriverA,
            recipient_a,
            recovery_share_commitment_a,
            deriver_a_signing_key_id.into(),
        )?;
        let deriver_b = role_descriptor(
            TwoPartyDeriverRole::DeriverB,
            recipient_b,
            recovery_share_commitment_b,
            deriver_b_signing_key_id.into(),
        )?;
        let descriptor = Self {
            identity,
            identity_digest,
            source_custody_lineage,
            recovery_set_id,
            creation_time: creation_time.into(),
            stable_root_commitment,
            deriver_a,
            deriver_b,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Returns the exact tenant-root identity.
    pub const fn tenant_root_identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the exact identity digest bound into this descriptor.
    pub const fn tenant_root_identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the source custody-lineage identifier.
    pub const fn source_custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.source_custody_lineage
    }

    /// Returns the tenant recovery-set identifier.
    pub const fn recovery_set_id(&self) -> TenantRootRecoverySetId {
        self.recovery_set_id
    }

    /// Returns the exact RFC 3339 millisecond creation time.
    pub fn creation_time(&self) -> &str {
        &self.creation_time
    }

    /// Returns the stable public root commitment.
    pub const fn stable_root_commitment(&self) -> TwoPartyRootCommitment {
        self.stable_root_commitment
    }

    /// Returns the fixed HPKE suite identifier.
    pub const fn hpke_suite() -> &'static str {
        TENANT_ROOT_RECOVERY_HPKE_SUITE_V1
    }

    /// Returns the role-specific descriptor without allowing role substitution.
    pub const fn role(&self, role: TwoPartyDeriverRole) -> &TenantRootRecoveryRoleDescriptorV1 {
        match role {
            TwoPartyDeriverRole::DeriverA => &self.deriver_a,
            TwoPartyDeriverRole::DeriverB => &self.deriver_b,
        }
    }

    /// Returns Deriver A's descriptor entry.
    pub const fn deriver_a(&self) -> &TenantRootRecoveryRoleDescriptorV1 {
        &self.deriver_a
    }

    /// Returns Deriver B's descriptor entry.
    pub const fn deriver_b(&self) -> &TenantRootRecoveryRoleDescriptorV1 {
        &self.deriver_b
    }

    /// Returns the exact canonical RFC 8785 JSON bytes.
    pub fn canonical_json(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        canonical_json_bytes(&descriptor_value(self))
    }

    /// Returns the exact canonical descriptor bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.canonical_json()
    }

    /// Returns the SHA-256 digest of canonical descriptor JSON.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootRecoveryDescriptorDigestV1> {
        Ok(TenantRootRecoveryDescriptorDigestV1(
            Sha256::digest(self.canonical_json()?).into(),
        ))
    }

    /// Parses one exact canonical descriptor, rejecting unknown, duplicate, and trailing data.
    pub fn from_canonical_json(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        let value = strict_json_value(bytes)?;
        let descriptor = descriptor_from_value(value)?;
        let canonical = descriptor.canonical_json()?;
        if canonical != bytes {
            return Err(malformed(
                "tenant root recovery descriptor is not canonical JSON",
            ));
        }
        Ok(descriptor)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if !bool::from(
            self.identity
                .digest()?
                .as_bytes()
                .ct_eq(self.identity_digest.as_bytes()),
        ) {
            return Err(malformed(
                "tenant root recovery descriptor identity digest does not match identity",
            ));
        }
        validate_rfc3339_millis(&self.creation_time, "recovery descriptor creation time")?;
        let commitments = TwoPartyRootShareCommitments::new(
            self.deriver_a.recovery_share_commitment,
            self.deriver_b.recovery_share_commitment,
        )
        .map_err(|_| verification_failed("tenant root recovery share commitments are invalid"))?;
        if !bool::from(
            commitments
                .root()
                .to_bytes()
                .ct_eq(&self.stable_root_commitment.to_bytes()),
        ) {
            return Err(verification_failed(
                "tenant root recovery commitments do not reconstruct stable root commitment",
            ));
        }
        if self.deriver_a.recipient_fingerprint == self.deriver_b.recipient_fingerprint {
            return Err(malformed(
                "tenant root recovery recipient fingerprints must differ",
            ));
        }
        if self.deriver_a.deriver_signing_key_id == self.deriver_b.deriver_signing_key_id {
            return Err(malformed(
                "tenant root recovery Deriver signing key ids must differ",
            ));
        }
        if self.deriver_a.recipient_fingerprint != self.deriver_a.recipient_public_key.fingerprint()
            || self.deriver_b.recipient_fingerprint
                != self.deriver_b.recipient_public_key.fingerprint()
        {
            return Err(malformed(
                "tenant root recovery recipient fingerprint does not match public key",
            ));
        }
        Ok(())
    }
}

impl Serialize for TenantRootRecoveryDescriptorV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        descriptor_value(self).serialize(serializer)
    }
}

/// Public package header carried inside one binary role package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryPackageHeaderV1 {
    format_version: String,
    descriptor_digest: TenantRootRecoveryDescriptorDigestV1,
    identity_digest: TenantRootIdentityDigestV1,
    source_custody_lineage: TenantRootCustodyLineageId,
    recovery_set_id: TenantRootRecoverySetId,
    role: TwoPartyDeriverRole,
    share_id: ThresholdShareId,
    recipient_fingerprint: TenantRootRecoveryRecipientFingerprintV1,
    recovery_share_commitment: SigningRootShareCommitment,
    stable_root_commitment: TwoPartyRootCommitment,
    creation_time: String,
    hpke_suite: String,
    deriver_signing_key_id: String,
}

impl TenantRootRecoveryPackageHeaderV1 {
    /// Returns the fixed package format version.
    pub fn format_version(&self) -> &str {
        &self.format_version
    }

    /// Returns the bound descriptor digest.
    pub const fn descriptor_digest(&self) -> TenantRootRecoveryDescriptorDigestV1 {
        self.descriptor_digest
    }

    /// Returns the bound tenant identity digest.
    pub const fn tenant_root_identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the bound source lineage.
    pub const fn source_custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.source_custody_lineage
    }

    /// Returns the bound recovery-set identifier.
    pub const fn recovery_set_id(&self) -> TenantRootRecoverySetId {
        self.recovery_set_id
    }

    /// Returns the fixed package role.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the fixed package share id.
    pub const fn share_id(&self) -> ThresholdShareId {
        self.share_id
    }

    /// Returns the bound recipient fingerprint.
    pub const fn recipient_fingerprint(&self) -> TenantRootRecoveryRecipientFingerprintV1 {
        self.recipient_fingerprint
    }

    /// Returns the bound recovery-share commitment.
    pub const fn recovery_share_commitment(&self) -> SigningRootShareCommitment {
        self.recovery_share_commitment
    }

    /// Returns the bound stable root commitment.
    pub const fn stable_root_commitment(&self) -> TwoPartyRootCommitment {
        self.stable_root_commitment
    }

    /// Returns the exact creation time.
    pub fn creation_time(&self) -> &str {
        &self.creation_time
    }

    /// Returns the fixed package HPKE suite identifier.
    pub fn hpke_suite(&self) -> &str {
        &self.hpke_suite
    }

    /// Returns the Deriver signing-key identifier.
    pub fn deriver_signing_key_id(&self) -> &str {
        &self.deriver_signing_key_id
    }

    /// Returns the exact canonical RFC 8785 header bytes.
    pub fn canonical_json(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        canonical_json_bytes(&package_header_value(self))
    }

    /// Returns the exact canonical package-header bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.canonical_json()
    }

    fn from_descriptor(
        descriptor: &TenantRootRecoveryDescriptorV1,
        role: TwoPartyDeriverRole,
    ) -> RouterAbDerivationResult<Self> {
        let role_descriptor = descriptor.role(role);
        Ok(Self {
            format_version: TENANT_ROOT_RECOVERY_PACKAGE_FORMAT_V1.to_owned(),
            descriptor_digest: descriptor.digest()?,
            identity_digest: descriptor.identity_digest,
            source_custody_lineage: descriptor.source_custody_lineage,
            recovery_set_id: descriptor.recovery_set_id,
            role,
            share_id: role_descriptor.share_id,
            recipient_fingerprint: role_descriptor.recipient_fingerprint,
            recovery_share_commitment: role_descriptor.recovery_share_commitment,
            stable_root_commitment: descriptor.stable_root_commitment,
            creation_time: descriptor.creation_time.clone(),
            hpke_suite: TENANT_ROOT_RECOVERY_HPKE_SUITE_V1.to_owned(),
            deriver_signing_key_id: role_descriptor.deriver_signing_key_id.clone(),
        })
    }

    fn validate_against_descriptor(
        &self,
        descriptor: &TenantRootRecoveryDescriptorV1,
        role: TwoPartyDeriverRole,
    ) -> RouterAbDerivationResult<()> {
        self.validate()?;
        let expected = Self::from_descriptor(descriptor, role)?;
        if self != &expected {
            return Err(malformed(
                "tenant root recovery package header does not match descriptor and role",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.format_version != TENANT_ROOT_RECOVERY_PACKAGE_FORMAT_V1
            || self.hpke_suite != TENANT_ROOT_RECOVERY_HPKE_SUITE_V1
        {
            return Err(malformed(
                "tenant root recovery package header version or suite is invalid",
            ));
        }
        if self.share_id != self.role.share_id()
            || self.recovery_share_commitment.id() != self.share_id
        {
            return Err(malformed(
                "tenant root recovery package role and share id do not match",
            ));
        }
        validate_rfc3339_millis(&self.creation_time, "recovery package creation time")?;
        require_key_id(
            "recovery package Deriver signing key id",
            &self.deriver_signing_key_id,
        )
    }
}

impl Serialize for TenantRootRecoveryPackageHeaderV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        package_header_value(self).serialize(serializer)
    }
}

/// One role's recipient-encrypted tenant recovery share package.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryPackageV1 {
    header: TenantRootRecoveryPackageHeaderV1,
    encapsulated_key: [u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES],
    ciphertext: Vec<u8>,
    signature: [u8; TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES],
}

impl fmt::Debug for TenantRootRecoveryPackageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRecoveryPackageV1")
            .field("header", &self.header)
            .field("encapsulated_key", &hex::encode(self.encapsulated_key))
            .field("ciphertext", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl TenantRootRecoveryPackageV1 {
    /// Seals one role-local share proven to come from a dedicated recovery resharing.
    pub fn seal<R>(
        descriptor: &TenantRootRecoveryDescriptorV1,
        verified_share: &VerifiedTenantRootRecoveryShareV1,
        rng: &mut R,
        deriver_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self>
    where
        R: RngCore + CryptoRng,
    {
        let role = verified_share.role();
        if descriptor.identity_digest != verified_share.tenant_root_identity_digest()
            || descriptor.source_custody_lineage != verified_share.source_custody_lineage()
            || descriptor.recovery_set_id != verified_share.recovery_set_id()
            || descriptor.stable_root_commitment != verified_share.stable_root_commitment()
            || descriptor.role(role).recipient_fingerprint != verified_share.recipient_fingerprint()
            || descriptor.role(role).recovery_share_commitment
                != verified_share.recovery_share_commitment()
            || descriptor.role(role).deriver_signing_key_id
                != verified_share.deriver_signing_key_id()
        {
            return Err(verification_failed(
                "tenant root verified recovery share does not match descriptor",
            ));
        }
        let share_wire = verified_share.share_wire();
        let share = share_wire
            .to_share()
            .map_err(|_| malformed("tenant root recovery share wire is invalid"))?;
        if bool::from(
            share
                .to_bytes()
                .ct_eq(&[0_u8; TENANT_ROOT_RECOVERY_SHARE_WIRE_BYTES - 2]),
        ) {
            return Err(malformed(
                "tenant root recovery share scalar must be non-zero",
            ));
        }
        if share.id() != role.share_id() {
            return Err(malformed(
                "tenant root recovery share wire does not match selected role",
            ));
        }
        descriptor.validate()?;
        if !bool::from(
            SigningRootShareCommitment::from_share(&share)
                .to_bytes()
                .ct_eq(&descriptor.role(role).recovery_share_commitment.to_bytes()),
        ) {
            return Err(verification_failed(
                "tenant root recovery share does not match descriptor commitment",
            ));
        }
        let header = TenantRootRecoveryPackageHeaderV1::from_descriptor(descriptor, role)?;
        let header_bytes = header.canonical_json()?;
        let recipient_key = DhKemX25519HkdfSha256::pk_from_bytes(
            descriptor.role(role).recipient_public_key.as_bytes(),
        )
        .map_err(|_| malformed("tenant root recovery recipient public key is invalid"))?;
        let plaintext = Zeroizing::new(share_wire.to_bytes());
        let authenticated_data = package_authenticated_data(&header_bytes);
        let (encapsulated_key, ciphertext) = TenantRootRecoveryHpkeV1::seal_base(
            rng,
            &recipient_key,
            TENANT_ROOT_RECOVERY_PACKAGE_HPKE_INFO_V1,
            &authenticated_data,
            plaintext.as_ref(),
        )
        .map_err(|_| verification_failed("tenant root recovery package encryption failed"))?;
        if ciphertext.len() != TENANT_ROOT_RECOVERY_PACKAGE_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant root recovery package ciphertext length is invalid",
            ));
        }
        let encapsulated_key: [u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES] = encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| malformed("tenant root recovery encapsulated key length is invalid"))?;
        let signature_input =
            package_signature_input(&header_bytes, &encapsulated_key, &ciphertext)?;
        let signature = SigningKey::from_bytes(deriver_signing_key_bytes)
            .sign(&signature_input)
            .to_bytes();
        let package = Self {
            header,
            encapsulated_key,
            ciphertext,
            signature,
        };
        package.validate_encoded_size()?;
        Ok(package)
    }

    /// Returns the public package header.
    pub const fn header(&self) -> &TenantRootRecoveryPackageHeaderV1 {
        &self.header
    }

    /// Returns the exact encapsulated HPKE key.
    pub const fn encapsulated_key(&self) -> &[u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES] {
        &self.encapsulated_key
    }

    /// Returns the ciphertext length without exposing plaintext material.
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// Returns the fixed package signature bytes.
    pub const fn signature(&self) -> &[u8; TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES] {
        &self.signature
    }

    /// Encodes the complete binary package file.
    pub fn to_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate_encoded_size()?;
        let header = self.header.canonical_json()?;
        let header_len = u32::try_from(header.len())
            .map_err(|_| malformed("tenant root recovery package header is too long"))?;
        let ciphertext_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| malformed("tenant root recovery package ciphertext is too long"))?;
        let capacity = TENANT_ROOT_RECOVERY_PACKAGE_MAGIC.len()
            + 4
            + header.len()
            + TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES
            + 4
            + self.ciphertext.len()
            + TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(TENANT_ROOT_RECOVERY_PACKAGE_MAGIC);
        bytes.extend_from_slice(&header_len.to_be_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&self.encapsulated_key);
        bytes.extend_from_slice(&ciphertext_len.to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Alias used by digest and binary transport callers for the complete file bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.to_bytes()
    }

    /// Returns SHA-256 over the complete binary package file.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootRecoveryPackageDigestV1> {
        Ok(TenantRootRecoveryPackageDigestV1(
            Sha256::digest(self.to_bytes()?).into(),
        ))
    }

    /// Decodes one exact capped package file and recanonicalizes its header.
    pub fn decode(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.len() > TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1 {
            return Err(malformed("tenant root recovery package exceeds size cap"));
        }
        let mut cursor = 0_usize;
        let magic = take_bytes(bytes, &mut cursor, TENANT_ROOT_RECOVERY_PACKAGE_MAGIC.len())?;
        if magic != TENANT_ROOT_RECOVERY_PACKAGE_MAGIC {
            return Err(malformed("tenant root recovery package magic is invalid"));
        }
        let header_len = usize::try_from(read_u32_be(bytes, &mut cursor)?)
            .map_err(|_| malformed("tenant root recovery package header length is invalid"))?;
        if header_len > TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant root recovery package header exceeds size cap",
            ));
        }
        let header_bytes = take_bytes(bytes, &mut cursor, header_len)?;
        let header = package_header_from_canonical_json(header_bytes)?;
        let encapsulated_key = take_fixed_bytes::<32>(bytes, &mut cursor)?;
        if !is_canonical_nonzero_x25519_encoding(&encapsulated_key) {
            return Err(malformed(
                "tenant root recovery encapsulated key is not canonical",
            ));
        }
        DhKemX25519HkdfSha256::enc_from_bytes(&encapsulated_key)
            .map_err(|_| malformed("tenant root recovery encapsulated key is invalid"))?;
        let ciphertext_len = usize::try_from(read_u32_be(bytes, &mut cursor)?)
            .map_err(|_| malformed("tenant root recovery package ciphertext length is invalid"))?;
        if ciphertext_len != TENANT_ROOT_RECOVERY_PACKAGE_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant root recovery package ciphertext length is invalid",
            ));
        }
        let ciphertext = take_bytes(bytes, &mut cursor, ciphertext_len)?.to_vec();
        let signature = take_fixed_bytes::<64>(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(malformed("tenant root recovery package has trailing bytes"));
        }
        let package = Self {
            header,
            encapsulated_key,
            ciphertext,
            signature,
        };
        package.validate_encoded_size()?;
        Ok(package)
    }

    /// Verifies the role signature against an externally trusted verifying key.
    fn verify(
        &self,
        descriptor: &TenantRootRecoveryDescriptorV1,
        role: TwoPartyDeriverRole,
        trusted_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<()> {
        self.header.validate_against_descriptor(descriptor, role)?;
        self.validate_encoded_size()?;
        let header_bytes = self.header.canonical_json()?;
        let verifying_key = VerifyingKey::from_bytes(trusted_verifying_key)
            .map_err(|_| malformed("tenant root recovery Deriver verifying key is invalid"))?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(
                &package_signature_input(&header_bytes, &self.encapsulated_key, &self.ciphertext)?,
                &signature,
            )
            .map_err(|_| {
                verification_failed("tenant root recovery package signature verification failed")
            })
    }

    /// Opens one package after verifying its descriptor, role signature, and recipient key.
    fn open(
        &self,
        descriptor: &TenantRootRecoveryDescriptorV1,
        recipient: &TenantRootRecoveryRecipientKeypairV1,
        trusted_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<SigningRootShareWire> {
        let role = self.header.role;
        self.verify(descriptor, role, trusted_verifying_key)?;
        let expected_public_key = descriptor.role(role).recipient_public_key;
        if !bool::from(
            recipient
                .public_key
                .as_bytes()
                .ct_eq(expected_public_key.as_bytes()),
        ) {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "tenant root recovery recipient key does not match package role",
            ));
        }
        if !bool::from(
            recipient
                .public_key
                .fingerprint()
                .as_bytes()
                .ct_eq(self.header.recipient_fingerprint.as_bytes()),
        ) {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "tenant root recovery recipient fingerprint does not match package",
            ));
        }
        let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient.private_key.as_ref())
            .map_err(|_| malformed("tenant root recovery recipient private key is invalid"))?;
        let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(&self.encapsulated_key)
            .map_err(|_| malformed("tenant root recovery encapsulated key is invalid"))?;
        let header_bytes = self.header.canonical_json()?;
        let plaintext = Zeroizing::new(
            TenantRootRecoveryHpkeV1::open_base(
                &encapsulated_key,
                &private_key,
                TENANT_ROOT_RECOVERY_PACKAGE_HPKE_INFO_V1,
                &package_authenticated_data(&header_bytes),
                &self.ciphertext,
            )
            .map_err(|_| verification_failed("tenant root recovery package decryption failed"))?,
        );
        if plaintext.len() != TENANT_ROOT_RECOVERY_SHARE_WIRE_BYTES {
            return Err(malformed(
                "tenant root recovery plaintext length is invalid",
            ));
        }
        let mut share_bytes = Zeroizing::new([0_u8; TENANT_ROOT_RECOVERY_SHARE_WIRE_BYTES]);
        share_bytes.copy_from_slice(&plaintext);
        let share = SigningRootShareWire::decode(*share_bytes)
            .map_err(|_| verification_failed("tenant root recovery plaintext share is invalid"))?;
        let opened_share = share
            .to_share()
            .map_err(|_| malformed("tenant root recovery plaintext share is invalid"))?;
        if bool::from(
            opened_share
                .to_bytes()
                .ct_eq(&[0_u8; TENANT_ROOT_RECOVERY_SHARE_WIRE_BYTES - 2]),
        ) {
            return Err(verification_failed(
                "tenant root recovery plaintext share scalar must be non-zero",
            ));
        }
        if opened_share.id() != role.share_id() {
            return Err(malformed(
                "tenant root recovery plaintext share does not match package role",
            ));
        }
        if SigningRootShareCommitment::from_share(&opened_share)
            != self.header.recovery_share_commitment
        {
            return Err(verification_failed(
                "tenant root recovery plaintext share does not match package commitment",
            ));
        }
        Ok(share)
    }

    fn validate_encoded_size(&self) -> RouterAbDerivationResult<()> {
        if !is_canonical_nonzero_x25519_encoding(&self.encapsulated_key) {
            return Err(malformed(
                "tenant root recovery encapsulated key is not canonical",
            ));
        }
        if self.ciphertext.len() != TENANT_ROOT_RECOVERY_PACKAGE_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant root recovery package ciphertext length is invalid",
            ));
        }
        let header_len = self.header.canonical_json()?.len();
        let total = TENANT_ROOT_RECOVERY_PACKAGE_MAGIC
            .len()
            .checked_add(4)
            .and_then(|value| value.checked_add(header_len))
            .and_then(|value| value.checked_add(TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(self.ciphertext.len()))
            .and_then(|value| value.checked_add(TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES))
            .ok_or_else(|| malformed("tenant root recovery package length overflows"))?;
        if total > TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1 {
            return Err(malformed("tenant root recovery package exceeds size cap"));
        }
        Ok(())
    }
}

/// Externally supplied trusted keys used to verify a complete recovery artifact set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryTrustedVerifyingKeysV1 {
    /// Trusted Deriver A role-signing key.
    pub deriver_a: [u8; 32],
    /// Trusted Deriver B role-signing key.
    pub deriver_b: [u8; 32],
    /// Trusted control-plane manifest-signing key.
    pub control_plane: [u8; 32],
}

/// One role share opened only after its manifest, package binding, signature, and commitment pass.
pub struct VerifiedTenantRootRecoveryRoleShareV1 {
    role: TwoPartyDeriverRole,
    share_wire: SigningRootShareWire,
    identity_digest: TenantRootIdentityDigestV1,
    recovery_set_id: TenantRootRecoverySetId,
    manifest_digest: [u8; 32],
    package_digest: TenantRootRecoveryPackageDigestV1,
    stable_root_commitment: TwoPartyRootCommitment,
    recovery_share_commitment: SigningRootShareCommitment,
}

impl fmt::Debug for VerifiedTenantRootRecoveryRoleShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRecoveryRoleShareV1")
            .field("role", &self.role)
            .field("share_wire", &"[redacted]")
            .field("identity_digest", &self.identity_digest)
            .field("recovery_set_id", &self.recovery_set_id)
            .field("manifest_digest", &hex::encode(self.manifest_digest))
            .field("package_digest", &self.package_digest)
            .field("stable_root_commitment", &self.stable_root_commitment)
            .field("recovery_share_commitment", &self.recovery_share_commitment)
            .finish()
    }
}

impl VerifiedTenantRootRecoveryRoleShareV1 {
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    pub const fn tenant_root_identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    pub const fn recovery_set_id(&self) -> TenantRootRecoverySetId {
        self.recovery_set_id
    }

    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    pub const fn package_digest(&self) -> TenantRootRecoveryPackageDigestV1 {
        self.package_digest
    }

    pub const fn stable_root_commitment(&self) -> TwoPartyRootCommitment {
        self.stable_root_commitment
    }

    pub const fn recovery_share_commitment(&self) -> SigningRootShareCommitment {
        self.recovery_share_commitment
    }

    pub(super) const fn share_wire(&self) -> &SigningRootShareWire {
        &self.share_wire
    }
}

/// Public signed manifest binding the descriptor and both complete package files.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryManifestV1 {
    descriptor: TenantRootRecoveryDescriptorV1,
    deriver_a_package_length: u32,
    deriver_a_package_digest: TenantRootRecoveryPackageDigestV1,
    deriver_b_package_length: u32,
    deriver_b_package_digest: TenantRootRecoveryPackageDigestV1,
    deriver_a_signer_certificate_chain: Vec<String>,
    deriver_b_signer_certificate_chain: Vec<String>,
    control_plane_signer_certificate_chain: Vec<String>,
    control_plane_signature: [u8; TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES],
}

impl fmt::Debug for TenantRootRecoveryManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRecoveryManifestV1")
            .field("descriptor", &self.descriptor)
            .field("deriver_a_package_length", &self.deriver_a_package_length)
            .field("deriver_a_package_digest", &self.deriver_a_package_digest)
            .field("deriver_b_package_length", &self.deriver_b_package_length)
            .field("deriver_b_package_digest", &self.deriver_b_package_digest)
            .field(
                "deriver_a_signer_certificate_chain",
                &self.deriver_a_signer_certificate_chain,
            )
            .field(
                "deriver_b_signer_certificate_chain",
                &self.deriver_b_signer_certificate_chain,
            )
            .field(
                "control_plane_signer_certificate_chain",
                &self.control_plane_signer_certificate_chain,
            )
            .field("control_plane_signature", &"[redacted]")
            .finish()
    }
}

impl TenantRootRecoveryManifestV1 {
    /// Signs a manifest over one exact descriptor and its A/B package digests and lengths.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        descriptor: TenantRootRecoveryDescriptorV1,
        package_a: &TenantRootRecoveryPackageV1,
        package_b: &TenantRootRecoveryPackageV1,
        deriver_a_signer_certificate_chain: Vec<String>,
        deriver_b_signer_certificate_chain: Vec<String>,
        control_plane_signer_certificate_chain: Vec<String>,
        control_plane_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let (deriver_a_package_length, deriver_a_package_digest) =
            package_binding(&descriptor, package_a, TwoPartyDeriverRole::DeriverA)?;
        let (deriver_b_package_length, deriver_b_package_digest) =
            package_binding(&descriptor, package_b, TwoPartyDeriverRole::DeriverB)?;
        validate_certificate_chain(
            &deriver_a_signer_certificate_chain,
            "Deriver A signer certificate chain",
        )?;
        validate_certificate_chain(
            &deriver_b_signer_certificate_chain,
            "Deriver B signer certificate chain",
        )?;
        validate_certificate_chain(
            &control_plane_signer_certificate_chain,
            "control-plane signer certificate chain",
        )?;
        let mut manifest = Self {
            descriptor,
            deriver_a_package_length,
            deriver_a_package_digest,
            deriver_b_package_length,
            deriver_b_package_digest,
            deriver_a_signer_certificate_chain,
            deriver_b_signer_certificate_chain,
            control_plane_signer_certificate_chain,
            control_plane_signature: [0_u8; TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES],
        };
        let signature_input = manifest_signature_input(&manifest.unsigned_canonical_json()?);
        manifest.control_plane_signature = SigningKey::from_bytes(control_plane_signing_key_bytes)
            .sign(&signature_input)
            .to_bytes();
        manifest.validate()?;
        Ok(manifest)
    }

    /// Returns the descriptor bound into this manifest.
    pub const fn descriptor(&self) -> &TenantRootRecoveryDescriptorV1 {
        &self.descriptor
    }

    /// Returns the A package length and digest recorded by this manifest.
    pub const fn deriver_a_package_length(&self) -> u32 {
        self.deriver_a_package_length
    }

    /// Returns the B package length and digest recorded by this manifest.
    pub const fn deriver_b_package_length(&self) -> u32 {
        self.deriver_b_package_length
    }

    /// Returns the A package digest recorded by this manifest.
    pub const fn deriver_a_package_digest(&self) -> TenantRootRecoveryPackageDigestV1 {
        self.deriver_a_package_digest
    }

    /// Returns the B package digest recorded by this manifest.
    pub const fn deriver_b_package_digest(&self) -> TenantRootRecoveryPackageDigestV1 {
        self.deriver_b_package_digest
    }

    /// Returns the public A signer certificate chain without treating it as a trust root.
    pub fn deriver_a_signer_certificate_chain(&self) -> &[String] {
        &self.deriver_a_signer_certificate_chain
    }

    /// Returns the public B signer certificate chain without treating it as a trust root.
    pub fn deriver_b_signer_certificate_chain(&self) -> &[String] {
        &self.deriver_b_signer_certificate_chain
    }

    /// Returns the public control-plane signer certificate chain without treating it as a trust root.
    pub fn control_plane_signer_certificate_chain(&self) -> &[String] {
        &self.control_plane_signer_certificate_chain
    }

    /// Returns the control-plane signature bytes.
    pub const fn control_plane_signature(
        &self,
    ) -> &[u8; TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES] {
        &self.control_plane_signature
    }

    /// Returns the exact unsigned canonical manifest bytes used by the signature.
    pub fn unsigned_canonical_json(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate_shape()?;
        canonical_json_bytes(&manifest_value(self, false))
    }

    /// Returns the exact canonical signed manifest JSON bytes.
    pub fn canonical_json(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        canonical_json_bytes(&manifest_value(self, true))
    }

    /// Returns the exact canonical signed manifest bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.canonical_json()
    }

    /// Returns SHA-256 over the complete signed manifest JSON.
    pub fn digest(&self) -> RouterAbDerivationResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_json()?).into())
    }

    /// Parses one exact capped canonical manifest.
    pub fn from_canonical_json(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.len() > TENANT_ROOT_RECOVERY_MANIFEST_MAX_BYTES_V1 {
            return Err(malformed("tenant root recovery manifest exceeds size cap"));
        }
        let value = strict_json_value(bytes)?;
        let manifest = manifest_from_value(value)?;
        if manifest.canonical_json()? != bytes {
            return Err(malformed(
                "tenant root recovery manifest is not canonical JSON",
            ));
        }
        Ok(manifest)
    }

    /// Verifies the control-plane signature with an externally trusted key.
    pub fn verify(
        &self,
        trusted_control_plane_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<()> {
        self.validate()?;
        let verifying_key =
            VerifyingKey::from_bytes(trusted_control_plane_verifying_key).map_err(|_| {
                malformed("tenant root recovery control-plane verifying key is invalid")
            })?;
        let signature = Signature::from_bytes(&self.control_plane_signature);
        verifying_key
            .verify_strict(
                &manifest_signature_input(&self.unsigned_canonical_json()?),
                &signature,
            )
            .map_err(|_| {
                verification_failed("tenant root recovery manifest signature verification failed")
            })
    }

    /// Verifies the control-plane signature, package bindings, and both role signatures.
    pub fn verify_packages(
        &self,
        package_a: &TenantRootRecoveryPackageV1,
        package_b: &TenantRootRecoveryPackageV1,
        trusted_keys: &TenantRootRecoveryTrustedVerifyingKeysV1,
    ) -> RouterAbDerivationResult<()> {
        self.verify(&trusted_keys.control_plane)?;
        package_a.verify(
            &self.descriptor,
            TwoPartyDeriverRole::DeriverA,
            &trusted_keys.deriver_a,
        )?;
        package_b.verify(
            &self.descriptor,
            TwoPartyDeriverRole::DeriverB,
            &trusted_keys.deriver_b,
        )?;
        let (length_a, digest_a) =
            package_binding(&self.descriptor, package_a, TwoPartyDeriverRole::DeriverA)?;
        let (length_b, digest_b) =
            package_binding(&self.descriptor, package_b, TwoPartyDeriverRole::DeriverB)?;
        if length_a != self.deriver_a_package_length
            || digest_a != self.deriver_a_package_digest
            || length_b != self.deriver_b_package_length
            || digest_b != self.deriver_b_package_digest
        {
            return Err(verification_failed(
                "tenant root recovery manifest package binding does not match package files",
            ));
        }
        Ok(())
    }

    /// Verifies one role package against this signed manifest and external trust bundle.
    pub fn verify_role_package(
        &self,
        package: &TenantRootRecoveryPackageV1,
        trusted_keys: &TenantRootRecoveryTrustedVerifyingKeysV1,
    ) -> RouterAbDerivationResult<()> {
        self.verify(&trusted_keys.control_plane)?;
        let role = package.header.role;
        let trusted_role_key = match role {
            TwoPartyDeriverRole::DeriverA => &trusted_keys.deriver_a,
            TwoPartyDeriverRole::DeriverB => &trusted_keys.deriver_b,
        };
        package.verify(&self.descriptor, role, trusted_role_key)?;
        let (length, digest) = package_binding(&self.descriptor, package, role)?;
        let (expected_length, expected_digest) = match role {
            TwoPartyDeriverRole::DeriverA => {
                (self.deriver_a_package_length, self.deriver_a_package_digest)
            }
            TwoPartyDeriverRole::DeriverB => {
                (self.deriver_b_package_length, self.deriver_b_package_digest)
            }
        };
        if length != expected_length || digest != expected_digest {
            return Err(verification_failed(
                "tenant root recovery manifest role-package binding does not match package file",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        self.validate_shape()?;
        if self.control_plane_signature == [0_u8; TENANT_ROOT_RECOVERY_PACKAGE_SIGNATURE_BYTES] {
            return Err(malformed(
                "tenant root recovery manifest control-plane signature is empty",
            ));
        }
        Ok(())
    }

    fn validate_shape(&self) -> RouterAbDerivationResult<()> {
        self.descriptor.validate()?;
        validate_certificate_chain(
            &self.deriver_a_signer_certificate_chain,
            "Deriver A signer certificate chain",
        )?;
        validate_certificate_chain(
            &self.deriver_b_signer_certificate_chain,
            "Deriver B signer certificate chain",
        )?;
        validate_certificate_chain(
            &self.control_plane_signer_certificate_chain,
            "control-plane signer certificate chain",
        )?;
        if self.deriver_a_package_length == 0 || self.deriver_b_package_length == 0 {
            return Err(malformed(
                "tenant root recovery manifest package length is zero",
            ));
        }
        if usize::try_from(self.deriver_a_package_length)
            .map_err(|_| malformed("tenant root recovery manifest package length is invalid"))?
            > TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1
            || usize::try_from(self.deriver_b_package_length)
                .map_err(|_| malformed("tenant root recovery manifest package length is invalid"))?
                > TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES_V1
        {
            return Err(malformed(
                "tenant root recovery manifest package length exceeds cap",
            ));
        }
        Ok(())
    }
}

impl Serialize for TenantRootRecoveryManifestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        manifest_value(self, true).serialize(serializer)
    }
}

/// Encrypts one role's recovery share and signs the package.
pub fn seal_tenant_root_recovery_package_v1<R>(
    descriptor: &TenantRootRecoveryDescriptorV1,
    verified_share: &VerifiedTenantRootRecoveryShareV1,
    rng: &mut R,
    deriver_signing_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<TenantRootRecoveryPackageV1>
where
    R: RngCore + CryptoRng,
{
    TenantRootRecoveryPackageV1::seal(descriptor, verified_share, rng, deriver_signing_key_bytes)
}

/// Verifies one role package against its signed manifest before opening its secret share.
pub fn verify_and_open_tenant_root_recovery_role_package_v1(
    manifest: &TenantRootRecoveryManifestV1,
    package: &TenantRootRecoveryPackageV1,
    recipient: &TenantRootRecoveryRecipientKeypairV1,
    trusted_keys: &TenantRootRecoveryTrustedVerifyingKeysV1,
) -> RouterAbDerivationResult<VerifiedTenantRootRecoveryRoleShareV1> {
    manifest.verify_role_package(package, trusted_keys)?;
    let role = package.header.role;
    let trusted_role_key = match role {
        TwoPartyDeriverRole::DeriverA => &trusted_keys.deriver_a,
        TwoPartyDeriverRole::DeriverB => &trusted_keys.deriver_b,
    };
    let share_wire = package.open(manifest.descriptor(), recipient, trusted_role_key)?;
    Ok(VerifiedTenantRootRecoveryRoleShareV1 {
        role,
        share_wire,
        identity_digest: package.header.identity_digest,
        recovery_set_id: package.header.recovery_set_id,
        manifest_digest: manifest.digest()?,
        package_digest: package.digest()?,
        stable_root_commitment: package.header.stable_root_commitment,
        recovery_share_commitment: package.header.recovery_share_commitment,
    })
}

/// Decodes one capped role package binary file.
pub fn decode_tenant_root_recovery_package_v1(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootRecoveryPackageV1> {
    TenantRootRecoveryPackageV1::decode(bytes)
}

/// Signs one public manifest over both role packages and certificate chains.
#[allow(clippy::too_many_arguments)]
pub fn sign_tenant_root_recovery_manifest_v1(
    descriptor: TenantRootRecoveryDescriptorV1,
    package_a: &TenantRootRecoveryPackageV1,
    package_b: &TenantRootRecoveryPackageV1,
    deriver_a_signer_certificate_chain: Vec<String>,
    deriver_b_signer_certificate_chain: Vec<String>,
    control_plane_signer_certificate_chain: Vec<String>,
    control_plane_signing_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<TenantRootRecoveryManifestV1> {
    TenantRootRecoveryManifestV1::sign(
        descriptor,
        package_a,
        package_b,
        deriver_a_signer_certificate_chain,
        deriver_b_signer_certificate_chain,
        control_plane_signer_certificate_chain,
        control_plane_signing_key_bytes,
    )
}

/// Decodes one capped canonical public manifest.
pub fn decode_tenant_root_recovery_manifest_v1(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootRecoveryManifestV1> {
    TenantRootRecoveryManifestV1::from_canonical_json(bytes)
}

fn role_descriptor(
    role: TwoPartyDeriverRole,
    recipient_public_key: TenantRootRecoveryRecipientPublicKeyV1,
    recovery_share_commitment: SigningRootShareCommitment,
    deriver_signing_key_id: String,
) -> RouterAbDerivationResult<TenantRootRecoveryRoleDescriptorV1> {
    if recovery_share_commitment.id() != role.share_id() {
        return Err(malformed(
            "tenant root recovery share commitment does not match role",
        ));
    }
    require_key_id(
        "tenant root recovery Deriver signing key id",
        &deriver_signing_key_id,
    )?;
    Ok(TenantRootRecoveryRoleDescriptorV1 {
        role,
        share_id: role.share_id(),
        recipient_fingerprint: recipient_public_key.fingerprint(),
        recipient_public_key,
        recovery_share_commitment,
        deriver_signing_key_id,
    })
}

fn descriptor_value(descriptor: &TenantRootRecoveryDescriptorV1) -> Value {
    json_object(vec![
        (
            "creationTime",
            Value::String(descriptor.creation_time.clone()),
        ),
        ("deriverA", role_descriptor_value(&descriptor.deriver_a)),
        ("deriverB", role_descriptor_value(&descriptor.deriver_b)),
        (
            "formatVersion",
            Value::String(TENANT_ROOT_RECOVERY_DESCRIPTOR_FORMAT_V1.to_owned()),
        ),
        (
            "hpkeSuite",
            Value::String(TENANT_ROOT_RECOVERY_HPKE_SUITE_V1.to_owned()),
        ),
        (
            "sourceCustodyLineageId",
            Value::String(descriptor.source_custody_lineage.to_base64url()),
        ),
        (
            "stableRootCommitment",
            Value::String(encode_base64url(
                &descriptor.stable_root_commitment.to_bytes(),
            )),
        ),
        ("tenantRootIdentity", identity_value(&descriptor.identity)),
        (
            "tenantRootIdentityDigest",
            Value::String(encode_base64url(descriptor.identity_digest.as_bytes())),
        ),
        (
            "tenantRootRecoverySetId",
            Value::String(descriptor.recovery_set_id.to_base64url()),
        ),
    ])
}

fn role_descriptor_value(role: &TenantRootRecoveryRoleDescriptorV1) -> Value {
    json_object(vec![
        (
            "deriverSigningKeyId",
            Value::String(role.deriver_signing_key_id.clone()),
        ),
        (
            "recoveryShareCommitment",
            Value::String(encode_base64url(&role.recovery_share_commitment.to_bytes())),
        ),
        (
            "recipientFingerprint",
            Value::String(encode_base64url(role.recipient_fingerprint.as_bytes())),
        ),
        (
            "recipientPublicKey",
            Value::String(encode_base64url(role.recipient_public_key.as_bytes())),
        ),
        ("role", Value::String(role.role.as_str().to_owned())),
        (
            "shareId",
            Value::Number(Number::from(u64::from(role.share_id.get().get()))),
        ),
    ])
}

fn identity_value(identity: &TenantRootIdentityV1) -> Value {
    json_object(vec![
        ("envId", Value::String(identity.env_id().to_owned())),
        ("orgId", Value::String(identity.org_id().to_owned())),
        ("projectId", Value::String(identity.project_id().to_owned())),
        (
            "signingRootId",
            Value::String(identity.signing_root_id().to_owned()),
        ),
        (
            "signingRootVersion",
            Value::String(identity.signing_root_version().to_owned()),
        ),
    ])
}

fn package_header_value(header: &TenantRootRecoveryPackageHeaderV1) -> Value {
    json_object(vec![
        ("creationTime", Value::String(header.creation_time.clone())),
        (
            "deriverSigningKeyId",
            Value::String(header.deriver_signing_key_id.clone()),
        ),
        (
            "descriptorDigest",
            Value::String(encode_base64url(header.descriptor_digest.as_bytes())),
        ),
        (
            "formatVersion",
            Value::String(header.format_version.clone()),
        ),
        ("hpkeSuite", Value::String(header.hpke_suite.clone())),
        (
            "recoveryShareCommitment",
            Value::String(encode_base64url(
                &header.recovery_share_commitment.to_bytes(),
            )),
        ),
        (
            "recipientFingerprint",
            Value::String(encode_base64url(header.recipient_fingerprint.as_bytes())),
        ),
        ("role", Value::String(header.role.as_str().to_owned())),
        (
            "shareId",
            Value::Number(Number::from(u64::from(header.share_id.get().get()))),
        ),
        (
            "sourceCustodyLineageId",
            Value::String(header.source_custody_lineage.to_base64url()),
        ),
        (
            "stableRootCommitment",
            Value::String(encode_base64url(&header.stable_root_commitment.to_bytes())),
        ),
        (
            "tenantRootIdentityDigest",
            Value::String(encode_base64url(header.identity_digest.as_bytes())),
        ),
        (
            "tenantRootRecoverySetId",
            Value::String(header.recovery_set_id.to_base64url()),
        ),
    ])
}

fn manifest_value(manifest: &TenantRootRecoveryManifestV1, include_signature: bool) -> Value {
    let mut entries = vec![
        (
            "controlPlaneSignerCertificateChain",
            certificate_chain_value(&manifest.control_plane_signer_certificate_chain),
        ),
        (
            "deriverAPackageDigest",
            Value::String(encode_base64url(
                manifest.deriver_a_package_digest.as_bytes(),
            )),
        ),
        (
            "deriverAPackageLength",
            Value::Number(Number::from(u64::from(manifest.deriver_a_package_length))),
        ),
        (
            "deriverASignerCertificateChain",
            certificate_chain_value(&manifest.deriver_a_signer_certificate_chain),
        ),
        (
            "deriverBPackageDigest",
            Value::String(encode_base64url(
                manifest.deriver_b_package_digest.as_bytes(),
            )),
        ),
        (
            "deriverBPackageLength",
            Value::Number(Number::from(u64::from(manifest.deriver_b_package_length))),
        ),
        (
            "deriverBSignerCertificateChain",
            certificate_chain_value(&manifest.deriver_b_signer_certificate_chain),
        ),
        ("descriptor", descriptor_value(&manifest.descriptor)),
        (
            "formatVersion",
            Value::String(TENANT_ROOT_RECOVERY_MANIFEST_FORMAT_V1.to_owned()),
        ),
    ];
    if include_signature {
        entries.push((
            "controlPlaneSignature",
            Value::String(encode_base64url(&manifest.control_plane_signature)),
        ));
    }
    json_object(entries)
}

fn certificate_chain_value(chain: &[String]) -> Value {
    Value::Array(chain.iter().cloned().map(Value::String).collect())
}

fn json_object(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

fn descriptor_from_value(value: Value) -> RouterAbDerivationResult<TenantRootRecoveryDescriptorV1> {
    let wire: DescriptorWire = serde_json::from_value(value).map_err(|error| {
        malformed_owned(format!("invalid tenant root recovery descriptor: {error}"))
    })?;
    if wire.format_version != TENANT_ROOT_RECOVERY_DESCRIPTOR_FORMAT_V1
        || wire.hpke_suite != TENANT_ROOT_RECOVERY_HPKE_SUITE_V1
    {
        return Err(malformed(
            "tenant root recovery descriptor version or suite is invalid",
        ));
    }
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(decode_base64url_fixed(
        &wire.tenant_root_identity_digest,
        "tenant root identity digest",
    )?);
    let source_lineage =
        TenantRootCustodyLineageId::from_base64url(&wire.source_custody_lineage_id)?;
    let recovery_set_id =
        TenantRootRecoverySetId::from_base64url(&wire.tenant_root_recovery_set_id)?;
    let root = TwoPartyRootCommitment::from_bytes(decode_base64url_fixed(
        &wire.stable_root_commitment,
        "stable root commitment",
    )?)
    .map_err(|_| malformed("stable root commitment is invalid"))?;
    let recipient_a = decode_role_wire(&wire.deriver_a, TwoPartyDeriverRole::DeriverA)?;
    let recipient_b = decode_role_wire(&wire.deriver_b, TwoPartyDeriverRole::DeriverB)?;
    let descriptor = TenantRootRecoveryDescriptorV1::new(
        wire.tenant_root_identity,
        source_lineage,
        recovery_set_id,
        wire.creation_time,
        root,
        recipient_a.0,
        recipient_b.0,
        recipient_a.1,
        recipient_b.1,
        recipient_a.2,
        recipient_b.2,
    )?;
    if !bool::from(
        descriptor
            .identity_digest
            .as_bytes()
            .ct_eq(identity_digest.as_bytes()),
    ) {
        return Err(malformed(
            "tenant root recovery descriptor identity digest is incorrect",
        ));
    }
    if !bool::from(descriptor.deriver_a.recipient_fingerprint.as_bytes().ct_eq(
        &decode_base64url_fixed::<32>(
            &wire.deriver_a.recipient_fingerprint,
            "Deriver A recipient fingerprint",
        )?,
    )) || !bool::from(descriptor.deriver_b.recipient_fingerprint.as_bytes().ct_eq(
        &decode_base64url_fixed::<32>(
            &wire.deriver_b.recipient_fingerprint,
            "Deriver B recipient fingerprint",
        )?,
    )) {
        return Err(malformed(
            "tenant root recovery descriptor recipient fingerprint is incorrect",
        ));
    }
    Ok(descriptor)
}

fn decode_role_wire(
    wire: &RoleDescriptorWire,
    expected_role: TwoPartyDeriverRole,
) -> RouterAbDerivationResult<(
    TenantRootRecoveryRecipientPublicKeyV1,
    SigningRootShareCommitment,
    String,
)> {
    let role = parse_role(&wire.role)?;
    if role != expected_role || wire.share_id != expected_role.share_id().get().get() {
        return Err(malformed(
            "tenant root recovery descriptor role or share id is invalid",
        ));
    }
    let recipient = TenantRootRecoveryRecipientPublicKeyV1::from_bytes(decode_base64url_fixed(
        &wire.recipient_public_key,
        "recipient public key",
    )?)?;
    let commitment = SigningRootShareCommitment::from_bytes(decode_base64url_fixed(
        &wire.recovery_share_commitment,
        "recovery share commitment",
    )?)
    .map_err(|_| malformed("recovery share commitment is invalid"))?;
    Ok((recipient, commitment, wire.deriver_signing_key_id.clone()))
}

fn package_header_from_canonical_json(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootRecoveryPackageHeaderV1> {
    let value = strict_json_value(bytes)?;
    let wire: PackageHeaderWire = serde_json::from_value(value).map_err(|error| {
        malformed_owned(format!(
            "invalid tenant root recovery package header: {error}"
        ))
    })?;
    let header = TenantRootRecoveryPackageHeaderV1 {
        format_version: wire.format_version,
        descriptor_digest: TenantRootRecoveryDescriptorDigestV1::from_bytes(
            decode_base64url_fixed(&wire.descriptor_digest, "descriptor digest")?,
        ),
        identity_digest: TenantRootIdentityDigestV1::from_bytes(decode_base64url_fixed(
            &wire.tenant_root_identity_digest,
            "tenant root identity digest",
        )?),
        source_custody_lineage: TenantRootCustodyLineageId::from_base64url(
            &wire.source_custody_lineage_id,
        )?,
        recovery_set_id: TenantRootRecoverySetId::from_base64url(
            &wire.tenant_root_recovery_set_id,
        )?,
        role: parse_role(&wire.role)?,
        share_id: ThresholdShareId::from_u16(wire.share_id)
            .map_err(|_| malformed("recovery package share id is invalid"))?,
        recipient_fingerprint: TenantRootRecoveryRecipientFingerprintV1::from_bytes(
            decode_base64url_fixed(&wire.recipient_fingerprint, "recipient fingerprint")?,
        ),
        recovery_share_commitment: SigningRootShareCommitment::from_bytes(decode_base64url_fixed(
            &wire.recovery_share_commitment,
            "recovery share commitment",
        )?)
        .map_err(|_| malformed("recovery package recovery share commitment is invalid"))?,
        stable_root_commitment: TwoPartyRootCommitment::from_bytes(decode_base64url_fixed(
            &wire.stable_root_commitment,
            "stable root commitment",
        )?)
        .map_err(|_| malformed("recovery package stable root commitment is invalid"))?,
        creation_time: wire.creation_time,
        hpke_suite: wire.hpke_suite,
        deriver_signing_key_id: wire.deriver_signing_key_id,
    };
    header.validate()?;
    if header.canonical_json()? != bytes {
        return Err(malformed(
            "tenant root recovery package header is not canonical JSON",
        ));
    }
    Ok(header)
}

fn manifest_from_value(value: Value) -> RouterAbDerivationResult<TenantRootRecoveryManifestV1> {
    let wire: ManifestWire = serde_json::from_value(value).map_err(|error| {
        malformed_owned(format!("invalid tenant root recovery manifest: {error}"))
    })?;
    if wire.format_version != TENANT_ROOT_RECOVERY_MANIFEST_FORMAT_V1 {
        return Err(malformed(
            "tenant root recovery manifest version is invalid",
        ));
    }
    let manifest = TenantRootRecoveryManifestV1 {
        descriptor: descriptor_from_value(wire.descriptor)?,
        deriver_a_package_length: wire.deriver_a_package_length,
        deriver_a_package_digest: TenantRootRecoveryPackageDigestV1::from_bytes(
            decode_base64url_fixed(&wire.deriver_a_package_digest, "Deriver A package digest")?,
        ),
        deriver_b_package_length: wire.deriver_b_package_length,
        deriver_b_package_digest: TenantRootRecoveryPackageDigestV1::from_bytes(
            decode_base64url_fixed(&wire.deriver_b_package_digest, "Deriver B package digest")?,
        ),
        deriver_a_signer_certificate_chain: wire.deriver_a_signer_certificate_chain,
        deriver_b_signer_certificate_chain: wire.deriver_b_signer_certificate_chain,
        control_plane_signer_certificate_chain: wire.control_plane_signer_certificate_chain,
        control_plane_signature: decode_base64url_fixed(
            &wire.control_plane_signature,
            "control-plane signature",
        )?,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn package_binding(
    descriptor: &TenantRootRecoveryDescriptorV1,
    package: &TenantRootRecoveryPackageV1,
    role: TwoPartyDeriverRole,
) -> RouterAbDerivationResult<(u32, TenantRootRecoveryPackageDigestV1)> {
    package
        .header
        .validate_against_descriptor(descriptor, role)?;
    let bytes = package.to_bytes()?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| malformed("tenant root recovery package length is too large"))?;
    Ok((
        length,
        TenantRootRecoveryPackageDigestV1(Sha256::digest(bytes).into()),
    ))
}

fn package_authenticated_data(header_bytes: &[u8]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(TENANT_ROOT_RECOVERY_PACKAGE_DOMAIN_V1.len() + header_bytes.len());
    bytes.extend_from_slice(TENANT_ROOT_RECOVERY_PACKAGE_DOMAIN_V1);
    bytes.extend_from_slice(header_bytes);
    bytes
}

fn package_signature_input(
    header_bytes: &[u8],
    encapsulated_key: &[u8; TENANT_ROOT_RECOVERY_RECIPIENT_KEY_BYTES],
    ciphertext: &[u8],
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(
        TENANT_ROOT_RECOVERY_PACKAGE_DOMAIN_V1.len()
            + header_bytes.len()
            + encapsulated_key.len()
            + 4
            + ciphertext.len(),
    );
    bytes.extend_from_slice(TENANT_ROOT_RECOVERY_PACKAGE_DOMAIN_V1);
    bytes.extend_from_slice(header_bytes);
    bytes.extend_from_slice(encapsulated_key);
    let ciphertext_len = u32::try_from(ciphertext.len())
        .map_err(|_| malformed("tenant root recovery package ciphertext is too long"))?;
    bytes.extend_from_slice(&ciphertext_len.to_be_bytes());
    bytes.extend_from_slice(ciphertext);
    Ok(bytes)
}

fn manifest_signature_input(unsigned_manifest: &[u8]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(TENANT_ROOT_RECOVERY_MANIFEST_DOMAIN_V1.len() + unsigned_manifest.len());
    bytes.extend_from_slice(TENANT_ROOT_RECOVERY_MANIFEST_DOMAIN_V1);
    bytes.extend_from_slice(unsigned_manifest);
    bytes
}

fn strict_json_value(bytes: &[u8]) -> RouterAbDerivationResult<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde::Deserializer::deserialize_any(&mut deserializer, StrictJsonVisitor)
        .map_err(|error| malformed_owned(format!("invalid recovery JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| malformed_owned(format!("recovery JSON has trailing data: {error}")))?;
    Ok(value)
}

struct StrictJsonSeed;

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point JSON values are not accepted"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map_access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();
        while let Some(key) = map_access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = map_access.next_value_seed(StrictJsonSeed)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

fn canonical_json_bytes(value: &Value) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical_json(value: &Value, bytes: &mut Vec<u8>) -> RouterAbDerivationResult<()> {
    match value {
        Value::Null => bytes.extend_from_slice(b"null"),
        Value::Bool(value) => bytes.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => {
            if value.as_u64().is_none() && value.as_i64().is_none() {
                return Err(malformed("recovery JSON number is not an exact integer"));
            }
            bytes.extend_from_slice(value.to_string().as_bytes());
        }
        Value::String(value) => {
            let encoded = serde_json::to_vec(value).map_err(|error| {
                malformed_owned(format!("failed to encode recovery JSON string: {error}"))
            })?;
            bytes.extend_from_slice(&encoded);
        }
        Value::Array(values) => {
            bytes.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                write_canonical_json(value, bytes)?;
            }
            bytes.push(b']');
        }
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            bytes.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                let encoded_key = serde_json::to_vec(key).map_err(|error| {
                    malformed_owned(format!("failed to encode recovery JSON key: {error}"))
                })?;
                bytes.extend_from_slice(&encoded_key);
                bytes.push(b':');
                write_canonical_json(&map[*key], bytes)?;
            }
            bytes.push(b'}');
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorWire {
    creation_time: String,
    deriver_a: RoleDescriptorWire,
    deriver_b: RoleDescriptorWire,
    format_version: String,
    hpke_suite: String,
    source_custody_lineage_id: String,
    stable_root_commitment: String,
    tenant_root_identity: TenantRootIdentityV1,
    tenant_root_identity_digest: String,
    tenant_root_recovery_set_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleDescriptorWire {
    deriver_signing_key_id: String,
    recovery_share_commitment: String,
    recipient_fingerprint: String,
    recipient_public_key: String,
    role: String,
    share_id: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackageHeaderWire {
    creation_time: String,
    deriver_signing_key_id: String,
    descriptor_digest: String,
    format_version: String,
    hpke_suite: String,
    recovery_share_commitment: String,
    recipient_fingerprint: String,
    role: String,
    share_id: u16,
    source_custody_lineage_id: String,
    stable_root_commitment: String,
    tenant_root_identity_digest: String,
    tenant_root_recovery_set_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestWire {
    control_plane_signer_certificate_chain: Vec<String>,
    control_plane_signature: String,
    deriver_a_package_digest: String,
    deriver_a_package_length: u32,
    deriver_a_signer_certificate_chain: Vec<String>,
    deriver_b_package_digest: String,
    deriver_b_package_length: u32,
    deriver_b_signer_certificate_chain: Vec<String>,
    descriptor: Value,
    format_version: String,
}

fn parse_role(value: &str) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
    match value {
        "deriver_a" => Ok(TwoPartyDeriverRole::DeriverA),
        "deriver_b" => Ok(TwoPartyDeriverRole::DeriverB),
        _ => Err(malformed("tenant root recovery role is invalid")),
    }
}

fn validate_certificate_chain(
    chain: &[String],
    field: &'static str,
) -> RouterAbDerivationResult<()> {
    if chain.is_empty() {
        return Err(malformed_owned(format!("{field} is required")));
    }
    for certificate in chain {
        if certificate.is_empty() {
            return Err(malformed_owned(format!(
                "{field} contains an empty certificate"
            )));
        }
    }
    Ok(())
}

fn validate_rfc3339_millis(value: &str, field: &'static str) -> RouterAbDerivationResult<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
        || ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..23]
            .iter()
            .flat_map(|range| range.clone())
            .all(|index| bytes[index].is_ascii_digit())
    {
        return Err(malformed_owned(format!(
            "{field} must be RFC 3339 UTC with millisecond precision"
        )));
    }
    let month = parse_decimal(&bytes[5..7]);
    let day = parse_decimal(&bytes[8..10]);
    let hour = parse_decimal(&bytes[11..13]);
    let minute = parse_decimal(&bytes[14..16]);
    let second = parse_decimal(&bytes[17..19]);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(malformed_owned(format!(
            "{field} contains an invalid UTC date or time"
        )));
    }
    Ok(())
}

fn parse_decimal(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |value, digit| value * 10 + digit.saturating_sub(b'0'))
}

fn require_nonzero_bytes(bytes: &[u8], message: &'static str) -> RouterAbDerivationResult<()> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(malformed(message))
    } else {
        Ok(())
    }
}

fn require_key_id(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    u32::try_from(value.len()).map_err(|_| malformed("tenant root recovery key id is too long"))?;
    Ok(())
}

fn encode_base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn decode_base64url_fixed<const N: usize>(
    value: &str,
    field: &'static str,
) -> RouterAbDerivationResult<[u8; N]> {
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| malformed_owned(format!("{field} is invalid base64url")))?;
    if decoded.len() != N || Base64UrlUnpadded::encode_string(&decoded) != value {
        return Err(malformed_owned(format!(
            "{field} is not canonical base64url"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| malformed_owned(format!("{field} has an invalid length")))
}

fn read_u32_be(bytes: &[u8], cursor: &mut usize) -> RouterAbDerivationResult<u32> {
    let field = take_bytes(bytes, cursor, 4)?;
    Ok(u32::from_be_bytes(field.try_into().map_err(|_| {
        malformed("recovery package integer length is invalid")
    })?))
}

fn take_fixed_bytes<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> RouterAbDerivationResult<[u8; N]> {
    take_bytes(bytes, cursor, N)?
        .try_into()
        .map_err(|_| malformed("recovery package fixed field length is invalid"))
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> RouterAbDerivationResult<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| malformed("recovery package length overflows"))?;
    if end > bytes.len() {
        return Err(malformed("recovery package is truncated"));
    }
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn malformed_owned(message: String) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn verification_failed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}
