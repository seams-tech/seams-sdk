use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootProtocolDigestV1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_CREATION_CAPABILITY_DOMAIN_V1: &[u8] = b"tenant_root_creation_capability_v1";
const TENANT_ROOT_CREATION_CAPABILITY_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_creation_capability_authentication_v1";
const TENANT_ROOT_CREATION_OPERATION_V1: &[u8] = b"tenant_root_create_v1";
const TENANT_ROOT_CONTROL_PLANE_AUTHORITY_ID_LEN_V1: usize = 32;
const TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1: usize = 32;
const TENANT_ROOT_CREATION_CAPABILITY_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact operation authenticated by an initial tenant-root creation capability.
pub const TENANT_ROOT_CREATION_CAPABILITY_OPERATION_V1: &str = "tenant_root_create_v1";

/// Exact lifecycle revision authenticated by an initial tenant-root creation capability.
pub const TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1: u64 = 1;

/// Maximum canonical wire size accepted for one creation capability.
pub const TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1: usize = 16 * 1024;

/// 32-byte identifier for the authority that owns one tenant-root Durable Object.
///
/// Cloudflare object-id bytes are parsed into this type by the adapter boundary.
/// This core type deliberately carries only the exact bytes and no platform
/// serialization or object-id dependency.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootControlPlaneAuthorityIdV1([u8; TENANT_ROOT_CONTROL_PLANE_AUTHORITY_ID_LEN_V1]);

impl TenantRootControlPlaneAuthorityIdV1 {
    /// Creates an authority identifier from exactly 32 bytes.
    pub const fn from_bytes(bytes: [u8; TENANT_ROOT_CONTROL_PLANE_AUTHORITY_ID_LEN_V1]) -> Self {
        Self(bytes)
    }

    /// Returns the exact authority identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_CONTROL_PLANE_AUTHORITY_ID_LEN_V1] {
        &self.0
    }

    /// Consumes the identifier and returns its exact bytes.
    pub const fn into_bytes(self) -> [u8; TENANT_ROOT_CONTROL_PLANE_AUTHORITY_ID_LEN_V1] {
        self.0
    }
}

impl fmt::Debug for TenantRootControlPlaneAuthorityIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootControlPlaneAuthorityIdV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Non-zero 32-byte one-use nonce for an initial tenant-root creation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootCreationCapabilityNonceV1([u8; TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1]);

impl TenantRootCreationCapabilityNonceV1 {
    /// Parses one exact non-zero capability nonce.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1],
    ) -> RouterAbDerivationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root creation capability nonce must be non-zero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Samples one fresh non-zero capability nonce.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1];
            rng.fill_bytes(&mut bytes);
            if let Ok(nonce) = Self::from_bytes(bytes) {
                return nonce;
            }
        }
    }

    /// Returns the exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1] {
        &self.0
    }

    /// Consumes the nonce and returns its exact bytes.
    pub const fn into_bytes(self) -> [u8; TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1] {
        self.0
    }
}

impl fmt::Debug for TenantRootCreationCapabilityNonceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootCreationCapabilityNonceV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TenantRootCreationCapabilityDataV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    started_journal_digest: TenantRootProtocolDigestV1,
    expected_revision: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    nonce: TenantRootCreationCapabilityNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootCreationCapabilityDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootCreationCapabilityDataV1")
            .field("identity_digest", &self.identity_digest)
            .field("custody_lineage", &self.custody_lineage)
            .field("started_journal_digest", &self.started_journal_digest)
            .field("expected_revision", &self.expected_revision)
            .field("authority_id", &self.authority_id)
            .field("nonce", &self.nonce)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Signed initial-creation authority before cryptographic verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootCreationCapabilityV1 {
    data: TenantRootCreationCapabilityDataV1,
}

impl TenantRootCreationCapabilityV1 {
    /// Signs one exact initial-creation authority capability.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        started_journal_digest: TenantRootProtocolDigestV1,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        nonce: TenantRootCreationCapabilityNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let mut data = TenantRootCreationCapabilityDataV1 {
            identity_digest,
            custody_lineage,
            started_journal_digest,
            expected_revision: TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1,
            authority_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id: issuer_key_id.into(),
            signature: [0; 64],
        };
        validate_unsigned_data(&data)?;
        let unsigned = unsigned_canonical_bytes(&data)?;
        data.signature = SigningKey::from_bytes(issuer_signing_key_bytes)
            .sign(&authentication_input(&data.issuer_key_id, &unsigned)?)
            .to_bytes();
        validate_data(&data)?;
        let capability = Self { data };
        capability.canonical_bytes()?;
        Ok(capability)
    }

    /// Decodes exactly one canonical signed creation capability wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root creation capability wire length is invalid",
            ));
        }
        let mut decoder = CreationCapabilityWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_CREATION_CAPABILITY_DOMAIN_V1)?;
        if decoder.field("tenant-root creation capability operation")?
            != TENANT_ROOT_CREATION_OPERATION_V1
        {
            return Err(malformed(
                "tenant-root creation capability operation is invalid",
            ));
        }
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root creation capability identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root creation capability custody lineage")?,
        )?;
        let started_journal_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root creation capability Started journal digest")?,
        )?;
        let expected_revision =
            decoder.u64_field("tenant-root creation capability expected revision")?;
        if expected_revision != TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1 {
            return Err(malformed(
                "tenant-root creation capability expected revision is invalid",
            ));
        }
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<TENANT_ROOT_CONTROL_PLANE_AUTHORITY_ID_LEN_V1>(
                "tenant-root creation capability authority id",
            )?,
        );
        let nonce = TenantRootCreationCapabilityNonceV1::from_bytes(
            decoder.fixed_field::<TENANT_ROOT_CREATION_CAPABILITY_NONCE_LEN_V1>(
                "tenant-root creation capability nonce",
            )?,
        )?;
        let issued_at_ms = decoder.u64_field("tenant-root creation capability issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root creation capability expiry")?;
        let issuer_key_id = decoder.text_field(
            "tenant-root creation capability issuer key id",
            TENANT_ROOT_CREATION_CAPABILITY_ISSUER_KEY_ID_MAX_BYTES_V1,
        )?;
        require_tenant_root_identifier(
            "tenant-root creation capability issuer key id",
            &issuer_key_id,
        )?;
        let signature = decoder.fixed_field::<64>("tenant-root creation capability signature")?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root creation capability signature must be nonzero",
            ));
        }
        decoder.finish()?;

        let capability = Self {
            data: TenantRootCreationCapabilityDataV1 {
                identity_digest,
                custody_lineage,
                started_journal_digest,
                expected_revision,
                authority_id,
                nonce,
                issued_at_ms,
                expires_at_ms,
                issuer_key_id,
                signature,
            },
        };
        validate_data(&capability.data)?;
        if capability.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root creation capability wire is not canonical",
            ));
        }
        Ok(capability)
    }

    /// Returns the exact operation authenticated by this capability.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_CREATION_CAPABILITY_OPERATION_V1
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.data.identity_digest
    }

    /// Returns the custody lineage authenticated by this capability.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.data.custody_lineage
    }

    /// Returns the digest of the Started journal bound by this capability.
    pub const fn started_journal_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.started_journal_digest
    }

    /// Returns the exact expected lifecycle revision.
    pub const fn expected_revision(&self) -> u64 {
        self.data.expected_revision
    }

    /// Returns the Durable Object authority identifier.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.data.authority_id
    }

    /// Returns the one-use capability nonce.
    pub const fn nonce(&self) -> TenantRootCreationCapabilityNonceV1 {
        self.data.nonce
    }

    /// Returns the authenticated issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.data.issued_at_ms
    }

    /// Returns the authenticated expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.data.expires_at_ms
    }

    /// Returns the authenticated issuer signing-key identifier.
    pub fn issuer_key_id(&self) -> &str {
        &self.data.issuer_key_id
    }

    /// Returns the exact canonical signed capability bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        canonical_bytes_from_unsigned(unsigned, &self.data.signature)
    }

    /// Returns the digest of the exact canonical signed capability bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Verifies every immutable binding and the issuer's strict Ed25519 signature.
    ///
    /// Verification authenticates the capability without checking wall-clock
    /// freshness. Call `require_fresh` on the resulting token before accepting
    /// an unseen capability; an already accepted token can be replayed by its
    /// exact persisted digest after the capability expires.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_identity_digest: TenantRootIdentityDigestV1,
        expected_custody_lineage: TenantRootCustodyLineageId,
        expected_started_journal_digest: TenantRootProtocolDigestV1,
        expected_revision: u64,
        expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootCreationCapabilityV1> {
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root creation capability expected issuer key id",
            expected_issuer_key_id,
        )?;
        if expected_revision != TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1 {
            return Err(replay_mismatch(
                "tenant-root creation capability expected revision is not one",
            ));
        }
        if self.data.identity_digest != expected_identity_digest {
            return Err(replay_mismatch(
                "tenant-root creation capability identity digest does not match its expected identity",
            ));
        }
        if self.data.custody_lineage != expected_custody_lineage {
            return Err(replay_mismatch(
                "tenant-root creation capability custody lineage does not match its expected lineage",
            ));
        }
        if self.data.started_journal_digest != expected_started_journal_digest {
            return Err(replay_mismatch(
                "tenant-root creation capability Started journal digest does not match its expected journal",
            ));
        }
        if self.data.expected_revision != expected_revision {
            return Err(replay_mismatch(
                "tenant-root creation capability expected revision does not match its expected revision",
            ));
        }
        if self.data.authority_id != expected_authority_id {
            return Err(replay_mismatch(
                "tenant-root creation capability authority id does not match its expected authority",
            ));
        }
        if self.data.issuer_key_id != expected_issuer_key_id {
            return Err(replay_mismatch(
                "tenant-root creation capability issuer key id does not match its expected issuer",
            ));
        }

        let unsigned = unsigned_canonical_bytes(&self.data)?;
        let verifying_key = VerifyingKey::from_bytes(trusted_issuer_verifying_key)
            .map_err(|_| malformed("tenant-root creation capability verifying key is invalid"))?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.issuer_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| {
                verification_failed("tenant-root creation capability signature is invalid")
            })?;
        let canonical_bytes = canonical_bytes_from_unsigned(unsigned, &self.data.signature)?;
        let digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&canonical_bytes).into())?;
        Ok(VerifiedTenantRootCreationCapabilityV1 {
            capability: self.clone(),
            canonical_bytes,
            digest,
        })
    }
}

/// Strictly verified initial-creation authority.
///
/// This token has no public constructor and is intentionally neither cloneable
/// nor copyable. Its exact bytes and digest can be retained for durable replay.
pub struct VerifiedTenantRootCreationCapabilityV1 {
    capability: TenantRootCreationCapabilityV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootCreationCapabilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootCreationCapabilityV1")
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootCreationCapabilityV1 {
    /// Returns the exact operation authenticated by this token.
    pub const fn operation(&self) -> &'static str {
        self.capability.operation()
    }

    /// Returns the verified tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.capability.identity_digest()
    }

    /// Returns the verified custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.capability.custody_lineage()
    }

    /// Returns the verified Started journal digest.
    pub const fn started_journal_digest(&self) -> TenantRootProtocolDigestV1 {
        self.capability.started_journal_digest()
    }

    /// Returns the verified expected lifecycle revision.
    pub const fn expected_revision(&self) -> u64 {
        self.capability.expected_revision()
    }

    /// Returns the verified Durable Object authority identifier.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.capability.authority_id()
    }

    /// Returns the verified one-use capability nonce.
    pub const fn nonce(&self) -> TenantRootCreationCapabilityNonceV1 {
        self.capability.nonce()
    }

    /// Returns the verified issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.capability.issued_at_ms()
    }

    /// Returns the verified expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.capability.expires_at_ms()
    }

    /// Returns the verified issuer signing-key identifier.
    pub fn issuer_key_id(&self) -> &str {
        self.capability.issuer_key_id()
    }

    /// Returns the exact canonical signed capability bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed capability bytes.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Consumes this token into the exact canonical signed capability bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    /// Requires the capability to be within its inclusive issue-to-expiry window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.issued_at_ms() || now_ms > self.expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root creation capability is outside its freshness window",
            ));
        }
        Ok(())
    }
}

fn validate_data(data: &TenantRootCreationCapabilityDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root creation capability signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(
    data: &TenantRootCreationCapabilityDataV1,
) -> RouterAbDerivationResult<()> {
    if data.expected_revision != TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1 {
        return Err(malformed(
            "tenant-root creation capability expected revision must be one",
        ));
    }
    require_tenant_root_identifier(
        "tenant-root creation capability issuer key id",
        &data.issuer_key_id,
    )?;
    if data.issuer_key_id.len() > TENANT_ROOT_CREATION_CAPABILITY_ISSUER_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root creation capability issuer key id is too long",
        ));
    }
    if data.issued_at_ms == 0 || data.expires_at_ms <= data.issued_at_ms {
        return Err(malformed(
            "tenant-root creation capability expiry must follow a non-zero issue time",
        ));
    }
    if data.expires_at_ms - data.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root creation capability lifetime exceeds the frozen maximum window",
        ));
    }
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootCreationCapabilityDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    validate_unsigned_data(data)?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_CREATION_CAPABILITY_DOMAIN_V1)?;
    push_field(&mut bytes, TENANT_ROOT_CREATION_OPERATION_V1)?;
    push_field(&mut bytes, data.identity_digest.as_bytes())?;
    push_field(&mut bytes, data.custody_lineage.as_bytes())?;
    push_field(&mut bytes, data.started_journal_digest.as_bytes())?;
    push_field(&mut bytes, &data.expected_revision.to_be_bytes())?;
    push_field(&mut bytes, data.authority_id.as_bytes())?;
    push_field(&mut bytes, data.nonce.as_bytes())?;
    push_field(&mut bytes, &data.issued_at_ms.to_be_bytes())?;
    push_field(&mut bytes, &data.expires_at_ms.to_be_bytes())?;
    push_field(&mut bytes, data.issuer_key_id.as_bytes())?;
    Ok(bytes)
}

fn canonical_bytes_from_unsigned(
    unsigned: Vec<u8>,
    signature: &[u8; 64],
) -> RouterAbDerivationResult<Vec<u8>> {
    if signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root creation capability signature must be nonzero",
        ));
    }
    let mut bytes = unsigned;
    push_field(&mut bytes, signature)?;
    Ok(bytes)
}

fn authentication_input(issuer_key_id: &str, unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier(
        "tenant-root creation capability issuer key id",
        issuer_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_CREATION_CAPABILITY_AUTH_DOMAIN_V1)?;
    push_field(&mut bytes, issuer_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root creation capability field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root creation capability field is too long"))?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root creation capability wire length overflows"))?;
    if new_len > TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root creation capability wire is too long",
        ));
    }
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn malformed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn replay_mismatch(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::ReplayMismatch, message)
}

fn verification_failed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}

struct CreationCapabilityWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CreationCapabilityWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root creation capability offset overflows"))?;
        let length_bytes = self.bytes.get(self.offset..length_end).ok_or_else(|| {
            malformed("tenant-root creation capability field length is truncated")
        })?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte creation capability field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root creation capability field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root creation capability field is truncated"))?;
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
        if self.field("tenant-root creation capability domain")? != expected {
            return Err(malformed(
                "tenant-root creation capability domain is invalid",
            ));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root creation capability fixed field length is invalid"))
    }

    fn u64_field(&mut self, name: &'static str) -> RouterAbDerivationResult<u64> {
        Ok(u64::from_be_bytes(self.fixed_field::<8>(name)?))
    }

    fn text_field(
        &mut self,
        name: &'static str,
        max_bytes: usize,
    ) -> RouterAbDerivationResult<String> {
        let bytes = self.field(name)?;
        if bytes.len() > max_bytes {
            return Err(malformed(
                "tenant-root creation capability text field is too long",
            ));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root creation capability text field is invalid UTF-8"))
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root creation capability wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
