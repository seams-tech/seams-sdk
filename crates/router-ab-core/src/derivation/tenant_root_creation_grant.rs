//! Authenticated authorization to create one tenant root.
//!
//! Every other R120 creation artifact is derived from authoritative state the
//! control plane can read. Genesis has none: before the Started journal exists
//! there is no Durable Object record to consult, so the authorization to create
//! a root has to arrive as an independently signed grant.
//!
//! A grant names the tenant and its custody lineage, and nothing else. The
//! issuer verifies it, then constructs the journal and creation capability
//! itself; the grant never carries a journal digest, an authority id, a
//! revision, or any field the issuer is supposed to derive. That keeps genesis
//! under the same rule as every later operation: the caller says *what* to
//! authorize, never *what to sign*.
//!
//! The signing authority is deliberately not fixed here. `verify` takes the
//! trusted verifying key from its caller, so the same type serves a
//! provisioning grant signed by an operator authority, a Gateway-signed tenant
//! assertion, or a dual-authority signature — the choice is a deployment
//! binding, not a protocol change.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootIdentityV1, TenantRootProtocolDigestV1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_CREATION_GRANT_DOMAIN_V1: &[u8] = b"tenant_root_creation_grant_v1";
const TENANT_ROOT_CREATION_GRANT_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_creation_grant_authentication_v1";
const TENANT_ROOT_CREATION_GRANT_OPERATION_V1: &[u8] = b"tenant_root_authorize_create_v1";
const TENANT_ROOT_CREATION_GRANT_NONCE_LEN_V1: usize = 32;
const TENANT_ROOT_CREATION_GRANT_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact operation authenticated by a tenant-root creation grant.
pub const TENANT_ROOT_CREATION_GRANT_OPERATION_LABEL_V1: &str = "tenant_root_authorize_create_v1";

/// Maximum canonical wire size accepted for one creation grant.
pub const TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1: usize = 16 * 1024;

/// One-use nonce binding a creation grant to a single authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantRootCreationGrantNonceV1([u8; TENANT_ROOT_CREATION_GRANT_NONCE_LEN_V1]);

impl TenantRootCreationGrantNonceV1 {
    /// Creates a nonce, rejecting the all-zero value.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_CREATION_GRANT_NONCE_LEN_V1],
    ) -> RouterAbDerivationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root creation grant nonce must be nonzero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Draws a fresh nonce.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_CREATION_GRANT_NONCE_LEN_V1];
            rng.fill_bytes(&mut bytes);
            if let Ok(nonce) = Self::from_bytes(bytes) {
                return nonce;
            }
        }
    }

    /// Returns the exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_CREATION_GRANT_NONCE_LEN_V1] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TenantRootCreationGrantDataV1 {
    /// The exact canonical identity preimage. The issuer builds the Started
    /// journal from this, so the grant carries the identity itself rather than
    /// only its digest.
    identity_canonical_bytes: Vec<u8>,
    custody_lineage: TenantRootCustodyLineageId,
    nonce: TenantRootCreationGrantNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    grant_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootCreationGrantDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootCreationGrantDataV1")
            .field("custody_lineage", &self.custody_lineage)
            .field("nonce", &self.nonce)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("grant_key_id", &self.grant_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// A signed creation grant before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootCreationGrantV1 {
    data: TenantRootCreationGrantDataV1,
}

impl TenantRootCreationGrantV1 {
    /// Signs one exact creation grant.
    pub fn sign(
        identity: &TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
        nonce: TenantRootCreationGrantNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        grant_key_id: impl Into<String>,
        grant_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let mut data = TenantRootCreationGrantDataV1 {
            identity_canonical_bytes: identity.canonical_bytes()?,
            custody_lineage,
            nonce,
            issued_at_ms,
            expires_at_ms,
            grant_key_id: grant_key_id.into(),
            signature: [0; 64],
        };
        validate_unsigned_data(&data)?;
        let unsigned = unsigned_canonical_bytes(&data)?;
        data.signature = SigningKey::from_bytes(grant_signing_key_bytes)
            .sign(&authentication_input(&data.grant_key_id, &unsigned)?)
            .to_bytes();
        validate_data(&data)?;
        let grant = Self { data };
        grant.canonical_bytes()?;
        Ok(grant)
    }

    /// Decodes exactly one canonical signed grant wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root creation grant wire length is invalid",
            ));
        }
        let mut decoder = CreationGrantWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_CREATION_GRANT_DOMAIN_V1)?;
        if decoder.field("tenant-root creation grant operation")?
            != TENANT_ROOT_CREATION_GRANT_OPERATION_V1
        {
            return Err(malformed("tenant-root creation grant operation is invalid"));
        }
        let identity_canonical_bytes = decoder
            .field("tenant-root creation grant identity")?
            .to_vec();
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root creation grant custody lineage")?,
        )?;
        let nonce = TenantRootCreationGrantNonceV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root creation grant nonce")?,
        )?;
        let issued_at_ms = decoder.u64_field("tenant-root creation grant issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root creation grant expiry")?;
        let grant_key_id = decoder.text_field(
            "tenant-root creation grant key id",
            TENANT_ROOT_CREATION_GRANT_KEY_ID_MAX_BYTES_V1,
        )?;
        let signature = decoder.fixed_field::<64>("tenant-root creation grant signature")?;
        decoder.finish()?;
        let data = TenantRootCreationGrantDataV1 {
            identity_canonical_bytes,
            custody_lineage,
            nonce,
            issued_at_ms,
            expires_at_ms,
            grant_key_id,
            signature,
        };
        validate_data(&data)?;
        let grant = Self { data };
        // Re-encode and compare so a decoded grant is byte-exact.
        if grant.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root creation grant wire is not canonical",
            ));
        }
        Ok(grant)
    }

    /// Returns the key id that signed this grant.
    pub fn grant_key_id(&self) -> &str {
        &self.data.grant_key_id
    }

    /// Returns the exact canonical signed grant bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        canonical_bytes_from_unsigned(unsigned, &self.data.signature)
    }

    /// Returns the digest of the exact canonical signed grant bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Verifies this grant under a caller-supplied trusted authority.
    ///
    /// `expected_grant_key_id` and `trusted_grant_verifying_key` are the
    /// verifier's own configuration. Nothing about who may authorize a tenant
    /// root is decided here: a verifier that reads its expected key id from the
    /// grant it is checking has verified nothing.
    pub fn verify(
        &self,
        expected_grant_key_id: &str,
        trusted_grant_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootCreationGrantV1> {
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root creation grant expected key id",
            expected_grant_key_id,
        )?;
        if self.data.grant_key_id != expected_grant_key_id {
            return Err(replay_mismatch(
                "tenant-root creation grant key id does not match its expected authority",
            ));
        }
        let verifying_key =
            VerifyingKey::from_bytes(trusted_grant_verifying_key).map_err(|_| {
                verification_failed("tenant-root creation grant authority key is invalid")
            })?;
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.grant_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| verification_failed("tenant-root creation grant signature is invalid"))?;
        // The identity preimage must decode to exactly the bytes it arrived as,
        // so a grant cannot authorize one tenant while encoding another.
        let identity =
            TenantRootIdentityV1::decode_canonical_bytes(&self.data.identity_canonical_bytes)?;
        if identity.canonical_bytes()? != self.data.identity_canonical_bytes {
            return Err(malformed(
                "tenant-root creation grant identity encoding is not canonical",
            ));
        }
        Ok(VerifiedTenantRootCreationGrantV1 {
            identity_digest: identity.digest()?,
            identity,
            custody_lineage: self.data.custody_lineage,
            nonce: self.data.nonce,
            issued_at_ms: self.data.issued_at_ms,
            expires_at_ms: self.data.expires_at_ms,
            grant_key_id: self.data.grant_key_id.clone(),
        })
    }
}

/// An authenticated creation grant.
///
/// Holding this value proves the grant verified under a caller-supplied
/// authority. It is not `Clone`: it is an authorization, not a record.
#[derive(Debug)]
pub struct VerifiedTenantRootCreationGrantV1 {
    identity: TenantRootIdentityV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    nonce: TenantRootCreationGrantNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    grant_key_id: String,
}

impl VerifiedTenantRootCreationGrantV1 {
    /// Returns the authorized tenant identity.
    pub const fn identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the authorized tenant identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the authorized custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the one-use nonce.
    pub const fn nonce(&self) -> TenantRootCreationGrantNonceV1 {
        self.nonce
    }

    /// Returns the key id that signed this grant.
    pub fn grant_key_id(&self) -> &str {
        &self.grant_key_id
    }

    /// Returns the authorization issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the authorization expiry.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Requires `now_ms` to fall inside the authorized window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms <= self.issued_at_ms || now_ms >= self.expires_at_ms {
            return Err(malformed(
                "tenant-root creation grant is outside its freshness window",
            ));
        }
        Ok(())
    }
}

fn validate_data(data: &TenantRootCreationGrantDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root creation grant signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(data: &TenantRootCreationGrantDataV1) -> RouterAbDerivationResult<()> {
    if data.issued_at_ms == 0 || data.expires_at_ms <= data.issued_at_ms {
        return Err(malformed(
            "tenant-root creation grant expiry must follow a non-zero issue time",
        ));
    }
    if data.expires_at_ms - data.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root creation grant lifetime exceeds the frozen maximum window",
        ));
    }
    require_tenant_root_identifier("tenant-root creation grant key id", &data.grant_key_id)?;
    if data.grant_key_id.len() > TENANT_ROOT_CREATION_GRANT_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed("tenant-root creation grant key id is too long"));
    }
    if data.identity_canonical_bytes.is_empty() {
        return Err(malformed("tenant-root creation grant identity is required"));
    }
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootCreationGrantDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_CREATION_GRANT_DOMAIN_V1)?;
    push_field(&mut bytes, TENANT_ROOT_CREATION_GRANT_OPERATION_V1)?;
    push_field(&mut bytes, &data.identity_canonical_bytes)?;
    push_field(&mut bytes, data.custody_lineage.as_bytes())?;
    push_field(&mut bytes, data.nonce.as_bytes())?;
    push_field(&mut bytes, &data.issued_at_ms.to_be_bytes())?;
    push_field(&mut bytes, &data.expires_at_ms.to_be_bytes())?;
    push_field(&mut bytes, data.grant_key_id.as_bytes())?;
    Ok(bytes)
}

fn canonical_bytes_from_unsigned(
    mut unsigned: Vec<u8>,
    signature: &[u8; 64],
) -> RouterAbDerivationResult<Vec<u8>> {
    push_field(&mut unsigned, signature)?;
    Ok(unsigned)
}

fn authentication_input(grant_key_id: &str, unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier("tenant-root creation grant key id", grant_key_id)?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_CREATION_GRANT_AUTH_DOMAIN_V1)?;
    push_field(&mut bytes, grant_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root creation grant field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root creation grant field is too long"))?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root creation grant wire length overflows"))?;
    if new_len > TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1 {
        return Err(malformed("tenant-root creation grant wire is too long"));
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

struct CreationGrantWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CreationGrantWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root creation grant wire offset overflows"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root creation grant field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte creation grant field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root creation grant field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root creation grant field is truncated"))?;
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
        if self.field("tenant-root creation grant domain")? != expected {
            return Err(malformed("tenant-root creation grant domain is invalid"));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root creation grant fixed field length is invalid"))
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
                "tenant-root creation grant text field is too long",
            ));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root creation grant text field is invalid UTF-8"))
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root creation grant wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
