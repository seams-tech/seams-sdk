use core::{fmt, num::NonZeroU64};

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{CryptoRng, RngCore};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};

const TENANT_ROOT_IDENTITY_DOMAIN_V1: &[u8] = b"seams/tenant-root-identity/v1";
const TENANT_ROOT_LINEAGE_BYTES: usize = 16;
const TENANT_ROOT_MAX_IDENTIFIER_BYTES_V1: usize = 256;
const TENANT_ROOT_IDENTITY_MAX_WIRE_BYTES_V1: usize =
    TENANT_ROOT_IDENTITY_DOMAIN_V1.len() + 5 * (4 + TENANT_ROOT_MAX_IDENTIFIER_BYTES_V1);

/// Frozen peer clock-skew allowance for every tenant-root ceremony and custody binding.
pub const TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1: u64 = 60_000;

/// Frozen maximum issue-to-expiry window for every tenant-root ceremony and custody binding.
pub const TENANT_ROOT_MAX_LIFETIME_MS_V1: u64 = 300_000;

/// Canonical server-resolved identity for one logical tenant derivation root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootIdentityV1 {
    org_id: String,
    project_id: String,
    env_id: String,
    signing_root_id: String,
    signing_root_version: String,
}

impl TenantRootIdentityV1 {
    /// Creates one exact server-resolved tenant-root identity.
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        env_id: impl Into<String>,
        signing_root_id: impl Into<String>,
        signing_root_version: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let identity = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            env_id: env_id.into(),
            signing_root_id: signing_root_id.into(),
            signing_root_version: signing_root_version.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Returns the organization identifier bytes exactly as resolved.
    pub fn org_id(&self) -> &str {
        &self.org_id
    }

    /// Returns the project identifier bytes exactly as resolved.
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Returns the environment identifier bytes exactly as resolved.
    pub fn env_id(&self) -> &str {
        &self.env_id
    }

    /// Returns the persisted signing-root identifier.
    pub fn signing_root_id(&self) -> &str {
        &self.signing_root_id
    }

    /// Returns the persisted signing-root version.
    pub fn signing_root_version(&self) -> &str {
        &self.signing_root_version
    }

    /// Returns the exact canonical identity bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let fields = [
            self.org_id.as_bytes(),
            self.project_id.as_bytes(),
            self.env_id.as_bytes(),
            self.signing_root_id.as_bytes(),
            self.signing_root_version.as_bytes(),
        ];
        let mut bytes = Vec::with_capacity(
            TENANT_ROOT_IDENTITY_DOMAIN_V1.len()
                + fields.iter().map(|field| field.len() + 4).sum::<usize>(),
        );
        bytes.extend_from_slice(TENANT_ROOT_IDENTITY_DOMAIN_V1);
        for field in fields {
            push_len32(&mut bytes, field)?;
        }
        Ok(bytes)
    }

    /// Parses one exact canonical identity wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_IDENTITY_MAX_WIRE_BYTES_V1 {
            return Err(malformed("tenant root identity wire length is invalid"));
        }
        let mut decoder = TenantRootIdentityWireDecoderV1::new(bytes)?;
        let org_id = decoder.text_field("orgId")?;
        let project_id = decoder.text_field("projectId")?;
        let env_id = decoder.text_field("envId")?;
        let signing_root_id = decoder.text_field("signingRootId")?;
        let signing_root_version = decoder.text_field("signingRootVersion")?;
        decoder.finish()?;
        let identity = Self::new(
            org_id,
            project_id,
            env_id,
            signing_root_id,
            signing_root_version,
        )?;
        if identity.canonical_bytes()? != bytes {
            return Err(malformed("tenant root identity wire is not canonical"));
        }
        Ok(identity)
    }

    /// Returns the SHA-256 digest of the exact canonical identity bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootIdentityDigestV1> {
        Ok(TenantRootIdentityDigestV1(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        require_tenant_root_identifier("orgId", &self.org_id)?;
        require_tenant_root_identifier("projectId", &self.project_id)?;
        require_tenant_root_identifier("envId", &self.env_id)?;
        require_tenant_root_identifier("signingRootId", &self.signing_root_id)?;
        require_tenant_root_identifier("signingRootVersion", &self.signing_root_version)
    }
}

impl<'de> Deserialize<'de> for TenantRootIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            org_id: String,
            project_id: String,
            env_id: String,
            signing_root_id: String,
            signing_root_version: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        TenantRootIdentityV1::new(
            wire.org_id,
            wire.project_id,
            wire.env_id,
            wire.signing_root_id,
            wire.signing_root_version,
        )
        .map_err(D::Error::custom)
    }
}

/// Public SHA-256 digest that identifies one logical tenant derivation root.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRootIdentityDigestV1([u8; 32]);

impl TenantRootIdentityDigestV1 {
    /// Parses an exact 32-byte identity digest.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a copy of the exact digest bytes.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for TenantRootIdentityDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootIdentityDigestV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Random public identifier for one deployment's custody of a logical tenant root.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootCustodyLineageId([u8; TENANT_ROOT_LINEAGE_BYTES]);

impl TenantRootCustodyLineageId {
    /// Creates a non-zero custody-lineage identifier from exact random bytes.
    pub fn from_bytes(bytes: [u8; TENANT_ROOT_LINEAGE_BYTES]) -> RouterAbDerivationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(malformed("tenant root custody lineage must be non-zero"));
        }
        Ok(Self(bytes))
    }

    /// Samples a fresh non-zero custody-lineage identifier.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_LINEAGE_BYTES];
            rng.fill_bytes(&mut bytes);
            if let Ok(lineage) = Self::from_bytes(bytes) {
                return lineage;
            }
        }
    }

    /// Parses the exact unpadded base64url boundary encoding.
    pub fn from_base64url(value: &str) -> RouterAbDerivationResult<Self> {
        let mut bytes = [0_u8; TENANT_ROOT_LINEAGE_BYTES];
        let decoded = Base64UrlUnpadded::decode(value, &mut bytes)
            .map_err(|_| malformed("tenant root custody lineage is invalid base64url"))?;
        if decoded.len() != TENANT_ROOT_LINEAGE_BYTES
            || Base64UrlUnpadded::encode_string(decoded) != value
        {
            return Err(malformed(
                "tenant root custody lineage is not canonical base64url",
            ));
        }
        Self::from_bytes(bytes)
    }

    /// Returns the exact unpadded base64url boundary encoding.
    pub fn to_base64url(self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }

    /// Returns the exact 128-bit lineage identifier.
    pub fn as_bytes(&self) -> &[u8; TENANT_ROOT_LINEAGE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TenantRootCustodyLineageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootCustodyLineageId")
            .field(&self.to_base64url())
            .finish()
    }
}

impl Serialize for TenantRootCustodyLineageId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for TenantRootCustodyLineageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_base64url(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Monotonic non-zero custody epoch for one tenant-root lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TenantRootShareEpoch(NonZeroU64);

impl TenantRootShareEpoch {
    /// The first active epoch in a fresh custody lineage.
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    /// Parses one positive custody epoch.
    pub fn new(value: u64) -> RouterAbDerivationResult<Self> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| malformed("tenant root share epoch must be positive"))
    }

    /// Returns the positive epoch value.
    pub fn get(self) -> NonZeroU64 {
        self.0
    }

    /// Returns the exact next epoch, rejecting `u64` exhaustion.
    pub fn next(self) -> RouterAbDerivationResult<Self> {
        self.0
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
            .ok_or_else(|| malformed("tenant root share epoch is exhausted"))
    }
}

impl<'de> Deserialize<'de> for TenantRootShareEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Validates one tenant-root boundary identifier.
///
/// Every tenant-root identity field, role signing-key id, and Deriver deployment
/// identity uses these exact rules: non-empty, no leading or trailing whitespace,
/// no control characters, and at most 256 UTF-8 bytes. Canonicalization never
/// happens here; a non-canonical raw input fails instead.
pub(crate) fn require_tenant_root_identifier(
    field: &'static str,
    value: &str,
) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    if value.len() > TENANT_ROOT_MAX_IDENTIFIER_BYTES_V1 {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} exceeds {TENANT_ROOT_MAX_IDENTIFIER_BYTES_V1} UTF-8 bytes"),
        ));
    }
    if value.trim() != value {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} has leading or trailing whitespace"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} contains control characters"),
        ));
    }
    Ok(())
}

fn push_len32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant root identity field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct TenantRootIdentityWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TenantRootIdentityWireDecoderV1<'a> {
    fn new(bytes: &'a [u8]) -> RouterAbDerivationResult<Self> {
        if !bytes.starts_with(TENANT_ROOT_IDENTITY_DOMAIN_V1) {
            return Err(malformed("tenant root identity wire domain is invalid"));
        }
        Ok(Self {
            bytes,
            offset: TENANT_ROOT_IDENTITY_DOMAIN_V1.len(),
        })
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant root identity wire offset overflow"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant root identity wire field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte tenant root identity field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant root identity wire field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant root identity wire field is truncated"))?;
        self.offset = value_end;
        if value.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                format!("{name} is required"),
            ));
        }
        Ok(value)
    }

    fn text_field(&mut self, name: &'static str) -> RouterAbDerivationResult<String> {
        let bytes = self.field(name)?;
        if bytes.len() > TENANT_ROOT_MAX_IDENTIFIER_BYTES_V1 {
            return Err(malformed(
                "tenant root identity wire text field is too long",
            ));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant root identity wire text field is invalid UTF-8"))
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed("tenant root identity wire has trailing bytes"));
        }
        Ok(())
    }
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
