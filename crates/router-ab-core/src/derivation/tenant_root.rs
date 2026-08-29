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

    /// Returns the SHA-256 digest of the exact canonical identity bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootIdentityDigestV1> {
        Ok(TenantRootIdentityDigestV1(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        require_identity_field("orgId", &self.org_id)?;
        require_identity_field("projectId", &self.project_id)?;
        require_identity_field("envId", &self.env_id)?;
        require_identity_field("signingRootId", &self.signing_root_id)?;
        require_identity_field("signingRootVersion", &self.signing_root_version)
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

fn require_identity_field(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    u32::try_from(value.len()).map_err(|_| malformed("tenant root identity field is too long"))?;
    Ok(())
}

fn push_len32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant root identity field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
