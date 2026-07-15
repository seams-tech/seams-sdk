use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::PublicDigest32;

const CONTEXT_VERSION: &[u8] = b"router-ab-ecdsa-threshold-prf/context/v1";
const CONTEXT_DIGEST_VERSION: &[u8] = b"router-ab-ecdsa-threshold-prf/context-digest/v1";

/// Router/A/B derivation request kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// Initial account registration.
    Registration,
    /// Same-root account recovery ceremony.
    Recovery,
    /// Client or server export ceremony.
    Export,
    /// Root or role-share refresh ceremony.
    Refresh,
}

impl RequestKind {
    /// Returns the canonical request-kind label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Recovery => "recovery",
            Self::Export => "export",
            Self::Refresh => "refresh",
        }
    }
}

/// Monotonic epoch label for A/B root-share material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootShareEpoch(String);

impl RootShareEpoch {
    /// Creates a new root-share epoch.
    pub fn new(value: impl Into<String>) -> RouterAbDerivationResult<Self> {
        let value = value.into();
        require_non_empty("root_share_epoch", &value)?;
        Ok(Self(value))
    }

    /// Returns the epoch string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RootShareEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Account-scoped identity bound into a derivation ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountScope {
    /// Network namespace, such as `near-mainnet`.
    network_id: String,
    /// Account identifier in the target network namespace.
    account_id: String,
    /// Canonical account public key string.
    account_public_key: String,
}

impl AccountScope {
    /// Creates a validated account scope.
    pub fn new(
        network_id: impl Into<String>,
        account_id: impl Into<String>,
        account_public_key: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let scope = Self {
            network_id: network_id.into(),
            account_id: account_id.into(),
            account_public_key: account_public_key.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Network namespace.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Account identifier.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Canonical account public key.
    pub fn account_public_key(&self) -> &str {
        &self.account_public_key
    }

    /// Validates required account-scope fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("network_id", &self.network_id)?;
        require_non_empty("account_id", &self.account_id)?;
        require_non_empty("account_public_key", &self.account_public_key)?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AccountScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            network_id: String,
            account_id: String,
            account_public_key: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.network_id, wire.account_id, wire.account_public_key)
            .map_err(D::Error::custom)
    }
}

/// Canonical derivation context for the fixed ECDSA threshold-PRF construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DerivationContext {
    /// Request kind for this derivation ceremony.
    request_kind: RequestKind,
    /// Account scope bound into derived material.
    account_scope: AccountScope,
    /// Epoch of A/B root material.
    root_share_epoch: RootShareEpoch,
    /// Router-generated ceremony identifier.
    ceremony_id: String,
}

impl DerivationContext {
    /// Creates a validated derivation context.
    pub fn new(
        request_kind: RequestKind,
        account_scope: AccountScope,
        root_share_epoch: RootShareEpoch,
        ceremony_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let context = Self {
            request_kind,
            account_scope,
            root_share_epoch,
            ceremony_id: ceremony_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Request kind.
    pub fn request_kind(&self) -> RequestKind {
        self.request_kind
    }

    /// Account scope.
    pub fn account_scope(&self) -> &AccountScope {
        &self.account_scope
    }

    /// Root-share epoch.
    pub fn root_share_epoch(&self) -> &RootShareEpoch {
        &self.root_share_epoch
    }

    /// Router-generated ceremony identifier.
    pub fn ceremony_id(&self) -> &str {
        &self.ceremony_id
    }

    /// Validates required derivation-context fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        self.account_scope.validate()?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("ceremony_id", &self.ceremony_id)?;
        Ok(())
    }

    /// Encodes the context with explicit domain tags and length prefixes.
    pub fn encode_context_v1(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;

        let mut out = Vec::new();
        push_field(&mut out, CONTEXT_VERSION);
        push_field(&mut out, self.request_kind.as_str().as_bytes());
        push_field(&mut out, self.account_scope.network_id.as_bytes());
        push_field(&mut out, self.account_scope.account_id.as_bytes());
        push_field(&mut out, self.account_scope.account_public_key.as_bytes());
        push_field(&mut out, self.root_share_epoch.as_str().as_bytes());
        push_field(&mut out, self.ceremony_id.as_bytes());
        Ok(out)
    }

    /// Computes the fixed ECDSA threshold-PRF context digest.
    pub fn context_digest_v1(&self) -> RouterAbDerivationResult<PublicDigest32> {
        context_digest_v1(self)
    }
}

impl<'de> Deserialize<'de> for DerivationContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            request_kind: RequestKind,
            account_scope: AccountScope,
            root_share_epoch: RootShareEpoch,
            ceremony_id: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.request_kind,
            wire.account_scope,
            wire.root_share_epoch,
            wire.ceremony_id,
        )
        .map_err(D::Error::custom)
    }
}

/// Computes the V1 context digest.
pub fn context_digest_v1(context: &DerivationContext) -> RouterAbDerivationResult<PublicDigest32> {
    let context_bytes = context.encode_context_v1()?;
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, CONTEXT_DIGEST_VERSION);
    push_hash_field(&mut hasher, &context_bytes);
    Ok(PublicDigest32::new(hasher.finalize().into()))
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u32;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}
