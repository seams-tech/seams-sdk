use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::PublicDigest32;

const CONTEXT_VERSION: &[u8] = b"router-ab-derivation/context/v1";
const CONTEXT_DIGEST_VERSION: &[u8] = b"router-ab-derivation/context-digest/v1";

/// Candidate derivation family under evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateId {
    /// Two signers evaluate a threshold PRF and combine output shares.
    MpcThresholdPrfV1,
}

impl CandidateId {
    /// Returns the canonical candidate label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MpcThresholdPrfV1 => "mpc_threshold_prf_v1",
        }
    }
}

/// Router/A/B derivation request kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// Initial account registration.
    Registration,
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
            Self::Export => "export",
            Self::Refresh => "refresh",
        }
    }
}

/// Output correctness level required by the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrectnessLevel {
    /// Minimum Level C: transcript-bound server blindness with no public share relation check.
    MinimumLevelC,
    /// Later hardening path that binds public verifying shares.
    PublicShareBindingV1,
}

impl CorrectnessLevel {
    /// Returns the canonical correctness label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinimumLevelC => "minimum_level_c",
            Self::PublicShareBindingV1 => "public_share_binding_v1",
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

/// Canonical derivation context shared by all candidate families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DerivationContext {
    /// Candidate family being evaluated.
    candidate_id: CandidateId,
    /// Request kind for this derivation ceremony.
    request_kind: RequestKind,
    /// Output correctness level for this ceremony.
    correctness_level: CorrectnessLevel,
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
        candidate_id: CandidateId,
        request_kind: RequestKind,
        correctness_level: CorrectnessLevel,
        account_scope: AccountScope,
        root_share_epoch: RootShareEpoch,
        ceremony_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let context = Self {
            candidate_id,
            request_kind,
            correctness_level,
            account_scope,
            root_share_epoch,
            ceremony_id: ceremony_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Candidate family.
    pub fn candidate_id(&self) -> CandidateId {
        self.candidate_id
    }

    /// Request kind.
    pub fn request_kind(&self) -> RequestKind {
        self.request_kind
    }

    /// Correctness level.
    pub fn correctness_level(&self) -> CorrectnessLevel {
        self.correctness_level
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
        push_field(&mut out, self.candidate_id.as_str().as_bytes());
        push_field(&mut out, self.request_kind.as_str().as_bytes());
        push_field(&mut out, self.correctness_level.as_str().as_bytes());
        push_field(&mut out, self.account_scope.network_id.as_bytes());
        push_field(&mut out, self.account_scope.account_id.as_bytes());
        push_field(&mut out, self.account_scope.account_public_key.as_bytes());
        push_field(&mut out, self.root_share_epoch.as_str().as_bytes());
        push_field(&mut out, self.ceremony_id.as_bytes());
        Ok(out)
    }

    /// Computes the context digest specified by `encoding-and-transcript.md`.
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
        struct Wire {
            candidate_id: CandidateId,
            request_kind: RequestKind,
            correctness_level: CorrectnessLevel,
            account_scope: AccountScope,
            root_share_epoch: RootShareEpoch,
            ceremony_id: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.candidate_id,
            wire.request_kind,
            wire.correctness_level,
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
