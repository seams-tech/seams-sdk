use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, StableTenantDerivationContextV2, TenantRootActiveRefreshV1,
    TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootProtocolDigestV1, TenantRootShareEpoch,
    VerifiedTenantRootSignedActivationReceiptV1, TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1,
    TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_CUSTODY_BINDING_DOMAIN_V1: &[u8] = b"seams/tenant-root-custody-binding/v1";
const TENANT_ROOT_DERIVATION_ID_LEN: usize = 16;
const TENANT_ROOT_DERIVATION_NONCE_LEN: usize = 32;

/// Router-issued identifier for one admitted tenant-root derivation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootDerivationOperationIdV1([u8; TENANT_ROOT_DERIVATION_ID_LEN]);

impl TenantRootDerivationOperationIdV1 {
    /// Parses one exact non-zero 128-bit operation identifier.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_DERIVATION_ID_LEN],
    ) -> RouterAbDerivationResult<Self> {
        require_nonzero(
            &bytes,
            "tenant-root derivation operation id must be non-zero",
        )?;
        Ok(Self(bytes))
    }

    /// Returns the exact identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_DERIVATION_ID_LEN] {
        &self.0
    }
}

impl Serialize for TenantRootDerivationOperationIdV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for TenantRootDerivationOperationIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_bytes(decode_fixed_b64u(
            &value,
            "tenant-root derivation operation id",
        )?)
        .map_err(D::Error::custom)
    }
}

/// Router-issued one-use session identifier for a derivation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootDerivationSessionIdV1([u8; TENANT_ROOT_DERIVATION_ID_LEN]);

impl TenantRootDerivationSessionIdV1 {
    /// Parses one exact non-zero 128-bit derivation session identifier.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_DERIVATION_ID_LEN],
    ) -> RouterAbDerivationResult<Self> {
        require_nonzero(&bytes, "tenant-root derivation session id must be non-zero")?;
        Ok(Self(bytes))
    }

    /// Returns the exact identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_DERIVATION_ID_LEN] {
        &self.0
    }
}

impl Serialize for TenantRootDerivationSessionIdV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for TenantRootDerivationSessionIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_bytes(decode_fixed_b64u(
            &value,
            "tenant-root derivation session id",
        )?)
        .map_err(D::Error::custom)
    }
}

/// Router-issued replay nonce for one tenant-root derivation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootDerivationNonceV1([u8; TENANT_ROOT_DERIVATION_NONCE_LEN]);

impl TenantRootDerivationNonceV1 {
    /// Parses one exact non-zero 256-bit replay nonce.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_DERIVATION_NONCE_LEN],
    ) -> RouterAbDerivationResult<Self> {
        require_nonzero(&bytes, "tenant-root derivation nonce must be non-zero")?;
        Ok(Self(bytes))
    }

    /// Returns the exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_DERIVATION_NONCE_LEN] {
        &self.0
    }
}

impl Serialize for TenantRootDerivationNonceV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for TenantRootDerivationNonceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_bytes(decode_fixed_b64u(&value, "tenant-root derivation nonce")?)
            .map_err(D::Error::custom)
    }
}

/// Exact authenticated Deriver identities accepting the custody binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeriverIdentitiesV1 {
    deriver_a: String,
    deriver_b: String,
}

impl TenantRootDeriverIdentitiesV1 {
    /// Creates an exact distinct A/B identity pair.
    pub fn new(
        deriver_a: impl Into<String>,
        deriver_b: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let identities = Self {
            deriver_a: deriver_a.into(),
            deriver_b: deriver_b.into(),
        };
        require_tenant_root_identifier("tenant-root Deriver A identity", &identities.deriver_a)?;
        require_tenant_root_identifier("tenant-root Deriver B identity", &identities.deriver_b)?;
        if identities.deriver_a == identities.deriver_b {
            return Err(malformed("tenant-root Deriver identities must be distinct"));
        }
        Ok(identities)
    }

    /// Returns Deriver A's exact authenticated identity.
    pub fn deriver_a(&self) -> &str {
        &self.deriver_a
    }

    /// Returns Deriver B's exact authenticated identity.
    pub fn deriver_b(&self) -> &str {
        &self.deriver_b
    }
}

/// Epoch-bound public custody record kept separate from stable derivation bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCustodyBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    derivers: TenantRootDeriverIdentitiesV1,
    commitments: TenantRootEpochCommitmentsV1,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    operation_id: TenantRootDerivationOperationIdV1,
    session_id: TenantRootDerivationSessionIdV1,
    nonce: TenantRootDerivationNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    stable_context_digest: TenantRootProtocolDigestV1,
    outer_transcript_digest: TenantRootProtocolDigestV1,
}

impl TenantRootCustodyBindingV1 {
    /// Binds one stable active epoch to an admitted derivation operation.
    #[allow(clippy::too_many_arguments)]
    pub fn from_active(
        active: &TenantRootActiveRefreshV1,
        derivers: TenantRootDeriverIdentitiesV1,
        operation_id: TenantRootDerivationOperationIdV1,
        session_id: TenantRootDerivationSessionIdV1,
        nonce: TenantRootDerivationNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        stable_context: &StableTenantDerivationContextV2,
        outer_transcript_digest: TenantRootProtocolDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest: active.identity().digest()?,
            custody_lineage: active.custody_lineage(),
            epoch: active.current().epoch(),
            derivers,
            commitments: active.current().verified().commitments().clone(),
            activation_receipt_digest: active.current().activation_receipt_digest(),
            operation_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            stable_context_digest: stable_context.digest()?,
            outer_transcript_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Binds the active epoch authenticated by one issuer-verified activation receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_activation_receipt(
        activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
        derivers: TenantRootDeriverIdentitiesV1,
        operation_id: TenantRootDerivationOperationIdV1,
        session_id: TenantRootDerivationSessionIdV1,
        nonce: TenantRootDerivationNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        stable_context: &StableTenantDerivationContextV2,
        outer_transcript_digest: TenantRootProtocolDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        Self::from_verified_activation_receipt_with_stable_context_digest(
            activation_receipt,
            derivers,
            operation_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            stable_context.digest()?,
            outer_transcript_digest,
        )
    }

    /// Binds an active epoch to a protocol-specific stable-context digest.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_activation_receipt_with_stable_context_digest(
        activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
        derivers: TenantRootDeriverIdentitiesV1,
        operation_id: TenantRootDerivationOperationIdV1,
        session_id: TenantRootDerivationSessionIdV1,
        nonce: TenantRootDerivationNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        stable_context_digest: TenantRootProtocolDigestV1,
        outer_transcript_digest: TenantRootProtocolDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        let (identity_digest, custody_lineage, epoch, commitments) =
            match activation_receipt.binding() {
                super::TenantRootActivationReceiptBindingV1::InitialCreation(binding) => (
                    binding.identity_digest(),
                    binding.custody_lineage(),
                    binding.epoch(),
                    binding.commitments().clone(),
                ),
                super::TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => (
                    binding.identity_digest(),
                    binding.custody_lineage(),
                    binding.next_epoch(),
                    binding.next_commitments().clone(),
                ),
            };
        let binding = Self {
            identity_digest,
            custody_lineage,
            epoch,
            derivers,
            commitments,
            activation_receipt_digest: activation_receipt.digest(),
            operation_id,
            session_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            stable_context_digest,
            outer_transcript_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates exact identities, lifetime, and commitments.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_tenant_root_identifier(
            "tenant-root Deriver A identity",
            self.derivers.deriver_a(),
        )?;
        require_tenant_root_identifier(
            "tenant-root Deriver B identity",
            self.derivers.deriver_b(),
        )?;
        if self.derivers.deriver_a() == self.derivers.deriver_b() {
            return Err(malformed("tenant-root Deriver identities must be distinct"));
        }
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(malformed(
                "tenant-root custody binding expiry must follow a non-zero issue time",
            ));
        }
        if self.expires_at_ms - self.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
            return Err(malformed(
                "tenant-root custody binding lifetime exceeds the frozen maximum window",
            ));
        }
        TenantRootEpochCommitmentsV1::new(
            self.commitments.deriver_a().clone(),
            self.commitments.deriver_b().clone(),
        )?;
        Ok(())
    }

    /// Applies the frozen 60-second clock-skew allowance.
    pub fn validate_at(&self, peer_now_ms: u64) -> RouterAbDerivationResult<()> {
        self.validate()?;
        if self.issued_at_ms > peer_now_ms.saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1)
            || peer_now_ms
                > self
                    .expires_at_ms
                    .saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1)
        {
            return Err(malformed(
                "tenant-root custody binding is outside the allowed clock-skew window",
            ));
        }
        Ok(())
    }

    /// Returns the identity digest selected by the control plane.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the custody lineage selected by the control plane.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact epoch selected by the control plane.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the exact A/B commitments selected by the control plane.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    /// Returns the stable public root commitment selected by the control plane.
    pub const fn root_commitment(&self) -> &[u8; 32] {
        self.commitments.root_commitment()
    }

    /// Returns the activation receipt accepted for this active epoch.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.activation_receipt_digest
    }

    /// Returns the stable-context digest without exposing custody metadata as context bytes.
    pub const fn stable_context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.stable_context_digest
    }

    /// Returns the exact canonical custody bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_field(&mut bytes, TENANT_ROOT_CUSTODY_BINDING_DOMAIN_V1)?;
        push_field(&mut bytes, self.identity_digest.as_bytes())?;
        push_field(&mut bytes, self.custody_lineage.as_bytes())?;
        push_field(&mut bytes, &self.epoch.get().get().to_be_bytes())?;
        push_field(&mut bytes, self.derivers.deriver_a().as_bytes())?;
        push_field(&mut bytes, self.derivers.deriver_b().as_bytes())?;
        push_field(&mut bytes, self.commitments.deriver_a().as_bytes())?;
        push_field(&mut bytes, self.commitments.deriver_b().as_bytes())?;
        push_field(&mut bytes, self.commitments.root_commitment())?;
        push_field(&mut bytes, self.activation_receipt_digest.as_bytes())?;
        push_field(&mut bytes, self.operation_id.as_bytes())?;
        push_field(&mut bytes, self.session_id.as_bytes())?;
        push_field(&mut bytes, self.nonce.as_bytes())?;
        push_field(&mut bytes, &self.issued_at_ms.to_be_bytes())?;
        push_field(&mut bytes, &self.expires_at_ms.to_be_bytes())?;
        push_field(&mut bytes, self.stable_context_digest.as_bytes())?;
        push_field(&mut bytes, self.outer_transcript_digest.as_bytes())?;
        Ok(bytes)
    }

    /// Returns the SHA-256 digest of the exact epoch-bound custody record.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }
}

fn decode_fixed_b64u<const N: usize, E>(value: &str, field: &'static str) -> Result<[u8; N], E>
where
    E: DeError,
{
    let mut bytes = [0_u8; N];
    let decoded = Base64UrlUnpadded::decode(value, &mut bytes)
        .map_err(|_| E::custom(format!("{field} is invalid base64url")))?;
    if decoded.len() != N || Base64UrlUnpadded::encode_string(decoded) != value {
        return Err(E::custom(format!("{field} is not canonical base64url")));
    }
    Ok(bytes)
}

fn require_nonzero(bytes: &[u8], message: &'static str) -> RouterAbDerivationResult<()> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(malformed(message))
    } else {
        Ok(())
    }
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root custody binding field is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
