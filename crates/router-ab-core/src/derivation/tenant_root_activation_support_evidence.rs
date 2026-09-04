use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{
    require_tenant_root_identifier, MpcPrfShareCommitmentWireV1, RouterAbDerivationError,
    RouterAbDerivationErrorCode, RouterAbDerivationResult, TenantRootActivationReceiptTransitionV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootProtocolDigestV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootShareEpoch, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const PROVIDER_CANARY_RECEIPT_DOMAIN_V1: &[u8] = b"seams/tenant-root-provider-canary-receipt/v1";
const PROVIDER_CANARY_RECEIPT_AUTH_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-provider-canary-receipt-authentication/v1";
const ACCEPTED_LOSS_AUTHORIZATION_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-accepted-permanent-loss-authorization/v1";
const ACCEPTED_LOSS_AUTHORIZATION_AUTH_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-accepted-permanent-loss-authorization-authentication/v1";
const INITIAL_CREATION_OPERATION_V1: &[u8] = b"initial_creation";
const REFRESH_SWAP_OPERATION_V1: &[u8] = b"refresh_swap";
const ECDSA_CURVE_FAMILY_V1: &[u8] = b"ecdsa";
const ED25519_CURVE_FAMILY_V1: &[u8] = b"ed25519";
const MAX_IDENTIFIER_BYTES_V1: usize = 256;
const MAX_REASON_BYTES_V1: usize = 4 * 1024;

/// Maximum canonical wire size for one provider canary receipt.
pub const TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1: usize = 16 * 1024;

/// Maximum canonical wire size for one accepted-loss authorization.
pub const TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1: usize = 16 * 1024;

/// The two public curve families whose activation canaries are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRootCanaryCurveFamilyV1 {
    /// ECDSA threshold-PRF derivation.
    Ecdsa,
    /// Ed25519 target derivation.
    Ed25519,
}

impl TenantRootCanaryCurveFamilyV1 {
    fn wire_bytes(self) -> &'static [u8] {
        match self {
            Self::Ecdsa => ECDSA_CURVE_FAMILY_V1,
            Self::Ed25519 => ED25519_CURVE_FAMILY_V1,
        }
    }

    /// Returns the fixed public curve-family label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ecdsa => "ecdsa",
            Self::Ed25519 => "ed25519",
        }
    }

    fn from_wire(value: &[u8]) -> RouterAbDerivationResult<Self> {
        match value {
            ECDSA_CURVE_FAMILY_V1 => Ok(Self::Ecdsa),
            ED25519_CURVE_FAMILY_V1 => Ok(Self::Ed25519),
            _ => Err(malformed(
                "tenant-root provider canary curve family is invalid",
            )),
        }
    }
}

/// Public digest of one exact signed provider canary receipt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootProviderCanaryReceiptDigestV1([u8; 32]);

impl fmt::Debug for TenantRootProviderCanaryReceiptDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootProviderCanaryReceiptDigestV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl TenantRootProviderCanaryReceiptDigestV1 {
    fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the exact SHA-256 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public digest of one exact signed accepted-loss authorization.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootAcceptedPermanentLossAuthorizationDigestV1([u8; 32]);

impl fmt::Debug for TenantRootAcceptedPermanentLossAuthorizationDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootAcceptedPermanentLossAuthorizationDigestV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl TenantRootAcceptedPermanentLossAuthorizationDigestV1 {
    fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the exact SHA-256 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public fields authenticated by one provider canary receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootProviderCanaryReceiptBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    commitments: TenantRootEpochCommitmentsV1,
    curve_family: TenantRootCanaryCurveFamilyV1,
    provider_key_version_ref: String,
    completed_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    signing_key_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl TenantRootProviderCanaryReceiptBindingV1 {
    /// Creates the exact public binding for one provider canary completion.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        transition: TenantRootActivationReceiptTransitionV1,
        target_epoch: TenantRootShareEpoch,
        commitments: TenantRootEpochCommitmentsV1,
        curve_family: TenantRootCanaryCurveFamilyV1,
        provider_key_version_ref: impl Into<String>,
        completed_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        signing_key_id: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest,
            custody_lineage,
            transition,
            target_epoch,
            commitments,
            curve_family,
            provider_key_version_ref: provider_key_version_ref.into(),
            completed_at_ms,
            authority_id,
            signing_key_id: signing_key_id.into(),
            issued_at_ms,
            expires_at_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the tenant identity authenticated by this binding.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the custody lineage authenticated by this binding.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the activation transition authenticated by this binding.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.transition
    }

    /// Returns the exact epoch whose canary completed.
    pub const fn target_epoch(&self) -> TenantRootShareEpoch {
        self.target_epoch
    }

    /// Returns the exact role and joined-root commitments authenticated by this binding.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    /// Returns the derivation curve family authenticated by this binding.
    pub const fn curve_family(&self) -> TenantRootCanaryCurveFamilyV1 {
        self.curve_family
    }

    /// Returns the provider's opaque key-version reference.
    pub fn provider_key_version_ref(&self) -> &str {
        &self.provider_key_version_ref
    }

    /// Returns the provider completion time.
    pub const fn completed_at_ms(&self) -> u64 {
        self.completed_at_ms
    }

    /// Returns the control-plane authority authenticated by this binding.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.authority_id
    }

    /// Returns the control-plane signing key identifier.
    pub fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    /// Returns the receipt issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the receipt expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the exact unsigned canonical bytes covered by the receipt signature.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        unsigned_provider_canary_bytes(self)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        validate_identity(self.identity_digest)?;
        validate_transition_epoch(self.transition, self.target_epoch)?;
        validate_commitments(&self.commitments)?;
        require_tenant_root_identifier(
            "tenant-root provider canary key-version reference",
            &self.provider_key_version_ref,
        )?;
        require_tenant_root_identifier(
            "tenant-root provider canary signing key id",
            &self.signing_key_id,
        )?;
        validate_authority_id(self.authority_id, "tenant-root provider canary authority")?;
        validate_time_window(
            self.issued_at_ms,
            self.expires_at_ms,
            self.completed_at_ms,
            "tenant-root provider canary",
        )
    }
}

/// A provider canary receipt signed over one exact public binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedProviderCanaryReceiptV1 {
    binding: TenantRootProviderCanaryReceiptBindingV1,
    signature: [u8; 64],
}

impl TenantRootSignedProviderCanaryReceiptV1 {
    /// Signs one exact provider canary binding with its control-plane key.
    pub fn sign(
        binding: TenantRootProviderCanaryReceiptBindingV1,
        signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        binding.validate()?;
        let unsigned = binding.canonical_bytes()?;
        let signature = SigningKey::from_bytes(signing_key_bytes)
            .sign(&signature_input(
                PROVIDER_CANARY_RECEIPT_AUTH_DOMAIN_V1,
                binding.signing_key_id(),
                &unsigned,
            )?)
            .to_bytes();
        let receipt = Self { binding, signature };
        receipt.canonical_bytes()?;
        Ok(receipt)
    }

    /// Decodes exactly one canonical signed provider canary receipt.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root provider canary receipt wire length is invalid",
            ));
        }
        let mut decoder = EvidenceWireDecoderV1::new(bytes);
        decoder.require_field(
            PROVIDER_CANARY_RECEIPT_DOMAIN_V1,
            "tenant-root provider canary receipt domain",
        )?;
        let transition = decode_transition(
            decoder.field("tenant-root provider canary receipt transition")?,
            "tenant-root provider canary receipt transition",
        )?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root provider canary receipt identity")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root provider canary receipt lineage")?,
        )?;
        let target_epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root provider canary receipt target epoch")?,
        )?;
        let commitments = decode_commitments(&mut decoder, "tenant-root provider canary receipt")?;
        let curve_family = TenantRootCanaryCurveFamilyV1::from_wire(
            decoder.field("tenant-root provider canary receipt curve family")?,
        )?;
        let provider_key_version_ref = decoder.text_field(
            "tenant-root provider canary receipt provider key-version reference",
            MAX_IDENTIFIER_BYTES_V1,
        )?;
        let completed_at_ms =
            decoder.u64_field("tenant-root provider canary receipt completion")?;
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root provider canary receipt authority")?,
        );
        let signing_key_id = decoder.text_field(
            "tenant-root provider canary receipt signing key id",
            MAX_IDENTIFIER_BYTES_V1,
        )?;
        let issued_at_ms = decoder.u64_field("tenant-root provider canary receipt issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root provider canary receipt expiry")?;
        let signature =
            decoder.fixed_field::<64>("tenant-root provider canary receipt signature")?;
        decoder.finish("tenant-root provider canary receipt")?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root provider canary receipt signature must be nonzero",
            ));
        }
        let receipt = Self {
            binding: TenantRootProviderCanaryReceiptBindingV1::new(
                identity_digest,
                custody_lineage,
                transition,
                target_epoch,
                commitments,
                curve_family,
                provider_key_version_ref,
                completed_at_ms,
                authority_id,
                signing_key_id,
                issued_at_ms,
                expires_at_ms,
            )?,
            signature,
        };
        if receipt.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root provider canary receipt wire is not canonical",
            ));
        }
        Ok(receipt)
    }

    /// Returns the exact public binding authenticated by this receipt.
    pub const fn binding(&self) -> &TenantRootProviderCanaryReceiptBindingV1 {
        &self.binding
    }

    /// Returns the tenant identity authenticated by this receipt.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding.identity_digest()
    }

    /// Returns the custody lineage authenticated by this receipt.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding.custody_lineage()
    }

    /// Returns the activation transition authenticated by this receipt.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.binding.transition()
    }

    /// Returns the target epoch authenticated by this receipt.
    pub const fn target_epoch(&self) -> TenantRootShareEpoch {
        self.binding.target_epoch()
    }

    /// Returns the exact epoch commitments authenticated by this receipt.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.binding.commitments()
    }

    /// Returns the curve family authenticated by this receipt.
    pub const fn curve_family(&self) -> TenantRootCanaryCurveFamilyV1 {
        self.binding.curve_family()
    }

    /// Returns the provider key-version reference authenticated by this receipt.
    pub fn provider_key_version_ref(&self) -> &str {
        self.binding.provider_key_version_ref()
    }

    /// Returns the provider completion time authenticated by this receipt.
    pub const fn completed_at_ms(&self) -> u64 {
        self.binding.completed_at_ms()
    }

    /// Returns the authority authenticated by this receipt.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding.authority_id()
    }

    /// Returns the signing key identifier authenticated by this receipt.
    pub fn signing_key_id(&self) -> &str {
        self.binding.signing_key_id()
    }

    /// Returns the issue time authenticated by this receipt.
    pub const fn issued_at_ms(&self) -> u64 {
        self.binding.issued_at_ms()
    }

    /// Returns the expiry time authenticated by this receipt.
    pub const fn expires_at_ms(&self) -> u64 {
        self.binding.expires_at_ms()
    }

    /// Returns the exact signature bytes.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns the exact canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = self.binding.canonical_bytes()?;
        push_field(
            &mut bytes,
            &self.signature,
            TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
        )?;
        Ok(bytes)
    }

    /// Returns SHA-256 of the exact signed canonical receipt bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProviderCanaryReceiptDigestV1> {
        Ok(TenantRootProviderCanaryReceiptDigestV1::from_canonical_bytes(&self.canonical_bytes()?))
    }

    /// Verifies this receipt against one exact expected binding and trusted key.
    pub fn verify(
        &self,
        expected: &TenantRootProviderCanaryReceiptBindingV1,
        trusted_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootProviderCanaryReceiptV1> {
        self.binding.validate()?;
        expected.validate()?;
        if &self.binding != expected {
            return Err(replay_mismatch(
                "tenant-root provider canary receipt does not match its expected binding",
            ));
        }
        verify_signature(
            PROVIDER_CANARY_RECEIPT_AUTH_DOMAIN_V1,
            self.binding.signing_key_id(),
            &self.binding.canonical_bytes()?,
            &self.signature,
            trusted_verifying_key,
            "tenant-root provider canary receipt signature is invalid",
        )?;
        let canonical_bytes = self.canonical_bytes()?;
        let digest =
            TenantRootProviderCanaryReceiptDigestV1::from_canonical_bytes(&canonical_bytes);
        Ok(VerifiedTenantRootProviderCanaryReceiptV1 {
            receipt: self.clone(),
            canonical_bytes,
            digest,
        })
    }
}

/// Provider-canary receipt after exact binding and signature verification.
pub struct VerifiedTenantRootProviderCanaryReceiptV1 {
    receipt: TenantRootSignedProviderCanaryReceiptV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProviderCanaryReceiptDigestV1,
}

impl fmt::Debug for VerifiedTenantRootProviderCanaryReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootProviderCanaryReceiptV1")
            .field("binding", &self.receipt.binding)
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public authenticated bytes]")
            .finish()
    }
}

impl VerifiedTenantRootProviderCanaryReceiptV1 {
    /// Returns the exact binding authenticated by this token.
    pub const fn binding(&self) -> &TenantRootProviderCanaryReceiptBindingV1 {
        self.receipt.binding()
    }

    /// Returns the tenant identity authenticated by this token.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding().identity_digest()
    }

    /// Returns the custody lineage authenticated by this token.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding().custody_lineage()
    }

    /// Returns the activation transition authenticated by this token.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.binding().transition()
    }

    /// Returns the target epoch authenticated by this token.
    pub const fn target_epoch(&self) -> TenantRootShareEpoch {
        self.binding().target_epoch()
    }

    /// Returns the exact epoch commitments authenticated by this token.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.binding().commitments()
    }

    /// Returns the curve family authenticated by this token.
    pub const fn curve_family(&self) -> TenantRootCanaryCurveFamilyV1 {
        self.binding().curve_family()
    }

    /// Returns the provider key-version reference authenticated by this token.
    pub fn provider_key_version_ref(&self) -> &str {
        self.binding().provider_key_version_ref()
    }

    /// Returns the provider completion time authenticated by this token.
    pub const fn completed_at_ms(&self) -> u64 {
        self.binding().completed_at_ms()
    }

    /// Returns the authority authenticated by this token.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding().authority_id()
    }

    /// Returns the signing key identifier authenticated by this token.
    pub fn signing_key_id(&self) -> &str {
        self.binding().signing_key_id()
    }

    /// Returns the issue time authenticated by this token.
    pub const fn issued_at_ms(&self) -> u64 {
        self.binding().issued_at_ms()
    }

    /// Returns the expiry time authenticated by this token.
    pub const fn expires_at_ms(&self) -> u64 {
        self.binding().expires_at_ms()
    }

    /// Returns the exact canonical signed bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact accepted canonical bytes.
    pub const fn digest(&self) -> TenantRootProviderCanaryReceiptDigestV1 {
        self.digest
    }

    /// Requires the token to be used inside its inclusive freshness window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.binding().issued_at_ms() || now_ms > self.binding().expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root provider canary receipt is outside its freshness window",
            ));
        }
        Ok(())
    }

    /// Consumes the token into the exact accepted canonical bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

/// Public fields for an explicit accepted-permanent-loss authorization.
///
/// This binding is independent from current-role backup receipts. It authorizes
/// one exact activation scope when the deployment deliberately accepts future
/// derivation loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootAcceptedPermanentLossAuthorizationBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    context_digest: TenantRootProtocolDigestV1,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    one_use_policy_id: String,
    incident_id: String,
    reason: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    first_authority_id: TenantRootControlPlaneAuthorityIdV1,
    first_signing_key_id: String,
    second_authority_id: TenantRootControlPlaneAuthorityIdV1,
    second_signing_key_id: String,
}

impl TenantRootAcceptedPermanentLossAuthorizationBindingV1 {
    /// Creates the exact public dual-approval authorization binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        transition: TenantRootActivationReceiptTransitionV1,
        target_epoch: TenantRootShareEpoch,
        context_digest: TenantRootProtocolDigestV1,
        commitments: TenantRootEpochCommitmentsV1,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
        one_use_policy_id: impl Into<String>,
        incident_id: impl Into<String>,
        reason: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
        first_authority_id: TenantRootControlPlaneAuthorityIdV1,
        first_signing_key_id: impl Into<String>,
        second_authority_id: TenantRootControlPlaneAuthorityIdV1,
        second_signing_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest,
            custody_lineage,
            transition,
            target_epoch,
            context_digest,
            commitments,
            installation_receipts,
            expected_control_plane_revision,
            result_control_plane_revision,
            one_use_policy_id: one_use_policy_id.into(),
            incident_id: incident_id.into(),
            reason: reason.into(),
            issued_at_ms,
            expires_at_ms,
            first_authority_id,
            first_signing_key_id: first_signing_key_id.into(),
            second_authority_id,
            second_signing_key_id: second_signing_key_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the tenant identity authenticated by this authorization.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the custody lineage authenticated by this authorization.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact activation transition authorized for the loss branch.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.transition
    }

    /// Returns the exact activation epoch authorized for the loss branch.
    pub const fn target_epoch(&self) -> TenantRootShareEpoch {
        self.target_epoch
    }

    /// Returns the exact ceremony context digest authorized for activation.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.context_digest
    }

    /// Returns the exact target A/B and joined-root commitments authorized for activation.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    /// Returns the exact A/B installation receipt digests authorized for activation.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.installation_receipts
    }

    /// Returns the authoritative lifecycle revision from which activation is claimed.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }

    /// Returns the authoritative lifecycle revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.result_control_plane_revision
    }

    /// Returns the one-use policy identifier.
    pub fn one_use_policy_id(&self) -> &str {
        &self.one_use_policy_id
    }

    /// Returns the incident identifier bound to this authorization.
    pub fn incident_id(&self) -> &str {
        &self.incident_id
    }

    /// Returns the operator reason bound to this authorization.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns the authorization issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the authorization expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the first approving control-plane authority.
    pub const fn first_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.first_authority_id
    }

    /// Returns the first approving key identifier.
    pub fn first_signing_key_id(&self) -> &str {
        &self.first_signing_key_id
    }

    /// Returns the second approving control-plane authority.
    pub const fn second_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.second_authority_id
    }

    /// Returns the second approving key identifier.
    pub fn second_signing_key_id(&self) -> &str {
        &self.second_signing_key_id
    }

    /// Returns the exact unsigned canonical bytes covered by both signatures.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        unsigned_accepted_loss_bytes(self)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        validate_identity(self.identity_digest)?;
        validate_transition_epoch(self.transition, self.target_epoch)?;
        validate_commitments(&self.commitments)?;
        validate_revisions(
            self.expected_control_plane_revision,
            self.result_control_plane_revision,
            "tenant-root accepted-loss authorization",
        )?;
        require_tenant_root_identifier(
            "tenant-root accepted-loss one-use policy id",
            &self.one_use_policy_id,
        )?;
        require_tenant_root_identifier("tenant-root accepted-loss incident id", &self.incident_id)?;
        validate_reason(&self.reason)?;
        validate_lifetime_window(
            self.issued_at_ms,
            self.expires_at_ms,
            "tenant-root accepted-loss authorization",
        )?;
        validate_authority_id(
            self.first_authority_id,
            "tenant-root accepted-loss first authority",
        )?;
        validate_authority_id(
            self.second_authority_id,
            "tenant-root accepted-loss second authority",
        )?;
        if self.first_authority_id == self.second_authority_id {
            return Err(malformed(
                "tenant-root accepted-loss authority ids must be distinct",
            ));
        }
        require_tenant_root_identifier(
            "tenant-root accepted-loss first signing key id",
            &self.first_signing_key_id,
        )?;
        require_tenant_root_identifier(
            "tenant-root accepted-loss second signing key id",
            &self.second_signing_key_id,
        )?;
        if self.first_signing_key_id == self.second_signing_key_id {
            return Err(malformed(
                "tenant-root accepted-loss signing key ids must be distinct",
            ));
        }
        Ok(())
    }
}

/// An accepted-permanent-loss authorization carrying two control-plane signatures.
#[derive(Debug, PartialEq, Eq)]
pub struct TenantRootSignedAcceptedPermanentLossAuthorizationV1 {
    binding: TenantRootAcceptedPermanentLossAuthorizationBindingV1,
    first_signature: [u8; 64],
    second_signature: [u8; 64],
}

impl TenantRootSignedAcceptedPermanentLossAuthorizationV1 {
    /// Signs one exact authorization binding with two distinct control-plane keys.
    pub fn sign(
        binding: TenantRootAcceptedPermanentLossAuthorizationBindingV1,
        first_signing_key_bytes: &[u8; 32],
        second_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        binding.validate()?;
        let first_key = SigningKey::from_bytes(first_signing_key_bytes);
        let second_key = SigningKey::from_bytes(second_signing_key_bytes);
        if first_key.verifying_key() == second_key.verifying_key() {
            return Err(malformed(
                "tenant-root accepted-loss authorization requires distinct signing keys",
            ));
        }
        let unsigned = binding.canonical_bytes()?;
        let first_signature = first_key
            .sign(&signature_input(
                ACCEPTED_LOSS_AUTHORIZATION_AUTH_DOMAIN_V1,
                binding.first_signing_key_id(),
                &unsigned,
            )?)
            .to_bytes();
        let second_signature = second_key
            .sign(&signature_input(
                ACCEPTED_LOSS_AUTHORIZATION_AUTH_DOMAIN_V1,
                binding.second_signing_key_id(),
                &unsigned,
            )?)
            .to_bytes();
        let authorization = Self {
            binding,
            first_signature,
            second_signature,
        };
        authorization.canonical_bytes()?;
        Ok(authorization)
    }

    /// Decodes exactly one canonical dual-signed accepted-loss authorization.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty()
            || bytes.len() > TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1
        {
            return Err(malformed(
                "tenant-root accepted-loss authorization wire length is invalid",
            ));
        }
        let mut decoder = EvidenceWireDecoderV1::new(bytes);
        decoder.require_field(
            ACCEPTED_LOSS_AUTHORIZATION_DOMAIN_V1,
            "tenant-root accepted-loss authorization domain",
        )?;
        let transition = decode_transition(
            decoder.field("tenant-root accepted-loss authorization transition")?,
            "tenant-root accepted-loss authorization transition",
        )?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root accepted-loss authorization identity")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root accepted-loss authorization lineage")?,
        )?;
        let target_epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root accepted-loss authorization target epoch")?,
        )?;
        let context_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root accepted-loss authorization context digest")?,
        )?;
        let commitments =
            decode_commitments(&mut decoder, "tenant-root accepted-loss authorization")?;
        let installation_receipts = decode_installation_receipts(&mut decoder)?;
        let expected_control_plane_revision =
            decoder.u64_field("tenant-root accepted-loss authorization expected revision")?;
        let result_control_plane_revision =
            decoder.u64_field("tenant-root accepted-loss authorization result revision")?;
        let one_use_policy_id = decoder.text_field(
            "tenant-root accepted-loss authorization one-use policy id",
            MAX_IDENTIFIER_BYTES_V1,
        )?;
        let incident_id = decoder.text_field(
            "tenant-root accepted-loss authorization incident id",
            MAX_IDENTIFIER_BYTES_V1,
        )?;
        let reason = decoder.text_field(
            "tenant-root accepted-loss authorization reason",
            MAX_REASON_BYTES_V1,
        )?;
        let issued_at_ms =
            decoder.u64_field("tenant-root accepted-loss authorization issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root accepted-loss authorization expiry")?;
        let first_authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root accepted-loss first authority")?,
        );
        let first_signing_key_id = decoder.text_field(
            "tenant-root accepted-loss first signing key id",
            MAX_IDENTIFIER_BYTES_V1,
        )?;
        let second_authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root accepted-loss second authority")?,
        );
        let second_signing_key_id = decoder.text_field(
            "tenant-root accepted-loss second signing key id",
            MAX_IDENTIFIER_BYTES_V1,
        )?;
        let first_signature =
            decoder.fixed_field::<64>("tenant-root accepted-loss authorization first signature")?;
        let second_signature = decoder
            .fixed_field::<64>("tenant-root accepted-loss authorization second signature")?;
        decoder.finish("tenant-root accepted-loss authorization")?;
        if first_signature.iter().all(|byte| *byte == 0)
            || second_signature.iter().all(|byte| *byte == 0)
        {
            return Err(malformed(
                "tenant-root accepted-loss authorization signatures must be nonzero",
            ));
        }
        let authorization = Self {
            binding: TenantRootAcceptedPermanentLossAuthorizationBindingV1::new(
                identity_digest,
                custody_lineage,
                transition,
                target_epoch,
                context_digest,
                commitments,
                installation_receipts,
                expected_control_plane_revision,
                result_control_plane_revision,
                one_use_policy_id,
                incident_id,
                reason,
                issued_at_ms,
                expires_at_ms,
                first_authority_id,
                first_signing_key_id,
                second_authority_id,
                second_signing_key_id,
            )?,
            first_signature,
            second_signature,
        };
        if authorization.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root accepted-loss authorization wire is not canonical",
            ));
        }
        Ok(authorization)
    }

    /// Returns the exact authorization binding.
    pub const fn binding(&self) -> &TenantRootAcceptedPermanentLossAuthorizationBindingV1 {
        &self.binding
    }

    /// Returns the tenant identity authenticated by this authorization.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding.identity_digest()
    }

    /// Returns the custody lineage authenticated by this authorization.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding.custody_lineage()
    }

    /// Returns the activation transition authenticated by this authorization.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.binding.transition()
    }

    /// Returns the target epoch authenticated by this authorization.
    pub const fn target_epoch(&self) -> TenantRootShareEpoch {
        self.binding.target_epoch()
    }

    /// Returns the exact ceremony context digest authenticated by this authorization.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.binding.context_digest()
    }

    /// Returns the exact target A/B and joined-root commitments authenticated by this authorization.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.binding.commitments()
    }

    /// Returns the exact A/B installation receipt digests authenticated by this authorization.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.binding.installation_receipts()
    }

    /// Returns the expected lifecycle revision authenticated by this authorization.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.binding.expected_control_plane_revision()
    }

    /// Returns the result lifecycle revision authenticated by this authorization.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.binding.result_control_plane_revision()
    }

    /// Returns the one-use policy identifier authenticated by this authorization.
    pub fn one_use_policy_id(&self) -> &str {
        self.binding.one_use_policy_id()
    }

    /// Returns the incident identifier authenticated by this authorization.
    pub fn incident_id(&self) -> &str {
        self.binding.incident_id()
    }

    /// Returns the reason authenticated by this authorization.
    pub fn reason(&self) -> &str {
        self.binding.reason()
    }

    /// Returns the authorization issue time authenticated by this authorization.
    pub const fn issued_at_ms(&self) -> u64 {
        self.binding.issued_at_ms()
    }

    /// Returns the authorization expiry authenticated by this authorization.
    pub const fn expires_at_ms(&self) -> u64 {
        self.binding.expires_at_ms()
    }

    /// Returns the first approving authority authenticated by this authorization.
    pub const fn first_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding.first_authority_id()
    }

    /// Returns the first approving key identifier authenticated by this authorization.
    pub fn first_signing_key_id(&self) -> &str {
        self.binding.first_signing_key_id()
    }

    /// Returns the second approving authority authenticated by this authorization.
    pub const fn second_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding.second_authority_id()
    }

    /// Returns the second approving key identifier authenticated by this authorization.
    pub fn second_signing_key_id(&self) -> &str {
        self.binding.second_signing_key_id()
    }

    /// Returns the first control-plane signature.
    pub const fn first_signature(&self) -> &[u8; 64] {
        &self.first_signature
    }

    /// Returns the second control-plane signature.
    pub const fn second_signature(&self) -> &[u8; 64] {
        &self.second_signature
    }

    /// Returns the exact canonical signed authorization bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = self.binding.canonical_bytes()?;
        push_field(
            &mut bytes,
            &self.first_signature,
            TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
        )?;
        push_field(
            &mut bytes,
            &self.second_signature,
            TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
        )?;
        Ok(bytes)
    }

    /// Returns SHA-256 of the exact signed canonical authorization bytes.
    pub fn digest(
        &self,
    ) -> RouterAbDerivationResult<TenantRootAcceptedPermanentLossAuthorizationDigestV1> {
        Ok(
            TenantRootAcceptedPermanentLossAuthorizationDigestV1::from_canonical_bytes(
                &self.canonical_bytes()?,
            ),
        )
    }

    /// Verifies both signatures against one exact expected binding and trusted keys.
    pub fn verify(
        self,
        expected: &TenantRootAcceptedPermanentLossAuthorizationBindingV1,
        first_trusted_verifying_key: &[u8; 32],
        second_trusted_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootAcceptedPermanentLossAuthorizationV1> {
        self.binding.validate()?;
        expected.validate()?;
        if &self.binding != expected {
            return Err(replay_mismatch(
                "tenant-root accepted-loss authorization does not match its expected binding",
            ));
        }
        if first_trusted_verifying_key == second_trusted_verifying_key {
            return Err(verification_failed(
                "tenant-root accepted-loss authorization requires distinct trusted keys",
            ));
        }
        let unsigned = self.binding.canonical_bytes()?;
        verify_signature(
            ACCEPTED_LOSS_AUTHORIZATION_AUTH_DOMAIN_V1,
            self.binding.first_signing_key_id(),
            &unsigned,
            &self.first_signature,
            first_trusted_verifying_key,
            "tenant-root accepted-loss first signature is invalid",
        )?;
        verify_signature(
            ACCEPTED_LOSS_AUTHORIZATION_AUTH_DOMAIN_V1,
            self.binding.second_signing_key_id(),
            &unsigned,
            &self.second_signature,
            second_trusted_verifying_key,
            "tenant-root accepted-loss second signature is invalid",
        )?;
        let canonical_bytes = self.canonical_bytes()?;
        let digest = TenantRootAcceptedPermanentLossAuthorizationDigestV1::from_canonical_bytes(
            &canonical_bytes,
        );
        Ok(VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
            authorization: self,
            canonical_bytes,
            digest,
        })
    }
}

/// Accepted-loss authorization after both exact approvals are verified.
pub struct VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
    authorization: TenantRootSignedAcceptedPermanentLossAuthorizationV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootAcceptedPermanentLossAuthorizationDigestV1,
}

impl fmt::Debug for VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootAcceptedPermanentLossAuthorizationV1")
            .field("binding", &self.authorization.binding)
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public authenticated bytes]")
            .finish()
    }
}

impl VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
    /// Returns the exact binding authenticated by this token.
    pub const fn binding(&self) -> &TenantRootAcceptedPermanentLossAuthorizationBindingV1 {
        self.authorization.binding()
    }

    /// Returns the tenant identity authenticated by this token.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding().identity_digest()
    }

    /// Returns the custody lineage authenticated by this token.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding().custody_lineage()
    }

    /// Returns the activation transition authenticated by this token.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.binding().transition()
    }

    /// Returns the target epoch authenticated by this token.
    pub const fn target_epoch(&self) -> TenantRootShareEpoch {
        self.binding().target_epoch()
    }

    /// Returns the exact ceremony context digest authenticated by this token.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.binding().context_digest()
    }

    /// Returns the exact target A/B and joined-root commitments authenticated by this token.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.binding().commitments()
    }

    /// Returns the exact A/B installation receipt digests authenticated by this token.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.binding().installation_receipts()
    }

    /// Returns the expected lifecycle revision authenticated by this token.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.binding().expected_control_plane_revision()
    }

    /// Returns the result lifecycle revision authenticated by this token.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.binding().result_control_plane_revision()
    }

    /// Returns the one-use policy identifier authenticated by this token.
    pub fn one_use_policy_id(&self) -> &str {
        self.binding().one_use_policy_id()
    }

    /// Returns the incident identifier authenticated by this token.
    pub fn incident_id(&self) -> &str {
        self.binding().incident_id()
    }

    /// Returns the reason authenticated by this token.
    pub fn reason(&self) -> &str {
        self.binding().reason()
    }

    /// Returns the authorization issue time authenticated by this token.
    pub const fn issued_at_ms(&self) -> u64 {
        self.binding().issued_at_ms()
    }

    /// Returns the authorization expiry authenticated by this token.
    pub const fn expires_at_ms(&self) -> u64 {
        self.binding().expires_at_ms()
    }

    /// Returns the first approving authority authenticated by this token.
    pub const fn first_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding().first_authority_id()
    }

    /// Returns the first approving key identifier authenticated by this token.
    pub fn first_signing_key_id(&self) -> &str {
        self.binding().first_signing_key_id()
    }

    /// Returns the second approving authority authenticated by this token.
    pub const fn second_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding().second_authority_id()
    }

    /// Returns the second approving key identifier authenticated by this token.
    pub fn second_signing_key_id(&self) -> &str {
        self.binding().second_signing_key_id()
    }

    /// Returns the exact canonical signed bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact accepted canonical bytes.
    pub const fn digest(&self) -> TenantRootAcceptedPermanentLossAuthorizationDigestV1 {
        self.digest
    }

    /// Requires the token to be used inside its inclusive freshness window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.binding().issued_at_ms() || now_ms > self.binding().expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root accepted-loss authorization is outside its freshness window",
            ));
        }
        Ok(())
    }

    /// Consumes the token into the exact accepted canonical bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

fn unsigned_provider_canary_bytes(
    binding: &TenantRootProviderCanaryReceiptBindingV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    binding.validate()?;
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        PROVIDER_CANARY_RECEIPT_DOMAIN_V1,
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    append_binding_scope(
        &mut bytes,
        binding.identity_digest,
        binding.custody_lineage,
        binding.transition,
        binding.target_epoch,
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    append_commitments(
        &mut bytes,
        &binding.commitments,
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.curve_family.wire_bytes(),
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.provider_key_version_ref.as_bytes(),
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.completed_at_ms,
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.authority_id.as_bytes(),
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.signing_key_id.as_bytes(),
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.issued_at_ms,
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.expires_at_ms,
        TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
    )?;
    Ok(bytes)
}

fn unsigned_accepted_loss_bytes(
    binding: &TenantRootAcceptedPermanentLossAuthorizationBindingV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    binding.validate()?;
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        ACCEPTED_LOSS_AUTHORIZATION_DOMAIN_V1,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    append_binding_scope(
        &mut bytes,
        binding.identity_digest,
        binding.custody_lineage,
        binding.transition,
        binding.target_epoch,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.context_digest.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    append_commitments(
        &mut bytes,
        &binding.commitments,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    append_installation_receipts(
        &mut bytes,
        &binding.installation_receipts,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.expected_control_plane_revision,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.result_control_plane_revision,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.one_use_policy_id.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.incident_id.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.reason.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.issued_at_ms,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_u64(
        &mut bytes,
        binding.expires_at_ms,
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.first_authority_id.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.first_signing_key_id.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.second_authority_id.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    push_field(
        &mut bytes,
        binding.second_signing_key_id.as_bytes(),
        TENANT_ROOT_ACCEPTED_PERMANENT_LOSS_AUTHORIZATION_MAX_BYTES_V1,
    )?;
    Ok(bytes)
}

fn append_binding_scope(
    bytes: &mut Vec<u8>,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    max_bytes: usize,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, transition_wire_bytes(transition), max_bytes)?;
    push_field(bytes, identity_digest.as_bytes(), max_bytes)?;
    push_field(bytes, custody_lineage.as_bytes(), max_bytes)?;
    push_u64(bytes, target_epoch.get().get(), max_bytes)
}

fn append_commitments(
    bytes: &mut Vec<u8>,
    commitments: &TenantRootEpochCommitmentsV1,
    max_bytes: usize,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, commitments.deriver_a().as_bytes(), max_bytes)?;
    push_field(bytes, commitments.deriver_b().as_bytes(), max_bytes)?;
    push_field(bytes, commitments.root_commitment(), max_bytes)
}

fn append_installation_receipts(
    bytes: &mut Vec<u8>,
    receipts: &TenantRootRoleInstallationReceiptsV1,
    max_bytes: usize,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, receipts.deriver_a().as_bytes(), max_bytes)?;
    push_field(bytes, receipts.deriver_b().as_bytes(), max_bytes)
}

fn decode_commitments(
    decoder: &mut EvidenceWireDecoderV1<'_>,
    prefix: &str,
) -> RouterAbDerivationResult<TenantRootEpochCommitmentsV1> {
    let deriver_a = MpcPrfShareCommitmentWireV1::new(
        decoder
            .field("tenant-root provider canary Deriver A commitment")?
            .to_vec(),
    )?;
    let deriver_b = MpcPrfShareCommitmentWireV1::new(
        decoder
            .field("tenant-root provider canary Deriver B commitment")?
            .to_vec(),
    )?;
    let expected_root = decoder.fixed_field::<32>("tenant-root provider canary root commitment")?;
    let commitments = TenantRootEpochCommitmentsV1::new(deriver_a, deriver_b)?;
    if commitments.root_commitment() != &expected_root {
        return Err(malformed(format!(
            "{prefix} root commitment does not match its role commitments"
        )));
    }
    Ok(commitments)
}

fn decode_installation_receipts(
    decoder: &mut EvidenceWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootRoleInstallationReceiptsV1> {
    let deriver_a = TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
        "tenant-root accepted-loss authorization Deriver A installation receipt",
    )?)?;
    let deriver_b = TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
        "tenant-root accepted-loss authorization Deriver B installation receipt",
    )?)?;
    TenantRootRoleInstallationReceiptsV1::new(deriver_a, deriver_b)
}

fn validate_commitments(
    commitments: &TenantRootEpochCommitmentsV1,
) -> RouterAbDerivationResult<()> {
    let rebuilt = TenantRootEpochCommitmentsV1::new(
        commitments.deriver_a().clone(),
        commitments.deriver_b().clone(),
    )?;
    if rebuilt != *commitments {
        return Err(malformed(
            "tenant-root provider canary commitments are not canonical",
        ));
    }
    Ok(())
}

fn validate_identity(identity_digest: TenantRootIdentityDigestV1) -> RouterAbDerivationResult<()> {
    if identity_digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root activation support identity digest must be non-zero",
        ));
    }
    Ok(())
}

fn validate_authority_id(
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    field: &'static str,
) -> RouterAbDerivationResult<()> {
    if authority_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(malformed(format!("{field} must be non-zero")));
    }
    Ok(())
}

fn validate_transition_epoch(
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
) -> RouterAbDerivationResult<()> {
    match transition {
        TenantRootActivationReceiptTransitionV1::InitialCreation
            if target_epoch != TenantRootShareEpoch::INITIAL =>
        {
            Err(malformed(
                "tenant-root initial-creation provider evidence must target epoch one",
            ))
        }
        TenantRootActivationReceiptTransitionV1::RefreshSwap
            if target_epoch == TenantRootShareEpoch::INITIAL =>
        {
            Err(malformed(
                "tenant-root refresh provider evidence must target a later epoch",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_time_window(
    issued_at_ms: u64,
    expires_at_ms: u64,
    completed_at_ms: u64,
    prefix: &str,
) -> RouterAbDerivationResult<()> {
    if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        return Err(malformed(format!(
            "{prefix} expiry must follow a non-zero issue time"
        )));
    }
    if expires_at_ms - issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(format!(
            "{prefix} lifetime exceeds the frozen maximum window"
        )));
    }
    if completed_at_ms < issued_at_ms || completed_at_ms > expires_at_ms {
        return Err(malformed(format!(
            "{prefix} completion time must fall within its freshness window"
        )));
    }
    Ok(())
}

fn validate_lifetime_window(
    issued_at_ms: u64,
    expires_at_ms: u64,
    prefix: &str,
) -> RouterAbDerivationResult<()> {
    if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        return Err(malformed(format!(
            "{prefix} expiry must follow a non-zero issue time"
        )));
    }
    if expires_at_ms - issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(format!(
            "{prefix} lifetime exceeds the frozen maximum window"
        )));
    }
    Ok(())
}

fn validate_revisions(
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    prefix: &str,
) -> RouterAbDerivationResult<()> {
    if expected_control_plane_revision == 0 {
        return Err(malformed(format!(
            "{prefix} expected revision must be positive"
        )));
    }
    let expected_result_control_plane_revision = expected_control_plane_revision
        .checked_add(1)
        .ok_or_else(|| malformed(format!("{prefix} expected revision cannot advance")))?;
    if result_control_plane_revision != expected_result_control_plane_revision {
        return Err(malformed(format!(
            "{prefix} result revision must advance exactly one"
        )));
    }
    Ok(())
}

fn validate_reason(reason: &str) -> RouterAbDerivationResult<()> {
    if reason.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root accepted-loss authorization reason is required",
        ));
    }
    if reason.len() > MAX_REASON_BYTES_V1 {
        return Err(malformed(
            "tenant-root accepted-loss authorization reason is too long",
        ));
    }
    if reason.trim() != reason || reason.chars().any(char::is_control) {
        return Err(malformed(
            "tenant-root accepted-loss authorization reason is not canonical",
        ));
    }
    Ok(())
}

fn transition_wire_bytes(transition: TenantRootActivationReceiptTransitionV1) -> &'static [u8] {
    match transition {
        TenantRootActivationReceiptTransitionV1::InitialCreation => INITIAL_CREATION_OPERATION_V1,
        TenantRootActivationReceiptTransitionV1::RefreshSwap => REFRESH_SWAP_OPERATION_V1,
    }
}

fn decode_transition(
    value: &[u8],
    field: &'static str,
) -> RouterAbDerivationResult<TenantRootActivationReceiptTransitionV1> {
    match value {
        INITIAL_CREATION_OPERATION_V1 => {
            Ok(TenantRootActivationReceiptTransitionV1::InitialCreation)
        }
        REFRESH_SWAP_OPERATION_V1 => Ok(TenantRootActivationReceiptTransitionV1::RefreshSwap),
        _ => Err(malformed(format!("{field} is invalid"))),
    }
}

fn signature_input(
    domain: &[u8],
    signing_key_id: &str,
    unsigned: &[u8],
) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier("tenant-root support signing key id", signing_key_id)?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, domain, usize::MAX)?;
    push_field(&mut bytes, signing_key_id.as_bytes(), usize::MAX)?;
    push_field(&mut bytes, unsigned, usize::MAX)?;
    Ok(bytes)
}

fn verify_signature(
    domain: &[u8],
    signing_key_id: &str,
    unsigned: &[u8],
    signature: &[u8; 64],
    trusted_verifying_key: &[u8; 32],
    message: &'static str,
) -> RouterAbDerivationResult<()> {
    let verifying_key = VerifyingKey::from_bytes(trusted_verifying_key)
        .map_err(|_| malformed("tenant-root support verifying key is invalid"))?;
    verifying_key
        .verify_strict(
            &signature_input(domain, signing_key_id, unsigned)?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| verification_failed(message))
}

fn push_u64(bytes: &mut Vec<u8>, value: u64, max_bytes: usize) -> RouterAbDerivationResult<()> {
    push_field(bytes, &value.to_be_bytes(), max_bytes)
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8], max_bytes: usize) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root activation support evidence field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root activation support evidence field is too long"))?;
    let new_length = bytes
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root activation support evidence length overflows"))?;
    if new_length > max_bytes {
        return Err(malformed(
            "tenant-root activation support evidence wire is too long",
        ));
    }
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
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

struct EvidenceWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> EvidenceWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root activation support evidence offset overflows"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed(format!("{name} field length is truncated")))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte support evidence field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed(format!("{name} field length overflows")))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed(format!("{name} field is truncated")))?;
        self.offset = value_end;
        if value.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                format!("{name} is required"),
            ));
        }
        Ok(value)
    }

    fn require_field(
        &mut self,
        expected: &[u8],
        name: &'static str,
    ) -> RouterAbDerivationResult<()> {
        if self.field(name)? != expected {
            return Err(malformed(format!("{name} is invalid")));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed(format!("{name} fixed field length is invalid")))
    }

    fn u64_field(&mut self, name: &'static str) -> RouterAbDerivationResult<u64> {
        Ok(u64::from_be_bytes(self.fixed_field::<8>(name)?))
    }

    fn text_field(
        &mut self,
        name: &'static str,
        max_bytes: usize,
    ) -> RouterAbDerivationResult<String> {
        let value = self.field(name)?;
        if value.len() > max_bytes {
            return Err(malformed(format!("{name} is too long")));
        }
        core::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| malformed(format!("{name} is invalid UTF-8")))
    }

    fn finish(self, prefix: &'static str) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(format!("{prefix} wire has trailing bytes")));
        }
        Ok(())
    }
}
