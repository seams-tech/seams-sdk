use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{
    require_tenant_root_identifier, MpcPrfShareCommitmentWireV1, RouterAbDerivationError,
    RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootAcceptedPermanentLossAuthorizationDigestV1,
    TenantRootActivationAvailabilityEvidenceViewV1, TenantRootCanaryReceiptsV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootProtocolDigestV1,
    TenantRootRoleBackupReceiptsV1, TenantRootRoleInstallationReceiptsV1, TenantRootShareEpoch,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_ACTIVATION_RECEIPT_DOMAIN_V1: &[u8] = b"seams/tenant-root-activation-receipt/v1";
const TENANT_ROOT_ACTIVATION_RECEIPT_AUTH_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-activation-receipt-authentication/v1";
const TENANT_ROOT_ACTIVATION_INITIAL_CREATION_OPERATION_BYTES_V1: &[u8] = b"initial_creation";
const TENANT_ROOT_ACTIVATION_REFRESH_SWAP_OPERATION_BYTES_V1: &[u8] = b"refresh_swap";
const TENANT_ROOT_ACTIVATION_CURRENT_ROLE_BACKUPS_BRANCH_BYTES_V1: &[u8] = b"current_role_backups";
const TENANT_ROOT_ACTIVATION_ACCEPTED_PERMANENT_DERIVATION_LOSS_BRANCH_BYTES_V1: &[u8] =
    b"accepted_permanent_derivation_loss";
const TENANT_ROOT_ACTIVATION_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Initial activation is committed from the creation `Verified` revision.
pub const TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1: u64 = 2;

/// Initial activation advances the creation `Verified` revision to `Active`.
pub const TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1: u64 = 3;

/// Exact operation label for an initial-creation activation receipt.
pub const TENANT_ROOT_ACTIVATION_INITIAL_CREATION_OPERATION_V1: &str = "initial_creation";

/// Exact operation label for a refresh-swap activation receipt.
pub const TENANT_ROOT_ACTIVATION_REFRESH_SWAP_OPERATION_V1: &str = "refresh_swap";

/// Maximum canonical wire size for one signed activation receipt.
pub const TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1: usize = 16 * 1024;

/// The two forward-only transitions that may produce an activation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRootActivationReceiptTransitionV1 {
    /// Activates epoch one in a fresh custody lineage.
    InitialCreation,
    /// Swaps one active epoch for its exact next epoch.
    RefreshSwap,
}

impl TenantRootActivationReceiptTransitionV1 {
    const fn operation_bytes(self) -> &'static [u8] {
        match self {
            Self::InitialCreation => TENANT_ROOT_ACTIVATION_INITIAL_CREATION_OPERATION_BYTES_V1,
            Self::RefreshSwap => TENANT_ROOT_ACTIVATION_REFRESH_SWAP_OPERATION_BYTES_V1,
        }
    }

    /// Returns the fixed wire operation label.
    pub const fn operation(self) -> &'static str {
        match self {
            Self::InitialCreation => TENANT_ROOT_ACTIVATION_INITIAL_CREATION_OPERATION_V1,
            Self::RefreshSwap => TENANT_ROOT_ACTIVATION_REFRESH_SWAP_OPERATION_V1,
        }
    }
}

/// Exact availability branch carried by a signed activation receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootActivationReceiptAvailabilityV1 {
    /// Both current roles have independently verified managed-backup receipts.
    CurrentRoleBackups {
        /// Exact A/B signed managed-backup receipt digests.
        receipts: TenantRootRoleBackupReceiptsV1,
    },
    /// The deployment accepted permanent derivation loss with a dual-authority authorization.
    AcceptedPermanentDerivationLoss {
        /// Exact canonical bytes of the verified dual-authority authorization.
        authorization_bytes: Vec<u8>,
        /// SHA-256 of `authorization_bytes`.
        authorization_digest: TenantRootAcceptedPermanentLossAuthorizationDigestV1,
    },
}

impl TenantRootActivationReceiptAvailabilityV1 {
    /// Returns the exact A/B managed-backup receipt digests for this branch.
    pub const fn current_role_backup_receipts(&self) -> Option<TenantRootRoleBackupReceiptsV1> {
        match self {
            Self::CurrentRoleBackups { receipts } => Some(*receipts),
            Self::AcceptedPermanentDerivationLoss { .. } => None,
        }
    }

    /// Returns the exact accepted-loss authorization bytes for this branch.
    pub fn accepted_loss_authorization_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::CurrentRoleBackups { .. } => None,
            Self::AcceptedPermanentDerivationLoss {
                authorization_bytes,
                ..
            } => Some(authorization_bytes),
        }
    }

    /// Returns the exact accepted-loss authorization digest for this branch.
    pub const fn accepted_loss_authorization_digest(
        &self,
    ) -> Option<&TenantRootAcceptedPermanentLossAuthorizationDigestV1> {
        match self {
            Self::CurrentRoleBackups { .. } => None,
            Self::AcceptedPermanentDerivationLoss {
                authorization_digest,
                ..
            } => Some(authorization_digest),
        }
    }

    fn from_verified_availability(
        availability: TenantRootActivationAvailabilityEvidenceViewV1<'_>,
    ) -> RouterAbDerivationResult<Self> {
        match availability {
            TenantRootActivationAvailabilityEvidenceViewV1::CurrentRoleBackups {
                deriver_a,
                deriver_b,
            } => Ok(Self::CurrentRoleBackups {
                receipts: TenantRootRoleBackupReceiptsV1::new(
                    deriver_a.receipt_digest(),
                    deriver_b.receipt_digest(),
                )?,
            }),
            TenantRootActivationAvailabilityEvidenceViewV1::AcceptedPermanentDerivationLoss {
                authorization,
            } => {
                let authorization_bytes = authorization.canonical_bytes().to_vec();
                let authorization_digest = authorization.digest();
                let derived_digest: [u8; 32] = Sha256::digest(&authorization_bytes).into();
                if authorization_digest.as_bytes() != &derived_digest {
                    return Err(malformed(
                        "tenant-root accepted-loss authorization digest is inconsistent",
                    ));
                }
                Ok(Self::AcceptedPermanentDerivationLoss {
                    authorization_bytes,
                    authorization_digest,
                })
            }
        }
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        match self {
            Self::CurrentRoleBackups { receipts } => {
                TenantRootRoleBackupReceiptsV1::new(receipts.deriver_a(), receipts.deriver_b())?;
            }
            Self::AcceptedPermanentDerivationLoss {
                authorization_bytes,
                authorization_digest,
            } => {
                if authorization_bytes.is_empty() {
                    return Err(malformed(
                        "tenant-root accepted-loss authorization bytes are required",
                    ));
                }
                let authorization =
                    TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
                        authorization_bytes,
                    )?;
                let derived_digest = authorization.digest()?;
                if &derived_digest != authorization_digest {
                    return Err(malformed(
                        "tenant-root accepted-loss authorization digest does not match its bytes",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Unsigned public fields expected for initial-creation activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootInitialCreationActivationReceiptBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    context_digest: TenantRootProtocolDigestV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    availability: TenantRootActivationReceiptAvailabilityV1,
    canary_receipts: TenantRootCanaryReceiptsV1,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: String,
}

impl TenantRootInitialCreationActivationReceiptBindingV1 {
    /// Builds the exact initial-creation binding from verified activation evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_bundle(
        bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        bundle.require_fresh(activated_at_ms)?;
        let context = bundle.context();
        Self::new(
            bundle.identity_digest(),
            bundle.custody_lineage(),
            bundle.context_digest(),
            bundle.expected_control_plane_revision(),
            bundle.result_control_plane_revision(),
            bundle.commitments().clone(),
            bundle.installation_receipts(),
            TenantRootActivationReceiptAvailabilityV1::from_verified_availability(
                bundle.availability(),
            )?,
            bundle.canary_receipts(),
            activated_at_ms,
            authority_id,
            context.issued_at_ms(),
            context.expires_at_ms(),
            issuer_key_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        context_digest: TenantRootProtocolDigestV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
        commitments: TenantRootEpochCommitmentsV1,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        availability: TenantRootActivationReceiptAvailabilityV1,
        canary_receipts: TenantRootCanaryReceiptsV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest,
            custody_lineage,
            context_digest,
            expected_control_plane_revision,
            result_control_plane_revision,
            commitments,
            installation_receipts,
            availability,
            canary_receipts,
            activated_at_ms,
            authority_id,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id: issuer_key_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the fixed initial-creation transition.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        TenantRootActivationReceiptTransitionV1::InitialCreation
    }

    /// Returns the fixed initial epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        TenantRootShareEpoch::INITIAL
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact creation ceremony context digest.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.context_digest
    }

    /// Returns the expected control-plane revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }

    /// Returns the exact control-plane revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.result_control_plane_revision
    }

    /// Returns the exact epoch-one A/B and root commitments.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    /// Returns both exact role installation receipt digests.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.installation_receipts
    }

    /// Returns the exact availability branch authenticated by this binding.
    pub const fn availability(&self) -> &TenantRootActivationReceiptAvailabilityV1 {
        &self.availability
    }

    /// Returns both exact continuity-canary receipt digests.
    pub const fn canary_receipts(&self) -> TenantRootCanaryReceiptsV1 {
        self.canary_receipts
    }

    /// Returns the authenticated activation time.
    pub const fn activated_at_ms(&self) -> u64 {
        self.activated_at_ms
    }

    /// Returns the tenant-root control-plane authority.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.authority_id
    }

    /// Returns the receipt issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the receipt expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the issuer key identifier authenticated by the signature.
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.expected_control_plane_revision
            != TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1
            || self.result_control_plane_revision
                != TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1
        {
            return Err(malformed(
                "tenant-root initial activation expected revision is invalid",
            ));
        }
        validate_commitments(&self.commitments)?;
        self.availability.validate()?;
        validate_receipt_window(self.issued_at_ms, self.expires_at_ms, self.activated_at_ms)?;
        validate_issuer_key_id(&self.issuer_key_id)
    }
}

/// Unsigned public fields expected for a refresh-swap activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRefreshSwapActivationReceiptBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    current_epoch: TenantRootShareEpoch,
    next_epoch: TenantRootShareEpoch,
    current_commitments: TenantRootEpochCommitmentsV1,
    next_commitments: TenantRootEpochCommitmentsV1,
    context_digest: TenantRootProtocolDigestV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    availability: TenantRootActivationReceiptAvailabilityV1,
    canary_receipts: TenantRootCanaryReceiptsV1,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: String,
}

impl TenantRootRefreshSwapActivationReceiptBindingV1 {
    /// Builds the exact refresh-swap binding from verified activation evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_bundle(
        bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        bundle.require_fresh(activated_at_ms)?;
        let context = bundle.context();
        Self::new(
            bundle.identity_digest(),
            bundle.custody_lineage(),
            bundle.current_epoch(),
            bundle.next_epoch(),
            bundle.current_commitments().clone(),
            bundle.next_commitments().clone(),
            bundle.context_digest(),
            bundle.expected_control_plane_revision(),
            bundle.result_control_plane_revision(),
            bundle.installation_receipts(),
            TenantRootActivationReceiptAvailabilityV1::from_verified_availability(
                bundle.availability(),
            )?,
            bundle.canary_receipts(),
            activated_at_ms,
            authority_id,
            context.issued_at_ms(),
            context.expires_at_ms(),
            issuer_key_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        current_epoch: TenantRootShareEpoch,
        next_epoch: TenantRootShareEpoch,
        current_commitments: TenantRootEpochCommitmentsV1,
        next_commitments: TenantRootEpochCommitmentsV1,
        context_digest: TenantRootProtocolDigestV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        availability: TenantRootActivationReceiptAvailabilityV1,
        canary_receipts: TenantRootCanaryReceiptsV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest,
            custody_lineage,
            current_epoch,
            next_epoch,
            current_commitments,
            next_commitments,
            context_digest,
            expected_control_plane_revision,
            result_control_plane_revision,
            installation_receipts,
            availability,
            canary_receipts,
            activated_at_ms,
            authority_id,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id: issuer_key_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the fixed refresh-swap transition.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        TenantRootActivationReceiptTransitionV1::RefreshSwap
    }

    /// Returns the active epoch before the swap.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.current_epoch
    }

    /// Returns the exact next epoch activated by the swap.
    pub const fn next_epoch(&self) -> TenantRootShareEpoch {
        self.next_epoch
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact refresh ceremony context digest.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.context_digest
    }

    /// Returns the expected control-plane revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }

    /// Returns the exact control-plane revision produced by the swap.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.result_control_plane_revision
    }

    /// Returns the exact commitments for the epoch being retired.
    pub const fn current_commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.current_commitments
    }

    /// Returns the exact commitments for the epoch being activated.
    pub const fn next_commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.next_commitments
    }

    /// Returns both exact role installation receipt digests.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.installation_receipts
    }

    /// Returns the exact availability branch authenticated by this binding.
    pub const fn availability(&self) -> &TenantRootActivationReceiptAvailabilityV1 {
        &self.availability
    }

    /// Returns both exact continuity-canary receipt digests.
    pub const fn canary_receipts(&self) -> TenantRootCanaryReceiptsV1 {
        self.canary_receipts
    }

    /// Returns the authenticated activation time.
    pub const fn activated_at_ms(&self) -> u64 {
        self.activated_at_ms
    }

    /// Returns the tenant-root control-plane authority.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.authority_id
    }

    /// Returns the receipt issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the receipt expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the issuer key identifier authenticated by the signature.
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.current_epoch.next()? != self.next_epoch {
            return Err(malformed(
                "tenant-root refresh activation epochs must advance exactly one",
            ));
        }
        if self.current_commitments.root_commitment() != self.next_commitments.root_commitment() {
            return Err(malformed(
                "tenant-root refresh activation changed the public root commitment",
            ));
        }
        validate_commitments(&self.current_commitments)?;
        validate_commitments(&self.next_commitments)?;
        if self.current_commitments == self.next_commitments {
            return Err(malformed(
                "tenant-root refresh activation must replace the role commitments",
            ));
        }
        if self.expected_control_plane_revision == 0 {
            return Err(malformed(
                "tenant-root refresh activation expected revision must be positive",
            ));
        }
        let expected_result_control_plane_revision = self
            .expected_control_plane_revision
            .checked_add(1)
            .ok_or_else(|| {
                malformed("tenant-root refresh activation expected revision cannot advance")
            })?;
        if self.result_control_plane_revision != expected_result_control_plane_revision {
            return Err(malformed(
                "tenant-root refresh activation result revision must advance exactly one",
            ));
        }
        self.availability.validate()?;
        validate_receipt_window(self.issued_at_ms, self.expires_at_ms, self.activated_at_ms)?;
        validate_issuer_key_id(&self.issuer_key_id)
    }
}

/// Exact branch-specific unsigned fields authenticated by an activation receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootActivationReceiptBindingV1 {
    /// Epoch-one creation activation.
    InitialCreation(TenantRootInitialCreationActivationReceiptBindingV1),
    /// One-step forward refresh swap.
    RefreshSwap(TenantRootRefreshSwapActivationReceiptBindingV1),
}

impl TenantRootActivationReceiptBindingV1 {
    /// Returns the exact forward-only transition.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        match self {
            Self::InitialCreation(binding) => binding.transition(),
            Self::RefreshSwap(binding) => binding.transition(),
        }
    }

    /// Returns the exact identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        match self {
            Self::InitialCreation(binding) => binding.identity_digest(),
            Self::RefreshSwap(binding) => binding.identity_digest(),
        }
    }

    /// Returns the exact custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        match self {
            Self::InitialCreation(binding) => binding.custody_lineage(),
            Self::RefreshSwap(binding) => binding.custody_lineage(),
        }
    }

    /// Returns the exact ceremony context digest.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        match self {
            Self::InitialCreation(binding) => binding.context_digest(),
            Self::RefreshSwap(binding) => binding.context_digest(),
        }
    }

    /// Returns the revision from which activation was dispatched.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        match self {
            Self::InitialCreation(binding) => binding.expected_control_plane_revision(),
            Self::RefreshSwap(binding) => binding.expected_control_plane_revision(),
        }
    }

    /// Returns the exact control-plane revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        match self {
            Self::InitialCreation(binding) => binding.result_control_plane_revision(),
            Self::RefreshSwap(binding) => binding.result_control_plane_revision(),
        }
    }

    /// Returns the exact availability branch authenticated by this binding.
    pub const fn availability(&self) -> &TenantRootActivationReceiptAvailabilityV1 {
        match self {
            Self::InitialCreation(binding) => binding.availability(),
            Self::RefreshSwap(binding) => binding.availability(),
        }
    }

    /// Returns the activation timestamp.
    pub const fn activated_at_ms(&self) -> u64 {
        match self {
            Self::InitialCreation(binding) => binding.activated_at_ms(),
            Self::RefreshSwap(binding) => binding.activated_at_ms(),
        }
    }

    /// Returns the control-plane authority.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        match self {
            Self::InitialCreation(binding) => binding.authority_id(),
            Self::RefreshSwap(binding) => binding.authority_id(),
        }
    }

    /// Returns the receipt issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        match self {
            Self::InitialCreation(binding) => binding.issued_at_ms(),
            Self::RefreshSwap(binding) => binding.issued_at_ms(),
        }
    }

    /// Returns the receipt expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        match self {
            Self::InitialCreation(binding) => binding.expires_at_ms(),
            Self::RefreshSwap(binding) => binding.expires_at_ms(),
        }
    }

    /// Returns the issuer key identifier.
    pub fn issuer_key_id(&self) -> &str {
        match self {
            Self::InitialCreation(binding) => binding.issuer_key_id(),
            Self::RefreshSwap(binding) => binding.issuer_key_id(),
        }
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        match self {
            Self::InitialCreation(binding) => binding.validate(),
            Self::RefreshSwap(binding) => binding.validate(),
        }
    }
}

/// Control-plane-signed activation receipt before issuer verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootSignedActivationReceiptV1 {
    binding: TenantRootActivationReceiptBindingV1,
    signature: [u8; 64],
}

impl TenantRootSignedActivationReceiptV1 {
    /// Signs an activation whose binding is derived from verified creation evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_initial_creation(
        bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let binding = TenantRootInitialCreationActivationReceiptBindingV1::from_verified_bundle(
            bundle,
            activated_at_ms,
            authority_id,
            issuer_key_id,
        )?;
        Self::sign_binding(
            TenantRootActivationReceiptBindingV1::InitialCreation(binding),
            issuer_signing_key_bytes,
        )
    }

    /// Signs an activation whose binding is derived from verified refresh evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_refresh_swap(
        bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let binding = TenantRootRefreshSwapActivationReceiptBindingV1::from_verified_bundle(
            bundle,
            activated_at_ms,
            authority_id,
            issuer_key_id,
        )?;
        Self::sign_binding(
            TenantRootActivationReceiptBindingV1::RefreshSwap(binding),
            issuer_signing_key_bytes,
        )
    }

    fn sign_binding(
        binding: TenantRootActivationReceiptBindingV1,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        binding.validate()?;
        let unsigned = unsigned_canonical_bytes(&binding)?;
        let signature = SigningKey::from_bytes(issuer_signing_key_bytes)
            .sign(&authentication_input(binding.issuer_key_id(), &unsigned)?)
            .to_bytes();
        let receipt = Self { binding, signature };
        receipt.canonical_bytes()?;
        Ok(receipt)
    }

    /// Decodes exactly one canonical signed activation receipt wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root activation receipt wire length is invalid",
            ));
        }
        let mut decoder = ActivationReceiptWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_ACTIVATION_RECEIPT_DOMAIN_V1)?;
        let operation = decoder.field("tenant-root activation receipt operation")?;
        let binding = match operation {
            TENANT_ROOT_ACTIVATION_INITIAL_CREATION_OPERATION_BYTES_V1 => {
                TenantRootActivationReceiptBindingV1::InitialCreation(
                    decode_initial_creation_binding(&mut decoder)?,
                )
            }
            TENANT_ROOT_ACTIVATION_REFRESH_SWAP_OPERATION_BYTES_V1 => {
                TenantRootActivationReceiptBindingV1::RefreshSwap(decode_refresh_swap_binding(
                    &mut decoder,
                )?)
            }
            _ => {
                return Err(malformed(
                    "tenant-root activation receipt operation is invalid",
                ));
            }
        };
        let signature = decoder.fixed_field::<64>("tenant-root activation receipt signature")?;
        decoder.finish()?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root activation receipt signature must be nonzero",
            ));
        }
        let receipt = Self { binding, signature };
        receipt.binding.validate()?;
        if receipt.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root activation receipt wire is not canonical",
            ));
        }
        Ok(receipt)
    }

    /// Returns the exact branch authenticated by this receipt.
    pub const fn binding(&self) -> &TenantRootActivationReceiptBindingV1 {
        &self.binding
    }

    /// Returns the exact availability branch authenticated by this receipt.
    pub const fn availability(&self) -> &TenantRootActivationReceiptAvailabilityV1 {
        self.binding.availability()
    }

    /// Returns the exact forward-only transition.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.binding.transition()
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding.identity_digest()
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding.custody_lineage()
    }

    /// Returns the exact ceremony context digest.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.binding.context_digest()
    }

    /// Returns the expected control-plane revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.binding.expected_control_plane_revision()
    }

    /// Returns the exact control-plane revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.binding.result_control_plane_revision()
    }

    /// Returns the activation timestamp.
    pub const fn activated_at_ms(&self) -> u64 {
        self.binding.activated_at_ms()
    }

    /// Returns the receipt issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.binding.issued_at_ms()
    }

    /// Returns the receipt expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        self.binding.expires_at_ms()
    }

    /// Returns the issuer key identifier authenticated by the signature.
    pub fn issuer_key_id(&self) -> &str {
        self.binding.issuer_key_id()
    }

    /// Returns the exact issuer signature bytes.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns the exact canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.validate()?;
        if self.signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root activation receipt signature must be nonzero",
            ));
        }
        let mut bytes = unsigned_canonical_bytes(&self.binding)?;
        push_field(&mut bytes, &self.signature)?;
        Ok(bytes)
    }

    /// Returns the SHA-256 digest of the exact signed receipt bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootLifecycleReceiptDigestV1> {
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            Sha256::digest(self.canonical_bytes()?).into(),
        )
    }

    /// Verifies this receipt's own binding against a trusted issuer key.
    ///
    /// The returned token retains the exact canonical bytes accepted by this
    /// receipt, so callers can authenticate a persisted receipt without an
    /// activation evidence bundle.
    pub fn verify_issuer_signature(
        self,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootSignedActivationReceiptV1> {
        self.binding.validate()?;
        verify_signature(&self.binding, &self.signature, trusted_issuer_verifying_key)?;
        let canonical_bytes = self.canonical_bytes()?;
        let digest = TenantRootLifecycleReceiptDigestV1::from_bytes(
            Sha256::digest(&canonical_bytes).into(),
        )?;
        Ok(VerifiedTenantRootSignedActivationReceiptV1 {
            receipt: self,
            canonical_bytes,
            digest,
        })
    }

    fn verify_binding(
        self,
        expected: &TenantRootActivationReceiptBindingV1,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootSignedActivationReceiptV1> {
        self.binding.validate()?;
        expected.validate()?;
        let actual_unsigned = unsigned_canonical_bytes(&self.binding)?;
        let expected_unsigned = unsigned_canonical_bytes(expected)?;
        if actual_unsigned != expected_unsigned {
            return Err(replay_mismatch(
                "tenant-root activation receipt does not match its expected binding",
            ));
        }
        self.verify_issuer_signature(trusted_issuer_verifying_key)
    }

    /// Verifies an initial-creation receipt against verified evidence and authority metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_initial_creation(
        self,
        bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_key_id: impl Into<String>,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootSignedActivationReceiptV1> {
        let expected = TenantRootInitialCreationActivationReceiptBindingV1::from_verified_bundle(
            bundle,
            activated_at_ms,
            authority_id,
            issuer_key_id,
        )?;
        self.verify_binding(
            &TenantRootActivationReceiptBindingV1::InitialCreation(expected.clone()),
            trusted_issuer_verifying_key,
        )
    }

    /// Verifies a refresh-swap receipt against verified evidence and authority metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_refresh_swap(
        self,
        bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
        activated_at_ms: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_key_id: impl Into<String>,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootSignedActivationReceiptV1> {
        let expected = TenantRootRefreshSwapActivationReceiptBindingV1::from_verified_bundle(
            bundle,
            activated_at_ms,
            authority_id,
            issuer_key_id,
        )?;
        self.verify_binding(
            &TenantRootActivationReceiptBindingV1::RefreshSwap(expected.clone()),
            trusted_issuer_verifying_key,
        )
    }
}

/// Issuer-verified activation receipt retaining the exact accepted wire.
///
/// This token intentionally has no public constructor and does not implement
/// `Clone` or `Copy`; callers must retain or consume the exact verified bytes.
pub struct VerifiedTenantRootSignedActivationReceiptV1 {
    receipt: TenantRootSignedActivationReceiptV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootLifecycleReceiptDigestV1,
}

impl fmt::Debug for VerifiedTenantRootSignedActivationReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootSignedActivationReceiptV1")
            .field("transition", &self.receipt.transition())
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public authenticated bytes]")
            .finish()
    }
}

impl VerifiedTenantRootSignedActivationReceiptV1 {
    /// Returns the exact branch authenticated by this token.
    pub const fn binding(&self) -> &TenantRootActivationReceiptBindingV1 {
        self.receipt.binding()
    }

    /// Returns the exact availability branch authenticated by this token.
    pub const fn availability(&self) -> &TenantRootActivationReceiptAvailabilityV1 {
        self.receipt.availability()
    }

    /// Returns the exact transition authenticated by this token.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.receipt.transition()
    }

    /// Returns the exact identity digest authenticated by this token.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.receipt.identity_digest()
    }

    /// Returns the exact custody lineage authenticated by this token.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.receipt.custody_lineage()
    }

    /// Returns the exact ceremony context digest authenticated by this token.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.receipt.context_digest()
    }

    /// Returns the expected control-plane revision authenticated by this token.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.receipt.expected_control_plane_revision()
    }

    /// Returns the exact control-plane revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.receipt.result_control_plane_revision()
    }

    /// Returns the authenticated activation timestamp.
    pub const fn activated_at_ms(&self) -> u64 {
        self.receipt.activated_at_ms()
    }

    /// Returns the authenticated issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.receipt.issued_at_ms()
    }

    /// Returns the authenticated expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.receipt.expires_at_ms()
    }

    /// Returns the authenticated issuer key identifier.
    pub fn issuer_key_id(&self) -> &str {
        self.receipt.issuer_key_id()
    }

    /// Returns the exact issuer signature bytes authenticated by this token.
    pub const fn signature(&self) -> &[u8; 64] {
        self.receipt.signature()
    }

    /// Returns the exact canonical signed receipt bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub const fn digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.digest
    }

    /// Requires the token to be used inside its inclusive freshness window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.issued_at_ms() || now_ms > self.expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root activation receipt is outside its freshness window",
            ));
        }
        Ok(())
    }

    /// Consumes the token into the exact canonical signed receipt bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

fn decode_initial_creation_binding(
    decoder: &mut ActivationReceiptWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootInitialCreationActivationReceiptBindingV1> {
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root initial activation identity digest")?,
    );
    let custody_lineage = TenantRootCustodyLineageId::from_bytes(
        decoder.fixed_field::<16>("tenant-root initial activation custody lineage")?,
    )?;
    let epoch =
        TenantRootShareEpoch::new(decoder.u64_field("tenant-root initial activation epoch")?)?;
    if epoch != TenantRootShareEpoch::INITIAL {
        return Err(malformed(
            "tenant-root initial activation epoch must be one",
        ));
    }
    let context_digest = TenantRootProtocolDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root initial activation context digest")?,
    )?;
    let expected_control_plane_revision =
        decoder.u64_field("tenant-root initial activation expected revision")?;
    let result_control_plane_revision =
        decoder.u64_field("tenant-root initial activation result revision")?;
    let commitments = decode_commitments(decoder, "tenant-root initial activation")?;
    let installation_receipts =
        decode_installation_receipts(decoder, "tenant-root initial activation")?;
    let availability = decode_availability(decoder)?;
    let canary_receipts = decode_canary_receipts(decoder, "tenant-root initial activation")?;
    let activated_at_ms = decoder.u64_field("tenant-root initial activation time")?;
    let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root initial activation authority")?,
    );
    let issued_at_ms = decoder.u64_field("tenant-root initial activation issue time")?;
    let expires_at_ms = decoder.u64_field("tenant-root initial activation expiry")?;
    let issuer_key_id = decoder.text_field(
        "tenant-root initial activation issuer key id",
        TENANT_ROOT_ACTIVATION_ISSUER_KEY_ID_MAX_BYTES_V1,
    )?;
    TenantRootInitialCreationActivationReceiptBindingV1::new(
        identity_digest,
        custody_lineage,
        context_digest,
        expected_control_plane_revision,
        result_control_plane_revision,
        commitments,
        installation_receipts,
        availability,
        canary_receipts,
        activated_at_ms,
        authority_id,
        issued_at_ms,
        expires_at_ms,
        issuer_key_id,
    )
}

fn decode_refresh_swap_binding(
    decoder: &mut ActivationReceiptWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootRefreshSwapActivationReceiptBindingV1> {
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root refresh activation identity digest")?,
    );
    let custody_lineage = TenantRootCustodyLineageId::from_bytes(
        decoder.fixed_field::<16>("tenant-root refresh activation custody lineage")?,
    )?;
    let current_epoch = TenantRootShareEpoch::new(
        decoder.u64_field("tenant-root refresh activation current epoch")?,
    )?;
    let next_epoch =
        TenantRootShareEpoch::new(decoder.u64_field("tenant-root refresh activation next epoch")?)?;
    let context_digest = TenantRootProtocolDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root refresh activation context digest")?,
    )?;
    let expected_control_plane_revision =
        decoder.u64_field("tenant-root refresh activation expected revision")?;
    let result_control_plane_revision =
        decoder.u64_field("tenant-root refresh activation result revision")?;
    let current_commitments = decode_commitments(decoder, "tenant-root refresh current")?;
    let next_commitments = decode_commitments(decoder, "tenant-root refresh next")?;
    let installation_receipts =
        decode_installation_receipts(decoder, "tenant-root refresh activation")?;
    let availability = decode_availability(decoder)?;
    let canary_receipts = decode_canary_receipts(decoder, "tenant-root refresh activation")?;
    let activated_at_ms = decoder.u64_field("tenant-root refresh activation time")?;
    let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root refresh activation authority")?,
    );
    let issued_at_ms = decoder.u64_field("tenant-root refresh activation issue time")?;
    let expires_at_ms = decoder.u64_field("tenant-root refresh activation expiry")?;
    let issuer_key_id = decoder.text_field(
        "tenant-root refresh activation issuer key id",
        TENANT_ROOT_ACTIVATION_ISSUER_KEY_ID_MAX_BYTES_V1,
    )?;
    TenantRootRefreshSwapActivationReceiptBindingV1::new(
        identity_digest,
        custody_lineage,
        current_epoch,
        next_epoch,
        current_commitments,
        next_commitments,
        context_digest,
        expected_control_plane_revision,
        result_control_plane_revision,
        installation_receipts,
        availability,
        canary_receipts,
        activated_at_ms,
        authority_id,
        issued_at_ms,
        expires_at_ms,
        issuer_key_id,
    )
}

fn decode_commitments(
    decoder: &mut ActivationReceiptWireDecoderV1<'_>,
    prefix: &str,
) -> RouterAbDerivationResult<TenantRootEpochCommitmentsV1> {
    let deriver_a = MpcPrfShareCommitmentWireV1::new(
        decoder
            .field("tenant-root activation Deriver A commitment")?
            .to_vec(),
    )?;
    let deriver_b = MpcPrfShareCommitmentWireV1::new(
        decoder
            .field("tenant-root activation Deriver B commitment")?
            .to_vec(),
    )?;
    let root_commitment = decoder.fixed_field::<32>("tenant-root activation root commitment")?;
    let commitments = TenantRootEpochCommitmentsV1::new(deriver_a, deriver_b)?;
    if commitments.root_commitment() != &root_commitment {
        return Err(malformed(format!(
            "{prefix} root commitment does not match its role commitments"
        )));
    }
    Ok(commitments)
}

fn decode_installation_receipts(
    decoder: &mut ActivationReceiptWireDecoderV1<'_>,
    _prefix: &str,
) -> RouterAbDerivationResult<TenantRootRoleInstallationReceiptsV1> {
    TenantRootRoleInstallationReceiptsV1::new(
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root activation Deriver A installation receipt")?,
        )?,
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root activation Deriver B installation receipt")?,
        )?,
    )
}

fn decode_availability(
    decoder: &mut ActivationReceiptWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootActivationReceiptAvailabilityV1> {
    let branch = decoder.field("tenant-root activation availability branch")?;
    match branch {
        TENANT_ROOT_ACTIVATION_CURRENT_ROLE_BACKUPS_BRANCH_BYTES_V1 => Ok(
            TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups {
                receipts: TenantRootRoleBackupReceiptsV1::new(
                    TenantRootLifecycleReceiptDigestV1::from_bytes(
                        decoder
                            .fixed_field::<32>("tenant-root activation Deriver A backup receipt")?,
                    )?,
                    TenantRootLifecycleReceiptDigestV1::from_bytes(
                        decoder
                            .fixed_field::<32>("tenant-root activation Deriver B backup receipt")?,
                    )?,
                )?,
            },
        ),
        TENANT_ROOT_ACTIVATION_ACCEPTED_PERMANENT_DERIVATION_LOSS_BRANCH_BYTES_V1 => {
            let authorization_bytes = decoder
                .field("tenant-root activation accepted-loss authorization")?
                .to_vec();
            let authorization =
                TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
                    &authorization_bytes,
                )?;
            let authorization_digest = authorization.digest()?;
            let encoded_digest =
                decoder.fixed_field::<32>("tenant-root activation accepted-loss digest")?;
            if authorization_digest.as_bytes() != &encoded_digest {
                return Err(malformed(
                    "tenant-root accepted-loss authorization digest does not match its bytes",
                ));
            }
            Ok(
                TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
                    authorization_bytes,
                    authorization_digest,
                },
            )
        }
        _ => Err(malformed(
            "tenant-root activation availability branch is invalid",
        )),
    }
}

fn decode_canary_receipts(
    decoder: &mut ActivationReceiptWireDecoderV1<'_>,
    _prefix: &str,
) -> RouterAbDerivationResult<TenantRootCanaryReceiptsV1> {
    TenantRootCanaryReceiptsV1::new(
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root activation ECDSA canary receipt")?,
        )?,
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root activation Ed25519 canary receipt")?,
        )?,
    )
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
            "tenant-root activation commitments are not canonical",
        ));
    }
    Ok(())
}

fn validate_receipt_window(
    issued_at_ms: u64,
    expires_at_ms: u64,
    activated_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        return Err(malformed(
            "tenant-root activation receipt expiry must follow a non-zero issue time",
        ));
    }
    if expires_at_ms - issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root activation receipt lifetime exceeds the frozen maximum window",
        ));
    }
    if activated_at_ms < issued_at_ms || activated_at_ms > expires_at_ms {
        return Err(malformed(
            "tenant-root activation time must fall within the receipt window",
        ));
    }
    Ok(())
}

fn validate_issuer_key_id(value: &str) -> RouterAbDerivationResult<()> {
    require_tenant_root_identifier("tenant-root activation issuer key id", value)?;
    if value.len() > TENANT_ROOT_ACTIVATION_ISSUER_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root activation issuer key id is too long",
        ));
    }
    Ok(())
}

fn unsigned_canonical_bytes(
    binding: &TenantRootActivationReceiptBindingV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    binding.validate()?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ACTIVATION_RECEIPT_DOMAIN_V1)?;
    push_field(&mut bytes, binding.transition().operation_bytes())?;
    push_field(&mut bytes, binding.identity_digest().as_bytes())?;
    push_field(&mut bytes, binding.custody_lineage().as_bytes())?;
    match binding {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => {
            push_field(
                &mut bytes,
                &TenantRootShareEpoch::INITIAL.get().get().to_be_bytes(),
            )?;
            push_field(&mut bytes, binding.context_digest.as_bytes())?;
            push_field(
                &mut bytes,
                &binding.expected_control_plane_revision.to_be_bytes(),
            )?;
            push_field(
                &mut bytes,
                &binding.result_control_plane_revision.to_be_bytes(),
            )?;
            append_commitments(&mut bytes, &binding.commitments)?;
            append_installation_receipts(&mut bytes, &binding.installation_receipts)?;
            append_availability(&mut bytes, &binding.availability)?;
            append_canaries(&mut bytes, &binding.canary_receipts)?;
            append_common_suffix(
                &mut bytes,
                binding.activated_at_ms,
                binding.authority_id,
                binding.issued_at_ms,
                binding.expires_at_ms,
                &binding.issuer_key_id,
            )?;
        }
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => {
            push_field(&mut bytes, &binding.current_epoch.get().get().to_be_bytes())?;
            push_field(&mut bytes, &binding.next_epoch.get().get().to_be_bytes())?;
            push_field(&mut bytes, binding.context_digest.as_bytes())?;
            push_field(
                &mut bytes,
                &binding.expected_control_plane_revision.to_be_bytes(),
            )?;
            push_field(
                &mut bytes,
                &binding.result_control_plane_revision.to_be_bytes(),
            )?;
            append_commitments(&mut bytes, &binding.current_commitments)?;
            append_commitments(&mut bytes, &binding.next_commitments)?;
            append_installation_receipts(&mut bytes, &binding.installation_receipts)?;
            append_availability(&mut bytes, &binding.availability)?;
            append_canaries(&mut bytes, &binding.canary_receipts)?;
            append_common_suffix(
                &mut bytes,
                binding.activated_at_ms,
                binding.authority_id,
                binding.issued_at_ms,
                binding.expires_at_ms,
                &binding.issuer_key_id,
            )?;
        }
    }
    if bytes.len() > TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1 {
        return Err(malformed("tenant-root activation receipt wire is too long"));
    }
    Ok(bytes)
}

fn append_commitments(
    bytes: &mut Vec<u8>,
    commitments: &TenantRootEpochCommitmentsV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, commitments.deriver_a().as_bytes())?;
    push_field(bytes, commitments.deriver_b().as_bytes())?;
    push_field(bytes, commitments.root_commitment())
}

fn append_installation_receipts(
    bytes: &mut Vec<u8>,
    installation: &TenantRootRoleInstallationReceiptsV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, installation.deriver_a().as_bytes())?;
    push_field(bytes, installation.deriver_b().as_bytes())
}

fn append_availability(
    bytes: &mut Vec<u8>,
    availability: &TenantRootActivationReceiptAvailabilityV1,
) -> RouterAbDerivationResult<()> {
    match availability {
        TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { receipts } => {
            push_field(
                bytes,
                TENANT_ROOT_ACTIVATION_CURRENT_ROLE_BACKUPS_BRANCH_BYTES_V1,
            )?;
            push_field(bytes, receipts.deriver_a().as_bytes())?;
            push_field(bytes, receipts.deriver_b().as_bytes())
        }
        TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
            authorization_bytes,
            authorization_digest,
        } => {
            push_field(
                bytes,
                TENANT_ROOT_ACTIVATION_ACCEPTED_PERMANENT_DERIVATION_LOSS_BRANCH_BYTES_V1,
            )?;
            push_field(bytes, authorization_bytes)?;
            push_field(bytes, authorization_digest.as_bytes())
        }
    }
}

fn append_canaries(
    bytes: &mut Vec<u8>,
    canaries: &TenantRootCanaryReceiptsV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, canaries.ecdsa().as_bytes())?;
    push_field(bytes, canaries.ed25519().as_bytes())
}

fn append_common_suffix(
    bytes: &mut Vec<u8>,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: &str,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, &activated_at_ms.to_be_bytes())?;
    push_field(bytes, authority_id.as_bytes())?;
    push_field(bytes, &issued_at_ms.to_be_bytes())?;
    push_field(bytes, &expires_at_ms.to_be_bytes())?;
    push_field(bytes, issuer_key_id.as_bytes())
}

fn authentication_input(issuer_key_id: &str, unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    validate_issuer_key_id(issuer_key_id)?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ACTIVATION_RECEIPT_AUTH_DOMAIN_V1)?;
    push_field(&mut bytes, issuer_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn verify_signature(
    binding: &TenantRootActivationReceiptBindingV1,
    signature: &[u8; 64],
    trusted_issuer_verifying_key: &[u8; 32],
) -> RouterAbDerivationResult<()> {
    let unsigned = unsigned_canonical_bytes(binding)?;
    let verifying_key = VerifyingKey::from_bytes(trusted_issuer_verifying_key)
        .map_err(|_| malformed("tenant-root activation issuer verifying key is invalid"))?;
    verifying_key
        .verify_strict(
            &authentication_input(binding.issuer_key_id(), &unsigned)?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::OutputVerificationFailed,
                "tenant-root activation receipt issuer signature is invalid",
            )
        })
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root activation receipt field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root activation receipt field is too long"))?;
    let new_length = bytes
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root activation receipt wire length overflows"))?;
    if new_length > TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1 {
        return Err(malformed("tenant-root activation receipt wire is too long"));
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

struct ActivationReceiptWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ActivationReceiptWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root activation receipt offset overflows"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root activation receipt field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte activation receipt field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root activation receipt field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root activation receipt field is truncated"))?;
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
        if self.field("tenant-root activation receipt domain")? != expected {
            return Err(malformed(
                "tenant-root activation receipt domain is invalid",
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
            .map_err(|_| malformed("tenant-root activation receipt fixed field length is invalid"))
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
            return Err(malformed(
                "tenant-root activation receipt text field is too long",
            ));
        }
        core::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root activation receipt text field is invalid UTF-8"))
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root activation receipt wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
