use core::fmt;

use threshold_prf::TwoPartyDeriverRole;

use super::{
    verify_tenant_root_creation_evidence_v1, verify_tenant_root_refresh_evidence_v1,
    MpcPrfShareCommitmentWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootAcceptedLossReceiptV1,
    TenantRootActivationReceiptTransitionV1, TenantRootBackupPolicyV1,
    TenantRootCanaryCurveFamilyV1, TenantRootCanaryReceiptsV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootProtocolDigestV1, TenantRootProviderCanaryReceiptDigestV1,
    TenantRootRoleBackupReceiptsV1, TenantRootRoleInstallationReceiptsV1, TenantRootShareEpoch,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1,
    VerifiedTenantRootAcceptedPermanentLossAuthorizationV1, VerifiedTenantRootManagedBackupV1,
    VerifiedTenantRootProviderCanaryReceiptV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};

/// Exact availability evidence accepted by a tenant-root activation.
///
/// Each branch owns the source artifact accepted by activation. The enum
/// deliberately has no clone or copy implementation so an activation cannot be
/// assembled from duplicated evidence tokens.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TenantRootActivationAvailabilityEvidenceV1 {
    /// Both current roles retain their independently verified managed backups.
    CurrentRoleBackups {
        /// Deriver A's exact verified managed-backup artifact.
        deriver_a: VerifiedTenantRootManagedBackupV1,
        /// Deriver B's exact verified managed-backup artifact.
        deriver_b: VerifiedTenantRootManagedBackupV1,
    },
    /// The deployment has an exact dual-authority authorization for permanent loss.
    AcceptedPermanentDerivationLoss {
        /// Exact accepted-loss authorization retained from a verified token.
        authorization: TenantRootAcceptedLossReceiptV1,
    },
}

impl TenantRootActivationAvailabilityEvidenceV1 {
    /// Creates the managed-backup availability branch.
    pub fn current_role_backups(
        deriver_a: VerifiedTenantRootManagedBackupV1,
        deriver_b: VerifiedTenantRootManagedBackupV1,
    ) -> Self {
        Self::CurrentRoleBackups {
            deriver_a,
            deriver_b,
        }
    }

    /// Creates the explicit accepted-permanent-loss availability branch.
    pub fn accepted_permanent_derivation_loss(
        authorization: TenantRootAcceptedLossReceiptV1,
    ) -> Self {
        Self::AcceptedPermanentDerivationLoss { authorization }
    }
}

/// Read-only view of the exact availability artifact retained by a bundle.
#[derive(Debug)]
pub enum TenantRootActivationAvailabilityEvidenceViewV1<'a> {
    /// Both verified managed backups retained by the bundle.
    CurrentRoleBackups {
        /// Deriver A's exact verified managed-backup artifact.
        deriver_a: &'a VerifiedTenantRootManagedBackupV1,
        /// Deriver B's exact verified managed-backup artifact.
        deriver_b: &'a VerifiedTenantRootManagedBackupV1,
    },
    /// The accepted-loss authorization retained by the bundle.
    AcceptedPermanentDerivationLoss {
        /// Exact accepted-loss authorization retained from a verified token.
        authorization: &'a TenantRootAcceptedLossReceiptV1,
    },
}

/// Verified initial-creation activation evidence assembled from exact source artifacts.
///
/// The bundle owns every verified evidence token and intentionally does not
/// implement `Clone` or `Copy`.
#[derive(Debug)]
pub struct VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
    common: ActivationEvidenceBundlePartsV1,
}

impl VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
    /// Builds the epoch-one activation evidence from one exact A/B creation ceremony.
    pub fn new(
        deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        availability: TenantRootActivationAvailabilityEvidenceV1,
        ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        let common = build_creation_evidence(
            deriver_a_installation,
            deriver_b_installation,
            availability,
            ecdsa_canary,
            ed25519_canary,
            expected_control_plane_revision,
            result_control_plane_revision,
        )?;
        Ok(Self { common })
    }

    /// Builds epoch-one evidence with explicit managed-backup availability.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_managed_backups(
        deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_a_backup: VerifiedTenantRootManagedBackupV1,
        deriver_b_backup: VerifiedTenantRootManagedBackupV1,
        ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        Self::new(
            deriver_a_installation,
            deriver_b_installation,
            TenantRootActivationAvailabilityEvidenceV1::current_role_backups(
                deriver_a_backup,
                deriver_b_backup,
            ),
            ecdsa_canary,
            ed25519_canary,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
    }

    /// Builds epoch-one evidence with an exact accepted-loss authorization.
    pub fn from_verified_accepted_loss(
        deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        authorization: VerifiedTenantRootAcceptedPermanentLossAuthorizationV1,
        ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        Self::new(
            deriver_a_installation,
            deriver_b_installation,
            TenantRootActivationAvailabilityEvidenceV1::accepted_permanent_derivation_loss(
                TenantRootAcceptedLossReceiptV1::from_verified(authorization),
            ),
            ecdsa_canary,
            ed25519_canary,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
    }

    /// Returns the forward-only activation transition.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.common.transition()
    }

    /// Returns the exact epoch branch authenticated by the ceremony.
    pub const fn epochs(&self) -> TenantRootCeremonyEpochsV1 {
        self.common.epochs()
    }

    /// Returns the initial epoch authenticated by this bundle.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        TenantRootShareEpoch::INITIAL
    }

    /// Returns the server-resolved tenant identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.common.identity_digest()
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.common.custody_lineage()
    }

    /// Returns the exact ceremony context used by both installation wires.
    pub const fn context(&self) -> &TenantRootCeremonyContextV1 {
        self.common.context()
    }

    /// Returns the digest of the exact ceremony context.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.common.context_digest()
    }

    /// Returns the authoritative lifecycle revision from which activation is claimed.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.common.expected_control_plane_revision()
    }

    /// Returns the authoritative lifecycle revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.common.result_control_plane_revision()
    }

    /// Returns the exact A/B commitments derived by creation verification.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.common.commitments()
    }

    /// Returns the stable joined public root commitment.
    pub const fn root_commitment(&self) -> &[u8; 32] {
        self.common.root_commitment()
    }

    /// Returns the exact role-installation receipt digest projection.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.common.installation_receipts()
    }

    /// Returns the exact availability projection for a strict activation receipt.
    pub fn backup_policy(&self) -> TenantRootBackupPolicyV1 {
        self.common.backup_policy()
    }

    /// Returns both exact provider-canary receipt digest projections.
    pub const fn canary_receipts(&self) -> TenantRootCanaryReceiptsV1 {
        self.common.canary_receipts()
    }

    /// Returns read-only access to the owned availability artifact.
    pub fn availability(&self) -> TenantRootActivationAvailabilityEvidenceViewV1<'_> {
        self.common.availability()
    }

    /// Requires all freshness windows to contain the supplied activation time.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        self.common.require_fresh(now_ms)
    }

    /// Consumes the bundle into the exact A/B signed installation-evidence wires.
    pub fn into_installation_evidence_bytes(self) -> (Vec<u8>, Vec<u8>) {
        self.common.into_installation_evidence_bytes()
    }
}

/// Verified refresh-swap activation evidence assembled from exact source artifacts.
///
/// The bundle owns every verified evidence token and intentionally does not
/// implement `Clone` or `Copy`.
#[derive(Debug)]
pub struct VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
    common: ActivationEvidenceBundlePartsV1,
    current_commitments: TenantRootEpochCommitmentsV1,
    current_epoch: TenantRootShareEpoch,
    next_epoch: TenantRootShareEpoch,
}

impl VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
    /// Builds one exact next-epoch activation evidence from a refresh ceremony.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_commitments: &TenantRootEpochCommitmentsV1,
        deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        availability: TenantRootActivationAvailabilityEvidenceV1,
        ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        let current_commitments = clone_commitments(current_commitments)?;
        let common = build_refresh_evidence(
            &current_commitments,
            deriver_a_installation,
            deriver_b_installation,
            availability,
            ecdsa_canary,
            ed25519_canary,
            expected_control_plane_revision,
            result_control_plane_revision,
        )?;
        let TenantRootCeremonyEpochsV1::Refresh { current, next } = common.epochs() else {
            return Err(malformed(
                "tenant-root refresh activation evidence scope has no refresh epochs",
            ));
        };
        Ok(Self {
            common,
            current_commitments,
            current_epoch: current,
            next_epoch: next,
        })
    }

    /// Builds refresh evidence with explicit managed-backup availability.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_managed_backups(
        current_commitments: &TenantRootEpochCommitmentsV1,
        deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_a_backup: VerifiedTenantRootManagedBackupV1,
        deriver_b_backup: VerifiedTenantRootManagedBackupV1,
        ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        Self::new(
            current_commitments,
            deriver_a_installation,
            deriver_b_installation,
            TenantRootActivationAvailabilityEvidenceV1::current_role_backups(
                deriver_a_backup,
                deriver_b_backup,
            ),
            ecdsa_canary,
            ed25519_canary,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
    }

    /// Builds refresh evidence with an exact accepted-loss authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_accepted_loss(
        current_commitments: &TenantRootEpochCommitmentsV1,
        deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        authorization: VerifiedTenantRootAcceptedPermanentLossAuthorizationV1,
        ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        Self::new(
            current_commitments,
            deriver_a_installation,
            deriver_b_installation,
            TenantRootActivationAvailabilityEvidenceV1::accepted_permanent_derivation_loss(
                TenantRootAcceptedLossReceiptV1::from_verified(authorization),
            ),
            ecdsa_canary,
            ed25519_canary,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
    }

    /// Returns the forward-only activation transition.
    pub const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        self.common.transition()
    }

    /// Returns the exact refresh epoch branch authenticated by the ceremony.
    pub const fn epochs(&self) -> TenantRootCeremonyEpochsV1 {
        self.common.epochs()
    }

    /// Returns the active epoch before this swap.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.current_epoch
    }

    /// Returns the next epoch activated by this swap.
    pub const fn next_epoch(&self) -> TenantRootShareEpoch {
        self.next_epoch
    }

    /// Returns the server-resolved tenant identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.common.identity_digest()
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.common.custody_lineage()
    }

    /// Returns the exact ceremony context used by both installation wires.
    pub const fn context(&self) -> &TenantRootCeremonyContextV1 {
        self.common.context()
    }

    /// Returns the digest of the exact ceremony context.
    pub const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.common.context_digest()
    }

    /// Returns the authoritative lifecycle revision from which activation is claimed.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.common.expected_control_plane_revision()
    }

    /// Returns the authoritative lifecycle revision produced by activation.
    pub const fn result_control_plane_revision(&self) -> u64 {
        self.common.result_control_plane_revision()
    }

    /// Returns the active epoch's exact A/B commitments.
    pub const fn current_commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.current_commitments
    }

    /// Returns the next epoch's exact A/B commitments derived by refresh verification.
    pub const fn next_commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.common.commitments()
    }

    /// Returns the next epoch's stable joined public root commitment.
    pub const fn root_commitment(&self) -> &[u8; 32] {
        self.common.root_commitment()
    }

    /// Returns the exact role-installation receipt digest projection.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.common.installation_receipts()
    }

    /// Returns the exact availability projection for a strict activation receipt.
    pub fn backup_policy(&self) -> TenantRootBackupPolicyV1 {
        self.common.backup_policy()
    }

    /// Returns both exact provider-canary receipt digest projections.
    pub const fn canary_receipts(&self) -> TenantRootCanaryReceiptsV1 {
        self.common.canary_receipts()
    }

    /// Returns read-only access to the owned availability artifact.
    pub fn availability(&self) -> TenantRootActivationAvailabilityEvidenceViewV1<'_> {
        self.common.availability()
    }

    /// Requires all freshness windows to contain the supplied activation time.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        self.common.require_fresh(now_ms)
    }

    /// Consumes the bundle into the exact A/B signed installation-evidence wires.
    pub fn into_installation_evidence_bytes(self) -> (Vec<u8>, Vec<u8>) {
        self.common.into_installation_evidence_bytes()
    }
}

struct ActivationEvidenceBundlePartsV1 {
    deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    availability: TenantRootActivationAvailabilityEvidenceV1,
    ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
    ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epochs: TenantRootCeremonyEpochsV1,
    context_digest: TenantRootProtocolDigestV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    backup_policy: TenantRootBackupPolicyV1,
    canary_receipts: TenantRootCanaryReceiptsV1,
}

impl fmt::Debug for ActivationEvidenceBundlePartsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationEvidenceBundlePartsV1")
            .field("deriver_a_installation", &self.deriver_a_installation)
            .field("deriver_b_installation", &self.deriver_b_installation)
            .field("availability", &self.availability)
            .field("ecdsa_canary", &self.ecdsa_canary)
            .field("ed25519_canary", &self.ed25519_canary)
            .field("identity_digest", &self.identity_digest)
            .field("custody_lineage", &self.custody_lineage)
            .field("epochs", &self.epochs)
            .field("context_digest", &self.context_digest)
            .field(
                "expected_control_plane_revision",
                &self.expected_control_plane_revision,
            )
            .field(
                "result_control_plane_revision",
                &self.result_control_plane_revision,
            )
            .field("commitments", &self.commitments)
            .field("installation_receipts", &self.installation_receipts)
            .field("backup_policy", &self.backup_policy)
            .field("canary_receipts", &self.canary_receipts)
            .finish()
    }
}

impl ActivationEvidenceBundlePartsV1 {
    const fn transition(&self) -> TenantRootActivationReceiptTransitionV1 {
        match self.epochs {
            TenantRootCeremonyEpochsV1::Create { .. } => {
                TenantRootActivationReceiptTransitionV1::InitialCreation
            }
            TenantRootCeremonyEpochsV1::Refresh { .. } => {
                TenantRootActivationReceiptTransitionV1::RefreshSwap
            }
        }
    }

    const fn epochs(&self) -> TenantRootCeremonyEpochsV1 {
        self.epochs
    }

    const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    const fn context(&self) -> &TenantRootCeremonyContextV1 {
        self.deriver_a_installation
            .evidence()
            .transcript()
            .context()
    }

    const fn context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.context_digest
    }

    const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }

    const fn result_control_plane_revision(&self) -> u64 {
        self.result_control_plane_revision
    }

    const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    const fn root_commitment(&self) -> &[u8; 32] {
        self.commitments.root_commitment()
    }

    const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.installation_receipts
    }

    fn backup_policy(&self) -> TenantRootBackupPolicyV1 {
        self.backup_policy.clone()
    }

    const fn canary_receipts(&self) -> TenantRootCanaryReceiptsV1 {
        self.canary_receipts
    }

    fn availability(&self) -> TenantRootActivationAvailabilityEvidenceViewV1<'_> {
        match &self.availability {
            TenantRootActivationAvailabilityEvidenceV1::CurrentRoleBackups {
                deriver_a,
                deriver_b,
            } => TenantRootActivationAvailabilityEvidenceViewV1::CurrentRoleBackups {
                deriver_a,
                deriver_b,
            },
            TenantRootActivationAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
                authorization,
            } => TenantRootActivationAvailabilityEvidenceViewV1::AcceptedPermanentDerivationLoss {
                authorization,
            },
        }
    }

    fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        self.ecdsa_canary.require_fresh(now_ms)?;
        self.ed25519_canary.require_fresh(now_ms)?;
        if let TenantRootActivationAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
            authorization,
        } = &self.availability
        {
            require_accepted_loss_fresh(authorization, now_ms)?;
        }
        Ok(())
    }

    fn into_installation_evidence_bytes(self) -> (Vec<u8>, Vec<u8>) {
        (
            self.deriver_a_installation.into_canonical_bytes(),
            self.deriver_b_installation.into_canonical_bytes(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn build_creation_evidence(
    deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    availability: TenantRootActivationAvailabilityEvidenceV1,
    ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
    ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> RouterAbDerivationResult<ActivationEvidenceBundlePartsV1> {
    validate_revisions(
        expected_control_plane_revision,
        result_control_plane_revision,
        "tenant-root initial activation evidence",
    )?;
    let (identity_digest, custody_lineage, epochs, context_digest) = validate_installation_scope(
        &deriver_a_installation,
        &deriver_b_installation,
        TenantRootActivationReceiptTransitionV1::InitialCreation,
    )?;
    let commitments =
        TenantRootEpochCommitmentsV1::from_verified(verify_tenant_root_creation_evidence_v1(
            deriver_a_installation.evidence(),
            deriver_b_installation.evidence(),
        )?)?;
    let installation_receipts =
        installation_receipts(&deriver_a_installation, &deriver_b_installation)?;
    let backup_policy = validate_availability(
        &availability,
        identity_digest,
        custody_lineage,
        TenantRootShareEpoch::INITIAL,
        &commitments,
        &installation_receipts,
        deriver_a_installation.evidence().transcript().context(),
        expected_control_plane_revision,
        result_control_plane_revision,
    )?;
    let canary_receipts = validate_canaries(
        &ecdsa_canary,
        &ed25519_canary,
        identity_digest,
        custody_lineage,
        TenantRootActivationReceiptTransitionV1::InitialCreation,
        TenantRootShareEpoch::INITIAL,
        &commitments,
        &deriver_a_installation,
    )?;
    Ok(ActivationEvidenceBundlePartsV1 {
        deriver_a_installation,
        deriver_b_installation,
        availability,
        ecdsa_canary,
        ed25519_canary,
        identity_digest,
        custody_lineage,
        epochs,
        context_digest,
        expected_control_plane_revision,
        result_control_plane_revision,
        commitments,
        installation_receipts,
        backup_policy,
        canary_receipts,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_refresh_evidence(
    current_commitments: &TenantRootEpochCommitmentsV1,
    deriver_a_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    deriver_b_installation: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    availability: TenantRootActivationAvailabilityEvidenceV1,
    ecdsa_canary: VerifiedTenantRootProviderCanaryReceiptV1,
    ed25519_canary: VerifiedTenantRootProviderCanaryReceiptV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> RouterAbDerivationResult<ActivationEvidenceBundlePartsV1> {
    validate_revisions(
        expected_control_plane_revision,
        result_control_plane_revision,
        "tenant-root refresh activation evidence",
    )?;
    let (identity_digest, custody_lineage, epochs, context_digest) = validate_installation_scope(
        &deriver_a_installation,
        &deriver_b_installation,
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
    )?;
    let TenantRootCeremonyEpochsV1::Refresh { next, .. } = epochs else {
        return Err(malformed(
            "tenant-root refresh activation evidence scope has no refresh epochs",
        ));
    };
    let commitments =
        TenantRootEpochCommitmentsV1::from_verified(verify_tenant_root_refresh_evidence_v1(
            &current_commitments.threshold_pair()?,
            deriver_a_installation.evidence(),
            deriver_b_installation.evidence(),
        )?)?;
    let installation_receipts =
        installation_receipts(&deriver_a_installation, &deriver_b_installation)?;
    let backup_policy = validate_availability(
        &availability,
        identity_digest,
        custody_lineage,
        next,
        &commitments,
        &installation_receipts,
        deriver_a_installation.evidence().transcript().context(),
        expected_control_plane_revision,
        result_control_plane_revision,
    )?;
    let canary_receipts = validate_canaries(
        &ecdsa_canary,
        &ed25519_canary,
        identity_digest,
        custody_lineage,
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
        next,
        &commitments,
        &deriver_a_installation,
    )?;
    Ok(ActivationEvidenceBundlePartsV1 {
        deriver_a_installation,
        deriver_b_installation,
        availability,
        ecdsa_canary,
        ed25519_canary,
        identity_digest,
        custody_lineage,
        epochs,
        context_digest,
        expected_control_plane_revision,
        result_control_plane_revision,
        commitments,
        installation_receipts,
        backup_policy,
        canary_receipts,
    })
}

fn validate_installation_scope(
    deriver_a_installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    deriver_b_installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    transition: TenantRootActivationReceiptTransitionV1,
) -> RouterAbDerivationResult<(
    TenantRootIdentityDigestV1,
    TenantRootCustodyLineageId,
    TenantRootCeremonyEpochsV1,
    TenantRootProtocolDigestV1,
)> {
    let deriver_a = deriver_a_installation.evidence();
    let deriver_b = deriver_b_installation.evidence();
    require_installation_role(deriver_a.transcript().role(), TwoPartyDeriverRole::DeriverA)?;
    require_installation_role(deriver_b.transcript().role(), TwoPartyDeriverRole::DeriverB)?;
    let context = deriver_a.transcript().context();
    context.validate()?;
    if deriver_b.transcript().context() != context {
        return Err(replay_mismatch(
            "tenant-root activation installation evidence contexts differ",
        ));
    }
    let epochs = context.epochs();
    let context_digest = context.digest()?;
    let expected_epochs = match transition {
        TenantRootActivationReceiptTransitionV1::InitialCreation => {
            TenantRootCeremonyEpochsV1::Create {
                next: TenantRootShareEpoch::INITIAL,
            }
        }
        TenantRootActivationReceiptTransitionV1::RefreshSwap => {
            if !matches!(epochs, TenantRootCeremonyEpochsV1::Refresh { .. }) {
                return Err(malformed(
                    "tenant-root refresh activation evidence requires refresh epochs",
                ));
            }
            epochs
        }
    };
    if epochs != expected_epochs {
        return Err(replay_mismatch(
            "tenant-root activation installation evidence epoch branch is inconsistent",
        ));
    }
    Ok((
        context.identity_digest(),
        context.custody_lineage(),
        epochs,
        context_digest,
    ))
}

fn installation_receipts(
    deriver_a_installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    deriver_b_installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> RouterAbDerivationResult<TenantRootRoleInstallationReceiptsV1> {
    TenantRootRoleInstallationReceiptsV1::new(
        deriver_a_installation.lifecycle_receipt_digest()?,
        deriver_b_installation.lifecycle_receipt_digest()?,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_availability(
    availability: &TenantRootActivationAvailabilityEvidenceV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    target_epoch: TenantRootShareEpoch,
    commitments: &TenantRootEpochCommitmentsV1,
    installation_receipts: &TenantRootRoleInstallationReceiptsV1,
    context: &TenantRootCeremonyContextV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> RouterAbDerivationResult<TenantRootBackupPolicyV1> {
    match availability {
        TenantRootActivationAvailabilityEvidenceV1::CurrentRoleBackups {
            deriver_a,
            deriver_b,
        } => {
            if deriver_a.binding().backup_provider_id() == deriver_b.binding().backup_provider_id()
            {
                return Err(replay_mismatch(
                    "tenant-root managed backups must use independent providers",
                ));
            }
            if deriver_a.binding().backup_key_version() == deriver_b.binding().backup_key_version()
            {
                return Err(replay_mismatch(
                    "tenant-root managed backups must use independent key versions",
                ));
            }
            if deriver_a.binding().role_signing_key_id()
                == deriver_b.binding().role_signing_key_id()
            {
                return Err(replay_mismatch(
                    "tenant-root managed backups must use independent role authorities",
                ));
            }
            validate_managed_backup(
                deriver_a,
                TenantRootManagedRestoreRoleV1::DeriverA,
                identity_digest,
                custody_lineage,
                target_epoch,
                commitments.deriver_a(),
                installation_receipts.deriver_a(),
                context,
            )?;
            validate_managed_backup(
                deriver_b,
                TenantRootManagedRestoreRoleV1::DeriverB,
                identity_digest,
                custody_lineage,
                target_epoch,
                commitments.deriver_b(),
                installation_receipts.deriver_b(),
                context,
            )?;
            Ok(TenantRootBackupPolicyV1::CurrentRoleBackups(
                TenantRootRoleBackupReceiptsV1::new(
                    deriver_a.receipt_digest(),
                    deriver_b.receipt_digest(),
                )?,
            ))
        }
        TenantRootActivationAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
            authorization,
        } => {
            let signed =
                TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
                    authorization.authorization_bytes(),
                )?;
            if signed.digest()? != *authorization.authorization_digest()
                || signed.identity_digest() != identity_digest
                || signed.custody_lineage() != custody_lineage
                || signed.transition() != transition_for_epochs(context.epochs())
                || signed.target_epoch() != target_epoch
                || signed.context_digest() != context.digest()?
                || signed.commitments() != commitments
                || signed.installation_receipts() != *installation_receipts
                || signed.expected_control_plane_revision() != expected_control_plane_revision
                || signed.result_control_plane_revision() != result_control_plane_revision
                || signed.issued_at_ms() != context.issued_at_ms()
                || signed.expires_at_ms() != context.expires_at_ms()
            {
                return Err(replay_mismatch(
                    "tenant-root accepted-loss authorization does not match activation evidence",
                ));
            }
            Ok(TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(
                authorization.clone(),
            ))
        }
    }
}

fn require_accepted_loss_fresh(
    authorization: &TenantRootAcceptedLossReceiptV1,
    now_ms: u64,
) -> RouterAbDerivationResult<()> {
    let signed = TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
        authorization.authorization_bytes(),
    )?;
    if now_ms < signed.issued_at_ms() || now_ms > signed.expires_at_ms() {
        return Err(replay_mismatch(
            "tenant-root accepted-loss authorization is outside its freshness window",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_managed_backup(
    backup: &VerifiedTenantRootManagedBackupV1,
    expected_role: TenantRootManagedRestoreRoleV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    target_epoch: TenantRootShareEpoch,
    expected_commitment: &MpcPrfShareCommitmentWireV1,
    expected_installation_receipt: TenantRootLifecycleReceiptDigestV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbDerivationResult<()> {
    if backup.role() != expected_role
        || backup.identity_digest() != identity_digest
        || backup.custody_lineage() != custody_lineage
        || backup.epoch() != target_epoch
        || backup.share_commitment() != expected_commitment
        || backup.installation_receipt_digest() != expected_installation_receipt
        || backup.binding().role_signing_key_id()
            != context.signing_key_id(role_for_restore(expected_role))
    {
        return Err(replay_mismatch(
            "tenant-root managed-backup provenance does not match installation evidence",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_canaries(
    ecdsa_canary: &VerifiedTenantRootProviderCanaryReceiptV1,
    ed25519_canary: &VerifiedTenantRootProviderCanaryReceiptV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    commitments: &TenantRootEpochCommitmentsV1,
    installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> RouterAbDerivationResult<TenantRootCanaryReceiptsV1> {
    let context = installation.evidence().transcript().context();
    validate_canary(
        ecdsa_canary,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
        identity_digest,
        custody_lineage,
        transition,
        target_epoch,
        commitments,
        context,
    )?;
    validate_canary(
        ed25519_canary,
        TenantRootCanaryCurveFamilyV1::Ed25519,
        identity_digest,
        custody_lineage,
        transition,
        target_epoch,
        commitments,
        context,
    )?;
    TenantRootCanaryReceiptsV1::new(
        project_canary_receipt_digest(ecdsa_canary.digest())?,
        project_canary_receipt_digest(ed25519_canary.digest())?,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_canary(
    canary: &VerifiedTenantRootProviderCanaryReceiptV1,
    expected_family: TenantRootCanaryCurveFamilyV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    commitments: &TenantRootEpochCommitmentsV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbDerivationResult<()> {
    if canary.curve_family() != expected_family
        || canary.identity_digest() != identity_digest
        || canary.custody_lineage() != custody_lineage
        || canary.transition() != transition
        || canary.target_epoch() != target_epoch
        || canary.commitments() != commitments
        || canary.issued_at_ms() < context.issued_at_ms()
        || canary.expires_at_ms() > context.expires_at_ms()
        || canary.completed_at_ms() < context.issued_at_ms()
        || canary.completed_at_ms() > context.expires_at_ms()
    {
        return Err(replay_mismatch(
            "tenant-root provider canary provenance does not match activation evidence",
        ));
    }
    Ok(())
}

fn clone_commitments(
    commitments: &TenantRootEpochCommitmentsV1,
) -> RouterAbDerivationResult<TenantRootEpochCommitmentsV1> {
    TenantRootEpochCommitmentsV1::new(
        commitments.deriver_a().clone(),
        commitments.deriver_b().clone(),
    )
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

fn project_canary_receipt_digest(
    digest: TenantRootProviderCanaryReceiptDigestV1,
) -> RouterAbDerivationResult<TenantRootLifecycleReceiptDigestV1> {
    TenantRootLifecycleReceiptDigestV1::from_bytes(*digest.as_bytes())
}

fn role_for_restore(role: TenantRootManagedRestoreRoleV1) -> TwoPartyDeriverRole {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        TenantRootManagedRestoreRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

fn transition_for_epochs(
    epochs: TenantRootCeremonyEpochsV1,
) -> TenantRootActivationReceiptTransitionV1 {
    match epochs {
        TenantRootCeremonyEpochsV1::Create { .. } => {
            TenantRootActivationReceiptTransitionV1::InitialCreation
        }
        TenantRootCeremonyEpochsV1::Refresh { .. } => {
            TenantRootActivationReceiptTransitionV1::RefreshSwap
        }
    }
}

fn require_installation_role(
    actual: TwoPartyDeriverRole,
    expected: TwoPartyDeriverRole,
) -> RouterAbDerivationResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(replay_mismatch(
            "tenant-root activation installation evidence role is invalid",
        ))
    }
}

fn malformed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn replay_mismatch(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::ReplayMismatch, message)
}
