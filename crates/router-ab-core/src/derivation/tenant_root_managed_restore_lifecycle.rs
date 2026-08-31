use serde::Serialize;

use super::{
    ActiveTenantRootEpochV1, MpcPrfShareCommitmentWireV1, RouterAbDerivationError,
    RouterAbDerivationErrorCode, RouterAbDerivationResult, TenantRootActivationReceiptV1,
    TenantRootActiveRefreshV1, TenantRootBackupPolicyV1, TenantRootCanaryReceiptsV1,
    TenantRootCeremonyContextV1, TenantRootCleanupIncompleteRefreshV1, TenantRootCustodyLineageId,
    TenantRootFailedBeforeActivationRefreshV1, TenantRootIdentityDigestV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootPendingCleanupFailureV1,
    TenantRootPendingCleanupReceiptV1, TenantRootPreparingRefreshV1, TenantRootRefreshFailureV1,
    TenantRootRetiringRefreshV1, TenantRootRoleInstallationReceiptsV1,
    TenantRootRoleRetirementReceiptsV1, TenantRootShareEpoch, TenantRootVerifiedRefreshV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
};

/// One role eligible for service-managed current-epoch recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootManagedRestoreRoleV1 {
    /// Deriver A's role-local share and backup authority.
    DeriverA,
    /// Deriver B's role-local share and backup authority.
    DeriverB,
}

impl TenantRootManagedRestoreRoleV1 {
    /// Returns the other role in the fixed A/B pair.
    pub const fn peer(self) -> Self {
        match self {
            Self::DeriverA => Self::DeriverB,
            Self::DeriverB => Self::DeriverA,
        }
    }
}

/// Signed observation that one active role is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRoleUnavailableReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    role: TenantRootManagedRestoreRoleV1,
    unavailable_at_ms: u64,
}

impl TenantRootRoleUnavailableReceiptV1 {
    /// Creates one role-specific unavailability observation.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        role: TenantRootManagedRestoreRoleV1,
        unavailable_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root role-unavailable timestamp", unavailable_at_ms)?;
        Ok(Self {
            digest,
            role,
            unavailable_at_ms,
        })
    }

    /// Returns the unavailable role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.role
    }

    /// Returns the observation time.
    pub const fn unavailable_at_ms(&self) -> u64 {
        self.unavailable_at_ms
    }
}

/// Exact signed, one-use incident capability accepted by a role backup authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreCapabilityV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl TenantRootManagedRestoreCapabilityV1 {
    /// Creates one already-authenticated restore capability with exact custody bindings.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_lifetime(
            "tenant-root managed-restore capability",
            issued_at_ms,
            expires_at_ms,
        )?;
        Ok(Self {
            digest,
            identity_digest,
            custody_lineage,
            role,
            epoch,
            activation_receipt_digest,
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// Returns the capability digest used by the one-use replay store.
    pub const fn digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.digest
    }

    /// Returns the authorized role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.role
    }
}

/// Role-signed evidence that the recovered share was installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreInstallationReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    capability_digest: TenantRootLifecycleReceiptDigestV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
    installed_at_ms: u64,
}

impl TenantRootManagedRestoreInstallationReceiptV1 {
    /// Creates exact installed-share evidence for one managed restore attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        capability_digest: TenantRootLifecycleReceiptDigestV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        share_commitment: MpcPrfShareCommitmentWireV1,
        installed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp(
            "tenant-root managed-restore installation timestamp",
            installed_at_ms,
        )?;
        Ok(Self {
            digest,
            capability_digest,
            identity_digest,
            custody_lineage,
            role,
            epoch,
            activation_receipt_digest,
            share_commitment,
            installed_at_ms,
        })
    }

    /// Returns the restored role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.role
    }

    /// Returns the installation time.
    pub const fn installed_at_ms(&self) -> u64 {
        self.installed_at_ms
    }
}

/// Peer-role proof that the other current share is still authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestorePeerVerificationReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
    verified_at_ms: u64,
}

impl TenantRootManagedRestorePeerVerificationReceiptV1 {
    /// Creates exact current-share evidence from the available peer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        share_commitment: MpcPrfShareCommitmentWireV1,
        verified_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp(
            "tenant-root managed-restore peer-verification timestamp",
            verified_at_ms,
        )?;
        Ok(Self {
            digest,
            identity_digest,
            custody_lineage,
            role,
            epoch,
            activation_receipt_digest,
            share_commitment,
            verified_at_ms,
        })
    }
}

/// Signed failure for a managed restore attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreFailureV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    failed_at_ms: u64,
}

impl TenantRootManagedRestoreFailureV1 {
    /// Creates one non-zero-time failure receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        failed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp(
            "tenant-root managed-restore failure timestamp",
            failed_at_ms,
        )?;
        Ok(Self {
            digest,
            failed_at_ms,
        })
    }
}

/// Proof that the failed role-local restore installation was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreCleanupReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    role: TenantRootManagedRestoreRoleV1,
    cleaned_at_ms: u64,
}

impl TenantRootManagedRestoreCleanupReceiptV1 {
    /// Creates one role-specific complete-cleanup receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        role: TenantRootManagedRestoreRoleV1,
        cleaned_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp(
            "tenant-root managed-restore cleanup timestamp",
            cleaned_at_ms,
        )?;
        Ok(Self {
            digest,
            role,
            cleaned_at_ms,
        })
    }
}

/// Evidence that failed restore material may still exist in one role store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreCleanupFailureV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    role: TenantRootManagedRestoreRoleV1,
    observed_at_ms: u64,
}

impl TenantRootManagedRestoreCleanupFailureV1 {
    /// Creates one role-specific incomplete-cleanup observation.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        role: TenantRootManagedRestoreRoleV1,
        observed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp(
            "tenant-root managed-restore incomplete-cleanup timestamp",
            observed_at_ms,
        )?;
        Ok(Self {
            digest,
            role,
            observed_at_ms,
        })
    }
}

/// Exact failed restore stage retained until cleanup completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum TenantRootManagedRestoreFailedAttemptV1 {
    /// The role had not returned an accepted installation receipt.
    Installing {
        /// Consumed capability.
        capability: TenantRootManagedRestoreCapabilityV1,
        /// Restore start time.
        started_at_ms: u64,
    },
    /// A role-local share was installed and then failed verification or coordination.
    Installed {
        /// Consumed capability.
        capability: TenantRootManagedRestoreCapabilityV1,
        /// Accepted installation receipt.
        installation: TenantRootManagedRestoreInstallationReceiptV1,
    },
}

impl TenantRootManagedRestoreFailedAttemptV1 {
    fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        match self {
            Self::Installing { capability, .. } | Self::Installed { capability, .. } => {
                capability.role
            }
        }
    }

    fn capability_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        match self {
            Self::Installing { capability, .. } | Self::Installed { capability, .. } => {
                capability.digest
            }
        }
    }

    fn earliest_failure_at_ms(&self) -> u64 {
        match self {
            Self::Installing { started_at_ms, .. } => *started_at_ms,
            Self::Installed { installation, .. } => installation.installed_at_ms,
        }
    }
}

/// Exact evidence explaining why the role remains unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum TenantRootRoleUnavailabilityEvidenceV1 {
    /// Initial signed role-outage observation.
    Observed(TenantRootRoleUnavailableReceiptV1),
    /// A failed restore attempt was completely removed before another attempt.
    RestoreAttemptCleaned {
        /// Initial role-outage observation.
        observed: TenantRootRoleUnavailableReceiptV1,
        /// Failed attempt that consumed a one-use capability.
        attempt: Box<TenantRootManagedRestoreFailedAttemptV1>,
        /// Signed attempt failure.
        failure: TenantRootManagedRestoreFailureV1,
        /// Complete cleanup receipt.
        cleanup: TenantRootManagedRestoreCleanupReceiptV1,
    },
}

impl TenantRootRoleUnavailabilityEvidenceV1 {
    fn observed(&self) -> TenantRootRoleUnavailableReceiptV1 {
        match self {
            Self::Observed(observed) | Self::RestoreAttemptCleaned { observed, .. } => *observed,
        }
    }

    fn earliest_new_capability_at_ms(&self) -> u64 {
        match self {
            Self::Observed(observed) => observed.unavailable_at_ms,
            Self::RestoreAttemptCleaned { cleanup, .. } => cleanup.cleaned_at_ms,
        }
    }

    fn previous_capability_digest(&self) -> Option<TenantRootLifecycleReceiptDigestV1> {
        match self {
            Self::Observed(_) => None,
            Self::RestoreAttemptCleaned { attempt, .. } => Some(attempt.capability_digest()),
        }
    }
}

/// Stable state with both active role shares available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreAvailableV1 {
    active: TenantRootActiveRefreshV1,
}

impl TenantRootManagedRestoreAvailableV1 {
    /// Admits an active root into the managed availability state machine.
    pub fn new(active: TenantRootActiveRefreshV1) -> RouterAbDerivationResult<Self> {
        if !matches!(
            active.current().verified().backup_policy(),
            TenantRootBackupPolicyV1::CurrentRoleBackups(_)
        ) {
            return Err(malformed(
                "tenant root without current role backups cannot enter managed restore",
            ));
        }
        Ok(Self { active })
    }

    /// Returns the active refresh state used by normal derivation.
    pub const fn active(&self) -> &TenantRootActiveRefreshV1 {
        &self.active
    }

    /// Returns the authoritative lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.active.revision()
    }

    /// Fences new derivation ceremonies after one exact role becomes unavailable.
    pub fn mark_role_unavailable(
        self,
        receipt: TenantRootRoleUnavailableReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
        if receipt.unavailable_at_ms < self.active.current().activation().activated_at_ms() {
            return Err(malformed(
                "tenant-root role unavailability cannot predate active-epoch activation",
            ));
        }
        let revision = next_revision(self.revision())?;
        Ok(TenantRootManagedRestoreRoleUnavailableV1 {
            active: self.active,
            evidence: TenantRootRoleUnavailabilityEvidenceV1::Observed(receipt),
            revision,
        })
    }
}

/// Fenced state after exactly one active role becomes unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreRoleUnavailableV1 {
    active: TenantRootActiveRefreshV1,
    evidence: TenantRootRoleUnavailabilityEvidenceV1,
    revision: u64,
}

impl TenantRootManagedRestoreRoleUnavailableV1 {
    /// Returns the only role eligible for managed recovery.
    pub fn unavailable_role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.evidence.observed().role
    }

    /// Returns the authoritative lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Consumes one fresh, current-epoch capability and starts role-local restore.
    pub fn start_restore(
        self,
        capability: TenantRootManagedRestoreCapabilityV1,
        started_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreInstallingV1> {
        validate_capability(&self.active, &self.evidence, &capability, started_at_ms)?;
        let role = capability.role;
        let core = TenantRootManagedRestoreInstallingCoreV1 {
            active: self.active,
            evidence: self.evidence,
            capability,
            started_at_ms,
            revision: next_revision(self.revision)?,
        };
        Ok(match role {
            TenantRootManagedRestoreRoleV1::DeriverA => {
                TenantRootManagedRestoreInstallingV1::RestoringA(
                    TenantRootManagedRestoreRestoringAV1 { core },
                )
            }
            TenantRootManagedRestoreRoleV1::DeriverB => {
                TenantRootManagedRestoreInstallingV1::RestoringB(
                    TenantRootManagedRestoreRestoringBV1 { core },
                )
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantRootManagedRestoreInstallingCoreV1 {
    active: TenantRootActiveRefreshV1,
    evidence: TenantRootRoleUnavailabilityEvidenceV1,
    capability: TenantRootManagedRestoreCapabilityV1,
    started_at_ms: u64,
    revision: u64,
}

/// Exact branch produced when managed restore begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum TenantRootManagedRestoreInstallingV1 {
    /// Deriver A alone is restoring its role-local current share.
    RestoringA(TenantRootManagedRestoreRestoringAV1),
    /// Deriver B alone is restoring its role-local current share.
    RestoringB(TenantRootManagedRestoreRestoringBV1),
}

/// Deriver A role-local installation branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TenantRootManagedRestoreRestoringAV1 {
    core: TenantRootManagedRestoreInstallingCoreV1,
}

impl TenantRootManagedRestoreRestoringAV1 {
    /// Accepts Deriver A's exact current-share installation evidence.
    pub fn accept_installation(
        self,
        receipt: TenantRootManagedRestoreInstallationReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreVerifyingV1> {
        accept_installation(self.core, receipt)
    }

    /// Returns to role-unavailable after complete failed-installation cleanup.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootManagedRestoreFailureV1,
        cleanup: TenantRootManagedRestoreCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
        fail_installation_with_cleanup(self.core, failure, cleanup)
    }

    /// Blocks further restore while failed-installation cleanup is incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootManagedRestoreFailureV1,
        cleanup: TenantRootManagedRestoreCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreCleanupIncompleteV1> {
        fail_installation_with_incomplete_cleanup(self.core, failure, cleanup)
    }
}

/// Deriver B role-local installation branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TenantRootManagedRestoreRestoringBV1 {
    core: TenantRootManagedRestoreInstallingCoreV1,
}

impl TenantRootManagedRestoreRestoringBV1 {
    /// Accepts Deriver B's exact current-share installation evidence.
    pub fn accept_installation(
        self,
        receipt: TenantRootManagedRestoreInstallationReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreVerifyingV1> {
        accept_installation(self.core, receipt)
    }

    /// Returns to role-unavailable after complete failed-installation cleanup.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootManagedRestoreFailureV1,
        cleanup: TenantRootManagedRestoreCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
        fail_installation_with_cleanup(self.core, failure, cleanup)
    }

    /// Blocks further restore while failed-installation cleanup is incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootManagedRestoreFailureV1,
        cleanup: TenantRootManagedRestoreCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreCleanupIncompleteV1> {
        fail_installation_with_incomplete_cleanup(self.core, failure, cleanup)
    }
}

/// Restored-role installation is present and awaits peer/current commitment verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreVerifyingV1 {
    active: TenantRootActiveRefreshV1,
    evidence: TenantRootRoleUnavailabilityEvidenceV1,
    capability: TenantRootManagedRestoreCapabilityV1,
    installation: TenantRootManagedRestoreInstallationReceiptV1,
    revision: u64,
}

impl TenantRootManagedRestoreVerifyingV1 {
    /// Verifies both exact current commitments and immediately starts forward refresh.
    pub fn begin_forward_refresh(
        self,
        peer: TenantRootManagedRestorePeerVerificationReceiptV1,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardPreparingV1> {
        validate_peer_verification(&self.active, &self.capability, &self.installation, &peer)?;
        if context.issued_at_ms() < peer.verified_at_ms {
            return Err(malformed(
                "tenant-root forward refresh cannot predate managed-restore verification",
            ));
        }
        let restored = TenantRootManagedRestoreVerificationEvidenceV1 {
            role: self.capability.role,
            epoch: self.capability.epoch,
            capability_digest: self.capability.digest,
            installation_receipt_digest: self.installation.digest,
            peer_receipt_digest: peer.digest,
            verified_at_ms: peer.verified_at_ms,
        };
        let refresh = self
            .active
            .resume_at_revision(self.revision)?
            .start(context)?;
        Ok(TenantRootManagedRestoreForwardPreparingV1 { restored, refresh })
    }

    /// Returns to role-unavailable after complete cleanup of the installed share.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootManagedRestoreFailureV1,
        cleanup: TenantRootManagedRestoreCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
        fail_attempt_with_cleanup(
            self.active,
            self.evidence,
            TenantRootManagedRestoreFailedAttemptV1::Installed {
                capability: self.capability,
                installation: self.installation,
            },
            self.revision,
            failure,
            cleanup,
        )
    }

    /// Blocks further restore while cleanup of the installed share is incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootManagedRestoreFailureV1,
        cleanup: TenantRootManagedRestoreCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreCleanupIncompleteV1> {
        fail_attempt_with_incomplete_cleanup(
            self.active,
            self.evidence,
            TenantRootManagedRestoreFailedAttemptV1::Installed {
                capability: self.capability,
                installation: self.installation,
            },
            self.revision,
            failure,
            cleanup,
        )
    }
}

/// Public proof that one restored share and its peer matched the active epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreVerificationEvidenceV1 {
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
    capability_digest: TenantRootLifecycleReceiptDigestV1,
    installation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    peer_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    verified_at_ms: u64,
}

impl TenantRootManagedRestoreVerificationEvidenceV1 {
    /// Returns the recovered role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.role
    }

    /// Returns the recovered current epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }
}

/// Managed restore is blocked until the failed role-local installation is removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreCleanupIncompleteV1 {
    active: TenantRootActiveRefreshV1,
    evidence: TenantRootRoleUnavailabilityEvidenceV1,
    attempt: TenantRootManagedRestoreFailedAttemptV1,
    failure: TenantRootManagedRestoreFailureV1,
    cleanup: TenantRootManagedRestoreCleanupFailureV1,
    revision: u64,
}

impl TenantRootManagedRestoreCleanupIncompleteV1 {
    /// Accepts eventual complete cleanup and returns to the same unavailable role.
    pub fn complete_cleanup(
        self,
        cleanup: TenantRootManagedRestoreCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
        validate_cleanup_role_and_order(self.attempt.role(), self.cleanup.observed_at_ms, cleanup)?;
        Ok(TenantRootManagedRestoreRoleUnavailableV1 {
            active: self.active,
            evidence: TenantRootRoleUnavailabilityEvidenceV1::RestoreAttemptCleaned {
                observed: self.evidence.observed(),
                attempt: Box::new(self.attempt),
                failure: self.failure,
                cleanup,
            },
            revision: next_revision(self.revision)?,
        })
    }
}

/// Forward refresh after restore has begun and the next epoch is pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreForwardPreparingV1 {
    restored: TenantRootManagedRestoreVerificationEvidenceV1,
    refresh: TenantRootPreparingRefreshV1,
}

impl TenantRootManagedRestoreForwardPreparingV1 {
    /// Verifies the next epoch using the normal refresh continuity contract.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        deriver_a: &VerifiedTenantRootShareInstallationEvidenceV1,
        deriver_b: &VerifiedTenantRootShareInstallationEvidenceV1,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        backup_policy: TenantRootBackupPolicyV1,
        canary_receipts: TenantRootCanaryReceiptsV1,
        verified_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardVerifiedV1> {
        Ok(TenantRootManagedRestoreForwardVerifiedV1 {
            restored: self.restored,
            refresh: self.refresh.verify(
                deriver_a,
                deriver_b,
                installation_receipts,
                backup_policy,
                canary_receipts,
                verified_at_ms,
            )?,
        })
    }

    /// Records a failed forward refresh after complete pending cleanup.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardFailedV1> {
        Ok(TenantRootManagedRestoreForwardFailedV1 {
            restored: self.restored,
            refresh: self.refresh.fail_with_cleanup(failure, cleanup)?,
        })
    }

    /// Records a failed forward refresh whose pending cleanup remains incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardCleanupIncompleteV1> {
        Ok(TenantRootManagedRestoreForwardCleanupIncompleteV1 {
            restored: self.restored,
            refresh: self
                .refresh
                .fail_with_incomplete_cleanup(failure, cleanup)?,
        })
    }
}

/// Forward refresh passed all pre-activation gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreForwardVerifiedV1 {
    restored: TenantRootManagedRestoreVerificationEvidenceV1,
    refresh: TenantRootVerifiedRefreshV1,
}

impl TenantRootManagedRestoreForwardVerifiedV1 {
    /// Activates the next epoch and enters mandatory old-epoch retirement.
    pub fn activate(
        self,
        activation: TenantRootActivationReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardRetiringV1> {
        Ok(TenantRootManagedRestoreForwardRetiringV1 {
            restored: self.restored,
            refresh: self.refresh.activate(activation)?,
        })
    }

    /// Records a failed verified refresh after complete pending cleanup.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardFailedV1> {
        Ok(TenantRootManagedRestoreForwardFailedV1 {
            restored: self.restored,
            refresh: self.refresh.fail_with_cleanup(failure, cleanup)?,
        })
    }

    /// Records a failed verified refresh whose cleanup remains incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardCleanupIncompleteV1> {
        Ok(TenantRootManagedRestoreForwardCleanupIncompleteV1 {
            restored: self.restored,
            refresh: self
                .refresh
                .fail_with_incomplete_cleanup(failure, cleanup)?,
        })
    }
}

/// New epoch is active while the restored epoch and backup keys are destroyed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreForwardRetiringV1 {
    restored: TenantRootManagedRestoreVerificationEvidenceV1,
    refresh: TenantRootRetiringRefreshV1,
}

impl TenantRootManagedRestoreForwardRetiringV1 {
    /// Returns to availability only after both roles prove old-epoch retirement.
    pub fn finish_retirement(
        self,
        receipts: TenantRootRoleRetirementReceiptsV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreAvailableV1> {
        TenantRootManagedRestoreAvailableV1::new(self.refresh.finish_retirement(receipts)?)
    }
}

/// Forward refresh failed before activation and may only retry with a fresh ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreForwardFailedV1 {
    restored: TenantRootManagedRestoreVerificationEvidenceV1,
    refresh: TenantRootFailedBeforeActivationRefreshV1,
}

impl TenantRootManagedRestoreForwardFailedV1 {
    /// Starts another forward refresh after complete pending cleanup.
    pub fn retry(
        self,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardPreparingV1> {
        Ok(TenantRootManagedRestoreForwardPreparingV1 {
            restored: self.restored,
            refresh: self.refresh.retry(context)?,
        })
    }
}

/// Forward refresh cleanup is incomplete and blocks another ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRestoreForwardCleanupIncompleteV1 {
    restored: TenantRootManagedRestoreVerificationEvidenceV1,
    refresh: TenantRootCleanupIncompleteRefreshV1,
}

impl TenantRootManagedRestoreForwardCleanupIncompleteV1 {
    /// Completes pending cleanup while keeping the tenant fenced for refresh retry.
    pub fn complete_cleanup(
        self,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreForwardFailedV1> {
        Ok(TenantRootManagedRestoreForwardFailedV1 {
            restored: self.restored,
            refresh: self.refresh.complete_cleanup(cleanup)?,
        })
    }
}

/// Exhaustive nested state while mandatory post-restore refresh is in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", content = "state", rename_all = "snake_case")]
pub enum TenantRootManagedRestoreForwardRefreshStateV1 {
    /// Next epoch is pending.
    Preparing(TenantRootManagedRestoreForwardPreparingV1),
    /// Next epoch passed pre-activation gates.
    Verified(TenantRootManagedRestoreForwardVerifiedV1),
    /// Next epoch is active and the restored epoch is retiring.
    Retiring(TenantRootManagedRestoreForwardRetiringV1),
    /// Pre-activation failure was fully cleaned and requires a fresh retry.
    FailedBeforeActivation(TenantRootManagedRestoreForwardFailedV1),
    /// Pending refresh cleanup is incomplete.
    CleanupIncomplete(TenantRootManagedRestoreForwardCleanupIncompleteV1),
}

impl TenantRootManagedRestoreForwardRefreshStateV1 {
    /// Returns the authoritative refresh lifecycle revision.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Preparing(state) => state.refresh.revision(),
            Self::Verified(state) => state.refresh.revision(),
            Self::Retiring(state) => state.refresh.revision(),
            Self::FailedBeforeActivation(state) => state.refresh.revision(),
            Self::CleanupIncomplete(state) => state.refresh.revision(),
        }
    }
}

/// Exhaustive service-managed one-role restore state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum TenantRootManagedRestoreStateV1 {
    /// Both current role shares are available.
    Available(TenantRootManagedRestoreAvailableV1),
    /// Exactly one current role is unavailable and derivation is fenced.
    RoleUnavailable(TenantRootManagedRestoreRoleUnavailableV1),
    /// Deriver A is installing its role-local backup.
    RestoringA(TenantRootManagedRestoreRestoringAV1),
    /// Deriver B is installing its role-local backup.
    RestoringB(TenantRootManagedRestoreRestoringBV1),
    /// Restored and peer current commitments are being verified.
    Verifying(TenantRootManagedRestoreVerifyingV1),
    /// Mandatory post-restore refresh is in flight.
    ForwardRefreshing(TenantRootManagedRestoreForwardRefreshStateV1),
    /// Failed role-local restore cleanup blocks another attempt.
    CleanupIncomplete(TenantRootManagedRestoreCleanupIncompleteV1),
}

impl TenantRootManagedRestoreStateV1 {
    /// Returns the authoritative lifecycle revision.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Available(state) => state.revision(),
            Self::RoleUnavailable(state) => state.revision,
            Self::RestoringA(state) => state.core.revision,
            Self::RestoringB(state) => state.core.revision,
            Self::Verifying(state) => state.revision,
            Self::ForwardRefreshing(state) => state.revision(),
            Self::CleanupIncomplete(state) => state.revision,
        }
    }
}

impl From<TenantRootManagedRestoreAvailableV1> for TenantRootManagedRestoreStateV1 {
    fn from(state: TenantRootManagedRestoreAvailableV1) -> Self {
        Self::Available(state)
    }
}

impl From<TenantRootManagedRestoreRoleUnavailableV1> for TenantRootManagedRestoreStateV1 {
    fn from(state: TenantRootManagedRestoreRoleUnavailableV1) -> Self {
        Self::RoleUnavailable(state)
    }
}

impl From<TenantRootManagedRestoreInstallingV1> for TenantRootManagedRestoreStateV1 {
    fn from(state: TenantRootManagedRestoreInstallingV1) -> Self {
        match state {
            TenantRootManagedRestoreInstallingV1::RestoringA(state) => Self::RestoringA(state),
            TenantRootManagedRestoreInstallingV1::RestoringB(state) => Self::RestoringB(state),
        }
    }
}

impl From<TenantRootManagedRestoreVerifyingV1> for TenantRootManagedRestoreStateV1 {
    fn from(state: TenantRootManagedRestoreVerifyingV1) -> Self {
        Self::Verifying(state)
    }
}

impl From<TenantRootManagedRestoreCleanupIncompleteV1> for TenantRootManagedRestoreStateV1 {
    fn from(state: TenantRootManagedRestoreCleanupIncompleteV1) -> Self {
        Self::CleanupIncomplete(state)
    }
}

macro_rules! forward_refresh_state_conversion {
    ($state:ty, $variant:ident) => {
        impl From<$state> for TenantRootManagedRestoreForwardRefreshStateV1 {
            fn from(state: $state) -> Self {
                Self::$variant(state)
            }
        }

        impl From<$state> for TenantRootManagedRestoreStateV1 {
            fn from(state: $state) -> Self {
                Self::ForwardRefreshing(state.into())
            }
        }
    };
}

forward_refresh_state_conversion!(TenantRootManagedRestoreForwardPreparingV1, Preparing);
forward_refresh_state_conversion!(TenantRootManagedRestoreForwardVerifiedV1, Verified);
forward_refresh_state_conversion!(TenantRootManagedRestoreForwardRetiringV1, Retiring);
forward_refresh_state_conversion!(
    TenantRootManagedRestoreForwardFailedV1,
    FailedBeforeActivation
);
forward_refresh_state_conversion!(
    TenantRootManagedRestoreForwardCleanupIncompleteV1,
    CleanupIncomplete
);

fn accept_installation(
    core: TenantRootManagedRestoreInstallingCoreV1,
    receipt: TenantRootManagedRestoreInstallationReceiptV1,
) -> RouterAbDerivationResult<TenantRootManagedRestoreVerifyingV1> {
    validate_installation(&core, &receipt)?;
    Ok(TenantRootManagedRestoreVerifyingV1 {
        active: core.active,
        evidence: core.evidence,
        capability: core.capability,
        installation: receipt,
        revision: next_revision(core.revision)?,
    })
}

fn fail_installation_with_cleanup(
    core: TenantRootManagedRestoreInstallingCoreV1,
    failure: TenantRootManagedRestoreFailureV1,
    cleanup: TenantRootManagedRestoreCleanupReceiptV1,
) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
    fail_attempt_with_cleanup(
        core.active,
        core.evidence,
        TenantRootManagedRestoreFailedAttemptV1::Installing {
            capability: core.capability,
            started_at_ms: core.started_at_ms,
        },
        core.revision,
        failure,
        cleanup,
    )
}

fn fail_installation_with_incomplete_cleanup(
    core: TenantRootManagedRestoreInstallingCoreV1,
    failure: TenantRootManagedRestoreFailureV1,
    cleanup: TenantRootManagedRestoreCleanupFailureV1,
) -> RouterAbDerivationResult<TenantRootManagedRestoreCleanupIncompleteV1> {
    fail_attempt_with_incomplete_cleanup(
        core.active,
        core.evidence,
        TenantRootManagedRestoreFailedAttemptV1::Installing {
            capability: core.capability,
            started_at_ms: core.started_at_ms,
        },
        core.revision,
        failure,
        cleanup,
    )
}

fn fail_attempt_with_cleanup(
    active: TenantRootActiveRefreshV1,
    evidence: TenantRootRoleUnavailabilityEvidenceV1,
    attempt: TenantRootManagedRestoreFailedAttemptV1,
    revision: u64,
    failure: TenantRootManagedRestoreFailureV1,
    cleanup: TenantRootManagedRestoreCleanupReceiptV1,
) -> RouterAbDerivationResult<TenantRootManagedRestoreRoleUnavailableV1> {
    validate_failure_order(&attempt, failure, cleanup.role, cleanup.cleaned_at_ms)?;
    Ok(TenantRootManagedRestoreRoleUnavailableV1 {
        active,
        evidence: TenantRootRoleUnavailabilityEvidenceV1::RestoreAttemptCleaned {
            observed: evidence.observed(),
            attempt: Box::new(attempt),
            failure,
            cleanup,
        },
        revision: next_revision(revision)?,
    })
}

fn fail_attempt_with_incomplete_cleanup(
    active: TenantRootActiveRefreshV1,
    evidence: TenantRootRoleUnavailabilityEvidenceV1,
    attempt: TenantRootManagedRestoreFailedAttemptV1,
    revision: u64,
    failure: TenantRootManagedRestoreFailureV1,
    cleanup: TenantRootManagedRestoreCleanupFailureV1,
) -> RouterAbDerivationResult<TenantRootManagedRestoreCleanupIncompleteV1> {
    validate_failure_order(&attempt, failure, cleanup.role, cleanup.observed_at_ms)?;
    Ok(TenantRootManagedRestoreCleanupIncompleteV1 {
        active,
        evidence,
        attempt,
        failure,
        cleanup,
        revision: next_revision(revision)?,
    })
}

fn validate_capability(
    active: &TenantRootActiveRefreshV1,
    evidence: &TenantRootRoleUnavailabilityEvidenceV1,
    capability: &TenantRootManagedRestoreCapabilityV1,
    started_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    let observed = evidence.observed();
    if capability.role != observed.role {
        return Err(malformed(
            "managed restore cannot substitute the unavailable role; dual-role loss requires tenant recovery",
        ));
    }
    if capability.identity_digest != active.identity().digest()?
        || capability.custody_lineage != active.custody_lineage()
        || capability.epoch != active.current().epoch()
        || capability.activation_receipt_digest != active.current().activation().digest()
    {
        return Err(malformed(
            "tenant-root managed-restore capability does not match the authoritative active custody binding",
        ));
    }
    if capability.issued_at_ms < evidence.earliest_new_capability_at_ms()
        || started_at_ms < capability.issued_at_ms
        || started_at_ms > capability.expires_at_ms
    {
        return Err(malformed(
            "tenant-root managed-restore capability is stale or outside its lifetime",
        ));
    }
    if evidence.previous_capability_digest() == Some(capability.digest) {
        return Err(malformed(
            "tenant-root managed-restore retry requires a fresh one-use capability",
        ));
    }
    Ok(())
}

fn validate_installation(
    core: &TenantRootManagedRestoreInstallingCoreV1,
    receipt: &TenantRootManagedRestoreInstallationReceiptV1,
) -> RouterAbDerivationResult<()> {
    if receipt.capability_digest != core.capability.digest
        || receipt.identity_digest != core.capability.identity_digest
        || receipt.custody_lineage != core.capability.custody_lineage
        || receipt.role != core.capability.role
        || receipt.epoch != core.capability.epoch
        || receipt.activation_receipt_digest != core.capability.activation_receipt_digest
        || &receipt.share_commitment != role_commitment(core.active.current(), core.capability.role)
    {
        return Err(malformed(
            "tenant-root managed-restore installation does not match its capability and active commitment",
        ));
    }
    if receipt.installed_at_ms < core.started_at_ms
        || receipt.installed_at_ms > core.capability.expires_at_ms
    {
        return Err(malformed(
            "tenant-root managed-restore installation is outside its capability lifetime",
        ));
    }
    Ok(())
}

fn validate_peer_verification(
    active: &TenantRootActiveRefreshV1,
    capability: &TenantRootManagedRestoreCapabilityV1,
    installation: &TenantRootManagedRestoreInstallationReceiptV1,
    peer: &TenantRootManagedRestorePeerVerificationReceiptV1,
) -> RouterAbDerivationResult<()> {
    if peer.digest == installation.digest
        || peer.identity_digest != capability.identity_digest
        || peer.custody_lineage != capability.custody_lineage
        || peer.role != capability.role.peer()
        || peer.epoch != capability.epoch
        || peer.activation_receipt_digest != capability.activation_receipt_digest
        || &peer.share_commitment != role_commitment(active.current(), peer.role)
    {
        return Err(malformed(
            "tenant-root managed-restore peer verification does not match the active role pair",
        ));
    }
    if peer.verified_at_ms < installation.installed_at_ms
        || peer.verified_at_ms > capability.expires_at_ms
    {
        return Err(malformed(
            "tenant-root managed-restore peer verification is outside its capability lifetime",
        ));
    }
    Ok(())
}

fn role_commitment(
    active: &ActiveTenantRootEpochV1,
    role: TenantRootManagedRestoreRoleV1,
) -> &MpcPrfShareCommitmentWireV1 {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => active.verified().commitments().deriver_a(),
        TenantRootManagedRestoreRoleV1::DeriverB => active.verified().commitments().deriver_b(),
    }
}

fn validate_failure_order(
    attempt: &TenantRootManagedRestoreFailedAttemptV1,
    failure: TenantRootManagedRestoreFailureV1,
    cleanup_role: TenantRootManagedRestoreRoleV1,
    cleanup_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    if cleanup_role != attempt.role()
        || failure.failed_at_ms < attempt.earliest_failure_at_ms()
        || cleanup_at_ms < failure.failed_at_ms
    {
        return Err(malformed(
            "tenant-root managed-restore failure and cleanup evidence are inconsistent",
        ));
    }
    Ok(())
}

fn validate_cleanup_role_and_order(
    expected_role: TenantRootManagedRestoreRoleV1,
    observed_at_ms: u64,
    cleanup: TenantRootManagedRestoreCleanupReceiptV1,
) -> RouterAbDerivationResult<()> {
    if cleanup.role != expected_role || cleanup.cleaned_at_ms < observed_at_ms {
        return Err(malformed(
            "tenant-root managed-restore cleanup completion is inconsistent",
        ));
    }
    Ok(())
}

fn require_lifetime(
    field: &'static str,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    require_timestamp(field, issued_at_ms)?;
    if expires_at_ms <= issued_at_ms {
        return Err(malformed(
            "tenant-root managed-restore capability lifetime is invalid",
        ));
    }
    Ok(())
}

fn require_timestamp(field: &'static str, value: u64) -> RouterAbDerivationResult<()> {
    if value == 0 {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} must be non-zero"),
        ));
    }
    Ok(())
}

fn next_revision(current: u64) -> RouterAbDerivationResult<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| malformed("tenant-root managed-restore lifecycle revision is exhausted"))
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
