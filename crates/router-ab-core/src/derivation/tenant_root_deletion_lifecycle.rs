use serde::Serialize;

use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootActiveRefreshV1, TenantRootBackupPolicyV1, TenantRootCustodyLineageId,
    TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootShareEpoch,
};

/// Deployment claim governing the evidence required for root deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootDestructionProfileV1 {
    /// Independent role key providers can prove permanent key destruction.
    #[serde(rename = "managed_healing_v1")]
    ManagedHealing,
    /// Service paths are removed without a cryptographic-erasure claim.
    #[serde(rename = "operational_rotation_v1")]
    OperationalRotation,
}

/// Signed tenant-root deletion authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletionAuthorizationV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    actor_digest: TenantRootLifecycleReceiptDigestV1,
    requested_at_ms: u64,
}

impl TenantRootDeletionAuthorizationV1 {
    /// Creates one actor-bound deletion authorization.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        actor_digest: TenantRootLifecycleReceiptDigestV1,
        requested_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct(&[digest, actor_digest])?;
        require_timestamp("tenant-root deletion request timestamp", requested_at_ms)?;
        Ok(Self {
            digest,
            actor_digest,
            requested_at_ms,
        })
    }
}

/// Control-plane proof that new derivation ceremonies are fenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletionFenceReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    fenced_at_ms: u64,
}

impl TenantRootDeletionFenceReceiptV1 {
    /// Creates one deletion fence receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        fenced_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root deletion fence timestamp", fenced_at_ms)?;
        Ok(Self {
            digest,
            fenced_at_ms,
        })
    }
}

/// Proof that every derivation session using the active epoch finished or expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletionDrainReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    epoch: TenantRootShareEpoch,
    drained_at_ms: u64,
}

impl TenantRootDeletionDrainReceiptV1 {
    /// Creates one epoch-specific session-drain receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        epoch: TenantRootShareEpoch,
        drained_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root deletion drain timestamp", drained_at_ms)?;
        Ok(Self {
            digest,
            epoch,
            drained_at_ms,
        })
    }
}

/// Signed command beginning irreversible service-held material destruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDestructionCommandV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    started_at_ms: u64,
}

impl TenantRootDestructionCommandV1 {
    /// Creates one destruction command.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        started_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root destruction start timestamp", started_at_ms)?;
        Ok(Self {
            digest,
            started_at_ms,
        })
    }
}

/// One role's permanent online/backup key destruction and provider probe evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRoleDestructionReceiptV1 {
    role: TenantRootManagedRestoreRoleV1,
    online_key_destruction_digest: TenantRootLifecycleReceiptDigestV1,
    backup_key_destruction_digest: TenantRootLifecycleReceiptDigestV1,
    permanent_decrypt_probe_digest: TenantRootLifecycleReceiptDigestV1,
    destroyed_at_ms: u64,
    probed_at_ms: u64,
}

impl TenantRootManagedRoleDestructionReceiptV1 {
    /// Creates role-local permanent-destruction evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: TenantRootManagedRestoreRoleV1,
        online_key_destruction_digest: TenantRootLifecycleReceiptDigestV1,
        backup_key_destruction_digest: TenantRootLifecycleReceiptDigestV1,
        permanent_decrypt_probe_digest: TenantRootLifecycleReceiptDigestV1,
        destroyed_at_ms: u64,
        probed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct(&[
            online_key_destruction_digest,
            backup_key_destruction_digest,
            permanent_decrypt_probe_digest,
        ])?;
        require_order(destroyed_at_ms, probed_at_ms)?;
        Ok(Self {
            role,
            online_key_destruction_digest,
            backup_key_destruction_digest,
            permanent_decrypt_probe_digest,
            destroyed_at_ms,
            probed_at_ms,
        })
    }
}

/// Exact A/B permanent-destruction evidence for `managed_healing_v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootManagedRoleDestructionReceiptsV1 {
    deriver_a: TenantRootManagedRoleDestructionReceiptV1,
    deriver_b: TenantRootManagedRoleDestructionReceiptV1,
}

impl TenantRootManagedRoleDestructionReceiptsV1 {
    /// Creates the exact ordered A/B receipt pair.
    pub fn new(
        deriver_a: TenantRootManagedRoleDestructionReceiptV1,
        deriver_b: TenantRootManagedRoleDestructionReceiptV1,
    ) -> RouterAbDerivationResult<Self> {
        if deriver_a.role != TenantRootManagedRestoreRoleV1::DeriverA
            || deriver_b.role != TenantRootManagedRestoreRoleV1::DeriverB
        {
            return Err(malformed(
                "tenant-root managed destruction receipts require exact A/B roles",
            ));
        }
        require_distinct(&[
            deriver_a.online_key_destruction_digest,
            deriver_a.backup_key_destruction_digest,
            deriver_a.permanent_decrypt_probe_digest,
            deriver_b.online_key_destruction_digest,
            deriver_b.backup_key_destruction_digest,
            deriver_b.permanent_decrypt_probe_digest,
        ])?;
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    fn completed_at_ms(&self) -> u64 {
        self.deriver_a.probed_at_ms.max(self.deriver_b.probed_at_ms)
    }

    fn earliest_at_ms(&self) -> u64 {
        self.deriver_a
            .destroyed_at_ms
            .min(self.deriver_b.destroyed_at_ms)
    }
}

/// One role's removal from every active service path without an erasure claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootOperationalRoleRemovalReceiptV1 {
    role: TenantRootManagedRestoreRoleV1,
    service_path_removal_digest: TenantRootLifecycleReceiptDigestV1,
    ciphertext_removal_digest: TenantRootLifecycleReceiptDigestV1,
    removed_at_ms: u64,
}

impl TenantRootOperationalRoleRemovalReceiptV1 {
    /// Creates role-local operational-removal evidence.
    pub fn new(
        role: TenantRootManagedRestoreRoleV1,
        service_path_removal_digest: TenantRootLifecycleReceiptDigestV1,
        ciphertext_removal_digest: TenantRootLifecycleReceiptDigestV1,
        removed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct(&[service_path_removal_digest, ciphertext_removal_digest])?;
        require_timestamp("tenant-root operational removal timestamp", removed_at_ms)?;
        Ok(Self {
            role,
            service_path_removal_digest,
            ciphertext_removal_digest,
            removed_at_ms,
        })
    }
}

/// Exact A/B service-path removal evidence for `operational_rotation_v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootOperationalRoleRemovalReceiptsV1 {
    deriver_a: TenantRootOperationalRoleRemovalReceiptV1,
    deriver_b: TenantRootOperationalRoleRemovalReceiptV1,
}

impl TenantRootOperationalRoleRemovalReceiptsV1 {
    /// Creates the exact ordered A/B receipt pair.
    pub fn new(
        deriver_a: TenantRootOperationalRoleRemovalReceiptV1,
        deriver_b: TenantRootOperationalRoleRemovalReceiptV1,
    ) -> RouterAbDerivationResult<Self> {
        if deriver_a.role != TenantRootManagedRestoreRoleV1::DeriverA
            || deriver_b.role != TenantRootManagedRestoreRoleV1::DeriverB
        {
            return Err(malformed(
                "tenant-root operational removal receipts require exact A/B roles",
            ));
        }
        require_distinct(&[
            deriver_a.service_path_removal_digest,
            deriver_a.ciphertext_removal_digest,
            deriver_b.service_path_removal_digest,
            deriver_b.ciphertext_removal_digest,
        ])?;
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    fn completed_at_ms(&self) -> u64 {
        self.deriver_a
            .removed_at_ms
            .max(self.deriver_b.removed_at_ms)
    }

    fn earliest_at_ms(&self) -> u64 {
        self.deriver_a
            .removed_at_ms
            .min(self.deriver_b.removed_at_ms)
    }
}

/// Control-plane cleanup of every service-held lineage capability and recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootServiceCleanupReceiptV1 {
    commands_digest: TenantRootLifecycleReceiptDigestV1,
    capabilities_digest: TenantRootLifecycleReceiptDigestV1,
    restore_sessions_digest: TenantRootLifecycleReceiptDigestV1,
    recovery_ciphertext_digest: TenantRootLifecycleReceiptDigestV1,
    provider_credentials_digest: TenantRootLifecycleReceiptDigestV1,
    completed_at_ms: u64,
}

impl TenantRootServiceCleanupReceiptV1 {
    /// Creates exhaustive service-held cleanup evidence for one lineage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commands_digest: TenantRootLifecycleReceiptDigestV1,
        capabilities_digest: TenantRootLifecycleReceiptDigestV1,
        restore_sessions_digest: TenantRootLifecycleReceiptDigestV1,
        recovery_ciphertext_digest: TenantRootLifecycleReceiptDigestV1,
        provider_credentials_digest: TenantRootLifecycleReceiptDigestV1,
        completed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct(&[
            commands_digest,
            capabilities_digest,
            restore_sessions_digest,
            recovery_ciphertext_digest,
            provider_credentials_digest,
        ])?;
        require_timestamp("tenant-root service cleanup timestamp", completed_at_ms)?;
        Ok(Self {
            commands_digest,
            capabilities_digest,
            restore_sessions_digest,
            recovery_ciphertext_digest,
            provider_credentials_digest,
            completed_at_ms,
        })
    }
}

/// Required limitation for deployments without verified cryptographic erasure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootOperationalErasureClaimV1 {
    /// Service paths were removed; cryptographic erasure was not verified.
    CryptographicErasureUnverified,
}

/// Exact successful destruction evidence selected by deployment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(
    tag = "profile",
    content = "evidence",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum TenantRootDeletionEvidenceV1 {
    /// Both role key providers proved permanent destruction.
    #[serde(rename = "managed_healing_v1")]
    ManagedHealing {
        /// Exact A/B permanent-destruction receipts.
        roles: TenantRootManagedRoleDestructionReceiptsV1,
        /// Exhaustive control-plane cleanup receipt.
        service_cleanup: TenantRootServiceCleanupReceiptV1,
    },
    /// All service paths were removed with the required weaker claim.
    #[serde(rename = "operational_rotation_v1")]
    OperationalRotation {
        /// Exact A/B service-path removal receipts.
        roles: TenantRootOperationalRoleRemovalReceiptsV1,
        /// Exhaustive control-plane cleanup receipt.
        service_cleanup: TenantRootServiceCleanupReceiptV1,
        /// Explicitly records the absence of a cryptographic-erasure guarantee.
        erasure_claim: TenantRootOperationalErasureClaimV1,
    },
}

impl TenantRootDeletionEvidenceV1 {
    fn profile(&self) -> TenantRootDestructionProfileV1 {
        match self {
            Self::ManagedHealing { .. } => TenantRootDestructionProfileV1::ManagedHealing,
            Self::OperationalRotation { .. } => TenantRootDestructionProfileV1::OperationalRotation,
        }
    }

    fn completed_at_ms(&self) -> u64 {
        match self {
            Self::ManagedHealing {
                roles,
                service_cleanup,
            } => roles.completed_at_ms().max(service_cleanup.completed_at_ms),
            Self::OperationalRotation {
                roles,
                service_cleanup,
                ..
            } => roles.completed_at_ms().max(service_cleanup.completed_at_ms),
        }
    }

    fn earliest_at_ms(&self) -> u64 {
        match self {
            Self::ManagedHealing {
                roles,
                service_cleanup,
            } => roles.earliest_at_ms().min(service_cleanup.completed_at_ms),
            Self::OperationalRotation {
                roles,
                service_cleanup,
                ..
            } => roles.earliest_at_ms().min(service_cleanup.completed_at_ms),
        }
    }
}

/// Signed public terminal deletion receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletedReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    deleted_at_ms: u64,
}

impl TenantRootDeletedReceiptV1 {
    /// Creates one terminal deletion receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        deleted_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root deleted timestamp", deleted_at_ms)?;
        Ok(Self {
            digest,
            deleted_at_ms,
        })
    }
}

/// Required statement about recovery copies already controlled by the tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootTenantCopyDispositionV1 {
    /// Tenant-held recovery packages and keys remain outside service control.
    OutsideServiceControl,
}

/// Signed failure from an incomplete destruction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDestructionFailureV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    failed_at_ms: u64,
}

impl TenantRootDestructionFailureV1 {
    /// Creates one destruction failure receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        failed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root destruction failure timestamp", failed_at_ms)?;
        Ok(Self {
            digest,
            failed_at_ms,
        })
    }
}

/// Redacted digest of partial destruction progress retained while fenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDestructionProgressReceiptV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    observed_at_ms: u64,
}

impl TenantRootDestructionProgressReceiptV1 {
    /// Creates one redacted partial-progress receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        observed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root destruction progress timestamp", observed_at_ms)?;
        Ok(Self {
            digest,
            observed_at_ms,
        })
    }
}

/// Stable pre-deletion state with no root mutation in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletionActiveV1 {
    active: TenantRootActiveRefreshV1,
    profile: TenantRootDestructionProfileV1,
}

impl TenantRootDeletionActiveV1 {
    /// Admits a stable active root under one exact deployment claim.
    pub fn new(
        active: TenantRootActiveRefreshV1,
        profile: TenantRootDestructionProfileV1,
    ) -> RouterAbDerivationResult<Self> {
        if profile == TenantRootDestructionProfileV1::ManagedHealing
            && !matches!(
                active.current().verified().backup_policy(),
                TenantRootBackupPolicyV1::CurrentRoleBackups(_)
            )
        {
            return Err(malformed(
                "managed-healing deletion requires current role backup custody",
            ));
        }
        Ok(Self { active, profile })
    }

    /// Returns the active lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.active.revision()
    }

    /// Irreversibly fences derivation for this lineage.
    pub fn fence(
        self,
        authorization: TenantRootDeletionAuthorizationV1,
        fence: TenantRootDeletionFenceReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootDeletionFencedV1> {
        if authorization.requested_at_ms < self.active.current().activation_time_ms()
            || fence.fenced_at_ms < authorization.requested_at_ms
            || authorization.digest == fence.digest
        {
            return Err(malformed(
                "tenant-root deletion authorization and fence are inconsistent",
            ));
        }
        let revision = next_revision(self.revision())?;
        Ok(TenantRootDeletionFencedV1 {
            active: self.active,
            profile: self.profile,
            authorization,
            fence,
            revision,
        })
    }
}

/// Derivation is fenced while active-epoch sessions drain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletionFencedV1 {
    active: TenantRootActiveRefreshV1,
    profile: TenantRootDestructionProfileV1,
    authorization: TenantRootDeletionAuthorizationV1,
    fence: TenantRootDeletionFenceReceiptV1,
    revision: u64,
}

impl TenantRootDeletionFencedV1 {
    /// Begins destruction only after the exact active epoch has drained.
    pub fn begin_destruction(
        self,
        drain: TenantRootDeletionDrainReceiptV1,
        command: TenantRootDestructionCommandV1,
    ) -> RouterAbDerivationResult<TenantRootDeletionDestroyingV1> {
        require_distinct(&[
            self.authorization.digest,
            self.fence.digest,
            drain.digest,
            command.digest,
        ])?;
        if drain.epoch != self.active.current().epoch()
            || drain.drained_at_ms < self.fence.fenced_at_ms
            || command.started_at_ms < drain.drained_at_ms
        {
            return Err(malformed(
                "tenant-root destruction requires a drained active epoch and distinct receipts",
            ));
        }
        Ok(TenantRootDeletionDestroyingV1 {
            active: self.active,
            profile: self.profile,
            authorization: self.authorization,
            fence: self.fence,
            drain,
            command,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Irreversible destruction is in progress and derivation remains fenced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletionDestroyingV1 {
    active: TenantRootActiveRefreshV1,
    profile: TenantRootDestructionProfileV1,
    authorization: TenantRootDeletionAuthorizationV1,
    fence: TenantRootDeletionFenceReceiptV1,
    drain: TenantRootDeletionDrainReceiptV1,
    command: TenantRootDestructionCommandV1,
    revision: u64,
}

impl TenantRootDeletionDestroyingV1 {
    /// Completes deletion with evidence matching the deployment claim.
    pub fn complete(
        self,
        evidence: TenantRootDeletionEvidenceV1,
        receipt: TenantRootDeletedReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootDeletedV1> {
        let revision = self.revision;
        let earliest_completion_at_ms = self.command.started_at_ms;
        complete_deletion(
            self,
            TenantRootDeletionCompletionPathV1::Direct,
            revision,
            earliest_completion_at_ms,
            evidence,
            receipt,
        )
    }

    /// Records partial destruction and preserves the irreversible fence.
    pub fn record_incomplete(
        self,
        failure: TenantRootDestructionFailureV1,
        progress: TenantRootDestructionProgressReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootDestructionIncompleteV1> {
        if failure.failed_at_ms < self.command.started_at_ms
            || progress.observed_at_ms < failure.failed_at_ms
            || failure.digest == progress.digest
        {
            return Err(malformed(
                "tenant-root destruction failure and progress receipts are inconsistent",
            ));
        }
        let revision = next_revision(self.revision)?;
        Ok(TenantRootDestructionIncompleteV1 {
            destroying: self,
            failure,
            progress,
            revision,
        })
    }
}

/// Partial destruction remains irreversibly fenced until complete evidence arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDestructionIncompleteV1 {
    destroying: TenantRootDeletionDestroyingV1,
    failure: TenantRootDestructionFailureV1,
    progress: TenantRootDestructionProgressReceiptV1,
    revision: u64,
}

impl TenantRootDestructionIncompleteV1 {
    /// Completes the same deletion operation after the missing destruction succeeds.
    pub fn complete(
        self,
        evidence: TenantRootDeletionEvidenceV1,
        receipt: TenantRootDeletedReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootDeletedV1> {
        let prior_incomplete = TenantRootDeletionIncompleteAuditV1 {
            failure: self.failure,
            progress: self.progress,
        };
        complete_deletion(
            self.destroying,
            TenantRootDeletionCompletionPathV1::AfterIncomplete(prior_incomplete),
            self.revision,
            self.progress.observed_at_ms,
            evidence,
            receipt,
        )
    }
}

/// Terminal public audit state after every service-held path is removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootDeletedV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    root_commitment: [u8; 32],
    profile: TenantRootDestructionProfileV1,
    authorization: TenantRootDeletionAuthorizationV1,
    fence: TenantRootDeletionFenceReceiptV1,
    drain: TenantRootDeletionDrainReceiptV1,
    command: TenantRootDestructionCommandV1,
    completion_path: TenantRootDeletionCompletionPathV1,
    evidence: TenantRootDeletionEvidenceV1,
    receipt: TenantRootDeletedReceiptV1,
    tenant_copies: TenantRootTenantCopyDispositionV1,
    revision: u64,
}

impl TenantRootDeletedV1 {
    /// Returns the terminal lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the public stable root commitment retained for audit.
    pub const fn root_commitment(&self) -> &[u8; 32] {
        &self.root_commitment
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantRootDeletionIncompleteAuditV1 {
    failure: TenantRootDestructionFailureV1,
    progress: TenantRootDestructionProgressReceiptV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
enum TenantRootDeletionCompletionPathV1 {
    Direct,
    AfterIncomplete(TenantRootDeletionIncompleteAuditV1),
}

/// Exhaustive forward-only tenant-root deletion state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum TenantRootDeletionStateV1 {
    /// Stable active root before deletion starts.
    Active(TenantRootDeletionActiveV1),
    /// New derivation is fenced while sessions drain.
    Fenced(TenantRootDeletionFencedV1),
    /// Service-held material destruction is in progress.
    Destroying(TenantRootDeletionDestroyingV1),
    /// Every required service-held path was removed.
    Deleted(TenantRootDeletedV1),
    /// Partial destruction remains fenced.
    DestructionIncomplete(TenantRootDestructionIncompleteV1),
}

impl TenantRootDeletionStateV1 {
    /// Returns the authoritative lifecycle revision.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Active(state) => state.revision(),
            Self::Fenced(state) => state.revision,
            Self::Destroying(state) => state.revision,
            Self::Deleted(state) => state.revision,
            Self::DestructionIncomplete(state) => state.revision,
        }
    }
}

impl From<TenantRootDeletionActiveV1> for TenantRootDeletionStateV1 {
    fn from(state: TenantRootDeletionActiveV1) -> Self {
        Self::Active(state)
    }
}

impl From<TenantRootDeletionFencedV1> for TenantRootDeletionStateV1 {
    fn from(state: TenantRootDeletionFencedV1) -> Self {
        Self::Fenced(state)
    }
}

impl From<TenantRootDeletionDestroyingV1> for TenantRootDeletionStateV1 {
    fn from(state: TenantRootDeletionDestroyingV1) -> Self {
        Self::Destroying(state)
    }
}

impl From<TenantRootDeletedV1> for TenantRootDeletionStateV1 {
    fn from(state: TenantRootDeletedV1) -> Self {
        Self::Deleted(state)
    }
}

impl From<TenantRootDestructionIncompleteV1> for TenantRootDeletionStateV1 {
    fn from(state: TenantRootDestructionIncompleteV1) -> Self {
        Self::DestructionIncomplete(state)
    }
}

fn complete_deletion(
    destroying: TenantRootDeletionDestroyingV1,
    completion_path: TenantRootDeletionCompletionPathV1,
    current_revision: u64,
    earliest_completion_at_ms: u64,
    evidence: TenantRootDeletionEvidenceV1,
    receipt: TenantRootDeletedReceiptV1,
) -> RouterAbDerivationResult<TenantRootDeletedV1> {
    if evidence.profile() != destroying.profile {
        return Err(malformed(
            "tenant-root deletion evidence does not match the deployment profile",
        ));
    }
    require_distinct(&[
        destroying.authorization.digest,
        destroying.fence.digest,
        destroying.drain.digest,
        destroying.command.digest,
        receipt.digest,
    ])?;
    if evidence.earliest_at_ms() < earliest_completion_at_ms
        || receipt.deleted_at_ms < evidence.completed_at_ms()
    {
        return Err(malformed(
            "tenant-root deletion evidence and terminal receipt are out of order",
        ));
    }
    let revision = next_revision(current_revision)?;
    Ok(TenantRootDeletedV1 {
        identity: destroying.active.identity().clone(),
        custody_lineage: destroying.active.custody_lineage(),
        epoch: destroying.active.current().epoch(),
        root_commitment: *destroying
            .active
            .current()
            .verified()
            .commitments()
            .root_commitment(),
        profile: destroying.profile,
        authorization: destroying.authorization,
        fence: destroying.fence,
        drain: destroying.drain,
        command: destroying.command,
        completion_path,
        evidence,
        receipt,
        tenant_copies: TenantRootTenantCopyDispositionV1::OutsideServiceControl,
        revision,
    })
}

fn require_distinct(
    digests: &[TenantRootLifecycleReceiptDigestV1],
) -> RouterAbDerivationResult<()> {
    for (index, digest) in digests.iter().enumerate() {
        if digests[index + 1..].contains(digest) {
            return Err(malformed(
                "tenant-root deletion receipt digests must be distinct",
            ));
        }
    }
    Ok(())
}

fn require_order(started_at_ms: u64, completed_at_ms: u64) -> RouterAbDerivationResult<()> {
    require_timestamp("tenant-root destruction start timestamp", started_at_ms)?;
    if completed_at_ms < started_at_ms {
        return Err(malformed(
            "tenant-root destruction completion cannot predate its start",
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
        .ok_or_else(|| malformed("tenant-root deletion lifecycle revision is exhausted"))
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
