use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootProtocolDigestV1, TenantRootShareEpoch,
};

const TENANT_ROOT_COMMAND_REPLAY_KEY_DOMAIN_V1: &[u8] = b"seams/tenant-root-command-replay-key/v1";
const TENANT_ROOT_ROLE_COMMAND_DOMAIN_V1: &[u8] = b"seams/tenant-root-role-command/v1";

/// Exact role-local lookup key for one tenant-root command session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootCommandReplayKeyV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    session_id: TenantRootCeremonySessionIdV1,
    nonce: TenantRootCeremonyNonceV1,
    role: TwoPartyDeriverRole,
}

impl TenantRootCommandReplayKeyV1 {
    /// Creates Deriver A's exact role-local command replay key.
    pub const fn deriver_a(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        session_id: TenantRootCeremonySessionIdV1,
        nonce: TenantRootCeremonyNonceV1,
    ) -> Self {
        Self::new(
            identity_digest,
            custody_lineage,
            session_id,
            nonce,
            TwoPartyDeriverRole::DeriverA,
        )
    }

    /// Creates Deriver B's exact role-local command replay key.
    pub const fn deriver_b(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        session_id: TenantRootCeremonySessionIdV1,
        nonce: TenantRootCeremonyNonceV1,
    ) -> Self {
        Self::new(
            identity_digest,
            custody_lineage,
            session_id,
            nonce,
            TwoPartyDeriverRole::DeriverB,
        )
    }

    /// Creates one exact server-resolved command replay key.
    pub const fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        session_id: TenantRootCeremonySessionIdV1,
        nonce: TenantRootCeremonyNonceV1,
        role: TwoPartyDeriverRole,
    ) -> Self {
        Self {
            identity_digest,
            custody_lineage,
            session_id,
            nonce,
            role,
        }
    }

    /// Returns the digest used to locate one role-local replay row.
    ///
    /// The nonce remains authenticated inside the record. The lookup digest
    /// excludes it so reusing one session with another nonce reaches the same
    /// row and fails as a conflict.
    pub fn storage_key_digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        let mut hasher = Sha256::new();
        hasher.update(TENANT_ROOT_COMMAND_REPLAY_KEY_DOMAIN_V1);
        hasher.update(self.identity_digest.as_bytes());
        hasher.update(self.custody_lineage.as_bytes());
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.role.as_str().as_bytes());
        TenantRootProtocolDigestV1::from_bytes(hasher.finalize().into())
    }

    /// Returns the server-resolved logical tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the physical custody lineage bound to this command.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the one-use ceremony session identifier.
    pub const fn session_id(&self) -> TenantRootCeremonySessionIdV1 {
        self.session_id
    }

    /// Returns the exact command nonce authenticated by the stored record.
    pub const fn nonce(&self) -> TenantRootCeremonyNonceV1 {
        self.nonce
    }

    /// Returns the exact role owning the replay record.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }
}

/// Exact public scope selected by the control plane for one role-store command.
///
/// The role-local replay key identifies the authenticated tenant, physical
/// custody lineage, one-use session, nonce, and role. The epoch and expected
/// control-plane revision are required command coordinates and never come from
/// a request body or a role-local store lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootCommandScopeV1 {
    key: TenantRootCommandReplayKeyV1,
    epoch: TenantRootShareEpoch,
    expected_control_plane_revision: u64,
}

impl TenantRootCommandScopeV1 {
    /// Creates one exact control-plane command scope.
    pub fn new(
        key: TenantRootCommandReplayKeyV1,
        epoch: TenantRootShareEpoch,
        expected_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        if expected_control_plane_revision == 0 {
            return Err(malformed(
                "tenant-root command control-plane revision must be positive",
            ));
        }
        Ok(Self {
            key,
            epoch,
            expected_control_plane_revision,
        })
    }

    /// Returns the exact role-local replay key selected by the control plane.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        &self.key
    }

    /// Returns the exact custody epoch selected by the control plane.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the expected control-plane lifecycle revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }

    /// Returns the exact fixed-width command bytes for the operation.
    pub fn canonical_bytes(
        &self,
        operation: TenantRootCommandOperationV1,
    ) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        push_field(&mut bytes, TENANT_ROOT_ROLE_COMMAND_DOMAIN_V1)?;
        push_field(&mut bytes, operation.tag().as_bytes())?;
        push_field(&mut bytes, self.key.identity_digest.as_bytes())?;
        push_field(&mut bytes, self.key.custody_lineage.as_bytes())?;
        push_field(&mut bytes, self.key.role.as_str().as_bytes())?;
        push_field(&mut bytes, &self.epoch.get().get().to_be_bytes())?;
        push_field(
            &mut bytes,
            &self.expected_control_plane_revision.to_be_bytes(),
        )?;
        push_field(&mut bytes, self.key.session_id.as_bytes())?;
        push_field(&mut bytes, self.key.nonce.as_bytes())?;
        push_field(&mut bytes, operation.payload_digest().as_bytes())?;
        Ok(bytes)
    }

    /// Returns the digest of the exact role-store command fields.
    pub fn command_digest(
        &self,
        operation: TenantRootCommandOperationV1,
    ) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(
            Sha256::digest(self.canonical_bytes(operation)?).into(),
        )
    }
}

/// One role-store operation with a digest of its exact non-secret payload.
///
/// Payload bytes are represented only by their typed public digest. Secret
/// role shares and ciphertext never enter this command scope or its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRootCommandOperationV1 {
    /// Insert one pending role-share record.
    InsertPending {
        /// Digest of the exact public operation payload.
        payload_digest: TenantRootProtocolDigestV1,
    },
    /// Activate the initial epoch-one role-share record.
    ActivateInitial {
        /// Digest of the exact public operation payload.
        payload_digest: TenantRootProtocolDigestV1,
    },
    /// Swap one active role-share epoch for its exact successor.
    SwapActiveEpoch {
        /// Digest of the exact public operation payload.
        payload_digest: TenantRootProtocolDigestV1,
    },
    /// Remove one exact pending role-share record after a failed operation.
    CleanupPending {
        /// Digest of the exact public operation payload.
        payload_digest: TenantRootProtocolDigestV1,
    },
}

impl TenantRootCommandOperationV1 {
    /// Creates an insert-pending operation from its public payload digest.
    pub const fn insert_pending(payload_digest: TenantRootProtocolDigestV1) -> Self {
        Self::InsertPending { payload_digest }
    }

    /// Creates an initial-activation operation from its public payload digest.
    pub const fn activate_initial(payload_digest: TenantRootProtocolDigestV1) -> Self {
        Self::ActivateInitial { payload_digest }
    }

    /// Creates an active-epoch-swap operation from its public payload digest.
    pub const fn swap_active_epoch(payload_digest: TenantRootProtocolDigestV1) -> Self {
        Self::SwapActiveEpoch { payload_digest }
    }

    /// Creates a pending-cleanup operation from its public payload digest.
    pub const fn cleanup_pending(payload_digest: TenantRootProtocolDigestV1) -> Self {
        Self::CleanupPending { payload_digest }
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::InsertPending { .. } => "insert_pending",
            Self::ActivateInitial { .. } => "activate_initial",
            Self::SwapActiveEpoch { .. } => "swap_active_epoch",
            Self::CleanupPending { .. } => "cleanup_pending",
        }
    }

    const fn payload_digest(self) -> TenantRootProtocolDigestV1 {
        match self {
            Self::InsertPending { payload_digest }
            | Self::ActivateInitial { payload_digest }
            | Self::SwapActiveEpoch { payload_digest }
            | Self::CleanupPending { payload_digest } => payload_digest,
        }
    }
}

/// Reserved one-use command that has no execution checkpoint yet.
///
/// This token is consumed by either `checkpoint_executed` or `fail`, so a
/// caller cannot duplicate the one-use reservation in memory.
#[derive(Debug, PartialEq, Eq)]
pub struct ReservedTenantRootCommandV1 {
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    reserved_at_ms: u64,
}

impl ReservedTenantRootCommandV1 {
    /// Returns the exact role-local replay key.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        &self.key
    }

    /// Returns the digest of the exact command payload bytes.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        self.command_digest
    }

    /// Returns the durable reservation timestamp.
    pub const fn reserved_at_ms(&self) -> u64 {
        self.reserved_at_ms
    }

    /// Checkpoints that the command mutation has been durably applied.
    pub fn checkpoint_executed(
        self,
        executed_at_ms: u64,
    ) -> RouterAbDerivationResult<ExecutedTenantRootCommandV1> {
        require_terminal_time(self.reserved_at_ms, executed_at_ms)?;
        Ok(ExecutedTenantRootCommandV1 {
            reserved: self,
            executed_at_ms,
        })
    }

    /// Terminates this exact command with its signed failure receipt digest.
    pub fn fail(
        self,
        failure_receipt_digest: TenantRootProtocolDigestV1,
        failed_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootCommandReplayRecordV1> {
        require_terminal_time(self.reserved_at_ms, failed_at_ms)?;
        Ok(TenantRootCommandReplayRecordV1::Failed(
            FailedTenantRootCommandV1 {
                reserved: self,
                failure_receipt_digest,
            },
        ))
    }
}

/// One-use command whose mutation has been durably checkpointed.
///
/// This token can only be produced by consuming a reservation and can only
/// move to the successful terminal state.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutedTenantRootCommandV1 {
    reserved: ReservedTenantRootCommandV1,
    executed_at_ms: u64,
}

impl ExecutedTenantRootCommandV1 {
    /// Returns the exact role-local replay key.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        &self.reserved.key
    }

    /// Returns the digest of the exact command payload bytes.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        self.reserved.command_digest
    }

    /// Returns the durable reservation timestamp.
    pub const fn reserved_at_ms(&self) -> u64 {
        self.reserved.reserved_at_ms
    }

    /// Returns the durable execution-checkpoint timestamp.
    pub const fn executed_at_ms(&self) -> u64 {
        self.executed_at_ms
    }

    /// Completes this exact checkpoint with its signed public receipt digest.
    pub fn complete(
        self,
        receipt_digest: TenantRootProtocolDigestV1,
        completed_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootCommandReplayRecordV1> {
        require_terminal_time(self.executed_at_ms, completed_at_ms)?;
        Ok(TenantRootCommandReplayRecordV1::Completed(
            CompletedTenantRootCommandV1 {
                executed: self,
                receipt_digest,
            },
        ))
    }
}

/// Successfully completed command and its exact prior receipt digest.
#[derive(Debug, PartialEq, Eq)]
pub struct CompletedTenantRootCommandV1 {
    executed: ExecutedTenantRootCommandV1,
    receipt_digest: TenantRootProtocolDigestV1,
}

/// Failed command that consumed the one-use session.
#[derive(Debug, PartialEq, Eq)]
pub struct FailedTenantRootCommandV1 {
    reserved: ReservedTenantRootCommandV1,
    failure_receipt_digest: TenantRootProtocolDigestV1,
}

/// Exhaustive durable state for one role-local one-use command.
#[derive(Debug, PartialEq, Eq)]
pub enum TenantRootCommandReplayRecordV1 {
    /// The command is reserved before its mutation is applied.
    Reserved(ReservedTenantRootCommandV1),
    /// The command mutation is checkpointed and its terminal receipt is pending.
    Executed(ExecutedTenantRootCommandV1),
    /// Execution completed and identical retries reuse its prior receipt.
    Completed(CompletedTenantRootCommandV1),
    /// Execution failed terminally and the session cannot execute again.
    Failed(FailedTenantRootCommandV1),
}

impl TenantRootCommandReplayRecordV1 {
    /// Returns the exact replay key shared by every lifecycle branch.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        match self {
            Self::Reserved(record) => &record.key,
            Self::Executed(record) => &record.reserved.key,
            Self::Completed(record) => &record.executed.reserved.key,
            Self::Failed(record) => &record.reserved.key,
        }
    }

    /// Returns the exact payload digest shared by every lifecycle branch.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        match self {
            Self::Reserved(record) => record.command_digest,
            Self::Executed(record) => record.reserved.command_digest,
            Self::Completed(record) => record.executed.reserved.command_digest,
            Self::Failed(record) => record.reserved.command_digest,
        }
    }
}

/// Idempotency decision returned before command execution.
#[derive(Debug, PartialEq, Eq)]
pub enum TenantRootCommandReplayDecisionV1 {
    /// The caller must durably store this reservation before executing.
    Execute(ReservedTenantRootCommandV1),
    /// The identical command is already executing.
    InProgress,
    /// Return the prior successful receipt identified by this digest.
    ReplayCompleted {
        /// Digest of the exact previously committed receipt bytes.
        receipt_digest: TenantRootProtocolDigestV1,
    },
    /// Return the prior terminal failure identified by this digest.
    ReplayFailed {
        /// Digest of the exact previously committed failure receipt bytes.
        failure_receipt_digest: TenantRootProtocolDigestV1,
    },
}

/// Reserves a fresh one-use command or reconciles one exact retry.
pub fn reserve_tenant_root_command_v1(
    existing: Option<&TenantRootCommandReplayRecordV1>,
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    reserved_at_ms: u64,
) -> RouterAbDerivationResult<TenantRootCommandReplayDecisionV1> {
    if reserved_at_ms == 0 {
        return Err(malformed(
            "tenant-root command reservation time must be positive",
        ));
    }
    let Some(existing) = existing else {
        return Ok(TenantRootCommandReplayDecisionV1::Execute(
            ReservedTenantRootCommandV1 {
                key,
                command_digest,
                reserved_at_ms,
            },
        ));
    };
    if existing.key() != &key || existing.command_digest() != command_digest {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::ReplayMismatch,
            "tenant-root command session was reused with different authenticated bytes",
        ));
    }
    match existing {
        TenantRootCommandReplayRecordV1::Reserved(_)
        | TenantRootCommandReplayRecordV1::Executed(_) => {
            Ok(TenantRootCommandReplayDecisionV1::InProgress)
        }
        TenantRootCommandReplayRecordV1::Completed(record) => {
            Ok(TenantRootCommandReplayDecisionV1::ReplayCompleted {
                receipt_digest: record.receipt_digest,
            })
        }
        TenantRootCommandReplayRecordV1::Failed(record) => {
            Ok(TenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_digest: record.failure_receipt_digest,
            })
        }
    }
}

fn require_terminal_time(reserved_at_ms: u64, terminal_at_ms: u64) -> RouterAbDerivationResult<()> {
    if terminal_at_ms < reserved_at_ms {
        return Err(malformed(
            "tenant-root command terminal time precedes its reservation",
        ));
    }
    Ok(())
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root role command field is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
