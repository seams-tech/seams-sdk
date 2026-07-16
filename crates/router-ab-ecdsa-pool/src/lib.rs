#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Storage-independent persistent lifecycle for fixed-role ECDSA presignatures.
//!
//! The crate emits revisioned compare-and-swap mutations. IndexedDB, Durable
//! Object, or database adapters must atomically persist the replacement record
//! and delete sealed material when a mutation enters the tombstone state.

use core::fmt;

macro_rules! define_nonzero_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Parses a non-zero fixed-width binding.
            pub fn new(bytes: [u8; 32]) -> Result<Self, PoolIdentityError> {
                if bytes == [0; 32] {
                    return Err(PoolIdentityError::ZeroBinding);
                }
                Ok(Self(bytes))
            }

            /// Returns the fixed-width binding bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

define_nonzero_digest!(
    /// Authenticated wallet identity digest.
    WalletBinding
);
define_nonzero_digest!(
    /// Authenticated account identity digest.
    AccountBinding
);
define_nonzero_digest!(
    /// Authenticated signing-scope digest.
    SigningScopeBinding
);
define_nonzero_digest!(
    /// Unique presignature-pair identifier.
    PresignPairId
);
define_nonzero_digest!(
    /// Exact online request identifier.
    RequestBinding
);
define_nonzero_digest!(
    /// Unique reservation attempt identifier.
    ReservationId
);
define_nonzero_digest!(
    /// Locator for sealed role-local presignature material.
    MaterialLocator
);
define_nonzero_digest!(
    /// Exact production protocol identifier.
    ProtocolBinding
);

/// Identity parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolIdentityError {
    /// A required digest was all zeroes.
    ZeroBinding,
    /// An epoch must be non-zero.
    ZeroEpoch,
}

impl fmt::Display for PoolIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroBinding => "pool binding must be non-zero",
            Self::ZeroEpoch => "pool epoch must be non-zero",
        })
    }
}

impl std::error::Error for PoolIdentityError {}

/// Non-zero key epoch selected by the authenticated registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyEpoch(u64);

impl KeyEpoch {
    /// Parses a non-zero key epoch.
    pub fn new(value: u64) -> Result<Self, PoolIdentityError> {
        if value == 0 {
            return Err(PoolIdentityError::ZeroEpoch);
        }
        Ok(Self(value))
    }

    /// Returns the epoch value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Non-zero activation epoch selected by the authenticated registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ActivationEpoch(u64);

impl ActivationEpoch {
    /// Parses a non-zero activation epoch.
    pub fn new(value: u64) -> Result<Self, PoolIdentityError> {
        if value == 0 {
            return Err(PoolIdentityError::ZeroEpoch);
        }
        Ok(Self(value))
    }

    /// Returns the epoch value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Fixed owner of one role-local pool record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PoolRole {
    /// Browser/client role.
    Client,
    /// SigningWorker role.
    SigningWorker,
}

/// Complete authenticated identity of one role-local pair record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PoolRecordKey {
    wallet: WalletBinding,
    account: AccountBinding,
    signing_scope: SigningScopeBinding,
    pair_id: PresignPairId,
    role: PoolRole,
    key_epoch: KeyEpoch,
    activation_epoch: ActivationEpoch,
    protocol: ProtocolBinding,
}

impl PoolRecordKey {
    /// Constructs one exact pool identity from already authenticated bindings.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        wallet: WalletBinding,
        account: AccountBinding,
        signing_scope: SigningScopeBinding,
        pair_id: PresignPairId,
        role: PoolRole,
        key_epoch: KeyEpoch,
        activation_epoch: ActivationEpoch,
        protocol: ProtocolBinding,
    ) -> Self {
        Self {
            wallet,
            account,
            signing_scope,
            pair_id,
            role,
            key_epoch,
            activation_epoch,
            protocol,
        }
    }

    /// Returns the role owning this record.
    pub const fn role(&self) -> PoolRole {
        self.role
    }

    /// Returns the presignature-pair identifier.
    pub const fn pair_id(&self) -> PresignPairId {
        self.pair_id
    }
}

/// Monotonic record revision used for compare-and-swap persistence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    /// Initial available-record revision.
    pub const INITIAL: Self = Self(0);

    /// Returns the revision value.
    pub const fn value(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, PoolTransitionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(PoolTransitionError::RevisionExhausted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveRecordHeader {
    key: PoolRecordKey,
    revision: Revision,
    material: MaterialLocator,
    created_at_ms: u64,
    material_expires_at_ms: u64,
}

/// Available role-local material that has never been reserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableRecord(ActiveRecordHeader);

impl AvailableRecord {
    /// Creates one available record at revision zero.
    pub fn new(
        key: PoolRecordKey,
        material: MaterialLocator,
        created_at_ms: u64,
        material_expires_at_ms: u64,
    ) -> Result<Self, PoolTransitionError> {
        if material_expires_at_ms <= created_at_ms {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        Ok(Self(ActiveRecordHeader {
            key,
            revision: Revision::INITIAL,
            material,
            created_at_ms,
            material_expires_at_ms,
        }))
    }

    /// Returns the record key.
    pub const fn key(&self) -> &PoolRecordKey {
        &self.0.key
    }

    /// Returns the record revision.
    pub const fn revision(&self) -> Revision {
        self.0.revision
    }

    /// Plans an atomic transition to the reserved state.
    pub fn reserve(
        &self,
        binding: ReservationBinding,
        reserved_at_ms: u64,
        lease_expires_at_ms: u64,
    ) -> Result<PoolMutation, PoolTransitionError> {
        if reserved_at_ms < self.0.created_at_ms {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        if reserved_at_ms >= self.0.material_expires_at_ms {
            return Err(PoolTransitionError::MaterialExpired);
        }
        if lease_expires_at_ms <= reserved_at_ms
            || lease_expires_at_ms > self.0.material_expires_at_ms
        {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        let next = ReservedRecord {
            header: self.0.with_next_revision()?,
            binding,
            reserved_at_ms,
            lease_expires_at_ms,
        };
        Ok(PoolMutation::new(self.0.revision, next.into()))
    }

    /// Plans terminal destruction of expired available material.
    pub fn expire(&self, now_ms: u64) -> Result<PoolMutation, PoolTransitionError> {
        if now_ms < self.0.material_expires_at_ms {
            return Err(PoolTransitionError::TooEarly);
        }
        self.0.tombstone(
            TombstoneReason::MaterialExpired,
            now_ms,
            TombstoneOrigin::Unused,
        )
    }

    /// Plans terminal destruction after key or activation epoch retirement.
    pub fn retire(
        &self,
        reason: TombstoneReason,
        now_ms: u64,
    ) -> Result<PoolMutation, PoolTransitionError> {
        if !matches!(
            reason,
            TombstoneReason::KeyEpochRetired | TombstoneReason::ActivationEpochRetired
        ) {
            return Err(PoolTransitionError::InvalidTerminalReason);
        }
        self.0.tombstone(reason, now_ms, TombstoneOrigin::Unused)
    }
}

impl ActiveRecordHeader {
    fn with_next_revision(&self) -> Result<Self, PoolTransitionError> {
        let mut next = self.clone();
        next.revision = next.revision.next()?;
        Ok(next)
    }

    fn tombstone(
        &self,
        reason: TombstoneReason,
        terminal_at_ms: u64,
        origin: TombstoneOrigin,
    ) -> Result<PoolMutation, PoolTransitionError> {
        if terminal_at_ms < self.created_at_ms {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        let next = TombstoneRecord {
            key: self.key,
            revision: self.revision.next()?,
            material: self.material,
            created_at_ms: self.created_at_ms,
            terminal_at_ms,
            reason,
            origin,
        };
        Ok(PoolMutation::new(self.revision, next.into()))
    }
}

/// Exact reservation and online-request binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReservationBinding {
    reservation_id: ReservationId,
    request: RequestBinding,
}

impl ReservationBinding {
    /// Constructs an exact reservation binding.
    pub const fn new(reservation_id: ReservationId, request: RequestBinding) -> Self {
        Self {
            reservation_id,
            request,
        }
    }
}

/// Persisted reservation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedRecord {
    header: ActiveRecordHeader,
    binding: ReservationBinding,
    reserved_at_ms: u64,
    lease_expires_at_ms: u64,
}

impl ReservedRecord {
    /// Returns the record key.
    pub const fn key(&self) -> &PoolRecordKey {
        &self.header.key
    }

    /// Returns the record revision.
    pub const fn revision(&self) -> Revision {
        self.header.revision
    }

    /// Returns the exact reservation binding.
    pub const fn binding(&self) -> ReservationBinding {
        self.binding
    }

    /// Plans commit or a mandatory terminal burn for a late/substituted use.
    pub fn commit(&self, binding: ReservationBinding, now_ms: u64) -> CommitDecision {
        if now_ms < self.reserved_at_ms {
            return CommitDecision::Rejected(PoolTransitionError::InvalidTimestampOrder);
        }
        let burn_reason = if binding != self.binding {
            Some(TombstoneReason::BindingRejected)
        } else if now_ms >= self.header.material_expires_at_ms {
            Some(TombstoneReason::MaterialExpired)
        } else if now_ms >= self.lease_expires_at_ms {
            Some(TombstoneReason::Timeout)
        } else {
            None
        };
        if let Some(reason) = burn_reason {
            return match self.header.tombstone(
                reason,
                now_ms,
                TombstoneOrigin::Attempted(self.binding),
            ) {
                Ok(mutation) => CommitDecision::Burned(mutation),
                Err(error) => CommitDecision::Rejected(error),
            };
        }
        let next_header = match self.header.with_next_revision() {
            Ok(header) => header,
            Err(error) => return CommitDecision::Rejected(error),
        };
        CommitDecision::Committed(PoolMutation::new(
            self.header.revision,
            CommittedRecord {
                header: next_header,
                binding: self.binding,
                reserved_at_ms: self.reserved_at_ms,
                committed_at_ms: now_ms,
            }
            .into(),
        ))
    }

    /// Plans a terminal burn for a known failure before commitment.
    pub fn destroy(
        &self,
        reason: TombstoneReason,
        now_ms: u64,
    ) -> Result<PoolMutation, PoolTransitionError> {
        if now_ms < self.reserved_at_ms {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        if reason == TombstoneReason::Succeeded {
            return Err(PoolTransitionError::InvalidTerminalReason);
        }
        self.header
            .tombstone(reason, now_ms, TombstoneOrigin::Attempted(self.binding))
    }

    /// Burns a reservation encountered during crash recovery.
    pub fn recover_after_crash(&self, now_ms: u64) -> Result<PoolMutation, PoolTransitionError> {
        self.destroy(TombstoneReason::CrashRecovery, now_ms)
    }
}

/// Result of planning a reserved-to-committed transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitDecision {
    /// The exact reservation can advance to committed use.
    Committed(PoolMutation),
    /// The attempted use must atomically become a tombstone.
    Burned(PoolMutation),
    /// The command itself was malformed and produced no mutation.
    Rejected(PoolTransitionError),
}

/// Persisted committed-use state. Online output still requires terminal burn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRecord {
    header: ActiveRecordHeader,
    binding: ReservationBinding,
    reserved_at_ms: u64,
    committed_at_ms: u64,
}

impl CommittedRecord {
    /// Returns the record key.
    pub const fn key(&self) -> &PoolRecordKey {
        &self.header.key
    }

    /// Returns the record revision.
    pub const fn revision(&self) -> Revision {
        self.header.revision
    }

    /// Returns the exact committed reservation binding.
    pub const fn binding(&self) -> ReservationBinding {
        self.binding
    }

    /// Returns the original reservation timestamp.
    pub const fn reserved_at_ms(&self) -> u64 {
        self.reserved_at_ms
    }

    /// Plans terminal consumption or destruction before output release.
    pub fn finish(
        &self,
        reason: TombstoneReason,
        now_ms: u64,
    ) -> Result<PoolMutation, PoolTransitionError> {
        if now_ms < self.committed_at_ms {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        let reason = if now_ms >= self.header.material_expires_at_ms {
            TombstoneReason::MaterialExpired
        } else {
            reason
        };
        self.header
            .tombstone(reason, now_ms, TombstoneOrigin::Attempted(self.binding))
    }

    /// Burns a committed use after crash or ambiguous-delivery recovery.
    pub fn recover_ambiguous_delivery(
        &self,
        now_ms: u64,
    ) -> Result<PoolMutation, PoolTransitionError> {
        self.finish(TombstoneReason::AmbiguousDelivery, now_ms)
    }
}

/// Terminal origin retained for audit and idempotency checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TombstoneOrigin {
    /// Material expired or its epoch retired before reservation.
    Unused,
    /// A reservation attempt existed.
    Attempted(ReservationBinding),
}

/// Permanent terminal disposition of one pair half.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TombstoneReason {
    /// A signature share or final signature completed successfully.
    Succeeded,
    /// Cryptographic or policy validation rejected the attempt.
    Rejected,
    /// An identity or request binding was substituted.
    BindingRejected,
    /// The reservation or protocol attempt timed out.
    Timeout,
    /// The caller cancelled the attempt.
    Cancelled,
    /// Startup recovery found an interrupted reservation.
    CrashRecovery,
    /// The peer aborted the protocol.
    PeerAbort,
    /// Output delivery may have occurred before failure became visible.
    AmbiguousDelivery,
    /// Persistent storage failed during the attempt.
    PersistenceFailure,
    /// The material lifetime elapsed.
    MaterialExpired,
    /// The authenticated key epoch retired.
    KeyEpochRetired,
    /// The authenticated activation epoch retired.
    ActivationEpochRetired,
}

/// Absorbing terminal record. It exposes no transition back to availability.
///
/// ```compile_fail
/// use router_ab_ecdsa_pool::{ReservationBinding, TombstoneRecord};
/// fn revive(record: TombstoneRecord, binding: ReservationBinding) {
///     let _ = record.reserve(binding, 1, 2);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TombstoneRecord {
    key: PoolRecordKey,
    revision: Revision,
    material: MaterialLocator,
    created_at_ms: u64,
    terminal_at_ms: u64,
    reason: TombstoneReason,
    origin: TombstoneOrigin,
}

impl TombstoneRecord {
    /// Returns the record key.
    pub const fn key(&self) -> &PoolRecordKey {
        &self.key
    }

    /// Returns the terminal revision.
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the permanent terminal reason.
    pub const fn reason(&self) -> TombstoneReason {
        self.reason
    }

    /// Returns the terminal origin.
    pub const fn origin(&self) -> TombstoneOrigin {
        self.origin
    }

    /// Returns the material locator that the atomic adapter must delete.
    pub const fn material_to_destroy(&self) -> MaterialLocator {
        self.material
    }

    /// Returns the creation timestamp retained for audit.
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Returns the terminal timestamp retained for audit.
    pub const fn terminal_at_ms(&self) -> u64 {
        self.terminal_at_ms
    }
}

/// Exact discriminated persisted record state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolRecord {
    /// Never-reserved material.
    Available(AvailableRecord),
    /// Material reserved for one exact request.
    Reserved(ReservedRecord),
    /// Material committed to one exact online use.
    Committed(CommittedRecord),
    /// Permanently terminal material.
    Tombstone(TombstoneRecord),
}

impl PoolRecord {
    /// Returns the exact record key in every state.
    pub const fn key(&self) -> &PoolRecordKey {
        match self {
            Self::Available(record) => record.key(),
            Self::Reserved(record) => record.key(),
            Self::Committed(record) => record.key(),
            Self::Tombstone(record) => record.key(),
        }
    }

    /// Returns the monotonic revision in every state.
    pub const fn revision(&self) -> Revision {
        match self {
            Self::Available(record) => record.revision(),
            Self::Reserved(record) => record.revision(),
            Self::Committed(record) => record.revision(),
            Self::Tombstone(record) => record.revision(),
        }
    }
}

impl From<AvailableRecord> for PoolRecord {
    fn from(value: AvailableRecord) -> Self {
        Self::Available(value)
    }
}

impl From<ReservedRecord> for PoolRecord {
    fn from(value: ReservedRecord) -> Self {
        Self::Reserved(value)
    }
}

impl From<CommittedRecord> for PoolRecord {
    fn from(value: CommittedRecord) -> Self {
        Self::Committed(value)
    }
}

impl From<TombstoneRecord> for PoolRecord {
    fn from(value: TombstoneRecord) -> Self {
        Self::Tombstone(value)
    }
}

/// Compare-and-swap mutation emitted by one valid state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolMutation {
    expected_revision: Revision,
    replacement: PoolRecord,
}

impl PoolMutation {
    fn new(expected_revision: Revision, replacement: PoolRecord) -> Self {
        Self {
            expected_revision,
            replacement,
        }
    }

    /// Returns the exact key that the adapter must compare and replace.
    pub const fn key(&self) -> &PoolRecordKey {
        self.replacement.key()
    }

    /// Returns the revision that must still be persisted.
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }

    /// Returns the replacement record.
    pub const fn replacement(&self) -> &PoolRecord {
        &self.replacement
    }

    /// Consumes the mutation and returns its replacement record.
    pub fn into_replacement(self) -> PoolRecord {
        self.replacement
    }

    /// Returns the material locator to delete for terminal mutations.
    pub const fn material_to_destroy(&self) -> Option<MaterialLocator> {
        match &self.replacement {
            PoolRecord::Tombstone(record) => Some(record.material_to_destroy()),
            PoolRecord::Available(_) | PoolRecord::Reserved(_) | PoolRecord::Committed(_) => None,
        }
    }
}

/// State-transition planning failure that emits no mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolTransitionError {
    /// Timestamps violate creation, reservation, lease, or commit ordering.
    InvalidTimestampOrder,
    /// The available material has already expired.
    MaterialExpired,
    /// A timeout/expiry transition was requested before its deadline.
    TooEarly,
    /// The requested terminal reason is invalid for the current state.
    InvalidTerminalReason,
    /// The monotonic revision counter is exhausted.
    RevisionExhausted,
}

impl fmt::Display for PoolTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTimestampOrder => "pool timestamps are out of order",
            Self::MaterialExpired => "presignature material is expired",
            Self::TooEarly => "pool transition deadline has not elapsed",
            Self::InvalidTerminalReason => "terminal reason is invalid for this state",
            Self::RevisionExhausted => "pool revision counter is exhausted",
        })
    }
}

impl std::error::Error for PoolTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest<T>(value: u8, constructor: fn([u8; 32]) -> Result<T, PoolIdentityError>) -> T {
        constructor([value; 32]).unwrap()
    }

    fn key(role: PoolRole) -> PoolRecordKey {
        PoolRecordKey::new(
            digest(1, WalletBinding::new),
            digest(2, AccountBinding::new),
            digest(3, SigningScopeBinding::new),
            digest(4, PresignPairId::new),
            role,
            KeyEpoch::new(5).unwrap(),
            ActivationEpoch::new(6).unwrap(),
            digest(7, ProtocolBinding::new),
        )
    }

    fn binding(value: u8) -> ReservationBinding {
        ReservationBinding::new(
            digest(value, ReservationId::new),
            digest(value.wrapping_add(1), RequestBinding::new),
        )
    }

    fn available() -> AvailableRecord {
        AvailableRecord::new(
            key(PoolRole::Client),
            digest(9, MaterialLocator::new),
            1_000,
            100_000,
        )
        .unwrap()
    }

    fn reserved() -> ReservedRecord {
        let mutation = available().reserve(binding(10), 2_000, 10_000).unwrap();
        match mutation.into_replacement() {
            PoolRecord::Reserved(record) => record,
            _ => panic!("reserve must produce a reserved record"),
        }
    }

    fn committed() -> CommittedRecord {
        match reserved().commit(binding(10), 3_000) {
            CommitDecision::Committed(mutation) => match mutation.into_replacement() {
                PoolRecord::Committed(record) => record,
                _ => panic!("commit must produce a committed record"),
            },
            _ => panic!("valid commit must succeed"),
        }
    }

    #[derive(Debug)]
    struct TestStore {
        record: PoolRecord,
    }

    impl TestStore {
        fn apply(&mut self, mutation: PoolMutation) -> bool {
            if self.record.key() != mutation.key()
                || self.record.revision() != mutation.expected_revision()
            {
                return false;
            }
            self.record = mutation.into_replacement();
            true
        }
    }

    #[test]
    fn exact_lifecycle_is_monotonic_and_terminal() {
        let available = available();
        assert_eq!(available.revision(), Revision::INITIAL);
        let reserved = match available
            .reserve(binding(10), 2_000, 10_000)
            .unwrap()
            .into_replacement()
        {
            PoolRecord::Reserved(record) => record,
            _ => panic!("expected reserved"),
        };
        assert_eq!(reserved.revision().value(), 1);
        let committed = match reserved.commit(binding(10), 3_000) {
            CommitDecision::Committed(mutation) => match mutation.into_replacement() {
                PoolRecord::Committed(record) => record,
                _ => panic!("expected committed"),
            },
            _ => panic!("expected successful commit"),
        };
        assert_eq!(committed.revision().value(), 2);
        let terminal = match committed
            .finish(TombstoneReason::Succeeded, 4_000)
            .unwrap()
            .into_replacement()
        {
            PoolRecord::Tombstone(record) => record,
            _ => panic!("expected tombstone"),
        };
        assert_eq!(terminal.revision().value(), 3);
        assert_eq!(terminal.reason(), TombstoneReason::Succeeded);
        assert_eq!(terminal.origin(), TombstoneOrigin::Attempted(binding(10)));
    }

    #[test]
    fn stale_compare_and_swap_cannot_reserve_twice() {
        let available = available();
        let first = available.reserve(binding(10), 2_000, 10_000).unwrap();
        let stale = available.reserve(binding(20), 2_000, 10_000).unwrap();
        let mut store = TestStore {
            record: available.into(),
        };
        assert!(store.apply(first));
        assert!(!store.apply(stale));
        assert!(matches!(store.record, PoolRecord::Reserved(_)));
    }

    #[test]
    fn late_or_substituted_commit_burns_the_original_attempt() {
        let timeout = match reserved().commit(binding(10), 10_000) {
            CommitDecision::Burned(mutation) => mutation,
            _ => panic!("late commit must burn"),
        };
        let PoolRecord::Tombstone(timeout) = timeout.into_replacement() else {
            panic!("late commit must tombstone");
        };
        assert_eq!(timeout.reason(), TombstoneReason::Timeout);

        let substituted = match reserved().commit(binding(30), 3_000) {
            CommitDecision::Burned(mutation) => mutation,
            _ => panic!("substituted commit must burn"),
        };
        let PoolRecord::Tombstone(substituted) = substituted.into_replacement() else {
            panic!("substituted commit must tombstone");
        };
        assert_eq!(substituted.reason(), TombstoneReason::BindingRejected);
        assert_eq!(
            substituted.origin(),
            TombstoneOrigin::Attempted(binding(10))
        );
    }

    #[test]
    fn crash_and_ambiguous_recovery_are_terminal() {
        let PoolRecord::Tombstone(reserved_recovery) = reserved()
            .recover_after_crash(3_000)
            .unwrap()
            .into_replacement()
        else {
            panic!("reserved recovery must tombstone");
        };
        assert_eq!(reserved_recovery.reason(), TombstoneReason::CrashRecovery);

        let PoolRecord::Tombstone(committed_recovery) = committed()
            .recover_ambiguous_delivery(4_000)
            .unwrap()
            .into_replacement()
        else {
            panic!("committed recovery must tombstone");
        };
        assert_eq!(
            committed_recovery.reason(),
            TombstoneReason::AmbiguousDelivery
        );
    }

    #[test]
    fn available_expiry_and_epoch_retirement_destroy_material() {
        assert_eq!(
            available().expire(99_999),
            Err(PoolTransitionError::TooEarly)
        );
        let expired = available().expire(100_000).unwrap();
        assert_eq!(
            expired.material_to_destroy(),
            Some(digest(9, MaterialLocator::new))
        );
        let retired = available()
            .retire(TombstoneReason::KeyEpochRetired, 2_000)
            .unwrap();
        let PoolRecord::Tombstone(retired) = retired.into_replacement() else {
            panic!("retirement must tombstone");
        };
        assert_eq!(retired.reason(), TombstoneReason::KeyEpochRetired);
    }

    #[test]
    fn reserved_success_is_unrepresentable_and_peer_abort_burns() {
        assert_eq!(
            reserved().destroy(TombstoneReason::Succeeded, 3_000),
            Err(PoolTransitionError::InvalidTerminalReason)
        );
        let PoolRecord::Tombstone(aborted) = reserved()
            .destroy(TombstoneReason::PeerAbort, 3_000)
            .unwrap()
            .into_replacement()
        else {
            panic!("peer abort must tombstone");
        };
        assert_eq!(aborted.reason(), TombstoneReason::PeerAbort);
    }

    #[test]
    fn committed_output_after_material_expiry_is_burned() {
        let PoolRecord::Tombstone(expired) = committed()
            .finish(TombstoneReason::Succeeded, 100_000)
            .unwrap()
            .into_replacement()
        else {
            panic!("expired committed use must tombstone");
        };
        assert_eq!(expired.reason(), TombstoneReason::MaterialExpired);
    }

    #[test]
    fn zero_bindings_and_epochs_are_rejected() {
        assert_eq!(
            WalletBinding::new([0; 32]),
            Err(PoolIdentityError::ZeroBinding)
        );
        assert_eq!(KeyEpoch::new(0), Err(PoolIdentityError::ZeroEpoch));
        assert_eq!(ActivationEpoch::new(0), Err(PoolIdentityError::ZeroEpoch));
    }
}
