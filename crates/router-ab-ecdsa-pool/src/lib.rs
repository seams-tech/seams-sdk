#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Storage-independent persistent lifecycle for fixed-role ECDSA presignatures.
//!
//! The crate emits revisioned compare-and-swap mutations. IndexedDB, Durable
//! Object, or database adapters must atomically persist the replacement record
//! and apply its exact retain, take, or destroy material disposition.

use core::fmt;
use serde::{Deserialize, Serialize};

macro_rules! define_nonzero_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
}

impl fmt::Display for PoolIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroBinding => "pool binding must be non-zero",
        })
    }
}

impl std::error::Error for PoolIdentityError {}

define_nonzero_digest!(
    /// Authenticated SigningWorker key-epoch binding.
    KeyEpoch
);
define_nonzero_digest!(
    /// Authenticated activation-epoch binding.
    ActivationEpoch
);

/// Fixed owner of one role-local pool record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolRole {
    /// Browser/client role.
    Client,
    /// SigningWorker role.
    SigningWorker,
}

/// Complete authenticated identity of one role-local pair record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ActiveRecordHeader {
    key: PoolRecordKey,
    revision: Revision,
    material: MaterialLocator,
    created_at_ms: u64,
    material_expires_at_ms: u64,
}

/// Available role-local material that has never been reserved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    /// Returns the material expiry deadline.
    pub const fn material_expires_at_ms(&self) -> u64 {
        self.0.material_expires_at_ms
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
        Ok(PoolMutation::retain(self.0.revision, next.into()))
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
            created_at_ms: self.created_at_ms,
            terminal_at_ms,
            reason,
            origin,
        };
        Ok(PoolMutation::destroy(
            self.revision,
            next.into(),
            self.material,
        ))
    }
}

/// Exact reservation and online-request binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    /// Returns the material expiry deadline.
    pub const fn material_expires_at_ms(&self) -> u64 {
        self.header.material_expires_at_ms
    }

    /// Returns the reservation lease deadline.
    pub const fn lease_expires_at_ms(&self) -> u64 {
        self.lease_expires_at_ms
    }

    /// Returns the first deadline at which cleanup must burn this reservation.
    pub const fn cleanup_deadline_ms(&self) -> u64 {
        if self.lease_expires_at_ms < self.header.material_expires_at_ms {
            self.lease_expires_at_ms
        } else {
            self.header.material_expires_at_ms
        }
    }

    /// Plans atomic consumption or a mandatory terminal burn.
    pub fn consume(&self, binding: ReservationBinding, now_ms: u64) -> ConsumeDecision {
        if now_ms < self.reserved_at_ms {
            return ConsumeDecision::Rejected(PoolTransitionError::InvalidTimestampOrder);
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
                Ok(mutation) => ConsumeDecision::Burned(mutation),
                Err(error) => ConsumeDecision::Rejected(error),
            };
        }
        let revision = match self.header.revision.next() {
            Ok(revision) => revision,
            Err(error) => return ConsumeDecision::Rejected(error),
        };
        let next = ConsumedRecord {
            key: self.header.key,
            revision,
            binding: self.binding,
            created_at_ms: self.header.created_at_ms,
            reserved_at_ms: self.reserved_at_ms,
            consumed_at_ms: now_ms,
        };
        ConsumeDecision::Consumed(PoolMutation::take(
            self.header.revision,
            next.into(),
            self.header.material,
        ))
    }

    /// Plans a terminal burn for a known failure before consumption.
    pub fn destroy(
        &self,
        reason: TombstoneReason,
        now_ms: u64,
    ) -> Result<PoolMutation, PoolTransitionError> {
        if now_ms < self.reserved_at_ms {
            return Err(PoolTransitionError::InvalidTimestampOrder);
        }
        self.header
            .tombstone(reason, now_ms, TombstoneOrigin::Attempted(self.binding))
    }

    /// Burns a reservation encountered during crash recovery.
    pub fn recover_after_crash(&self, now_ms: u64) -> Result<PoolMutation, PoolTransitionError> {
        self.destroy(TombstoneReason::CrashRecovery, now_ms)
    }

    /// Plans terminal cleanup after the material or lease deadline.
    pub fn expire(&self, now_ms: u64) -> Result<PoolMutation, PoolTransitionError> {
        let reason = if now_ms >= self.header.material_expires_at_ms {
            TombstoneReason::MaterialExpired
        } else if now_ms >= self.lease_expires_at_ms {
            TombstoneReason::Timeout
        } else {
            return Err(PoolTransitionError::TooEarly);
        };
        self.destroy(reason, now_ms)
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
        self.destroy(reason, now_ms)
    }
}

/// Result of planning a reserved-to-consumed transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeDecision {
    /// The exact reservation can atomically take and burn its material.
    Consumed(PoolMutation),
    /// The attempted use must atomically become a tombstone.
    Burned(PoolMutation),
    /// The command itself was malformed and produced no mutation.
    Rejected(PoolTransitionError),
}

/// Material-free absorbing record for one authorized online use.
///
/// ```compile_fail
/// use router_ab_ecdsa_pool::{ConsumedRecord, ReservationBinding};
/// fn consume_again(record: ConsumedRecord, binding: ReservationBinding) {
///     let _ = record.consume(binding, 1);
/// }
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsumedRecord {
    key: PoolRecordKey,
    revision: Revision,
    binding: ReservationBinding,
    created_at_ms: u64,
    reserved_at_ms: u64,
    consumed_at_ms: u64,
}

impl ConsumedRecord {
    /// Returns the record key.
    pub const fn key(&self) -> &PoolRecordKey {
        &self.key
    }

    /// Returns the record revision.
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the exact consumed reservation binding.
    pub const fn binding(&self) -> ReservationBinding {
        self.binding
    }

    /// Returns the material creation timestamp retained for audit.
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Returns the original reservation timestamp.
    pub const fn reserved_at_ms(&self) -> u64 {
        self.reserved_at_ms
    }

    /// Returns the atomic consumption timestamp.
    pub const fn consumed_at_ms(&self) -> u64 {
        self.consumed_at_ms
    }
}

/// Terminal origin retained for audit and idempotency checks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneOrigin {
    /// Material expired or its epoch retired before reservation.
    Unused,
    /// A reservation attempt existed.
    Attempted(ReservationBinding),
}

/// Permanent terminal disposition of one pair half.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneReason {
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TombstoneRecord {
    key: PoolRecordKey,
    revision: Revision,
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolRecord {
    /// Never-reserved material.
    Available(AvailableRecord),
    /// Material reserved for one exact request.
    Reserved(ReservedRecord),
    /// Material-free terminal evidence of one authorized online use.
    Consumed(ConsumedRecord),
    /// Permanently terminal material.
    Tombstone(TombstoneRecord),
}

impl PoolRecord {
    /// Returns the exact record key in every state.
    pub const fn key(&self) -> &PoolRecordKey {
        match self {
            Self::Available(record) => record.key(),
            Self::Reserved(record) => record.key(),
            Self::Consumed(record) => record.key(),
            Self::Tombstone(record) => record.key(),
        }
    }

    /// Returns the monotonic revision in every state.
    pub const fn revision(&self) -> Revision {
        match self {
            Self::Available(record) => record.revision(),
            Self::Reserved(record) => record.revision(),
            Self::Consumed(record) => record.revision(),
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

impl From<ConsumedRecord> for PoolRecord {
    fn from(value: ConsumedRecord) -> Self {
        Self::Consumed(value)
    }
}

impl From<TombstoneRecord> for PoolRecord {
    fn from(value: TombstoneRecord) -> Self {
        Self::Tombstone(value)
    }
}

/// Atomic sealed-material disposition paired with one CAS replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterialDisposition {
    /// Leave the sealed material in storage.
    Retain,
    /// Return the sealed material exactly once and delete it from storage.
    Take(MaterialLocator),
    /// Delete the sealed material without returning it.
    Destroy(MaterialLocator),
}

/// Compare-and-swap mutation emitted by one valid state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolMutation {
    expected_revision: Revision,
    replacement: PoolRecord,
    material_disposition: MaterialDisposition,
}

impl PoolMutation {
    fn retain(expected_revision: Revision, replacement: PoolRecord) -> Self {
        Self {
            expected_revision,
            replacement,
            material_disposition: MaterialDisposition::Retain,
        }
    }

    fn take(
        expected_revision: Revision,
        replacement: PoolRecord,
        material: MaterialLocator,
    ) -> Self {
        Self {
            expected_revision,
            replacement,
            material_disposition: MaterialDisposition::Take(material),
        }
    }

    fn destroy(
        expected_revision: Revision,
        replacement: PoolRecord,
        material: MaterialLocator,
    ) -> Self {
        Self {
            expected_revision,
            replacement,
            material_disposition: MaterialDisposition::Destroy(material),
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

    /// Returns the exact material operation to apply in the CAS transaction.
    pub const fn material_disposition(&self) -> MaterialDisposition {
        self.material_disposition
    }

    /// Consumes the mutation into its replacement and material disposition.
    pub fn into_parts(self) -> (PoolRecord, MaterialDisposition) {
        (self.replacement, self.material_disposition)
    }
}

/// State-transition planning failure that emits no mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolTransitionError {
    /// Timestamps violate creation, reservation, lease, or consumption ordering.
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
            digest(5, KeyEpoch::new),
            digest(6, ActivationEpoch::new),
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
        match mutation.into_parts().0 {
            PoolRecord::Reserved(record) => record,
            _ => panic!("reserve must produce a reserved record"),
        }
    }

    #[derive(Debug)]
    struct TestStore {
        record: PoolRecord,
        material: Option<MaterialLocator>,
    }

    impl TestStore {
        fn apply(&mut self, mutation: PoolMutation) -> Result<Option<MaterialLocator>, ()> {
            if self.record.key() != mutation.key()
                || self.record.revision() != mutation.expected_revision()
            {
                return Err(());
            }
            let (replacement, disposition) = mutation.into_parts();
            let taken = match disposition {
                MaterialDisposition::Retain => None,
                MaterialDisposition::Take(locator) => {
                    if self.material != Some(locator) {
                        return Err(());
                    }
                    self.material.take()
                }
                MaterialDisposition::Destroy(locator) => {
                    if self.material != Some(locator) {
                        return Err(());
                    }
                    self.material = None;
                    None
                }
            };
            self.record = replacement;
            Ok(taken)
        }
    }

    #[test]
    fn exact_lifecycle_atomically_takes_material_into_consumed_state() {
        let available = available();
        assert_eq!(available.revision(), Revision::INITIAL);
        let reserve = available.reserve(binding(10), 2_000, 10_000).unwrap();
        assert_eq!(reserve.material_disposition(), MaterialDisposition::Retain);
        let reserved = match reserve.into_parts().0 {
            PoolRecord::Reserved(record) => record,
            _ => panic!("expected reserved"),
        };
        assert_eq!(reserved.revision().value(), 1);
        let consume = match reserved.consume(binding(10), 3_000) {
            ConsumeDecision::Consumed(mutation) => mutation,
            _ => panic!("expected successful consumption"),
        };
        assert_eq!(
            consume.material_disposition(),
            MaterialDisposition::Take(digest(9, MaterialLocator::new))
        );
        let consumed = match consume.into_parts().0 {
            PoolRecord::Consumed(record) => record,
            _ => panic!("expected consumed"),
        };
        assert_eq!(consumed.revision().value(), 2);
        assert_eq!(consumed.binding(), binding(10));
        assert_eq!(consumed.created_at_ms(), 1_000);
        assert_eq!(consumed.reserved_at_ms(), 2_000);
        assert_eq!(consumed.consumed_at_ms(), 3_000);
    }

    #[test]
    fn stale_compare_and_swap_cannot_reserve_twice() {
        let available = available();
        let first = available.reserve(binding(10), 2_000, 10_000).unwrap();
        let stale = available.reserve(binding(20), 2_000, 10_000).unwrap();
        let mut store = TestStore {
            record: available.into(),
            material: Some(digest(9, MaterialLocator::new)),
        };
        assert_eq!(store.apply(first), Ok(None));
        assert_eq!(store.apply(stale), Err(()));
        assert!(matches!(store.record, PoolRecord::Reserved(_)));
    }

    #[test]
    fn stale_compare_and_swap_cannot_take_material_twice() {
        let reserved = reserved();
        let first = match reserved.consume(binding(10), 3_000) {
            ConsumeDecision::Consumed(mutation) => mutation,
            _ => panic!("first consume must succeed"),
        };
        let stale = match reserved.consume(binding(10), 3_000) {
            ConsumeDecision::Consumed(mutation) => mutation,
            _ => panic!("stale plan must still describe the same CAS"),
        };
        let mut store = TestStore {
            record: reserved.into(),
            material: Some(digest(9, MaterialLocator::new)),
        };
        assert_eq!(
            store.apply(first),
            Ok(Some(digest(9, MaterialLocator::new)))
        );
        assert_eq!(store.apply(stale), Err(()));
        assert!(matches!(store.record, PoolRecord::Consumed(_)));
        assert_eq!(store.material, None);
    }

    #[test]
    fn late_or_substituted_consume_burns_the_original_attempt() {
        let timeout = match reserved().consume(binding(10), 10_000) {
            ConsumeDecision::Burned(mutation) => mutation,
            _ => panic!("late consume must burn"),
        };
        assert_eq!(
            timeout.material_disposition(),
            MaterialDisposition::Destroy(digest(9, MaterialLocator::new))
        );
        let PoolRecord::Tombstone(timeout) = timeout.into_parts().0 else {
            panic!("late consume must tombstone");
        };
        assert_eq!(timeout.reason(), TombstoneReason::Timeout);

        let substituted = match reserved().consume(binding(30), 3_000) {
            ConsumeDecision::Burned(mutation) => mutation,
            _ => panic!("substituted consume must burn"),
        };
        let PoolRecord::Tombstone(substituted) = substituted.into_parts().0 else {
            panic!("substituted consume must tombstone");
        };
        assert_eq!(substituted.reason(), TombstoneReason::BindingRejected);
        assert_eq!(
            substituted.origin(),
            TombstoneOrigin::Attempted(binding(10))
        );
    }

    #[test]
    fn crash_recovery_is_terminal_and_destroys_material() {
        let recovery = reserved().recover_after_crash(3_000).unwrap();
        assert_eq!(
            recovery.material_disposition(),
            MaterialDisposition::Destroy(digest(9, MaterialLocator::new))
        );
        let PoolRecord::Tombstone(reserved_recovery) = reserved()
            .recover_after_crash(3_000)
            .unwrap()
            .into_parts()
            .0
        else {
            panic!("reserved recovery must tombstone");
        };
        assert_eq!(reserved_recovery.reason(), TombstoneReason::CrashRecovery);
    }

    #[test]
    fn available_expiry_and_epoch_retirement_destroy_material() {
        assert_eq!(
            available().expire(99_999),
            Err(PoolTransitionError::TooEarly)
        );
        let expired = available().expire(100_000).unwrap();
        assert_eq!(
            expired.material_disposition(),
            MaterialDisposition::Destroy(digest(9, MaterialLocator::new))
        );
        let retired = available()
            .retire(TombstoneReason::KeyEpochRetired, 2_000)
            .unwrap();
        let PoolRecord::Tombstone(retired) = retired.into_parts().0 else {
            panic!("retirement must tombstone");
        };
        assert_eq!(retired.reason(), TombstoneReason::KeyEpochRetired);
    }

    #[test]
    fn reserved_expiry_chooses_the_elapsed_deadline() {
        let reserved = reserved();
        assert_eq!(reserved.material_expires_at_ms(), 100_000);
        assert_eq!(reserved.lease_expires_at_ms(), 10_000);
        assert_eq!(reserved.cleanup_deadline_ms(), 10_000);
        assert_eq!(reserved.expire(9_999), Err(PoolTransitionError::TooEarly));
        let PoolRecord::Tombstone(timed_out) = reserved.expire(10_000).unwrap().into_parts().0
        else {
            panic!("lease expiry must tombstone");
        };
        assert_eq!(timed_out.reason(), TombstoneReason::Timeout);

        let material_limited = match available()
            .reserve(binding(10), 2_000, 100_000)
            .unwrap()
            .into_parts()
            .0
        {
            PoolRecord::Reserved(record) => record,
            _ => panic!("expected reservation"),
        };
        assert_eq!(material_limited.cleanup_deadline_ms(), 100_000);
        let PoolRecord::Tombstone(expired) =
            material_limited.expire(100_000).unwrap().into_parts().0
        else {
            panic!("material expiry must tombstone");
        };
        assert_eq!(expired.reason(), TombstoneReason::MaterialExpired);
    }

    #[test]
    fn reserved_failure_and_retirement_burn_material() {
        let aborted = reserved()
            .destroy(TombstoneReason::PeerAbort, 3_000)
            .unwrap();
        assert_eq!(
            aborted.material_disposition(),
            MaterialDisposition::Destroy(digest(9, MaterialLocator::new))
        );
        let PoolRecord::Tombstone(aborted) = aborted.into_parts().0 else {
            panic!("peer abort must tombstone");
        };
        assert_eq!(aborted.reason(), TombstoneReason::PeerAbort);

        let retired = reserved()
            .retire(TombstoneReason::ActivationEpochRetired, 3_000)
            .unwrap()
            .into_parts()
            .0;
        let PoolRecord::Tombstone(retired) = retired else {
            panic!("retirement must tombstone");
        };
        assert_eq!(retired.reason(), TombstoneReason::ActivationEpochRetired);
        assert_eq!(
            reserved().retire(TombstoneReason::Rejected, 3_000),
            Err(PoolTransitionError::InvalidTerminalReason)
        );
    }

    #[test]
    fn consumption_after_material_expiry_is_burned() {
        let mutation = available().reserve(binding(10), 2_000, 100_000).unwrap();
        let PoolRecord::Reserved(reserved) = mutation.into_parts().0 else {
            panic!("expected reservation");
        };
        let ConsumeDecision::Burned(expired) = reserved.consume(binding(10), 100_000) else {
            panic!("expired consume must burn");
        };
        let PoolRecord::Tombstone(expired) = expired.into_parts().0 else {
            panic!("expired consume must tombstone");
        };
        assert_eq!(expired.reason(), TombstoneReason::MaterialExpired);
    }

    #[test]
    fn zero_bindings_and_epochs_are_rejected() {
        assert_eq!(
            WalletBinding::new([0; 32]),
            Err(PoolIdentityError::ZeroBinding)
        );
        assert_eq!(KeyEpoch::new([0; 32]), Err(PoolIdentityError::ZeroBinding));
        assert_eq!(
            ActivationEpoch::new([0; 32]),
            Err(PoolIdentityError::ZeroBinding)
        );
    }
}
