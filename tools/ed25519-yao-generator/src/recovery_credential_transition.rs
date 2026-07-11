//! Construction-independent recovery credential suspension and promotion.
//!
//! Admitted recovery moves the active credential into a typed suspended state.
//! Only a strictly receipt-verified recovery-origin SigningWorker activation can
//! promote the distinct replacement and tombstone the old binding. Transaction
//! digests remain opaque host evidence; this module makes no durability or
//! selected-profile claim.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::authenticated_store::{
    ActiveStoreStateVersionV1, AuthenticatedRegisteredStoreResolutionV1,
    StoreAuthoritySignature64V1, StoreAuthorityVerifyingKeyV1,
};
use crate::lifecycle_domain::{
    ActiveCredentialBindingDigest32V1, AuthenticatedRecoveryCredentialContinuityEvidenceV1,
    RecoveryCredentialContinuityErrorV1, RegisteredLifecyclePreStateV1,
};
use crate::signing_worker_activation::{
    SigningWorkerActivationReceiptDigest32V1, SigningWorkerActivationSuccessV1,
};

/// Canonical signed recovery-promotion body domain.
pub const RECOVERY_PROMOTION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recovery-promotion/v1";
/// Domain for the authenticated recovery-promotion receipt digest.
pub const RECOVERY_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recovery-promotion-receipt-digest/v1";
/// Domain for a complete recovery registered-state projection.
pub const RECOVERY_PROMOTION_STATE_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recovery-promotion-state-digest/v1";
/// Domain for the retired old-credential tombstone.
pub const RECOVERY_CREDENTIAL_TOMBSTONE_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recovery-credential-tombstone-digest/v1";

/// Authenticated registered state whose old credential is suspended by recovery admission.
pub struct AuthenticatedRecoveryCredentialSuspensionV1 {
    state: AuthenticatedRegisteredStoreResolutionV1,
    continuity: AuthenticatedRecoveryCredentialContinuityEvidenceV1,
}

impl AuthenticatedRecoveryCredentialSuspensionV1 {
    pub(crate) fn try_from_admitted(
        state: AuthenticatedRegisteredStoreResolutionV1,
        continuity: AuthenticatedRecoveryCredentialContinuityEvidenceV1,
    ) -> Result<Self, RejectedRecoveryCredentialSuspensionV1> {
        let reason = if state.active_state_version() != continuity.active_state_version() {
            Some(RecoveryCredentialContinuityErrorV1::ActiveStateVersionMismatch)
        } else if state.state().active_credential_binding_digest()
            != continuity.active_credential_binding_digest()
        {
            Some(RecoveryCredentialContinuityErrorV1::ActiveCredentialBindingMismatch)
        } else if state.state().registered_public_key() != continuity.registered_public_key() {
            Some(RecoveryCredentialContinuityErrorV1::RegisteredPublicKeyMismatch)
        } else if state.state().stable_scope() != continuity.stable_scope() {
            Some(RecoveryCredentialContinuityErrorV1::StableScopeMismatch)
        } else {
            None
        };
        match reason {
            Some(reason) => Err(RejectedRecoveryCredentialSuspensionV1 {
                reason,
                state: Box::new(state),
            }),
            None => Ok(Self { state, continuity }),
        }
    }

    /// Returns the authenticated registered metadata beneath the suspension.
    pub const fn state(&self) -> &RegisteredLifecyclePreStateV1 {
        self.state.state()
    }

    /// Returns the authenticated active-state version that was suspended.
    pub const fn active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.state.active_state_version()
    }

    /// Returns the exact old-to-replacement continuity binding.
    pub const fn continuity(&self) -> AuthenticatedRecoveryCredentialContinuityEvidenceV1 {
        self.continuity
    }

    pub(crate) const fn store_resolution(&self) -> &AuthenticatedRegisteredStoreResolutionV1 {
        &self.state
    }
}

pub(crate) struct RejectedRecoveryCredentialSuspensionV1 {
    reason: RecoveryCredentialContinuityErrorV1,
    state: Box<AuthenticatedRegisteredStoreResolutionV1>,
}

impl RejectedRecoveryCredentialSuspensionV1 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        RecoveryCredentialContinuityErrorV1,
        AuthenticatedRegisteredStoreResolutionV1,
    ) {
        (self.reason, *self.state)
    }
}

impl fmt::Debug for AuthenticatedRecoveryCredentialSuspensionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRecoveryCredentialSuspensionV1")
            .field("active_state_version", &self.active_state_version())
            .field("credential_state", &"suspended")
            .finish()
    }
}

/// Nonzero digest returned by the production atomic recovery-promotion transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryPromotionTransactionReceiptDigest32V1([u8; 32]);

impl RecoveryPromotionTransactionReceiptDigest32V1 {
    /// Validates one nonzero opaque transaction-receipt digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, RecoveryPromotionErrorV1> {
        let mut index = 0;
        let mut nonzero = 0u8;
        while index < bytes.len() {
            nonzero |= bytes[index];
            index += 1;
        }
        if nonzero == 0 {
            return Err(RecoveryPromotionErrorV1::ZeroTransactionReceiptDigest);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// SHA-256 digest of one complete registered-state projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryPromotionStateDigest32V1([u8; 32]);

impl RecoveryPromotionStateDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Old credential retired by one authenticated recovery promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCredentialTombstoneV1 {
    credential_binding_digest: ActiveCredentialBindingDigest32V1,
    retired_state_version: ActiveStoreStateVersionV1,
    digest: RecoveryCredentialTombstoneDigest32V1,
}

impl RecoveryCredentialTombstoneV1 {
    fn new(
        credential_binding_digest: ActiveCredentialBindingDigest32V1,
        retired_state_version: ActiveStoreStateVersionV1,
    ) -> Result<Self, RecoveryPromotionErrorV1> {
        let mut encoded = Vec::new();
        push_lp32(&mut encoded, RECOVERY_CREDENTIAL_TOMBSTONE_DIGEST_DOMAIN_V1)?;
        push_lp32(&mut encoded, credential_binding_digest.as_bytes())?;
        push_lp32(&mut encoded, &retired_state_version.value().to_be_bytes())?;
        Ok(Self {
            credential_binding_digest,
            retired_state_version,
            digest: RecoveryCredentialTombstoneDigest32V1(Sha256::digest(encoded).into()),
        })
    }

    /// Returns the credential binding that is no longer sign-capable.
    pub const fn credential_binding_digest(&self) -> ActiveCredentialBindingDigest32V1 {
        self.credential_binding_digest
    }

    /// Returns the active-state version retired with the old credential.
    pub const fn retired_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.retired_state_version
    }

    /// Returns the canonical tombstone digest.
    pub const fn digest(&self) -> RecoveryCredentialTombstoneDigest32V1 {
        self.digest
    }
}

/// Digest of one exact old-credential tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryCredentialTombstoneDigest32V1([u8; 32]);

impl RecoveryCredentialTombstoneDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Deterministic store-authority-signed recovery-promotion body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPromotionReceiptBodyV1 {
    authority_key_epoch: u64,
    authority_key_digest: [u8; 32],
    durable_identity: Vec<u8>,
    old_active_state_version: ActiveStoreStateVersionV1,
    next_active_state_version: ActiveStoreStateVersionV1,
    worker_activation_receipt_digest: SigningWorkerActivationReceiptDigest32V1,
    worker_id: String,
    worker_recipient_key_epoch: u64,
    activation_epoch: u64,
    package_set_digest: [u8; 32],
    output_committed_receipt_digest: [u8; 32],
    worker_storage_receipt_digest: [u8; 32],
    old_state_digest: RecoveryPromotionStateDigest32V1,
    next_state_digest: RecoveryPromotionStateDigest32V1,
    old_credential_binding_digest: [u8; 32],
    replacement_credential_binding_digest: [u8; 32],
    same_root_evidence_artifact_digest: [u8; 32],
    tombstone_digest: RecoveryCredentialTombstoneDigest32V1,
    transaction_receipt_digest: RecoveryPromotionTransactionReceiptDigest32V1,
}

impl RecoveryPromotionReceiptBodyV1 {
    /// Encodes the exact bytes signed by the store authority.
    pub fn encode(&self) -> Result<Vec<u8>, RecoveryPromotionErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, RECOVERY_PROMOTION_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, &self.authority_key_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.authority_key_digest)?;
        push_lp32(&mut output, &self.durable_identity)?;
        push_lp32(
            &mut output,
            &self.old_active_state_version.value().to_be_bytes(),
        )?;
        push_lp32(
            &mut output,
            &self.next_active_state_version.value().to_be_bytes(),
        )?;
        push_lp32(
            &mut output,
            self.worker_activation_receipt_digest.as_bytes(),
        )?;
        push_lp32(&mut output, self.worker_id.as_bytes())?;
        push_lp32(&mut output, &self.worker_recipient_key_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.activation_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.package_set_digest)?;
        push_lp32(&mut output, &self.output_committed_receipt_digest)?;
        push_lp32(&mut output, &self.worker_storage_receipt_digest)?;
        push_lp32(&mut output, self.old_state_digest.as_bytes())?;
        push_lp32(&mut output, self.next_state_digest.as_bytes())?;
        push_lp32(&mut output, &self.old_credential_binding_digest)?;
        push_lp32(&mut output, &self.replacement_credential_binding_digest)?;
        push_lp32(&mut output, &self.same_root_evidence_artifact_digest)?;
        push_lp32(&mut output, self.tombstone_digest.as_bytes())?;
        push_lp32(&mut output, self.transaction_receipt_digest.as_bytes())?;
        Ok(output)
    }

    /// Returns the active-state version retired by promotion.
    pub const fn old_active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.old_active_state_version
    }

    /// Returns the promoted active-state version.
    pub const fn next_active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.next_active_state_version
    }

    /// Returns the verified worker receipt bound to promotion.
    pub const fn worker_activation_receipt_digest(
        &self,
    ) -> SigningWorkerActivationReceiptDigest32V1 {
        self.worker_activation_receipt_digest
    }

    /// Returns the old credential binding that must be tombstoned.
    pub const fn old_credential_binding_digest(&self) -> &[u8; 32] {
        &self.old_credential_binding_digest
    }

    /// Returns the distinct replacement credential made active by promotion.
    pub const fn replacement_credential_binding_digest(&self) -> &[u8; 32] {
        &self.replacement_credential_binding_digest
    }

    /// Returns the tombstone committed by the signed body.
    pub const fn tombstone_digest(&self) -> RecoveryCredentialTombstoneDigest32V1 {
        self.tombstone_digest
    }
}

/// Digest of one exact signed recovery-promotion body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryPromotionReceiptDigest32V1([u8; 32]);

impl RecoveryPromotionReceiptDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Recovery activation and promoted state awaiting a store-authority signature.
pub struct PreparedRecoveryPromotionV1 {
    activation: SigningWorkerActivationSuccessV1,
    next_state: RegisteredLifecyclePreStateV1,
    tombstone: RecoveryCredentialTombstoneV1,
    body: RecoveryPromotionReceiptBodyV1,
    authority: StoreAuthorityVerifyingKeyV1,
}

impl PreparedRecoveryPromotionV1 {
    /// Returns the exact bytes the store authority must sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, RecoveryPromotionErrorV1> {
        self.body.encode()
    }

    /// Returns the deterministic public promotion body.
    pub const fn receipt_body(&self) -> &RecoveryPromotionReceiptBodyV1 {
        &self.body
    }

    /// Strictly verifies authority before releasing the promoted credential state.
    pub fn verify(
        self,
        signature: StoreAuthoritySignature64V1,
    ) -> Result<AuthenticatedRecoveryPromotionV1, RejectedRecoveryPromotionReceiptV1> {
        let reason = match self.signing_bytes() {
            Ok(bytes)
                if self
                    .authority
                    .verify_transition_signature(&bytes, signature) =>
            {
                None
            }
            Ok(_) => Some(RecoveryPromotionErrorV1::InvalidAuthoritySignature),
            Err(error) => Some(error),
        };
        if let Some(reason) = reason {
            return Err(RejectedRecoveryPromotionReceiptV1 {
                reason,
                prepared: Box::new(self),
                signature,
            });
        }
        let digest = promotion_receipt_digest(&self.body)
            .expect("validated recovery-promotion fields always fit LP32");
        Ok(AuthenticatedRecoveryPromotionV1 {
            activation: self.activation,
            next_state: self.next_state,
            tombstone: self.tombstone,
            receipt: VerifiedRecoveryPromotionReceiptV1 {
                body: self.body,
                digest,
                signature,
            },
        })
    }
}

impl fmt::Debug for PreparedRecoveryPromotionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRecoveryPromotionV1")
            .field("activation", &"[retained activated secret]")
            .field("body", &self.body)
            .finish()
    }
}

/// Authenticated replacement-credential promotion retaining the activated worker state.
pub struct AuthenticatedRecoveryPromotionV1 {
    activation: SigningWorkerActivationSuccessV1,
    next_state: RegisteredLifecyclePreStateV1,
    tombstone: RecoveryCredentialTombstoneV1,
    receipt: VerifiedRecoveryPromotionReceiptV1,
}

impl AuthenticatedRecoveryPromotionV1 {
    /// Returns the promoted registered-state projection.
    pub const fn next_state(&self) -> &RegisteredLifecyclePreStateV1 {
        &self.next_state
    }

    /// Returns the old-credential tombstone.
    pub const fn tombstone(&self) -> RecoveryCredentialTombstoneV1 {
        self.tombstone
    }

    /// Returns the authenticated recovery-promotion receipt.
    pub const fn receipt(&self) -> &VerifiedRecoveryPromotionReceiptV1 {
        &self.receipt
    }

    /// Returns the still-live verified worker activation.
    pub const fn activation(&self) -> &SigningWorkerActivationSuccessV1 {
        &self.activation
    }
}

impl fmt::Debug for AuthenticatedRecoveryPromotionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRecoveryPromotionV1")
            .field("activation", &"[retained activated secret]")
            .field("next_state", &self.next_state)
            .field("tombstone", &self.tombstone)
            .field("receipt", &self.receipt)
            .finish()
    }
}

/// Strictly verified store-authority recovery-promotion receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecoveryPromotionReceiptV1 {
    body: RecoveryPromotionReceiptBodyV1,
    digest: RecoveryPromotionReceiptDigest32V1,
    signature: StoreAuthoritySignature64V1,
}

impl VerifiedRecoveryPromotionReceiptV1 {
    /// Returns the exact signed body.
    pub const fn body(&self) -> &RecoveryPromotionReceiptBodyV1 {
        &self.body
    }

    /// Returns the promotion-receipt digest.
    pub const fn digest(&self) -> RecoveryPromotionReceiptDigest32V1 {
        self.digest
    }

    /// Returns the verified signature bytes.
    pub const fn signature(&self) -> StoreAuthoritySignature64V1 {
        self.signature
    }
}

/// Failed promotion preparation retaining the verified activation for retry.
pub struct RejectedRecoveryPromotionPreparationV1 {
    reason: RecoveryPromotionErrorV1,
    activation: Box<SigningWorkerActivationSuccessV1>,
}

impl RejectedRecoveryPromotionPreparationV1 {
    /// Returns the precise preparation failure.
    pub const fn reason(&self) -> RecoveryPromotionErrorV1 {
        self.reason
    }

    /// Recovers the unchanged verified activation.
    pub fn into_activation(self) -> SigningWorkerActivationSuccessV1 {
        *self.activation
    }
}

impl fmt::Debug for RejectedRecoveryPromotionPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRecoveryPromotionPreparationV1")
            .field("reason", &self.reason)
            .field("activation", &"[retained activated secret]")
            .finish()
    }
}

/// Failed authority verification retaining the prepared promotion for retry.
pub struct RejectedRecoveryPromotionReceiptV1 {
    reason: RecoveryPromotionErrorV1,
    prepared: Box<PreparedRecoveryPromotionV1>,
    signature: StoreAuthoritySignature64V1,
}

impl RejectedRecoveryPromotionReceiptV1 {
    /// Returns the precise receipt failure.
    pub const fn reason(&self) -> RecoveryPromotionErrorV1 {
        self.reason
    }

    /// Recovers the prepared transition and rejected signature.
    pub fn into_parts(self) -> (PreparedRecoveryPromotionV1, StoreAuthoritySignature64V1) {
        (*self.prepared, self.signature)
    }
}

impl fmt::Debug for RejectedRecoveryPromotionReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRecoveryPromotionReceiptV1")
            .field("reason", &self.reason)
            .field("prepared", &"[retained activated secret]")
            .finish()
    }
}

/// Recovery promotion validation or signature failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPromotionErrorV1 {
    /// The opaque transaction-receipt digest was zero.
    ZeroTransactionReceiptDigest,
    /// The verified activation originated from registration or refresh.
    ActivationOriginMismatch,
    /// The promoted active-state version did not strictly advance.
    ActiveStateVersionDidNotAdvance,
    /// The activated epoch did not strictly advance from the suspended state.
    ActivationEpochDidNotAdvance,
    /// The replacement credential unexpectedly equals the suspended credential.
    ReplacementCredentialDidNotChange,
    /// Strict store-authority signature verification failed.
    InvalidAuthoritySignature,
    /// A canonical identity or LP32 field exceeded the version-one range.
    ValueTooLong,
    /// Durable identity encoding failed.
    DurableIdentityEncoding,
}

impl fmt::Display for RecoveryPromotionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroTransactionReceiptDigest => "recovery transaction receipt digest is zero",
            Self::ActivationOriginMismatch => "only verified recovery activation can be promoted",
            Self::ActiveStateVersionDidNotAdvance => "active state version did not advance",
            Self::ActivationEpochDidNotAdvance => "activation epoch did not advance",
            Self::ReplacementCredentialDidNotChange => {
                "recovery replacement credential equals suspended credential"
            }
            Self::InvalidAuthoritySignature => "recovery promotion signature is invalid",
            Self::ValueTooLong => "recovery promotion LP32 value exceeds U32 length",
            Self::DurableIdentityEncoding => "durable identity encoding failed",
        })
    }
}

impl std::error::Error for RecoveryPromotionErrorV1 {}

/// Builds promotion only after a verified recovery-origin worker activation exists.
pub(crate) fn prepare_authenticated_recovery_promotion_v1(
    activation: SigningWorkerActivationSuccessV1,
    next_active_state_version: ActiveStoreStateVersionV1,
    transaction_receipt_digest: RecoveryPromotionTransactionReceiptDigest32V1,
) -> Result<PreparedRecoveryPromotionV1, RejectedRecoveryPromotionPreparationV1> {
    let Some(terminal) = activation.state().recovery_terminal_evaluation() else {
        return Err(RejectedRecoveryPromotionPreparationV1 {
            reason: RecoveryPromotionErrorV1::ActivationOriginMismatch,
            activation: Box::new(activation),
        });
    };
    let suspension = terminal.suspension();
    let old_active_state_version = suspension.active_state_version();
    if next_active_state_version.value() <= old_active_state_version.value() {
        return Err(RejectedRecoveryPromotionPreparationV1 {
            reason: RecoveryPromotionErrorV1::ActiveStateVersionDidNotAdvance,
            activation: Box::new(activation),
        });
    }
    let old_state = suspension.state();
    let authority = suspension.store_resolution().trusted_transition_authority();
    if activation.state().activation_epoch().value() <= old_state.active_activation_epoch.value() {
        return Err(RejectedRecoveryPromotionPreparationV1 {
            reason: RecoveryPromotionErrorV1::ActivationEpochDidNotAdvance,
            activation: Box::new(activation),
        });
    }
    let continuity = suspension.continuity();
    let replacement = ActiveCredentialBindingDigest32V1::new(
        *continuity
            .replacement_credential_binding_digest()
            .as_bytes(),
    )
    .expect("recovery replacement credential binding is nonzero");
    if replacement == old_state.active_credential_binding_digest() {
        return Err(RejectedRecoveryPromotionPreparationV1 {
            reason: RecoveryPromotionErrorV1::ReplacementCredentialDidNotChange,
            activation: Box::new(activation),
        });
    }

    let next_state = RegisteredLifecyclePreStateV1 {
        registered_public_key: old_state.registered_public_key,
        active_credential_binding_digest: replacement,
        stable_scope: old_state.stable_scope,
        active_activation_epoch: activation.state().activation_epoch(),
        deriver_a_root_record: old_state.deriver_a_root_record,
        deriver_a_root_binding: old_state.deriver_a_root_binding,
        deriver_a_root_epoch: old_state.deriver_a_root_epoch,
        deriver_a_state_record: old_state.deriver_a_state_record,
        deriver_a_input_state_epoch: old_state.deriver_a_input_state_epoch,
        deriver_b_root_record: old_state.deriver_b_root_record,
        deriver_b_root_binding: old_state.deriver_b_root_binding,
        deriver_b_root_epoch: old_state.deriver_b_root_epoch,
        deriver_b_state_record: old_state.deriver_b_state_record,
        deriver_b_input_state_epoch: old_state.deriver_b_input_state_epoch,
    };
    let tombstone = match RecoveryCredentialTombstoneV1::new(
        old_state.active_credential_binding_digest,
        old_active_state_version,
    ) {
        Ok(value) => value,
        Err(reason) => {
            return Err(RejectedRecoveryPromotionPreparationV1 {
                reason,
                activation: Box::new(activation),
            })
        }
    };
    let durable_identity = match suspension.store_resolution().durable_identity().encode() {
        Ok(value) => value,
        Err(_) => {
            return Err(RejectedRecoveryPromotionPreparationV1 {
                reason: RecoveryPromotionErrorV1::DurableIdentityEncoding,
                activation: Box::new(activation),
            })
        }
    };
    let old_state_digest = match promotion_state_digest(old_state) {
        Ok(value) => value,
        Err(reason) => {
            return Err(RejectedRecoveryPromotionPreparationV1 {
                reason,
                activation: Box::new(activation),
            })
        }
    };
    let next_state_digest = match promotion_state_digest(&next_state) {
        Ok(value) => value,
        Err(reason) => {
            return Err(RejectedRecoveryPromotionPreparationV1 {
                reason,
                activation: Box::new(activation),
            })
        }
    };
    let body = RecoveryPromotionReceiptBodyV1 {
        authority_key_epoch: authority.key_epoch().value(),
        authority_key_digest: authority.key_digest(),
        durable_identity,
        old_active_state_version,
        next_active_state_version,
        worker_activation_receipt_digest: activation.receipt().digest(),
        worker_id: activation.state().worker().id().as_str().to_owned(),
        worker_recipient_key_epoch: activation.state().worker().key_epoch().value(),
        activation_epoch: activation.state().activation_epoch().value(),
        package_set_digest: *activation.state().package_set_digest().as_bytes(),
        output_committed_receipt_digest: *activation
            .state()
            .output_committed_receipt_digest()
            .as_bytes(),
        worker_storage_receipt_digest: *activation.state().storage_receipt_digest().as_bytes(),
        old_state_digest,
        next_state_digest,
        old_credential_binding_digest: *continuity.active_credential_binding_digest().as_bytes(),
        replacement_credential_binding_digest: *continuity
            .replacement_credential_binding_digest()
            .as_bytes(),
        same_root_evidence_artifact_digest: *continuity
            .same_root_evidence_artifact_digest()
            .as_bytes(),
        tombstone_digest: tombstone.digest(),
        transaction_receipt_digest,
    };
    Ok(PreparedRecoveryPromotionV1 {
        activation,
        next_state,
        tombstone,
        body,
        authority,
    })
}

fn promotion_state_digest(
    state: &RegisteredLifecyclePreStateV1,
) -> Result<RecoveryPromotionStateDigest32V1, RecoveryPromotionErrorV1> {
    let mut output = Vec::new();
    push_lp32(&mut output, RECOVERY_PROMOTION_STATE_DIGEST_DOMAIN_V1)?;
    push_lp32(&mut output, state.registered_public_key.as_bytes())?;
    push_lp32(
        &mut output,
        state.active_credential_binding_digest.as_bytes(),
    )?;
    push_lp32(
        &mut output,
        &state
            .stable_scope
            .encode()
            .map_err(|_| RecoveryPromotionErrorV1::ValueTooLong)?,
    )?;
    push_lp32(
        &mut output,
        &state.active_activation_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_a_root_record.as_bytes())?;
    push_lp32(&mut output, state.deriver_a_root_binding.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_a_root_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_a_state_record.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_a_input_state_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_b_root_record.as_bytes())?;
    push_lp32(&mut output, state.deriver_b_root_binding.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_b_root_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_b_state_record.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_b_input_state_epoch.value().to_be_bytes(),
    )?;
    Ok(RecoveryPromotionStateDigest32V1(
        Sha256::digest(output).into(),
    ))
}

fn promotion_receipt_digest(
    body: &RecoveryPromotionReceiptBodyV1,
) -> Result<RecoveryPromotionReceiptDigest32V1, RecoveryPromotionErrorV1> {
    let mut output = Vec::new();
    push_lp32(&mut output, RECOVERY_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1)?;
    push_lp32(&mut output, &body.encode()?)?;
    Ok(RecoveryPromotionReceiptDigest32V1(
        Sha256::digest(output).into(),
    ))
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RecoveryPromotionErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| RecoveryPromotionErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::activation_recipient_party_view_fixtures::canonical_activated_recipient_fixture_v1;
    use crate::authenticated_store::StoreAuthorityKeyEpochV1;
    use crate::lifecycle_domain::ActivationPackageOriginV1;
    use crate::signing_worker_activation::tests::{
        verified_recovery_activation, verified_refresh_activation,
    };

    fn authority(seed: u8, epoch: u64) -> (SigningKey, StoreAuthorityVerifyingKeyV1) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let authority = StoreAuthorityVerifyingKeyV1::parse(
            StoreAuthorityKeyEpochV1::new(epoch).expect("authority epoch"),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("authority");
        (signing_key, authority)
    }

    fn prepared() -> (SigningKey, PreparedRecoveryPromotionV1) {
        let activation = verified_recovery_activation();
        let old_version = activation
            .state()
            .recovery_terminal_evaluation()
            .expect("recovery terminal admission")
            .suspension()
            .active_state_version()
            .value();
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        let prepared = prepare_authenticated_recovery_promotion_v1(
            activation,
            ActiveStoreStateVersionV1::new(old_version + 1).expect("next state version"),
            RecoveryPromotionTransactionReceiptDigest32V1::new([0xec; 32])
                .expect("transaction receipt"),
        )
        .expect("prepared promotion");
        (signing_key, prepared)
    }

    #[test]
    fn verified_recovery_promotion_preserves_identity_and_retires_only_old_credential() {
        let (signing_key, prepared) = prepared();
        let signature = StoreAuthoritySignature64V1::from_bytes(
            signing_key
                .sign(&prepared.signing_bytes().expect("promotion bytes"))
                .to_bytes(),
        );
        let promoted = prepared.verify(signature).expect("promotion");
        let old = promoted
            .activation()
            .state()
            .recovery_terminal_evaluation()
            .expect("recovery terminal admission")
            .suspension()
            .state();
        let next = promoted.next_state();

        assert_eq!(next.registered_public_key, old.registered_public_key);
        assert_eq!(next.stable_scope, old.stable_scope);
        assert_eq!(next.deriver_a_root_record, old.deriver_a_root_record);
        assert_eq!(next.deriver_a_root_binding, old.deriver_a_root_binding);
        assert_eq!(next.deriver_a_root_epoch, old.deriver_a_root_epoch);
        assert_eq!(next.deriver_a_state_record, old.deriver_a_state_record);
        assert_eq!(
            next.deriver_a_input_state_epoch,
            old.deriver_a_input_state_epoch
        );
        assert_eq!(next.deriver_b_root_record, old.deriver_b_root_record);
        assert_eq!(next.deriver_b_root_binding, old.deriver_b_root_binding);
        assert_eq!(next.deriver_b_root_epoch, old.deriver_b_root_epoch);
        assert_eq!(next.deriver_b_state_record, old.deriver_b_state_record);
        assert_eq!(
            next.deriver_b_input_state_epoch,
            old.deriver_b_input_state_epoch
        );
        assert_ne!(
            next.active_credential_binding_digest,
            old.active_credential_binding_digest
        );
        assert_eq!(
            promoted.tombstone().credential_binding_digest(),
            old.active_credential_binding_digest
        );
        assert_eq!(
            next.active_activation_epoch,
            promoted.activation().state().activation_epoch()
        );
        assert_eq!(
            promoted.receipt().body().worker_activation_receipt_digest(),
            promoted.activation().receipt().digest()
        );
    }

    #[test]
    fn non_recovery_activations_cannot_prepare_credential_promotion() {
        let registration =
            canonical_activated_recipient_fixture_v1(ActivationPackageOriginV1::Registration)
                .into_recipient_states()
                .1;
        for activation in [registration, verified_refresh_activation()] {
            let origin = activation.state().origin();
            let rejection = prepare_authenticated_recovery_promotion_v1(
                activation,
                ActiveStoreStateVersionV1::new(99).expect("state version"),
                RecoveryPromotionTransactionReceiptDigest32V1::new([0xec; 32])
                    .expect("transaction receipt"),
            )
            .expect_err("non-recovery activation entered recovery promotion");
            assert_eq!(
                rejection.reason(),
                RecoveryPromotionErrorV1::ActivationOriginMismatch
            );
            assert_eq!(rejection.into_activation().state().origin(), origin);
        }
    }

    #[test]
    fn stale_state_version_rejection_retains_verified_recovery_activation() {
        let activation = verified_recovery_activation();
        let old_version = activation
            .state()
            .recovery_terminal_evaluation()
            .expect("recovery terminal admission")
            .suspension()
            .active_state_version();
        let rejection = prepare_authenticated_recovery_promotion_v1(
            activation,
            old_version,
            RecoveryPromotionTransactionReceiptDigest32V1::new([0xec; 32])
                .expect("transaction receipt"),
        )
        .expect_err("stale state version was accepted");
        assert_eq!(
            rejection.reason(),
            RecoveryPromotionErrorV1::ActiveStateVersionDidNotAdvance
        );
        assert_eq!(
            rejection.into_activation().state().origin(),
            ActivationPackageOriginV1::Recovery
        );
    }

    #[test]
    fn invalid_signature_retains_prepared_promotion_for_retry() {
        let (_, prepared) = prepared();
        let rejection = prepared
            .verify(StoreAuthoritySignature64V1::from_bytes([0x55; 64]))
            .expect_err("invalid signature was accepted");
        assert_eq!(
            rejection.reason(),
            RecoveryPromotionErrorV1::InvalidAuthoritySignature
        );
        let (prepared, _) = rejection.into_parts();
        assert_eq!(
            prepared.activation.state().origin(),
            ActivationPackageOriginV1::Recovery
        );
        assert!(!prepared.signing_bytes().expect("retained bytes").is_empty());
    }

    #[test]
    fn authority_substitution_fails_closed() {
        let (_, prepared) = prepared();
        let (attacker_key, _) = authority(0xed, 1);
        let signature = StoreAuthoritySignature64V1::from_bytes(
            attacker_key
                .sign(&prepared.signing_bytes().expect("promotion bytes"))
                .to_bytes(),
        );
        let rejection = prepared
            .verify(signature)
            .expect_err("coherent attacker authority was accepted");
        assert_eq!(
            rejection.reason(),
            RecoveryPromotionErrorV1::InvalidAuthoritySignature
        );
    }

    #[test]
    fn promotion_bytes_and_tombstone_are_deterministic() {
        let (_, first) = prepared();
        let (_, second) = prepared();
        assert_eq!(
            first.signing_bytes().expect("first bytes"),
            second.signing_bytes().expect("second bytes")
        );
        assert_eq!(first.tombstone, second.tombstone);
        assert_eq!(
            first.receipt_body().old_credential_binding_digest(),
            first.tombstone.credential_binding_digest().as_bytes()
        );
        assert_eq!(
            first.receipt_body().tombstone_digest(),
            first.tombstone.digest()
        );
    }

    #[test]
    fn transaction_receipt_digest_must_be_nonzero() {
        assert_eq!(
            RecoveryPromotionTransactionReceiptDigest32V1::new([0; 32]),
            Err(RecoveryPromotionErrorV1::ZeroTransactionReceiptDigest)
        );
    }
}
