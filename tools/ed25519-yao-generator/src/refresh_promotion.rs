//! Authenticated host semantics for refresh promotion after worker activation.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::authenticated_store::{
    ActiveStoreStateVersionV1, StoreAuthoritySignature64V1, StoreAuthorityVerifyingKeyV1,
};
use crate::lifecycle_domain::RegisteredLifecyclePreStateV1;
use crate::signing_worker_activation::{
    SigningWorkerActivationReceiptDigest32V1, SigningWorkerActivationSuccessV1,
};

/// Canonical signed refresh-promotion domain.
pub const REFRESH_PROMOTION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/refresh-promotion/v1";
/// Domain for the authenticated promotion-receipt digest.
pub const REFRESH_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/refresh-promotion-receipt-digest/v1";
/// Domain for a complete registered-state promotion projection.
pub const REFRESH_PROMOTION_STATE_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/refresh-promotion-state-digest/v1";

/// Nonzero digest returned by the durable atomic storage transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefreshPromotionTransactionReceiptDigest32V1([u8; 32]);

impl RefreshPromotionTransactionReceiptDigest32V1 {
    /// Validates one nonzero transaction-receipt digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, RefreshPromotionErrorV1> {
        let mut index = 0;
        let mut nonzero = 0u8;
        while index < bytes.len() {
            nonzero |= bytes[index];
            index += 1;
        }
        if nonzero == 0 {
            return Err(RefreshPromotionErrorV1::ZeroTransactionReceiptDigest);
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
pub struct RefreshPromotionStateDigest32V1([u8; 32]);

impl RefreshPromotionStateDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Deterministic store-authority-signed refresh promotion body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshPromotionReceiptBodyV1 {
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
    old_state_digest: RefreshPromotionStateDigest32V1,
    next_state_digest: RefreshPromotionStateDigest32V1,
    old_deriver_a_state_epoch: u64,
    next_deriver_a_state_epoch: u64,
    old_deriver_b_state_epoch: u64,
    next_deriver_b_state_epoch: u64,
    transaction_receipt_digest: RefreshPromotionTransactionReceiptDigest32V1,
}

impl RefreshPromotionReceiptBodyV1 {
    /// Encodes the exact bytes signed by the store authority.
    pub fn encode(&self) -> Result<Vec<u8>, RefreshPromotionErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, REFRESH_PROMOTION_ENCODING_DOMAIN_V1)?;
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
        push_lp32(&mut output, &self.old_deriver_a_state_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.next_deriver_a_state_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.old_deriver_b_state_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.next_deriver_b_state_epoch.to_be_bytes())?;
        push_lp32(&mut output, self.transaction_receipt_digest.as_bytes())?;
        Ok(output)
    }

    /// Returns the previous active state version.
    pub const fn old_active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.old_active_state_version
    }

    /// Returns the promoted active state version.
    pub const fn next_active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.next_active_state_version
    }

    /// Returns the verified worker-activation receipt bound into promotion.
    pub const fn worker_activation_receipt_digest(
        &self,
    ) -> SigningWorkerActivationReceiptDigest32V1 {
        self.worker_activation_receipt_digest
    }
}

/// Digest of one exact signed refresh-promotion body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefreshPromotionReceiptDigest32V1([u8; 32]);

impl RefreshPromotionReceiptDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Refresh activation and next state awaiting a store-authority signature.
pub struct PreparedRefreshPromotionV1 {
    activation: SigningWorkerActivationSuccessV1,
    next_state: RegisteredLifecyclePreStateV1,
    body: RefreshPromotionReceiptBodyV1,
    authority: StoreAuthorityVerifyingKeyV1,
}

impl PreparedRefreshPromotionV1 {
    /// Returns the exact bytes the store authority must sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, RefreshPromotionErrorV1> {
        self.body.encode()
    }

    /// Returns the deterministic public promotion body.
    pub const fn receipt_body(&self) -> &RefreshPromotionReceiptBodyV1 {
        &self.body
    }

    /// Strictly verifies the authority signature and releases promoted state.
    pub fn verify(
        self,
        signature: StoreAuthoritySignature64V1,
    ) -> Result<AuthenticatedRefreshPromotionV1, RejectedRefreshPromotionReceiptV1> {
        let reason = match self.signing_bytes() {
            Ok(bytes)
                if self
                    .authority
                    .verify_transition_signature(&bytes, signature) =>
            {
                None
            }
            Ok(_) => Some(RefreshPromotionErrorV1::InvalidAuthoritySignature),
            Err(error) => Some(error),
        };
        if let Some(reason) = reason {
            return Err(RejectedRefreshPromotionReceiptV1 {
                reason,
                prepared: Box::new(self),
                signature,
            });
        }
        let digest = promotion_receipt_digest(&self.body)
            .expect("validated promotion receipt fields always fit LP32");
        Ok(AuthenticatedRefreshPromotionV1 {
            activation: self.activation,
            next_state: self.next_state,
            receipt: VerifiedRefreshPromotionReceiptV1 {
                body: self.body,
                digest,
                signature,
            },
        })
    }
}

impl fmt::Debug for PreparedRefreshPromotionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRefreshPromotionV1")
            .field("activation", &"[retained activated secret]")
            .field("body", &self.body)
            .finish()
    }
}

/// Authenticated refresh promotion retaining the activated SigningWorker secret.
pub struct AuthenticatedRefreshPromotionV1 {
    activation: SigningWorkerActivationSuccessV1,
    next_state: RegisteredLifecyclePreStateV1,
    receipt: VerifiedRefreshPromotionReceiptV1,
}

impl AuthenticatedRefreshPromotionV1 {
    /// Returns the promoted registered-state projection.
    pub const fn next_state(&self) -> &RegisteredLifecyclePreStateV1 {
        &self.next_state
    }

    /// Returns the authenticated promotion receipt.
    pub const fn receipt(&self) -> &VerifiedRefreshPromotionReceiptV1 {
        &self.receipt
    }

    /// Returns the still-live verified worker activation.
    pub const fn activation(&self) -> &SigningWorkerActivationSuccessV1 {
        &self.activation
    }
}

impl fmt::Debug for AuthenticatedRefreshPromotionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRefreshPromotionV1")
            .field("activation", &"[retained activated secret]")
            .field("next_state", &self.next_state)
            .field("receipt", &self.receipt)
            .finish()
    }
}

/// Strictly verified store-authority refresh-promotion receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRefreshPromotionReceiptV1 {
    body: RefreshPromotionReceiptBodyV1,
    digest: RefreshPromotionReceiptDigest32V1,
    signature: StoreAuthoritySignature64V1,
}

impl VerifiedRefreshPromotionReceiptV1 {
    /// Returns the exact signed body.
    pub const fn body(&self) -> &RefreshPromotionReceiptBodyV1 {
        &self.body
    }

    /// Returns the promotion-receipt digest.
    pub const fn digest(&self) -> RefreshPromotionReceiptDigest32V1 {
        self.digest
    }

    /// Returns the verified signature bytes.
    pub const fn signature(&self) -> StoreAuthoritySignature64V1 {
        self.signature
    }
}

/// Failed preparation retaining the verified activation for retry.
pub struct RejectedRefreshPromotionPreparationV1 {
    reason: RefreshPromotionErrorV1,
    activation: Box<SigningWorkerActivationSuccessV1>,
}

impl RejectedRefreshPromotionPreparationV1 {
    /// Returns the precise preparation failure.
    pub const fn reason(&self) -> RefreshPromotionErrorV1 {
        self.reason
    }

    /// Recovers the unchanged verified activation.
    pub fn into_activation(self) -> SigningWorkerActivationSuccessV1 {
        *self.activation
    }
}

impl fmt::Debug for RejectedRefreshPromotionPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRefreshPromotionPreparationV1")
            .field("reason", &self.reason)
            .field("activation", &"[retained activated secret]")
            .finish()
    }
}

/// Failed authority verification retaining the prepared promotion for retry.
pub struct RejectedRefreshPromotionReceiptV1 {
    reason: RefreshPromotionErrorV1,
    prepared: Box<PreparedRefreshPromotionV1>,
    signature: StoreAuthoritySignature64V1,
}

impl RejectedRefreshPromotionReceiptV1 {
    /// Returns the precise receipt failure.
    pub const fn reason(&self) -> RefreshPromotionErrorV1 {
        self.reason
    }

    /// Recovers the prepared transition and rejected signature.
    pub fn into_parts(self) -> (PreparedRefreshPromotionV1, StoreAuthoritySignature64V1) {
        (*self.prepared, self.signature)
    }
}

impl fmt::Debug for RejectedRefreshPromotionReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRefreshPromotionReceiptV1")
            .field("reason", &self.reason)
            .field("prepared", &"[retained activated secret]")
            .finish()
    }
}

/// Refresh-promotion validation or signature failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPromotionErrorV1 {
    /// The transaction-receipt digest was zero.
    ZeroTransactionReceiptDigest,
    /// The activated origin was registration or recovery.
    ActivationOriginMismatch,
    /// The promoted active-state version did not strictly advance.
    ActiveStateVersionDidNotAdvance,
    /// The activated epoch did not strictly advance from the signed old state.
    ActivationEpochDidNotAdvance,
    /// Strict store-authority signature verification failed.
    InvalidAuthoritySignature,
    /// A canonical identity or LP32 field exceeded the version-one range.
    ValueTooLong,
    /// Durable identity encoding failed.
    DurableIdentityEncoding,
}

impl fmt::Display for RefreshPromotionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroTransactionReceiptDigest => "refresh transaction receipt digest is zero",
            Self::ActivationOriginMismatch => "only verified refresh activation can be promoted",
            Self::ActiveStateVersionDidNotAdvance => "active state version did not advance",
            Self::ActivationEpochDidNotAdvance => "activation epoch did not advance",
            Self::InvalidAuthoritySignature => "refresh promotion signature is invalid",
            Self::ValueTooLong => "refresh promotion LP32 value exceeds U32 length",
            Self::DurableIdentityEncoding => "durable identity encoding failed",
        })
    }
}

impl std::error::Error for RefreshPromotionErrorV1 {}

/// Builds a promotion only after a verified refresh activation exists.
pub(crate) fn prepare_authenticated_refresh_promotion_v1(
    activation: SigningWorkerActivationSuccessV1,
    next_active_state_version: ActiveStoreStateVersionV1,
    transaction_receipt_digest: RefreshPromotionTransactionReceiptDigest32V1,
) -> Result<PreparedRefreshPromotionV1, RejectedRefreshPromotionPreparationV1> {
    let Some(terminal) = activation.state().refresh_terminal_evaluation()
    else {
        return Err(RejectedRefreshPromotionPreparationV1 {
            reason: RefreshPromotionErrorV1::ActivationOriginMismatch,
            activation: Box::new(activation),
        });
    };
    let old_resolution = terminal.state();
    let next_a = terminal.proposed_next_deriver_a();
    let next_b = terminal.proposed_next_deriver_b();
    let old_active_state_version = old_resolution.active_state_version();
    let authority = old_resolution.trusted_transition_authority();
    if next_active_state_version.value() <= old_active_state_version.value() {
        return Err(RejectedRefreshPromotionPreparationV1 {
            reason: RefreshPromotionErrorV1::ActiveStateVersionDidNotAdvance,
            activation: Box::new(activation),
        });
    }
    let old_state = old_resolution.state();
    if activation.state().activation_epoch().value() <= old_state.active_activation_epoch.value() {
        return Err(RejectedRefreshPromotionPreparationV1 {
            reason: RefreshPromotionErrorV1::ActivationEpochDidNotAdvance,
            activation: Box::new(activation),
        });
    }

    let next_state = RegisteredLifecyclePreStateV1 {
        registered_public_key: old_state.registered_public_key,
        active_credential_binding_digest: old_state.active_credential_binding_digest,
        stable_scope: old_state.stable_scope,
        active_activation_epoch: activation.state().activation_epoch(),
        deriver_a_root_record: next_a.role_root_record_digest(),
        deriver_a_root_binding: next_a.root_binding_artifact_digest(),
        deriver_a_root_epoch: next_a.role_root_epoch(),
        deriver_a_state_record: next_a.record_digest(),
        deriver_a_input_state_epoch: next_a.epoch(),
        deriver_b_root_record: next_b.role_root_record_digest(),
        deriver_b_root_binding: next_b.root_binding_artifact_digest(),
        deriver_b_root_epoch: next_b.role_root_epoch(),
        deriver_b_state_record: next_b.record_digest(),
        deriver_b_input_state_epoch: next_b.epoch(),
    };
    let durable_identity = match old_resolution.durable_identity().encode() {
        Ok(value) => value,
        Err(_) => {
            return Err(RejectedRefreshPromotionPreparationV1 {
                reason: RefreshPromotionErrorV1::DurableIdentityEncoding,
                activation: Box::new(activation),
            })
        }
    };
    let old_state_digest = match promotion_state_digest(old_state) {
        Ok(value) => value,
        Err(reason) => {
            return Err(RejectedRefreshPromotionPreparationV1 {
                reason,
                activation: Box::new(activation),
            })
        }
    };
    let next_state_digest = match promotion_state_digest(&next_state) {
        Ok(value) => value,
        Err(reason) => {
            return Err(RejectedRefreshPromotionPreparationV1 {
                reason,
                activation: Box::new(activation),
            })
        }
    };
    let body = RefreshPromotionReceiptBodyV1 {
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
        old_deriver_a_state_epoch: old_state.deriver_a_input_state_epoch.value(),
        next_deriver_a_state_epoch: next_state.deriver_a_input_state_epoch.value(),
        old_deriver_b_state_epoch: old_state.deriver_b_input_state_epoch.value(),
        next_deriver_b_state_epoch: next_state.deriver_b_input_state_epoch.value(),
        transaction_receipt_digest,
    };
    Ok(PreparedRefreshPromotionV1 {
        activation,
        next_state,
        body,
        authority,
    })
}

fn promotion_state_digest(
    state: &RegisteredLifecyclePreStateV1,
) -> Result<RefreshPromotionStateDigest32V1, RefreshPromotionErrorV1> {
    let mut output = Vec::new();
    push_lp32(&mut output, REFRESH_PROMOTION_STATE_DIGEST_DOMAIN_V1)?;
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
            .map_err(|_| RefreshPromotionErrorV1::ValueTooLong)?,
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
    Ok(RefreshPromotionStateDigest32V1(
        Sha256::digest(output).into(),
    ))
}

fn promotion_receipt_digest(
    body: &RefreshPromotionReceiptBodyV1,
) -> Result<RefreshPromotionReceiptDigest32V1, RefreshPromotionErrorV1> {
    let mut output = Vec::new();
    push_lp32(&mut output, REFRESH_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1)?;
    push_lp32(&mut output, &body.encode()?)?;
    Ok(RefreshPromotionReceiptDigest32V1(
        Sha256::digest(output).into(),
    ))
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RefreshPromotionErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| RefreshPromotionErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::authenticated_store::StoreAuthorityKeyEpochV1;
    use crate::signing_worker_activation::tests::verified_refresh_activation;

    fn authority(seed: u8, epoch: u64) -> (SigningKey, StoreAuthorityVerifyingKeyV1) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let authority = StoreAuthorityVerifyingKeyV1::parse(
            StoreAuthorityKeyEpochV1::new(epoch).expect("authority epoch"),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("authority");
        (signing_key, authority)
    }

    fn prepared() -> (SigningKey, PreparedRefreshPromotionV1) {
        let activation = verified_refresh_activation();
        let old_version = activation
            .state()
            .refresh_terminal_evaluation()
            .expect("refresh terminal")
            .state()
            .active_state_version()
            .value();
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        let prepared = prepare_authenticated_refresh_promotion_v1(
            activation,
            ActiveStoreStateVersionV1::new(old_version + 1).expect("next state version"),
            RefreshPromotionTransactionReceiptDigest32V1::new([0xe2; 32])
                .expect("transaction receipt"),
        )
        .expect("prepared promotion");
        (signing_key, prepared)
    }

    #[test]
    fn verified_promotion_advances_exact_state_and_retains_worker_activation() {
        let (signing_key, prepared) = prepared();
        let signature = StoreAuthoritySignature64V1::from_bytes(
            signing_key
                .sign(&prepared.signing_bytes().expect("promotion bytes"))
                .to_bytes(),
        );
        let promoted = prepared.verify(signature).expect("promotion");
        assert!(
            promoted
                .receipt()
                .body()
                .next_active_state_version()
                .value()
                > promoted.receipt().body().old_active_state_version().value()
        );
        assert_eq!(
            promoted.next_state().active_activation_epoch(),
            promoted.activation().state().activation_epoch()
        );
        assert_eq!(
            promoted.receipt().body().worker_activation_receipt_digest(),
            promoted.activation().receipt().digest()
        );
        assert!(format!("{promoted:?}").contains("retained activated secret"));
    }

    #[test]
    fn stale_state_version_rejection_retains_verified_activation() {
        let activation = verified_refresh_activation();
        let old_version = activation
            .state()
            .refresh_terminal_evaluation()
            .expect("refresh terminal")
            .state()
            .active_state_version();
        let rejection = prepare_authenticated_refresh_promotion_v1(
            activation,
            old_version,
            RefreshPromotionTransactionReceiptDigest32V1::new([0xe2; 32])
                .expect("transaction receipt"),
        )
        .expect_err("stale state version was accepted");
        assert_eq!(
            rejection.reason(),
            RefreshPromotionErrorV1::ActiveStateVersionDidNotAdvance
        );
        assert_eq!(
            rejection.into_activation().state().origin(),
            crate::lifecycle_domain::ActivationPackageOriginV1::Refresh
        );
    }

    #[test]
    fn invalid_signature_retains_prepared_transition_for_retry() {
        let (_, prepared) = prepared();
        let rejection = prepared
            .verify(StoreAuthoritySignature64V1::from_bytes([0x55; 64]))
            .expect_err("invalid signature was accepted");
        assert_eq!(
            rejection.reason(),
            RefreshPromotionErrorV1::InvalidAuthoritySignature
        );
        let (prepared, _) = rejection.into_parts();
        assert!(!prepared.signing_bytes().expect("retained bytes").is_empty());
    }

    #[test]
    fn authority_substitution_fails_closed() {
        let (_, prepared) = prepared();
        let (attacker_key, _) = authority(0xe3, 1);
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
            RefreshPromotionErrorV1::InvalidAuthoritySignature
        );
    }

    #[test]
    fn promotion_bytes_are_deterministic_for_the_same_transition() {
        let (_, first) = prepared();
        let (_, second) = prepared();
        assert_eq!(
            first.signing_bytes().expect("first bytes"),
            second.signing_bytes().expect("second bytes")
        );
    }

    #[test]
    fn transaction_receipt_digest_must_be_nonzero() {
        assert_eq!(
            RefreshPromotionTransactionReceiptDigest32V1::new([0; 32]),
            Err(RefreshPromotionErrorV1::ZeroTransactionReceiptDigest)
        );
    }
}
