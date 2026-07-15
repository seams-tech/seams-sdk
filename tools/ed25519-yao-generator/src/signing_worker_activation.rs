//! Profile-neutral SigningWorker activation after authenticated package opening.
//!
//! A selected security profile must decrypt and authenticate each recipient
//! package before it can construct the sealed opened-share inputs accepted here.
//! This module independently rechecks their semantic descriptors, combines only
//! the A/B SigningWorker shares, retains the activated scalar, and requires a
//! strict SigningWorker receipt signature before exposing activation success.

use core::{fmt, marker::PhantomData, num::NonZeroU64};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::activation_delivery::{
    HostOnlyActivationReleaseIdentityV1, HostOnlySigningWorkerActivationReleaseAuthorityV1,
};
use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyPublicRequestContextDigest32V1,
    CeremonySigningWorkerBindingV1,
};
use crate::lifecycle_domain::{
    ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1,
    MetadataConsumedActivationStateV1, RecoveryRequestV1, RefreshRequestV1, RegistrationRequestV1,
};
use crate::provenance::{DeriverAProvenanceRoleV1, DeriverBProvenanceRoleV1};
use crate::registration_evaluation_admission::RegistrationCandidateStateV1;
use crate::semantic_artifacts::{
    ActivationArtifactBindingV1, ActivationOutputCommittedReceiptDigest32V1,
    CommittedActivationArtifactsV1, DeriverASigningWorkerScalarActivationPackageDescriptorV1,
    DeriverBSigningWorkerScalarActivationPackageDescriptorV1,
    OpaqueHostReferencePackageAuthenticationDigest32V1, SigningWorkerRecipientKeyBindingDigest32V1,
    SIGNING_WORKER_RECIPIENT_TAG_V1, SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1,
};
use crate::RegisteredEd25519PublicKey32V1;

/// Canonical signed SigningWorker activation-receipt domain.
pub const SIGNING_WORKER_ACTIVATION_RECEIPT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/signing-worker-activation-receipt/v1";
/// Domain for the activation-receipt digest.
pub const SIGNING_WORKER_ACTIVATION_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/signing-worker-activation-receipt-digest/v1";
/// Domain for the receipt-authority verifying-key digest.
pub const SIGNING_WORKER_RECEIPT_KEY_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/signing-worker-receipt-key-digest/v1";

const REGISTRATION_ORIGIN_TAG_V1: u8 = 0x01;
const RECOVERY_ORIGIN_TAG_V1: u8 = 0x02;
const REFRESH_ORIGIN_TAG_V1: u8 = 0x03;

/// Nonzero epoch for the SigningWorker receipt-signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SigningWorkerReceiptKeyEpochV1(NonZeroU64);

impl SigningWorkerReceiptKeyEpochV1 {
    /// Validates a nonzero receipt-signing-key epoch.
    pub const fn new(value: u64) -> Result<Self, SigningWorkerActivationErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(SigningWorkerActivationErrorV1::ZeroReceiptKeyEpoch),
        }
    }

    /// Returns the numeric epoch.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

/// Validated non-weak key used to verify SigningWorker activation receipts.
#[derive(Clone)]
pub struct SigningWorkerReceiptVerifyingKeyV1 {
    worker: CeremonySigningWorkerBindingV1,
    key_epoch: SigningWorkerReceiptKeyEpochV1,
    verifying_key: VerifyingKey,
    key_digest: [u8; 32],
}

impl SigningWorkerReceiptVerifyingKeyV1 {
    /// Parses an Ed25519 receipt key and rejects weak Edwards points.
    pub fn parse(
        worker: CeremonySigningWorkerBindingV1,
        key_epoch: SigningWorkerReceiptKeyEpochV1,
        bytes: [u8; 32],
    ) -> Result<Self, SigningWorkerActivationErrorV1> {
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| SigningWorkerActivationErrorV1::InvalidReceiptVerifyingKey)?;
        if verifying_key.is_weak() {
            return Err(SigningWorkerActivationErrorV1::WeakReceiptVerifyingKey);
        }
        let mut encoded = Vec::new();
        push_lp32(&mut encoded, SIGNING_WORKER_RECEIPT_KEY_DIGEST_DOMAIN_V1)?;
        push_lp32(&mut encoded, worker.id().as_str().as_bytes())?;
        push_lp32(&mut encoded, &worker.key_epoch().value().to_be_bytes())?;
        push_lp32(&mut encoded, &bytes)?;
        Ok(Self {
            worker,
            key_epoch,
            verifying_key,
            key_digest: Sha256::digest(encoded).into(),
        })
    }

    /// Returns the receipt-key epoch.
    pub const fn key_epoch(&self) -> SigningWorkerReceiptKeyEpochV1 {
        self.key_epoch
    }

    /// Returns the domain-separated receipt-key digest.
    pub const fn key_digest(&self) -> [u8; 32] {
        self.key_digest
    }

    /// Returns the exact trusted Ed25519 receipt-verifying key bytes.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Returns the worker identity authorized to issue receipts with this key.
    pub const fn worker(&self) -> &CeremonySigningWorkerBindingV1 {
        &self.worker
    }
}

impl fmt::Debug for SigningWorkerReceiptVerifyingKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningWorkerReceiptVerifyingKeyV1")
            .field("worker", &self.worker)
            .field("key_epoch", &self.key_epoch)
            .field("key_digest", &"[computed SHA-256]")
            .finish()
    }
}

/// Raw Ed25519 signature over one activation receipt body.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigningWorkerActivationReceiptSignature64V1([u8; 64]);

impl SigningWorkerActivationReceiptSignature64V1 {
    /// Wraps exact signature bytes for strict verification.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the exact signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for SigningWorkerActivationReceiptSignature64V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningWorkerActivationReceiptSignature64V1([signature])")
    }
}

/// Nonzero opaque worker-output retention evidence digest.
///
/// This host-reference slot does not prove durable storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningWorkerOutputStorageReceiptDigest32V1([u8; 32]);

impl SigningWorkerOutputStorageReceiptDigest32V1 {
    /// Validates one nonzero public storage-receipt digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, SigningWorkerActivationErrorV1> {
        let mut index = 0;
        let mut nonzero = 0u8;
        while index < bytes.len() {
            nonzero |= bytes[index];
            index += 1;
        }
        if nonzero == 0 {
            return Err(SigningWorkerActivationErrorV1::ZeroStorageReceiptDigest);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

struct ProfileVerifiedOpenedSigningWorkerShareCoreV1<Role> {
    scalar: Scalar,
    recipient_key_binding: [u8; 32],
    activation_epoch: CeremonyActivationEpochV1,
    package_authentication_digest: OpaqueHostReferencePackageAuthenticationDigest32V1,
    role: PhantomData<Role>,
}

impl<Role> ProfileVerifiedOpenedSigningWorkerShareCoreV1<Role> {
    fn from_opened_plaintext(
        scalar_bytes: [u8; 32],
        recipient_key_binding: [u8; 32],
        activation_epoch: CeremonyActivationEpochV1,
        package_authentication_digest: OpaqueHostReferencePackageAuthenticationDigest32V1,
    ) -> Result<Self, SigningWorkerActivationErrorV1> {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(scalar_bytes))
            .ok_or(SigningWorkerActivationErrorV1::NoncanonicalScalarShare)?;
        Ok(Self {
            scalar,
            recipient_key_binding,
            activation_epoch,
            package_authentication_digest,
            role: PhantomData,
        })
    }

    fn into_scalar(mut self) -> Scalar {
        core::mem::replace(&mut self.scalar, Scalar::ZERO)
    }
}

impl<Role> Drop for ProfileVerifiedOpenedSigningWorkerShareCoreV1<Role> {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

/// Deriver A SigningWorker share emitted only by the selected authenticated opener.
pub struct ProfileVerifiedOpenedDeriverASigningWorkerShareV1(
    ProfileVerifiedOpenedSigningWorkerShareCoreV1<DeriverAProvenanceRoleV1>,
);

/// Deriver B SigningWorker share emitted only by the selected authenticated opener.
pub struct ProfileVerifiedOpenedDeriverBSigningWorkerShareV1(
    ProfileVerifiedOpenedSigningWorkerShareCoreV1<DeriverBProvenanceRoleV1>,
);

impl fmt::Debug for ProfileVerifiedOpenedDeriverASigningWorkerShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileVerifiedOpenedDeriverASigningWorkerShareV1([secret])")
    }
}

impl fmt::Debug for ProfileVerifiedOpenedDeriverBSigningWorkerShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileVerifiedOpenedDeriverBSigningWorkerShareV1([secret])")
    }
}

/// Origin-specific lifecycle authority retained after worker activation.
pub enum ActivatedSigningWorkerOriginStateV1 {
    /// Registration established the first active worker share.
    Registration {
        /// Consumed origin request.
        origin: RegistrationRequestV1,
        /// Candidate authority retained for registration promotion.
        candidate: RegistrationCandidateStateV1,
    },
    /// Recovery preserved registered identity and staged credential continuity.
    Recovery {
        /// Consumed origin request.
        origin: RecoveryRequestV1,
        /// Terminal evaluator admission retained until promotion.
        terminal: crate::recovery_evaluation_admission::TerminalRecoveryEvaluationV1,
    },
    /// Refresh staged role-specific next state for later atomic promotion.
    Refresh {
        /// Consumed origin request.
        origin: RefreshRequestV1,
        /// Terminal evaluator admission retained until promotion.
        terminal: crate::refresh_evaluation_admission::TerminalRefreshEvaluationV1,
    },
}

/// Activated SigningWorker scalar and its exact public lifecycle binding.
struct ActivatedSigningWorkerSecretV1(Scalar);

impl Drop for ActivatedSigningWorkerSecretV1 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret SigningWorker scalar activated under one exact public lifecycle binding.
pub struct ActivatedSigningWorkerStateV1 {
    #[allow(dead_code)]
    scalar: ActivatedSigningWorkerSecretV1,
    origin_state: ActivatedSigningWorkerOriginStateV1,
    worker: CeremonySigningWorkerBindingV1,
    activation_epoch: CeremonyActivationEpochV1,
    release_identity: HostOnlyActivationReleaseIdentityV1,
    x_server: [u8; 32],
    registered_public_key: RegisteredEd25519PublicKey32V1,
    storage_receipt_digest: SigningWorkerOutputStorageReceiptDigest32V1,
}

impl ActivatedSigningWorkerStateV1 {
    /// Returns the lifecycle origin that produced this state.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.release_identity.origin()
    }

    /// Returns the selected worker identity and recipient-key epoch.
    pub const fn worker(&self) -> &CeremonySigningWorkerBindingV1 {
        &self.worker
    }

    /// Returns the active activation epoch.
    pub const fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.activation_epoch
    }

    /// Returns the reconstructed public SigningWorker point.
    pub const fn x_server(&self) -> &[u8; 32] {
        &self.x_server
    }

    /// Returns the registered public identity preserved by activation.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the durable storage-receipt digest for the activated secret.
    pub const fn storage_receipt_digest(&self) -> SigningWorkerOutputStorageReceiptDigest32V1 {
        self.storage_receipt_digest
    }

    /// Returns the complete committed package-set digest.
    pub const fn package_set_digest(
        &self,
    ) -> crate::semantic_artifacts::ActivationPackageSetDigest32V1 {
        self.release_identity.package_set_digest()
    }

    /// Returns the output-committed receipt digest consumed by activation.
    pub const fn output_committed_receipt_digest(
        &self,
    ) -> ActivationOutputCommittedReceiptDigest32V1 {
        self.release_identity.output_committed_receipt_digest()
    }

    /// Returns the complete atomic-release identity retained through activation.
    pub const fn release_identity(&self) -> HostOnlyActivationReleaseIdentityV1 {
        self.release_identity
    }

    /// Consumes activated worker state into the origin authority needed for promotion.
    #[allow(dead_code)]
    pub(crate) fn into_origin_state(self) -> ActivatedSigningWorkerOriginStateV1 {
        self.origin_state
    }

    /// Borrows the exact terminal refresh admission retained for promotion.
    pub(crate) const fn refresh_terminal_evaluation(
        &self,
    ) -> Option<&crate::refresh_evaluation_admission::TerminalRefreshEvaluationV1> {
        match &self.origin_state {
            ActivatedSigningWorkerOriginStateV1::Refresh { terminal, .. } => Some(terminal),
            ActivatedSigningWorkerOriginStateV1::Registration { .. }
            | ActivatedSigningWorkerOriginStateV1::Recovery { .. } => None,
        }
    }

    /// Borrows the exact terminal recovery admission retained for promotion.
    pub(crate) const fn recovery_terminal_evaluation(
        &self,
    ) -> Option<&crate::recovery_evaluation_admission::TerminalRecoveryEvaluationV1> {
        match &self.origin_state {
            ActivatedSigningWorkerOriginStateV1::Recovery { terminal, .. } => Some(terminal),
            ActivatedSigningWorkerOriginStateV1::Registration { .. }
            | ActivatedSigningWorkerOriginStateV1::Refresh { .. } => None,
        }
    }

    /// Borrows the candidate authority required for registration promotion.
    #[allow(dead_code)]
    pub(crate) const fn registration_promotion_input(
        &self,
    ) -> Option<&RegistrationCandidateStateV1> {
        match &self.origin_state {
            ActivatedSigningWorkerOriginStateV1::Registration { candidate, .. } => Some(candidate),
            ActivatedSigningWorkerOriginStateV1::Recovery { .. }
            | ActivatedSigningWorkerOriginStateV1::Refresh { .. } => None,
        }
    }
}

impl fmt::Debug for ActivatedSigningWorkerStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedSigningWorkerStateV1")
            .field("origin", &self.origin())
            .field("worker", &self.worker)
            .field("activation_epoch", &self.activation_epoch)
            .field("x_server", &"[public point]")
            .field("registered_public_key", &self.registered_public_key)
            .field("scalar", &"[secret]")
            .finish()
    }
}

/// Public deterministic body signed by the SigningWorker after secret storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningWorkerActivationReceiptBodyV1 {
    receipt_key_epoch: SigningWorkerReceiptKeyEpochV1,
    receipt_key_digest: [u8; 32],
    worker: CeremonySigningWorkerBindingV1,
    origin: ActivationPackageOriginV1,
    activation_request_context_digest: [u8; 32],
    activation_authorization_digest: [u8; 32],
    activation_transcript_digest: [u8; 32],
    artifact_binding: ActivationArtifactBindingV1,
    output_committed_receipt_digest: ActivationOutputCommittedReceiptDigest32V1,
    x_server: [u8; 32],
    registered_public_key: RegisteredEd25519PublicKey32V1,
    storage_receipt_digest: SigningWorkerOutputStorageReceiptDigest32V1,
}

impl SigningWorkerActivationReceiptBodyV1 {
    /// Encodes the exact deterministic signed receipt body.
    pub fn encode(&self) -> Result<Vec<u8>, SigningWorkerActivationErrorV1> {
        let mut output = Vec::new();
        push_lp32(
            &mut output,
            SIGNING_WORKER_ACTIVATION_RECEIPT_ENCODING_DOMAIN_V1,
        )?;
        push_lp32(&mut output, &self.receipt_key_epoch.value().to_be_bytes())?;
        push_lp32(&mut output, &self.receipt_key_digest)?;
        push_lp32(&mut output, self.worker.id().as_str().as_bytes())?;
        push_lp32(&mut output, &self.worker.key_epoch().value().to_be_bytes())?;
        push_lp32(&mut output, &[origin_tag(self.origin)])?;
        push_lp32(&mut output, &self.activation_request_context_digest)?;
        push_lp32(&mut output, &self.activation_authorization_digest)?;
        push_lp32(&mut output, &self.activation_transcript_digest)?;
        encode_artifact_binding(&mut output, self.artifact_binding)?;
        push_lp32(&mut output, self.output_committed_receipt_digest.as_bytes())?;
        push_lp32(&mut output, &self.x_server)?;
        push_lp32(&mut output, self.registered_public_key.as_bytes())?;
        push_lp32(&mut output, self.storage_receipt_digest.as_bytes())?;
        Ok(output)
    }

    /// Computes the domain-separated activation-receipt digest.
    pub fn digest(
        &self,
    ) -> Result<SigningWorkerActivationReceiptDigest32V1, SigningWorkerActivationErrorV1> {
        let mut encoded = Vec::new();
        push_lp32(
            &mut encoded,
            SIGNING_WORKER_ACTIVATION_RECEIPT_DIGEST_DOMAIN_V1,
        )?;
        push_lp32(&mut encoded, &self.encode()?)?;
        Ok(SigningWorkerActivationReceiptDigest32V1(
            Sha256::digest(encoded).into(),
        ))
    }
}

/// SHA-256 identity of one exact signed activation receipt body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningWorkerActivationReceiptDigest32V1([u8; 32]);

impl SigningWorkerActivationReceiptDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Activated state awaiting strict verification of its worker receipt signature.
pub struct PreparedSigningWorkerActivationV1 {
    state: ActivatedSigningWorkerStateV1,
    receipt_body: SigningWorkerActivationReceiptBodyV1,
}

impl PreparedSigningWorkerActivationV1 {
    /// Returns the exact deterministic bytes the SigningWorker must sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SigningWorkerActivationErrorV1> {
        self.receipt_body.encode()
    }

    /// Returns the public receipt body awaiting signature verification.
    pub const fn receipt_body(&self) -> &SigningWorkerActivationReceiptBodyV1 {
        &self.receipt_body
    }

    /// Strictly verifies the worker signature before releasing activated state.
    pub fn verify_receipt(
        self,
        signature: SigningWorkerActivationReceiptSignature64V1,
        authority: &SigningWorkerReceiptVerifyingKeyV1,
    ) -> Result<SigningWorkerActivationSuccessV1, RejectedSigningWorkerReceiptV1> {
        let reason = if &self.receipt_body.worker != authority.worker() {
            Some(SigningWorkerActivationErrorV1::ReceiptAuthorityWorkerMismatch)
        } else if self.receipt_body.receipt_key_epoch != authority.key_epoch() {
            Some(SigningWorkerActivationErrorV1::ReceiptKeyEpochMismatch)
        } else if self.receipt_body.receipt_key_digest != authority.key_digest() {
            Some(SigningWorkerActivationErrorV1::ReceiptKeyDigestMismatch)
        } else {
            match self.signing_bytes() {
                Ok(message) => {
                    let signature_value = Signature::from_bytes(signature.as_bytes());
                    authority
                        .verifying_key
                        .verify_strict(&message, &signature_value)
                        .err()
                        .map(|_| SigningWorkerActivationErrorV1::InvalidReceiptSignature)
                }
                Err(error) => Some(error),
            }
        };
        if let Some(reason) = reason {
            return Err(RejectedSigningWorkerReceiptV1 {
                reason,
                prepared: Box::new(self),
                signature,
            });
        }
        let receipt = VerifiedSigningWorkerActivationReceiptV1 {
            digest: self
                .receipt_body
                .digest()
                .expect("validated receipt fields always fit LP32"),
            body: self.receipt_body,
            signature,
        };
        Ok(SigningWorkerActivationSuccessV1 {
            state: self.state,
            receipt,
            receipt_authority: authority.clone(),
        })
    }
}

impl fmt::Debug for PreparedSigningWorkerActivationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSigningWorkerActivationV1")
            .field("state", &self.state)
            .field("receipt_body", &self.receipt_body)
            .finish()
    }
}

/// Failed receipt verification retaining the activated secret for safe retry.
pub struct RejectedSigningWorkerReceiptV1 {
    reason: SigningWorkerActivationErrorV1,
    prepared: Box<PreparedSigningWorkerActivationV1>,
    signature: SigningWorkerActivationReceiptSignature64V1,
}

impl RejectedSigningWorkerReceiptV1 {
    /// Returns the exact verification failure.
    pub const fn reason(&self) -> SigningWorkerActivationErrorV1 {
        self.reason
    }

    /// Recovers the prepared activation and rejected signature.
    pub fn into_parts(
        self,
    ) -> (
        PreparedSigningWorkerActivationV1,
        SigningWorkerActivationReceiptSignature64V1,
    ) {
        (*self.prepared, self.signature)
    }
}

impl fmt::Debug for RejectedSigningWorkerReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedSigningWorkerReceiptV1")
            .field("reason", &self.reason)
            .field("prepared", &"[retained activated state]")
            .finish()
    }
}

/// Strictly verified activation receipt and the corresponding activated secret state.
pub struct SigningWorkerActivationSuccessV1 {
    state: ActivatedSigningWorkerStateV1,
    receipt: VerifiedSigningWorkerActivationReceiptV1,
    receipt_authority: SigningWorkerReceiptVerifyingKeyV1,
}

impl SigningWorkerActivationSuccessV1 {
    /// Returns the activated SigningWorker state.
    pub const fn state(&self) -> &ActivatedSigningWorkerStateV1 {
        &self.state
    }

    /// Returns the strictly verified idempotent activation receipt.
    pub const fn receipt(&self) -> &VerifiedSigningWorkerActivationReceiptV1 {
        &self.receipt
    }

    /// Returns the exact trusted authority used for strict receipt verification.
    pub const fn receipt_authority(&self) -> &SigningWorkerReceiptVerifyingKeyV1 {
        &self.receipt_authority
    }

    /// Consumes the success into activated state and verified receipt.
    pub fn into_parts(
        self,
    ) -> (
        ActivatedSigningWorkerStateV1,
        VerifiedSigningWorkerActivationReceiptV1,
        SigningWorkerReceiptVerifyingKeyV1,
    ) {
        (self.state, self.receipt, self.receipt_authority)
    }
}

impl fmt::Debug for SigningWorkerActivationSuccessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningWorkerActivationSuccessV1")
            .field("state", &self.state)
            .field("receipt", &self.receipt)
            .field("receipt_authority", &self.receipt_authority)
            .finish()
    }
}

/// Strictly verified deterministic SigningWorker activation receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigningWorkerActivationReceiptV1 {
    body: SigningWorkerActivationReceiptBodyV1,
    digest: SigningWorkerActivationReceiptDigest32V1,
    signature: SigningWorkerActivationReceiptSignature64V1,
}

impl VerifiedSigningWorkerActivationReceiptV1 {
    /// Returns the exact signed receipt body.
    pub const fn body(&self) -> &SigningWorkerActivationReceiptBodyV1 {
        &self.body
    }

    /// Returns the receipt-body digest.
    pub const fn digest(&self) -> SigningWorkerActivationReceiptDigest32V1 {
        self.digest
    }

    /// Returns the verified signature bytes.
    pub const fn signature(&self) -> SigningWorkerActivationReceiptSignature64V1 {
        self.signature
    }
}

/// Activation preparation rejected before secret state or receipt creation.
pub struct RejectedSigningWorkerActivationPreparationV1 {
    reason: SigningWorkerActivationErrorV1,
    release_authority: Box<HostOnlySigningWorkerActivationReleaseAuthorityV1>,
}

impl RejectedSigningWorkerActivationPreparationV1 {
    /// Returns the exact rejection reason.
    pub const fn reason(&self) -> SigningWorkerActivationErrorV1 {
        self.reason
    }

    /// Recovers the unchanged SigningWorker release authority for exact retry.
    pub fn into_release_authority(self) -> HostOnlySigningWorkerActivationReleaseAuthorityV1 {
        *self.release_authority
    }
}

impl fmt::Debug for RejectedSigningWorkerActivationPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedSigningWorkerActivationPreparationV1")
            .field("reason", &self.reason)
            .field("release_authority", &"[retained]")
            .finish()
    }
}

/// Failure while validating opened packages or a signed activation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningWorkerActivationErrorV1 {
    /// Receipt key epochs must be nonzero.
    ZeroReceiptKeyEpoch,
    /// The receipt verifying key did not decode.
    InvalidReceiptVerifyingKey,
    /// The receipt verifying key was weak.
    WeakReceiptVerifyingKey,
    /// Storage receipt digests must be nonzero.
    ZeroStorageReceiptDigest,
    /// Opened scalar bytes were not canonical modulo the Ed25519 group order.
    NoncanonicalScalarShare,
    /// The runtime SigningWorker did not match the origin request.
    SigningWorkerMismatch,
    /// A descriptor was not addressed to SigningWorker scalar output.
    RecipientOrOutputKindMismatch,
    /// A descriptor or opened plaintext named another recipient binding.
    RecipientKeyBindingMismatch,
    /// A descriptor or opened plaintext named another activation epoch.
    ActivationEpochMismatch,
    /// A descriptor came from another request context.
    RequestContextDigestMismatch,
    /// The selected opener authenticated another package binding.
    PackageAuthenticationMismatch,
    /// An opened scalar did not match its role-specific public share commitment.
    ScalarSharePointMismatch,
    /// An opened scalar differed from the exact same-evaluation retained share.
    RetainedScalarShareMismatch,
    /// The two opened role shares did not reconstruct the committed worker point.
    JoinedSigningWorkerPointMismatch,
    /// The reconstructed worker point violated the registered identity relation.
    RegisteredIdentityRelationMismatch,
    /// The receipt authority key epoch differed from the signed body.
    ReceiptKeyEpochMismatch,
    /// The receipt authority was configured for another SigningWorker.
    ReceiptAuthorityWorkerMismatch,
    /// The receipt authority key digest differed from the signed body.
    ReceiptKeyDigestMismatch,
    /// Strict receipt signature verification failed.
    InvalidReceiptSignature,
    /// One LP32 field exceeded the version-one length limit.
    ValueTooLong,
}

impl fmt::Display for SigningWorkerActivationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroReceiptKeyEpoch => "SigningWorker receipt key epoch must be nonzero",
            Self::InvalidReceiptVerifyingKey => "SigningWorker receipt verifying key is invalid",
            Self::WeakReceiptVerifyingKey => "SigningWorker receipt verifying key must not be weak",
            Self::ZeroStorageReceiptDigest => {
                "SigningWorker storage receipt digest must be nonzero"
            }
            Self::NoncanonicalScalarShare => "opened SigningWorker scalar share is noncanonical",
            Self::SigningWorkerMismatch => {
                "runtime SigningWorker does not match the origin request"
            }
            Self::RecipientOrOutputKindMismatch => {
                "package descriptor is not SigningWorker scalar output"
            }
            Self::RecipientKeyBindingMismatch => "SigningWorker recipient key binding mismatch",
            Self::ActivationEpochMismatch => "SigningWorker activation epoch mismatch",
            Self::RequestContextDigestMismatch => "SigningWorker package request-context mismatch",
            Self::PackageAuthenticationMismatch => {
                "selected opener authenticated another package binding"
            }
            Self::ScalarSharePointMismatch => {
                "opened SigningWorker scalar does not match its public share point"
            }
            Self::RetainedScalarShareMismatch => {
                "opened SigningWorker scalar differs from the retained evaluation share"
            }
            Self::JoinedSigningWorkerPointMismatch => {
                "opened A/B shares do not reconstruct the committed SigningWorker point"
            }
            Self::RegisteredIdentityRelationMismatch => {
                "activated SigningWorker point violates the registered identity relation"
            }
            Self::ReceiptKeyEpochMismatch => "SigningWorker receipt key epoch mismatch",
            Self::ReceiptAuthorityWorkerMismatch => {
                "SigningWorker receipt authority belongs to another worker"
            }
            Self::ReceiptKeyDigestMismatch => "SigningWorker receipt key digest mismatch",
            Self::InvalidReceiptSignature => {
                "SigningWorker activation receipt signature is invalid"
            }
            Self::ValueTooLong => "SigningWorker activation LP32 value exceeds U32 length",
        })
    }
}

impl std::error::Error for SigningWorkerActivationErrorV1 {}

/// Combines selected-profile authenticated openings into a receipt-pending worker state.
pub(crate) fn prepare_signing_worker_activation_v1(
    release_authority: HostOnlySigningWorkerActivationReleaseAuthorityV1,
    runtime_worker: CeremonySigningWorkerBindingV1,
    opened_a: ProfileVerifiedOpenedDeriverASigningWorkerShareV1,
    opened_b: ProfileVerifiedOpenedDeriverBSigningWorkerShareV1,
    storage_receipt_digest: SigningWorkerOutputStorageReceiptDigest32V1,
    receipt_authority: &SigningWorkerReceiptVerifyingKeyV1,
) -> Result<PreparedSigningWorkerActivationV1, RejectedSigningWorkerActivationPreparationV1> {
    let validation = validate_activation_preparation(
        release_authority.metadata(),
        &runtime_worker,
        &opened_a.0,
        &opened_b.0,
    );
    if let Err(reason) = validation {
        return Err(RejectedSigningWorkerActivationPreparationV1 {
            reason,
            release_authority: Box::new(release_authority),
        });
    }
    if receipt_authority.worker() != &runtime_worker {
        return Err(RejectedSigningWorkerActivationPreparationV1 {
            reason: SigningWorkerActivationErrorV1::ReceiptAuthorityWorkerMismatch,
            release_authority: Box::new(release_authority),
        });
    }

    let release_identity = release_authority.release_identity();
    let metadata = release_authority.into_metadata();
    let activation_dag = metadata.post_state().activation_dag();
    let state = metadata.into_post_state();
    let (origin_state, artifacts) = split_origin_state(state);
    let artifact_binding = artifacts.binding();
    let output_committed_receipt_digest = artifacts.receipt().digest();
    let packages = artifacts.packages();
    let scalar = opened_a.0.into_scalar() + opened_b.0.into_scalar();
    let activated_state = ActivatedSigningWorkerStateV1 {
        scalar: ActivatedSigningWorkerSecretV1(scalar),
        origin_state,
        worker: runtime_worker.clone(),
        activation_epoch: artifact_binding.activation_epoch(),
        release_identity,
        x_server: *packages.x_server(),
        registered_public_key: packages.registered_public_key(),
        storage_receipt_digest,
    };
    let receipt_body = SigningWorkerActivationReceiptBodyV1 {
        receipt_key_epoch: receipt_authority.key_epoch(),
        receipt_key_digest: receipt_authority.key_digest(),
        worker: runtime_worker,
        origin: artifact_binding.origin(),
        activation_request_context_digest: *activation_dag.request_context_digest().as_bytes(),
        activation_authorization_digest: *activation_dag.authorization_digest().as_bytes(),
        activation_transcript_digest: *activation_dag.transcript_digest().as_bytes(),
        artifact_binding,
        output_committed_receipt_digest,
        x_server: *packages.x_server(),
        registered_public_key: packages.registered_public_key(),
        storage_receipt_digest,
    };
    Ok(PreparedSigningWorkerActivationV1 {
        state: activated_state,
        receipt_body,
    })
}

/// Constructs exact opened worker shares solely for deterministic host fixtures.
///
/// The generator crate has no production dependency path. A deployed opener
/// must construct the sealed profile-verified types through the selected
/// protocol implementation.
pub(crate) fn host_fixture_opened_signing_worker_shares_v1(
    metadata: &ActivationMetadataConsumptionSuccessV1,
) -> (
    ProfileVerifiedOpenedDeriverASigningWorkerShareV1,
    ProfileVerifiedOpenedDeriverBSigningWorkerShareV1,
) {
    let packages = metadata.post_state().artifacts().packages();
    let shares = metadata.post_state().committed_output().shares();
    let a = packages.deriver_a_signing_worker();
    let b = packages.deriver_b_signing_worker();
    (
        ProfileVerifiedOpenedDeriverASigningWorkerShareV1(
            ProfileVerifiedOpenedSigningWorkerShareCoreV1::from_opened_plaintext(
                shares.deriver_a().signing_worker().expose_fixture_bytes(),
                *a.recipient_key_binding(),
                a.activation_epoch(),
                a.package_authentication_digest(),
            )
            .expect("typed fixture share remains canonical"),
        ),
        ProfileVerifiedOpenedDeriverBSigningWorkerShareV1(
            ProfileVerifiedOpenedSigningWorkerShareCoreV1::from_opened_plaintext(
                shares.deriver_b().signing_worker().expose_fixture_bytes(),
                *b.recipient_key_binding(),
                b.activation_epoch(),
                b.package_authentication_digest(),
            )
            .expect("typed fixture share remains canonical"),
        ),
    )
}

fn validate_activation_preparation(
    metadata: &ActivationMetadataConsumptionSuccessV1,
    runtime_worker: &CeremonySigningWorkerBindingV1,
    opened_a: &ProfileVerifiedOpenedSigningWorkerShareCoreV1<DeriverAProvenanceRoleV1>,
    opened_b: &ProfileVerifiedOpenedSigningWorkerShareCoreV1<DeriverBProvenanceRoleV1>,
) -> Result<(), SigningWorkerActivationErrorV1> {
    let post_state = metadata.post_state();
    let expected_worker = origin_request_context(post_state).signing_worker_binding();
    if runtime_worker != expected_worker {
        return Err(SigningWorkerActivationErrorV1::SigningWorkerMismatch);
    }
    let artifacts = post_state.artifacts();
    let binding = artifacts.binding();
    let packages = artifacts.packages();
    let descriptor_a = packages.deriver_a_signing_worker();
    let descriptor_b = packages.deriver_b_signing_worker();
    validate_descriptor_common(descriptor_a, opened_a, binding)?;
    validate_descriptor_common(descriptor_b, opened_b, binding)?;
    let retained = post_state.committed_output().shares();
    validate_retained_share(
        opened_a.scalar,
        retained.deriver_a().signing_worker().expose_fixture_bytes(),
    )?;
    validate_retained_share(
        opened_b.scalar,
        retained.deriver_b().signing_worker().expose_fixture_bytes(),
    )?;
    validate_opened_share_point(opened_a.scalar, descriptor_a.scalar_share_point())?;
    validate_opened_share_point(opened_b.scalar, descriptor_b.scalar_share_point())?;

    let joined_scalar = opened_a.scalar + opened_b.scalar;
    let joined_point = (ED25519_BASEPOINT_POINT * joined_scalar)
        .compress()
        .to_bytes();
    if !bool::from(joined_point.ct_eq(packages.x_server())) {
        return Err(SigningWorkerActivationErrorV1::JoinedSigningWorkerPointMismatch);
    }
    let x_client = CompressedEdwardsY(*packages.x_client())
        .decompress()
        .ok_or(SigningWorkerActivationErrorV1::RegisteredIdentityRelationMismatch)?;
    let x_server = CompressedEdwardsY(joined_point)
        .decompress()
        .ok_or(SigningWorkerActivationErrorV1::RegisteredIdentityRelationMismatch)?;
    let derived = (x_client + x_client - x_server).compress().to_bytes();
    if !bool::from(derived.ct_eq(packages.registered_public_key().as_bytes())) {
        return Err(SigningWorkerActivationErrorV1::RegisteredIdentityRelationMismatch);
    }
    Ok(())
}

fn validate_retained_share(
    scalar: Scalar,
    retained: [u8; 32],
) -> Result<(), SigningWorkerActivationErrorV1> {
    if !bool::from(scalar.to_bytes().ct_eq(&retained)) {
        return Err(SigningWorkerActivationErrorV1::RetainedScalarShareMismatch);
    }
    Ok(())
}

trait SigningWorkerDescriptorV1 {
    fn recipient_tag(&self) -> u8;
    fn output_tag(&self) -> u8;
    fn recipient_key_binding(&self) -> &[u8; 32];
    fn activation_epoch(&self) -> CeremonyActivationEpochV1;
    fn request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1;
    fn package_authentication_digest(&self) -> OpaqueHostReferencePackageAuthenticationDigest32V1;
}

macro_rules! impl_signing_worker_descriptor {
    ($type:ty) => {
        impl SigningWorkerDescriptorV1 for $type {
            fn recipient_tag(&self) -> u8 {
                self.recipient_tag()
            }

            fn output_tag(&self) -> u8 {
                self.output_tag()
            }

            fn recipient_key_binding(&self) -> &[u8; 32] {
                self.recipient_key_binding()
            }

            fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
                self.activation_epoch()
            }

            fn request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
                self.request_context_digest()
            }

            fn package_authentication_digest(
                &self,
            ) -> OpaqueHostReferencePackageAuthenticationDigest32V1 {
                self.package_authentication_digest()
            }
        }
    };
}

impl_signing_worker_descriptor!(DeriverASigningWorkerScalarActivationPackageDescriptorV1);
impl_signing_worker_descriptor!(DeriverBSigningWorkerScalarActivationPackageDescriptorV1);

fn validate_descriptor_common<Role, Descriptor: SigningWorkerDescriptorV1>(
    descriptor: &Descriptor,
    opened: &ProfileVerifiedOpenedSigningWorkerShareCoreV1<Role>,
    binding: ActivationArtifactBindingV1,
) -> Result<(), SigningWorkerActivationErrorV1> {
    if descriptor.recipient_tag() != SIGNING_WORKER_RECIPIENT_TAG_V1
        || descriptor.output_tag() != SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1
    {
        return Err(SigningWorkerActivationErrorV1::RecipientOrOutputKindMismatch);
    }
    let expected_recipient = SigningWorkerRecipientKeyBindingDigest32V1::derive(
        &binding.origin_request_context_digest(),
    );
    if !bool::from(
        descriptor
            .recipient_key_binding()
            .ct_eq(expected_recipient.as_bytes()),
    ) || !bool::from(
        opened
            .recipient_key_binding
            .ct_eq(expected_recipient.as_bytes()),
    ) {
        return Err(SigningWorkerActivationErrorV1::RecipientKeyBindingMismatch);
    }
    if descriptor.activation_epoch() != binding.activation_epoch()
        || opened.activation_epoch != binding.activation_epoch()
    {
        return Err(SigningWorkerActivationErrorV1::ActivationEpochMismatch);
    }
    if descriptor.request_context_digest() != binding.origin_request_context_digest() {
        return Err(SigningWorkerActivationErrorV1::RequestContextDigestMismatch);
    }
    if descriptor.package_authentication_digest() != opened.package_authentication_digest {
        return Err(SigningWorkerActivationErrorV1::PackageAuthenticationMismatch);
    }
    Ok(())
}

fn validate_opened_share_point(
    scalar: Scalar,
    expected_point: &[u8; 32],
) -> Result<(), SigningWorkerActivationErrorV1> {
    let actual = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    if !bool::from(actual.ct_eq(expected_point)) {
        return Err(SigningWorkerActivationErrorV1::ScalarSharePointMismatch);
    }
    Ok(())
}

pub(crate) fn origin_request_context(
    state: &MetadataConsumedActivationStateV1,
) -> &crate::ceremony_context::CeremonyPublicRequestContextV1 {
    match state {
        MetadataConsumedActivationStateV1::Registration(value) => value.origin_request_context(),
        MetadataConsumedActivationStateV1::Recovery(value) => value.origin_request_context(),
        MetadataConsumedActivationStateV1::Refresh(value) => value.origin_request_context(),
    }
}

fn split_origin_state(
    state: MetadataConsumedActivationStateV1,
) -> (
    ActivatedSigningWorkerOriginStateV1,
    CommittedActivationArtifactsV1,
) {
    match state {
        MetadataConsumedActivationStateV1::Registration(value) => {
            let (origin, candidate, output) = value.into_parts();
            let (artifacts, _shares) = output.into_parts();
            (
                ActivatedSigningWorkerOriginStateV1::Registration { origin, candidate },
                artifacts,
            )
        }
        MetadataConsumedActivationStateV1::Recovery(value) => {
            let (origin, terminal, output) = value.into_parts();
            let (artifacts, _shares) = output.into_parts();
            (
                ActivatedSigningWorkerOriginStateV1::Recovery { origin, terminal },
                artifacts,
            )
        }
        MetadataConsumedActivationStateV1::Refresh(value) => {
            let (origin, terminal, output) = value.into_parts();
            let (artifacts, _shares) = output.into_parts();
            (
                ActivatedSigningWorkerOriginStateV1::Refresh { origin, terminal },
                artifacts,
            )
        }
    }
}

fn encode_artifact_binding(
    output: &mut Vec<u8>,
    binding: ActivationArtifactBindingV1,
) -> Result<(), SigningWorkerActivationErrorV1> {
    push_lp32(output, &[origin_tag(binding.origin())])?;
    push_lp32(output, &[binding.origin_request_kind().tag()])?;
    push_lp32(output, binding.origin_request_context_digest().as_bytes())?;
    push_lp32(output, binding.origin_authorization_digest().as_bytes())?;
    push_lp32(output, binding.origin_transcript_digest().as_bytes())?;
    push_lp32(output, binding.one_use_execution_id().as_bytes())?;
    push_lp32(output, binding.package_set_digest().as_bytes())?;
    push_lp32(output, &binding.activation_epoch().value().to_be_bytes())?;
    push_lp32(output, binding.registered_public_key().as_bytes())
}

const fn origin_tag(origin: ActivationPackageOriginV1) -> u8 {
    match origin {
        ActivationPackageOriginV1::Registration => REGISTRATION_ORIGIN_TAG_V1,
        ActivationPackageOriginV1::Recovery => RECOVERY_ORIGIN_TAG_V1,
        ActivationPackageOriginV1::Refresh => REFRESH_ORIGIN_TAG_V1,
    }
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SigningWorkerActivationErrorV1> {
    let length =
        u32::try_from(value.len()).map_err(|_| SigningWorkerActivationErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::activation_delivery::HostOnlyActivationRecipientReleaseEvidenceV1;
    use crate::ceremony_context::{
        CeremonyArtifactSuiteDigest32V1, CeremonyAuthorizationRecordDigest32V1,
        CeremonyReplayNonce32V1, CeremonyRequestExpiryV1, CeremonyRequestIdV1,
        CeremonySigningWorkerIdV1, CeremonySigningWorkerKeyEpochV1, CeremonyTranscriptNonce32V1,
        CeremonyTransportBindingDigest32V1,
    };
    use crate::lifecycle_domain::{
        consume_activation_metadata_v1, ActivationControlFreshFieldsV1, ActivationRequestV1,
        PendingActivationPreStateV1,
    };
    use crate::semantic_artifacts::{
        OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
        OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
    };
    use crate::semantic_fixture_material::{
        reference_fixture, registration_ideal_coins, registration_inputs,
    };
    use crate::semantic_lifecycle_fixtures::{
        recovery_pending, refresh_pending, registration_pending,
    };
    use crate::{
        evaluate_host_only_registration_output_sharing_v1,
        prepare_host_only_registration_reference_v1,
    };

    fn receipt_authority_for(
        worker: &CeremonySigningWorkerBindingV1,
    ) -> (SigningKey, SigningWorkerReceiptVerifyingKeyV1) {
        let signing_key = SigningKey::from_bytes(&[0x6a; 32]);
        let authority = SigningWorkerReceiptVerifyingKeyV1::parse(
            worker.clone(),
            SigningWorkerReceiptKeyEpochV1::new(3).expect("receipt key epoch"),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("receipt authority");
        (signing_key, authority)
    }

    fn activation_metadata() -> ActivationMetadataConsumptionSuccessV1 {
        activation_metadata_for(registration_pending(), "worker-activation-fixture", 0xb1)
    }

    fn activation_metadata_for(
        pending: PendingActivationPreStateV1,
        request_id: &str,
        replay_byte: u8,
    ) -> ActivationMetadataConsumptionSuccessV1 {
        let request = ActivationRequestV1::new(
            ActivationControlFreshFieldsV1::new(
                CeremonyRequestIdV1::parse(request_id).expect("request id"),
                CeremonyReplayNonce32V1::new([replay_byte; 32]),
                CeremonyRequestExpiryV1::new(500).expect("expiry"),
                CeremonyAuthorizationRecordDigest32V1::new([0xb2; 32]).expect("authorization"),
                CeremonyTranscriptNonce32V1::new([0xb3; 32]),
                CeremonyTransportBindingDigest32V1::new([0xb4; 32]).expect("transport"),
                CeremonyArtifactSuiteDigest32V1::new([0xb5; 32]).expect("suite"),
            ),
            pending,
        )
        .expect("activation request");
        consume_activation_metadata_v1(request)
    }

    fn release_authority(
        metadata: ActivationMetadataConsumptionSuccessV1,
    ) -> HostOnlySigningWorkerActivationReleaseAuthorityV1 {
        let evidence = HostOnlyActivationRecipientReleaseEvidenceV1::for_metadata_consumed(
            &metadata,
            OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new([0xb6; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new([0xb7; 32])
                .expect("worker delivery evidence"),
        );
        let (_client, worker) = metadata
            .release_recipients_v1(evidence)
            .expect("recipient release")
            .into_capabilities();
        worker
    }

    fn worker_share_bytes() -> ([u8; 32], [u8; 32]) {
        let fixture = reference_fixture();
        let prepared = prepare_host_only_registration_reference_v1(registration_inputs(&fixture));
        let success = evaluate_host_only_registration_output_sharing_v1(
            prepared,
            registration_ideal_coins(3, 5),
        );
        (
            success
                .output_shares()
                .deriver_a()
                .signing_worker()
                .expose_fixture_bytes(),
            success
                .output_shares()
                .deriver_b()
                .signing_worker()
                .expose_fixture_bytes(),
        )
    }

    fn opened_shares(
        metadata: &ActivationMetadataConsumptionSuccessV1,
    ) -> (
        ProfileVerifiedOpenedDeriverASigningWorkerShareV1,
        ProfileVerifiedOpenedDeriverBSigningWorkerShareV1,
    ) {
        let packages = metadata.post_state().artifacts().packages();
        let a = packages.deriver_a_signing_worker();
        let b = packages.deriver_b_signing_worker();
        let (a_bytes, b_bytes) = worker_share_bytes();
        (
            ProfileVerifiedOpenedDeriverASigningWorkerShareV1(
                ProfileVerifiedOpenedSigningWorkerShareCoreV1::from_opened_plaintext(
                    a_bytes,
                    *a.recipient_key_binding(),
                    a.activation_epoch(),
                    a.package_authentication_digest(),
                )
                .expect("opened A share"),
            ),
            ProfileVerifiedOpenedDeriverBSigningWorkerShareV1(
                ProfileVerifiedOpenedSigningWorkerShareCoreV1::from_opened_plaintext(
                    b_bytes,
                    *b.recipient_key_binding(),
                    b.activation_epoch(),
                    b.package_authentication_digest(),
                )
                .expect("opened B share"),
            ),
        )
    }

    fn prepare_valid() -> (SigningKey, PreparedSigningWorkerActivationV1) {
        let metadata = activation_metadata();
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let (opened_a, opened_b) = opened_shares(&metadata);
        let (signing_key, authority) = receipt_authority_for(&worker);
        let prepared = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1; 32]).expect("storage receipt"),
            &authority,
        )
        .expect("activation preparation");
        (signing_key, prepared)
    }

    pub(crate) fn verified_refresh_activation() -> SigningWorkerActivationSuccessV1 {
        let metadata =
            activation_metadata_for(refresh_pending(), "refresh-promotion-activation", 0xd7);
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let (opened_a, opened_b) = opened_shares(&metadata);
        let (signing_key, authority) = receipt_authority_for(&worker);
        let prepared = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xd8; 32]).expect("storage receipt"),
            &authority,
        )
        .expect("refresh activation preparation");
        let signature = SigningWorkerActivationReceiptSignature64V1::from_bytes(
            signing_key
                .sign(&prepared.signing_bytes().expect("receipt bytes"))
                .to_bytes(),
        );
        prepared
            .verify_receipt(signature, &authority)
            .expect("verified refresh activation")
    }

    pub(crate) fn verified_recovery_activation() -> SigningWorkerActivationSuccessV1 {
        let metadata =
            activation_metadata_for(recovery_pending(), "recovery-promotion-activation", 0xd9);
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let (opened_a, opened_b) = opened_shares(&metadata);
        let (signing_key, authority) = receipt_authority_for(&worker);
        let prepared = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xda; 32]).expect("storage receipt"),
            &authority,
        )
        .expect("recovery activation preparation");
        let signature = SigningWorkerActivationReceiptSignature64V1::from_bytes(
            signing_key
                .sign(&prepared.signing_bytes().expect("receipt bytes"))
                .to_bytes(),
        );
        prepared
            .verify_receipt(signature, &authority)
            .expect("verified recovery activation")
    }

    #[test]
    fn verified_receipt_releases_only_the_bound_activated_worker_state() {
        let (signing_key, prepared) = prepare_valid();
        let expected_bytes = prepared.signing_bytes().expect("receipt bytes");
        let (_, authority) = receipt_authority_for(&prepared.receipt_body.worker);
        let signature = SigningWorkerActivationReceiptSignature64V1::from_bytes(
            signing_key.sign(&expected_bytes).to_bytes(),
        );
        let success = prepared
            .verify_receipt(signature, &authority)
            .expect("verified receipt");
        assert_eq!(
            success.state().origin(),
            ActivationPackageOriginV1::Registration
        );
        assert_eq!(success.state().activation_epoch().value(), 9);
        assert_eq!(
            success.state().x_server(),
            success.receipt().body.x_server.as_ref()
        );
        assert_eq!(
            success.state().registered_public_key(),
            success.receipt().body.registered_public_key
        );
        assert_eq!(
            success.receipt().digest(),
            success.receipt().body.digest().expect("receipt digest")
        );
        assert_eq!(
            success.receipt_authority().worker(),
            &success.receipt().body.worker
        );
        assert_eq!(
            success.receipt_authority().key_epoch(),
            authority.key_epoch()
        );
        assert_eq!(
            success.receipt_authority().key_digest(),
            authority.key_digest()
        );
        assert_eq!(
            success.receipt_authority().verifying_key_bytes(),
            authority.verifying_key_bytes()
        );
        assert!(format!("{success:?}").contains("[secret]"));
    }

    #[test]
    fn wrong_worker_is_rejected_without_losing_release_authority() {
        let metadata = activation_metadata();
        let expected_package_set_digest = metadata.post_state().artifacts().packages().digest();
        let (opened_a, opened_b) = opened_shares(&metadata);
        let wrong_worker = CeremonySigningWorkerBindingV1::new(
            CeremonySigningWorkerIdV1::parse("wrong-worker").expect("worker id"),
            CeremonySigningWorkerKeyEpochV1::new(99).expect("worker epoch"),
        );
        let (_, authority) = receipt_authority_for(&wrong_worker);
        let rejection = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            wrong_worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1; 32]).expect("storage receipt"),
            &authority,
        )
        .expect_err("wrong worker was accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::SigningWorkerMismatch
        );
        assert_eq!(
            rejection.into_release_authority().package_set_digest(),
            expected_package_set_digest
        );
    }

    #[test]
    fn role_share_and_package_authentication_splices_are_rejected() {
        let metadata = activation_metadata();
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let packages = metadata.post_state().artifacts().packages();
        let a = packages.deriver_a_signing_worker();
        let b = packages.deriver_b_signing_worker();
        let (a_bytes, b_bytes) = worker_share_bytes();
        let opened_a = ProfileVerifiedOpenedDeriverASigningWorkerShareV1(
            ProfileVerifiedOpenedSigningWorkerShareCoreV1::from_opened_plaintext(
                b_bytes,
                *a.recipient_key_binding(),
                a.activation_epoch(),
                a.package_authentication_digest(),
            )
            .expect("role-spliced A share"),
        );
        let opened_b = ProfileVerifiedOpenedDeriverBSigningWorkerShareV1(
            ProfileVerifiedOpenedSigningWorkerShareCoreV1::from_opened_plaintext(
                a_bytes,
                *b.recipient_key_binding(),
                b.activation_epoch(),
                b.package_authentication_digest(),
            )
            .expect("role-spliced B share"),
        );
        let (_, authority) = receipt_authority_for(&worker);
        let rejection = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1; 32]).expect("storage receipt"),
            &authority,
        )
        .expect_err("role-spliced shares were accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::RetainedScalarShareMismatch
        );
    }

    #[test]
    fn authenticated_opener_binding_splice_is_rejected() {
        let metadata = activation_metadata();
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let (mut opened_a, opened_b) = opened_shares(&metadata);
        opened_a.0.package_authentication_digest =
            OpaqueHostReferencePackageAuthenticationDigest32V1::new([0xee; 32])
                .expect("alternate authentication");
        let (_, authority) = receipt_authority_for(&worker);
        let rejection = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1; 32]).expect("storage receipt"),
            &authority,
        )
        .expect_err("package-authentication splice was accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::PackageAuthenticationMismatch
        );
    }

    #[test]
    fn opened_recipient_and_activation_epoch_splices_are_rejected() {
        let metadata = activation_metadata();
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let (mut opened_a, opened_b) = opened_shares(&metadata);
        opened_a.0.recipient_key_binding[0] ^= 1;
        let (_, authority) = receipt_authority_for(&worker);
        let rejection = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1; 32]).expect("storage receipt"),
            &authority,
        )
        .expect_err("recipient-binding splice was accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::RecipientKeyBindingMismatch
        );

        let metadata = activation_metadata();
        let worker = origin_request_context(metadata.post_state())
            .signing_worker_binding()
            .clone();
        let (mut opened_a, opened_b) = opened_shares(&metadata);
        opened_a.0.activation_epoch =
            CeremonyActivationEpochV1::new(opened_a.0.activation_epoch.value() + 1)
                .expect("alternate epoch");
        let (_, authority) = receipt_authority_for(&worker);
        let rejection = prepare_signing_worker_activation_v1(
            release_authority(metadata),
            worker,
            opened_a,
            opened_b,
            SigningWorkerOutputStorageReceiptDigest32V1::new([0xc1; 32]).expect("storage receipt"),
            &authority,
        )
        .expect_err("activation-epoch splice was accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::ActivationEpochMismatch
        );
    }

    #[test]
    fn all_three_origins_activate_only_their_committed_worker_shares() {
        for (index, pending) in [
            registration_pending(),
            recovery_pending(),
            refresh_pending(),
        ]
        .into_iter()
        .enumerate()
        {
            let expected_registration_candidate = match &pending {
                PendingActivationPreStateV1::Registration(value) => {
                    Some(value.candidate().digest())
                }
                PendingActivationPreStateV1::Recovery(_)
                | PendingActivationPreStateV1::Refresh(_) => None,
            };
            let metadata = activation_metadata_for(
                pending,
                &format!("worker-origin-activation-{index}"),
                0xc0 + u8::try_from(index).expect("small index"),
            );
            let expected_origin = metadata.post_state().origin();
            let worker = origin_request_context(metadata.post_state())
                .signing_worker_binding()
                .clone();
            let (opened_a, opened_b) = opened_shares(&metadata);
            let (signing_key, authority) = receipt_authority_for(&worker);
            let prepared = prepare_signing_worker_activation_v1(
                release_authority(metadata),
                worker,
                opened_a,
                opened_b,
                SigningWorkerOutputStorageReceiptDigest32V1::new([0xd0 + index as u8; 32])
                    .expect("storage receipt"),
                &authority,
            )
            .expect("origin activation preparation");
            let signature = SigningWorkerActivationReceiptSignature64V1::from_bytes(
                signing_key
                    .sign(&prepared.signing_bytes().expect("receipt bytes"))
                    .to_bytes(),
            );
            let success = prepared
                .verify_receipt(signature, &authority)
                .expect("origin receipt");
            assert_eq!(success.state().origin(), expected_origin);
            assert_eq!(
                success
                    .state()
                    .registration_promotion_input()
                    .map(RegistrationCandidateStateV1::digest),
                expected_registration_candidate
            );
        }
    }

    #[test]
    fn invalid_receipt_signature_retains_activated_state_for_retry() {
        let (_signing_key, prepared) = prepare_valid();
        let (_, authority) = receipt_authority_for(&prepared.receipt_body.worker);
        let rejection = prepared
            .verify_receipt(
                SigningWorkerActivationReceiptSignature64V1::from_bytes([0x55; 64]),
                &authority,
            )
            .expect_err("invalid receipt signature was accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::InvalidReceiptSignature
        );
        let (prepared, _) = rejection.into_parts();
        assert_eq!(prepared.state.activation_epoch().value(), 9);
    }

    #[test]
    fn receipt_authority_for_another_worker_is_rejected_before_signature_use() {
        let (signing_key, prepared) = prepare_valid();
        let wrong_worker = CeremonySigningWorkerBindingV1::new(
            CeremonySigningWorkerIdV1::parse("wrong-receipt-worker").expect("worker id"),
            CeremonySigningWorkerKeyEpochV1::new(7).expect("worker key epoch"),
        );
        let (_, wrong_authority) = receipt_authority_for(&wrong_worker);
        let signature = SigningWorkerActivationReceiptSignature64V1::from_bytes(
            signing_key
                .sign(&prepared.signing_bytes().expect("receipt bytes"))
                .to_bytes(),
        );
        let rejection = prepared
            .verify_receipt(signature, &wrong_authority)
            .expect_err("receipt authority for another worker was accepted");
        assert_eq!(
            rejection.reason(),
            SigningWorkerActivationErrorV1::ReceiptAuthorityWorkerMismatch
        );
    }

    #[test]
    fn receipt_bytes_are_idempotent_for_the_same_committed_activation() {
        let (signing_key_a, prepared_a) = prepare_valid();
        let (signing_key_b, prepared_b) = prepare_valid();
        let bytes_a = prepared_a.signing_bytes().expect("first receipt bytes");
        let bytes_b = prepared_b.signing_bytes().expect("second receipt bytes");
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(
            signing_key_a.sign(&bytes_a).to_bytes(),
            signing_key_b.sign(&bytes_b).to_bytes()
        );
    }

    #[test]
    fn opened_scalar_parser_rejects_noncanonical_order_bytes() {
        let order = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        assert!(matches!(
            ProfileVerifiedOpenedSigningWorkerShareCoreV1::<DeriverAProvenanceRoleV1>::from_opened_plaintext(
                order,
                [0x11; 32],
                CeremonyActivationEpochV1::new(1).expect("epoch"),
                OpaqueHostReferencePackageAuthenticationDigest32V1::new([0x22; 32])
                    .expect("authentication"),
            ),
            Err(SigningWorkerActivationErrorV1::NoncanonicalScalarShare)
        ));
    }
}
