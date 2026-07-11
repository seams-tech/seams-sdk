//! Host-only activation recipient release after metadata authorization consumption.
//!
//! Metadata consumption owns the one-use activation authorization transition.
//! This module atomically splits the retained same-evaluation output into a
//! Client release and a SigningWorker activation authority. It defines no
//! ciphertext opener, transport, durable transaction, or selected profile.

use core::fmt;

use crate::ceremony_context::CeremonyTranscriptDigest32V1;
use crate::lifecycle_domain::{
    ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1, ZeroReevaluationWitnessV1,
};
use crate::output_sharing::reconstruct_host_only_client_scalar_output_v1;
use crate::semantic_artifacts::{
    ActivationOutputCommittedReceiptDigest32V1, ActivationPackageSetDigest32V1,
    OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
};
use crate::CanonicalScalarBytes;

/// Complete public identity shared by both capabilities from one atomic release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyActivationReleaseIdentityV1 {
    origin: ActivationPackageOriginV1,
    package_set_digest: ActivationPackageSetDigest32V1,
    output_committed_receipt_digest: ActivationOutputCommittedReceiptDigest32V1,
    activation_transcript_digest: CeremonyTranscriptDigest32V1,
}

impl HostOnlyActivationReleaseIdentityV1 {
    fn for_metadata(metadata: &ActivationMetadataConsumptionSuccessV1) -> Self {
        Self {
            origin: metadata.post_state().origin(),
            package_set_digest: metadata.post_state().artifacts().packages().digest(),
            output_committed_receipt_digest: metadata.post_state().artifacts().receipt().digest(),
            activation_transcript_digest: metadata
                .post_state()
                .activation_dag()
                .transcript_digest(),
        }
    }

    /// Returns the lifecycle origin that produced the released output.
    pub const fn origin(self) -> ActivationPackageOriginV1 {
        self.origin
    }

    /// Returns the complete committed package-set identity.
    pub const fn package_set_digest(self) -> ActivationPackageSetDigest32V1 {
        self.package_set_digest
    }

    /// Returns the exact output-committed receipt identity.
    pub const fn output_committed_receipt_digest(
        self,
    ) -> ActivationOutputCommittedReceiptDigest32V1 {
        self.output_committed_receipt_digest
    }

    /// Returns the activation-control transcript that consumed authorization.
    pub const fn activation_transcript_digest(self) -> CeremonyTranscriptDigest32V1 {
        self.activation_transcript_digest
    }
}

/// Two-recipient evidence bound to one metadata-consumed activation output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyActivationRecipientReleaseEvidenceV1 {
    package_set_digest: ActivationPackageSetDigest32V1,
    output_committed_receipt_digest: ActivationOutputCommittedReceiptDigest32V1,
    activation_transcript_digest: CeremonyTranscriptDigest32V1,
    client_delivery_evidence: OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
    signing_worker_delivery_evidence:
        OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
}

impl HostOnlyActivationRecipientReleaseEvidenceV1 {
    /// Binds both recipient acknowledgements to one metadata-consumed output.
    pub fn for_metadata_consumed(
        metadata: &ActivationMetadataConsumptionSuccessV1,
        client_delivery_evidence: OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
        signing_worker_delivery_evidence:
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
    ) -> Self {
        Self {
            package_set_digest: metadata.post_state().artifacts().packages().digest(),
            output_committed_receipt_digest: metadata.post_state().artifacts().receipt().digest(),
            activation_transcript_digest: metadata
                .post_state()
                .activation_dag()
                .transcript_digest(),
            client_delivery_evidence,
            signing_worker_delivery_evidence,
        }
    }

    /// Binds a retry to the exact delivery-uncertain output.
    pub fn for_redelivery_pending(
        pending: &HostOnlyActivationRedeliveryPendingV1,
        client_delivery_evidence: OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
        signing_worker_delivery_evidence:
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
    ) -> Self {
        Self {
            package_set_digest: pending.package_set_digest(),
            output_committed_receipt_digest: pending.output_committed_receipt_digest(),
            activation_transcript_digest: pending.activation_transcript_digest(),
            client_delivery_evidence,
            signing_worker_delivery_evidence,
        }
    }

    pub(crate) const fn client_delivery_evidence(
        &self,
    ) -> OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1 {
        self.client_delivery_evidence
    }

    pub(crate) const fn signing_worker_delivery_evidence(
        &self,
    ) -> OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1 {
        self.signing_worker_delivery_evidence
    }
}

/// Activation release rejected before either recipient capability was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyActivationReleaseErrorV1 {
    /// Release evidence named another committed package set.
    PackageSetDigestMismatch,
    /// Release evidence named another output-committed receipt.
    OutputCommittedReceiptDigestMismatch,
    /// Release evidence named another activation-control transcript.
    ActivationTranscriptDigestMismatch,
}

impl fmt::Display for HostOnlyActivationReleaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PackageSetDigestMismatch => {
                "activation release evidence names another package set"
            }
            Self::OutputCommittedReceiptDigestMismatch => {
                "activation release evidence names another output-committed receipt"
            }
            Self::ActivationTranscriptDigestMismatch => {
                "activation release evidence names another activation transcript"
            }
        })
    }
}

impl std::error::Error for HostOnlyActivationReleaseErrorV1 {}

/// Delivery-uncertain activation retaining metadata-consumed exact output identity.
pub struct HostOnlyActivationRedeliveryPendingV1(ActivationMetadataConsumptionSuccessV1);

impl HostOnlyActivationRedeliveryPendingV1 {
    /// Returns the retained package-set identity.
    pub fn package_set_digest(&self) -> ActivationPackageSetDigest32V1 {
        self.0.post_state().artifacts().packages().digest()
    }

    /// Returns the retained output-committed receipt identity.
    pub fn output_committed_receipt_digest(&self) -> ActivationOutputCommittedReceiptDigest32V1 {
        self.0.post_state().artifacts().receipt().digest()
    }

    /// Returns the activation transcript that consumed authorization.
    pub fn activation_transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
        self.0.post_state().activation_dag().transcript_digest()
    }

    /// Returns the witness that uncertainty performed no private evaluation work.
    pub const fn zero_private_evaluation_work(&self) -> ZeroReevaluationWitnessV1 {
        ZeroReevaluationWitnessV1::no_private_evaluation_work()
    }

    /// Retries the atomic recipient release.
    pub fn release_recipients_v1(
        self,
        evidence: HostOnlyActivationRecipientReleaseEvidenceV1,
    ) -> Result<HostOnlyActivationRecipientsReleasedV1, RejectedHostOnlyActivationReleaseV1> {
        release_metadata(self.0, evidence)
    }
}

/// Rejected release retaining the complete metadata-consumed state and evidence.
pub struct RejectedHostOnlyActivationReleaseV1 {
    reason: HostOnlyActivationReleaseErrorV1,
    pending: Box<HostOnlyActivationRedeliveryPendingV1>,
    evidence: Box<HostOnlyActivationRecipientReleaseEvidenceV1>,
}

impl RejectedHostOnlyActivationReleaseV1 {
    /// Returns the exact public rejection reason.
    pub const fn reason(&self) -> HostOnlyActivationReleaseErrorV1 {
        self.reason
    }

    /// Recovers the exact pending state and rejected evidence.
    pub fn into_parts(
        self,
    ) -> (
        HostOnlyActivationRedeliveryPendingV1,
        HostOnlyActivationRecipientReleaseEvidenceV1,
    ) {
        (*self.pending, *self.evidence)
    }
}

impl fmt::Debug for RejectedHostOnlyActivationReleaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedHostOnlyActivationReleaseV1")
            .field("reason", &self.reason)
            .field("pending", &"retained")
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Move-only Client scalar released from the exact retained A/B shares.
pub struct HostOnlyActivationClientReleasedV1 {
    scalar: CanonicalScalarBytes,
    release_identity: HostOnlyActivationReleaseIdentityV1,
    delivery_evidence: OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
}

impl HostOnlyActivationClientReleasedV1 {
    /// Returns the released Client scalar.
    pub const fn x_client_base(&self) -> &CanonicalScalarBytes {
        &self.scalar
    }

    /// Returns the package-set identity authorized for release.
    pub const fn package_set_digest(&self) -> ActivationPackageSetDigest32V1 {
        self.release_identity.package_set_digest()
    }

    /// Returns the complete output identity authorized for release.
    pub const fn release_identity(&self) -> HostOnlyActivationReleaseIdentityV1 {
        self.release_identity
    }

    /// Returns the opaque Client delivery evidence.
    pub const fn delivery_evidence(
        &self,
    ) -> OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1 {
        self.delivery_evidence
    }
}

/// Move-only authority required before SigningWorker package opening can activate state.
pub struct HostOnlySigningWorkerActivationReleaseAuthorityV1 {
    metadata: ActivationMetadataConsumptionSuccessV1,
    release_identity: HostOnlyActivationReleaseIdentityV1,
    delivery_evidence: OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
}

impl HostOnlySigningWorkerActivationReleaseAuthorityV1 {
    /// Returns the released package-set identity.
    pub const fn package_set_digest(&self) -> ActivationPackageSetDigest32V1 {
        self.release_identity.package_set_digest()
    }

    /// Returns the complete output identity authorized for worker activation.
    pub const fn release_identity(&self) -> HostOnlyActivationReleaseIdentityV1 {
        self.release_identity
    }

    /// Returns the opaque SigningWorker delivery evidence.
    pub const fn delivery_evidence(
        &self,
    ) -> OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1 {
        self.delivery_evidence
    }

    pub(crate) const fn metadata(&self) -> &ActivationMetadataConsumptionSuccessV1 {
        &self.metadata
    }

    pub(crate) fn into_metadata(self) -> ActivationMetadataConsumptionSuccessV1 {
        self.metadata
    }
}

/// Atomic activation recipient release yielding disjoint Client and worker capabilities.
pub struct HostOnlyActivationRecipientsReleasedV1 {
    client: HostOnlyActivationClientReleasedV1,
    signing_worker: HostOnlySigningWorkerActivationReleaseAuthorityV1,
    zero_private_evaluation_work: ZeroReevaluationWitnessV1,
}

impl HostOnlyActivationRecipientsReleasedV1 {
    /// Returns the witness that release performed no private reevaluation.
    pub const fn zero_private_evaluation_work(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_private_evaluation_work
    }

    /// Consumes the atomic release into disjoint one-recipient capabilities.
    pub fn into_capabilities(
        self,
    ) -> (
        HostOnlyActivationClientReleasedV1,
        HostOnlySigningWorkerActivationReleaseAuthorityV1,
    ) {
        (self.client, self.signing_worker)
    }

    /// Models exact-identity recipient redelivery as a released-state self-loop.
    pub fn redeliver_v1(self) -> HostOnlyActivationRedeliveryV1 {
        let digest = self.client.package_set_digest();
        HostOnlyActivationRedeliveryV1 {
            released: self,
            before_package_set_digest: digest,
            after_package_set_digest: digest,
            zero_private_evaluation_work: ZeroReevaluationWitnessV1::no_private_evaluation_work(),
        }
    }
}

/// Exact released-state self-loop produced by a recipient redelivery attempt.
pub struct HostOnlyActivationRedeliveryV1 {
    released: HostOnlyActivationRecipientsReleasedV1,
    before_package_set_digest: ActivationPackageSetDigest32V1,
    after_package_set_digest: ActivationPackageSetDigest32V1,
    zero_private_evaluation_work: ZeroReevaluationWitnessV1,
}

impl HostOnlyActivationRedeliveryV1 {
    /// Returns the release identity before redelivery.
    pub const fn before_package_set_digest(&self) -> ActivationPackageSetDigest32V1 {
        self.before_package_set_digest
    }

    /// Returns the identical release identity after redelivery.
    pub const fn after_package_set_digest(&self) -> ActivationPackageSetDigest32V1 {
        self.after_package_set_digest
    }

    /// Returns the witness that redelivery performed no private reevaluation.
    pub const fn zero_private_evaluation_work(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_private_evaluation_work
    }

    /// Recovers the unchanged released state.
    pub fn into_released(self) -> HostOnlyActivationRecipientsReleasedV1 {
        self.released
    }
}

impl ActivationMetadataConsumptionSuccessV1 {
    /// Records delivery uncertainty without changing output or authorization state.
    pub fn delivery_uncertain_v1(self) -> HostOnlyActivationRedeliveryPendingV1 {
        HostOnlyActivationRedeliveryPendingV1(self)
    }

    /// Atomically releases the retained output to Client and SigningWorker.
    pub fn release_recipients_v1(
        self,
        evidence: HostOnlyActivationRecipientReleaseEvidenceV1,
    ) -> Result<HostOnlyActivationRecipientsReleasedV1, RejectedHostOnlyActivationReleaseV1> {
        release_metadata(self, evidence)
    }
}

fn release_metadata(
    metadata: ActivationMetadataConsumptionSuccessV1,
    evidence: HostOnlyActivationRecipientReleaseEvidenceV1,
) -> Result<HostOnlyActivationRecipientsReleasedV1, RejectedHostOnlyActivationReleaseV1> {
    let expected = metadata.post_state().artifacts().packages().digest();
    let expected_receipt = metadata.post_state().artifacts().receipt().digest();
    let expected_transcript = metadata.post_state().activation_dag().transcript_digest();
    let reason = if evidence.package_set_digest != expected {
        Some(HostOnlyActivationReleaseErrorV1::PackageSetDigestMismatch)
    } else if evidence.output_committed_receipt_digest != expected_receipt {
        Some(HostOnlyActivationReleaseErrorV1::OutputCommittedReceiptDigestMismatch)
    } else if evidence.activation_transcript_digest != expected_transcript {
        Some(HostOnlyActivationReleaseErrorV1::ActivationTranscriptDigestMismatch)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(RejectedHostOnlyActivationReleaseV1 {
            reason,
            pending: Box::new(HostOnlyActivationRedeliveryPendingV1(metadata)),
            evidence: Box::new(evidence),
        });
    }
    let release_identity = HostOnlyActivationReleaseIdentityV1::for_metadata(&metadata);
    let shares = metadata.post_state().committed_output().shares();
    let scalar = reconstruct_host_only_client_scalar_output_v1(
        shares.deriver_a().client(),
        shares.deriver_b().client(),
    );
    Ok(HostOnlyActivationRecipientsReleasedV1 {
        client: HostOnlyActivationClientReleasedV1 {
            scalar,
            release_identity,
            delivery_evidence: evidence.client_delivery_evidence,
        },
        signing_worker: HostOnlySigningWorkerActivationReleaseAuthorityV1 {
            metadata,
            release_identity,
            delivery_evidence: evidence.signing_worker_delivery_evidence,
        },
        zero_private_evaluation_work: ZeroReevaluationWitnessV1::no_private_evaluation_work(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony_context::{
        CeremonyArtifactSuiteDigest32V1, CeremonyAuthorizationRecordDigest32V1,
        CeremonyReplayNonce32V1, CeremonyRequestExpiryV1, CeremonyRequestIdV1,
        CeremonyTranscriptNonce32V1, CeremonyTransportBindingDigest32V1,
    };
    use crate::lifecycle_domain::{
        consume_activation_metadata_v1, ActivationControlFreshFieldsV1, ActivationRequestV1,
        PendingActivationPreStateV1,
    };
    use crate::output_sharing::reconstruct_host_only_client_scalar_output_v1;
    use crate::semantic_artifacts::{
        OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
        OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
    };
    use crate::semantic_lifecycle_fixtures::{
        recovery_pending, refresh_pending, registration_pending,
    };

    fn build_metadata(
        pending: PendingActivationPreStateV1,
        index: u8,
    ) -> ActivationMetadataConsumptionSuccessV1 {
        let request = ActivationRequestV1::new(
            ActivationControlFreshFieldsV1::new(
                CeremonyRequestIdV1::parse(&format!("activation-delivery-{index}"))
                    .expect("request id"),
                CeremonyReplayNonce32V1::new([0x91 + index; 32]),
                CeremonyRequestExpiryV1::new(700 + u64::from(index)).expect("expiry"),
                CeremonyAuthorizationRecordDigest32V1::new([0xa1 + index; 32])
                    .expect("authorization"),
                CeremonyTranscriptNonce32V1::new([0xb1 + index; 32]),
                CeremonyTransportBindingDigest32V1::new([0xc1 + index; 32]).expect("transport"),
                CeremonyArtifactSuiteDigest32V1::new([0xd1 + index; 32]).expect("suite"),
            ),
            pending,
        )
        .expect("activation request");
        consume_activation_metadata_v1(request)
    }

    fn evidence(
        metadata: &ActivationMetadataConsumptionSuccessV1,
        index: u8,
    ) -> HostOnlyActivationRecipientReleaseEvidenceV1 {
        HostOnlyActivationRecipientReleaseEvidenceV1::for_metadata_consumed(
            metadata,
            OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new([0xe1 + index; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new(
                [0xf1 + index; 32],
            )
            .expect("worker delivery evidence"),
        )
    }

    fn assert_zero_work(witness: ZeroReevaluationWitnessV1) {
        assert_eq!(witness.yao_evaluations(), 0);
        assert_eq!(witness.deriver_a_invocations(), 0);
        assert_eq!(witness.deriver_b_invocations(), 0);
        assert_eq!(witness.contribution_derivations(), 0);
        assert_eq!(witness.output_share_samples(), 0);
    }

    #[test]
    fn all_origins_release_exact_client_scalar_and_worker_authority() {
        for (index, pending) in [
            registration_pending(),
            recovery_pending(),
            refresh_pending(),
        ]
        .into_iter()
        .enumerate()
        {
            let metadata = build_metadata(pending, u8::try_from(index).expect("small index"));
            let output = metadata.post_state().committed_output();
            let expected_origin = metadata.post_state().origin();
            let expected_digest = output.artifacts().packages().digest();
            let expected_receipt = output.artifacts().receipt().digest();
            let expected_transcript = metadata.post_state().activation_dag().transcript_digest();
            let expected_client = reconstruct_host_only_client_scalar_output_v1(
                output.shares().deriver_a().client(),
                output.shares().deriver_b().client(),
            )
            .expose_bytes();
            let evidence = evidence(&metadata, u8::try_from(index).expect("small index"));
            let released = metadata
                .release_recipients_v1(evidence)
                .expect("release recipients");
            assert_zero_work(released.zero_private_evaluation_work());
            let (client, worker) = released.into_capabilities();
            assert_eq!(client.x_client_base().expose_bytes(), expected_client);
            assert_eq!(client.package_set_digest(), expected_digest);
            assert_eq!(worker.package_set_digest(), expected_digest);
            assert_eq!(client.release_identity(), worker.release_identity());
            assert_eq!(client.release_identity().origin(), expected_origin);
            assert_eq!(
                client.release_identity().output_committed_receipt_digest(),
                expected_receipt
            );
            assert_eq!(
                client.release_identity().activation_transcript_digest(),
                expected_transcript
            );
        }
    }

    #[test]
    fn uncertainty_rejection_and_retry_preserve_exact_identity() {
        let metadata = build_metadata(registration_pending(), 3);
        let expected_digest = metadata.post_state().artifacts().packages().digest();
        let pending = metadata.delivery_uncertain_v1();
        assert_eq!(pending.package_set_digest(), expected_digest);
        assert_zero_work(pending.zero_private_evaluation_work());
        let mut wrong = HostOnlyActivationRecipientReleaseEvidenceV1::for_redelivery_pending(
            &pending,
            OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new([0x31; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new([0x32; 32])
                .expect("worker delivery evidence"),
        );
        wrong.package_set_digest = build_metadata(refresh_pending(), 4)
            .post_state()
            .artifacts()
            .packages()
            .digest();
        let rejection = pending
            .release_recipients_v1(wrong)
            .err()
            .expect("cross-output release must fail");
        assert_eq!(
            rejection.reason(),
            HostOnlyActivationReleaseErrorV1::PackageSetDigestMismatch
        );
        let (pending, _wrong) = rejection.into_parts();
        assert_eq!(pending.package_set_digest(), expected_digest);
        let retry = HostOnlyActivationRecipientReleaseEvidenceV1::for_redelivery_pending(
            &pending,
            OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new([0x33; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new([0x34; 32])
                .expect("worker delivery evidence"),
        );
        let released = pending
            .release_recipients_v1(retry)
            .expect("coherent retry succeeds");
        let redelivery = released.redeliver_v1();
        assert_eq!(redelivery.before_package_set_digest(), expected_digest);
        assert_eq!(redelivery.after_package_set_digest(), expected_digest);
        assert_zero_work(redelivery.zero_private_evaluation_work());
        let (_client, worker) = redelivery.into_released().into_capabilities();
        assert_eq!(worker.package_set_digest(), expected_digest);
    }
}
