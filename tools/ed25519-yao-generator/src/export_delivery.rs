//! Construction-independent host-only export release and redelivery semantics.
//!
//! This module retains the exact output shares produced with one committed
//! package set until Client release. It defines no ciphertext opener, network
//! frame, durable transaction, timing claim, or selected P0-P3 mechanism.

use core::fmt;

use crate::authenticated_store::AuthenticatedRegisteredStoreResolutionV1;
use crate::lifecycle_domain::{
    ExportRequestV1, HostOnlyExportOutputCommittedV1, ZeroReevaluationWitnessV1,
};
use crate::semantic_artifacts::{
    ExportPackageSetDigest32V1, ExportReleasedReceiptDigest32V1,
    OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceConsumedExportAuthorizationDigest32V1, OutputCommittedExportArtifactsV1,
    ReleasedExportArtifactsV1,
};
use crate::HostOnlySeedExportSharesV1;

/// Client-release evidence bound to one exact output-committed package set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyExportClientReleaseEvidenceV1 {
    package_set_digest: ExportPackageSetDigest32V1,
    client_delivery_evidence: OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
    consumed_authorization: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
}

impl HostOnlyExportClientReleaseEvidenceV1 {
    /// Binds release evidence to one output-committed export.
    pub fn for_output_committed(
        committed: &HostOnlyExportOutputCommittedV1,
        client_delivery_evidence: OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
        consumed_authorization: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    ) -> Self {
        Self {
            package_set_digest: committed.artifacts().packages().digest(),
            client_delivery_evidence,
            consumed_authorization,
        }
    }

    /// Binds retry evidence to one exact delivery-uncertain export.
    pub fn for_redelivery_pending(
        pending: &HostOnlyExportRedeliveryPendingV1,
        client_delivery_evidence: OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
        consumed_authorization: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    ) -> Self {
        Self {
            package_set_digest: pending.package_set_digest(),
            client_delivery_evidence,
            consumed_authorization,
        }
    }
}

/// Reason an export release was rejected before authorization consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyExportReleaseErrorV1 {
    /// Evidence was bound to another output-committed package set.
    PackageSetDigestMismatch,
}

impl fmt::Display for HostOnlyExportReleaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageSetDigestMismatch => {
                formatter.write_str("client release evidence names another export package set")
            }
        }
    }
}

impl std::error::Error for HostOnlyExportReleaseErrorV1 {}

struct HostOnlyExportReleaseReadyV1 {
    request: crate::lifecycle_domain::ExportRequestV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    artifacts: OutputCommittedExportArtifactsV1,
    shares: HostOnlySeedExportSharesV1,
}

impl HostOnlyExportReleaseReadyV1 {
    fn from_output_committed(committed: HostOnlyExportOutputCommittedV1) -> Self {
        let (request, state, artifacts, shares) = committed.into_parts();
        Self {
            request,
            state,
            artifacts,
            shares,
        }
    }

    fn package_set_digest(&self) -> ExportPackageSetDigest32V1 {
        self.artifacts.packages().digest()
    }
}

/// Delivery-uncertain export retaining the exact committed packages and shares.
pub struct HostOnlyExportRedeliveryPendingV1(HostOnlyExportReleaseReadyV1);

impl HostOnlyExportRedeliveryPendingV1 {
    /// Returns the package-set identity that every retry must preserve.
    pub fn package_set_digest(&self) -> ExportPackageSetDigest32V1 {
        self.0.package_set_digest()
    }

    /// Returns the zero private-evaluation work witness for entering uncertainty.
    pub const fn zero_private_evaluation_work(&self) -> ZeroReevaluationWitnessV1 {
        ZeroReevaluationWitnessV1::no_private_evaluation_work()
    }

    /// Retries release without reevaluating or replacing shares.
    pub fn release_v1(
        self,
        evidence: HostOnlyExportClientReleaseEvidenceV1,
    ) -> Result<HostOnlyExportReleasedV1, RejectedHostOnlyExportReleaseV1> {
        release_ready(self.0, evidence)
    }
}

/// Rejected release retaining the complete exact redelivery state and evidence.
pub struct RejectedHostOnlyExportReleaseV1 {
    reason: HostOnlyExportReleaseErrorV1,
    pending: Box<HostOnlyExportRedeliveryPendingV1>,
    evidence: HostOnlyExportClientReleaseEvidenceV1,
}

impl RejectedHostOnlyExportReleaseV1 {
    /// Returns the public rejection reason.
    pub const fn reason(&self) -> HostOnlyExportReleaseErrorV1 {
        self.reason
    }

    /// Recovers the exact pending state and rejected evidence.
    pub fn into_parts(
        self,
    ) -> (
        HostOnlyExportRedeliveryPendingV1,
        HostOnlyExportClientReleaseEvidenceV1,
    ) {
        (*self.pending, self.evidence)
    }
}

impl fmt::Debug for RejectedHostOnlyExportReleaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedHostOnlyExportReleaseV1")
            .field("reason", &self.reason)
            .field("pending", &"retained")
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Non-callable audit identity proving export authorization was consumed at release.
pub struct HostOnlyConsumedExportAuthorizationV1 {
    request: ExportRequestV1,
    evidence_digest: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
}

impl HostOnlyConsumedExportAuthorizationV1 {
    /// Returns the consumed, non-callable export request for audit projection.
    pub const fn request(&self) -> &ExportRequestV1 {
        &self.request
    }

    /// Returns the opaque consumption/replay evidence slot.
    pub const fn evidence_digest(
        &self,
    ) -> OpaqueHostReferenceConsumedExportAuthorizationDigest32V1 {
        self.evidence_digest
    }
}

/// Export state after Client release and authorization consumption.
pub struct HostOnlyExportReleasedV1 {
    state: AuthenticatedRegisteredStoreResolutionV1,
    artifacts: ReleasedExportArtifactsV1,
    shares: HostOnlySeedExportSharesV1,
    consumed_authorization: HostOnlyConsumedExportAuthorizationV1,
    zero_private_evaluation_work: ZeroReevaluationWitnessV1,
}

impl HostOnlyExportReleasedV1 {
    /// Returns the unchanged registered state.
    pub const fn state(&self) -> &AuthenticatedRegisteredStoreResolutionV1 {
        &self.state
    }

    /// Returns the exact output-committed and released receipts.
    pub const fn artifacts(&self) -> &ReleasedExportArtifactsV1 {
        &self.artifacts
    }

    /// Returns the consumed authorization audit identity.
    pub const fn consumed_authorization(&self) -> &HostOnlyConsumedExportAuthorizationV1 {
        &self.consumed_authorization
    }

    /// Returns the zero private-evaluation work witness for first release.
    pub const fn zero_private_evaluation_work(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_private_evaluation_work
    }

    /// Models exact-identity redelivery as a released-state self-loop.
    pub fn redeliver_v1(self) -> HostOnlyExportRedeliveryV1 {
        let digest = self.artifacts.receipt().digest();
        HostOnlyExportRedeliveryV1 {
            released: self,
            before_receipt_digest: digest,
            after_receipt_digest: digest,
            zero_private_evaluation_work: ZeroReevaluationWitnessV1::no_private_evaluation_work(),
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AuthenticatedRegisteredStoreResolutionV1,
        ReleasedExportArtifactsV1,
        HostOnlySeedExportSharesV1,
        HostOnlyConsumedExportAuthorizationV1,
    ) {
        (
            self.state,
            self.artifacts,
            self.shares,
            self.consumed_authorization,
        )
    }
}

/// Exact released-state self-loop produced by a redelivery attempt.
pub struct HostOnlyExportRedeliveryV1 {
    released: HostOnlyExportReleasedV1,
    before_receipt_digest: ExportReleasedReceiptDigest32V1,
    after_receipt_digest: ExportReleasedReceiptDigest32V1,
    zero_private_evaluation_work: ZeroReevaluationWitnessV1,
}

impl HostOnlyExportRedeliveryV1 {
    /// Returns the released receipt identity before redelivery.
    pub const fn before_receipt_digest(&self) -> ExportReleasedReceiptDigest32V1 {
        self.before_receipt_digest
    }

    /// Returns the identical released receipt identity after redelivery.
    pub const fn after_receipt_digest(&self) -> ExportReleasedReceiptDigest32V1 {
        self.after_receipt_digest
    }

    /// Returns the zero private-evaluation work witness for redelivery.
    pub const fn zero_private_evaluation_work(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_private_evaluation_work
    }

    /// Recovers the unchanged released state.
    pub fn into_released(self) -> HostOnlyExportReleasedV1 {
        self.released
    }
}

impl HostOnlyExportOutputCommittedV1 {
    /// Records delivery uncertainty while retaining exact packages, shares, and authorization.
    pub fn delivery_uncertain_v1(self) -> HostOnlyExportRedeliveryPendingV1 {
        HostOnlyExportRedeliveryPendingV1(HostOnlyExportReleaseReadyV1::from_output_committed(self))
    }

    /// Releases the exact retained export output and consumes authorization.
    pub fn release_v1(
        self,
        evidence: HostOnlyExportClientReleaseEvidenceV1,
    ) -> Result<HostOnlyExportReleasedV1, RejectedHostOnlyExportReleaseV1> {
        release_ready(
            HostOnlyExportReleaseReadyV1::from_output_committed(self),
            evidence,
        )
    }
}

fn release_ready(
    ready: HostOnlyExportReleaseReadyV1,
    evidence: HostOnlyExportClientReleaseEvidenceV1,
) -> Result<HostOnlyExportReleasedV1, RejectedHostOnlyExportReleaseV1> {
    if evidence.package_set_digest != ready.package_set_digest() {
        return Err(RejectedHostOnlyExportReleaseV1 {
            reason: HostOnlyExportReleaseErrorV1::PackageSetDigestMismatch,
            pending: Box::new(HostOnlyExportRedeliveryPendingV1(ready)),
            evidence,
        });
    }
    let consumed_authorization = HostOnlyConsumedExportAuthorizationV1 {
        request: ready.request,
        evidence_digest: evidence.consumed_authorization,
    };
    Ok(HostOnlyExportReleasedV1 {
        state: ready.state,
        artifacts: ready.artifacts.into_released(
            evidence.client_delivery_evidence,
            evidence.consumed_authorization,
        ),
        shares: ready.shares,
        consumed_authorization,
        zero_private_evaluation_work: ZeroReevaluationWitnessV1::no_private_evaluation_work(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate_full_clear_reference_export_v1;
    use crate::output_party_views::build_host_only_export_released_party_view_set_v1;
    use crate::semantic_artifacts::{
        OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
        OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    };
    use crate::semantic_fixture_material::reference_fixture;
    use crate::semantic_lifecycle_fixtures::canonical_export_output_committed_v1;

    fn release_evidence(
        committed: &HostOnlyExportOutputCommittedV1,
    ) -> HostOnlyExportClientReleaseEvidenceV1 {
        HostOnlyExportClientReleaseEvidenceV1::for_output_committed(
            committed,
            OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0xd1; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0xd2; 32])
                .expect("consumed authorization evidence"),
        )
    }

    fn assert_zero_private_evaluation_work(witness: ZeroReevaluationWitnessV1) {
        assert_eq!(witness.yao_evaluations(), 0);
        assert_eq!(witness.deriver_a_invocations(), 0);
        assert_eq!(witness.deriver_b_invocations(), 0);
        assert_eq!(witness.contribution_derivations(), 0);
        assert_eq!(witness.output_share_samples(), 0);
    }

    #[test]
    fn release_consumes_authorization_after_commit_and_delivers_the_retained_seed() {
        let committed = canonical_export_output_committed_v1();
        let state_version = committed.state().active_state_version();
        let request_digest = committed.request().validated_dag().request_context_digest();
        let evidence = release_evidence(&committed);
        let released = committed.release_v1(evidence).expect("release succeeds");
        assert_eq!(released.state().active_state_version(), state_version);
        assert_eq!(
            released
                .consumed_authorization()
                .request()
                .validated_dag()
                .request_context_digest(),
            request_digest
        );
        assert_zero_private_evaluation_work(released.zero_private_evaluation_work());

        let fixture = reference_fixture();
        let expected_seed =
            evaluate_full_clear_reference_export_v1(&fixture.deriver_a, &fixture.deriver_b)
                .seed()
                .expose_bytes();
        let client = build_host_only_export_released_party_view_set_v1(released)
            .expect("released view is coherent")
            .observe_client_v1();
        assert_eq!(client.seed().expose_bytes(), expected_seed);
    }

    #[test]
    fn delivery_uncertainty_retains_exact_package_identity_for_retry() {
        let committed = canonical_export_output_committed_v1();
        let expected_digest = committed.artifacts().packages().digest();
        let pending = committed.delivery_uncertain_v1();
        assert_eq!(pending.package_set_digest(), expected_digest);
        let evidence = HostOnlyExportClientReleaseEvidenceV1::for_redelivery_pending(
            &pending,
            OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0xd3; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0xd4; 32])
                .expect("consumed authorization evidence"),
        );
        let released = pending
            .release_v1(evidence)
            .expect("retry release succeeds");
        assert_eq!(released.artifacts().packages().digest(), expected_digest);
    }

    #[test]
    fn cross_commitment_release_evidence_is_rejected_without_losing_retry_state() {
        let committed = canonical_export_output_committed_v1();
        let mut evidence = release_evidence(&committed);
        evidence.package_set_digest = ExportPackageSetDigest32V1::from_fixture_bytes([0xe1; 32]);
        let rejection = committed
            .release_v1(evidence)
            .err()
            .expect("cross-commitment evidence must fail");
        assert_eq!(
            rejection.reason(),
            HostOnlyExportReleaseErrorV1::PackageSetDigestMismatch
        );
        let (pending, _evidence) = rejection.into_parts();
        let retry = HostOnlyExportClientReleaseEvidenceV1::for_redelivery_pending(
            &pending,
            OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0xe2; 32])
                .expect("client delivery evidence"),
            OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0xe3; 32])
                .expect("consumed authorization evidence"),
        );
        pending.release_v1(retry).expect("coherent retry succeeds");
    }

    #[test]
    fn redelivery_is_an_exact_released_state_self_loop_with_zero_private_work() {
        let committed = canonical_export_output_committed_v1();
        let evidence = release_evidence(&committed);
        let released = committed.release_v1(evidence).expect("release succeeds");
        let before = released.artifacts().receipt().digest();
        let redelivery = released.redeliver_v1();
        assert_eq!(redelivery.before_receipt_digest(), before);
        assert_eq!(redelivery.after_receipt_digest(), before);
        assert_zero_private_evaluation_work(redelivery.zero_private_evaluation_work());
        assert_eq!(
            redelivery.into_released().artifacts().receipt().digest(),
            before
        );
    }
}
