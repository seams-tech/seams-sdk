//! Construction-independent host-only output-custody party views.
//!
//! This module composes typed output shares, committed semantic artifacts, and
//! public lifecycle projections into consuming role views. It defines no
//! production cryptography, wire format, persistence record, selected security
//! profile, or real/ideal noninterference game.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;

use crate::export_delivery::HostOnlyExportReleasedV1;
use crate::lifecycle_domain::{
    ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1, PendingActivationPreStateV1,
    UniformLifecycleAbortV1, ZeroReevaluationWitnessV1,
};
use crate::lifecycle_persistence::{
    EvaluationAbortedPersistenceProjectionV1, MetadataConsumedActivationProjectionV1,
    OutputCommittedArtifactIdentityV1,
};
use crate::semantic_artifacts::{
    ActivationOutputCommittedReceiptBodyV1, CommittedActivationArtifactsV1,
    ReleasedExportArtifactsV1,
};
use crate::{
    reconstruct_host_only_client_scalar_output_v1, reconstruct_host_only_seed_export_v1,
    reconstruct_host_only_signing_worker_scalar_output_v1, CanonicalScalarBytes,
    HostOnlyActivationOutputSharesV1, HostOnlyDeriverAActivationOutputSharesV1,
    HostOnlyDeriverASeedExportShareV1, HostOnlyDeriverBActivationOutputSharesV1,
    HostOnlyDeriverBSeedExportShareV1, SeedBytes,
};

/// Exact host-only output-view stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyOutputPartyViewStageV1 {
    /// Registration activation packages are output-committed.
    RegistrationPackagePrepared,
    /// Recovery activation packages are output-committed.
    RecoveryPackagePrepared,
    /// Refresh activation packages are output-committed.
    RefreshPackagePrepared,
    /// Fresh activation metadata was consumed without private-output work.
    ActivationMetadataConsumed,
    /// An authorized export seed was released in the host model.
    ExportReleased,
}

/// Circuit family fixed by an output-view stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyOutputPartyViewCircuitFamilyV1 {
    /// Registration, recovery, refresh, and activation use the activation family.
    Activation,
    /// Authorized export uses the export family.
    Export,
}

/// Public terminal label for a host-only output-view stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyOutputPartyViewTerminalV1 {
    /// Activation-family packages and receipt are committed.
    OutputCommitted,
    /// Activation metadata authority was consumed.
    MetadataConsumed,
    /// The export seed was released to the authorized Client view.
    ExportReleased,
}

/// Closed export state effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyExportStateEffectV1 {
    /// Export leaves the registered host state unchanged.
    RegisteredStateRetained,
}

/// Common public leakage for registration, recovery, or refresh package preparation.
#[derive(Debug, PartialEq, Eq)]
pub struct HostOnlyActivationPackagePreparedPublicLeakageV1 {
    stage: HostOnlyOutputPartyViewStageV1,
    artifacts: CommittedActivationArtifactsV1,
    identity: OutputCommittedArtifactIdentityV1,
}

impl HostOnlyActivationPackagePreparedPublicLeakageV1 {
    /// Returns the exact origin-specific package-prepared stage.
    pub const fn stage(&self) -> HostOnlyOutputPartyViewStageV1 {
        self.stage
    }

    /// Returns the full committed public package set and receipt.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        &self.artifacts
    }

    /// Returns the exact output-committed public identity.
    pub const fn identity(&self) -> OutputCommittedArtifactIdentityV1 {
        self.identity
    }
}

/// Common public leakage for activation metadata consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyActivationMetadataConsumedPublicLeakageV1 {
    projection: MetadataConsumedActivationProjectionV1,
    zero_reevaluation: ZeroReevaluationWitnessV1,
}

impl HostOnlyActivationMetadataConsumedPublicLeakageV1 {
    /// Returns the public metadata-consumed projection.
    pub const fn projection(&self) -> MetadataConsumedActivationProjectionV1 {
        self.projection
    }

    /// Returns all five zero private-work counters.
    pub const fn zero_reevaluation(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_reevaluation
    }
}

/// Common public leakage for a released export.
#[derive(Debug, PartialEq, Eq)]
pub struct HostOnlyExportReleasedPublicLeakageV1 {
    artifacts: ReleasedExportArtifactsV1,
    state_effect: HostOnlyExportStateEffectV1,
}

impl HostOnlyExportReleasedPublicLeakageV1 {
    /// Returns the full committed public export package set and receipt.
    pub const fn artifacts(&self) -> &ReleasedExportArtifactsV1 {
        &self.artifacts
    }

    /// Returns the closed registered-state effect.
    pub const fn state_effect(&self) -> HostOnlyExportStateEffectV1 {
        self.state_effect
    }
}

/// Closed common public leakage carried by every role view.
#[derive(Debug, PartialEq, Eq)]
pub enum HostOnlyCommonOutputPublicLeakageV1 {
    /// Registration, recovery, or refresh package-prepared leakage.
    ActivationPackagePrepared(Box<HostOnlyActivationPackagePreparedPublicLeakageV1>),
    /// Activation metadata-consumed leakage.
    ActivationMetadataConsumed(Box<HostOnlyActivationMetadataConsumedPublicLeakageV1>),
    /// Export-released leakage.
    ExportReleased(Box<HostOnlyExportReleasedPublicLeakageV1>),
}

impl HostOnlyCommonOutputPublicLeakageV1 {
    /// Returns the exact lifecycle stage.
    pub const fn stage(&self) -> HostOnlyOutputPartyViewStageV1 {
        match self {
            Self::ActivationPackagePrepared(leakage) => leakage.stage(),
            Self::ActivationMetadataConsumed(_) => {
                HostOnlyOutputPartyViewStageV1::ActivationMetadataConsumed
            }
            Self::ExportReleased(_) => HostOnlyOutputPartyViewStageV1::ExportReleased,
        }
    }

    /// Returns the circuit family derived from the stage.
    pub const fn circuit_family(&self) -> HostOnlyOutputPartyViewCircuitFamilyV1 {
        match self {
            Self::ActivationPackagePrepared(_) | Self::ActivationMetadataConsumed(_) => {
                HostOnlyOutputPartyViewCircuitFamilyV1::Activation
            }
            Self::ExportReleased(_) => HostOnlyOutputPartyViewCircuitFamilyV1::Export,
        }
    }

    /// Returns the public terminal label derived from the stage.
    pub const fn terminal(&self) -> HostOnlyOutputPartyViewTerminalV1 {
        match self {
            Self::ActivationPackagePrepared(_) => {
                HostOnlyOutputPartyViewTerminalV1::OutputCommitted
            }
            Self::ActivationMetadataConsumed(_) => {
                HostOnlyOutputPartyViewTerminalV1::MetadataConsumed
            }
            Self::ExportReleased(_) => HostOnlyOutputPartyViewTerminalV1::ExportReleased,
        }
    }
}

/// One public-only abort view shared by Router, observer, and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyPublicAbortViewV1 {
    abort: UniformLifecycleAbortV1,
}

impl HostOnlyPublicAbortViewV1 {
    /// Projects a redacted profile-neutral abort.
    pub const fn from_abort(abort: UniformLifecycleAbortV1) -> Self {
        Self { abort }
    }

    /// Returns the exact redacted abort envelope.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }
}

macro_rules! define_evaluator_abort_party_view {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            common: HostOnlyPublicAbortViewV1,
        }

        impl $name {
            /// Returns the exact common public abort; this view has no private extension.
            pub const fn common(&self) -> HostOnlyPublicAbortViewV1 {
                self.common
            }
        }
    };
}

define_evaluator_abort_party_view!(
    HostOnlyDeriverAEvaluatorAbortPartyViewV1,
    "Deriver A's admitted evaluator-abort view with no new private output."
);
define_evaluator_abort_party_view!(
    HostOnlyDeriverBEvaluatorAbortPartyViewV1,
    "Deriver B's admitted evaluator-abort view with no new private output."
);
define_evaluator_abort_party_view!(
    HostOnlyClientEvaluatorAbortPartyViewV1,
    "Client's admitted evaluator-abort view with no scalar or seed output."
);
define_evaluator_abort_party_view!(
    HostOnlySigningWorkerEvaluatorAbortPartyViewV1,
    "SigningWorker's admitted evaluator-abort view with no private output."
);
define_evaluator_abort_party_view!(
    HostOnlyRouterEvaluatorAbortPartyViewV1,
    "Router's public-only admitted evaluator-abort view."
);
define_evaluator_abort_party_view!(
    HostOnlyObserverEvaluatorAbortPartyViewV1,
    "Observer's public-only admitted evaluator-abort view."
);
define_evaluator_abort_party_view!(
    HostOnlyDiagnosticsEvaluatorAbortPartyViewV1,
    "Diagnostics' public-only admitted evaluator-abort view."
);

/// Validated common-only party-view set for one admitted evaluator abort.
pub struct HostOnlyEvaluatorAbortPartyViewSetV1 {
    common: HostOnlyPublicAbortViewV1,
}

impl HostOnlyEvaluatorAbortPartyViewSetV1 {
    /// Consumes the set into Deriver A's common-only abort view.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverAEvaluatorAbortPartyViewV1 {
        HostOnlyDeriverAEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into Deriver B's common-only abort view.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBEvaluatorAbortPartyViewV1 {
        HostOnlyDeriverBEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the Client's common-only abort view.
    pub fn observe_client_v1(self) -> HostOnlyClientEvaluatorAbortPartyViewV1 {
        HostOnlyClientEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the SigningWorker's common-only abort view.
    pub fn observe_signing_worker_v1(self) -> HostOnlySigningWorkerEvaluatorAbortPartyViewV1 {
        HostOnlySigningWorkerEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the Router's common-only abort view.
    pub fn observe_router_v1(self) -> HostOnlyRouterEvaluatorAbortPartyViewV1 {
        HostOnlyRouterEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the observer's common-only abort view.
    pub fn observe_observer_v1(self) -> HostOnlyObserverEvaluatorAbortPartyViewV1 {
        HostOnlyObserverEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into diagnostics' common-only abort view.
    pub fn observe_diagnostics_v1(self) -> HostOnlyDiagnosticsEvaluatorAbortPartyViewV1 {
        HostOnlyDiagnosticsEvaluatorAbortPartyViewV1 {
            common: self.common,
        }
    }
}

/// Projects an admitted evaluator abort into seven common-only role views.
pub(crate) fn build_host_only_evaluator_abort_party_view_set_v1(
    projection: &EvaluationAbortedPersistenceProjectionV1,
) -> HostOnlyEvaluatorAbortPartyViewSetV1 {
    HostOnlyEvaluatorAbortPartyViewSetV1 {
        common: HostOnlyPublicAbortViewV1::from_abort(projection.abort()),
    }
}

/// Failure while validating a private host aggregate against committed public artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyOutputPartyViewErrorV1 {
    /// Deriver A's Client share does not match its committed descriptor point.
    ActivationDeriverAClientSharePointMismatch,
    /// Deriver B's Client share does not match its committed descriptor point.
    ActivationDeriverBClientSharePointMismatch,
    /// Deriver A's SigningWorker share does not match its committed descriptor point.
    ActivationDeriverASigningWorkerSharePointMismatch,
    /// Deriver B's SigningWorker share does not match its committed descriptor point.
    ActivationDeriverBSigningWorkerSharePointMismatch,
    /// Reconstructed Client scalar does not match the public Client point.
    ActivationClientPointMismatch,
    /// Reconstructed SigningWorker scalar does not match the public SigningWorker point.
    ActivationSigningWorkerPointMismatch,
    /// The joined public points do not reconstruct the registered public key.
    ActivationRegisteredPublicKeyRelationMismatch,
    /// Activation metadata consumption reported new private-output work.
    ActivationMetadataPerformedPrivateWork,
    /// Reconstructed export seed does not derive the receipt's registered public key.
    ExportRegisteredPublicKeyMismatch,
}

impl fmt::Display for HostOnlyOutputPartyViewErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ActivationDeriverAClientSharePointMismatch => {
                "Deriver A Client share must match its committed descriptor point"
            }
            Self::ActivationDeriverBClientSharePointMismatch => {
                "Deriver B Client share must match its committed descriptor point"
            }
            Self::ActivationDeriverASigningWorkerSharePointMismatch => {
                "Deriver A SigningWorker share must match its committed descriptor point"
            }
            Self::ActivationDeriverBSigningWorkerSharePointMismatch => {
                "Deriver B SigningWorker share must match its committed descriptor point"
            }
            Self::ActivationClientPointMismatch => {
                "reconstructed Client scalar must match the committed Client point"
            }
            Self::ActivationSigningWorkerPointMismatch => {
                "reconstructed SigningWorker scalar must match the committed SigningWorker point"
            }
            Self::ActivationRegisteredPublicKeyRelationMismatch => {
                "committed points must reconstruct the registered public key"
            }
            Self::ActivationMetadataPerformedPrivateWork => {
                "activation metadata consumption must perform zero private-output work"
            }
            Self::ExportRegisteredPublicKeyMismatch => {
                "reconstructed export seed must derive the registered public key"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HostOnlyOutputPartyViewErrorV1 {}

/// Deriver A's package-prepared activation output view.
pub struct HostOnlyDeriverAActivationOutputPartyViewV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    shares: HostOnlyDeriverAActivationOutputSharesV1,
}

impl HostOnlyDeriverAActivationOutputPartyViewV1 {
    /// Returns the common public leakage.
    pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
        &self.common
    }

    /// Returns only Deriver A's two activation scalar shares.
    pub const fn output_shares(&self) -> &HostOnlyDeriverAActivationOutputSharesV1 {
        &self.shares
    }
}

/// Deriver B's package-prepared activation output view.
pub struct HostOnlyDeriverBActivationOutputPartyViewV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    shares: HostOnlyDeriverBActivationOutputSharesV1,
}

impl HostOnlyDeriverBActivationOutputPartyViewV1 {
    /// Returns the common public leakage.
    pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
        &self.common
    }

    /// Returns only Deriver B's two activation scalar shares.
    pub const fn output_shares(&self) -> &HostOnlyDeriverBActivationOutputSharesV1 {
        &self.shares
    }
}

/// Client's package-prepared activation output view.
pub struct HostOnlyClientActivationOutputPartyViewV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
}

impl HostOnlyClientActivationOutputPartyViewV1 {
    /// Returns the common public leakage.
    pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
        &self.common
    }
}

macro_rules! define_empty_party_view {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            common: HostOnlyCommonOutputPublicLeakageV1,
        }

        impl $name {
            /// Returns the common public leakage; this view has no private extension.
            pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
                &self.common
            }
        }
    };
}

define_empty_party_view!(
    HostOnlySigningWorkerActivationPackagePreparedPartyViewV1,
    "SigningWorker's package-prepared view with no clear scalar output."
);
define_empty_party_view!(
    HostOnlyRouterActivationPackagePreparedPartyViewV1,
    "Router's public-only package-prepared view."
);
define_empty_party_view!(
    HostOnlyObserverActivationPackagePreparedPartyViewV1,
    "Observer's public-only package-prepared view."
);
define_empty_party_view!(
    HostOnlyDiagnosticsActivationPackagePreparedPartyViewV1,
    "Diagnostics' public-only package-prepared view."
);

/// Private validated activation package-prepared aggregate.
pub struct HostOnlyActivationPackagePreparedPartyViewSetV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    deriver_a: HostOnlyDeriverAActivationOutputSharesV1,
    deriver_b: HostOnlyDeriverBActivationOutputSharesV1,
}

impl HostOnlyActivationPackagePreparedPartyViewSetV1 {
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn semantic_trace_identity_v1(
        &self,
    ) -> (ActivationPackageOriginV1, [u8; 32], [u8; 32]) {
        match &self.common {
            HostOnlyCommonOutputPublicLeakageV1::ActivationPackagePrepared(leakage) => (
                leakage.artifacts().binding().origin(),
                *leakage.artifacts().packages().digest().as_bytes(),
                *leakage.artifacts().receipt().digest().as_bytes(),
            ),
            _ => unreachable!("activation package view has activation-package leakage"),
        }
    }

    /// Consumes the validated set into Deriver A's static observation.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverAActivationOutputPartyViewV1 {
        HostOnlyDeriverAActivationOutputPartyViewV1 {
            common: self.common,
            shares: self.deriver_a,
        }
    }

    /// Consumes the validated set into Deriver B's static observation.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBActivationOutputPartyViewV1 {
        HostOnlyDeriverBActivationOutputPartyViewV1 {
            common: self.common,
            shares: self.deriver_b,
        }
    }

    /// Consumes the validated set into the Client observation.
    pub fn observe_client_v1(self) -> HostOnlyClientActivationOutputPartyViewV1 {
        HostOnlyClientActivationOutputPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the empty SigningWorker observation.
    pub fn observe_signing_worker_v1(
        self,
    ) -> HostOnlySigningWorkerActivationPackagePreparedPartyViewV1 {
        HostOnlySigningWorkerActivationPackagePreparedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the Router observation.
    pub fn observe_router_v1(self) -> HostOnlyRouterActivationPackagePreparedPartyViewV1 {
        HostOnlyRouterActivationPackagePreparedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the public observer observation.
    pub fn observe_observer_v1(self) -> HostOnlyObserverActivationPackagePreparedPartyViewV1 {
        HostOnlyObserverActivationPackagePreparedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the diagnostics observation.
    pub fn observe_diagnostics_v1(self) -> HostOnlyDiagnosticsActivationPackagePreparedPartyViewV1 {
        HostOnlyDiagnosticsActivationPackagePreparedPartyViewV1 {
            common: self.common,
        }
    }
}

define_empty_party_view!(
    HostOnlyDeriverAActivationMetadataConsumedPartyViewV1,
    "Deriver A's metadata-consumed view with no new private output."
);
define_empty_party_view!(
    HostOnlyDeriverBActivationMetadataConsumedPartyViewV1,
    "Deriver B's metadata-consumed view with no new private output."
);
define_empty_party_view!(
    HostOnlyClientActivationMetadataConsumedPartyViewV1,
    "Client's metadata-consumed view with no new private output."
);
define_empty_party_view!(
    HostOnlySigningWorkerActivationMetadataConsumedPartyViewV1,
    "SigningWorker's metadata-consumed view with no clear scalar output."
);
define_empty_party_view!(
    HostOnlyRouterActivationMetadataConsumedPartyViewV1,
    "Router's public-only metadata-consumed view."
);
define_empty_party_view!(
    HostOnlyObserverActivationMetadataConsumedPartyViewV1,
    "Observer's public-only metadata-consumed view."
);
define_empty_party_view!(
    HostOnlyDiagnosticsActivationMetadataConsumedPartyViewV1,
    "Diagnostics' public-only metadata-consumed view."
);

/// Private validated activation metadata-consumed aggregate.
pub struct HostOnlyActivationMetadataConsumedPartyViewSetV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
}

impl HostOnlyActivationMetadataConsumedPartyViewSetV1 {
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn semantic_trace_identity_v1(
        &self,
    ) -> (ActivationPackageOriginV1, [u8; 32], [u8; 32]) {
        match &self.common {
            HostOnlyCommonOutputPublicLeakageV1::ActivationMetadataConsumed(leakage) => {
                let identity = leakage.projection().committed().identity();
                (
                    identity.origin(),
                    *identity.package_set_digest().as_bytes(),
                    *identity.receipt_digest().as_bytes(),
                )
            }
            _ => unreachable!("metadata-consumed view has metadata leakage"),
        }
    }

    /// Consumes the validated set into Deriver A's empty observation.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverAActivationMetadataConsumedPartyViewV1 {
        HostOnlyDeriverAActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into Deriver B's empty observation.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBActivationMetadataConsumedPartyViewV1 {
        HostOnlyDeriverBActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the Client's empty observation.
    pub fn observe_client_v1(self) -> HostOnlyClientActivationMetadataConsumedPartyViewV1 {
        HostOnlyClientActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the SigningWorker's empty observation.
    pub fn observe_signing_worker_v1(
        self,
    ) -> HostOnlySigningWorkerActivationMetadataConsumedPartyViewV1 {
        HostOnlySigningWorkerActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the Router observation.
    pub fn observe_router_v1(self) -> HostOnlyRouterActivationMetadataConsumedPartyViewV1 {
        HostOnlyRouterActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the public observer observation.
    pub fn observe_observer_v1(self) -> HostOnlyObserverActivationMetadataConsumedPartyViewV1 {
        HostOnlyObserverActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the diagnostics observation.
    pub fn observe_diagnostics_v1(
        self,
    ) -> HostOnlyDiagnosticsActivationMetadataConsumedPartyViewV1 {
        HostOnlyDiagnosticsActivationMetadataConsumedPartyViewV1 {
            common: self.common,
        }
    }
}

/// Deriver A's export-released output view.
pub struct HostOnlyDeriverAExportOutputPartyViewV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    seed_share: HostOnlyDeriverASeedExportShareV1,
}

impl HostOnlyDeriverAExportOutputPartyViewV1 {
    /// Returns the common public leakage.
    pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
        &self.common
    }

    /// Returns only Deriver A's export seed share.
    pub const fn seed_share(&self) -> &HostOnlyDeriverASeedExportShareV1 {
        &self.seed_share
    }
}

/// Deriver B's export-released output view.
pub struct HostOnlyDeriverBExportOutputPartyViewV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    seed_share: HostOnlyDeriverBSeedExportShareV1,
}

impl HostOnlyDeriverBExportOutputPartyViewV1 {
    /// Returns the common public leakage.
    pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
        &self.common
    }

    /// Returns only Deriver B's export seed share.
    pub const fn seed_share(&self) -> &HostOnlyDeriverBSeedExportShareV1 {
        &self.seed_share
    }
}

/// Client's authorized export-released output view.
pub struct HostOnlyClientExportOutputPartyViewV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    seed: SeedBytes,
}

impl HostOnlyClientExportOutputPartyViewV1 {
    /// Returns the common public leakage.
    pub const fn common(&self) -> &HostOnlyCommonOutputPublicLeakageV1 {
        &self.common
    }

    /// Returns the authorized reconstructed RFC 8032 seed.
    pub const fn seed(&self) -> &SeedBytes {
        &self.seed
    }
}

define_empty_party_view!(
    HostOnlySigningWorkerExportReleasedPartyViewV1,
    "SigningWorker's export-released view with no eligible output."
);
define_empty_party_view!(
    HostOnlyRouterExportReleasedPartyViewV1,
    "Router's public-only export-released view."
);
define_empty_party_view!(
    HostOnlyObserverExportReleasedPartyViewV1,
    "Observer's public-only export-released view."
);
define_empty_party_view!(
    HostOnlyDiagnosticsExportReleasedPartyViewV1,
    "Diagnostics' public-only export-released view."
);

/// Private validated export-released aggregate.
pub struct HostOnlyExportReleasedPartyViewSetV1 {
    common: HostOnlyCommonOutputPublicLeakageV1,
    deriver_a: HostOnlyDeriverASeedExportShareV1,
    deriver_b: HostOnlyDeriverBSeedExportShareV1,
    client: SeedBytes,
}

impl HostOnlyExportReleasedPartyViewSetV1 {
    /// Consumes the validated set into Deriver A's static observation.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverAExportOutputPartyViewV1 {
        HostOnlyDeriverAExportOutputPartyViewV1 {
            common: self.common,
            seed_share: self.deriver_a,
        }
    }

    /// Consumes the validated set into Deriver B's static observation.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBExportOutputPartyViewV1 {
        HostOnlyDeriverBExportOutputPartyViewV1 {
            common: self.common,
            seed_share: self.deriver_b,
        }
    }

    /// Consumes the validated set into the authorized Client observation.
    pub fn observe_client_v1(self) -> HostOnlyClientExportOutputPartyViewV1 {
        HostOnlyClientExportOutputPartyViewV1 {
            common: self.common,
            seed: self.client,
        }
    }

    /// Consumes the validated set into the ineligible SigningWorker observation.
    pub fn observe_signing_worker_v1(self) -> HostOnlySigningWorkerExportReleasedPartyViewV1 {
        HostOnlySigningWorkerExportReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the Router observation.
    pub fn observe_router_v1(self) -> HostOnlyRouterExportReleasedPartyViewV1 {
        HostOnlyRouterExportReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the public observer observation.
    pub fn observe_observer_v1(self) -> HostOnlyObserverExportReleasedPartyViewV1 {
        HostOnlyObserverExportReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the validated set into the diagnostics observation.
    pub fn observe_diagnostics_v1(self) -> HostOnlyDiagnosticsExportReleasedPartyViewV1 {
        HostOnlyDiagnosticsExportReleasedPartyViewV1 {
            common: self.common,
        }
    }
}

pub(crate) fn build_host_only_activation_package_prepared_party_view_set_v1(
    pending: PendingActivationPreStateV1,
) -> Result<HostOnlyActivationPackagePreparedPartyViewSetV1, HostOnlyOutputPartyViewErrorV1> {
    let (artifacts, shares) = pending.into_committed_output().into_parts();
    validate_activation_share_points(&artifacts, &shares)?;

    let client = reconstruct_host_only_client_scalar_output_v1(
        shares.deriver_a().client(),
        shares.deriver_b().client(),
    );
    let signing_worker = reconstruct_host_only_signing_worker_scalar_output_v1(
        shares.deriver_a().signing_worker(),
        shares.deriver_b().signing_worker(),
    );
    validate_activation_joined_relations(artifacts.receipt(), &client, &signing_worker)?;

    let identity = OutputCommittedArtifactIdentityV1::from_binding(
        artifacts.binding(),
        artifacts.receipt().digest(),
    );
    let stage = package_prepared_stage(artifacts.binding().origin());
    let common = HostOnlyCommonOutputPublicLeakageV1::ActivationPackagePrepared(Box::new(
        HostOnlyActivationPackagePreparedPublicLeakageV1 {
            stage,
            artifacts,
            identity,
        },
    ));
    let (deriver_a, deriver_b) = shares.into_role_shares();

    Ok(HostOnlyActivationPackagePreparedPartyViewSetV1 {
        common,
        deriver_a,
        deriver_b,
    })
}

pub(crate) fn build_host_only_activation_metadata_consumed_party_view_set_v1(
    success: &ActivationMetadataConsumptionSuccessV1,
) -> Result<HostOnlyActivationMetadataConsumedPartyViewSetV1, HostOnlyOutputPartyViewErrorV1> {
    let zero_reevaluation = success.zero_reevaluation();
    if has_private_output_work(zero_reevaluation) {
        return Err(HostOnlyOutputPartyViewErrorV1::ActivationMetadataPerformedPrivateWork);
    }
    let projection = MetadataConsumedActivationProjectionV1::from_success(success);
    let common = HostOnlyCommonOutputPublicLeakageV1::ActivationMetadataConsumed(Box::new(
        HostOnlyActivationMetadataConsumedPublicLeakageV1 {
            projection,
            zero_reevaluation,
        },
    ));
    Ok(HostOnlyActivationMetadataConsumedPartyViewSetV1 { common })
}

pub(crate) fn build_host_only_export_released_party_view_set_v1(
    released: HostOnlyExportReleasedV1,
) -> Result<HostOnlyExportReleasedPartyViewSetV1, HostOnlyOutputPartyViewErrorV1> {
    let (_state, artifacts, shares, _consumed_authorization) = released.into_parts();
    let client = reconstruct_host_only_seed_export_v1(shares.deriver_a(), shares.deriver_b());
    let public_key = SigningKey::from_bytes(&client.expose_bytes())
        .verifying_key()
        .to_bytes();
    if public_key != *artifacts.receipt().registered_public_key().as_bytes() {
        return Err(HostOnlyOutputPartyViewErrorV1::ExportRegisteredPublicKeyMismatch);
    }

    let common = HostOnlyCommonOutputPublicLeakageV1::ExportReleased(Box::new(
        HostOnlyExportReleasedPublicLeakageV1 {
            artifacts,
            state_effect: HostOnlyExportStateEffectV1::RegisteredStateRetained,
        },
    ));
    let (deriver_a, deriver_b) = shares.into_role_shares();
    Ok(HostOnlyExportReleasedPartyViewSetV1 {
        common,
        deriver_a,
        deriver_b,
        client,
    })
}

fn package_prepared_stage(origin: ActivationPackageOriginV1) -> HostOnlyOutputPartyViewStageV1 {
    match origin {
        ActivationPackageOriginV1::Registration => {
            HostOnlyOutputPartyViewStageV1::RegistrationPackagePrepared
        }
        ActivationPackageOriginV1::Recovery => {
            HostOnlyOutputPartyViewStageV1::RecoveryPackagePrepared
        }
        ActivationPackageOriginV1::Refresh => {
            HostOnlyOutputPartyViewStageV1::RefreshPackagePrepared
        }
    }
}

fn validate_activation_share_points(
    artifacts: &CommittedActivationArtifactsV1,
    shares: &HostOnlyActivationOutputSharesV1,
) -> Result<(), HostOnlyOutputPartyViewErrorV1> {
    let packages = artifacts.packages();
    for (actual, expected, error) in [
        (
            scalar_share_point(shares.deriver_a().client().expose_fixture_bytes()),
            packages.deriver_a_client().scalar_share_point(),
            HostOnlyOutputPartyViewErrorV1::ActivationDeriverAClientSharePointMismatch,
        ),
        (
            scalar_share_point(shares.deriver_b().client().expose_fixture_bytes()),
            packages.deriver_b_client().scalar_share_point(),
            HostOnlyOutputPartyViewErrorV1::ActivationDeriverBClientSharePointMismatch,
        ),
        (
            scalar_share_point(shares.deriver_a().signing_worker().expose_fixture_bytes()),
            packages.deriver_a_signing_worker().scalar_share_point(),
            HostOnlyOutputPartyViewErrorV1::ActivationDeriverASigningWorkerSharePointMismatch,
        ),
        (
            scalar_share_point(shares.deriver_b().signing_worker().expose_fixture_bytes()),
            packages.deriver_b_signing_worker().scalar_share_point(),
            HostOnlyOutputPartyViewErrorV1::ActivationDeriverBSigningWorkerSharePointMismatch,
        ),
    ] {
        if actual != *expected {
            return Err(error);
        }
    }
    Ok(())
}

fn validate_activation_joined_relations(
    receipt: &ActivationOutputCommittedReceiptBodyV1,
    client: &CanonicalScalarBytes,
    signing_worker: &CanonicalScalarBytes,
) -> Result<(), HostOnlyOutputPartyViewErrorV1> {
    let client_point = scalar_share_point(client.expose_bytes());
    if client_point != *receipt.x_client() {
        return Err(HostOnlyOutputPartyViewErrorV1::ActivationClientPointMismatch);
    }
    let signing_worker_point = scalar_share_point(signing_worker.expose_bytes());
    if signing_worker_point != *receipt.x_server() {
        return Err(HostOnlyOutputPartyViewErrorV1::ActivationSigningWorkerPointMismatch);
    }

    let client_point = canonical_scalar(client.expose_bytes());
    let signing_worker_point = canonical_scalar(signing_worker.expose_bytes());
    let registered_public_key = (ED25519_BASEPOINT_POINT
        * (client_point + client_point - signing_worker_point))
        .compress()
        .to_bytes();
    if registered_public_key != *receipt.registered_public_key().as_bytes() {
        return Err(HostOnlyOutputPartyViewErrorV1::ActivationRegisteredPublicKeyRelationMismatch);
    }
    Ok(())
}

fn scalar_share_point(bytes: [u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * canonical_scalar(bytes))
        .compress()
        .to_bytes()
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("typed host-only scalar must remain canonical")
}

fn has_private_output_work(witness: ZeroReevaluationWitnessV1) -> bool {
    witness.yao_evaluations() != 0
        || witness.deriver_a_invocations() != 0
        || witness.deriver_b_invocations() != 0
        || witness.contribution_derivations() != 0
        || witness.output_share_samples() != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony_context::{
        CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1,
        CeremonyAuthorizationRecordDigest32V1, CeremonyReplayNonce32V1, CeremonyRequestExpiryV1,
        CeremonyRequestIdV1, CeremonyTranscriptNonce32V1, CeremonyTransportBindingDigest32V1,
    };
    use crate::evaluate_full_clear_reference_export_v1;
    use crate::lifecycle_domain::{
        consume_activation_metadata_v1, ActivationControlFreshFieldsV1,
        ActivationReceiptEvidenceV1, ActivationRequestV1, PendingActivationPreStateV1,
        RegistrationArtifactIssuanceV1, RegistrationRequestV1,
    };
    use crate::semantic_artifacts::{
        OneUseExecutionId32V1, OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    };
    use crate::semantic_artifacts_tests::{provenance_pair, registration_ceremony};
    use crate::semantic_fixture_material::{
        activation_bindings, reference_fixture, registration_admission, registration_ideal_coins,
        registration_inputs,
    };
    use crate::semantic_lifecycle_fixtures::canonical_export_released_v1;

    fn activation_receipt_evidence() -> ActivationReceiptEvidenceV1 {
        ActivationReceiptEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x92; 32])
                .expect("A receipt evidence"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x93; 32])
                .expect("B receipt evidence"),
        )
    }

    fn pending_activation(
        client_coin: u64,
        signing_worker_coin: u64,
    ) -> PendingActivationPreStateV1 {
        let fixture = reference_fixture();
        let (request_context, authorization, transcript) = registration_ceremony("party-views");
        let request = RegistrationRequestV1::new(request_context, authorization, transcript)
            .expect("registration request");
        let provenance = provenance_pair(request.validated_dag(), None);
        let activation_epoch = CeremonyActivationEpochV1::new(7).expect("activation epoch");
        let execution_id = OneUseExecutionId32V1::new([0xa1; 32]).expect("one-use execution id");
        let admission =
            registration_admission(&request, &provenance, activation_epoch, execution_id);
        let session = request
            .begin_host_reference_artifact_session(
                RegistrationArtifactIssuanceV1::new(activation_epoch, execution_id, admission),
                &provenance,
            )
            .expect("registration session");
        let pending = session
            .evaluate_and_commit_host_reference(
                registration_inputs(&fixture),
                registration_ideal_coins(client_coin, signing_worker_coin),
                activation_bindings(),
                activation_receipt_evidence(),
            )
            .expect("pending activation");
        PendingActivationPreStateV1::Registration(Box::new(pending))
    }

    fn metadata_success() -> ActivationMetadataConsumptionSuccessV1 {
        let pending = pending_activation(3, 5);
        let fresh = ActivationControlFreshFieldsV1::new(
            CeremonyRequestIdV1::parse("party-view-activation").expect("request id"),
            CeremonyReplayNonce32V1::new([0xf1; 32]),
            CeremonyRequestExpiryV1::new(20_001).expect("expiry"),
            CeremonyAuthorizationRecordDigest32V1::new([0xb1; 32]).expect("authorization record"),
            CeremonyTranscriptNonce32V1::new([0xf2; 32]),
            CeremonyTransportBindingDigest32V1::new([0xb2; 32]).expect("transport binding"),
            CeremonyArtifactSuiteDigest32V1::new([0xb3; 32]).expect("artifact suite"),
        );
        let request = ActivationRequestV1::new(fresh, pending).expect("fresh activation metadata");
        consume_activation_metadata_v1(request)
    }

    fn scalar_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn validated_activation_views() -> HostOnlyActivationPackagePreparedPartyViewSetV1 {
        build_host_only_activation_package_prepared_party_view_set_v1(pending_activation(3, 5))
            .expect("validated activation views")
    }

    fn validated_metadata_views() -> HostOnlyActivationMetadataConsumedPartyViewSetV1 {
        build_host_only_activation_metadata_consumed_party_view_set_v1(&metadata_success())
            .expect("validated metadata views")
    }

    fn validated_export_views() -> HostOnlyExportReleasedPartyViewSetV1 {
        build_host_only_export_released_party_view_set_v1(canonical_export_released_v1())
            .expect("validated export views")
    }

    #[test]
    fn activation_views_share_exact_public_leakage_and_isolate_private_extensions() {
        let client =
            build_host_only_activation_package_prepared_party_view_set_v1(pending_activation(3, 5))
                .expect("validated activation views")
                .observe_client_v1();
        assert_eq!(
            client.common().stage(),
            HostOnlyOutputPartyViewStageV1::RegistrationPackagePrepared
        );
        assert_eq!(
            client.common().circuit_family(),
            HostOnlyOutputPartyViewCircuitFamilyV1::Activation
        );
        assert_eq!(
            client.common().terminal(),
            HostOnlyOutputPartyViewTerminalV1::OutputCommitted
        );

        let deriver_a =
            build_host_only_activation_package_prepared_party_view_set_v1(pending_activation(3, 5))
                .expect("validated activation views")
                .observe_deriver_a_v1();
        assert_eq!(
            deriver_a.output_shares().client().expose_fixture_bytes(),
            scalar_bytes(3)
        );
        assert_eq!(client.common(), deriver_a.common());

        let router =
            build_host_only_activation_package_prepared_party_view_set_v1(pending_activation(3, 5))
                .expect("validated activation views")
                .observe_router_v1();
        assert_eq!(client.common(), router.common());
        let deriver_b = validated_activation_views().observe_deriver_b_v1();
        let signing_worker = validated_activation_views().observe_signing_worker_v1();
        let observer = validated_activation_views().observe_observer_v1();
        let diagnostics = validated_activation_views().observe_diagnostics_v1();
        assert_eq!(client.common(), deriver_b.common());
        assert_eq!(client.common(), signing_worker.common());
        assert_eq!(client.common(), observer.common());
        assert_eq!(client.common(), diagnostics.common());
    }

    #[test]
    fn metadata_consumption_projects_equal_public_views_and_zero_private_work() {
        let success = metadata_success();
        let signing_worker =
            build_host_only_activation_metadata_consumed_party_view_set_v1(&success)
                .expect("metadata view")
                .observe_signing_worker_v1();
        assert_eq!(
            signing_worker.common().stage(),
            HostOnlyOutputPartyViewStageV1::ActivationMetadataConsumed
        );
        let leakage = match signing_worker.common() {
            HostOnlyCommonOutputPublicLeakageV1::ActivationMetadataConsumed(leakage) => leakage,
            _ => panic!("metadata stage projected a different leakage branch"),
        };
        assert!(!has_private_output_work(leakage.zero_reevaluation()));

        let success = metadata_success();
        let observer = build_host_only_activation_metadata_consumed_party_view_set_v1(&success)
            .expect("metadata view")
            .observe_observer_v1();
        assert_eq!(signing_worker.common(), observer.common());
        let deriver_a = validated_metadata_views().observe_deriver_a_v1();
        let deriver_b = validated_metadata_views().observe_deriver_b_v1();
        let client = validated_metadata_views().observe_client_v1();
        let router = validated_metadata_views().observe_router_v1();
        let diagnostics = validated_metadata_views().observe_diagnostics_v1();
        assert_eq!(signing_worker.common(), deriver_a.common());
        assert_eq!(signing_worker.common(), deriver_b.common());
        assert_eq!(signing_worker.common(), client.common());
        assert_eq!(signing_worker.common(), router.common());
        assert_eq!(signing_worker.common(), diagnostics.common());
    }

    #[test]
    fn export_views_release_only_the_authorized_client_seed() {
        let fixture = reference_fixture();
        let expected_seed =
            evaluate_full_clear_reference_export_v1(&fixture.deriver_a, &fixture.deriver_b)
                .seed()
                .expose_bytes();
        let client = validated_export_views().observe_client_v1();
        assert_eq!(client.seed().expose_bytes(), expected_seed);
        assert_eq!(
            client.common().stage(),
            HostOnlyOutputPartyViewStageV1::ExportReleased
        );
        assert_eq!(
            client.common().circuit_family(),
            HostOnlyOutputPartyViewCircuitFamilyV1::Export
        );

        let deriver_a = validated_export_views().observe_deriver_a_v1();
        assert_eq!(client.common(), deriver_a.common());
        let deriver_b = validated_export_views().observe_deriver_b_v1();
        let signing_worker = validated_export_views().observe_signing_worker_v1();
        let router = validated_export_views().observe_router_v1();
        let observer = validated_export_views().observe_observer_v1();
        let diagnostics = validated_export_views().observe_diagnostics_v1();
        assert_eq!(client.common(), deriver_b.common());
        assert_eq!(client.common(), signing_worker.common());
        assert_eq!(client.common(), router.common());
        assert_eq!(client.common(), observer.common());
        assert_eq!(client.common(), diagnostics.common());
    }
}
