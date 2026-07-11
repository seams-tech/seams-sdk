//! Construction-independent host-only evaluation-input custody views.
//!
//! These types project validated public ceremony/provenance bindings and
//! public synthetic role inputs into one static party observation. They define
//! no production protocol, wire format, protocol randomness, frame, entropy
//! source, durable transition, or real/ideal security claim.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use crate::ceremony_context::{
    CeremonyAuthorizationDigest32V1, CeremonyPublicRequestContextDigest32V1,
    CeremonyTranscriptDigest32V1, CeremonyValidatedDagV1,
};
use crate::lifecycle_domain::{
    ActivationRequestV1, ExportRequestV1, RecoveryRequestV1, RefreshRequestV1,
    RegistrationRequestV1,
};
use crate::provenance::{
    ProvenanceEncodingErrorV1, ProvenanceRequestKindV1, RoleInputProvenancePairDigest32V1,
    RoleInputProvenancePairV1,
};
use crate::{
    DeriverAClientY, DeriverAContribution, DeriverAServerY, DeriverBClientY, DeriverBContribution,
    DeriverBServerY, HostOnlyActivationNoIdealCoinsV1, HostOnlyPreparedExportReferenceV1,
    HostOnlyPreparedRecoveryReferenceV1, HostOnlyPreparedRefreshReferenceV1,
    HostOnlyPreparedRegistrationReferenceV1, RawDeriverAContribution, RawDeriverBContribution,
};

/// Exact host-only evaluation-input custody stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyEvaluationInputStageV1 {
    /// Registration input admission accepted one activation-family evaluation.
    RegistrationEvaluationAccepted,
    /// Activation continuation accepted a metadata-only zero-evaluation step.
    ActivationContinuationAccepted,
    /// Recovery input admission accepted one activation-family evaluation.
    RecoveryEvaluationAccepted,
    /// Refresh input admission accepted one activation-family evaluation.
    RefreshEvaluationAccepted,
    /// Export input admission accepted one export-family evaluation.
    ExportEvaluationAccepted,
}

impl HostOnlyEvaluationInputStageV1 {
    /// Returns the frozen snake-case stage label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistrationEvaluationAccepted => "registration_evaluation_accepted",
            Self::ActivationContinuationAccepted => "activation_continuation_accepted",
            Self::RecoveryEvaluationAccepted => "recovery_evaluation_accepted",
            Self::RefreshEvaluationAccepted => "refresh_evaluation_accepted",
            Self::ExportEvaluationAccepted => "export_evaluation_accepted",
        }
    }
}

/// Construction-independent evaluator plan fixed by a lifecycle branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyEvaluationPlanV1 {
    /// Exactly one activation-family ideal evaluation.
    OneActivationEvaluation,
    /// Metadata/control continuation with no private evaluation work.
    ZeroEvaluationContinuation,
    /// Exactly one export-family ideal evaluation.
    OneExportEvaluation,
}

impl HostOnlyEvaluationPlanV1 {
    /// Returns the frozen snake-case plan label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneActivationEvaluation => "one_activation_evaluation",
            Self::ZeroEvaluationContinuation => "zero_evaluation_continuation",
            Self::OneExportEvaluation => "one_export_evaluation",
        }
    }
}

/// Typed evaluator-window operation counts derived from the fixed plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyEvaluationWindowCountsV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    ideal_output_share_samples: u8,
}

impl HostOnlyEvaluationWindowCountsV1 {
    const ONE_ACTIVATION: Self = Self {
        yao_evaluations: 1,
        deriver_a_invocations: 1,
        deriver_b_invocations: 1,
        contribution_derivations: 0,
        ideal_output_share_samples: 2,
    };
    const ZERO_CONTINUATION: Self = Self {
        yao_evaluations: 0,
        deriver_a_invocations: 0,
        deriver_b_invocations: 0,
        contribution_derivations: 0,
        ideal_output_share_samples: 0,
    };
    const ONE_EXPORT: Self = Self {
        yao_evaluations: 1,
        deriver_a_invocations: 1,
        deriver_b_invocations: 1,
        contribution_derivations: 0,
        ideal_output_share_samples: 1,
    };

    /// Returns the exact number of ideal Yao evaluations in the evaluator window.
    pub const fn yao_evaluations(self) -> u8 {
        self.yao_evaluations
    }

    /// Returns the exact number of Deriver A invocations in the evaluator window.
    pub const fn deriver_a_invocations(self) -> u8 {
        self.deriver_a_invocations
    }

    /// Returns the exact number of Deriver B invocations in the evaluator window.
    pub const fn deriver_b_invocations(self) -> u8 {
        self.deriver_b_invocations
    }

    /// Returns the exact number of contribution derivations in the evaluator window.
    pub const fn contribution_derivations(self) -> u8 {
        self.contribution_derivations
    }

    /// Returns the exact number of ideal-function output-share samples.
    pub const fn ideal_output_share_samples(self) -> u8 {
        self.ideal_output_share_samples
    }
}

/// Public extension-kind label for a static party observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyEvaluationInputExtensionKindV1 {
    /// Deriver A's four activation-family contribution fields.
    DeriverAActivationEvaluationInputs,
    /// Deriver B's four activation-family contribution fields.
    DeriverBActivationEvaluationInputs,
    /// Deriver A's two export-family seed contribution fields.
    DeriverAExportEvaluationInputs,
    /// Deriver B's two export-family seed contribution fields.
    DeriverBExportEvaluationInputs,
    /// Empty Deriver A extension.
    DeriverAEmpty,
    /// Empty Deriver B extension.
    DeriverBEmpty,
    /// Empty Client extension.
    ClientEmpty,
    /// Empty SigningWorker extension.
    SigningWorkerEmpty,
    /// Empty Router extension.
    RouterEmpty,
    /// Empty public-observer extension.
    ObserverEmpty,
    /// Empty diagnostics extension.
    DiagnosticsEmpty,
}

impl HostOnlyEvaluationInputExtensionKindV1 {
    /// Returns the frozen snake-case extension-kind label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeriverAActivationEvaluationInputs => "deriver_a_activation_evaluation_inputs",
            Self::DeriverBActivationEvaluationInputs => "deriver_b_activation_evaluation_inputs",
            Self::DeriverAExportEvaluationInputs => "deriver_a_export_evaluation_inputs",
            Self::DeriverBExportEvaluationInputs => "deriver_b_export_evaluation_inputs",
            Self::DeriverAEmpty => "deriver_a_empty",
            Self::DeriverBEmpty => "deriver_b_empty",
            Self::ClientEmpty => "client_empty",
            Self::SigningWorkerEmpty => "signing_worker_empty",
            Self::RouterEmpty => "router_empty",
            Self::ObserverEmpty => "observer_empty",
            Self::DiagnosticsEmpty => "diagnostics_empty",
        }
    }
}

/// Failure while binding a sealed ceremony to an ordered provenance pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyEvaluationInputViewErrorV1 {
    /// The provenance request branch differs from the sealed ceremony branch.
    ProvenanceRequestKindMismatch,
    /// Provenance names another public request-context digest.
    RequestContextDigestMismatch,
    /// Provenance names another authorization digest.
    AuthorizationDigestMismatch,
    /// Provenance names another transcript digest.
    TranscriptDigestMismatch,
    /// Canonical provenance-pair hashing failed.
    ProvenanceEncoding(ProvenanceEncodingErrorV1),
}

impl fmt::Display for HostOnlyEvaluationInputViewErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProvenanceRequestKindMismatch => {
                "provenance request kind must match the sealed ceremony branch"
            }
            Self::RequestContextDigestMismatch => {
                "provenance request-context digest must match the sealed ceremony"
            }
            Self::AuthorizationDigestMismatch => {
                "provenance authorization digest must match the sealed ceremony"
            }
            Self::TranscriptDigestMismatch => {
                "provenance transcript digest must match the sealed ceremony"
            }
            Self::ProvenanceEncoding(_) => "canonical provenance-pair hashing failed",
        })
    }
}

impl std::error::Error for HostOnlyEvaluationInputViewErrorV1 {}

impl From<ProvenanceEncodingErrorV1> for HostOnlyEvaluationInputViewErrorV1 {
    fn from(error: ProvenanceEncodingErrorV1) -> Self {
        Self::ProvenanceEncoding(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatedEvaluationBindingV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_digest: CeremonyAuthorizationDigest32V1,
    transcript_digest: CeremonyTranscriptDigest32V1,
    provenance_pair_digest: RoleInputProvenancePairDigest32V1,
}

macro_rules! define_evaluation_common {
    ($name:ident, $documentation:literal, $stage:ident, $plan:ident, $counts:ident) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            request_context_digest: CeremonyPublicRequestContextDigest32V1,
            authorization_digest: CeremonyAuthorizationDigest32V1,
            transcript_digest: CeremonyTranscriptDigest32V1,
            provenance_pair_digest: RoleInputProvenancePairDigest32V1,
        }

        impl $name {
            fn from_validated(binding: ValidatedEvaluationBindingV1) -> Self {
                Self {
                    request_context_digest: binding.request_context_digest,
                    authorization_digest: binding.authorization_digest,
                    transcript_digest: binding.transcript_digest,
                    provenance_pair_digest: binding.provenance_pair_digest,
                }
            }

            /// Returns the exact lifecycle stage.
            pub const fn stage(&self) -> HostOnlyEvaluationInputStageV1 {
                HostOnlyEvaluationInputStageV1::$stage
            }

            /// Returns the exact ideal evaluation plan.
            pub const fn evaluation_plan(&self) -> HostOnlyEvaluationPlanV1 {
                HostOnlyEvaluationPlanV1::$plan
            }

            /// Returns evaluator-window counts derived from the fixed plan.
            pub const fn evaluation_counts(&self) -> HostOnlyEvaluationWindowCountsV1 {
                HostOnlyEvaluationWindowCountsV1::$counts
            }

            /// Returns the sealed public request-context digest.
            pub const fn request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
                self.request_context_digest
            }

            /// Returns the sealed authorization digest.
            pub const fn authorization_digest(&self) -> CeremonyAuthorizationDigest32V1 {
                self.authorization_digest
            }

            /// Returns the sealed transcript digest.
            pub const fn transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
                self.transcript_digest
            }

            /// Returns the ordered A/B provenance-pair digest.
            pub const fn provenance_pair_digest(&self) -> RoleInputProvenancePairDigest32V1 {
                self.provenance_pair_digest
            }
        }
    };
}

define_evaluation_common!(
    HostOnlyRegistrationEvaluationInputCommonV1,
    "Common public registration evaluation-input binding.",
    RegistrationEvaluationAccepted,
    OneActivationEvaluation,
    ONE_ACTIVATION
);
define_evaluation_common!(
    HostOnlyRecoveryEvaluationInputCommonV1,
    "Common public recovery evaluation-input binding.",
    RecoveryEvaluationAccepted,
    OneActivationEvaluation,
    ONE_ACTIVATION
);
define_evaluation_common!(
    HostOnlyRefreshEvaluationInputCommonV1,
    "Common public refresh evaluation-input binding.",
    RefreshEvaluationAccepted,
    OneActivationEvaluation,
    ONE_ACTIVATION
);
define_evaluation_common!(
    HostOnlyExportEvaluationInputCommonV1,
    "Common public export evaluation-input binding.",
    ExportEvaluationAccepted,
    OneExportEvaluation,
    ONE_EXPORT
);

/// Common public activation-continuation ceremony binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyActivationContinuationInputCommonV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_digest: CeremonyAuthorizationDigest32V1,
    transcript_digest: CeremonyTranscriptDigest32V1,
}

impl HostOnlyActivationContinuationInputCommonV1 {
    fn from_dag(dag: CeremonyValidatedDagV1) -> Self {
        Self {
            request_context_digest: dag.request_context_digest(),
            authorization_digest: dag.authorization_digest(),
            transcript_digest: dag.transcript_digest(),
        }
    }

    /// Returns the exact activation-continuation stage.
    pub const fn stage(&self) -> HostOnlyEvaluationInputStageV1 {
        HostOnlyEvaluationInputStageV1::ActivationContinuationAccepted
    }

    /// Returns the zero-evaluation continuation plan.
    pub const fn evaluation_plan(&self) -> HostOnlyEvaluationPlanV1 {
        HostOnlyEvaluationPlanV1::ZeroEvaluationContinuation
    }

    /// Returns the all-zero evaluator-window witness.
    pub const fn evaluation_counts(&self) -> HostOnlyEvaluationWindowCountsV1 {
        HostOnlyEvaluationWindowCountsV1::ZERO_CONTINUATION
    }

    /// Returns the sealed public request-context digest.
    pub const fn request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
        self.request_context_digest
    }

    /// Returns the sealed authorization digest.
    pub const fn authorization_digest(&self) -> CeremonyAuthorizationDigest32V1 {
        self.authorization_digest
    }

    /// Returns the sealed transcript digest.
    pub const fn transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
        self.transcript_digest
    }
}

/// Deriver A's four-field activation-family evaluation-input observation.
pub struct HostOnlyDeriverAActivationEvaluationInputViewV1<Common> {
    common: Common,
    contribution: DeriverAContribution,
}

impl<Common> HostOnlyDeriverAActivationEvaluationInputViewV1<Common> {
    /// Returns the common public branch binding.
    pub const fn common(&self) -> &Common {
        &self.common
    }

    /// Returns the fixed role-extension kind.
    pub const fn kind(&self) -> HostOnlyEvaluationInputExtensionKindV1 {
        HostOnlyEvaluationInputExtensionKindV1::DeriverAActivationEvaluationInputs
    }

    /// Returns only Deriver A's four validated contribution fields.
    pub const fn contribution(&self) -> &DeriverAContribution {
        &self.contribution
    }
}

/// Deriver B's four-field activation-family evaluation-input observation.
pub struct HostOnlyDeriverBActivationEvaluationInputViewV1<Common> {
    common: Common,
    contribution: DeriverBContribution,
}

impl<Common> HostOnlyDeriverBActivationEvaluationInputViewV1<Common> {
    /// Returns the common public branch binding.
    pub const fn common(&self) -> &Common {
        &self.common
    }

    /// Returns the fixed role-extension kind.
    pub const fn kind(&self) -> HostOnlyEvaluationInputExtensionKindV1 {
        HostOnlyEvaluationInputExtensionKindV1::DeriverBActivationEvaluationInputs
    }

    /// Returns only Deriver B's four validated contribution fields.
    pub const fn contribution(&self) -> &DeriverBContribution {
        &self.contribution
    }
}

/// Deriver A's y-only export evaluation-input observation.
pub struct HostOnlyDeriverAExportEvaluationInputViewV1 {
    common: HostOnlyExportEvaluationInputCommonV1,
    y_client: DeriverAClientY,
    y_server: DeriverAServerY,
}

impl HostOnlyDeriverAExportEvaluationInputViewV1 {
    /// Returns the common public export binding.
    pub const fn common(&self) -> &HostOnlyExportEvaluationInputCommonV1 {
        &self.common
    }

    /// Returns the fixed role-extension kind.
    pub const fn kind(&self) -> HostOnlyEvaluationInputExtensionKindV1 {
        HostOnlyEvaluationInputExtensionKindV1::DeriverAExportEvaluationInputs
    }

    /// Returns Deriver A's client-labelled seed contribution.
    pub const fn y_client(&self) -> &DeriverAClientY {
        &self.y_client
    }

    /// Returns Deriver A's server-labelled seed contribution.
    pub const fn y_server(&self) -> &DeriverAServerY {
        &self.y_server
    }
}

/// Deriver B's y-only export evaluation-input observation.
pub struct HostOnlyDeriverBExportEvaluationInputViewV1 {
    common: HostOnlyExportEvaluationInputCommonV1,
    y_client: DeriverBClientY,
    y_server: DeriverBServerY,
}

impl HostOnlyDeriverBExportEvaluationInputViewV1 {
    /// Returns the common public export binding.
    pub const fn common(&self) -> &HostOnlyExportEvaluationInputCommonV1 {
        &self.common
    }

    /// Returns the fixed role-extension kind.
    pub const fn kind(&self) -> HostOnlyEvaluationInputExtensionKindV1 {
        HostOnlyEvaluationInputExtensionKindV1::DeriverBExportEvaluationInputs
    }

    /// Returns Deriver B's client-labelled seed contribution.
    pub const fn y_client(&self) -> &DeriverBClientY {
        &self.y_client
    }

    /// Returns Deriver B's server-labelled seed contribution.
    pub const fn y_server(&self) -> &DeriverBServerY {
        &self.y_server
    }
}

macro_rules! define_empty_evaluation_input_view {
    ($name:ident, $documentation:literal, $kind:ident) => {
        #[doc = $documentation]
        pub struct $name<Common> {
            common: Common,
        }

        impl<Common> $name<Common> {
            /// Returns the common public branch binding; there is no private extension.
            pub const fn common(&self) -> &Common {
                &self.common
            }

            /// Returns the fixed empty role-extension kind.
            pub const fn kind(&self) -> HostOnlyEvaluationInputExtensionKindV1 {
                HostOnlyEvaluationInputExtensionKindV1::$kind
            }
        }
    };
}

define_empty_evaluation_input_view!(
    HostOnlyDeriverAEmptyEvaluationInputViewV1,
    "Deriver A's empty evaluation-input observation.",
    DeriverAEmpty
);
define_empty_evaluation_input_view!(
    HostOnlyDeriverBEmptyEvaluationInputViewV1,
    "Deriver B's empty evaluation-input observation.",
    DeriverBEmpty
);
define_empty_evaluation_input_view!(
    HostOnlyClientEmptyEvaluationInputViewV1,
    "Client evaluation-input observation with no private extension.",
    ClientEmpty
);
define_empty_evaluation_input_view!(
    HostOnlySigningWorkerEmptyEvaluationInputViewV1,
    "SigningWorker evaluation-input observation with no private extension.",
    SigningWorkerEmpty
);
define_empty_evaluation_input_view!(
    HostOnlyRouterEmptyEvaluationInputViewV1,
    "Router evaluation-input observation with no private extension.",
    RouterEmpty
);
define_empty_evaluation_input_view!(
    HostOnlyObserverEmptyEvaluationInputViewV1,
    "Public-observer evaluation-input observation with no private extension.",
    ObserverEmpty
);
define_empty_evaluation_input_view!(
    HostOnlyDiagnosticsEmptyEvaluationInputViewV1,
    "Diagnostics evaluation-input observation with no private extension.",
    DiagnosticsEmpty
);

macro_rules! define_activation_evaluation_set {
    ($name:ident, $common:ty, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            common: $common,
            deriver_a: DeriverAContribution,
            deriver_b: DeriverBContribution,
        }

        impl $name {
            /// Consumes the validated set into Deriver A's static observation.
            pub fn observe_deriver_a_v1(
                self,
            ) -> HostOnlyDeriverAActivationEvaluationInputViewV1<$common> {
                HostOnlyDeriverAActivationEvaluationInputViewV1 {
                    common: self.common,
                    contribution: self.deriver_a,
                }
            }

            /// Consumes the validated set into Deriver B's static observation.
            pub fn observe_deriver_b_v1(
                self,
            ) -> HostOnlyDeriverBActivationEvaluationInputViewV1<$common> {
                HostOnlyDeriverBActivationEvaluationInputViewV1 {
                    common: self.common,
                    contribution: self.deriver_b,
                }
            }

            /// Consumes the validated set into the Client's empty observation.
            pub fn observe_client_v1(self) -> HostOnlyClientEmptyEvaluationInputViewV1<$common> {
                HostOnlyClientEmptyEvaluationInputViewV1 {
                    common: self.common,
                }
            }

            /// Consumes the validated set into the SigningWorker's empty observation.
            pub fn observe_signing_worker_v1(
                self,
            ) -> HostOnlySigningWorkerEmptyEvaluationInputViewV1<$common> {
                HostOnlySigningWorkerEmptyEvaluationInputViewV1 {
                    common: self.common,
                }
            }

            /// Consumes the validated set into the Router's empty observation.
            pub fn observe_router_v1(self) -> HostOnlyRouterEmptyEvaluationInputViewV1<$common> {
                HostOnlyRouterEmptyEvaluationInputViewV1 {
                    common: self.common,
                }
            }

            /// Consumes the validated set into the public observer's empty observation.
            pub fn observe_observer_v1(
                self,
            ) -> HostOnlyObserverEmptyEvaluationInputViewV1<$common> {
                HostOnlyObserverEmptyEvaluationInputViewV1 {
                    common: self.common,
                }
            }

            /// Consumes the validated set into diagnostics' empty observation.
            pub fn observe_diagnostics_v1(
                self,
            ) -> HostOnlyDiagnosticsEmptyEvaluationInputViewV1<$common> {
                HostOnlyDiagnosticsEmptyEvaluationInputViewV1 {
                    common: self.common,
                }
            }
        }
    };
}

define_activation_evaluation_set!(
    HostOnlyRegistrationEvaluationInputViewSetV1,
    HostOnlyRegistrationEvaluationInputCommonV1,
    "Validated host-only registration evaluation-input custody set."
);
define_activation_evaluation_set!(
    HostOnlyRecoveryEvaluationInputViewSetV1,
    HostOnlyRecoveryEvaluationInputCommonV1,
    "Validated host-only recovery evaluation-input custody set."
);
define_activation_evaluation_set!(
    HostOnlyRefreshEvaluationInputViewSetV1,
    HostOnlyRefreshEvaluationInputCommonV1,
    "Validated host-only refresh evaluation-input custody set."
);

/// Validated metadata-only activation-continuation input custody set.
pub struct HostOnlyActivationContinuationInputViewSetV1 {
    common: HostOnlyActivationContinuationInputCommonV1,
}

macro_rules! activation_empty_projection {
    ($method:ident, $view:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub fn $method(self) -> $view<HostOnlyActivationContinuationInputCommonV1> {
            $view {
                common: self.common,
            }
        }
    };
}

impl HostOnlyActivationContinuationInputViewSetV1 {
    activation_empty_projection!(
        observe_deriver_a_v1,
        HostOnlyDeriverAEmptyEvaluationInputViewV1,
        "Consumes the set into Deriver A's empty observation."
    );
    activation_empty_projection!(
        observe_deriver_b_v1,
        HostOnlyDeriverBEmptyEvaluationInputViewV1,
        "Consumes the set into Deriver B's empty observation."
    );
    activation_empty_projection!(
        observe_client_v1,
        HostOnlyClientEmptyEvaluationInputViewV1,
        "Consumes the set into the Client's empty observation."
    );
    activation_empty_projection!(
        observe_signing_worker_v1,
        HostOnlySigningWorkerEmptyEvaluationInputViewV1,
        "Consumes the set into the SigningWorker's empty observation."
    );
    activation_empty_projection!(
        observe_router_v1,
        HostOnlyRouterEmptyEvaluationInputViewV1,
        "Consumes the set into the Router's empty observation."
    );
    activation_empty_projection!(
        observe_observer_v1,
        HostOnlyObserverEmptyEvaluationInputViewV1,
        "Consumes the set into the public observer's empty observation."
    );
    activation_empty_projection!(
        observe_diagnostics_v1,
        HostOnlyDiagnosticsEmptyEvaluationInputViewV1,
        "Consumes the set into diagnostics' empty observation."
    );
}

/// Validated y-only export evaluation-input custody set.
pub struct HostOnlyExportEvaluationInputViewSetV1 {
    common: HostOnlyExportEvaluationInputCommonV1,
    deriver_a_y_client: DeriverAClientY,
    deriver_a_y_server: DeriverAServerY,
    deriver_b_y_client: DeriverBClientY,
    deriver_b_y_server: DeriverBServerY,
}

impl HostOnlyExportEvaluationInputViewSetV1 {
    /// Consumes the set into Deriver A's y-only observation.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverAExportEvaluationInputViewV1 {
        HostOnlyDeriverAExportEvaluationInputViewV1 {
            common: self.common,
            y_client: self.deriver_a_y_client,
            y_server: self.deriver_a_y_server,
        }
    }

    /// Consumes the set into Deriver B's y-only observation.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBExportEvaluationInputViewV1 {
        HostOnlyDeriverBExportEvaluationInputViewV1 {
            common: self.common,
            y_client: self.deriver_b_y_client,
            y_server: self.deriver_b_y_server,
        }
    }

    /// Consumes the set into the Client's empty observation.
    pub fn observe_client_v1(
        self,
    ) -> HostOnlyClientEmptyEvaluationInputViewV1<HostOnlyExportEvaluationInputCommonV1> {
        HostOnlyClientEmptyEvaluationInputViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the SigningWorker's empty observation.
    pub fn observe_signing_worker_v1(
        self,
    ) -> HostOnlySigningWorkerEmptyEvaluationInputViewV1<HostOnlyExportEvaluationInputCommonV1>
    {
        HostOnlySigningWorkerEmptyEvaluationInputViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the Router's empty observation.
    pub fn observe_router_v1(
        self,
    ) -> HostOnlyRouterEmptyEvaluationInputViewV1<HostOnlyExportEvaluationInputCommonV1> {
        HostOnlyRouterEmptyEvaluationInputViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the public observer's empty observation.
    pub fn observe_observer_v1(
        self,
    ) -> HostOnlyObserverEmptyEvaluationInputViewV1<HostOnlyExportEvaluationInputCommonV1> {
        HostOnlyObserverEmptyEvaluationInputViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into diagnostics' empty observation.
    pub fn observe_diagnostics_v1(
        self,
    ) -> HostOnlyDiagnosticsEmptyEvaluationInputViewV1<HostOnlyExportEvaluationInputCommonV1> {
        HostOnlyDiagnosticsEmptyEvaluationInputViewV1 {
            common: self.common,
        }
    }
}

/// Builds a validated registration input-custody set from public synthetic host inputs.
pub fn build_host_only_registration_evaluation_input_view_set_v1(
    request: &RegistrationRequestV1,
    provenance: &RoleInputProvenancePairV1,
    prepared: &HostOnlyPreparedRegistrationReferenceV1,
) -> Result<HostOnlyRegistrationEvaluationInputViewSetV1, HostOnlyEvaluationInputViewErrorV1> {
    let common = HostOnlyRegistrationEvaluationInputCommonV1::from_validated(
        validate_evaluation_binding(request.validated_dag(), provenance)?,
    );
    Ok(HostOnlyRegistrationEvaluationInputViewSetV1 {
        common,
        deriver_a: copy_deriver_a_contribution(prepared.deriver_a()),
        deriver_b: copy_deriver_b_contribution(prepared.deriver_b()),
    })
}

/// Builds an all-empty activation-continuation input-custody set.
pub fn build_host_only_activation_continuation_input_view_set_v1(
    request: &ActivationRequestV1,
    no_ideal_coins: HostOnlyActivationNoIdealCoinsV1,
) -> HostOnlyActivationContinuationInputViewSetV1 {
    no_ideal_coins.into_zero_coin_witness();
    HostOnlyActivationContinuationInputViewSetV1 {
        common: HostOnlyActivationContinuationInputCommonV1::from_dag(request.validated_dag()),
    }
}

/// Builds a validated recovery input-custody set from public synthetic host inputs.
pub fn build_host_only_recovery_evaluation_input_view_set_v1(
    request: &RecoveryRequestV1,
    provenance: &RoleInputProvenancePairV1,
    prepared: &HostOnlyPreparedRecoveryReferenceV1,
) -> Result<HostOnlyRecoveryEvaluationInputViewSetV1, HostOnlyEvaluationInputViewErrorV1> {
    let common = HostOnlyRecoveryEvaluationInputCommonV1::from_validated(
        validate_evaluation_binding(request.validated_dag(), provenance)?,
    );
    Ok(HostOnlyRecoveryEvaluationInputViewSetV1 {
        common,
        deriver_a: copy_deriver_a_contribution(prepared.recovered_deriver_a()),
        deriver_b: copy_deriver_b_contribution(prepared.recovered_deriver_b()),
    })
}

/// Builds a validated refresh input-custody set from public synthetic host inputs.
pub fn build_host_only_refresh_evaluation_input_view_set_v1(
    request: &RefreshRequestV1,
    provenance: &RoleInputProvenancePairV1,
    prepared: &HostOnlyPreparedRefreshReferenceV1,
) -> Result<HostOnlyRefreshEvaluationInputViewSetV1, HostOnlyEvaluationInputViewErrorV1> {
    let common = HostOnlyRefreshEvaluationInputCommonV1::from_validated(
        validate_evaluation_binding(request.validated_dag(), provenance)?,
    );
    Ok(HostOnlyRefreshEvaluationInputViewSetV1 {
        common,
        deriver_a: copy_deriver_a_contribution(prepared.refreshed_deriver_a()),
        deriver_b: copy_deriver_b_contribution(prepared.refreshed_deriver_b()),
    })
}

/// Builds a validated y-only export input-custody set from public synthetic host inputs.
pub fn build_host_only_export_evaluation_input_view_set_v1(
    request: &ExportRequestV1,
    provenance: &RoleInputProvenancePairV1,
    prepared: &HostOnlyPreparedExportReferenceV1,
) -> Result<HostOnlyExportEvaluationInputViewSetV1, HostOnlyEvaluationInputViewErrorV1> {
    let common = HostOnlyExportEvaluationInputCommonV1::from_validated(
        validate_evaluation_binding(request.validated_dag(), provenance)?,
    );
    Ok(HostOnlyExportEvaluationInputViewSetV1 {
        common,
        deriver_a_y_client: DeriverAClientY(prepared.deriver_a_y_client_fixture_bytes()),
        deriver_a_y_server: DeriverAServerY(prepared.deriver_a_y_server_fixture_bytes()),
        deriver_b_y_client: DeriverBClientY(prepared.deriver_b_y_client_fixture_bytes()),
        deriver_b_y_server: DeriverBServerY(prepared.deriver_b_y_server_fixture_bytes()),
    })
}

fn copy_deriver_a_contribution(source: &DeriverAContribution) -> DeriverAContribution {
    DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: source.y_client().expose_bytes(),
        y_server: source.y_server().expose_bytes(),
        tau_client: source.tau_client().expose_bytes(),
        tau_server: source.tau_server().expose_bytes(),
    })
    .expect("validated host-only Deriver A contribution must remain canonical")
}

fn copy_deriver_b_contribution(source: &DeriverBContribution) -> DeriverBContribution {
    DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: source.y_client().expose_bytes(),
        y_server: source.y_server().expose_bytes(),
        tau_client: source.tau_client().expose_bytes(),
        tau_server: source.tau_server().expose_bytes(),
    })
    .expect("validated host-only Deriver B contribution must remain canonical")
}

fn validate_evaluation_binding(
    dag: CeremonyValidatedDagV1,
    provenance: &RoleInputProvenancePairV1,
) -> Result<ValidatedEvaluationBindingV1, HostOnlyEvaluationInputViewErrorV1> {
    let matching_kind = matches!(
        (dag.request_kind(), provenance.deriver_a().request_kind()),
        (
            crate::CeremonyRequestKindV1::Registration,
            ProvenanceRequestKindV1::Registration
        ) | (
            crate::CeremonyRequestKindV1::Recovery,
            ProvenanceRequestKindV1::Recovery
        ) | (
            crate::CeremonyRequestKindV1::Refresh,
            ProvenanceRequestKindV1::Refresh
        ) | (
            crate::CeremonyRequestKindV1::Export,
            ProvenanceRequestKindV1::Export
        )
    );
    if !matching_kind {
        return Err(HostOnlyEvaluationInputViewErrorV1::ProvenanceRequestKindMismatch);
    }
    if provenance.ceremony_request_context_digest() != dag.request_context_digest() {
        return Err(HostOnlyEvaluationInputViewErrorV1::RequestContextDigestMismatch);
    }
    if provenance.ceremony_authorization_digest() != dag.authorization_digest() {
        return Err(HostOnlyEvaluationInputViewErrorV1::AuthorizationDigestMismatch);
    }
    if provenance.ceremony_transcript_digest() != dag.transcript_digest() {
        return Err(HostOnlyEvaluationInputViewErrorV1::TranscriptDigestMismatch);
    }
    Ok(ValidatedEvaluationBindingV1 {
        request_context_digest: dag.request_context_digest(),
        authorization_digest: dag.authorization_digest(),
        transcript_digest: dag.transcript_digest(),
        provenance_pair_digest: provenance.digest()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony_context::{
        CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1,
        CeremonyAuthorizationRecordDigest32V1, CeremonyReplayNonce32V1, CeremonyRequestExpiryV1,
        CeremonyRequestIdV1, CeremonyTranscriptNonce32V1, CeremonyTransportBindingDigest32V1,
    };
    use crate::lifecycle_domain::{
        ActivationControlFreshFieldsV1, ActivationReceiptEvidenceV1, PendingActivationPreStateV1,
        RegistrationArtifactIssuanceV1,
    };
    use crate::semantic_artifacts::{
        OneUseExecutionId32V1, OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    };
    use crate::semantic_artifacts_tests::{
        export_ceremony, provenance_pair, recovery_ceremony, refresh_ceremony,
        registration_ceremony,
    };
    use crate::semantic_fixture_material::{
        activation_bindings, export_inputs, recovery_inputs, reference_fixture, refresh_inputs,
        registration_admission, registration_ideal_coins, registration_inputs,
    };
    use crate::{
        prepare_host_only_export_reference_v1, prepare_host_only_recovery_reference_v1,
        prepare_host_only_refresh_reference_v1, prepare_host_only_registration_reference_v1,
    };

    fn activation_receipt_evidence() -> ActivationReceiptEvidenceV1 {
        ActivationReceiptEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x92; 32])
                .expect("A receipt evidence"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x93; 32])
                .expect("B receipt evidence"),
        )
    }

    fn activation_request() -> ActivationRequestV1 {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = registration_ceremony("input-view-origin");
        let request = RegistrationRequestV1::new(context, authorization, transcript)
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
            .expect("registration artifact session");
        let pending = session
            .evaluate_and_commit_host_reference(
                registration_inputs(&fixture),
                registration_ideal_coins(3, 5),
                activation_bindings(),
                activation_receipt_evidence(),
            )
            .expect("registration pending activation");
        let fresh = ActivationControlFreshFieldsV1::new(
            CeremonyRequestIdV1::parse("evaluation-input-activation").expect("request id"),
            CeremonyReplayNonce32V1::new([0xb1; 32]),
            CeremonyRequestExpiryV1::new(20_000).expect("request expiry"),
            CeremonyAuthorizationRecordDigest32V1::new([0xb2; 32]).expect("authorization record"),
            CeremonyTranscriptNonce32V1::new([0xb3; 32]),
            CeremonyTransportBindingDigest32V1::new([0xb4; 32]).expect("transport binding"),
            CeremonyArtifactSuiteDigest32V1::new([0xb5; 32]).expect("artifact suite"),
        );
        ActivationRequestV1::new(
            fresh,
            PendingActivationPreStateV1::Registration(Box::new(pending)),
        )
        .expect("fresh activation continuation")
    }

    #[test]
    fn registration_projects_one_equal_common_value_and_only_one_role_input() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = registration_ceremony("input-view");
        let request = RegistrationRequestV1::new(context, authorization, transcript)
            .expect("registration request");
        let provenance = provenance_pair(request.validated_dag(), None);
        let prepared = prepare_host_only_registration_reference_v1(registration_inputs(&fixture));

        let deriver_a = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_deriver_a_v1();
        let deriver_b = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_deriver_b_v1();
        let client = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_client_v1();
        let signing_worker = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_signing_worker_v1();
        let router = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_router_v1();
        let observer = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_observer_v1();
        let diagnostics = build_host_only_registration_evaluation_input_view_set_v1(
            &request,
            &provenance,
            &prepared,
        )
        .expect("registration input views")
        .observe_diagnostics_v1();

        for common in [
            *deriver_b.common(),
            *client.common(),
            *signing_worker.common(),
            *router.common(),
            *observer.common(),
            *diagnostics.common(),
        ] {
            assert_eq!(common, *deriver_a.common());
        }
        assert_eq!(
            deriver_a.kind(),
            HostOnlyEvaluationInputExtensionKindV1::DeriverAActivationEvaluationInputs
        );
        assert_eq!(
            deriver_b.kind(),
            HostOnlyEvaluationInputExtensionKindV1::DeriverBActivationEvaluationInputs
        );
        assert_eq!(
            deriver_a.contribution().y_client().expose_bytes(),
            prepared.deriver_a().y_client().expose_bytes()
        );
        assert_eq!(
            deriver_b.contribution().tau_server().expose_bytes(),
            prepared.deriver_b().tau_server().expose_bytes()
        );
        assert_eq!(
            deriver_a.common().evaluation_counts(),
            HostOnlyEvaluationWindowCountsV1::ONE_ACTIVATION
        );
    }

    #[test]
    fn recovery_and_refresh_use_the_exact_prepared_role_inputs() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            RecoveryRequestV1::new(context, authorization, transcript).expect("recovery request");
        let provenance =
            provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let prepared = prepare_host_only_recovery_reference_v1(recovery_inputs(&fixture))
            .expect("recovery preparation");
        let a =
            build_host_only_recovery_evaluation_input_view_set_v1(&request, &provenance, &prepared)
                .expect("recovery input views")
                .observe_deriver_a_v1();
        assert_eq!(
            a.contribution().tau_client().expose_bytes(),
            prepared.recovered_deriver_a().tau_client().expose_bytes()
        );
        assert_eq!(
            a.common().stage(),
            HostOnlyEvaluationInputStageV1::RecoveryEvaluationAccepted
        );

        let (context, authorization, transcript) = refresh_ceremony();
        let request =
            RefreshRequestV1::new(context, authorization, transcript).expect("refresh request");
        let provenance =
            provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let prepared = prepare_host_only_refresh_reference_v1(refresh_inputs(&fixture))
            .expect("refresh preparation");
        let b =
            build_host_only_refresh_evaluation_input_view_set_v1(&request, &provenance, &prepared)
                .expect("refresh input views")
                .observe_deriver_b_v1();
        assert_eq!(
            b.contribution().y_server().expose_bytes(),
            prepared.refreshed_deriver_b().y_server().expose_bytes()
        );
        assert_eq!(
            b.common().stage(),
            HostOnlyEvaluationInputStageV1::RefreshEvaluationAccepted
        );
    }

    #[test]
    fn export_views_retain_only_prepared_y_inputs() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = export_ceremony(fixture.registered_public_key);
        let request =
            ExportRequestV1::new(context, authorization, transcript).expect("export request");
        let provenance =
            provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let prepared = prepare_host_only_export_reference_v1(
            export_inputs(&fixture),
            &fixture.registered_public_key,
        )
        .expect("export preparation");
        let a =
            build_host_only_export_evaluation_input_view_set_v1(&request, &provenance, &prepared)
                .expect("export input views")
                .observe_deriver_a_v1();
        let b =
            build_host_only_export_evaluation_input_view_set_v1(&request, &provenance, &prepared)
                .expect("export input views")
                .observe_deriver_b_v1();

        assert_eq!(
            a.y_client().expose_bytes(),
            fixture.deriver_a.y_client().expose_bytes()
        );
        assert_eq!(
            b.y_server().expose_bytes(),
            fixture.deriver_b.y_server().expose_bytes()
        );
        assert_eq!(a.common(), b.common());
        assert_eq!(
            a.common().evaluation_counts(),
            HostOnlyEvaluationWindowCountsV1::ONE_EXPORT
        );
    }

    #[test]
    fn activation_projects_all_empty_roles_and_a_zero_work_witness() {
        let request = activation_request();
        let a = build_host_only_activation_continuation_input_view_set_v1(
            &request,
            HostOnlyActivationNoIdealCoinsV1::from_host_only_fixture(),
        )
        .observe_deriver_a_v1();
        let b = build_host_only_activation_continuation_input_view_set_v1(
            &request,
            HostOnlyActivationNoIdealCoinsV1::from_host_only_fixture(),
        )
        .observe_deriver_b_v1();
        let client = build_host_only_activation_continuation_input_view_set_v1(
            &request,
            HostOnlyActivationNoIdealCoinsV1::from_host_only_fixture(),
        )
        .observe_client_v1();
        let router = build_host_only_activation_continuation_input_view_set_v1(
            &request,
            HostOnlyActivationNoIdealCoinsV1::from_host_only_fixture(),
        )
        .observe_router_v1();

        assert_eq!(a.common(), b.common());
        assert_eq!(a.common(), client.common());
        assert_eq!(a.common(), router.common());
        assert_eq!(
            a.kind(),
            HostOnlyEvaluationInputExtensionKindV1::DeriverAEmpty
        );
        assert_eq!(
            b.kind(),
            HostOnlyEvaluationInputExtensionKindV1::DeriverBEmpty
        );
        assert_eq!(
            a.common().evaluation_plan(),
            HostOnlyEvaluationPlanV1::ZeroEvaluationContinuation
        );
        assert_eq!(
            a.common().evaluation_counts(),
            HostOnlyEvaluationWindowCountsV1::ZERO_CONTINUATION
        );
    }

    #[test]
    fn mismatched_provenance_branch_is_rejected_before_projection() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = registration_ceremony("mismatch");
        let request = RegistrationRequestV1::new(context, authorization, transcript)
            .expect("registration request");
        let (context, authorization, transcript) = recovery_ceremony();
        let recovery =
            RecoveryRequestV1::new(context, authorization, transcript).expect("recovery request");
        let wrong_provenance = provenance_pair(
            recovery.validated_dag(),
            Some(fixture.registered_public_key),
        );
        let prepared = prepare_host_only_registration_reference_v1(registration_inputs(&fixture));

        assert!(matches!(
            build_host_only_registration_evaluation_input_view_set_v1(
                &request,
                &wrong_provenance,
                &prepared,
            ),
            Err(HostOnlyEvaluationInputViewErrorV1::ProvenanceRequestKindMismatch)
        ));
    }
}
