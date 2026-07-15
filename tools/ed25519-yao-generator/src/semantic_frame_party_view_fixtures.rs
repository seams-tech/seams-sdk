//! Strict label-only corpus for semantic traces and cumulative party views.

use core::fmt;

use serde::Serialize;

use crate::activation_delivery_fixtures::ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1;
use crate::activation_recipient_party_view_vector_fixtures::ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1;
use crate::ceremony_context::CeremonyRequestKindV1;
use crate::ceremony_fixtures::CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1;
use crate::corruption_game_interfaces::{
    HOST_ONLY_CORRUPTION_GAME_INTERFACE_SHAPES_V1, HOST_ONLY_CORRUPTION_KINDS_V1,
};
use crate::evaluation_input_view_fixtures::EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1;
use crate::evaluator_abort_view_fixtures::EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1;
use crate::export_delivery_fixtures::EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1;
use crate::export_evaluation_acceptance_fixtures::EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1;
use crate::lifecycle_fixtures::LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1;
use crate::output_party_view_fixtures::OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1;
use crate::provenance_fixtures::PROVENANCE_VECTOR_CORPUS_SCHEMA_V1;
use crate::recovery_credential_transition_fixtures::RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1;
use crate::recovery_evaluation_admission_fixtures::RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1;
use crate::refresh_evaluation_admission_fixtures::REFRESH_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1;
use crate::registration_evaluation_admission_fixtures::REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1;
use crate::semantic_delivery_views::{
    activation_success_trace_steps_v1, evaluator_abort_trace_steps_v1,
    export_success_trace_steps_v1, HostOnlySemanticPrivateValueClassV1,
    HostOnlySemanticPublicEventV1, HostOnlySemanticRoleV1, HostOnlySemanticTraceStepV1,
    HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1, HOST_ONLY_SEMANTIC_ROLES_V1,
};
use crate::semantic_frame_classes::{
    HostOnlySemanticFrameClassV1, HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1,
};
use crate::semantic_lifecycle_fixtures::SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1;
use crate::uniform_abort_fixtures::UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1;

/// Schema identifier for the strict semantic-frame party-view corpus.
pub const SEMANTIC_FRAME_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:semantic-frame-party-views:v1";

/// Scope separating construction-independent labels from runtime protocol claims.
pub const SEMANTIC_FRAME_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "construction_independent_semantic_trace_and_value_learning_v1";

const EXPLICIT_NONCLAIMS: [&str; 8] = [
    "runtime_frame_encoding_absent",
    "transport_and_endpoint_security_unclaimed",
    "production_role_view_serialization_absent",
    "secret_values_absent",
    "out_of_scope_corruptions_excluded",
    "selected_profile_satisfaction_unclaimed",
    "simulator_and_protocol_security_unclaimed",
    "constant_time_and_erasure_unclaimed",
];

/// Strict eight-case semantic-frame and cumulative party-view corpus.
#[derive(Serialize)]
pub struct SemanticFramePartyViewVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    ordered_roles: Vec<&'static str>,
    frame_classes: Vec<&'static str>,
    delivery_states: Vec<&'static str>,
    corruption_markers: Vec<&'static str>,
    interface_shapes: Vec<&'static str>,
    cases: Vec<SemanticFramePartyViewVectorCaseV1>,
}

impl SemanticFramePartyViewVectorCorpusV1 {
    /// Returns the fixed corpus schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the narrow construction-independent evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the exact case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
struct SemanticFramePartyViewVectorCaseV1 {
    case_id: &'static str,
    request_kind: SemanticFrameRequestKindVectorV1,
    outcome: SemanticFrameOutcomeVectorV1,
    source_references: Vec<SemanticFrameSourceReferenceVectorV1>,
    trace_steps: Vec<SemanticFrameTraceStepVectorV1>,
    retry_redelivery_policy: SemanticFrameRetryRedeliveryPolicyVectorV1,
    explicit_nonclaims: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticFrameRequestKindVectorV1 {
    Registration,
    Recovery,
    Refresh,
    Export,
}

impl SemanticFrameRequestKindVectorV1 {
    const fn ceremony_kind(self) -> CeremonyRequestKindV1 {
        match self {
            Self::Registration => CeremonyRequestKindV1::Registration,
            Self::Recovery => CeremonyRequestKindV1::Recovery,
            Self::Refresh => CeremonyRequestKindV1::Refresh,
            Self::Export => CeremonyRequestKindV1::Export,
        }
    }

    const fn is_export(self) -> bool {
        matches!(self, Self::Export)
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticFrameOutcomeVectorV1 {
    Success,
    EvaluatorAbort,
}

#[derive(Serialize)]
struct SemanticFrameSourceReferenceVectorV1 {
    artifact_kind: &'static str,
    schema: &'static str,
    case_selector: &'static str,
}

#[derive(Serialize)]
struct SemanticFrameTraceStepVectorV1 {
    ordinal: usize,
    delivery_state: &'static str,
    emitted_frame_classes: Vec<&'static str>,
    ordered_role_views: Vec<SemanticFrameRoleViewVectorV1>,
    identity_labels: Vec<&'static str>,
}

#[derive(Serialize)]
struct SemanticFrameRoleViewVectorV1 {
    role: &'static str,
    known_values: Vec<&'static str>,
    observed_frame_classes: Vec<&'static str>,
}

#[derive(Serialize)]
struct SemanticFrameRetryRedeliveryPolicyVectorV1 {
    evaluator_retry: SemanticFrameEvaluatorRetryVectorV1,
    redelivery: SemanticFrameRedeliveryVectorV1,
    fresh_identity_requirements: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticFrameEvaluatorRetryVectorV1 {
    NotApplicable,
    TerminalAbortNoResume,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticFrameRedeliveryVectorV1 {
    NotApplicable,
    ExactActivationRecipientRedelivery,
    ExactExportClientRedelivery,
}

/// Failure returned for noncanonical semantic-frame corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticFramePartyViewVectorCorpusParseErrorV1;

impl fmt::Display for SemanticFramePartyViewVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "semantic-frame party-view corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for SemanticFramePartyViewVectorCorpusParseErrorV1 {}

/// Builds the canonical eight-case semantic-frame and value-learning corpus.
pub fn canonical_semantic_frame_party_view_vector_corpus_v1() -> SemanticFramePartyViewVectorCorpusV1
{
    SemanticFramePartyViewVectorCorpusV1 {
        schema: SEMANTIC_FRAME_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: SEMANTIC_FRAME_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        ordered_roles: HOST_ONLY_SEMANTIC_ROLES_V1
            .iter()
            .map(|role| role.as_str())
            .collect(),
        frame_classes: HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1
            .iter()
            .map(|class| class.as_str())
            .collect(),
        delivery_states: HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1
            .iter()
            .map(|state| state.as_str())
            .collect(),
        corruption_markers: HOST_ONLY_CORRUPTION_KINDS_V1
            .iter()
            .map(|kind| kind.as_str())
            .collect(),
        interface_shapes: HOST_ONLY_CORRUPTION_GAME_INTERFACE_SHAPES_V1
            .iter()
            .map(|shape| shape.as_str())
            .collect(),
        cases: vec![
            success_case(SemanticFrameRequestKindVectorV1::Registration),
            success_case(SemanticFrameRequestKindVectorV1::Recovery),
            success_case(SemanticFrameRequestKindVectorV1::Refresh),
            success_case(SemanticFrameRequestKindVectorV1::Export),
            abort_case(SemanticFrameRequestKindVectorV1::Registration),
            abort_case(SemanticFrameRequestKindVectorV1::Recovery),
            abort_case(SemanticFrameRequestKindVectorV1::Refresh),
            abort_case(SemanticFrameRequestKindVectorV1::Export),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_semantic_frame_party_view_vector_corpus_v1())
            .expect("fixed semantic-frame party-view corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_semantic_frame_party_view_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<SemanticFramePartyViewVectorCorpusV1, SemanticFramePartyViewVectorCorpusParseErrorV1> {
    if encoded != canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1() {
        return Err(SemanticFramePartyViewVectorCorpusParseErrorV1);
    }
    Ok(canonical_semantic_frame_party_view_vector_corpus_v1())
}

fn success_case(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> SemanticFramePartyViewVectorCaseV1 {
    let steps = if request_kind.is_export() {
        export_success_trace_steps_v1().as_slice()
    } else {
        activation_success_trace_steps_v1().as_slice()
    };
    SemanticFramePartyViewVectorCaseV1 {
        case_id: success_case_id(request_kind),
        request_kind,
        outcome: SemanticFrameOutcomeVectorV1::Success,
        source_references: success_source_references(request_kind),
        trace_steps: trace_steps(steps, request_kind),
        retry_redelivery_policy: SemanticFrameRetryRedeliveryPolicyVectorV1 {
            evaluator_retry: SemanticFrameEvaluatorRetryVectorV1::NotApplicable,
            redelivery: if request_kind.is_export() {
                SemanticFrameRedeliveryVectorV1::ExactExportClientRedelivery
            } else {
                SemanticFrameRedeliveryVectorV1::ExactActivationRecipientRedelivery
            },
            fresh_identity_requirements: Vec::new(),
        },
        explicit_nonclaims: EXPLICIT_NONCLAIMS.to_vec(),
    }
}

fn abort_case(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> SemanticFramePartyViewVectorCaseV1 {
    let steps = evaluator_abort_trace_steps_v1(request_kind.ceremony_kind())
        .expect("activation control has no evaluator-abort trace");
    SemanticFramePartyViewVectorCaseV1 {
        case_id: abort_case_id(request_kind),
        request_kind,
        outcome: SemanticFrameOutcomeVectorV1::EvaluatorAbort,
        source_references: abort_source_references(request_kind),
        trace_steps: trace_steps(steps, request_kind),
        retry_redelivery_policy: SemanticFrameRetryRedeliveryPolicyVectorV1 {
            evaluator_retry: SemanticFrameEvaluatorRetryVectorV1::TerminalAbortNoResume,
            redelivery: SemanticFrameRedeliveryVectorV1::NotApplicable,
            fresh_identity_requirements: vec![
                "fresh_ceremony_request_identity",
                "fresh_replay_nonce_identity",
                "fresh_one_use_execution_identity",
            ],
        },
        explicit_nonclaims: EXPLICIT_NONCLAIMS.to_vec(),
    }
}

fn trace_steps(
    steps: &[HostOnlySemanticTraceStepV1],
    request_kind: SemanticFrameRequestKindVectorV1,
) -> Vec<SemanticFrameTraceStepVectorV1> {
    steps
        .iter()
        .copied()
        .enumerate()
        .map(|(ordinal, step)| SemanticFrameTraceStepVectorV1 {
            ordinal,
            delivery_state: step.state().as_str(),
            emitted_frame_classes: step
                .emitted_frame_classes()
                .iter()
                .map(|class| class.as_str())
                .collect(),
            ordered_role_views: ordered_role_views(step),
            identity_labels: identity_labels(step.state(), request_kind).to_vec(),
        })
        .collect()
}

fn ordered_role_views(step: HostOnlySemanticTraceStepV1) -> Vec<SemanticFrameRoleViewVectorV1> {
    let deriver_a = step.view_set().observe_deriver_a_v1();
    let deriver_b = step.view_set().observe_deriver_b_v1();
    let client = step.view_set().observe_client_v1();
    let signing_worker = step.view_set().observe_signing_worker_v1();
    let router = step.view_set().observe_router_v1();
    let observer = step.view_set().observe_observer_v1();
    let diagnostics = step.view_set().observe_diagnostics_v1();
    vec![
        role_view(
            HostOnlySemanticRoleV1::DeriverA,
            deriver_a.known_public_events(),
            deriver_a.known_private_values(),
            deriver_a.observed_frame_classes(),
        ),
        role_view(
            HostOnlySemanticRoleV1::DeriverB,
            deriver_b.known_public_events(),
            deriver_b.known_private_values(),
            deriver_b.observed_frame_classes(),
        ),
        role_view(
            HostOnlySemanticRoleV1::Client,
            client.known_public_events(),
            client.known_private_values(),
            client.observed_frame_classes(),
        ),
        role_view(
            HostOnlySemanticRoleV1::SigningWorker,
            signing_worker.known_public_events(),
            signing_worker.known_private_values(),
            signing_worker.observed_frame_classes(),
        ),
        role_view(
            HostOnlySemanticRoleV1::Router,
            router.known_public_events(),
            router.known_private_values(),
            router.observed_frame_classes(),
        ),
        role_view(
            HostOnlySemanticRoleV1::Observer,
            observer.known_public_events(),
            observer.known_private_values(),
            observer.observed_frame_classes(),
        ),
        role_view(
            HostOnlySemanticRoleV1::Diagnostics,
            diagnostics.known_public_events(),
            diagnostics.known_private_values(),
            diagnostics.observed_frame_classes(),
        ),
    ]
}

fn role_view(
    role: HostOnlySemanticRoleV1,
    public_events: &[HostOnlySemanticPublicEventV1],
    known_values: &[HostOnlySemanticPrivateValueClassV1],
    observed_frames: &[HostOnlySemanticFrameClassV1],
) -> SemanticFrameRoleViewVectorV1 {
    let mut values = Vec::with_capacity(public_events.len() + known_values.len());
    values.extend(public_events.iter().map(|value| value.as_str()));
    values.extend(known_values.iter().map(|value| value.as_str()));
    SemanticFrameRoleViewVectorV1 {
        role: role.as_str(),
        known_values: values,
        observed_frame_classes: observed_frames.iter().map(|class| class.as_str()).collect(),
    }
}

fn identity_labels(
    state: crate::semantic_delivery_views::HostOnlySemanticDeliveryStateV1,
    request_kind: SemanticFrameRequestKindVectorV1,
) -> &'static [&'static str] {
    use crate::semantic_delivery_views::HostOnlySemanticDeliveryStateV1 as State;
    match state {
        State::CeremonyAdmitted => &[
            "ceremony_request_identity",
            "authorization_identity",
            "transcript_identity",
        ],
        State::EvaluationInputsAccepted => &[
            "ceremony_request_identity",
            "authorization_identity",
            "transcript_identity",
            "provenance_pair_identity",
            "evaluator_admission_identity",
            "one_use_execution_identity",
            "evaluation_input_view_identity",
        ],
        State::PeerProtocolInProgress => &[
            "ceremony_request_identity",
            "authorization_identity",
            "transcript_identity",
            "provenance_pair_identity",
            "evaluator_admission_identity",
            "one_use_execution_identity",
            "evaluation_input_view_identity",
            "peer_protocol_execution_identity",
        ],
        State::OutputCommitted => OUTPUT_IDENTITIES,
        State::EvaluatorAborted => &[
            "ceremony_request_identity",
            "authorization_identity",
            "transcript_identity",
            "provenance_pair_identity",
            "evaluator_admission_identity",
            "one_use_execution_identity",
            "evaluation_input_view_identity",
            "peer_protocol_execution_identity",
            "burned_execution_identity",
            "uniform_abort_identity",
        ],
        State::ActivationMetadataConsumed => ACTIVATION_METADATA_IDENTITIES,
        State::RecipientDeliveryUncertain if request_kind.is_export() => {
            EXPORT_UNCERTAIN_IDENTITIES
        }
        State::RecipientDeliveryUncertain => ACTIVATION_UNCERTAIN_IDENTITIES,
        State::ActivationRecipientsReleased => ACTIVATION_RELEASED_IDENTITIES,
        State::ExportReleased => EXPORT_RELEASED_IDENTITIES,
        State::ExactRedelivery if request_kind.is_export() => EXPORT_REDELIVERY_IDENTITIES,
        State::ExactRedelivery => ACTIVATION_REDELIVERY_IDENTITIES,
        State::SigningWorkerActivated => ACTIVATED_IDENTITIES,
    }
}

const OUTPUT_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
];
const ACTIVATION_METADATA_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "activation_control_identity",
];
const ACTIVATION_UNCERTAIN_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "activation_control_identity",
    "activation_recipient_delivery_identity",
];
const ACTIVATION_RELEASED_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "activation_control_identity",
    "activation_recipient_delivery_identity",
    "activation_recipient_release_identity",
];
const ACTIVATION_REDELIVERY_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "activation_control_identity",
    "activation_recipient_delivery_identity",
    "activation_recipient_release_identity",
    "exact_redelivery_identity",
];
const ACTIVATED_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "activation_control_identity",
    "activation_recipient_delivery_identity",
    "activation_recipient_release_identity",
    "exact_redelivery_identity",
    "signing_worker_activation_receipt_identity",
];
const EXPORT_UNCERTAIN_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "export_client_delivery_identity",
];
const EXPORT_RELEASED_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "export_client_delivery_identity",
    "export_client_release_identity",
];
const EXPORT_REDELIVERY_IDENTITIES: &[&str] = &[
    "ceremony_request_identity",
    "authorization_identity",
    "transcript_identity",
    "provenance_pair_identity",
    "evaluator_admission_identity",
    "one_use_execution_identity",
    "evaluation_input_view_identity",
    "peer_protocol_execution_identity",
    "output_package_set_identity",
    "output_committed_receipt_identity",
    "export_client_delivery_identity",
    "export_client_release_identity",
    "exact_redelivery_identity",
];

fn success_source_references(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> Vec<SemanticFrameSourceReferenceVectorV1> {
    let mut references = common_source_references(request_kind);
    references.push(source(
        "semantic_lifecycle",
        SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1,
        semantic_lifecycle_selector(request_kind),
    ));
    references.push(source(
        "output_party_views",
        OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
        output_party_view_selector(request_kind),
    ));
    if request_kind.is_export() {
        references.push(source(
            "export_delivery",
            EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
            "export_output_commit_release_redelivery_v1",
        ));
        return references;
    }
    references.push(source(
        "activation_delivery",
        ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
        activation_delivery_selector(request_kind),
    ));
    references.push(source(
        "activation_recipient_party_views",
        ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
        activation_recipient_selector(request_kind),
    ));
    match request_kind {
        SemanticFrameRequestKindVectorV1::Recovery => references.push(source(
            "recovery_credential_transition",
            RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
            "recovery_credential_suspension_promotion_v1",
        )),
        SemanticFrameRequestKindVectorV1::Refresh => references.push(source(
            "lifecycle_continuity",
            LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1,
            "refresh_opposite_delta_continuity_v1",
        )),
        SemanticFrameRequestKindVectorV1::Registration
        | SemanticFrameRequestKindVectorV1::Export => {}
    }
    references
}

fn abort_source_references(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> Vec<SemanticFrameSourceReferenceVectorV1> {
    let mut references = common_source_references(request_kind);
    references.push(source(
        "uniform_abort",
        UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1,
        ceremony_selector(request_kind),
    ));
    references.push(source(
        "evaluator_abort_party_views",
        EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1,
        ceremony_selector(request_kind),
    ));
    references
}

fn common_source_references(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> Vec<SemanticFrameSourceReferenceVectorV1> {
    vec![
        source(
            "ceremony_context",
            CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1,
            ceremony_selector(request_kind),
        ),
        source(
            "input_provenance",
            PROVENANCE_VECTOR_CORPUS_SCHEMA_V1,
            provenance_selector(request_kind),
        ),
        source(
            "evaluation_input_party_views",
            EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
            evaluation_input_selector(request_kind),
        ),
        evaluator_source(request_kind),
    ]
}

const fn evaluator_source(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> SemanticFrameSourceReferenceVectorV1 {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => source(
            "registration_evaluator_admission",
            REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
            "registration_admitted_evaluation_output_committed_v1",
        ),
        SemanticFrameRequestKindVectorV1::Recovery => source(
            "recovery_evaluator_admission",
            RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
            "recovery_admitted_evaluation_output_committed_v1",
        ),
        SemanticFrameRequestKindVectorV1::Refresh => source(
            "refresh_evaluator_admission",
            REFRESH_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
            "refresh_admitted_evaluation_output_committed_v1",
        ),
        SemanticFrameRequestKindVectorV1::Export => source(
            "export_evaluator_authorization",
            EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1,
            "export_authorized_evaluation_released_v1",
        ),
    }
}

const fn source(
    artifact_kind: &'static str,
    schema: &'static str,
    case_selector: &'static str,
) -> SemanticFrameSourceReferenceVectorV1 {
    SemanticFrameSourceReferenceVectorV1 {
        artifact_kind,
        schema,
        case_selector,
    }
}

const fn success_case_id(request_kind: SemanticFrameRequestKindVectorV1) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => {
            "registration_success_worker_activated_v1"
        }
        SemanticFrameRequestKindVectorV1::Recovery => "recovery_success_worker_activated_v1",
        SemanticFrameRequestKindVectorV1::Refresh => "refresh_success_worker_activated_v1",
        SemanticFrameRequestKindVectorV1::Export => "export_release_exact_redelivery_v1",
    }
}

const fn abort_case_id(request_kind: SemanticFrameRequestKindVectorV1) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => "registration_evaluator_abort_v1",
        SemanticFrameRequestKindVectorV1::Recovery => "recovery_evaluator_abort_v1",
        SemanticFrameRequestKindVectorV1::Refresh => "refresh_evaluator_abort_v1",
        SemanticFrameRequestKindVectorV1::Export => "export_evaluator_abort_v1",
    }
}

const fn ceremony_selector(request_kind: SemanticFrameRequestKindVectorV1) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => "ceremony-registration-v1",
        SemanticFrameRequestKindVectorV1::Recovery => "ceremony-recovery-v1",
        SemanticFrameRequestKindVectorV1::Refresh => "ceremony-refresh-v1",
        SemanticFrameRequestKindVectorV1::Export => "ceremony-export-v1",
    }
}

const fn provenance_selector(request_kind: SemanticFrameRequestKindVectorV1) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => "registration_provenance_outer_v1",
        SemanticFrameRequestKindVectorV1::Recovery => "recovery_provenance_outer_v1",
        SemanticFrameRequestKindVectorV1::Refresh => "refresh_provenance_outer_v1",
        SemanticFrameRequestKindVectorV1::Export => "export_provenance_outer_v1",
    }
}

const fn evaluation_input_selector(request_kind: SemanticFrameRequestKindVectorV1) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => {
            "registration_evaluation_input_party_views_v1"
        }
        SemanticFrameRequestKindVectorV1::Recovery => "recovery_evaluation_input_party_views_v1",
        SemanticFrameRequestKindVectorV1::Refresh => "refresh_evaluation_input_party_views_v1",
        SemanticFrameRequestKindVectorV1::Export => "export_evaluation_input_party_views_v1",
    }
}

const fn semantic_lifecycle_selector(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => {
            "registration_semantic_artifacts_output_committed_v1"
        }
        SemanticFrameRequestKindVectorV1::Recovery => {
            "recovery_semantic_artifacts_output_committed_v1"
        }
        SemanticFrameRequestKindVectorV1::Refresh => {
            "refresh_semantic_artifacts_output_committed_v1"
        }
        SemanticFrameRequestKindVectorV1::Export => {
            "export_semantic_artifacts_host_reference_receipt_v1"
        }
    }
}

const fn output_party_view_selector(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => {
            "registration_output_party_views_package_prepared_v1"
        }
        SemanticFrameRequestKindVectorV1::Recovery => {
            "recovery_output_party_views_package_prepared_v1"
        }
        SemanticFrameRequestKindVectorV1::Refresh => {
            "refresh_output_party_views_package_prepared_v1"
        }
        SemanticFrameRequestKindVectorV1::Export => "export_output_party_views_released_v1",
    }
}

const fn activation_delivery_selector(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => "registration_activation_delivery_v1",
        SemanticFrameRequestKindVectorV1::Recovery => "recovery_activation_delivery_v1",
        SemanticFrameRequestKindVectorV1::Refresh => "refresh_activation_delivery_v1",
        SemanticFrameRequestKindVectorV1::Export => "",
    }
}

const fn activation_recipient_selector(
    request_kind: SemanticFrameRequestKindVectorV1,
) -> &'static str {
    match request_kind {
        SemanticFrameRequestKindVectorV1::Registration => {
            "registration_activation_recipient_party_views_v1"
        }
        SemanticFrameRequestKindVectorV1::Recovery => {
            "recovery_activation_recipient_party_views_v1"
        }
        SemanticFrameRequestKindVectorV1::Refresh => "refresh_activation_recipient_party_views_v1",
        SemanticFrameRequestKindVectorV1::Export => "",
    }
}
