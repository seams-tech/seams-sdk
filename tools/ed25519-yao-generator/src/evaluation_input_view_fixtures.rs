//! Strict synthetic corpus for construction-independent evaluation-input views.

use core::fmt;

use serde::Serialize;

use crate::ceremony_context::CeremonyRequestKindV1;
use crate::ceremony_fixtures::{
    canonical_export_ceremony_fixture_for_registered_key_v1,
    canonical_recovery_ceremony_fixture_v1, canonical_refresh_ceremony_fixture_v1,
    canonical_registration_ceremony_fixture_v1,
};
use crate::evaluation_input_views::{
    build_host_only_activation_continuation_input_view_set_v1,
    build_host_only_export_evaluation_input_view_set_v1,
    build_host_only_recovery_evaluation_input_view_set_v1,
    build_host_only_refresh_evaluation_input_view_set_v1,
    build_host_only_registration_evaluation_input_view_set_v1,
    HostOnlyActivationContinuationInputViewSetV1, HostOnlyDeriverAActivationEvaluationInputViewV1,
    HostOnlyDeriverAExportEvaluationInputViewV1, HostOnlyDeriverBActivationEvaluationInputViewV1,
    HostOnlyDeriverBExportEvaluationInputViewV1, HostOnlyEvaluationInputExtensionKindV1,
    HostOnlyEvaluationInputStageV1, HostOnlyEvaluationPlanV1, HostOnlyEvaluationWindowCountsV1,
    HostOnlyExportEvaluationInputViewSetV1, HostOnlyRecoveryEvaluationInputViewSetV1,
    HostOnlyRefreshEvaluationInputViewSetV1, HostOnlyRegistrationEvaluationInputViewSetV1,
};
use crate::lifecycle_domain::{
    ActivationPackageOriginV1, ExportRequestV1, RecoveryRequestV1, RefreshRequestV1,
    RegistrationRequestV1,
};
use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
use crate::semantic_fixture_material::{
    activation_coins, export_coin, export_inputs, recovery_inputs, reference_fixture,
    refresh_inputs, registration_inputs,
};
use crate::semantic_lifecycle_fixtures::{
    canonical_activation_request_v1, ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1, RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1, REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
};
use crate::{
    prepare_host_only_export_reference_v1, prepare_host_only_recovery_reference_v1,
    prepare_host_only_refresh_reference_v1, prepare_host_only_registration_reference_v1,
    HostOnlyActivationNoIdealCoinsV1,
};

/// Schema identifier for the strict evaluation-input party-view corpus.
pub const EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:evaluation-input-party-views-vectors:v1";
/// Scope separating synthetic private evidence from runtime public leakage.
pub const EVALUATION_INPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_evaluation_input_party_views_v1";

const REGISTRATION_CASE_ID_V1: &str = "registration_evaluation_input_party_views_v1";
const ACTIVATION_CASE_ID_V1: &str = "activation_no_evaluation_input_party_views_v1";
const RECOVERY_CASE_ID_V1: &str = "recovery_evaluation_input_party_views_v1";
const REFRESH_CASE_ID_V1: &str = "refresh_evaluation_input_party_views_v1";
const EXPORT_CASE_ID_V1: &str = "export_evaluation_input_party_views_v1";

const REGISTRATION_CEREMONY_CASE_ID_V1: &str = "ceremony-registration-v1";
const RECOVERY_CEREMONY_CASE_ID_V1: &str = "ceremony-recovery-v1";
const REFRESH_CEREMONY_CASE_ID_V1: &str = "ceremony-refresh-v1";
const EXPORT_CEREMONY_CASE_ID_V1: &str = "ceremony-export-v1";
const REGISTRATION_PROVENANCE_CASE_ID_V1: &str = "registration_provenance_outer_v1";
const RECOVERY_PROVENANCE_CASE_ID_V1: &str = "recovery_provenance_outer_v1";
const REFRESH_PROVENANCE_CASE_ID_V1: &str = "refresh_provenance_outer_v1";
const EXPORT_PROVENANCE_CASE_ID_V1: &str = "export_provenance_outer_v1";
const REGISTRATION_OUTPUT_VIEW_CASE_ID_V1: &str =
    "registration_output_party_views_package_prepared_v1";
const ACTIVATION_OUTPUT_VIEW_CASE_ID_V1: &str =
    "activation_output_party_views_metadata_consumed_v1";
const RECOVERY_OUTPUT_VIEW_CASE_ID_V1: &str = "recovery_output_party_views_package_prepared_v1";
const REFRESH_OUTPUT_VIEW_CASE_ID_V1: &str = "refresh_output_party_views_package_prepared_v1";
const EXPORT_OUTPUT_VIEW_CASE_ID_V1: &str = "export_output_party_views_released_v1";

/// Strict five-case synthetic evaluation-input party-view corpus.
#[derive(Serialize)]
pub struct EvaluationInputPartyViewVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<EvaluationInputPartyViewVectorCaseV1>,
}

impl EvaluationInputPartyViewVectorCorpusV1 {
    /// Returns the exact schema identifier.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the fixed protocol identifier.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the narrow host-only evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the fixed case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
#[serde(tag = "request_kind", content = "vector", rename_all = "snake_case")]
enum EvaluationInputPartyViewVectorCaseV1 {
    Registration(ActivationFamilyEvaluationInputVectorV1),
    Activation(ActivationContinuationInputVectorV1),
    Recovery(ActivationFamilyEvaluationInputVectorV1),
    Refresh(ActivationFamilyEvaluationInputVectorV1),
    Export(ExportEvaluationInputVectorV1),
}

#[derive(Serialize)]
struct ActivationFamilyEvaluationInputVectorV1 {
    case_id: String,
    stage: EvaluationInputStageVectorV1,
    host_only_source_references: ProducingSourceReferencesVectorV1,
    common_public: ProducingCommonPublicVectorV1,
    role_extensions: ActivationFamilyRoleExtensionsVectorV1,
    static_deriver_observations: StaticDeriverObservationsVectorV1<
        DeriverAActivationEvaluationInputsExtensionV1,
        DeriverBActivationEvaluationInputsExtensionV1,
    >,
    host_only_ideal_function_randomness: ActivationFamilyIdealRandomnessVectorV1,
}

#[derive(Serialize)]
struct ActivationContinuationInputVectorV1 {
    case_id: String,
    stage: EvaluationInputStageVectorV1,
    host_only_source_references: ActivationSourceReferencesVectorV1,
    common_public: ActivationCommonPublicVectorV1,
    role_extensions: ActivationEmptyRoleExtensionsVectorV1,
    static_deriver_observations:
        StaticDeriverObservationsVectorV1<DeriverAEmptyExtensionV1, DeriverBEmptyExtensionV1>,
    host_only_ideal_function_randomness: ActivationNoIdealRandomnessVectorV1,
}

#[derive(Serialize)]
struct ExportEvaluationInputVectorV1 {
    case_id: String,
    stage: EvaluationInputStageVectorV1,
    host_only_source_references: ProducingSourceReferencesVectorV1,
    common_public: ProducingCommonPublicVectorV1,
    role_extensions: ExportRoleExtensionsVectorV1,
    static_deriver_observations: StaticDeriverObservationsVectorV1<
        DeriverAExportEvaluationInputsExtensionV1,
        DeriverBExportEvaluationInputsExtensionV1,
    >,
    host_only_ideal_function_randomness: ExportIdealRandomnessVectorV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum EvaluationInputStageVectorV1 {
    #[serde(rename = "registration_evaluation_accepted")]
    Registration,
    #[serde(rename = "activation_continuation_accepted")]
    Activation,
    #[serde(rename = "recovery_evaluation_accepted")]
    Recovery,
    #[serde(rename = "refresh_evaluation_accepted")]
    Refresh,
    #[serde(rename = "export_evaluation_accepted")]
    Export,
}

#[derive(Serialize)]
struct ProducingSourceReferencesVectorV1 {
    ceremony_context_case_id: String,
    provenance_case_id: String,
    semantic_lifecycle_case_id: String,
    output_party_view_case_id: String,
}

#[derive(Serialize)]
struct ActivationSourceReferencesVectorV1 {
    semantic_lifecycle_case_id: String,
    output_party_view_case_id: String,
    activation_origin: ActivationOriginVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationOriginVectorV1 {
    Registration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProducingCommonPublicVectorV1 {
    stage: EvaluationInputStageVectorV1,
    request_kind: CeremonyRequestKindV1,
    evaluation_plan: EvaluationPlanVectorV1,
    public_request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    input_provenance_pair_digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActivationCommonPublicVectorV1 {
    stage: EvaluationInputStageVectorV1,
    request_kind: CeremonyRequestKindV1,
    evaluation_plan: EvaluationPlanVectorV1,
    public_request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct EvaluationPlanVectorV1 {
    kind: EvaluationPlanKindVectorV1,
    counts: EvaluationWindowCountsVectorV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluationPlanKindVectorV1 {
    OneActivationEvaluation,
    ZeroEvaluationContinuation,
    OneExportEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct EvaluationWindowCountsVectorV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    ideal_output_share_samples: u8,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverAActivationEvaluationInputsExtensionV1 {
    DeriverAActivationEvaluationInputs {
        y_client_hex: String,
        y_server_hex: String,
        tau_client_hex: String,
        tau_server_hex: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverBActivationEvaluationInputsExtensionV1 {
    DeriverBActivationEvaluationInputs {
        y_client_hex: String,
        y_server_hex: String,
        tau_client_hex: String,
        tau_server_hex: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverAExportEvaluationInputsExtensionV1 {
    DeriverAExportEvaluationInputs {
        y_client_hex: String,
        y_server_hex: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverBExportEvaluationInputsExtensionV1 {
    DeriverBExportEvaluationInputs {
        y_client_hex: String,
        y_server_hex: String,
    },
}

macro_rules! define_empty_extension {
    ($name:ident, $variant:ident) => {
        #[derive(Clone, PartialEq, Eq, Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum $name {
            $variant,
        }
    };
}

define_empty_extension!(DeriverAEmptyExtensionV1, DeriverAEmpty);
define_empty_extension!(DeriverBEmptyExtensionV1, DeriverBEmpty);
define_empty_extension!(ClientEmptyExtensionV1, ClientEmpty);
define_empty_extension!(SigningWorkerEmptyExtensionV1, SigningWorkerEmpty);
define_empty_extension!(RouterEmptyExtensionV1, RouterEmpty);
define_empty_extension!(ObserverEmptyExtensionV1, ObserverEmpty);
define_empty_extension!(DiagnosticsEmptyExtensionV1, DiagnosticsEmpty);

#[derive(Serialize)]
struct ActivationFamilyRoleExtensionsVectorV1 {
    deriver_a: DeriverAActivationEvaluationInputsExtensionV1,
    deriver_b: DeriverBActivationEvaluationInputsExtensionV1,
    client: ClientEmptyExtensionV1,
    signing_worker: SigningWorkerEmptyExtensionV1,
    router: RouterEmptyExtensionV1,
    observer: ObserverEmptyExtensionV1,
    diagnostics_logs: DiagnosticsEmptyExtensionV1,
}

#[derive(Serialize)]
struct ActivationEmptyRoleExtensionsVectorV1 {
    deriver_a: DeriverAEmptyExtensionV1,
    deriver_b: DeriverBEmptyExtensionV1,
    client: ClientEmptyExtensionV1,
    signing_worker: SigningWorkerEmptyExtensionV1,
    router: RouterEmptyExtensionV1,
    observer: ObserverEmptyExtensionV1,
    diagnostics_logs: DiagnosticsEmptyExtensionV1,
}

#[derive(Serialize)]
struct ExportRoleExtensionsVectorV1 {
    deriver_a: DeriverAExportEvaluationInputsExtensionV1,
    deriver_b: DeriverBExportEvaluationInputsExtensionV1,
    client: ClientEmptyExtensionV1,
    signing_worker: SigningWorkerEmptyExtensionV1,
    router: RouterEmptyExtensionV1,
    observer: ObserverEmptyExtensionV1,
    diagnostics_logs: DiagnosticsEmptyExtensionV1,
}

#[derive(Serialize)]
struct StaticDeriverObservationsVectorV1<DeriverAExtension, DeriverBExtension> {
    deriver_a: StaticDeriverAObservationVectorV1<DeriverAExtension>,
    deriver_b: StaticDeriverBObservationVectorV1<DeriverBExtension>,
}

#[derive(Serialize)]
struct StaticDeriverAObservationVectorV1<Extension> {
    observation_kind: StaticDeriverAObservationKindVectorV1,
    source_case_id: String,
    source_stage: EvaluationInputStageVectorV1,
    extension: Extension,
}

#[derive(Serialize)]
struct StaticDeriverBObservationVectorV1<Extension> {
    observation_kind: StaticDeriverBObservationKindVectorV1,
    source_case_id: String,
    source_stage: EvaluationInputStageVectorV1,
    extension: Extension,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StaticDeriverAObservationKindVectorV1 {
    StaticConsumingDeriverAEvaluationInputs,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StaticDeriverBObservationKindVectorV1 {
    StaticConsumingDeriverBEvaluationInputs,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ActivationFamilyIdealRandomnessVectorV1 {
    ActivationFamilyOutputSharingCoins {
        client_scalar_coin_hex: String,
        signing_worker_scalar_coin_hex: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ActivationNoIdealRandomnessVectorV1 {
    ActivationNoIdealFunctionRandomness,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExportIdealRandomnessVectorV1 {
    ExportSeedOutputCoin { seed_output_coin_hex: String },
}

/// Failure returned for any noncanonical corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationInputPartyViewVectorCorpusParseErrorV1;

impl fmt::Display for EvaluationInputPartyViewVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "evaluation-input party-view corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for EvaluationInputPartyViewVectorCorpusParseErrorV1 {}

/// Builds the canonical five-case synthetic evaluation-input party-view corpus.
pub fn canonical_evaluation_input_party_view_vector_corpus_v1(
) -> EvaluationInputPartyViewVectorCorpusV1 {
    EvaluationInputPartyViewVectorCorpusV1 {
        schema: EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: EVALUATION_INPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            EvaluationInputPartyViewVectorCaseV1::Registration(registration_case()),
            EvaluationInputPartyViewVectorCaseV1::Activation(activation_case()),
            EvaluationInputPartyViewVectorCaseV1::Recovery(recovery_case()),
            EvaluationInputPartyViewVectorCaseV1::Refresh(refresh_case()),
            EvaluationInputPartyViewVectorCaseV1::Export(export_case()),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_evaluation_input_party_view_vector_corpus_v1())
            .expect("fixed evaluation-input party-view corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_evaluation_input_party_view_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<EvaluationInputPartyViewVectorCorpusV1, EvaluationInputPartyViewVectorCorpusParseErrorV1>
{
    if encoded != canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1() {
        return Err(EvaluationInputPartyViewVectorCorpusParseErrorV1);
    }
    Ok(canonical_evaluation_input_party_view_vector_corpus_v1())
}

macro_rules! producing_common {
    ($common:expr, $request_kind:expr) => {{
        let common = $common;
        ProducingCommonPublicVectorV1 {
            stage: stage_vector(common.stage()),
            request_kind: $request_kind,
            evaluation_plan: evaluation_plan_vector(
                common.evaluation_plan(),
                common.evaluation_counts(),
            ),
            public_request_context_digest_hex: encode_hex(
                common.request_context_digest().as_bytes(),
            ),
            authorization_digest_hex: encode_hex(common.authorization_digest().as_bytes()),
            transcript_digest_hex: encode_hex(common.transcript_digest().as_bytes()),
            input_provenance_pair_digest_hex: encode_hex(
                common.provenance_pair_digest().as_bytes(),
            ),
        }
    }};
}

macro_rules! activation_family_case {
    ($set:ident, $case_id:expr, $request_kind:expr, $sources:expr) => {{
        let deriver_a_view = $set().observe_deriver_a_v1();
        let common_public = producing_common!(deriver_a_view.common(), $request_kind);
        let stage = common_public.stage;
        let deriver_a = activation_deriver_a_extension(&deriver_a_view);

        let deriver_b_view = $set().observe_deriver_b_v1();
        assert_eq!(
            producing_common!(deriver_b_view.common(), $request_kind),
            common_public
        );
        let deriver_b = activation_deriver_b_extension(&deriver_b_view);

        let client_view = $set().observe_client_v1();
        assert_eq!(producing_common!(client_view.common(), $request_kind), common_public);
        require_empty_kind(client_view.kind(), HostOnlyEvaluationInputExtensionKindV1::ClientEmpty);

        let signing_worker_view = $set().observe_signing_worker_v1();
        assert_eq!(
            producing_common!(signing_worker_view.common(), $request_kind),
            common_public
        );
        require_empty_kind(
            signing_worker_view.kind(),
            HostOnlyEvaluationInputExtensionKindV1::SigningWorkerEmpty,
        );

        let router_view = $set().observe_router_v1();
        assert_eq!(producing_common!(router_view.common(), $request_kind), common_public);
        require_empty_kind(router_view.kind(), HostOnlyEvaluationInputExtensionKindV1::RouterEmpty);

        let observer_view = $set().observe_observer_v1();
        assert_eq!(
            producing_common!(observer_view.common(), $request_kind),
            common_public
        );
        require_empty_kind(
            observer_view.kind(),
            HostOnlyEvaluationInputExtensionKindV1::ObserverEmpty,
        );

        let diagnostics_view = $set().observe_diagnostics_v1();
        assert_eq!(
            producing_common!(diagnostics_view.common(), $request_kind),
            common_public
        );
        require_empty_kind(
            diagnostics_view.kind(),
            HostOnlyEvaluationInputExtensionKindV1::DiagnosticsEmpty,
        );

        let static_deriver_a_view = $set().observe_deriver_a_v1();
        assert_eq!(
            producing_common!(static_deriver_a_view.common(), $request_kind),
            common_public
        );
        let static_deriver_a = activation_deriver_a_extension(&static_deriver_a_view);
        let static_deriver_b_view = $set().observe_deriver_b_v1();
        assert_eq!(
            producing_common!(static_deriver_b_view.common(), $request_kind),
            common_public
        );
        let static_deriver_b = activation_deriver_b_extension(&static_deriver_b_view);

        ActivationFamilyEvaluationInputVectorV1 {
            case_id: $case_id.to_owned(),
            stage,
            host_only_source_references: $sources,
            common_public,
            role_extensions: ActivationFamilyRoleExtensionsVectorV1 {
                deriver_a,
                deriver_b,
                client: ClientEmptyExtensionV1::ClientEmpty,
                signing_worker: SigningWorkerEmptyExtensionV1::SigningWorkerEmpty,
                router: RouterEmptyExtensionV1::RouterEmpty,
                observer: ObserverEmptyExtensionV1::ObserverEmpty,
                diagnostics_logs: DiagnosticsEmptyExtensionV1::DiagnosticsEmpty,
            },
            static_deriver_observations: StaticDeriverObservationsVectorV1 {
                deriver_a: StaticDeriverAObservationVectorV1 {
                    observation_kind:
                        StaticDeriverAObservationKindVectorV1::StaticConsumingDeriverAEvaluationInputs,
                    source_case_id: $case_id.to_owned(),
                    source_stage: stage,
                    extension: static_deriver_a,
                },
                deriver_b: StaticDeriverBObservationVectorV1 {
                    observation_kind:
                        StaticDeriverBObservationKindVectorV1::StaticConsumingDeriverBEvaluationInputs,
                    source_case_id: $case_id.to_owned(),
                    source_stage: stage,
                    extension: static_deriver_b,
                },
            },
            host_only_ideal_function_randomness: activation_randomness(),
        }
    }};
}

fn registration_case() -> ActivationFamilyEvaluationInputVectorV1 {
    activation_family_case!(
        registration_view_set,
        REGISTRATION_CASE_ID_V1,
        CeremonyRequestKindV1::Registration,
        producing_sources(
            REGISTRATION_CEREMONY_CASE_ID_V1,
            REGISTRATION_PROVENANCE_CASE_ID_V1,
            REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            REGISTRATION_OUTPUT_VIEW_CASE_ID_V1,
        )
    )
}

fn recovery_case() -> ActivationFamilyEvaluationInputVectorV1 {
    activation_family_case!(
        recovery_view_set,
        RECOVERY_CASE_ID_V1,
        CeremonyRequestKindV1::Recovery,
        producing_sources(
            RECOVERY_CEREMONY_CASE_ID_V1,
            RECOVERY_PROVENANCE_CASE_ID_V1,
            RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            RECOVERY_OUTPUT_VIEW_CASE_ID_V1,
        )
    )
}

fn refresh_case() -> ActivationFamilyEvaluationInputVectorV1 {
    activation_family_case!(
        refresh_view_set,
        REFRESH_CASE_ID_V1,
        CeremonyRequestKindV1::Refresh,
        producing_sources(
            REFRESH_CEREMONY_CASE_ID_V1,
            REFRESH_PROVENANCE_CASE_ID_V1,
            REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            REFRESH_OUTPUT_VIEW_CASE_ID_V1,
        )
    )
}

fn activation_case() -> ActivationContinuationInputVectorV1 {
    let deriver_a_view = activation_view_set().observe_deriver_a_v1();
    let common_public = activation_common(deriver_a_view.common());
    let stage = common_public.stage;
    require_empty_kind(
        deriver_a_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::DeriverAEmpty,
    );

    let deriver_b_view = activation_view_set().observe_deriver_b_v1();
    assert_eq!(activation_common(deriver_b_view.common()), common_public);
    require_empty_kind(
        deriver_b_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::DeriverBEmpty,
    );
    let client_view = activation_view_set().observe_client_v1();
    assert_eq!(activation_common(client_view.common()), common_public);
    require_empty_kind(
        client_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::ClientEmpty,
    );
    let signing_worker_view = activation_view_set().observe_signing_worker_v1();
    assert_eq!(
        activation_common(signing_worker_view.common()),
        common_public
    );
    require_empty_kind(
        signing_worker_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::SigningWorkerEmpty,
    );
    let router_view = activation_view_set().observe_router_v1();
    assert_eq!(activation_common(router_view.common()), common_public);
    require_empty_kind(
        router_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::RouterEmpty,
    );
    let observer_view = activation_view_set().observe_observer_v1();
    assert_eq!(activation_common(observer_view.common()), common_public);
    require_empty_kind(
        observer_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::ObserverEmpty,
    );
    let diagnostics_view = activation_view_set().observe_diagnostics_v1();
    assert_eq!(activation_common(diagnostics_view.common()), common_public);
    require_empty_kind(
        diagnostics_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::DiagnosticsEmpty,
    );

    let static_deriver_a_view = activation_view_set().observe_deriver_a_v1();
    assert_eq!(
        activation_common(static_deriver_a_view.common()),
        common_public
    );
    let static_deriver_b_view = activation_view_set().observe_deriver_b_v1();
    assert_eq!(
        activation_common(static_deriver_b_view.common()),
        common_public
    );

    ActivationContinuationInputVectorV1 {
        case_id: ACTIVATION_CASE_ID_V1.to_owned(),
        stage,
        host_only_source_references: ActivationSourceReferencesVectorV1 {
            semantic_lifecycle_case_id: ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
            output_party_view_case_id: ACTIVATION_OUTPUT_VIEW_CASE_ID_V1.to_owned(),
            activation_origin: ActivationOriginVectorV1::Registration,
        },
        common_public,
        role_extensions: ActivationEmptyRoleExtensionsVectorV1 {
            deriver_a: DeriverAEmptyExtensionV1::DeriverAEmpty,
            deriver_b: DeriverBEmptyExtensionV1::DeriverBEmpty,
            client: ClientEmptyExtensionV1::ClientEmpty,
            signing_worker: SigningWorkerEmptyExtensionV1::SigningWorkerEmpty,
            router: RouterEmptyExtensionV1::RouterEmpty,
            observer: ObserverEmptyExtensionV1::ObserverEmpty,
            diagnostics_logs: DiagnosticsEmptyExtensionV1::DiagnosticsEmpty,
        },
        static_deriver_observations: StaticDeriverObservationsVectorV1 {
            deriver_a: StaticDeriverAObservationVectorV1 {
                observation_kind:
                    StaticDeriverAObservationKindVectorV1::StaticConsumingDeriverAEvaluationInputs,
                source_case_id: ACTIVATION_CASE_ID_V1.to_owned(),
                source_stage: stage,
                extension: DeriverAEmptyExtensionV1::DeriverAEmpty,
            },
            deriver_b: StaticDeriverBObservationVectorV1 {
                observation_kind:
                    StaticDeriverBObservationKindVectorV1::StaticConsumingDeriverBEvaluationInputs,
                source_case_id: ACTIVATION_CASE_ID_V1.to_owned(),
                source_stage: stage,
                extension: DeriverBEmptyExtensionV1::DeriverBEmpty,
            },
        },
        host_only_ideal_function_randomness:
            ActivationNoIdealRandomnessVectorV1::ActivationNoIdealFunctionRandomness,
    }
}

fn export_case() -> ExportEvaluationInputVectorV1 {
    let deriver_a_view = export_view_set().observe_deriver_a_v1();
    let common_public = producing_common!(deriver_a_view.common(), CeremonyRequestKindV1::Export);
    let stage = common_public.stage;
    let deriver_a = export_deriver_a_extension(&deriver_a_view);

    let deriver_b_view = export_view_set().observe_deriver_b_v1();
    assert_eq!(
        producing_common!(deriver_b_view.common(), CeremonyRequestKindV1::Export),
        common_public
    );
    let deriver_b = export_deriver_b_extension(&deriver_b_view);

    let client_view = export_view_set().observe_client_v1();
    assert_eq!(
        producing_common!(client_view.common(), CeremonyRequestKindV1::Export),
        common_public
    );
    require_empty_kind(
        client_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::ClientEmpty,
    );
    let signing_worker_view = export_view_set().observe_signing_worker_v1();
    assert_eq!(
        producing_common!(signing_worker_view.common(), CeremonyRequestKindV1::Export),
        common_public
    );
    require_empty_kind(
        signing_worker_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::SigningWorkerEmpty,
    );
    let router_view = export_view_set().observe_router_v1();
    assert_eq!(
        producing_common!(router_view.common(), CeremonyRequestKindV1::Export),
        common_public
    );
    require_empty_kind(
        router_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::RouterEmpty,
    );
    let observer_view = export_view_set().observe_observer_v1();
    assert_eq!(
        producing_common!(observer_view.common(), CeremonyRequestKindV1::Export),
        common_public
    );
    require_empty_kind(
        observer_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::ObserverEmpty,
    );
    let diagnostics_view = export_view_set().observe_diagnostics_v1();
    assert_eq!(
        producing_common!(diagnostics_view.common(), CeremonyRequestKindV1::Export),
        common_public
    );
    require_empty_kind(
        diagnostics_view.kind(),
        HostOnlyEvaluationInputExtensionKindV1::DiagnosticsEmpty,
    );

    let static_deriver_a_view = export_view_set().observe_deriver_a_v1();
    assert_eq!(
        producing_common!(
            static_deriver_a_view.common(),
            CeremonyRequestKindV1::Export
        ),
        common_public
    );
    let static_deriver_a = export_deriver_a_extension(&static_deriver_a_view);
    let static_deriver_b_view = export_view_set().observe_deriver_b_v1();
    assert_eq!(
        producing_common!(
            static_deriver_b_view.common(),
            CeremonyRequestKindV1::Export
        ),
        common_public
    );
    let static_deriver_b = export_deriver_b_extension(&static_deriver_b_view);

    ExportEvaluationInputVectorV1 {
        case_id: EXPORT_CASE_ID_V1.to_owned(),
        stage,
        host_only_source_references: producing_sources(
            EXPORT_CEREMONY_CASE_ID_V1,
            EXPORT_PROVENANCE_CASE_ID_V1,
            EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            EXPORT_OUTPUT_VIEW_CASE_ID_V1,
        ),
        common_public,
        role_extensions: ExportRoleExtensionsVectorV1 {
            deriver_a,
            deriver_b,
            client: ClientEmptyExtensionV1::ClientEmpty,
            signing_worker: SigningWorkerEmptyExtensionV1::SigningWorkerEmpty,
            router: RouterEmptyExtensionV1::RouterEmpty,
            observer: ObserverEmptyExtensionV1::ObserverEmpty,
            diagnostics_logs: DiagnosticsEmptyExtensionV1::DiagnosticsEmpty,
        },
        static_deriver_observations: StaticDeriverObservationsVectorV1 {
            deriver_a: StaticDeriverAObservationVectorV1 {
                observation_kind:
                    StaticDeriverAObservationKindVectorV1::StaticConsumingDeriverAEvaluationInputs,
                source_case_id: EXPORT_CASE_ID_V1.to_owned(),
                source_stage: stage,
                extension: static_deriver_a,
            },
            deriver_b: StaticDeriverBObservationVectorV1 {
                observation_kind:
                    StaticDeriverBObservationKindVectorV1::StaticConsumingDeriverBEvaluationInputs,
                source_case_id: EXPORT_CASE_ID_V1.to_owned(),
                source_stage: stage,
                extension: static_deriver_b,
            },
        },
        host_only_ideal_function_randomness: export_randomness(),
    }
}

fn registration_view_set() -> HostOnlyRegistrationEvaluationInputViewSetV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) = canonical_registration_ceremony_fixture_v1();
    let request = RegistrationRequestV1::new(context, authorization, transcript)
        .expect("canonical registration request");
    let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Registration,
        fixture.registered_public_key,
    );
    let prepared = prepare_host_only_registration_reference_v1(registration_inputs(&fixture));
    build_host_only_registration_evaluation_input_view_set_v1(&request, &provenance, &prepared)
        .expect("canonical registration input views")
}

fn recovery_view_set() -> HostOnlyRecoveryEvaluationInputViewSetV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) = canonical_recovery_ceremony_fixture_v1();
    let request = RecoveryRequestV1::new(context, authorization, transcript)
        .expect("canonical recovery request");
    let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Recovery,
        fixture.registered_public_key,
    );
    let prepared = prepare_host_only_recovery_reference_v1(recovery_inputs(&fixture))
        .expect("canonical recovery preparation");
    build_host_only_recovery_evaluation_input_view_set_v1(&request, &provenance, &prepared)
        .expect("canonical recovery input views")
}

fn refresh_view_set() -> HostOnlyRefreshEvaluationInputViewSetV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) = canonical_refresh_ceremony_fixture_v1();
    let request = RefreshRequestV1::new(context, authorization, transcript)
        .expect("canonical refresh request");
    let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Refresh,
        fixture.registered_public_key,
    );
    let prepared = prepare_host_only_refresh_reference_v1(refresh_inputs(&fixture))
        .expect("canonical refresh preparation");
    build_host_only_refresh_evaluation_input_view_set_v1(&request, &provenance, &prepared)
        .expect("canonical refresh input views")
}

fn activation_view_set() -> HostOnlyActivationContinuationInputViewSetV1 {
    let request = canonical_activation_request_v1(ActivationPackageOriginV1::Registration);
    build_host_only_activation_continuation_input_view_set_v1(
        &request,
        HostOnlyActivationNoIdealCoinsV1::from_host_only_fixture(),
    )
}

fn export_view_set() -> HostOnlyExportEvaluationInputViewSetV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) =
        canonical_export_ceremony_fixture_for_registered_key_v1(fixture.registered_public_key);
    let request =
        ExportRequestV1::new(context, authorization, transcript).expect("canonical export request");
    let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Export,
        fixture.registered_public_key,
    );
    let prepared = prepare_host_only_export_reference_v1(
        export_inputs(&fixture),
        &fixture.registered_public_key,
    )
    .expect("canonical export preparation");
    build_host_only_export_evaluation_input_view_set_v1(&request, &provenance, &prepared)
        .expect("canonical export input views")
}

fn activation_deriver_a_extension<Common>(
    view: &HostOnlyDeriverAActivationEvaluationInputViewV1<Common>,
) -> DeriverAActivationEvaluationInputsExtensionV1 {
    let contribution = view.contribution();
    DeriverAActivationEvaluationInputsExtensionV1::DeriverAActivationEvaluationInputs {
        y_client_hex: encode_hex(&contribution.y_client().expose_bytes()),
        y_server_hex: encode_hex(&contribution.y_server().expose_bytes()),
        tau_client_hex: encode_hex(&contribution.tau_client().expose_bytes()),
        tau_server_hex: encode_hex(&contribution.tau_server().expose_bytes()),
    }
}

fn activation_deriver_b_extension<Common>(
    view: &HostOnlyDeriverBActivationEvaluationInputViewV1<Common>,
) -> DeriverBActivationEvaluationInputsExtensionV1 {
    let contribution = view.contribution();
    DeriverBActivationEvaluationInputsExtensionV1::DeriverBActivationEvaluationInputs {
        y_client_hex: encode_hex(&contribution.y_client().expose_bytes()),
        y_server_hex: encode_hex(&contribution.y_server().expose_bytes()),
        tau_client_hex: encode_hex(&contribution.tau_client().expose_bytes()),
        tau_server_hex: encode_hex(&contribution.tau_server().expose_bytes()),
    }
}

fn export_deriver_a_extension(
    view: &HostOnlyDeriverAExportEvaluationInputViewV1,
) -> DeriverAExportEvaluationInputsExtensionV1 {
    DeriverAExportEvaluationInputsExtensionV1::DeriverAExportEvaluationInputs {
        y_client_hex: encode_hex(&view.y_client().expose_bytes()),
        y_server_hex: encode_hex(&view.y_server().expose_bytes()),
    }
}

fn export_deriver_b_extension(
    view: &HostOnlyDeriverBExportEvaluationInputViewV1,
) -> DeriverBExportEvaluationInputsExtensionV1 {
    DeriverBExportEvaluationInputsExtensionV1::DeriverBExportEvaluationInputs {
        y_client_hex: encode_hex(&view.y_client().expose_bytes()),
        y_server_hex: encode_hex(&view.y_server().expose_bytes()),
    }
}

fn activation_common(
    common: &crate::evaluation_input_views::HostOnlyActivationContinuationInputCommonV1,
) -> ActivationCommonPublicVectorV1 {
    ActivationCommonPublicVectorV1 {
        stage: stage_vector(common.stage()),
        request_kind: CeremonyRequestKindV1::Activation,
        evaluation_plan: evaluation_plan_vector(
            common.evaluation_plan(),
            common.evaluation_counts(),
        ),
        public_request_context_digest_hex: encode_hex(common.request_context_digest().as_bytes()),
        authorization_digest_hex: encode_hex(common.authorization_digest().as_bytes()),
        transcript_digest_hex: encode_hex(common.transcript_digest().as_bytes()),
    }
}

fn evaluation_plan_vector(
    plan: HostOnlyEvaluationPlanV1,
    counts: HostOnlyEvaluationWindowCountsV1,
) -> EvaluationPlanVectorV1 {
    let kind = match plan {
        HostOnlyEvaluationPlanV1::OneActivationEvaluation => {
            EvaluationPlanKindVectorV1::OneActivationEvaluation
        }
        HostOnlyEvaluationPlanV1::ZeroEvaluationContinuation => {
            EvaluationPlanKindVectorV1::ZeroEvaluationContinuation
        }
        HostOnlyEvaluationPlanV1::OneExportEvaluation => {
            EvaluationPlanKindVectorV1::OneExportEvaluation
        }
    };
    EvaluationPlanVectorV1 {
        kind,
        counts: EvaluationWindowCountsVectorV1 {
            yao_evaluations: counts.yao_evaluations(),
            deriver_a_invocations: counts.deriver_a_invocations(),
            deriver_b_invocations: counts.deriver_b_invocations(),
            contribution_derivations: counts.contribution_derivations(),
            ideal_output_share_samples: counts.ideal_output_share_samples(),
        },
    }
}

fn stage_vector(stage: HostOnlyEvaluationInputStageV1) -> EvaluationInputStageVectorV1 {
    match stage {
        HostOnlyEvaluationInputStageV1::RegistrationEvaluationAccepted => {
            EvaluationInputStageVectorV1::Registration
        }
        HostOnlyEvaluationInputStageV1::ActivationContinuationAccepted => {
            EvaluationInputStageVectorV1::Activation
        }
        HostOnlyEvaluationInputStageV1::RecoveryEvaluationAccepted => {
            EvaluationInputStageVectorV1::Recovery
        }
        HostOnlyEvaluationInputStageV1::RefreshEvaluationAccepted => {
            EvaluationInputStageVectorV1::Refresh
        }
        HostOnlyEvaluationInputStageV1::ExportEvaluationAccepted => {
            EvaluationInputStageVectorV1::Export
        }
    }
}

fn producing_sources(
    ceremony: &str,
    provenance: &str,
    semantic: &str,
    output: &str,
) -> ProducingSourceReferencesVectorV1 {
    ProducingSourceReferencesVectorV1 {
        ceremony_context_case_id: ceremony.to_owned(),
        provenance_case_id: provenance.to_owned(),
        semantic_lifecycle_case_id: semantic.to_owned(),
        output_party_view_case_id: output.to_owned(),
    }
}

fn activation_randomness() -> ActivationFamilyIdealRandomnessVectorV1 {
    let coins = activation_coins(3, 5);
    ActivationFamilyIdealRandomnessVectorV1::ActivationFamilyOutputSharingCoins {
        client_scalar_coin_hex: encode_hex(&coins.client().expose_fixture_bytes()),
        signing_worker_scalar_coin_hex: encode_hex(&coins.signing_worker().expose_fixture_bytes()),
    }
}

fn export_randomness() -> ExportIdealRandomnessVectorV1 {
    let coin = export_coin();
    ExportIdealRandomnessVectorV1::ExportSeedOutputCoin {
        seed_output_coin_hex: encode_hex(&coin.expose_fixture_bytes()),
    }
}

fn require_empty_kind(
    actual: HostOnlyEvaluationInputExtensionKindV1,
    expected: HostOnlyEvaluationInputExtensionKindV1,
) {
    assert_eq!(actual, expected);
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
