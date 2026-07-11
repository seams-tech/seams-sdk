//! Strict synthetic corpus for profile-neutral output-custody party views.

use core::fmt;

use serde::Serialize;

use crate::ceremony_context::CeremonyRequestKindV1;
use crate::lifecycle_domain::{ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1};
use crate::output_party_views::{
    build_host_only_activation_metadata_consumed_party_view_set_v1,
    build_host_only_activation_package_prepared_party_view_set_v1,
    build_host_only_export_released_party_view_set_v1,
    HostOnlyActivationMetadataConsumedPartyViewSetV1,
    HostOnlyActivationPackagePreparedPartyViewSetV1, HostOnlyCommonOutputPublicLeakageV1,
    HostOnlyDeriverAActivationOutputPartyViewV1, HostOnlyDeriverAExportOutputPartyViewV1,
    HostOnlyDeriverBActivationOutputPartyViewV1, HostOnlyDeriverBExportOutputPartyViewV1,
    HostOnlyExportReleasedPartyViewSetV1, HostOnlyExportStateEffectV1,
    HostOnlyOutputPartyViewCircuitFamilyV1, HostOnlyOutputPartyViewStageV1,
    HostOnlyOutputPartyViewTerminalV1,
};
use crate::provenance::{PROVENANCE_DERIVER_A_ROLE_TAG_V1, PROVENANCE_DERIVER_B_ROLE_TAG_V1};
use crate::semantic_artifacts::{
    ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1,
    EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1, EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
    EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1,
};
use crate::semantic_lifecycle_fixtures::{
    canonical_activation_metadata_success_v1, canonical_export_released_v1, recovery_pending,
    refresh_pending, registration_pending, ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1, RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1, REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
};

/// Schema identifier for the strict output-party-view corpus.
pub const OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:output-party-views-vectors:v1";
/// Scope preventing synthetic custody evidence from becoming a runtime format.
pub const OUTPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_output_party_views_v1";

const REGISTRATION_OUTPUT_PARTY_VIEW_CASE_ID_V1: &str =
    "registration_output_party_views_package_prepared_v1";
const ACTIVATION_OUTPUT_PARTY_VIEW_CASE_ID_V1: &str =
    "activation_output_party_views_metadata_consumed_v1";
const RECOVERY_OUTPUT_PARTY_VIEW_CASE_ID_V1: &str =
    "recovery_output_party_views_package_prepared_v1";
const REFRESH_OUTPUT_PARTY_VIEW_CASE_ID_V1: &str = "refresh_output_party_views_package_prepared_v1";
const EXPORT_OUTPUT_PARTY_VIEW_CASE_ID_V1: &str = "export_output_party_views_released_v1";

const ACTIVATION_CIRCUIT_ID_V1: &str = "ed25519_yao_activation_v1";
const EXPORT_CIRCUIT_ID_V1: &str = "ed25519_yao_export_v1";
const CLIENT_RECIPIENT_TAG_V1: u8 = 0x01;
const SIGNING_WORKER_RECIPIENT_TAG_V1: u8 = 0x02;
const CLIENT_SCALAR_OUTPUT_TAG_V1: u8 = 0x01;
const SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1: u8 = 0x02;
const CLIENT_SEED_OUTPUT_TAG_V1: u8 = 0x03;

/// Strict five-case synthetic output-party-view corpus.
#[derive(Serialize)]
pub struct OutputPartyViewVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<OutputPartyViewVectorCaseV1>,
}

impl OutputPartyViewVectorCorpusV1 {
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

    /// Returns the fixed top-level case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
#[serde(tag = "request_kind", content = "vector", rename_all = "snake_case")]
enum OutputPartyViewVectorCaseV1 {
    Registration(ActivationPackagePreparedVectorV1),
    Activation(ActivationMetadataConsumedVectorV1),
    Recovery(ActivationPackagePreparedVectorV1),
    Refresh(ActivationPackagePreparedVectorV1),
    Export(ExportReleasedVectorV1),
}

#[derive(Serialize)]
struct ActivationPackagePreparedVectorV1 {
    case_id: String,
    stage: OutputPartyViewStageVectorV1,
    common_public: ActivationPackagePreparedCommonPublicVectorV1,
    role_extensions: ActivationPackagePreparedRoleExtensionsVectorV1,
    static_deriver_observations: StaticDeriverObservationsVectorV1<
        DeriverAActivationScalarSharesExtensionV1,
        DeriverBActivationScalarSharesExtensionV1,
    >,
}

#[derive(Serialize)]
struct ActivationMetadataConsumedVectorV1 {
    case_id: String,
    stage: OutputPartyViewStageVectorV1,
    common_public: ActivationMetadataConsumedCommonPublicVectorV1,
    role_extensions: ActivationMetadataConsumedRoleExtensionsVectorV1,
    static_deriver_observations: StaticDeriverObservationsVectorV1<
        DeriverANoNewPrivateOutputExtensionV1,
        DeriverBNoNewPrivateOutputExtensionV1,
    >,
}

#[derive(Serialize)]
struct ExportReleasedVectorV1 {
    case_id: String,
    stage: OutputPartyViewStageVectorV1,
    common_public: ExportReleasedCommonPublicVectorV1,
    role_extensions: ExportReleasedRoleExtensionsVectorV1,
    static_deriver_observations: StaticDeriverObservationsVectorV1<
        DeriverASeedShareExtensionV1,
        DeriverBSeedShareExtensionV1,
    >,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputPartyViewStageVectorV1 {
    RegistrationPackagePrepared,
    RecoveryPackagePrepared,
    RefreshPackagePrepared,
    ActivationMetadataConsumed,
    ExportReleased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputPartyViewTerminalVectorV1 {
    OutputCommitted,
    MetadataConsumed,
    ExportReleased,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputPartyViewStateEffectVectorV1 {
    RegisteredStateRetained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputPartyViewRoleVectorV1 {
    DeriverA,
    DeriverB,
}

impl OutputPartyViewRoleVectorV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::DeriverA => PROVENANCE_DERIVER_A_ROLE_TAG_V1,
            Self::DeriverB => PROVENANCE_DERIVER_B_ROLE_TAG_V1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputPartyViewRecipientVectorV1 {
    Client,
    SigningWorker,
}

impl OutputPartyViewRecipientVectorV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Client => CLIENT_RECIPIENT_TAG_V1,
            Self::SigningWorker => SIGNING_WORKER_RECIPIENT_TAG_V1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputPartyViewOutputFamilyVectorV1 {
    ClientScalar,
    SigningWorkerScalar,
    ClientSeed,
}

impl OutputPartyViewOutputFamilyVectorV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::ClientScalar => CLIENT_SCALAR_OUTPUT_TAG_V1,
            Self::SigningWorkerScalar => SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1,
            Self::ClientSeed => CLIENT_SEED_OUTPUT_TAG_V1,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ActivationPackagePreparedCommonPublicVectorV1 {
    semantic_lifecycle_case_id: String,
    stage: OutputPartyViewStageVectorV1,
    request_kind: CeremonyRequestKindV1,
    circuit_id: String,
    public_request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    transport_binding_digest_hex: String,
    artifact_suite_digest_hex: String,
    one_use_execution_id_hex: String,
    input_provenance_pair_digest_hex: String,
    host_reference_evaluation_evidence_digest_hex: String,
    package_projection: ActivationPackageProjectionVectorV1,
    package_set_digest_hex: String,
    receipt_body_digest_hex: String,
    activation_epoch: u64,
    registered_public_key_hex: String,
    x_client_hex: String,
    x_server_hex: String,
    deriver_a_receipt_evidence_digest_hex: String,
    deriver_b_receipt_evidence_digest_hex: String,
    terminal_state: OutputPartyViewTerminalVectorV1,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ActivationPackageProjectionVectorV1 {
    deriver_a_client: ActivationPackageProjectionMemberVectorV1,
    deriver_b_client: ActivationPackageProjectionMemberVectorV1,
    deriver_a_signing_worker: ActivationPackageProjectionMemberVectorV1,
    deriver_b_signing_worker: ActivationPackageProjectionMemberVectorV1,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ActivationPackageProjectionMemberVectorV1 {
    role: OutputPartyViewRoleVectorV1,
    recipient: OutputPartyViewRecipientVectorV1,
    output_family: OutputPartyViewOutputFamilyVectorV1,
    recipient_key_binding_hex: String,
    share_point_hex: String,
    recipient_protection_digest_hex: String,
    recipient_ciphertext_digest_hex: String,
    ciphertext_length: u64,
    output_binding_digest_hex: String,
    package_authentication_digest_hex: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ActivationMetadataConsumedCommonPublicVectorV1 {
    semantic_lifecycle_case_id: String,
    stage: OutputPartyViewStageVectorV1,
    request_kind: CeremonyRequestKindV1,
    circuit_id: String,
    origin_metadata_projections: Vec<ActivationOriginMetadataProjectionVectorV1>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ActivationOriginMetadataProjectionVectorV1 {
    origin_kind: CeremonyRequestKindV1,
    origin_case_id: String,
    origin_request_context_digest_hex: String,
    origin_authorization_digest_hex: String,
    origin_transcript_digest_hex: String,
    one_use_execution_id_hex: String,
    package_set_digest_hex: String,
    receipt_body_digest_hex: String,
    activation_epoch: u64,
    registered_public_key_hex: String,
    activation_request_context_digest_hex: String,
    activation_authorization_digest_hex: String,
    activation_transcript_digest_hex: String,
    terminal_state: OutputPartyViewTerminalVectorV1,
    zero_reevaluation: ZeroReevaluationVectorV1,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ZeroReevaluationVectorV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ExportReleasedCommonPublicVectorV1 {
    semantic_lifecycle_case_id: String,
    stage: OutputPartyViewStageVectorV1,
    request_kind: CeremonyRequestKindV1,
    circuit_id: String,
    public_request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    transport_binding_digest_hex: String,
    artifact_suite_digest_hex: String,
    one_use_execution_id_hex: String,
    input_provenance_pair_digest_hex: String,
    host_reference_evaluation_evidence_digest_hex: String,
    package_projection: ExportPackageProjectionVectorV1,
    package_set_digest_hex: String,
    receipt_body_digest_hex: String,
    registered_public_key_hex: String,
    output_committed_receipt_digest_hex: String,
    client_delivery_evidence_digest_hex: String,
    export_authorization_consumption_evidence_digest_hex: String,
    terminal_state: OutputPartyViewTerminalVectorV1,
    state_effect: OutputPartyViewStateEffectVectorV1,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ExportPackageProjectionVectorV1 {
    deriver_a_client: ExportPackageProjectionMemberVectorV1,
    deriver_b_client: ExportPackageProjectionMemberVectorV1,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ExportPackageProjectionMemberVectorV1 {
    role: OutputPartyViewRoleVectorV1,
    recipient: OutputPartyViewRecipientVectorV1,
    output_family: OutputPartyViewOutputFamilyVectorV1,
    recipient_key_binding_hex: String,
    recipient_protection_digest_hex: String,
    recipient_ciphertext_digest_hex: String,
    ciphertext_length: u64,
    output_binding_digest_hex: String,
    package_authentication_digest_hex: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverAActivationScalarSharesExtensionV1 {
    DeriverAActivationScalarShares {
        client_scalar_share_hex: String,
        signing_worker_scalar_share_hex: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverBActivationScalarSharesExtensionV1 {
    DeriverBActivationScalarShares {
        client_scalar_share_hex: String,
        signing_worker_scalar_share_hex: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverASeedShareExtensionV1 {
    DeriverASeedShare { seed_share_hex: String },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DeriverBSeedShareExtensionV1 {
    DeriverBSeedShare { seed_share_hex: String },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ClientAuthorizedSeedExtensionV1 {
    ClientAuthorizedSeed { seed_hex: String },
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

define_empty_extension!(
    SigningWorkerNoPrivateOutputExtensionV1,
    SigningWorkerNoPrivateOutput
);
define_empty_extension!(RouterNoPrivateOutputExtensionV1, RouterNoPrivateOutput);
define_empty_extension!(ObserverNoPrivateOutputExtensionV1, ObserverNoPrivateOutput);
define_empty_extension!(ClientNoPrivateOutputExtensionV1, ClientNoPrivateOutput);
define_empty_extension!(
    DiagnosticsLogsNoPrivateOutputExtensionV1,
    DiagnosticsLogsNoPrivateOutput
);
define_empty_extension!(
    DeriverANoNewPrivateOutputExtensionV1,
    DeriverANoNewPrivateOutput
);
define_empty_extension!(
    DeriverBNoNewPrivateOutputExtensionV1,
    DeriverBNoNewPrivateOutput
);
define_empty_extension!(
    ClientNoNewPrivateOutputExtensionV1,
    ClientNoNewPrivateOutput
);
define_empty_extension!(
    SigningWorkerNoNewPrivateOutputExtensionV1,
    SigningWorkerNoNewPrivateOutput
);
define_empty_extension!(
    RouterNoNewPrivateOutputExtensionV1,
    RouterNoNewPrivateOutput
);
define_empty_extension!(
    ObserverNoNewPrivateOutputExtensionV1,
    ObserverNoNewPrivateOutput
);
define_empty_extension!(
    DiagnosticsLogsNoNewPrivateOutputExtensionV1,
    DiagnosticsLogsNoNewPrivateOutput
);
define_empty_extension!(
    SigningWorkerNoExportOutputExtensionV1,
    SigningWorkerNoExportOutput
);

#[derive(Serialize)]
struct ActivationPackagePreparedRoleExtensionsVectorV1 {
    deriver_a: DeriverAActivationScalarSharesExtensionV1,
    deriver_b: DeriverBActivationScalarSharesExtensionV1,
    client: ClientNoPrivateOutputExtensionV1,
    signing_worker: SigningWorkerNoPrivateOutputExtensionV1,
    router: RouterNoPrivateOutputExtensionV1,
    observer: ObserverNoPrivateOutputExtensionV1,
    diagnostics_logs: DiagnosticsLogsNoPrivateOutputExtensionV1,
}

#[derive(Serialize)]
struct ActivationMetadataConsumedRoleExtensionsVectorV1 {
    deriver_a: DeriverANoNewPrivateOutputExtensionV1,
    deriver_b: DeriverBNoNewPrivateOutputExtensionV1,
    client: ClientNoNewPrivateOutputExtensionV1,
    signing_worker: SigningWorkerNoNewPrivateOutputExtensionV1,
    router: RouterNoNewPrivateOutputExtensionV1,
    observer: ObserverNoNewPrivateOutputExtensionV1,
    diagnostics_logs: DiagnosticsLogsNoNewPrivateOutputExtensionV1,
}

#[derive(Serialize)]
struct ExportReleasedRoleExtensionsVectorV1 {
    deriver_a: DeriverASeedShareExtensionV1,
    deriver_b: DeriverBSeedShareExtensionV1,
    client: ClientAuthorizedSeedExtensionV1,
    signing_worker: SigningWorkerNoExportOutputExtensionV1,
    router: RouterNoPrivateOutputExtensionV1,
    observer: ObserverNoPrivateOutputExtensionV1,
    diagnostics_logs: DiagnosticsLogsNoPrivateOutputExtensionV1,
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
    source_stage: OutputPartyViewStageVectorV1,
    extension: Extension,
}

#[derive(Serialize)]
struct StaticDeriverBObservationVectorV1<Extension> {
    observation_kind: StaticDeriverBObservationKindVectorV1,
    source_case_id: String,
    source_stage: OutputPartyViewStageVectorV1,
    extension: Extension,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StaticDeriverAObservationKindVectorV1 {
    StaticConsumingDeriverA,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StaticDeriverBObservationKindVectorV1 {
    StaticConsumingDeriverB,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ParsedSemanticCeremonyBindingV1 {
    public_request_context_digest: [u8; 32],
    authorization_digest: [u8; 32],
    transcript_digest: [u8; 32],
    transport_binding_digest: [u8; 32],
    artifact_suite_digest: [u8; 32],
    one_use_execution_id: [u8; 32],
    input_provenance_pair_digest: [u8; 32],
    host_reference_evaluation_evidence_digest: [u8; 32],
}

struct ParsedActivationDescriptorV1 {
    ceremony: ParsedSemanticCeremonyBindingV1,
    activation_epoch: u64,
    projection: ActivationPackageProjectionMemberVectorV1,
}

struct ParsedExportDescriptorV1 {
    ceremony: ParsedSemanticCeremonyBindingV1,
    projection: ExportPackageProjectionMemberVectorV1,
}

struct ParsedActivationReceiptV1 {
    ceremony: ParsedSemanticCeremonyBindingV1,
    activation_epoch: u64,
    package_set_digest: [u8; 32],
    x_client: [u8; 32],
    x_server: [u8; 32],
    registered_public_key: [u8; 32],
    deriver_a_receipt_evidence_digest: [u8; 32],
    deriver_b_receipt_evidence_digest: [u8; 32],
}

struct ParsedExportReceiptV1 {
    ceremony: ParsedSemanticCeremonyBindingV1,
    package_set_digest: [u8; 32],
    registered_public_key: [u8; 32],
    output_committed_receipt_digest: [u8; 32],
    client_delivery_evidence_digest: [u8; 32],
    export_authorization_consumption_evidence_digest: [u8; 32],
}

/// Failure returned for any noncanonical output-party-view corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputPartyViewVectorCorpusParseErrorV1;

impl fmt::Display for OutputPartyViewVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "output party-view corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for OutputPartyViewVectorCorpusParseErrorV1 {}

/// Builds the canonical five-case synthetic output-party-view corpus.
pub fn canonical_output_party_view_vector_corpus_v1() -> OutputPartyViewVectorCorpusV1 {
    OutputPartyViewVectorCorpusV1 {
        schema: OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: OUTPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            OutputPartyViewVectorCaseV1::Registration(activation_package_prepared_case(
                ActivationPackageOriginV1::Registration,
            )),
            OutputPartyViewVectorCaseV1::Activation(activation_metadata_consumed_case()),
            OutputPartyViewVectorCaseV1::Recovery(activation_package_prepared_case(
                ActivationPackageOriginV1::Recovery,
            )),
            OutputPartyViewVectorCaseV1::Refresh(activation_package_prepared_case(
                ActivationPackageOriginV1::Refresh,
            )),
            OutputPartyViewVectorCaseV1::Export(export_released_case()),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_output_party_view_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded = serde_json::to_vec_pretty(&canonical_output_party_view_vector_corpus_v1())
        .expect("fixed output party-view corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_output_party_view_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<OutputPartyViewVectorCorpusV1, OutputPartyViewVectorCorpusParseErrorV1> {
    if encoded != canonical_output_party_view_vector_corpus_json_bytes_v1() {
        return Err(OutputPartyViewVectorCorpusParseErrorV1);
    }
    Ok(canonical_output_party_view_vector_corpus_v1())
}

fn activation_package_prepared_case(
    origin: ActivationPackageOriginV1,
) -> ActivationPackagePreparedVectorV1 {
    let (case_id, stage) = activation_case_identity(origin);

    let deriver_a_view = activation_package_prepared_view_set(origin).observe_deriver_a_v1();
    let common_public = activation_package_prepared_common(deriver_a_view.common(), origin);
    let deriver_a = activation_deriver_a_extension(&deriver_a_view);

    let deriver_b_view = activation_package_prepared_view_set(origin).observe_deriver_b_v1();
    require_equal_activation_package_common(deriver_b_view.common(), origin, &common_public);
    let deriver_b = activation_deriver_b_extension(&deriver_b_view);

    let client_view = activation_package_prepared_view_set(origin).observe_client_v1();
    require_equal_activation_package_common(client_view.common(), origin, &common_public);
    let client = ClientNoPrivateOutputExtensionV1::ClientNoPrivateOutput;

    let signing_worker_view =
        activation_package_prepared_view_set(origin).observe_signing_worker_v1();
    require_equal_activation_package_common(signing_worker_view.common(), origin, &common_public);
    let router_view = activation_package_prepared_view_set(origin).observe_router_v1();
    require_equal_activation_package_common(router_view.common(), origin, &common_public);
    let observer_view = activation_package_prepared_view_set(origin).observe_observer_v1();
    require_equal_activation_package_common(observer_view.common(), origin, &common_public);
    let diagnostics_view = activation_package_prepared_view_set(origin).observe_diagnostics_v1();
    require_equal_activation_package_common(diagnostics_view.common(), origin, &common_public);

    let static_deriver_a_view = activation_package_prepared_view_set(origin).observe_deriver_a_v1();
    require_equal_activation_package_common(static_deriver_a_view.common(), origin, &common_public);
    let static_deriver_a = activation_deriver_a_extension(&static_deriver_a_view);
    let static_deriver_b_view = activation_package_prepared_view_set(origin).observe_deriver_b_v1();
    require_equal_activation_package_common(static_deriver_b_view.common(), origin, &common_public);
    let static_deriver_b = activation_deriver_b_extension(&static_deriver_b_view);

    ActivationPackagePreparedVectorV1 {
        case_id: case_id.to_owned(),
        stage,
        common_public,
        role_extensions: ActivationPackagePreparedRoleExtensionsVectorV1 {
            deriver_a,
            deriver_b,
            client,
            signing_worker: SigningWorkerNoPrivateOutputExtensionV1::SigningWorkerNoPrivateOutput,
            router: RouterNoPrivateOutputExtensionV1::RouterNoPrivateOutput,
            observer: ObserverNoPrivateOutputExtensionV1::ObserverNoPrivateOutput,
            diagnostics_logs:
                DiagnosticsLogsNoPrivateOutputExtensionV1::DiagnosticsLogsNoPrivateOutput,
        },
        static_deriver_observations: StaticDeriverObservationsVectorV1 {
            deriver_a: StaticDeriverAObservationVectorV1 {
                observation_kind: StaticDeriverAObservationKindVectorV1::StaticConsumingDeriverA,
                source_case_id: case_id.to_owned(),
                source_stage: stage,
                extension: static_deriver_a,
            },
            deriver_b: StaticDeriverBObservationVectorV1 {
                observation_kind: StaticDeriverBObservationKindVectorV1::StaticConsumingDeriverB,
                source_case_id: case_id.to_owned(),
                source_stage: stage,
                extension: static_deriver_b,
            },
        },
    }
}

fn activation_metadata_consumed_case() -> ActivationMetadataConsumedVectorV1 {
    let stage = OutputPartyViewStageVectorV1::ActivationMetadataConsumed;
    let origin_metadata_projections = [
        ActivationPackageOriginV1::Registration,
        ActivationPackageOriginV1::Recovery,
        ActivationPackageOriginV1::Refresh,
    ]
    .into_iter()
    .map(activation_origin_metadata_projection)
    .collect();

    ActivationMetadataConsumedVectorV1 {
        case_id: ACTIVATION_OUTPUT_PARTY_VIEW_CASE_ID_V1.to_owned(),
        stage,
        common_public: ActivationMetadataConsumedCommonPublicVectorV1 {
            semantic_lifecycle_case_id: ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
            stage,
            request_kind: CeremonyRequestKindV1::Activation,
            circuit_id: ACTIVATION_CIRCUIT_ID_V1.to_owned(),
            origin_metadata_projections,
        },
        role_extensions: ActivationMetadataConsumedRoleExtensionsVectorV1 {
            deriver_a: DeriverANoNewPrivateOutputExtensionV1::DeriverANoNewPrivateOutput,
            deriver_b: DeriverBNoNewPrivateOutputExtensionV1::DeriverBNoNewPrivateOutput,
            client: ClientNoNewPrivateOutputExtensionV1::ClientNoNewPrivateOutput,
            signing_worker:
                SigningWorkerNoNewPrivateOutputExtensionV1::SigningWorkerNoNewPrivateOutput,
            router: RouterNoNewPrivateOutputExtensionV1::RouterNoNewPrivateOutput,
            observer: ObserverNoNewPrivateOutputExtensionV1::ObserverNoNewPrivateOutput,
            diagnostics_logs:
                DiagnosticsLogsNoNewPrivateOutputExtensionV1::DiagnosticsLogsNoNewPrivateOutput,
        },
        static_deriver_observations: StaticDeriverObservationsVectorV1 {
            deriver_a: StaticDeriverAObservationVectorV1 {
                observation_kind: StaticDeriverAObservationKindVectorV1::StaticConsumingDeriverA,
                source_case_id: ACTIVATION_OUTPUT_PARTY_VIEW_CASE_ID_V1.to_owned(),
                source_stage: stage,
                extension: DeriverANoNewPrivateOutputExtensionV1::DeriverANoNewPrivateOutput,
            },
            deriver_b: StaticDeriverBObservationVectorV1 {
                observation_kind: StaticDeriverBObservationKindVectorV1::StaticConsumingDeriverB,
                source_case_id: ACTIVATION_OUTPUT_PARTY_VIEW_CASE_ID_V1.to_owned(),
                source_stage: stage,
                extension: DeriverBNoNewPrivateOutputExtensionV1::DeriverBNoNewPrivateOutput,
            },
        },
    }
}

fn export_released_case() -> ExportReleasedVectorV1 {
    let case_id = EXPORT_OUTPUT_PARTY_VIEW_CASE_ID_V1;
    let stage = OutputPartyViewStageVectorV1::ExportReleased;

    let deriver_a_view = export_released_view_set().observe_deriver_a_v1();
    let common_public = export_released_common(deriver_a_view.common());
    let deriver_a = export_deriver_a_extension(&deriver_a_view);

    let deriver_b_view = export_released_view_set().observe_deriver_b_v1();
    require_equal_export_common(deriver_b_view.common(), &common_public);
    let deriver_b = export_deriver_b_extension(&deriver_b_view);

    let client_view = export_released_view_set().observe_client_v1();
    require_equal_export_common(client_view.common(), &common_public);
    let client = ClientAuthorizedSeedExtensionV1::ClientAuthorizedSeed {
        seed_hex: encode_hex(&client_view.seed().expose_bytes()),
    };

    let signing_worker_view = export_released_view_set().observe_signing_worker_v1();
    require_equal_export_common(signing_worker_view.common(), &common_public);
    let router_view = export_released_view_set().observe_router_v1();
    require_equal_export_common(router_view.common(), &common_public);
    let observer_view = export_released_view_set().observe_observer_v1();
    require_equal_export_common(observer_view.common(), &common_public);
    let diagnostics_view = export_released_view_set().observe_diagnostics_v1();
    require_equal_export_common(diagnostics_view.common(), &common_public);

    let static_deriver_a_view = export_released_view_set().observe_deriver_a_v1();
    require_equal_export_common(static_deriver_a_view.common(), &common_public);
    let static_deriver_a = export_deriver_a_extension(&static_deriver_a_view);
    let static_deriver_b_view = export_released_view_set().observe_deriver_b_v1();
    require_equal_export_common(static_deriver_b_view.common(), &common_public);
    let static_deriver_b = export_deriver_b_extension(&static_deriver_b_view);

    ExportReleasedVectorV1 {
        case_id: case_id.to_owned(),
        stage,
        common_public,
        role_extensions: ExportReleasedRoleExtensionsVectorV1 {
            deriver_a,
            deriver_b,
            client,
            signing_worker: SigningWorkerNoExportOutputExtensionV1::SigningWorkerNoExportOutput,
            router: RouterNoPrivateOutputExtensionV1::RouterNoPrivateOutput,
            observer: ObserverNoPrivateOutputExtensionV1::ObserverNoPrivateOutput,
            diagnostics_logs:
                DiagnosticsLogsNoPrivateOutputExtensionV1::DiagnosticsLogsNoPrivateOutput,
        },
        static_deriver_observations: StaticDeriverObservationsVectorV1 {
            deriver_a: StaticDeriverAObservationVectorV1 {
                observation_kind: StaticDeriverAObservationKindVectorV1::StaticConsumingDeriverA,
                source_case_id: case_id.to_owned(),
                source_stage: stage,
                extension: static_deriver_a,
            },
            deriver_b: StaticDeriverBObservationVectorV1 {
                observation_kind: StaticDeriverBObservationKindVectorV1::StaticConsumingDeriverB,
                source_case_id: case_id.to_owned(),
                source_stage: stage,
                extension: static_deriver_b,
            },
        },
    }
}

fn activation_package_prepared_view_set(
    origin: ActivationPackageOriginV1,
) -> HostOnlyActivationPackagePreparedPartyViewSetV1 {
    let pending = match origin {
        ActivationPackageOriginV1::Registration => registration_pending(),
        ActivationPackageOriginV1::Recovery => recovery_pending(),
        ActivationPackageOriginV1::Refresh => refresh_pending(),
    };
    build_host_only_activation_package_prepared_party_view_set_v1(pending)
        .expect("canonical activation package-prepared party views")
}

fn activation_metadata_consumed_view_set(
    success: &ActivationMetadataConsumptionSuccessV1,
) -> HostOnlyActivationMetadataConsumedPartyViewSetV1 {
    build_host_only_activation_metadata_consumed_party_view_set_v1(success)
        .expect("canonical activation metadata-consumed party views")
}

fn export_released_view_set() -> HostOnlyExportReleasedPartyViewSetV1 {
    build_host_only_export_released_party_view_set_v1(canonical_export_released_v1())
        .expect("canonical export-released party views")
}

fn activation_deriver_a_extension(
    view: &HostOnlyDeriverAActivationOutputPartyViewV1,
) -> DeriverAActivationScalarSharesExtensionV1 {
    DeriverAActivationScalarSharesExtensionV1::DeriverAActivationScalarShares {
        client_scalar_share_hex: encode_hex(&view.output_shares().client().expose_fixture_bytes()),
        signing_worker_scalar_share_hex: encode_hex(
            &view.output_shares().signing_worker().expose_fixture_bytes(),
        ),
    }
}

fn activation_deriver_b_extension(
    view: &HostOnlyDeriverBActivationOutputPartyViewV1,
) -> DeriverBActivationScalarSharesExtensionV1 {
    DeriverBActivationScalarSharesExtensionV1::DeriverBActivationScalarShares {
        client_scalar_share_hex: encode_hex(&view.output_shares().client().expose_fixture_bytes()),
        signing_worker_scalar_share_hex: encode_hex(
            &view.output_shares().signing_worker().expose_fixture_bytes(),
        ),
    }
}

fn export_deriver_a_extension(
    view: &HostOnlyDeriverAExportOutputPartyViewV1,
) -> DeriverASeedShareExtensionV1 {
    DeriverASeedShareExtensionV1::DeriverASeedShare {
        seed_share_hex: encode_hex(&view.seed_share().expose_fixture_bytes()),
    }
}

fn export_deriver_b_extension(
    view: &HostOnlyDeriverBExportOutputPartyViewV1,
) -> DeriverBSeedShareExtensionV1 {
    DeriverBSeedShareExtensionV1::DeriverBSeedShare {
        seed_share_hex: encode_hex(&view.seed_share().expose_fixture_bytes()),
    }
}

fn activation_origin_metadata_projection(
    origin: ActivationPackageOriginV1,
) -> ActivationOriginMetadataProjectionVectorV1 {
    let success = canonical_activation_metadata_success_v1(origin);
    let (origin_case_id, _, origin_request_kind) = activation_semantic_identity(origin);

    let deriver_a_view = activation_metadata_consumed_view_set(&success).observe_deriver_a_v1();
    let projection = activation_origin_projection_from_common(
        deriver_a_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
    );

    let deriver_b_view = activation_metadata_consumed_view_set(&success).observe_deriver_b_v1();
    require_equal_activation_metadata_common(
        deriver_b_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
        &projection,
    );
    let client_view = activation_metadata_consumed_view_set(&success).observe_client_v1();
    require_equal_activation_metadata_common(
        client_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
        &projection,
    );
    let signing_worker_view =
        activation_metadata_consumed_view_set(&success).observe_signing_worker_v1();
    require_equal_activation_metadata_common(
        signing_worker_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
        &projection,
    );
    let router_view = activation_metadata_consumed_view_set(&success).observe_router_v1();
    require_equal_activation_metadata_common(
        router_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
        &projection,
    );
    let observer_view = activation_metadata_consumed_view_set(&success).observe_observer_v1();
    require_equal_activation_metadata_common(
        observer_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
        &projection,
    );
    let diagnostics_view = activation_metadata_consumed_view_set(&success).observe_diagnostics_v1();
    require_equal_activation_metadata_common(
        diagnostics_view.common(),
        origin,
        origin_case_id,
        origin_request_kind,
        &projection,
    );

    projection
}

fn require_equal_activation_package_common(
    common: &HostOnlyCommonOutputPublicLeakageV1,
    origin: ActivationPackageOriginV1,
    expected: &ActivationPackagePreparedCommonPublicVectorV1,
) {
    assert!(activation_package_prepared_common(common, origin) == *expected);
}

fn require_equal_activation_metadata_common(
    common: &HostOnlyCommonOutputPublicLeakageV1,
    origin: ActivationPackageOriginV1,
    origin_case_id: &str,
    origin_request_kind: CeremonyRequestKindV1,
    expected: &ActivationOriginMetadataProjectionVectorV1,
) {
    assert!(
        activation_origin_projection_from_common(
            common,
            origin,
            origin_case_id,
            origin_request_kind,
        ) == *expected
    );
}

fn require_equal_export_common(
    common: &HostOnlyCommonOutputPublicLeakageV1,
    expected: &ExportReleasedCommonPublicVectorV1,
) {
    assert!(export_released_common(common) == *expected);
}

fn activation_package_prepared_common(
    common: &HostOnlyCommonOutputPublicLeakageV1,
    origin: ActivationPackageOriginV1,
) -> ActivationPackagePreparedCommonPublicVectorV1 {
    let leakage = match common {
        HostOnlyCommonOutputPublicLeakageV1::ActivationPackagePrepared(value) => value,
        _ => panic!("expected activation package-prepared public leakage"),
    };
    let (_, expected_stage, request_kind) = activation_semantic_identity(origin);
    assert_eq!(leakage.stage(), core_stage(origin));
    assert_eq!(common.stage(), core_stage(origin));
    assert_eq!(
        common.circuit_family(),
        HostOnlyOutputPartyViewCircuitFamilyV1::Activation
    );
    assert_eq!(
        common.terminal(),
        HostOnlyOutputPartyViewTerminalV1::OutputCommitted
    );

    let artifacts = leakage.artifacts();
    let packages = artifacts.packages();
    let deriver_a_client = parse_activation_descriptor(
        &packages.deriver_a_client().encode(),
        ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
        request_kind,
        OutputPartyViewRoleVectorV1::DeriverA,
        OutputPartyViewRecipientVectorV1::Client,
        OutputPartyViewOutputFamilyVectorV1::ClientScalar,
    );
    let deriver_b_client = parse_activation_descriptor(
        &packages.deriver_b_client().encode(),
        ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
        request_kind,
        OutputPartyViewRoleVectorV1::DeriverB,
        OutputPartyViewRecipientVectorV1::Client,
        OutputPartyViewOutputFamilyVectorV1::ClientScalar,
    );
    let deriver_a_signing_worker = parse_activation_descriptor(
        &packages.deriver_a_signing_worker().encode(),
        ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
        request_kind,
        OutputPartyViewRoleVectorV1::DeriverA,
        OutputPartyViewRecipientVectorV1::SigningWorker,
        OutputPartyViewOutputFamilyVectorV1::SigningWorkerScalar,
    );
    let deriver_b_signing_worker = parse_activation_descriptor(
        &packages.deriver_b_signing_worker().encode(),
        ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
        request_kind,
        OutputPartyViewRoleVectorV1::DeriverB,
        OutputPartyViewRecipientVectorV1::SigningWorker,
        OutputPartyViewOutputFamilyVectorV1::SigningWorkerScalar,
    );
    let ceremony = deriver_a_client.ceremony;
    assert!(deriver_b_client.ceremony == ceremony);
    assert!(deriver_a_signing_worker.ceremony == ceremony);
    assert!(deriver_b_signing_worker.ceremony == ceremony);
    assert_eq!(
        deriver_a_client.activation_epoch,
        deriver_b_client.activation_epoch
    );
    assert_eq!(
        deriver_a_client.activation_epoch,
        deriver_a_signing_worker.activation_epoch
    );
    assert_eq!(
        deriver_a_client.activation_epoch,
        deriver_b_signing_worker.activation_epoch
    );

    let receipt = parse_activation_receipt(&artifacts.receipt().encode(), request_kind);
    assert!(receipt.ceremony == ceremony);
    assert_eq!(receipt.activation_epoch, deriver_a_client.activation_epoch);
    assert_eq!(
        receipt.package_set_digest,
        *artifacts.receipt().package_set_digest().as_bytes()
    );
    assert_eq!(
        receipt.package_set_digest,
        *artifacts.packages().digest().as_bytes()
    );
    assert_eq!(receipt.x_client, *artifacts.receipt().x_client());
    assert_eq!(receipt.x_server, *artifacts.receipt().x_server());
    assert_eq!(
        receipt.registered_public_key,
        *artifacts.receipt().registered_public_key().as_bytes()
    );

    let identity = leakage.identity();
    assert_eq!(identity.origin(), origin);
    assert_eq!(identity.origin_request_kind(), request_kind);
    assert_eq!(
        identity.origin_request_context_digest().as_bytes(),
        &ceremony.public_request_context_digest
    );
    assert_eq!(
        identity.origin_authorization_digest().as_bytes(),
        &ceremony.authorization_digest
    );
    assert_eq!(
        identity.origin_transcript_digest().as_bytes(),
        &ceremony.transcript_digest
    );
    assert_eq!(
        identity.one_use_execution_id().as_bytes(),
        &ceremony.one_use_execution_id
    );
    assert_eq!(
        identity.package_set_digest().as_bytes(),
        &receipt.package_set_digest
    );
    assert_eq!(
        identity.activation_epoch().value(),
        receipt.activation_epoch
    );
    assert_eq!(
        identity.registered_public_key().as_bytes(),
        &receipt.registered_public_key
    );

    ActivationPackagePreparedCommonPublicVectorV1 {
        semantic_lifecycle_case_id: activation_semantic_case_id(origin).to_owned(),
        stage: expected_stage,
        request_kind,
        circuit_id: ACTIVATION_CIRCUIT_ID_V1.to_owned(),
        public_request_context_digest_hex: encode_hex(&ceremony.public_request_context_digest),
        authorization_digest_hex: encode_hex(&ceremony.authorization_digest),
        transcript_digest_hex: encode_hex(&ceremony.transcript_digest),
        transport_binding_digest_hex: encode_hex(&ceremony.transport_binding_digest),
        artifact_suite_digest_hex: encode_hex(&ceremony.artifact_suite_digest),
        one_use_execution_id_hex: encode_hex(&ceremony.one_use_execution_id),
        input_provenance_pair_digest_hex: encode_hex(&ceremony.input_provenance_pair_digest),
        host_reference_evaluation_evidence_digest_hex: encode_hex(
            &ceremony.host_reference_evaluation_evidence_digest,
        ),
        package_projection: ActivationPackageProjectionVectorV1 {
            deriver_a_client: deriver_a_client.projection,
            deriver_b_client: deriver_b_client.projection,
            deriver_a_signing_worker: deriver_a_signing_worker.projection,
            deriver_b_signing_worker: deriver_b_signing_worker.projection,
        },
        package_set_digest_hex: encode_hex(&receipt.package_set_digest),
        receipt_body_digest_hex: encode_hex(identity.receipt_digest().as_bytes()),
        activation_epoch: receipt.activation_epoch,
        registered_public_key_hex: encode_hex(&receipt.registered_public_key),
        x_client_hex: encode_hex(&receipt.x_client),
        x_server_hex: encode_hex(&receipt.x_server),
        deriver_a_receipt_evidence_digest_hex: encode_hex(
            &receipt.deriver_a_receipt_evidence_digest,
        ),
        deriver_b_receipt_evidence_digest_hex: encode_hex(
            &receipt.deriver_b_receipt_evidence_digest,
        ),
        terminal_state: OutputPartyViewTerminalVectorV1::OutputCommitted,
    }
}

fn activation_origin_projection_from_common(
    common: &HostOnlyCommonOutputPublicLeakageV1,
    origin: ActivationPackageOriginV1,
    origin_case_id: &str,
    origin_request_kind: CeremonyRequestKindV1,
) -> ActivationOriginMetadataProjectionVectorV1 {
    let leakage = match common {
        HostOnlyCommonOutputPublicLeakageV1::ActivationMetadataConsumed(value) => value,
        _ => panic!("expected activation metadata-consumed public leakage"),
    };
    assert_eq!(
        common.stage(),
        HostOnlyOutputPartyViewStageV1::ActivationMetadataConsumed
    );
    assert_eq!(
        common.circuit_family(),
        HostOnlyOutputPartyViewCircuitFamilyV1::Activation
    );
    assert_eq!(
        common.terminal(),
        HostOnlyOutputPartyViewTerminalV1::MetadataConsumed
    );
    let projection = leakage.projection();
    let identity = projection.committed().identity();
    assert_eq!(identity.origin(), origin);
    assert_eq!(identity.origin_request_kind(), origin_request_kind);
    let zero = leakage.zero_reevaluation();
    assert_eq!(zero.yao_evaluations(), 0);
    assert_eq!(zero.deriver_a_invocations(), 0);
    assert_eq!(zero.deriver_b_invocations(), 0);
    assert_eq!(zero.contribution_derivations(), 0);
    assert_eq!(zero.output_share_samples(), 0);

    ActivationOriginMetadataProjectionVectorV1 {
        origin_kind: origin_request_kind,
        origin_case_id: origin_case_id.to_owned(),
        origin_request_context_digest_hex: encode_hex(
            identity.origin_request_context_digest().as_bytes(),
        ),
        origin_authorization_digest_hex: encode_hex(
            identity.origin_authorization_digest().as_bytes(),
        ),
        origin_transcript_digest_hex: encode_hex(identity.origin_transcript_digest().as_bytes()),
        one_use_execution_id_hex: encode_hex(identity.one_use_execution_id().as_bytes()),
        package_set_digest_hex: encode_hex(identity.package_set_digest().as_bytes()),
        receipt_body_digest_hex: encode_hex(identity.receipt_digest().as_bytes()),
        activation_epoch: identity.activation_epoch().value(),
        registered_public_key_hex: encode_hex(identity.registered_public_key().as_bytes()),
        activation_request_context_digest_hex: encode_hex(
            projection.activation_request_context_digest().as_bytes(),
        ),
        activation_authorization_digest_hex: encode_hex(
            projection.activation_authorization_digest().as_bytes(),
        ),
        activation_transcript_digest_hex: encode_hex(
            projection.activation_transcript_digest().as_bytes(),
        ),
        terminal_state: OutputPartyViewTerminalVectorV1::MetadataConsumed,
        zero_reevaluation: ZeroReevaluationVectorV1 {
            yao_evaluations: zero.yao_evaluations(),
            deriver_a_invocations: zero.deriver_a_invocations(),
            deriver_b_invocations: zero.deriver_b_invocations(),
            contribution_derivations: zero.contribution_derivations(),
            output_share_samples: zero.output_share_samples(),
        },
    }
}

fn export_released_common(
    common: &HostOnlyCommonOutputPublicLeakageV1,
) -> ExportReleasedCommonPublicVectorV1 {
    let leakage = match common {
        HostOnlyCommonOutputPublicLeakageV1::ExportReleased(value) => value,
        _ => panic!("expected export-released public leakage"),
    };
    assert_eq!(
        common.stage(),
        HostOnlyOutputPartyViewStageV1::ExportReleased
    );
    assert_eq!(
        common.circuit_family(),
        HostOnlyOutputPartyViewCircuitFamilyV1::Export
    );
    assert_eq!(
        common.terminal(),
        HostOnlyOutputPartyViewTerminalV1::ExportReleased
    );
    assert_eq!(
        leakage.state_effect(),
        HostOnlyExportStateEffectV1::RegisteredStateRetained
    );

    let artifacts = leakage.artifacts();
    let packages = artifacts.packages();
    let deriver_a_client = parse_export_descriptor(
        &packages.deriver_a_client().encode(),
        EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
        OutputPartyViewRoleVectorV1::DeriverA,
    );
    let deriver_b_client = parse_export_descriptor(
        &packages.deriver_b_client().encode(),
        EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
        OutputPartyViewRoleVectorV1::DeriverB,
    );
    let ceremony = deriver_a_client.ceremony;
    assert!(deriver_b_client.ceremony == ceremony);
    let receipt = parse_export_receipt(&artifacts.receipt().encode());
    assert!(receipt.ceremony == ceremony);
    assert_eq!(
        receipt.package_set_digest,
        *artifacts.packages().digest().as_bytes()
    );
    assert_eq!(
        receipt.package_set_digest,
        *artifacts.receipt().package_set_digest().as_bytes()
    );
    assert_eq!(
        receipt.registered_public_key,
        *artifacts.receipt().registered_public_key().as_bytes()
    );

    ExportReleasedCommonPublicVectorV1 {
        semantic_lifecycle_case_id: EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
        stage: OutputPartyViewStageVectorV1::ExportReleased,
        request_kind: CeremonyRequestKindV1::Export,
        circuit_id: EXPORT_CIRCUIT_ID_V1.to_owned(),
        public_request_context_digest_hex: encode_hex(&ceremony.public_request_context_digest),
        authorization_digest_hex: encode_hex(&ceremony.authorization_digest),
        transcript_digest_hex: encode_hex(&ceremony.transcript_digest),
        transport_binding_digest_hex: encode_hex(&ceremony.transport_binding_digest),
        artifact_suite_digest_hex: encode_hex(&ceremony.artifact_suite_digest),
        one_use_execution_id_hex: encode_hex(&ceremony.one_use_execution_id),
        input_provenance_pair_digest_hex: encode_hex(&ceremony.input_provenance_pair_digest),
        host_reference_evaluation_evidence_digest_hex: encode_hex(
            &ceremony.host_reference_evaluation_evidence_digest,
        ),
        package_projection: ExportPackageProjectionVectorV1 {
            deriver_a_client: deriver_a_client.projection,
            deriver_b_client: deriver_b_client.projection,
        },
        package_set_digest_hex: encode_hex(&receipt.package_set_digest),
        receipt_body_digest_hex: encode_hex(artifacts.receipt().digest().as_bytes()),
        registered_public_key_hex: encode_hex(&receipt.registered_public_key),
        output_committed_receipt_digest_hex: encode_hex(&receipt.output_committed_receipt_digest),
        client_delivery_evidence_digest_hex: encode_hex(&receipt.client_delivery_evidence_digest),
        export_authorization_consumption_evidence_digest_hex: encode_hex(
            &receipt.export_authorization_consumption_evidence_digest,
        ),
        terminal_state: OutputPartyViewTerminalVectorV1::ExportReleased,
        state_effect: OutputPartyViewStateEffectVectorV1::RegisteredStateRetained,
    }
}

fn parse_activation_descriptor(
    encoded: &[u8],
    expected_domain: &[u8],
    request_kind: CeremonyRequestKindV1,
    role: OutputPartyViewRoleVectorV1,
    recipient: OutputPartyViewRecipientVectorV1,
    output_family: OutputPartyViewOutputFamilyVectorV1,
) -> ParsedActivationDescriptorV1 {
    let fields = lp32_fields(encoded);
    assert_eq!(fields.len(), 21);
    assert_eq!(fields[0], expected_domain);
    assert_eq!(fields[1], [request_kind.tag()]);
    assert_eq!(fields[2], [role.tag()]);
    assert_eq!(fields[3], [recipient.tag()]);
    assert_eq!(fields[4], [output_family.tag()]);
    let ceremony = parse_ceremony_binding(&fields, 5);
    let activation_epoch = parse_be_u64(fields[13]);
    let ciphertext_length = parse_be_u64(fields[18]);
    assert!(activation_epoch > 0);
    assert!(ciphertext_length > 0);
    ParsedActivationDescriptorV1 {
        ceremony,
        activation_epoch,
        projection: ActivationPackageProjectionMemberVectorV1 {
            role,
            recipient,
            output_family,
            recipient_key_binding_hex: encode_hex(&fixed_32(fields[14])),
            share_point_hex: encode_hex(&fixed_32(fields[15])),
            recipient_protection_digest_hex: encode_hex(&fixed_32(fields[16])),
            recipient_ciphertext_digest_hex: encode_hex(&fixed_32(fields[17])),
            ciphertext_length,
            output_binding_digest_hex: encode_hex(&fixed_32(fields[19])),
            package_authentication_digest_hex: encode_hex(&fixed_32(fields[20])),
        },
    }
}

fn parse_export_descriptor(
    encoded: &[u8],
    expected_domain: &[u8],
    role: OutputPartyViewRoleVectorV1,
) -> ParsedExportDescriptorV1 {
    let fields = lp32_fields(encoded);
    assert_eq!(fields.len(), 19);
    assert_eq!(fields[0], expected_domain);
    assert_eq!(fields[1], [CeremonyRequestKindV1::Export.tag()]);
    assert_eq!(fields[2], [role.tag()]);
    assert_eq!(fields[3], [CLIENT_RECIPIENT_TAG_V1]);
    assert_eq!(fields[4], [CLIENT_SEED_OUTPUT_TAG_V1]);
    let ceremony = parse_ceremony_binding(&fields, 5);
    let ciphertext_length = parse_be_u64(fields[16]);
    assert!(ciphertext_length > 0);
    ParsedExportDescriptorV1 {
        ceremony,
        projection: ExportPackageProjectionMemberVectorV1 {
            role,
            recipient: OutputPartyViewRecipientVectorV1::Client,
            output_family: OutputPartyViewOutputFamilyVectorV1::ClientSeed,
            recipient_key_binding_hex: encode_hex(&fixed_32(fields[13])),
            recipient_protection_digest_hex: encode_hex(&fixed_32(fields[14])),
            recipient_ciphertext_digest_hex: encode_hex(&fixed_32(fields[15])),
            ciphertext_length,
            output_binding_digest_hex: encode_hex(&fixed_32(fields[17])),
            package_authentication_digest_hex: encode_hex(&fixed_32(fields[18])),
        },
    }
}

fn parse_activation_receipt(
    encoded: &[u8],
    request_kind: CeremonyRequestKindV1,
) -> ParsedActivationReceiptV1 {
    let fields = lp32_fields(encoded);
    assert_eq!(fields.len(), 19);
    assert_eq!(
        fields[0],
        ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1
    );
    assert_eq!(fields[1], [0x01]);
    assert_eq!(fields[2], [0x01]);
    assert_eq!(fields[3], [request_kind.tag()]);
    ParsedActivationReceiptV1 {
        ceremony: parse_ceremony_binding(&fields, 4),
        activation_epoch: parse_be_u64(fields[12]),
        package_set_digest: fixed_32(fields[13]),
        x_client: fixed_32(fields[14]),
        x_server: fixed_32(fields[15]),
        registered_public_key: fixed_32(fields[16]),
        deriver_a_receipt_evidence_digest: fixed_32(fields[17]),
        deriver_b_receipt_evidence_digest: fixed_32(fields[18]),
    }
}

fn parse_export_receipt(encoded: &[u8]) -> ParsedExportReceiptV1 {
    let fields = lp32_fields(encoded);
    assert_eq!(fields.len(), 17);
    assert_eq!(fields[0], EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1);
    assert_eq!(fields[1], [0x02]);
    assert_eq!(fields[2], [0x02]);
    assert_eq!(fields[3], [CeremonyRequestKindV1::Export.tag()]);
    ParsedExportReceiptV1 {
        ceremony: parse_ceremony_binding(&fields, 4),
        package_set_digest: fixed_32(fields[12]),
        registered_public_key: fixed_32(fields[13]),
        output_committed_receipt_digest: fixed_32(fields[14]),
        client_delivery_evidence_digest: fixed_32(fields[15]),
        export_authorization_consumption_evidence_digest: fixed_32(fields[16]),
    }
}

fn parse_ceremony_binding(fields: &[&[u8]], start: usize) -> ParsedSemanticCeremonyBindingV1 {
    ParsedSemanticCeremonyBindingV1 {
        public_request_context_digest: fixed_32(fields[start]),
        authorization_digest: fixed_32(fields[start + 1]),
        transcript_digest: fixed_32(fields[start + 2]),
        transport_binding_digest: fixed_32(fields[start + 3]),
        artifact_suite_digest: fixed_32(fields[start + 4]),
        one_use_execution_id: fixed_32(fields[start + 5]),
        input_provenance_pair_digest: fixed_32(fields[start + 6]),
        host_reference_evaluation_evidence_digest: fixed_32(fields[start + 7]),
    }
}

fn activation_case_identity(
    origin: ActivationPackageOriginV1,
) -> (&'static str, OutputPartyViewStageVectorV1) {
    match origin {
        ActivationPackageOriginV1::Registration => (
            REGISTRATION_OUTPUT_PARTY_VIEW_CASE_ID_V1,
            OutputPartyViewStageVectorV1::RegistrationPackagePrepared,
        ),
        ActivationPackageOriginV1::Recovery => (
            RECOVERY_OUTPUT_PARTY_VIEW_CASE_ID_V1,
            OutputPartyViewStageVectorV1::RecoveryPackagePrepared,
        ),
        ActivationPackageOriginV1::Refresh => (
            REFRESH_OUTPUT_PARTY_VIEW_CASE_ID_V1,
            OutputPartyViewStageVectorV1::RefreshPackagePrepared,
        ),
    }
}

fn activation_semantic_identity(
    origin: ActivationPackageOriginV1,
) -> (
    &'static str,
    OutputPartyViewStageVectorV1,
    CeremonyRequestKindV1,
) {
    match origin {
        ActivationPackageOriginV1::Registration => (
            REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            OutputPartyViewStageVectorV1::RegistrationPackagePrepared,
            CeremonyRequestKindV1::Registration,
        ),
        ActivationPackageOriginV1::Recovery => (
            RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            OutputPartyViewStageVectorV1::RecoveryPackagePrepared,
            CeremonyRequestKindV1::Recovery,
        ),
        ActivationPackageOriginV1::Refresh => (
            REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1,
            OutputPartyViewStageVectorV1::RefreshPackagePrepared,
            CeremonyRequestKindV1::Refresh,
        ),
    }
}

fn activation_semantic_case_id(origin: ActivationPackageOriginV1) -> &'static str {
    activation_semantic_identity(origin).0
}

fn core_stage(origin: ActivationPackageOriginV1) -> HostOnlyOutputPartyViewStageV1 {
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

fn lp32_fields(mut encoded: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        assert!(encoded.len() >= 4, "canonical LP32 prefix");
        let length = u32::from_be_bytes(
            encoded[..4]
                .try_into()
                .expect("canonical LP32 length prefix"),
        ) as usize;
        encoded = &encoded[4..];
        assert!(encoded.len() >= length, "canonical LP32 field length");
        let (field, remaining) = encoded.split_at(length);
        fields.push(field);
        encoded = remaining;
    }
    fields
}

fn fixed_32(value: &[u8]) -> [u8; 32] {
    value.try_into().expect("canonical fixed 32-byte field")
}

fn parse_be_u64(value: &[u8]) -> u64 {
    u64::from_be_bytes(value.try_into().expect("canonical fixed u64 field"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
