//! Strict benchmark-only reconciliation of fixed cores with Phase 1 semantics.

use core::fmt;

use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ceremony_context::CeremonyRequestKindV1;
use crate::evaluation_input_view_fixtures::{
    phase2b_activation_evaluation_input_projection_v1,
    phase2b_export_evaluation_input_projection_v1, Phase2bActivationEvaluationInputProjectionV1,
    Phase2bExportEvaluationInputProjectionV1,
};
use crate::output_party_view_fixtures::{
    phase2b_activation_output_party_projection_v1, phase2b_export_output_party_projection_v1,
};
use crate::{
    build_provisional_benchmark_manifest_v1,
    canonical_activation_delivery_vector_corpus_json_bytes_v1,
    canonical_activation_delivery_vector_corpus_v1,
    canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1,
    canonical_activation_recipient_party_view_vector_corpus_v1,
    canonical_ceremony_context_vector_corpus_v1,
    canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1,
    canonical_evaluation_input_party_view_vector_corpus_v1,
    canonical_evaluator_abort_view_vector_corpus_json_bytes_v1,
    canonical_evaluator_abort_view_vector_corpus_v1,
    canonical_export_delivery_vector_corpus_json_bytes_v1,
    canonical_export_delivery_vector_corpus_v1,
    canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1,
    canonical_export_evaluator_authorization_vector_corpus_v1, canonical_kdf_vector_corpus_v1,
    canonical_lifecycle_continuity_corpus_v1,
    canonical_output_party_view_vector_corpus_json_bytes_v1,
    canonical_output_party_view_vector_corpus_v1,
    canonical_output_sharing_vector_corpus_json_bytes_v1,
    canonical_output_sharing_vector_corpus_v1, canonical_provenance_vector_corpus_v1,
    canonical_recovery_credential_transition_vector_corpus_json_bytes_v1,
    canonical_recovery_credential_transition_vector_corpus_v1,
    canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_recovery_evaluator_admission_vector_corpus_v1,
    canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_refresh_evaluator_admission_vector_corpus_v1,
    canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_registration_evaluator_admission_vector_corpus_v1,
    canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1,
    canonical_semantic_frame_party_view_vector_corpus_v1,
    canonical_semantic_lifecycle_vector_corpus_json_bytes_v1,
    canonical_semantic_lifecycle_vector_corpus_v1,
    canonical_uniform_abort_vector_corpus_json_bytes_v1, canonical_uniform_abort_vector_corpus_v1,
    canonical_vector_corpus_v1, compile_provisional_activation_core_v1,
    compile_provisional_export_core_v1, PublicSyntheticActivationCoreInputsV1,
    PublicSyntheticDeriverAActivationInputsV1, PublicSyntheticDeriverAExportInputsV1,
    PublicSyntheticDeriverBActivationInputsV1, PublicSyntheticDeriverBExportInputsV1,
    PublicSyntheticExportCoreInputsV1, FIXED_SHA512_32_BIT_ORDER_V1,
    PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1, PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1,
    PROVISIONAL_BENCHMARK_WIRE_ORDER_V1,
};

/// Schema identifier for the strict Phase 2B core-reconciliation corpus.
pub const PHASE2B_CORE_RECONCILIATION_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:phase2b-core-reconciliation:v1";

/// Narrow benchmark-only evidence scope for the cross-corpus certificate.
pub const PHASE2B_CORE_RECONCILIATION_EVIDENCE_SCOPE_V1: &str =
    "benchmark_only_phase2b_core_cross_corpus_reconciliation_v1";

const FIXED_SHA512_COMPONENT_TAG_V1: u8 = 0x81;
const ACTIVATION_COMPONENT_TAG_V1: u8 = 0x91;
const EXPORT_COMPONENT_TAG_V1: u8 = 0x92;

const INPUT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/canonical-input/v1";
const IR_OUTPUT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/ir-output/v1";
const SCHEDULE_OUTPUT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/schedule-output/v1";
const PARTY_OUTPUT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/party-output/v1";
const AUTHORIZED_CLIENT_OUTPUT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-reconciliation/authorized-client-output/v1";

const EXPLICIT_NONCLAIMS_V1: [&str; 10] = [
    "production_artifact_authority_absent",
    "selected_security_profile_absent",
    "garbling_and_ot_unimplemented",
    "randomized_output_protection_unimplemented",
    "simulator_and_security_experiment_unimplemented",
    "runtime_frame_and_transport_encoding_absent",
    "durable_lifecycle_and_replay_semantics_absent",
    "production_constant_time_and_erasure_unclaimed",
    "independent_operator_reproducibility_unclaimed",
    "reviewer_approval_absent",
];

/// Strict five-case benchmark-only reconciliation certificate.
#[derive(Serialize)]
pub struct Phase2bCoreReconciliationCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    benchmark_manifest_binding: BenchmarkManifestBindingV1,
    phase1_corpus_commitments: Vec<Phase1CorpusCommitmentV1>,
    mapping_contracts: MappingContractsV1,
    cases: Vec<Phase2bCoreReconciliationCaseV1>,
    explicit_nonclaims: Vec<&'static str>,
}

impl Phase2bCoreReconciliationCorpusV1 {
    /// Returns the fixed corpus schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the benchmark-only evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the exact Phase 1 commitment count.
    pub fn phase1_corpus_count(&self) -> usize {
        self.phase1_corpus_commitments.len()
    }

    /// Returns the exact request-kind reconciliation count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
struct BenchmarkManifestBindingV1 {
    manifest_magic: &'static str,
    manifest_canonical_bytes: usize,
    manifest_digest_hex: String,
    compiler_contract: &'static str,
    bit_order: &'static str,
    wire_order: &'static str,
    bundle_index_file: &'static str,
    bundle_index_canonical_bytes: u64,
    bundle_index_digest_hex: String,
    components: Vec<BenchmarkComponentBindingV1>,
}

#[derive(Serialize)]
struct BenchmarkComponentBindingV1 {
    component_kind: &'static str,
    component_tag: u8,
    ir_file: &'static str,
    schedule_file: &'static str,
    input_schema: &'static str,
    output_schema: &'static str,
    ir_digest_hex: String,
    schedule_digest_hex: String,
}

#[derive(Serialize)]
struct Phase1CorpusCommitmentV1 {
    path: &'static str,
    schema: String,
    case_count: usize,
    canonical_bytes: usize,
    sha256_hex: String,
}

#[derive(Serialize)]
struct MappingContractsV1 {
    activation_family: ProducingMappingContractV1,
    activation_continuation: ActivationContinuationMappingContractV1,
    export_family: ProducingMappingContractV1,
}

#[derive(Serialize)]
struct ProducingMappingContractV1 {
    mapping_id: &'static str,
    component_kind: &'static str,
    input_fields: Vec<MappingFieldV1>,
    output_fields: Vec<MappingFieldV1>,
}

#[derive(Serialize)]
struct ActivationContinuationMappingContractV1 {
    mapping_id: &'static str,
    evaluation_plan: ZeroEvaluationPlanV1,
    input_fields: Vec<MappingFieldV1>,
    output_fields: Vec<MappingFieldV1>,
}

#[derive(Serialize)]
struct MappingFieldV1 {
    semantic_field: &'static str,
    source_role: &'static str,
    source_field: &'static str,
    wire_start: u32,
    wire_count: u32,
    byte_order: &'static str,
    bit_order: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
struct ZeroEvaluationPlanV1 {
    kind: &'static str,
    counts: ZeroEvaluationCountsV1,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
struct ZeroEvaluationCountsV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    ideal_output_share_samples: u8,
}

#[derive(Serialize)]
#[serde(tag = "request_kind", content = "vector", rename_all = "snake_case")]
enum Phase2bCoreReconciliationCaseV1 {
    Registration(ActivationEvaluationReconciliationV1),
    Activation(ActivationContinuationReconciliationV1),
    Recovery(ActivationEvaluationReconciliationV1),
    Refresh(ActivationEvaluationReconciliationV1),
    Export(ExportEvaluationReconciliationV1),
}

#[derive(Serialize)]
struct ActivationEvaluationReconciliationV1 {
    case_kind: &'static str,
    case_id: &'static str,
    evaluation_input_party_view_case_id: &'static str,
    output_party_view_case_id: &'static str,
    semantic_frame_success_case_id: &'static str,
    evaluator_admission_case_id: &'static str,
    mapping_id: &'static str,
    component_kind: &'static str,
    canonical_input_digest_hex: String,
    ir_evaluated_output_digest_hex: String,
    schedule_evaluated_output_digest_hex: String,
    party_output_reconstruction_digest_hex: String,
    reconciliation_result: &'static str,
}

#[derive(Serialize)]
struct ActivationContinuationReconciliationV1 {
    case_kind: &'static str,
    case_id: &'static str,
    evaluation_input_party_view_case_id: &'static str,
    output_party_view_case_id: &'static str,
    semantic_frame_success_case_id: &'static str,
    activation_origin: &'static str,
    mapping_id: &'static str,
    evaluation_plan: ZeroEvaluationPlanV1,
    reconciliation_result: &'static str,
}

#[derive(Serialize)]
struct ExportEvaluationReconciliationV1 {
    case_kind: &'static str,
    case_id: &'static str,
    evaluation_input_party_view_case_id: &'static str,
    output_party_view_case_id: &'static str,
    semantic_frame_success_case_id: &'static str,
    evaluator_authorization_case_id: &'static str,
    mapping_id: &'static str,
    component_kind: &'static str,
    canonical_input_digest_hex: String,
    ir_evaluated_output_digest_hex: String,
    schedule_evaluated_output_digest_hex: String,
    party_output_reconstruction_digest_hex: String,
    authorized_client_output_digest_hex: String,
    reconciliation_result: &'static str,
}

/// Failure returned for noncanonical reconciliation-certificate bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase2bCoreReconciliationCorpusParseErrorV1;

impl fmt::Display for Phase2bCoreReconciliationCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "Phase 2B core-reconciliation corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for Phase2bCoreReconciliationCorpusParseErrorV1 {}

/// Builds the exact benchmark-only five-case reconciliation certificate.
pub fn canonical_phase2b_core_reconciliation_corpus_v1() -> Phase2bCoreReconciliationCorpusV1 {
    Phase2bCoreReconciliationCorpusV1 {
        schema: PHASE2B_CORE_RECONCILIATION_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: PHASE2B_CORE_RECONCILIATION_EVIDENCE_SCOPE_V1.to_owned(),
        benchmark_manifest_binding: benchmark_manifest_binding(),
        phase1_corpus_commitments: phase1_corpus_commitments(),
        mapping_contracts: mapping_contracts(),
        cases: vec![
            Phase2bCoreReconciliationCaseV1::Registration(activation_evaluation_case(
                CeremonyRequestKindV1::Registration,
            )),
            Phase2bCoreReconciliationCaseV1::Activation(activation_continuation_case()),
            Phase2bCoreReconciliationCaseV1::Recovery(activation_evaluation_case(
                CeremonyRequestKindV1::Recovery,
            )),
            Phase2bCoreReconciliationCaseV1::Refresh(activation_evaluation_case(
                CeremonyRequestKindV1::Refresh,
            )),
            Phase2bCoreReconciliationCaseV1::Export(export_evaluation_case()),
        ],
        explicit_nonclaims: EXPLICIT_NONCLAIMS_V1.to_vec(),
    }
}

/// Encodes the exact canonical certificate with one trailing LF.
pub fn canonical_phase2b_core_reconciliation_corpus_json_bytes_v1() -> Vec<u8> {
    canonical_json_bytes(&canonical_phase2b_core_reconciliation_corpus_v1())
}

/// Accepts only exact canonical LF-terminated certificate bytes.
pub fn parse_canonical_phase2b_core_reconciliation_corpus_json_v1(
    encoded: &[u8],
) -> Result<Phase2bCoreReconciliationCorpusV1, Phase2bCoreReconciliationCorpusParseErrorV1> {
    if encoded != canonical_phase2b_core_reconciliation_corpus_json_bytes_v1() {
        return Err(Phase2bCoreReconciliationCorpusParseErrorV1);
    }
    Ok(canonical_phase2b_core_reconciliation_corpus_v1())
}

fn benchmark_manifest_binding() -> BenchmarkManifestBindingV1 {
    let manifest = build_provisional_benchmark_manifest_v1();
    let components = manifest
        .components()
        .map(|component| BenchmarkComponentBindingV1 {
            component_kind: component_kind(component.component_tag()),
            component_tag: component.component_tag(),
            ir_file: component.ir_filename(),
            schedule_file: component.schedule_filename(),
            input_schema: component.input_schema(),
            output_schema: component.output_schema(),
            ir_digest_hex: encode_hex(component.ir_digest()),
            schedule_digest_hex: encode_hex(component.schedule_digest()),
        })
        .collect();
    BenchmarkManifestBindingV1 {
        manifest_magic: "EYAOBM01",
        manifest_canonical_bytes: manifest.canonical_encoding().len(),
        manifest_digest_hex: encode_hex(manifest.digest().as_bytes()),
        compiler_contract: PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1,
        bit_order: FIXED_SHA512_32_BIT_ORDER_V1,
        wire_order: PROVISIONAL_BENCHMARK_WIRE_ORDER_V1,
        bundle_index_file: PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1,
        bundle_index_canonical_bytes: manifest.bundle_index_bytes(),
        bundle_index_digest_hex: encode_hex(manifest.bundle_index_digest()),
        components,
    }
}

const fn component_kind(tag: u8) -> &'static str {
    match tag {
        FIXED_SHA512_COMPONENT_TAG_V1 => "fixed_sha512_32",
        ACTIVATION_COMPONENT_TAG_V1 => "activation",
        EXPORT_COMPONENT_TAG_V1 => "export",
        _ => panic!("benchmark manifest contains an unknown component"),
    }
}

fn mapping_contracts() -> MappingContractsV1 {
    MappingContractsV1 {
        activation_family: ProducingMappingContractV1 {
            mapping_id: "activation_family_inputs_outputs_v1",
            component_kind: "activation",
            input_fields: activation_input_mapping(),
            output_fields: activation_output_mapping(),
        },
        activation_continuation: ActivationContinuationMappingContractV1 {
            mapping_id: "activation_continuation_zero_evaluation_v1",
            evaluation_plan: zero_evaluation_plan(),
            input_fields: Vec::new(),
            output_fields: Vec::new(),
        },
        export_family: ProducingMappingContractV1 {
            mapping_id: "export_family_inputs_outputs_v1",
            component_kind: "export",
            input_fields: export_input_mapping(),
            output_fields: export_output_mapping(),
        },
    }
}

fn mapping_field(
    semantic_field: &'static str,
    source_role: &'static str,
    source_field: &'static str,
    wire_start: u32,
) -> MappingFieldV1 {
    MappingFieldV1 {
        semantic_field,
        source_role,
        source_field,
        wire_start,
        wire_count: 256,
        byte_order: "little_endian",
        bit_order: "byte_index_ascending_lsb0",
    }
}

fn activation_input_mapping() -> Vec<MappingFieldV1> {
    vec![
        mapping_field("a.y_client", "deriver_a", "y_client_hex", 0),
        mapping_field("a.y_server", "deriver_a", "y_server_hex", 256),
        mapping_field("a.tau_client", "deriver_a", "tau_client_hex", 512),
        mapping_field("a.tau_server", "deriver_a", "tau_server_hex", 768),
        mapping_field("b.y_client", "deriver_b", "y_client_hex", 1024),
        mapping_field("b.y_server", "deriver_b", "y_server_hex", 1280),
        mapping_field("b.tau_client", "deriver_b", "tau_client_hex", 1536),
        mapping_field("b.tau_server", "deriver_b", "tau_server_hex", 1792),
    ]
}

fn activation_output_mapping() -> Vec<MappingFieldV1> {
    vec![
        mapping_field("x_client_base", "circuit_output", "x_client_base", 0),
        mapping_field("x_server_base", "circuit_output", "x_server_base", 256),
    ]
}

fn export_input_mapping() -> Vec<MappingFieldV1> {
    vec![
        mapping_field("a.y_client", "deriver_a", "y_client_hex", 0),
        mapping_field("a.y_server", "deriver_a", "y_server_hex", 256),
        mapping_field("b.y_client", "deriver_b", "y_client_hex", 512),
        mapping_field("b.y_server", "deriver_b", "y_server_hex", 768),
    ]
}

fn export_output_mapping() -> Vec<MappingFieldV1> {
    vec![mapping_field("seed", "circuit_output", "seed", 0)]
}

const fn zero_evaluation_plan() -> ZeroEvaluationPlanV1 {
    ZeroEvaluationPlanV1 {
        kind: "zero_evaluation_continuation",
        counts: ZeroEvaluationCountsV1 {
            yao_evaluations: 0,
            deriver_a_invocations: 0,
            deriver_b_invocations: 0,
            contribution_derivations: 0,
            ideal_output_share_samples: 0,
        },
    }
}

fn activation_evaluation_case(
    request_kind: CeremonyRequestKindV1,
) -> ActivationEvaluationReconciliationV1 {
    let input_projection = phase2b_activation_evaluation_input_projection_v1(request_kind);
    let output_projection = phase2b_activation_output_party_projection_v1(request_kind);
    let inputs = activation_core_inputs(&input_projection);
    let input_bytes = inputs.canonical_input_bytes_v1();

    let core = compile_provisional_activation_core_v1();
    let ir_output = core.evaluate_ir_public_synthetic_bytes_v1(&inputs);
    let schedule_output = core.evaluate_schedule_public_synthetic_bytes_v1(&inputs);
    assert_eq!(ir_output, schedule_output);

    let reconstructed_output = join_32(
        add_canonical_scalars(
            output_projection.deriver_a_client_share,
            output_projection.deriver_b_client_share,
        ),
        add_canonical_scalars(
            output_projection.deriver_a_signing_worker_share,
            output_projection.deriver_b_signing_worker_share,
        ),
    );
    assert_eq!(ir_output, reconstructed_output);

    ActivationEvaluationReconciliationV1 {
        case_kind: "activation_evaluation_reconciliation",
        case_id: activation_reconciliation_case_id(request_kind),
        evaluation_input_party_view_case_id: input_projection.case_id,
        output_party_view_case_id: output_party_view_case_id(request_kind),
        semantic_frame_success_case_id: semantic_frame_success_case_id(request_kind),
        evaluator_admission_case_id: evaluator_admission_case_id(request_kind),
        mapping_id: "activation_family_inputs_outputs_v1",
        component_kind: "activation",
        canonical_input_digest_hex: domain_digest_hex(INPUT_DIGEST_DOMAIN_V1, &input_bytes),
        ir_evaluated_output_digest_hex: domain_digest_hex(IR_OUTPUT_DIGEST_DOMAIN_V1, &ir_output),
        schedule_evaluated_output_digest_hex: domain_digest_hex(
            SCHEDULE_OUTPUT_DIGEST_DOMAIN_V1,
            &schedule_output,
        ),
        party_output_reconstruction_digest_hex: domain_digest_hex(
            PARTY_OUTPUT_DIGEST_DOMAIN_V1,
            &reconstructed_output,
        ),
        reconciliation_result: "exact_input_ir_schedule_and_party_output_match",
    }
}

fn activation_continuation_case() -> ActivationContinuationReconciliationV1 {
    ActivationContinuationReconciliationV1 {
        case_kind: "activation_continuation_reconciliation",
        case_id: "activation_phase2b_zero_evaluation_reconciliation_v1",
        evaluation_input_party_view_case_id: "activation_no_evaluation_input_party_views_v1",
        output_party_view_case_id: "activation_output_party_views_metadata_consumed_v1",
        semantic_frame_success_case_id: "registration_success_worker_activated_v1",
        activation_origin: "registration",
        mapping_id: "activation_continuation_zero_evaluation_v1",
        evaluation_plan: zero_evaluation_plan(),
        reconciliation_result: "exact_zero_evaluation_and_no_new_private_output",
    }
}

fn export_evaluation_case() -> ExportEvaluationReconciliationV1 {
    let input_projection = phase2b_export_evaluation_input_projection_v1();
    let output_projection = phase2b_export_output_party_projection_v1();
    let inputs = export_core_inputs(&input_projection);
    let input_bytes = inputs.canonical_input_bytes_v1();

    let core = compile_provisional_export_core_v1();
    let ir_output = core.evaluate_ir_public_synthetic_bytes_v1(&inputs);
    let schedule_output = core.evaluate_schedule_public_synthetic_bytes_v1(&inputs);
    assert_eq!(ir_output, schedule_output);
    let reconstructed_output = crate::wrapping_add_le_256(
        output_projection.deriver_a_seed_share,
        output_projection.deriver_b_seed_share,
    );
    assert_eq!(ir_output.as_slice(), reconstructed_output);
    assert_eq!(
        ir_output.as_slice(),
        output_projection.authorized_client_seed
    );

    ExportEvaluationReconciliationV1 {
        case_kind: "export_evaluation_reconciliation",
        case_id: "export_phase2b_core_reconciliation_v1",
        evaluation_input_party_view_case_id: input_projection.case_id,
        output_party_view_case_id: "export_output_party_views_released_v1",
        semantic_frame_success_case_id: "export_release_exact_redelivery_v1",
        evaluator_authorization_case_id: "export_authorized_evaluation_released_v1",
        mapping_id: "export_family_inputs_outputs_v1",
        component_kind: "export",
        canonical_input_digest_hex: domain_digest_hex(INPUT_DIGEST_DOMAIN_V1, &input_bytes),
        ir_evaluated_output_digest_hex: domain_digest_hex(IR_OUTPUT_DIGEST_DOMAIN_V1, &ir_output),
        schedule_evaluated_output_digest_hex: domain_digest_hex(
            SCHEDULE_OUTPUT_DIGEST_DOMAIN_V1,
            &schedule_output,
        ),
        party_output_reconstruction_digest_hex: domain_digest_hex(
            PARTY_OUTPUT_DIGEST_DOMAIN_V1,
            &reconstructed_output,
        ),
        authorized_client_output_digest_hex: domain_digest_hex(
            AUTHORIZED_CLIENT_OUTPUT_DIGEST_DOMAIN_V1,
            &output_projection.authorized_client_seed,
        ),
        reconciliation_result: "exact_input_ir_schedule_party_output_and_authorized_client_match",
    }
}

fn activation_core_inputs(
    projection: &Phase2bActivationEvaluationInputProjectionV1,
) -> PublicSyntheticActivationCoreInputsV1 {
    let deriver_a = PublicSyntheticDeriverAActivationInputsV1::new(
        projection.deriver_a_y_client,
        projection.deriver_a_y_server,
        projection.deriver_a_tau_client,
        projection.deriver_a_tau_server,
    )
    .expect("fixed Deriver A tau fields are canonical");
    let deriver_b = PublicSyntheticDeriverBActivationInputsV1::new(
        projection.deriver_b_y_client,
        projection.deriver_b_y_server,
        projection.deriver_b_tau_client,
        projection.deriver_b_tau_server,
    )
    .expect("fixed Deriver B tau fields are canonical");
    PublicSyntheticActivationCoreInputsV1::new(deriver_a, deriver_b)
}

fn export_core_inputs(
    projection: &Phase2bExportEvaluationInputProjectionV1,
) -> PublicSyntheticExportCoreInputsV1 {
    PublicSyntheticExportCoreInputsV1::new(
        PublicSyntheticDeriverAExportInputsV1::new(
            projection.deriver_a_y_client,
            projection.deriver_a_y_server,
        ),
        PublicSyntheticDeriverBExportInputsV1::new(
            projection.deriver_b_y_client,
            projection.deriver_b_y_server,
        ),
    )
}

fn phase1_corpus_commitments() -> Vec<Phase1CorpusCommitmentV1> {
    let arithmetic = canonical_vector_corpus_v1();
    let kdf = canonical_kdf_vector_corpus_v1();
    let ceremony = canonical_ceremony_context_vector_corpus_v1();
    let lifecycle = canonical_lifecycle_continuity_corpus_v1();
    let provenance = canonical_provenance_vector_corpus_v1();
    vec![
        commitment(
            "vectors/ed25519-yao-v1.json",
            arithmetic.schema.clone(),
            arithmetic.cases.len(),
            canonical_json_bytes(&arithmetic),
        ),
        commitment(
            "vectors/ed25519-yao-kdf-v1.json",
            kdf.schema.clone(),
            kdf.cases.len(),
            canonical_json_bytes(&kdf),
        ),
        commitment(
            "vectors/ed25519-yao-ceremony-context-v1.json",
            ceremony.schema.clone(),
            ceremony.cases.len(),
            canonical_json_bytes(&ceremony),
        ),
        commitment(
            "vectors/ed25519-yao-lifecycle-continuity-v1.json",
            lifecycle.schema.clone(),
            lifecycle.cases.len(),
            canonical_json_bytes(&lifecycle),
        ),
        commitment(
            "vectors/ed25519-yao-provenance-v1.json",
            provenance.schema.clone(),
            provenance.cases.len(),
            canonical_json_bytes(&provenance),
        ),
        strict_commitment(
            "vectors/ed25519-yao-output-sharing-v1.json",
            canonical_output_sharing_vector_corpus_v1().schema(),
            canonical_output_sharing_vector_corpus_v1().case_count(),
            canonical_output_sharing_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-semantic-lifecycle-v1.json",
            canonical_semantic_lifecycle_vector_corpus_v1().schema(),
            canonical_semantic_lifecycle_vector_corpus_v1().case_count(),
            canonical_semantic_lifecycle_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-output-party-views-v1.json",
            canonical_output_party_view_vector_corpus_v1().schema(),
            canonical_output_party_view_vector_corpus_v1().case_count(),
            canonical_output_party_view_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-evaluation-input-party-views-v1.json",
            canonical_evaluation_input_party_view_vector_corpus_v1().schema(),
            canonical_evaluation_input_party_view_vector_corpus_v1().case_count(),
            canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-uniform-abort-envelope-v1.json",
            canonical_uniform_abort_vector_corpus_v1().schema(),
            canonical_uniform_abort_vector_corpus_v1().case_count(),
            canonical_uniform_abort_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json",
            canonical_evaluator_abort_view_vector_corpus_v1().schema(),
            canonical_evaluator_abort_view_vector_corpus_v1().case_count(),
            canonical_evaluator_abort_view_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-export-delivery-v1.json",
            canonical_export_delivery_vector_corpus_v1().schema(),
            canonical_export_delivery_vector_corpus_v1().case_count(),
            canonical_export_delivery_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-activation-delivery-v1.json",
            canonical_activation_delivery_vector_corpus_v1().schema(),
            canonical_activation_delivery_vector_corpus_v1().case_count(),
            canonical_activation_delivery_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-activation-recipient-party-views-v1.json",
            canonical_activation_recipient_party_view_vector_corpus_v1().schema(),
            canonical_activation_recipient_party_view_vector_corpus_v1().case_count(),
            canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-recovery-credential-transition-v1.json",
            canonical_recovery_credential_transition_vector_corpus_v1().schema(),
            canonical_recovery_credential_transition_vector_corpus_v1().case_count(),
            canonical_recovery_credential_transition_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-export-evaluator-authorization-v1.json",
            canonical_export_evaluator_authorization_vector_corpus_v1().schema(),
            canonical_export_evaluator_authorization_vector_corpus_v1().case_count(),
            canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-registration-evaluator-admission-v1.json",
            canonical_registration_evaluator_admission_vector_corpus_v1().schema(),
            canonical_registration_evaluator_admission_vector_corpus_v1().case_count(),
            canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-recovery-evaluator-admission-v1.json",
            canonical_recovery_evaluator_admission_vector_corpus_v1().schema(),
            canonical_recovery_evaluator_admission_vector_corpus_v1().case_count(),
            canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-refresh-evaluator-admission-v1.json",
            canonical_refresh_evaluator_admission_vector_corpus_v1().schema(),
            canonical_refresh_evaluator_admission_vector_corpus_v1().case_count(),
            canonical_refresh_evaluator_admission_vector_corpus_json_bytes_v1(),
        ),
        strict_commitment(
            "vectors/ed25519-yao-semantic-frame-party-views-v1.json",
            canonical_semantic_frame_party_view_vector_corpus_v1().schema(),
            canonical_semantic_frame_party_view_vector_corpus_v1().case_count(),
            canonical_semantic_frame_party_view_vector_corpus_json_bytes_v1(),
        ),
    ]
}

fn strict_commitment(
    path: &'static str,
    schema: &str,
    case_count: usize,
    bytes: Vec<u8>,
) -> Phase1CorpusCommitmentV1 {
    commitment(path, schema.to_owned(), case_count, bytes)
}

fn commitment(
    path: &'static str,
    schema: String,
    case_count: usize,
    bytes: Vec<u8>,
) -> Phase1CorpusCommitmentV1 {
    Phase1CorpusCommitmentV1 {
        path,
        schema,
        case_count,
        canonical_bytes: bytes.len(),
        sha256_hex: encode_hex(&Sha256::digest(bytes)),
    }
}

const fn activation_reconciliation_case_id(request_kind: CeremonyRequestKindV1) -> &'static str {
    match request_kind {
        CeremonyRequestKindV1::Registration => "registration_phase2b_core_reconciliation_v1",
        CeremonyRequestKindV1::Recovery => "recovery_phase2b_core_reconciliation_v1",
        CeremonyRequestKindV1::Refresh => "refresh_phase2b_core_reconciliation_v1",
        CeremonyRequestKindV1::Activation | CeremonyRequestKindV1::Export => {
            panic!("activation case requires an evaluating activation-family request")
        }
    }
}

const fn output_party_view_case_id(request_kind: CeremonyRequestKindV1) -> &'static str {
    match request_kind {
        CeremonyRequestKindV1::Registration => {
            "registration_output_party_views_package_prepared_v1"
        }
        CeremonyRequestKindV1::Recovery => "recovery_output_party_views_package_prepared_v1",
        CeremonyRequestKindV1::Refresh => "refresh_output_party_views_package_prepared_v1",
        CeremonyRequestKindV1::Activation | CeremonyRequestKindV1::Export => {
            panic!("output-party selector requires an evaluating activation-family request")
        }
    }
}

const fn semantic_frame_success_case_id(request_kind: CeremonyRequestKindV1) -> &'static str {
    match request_kind {
        CeremonyRequestKindV1::Registration => "registration_success_worker_activated_v1",
        CeremonyRequestKindV1::Recovery => "recovery_success_worker_activated_v1",
        CeremonyRequestKindV1::Refresh => "refresh_success_worker_activated_v1",
        CeremonyRequestKindV1::Activation | CeremonyRequestKindV1::Export => {
            panic!("semantic-frame selector requires an evaluating activation-family request")
        }
    }
}

const fn evaluator_admission_case_id(request_kind: CeremonyRequestKindV1) -> &'static str {
    match request_kind {
        CeremonyRequestKindV1::Registration => {
            "registration_admitted_evaluation_output_committed_v1"
        }
        CeremonyRequestKindV1::Recovery => "recovery_admitted_evaluation_output_committed_v1",
        CeremonyRequestKindV1::Refresh => "refresh_admitted_evaluation_output_committed_v1",
        CeremonyRequestKindV1::Activation | CeremonyRequestKindV1::Export => {
            panic!("admission selector requires an evaluating activation-family request")
        }
    }
}

fn add_canonical_scalars(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let left = Option::<Scalar>::from(Scalar::from_canonical_bytes(left))
        .expect("fixed Deriver A share is canonical");
    let right = Option::<Scalar>::from(Scalar::from_canonical_bytes(right))
        .expect("fixed Deriver B share is canonical");
    (left + right).to_bytes()
}

fn join_32(left: [u8; 32], right: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    bytes
}

fn domain_digest_hex(domain: &[u8], payload: &[u8]) -> String {
    let mut preimage = Vec::new();
    push_lp32(&mut preimage, domain);
    push_lp32(&mut preimage, payload);
    encode_hex(&Sha256::digest(preimage))
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("fixed reconciliation field fits LP32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixed certificate serializes");
    bytes.push(b'\n');
    bytes
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::OnceLock;

    use serde_json::Value;

    use super::*;

    const COMMITTED_CORPUS: &str = "vectors/ed25519-yao-phase2b-core-reconciliation-v1.json";

    fn canonical_bytes() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES
            .get_or_init(canonical_phase2b_core_reconciliation_corpus_json_bytes_v1)
            .as_slice()
    }

    fn document() -> &'static Value {
        static DOCUMENT: OnceLock<Value> = OnceLock::new();
        DOCUMENT.get_or_init(|| {
            serde_json::from_slice(canonical_bytes()).expect("canonical certificate is JSON")
        })
    }

    fn generator_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn canonical_certificate_has_exact_envelope_case_order_and_committed_bytes() {
        let document = document();
        assert_eq!(
            document["schema"],
            PHASE2B_CORE_RECONCILIATION_CORPUS_SCHEMA_V1
        );
        assert_eq!(
            document["evidence_scope"],
            PHASE2B_CORE_RECONCILIATION_EVIDENCE_SCOPE_V1
        );
        assert_eq!(document.as_object().expect("object").len(), 8);
        let kinds = document["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .map(|case| case["request_kind"].as_str().expect("request kind"))
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                "registration",
                "activation",
                "recovery",
                "refresh",
                "export"
            ]
        );
        assert!(canonical_bytes().ends_with(b"\n"));
        assert!(!canonical_bytes().ends_with(b"\n\n"));
        let committed =
            fs::read(generator_root().join(COMMITTED_CORPUS)).expect("committed corpus");
        assert_eq!(committed, canonical_bytes());
        parse_canonical_phase2b_core_reconciliation_corpus_json_v1(&committed)
            .expect("committed certificate is canonical");
    }

    #[test]
    fn certificate_commits_exactly_the_twenty_phase1_corpora() {
        let commitments = document()["phase1_corpus_commitments"]
            .as_array()
            .expect("commitments");
        assert_eq!(commitments.len(), 20);
        assert_eq!(commitments[0]["path"], "vectors/ed25519-yao-v1.json");
        assert_eq!(
            commitments[19]["path"],
            "vectors/ed25519-yao-semantic-frame-party-views-v1.json"
        );
        for commitment in commitments {
            let object = commitment.as_object().expect("commitment object");
            assert_eq!(object.len(), 5);
            let relative = commitment["path"].as_str().expect("path");
            assert_ne!(relative, COMMITTED_CORPUS);
            let bytes = fs::read(generator_root().join(relative)).expect("Phase 1 corpus");
            assert_eq!(
                bytes.len() as u64,
                commitment["canonical_bytes"].as_u64().expect("byte count")
            );
            assert_eq!(
                encode_hex(&Sha256::digest(&bytes)),
                commitment["sha256_hex"].as_str().expect("digest")
            );
        }
    }

    #[test]
    fn manifest_binding_preserves_candidate_component_schema_and_order() {
        let binding = &document()["benchmark_manifest_binding"];
        let manifest = build_provisional_benchmark_manifest_v1();
        assert_eq!(binding["manifest_magic"], "EYAOBM01");
        assert_eq!(
            binding["manifest_canonical_bytes"],
            manifest.canonical_encoding().len()
        );
        assert_eq!(
            binding["manifest_digest_hex"],
            encode_hex(manifest.digest().as_bytes())
        );
        let components = binding["components"].as_array().expect("components");
        assert_eq!(components.len(), 3);
        assert_eq!(components[0]["component_kind"], "fixed_sha512_32");
        assert_eq!(components[1]["component_kind"], "activation");
        assert_eq!(components[2]["component_kind"], "export");
        assert_eq!(components[1]["component_tag"], 145);
        assert!(components[1]["output_schema"]
            .as_str()
            .expect("activation schema")
            .ends_with(":no-seed"));
        assert!(components[2]["input_schema"]
            .as_str()
            .expect("export schema")
            .ends_with(":no-tau"));
    }

    #[test]
    fn activation_mapping_and_three_rows_bind_exact_ir_schedule_party_outputs() {
        let mapping = &document()["mapping_contracts"]["activation_family"];
        let input_fields = mapping["input_fields"].as_array().expect("input fields");
        let output_fields = mapping["output_fields"].as_array().expect("output fields");
        assert_eq!(input_fields.len(), 8);
        assert_eq!(output_fields.len(), 2);
        assert_eq!(input_fields[0]["semantic_field"], "a.y_client");
        assert_eq!(input_fields[7]["semantic_field"], "b.tau_server");
        for (index, field) in input_fields.iter().enumerate() {
            assert_eq!(field["wire_start"], (index * 256) as u64);
            assert_eq!(field["wire_count"], 256);
            assert_eq!(field["bit_order"], "byte_index_ascending_lsb0");
        }
        for index in [0usize, 2, 3] {
            let vector = &document()["cases"][index]["vector"];
            assert_eq!(vector.as_object().expect("activation vector").len(), 13);
            assert_eq!(vector["case_kind"], "activation_evaluation_reconciliation");
            assert_eq!(vector["component_kind"], "activation");
            assert_eq!(
                vector["reconciliation_result"],
                "exact_input_ir_schedule_and_party_output_match"
            );
            for digest in [
                "canonical_input_digest_hex",
                "ir_evaluated_output_digest_hex",
                "schedule_evaluated_output_digest_hex",
                "party_output_reconstruction_digest_hex",
            ] {
                assert_lower_hex_32(vector[digest].as_str().expect("digest"));
            }
        }
    }

    #[test]
    fn export_mapping_and_row_bind_ir_schedule_party_and_authorized_client_outputs() {
        let mapping = &document()["mapping_contracts"]["export_family"];
        assert_eq!(mapping["component_kind"], "export");
        assert_eq!(mapping["input_fields"].as_array().expect("inputs").len(), 4);
        assert_eq!(
            mapping["output_fields"].as_array().expect("outputs").len(),
            1
        );
        assert_eq!(mapping["output_fields"][0]["semantic_field"], "seed");
        let vector = &document()["cases"][4]["vector"];
        assert_eq!(vector.as_object().expect("export vector").len(), 14);
        assert_eq!(vector["case_kind"], "export_evaluation_reconciliation");
        assert_eq!(vector["component_kind"], "export");
        assert_eq!(
            vector["reconciliation_result"],
            "exact_input_ir_schedule_party_output_and_authorized_client_match"
        );
        assert_eq!(
            vector["evaluator_authorization_case_id"],
            "export_authorized_evaluation_released_v1"
        );
        assert_lower_hex_32(
            vector["authorized_client_output_digest_hex"]
                .as_str()
                .expect("authorized client digest"),
        );
    }

    #[test]
    fn activation_is_structurally_zero_evaluation_and_mutations_fail_closed() {
        let mapping = &document()["mapping_contracts"]["activation_continuation"];
        assert_eq!(mapping.as_object().expect("continuation mapping").len(), 4);
        assert_eq!(mapping["input_fields"], serde_json::json!([]));
        assert_eq!(mapping["output_fields"], serde_json::json!([]));
        assert_eq!(mapping["evaluation_plan"]["counts"]["yao_evaluations"], 0);

        let activation = &document()["cases"][1]["vector"];
        assert_eq!(activation.as_object().expect("activation vector").len(), 9);
        for forbidden in [
            "component_kind",
            "canonical_input_digest_hex",
            "ir_evaluated_output_digest_hex",
            "schedule_evaluated_output_digest_hex",
            "party_output_reconstruction_digest_hex",
            "evaluator_admission_case_id",
        ] {
            assert!(activation.get(forbidden).is_none());
        }
        let mut mutation = canonical_bytes().to_vec();
        let last = mutation.len() - 2;
        mutation[last] ^= 1;
        assert!(parse_canonical_phase2b_core_reconciliation_corpus_json_v1(&mutation).is_err());

        let source = include_str!("phase2b_core_reconciliation.rs");
        let runtime_profile_field = ["security", "_profile", ":"].concat();
        let production_manifest_type = ["Production", "Manifest"].concat();
        assert!(!source.contains(&runtime_profile_field));
        assert!(!source.contains(&production_manifest_type));
    }

    fn assert_lower_hex_32(value: &str) {
        assert_eq!(value.len(), 64);
        assert!(value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
}
