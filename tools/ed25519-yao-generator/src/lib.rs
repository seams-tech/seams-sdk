#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![doc = "Host-only reference oracle for the fixed Ed25519 Yao functionality."]
#![doc = "This crate is generator/test infrastructure and has no production protocol API."]

#[cfg(target_arch = "wasm32")]
compile_error!("ed25519-yao-generator is host-only and must never be compiled for wasm32");

use core::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};

pub mod activation_delivery;
mod activation_delivery_fixtures;
mod activation_recipient_party_view_fixtures;
mod activation_recipient_party_view_vector_fixtures;
pub mod activation_recipient_party_views;
mod application_binding;
mod artifact_bundle;
pub mod authenticated_store;
mod benchmark_manifest;
pub mod ceremony_context;
#[cfg(test)]
mod ceremony_context_tests;
mod ceremony_fixtures;
mod circuit;
mod context;
mod continuity_reference;
mod evaluation_input_view_fixtures;
pub mod evaluation_input_views;
mod evaluator_abort_view_fixtures;
pub mod export_delivery;
mod export_delivery_fixtures;
pub mod export_evaluation_acceptance;
mod export_evaluation_acceptance_fixtures;
mod export_reference;
mod fixtures;
pub mod ideal_function_randomness;
mod joint_refresh_delta;
mod kdf;
mod kdf_fixtures;
pub mod lifecycle_domain;
mod lifecycle_fixtures;
pub mod lifecycle_persistence;
mod lifecycle_reference;
mod output_party_view_fixtures;
pub mod output_party_views;
mod output_sharing;
mod output_sharing_fixtures;
pub mod provenance;
mod provenance_fixtures;
#[cfg_attr(not(test), allow(dead_code))]
pub mod recovery_credential_transition;
mod recovery_credential_transition_fixtures;
pub mod recovery_evaluation_admission;
mod recovery_evaluation_admission_fixtures;
mod recovery_reference;
pub mod refresh_evaluation_admission;
#[cfg_attr(not(test), allow(dead_code))]
pub mod refresh_promotion;
mod refresh_reference;
mod registered_key;
pub mod registration_evaluation_admission;
mod registration_evaluation_admission_fixtures;
mod registration_reference;
pub mod semantic_artifacts;
#[cfg(test)]
mod semantic_artifacts_tests;
mod semantic_fixture_material;
mod semantic_lifecycle_fixtures;
#[cfg_attr(not(test), allow(dead_code))]
pub mod signing_worker_activation;
mod specification_goldens;
mod uniform_abort_fixtures;

pub use activation_delivery_fixtures::{
    canonical_activation_delivery_vector_corpus_json_bytes_v1,
    canonical_activation_delivery_vector_corpus_v1,
    parse_canonical_activation_delivery_vector_corpus_json_v1,
    ActivationDeliveryVectorCorpusParseErrorV1, ActivationDeliveryVectorCorpusV1,
    ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1, ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use activation_recipient_party_view_vector_fixtures::{
    canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1,
    canonical_activation_recipient_party_view_vector_corpus_v1,
    parse_canonical_activation_recipient_party_view_vector_corpus_json_v1,
    ActivationRecipientPartyViewVectorCorpusParseErrorV1,
    ActivationRecipientPartyViewVectorCorpusV1,
    ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
    ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use application_binding::{
    Ed25519YaoApplicationBindingBytesV1, Ed25519YaoApplicationBindingErrorV1,
    Ed25519YaoApplicationBindingFactsV1, Ed25519YaoApplicationBindingFieldV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1,
    ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
};
pub use artifact_bundle::{
    build_provisional_artifact_bundle_v1, ProvisionalArtifactBundleDigest32V1,
    ProvisionalArtifactBundleEntryV1, ProvisionalArtifactBundleErrorV1,
    ProvisionalArtifactBundleV1, ProvisionalArtifactFileDigest32V1,
    PROVISIONAL_ARTIFACT_ACTIVATION_IR_FILE_V1, PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1,
    PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1, PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1,
    PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1, PROVISIONAL_ARTIFACT_SHA512_IR_FILE_V1,
    PROVISIONAL_ARTIFACT_SHA512_SCHEDULE_FILE_V1,
};
pub use benchmark_manifest::{
    build_provisional_benchmark_manifest_v1, ProvisionalBenchmarkManifestComponentV1,
    ProvisionalBenchmarkManifestDigest32V1, ProvisionalBenchmarkManifestErrorV1,
    ProvisionalBenchmarkManifestV1, PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1,
    PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_BYTES_V1,
    PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_DIGEST_V1,
    PROVISIONAL_BENCHMARK_MANIFEST_DIGEST_DOMAIN_V1, PROVISIONAL_BENCHMARK_MANIFEST_MAGIC_V1,
    PROVISIONAL_BENCHMARK_WIRE_ORDER_V1,
};
pub use ceremony_context::CeremonyRequestKindV1;
pub use ceremony_fixtures::{
    canonical_ceremony_context_vector_corpus_v1, canonical_ceremony_fixture_dag_v1,
    CeremonyActivationAuthorizationVectorV1, CeremonyCaseVectorV1, CeremonyContextVectorCaseV1,
    CeremonyContextVectorCorpusV1, CeremonyExpectedEncodingsV1,
    CeremonyExportAuthorizationVectorV1, CeremonyPublicRequestContextVectorV1,
    CeremonyRecoveryAuthorizationVectorV1, CeremonyRefreshAuthorizationVectorV1,
    CeremonyRegistrationAuthorizationVectorV1, CeremonyTranscriptInputVectorV1,
    CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1, CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use circuit::{
    compile_fixed_sha512_32_v1, compile_provisional_activation_core_v1,
    compile_provisional_export_core_v1, BooleanCircuitMetricsV1, FixedSha512CircuitV1,
    ProvisionalActivationCoreDigest32V1, ProvisionalActivationCoreV1,
    ProvisionalActivationScheduleDigest32V1, ProvisionalBenchmarkComponentDigest32V1,
    ProvisionalBenchmarkScheduleDigest32V1, ProvisionalExportCoreDigest32V1,
    ProvisionalExportCoreV1, ProvisionalExportScheduleDigest32V1, ProvisionalScheduleMetricsV1,
    PublicSyntheticActivationCoreInputsV1, PublicSyntheticActivationCoreOutputsV1,
    PublicSyntheticActivationInputErrorV1, PublicSyntheticDeriverAActivationInputsV1,
    PublicSyntheticDeriverAExportInputsV1, PublicSyntheticDeriverBActivationInputsV1,
    PublicSyntheticDeriverBExportInputsV1, PublicSyntheticExportCoreInputsV1,
    PublicSyntheticExportCoreOutputV1, PublicSyntheticTauFieldV1, FIXED_SHA512_32_BIT_ORDER_V1,
    FIXED_SHA512_32_INPUT_SCHEMA_V1, FIXED_SHA512_32_OUTPUT_SCHEMA_V1,
    PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1, PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1,
    PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1, PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1,
};
pub use context::{
    ApplicationBindingDigest, NormalizedParticipantIds, ParticipantPosition,
    StableKeyDerivationContext, StableKeyDerivationContextBindingDigest,
    StableKeyDerivationContextBytes, StableKeyDerivationContextError,
    STABLE_KEY_DERIVATION_CONTEXT_BINDING_DOMAIN_V1, STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1,
    STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN,
};
pub use continuity_reference::HostOnlyActivationContinuityFieldV1;
pub use evaluation_input_view_fixtures::{
    canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1,
    canonical_evaluation_input_party_view_vector_corpus_v1,
    parse_canonical_evaluation_input_party_view_vector_corpus_json_v1,
    EvaluationInputPartyViewVectorCorpusParseErrorV1, EvaluationInputPartyViewVectorCorpusV1,
    EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
    EVALUATION_INPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use evaluation_input_views::{
    build_host_only_activation_continuation_input_view_set_v1,
    build_host_only_export_evaluation_input_view_set_v1,
    build_host_only_recovery_evaluation_input_view_set_v1,
    build_host_only_refresh_evaluation_input_view_set_v1,
    build_host_only_registration_evaluation_input_view_set_v1,
    HostOnlyActivationContinuationInputCommonV1, HostOnlyActivationContinuationInputViewSetV1,
    HostOnlyClientEmptyEvaluationInputViewV1, HostOnlyDeriverAActivationEvaluationInputViewV1,
    HostOnlyDeriverAEmptyEvaluationInputViewV1, HostOnlyDeriverAExportEvaluationInputViewV1,
    HostOnlyDeriverBActivationEvaluationInputViewV1, HostOnlyDeriverBEmptyEvaluationInputViewV1,
    HostOnlyDeriverBExportEvaluationInputViewV1, HostOnlyDiagnosticsEmptyEvaluationInputViewV1,
    HostOnlyEvaluationInputExtensionKindV1, HostOnlyEvaluationInputStageV1,
    HostOnlyEvaluationInputViewErrorV1, HostOnlyEvaluationPlanV1, HostOnlyEvaluationWindowCountsV1,
    HostOnlyExportEvaluationInputCommonV1, HostOnlyExportEvaluationInputViewSetV1,
    HostOnlyObserverEmptyEvaluationInputViewV1, HostOnlyRecoveryEvaluationInputCommonV1,
    HostOnlyRecoveryEvaluationInputViewSetV1, HostOnlyRefreshEvaluationInputCommonV1,
    HostOnlyRefreshEvaluationInputViewSetV1, HostOnlyRegistrationEvaluationInputCommonV1,
    HostOnlyRegistrationEvaluationInputViewSetV1, HostOnlyRouterEmptyEvaluationInputViewV1,
    HostOnlySigningWorkerEmptyEvaluationInputViewV1,
};
pub use evaluator_abort_view_fixtures::{
    canonical_evaluator_abort_view_vector_corpus_json_bytes_v1,
    canonical_evaluator_abort_view_vector_corpus_v1,
    parse_canonical_evaluator_abort_view_vector_corpus_json_v1,
    EvaluatorAbortViewVectorCorpusParseErrorV1, EvaluatorAbortViewVectorCorpusV1,
    EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1, EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use export_delivery_fixtures::{
    canonical_export_delivery_vector_corpus_json_bytes_v1,
    canonical_export_delivery_vector_corpus_v1,
    parse_canonical_export_delivery_vector_corpus_json_v1, ExportDeliveryVectorCorpusParseErrorV1,
    ExportDeliveryVectorCorpusV1, EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
    EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use export_evaluation_acceptance_fixtures::{
    canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1,
    canonical_export_evaluator_authorization_vector_corpus_v1,
    parse_canonical_export_evaluator_authorization_vector_corpus_json_v1,
    ExportEvaluatorAuthorizationVectorCorpusParseErrorV1,
    ExportEvaluatorAuthorizationVectorCorpusV1,
    EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1,
    EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use export_reference::{
    evaluate_host_only_export_output_sharing_v1, prepare_host_only_export_reference_v1,
    HostOnlyExportPublicKeyEqualityWitnessV1, HostOnlyExportReferenceErrorV1,
    HostOnlyExportReferenceInputsV1, HostOnlyExportReferenceSuccessV1,
    HostOnlyPreparedExportReferenceV1,
};
pub use fixtures::{
    canonical_vector_corpus_v1, differential_vector_corpus_v1, DifferentialVectorError,
    VectorCaseV1, VectorClearReferenceTraceV1, VectorContextV1, VectorCorpusV1, VectorExportCaseV1,
    VectorInputsV1, VectorReferenceCaseV1, DIFFERENTIAL_INPUT_DOMAIN_V1,
    MAX_DIFFERENTIAL_VECTOR_CASES_V1, VECTOR_CORPUS_SCHEMA_V1,
};
pub use ideal_function_randomness::{
    HostOnlyActivationNoIdealCoinsV1, HostOnlyExportIdealCoinV1, HostOnlyRecoveryIdealCoinsV1,
    HostOnlyRefreshIdealCoinsV1, HostOnlyRegistrationIdealCoinsV1,
};
pub use joint_refresh_delta::{
    HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1,
    HostOnlyJointRefreshDeltaCoinsV1, HostOnlyJointRefreshDeltaErrorV1,
};
pub use kdf::{
    derive_synthetic_client_contributions_v1, derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1, SyntheticClientContributionsV1,
    SyntheticClientDerivationRootV1, SyntheticDeriverAClientContributionV1,
    SyntheticDeriverADerivationRootV1, SyntheticDeriverAServerContributionV1,
    SyntheticDeriverBClientContributionV1, SyntheticDeriverBDerivationRootV1,
    SyntheticDeriverBServerContributionV1, SyntheticTauContributionV1, SyntheticYContributionV1,
    CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1, CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1,
    CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1, CONTRIBUTION_KDF_EXTRACT_SALT_V1,
    CONTRIBUTION_KDF_ROLE_A_TAG_V1, CONTRIBUTION_KDF_ROLE_B_TAG_V1,
    CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1, CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
    CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
};
pub use kdf_fixtures::{
    canonical_kdf_vector_corpus_v1, KdfApplicationBindingVectorV1, KdfClearReferenceTraceV1,
    KdfContinuityVectorCaseV1, KdfContributionVectorV1, KdfStableContextVectorV1,
    KdfSyntheticRootsV1, KdfVectorCorpusV1, KDF_VECTOR_CORPUS_SCHEMA_V1,
};
pub use lifecycle_fixtures::{
    canonical_lifecycle_continuity_corpus_v1, ActivationContinuityVectorV1,
    ActiveContinuityPublicStateV1, ClientContributionPairV1, FixtureIdentityV1, FrozenAdmissionV1,
    JointRefreshDeltaV1, LifecycleContinuityCaseV1, LifecycleContinuityCorpusV1,
    LifecycleContinuityValidationErrorV1, NonZeroEpochV1, OpenAdmissionV1,
    RecoveryActivationContinuationV1, RecoveryContinuityVectorV1, RecoveryHostOnlyReferenceV1,
    RecoveryPendingPublicStateV1, ReferenceOperationCountsV1, RefreshActivatedPublicStateV1,
    RefreshActivationContinuationV1, RefreshContinuityVectorV1, RefreshDeltaContributionV1,
    RefreshHostOnlyReferenceV1, RefreshPendingPublicStateV1, RegistrationActivationContinuationV1,
    RegistrationCandidateMetadataVectorV1, RegistrationPendingPublicStateV1,
    RetiredRoleInputEpochPairV1, RoleEpochPairV1, RoleEpochV1,
    LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1, LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1,
    RECOVERY_ACTIVATION_CASE_ID_V1, RECOVERY_CONTINUITY_CASE_ID_V1, REFRESH_ACTIVATION_CASE_ID_V1,
    REFRESH_CONTINUITY_CASE_ID_V1, REGISTRATION_ACTIVATION_CASE_ID_V1,
    REGISTRATION_CANDIDATE_CASE_ID_V1,
};
pub use output_party_view_fixtures::{
    canonical_output_party_view_vector_corpus_json_bytes_v1,
    canonical_output_party_view_vector_corpus_v1,
    parse_canonical_output_party_view_vector_corpus_json_v1,
    OutputPartyViewVectorCorpusParseErrorV1, OutputPartyViewVectorCorpusV1,
    OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1, OUTPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use output_sharing::{
    reconstruct_host_only_client_scalar_output_v1, reconstruct_host_only_seed_export_v1,
    reconstruct_host_only_signing_worker_scalar_output_v1, share_host_only_activation_outputs_v1,
    share_host_only_export_seed_v1, HostOnlyActivationOutputCoinsV1,
    HostOnlyActivationOutputSharesV1, HostOnlyClientScalarOutputCoinV1,
    HostOnlyDeriverAActivationOutputSharesV1, HostOnlyDeriverAClientScalarShareV1,
    HostOnlyDeriverASeedExportShareV1, HostOnlyDeriverASigningWorkerScalarShareV1,
    HostOnlyDeriverBActivationOutputSharesV1, HostOnlyDeriverBClientScalarShareV1,
    HostOnlyDeriverBSeedExportShareV1, HostOnlyDeriverBSigningWorkerScalarShareV1,
    HostOnlyOutputSharingErrorV1, HostOnlySeedExportSharesV1, HostOnlySeedOutputCoinV1,
    HostOnlySigningWorkerScalarOutputCoinV1,
};
pub use output_sharing_fixtures::{
    canonical_output_sharing_vector_corpus_json_bytes_v1,
    canonical_output_sharing_vector_corpus_v1,
    parse_canonical_output_sharing_vector_corpus_json_v1, OutputSharingVectorCorpusParseErrorV1,
    OutputSharingVectorCorpusV1,
};
pub use provenance_fixtures::{
    canonical_provenance_vector_corpus_v1, ProvenanceArtifactWrapperGoldenV1,
    ProvenanceCaseVectorV1, ProvenanceLifecycleVectorCaseV1, ProvenanceRoleStatementVectorV1,
    ProvenanceVectorCorpusV1, PROVENANCE_SYNTHETIC_DIGEST_FIXTURE_DOMAIN_V1,
    PROVENANCE_VECTOR_CORPUS_SCHEMA_V1, PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use recovery_credential_transition_fixtures::{
    canonical_recovery_credential_transition_vector_corpus_json_bytes_v1,
    canonical_recovery_credential_transition_vector_corpus_v1,
    parse_canonical_recovery_credential_transition_vector_corpus_json_v1,
    RecoveryCredentialTransitionVectorCorpusParseErrorV1,
    RecoveryCredentialTransitionVectorCorpusV1,
    RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
    RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use recovery_reference::{
    evaluate_host_only_recovery_output_sharing_v1, prepare_host_only_recovery_reference_v1,
    HostOnlyPreparedRecoveryReferenceV1, HostOnlyRecoveryContinuityWitnessV1,
    HostOnlyRecoveryReferenceErrorV1, HostOnlyRecoveryReferenceInputsV1,
    HostOnlyRecoveryReferenceSuccessV1,
};
pub use recovery_evaluation_admission::{
    accept_host_only_recovery_admission_v1, AcceptedRecoveryAdmissionV1,
    OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1,
    RecoveryAdmissionCheckedAtUnixMsV1, RecoveryAdmissionErrorV1, RejectedRecoveryAdmissionV1,
    TerminalRecoveryEvaluationV1,
    RECOVERY_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1,
    RECOVERY_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
};
pub use recovery_evaluation_admission_fixtures::{
    canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_recovery_evaluator_admission_vector_corpus_v1,
    parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1,
    RecoveryEvaluatorAdmissionVectorCorpusParseErrorV1,
    RecoveryEvaluatorAdmissionVectorCorpusV1,
    RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
    RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use refresh_evaluation_admission::{
    accept_host_only_refresh_admission_v1, AcceptedRefreshAdmissionV1,
    OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1, RefreshAdmissionCheckedAtUnixMsV1,
    RefreshAdmissionErrorV1, RejectedRefreshAdmissionV1, TerminalRefreshEvaluationV1,
    REFRESH_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1,
    REFRESH_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
};
pub use refresh_reference::{
    evaluate_host_only_refresh_output_sharing_v1, prepare_host_only_refresh_reference_v1,
    HostOnlyPreparedRefreshReferenceV1, HostOnlyRefreshContinuityFieldV1,
    HostOnlyRefreshContinuityWitnessV1, HostOnlyRefreshReferenceErrorV1,
    HostOnlyRefreshReferenceInputsV1, HostOnlyRefreshReferenceSuccessV1,
};
pub use registered_key::{RegisteredEd25519PublicKey32V1, RegisteredEd25519PublicKeyErrorV1};
pub use registration_evaluation_admission::{
    accept_host_only_registration_admission_v1, AcceptedRegistrationAdmissionV1,
    OpaqueRegistrationInputSelectionEvidenceDigest32V1, RegistrationAdmissionCheckedAtUnixMsV1,
    RegistrationAdmissionErrorV1, RegistrationCandidateStateDigest32V1,
    RegistrationCandidateStateV1, RegistrationSelectionAttemptId32V1,
    TerminalRegistrationSelectionV1, REGISTRATION_CANDIDATE_STATE_DIGEST_DOMAIN_V1,
    REGISTRATION_CANDIDATE_STATE_ENCODING_DOMAIN_V1,
    REGISTRATION_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1,
    REGISTRATION_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
};
pub use registration_evaluation_admission_fixtures::{
    canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1,
    canonical_registration_evaluator_admission_vector_corpus_v1,
    parse_canonical_registration_evaluator_admission_vector_corpus_json_v1,
    RegistrationEvaluatorAdmissionVectorCorpusParseErrorV1,
    RegistrationEvaluatorAdmissionVectorCorpusV1,
    REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
    REGISTRATION_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use registration_reference::{
    evaluate_host_only_registration_output_sharing_v1, prepare_host_only_registration_reference_v1,
    HostOnlyPreparedRegistrationReferenceV1, HostOnlyRegistrationReferenceInputsV1,
    HostOnlyRegistrationReferenceSuccessV1,
};
pub use semantic_lifecycle_fixtures::{
    canonical_semantic_lifecycle_vector_corpus_json_bytes_v1,
    canonical_semantic_lifecycle_vector_corpus_v1,
    parse_canonical_semantic_lifecycle_vector_corpus_json_v1,
    SemanticLifecycleVectorCorpusParseErrorV1, SemanticLifecycleVectorCorpusV1,
    SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1, SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1,
};
pub use specification_goldens::{
    canonical_fixed_reference_generated_block_v1, render_fixed_reference_specification_v1,
    FixedReferenceSpecificationErrorV1, FIXED_REFERENCE_GENERATED_BEGIN_V1,
    FIXED_REFERENCE_GENERATED_END_V1, FIXED_REFERENCE_GENERATED_SCHEMA_V1,
};
pub use uniform_abort_fixtures::{
    canonical_uniform_abort_vector_corpus_json_bytes_v1, canonical_uniform_abort_vector_corpus_v1,
    parse_canonical_uniform_abort_vector_corpus_json_v1, UniformAbortVectorCorpusParseErrorV1,
    UniformAbortVectorCorpusV1, UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1,
    UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1,
};

/// Fallible result returned while validating raw role contributions.
pub type OracleResult<T> = Result<T, OracleError>;

/// Fixed role associated with a malformed contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriverRole {
    /// First independently administered Deriver.
    A,
    /// Second independently administered Deriver.
    B,
}

impl fmt::Display for DeriverRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => formatter.write_str("Deriver A"),
            Self::B => formatter.write_str("Deriver B"),
        }
    }
}

/// Client or server contribution carried by one Deriver input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionSide {
    /// Contribution to the client-labelled share.
    Client,
    /// Contribution to the server-labelled share.
    Server,
}

impl fmt::Display for ContributionSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => formatter.write_str("client"),
            Self::Server => formatter.write_str("server"),
        }
    }
}

/// Boundary validation failures for reference-oracle inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    /// A tau contribution is greater than or equal to the Ed25519 scalar order.
    NonCanonicalTauContribution {
        /// Deriver that supplied the malformed scalar.
        role: DeriverRole,
        /// Client/server contribution that contained the malformed scalar.
        side: ContributionSide,
    },
}

impl fmt::Display for OracleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalTauContribution { role, side } => {
                write!(
                    formatter,
                    "{role} {side} tau contribution must be canonical"
                )
            }
        }
    }
}

impl std::error::Error for OracleError {}

/// Unvalidated named boundary input for Deriver A.
pub struct RawDeriverAContribution {
    /// A's client-labelled little-endian seed contribution.
    pub y_client: [u8; 32],
    /// A's server-labelled little-endian seed contribution.
    pub y_server: [u8; 32],
    /// A's client-labelled scalar contribution in canonical encoding.
    pub tau_client: [u8; 32],
    /// A's server-labelled scalar contribution in canonical encoding.
    pub tau_server: [u8; 32],
}

/// Unvalidated named boundary input for Deriver B.
pub struct RawDeriverBContribution {
    /// B's client-labelled little-endian seed contribution.
    pub y_client: [u8; 32],
    /// B's server-labelled little-endian seed contribution.
    pub y_server: [u8; 32],
    /// B's client-labelled scalar contribution in canonical encoding.
    pub tau_client: [u8; 32],
    /// B's server-labelled scalar contribution in canonical encoding.
    pub tau_server: [u8; 32],
}

/// Validated A/client seed contribution.
pub struct DeriverAClientY([u8; 32]);

impl DeriverAClientY {
    /// Explicitly exposes the synthetic/test-vector bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Validated A/server seed contribution.
pub struct DeriverAServerY([u8; 32]);

impl DeriverAServerY {
    /// Explicitly exposes the synthetic/test-vector bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Validated A/client scalar contribution.
pub struct DeriverAClientTau(Scalar);

impl DeriverAClientTau {
    fn parse(bytes: [u8; 32]) -> OracleResult<Self> {
        parse_canonical_tau(DeriverRole::A, ContributionSide::Client, bytes).map(Self)
    }

    /// Explicitly exposes the canonical synthetic/test-vector bytes.
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Validated A/server scalar contribution.
pub struct DeriverAServerTau(Scalar);

impl DeriverAServerTau {
    fn parse(bytes: [u8; 32]) -> OracleResult<Self> {
        parse_canonical_tau(DeriverRole::A, ContributionSide::Server, bytes).map(Self)
    }

    /// Explicitly exposes the canonical synthetic/test-vector bytes.
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Validated B/client seed contribution.
pub struct DeriverBClientY([u8; 32]);

impl DeriverBClientY {
    /// Explicitly exposes the synthetic/test-vector bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Validated B/server seed contribution.
pub struct DeriverBServerY([u8; 32]);

impl DeriverBServerY {
    /// Explicitly exposes the synthetic/test-vector bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Validated B/client scalar contribution.
pub struct DeriverBClientTau(Scalar);

impl DeriverBClientTau {
    fn parse(bytes: [u8; 32]) -> OracleResult<Self> {
        parse_canonical_tau(DeriverRole::B, ContributionSide::Client, bytes).map(Self)
    }

    /// Explicitly exposes the canonical synthetic/test-vector bytes.
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Validated B/server scalar contribution.
pub struct DeriverBServerTau(Scalar);

impl DeriverBServerTau {
    fn parse(bytes: [u8; 32]) -> OracleResult<Self> {
        parse_canonical_tau(DeriverRole::B, ContributionSide::Server, bytes).map(Self)
    }

    /// Explicitly exposes the canonical synthetic/test-vector bytes.
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Validated, field-specific inputs owned by Deriver A.
pub struct DeriverAContribution {
    y_client: DeriverAClientY,
    y_server: DeriverAServerY,
    tau_client: DeriverAClientTau,
    tau_server: DeriverAServerTau,
}

impl TryFrom<RawDeriverAContribution> for DeriverAContribution {
    type Error = OracleError;

    fn try_from(raw: RawDeriverAContribution) -> OracleResult<Self> {
        Ok(Self {
            y_client: DeriverAClientY(raw.y_client),
            y_server: DeriverAServerY(raw.y_server),
            tau_client: DeriverAClientTau::parse(raw.tau_client)?,
            tau_server: DeriverAServerTau::parse(raw.tau_server)?,
        })
    }
}

impl DeriverAContribution {
    /// Returns A's client-labelled seed contribution domain value.
    pub const fn y_client(&self) -> &DeriverAClientY {
        &self.y_client
    }

    /// Returns A's server-labelled seed contribution domain value.
    pub const fn y_server(&self) -> &DeriverAServerY {
        &self.y_server
    }

    /// Returns A's validated client-labelled scalar domain value.
    pub const fn tau_client(&self) -> &DeriverAClientTau {
        &self.tau_client
    }

    /// Returns A's validated server-labelled scalar domain value.
    pub const fn tau_server(&self) -> &DeriverAServerTau {
        &self.tau_server
    }
}

/// Validated, field-specific inputs owned by Deriver B.
pub struct DeriverBContribution {
    y_client: DeriverBClientY,
    y_server: DeriverBServerY,
    tau_client: DeriverBClientTau,
    tau_server: DeriverBServerTau,
}

impl TryFrom<RawDeriverBContribution> for DeriverBContribution {
    type Error = OracleError;

    fn try_from(raw: RawDeriverBContribution) -> OracleResult<Self> {
        Ok(Self {
            y_client: DeriverBClientY(raw.y_client),
            y_server: DeriverBServerY(raw.y_server),
            tau_client: DeriverBClientTau::parse(raw.tau_client)?,
            tau_server: DeriverBServerTau::parse(raw.tau_server)?,
        })
    }
}

impl DeriverBContribution {
    /// Returns B's client-labelled seed contribution domain value.
    pub const fn y_client(&self) -> &DeriverBClientY {
        &self.y_client
    }

    /// Returns B's server-labelled seed contribution domain value.
    pub const fn y_server(&self) -> &DeriverBServerY {
        &self.y_server
    }

    /// Returns B's validated client-labelled scalar domain value.
    pub const fn tau_client(&self) -> &DeriverBClientTau {
        &self.tau_client
    }

    /// Returns B's validated server-labelled scalar domain value.
    pub const fn tau_server(&self) -> &DeriverBServerTau {
        &self.tau_server
    }
}

/// Reconstructed 32-byte RFC 8032 seed.
pub struct SeedBytes([u8; 32]);

impl SeedBytes {
    /// Explicitly exposes the synthetic/test-vector seed bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Full SHA-512 digest bytes.
pub struct Sha512DigestBytes([u8; 64]);

impl Sha512DigestBytes {
    /// Explicitly exposes the synthetic/test-vector digest bytes.
    pub const fn expose_bytes(&self) -> [u8; 64] {
        self.0
    }
}

/// RFC 8032-clamped digest prefix before scalar reduction.
pub struct ClampedScalarBytes([u8; 32]);

impl ClampedScalarBytes {
    /// Explicitly exposes the synthetic/test-vector clamped bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Canonical little-endian Ed25519 scalar encoding.
pub struct CanonicalScalarBytes([u8; 32]);

impl CanonicalScalarBytes {
    /// Explicitly exposes the synthetic/test-vector scalar bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Canonical compressed Edwards point encoding.
pub struct CompressedEdwardsPointBytes([u8; 32]);

impl CompressedEdwardsPointBytes {
    /// Explicitly exposes the synthetic/test-vector point bytes.
    pub const fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Seed-excluding reference trace shared by activation and export vectors.
pub struct OracleMaterial {
    sha512_digest: Sha512DigestBytes,
    clamped_scalar_bytes: ClampedScalarBytes,
    signing_scalar: CanonicalScalarBytes,
    tau: CanonicalScalarBytes,
    x_client_base: CanonicalScalarBytes,
    x_server_base: CanonicalScalarBytes,
    x_client: CompressedEdwardsPointBytes,
    x_server: CompressedEdwardsPointBytes,
    public_key: CompressedEdwardsPointBytes,
}

impl OracleMaterial {
    /// Returns the full SHA-512 digest domain value.
    pub const fn sha512_digest(&self) -> &Sha512DigestBytes {
        &self.sha512_digest
    }

    /// Returns the clamped digest-prefix domain value before reduction.
    pub const fn clamped_scalar_bytes(&self) -> &ClampedScalarBytes {
        &self.clamped_scalar_bytes
    }

    /// Returns the canonical reduced signing scalar domain value.
    pub const fn signing_scalar(&self) -> &CanonicalScalarBytes {
        &self.signing_scalar
    }

    /// Returns the canonical sum of all four tau contributions.
    pub const fn tau(&self) -> &CanonicalScalarBytes {
        &self.tau
    }

    /// Returns the canonical `a + tau mod l` scalar domain value.
    pub const fn x_client_base(&self) -> &CanonicalScalarBytes {
        &self.x_client_base
    }

    /// Returns the canonical `a + 2*tau mod l` scalar domain value.
    pub const fn x_server_base(&self) -> &CanonicalScalarBytes {
        &self.x_server_base
    }

    /// Returns the compressed `[a + tau]B` point domain value.
    pub const fn x_client(&self) -> &CompressedEdwardsPointBytes {
        &self.x_client
    }

    /// Returns the compressed `[a + 2*tau]B` point domain value.
    pub const fn x_server(&self) -> &CompressedEdwardsPointBytes {
        &self.x_server
    }

    /// Returns the compressed RFC 8032 public-key domain value.
    pub const fn public_key(&self) -> &CompressedEdwardsPointBytes {
        &self.public_key
    }
}

/// Activation output, which intentionally cannot carry an exported seed.
///
/// ```compile_fail
/// use ed25519_yao_generator::ActivationOracleOutput;
///
/// fn expose_seed(output: ActivationOracleOutput) {
///     let _ = output.seed();
/// }
/// ```
pub struct ActivationOracleOutput {
    material: OracleMaterial,
}

impl ActivationOracleOutput {
    /// Returns the activation reference trace.
    pub const fn material(&self) -> &OracleMaterial {
        &self.material
    }
}

/// Explicit export output with a required reconstructed seed.
pub struct ExportOracleOutput {
    material: OracleMaterial,
    seed: SeedBytes,
}

impl ExportOracleOutput {
    /// Returns the export reference trace.
    pub const fn material(&self) -> &OracleMaterial {
        &self.material
    }

    /// Returns the required reconstructed seed domain value.
    pub const fn seed(&self) -> &SeedBytes {
        &self.seed
    }
}

struct SharedEvaluation {
    material: OracleMaterial,
    seed: SeedBytes,
}

struct DeriverAY([u8; 32]);
struct DeriverBY([u8; 32]);
struct DeriverATau(Scalar);
struct DeriverBTau(Scalar);

/// Evaluates the activation functionality without returning the reconstructed seed.
pub fn evaluate_activation(
    deriver_a: &DeriverAContribution,
    deriver_b: &DeriverBContribution,
) -> ActivationOracleOutput {
    let evaluation = evaluate_shared(deriver_a, deriver_b);
    ActivationOracleOutput {
        material: evaluation.material,
    }
}

/// Evaluates the full clear reference trace used only by arithmetic fixtures.
///
/// The branch export boundary is the y-only `HostOnlyExportReferenceInputsV1`.
/// This full trace also computes activation-family scalar material and must not
/// be used as an export input or protocol API.
pub fn evaluate_full_clear_reference_export_v1(
    deriver_a: &DeriverAContribution,
    deriver_b: &DeriverBContribution,
) -> ExportOracleOutput {
    let evaluation = evaluate_shared(deriver_a, deriver_b);
    ExportOracleOutput {
        material: evaluation.material,
        seed: evaluation.seed,
    }
}

/// Adds two 256-bit little-endian integers and discards the final carry.
pub fn wrapping_add_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut carry = 0u16;

    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }

    output
}

/// Applies the RFC 8032 pruning operation to a 32-byte digest prefix.
pub fn clamp_rfc8032(mut digest_prefix: [u8; 32]) -> [u8; 32] {
    digest_prefix[0] &= 248;
    digest_prefix[31] &= 63;
    digest_prefix[31] |= 64;
    digest_prefix
}

fn evaluate_shared(
    deriver_a: &DeriverAContribution,
    deriver_b: &DeriverBContribution,
) -> SharedEvaluation {
    let y_a = combine_deriver_a_y(&deriver_a.y_client, &deriver_a.y_server);
    let y_b = combine_deriver_b_y(&deriver_b.y_client, &deriver_b.y_server);
    let seed = combine_seed(y_a, y_b);
    let sha512_digest: [u8; 64] = Sha512::digest(seed.0).into();
    let mut digest_prefix = [0u8; 32];
    digest_prefix.copy_from_slice(&sha512_digest[..32]);

    let clamped_scalar_bytes = clamp_rfc8032(digest_prefix);
    let signing_scalar = Scalar::from_bytes_mod_order(clamped_scalar_bytes);
    let tau_a = combine_deriver_a_tau(&deriver_a.tau_client, &deriver_a.tau_server);
    let tau_b = combine_deriver_b_tau(&deriver_b.tau_client, &deriver_b.tau_server);
    let tau = combine_tau(tau_a, tau_b);
    let x_client_base = signing_scalar + tau;
    let x_server_base = signing_scalar + tau + tau;
    let x_client = (ED25519_BASEPOINT_POINT * x_client_base)
        .compress()
        .to_bytes();
    let x_server = (ED25519_BASEPOINT_POINT * x_server_base)
        .compress()
        .to_bytes();
    let public_key = SigningKey::from_bytes(&seed.0).verifying_key().to_bytes();

    SharedEvaluation {
        material: OracleMaterial {
            sha512_digest: Sha512DigestBytes(sha512_digest),
            clamped_scalar_bytes: ClampedScalarBytes(clamped_scalar_bytes),
            signing_scalar: CanonicalScalarBytes(signing_scalar.to_bytes()),
            tau: CanonicalScalarBytes(tau.to_bytes()),
            x_client_base: CanonicalScalarBytes(x_client_base.to_bytes()),
            x_server_base: CanonicalScalarBytes(x_server_base.to_bytes()),
            x_client: CompressedEdwardsPointBytes(x_client),
            x_server: CompressedEdwardsPointBytes(x_server),
            public_key: CompressedEdwardsPointBytes(public_key),
        },
        seed,
    }
}

fn combine_deriver_a_y(client: &DeriverAClientY, server: &DeriverAServerY) -> DeriverAY {
    DeriverAY(wrapping_add_le_256(client.0, server.0))
}

fn combine_deriver_b_y(client: &DeriverBClientY, server: &DeriverBServerY) -> DeriverBY {
    DeriverBY(wrapping_add_le_256(client.0, server.0))
}

fn combine_seed(deriver_a: DeriverAY, deriver_b: DeriverBY) -> SeedBytes {
    SeedBytes(wrapping_add_le_256(deriver_a.0, deriver_b.0))
}

fn combine_deriver_a_tau(client: &DeriverAClientTau, server: &DeriverAServerTau) -> DeriverATau {
    DeriverATau(client.0 + server.0)
}

fn combine_deriver_b_tau(client: &DeriverBClientTau, server: &DeriverBServerTau) -> DeriverBTau {
    DeriverBTau(client.0 + server.0)
}

fn combine_tau(deriver_a: DeriverATau, deriver_b: DeriverBTau) -> Scalar {
    deriver_a.0 + deriver_b.0
}

fn parse_canonical_tau(
    role: DeriverRole,
    side: ContributionSide,
    bytes: [u8; 32],
) -> OracleResult<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(OracleError::NonCanonicalTauContribution { role, side })
}
