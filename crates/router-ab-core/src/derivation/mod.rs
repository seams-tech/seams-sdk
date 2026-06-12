#![forbid(unsafe_code)]
//! Split derivation primitive candidates for the Router/A/B signer architecture.
//!
//! The crate is intentionally scoped to derivation and transcript-bound output
//! material. Router, signer, and relayer networking lives in adapters around
//! this crate.

mod bench;
mod candidate_mpc_prf;
mod candidate_mpc_prf_threshold_backend;
mod candidate_split_root;
mod context;
mod diagnostics;
mod envelope;
mod error;
mod evidence;
mod leakage;
mod material;
mod scope;
mod signer_plaintext;
mod state_machine;
mod transcript;
mod vectors;
mod wire;

pub use self::bench::{
    candidate_measurement_gate_report_v1, candidate_round_trip_profiles_v1,
    CandidateBenchmarkMeasurement, CandidateBenchmarkReport, CandidateMeasurementGateReportV1,
    CandidateMeasurementGateStatus, CandidateMeasurementGateV1, CandidateRoundTripProfileV1,
    CANDIDATE_MEASUREMENT_GATES_VERSION_V1,
};
pub use self::candidate_mpc_prf::{
    evaluate_mpc_threshold_prf_candidate, plan_mpc_prf_combine_v1,
    plan_mpc_prf_partial_verification_v1, plan_mpc_prf_purpose_binding_v1, MpcPrfCandidateInput,
    MpcPrfCandidateOutput, MpcPrfCombinePlanV1, MpcPrfCombinerInputV1, MpcPrfDleqProofWireV1,
    MpcPrfOutputEncodingV1, MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1, MpcPrfPartialBindingV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialVerificationInputV1, MpcPrfPartialVerificationPlanV1,
    MpcPrfPartialWireV1, MpcPrfPurposeBindingPlanV1, MpcPrfShareCommitmentWireV1,
    MpcPrfSignerPartialInputV1, MpcPrfSignerPartialV1, MpcPrfSuiteId, MpcPrfVerifiedPartialV1,
    MPC_PRF_COMMITMENT_WIRE_V1_LEN, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
};
pub use self::candidate_mpc_prf_threshold_backend::{
    combine_mpc_prf_batch_outputs_with_threshold_backend_v1,
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_partial_with_threshold_backend_v1,
    verify_mpc_prf_partial_with_threshold_backend_v1, MpcPrfSigningRootShareWireV1,
    MpcPrfThresholdBatchCombineInputV1, MpcPrfThresholdBatchCombinedOutputV1,
    MpcPrfThresholdCombineInputV1, MpcPrfThresholdCombinedOutputV1,
    MpcPrfThresholdSignerBatchInputV1, MpcPrfThresholdSignerBatchOutputV1,
    MpcPrfThresholdSignerInputV1, MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN,
};
pub use self::candidate_split_root::{
    combine_split_root_verified_output_shares_v1, derive_split_root_output_share_v1,
    evaluate_split_root_candidate, plan_split_root_combine_v1, plan_split_root_output_share_v1,
    plan_split_root_refresh_v1, SplitRootCandidateInput, SplitRootCandidateOutput,
    SplitRootCombinePlanV1, SplitRootCombinedOutputV1, SplitRootCombinerInputV1,
    SplitRootDerivationLabelV1, SplitRootOutputRequestV1, SplitRootOutputShareBindingV1,
    SplitRootOutputShareWireV1, SplitRootRefreshModeV1, SplitRootRefreshPlanInputV1,
    SplitRootRefreshPlanV1, SplitRootSecretShareV1, SplitRootSignerInputV1,
    SplitRootSignerOutputShareV1, SplitRootSuiteId, SplitRootVerifiedOutputShareV1,
    SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN, SPLIT_ROOT_SECRET_SHARE_V1_LEN,
};
pub use self::context::{
    context_digest_v1, AccountScope, CandidateId, CorrectnessLevel, DerivationContext, RequestKind,
    RootShareEpoch,
};
pub use self::diagnostics::redacted_diagnostic;
pub use self::envelope::{
    envelope_aad_v1, envelope_idempotency_key_v1, package_commitment_v1, ContentKind,
    DeliveryPackageV1, EnvelopeHeaderV1, EnvelopeKind, EnvelopeVersion,
};
pub use self::error::{
    RedactedDiagnostic, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult,
};
pub use self::evidence::{
    signer_receipt_digest_v1, verify_minimum_level_c_v1, AcceptedReplayCacheDecisionV1,
    AuthenticatedSignerReceiptV1, MinimumLevelCEvidenceV1, MinimumLevelCEvidenceVersion,
    MinimumLevelCVerificationInputV1, SignerReceiptVersion, VerifiedMinimumLevelCEvidenceV1,
};
pub use self::leakage::{default_leakage_questions, LeakageQuestion, LeakageQuestionId};
pub use self::material::{
    OpenedShareKind, PublicDigest32, PublicMaterial32, Role, SecretMaterial32,
};
pub use self::scope::{ExportScope, RefreshScope, RegistrationScope, RequestScope};
pub use self::signer_plaintext::{
    decode_signer_input_plaintext_v1, encode_signer_input_plaintext_v1, SignerInputPlaintextV1,
    SignerInputQuorumPolicyV1,
};
pub use self::state_machine::{
    abort_ceremony, accept_signer_inputs, begin_requested, bind_outputs, complete_coordination,
    create_role_envelopes, mark_delivered, verify_ceremony, AbortInput, BeginCeremonyInput,
    CeremonyAborted, CeremonyDelivered, CeremonyRequested, CeremonyStateLabel, CeremonyVerified,
    CoordinationComplete, CoordinationCompletionInput, CreateRoleEnvelopesInput,
    DeliveryReceiptInput, OutputBindingInput, OutputsBound, RoleEnvelopesCreated,
    SignerInputAcceptance, SignerInputsAccepted, VerificationInput,
};
pub use self::transcript::{
    transcript_binding_digest, transcript_digest_v1, IndexedSignerBinding, QuorumPolicy,
    SignerSetBinding, TranscriptBinding,
};
pub use self::vectors::{
    generated_contract_vectors_json_v1, generated_contract_vectors_v1, parse_vector_fixture_v1,
    validate_vector_fixture_v1, vector_case_context_v1, vector_case_transcript_v1,
    CandidateOutputVectorV1, ContextTranscriptVectorV1, ContractVectorCorpusV1,
    DerivationVectorCaseV1, DerivationVectorFixtureV1, DiagnosticVectorV1, EnvelopeVectorV1,
    MinimumLevelCVectorV1, RejectionVectorV1, CONTRACT_VECTOR_VERSION_V1,
};
pub use self::wire::{CanonicalEncoding, WireVersion};
