use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::candidate::{CandidateBackendFamily, FixedHiddenCoreCandidate};
use crate::context::CanonicalContext;
use crate::ddh_hidden_eval_executor::{
    execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool,
    execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool,
    execute_prime_order_ddh_hidden_eval_program_with_transport_server_inputs_with_pool,
    prepare_ddh_hidden_eval_constant_pool, probe_prime_order_ddh_hidden_eval_program_with_pool,
    DdhHiddenEvalCheckpoint, DdhHiddenEvalConstantPool, DdhHiddenEvalOutputBundles,
    DdhHiddenEvalProbe, DdhHiddenEvalProfile, DdhHiddenEvalServerInputs,
};
use crate::ddh_hss::{
    keygen_prime_order_ddh_hss_backend, role_views_for_backend, DdhHssBackend, DdhHssEvaluationKey,
    DdhHssEvaluator, DdhHssGarbler, DdhHssInputShareBundle, DdhHssOtInputBundleOffer,
    DdhHssOtReceiverStateBundle, DdhHssOtReconstructTiming, DdhHssOtReleasedRemoteBundle,
    DdhHssOtRemoteBundle, DdhHssOtResponseBundle, DdhHssOtSelectionBundle,
    DdhHssOtSenderStateBundle, DdhHssShareSide, DdhHssSharedWord, DdhHssTransportBundle,
    DdhHssTransportPurpose,
};
use crate::hidden_eval::{
    compile_prime_order_hidden_eval_program, HiddenEvalInputOwner, HiddenEvalProgram,
};
use crate::prime_order_cpu_executor::{
    compile_prime_order_cpu_execution_program, execute_prime_order_cpu_execution_program,
    PrimeOrderCpuExecutionProgram, PrimeOrderCpuExecutionResult,
};
use crate::prime_order_decoder::decode_prime_order_size_optimized_artifact;
use crate::prime_order_encoder::{
    build_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
    PrimeOrderEncodedArtifact,
};
use crate::prime_order_trace::PrimeOrderEvaluatorOps;
use crate::reference::{public_key_from_base_shares, FExpandInput};
use crate::{build_fixed_hidden_core_candidate, ProtoError, ProtoResult};

pub const PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION: &str = "prime_order_succinct_hss_v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HiddenCoreMaterialization {
    DdhPrimitiveBaseline,
}

pub struct PrimeOrderSuccinctHssPreparedSession {
    candidate: FixedHiddenCoreCandidate,
    artifact: PrimeOrderEncodedArtifact,
    artifact_bytes: Vec<u8>,
    hidden_eval_program: HiddenEvalProgram,
    hidden_eval_constants: DdhHiddenEvalConstantPool,
    ddh_backend: DdhHssBackend,
    ddh_garbler: DdhHssGarbler,
    ddh_evaluator: DdhHssEvaluator,
    execution_program: PrimeOrderCpuExecutionProgram,
    client_ot_offer: PrimeOrderSuccinctHssClientOtOffer,
    garbler_ot_state: PrimeOrderSuccinctHssGarblerOtState,
    shared_runtime_cached: PrimeOrderSuccinctHssSharedRuntime,
    garbler_session_cached: PrimeOrderSuccinctHssGarblerSession,
    evaluator_session_cached: PrimeOrderSuccinctHssEvaluatorSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssArtifactSummary {
    pub encoder_version: String,
    pub artifact_bytes: u64,
    pub artifact_digest: [u8; 32],
    pub section_count: usize,
    pub context_binding: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub round_template_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssRunBindings {
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssEvaluatorWitness {
    pub total_steps: usize,
    pub curve_cost_units: u64,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub output_checksum: u64,
    pub final_point_compressed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssDeliveryMaterial {
    pub report_version: String,
    pub fixed_function_id: String,
    pub hidden_core_materialization: HiddenCoreMaterialization,
    pub artifact: PrimeOrderSuccinctHssArtifactSummary,
    pub evaluation_key: DdhHssEvaluationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssClientPacket {
    pub context_binding: [u8; 32],
    pub y_client_request: DdhHssOtSelectionBundle,
    pub tau_client_request: DdhHssOtSelectionBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssEvaluatorOtState {
    pub context_binding: [u8; 32],
    pub y_client_local_state: DdhHssOtReceiverStateBundle,
    pub tau_client_local_state: DdhHssOtReceiverStateBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssClientOtOffer {
    pub context_binding: [u8; 32],
    pub y_client_offer: DdhHssOtInputBundleOffer,
    pub tau_client_offer: DdhHssOtInputBundleOffer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrimeOrderSuccinctHssTransportKind {
    ClientOtOffer,
    ClientOtRequest,
    ServerPacket,
    EvaluationResult,
    ClientOutput,
    ServerOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderSuccinctHssTransportFrame {
    report_version: String,
    context_binding: [u8; 32],
    kind: PrimeOrderSuccinctHssTransportKind,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssWireMessage {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssGarblerOtState {
    pub context_binding: [u8; 32],
    pub y_client_remote: DdhHssOtRemoteBundle,
    pub tau_client_remote: DdhHssOtRemoteBundle,
    pub y_client_sender_state: DdhHssOtSenderStateBundle,
    pub tau_client_sender_state: DdhHssOtSenderStateBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderSuccinctHssGarblerSession {
    context_binding: [u8; 32],
    ddh_garbler: DdhHssGarbler,
    client_ot_offer: PrimeOrderSuccinctHssClientOtOffer,
    garbler_ot_state: PrimeOrderSuccinctHssGarblerOtState,
}

#[derive(Clone)]
pub struct PrimeOrderSuccinctHssEvaluatorSession {
    context_binding: [u8; 32],
    ddh_evaluator: DdhHssEvaluator,
    client_ot_offer: PrimeOrderSuccinctHssClientOtOffer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderSuccinctHssSharedRuntime {
    candidate: FixedHiddenCoreCandidate,
    artifact: PrimeOrderSuccinctHssArtifactSummary,
    hidden_eval_program: HiddenEvalProgram,
    hidden_eval_constants: DdhHiddenEvalConstantPool,
    ddh_evaluator: DdhHssEvaluator,
    execution_program: PrimeOrderCpuExecutionProgram,
    execution_result: PrimeOrderCpuExecutionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssSharedRuntimeState {
    pub candidate: FixedHiddenCoreCandidate,
    pub ddh_evaluator: DdhHssEvaluator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssGarblerDriverState {
    pub runtime: PrimeOrderSuccinctHssSharedRuntimeState,
    pub garbler_session: PrimeOrderSuccinctHssGarblerSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssEvaluatorDriverState {
    pub runtime: PrimeOrderSuccinctHssSharedRuntimeState,
    pub evaluator_session: PrimeOrderSuccinctHssEvaluatorSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssGarblerSessionState {
    pub context_binding: [u8; 32],
    pub ddh_garbler: DdhHssGarbler,
    pub client_ot_offer: PrimeOrderSuccinctHssClientOtOffer,
    pub garbler_ot_state: PrimeOrderSuccinctHssGarblerOtState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssEvaluatorSessionState {
    pub context_binding: [u8; 32],
    pub ddh_evaluator: DdhHssEvaluator,
    pub client_ot_offer: PrimeOrderSuccinctHssClientOtOffer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssServerPacket {
    pub context_binding: [u8; 32],
    pub ot_transcript: PrimeOrderSuccinctHssOtTranscript,
    pub y_client_response: DdhHssOtResponseBundle,
    pub tau_client_response: DdhHssOtResponseBundle,
    pub y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub server_inputs: PrimeOrderSuccinctHssServerInputsPacket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssOtTranscript {
    pub context_binding: [u8; 32],
    pub y_client_offer_commitment: [u8; 32],
    pub y_client_request_commitment: [u8; 32],
    pub y_client_response_commitment: [u8; 32],
    pub y_client_remote_release_binding: [u8; 32],
    pub tau_client_offer_commitment: [u8; 32],
    pub tau_client_request_commitment: [u8; 32],
    pub tau_client_response_commitment: [u8; 32],
    pub tau_client_remote_release_binding: [u8; 32],
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssClientOutputPacket {
    pub context_binding: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssServerOutputPacket {
    pub context_binding: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssOutputDelivery {
    pub client: PrimeOrderSuccinctHssWireMessage,
    pub server: PrimeOrderSuccinctHssWireMessage,
}

struct PrimeOrderSuccinctHssTrustedServerEval {
    y_client_response: DdhHssOtResponseBundle,
    tau_client_response: DdhHssOtResponseBundle,
    y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
    server_input_commitment: [u8; 32],
    trusted_server_inputs: DdhHiddenEvalServerInputs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssEvaluationResult {
    pub context_binding: [u8; 32],
    pub bindings: PrimeOrderSuccinctHssRunBindings,
    pub evaluator_witness: PrimeOrderSuccinctHssEvaluatorWitness,
    pub client_output: PrimeOrderSuccinctHssWireMessage,
    pub client_output_binding: [u8; 32],
    pub server_output_payload_binding: [u8; 32],
    pub server_output_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderSuccinctHssClientOutputOpener {
    evaluator: DdhHssEvaluator,
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderSuccinctHssServerOutputOpener {
    garbler: DdhHssGarbler,
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderSuccinctHssOutputOpeners {
    pub client: PrimeOrderSuccinctHssClientOutputOpener,
    pub server: PrimeOrderSuccinctHssServerOutputOpener,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssServerInputsPacket {
    pub context_binding: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderSuccinctHssJointWordWire {
    width_bits: u16,
    left_word: u64,
    right_word: u64,
    left_commitment: [u8; 32],
    right_commitment: [u8; 32],
    provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderSuccinctHssJointBundleWire {
    owner: HiddenEvalInputOwner,
    label: String,
    words: Vec<PrimeOrderSuccinctHssJointWordWire>,
    commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderSuccinctHssEncodedBundlePayload {
    bundle: PrimeOrderSuccinctHssJointBundleWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderSuccinctHssEncodedTransportPairPayload {
    left: DdhHssTransportBundle,
    right: DdhHssTransportBundle,
}

#[derive(Debug, Serialize)]
struct PrimeOrderSuccinctHssEncodedTransportPairPayloadRef<'a> {
    left: &'a DdhHssTransportBundle,
    right: &'a DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderSuccinctHssEncodedServerInputsPayload {
    y_relayer_left: DdhHssTransportBundle,
    y_relayer_right: DdhHssTransportBundle,
    tau_relayer_left: DdhHssTransportBundle,
    tau_relayer_right: DdhHssTransportBundle,
}

#[derive(Debug, Serialize)]
struct PrimeOrderSuccinctHssEncodedServerInputsPayloadRef<'a> {
    y_relayer_left: &'a DdhHssTransportBundle,
    y_relayer_right: &'a DdhHssTransportBundle,
    tau_relayer_left: &'a DdhHssTransportBundle,
    tau_relayer_right: &'a DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimeOrderSuccinctHssOpenedServerInputs {
    y_relayer_left: DdhHssTransportBundle,
    y_relayer_right: DdhHssTransportBundle,
    tau_relayer_left: DdhHssTransportBundle,
    tau_relayer_right: DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderSuccinctHssEvaluationReport {
    pub report_version: String,
    pub backend_family: CandidateBackendFamily,
    pub fixed_function_id: String,
    pub hidden_core_materialization: HiddenCoreMaterialization,
    pub artifact: PrimeOrderSuccinctHssArtifactSummary,
    pub bindings: PrimeOrderSuccinctHssRunBindings,
    pub evaluator_witness: PrimeOrderSuccinctHssEvaluatorWitness,
    pub output_delivery: PrimeOrderSuccinctHssOutputDelivery,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrimeOrderSuccinctHssEvaluateTiming {
    pub ot_open_join_duration_ns: u64,
    pub ot_branch_key_derivation_duration_ns: u64,
    pub ot_branch_decrypt_duration_ns: u64,
    pub ot_point_scalar_reconstruction_duration_ns: u64,
    pub ot_commitment_verification_duration_ns: u64,
    pub server_input_open_duration_ns: u64,
    pub server_input_share_duration_ns: u64,
    pub server_input_commitment_duration_ns: u64,
    pub server_input_transcript_duration_ns: u64,
    pub server_input_seal_duration_ns: u64,
    pub output_sealing_finalization_duration_ns: u64,
    pub result_assembly_duration_ns: u64,
}

impl PrimeOrderSuccinctHssEvaluateTiming {
    fn add_assign(&mut self, other: Self) {
        self.ot_open_join_duration_ns = self
            .ot_open_join_duration_ns
            .saturating_add(other.ot_open_join_duration_ns);
        self.ot_branch_key_derivation_duration_ns = self
            .ot_branch_key_derivation_duration_ns
            .saturating_add(other.ot_branch_key_derivation_duration_ns);
        self.ot_branch_decrypt_duration_ns = self
            .ot_branch_decrypt_duration_ns
            .saturating_add(other.ot_branch_decrypt_duration_ns);
        self.ot_point_scalar_reconstruction_duration_ns = self
            .ot_point_scalar_reconstruction_duration_ns
            .saturating_add(other.ot_point_scalar_reconstruction_duration_ns);
        self.ot_commitment_verification_duration_ns = self
            .ot_commitment_verification_duration_ns
            .saturating_add(other.ot_commitment_verification_duration_ns);
        self.server_input_open_duration_ns = self
            .server_input_open_duration_ns
            .saturating_add(other.server_input_open_duration_ns);
        self.server_input_share_duration_ns = self
            .server_input_share_duration_ns
            .saturating_add(other.server_input_share_duration_ns);
        self.server_input_commitment_duration_ns = self
            .server_input_commitment_duration_ns
            .saturating_add(other.server_input_commitment_duration_ns);
        self.server_input_transcript_duration_ns = self
            .server_input_transcript_duration_ns
            .saturating_add(other.server_input_transcript_duration_ns);
        self.server_input_seal_duration_ns = self
            .server_input_seal_duration_ns
            .saturating_add(other.server_input_seal_duration_ns);
        self.output_sealing_finalization_duration_ns = self
            .output_sealing_finalization_duration_ns
            .saturating_add(other.output_sealing_finalization_duration_ns);
        self.result_assembly_duration_ns = self
            .result_assembly_duration_ns
            .saturating_add(other.result_assembly_duration_ns);
    }

    fn add_ot_reconstruct_timing(&mut self, other: DdhHssOtReconstructTiming) {
        self.ot_branch_key_derivation_duration_ns = self
            .ot_branch_key_derivation_duration_ns
            .saturating_add(other.branch_key_derivation_duration_ns);
        self.ot_branch_decrypt_duration_ns = self
            .ot_branch_decrypt_duration_ns
            .saturating_add(other.branch_decrypt_duration_ns);
        self.ot_point_scalar_reconstruction_duration_ns = self
            .ot_point_scalar_reconstruction_duration_ns
            .saturating_add(other.point_scalar_reconstruction_duration_ns);
        self.ot_commitment_verification_duration_ns = self
            .ot_commitment_verification_duration_ns
            .saturating_add(other.commitment_verification_duration_ns);
    }
}

pub fn prepare_prime_order_succinct_hss(
    context: &CanonicalContext,
) -> ProtoResult<PrimeOrderSuccinctHssPreparedSession> {
    let candidate = build_fixed_hidden_core_candidate(context)?;
    if candidate.backend.family != CandidateBackendFamily::PrimeOrderSizeOptimized {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS requires prime_order_size_optimized backend, got {}",
            candidate.backend.family.as_str()
        )));
    }

    let artifact = build_prime_order_size_optimized_artifact(&candidate)?;
    let artifact_bytes = materialize_prime_order_size_optimized_bytes(&candidate)?;
    let decoded = decode_prime_order_size_optimized_artifact(&artifact_bytes)?;
    let hidden_eval_program = compile_prime_order_hidden_eval_program(&decoded)?;
    let ddh_backend = keygen_prime_order_ddh_hss_backend(
        candidate.context_binding,
        candidate.template.candidate_digest,
        &hidden_eval_program,
    )?;
    let hidden_eval_constants = prepare_ddh_hidden_eval_constant_pool(&ddh_backend)?;
    let execution_program = compile_prime_order_cpu_execution_program(&decoded)?;
    let execution_result = execute_prime_order_cpu_execution_program(&execution_program)?;
    let ddh_roles = role_views_for_backend(&ddh_backend);
    let (y_client_offer, y_client_remote, y_client_sender_state) = ddh_roles
        .garbler
        .prepare_client_input_ot_bundle_offer("y_client_bits", 256)?;
    let (tau_client_offer, tau_client_remote, tau_client_sender_state) = ddh_roles
        .garbler
        .prepare_client_input_ot_bundle_offer("tau_client_bits", 256)?;
    let client_ot_offer = PrimeOrderSuccinctHssClientOtOffer {
        context_binding: candidate.context_binding,
        y_client_offer,
        tau_client_offer,
    };
    let garbler_ot_state = PrimeOrderSuccinctHssGarblerOtState {
        context_binding: candidate.context_binding,
        y_client_remote,
        tau_client_remote,
        y_client_sender_state,
        tau_client_sender_state,
    };
    let shared_runtime_cached = PrimeOrderSuccinctHssSharedRuntime {
        candidate: candidate.clone(),
        artifact: build_artifact_summary(&candidate, &artifact),
        hidden_eval_program: hidden_eval_program.clone(),
        hidden_eval_constants: hidden_eval_constants.clone(),
        ddh_evaluator: ddh_roles.evaluator.clone(),
        execution_program: execution_program.clone(),
        execution_result: execution_result.clone(),
    };
    let garbler_session_cached = PrimeOrderSuccinctHssGarblerSession {
        context_binding: candidate.context_binding,
        ddh_garbler: ddh_roles.garbler.clone(),
        client_ot_offer: client_ot_offer.clone(),
        garbler_ot_state: garbler_ot_state.clone(),
    };
    garbler_session_cached.validate_garbler_ot_state()?;
    let evaluator_session_cached = PrimeOrderSuccinctHssEvaluatorSession {
        context_binding: candidate.context_binding,
        ddh_evaluator: ddh_roles.evaluator.clone(),
        client_ot_offer: client_ot_offer.clone(),
    };

    Ok(PrimeOrderSuccinctHssPreparedSession {
        candidate,
        artifact,
        artifact_bytes,
        hidden_eval_program,
        hidden_eval_constants,
        ddh_garbler: ddh_roles.garbler,
        ddh_evaluator: ddh_roles.evaluator,
        ddh_backend,
        execution_program,
        client_ot_offer,
        garbler_ot_state,
        shared_runtime_cached,
        garbler_session_cached,
        evaluator_session_cached,
    })
}

pub fn evaluate_prime_order_succinct_hss(
    input: &FExpandInput,
) -> ProtoResult<PrimeOrderSuccinctHssEvaluationReport> {
    prepare_prime_order_succinct_hss(&input.context)?.evaluate(input)
}

fn build_artifact_summary(
    candidate: &FixedHiddenCoreCandidate,
    artifact: &PrimeOrderEncodedArtifact,
) -> PrimeOrderSuccinctHssArtifactSummary {
    PrimeOrderSuccinctHssArtifactSummary {
        encoder_version: artifact.encoder_version.clone(),
        artifact_bytes: artifact.total_bytes,
        artifact_digest: artifact.artifact_digest,
        section_count: artifact.sections.len(),
        context_binding: candidate.context_binding,
        candidate_digest: candidate.template.candidate_digest,
        round_template_digest: candidate.template.round_template_digest,
    }
}

impl PrimeOrderSuccinctHssPreparedSession {
    pub fn candidate(&self) -> &FixedHiddenCoreCandidate {
        &self.candidate
    }

    pub fn artifact(&self) -> &PrimeOrderEncodedArtifact {
        &self.artifact
    }

    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    pub fn execution_program(&self) -> &PrimeOrderCpuExecutionProgram {
        &self.execution_program
    }

    pub fn hidden_eval_program(&self) -> &HiddenEvalProgram {
        &self.hidden_eval_program
    }

    pub fn ddh_backend(&self) -> &DdhHssBackend {
        &self.ddh_backend
    }

    pub fn hidden_eval_constants(&self) -> &DdhHiddenEvalConstantPool {
        &self.hidden_eval_constants
    }

    pub fn artifact_summary(&self) -> PrimeOrderSuccinctHssArtifactSummary {
        build_artifact_summary(&self.candidate, &self.artifact)
    }

    pub fn prepared_context(&self) -> CanonicalContext {
        CanonicalContext {
            org_id: self.candidate.context_descriptor.org_id.clone(),
            account_id: self.candidate.context_descriptor.account_id.clone(),
            key_purpose: self.candidate.context_descriptor.key_purpose.clone(),
            key_version: self.candidate.context_descriptor.key_version.clone(),
            participant_ids: self.candidate.context_descriptor.participant_ids.clone(),
            derivation_version: self.candidate.context_descriptor.derivation_version,
        }
    }

    pub fn delivery_material(&self) -> PrimeOrderSuccinctHssDeliveryMaterial {
        PrimeOrderSuccinctHssDeliveryMaterial {
            report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
            fixed_function_id: self.candidate.fixed_function_id.clone(),
            hidden_core_materialization: HiddenCoreMaterialization::DdhPrimitiveBaseline,
            artifact: self.artifact_summary(),
            evaluation_key: self.ddh_backend.evaluation_key().clone(),
        }
    }

    pub fn output_openers(&self) -> PrimeOrderSuccinctHssOutputOpeners {
        runtime_output_openers(&self.garbler_session_cached, &self.evaluator_session_cached)
    }

    pub fn shared_runtime(&self) -> PrimeOrderSuccinctHssSharedRuntime {
        self.shared_runtime_cached.clone()
    }

    pub fn garbler_session(&self) -> PrimeOrderSuccinctHssGarblerSession {
        self.garbler_session_cached.clone()
    }

    pub fn evaluator_session(&self) -> PrimeOrderSuccinctHssEvaluatorSession {
        self.evaluator_session_cached.clone()
    }

    pub fn shared_runtime_state(&self) -> PrimeOrderSuccinctHssSharedRuntimeState {
        PrimeOrderSuccinctHssSharedRuntimeState {
            candidate: self.candidate.clone(),
            ddh_evaluator: self.ddh_evaluator.clone(),
        }
    }

    pub fn garbler_driver_state(&self) -> PrimeOrderSuccinctHssGarblerDriverState {
        PrimeOrderSuccinctHssGarblerDriverState {
            runtime: self.shared_runtime_state(),
            garbler_session: PrimeOrderSuccinctHssGarblerSessionState {
                context_binding: self.candidate.context_binding,
                ddh_garbler: self.ddh_garbler.clone(),
                client_ot_offer: self.client_ot_offer.clone(),
                garbler_ot_state: self.garbler_ot_state.clone(),
            },
        }
    }

    pub fn evaluator_driver_state(&self) -> PrimeOrderSuccinctHssEvaluatorDriverState {
        PrimeOrderSuccinctHssEvaluatorDriverState {
            runtime: self.shared_runtime_state(),
            evaluator_session: PrimeOrderSuccinctHssEvaluatorSessionState {
                context_binding: self.candidate.context_binding,
                ddh_evaluator: self.ddh_evaluator.clone(),
                client_ot_offer: self.client_ot_offer.clone(),
            },
        }
    }

    pub fn split_runtime(
        &self,
    ) -> (
        PrimeOrderSuccinctHssSharedRuntime,
        PrimeOrderSuccinctHssGarblerSession,
        PrimeOrderSuccinctHssEvaluatorSession,
    ) {
        (
            self.shared_runtime(),
            self.garbler_session(),
            self.evaluator_session(),
        )
    }

    pub fn materialize_hidden_outputs_for_debug(
        &self,
        output: &DdhHiddenEvalOutputBundles,
    ) -> ProtoResult<([u8; 32], [u8; 32], [u8; 32])> {
        let x_client_base = self
            .ddh_evaluator
            .decode_client_bit_bundle_array(&output.x_client_base)?;
        let x_relayer_bundle = self
            .ddh_garbler
            .join_share_bundle(&output.x_relayer_base_left, &output.x_relayer_base_right)?;
        let x_relayer_base = self
            .ddh_garbler
            .decode_server_bit_bundle_array(&x_relayer_bundle)?;
        let public_key = public_key_from_base_shares(x_client_base, x_relayer_base)?;
        Ok((x_client_base, x_relayer_base, public_key))
    }

    pub fn profile_hidden_eval_for_clear_input(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<DdhHiddenEvalProfile> {
        execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool(
            &self.hidden_eval_program,
            &self.ddh_backend,
            &self.hidden_eval_constants,
            input,
        )
    }

    pub fn probe_hidden_eval_for_clear_input(
        &self,
        input: &FExpandInput,
        stop_after: DdhHiddenEvalCheckpoint,
    ) -> ProtoResult<DdhHiddenEvalProbe> {
        probe_prime_order_ddh_hidden_eval_program_with_pool(
            &self.hidden_eval_program,
            &self.ddh_backend,
            &self.hidden_eval_constants,
            input,
            stop_after,
        )
    }

    pub fn prepare_client_ot_offer_message(&self) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        self.garbler_session().client_ot_offer_message()
    }

    pub fn prepare_garbler_ot_state(&self) -> ProtoResult<PrimeOrderSuccinctHssGarblerOtState> {
        Ok(self.garbler_ot_state.clone())
    }

    pub fn prepare_client_ot_request_from_offer_message(
        &self,
        offer_message: &PrimeOrderSuccinctHssWireMessage,
        y_client: [u8; 32],
        tau_client: [u8; 32],
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssWireMessage,
        PrimeOrderSuccinctHssEvaluatorOtState,
    )> {
        self.evaluator_session()
            .prepare_client_ot_request_from_offer_message(offer_message, y_client, tau_client)
    }

    pub fn prepare_server_message(
        &self,
        garbler_ot_state: &PrimeOrderSuccinctHssGarblerOtState,
        client_request_message: &PrimeOrderSuccinctHssWireMessage,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        self.validate_garbler_ot_state(garbler_ot_state, &self.client_ot_offer)?;
        self.garbler_session().prepare_server_message(
            client_request_message,
            y_relayer,
            tau_relayer,
        )
    }

    pub fn evaluate_from_transport_messages(
        &self,
        client_request_message: &PrimeOrderSuccinctHssWireMessage,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssEvaluationReport> {
        let (runtime, garbler_session, evaluator_session) = self.split_runtime();
        let evaluation_result_message = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                client_request_message,
                evaluator_ot_state,
                server_message,
            )?;
        garbler_session
            .finalize_report_from_evaluation_result_message(&runtime, &evaluation_result_message)
    }

    #[cfg(test)]
    pub(crate) fn decode_client_input_delivery(
        &self,
        client_request_message: &PrimeOrderSuccinctHssWireMessage,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<([u8; 32], [u8; 32])> {
        let (_runtime, _garbler_session, evaluator_session) = self.split_runtime();
        let client_packet: PrimeOrderSuccinctHssClientPacket = decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let server_packet: PrimeOrderSuccinctHssServerPacket = decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerPacket,
            server_message,
        )?;
        let (y_client_bundle, tau_client_bundle) = evaluator_session
            .reconstruct_client_input_bundles(&client_packet, evaluator_ot_state, &server_packet)?;
        Ok((
            self.decode_input_bit_bundle_array(
                &y_client_bundle,
                HiddenEvalInputOwner::Client,
                "y_client_bits",
            )?,
            self.decode_input_bit_bundle_array(
                &tau_client_bundle,
                HiddenEvalInputOwner::Client,
                "tau_client_bits",
            )?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn decode_server_input_delivery(
        &self,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<([u8; 32], [u8; 32])> {
        let server_packet = self.decode_server_message(server_message)?;
        let (_runtime, _garbler_session, evaluator_session) = self.split_runtime();
        let opened_server_inputs =
            evaluator_session.open_server_inputs_packet(&server_packet.server_inputs)?;
        Ok((
            self.decode_server_input_bit_bundle_array(
                &opened_server_inputs.y_relayer_left,
                &opened_server_inputs.y_relayer_right,
                HiddenEvalInputOwner::Server,
                "y_relayer_bits",
            )?,
            self.decode_server_input_bit_bundle_array(
                &opened_server_inputs.tau_relayer_left,
                &opened_server_inputs.tau_relayer_right,
                HiddenEvalInputOwner::Server,
                "tau_relayer_bits",
            )?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn decode_server_input_payload_json(
        &self,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<String> {
        let server_packet = self.decode_server_message(server_message)?;
        let aad = server_input_packet_aad(
            server_packet.server_inputs.context_binding,
            server_packet.server_inputs.server_input_commitment,
        );
        let plaintext = self.ddh_garbler.open_message(
            DdhHssTransportPurpose::ServerInput,
            &aad,
            server_packet.server_inputs.nonce,
            &server_packet.server_inputs.ciphertext,
        )?;
        let payload: PrimeOrderSuccinctHssEncodedServerInputsPayload =
            deserialize_transport_payload_with_label("server_input", &plaintext)?;
        serde_json::to_string(&payload).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to serialize decoded server input payload json: {err}"
            ))
        })
    }

    pub fn deliver_output_from_transport_messages(
        &self,
        client_request_message: &PrimeOrderSuccinctHssWireMessage,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssOutputDelivery> {
        Ok(self
            .evaluate_from_transport_messages(
                client_request_message,
                evaluator_ot_state,
                server_message,
            )?
            .output_delivery)
    }

    pub fn evaluate(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<PrimeOrderSuccinctHssEvaluationReport> {
        self.ensure_input_context(input)?;
        let runtime = &self.shared_runtime_cached;
        let garbler_session = &self.garbler_session_cached;
        let evaluator_session = &self.evaluator_session_cached;
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        let (trusted_server_eval, _timing) = garbler_session.prepare_trusted_server_eval_timed(
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        let (ddh_run, _timing) = evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &runtime.ddh_evaluator,
                &runtime.hidden_eval_program,
                &runtime.hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?;
        Ok(evaluator_session
            .build_final_report_from_hidden_run(runtime, garbler_session, ddh_run)?
            .0)
    }

    pub fn evaluate_hidden_run(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<crate::ddh_hidden_eval_executor::DdhHiddenEvalRun> {
        self.ensure_input_context(input)?;
        let runtime = &self.shared_runtime_cached;
        let garbler_session = &self.garbler_session_cached;
        let evaluator_session = &self.evaluator_session_cached;
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        let (trusted_server_eval, _timing) = garbler_session.prepare_trusted_server_eval_timed(
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        Ok(evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &runtime.ddh_evaluator,
                &runtime.hidden_eval_program,
                &runtime.hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?
            .0)
    }

    pub fn evaluate_with_timing(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssEvaluationReport,
        PrimeOrderSuccinctHssEvaluateTiming,
    )> {
        self.ensure_input_context(input)?;
        let runtime = &self.shared_runtime_cached;
        let garbler_session = &self.garbler_session_cached;
        let evaluator_session = &self.evaluator_session_cached;
        let mut timing = PrimeOrderSuccinctHssEvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let (trusted_server_eval, garbler_prepare_timing) = garbler_session
            .prepare_trusted_server_eval_timed(
                &client_packet,
                input.y_relayer,
                input.tau_relayer,
            )?;
        timing.add_assign(garbler_prepare_timing);
        let (ddh_run, evaluation_timing) = evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &runtime.ddh_evaluator,
                &runtime.hidden_eval_program,
                &runtime.hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?;
        timing.add_assign(evaluation_timing);
        let (report, result_assembly_duration_ns, output_sealing_finalization_duration_ns) =
            evaluator_session.build_final_report_from_hidden_run(
                runtime,
                garbler_session,
                ddh_run,
            )?;
        timing.result_assembly_duration_ns = timing
            .result_assembly_duration_ns
            .saturating_add(result_assembly_duration_ns);
        timing.output_sealing_finalization_duration_ns = timing
            .output_sealing_finalization_duration_ns
            .saturating_add(output_sealing_finalization_duration_ns);
        Ok((report, timing))
    }

    pub fn evaluate_hidden_run_with_timing(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<(
        crate::ddh_hidden_eval_executor::DdhHiddenEvalRun,
        PrimeOrderSuccinctHssEvaluateTiming,
    )> {
        self.ensure_input_context(input)?;
        let runtime = &self.shared_runtime_cached;
        let garbler_session = &self.garbler_session_cached;
        let evaluator_session = &self.evaluator_session_cached;
        let mut timing = PrimeOrderSuccinctHssEvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let (trusted_server_eval, garbler_prepare_timing) = garbler_session
            .prepare_trusted_server_eval_timed(
                &client_packet,
                input.y_relayer,
                input.tau_relayer,
            )?;
        timing.add_assign(garbler_prepare_timing);
        let (ddh_run, evaluation_timing) = evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &runtime.ddh_evaluator,
                &runtime.hidden_eval_program,
                &runtime.hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?;
        timing.add_assign(evaluation_timing);
        Ok((ddh_run, timing))
    }

    fn ensure_input_context(&self, input: &FExpandInput) -> ProtoResult<()> {
        let input_context_binding = input.context.binding_digest()?;
        if input_context_binding != self.candidate.context_binding {
            return Err(ProtoError::InvalidInput(
                "input context does not match prepared prime-order succinct HSS session"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_garbler_ot_state(
        &self,
        garbler_ot_state: &PrimeOrderSuccinctHssGarblerOtState,
        client_ot_offer: &PrimeOrderSuccinctHssClientOtOffer,
    ) -> ProtoResult<()> {
        if garbler_ot_state.context_binding != self.candidate.context_binding {
            return Err(ProtoError::InvalidInput(
                "garbler OT state context binding does not match prepared session".to_string(),
            ));
        }
        self.ddh_garbler.validate_client_input_ot_bundle_offer(
            &client_ot_offer.y_client_offer,
            &garbler_ot_state.y_client_sender_state,
            &garbler_ot_state.y_client_remote,
        )?;
        self.ddh_garbler.validate_client_input_ot_bundle_offer(
            &client_ot_offer.tau_client_offer,
            &garbler_ot_state.tau_client_sender_state,
            &garbler_ot_state.tau_client_remote,
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn decode_input_bit_bundle_array(
        &self,
        bundle: &DdhHssInputShareBundle,
        expected_owner: HiddenEvalInputOwner,
        expected_label: &str,
    ) -> ProtoResult<[u8; 32]> {
        decode_input_bit_bundle_array_with_backend(
            &self.ddh_backend,
            bundle,
            expected_owner,
            expected_label,
        )
    }

    #[cfg(test)]
    fn decode_server_input_bit_bundle_array(
        &self,
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
        expected_owner: HiddenEvalInputOwner,
        expected_label: &str,
    ) -> ProtoResult<[u8; 32]> {
        decode_server_input_bit_bundle_array_with_backend(
            &self.ddh_backend,
            left,
            right,
            expected_owner,
            expected_label,
        )
    }

    #[cfg(test)]
    pub(crate) fn decode_client_ot_offer_message(
        &self,
        message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssClientOtOffer> {
        decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtOffer,
            message,
        )
    }

    #[cfg(test)]
    pub(crate) fn decode_client_request_message(
        &self,
        message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssClientPacket> {
        decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtRequest,
            message,
        )
    }

    #[cfg(test)]
    pub(crate) fn decode_server_message(
        &self,
        message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssServerPacket> {
        decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerPacket,
            message,
        )
    }

    #[cfg(test)]
    pub(crate) fn encode_server_message(
        &self,
        packet: &PrimeOrderSuccinctHssServerPacket,
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        encode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerPacket,
            packet,
        )
    }

    #[cfg(test)]
    pub(crate) fn decode_client_output_message(
        &self,
        message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssClientOutputPacket> {
        decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOutput,
            message,
        )
    }

    #[cfg(test)]
    pub(crate) fn decode_evaluation_result_message(
        &self,
        message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssEvaluationResult> {
        decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::EvaluationResult,
            message,
        )
    }

    #[cfg(test)]
    pub(crate) fn encode_evaluation_result_message(
        &self,
        evaluation_result: &PrimeOrderSuccinctHssEvaluationResult,
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        encode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::EvaluationResult,
            evaluation_result,
        )
    }
}

impl PrimeOrderSuccinctHssSharedRuntimeState {
    pub fn materialize(&self) -> ProtoResult<PrimeOrderSuccinctHssSharedRuntime> {
        let artifact = build_prime_order_size_optimized_artifact(&self.candidate)?;
        let artifact_bytes = materialize_prime_order_size_optimized_bytes(&self.candidate)?;
        let decoded = decode_prime_order_size_optimized_artifact(&artifact_bytes)?;
        let hidden_eval_program = compile_prime_order_hidden_eval_program(&decoded)?;
        let execution_program = compile_prime_order_cpu_execution_program(&decoded)?;
        let execution_result = execute_prime_order_cpu_execution_program(&execution_program)?;
        Ok(PrimeOrderSuccinctHssSharedRuntime {
            candidate: self.candidate.clone(),
            artifact: build_artifact_summary(&self.candidate, &artifact),
            hidden_eval_program,
            hidden_eval_constants: prepare_ddh_hidden_eval_constant_pool(&self.ddh_evaluator)?,
            ddh_evaluator: self.ddh_evaluator.clone(),
            execution_program,
            execution_result,
        })
    }
}

impl PrimeOrderSuccinctHssGarblerSessionState {
    pub fn materialize(&self) -> PrimeOrderSuccinctHssGarblerSession {
        PrimeOrderSuccinctHssGarblerSession {
            context_binding: self.context_binding,
            ddh_garbler: self.ddh_garbler.clone(),
            client_ot_offer: self.client_ot_offer.clone(),
            garbler_ot_state: self.garbler_ot_state.clone(),
        }
    }
}

impl PrimeOrderSuccinctHssEvaluatorSessionState {
    pub fn materialize(&self) -> PrimeOrderSuccinctHssEvaluatorSession {
        PrimeOrderSuccinctHssEvaluatorSession {
            context_binding: self.context_binding,
            ddh_evaluator: self.ddh_evaluator.clone(),
            client_ot_offer: self.client_ot_offer.clone(),
        }
    }
}

impl PrimeOrderSuccinctHssGarblerDriverState {
    pub fn materialize(
        &self,
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssSharedRuntime,
        PrimeOrderSuccinctHssGarblerSession,
    )> {
        Ok((
            self.runtime.materialize()?,
            self.garbler_session.materialize(),
        ))
    }
}

impl PrimeOrderSuccinctHssEvaluatorDriverState {
    pub fn materialize(
        &self,
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssSharedRuntime,
        PrimeOrderSuccinctHssEvaluatorSession,
    )> {
        Ok((
            self.runtime.materialize()?,
            self.evaluator_session.materialize(),
        ))
    }
}

impl PrimeOrderSuccinctHssGarblerSession {
    pub fn client_ot_offer_message(&self) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        encode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtOffer,
            &self.client_ot_offer,
        )
    }

    pub fn server_output_opener(&self) -> PrimeOrderSuccinctHssServerOutputOpener {
        PrimeOrderSuccinctHssServerOutputOpener {
            garbler: self.ddh_garbler.clone(),
            context_binding: self.context_binding,
        }
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        self.ddh_garbler.run_binding(
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        )
    }

    pub fn prepare_server_message(
        &self,
        client_request_message: &PrimeOrderSuccinctHssWireMessage,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        let client_packet: PrimeOrderSuccinctHssClientPacket = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let server_packet = self.prepare_server_packet(&client_packet, y_relayer, tau_relayer)?;
        encode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerPacket,
            &server_packet,
        )
    }

    pub fn prepare_server_packet(
        &self,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<PrimeOrderSuccinctHssServerPacket> {
        Ok(self
            .prepare_server_packet_with_trusted_inputs(client_packet, y_relayer, tau_relayer)?
            .0)
    }

    fn prepare_server_packet_with_trusted_inputs(
        &self,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<(PrimeOrderSuccinctHssServerPacket, DdhHiddenEvalServerInputs)> {
        let (server_packet, trusted_server_inputs, _timing) = self
            .prepare_server_packet_with_trusted_inputs_timed(
                client_packet,
                y_relayer,
                tau_relayer,
            )?;
        Ok((server_packet, trusted_server_inputs))
    }

    fn prepare_trusted_server_eval_timed(
        &self,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssTrustedServerEval,
        PrimeOrderSuccinctHssEvaluateTiming,
    )> {
        validate_client_packet_context(self.context_binding, &client_packet)?;
        let mut timing = PrimeOrderSuccinctHssEvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_response, y_client_remote_release) =
            self.ddh_garbler.resolve_client_input_ot_selection_trusted(
                self.context_binding,
                &self.client_ot_offer.y_client_offer,
                &self.garbler_ot_state.y_client_sender_state,
                &self.garbler_ot_state.y_client_remote,
                &client_packet.y_client_request,
            )?;
        let (tau_client_response, tau_client_remote_release) =
            self.ddh_garbler.resolve_client_input_ot_selection_trusted(
                self.context_binding,
                &self.client_ot_offer.tau_client_offer,
                &self.garbler_ot_state.tau_client_sender_state,
                &self.garbler_ot_state.tau_client_remote,
                &client_packet.tau_client_request,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let server_input_phase_started = monotonic_now_ns();
        let server_input_share_started = monotonic_now_ns();
        let y_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_relayer_bits", &y_relayer)?;
        let tau_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_relayer_bits", &tau_relayer)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);
        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            HiddenEvalInputOwner::Server,
            &[&y_relayer_bundle, &tau_relayer_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);
        let trusted_server_inputs =
            DdhHiddenEvalServerInputs::from_joint_bundles(&y_relayer_bundle, &tau_relayer_bundle);
        let ot_transcript_started = monotonic_now_ns();
        let _ = build_ot_transcript(
            self.context_binding,
            &self.client_ot_offer,
            client_packet,
            &y_client_response,
            &tau_client_response,
            &y_client_remote_release,
            &tau_client_remote_release,
        );
        timing.server_input_transcript_duration_ns = elapsed_ns_u64(ot_transcript_started);
        timing.server_input_open_duration_ns = elapsed_ns_u64(server_input_phase_started);
        Ok((
            PrimeOrderSuccinctHssTrustedServerEval {
                y_client_response,
                tau_client_response,
                y_client_remote_release,
                tau_client_remote_release,
                server_input_commitment,
                trusted_server_inputs,
            },
            timing,
        ))
    }

    fn prepare_server_packet_with_trusted_inputs_timed(
        &self,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssServerPacket,
        DdhHiddenEvalServerInputs,
        PrimeOrderSuccinctHssEvaluateTiming,
    )> {
        validate_client_packet_context(self.context_binding, &client_packet)?;
        let mut timing = PrimeOrderSuccinctHssEvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_response, y_client_remote_release) =
            self.ddh_garbler.resolve_client_input_ot_selection_trusted(
                self.context_binding,
                &self.client_ot_offer.y_client_offer,
                &self.garbler_ot_state.y_client_sender_state,
                &self.garbler_ot_state.y_client_remote,
                &client_packet.y_client_request,
            )?;
        let (tau_client_response, tau_client_remote_release) =
            self.ddh_garbler.resolve_client_input_ot_selection_trusted(
                self.context_binding,
                &self.client_ot_offer.tau_client_offer,
                &self.garbler_ot_state.tau_client_sender_state,
                &self.garbler_ot_state.tau_client_remote,
                &client_packet.tau_client_request,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let server_input_open_started = monotonic_now_ns();
        let server_input_share_started = monotonic_now_ns();
        let y_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_relayer_bits", &y_relayer)?;
        let tau_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_relayer_bits", &tau_relayer)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);
        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            HiddenEvalInputOwner::Server,
            &[&y_relayer_bundle, &tau_relayer_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);
        let trusted_server_inputs =
            DdhHiddenEvalServerInputs::from_joint_bundles(&y_relayer_bundle, &tau_relayer_bundle);
        let ot_transcript_started = monotonic_now_ns();
        let ot_transcript = build_ot_transcript(
            self.context_binding,
            &self.client_ot_offer,
            &client_packet,
            &y_client_response,
            &tau_client_response,
            &y_client_remote_release,
            &tau_client_remote_release,
        );
        timing.server_input_transcript_duration_ns = elapsed_ns_u64(ot_transcript_started);
        let y_relayer_split = self.ddh_garbler.split_share_bundle(&y_relayer_bundle);
        let tau_relayer_split = self.ddh_garbler.split_share_bundle(&tau_relayer_bundle);
        let server_input_seal_started = monotonic_now_ns();
        let sealed_server_inputs = self.seal_server_inputs_packet(
            server_input_commitment,
            &y_relayer_split,
            &tau_relayer_split,
        )?;
        timing.server_input_seal_duration_ns = elapsed_ns_u64(server_input_seal_started);
        timing.server_input_open_duration_ns = elapsed_ns_u64(server_input_open_started);
        Ok((
            PrimeOrderSuccinctHssServerPacket {
                context_binding: self.context_binding,
                ot_transcript,
                y_client_response,
                tau_client_response,
                y_client_remote_release,
                tau_client_remote_release,
                server_inputs: sealed_server_inputs,
            },
            trusted_server_inputs,
            timing,
        ))
    }

    fn validate_garbler_ot_state(&self) -> ProtoResult<()> {
        if self.garbler_ot_state.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "garbler OT state context binding does not match garbler session".to_string(),
            ));
        }
        self.ddh_garbler.validate_client_input_ot_bundle_offer(
            &self.client_ot_offer.y_client_offer,
            &self.garbler_ot_state.y_client_sender_state,
            &self.garbler_ot_state.y_client_remote,
        )?;
        self.ddh_garbler.validate_client_input_ot_bundle_offer(
            &self.client_ot_offer.tau_client_offer,
            &self.garbler_ot_state.tau_client_sender_state,
            &self.garbler_ot_state.tau_client_remote,
        )?;
        Ok(())
    }

    pub fn validate_server_message(
        &self,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<()> {
        let packet: PrimeOrderSuccinctHssServerPacket = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerPacket,
            server_message,
        )?;
        self.validate_server_packet(&packet)
    }

    fn validate_server_packet(
        &self,
        packet: &PrimeOrderSuccinctHssServerPacket,
    ) -> ProtoResult<()> {
        if packet.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "server delivery packet context binding does not match garbler session".to_string(),
            ));
        }
        validate_ot_transcript(packet.context_binding, &packet.ot_transcript)?;
        if packet.ot_transcript.y_client_offer_commitment
            != self.client_ot_offer.y_client_offer.commitment
            || packet.ot_transcript.tau_client_offer_commitment
                != self.client_ot_offer.tau_client_offer.commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT transcript is not bound to the garbler session offer"
                    .to_string(),
            ));
        }
        if packet.y_client_response.owner != crate::HiddenEvalInputOwner::Client
            || packet.tau_client_response.owner != crate::HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT responses must be client-owned".to_string(),
            ));
        }
        if packet.y_client_response.label != "y_client_bits"
            || packet.tau_client_response.label != "tau_client_bits"
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT response labels are invalid".to_string(),
            ));
        }
        if packet.y_client_remote_release.owner != crate::HiddenEvalInputOwner::Client
            || packet.tau_client_remote_release.owner != crate::HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet client OT remote-share releases must be owned by the client"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.label != "y_client_bits"
            || packet.tau_client_remote_release.label != "tau_client_bits"
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet client OT remote-share release labels are invalid"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.context_binding != packet.context_binding
            || packet.tau_client_remote_release.context_binding != packet.context_binding
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share release context binding is invalid"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.share_side != crate::ddh_hss::DdhHssShareSide::Right
            || packet.tau_client_remote_release.share_side != crate::ddh_hss::DdhHssShareSide::Right
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet client OT remote-share releases must carry right-side shares"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.request_commitment
            != packet.ot_transcript.y_client_request_commitment
            || packet.tau_client_remote_release.request_commitment
                != packet.ot_transcript.tau_client_request_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the request transcript"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.response_commitment != packet.y_client_response.commitment
            || packet.tau_client_remote_release.response_commitment
                != packet.tau_client_response.commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the response transcript"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.response_commitment
            != packet.ot_transcript.y_client_response_commitment
            || packet.tau_client_remote_release.response_commitment
                != packet.ot_transcript.tau_client_response_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share release response binding is invalid"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.offer_commitment
            != packet.ot_transcript.y_client_offer_commitment
            || packet.tau_client_remote_release.offer_commitment
                != packet.ot_transcript.tau_client_offer_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the garbler session offer"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.transcript_binding
            != packet.ot_transcript.y_client_remote_release_binding
            || packet.tau_client_remote_release.transcript_binding
                != packet.ot_transcript.tau_client_remote_release_binding
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the server OT transcript"
                    .to_string(),
            ));
        }
        let opened_server_inputs = self.open_server_inputs_packet(&packet.server_inputs)?;
        let expected =
            opened_server_inputs.server_input_commitment_with_garbler(&self.ddh_garbler)?;
        if expected != packet.server_inputs.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "server delivery packet commitment is invalid".to_string(),
            ));
        }
        Ok(())
    }

    pub fn seal_server_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        let plaintext = serialize_transport_pair_payload("server_output_bundle", left, right)?;
        let aad = output_packet_aad(
            b"server_output",
            self.context_binding,
            run_binding,
            evaluation_digest,
        );
        let (nonce, ciphertext) = self.ddh_garbler.seal_message(
            DdhHssTransportPurpose::ServerOutput,
            &aad,
            &plaintext,
        )?;
        let packet = PrimeOrderSuccinctHssServerOutputPacket {
            context_binding: self.context_binding,
            run_binding,
            evaluation_digest,
            nonce,
            ciphertext,
        };
        encode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerOutput,
            &packet,
        )
    }

    fn seal_server_inputs_packet(
        &self,
        server_input_commitment: [u8; 32],
        y_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
        tau_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
    ) -> ProtoResult<PrimeOrderSuccinctHssServerInputsPacket> {
        let aad = server_input_packet_aad(self.context_binding, server_input_commitment);
        let plaintext = serialize_server_inputs_payload(y_relayer, tau_relayer)?;
        let (nonce, ciphertext) =
            self.ddh_garbler
                .seal_message(DdhHssTransportPurpose::ServerInput, &aad, &plaintext)?;
        Ok(PrimeOrderSuccinctHssServerInputsPacket {
            context_binding: self.context_binding,
            server_input_commitment,
            nonce,
            ciphertext,
        })
    }

    fn open_server_inputs_packet(
        &self,
        packet: &PrimeOrderSuccinctHssServerInputsPacket,
    ) -> ProtoResult<PrimeOrderSuccinctHssOpenedServerInputs> {
        open_server_inputs_packet_with_garbler(&self.ddh_garbler, self.context_binding, packet)
    }

    pub fn finalize_report_from_evaluation_result_message(
        &self,
        runtime: &PrimeOrderSuccinctHssSharedRuntime,
        evaluation_result_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssEvaluationReport> {
        let evaluation_result: PrimeOrderSuccinctHssEvaluationResult = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::EvaluationResult,
            evaluation_result_message,
        )?;
        runtime.finalize_report_from_evaluation_result(self, &evaluation_result)
    }
}

impl PrimeOrderSuccinctHssEvaluatorSession {
    pub fn client_output_opener(&self) -> PrimeOrderSuccinctHssClientOutputOpener {
        PrimeOrderSuccinctHssClientOutputOpener {
            evaluator: self.ddh_evaluator.clone(),
            context_binding: self.context_binding,
        }
    }

    pub fn prepare_client_ot_request_from_offer_message(
        &self,
        offer_message: &PrimeOrderSuccinctHssWireMessage,
        y_client: [u8; 32],
        tau_client: [u8; 32],
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssWireMessage,
        PrimeOrderSuccinctHssEvaluatorOtState,
    )> {
        let offer: PrimeOrderSuccinctHssClientOtOffer = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtOffer,
            offer_message,
        )?;
        let (client_packet, evaluator_state) =
            self.prepare_client_ot_request(&offer, y_client, tau_client)?;
        Ok((
            encode_transport_message(
                self.context_binding,
                PrimeOrderSuccinctHssTransportKind::ClientOtRequest,
                &client_packet,
            )?,
            evaluator_state,
        ))
    }

    pub fn prepare_client_ot_request(
        &self,
        offer: &PrimeOrderSuccinctHssClientOtOffer,
        y_client: [u8; 32],
        tau_client: [u8; 32],
    ) -> ProtoResult<(
        PrimeOrderSuccinctHssClientPacket,
        PrimeOrderSuccinctHssEvaluatorOtState,
    )> {
        self.validate_client_ot_offer(&offer)?;
        let (y_client_request, y_client_local_state) = self
            .ddh_evaluator
            .prepare_client_input_ot_request(&offer.y_client_offer, &y_client)?;
        let (tau_client_request, tau_client_local_state) = self
            .ddh_evaluator
            .prepare_client_input_ot_request(&offer.tau_client_offer, &tau_client)?;
        let client_packet = PrimeOrderSuccinctHssClientPacket {
            context_binding: self.context_binding,
            y_client_request,
            tau_client_request,
        };
        Ok((
            client_packet,
            PrimeOrderSuccinctHssEvaluatorOtState {
                context_binding: self.context_binding,
                y_client_local_state,
                tau_client_local_state,
            },
        ))
    }

    fn validate_client_ot_offer(
        &self,
        offer: &PrimeOrderSuccinctHssClientOtOffer,
    ) -> ProtoResult<()> {
        if offer.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "client OT offer context binding does not match evaluator session".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_server_packet(
        &self,
        packet: &PrimeOrderSuccinctHssServerPacket,
    ) -> ProtoResult<()> {
        if packet.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "server delivery packet context binding does not match evaluator session"
                    .to_string(),
            ));
        }
        validate_ot_transcript(packet.context_binding, &packet.ot_transcript)?;
        if packet.ot_transcript.y_client_offer_commitment
            != self.client_ot_offer.y_client_offer.commitment
            || packet.ot_transcript.tau_client_offer_commitment
                != self.client_ot_offer.tau_client_offer.commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT transcript is not bound to the evaluator offer"
                    .to_string(),
            ));
        }
        if packet.y_client_response.owner != HiddenEvalInputOwner::Client
            || packet.tau_client_response.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT responses must be client-owned".to_string(),
            ));
        }
        if packet.y_client_response.label != "y_client_bits"
            || packet.tau_client_response.label != "tau_client_bits"
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT response labels are invalid".to_string(),
            ));
        }
        if packet.y_client_remote_release.owner != HiddenEvalInputOwner::Client
            || packet.tau_client_remote_release.owner != HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet client OT remote-share releases must be client-owned"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.label != "y_client_bits"
            || packet.tau_client_remote_release.label != "tau_client_bits"
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet client OT remote-share release labels are invalid"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.context_binding != packet.context_binding
            || packet.tau_client_remote_release.context_binding != packet.context_binding
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share release context binding is invalid"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.request_commitment
            != packet.ot_transcript.y_client_request_commitment
            || packet.tau_client_remote_release.request_commitment
                != packet.ot_transcript.tau_client_request_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the request transcript"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.response_commitment != packet.y_client_response.commitment
            || packet.tau_client_remote_release.response_commitment
                != packet.tau_client_response.commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the response transcript"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.response_commitment
            != packet.ot_transcript.y_client_response_commitment
            || packet.tau_client_remote_release.response_commitment
                != packet.ot_transcript.tau_client_response_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share release response binding is invalid"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.offer_commitment
            != packet.ot_transcript.y_client_offer_commitment
            || packet.tau_client_remote_release.offer_commitment
                != packet.ot_transcript.tau_client_offer_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the evaluator offer"
                    .to_string(),
            ));
        }
        if packet.y_client_remote_release.transcript_binding
            != packet.ot_transcript.y_client_remote_release_binding
            || packet.tau_client_remote_release.transcript_binding
                != packet.ot_transcript.tau_client_remote_release_binding
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT remote-share releases are not bound to the transcript"
                    .to_string(),
            ));
        }
        let opened_server_inputs = self.open_server_inputs_packet(&packet.server_inputs)?;
        let expected =
            opened_server_inputs.server_input_commitment_with_evaluator(&self.ddh_evaluator)?;
        if expected != packet.server_inputs.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "server delivery packet commitment is invalid".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_evaluator_ot_state(
        &self,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
    ) -> ProtoResult<()> {
        if evaluator_ot_state.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "evaluator OT state context binding does not match evaluator session".to_string(),
            ));
        }
        if evaluator_ot_state.y_client_local_state.owner != crate::HiddenEvalInputOwner::Client
            || evaluator_ot_state.tau_client_local_state.owner
                != crate::HiddenEvalInputOwner::Client
        {
            return Err(ProtoError::InvalidInput(
                "evaluator OT state must be client-owned".to_string(),
            ));
        }
        if evaluator_ot_state.y_client_local_state.label != "y_client_bits"
            || evaluator_ot_state.tau_client_local_state.label != "tau_client_bits"
        {
            return Err(ProtoError::InvalidInput(
                "evaluator OT state labels are invalid".to_string(),
            ));
        }
        if evaluator_ot_state.y_client_local_state.words.len() != 256
            || evaluator_ot_state.tau_client_local_state.words.len() != 256
        {
            return Err(ProtoError::InvalidInput(
                "evaluator OT state must contain 256 bits".to_string(),
            ));
        }
        Ok(())
    }

    pub fn reconstruct_client_input_bundles(
        &self,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_packet: &PrimeOrderSuccinctHssServerPacket,
    ) -> ProtoResult<(DdhHssInputShareBundle, DdhHssInputShareBundle)> {
        validate_client_packet_context(self.context_binding, &client_packet)?;
        self.validate_evaluator_ot_state(evaluator_ot_state)?;
        self.validate_server_packet(&server_packet)?;
        if client_packet.y_client_request.commitment
            != server_packet.ot_transcript.y_client_request_commitment
            || client_packet.tau_client_request.commitment
                != server_packet.ot_transcript.tau_client_request_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT request commitments do not match client packet"
                    .to_string(),
            ));
        }
        let y_client_bundle = self.ddh_evaluator.reconstruct_client_ot_bundle(
            self.context_binding,
            &server_packet.y_client_response,
            &evaluator_ot_state.y_client_local_state,
            &server_packet.y_client_remote_release,
        )?;
        let tau_client_bundle = self.ddh_evaluator.reconstruct_client_ot_bundle(
            self.context_binding,
            &server_packet.tau_client_response,
            &evaluator_ot_state.tau_client_local_state,
            &server_packet.tau_client_remote_release,
        )?;
        Ok((y_client_bundle, tau_client_bundle))
    }

    fn reconstruct_client_input_bundles_from_trusted_server_eval_timed(
        &self,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        trusted_server_eval: &PrimeOrderSuccinctHssTrustedServerEval,
    ) -> ProtoResult<(
        DdhHssInputShareBundle,
        DdhHssInputShareBundle,
        PrimeOrderSuccinctHssEvaluateTiming,
    )> {
        let (y_client_bundle, y_timing) = self.ddh_evaluator.reconstruct_client_ot_bundle_timed(
            self.context_binding,
            &trusted_server_eval.y_client_response,
            &evaluator_ot_state.y_client_local_state,
            &trusted_server_eval.y_client_remote_release,
        )?;
        let (tau_client_bundle, tau_timing) =
            self.ddh_evaluator.reconstruct_client_ot_bundle_timed(
                self.context_binding,
                &trusted_server_eval.tau_client_response,
                &evaluator_ot_state.tau_client_local_state,
                &trusted_server_eval.tau_client_remote_release,
            )?;
        let mut timing = PrimeOrderSuccinctHssEvaluateTiming::default();
        timing.add_ot_reconstruct_timing(y_timing);
        timing.add_ot_reconstruct_timing(tau_timing);
        Ok((y_client_bundle, tau_client_bundle, timing))
    }

    pub fn evaluate_hidden_run_from_packets(
        &self,
        ddh_evaluator: &DdhHssEvaluator,
        hidden_eval_program: &HiddenEvalProgram,
        hidden_eval_constants: &DdhHiddenEvalConstantPool,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_packet: &PrimeOrderSuccinctHssServerPacket,
    ) -> ProtoResult<crate::ddh_hidden_eval_executor::DdhHiddenEvalRun> {
        let (y_client_bundle, tau_client_bundle) = self.reconstruct_client_input_bundles(
            client_packet,
            evaluator_ot_state,
            server_packet,
        )?;
        let expected_client_input_commitment = self.ddh_evaluator.combined_input_commitment(
            HiddenEvalInputOwner::Client,
            &[&y_client_bundle, &tau_client_bundle],
        );
        let opened_server_inputs = self.open_server_inputs_packet(&server_packet.server_inputs)?;
        let run =
            execute_prime_order_ddh_hidden_eval_program_with_transport_server_inputs_with_pool(
                hidden_eval_program,
                ddh_evaluator,
                hidden_eval_constants,
                &y_client_bundle,
                &opened_server_inputs.y_relayer_left,
                &opened_server_inputs.y_relayer_right,
                &tau_client_bundle,
                &opened_server_inputs.tau_relayer_left,
                &opened_server_inputs.tau_relayer_right,
            )?;
        if run.client_input_commitment != expected_client_input_commitment {
            return Err(ProtoError::InvalidInput(
                "client delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        if run.server_input_commitment != server_packet.server_inputs.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "server delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        Ok(run)
    }

    fn evaluate_hidden_run_from_trusted_server_eval_timed(
        &self,
        ddh_evaluator: &DdhHssEvaluator,
        hidden_eval_program: &HiddenEvalProgram,
        hidden_eval_constants: &DdhHiddenEvalConstantPool,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        trusted_server_eval: &PrimeOrderSuccinctHssTrustedServerEval,
    ) -> ProtoResult<(
        crate::ddh_hidden_eval_executor::DdhHiddenEvalRun,
        PrimeOrderSuccinctHssEvaluateTiming,
    )> {
        let mut timing = PrimeOrderSuccinctHssEvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_bundle, tau_client_bundle, ot_timing) = self
            .reconstruct_client_input_bundles_from_trusted_server_eval_timed(
                evaluator_ot_state,
                trusted_server_eval,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        timing.add_assign(ot_timing);
        let expected_client_input_commitment = self.ddh_evaluator.combined_input_commitment(
            HiddenEvalInputOwner::Client,
            &[&y_client_bundle, &tau_client_bundle],
        );
        let run = execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool(
            hidden_eval_program,
            ddh_evaluator,
            hidden_eval_constants,
            &y_client_bundle,
            &trusted_server_eval.trusted_server_inputs.y_relayer_bits,
            &tau_client_bundle,
            &trusted_server_eval.trusted_server_inputs.tau_relayer_bits,
        )?;
        if run.client_input_commitment != expected_client_input_commitment {
            return Err(ProtoError::InvalidInput(
                "client delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        if run.server_input_commitment != trusted_server_eval.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "server delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        Ok((run, timing))
    }

    fn evaluate_result_from_packets_untrusted(
        &self,
        runtime: &PrimeOrderSuccinctHssSharedRuntime,
        client_packet: &PrimeOrderSuccinctHssClientPacket,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_packet: &PrimeOrderSuccinctHssServerPacket,
    ) -> ProtoResult<PrimeOrderSuccinctHssEvaluationResult> {
        let ddh_run = self.evaluate_hidden_run_from_packets(
            &runtime.ddh_evaluator,
            &runtime.hidden_eval_program,
            &runtime.hidden_eval_constants,
            client_packet,
            evaluator_ot_state,
            server_packet,
        )?;
        Ok(self
            .build_evaluation_result_from_hidden_run(runtime, ddh_run)?
            .0)
    }

    fn build_evaluation_result_from_hidden_run(
        &self,
        runtime: &PrimeOrderSuccinctHssSharedRuntime,
        ddh_run: crate::ddh_hidden_eval_executor::DdhHiddenEvalRun,
    ) -> ProtoResult<(PrimeOrderSuccinctHssEvaluationResult, u64, u64)> {
        let result_assembly_started = monotonic_now_ns();
        let run_binding = self.ddh_evaluator.run_binding(
            runtime.artifact.artifact_digest,
            ddh_run.client_input_commitment,
            ddh_run.server_input_commitment,
        );
        let evaluation_digest = compute_evaluation_digest(
            runtime.artifact.artifact_digest,
            run_binding,
            &runtime.execution_result,
            &ddh_run.output,
        );
        let result_assembly_duration_ns = elapsed_ns_u64(result_assembly_started);
        let output_sealing_started = monotonic_now_ns();
        let client_output = self.seal_client_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.x_client_base,
        )?;
        let client_output_binding = nested_output_message_binding(
            self.context_binding,
            run_binding,
            evaluation_digest,
            b"client_output_message",
            &client_output.bytes,
        );
        let server_output_payload = serialize_transport_pair_payload(
            "server_output_bundle",
            &ddh_run.output.x_relayer_base_left,
            &ddh_run.output.x_relayer_base_right,
        )?;
        let server_output_payload_binding = server_output_payload_binding(
            self.context_binding,
            run_binding,
            evaluation_digest,
            &server_output_payload,
        );
        let output_sealing_finalization_duration_ns = elapsed_ns_u64(output_sealing_started);
        Ok((
            PrimeOrderSuccinctHssEvaluationResult {
                context_binding: self.context_binding,
                bindings: PrimeOrderSuccinctHssRunBindings {
                    client_input_commitment: ddh_run.client_input_commitment,
                    server_input_commitment: ddh_run.server_input_commitment,
                    run_binding,
                    evaluation_digest,
                },
                evaluator_witness: PrimeOrderSuccinctHssEvaluatorWitness {
                    total_steps: runtime.execution_program.trace.total_steps,
                    curve_cost_units: runtime.execution_program.trace.estimated_curve_cost_units,
                    evaluator_ops: runtime.execution_program.trace.evaluator_ops.clone(),
                    output_checksum: runtime.execution_result.output_checksum,
                    final_point_compressed: runtime.execution_result.final_point_compressed,
                },
                client_output,
                client_output_binding,
                server_output_payload_binding,
                server_output_payload,
            },
            result_assembly_duration_ns,
            output_sealing_finalization_duration_ns,
        ))
    }

    fn build_final_report_from_hidden_run(
        &self,
        runtime: &PrimeOrderSuccinctHssSharedRuntime,
        garbler_session: &PrimeOrderSuccinctHssGarblerSession,
        ddh_run: crate::ddh_hidden_eval_executor::DdhHiddenEvalRun,
    ) -> ProtoResult<(PrimeOrderSuccinctHssEvaluationReport, u64, u64)> {
        let result_assembly_started = monotonic_now_ns();
        let run_binding = self.ddh_evaluator.run_binding(
            runtime.artifact.artifact_digest,
            ddh_run.client_input_commitment,
            ddh_run.server_input_commitment,
        );
        let evaluation_digest = compute_evaluation_digest(
            runtime.artifact.artifact_digest,
            run_binding,
            &runtime.execution_result,
            &ddh_run.output,
        );
        let result_assembly_duration_ns = elapsed_ns_u64(result_assembly_started);
        let output_sealing_started = monotonic_now_ns();
        let client_output = self.seal_client_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.x_client_base,
        )?;
        let server_output = seal_server_output_packet_message(
            self.context_binding,
            &garbler_session.ddh_garbler,
            run_binding,
            evaluation_digest,
            &ddh_run.output.x_relayer_base_left,
            &ddh_run.output.x_relayer_base_right,
        )?;
        let output_sealing_finalization_duration_ns = elapsed_ns_u64(output_sealing_started);
        Ok((
            PrimeOrderSuccinctHssEvaluationReport {
                report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
                backend_family: CandidateBackendFamily::PrimeOrderSizeOptimized,
                fixed_function_id: runtime.candidate.fixed_function_id.clone(),
                hidden_core_materialization: HiddenCoreMaterialization::DdhPrimitiveBaseline,
                artifact: runtime.artifact.clone(),
                bindings: PrimeOrderSuccinctHssRunBindings {
                    client_input_commitment: ddh_run.client_input_commitment,
                    server_input_commitment: ddh_run.server_input_commitment,
                    run_binding,
                    evaluation_digest,
                },
                evaluator_witness: PrimeOrderSuccinctHssEvaluatorWitness {
                    total_steps: runtime.execution_program.trace.total_steps,
                    curve_cost_units: runtime.execution_program.trace.estimated_curve_cost_units,
                    evaluator_ops: runtime.execution_program.trace.evaluator_ops.clone(),
                    output_checksum: runtime.execution_result.output_checksum,
                    final_point_compressed: runtime.execution_result.final_point_compressed,
                },
                output_delivery: PrimeOrderSuccinctHssOutputDelivery {
                    client: client_output,
                    server: server_output,
                },
                notes: vec![
                    "Prepared session is bound to the encoded prime-order artifact and its compiled evaluator program.".to_string(),
                    "Per-run input sharing and transcript binding now run through the DDH primitive baseline owned by the prepared session.".to_string(),
                    "The DDH transport/output surface is now split into garbler/evaluator role views instead of one undifferentiated transport backend.".to_string(),
                    "The hidden evaluator now consumes pre-shared bit bundles instead of reconstructing clear F_expand inputs inside the executor.".to_string(),
                    "Evaluator-side execution now emits a serialized evaluation-result message that the garbler finalizes into the server output packet and final report.".to_string(),
                    "Output delivery now seals the hidden client/server base-share bundles directly; clear output bytes are only materialized through role-gated openers.".to_string(),
                    "This report is built on the current DDH primitive foundation; remaining work is final 2-party delivery semantics, security review, and performance hardening.".to_string(),
                ],
            },
            result_assembly_duration_ns,
            output_sealing_finalization_duration_ns,
        ))
    }

    pub fn evaluate_result_message_from_transport_messages(
        &self,
        runtime: &PrimeOrderSuccinctHssSharedRuntime,
        client_request_message: &PrimeOrderSuccinctHssWireMessage,
        evaluator_ot_state: &PrimeOrderSuccinctHssEvaluatorOtState,
        server_message: &PrimeOrderSuccinctHssWireMessage,
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        let client_packet: PrimeOrderSuccinctHssClientPacket = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let server_packet: PrimeOrderSuccinctHssServerPacket = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerPacket,
            server_message,
        )?;
        let evaluation_result = self.evaluate_result_from_packets_untrusted(
            runtime,
            &client_packet,
            evaluator_ot_state,
            &server_packet,
        )?;
        encode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::EvaluationResult,
            &evaluation_result,
        )
    }

    pub fn seal_client_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
        let aad = output_packet_aad(
            b"client_output",
            self.context_binding,
            run_binding,
            evaluation_digest,
        );
        let plaintext = serialize_encoded_bundle_payload(bundle)?;
        let (nonce, ciphertext) = self.ddh_evaluator.seal_message(
            DdhHssTransportPurpose::ClientOutput,
            &aad,
            &plaintext,
        )?;
        let packet = PrimeOrderSuccinctHssClientOutputPacket {
            context_binding: self.context_binding,
            run_binding,
            evaluation_digest,
            nonce,
            ciphertext,
        };
        encode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOutput,
            &packet,
        )
    }

    fn open_server_inputs_packet(
        &self,
        packet: &PrimeOrderSuccinctHssServerInputsPacket,
    ) -> ProtoResult<PrimeOrderSuccinctHssOpenedServerInputs> {
        open_server_inputs_packet_with_evaluator(&self.ddh_evaluator, self.context_binding, packet)
    }
}

impl PrimeOrderSuccinctHssSharedRuntime {
    pub fn artifact_summary(&self) -> &PrimeOrderSuccinctHssArtifactSummary {
        &self.artifact
    }

    pub fn output_openers(
        &self,
        garbler_session: &PrimeOrderSuccinctHssGarblerSession,
        evaluator_session: &PrimeOrderSuccinctHssEvaluatorSession,
    ) -> PrimeOrderSuccinctHssOutputOpeners {
        runtime_output_openers(garbler_session, evaluator_session)
    }

    pub fn finalize_report_from_evaluation_result(
        &self,
        garbler_session: &PrimeOrderSuccinctHssGarblerSession,
        evaluation_result: &PrimeOrderSuccinctHssEvaluationResult,
    ) -> ProtoResult<PrimeOrderSuccinctHssEvaluationReport> {
        debug_assert_eq!(
            evaluation_result.context_binding, self.candidate.context_binding,
            "evaluation result context binding should already match shared runtime"
        );
        if evaluation_result.context_binding != self.candidate.context_binding {
            return Err(ProtoError::InvalidInput(
                "evaluation result context binding does not match shared runtime".to_string(),
            ));
        }
        let client_packet: PrimeOrderSuccinctHssClientOutputPacket = decode_transport_message(
            self.candidate.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOutput,
            &evaluation_result.client_output,
        )?;
        if client_packet.run_binding != evaluation_result.bindings.run_binding
            || client_packet.evaluation_digest != evaluation_result.bindings.evaluation_digest
        {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output packet is not bound to the reported run"
                    .to_string(),
            ));
        }
        debug_assert_eq!(
            client_packet.run_binding, evaluation_result.bindings.run_binding,
            "client output packet run binding should match evaluation result bindings"
        );
        debug_assert_eq!(
            client_packet.evaluation_digest, evaluation_result.bindings.evaluation_digest,
            "client output packet evaluation digest should match evaluation result bindings"
        );
        let expected_client_output_binding = nested_output_message_binding(
            evaluation_result.context_binding,
            evaluation_result.bindings.run_binding,
            evaluation_result.bindings.evaluation_digest,
            b"client_output_message",
            &evaluation_result.client_output.bytes,
        );
        if evaluation_result.client_output_binding != expected_client_output_binding {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output binding is invalid".to_string(),
            ));
        }
        let expected_server_output_payload_binding = server_output_payload_binding(
            evaluation_result.context_binding,
            evaluation_result.bindings.run_binding,
            evaluation_result.bindings.evaluation_digest,
            &evaluation_result.server_output_payload,
        );
        if evaluation_result.server_output_payload_binding != expected_server_output_payload_binding
        {
            return Err(ProtoError::InvalidInput(
                "evaluation result server output payload binding is invalid".to_string(),
            ));
        }
        let (server_left, server_right) = deserialize_transport_pair_payload(
            DdhHssTransportPurpose::ServerOutput,
            &evaluation_result.server_output_payload,
        )?;
        debug_assert_eq!(
            server_left.owner,
            HiddenEvalInputOwner::Server,
            "server output payload should carry a server-owned hidden shared-value representation"
        );
        debug_assert_eq!(
            server_left.label, "x_relayer_base",
            "server output payload should carry x_relayer_base"
        );
        debug_assert_eq!(server_left.share_side, DdhHssShareSide::Left);
        debug_assert_eq!(server_right.share_side, DdhHssShareSide::Right);
        let server_output = seal_server_output_packet_message(
            self.candidate.context_binding,
            &garbler_session.ddh_garbler,
            evaluation_result.bindings.run_binding,
            evaluation_result.bindings.evaluation_digest,
            &server_left,
            &server_right,
        )?;
        let output_delivery = PrimeOrderSuccinctHssOutputDelivery {
            client: evaluation_result.client_output.clone(),
            server: server_output,
        };

        Ok(PrimeOrderSuccinctHssEvaluationReport {
            report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
            backend_family: CandidateBackendFamily::PrimeOrderSizeOptimized,
            fixed_function_id: self.candidate.fixed_function_id.clone(),
            hidden_core_materialization: HiddenCoreMaterialization::DdhPrimitiveBaseline,
            artifact: self.artifact.clone(),
            bindings: evaluation_result.bindings.clone(),
            evaluator_witness: evaluation_result.evaluator_witness.clone(),
            output_delivery,
            notes: vec![
                "Prepared session is bound to the encoded prime-order artifact and its compiled evaluator program.".to_string(),
                "Per-run input sharing and transcript binding now run through the DDH primitive baseline owned by the prepared session.".to_string(),
                "The DDH transport/output surface is now split into garbler/evaluator role views instead of one undifferentiated transport backend.".to_string(),
                "The hidden evaluator now consumes pre-shared bit bundles instead of reconstructing clear F_expand inputs inside the executor.".to_string(),
                "Evaluator-side execution now emits a serialized evaluation-result message that the garbler finalizes into the server output packet and final report.".to_string(),
                "Output delivery now seals the hidden client/server base-share bundles directly; clear output bytes are only materialized through role-gated openers.".to_string(),
                "This report is built on the current DDH primitive foundation; remaining work is final 2-party delivery semantics, security review, and performance hardening.".to_string(),
            ],
        })
    }
}

fn runtime_output_openers(
    garbler_session: &PrimeOrderSuccinctHssGarblerSession,
    evaluator_session: &PrimeOrderSuccinctHssEvaluatorSession,
) -> PrimeOrderSuccinctHssOutputOpeners {
    PrimeOrderSuccinctHssOutputOpeners {
        client: evaluator_session.client_output_opener(),
        server: garbler_session.server_output_opener(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn monotonic_now_ns() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}

#[cfg(target_arch = "wasm32")]
fn monotonic_now_ns() -> u128 {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|performance| (performance.now() * 1_000_000.0) as u128)
        .unwrap_or_else(|| (js_sys::Date::now() * 1_000_000.0) as u128)
}

fn elapsed_ns_u64(started_ns: u128) -> u64 {
    monotonic_now_ns()
        .saturating_sub(started_ns)
        .min(u64::MAX as u128) as u64
}

impl PrimeOrderSuccinctHssClientOutputOpener {
    pub fn open(&self, message: &PrimeOrderSuccinctHssWireMessage) -> ProtoResult<[u8; 32]> {
        let packet: PrimeOrderSuccinctHssClientOutputPacket = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ClientOutput,
            message,
        )?;
        decode_output_packet_with_evaluator(
            &self.evaluator,
            self.context_binding,
            &packet,
            "x_client_base",
        )
    }
}

impl PrimeOrderSuccinctHssServerOutputOpener {
    pub fn open(&self, message: &PrimeOrderSuccinctHssWireMessage) -> ProtoResult<[u8; 32]> {
        let packet: PrimeOrderSuccinctHssServerOutputPacket = decode_transport_message(
            self.context_binding,
            PrimeOrderSuccinctHssTransportKind::ServerOutput,
            message,
        )?;
        decode_output_packet_with_garbler(
            &self.garbler,
            self.context_binding,
            &packet,
            "x_relayer_base",
        )
    }
}

trait OutputPacketView {
    fn context_binding(&self) -> [u8; 32];
    fn run_binding(&self) -> [u8; 32];
    fn evaluation_digest(&self) -> [u8; 32];
    fn nonce(&self) -> [u8; 12];
    fn ciphertext(&self) -> &[u8];
}

impl OutputPacketView for PrimeOrderSuccinctHssClientOutputPacket {
    fn context_binding(&self) -> [u8; 32] {
        self.context_binding
    }

    fn run_binding(&self) -> [u8; 32] {
        self.run_binding
    }

    fn evaluation_digest(&self) -> [u8; 32] {
        self.evaluation_digest
    }

    fn nonce(&self) -> [u8; 12] {
        self.nonce
    }

    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl OutputPacketView for PrimeOrderSuccinctHssServerOutputPacket {
    fn context_binding(&self) -> [u8; 32] {
        self.context_binding
    }

    fn run_binding(&self) -> [u8; 32] {
        self.run_binding
    }

    fn evaluation_digest(&self) -> [u8; 32] {
        self.evaluation_digest
    }

    fn nonce(&self) -> [u8; 12] {
        self.nonce
    }

    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

fn build_ot_transcript(
    context_binding: [u8; 32],
    client_ot_offer: &PrimeOrderSuccinctHssClientOtOffer,
    client_packet: &PrimeOrderSuccinctHssClientPacket,
    y_client_response: &DdhHssOtResponseBundle,
    tau_client_response: &DdhHssOtResponseBundle,
    y_client_remote_release: &DdhHssOtReleasedRemoteBundle,
    tau_client_remote_release: &DdhHssOtReleasedRemoteBundle,
) -> PrimeOrderSuccinctHssOtTranscript {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/ot-transcript/v0");
    hasher.update(context_binding);
    hasher.update(client_ot_offer.y_client_offer.commitment);
    hasher.update(client_packet.y_client_request.commitment);
    hasher.update(y_client_response.commitment);
    hasher.update(y_client_remote_release.transcript_binding);
    hasher.update(client_ot_offer.tau_client_offer.commitment);
    hasher.update(client_packet.tau_client_request.commitment);
    hasher.update(tau_client_response.commitment);
    hasher.update(tau_client_remote_release.transcript_binding);
    let digest = hasher.finalize();
    let mut transcript_digest = [0u8; 32];
    transcript_digest.copy_from_slice(&digest);

    PrimeOrderSuccinctHssOtTranscript {
        context_binding,
        y_client_offer_commitment: client_ot_offer.y_client_offer.commitment,
        y_client_request_commitment: client_packet.y_client_request.commitment,
        y_client_response_commitment: y_client_response.commitment,
        y_client_remote_release_binding: y_client_remote_release.transcript_binding,
        tau_client_offer_commitment: client_ot_offer.tau_client_offer.commitment,
        tau_client_request_commitment: client_packet.tau_client_request.commitment,
        tau_client_response_commitment: tau_client_response.commitment,
        tau_client_remote_release_binding: tau_client_remote_release.transcript_binding,
        transcript_digest,
    }
}

fn validate_ot_transcript(
    expected_context_binding: [u8; 32],
    transcript: &PrimeOrderSuccinctHssOtTranscript,
) -> ProtoResult<()> {
    if transcript.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "server OT transcript context binding does not match expected value".to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/ot-transcript/v0");
    hasher.update(transcript.context_binding);
    hasher.update(transcript.y_client_offer_commitment);
    hasher.update(transcript.y_client_request_commitment);
    hasher.update(transcript.y_client_response_commitment);
    hasher.update(transcript.y_client_remote_release_binding);
    hasher.update(transcript.tau_client_offer_commitment);
    hasher.update(transcript.tau_client_request_commitment);
    hasher.update(transcript.tau_client_response_commitment);
    hasher.update(transcript.tau_client_remote_release_binding);
    let digest = hasher.finalize();
    if digest.as_slice() != transcript.transcript_digest.as_slice() {
        return Err(ProtoError::InvalidInput(
            "server OT transcript digest is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_client_packet_context(
    expected_context_binding: [u8; 32],
    packet: &PrimeOrderSuccinctHssClientPacket,
) -> ProtoResult<()> {
    if packet.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "client delivery packet context binding does not match expected session".to_string(),
        ));
    }
    if packet.y_client_request.owner != crate::HiddenEvalInputOwner::Client
        || packet.tau_client_request.owner != crate::HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "client OT request packet must be client-owned".to_string(),
        ));
    }
    if packet.y_client_request.label != "y_client_bits"
        || packet.tau_client_request.label != "tau_client_bits"
    {
        return Err(ProtoError::InvalidInput(
            "client OT request packet labels are invalid".to_string(),
        ));
    }
    if packet.y_client_request.words.len() != 256 || packet.tau_client_request.words.len() != 256 {
        return Err(ProtoError::InvalidInput(
            "client OT request packet must contain 256 bits".to_string(),
        ));
    }
    Ok(())
}

fn encode_transport_message<T: Serialize>(
    context_binding: [u8; 32],
    kind: PrimeOrderSuccinctHssTransportKind,
    payload: &T,
) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
    let payload_bytes = serialize_transport_payload_with_label("transport_frame", payload)?;
    let frame = PrimeOrderSuccinctHssTransportFrame {
        report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
        context_binding,
        kind,
        payload: payload_bytes,
    };
    let bytes = bincode::serialize(&frame).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize prime-order succinct HSS transport frame for {:?}: {err}",
            kind
        ))
    })?;
    Ok(PrimeOrderSuccinctHssWireMessage { bytes })
}

fn decode_transport_message<T: DeserializeOwned>(
    expected_context_binding: [u8; 32],
    expected_kind: PrimeOrderSuccinctHssTransportKind,
    message: &PrimeOrderSuccinctHssWireMessage,
) -> ProtoResult<T> {
    let frame: PrimeOrderSuccinctHssTransportFrame =
        bincode::deserialize(&message.bytes).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to decode prime-order succinct HSS transport frame for {:?}: {err}",
                expected_kind
            ))
        })?;
    if frame.report_version != PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS transport frame version mismatch: {}",
            frame.report_version
        )));
    }
    if frame.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "prime-order succinct HSS transport frame context binding does not match the runtime"
                .to_string(),
        ));
    }
    if frame.kind != expected_kind {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS transport frame kind mismatch: expected {:?}, got {:?}",
            expected_kind, frame.kind
        )));
    }
    deserialize_transport_payload_with_label("transport_frame", &frame.payload)
}

fn serialize_transport_payload_with_label<T: Serialize>(
    label: &str,
    payload: &T,
) -> ProtoResult<Vec<u8>> {
    bincode::serialize(payload).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize transport payload for {}: {err}",
            label
        ))
    })
}

fn deserialize_transport_payload<T: DeserializeOwned>(
    purpose: DdhHssTransportPurpose,
    plaintext: &[u8],
) -> ProtoResult<T> {
    deserialize_transport_payload_with_label(purpose.as_str(), plaintext)
}

fn deserialize_transport_payload_with_label<T: DeserializeOwned>(
    label: &str,
    plaintext: &[u8],
) -> ProtoResult<T> {
    bincode::deserialize(plaintext).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode transport payload for {}: {err}",
            label
        ))
    })
}

fn wire_word_from_joint(word: &DdhHssSharedWord) -> PrimeOrderSuccinctHssJointWordWire {
    PrimeOrderSuccinctHssJointWordWire {
        width_bits: word.width_bits,
        left_word: word.left_word,
        right_word: word.right_word,
        left_commitment: word.left_commitment,
        right_commitment: word.right_commitment,
        provenance_digest: word.provenance_digest,
    }
}

fn joint_word_from_wire(word: PrimeOrderSuccinctHssJointWordWire) -> DdhHssSharedWord {
    DdhHssSharedWord {
        width_bits: word.width_bits,
        left_word: word.left_word,
        right_word: word.right_word,
        left_commitment: word.left_commitment,
        right_commitment: word.right_commitment,
        provenance_digest: word.provenance_digest,
    }
}

fn wire_bundle_from_joint(bundle: &DdhHssInputShareBundle) -> PrimeOrderSuccinctHssJointBundleWire {
    PrimeOrderSuccinctHssJointBundleWire {
        owner: bundle.owner,
        label: bundle.label.clone(),
        words: bundle.words.iter().map(wire_word_from_joint).collect(),
        commitment: bundle.commitment,
    }
}

fn joint_bundle_from_wire(bundle: PrimeOrderSuccinctHssJointBundleWire) -> DdhHssInputShareBundle {
    DdhHssInputShareBundle {
        owner: bundle.owner,
        label: bundle.label,
        words: bundle.words.into_iter().map(joint_word_from_wire).collect(),
        commitment: bundle.commitment,
    }
}

fn serialize_encoded_bundle_payload(bundle: &DdhHssInputShareBundle) -> ProtoResult<Vec<u8>> {
    let payload = PrimeOrderSuccinctHssEncodedBundlePayload {
        bundle: wire_bundle_from_joint(bundle),
    };
    serialize_transport_payload_with_label("encoded_bundle", &payload)
}

fn serialize_transport_pair_payload(
    label: &str,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<Vec<u8>> {
    let payload = PrimeOrderSuccinctHssEncodedTransportPairPayloadRef { left, right };
    serialize_transport_payload_with_label(label, &payload)
}

impl PrimeOrderSuccinctHssOpenedServerInputs {
    fn server_input_commitment_with_garbler(
        &self,
        garbler: &DdhHssGarbler,
    ) -> ProtoResult<[u8; 32]> {
        Ok(combined_server_input_commitment_from_opened(
            garbler.evaluation_key(),
            self,
        ))
    }

    fn server_input_commitment_with_evaluator(
        &self,
        evaluator: &DdhHssEvaluator,
    ) -> ProtoResult<[u8; 32]> {
        Ok(combined_server_input_commitment_from_opened(
            evaluator.evaluation_key(),
            self,
        ))
    }
}

fn combined_server_input_commitment_from_opened(
    evaluation_key: &DdhHssEvaluationKey,
    opened_server_inputs: &PrimeOrderSuccinctHssOpenedServerInputs,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
    hasher.update(evaluation_key.key_id);
    hasher.update(b"server");
    for bundle in [
        (
            &opened_server_inputs.y_relayer_left.commitment,
            opened_server_inputs.y_relayer_left.label.as_bytes(),
        ),
        (
            &opened_server_inputs.tau_relayer_left.commitment,
            opened_server_inputs.tau_relayer_left.label.as_bytes(),
        ),
    ] {
        hasher.update(bundle.0);
        hasher.update(bundle.1);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn deserialize_encoded_bundle_payload(
    purpose: DdhHssTransportPurpose,
    plaintext: &[u8],
) -> ProtoResult<DdhHssInputShareBundle> {
    let payload: PrimeOrderSuccinctHssEncodedBundlePayload =
        deserialize_transport_payload(purpose, plaintext)?;
    Ok(joint_bundle_from_wire(payload.bundle))
}

fn deserialize_transport_pair_payload(
    purpose: DdhHssTransportPurpose,
    plaintext: &[u8],
) -> ProtoResult<(DdhHssTransportBundle, DdhHssTransportBundle)> {
    let payload: PrimeOrderSuccinctHssEncodedTransportPairPayload =
        deserialize_transport_payload(purpose, plaintext)?;
    Ok((payload.left, payload.right))
}

fn serialize_server_inputs_payload(
    y_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
    tau_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
) -> ProtoResult<Vec<u8>> {
    let payload = PrimeOrderSuccinctHssEncodedServerInputsPayloadRef {
        y_relayer_left: &y_relayer.0,
        y_relayer_right: &y_relayer.1,
        tau_relayer_left: &tau_relayer.0,
        tau_relayer_right: &tau_relayer.1,
    };
    serialize_transport_payload_with_label("server_inputs", &payload)
}

fn deserialize_server_inputs_payload(
    plaintext: &[u8],
) -> ProtoResult<PrimeOrderSuccinctHssOpenedServerInputs> {
    let payload: PrimeOrderSuccinctHssEncodedServerInputsPayload =
        deserialize_transport_payload(DdhHssTransportPurpose::ServerInput, plaintext)?;
    Ok(PrimeOrderSuccinctHssOpenedServerInputs {
        y_relayer_left: payload.y_relayer_left,
        y_relayer_right: payload.y_relayer_right,
        tau_relayer_left: payload.tau_relayer_left,
        tau_relayer_right: payload.tau_relayer_right,
    })
}

fn open_server_inputs_packet_with_evaluator(
    evaluator: &DdhHssEvaluator,
    expected_context_binding: [u8; 32],
    packet: &PrimeOrderSuccinctHssServerInputsPacket,
) -> ProtoResult<PrimeOrderSuccinctHssOpenedServerInputs> {
    if packet.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "server input packet context binding does not match evaluator session".to_string(),
        ));
    }
    let aad = server_input_packet_aad(packet.context_binding, packet.server_input_commitment);
    let plaintext = evaluator.open_message(
        DdhHssTransportPurpose::ServerInput,
        &aad,
        packet.nonce,
        &packet.ciphertext,
    )?;
    deserialize_server_inputs_payload(&plaintext)
}

fn open_server_inputs_packet_with_garbler(
    garbler: &DdhHssGarbler,
    expected_context_binding: [u8; 32],
    packet: &PrimeOrderSuccinctHssServerInputsPacket,
) -> ProtoResult<PrimeOrderSuccinctHssOpenedServerInputs> {
    if packet.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "server input packet context binding does not match garbler session".to_string(),
        ));
    }
    let aad = server_input_packet_aad(packet.context_binding, packet.server_input_commitment);
    let plaintext = garbler.open_message(
        DdhHssTransportPurpose::ServerInput,
        &aad,
        packet.nonce,
        &packet.ciphertext,
    )?;
    deserialize_server_inputs_payload(&plaintext)
}

fn seal_server_output_packet_message(
    context_binding: [u8; 32],
    garbler: &DdhHssGarbler,
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<PrimeOrderSuccinctHssWireMessage> {
    let plaintext = serialize_transport_pair_payload("server_output_bundle", left, right)?;
    let aad = output_packet_aad(
        b"server_output",
        context_binding,
        run_binding,
        evaluation_digest,
    );
    let (nonce, ciphertext) =
        garbler.seal_message(DdhHssTransportPurpose::ServerOutput, &aad, &plaintext)?;
    let packet = PrimeOrderSuccinctHssServerOutputPacket {
        context_binding,
        run_binding,
        evaluation_digest,
        nonce,
        ciphertext,
    };
    encode_transport_message(
        context_binding,
        PrimeOrderSuccinctHssTransportKind::ServerOutput,
        &packet,
    )
}

fn open_output_packet_payload_with_evaluator<T: OutputPacketView>(
    evaluator: &DdhHssEvaluator,
    expected_context_binding: [u8; 32],
    packet: &T,
) -> ProtoResult<DdhHssInputShareBundle> {
    if packet.context_binding() != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "output packet context binding does not match opener".to_string(),
        ));
    }
    let aad = output_packet_aad(
        b"client_output",
        packet.context_binding(),
        packet.run_binding(),
        packet.evaluation_digest(),
    );
    let plaintext = evaluator.open_message(
        DdhHssTransportPurpose::ClientOutput,
        &aad,
        packet.nonce(),
        packet.ciphertext(),
    )?;
    deserialize_encoded_bundle_payload(DdhHssTransportPurpose::ClientOutput, &plaintext)
}

fn open_output_packet_payload_with_garbler<T: OutputPacketView>(
    garbler: &DdhHssGarbler,
    expected_context_binding: [u8; 32],
    packet: &T,
) -> ProtoResult<(DdhHssTransportBundle, DdhHssTransportBundle)> {
    if packet.context_binding() != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "output packet context binding does not match opener".to_string(),
        ));
    }
    let aad = output_packet_aad(
        b"server_output",
        packet.context_binding(),
        packet.run_binding(),
        packet.evaluation_digest(),
    );
    let plaintext = garbler.open_message(
        DdhHssTransportPurpose::ServerOutput,
        &aad,
        packet.nonce(),
        packet.ciphertext(),
    )?;
    deserialize_transport_pair_payload(DdhHssTransportPurpose::ServerOutput, &plaintext)
}

#[cfg(test)]
fn decode_input_bit_bundle_array_with_backend(
    backend: &DdhHssBackend,
    bundle: &DdhHssInputShareBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if bundle.owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "input bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, bundle.owner
        )));
    }
    if bundle.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "input bundle label mismatch: expected {expected_label}, got {}",
            bundle.label
        )));
    }
    if bundle.words.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "decoded input bit bundle {expected_label} must be exactly 256 bits, got {}",
            bundle.words.len()
        )));
    }
    let mut out = [0u8; 32];
    for byte_idx in 0..32 {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let bit = backend.decode_word(&bundle.words[byte_idx * 8 + bit_idx]);
            value |= ((bit & 1) as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

#[cfg(test)]
fn decode_server_input_bit_bundle_array_with_backend(
    backend: &DdhHssBackend,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if left.owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "server input bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, left.owner
        )));
    }
    if left.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "server input bundle label mismatch: expected {expected_label}, got {}",
            left.label
        )));
    }
    if left.words.len() != 256 || right.words.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "decoded server input bit bundle {expected_label} must be exactly 256 bits, got {} and {}",
            left.words.len(),
            right.words.len()
        )));
    }
    let joint_words = left
        .words
        .iter()
        .zip(&right.words)
        .map(|(left_word, right_word)| DdhHssSharedWord {
            width_bits: left_word.width_bits,
            left_word: left_word.share_word,
            right_word: right_word.share_word,
            left_commitment: left_word.share_commitment,
            right_commitment: right_word.share_commitment,
            provenance_digest: left_word.provenance_digest,
        })
        .collect::<Vec<_>>();
    let expected_commitment =
        backend.input_commitment(expected_owner, expected_label, &joint_words);
    if expected_commitment != left.commitment || expected_commitment != right.commitment {
        return Err(ProtoError::InvalidInput(format!(
            "server input bundle commitment mismatch for {expected_label}"
        )));
    }
    let mut out = [0u8; 32];
    for byte_idx in 0..32 {
        let mut value = 0u8;
        for bit_idx in 0..8 {
            let left_word = &left.words[byte_idx * 8 + bit_idx];
            let right_word = &right.words[byte_idx * 8 + bit_idx];
            let bit = (left_word.share_word + right_word.share_word) & 1;
            value |= (bit as u8) << bit_idx;
        }
        out[byte_idx] = value;
    }
    Ok(out)
}

fn decode_bundle_array_from_words(
    decoded: Vec<u8>,
    bundle: &DdhHssInputShareBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if bundle.owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "input bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, bundle.owner
        )));
    }
    if bundle.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "input bundle label mismatch: expected {expected_label}, got {}",
            bundle.label
        )));
    }
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        ProtoError::Decode(format!(
            "decoded input bundle {expected_label} must be exactly 32 bytes, got {}",
            decoded.len()
        ))
    })
}

fn decode_output_packet_with_evaluator<T: OutputPacketView>(
    evaluator: &DdhHssEvaluator,
    expected_context_binding: [u8; 32],
    packet: &T,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    let payload =
        open_output_packet_payload_with_evaluator(evaluator, expected_context_binding, packet)?;
    if payload.words.len() == 256 && payload.words.iter().all(|word| word.width_bits == 1) {
        if payload.owner != HiddenEvalInputOwner::Client || payload.label != expected_label {
            return Err(ProtoError::InvalidInput(format!(
                "output bundle metadata mismatch for {expected_label}"
            )));
        }
        evaluator.decode_client_bit_bundle_array(&payload)
    } else {
        decode_bundle_array_from_words(
            evaluator.decode_client_bundle(&payload)?,
            &payload,
            HiddenEvalInputOwner::Client,
            expected_label,
        )
    }
}

fn decode_output_packet_with_garbler<T: OutputPacketView>(
    garbler: &DdhHssGarbler,
    expected_context_binding: [u8; 32],
    packet: &T,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    let (left, right) =
        open_output_packet_payload_with_garbler(garbler, expected_context_binding, packet)?;
    if left.owner != HiddenEvalInputOwner::Server || left.label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "output bundle metadata mismatch for {expected_label}"
        )));
    }
    if left.share_side != DdhHssShareSide::Left
        || right.share_side != DdhHssShareSide::Right
        || left.words.len() != right.words.len()
    {
        return Err(ProtoError::InvalidInput(
            "server output payload transport sides are invalid".to_string(),
        ));
    }
    let payload = garbler.join_share_bundle(&left, &right)?;
    if payload.words.len() == 256 && payload.words.iter().all(|word| word.width_bits == 1) {
        garbler.decode_server_bit_bundle_array(&payload)
    } else {
        decode_bundle_array_from_words(
            garbler.decode_server_bundle(&payload)?,
            &payload,
            HiddenEvalInputOwner::Server,
            expected_label,
        )
    }
}

impl PrimeOrderSuccinctHssEvaluationReport {
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "prime-order succinct HSS: backend={} materialization={:?}",
                self.backend_family.as_str(),
                self.hidden_core_materialization,
            ),
            format!(
                "artifact: {}B sections={} digest={} curve_cost={} steps={}",
                self.artifact.artifact_bytes,
                self.artifact.section_count,
                hex::encode(self.artifact.artifact_digest),
                self.evaluator_witness.curve_cost_units,
                self.evaluator_witness.total_steps,
            ),
            format!(
                "bindings: context={} run={} evaluation={}",
                hex::encode(self.artifact.context_binding),
                hex::encode(self.bindings.run_binding),
                hex::encode(self.bindings.evaluation_digest),
            ),
            format!(
                "evaluator: checksum={:016x} final_point={}",
                self.evaluator_witness.output_checksum,
                hex::encode(self.evaluator_witness.final_point_compressed),
            ),
            format!(
                "output_packets: client={}B server={}B",
                self.output_delivery.client.bytes.len(),
                self.output_delivery.server.bytes.len(),
            ),
        ]
    }
}

fn output_packet_aad(
    purpose_tag: &[u8],
    context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(7 + purpose_tag.len() + 32 + 32 + 32);
    aad.extend_from_slice(b"output/");
    aad.extend_from_slice(purpose_tag);
    aad.extend_from_slice(&context_binding);
    aad.extend_from_slice(&run_binding);
    aad.extend_from_slice(&evaluation_digest);
    aad
}

fn server_input_packet_aad(
    context_binding: [u8; 32],
    server_input_commitment: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(12 + 32 + 32);
    aad.extend_from_slice(b"server_input");
    aad.extend_from_slice(&context_binding);
    aad.extend_from_slice(&server_input_commitment);
    aad
}

fn compute_evaluation_digest(
    artifact_digest: [u8; 32],
    run_binding: [u8; 32],
    executor_result: &PrimeOrderCpuExecutionResult,
    output: &DdhHiddenEvalOutputBundles,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/evaluation-digest/v0");
    hasher.update(artifact_digest);
    hasher.update(run_binding);
    hasher.update(executor_result.output_checksum.to_le_bytes());
    hasher.update(executor_result.final_point_compressed);
    hasher.update(output.x_client_base.commitment);
    hasher.update(output.x_relayer_base_left.commitment);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn server_output_payload_binding(
    context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    server_output_payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        b"succinct-garbling-proto/prime-order-succinct-hss/server-output-payload-binding/v0",
    );
    hasher.update(context_binding);
    hasher.update(run_binding);
    hasher.update(evaluation_digest);
    hasher.update(server_output_payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn nested_output_message_binding(
    context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    label: &[u8],
    message_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        b"succinct-garbling-proto/prime-order-succinct-hss/nested-output-message-binding/v0",
    );
    hasher.update(context_binding);
    hasher.update(run_binding);
    hasher.update(evaluation_digest);
    hasher.update(label);
    hasher.update(message_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
