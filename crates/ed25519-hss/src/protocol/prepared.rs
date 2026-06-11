use crate::artifact::{
    build_prime_order_size_optimized_artifact, decode_prime_order_size_optimized_artifact,
    materialize_prime_order_size_optimized_bytes, PrimeOrderEncodedArtifact,
};
use crate::candidate::build_fixed_hidden_core_candidate;
use crate::candidate::{CandidateBackendFamily, FixedHiddenCoreCandidate};
use crate::client::ClientSession;
use crate::ddh::ddh_hss::role_views_for_backend;
use crate::ddh::hidden_eval_executor::{
    prepare_ddh_hidden_eval_constant_pool, DdhHiddenEvalConstantPool,
};
use crate::ddh::{
    compile_prime_order_hidden_eval_program, keygen_prime_order_ddh_hss_backend, DdhHssBackend,
    HiddenEvalProgram,
};
use crate::runtime::{
    compile_prime_order_cpu_execution_program, execute_prime_order_cpu_execution_program,
    shared::build_artifact_summary, PrimeOrderCpuExecutionProgram, SharedRuntime,
};
use crate::server::{ot::prepare_garbler_ot_state_for_session, ServerOtState, ServerSession};
use crate::shared::CanonicalContext;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{ClientOtOffer, OutputProjectionMode};
pub struct PreparedSession {
    candidate: FixedHiddenCoreCandidate,
    projection_mode: OutputProjectionMode,
    artifact: PrimeOrderEncodedArtifact,
    artifact_bytes: Vec<u8>,
    hidden_eval_program: HiddenEvalProgram,
    hidden_eval_constants: DdhHiddenEvalConstantPool,
    ddh_backend: DdhHssBackend,
    execution_program: PrimeOrderCpuExecutionProgram,
    shared_runtime_cached: SharedRuntime,
    garbler_session_cached: ServerSession,
    evaluator_session_cached: ClientSession,
}

pub fn prepare_prime_order_succinct_hss(
    context: &CanonicalContext,
) -> ProtoResult<PreparedSession> {
    let candidate = build_fixed_hidden_core_candidate(context)?;
    if candidate.backend.family != CandidateBackendFamily::PrimeOrderSizeOptimized {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS requires prime_order_size_optimized backend, got {}",
            candidate.backend.family.as_str()
        )));
    }

    let artifact = build_prime_order_size_optimized_artifact(&candidate)?;
    let projection_mode = OutputProjectionMode::trusted_server_projection();
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
    let backend_version = ddh_backend.evaluation_key().backend_version;
    let client_ot_offer = ClientOtOffer {
        backend_version,
        context_binding: candidate.context_binding,
        y_client_offer,
        tau_client_offer,
    };
    let garbler_ot_state = ServerOtState {
        backend_version,
        context_binding: candidate.context_binding,
        y_client_remote,
        tau_client_remote,
        y_client_sender_state,
        tau_client_sender_state,
    };
    let shared_runtime_cached = SharedRuntime {
        candidate: candidate.clone(),
        projection_mode: projection_mode.clone(),
        artifact: build_artifact_summary(&candidate, &artifact),
        hidden_eval_program: hidden_eval_program.clone(),
        execution_program: execution_program.clone(),
        execution_result: execution_result.clone(),
    };
    let prepared_garbler_ot_state = prepare_garbler_ot_state_for_session(
        &ddh_roles.garbler,
        &client_ot_offer,
        &garbler_ot_state,
    )?;
    let garbler_session_cached = ServerSession {
        context_binding: candidate.context_binding,
        ddh_garbler: ddh_roles.garbler.clone(),
        client_ot_offer: client_ot_offer.clone(),
        garbler_ot_state: garbler_ot_state.clone(),
        y_client_sender_words_prepared: prepared_garbler_ot_state.y_client_sender_words_prepared,
        tau_client_sender_words_prepared: prepared_garbler_ot_state
            .tau_client_sender_words_prepared,
    };
    garbler_session_cached.validate_garbler_ot_state()?;
    let evaluator_session_cached = ClientSession {
        context_binding: candidate.context_binding,
        ddh_evaluator: ddh_roles.evaluator.clone(),
    };

    Ok(PreparedSession {
        candidate,
        projection_mode,
        artifact,
        artifact_bytes,
        hidden_eval_program,
        hidden_eval_constants,
        ddh_backend,
        execution_program,
        shared_runtime_cached,
        garbler_session_cached,
        evaluator_session_cached,
    })
}

pub fn prepare_prime_order_succinct_hss_client(
    context: &CanonicalContext,
) -> ProtoResult<crate::client::ClientDriverState> {
    let candidate = build_fixed_hidden_core_candidate(context)?;
    if candidate.backend.family != CandidateBackendFamily::PrimeOrderSizeOptimized {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS requires prime_order_size_optimized backend, got {}",
            candidate.backend.family.as_str()
        )));
    }

    let artifact_bytes = materialize_prime_order_size_optimized_bytes(&candidate)?;
    let decoded = decode_prime_order_size_optimized_artifact(&artifact_bytes)?;
    let hidden_eval_program = compile_prime_order_hidden_eval_program(&decoded)?;
    let ddh_backend = keygen_prime_order_ddh_hss_backend(
        candidate.context_binding,
        candidate.template.candidate_digest,
        &hidden_eval_program,
    )?;
    let ddh_roles = role_views_for_backend(&ddh_backend);

    Ok(crate::client::ClientDriverState {
        runtime: crate::runtime::SharedRuntimeState {
            prepared_context: CanonicalContext {
                org_id: candidate.context_descriptor.org_id.clone(),
                account_id: candidate.context_descriptor.account_id.clone(),
                key_purpose: candidate.context_descriptor.key_purpose.clone(),
                key_version: candidate.context_descriptor.key_version.clone(),
                participant_ids: candidate.context_descriptor.participant_ids.clone(),
                derivation_version: candidate.context_descriptor.derivation_version,
            },
            projection_mode: OutputProjectionMode::trusted_server_projection(),
        },
        evaluator_session: crate::client::ClientSessionState {
            backend_version: ddh_roles.evaluator.evaluation_key().backend_version,
            context_binding: candidate.context_binding,
            ddh_evaluator: ddh_roles.evaluator,
        },
    })
}

impl PreparedSession {
    pub fn candidate(&self) -> &FixedHiddenCoreCandidate {
        &self.candidate
    }

    pub fn output_projection_mode(&self) -> &OutputProjectionMode {
        &self.projection_mode
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

    pub fn shared_runtime(&self) -> SharedRuntime {
        self.shared_runtime_cached.clone()
    }

    pub fn garbler_session(&self) -> ServerSession {
        self.garbler_session_cached.clone()
    }

    pub fn evaluator_session(&self) -> ClientSession {
        self.evaluator_session_cached.clone()
    }
}
