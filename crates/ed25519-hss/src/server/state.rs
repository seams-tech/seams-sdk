use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ddh::ddh_hss::DdhHssPreparedOtSenderStateWord;
use crate::ddh::hidden_eval_executor::{
    compute_message_schedule_completed_digest, compute_output_projection_continuation_digest,
    compute_round_core_completed_digest, DdhHiddenEvalMessageScheduleContinuation,
    DdhHiddenEvalOutputBundles, DdhHiddenEvalProjectorInputs, DdhHiddenEvalRoundCoreContinuation,
    DdhHiddenEvalServerOutputBundles,
};
use crate::ddh::{
    DdhHssBackendVersion, DdhHssGarbler, DdhHssOtRemoteBundle, DdhHssOtSenderStateBundle,
    DdhHssTransportBundle, HiddenEvalProgram,
};
use crate::runtime::SharedRuntimeState;
use crate::wire::{ClientOtOffer, OtTranscript, ServerEvalHandle, ServerEvalStageId, TranscriptId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOtState {
    pub backend_version: DdhHssBackendVersion,
    pub context_binding: [u8; 32],
    pub y_client_remote: DdhHssOtRemoteBundle,
    pub tau_client_remote: DdhHssOtRemoteBundle,
    pub y_client_sender_state: DdhHssOtSenderStateBundle,
    pub tau_client_sender_state: DdhHssOtSenderStateBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSession {
    pub(crate) context_binding: [u8; 32],
    pub(crate) ddh_garbler: DdhHssGarbler,
    pub(crate) client_ot_offer: ClientOtOffer,
    pub(crate) garbler_ot_state: ServerOtState,
    pub(crate) y_client_sender_words_prepared: Vec<DdhHssPreparedOtSenderStateWord>,
    pub(crate) tau_client_sender_words_prepared: Vec<DdhHssPreparedOtSenderStateWord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSessionState {
    pub backend_version: DdhHssBackendVersion,
    pub context_binding: [u8; 32],
    pub ddh_garbler: DdhHssGarbler,
    pub client_ot_offer: ClientOtOffer,
    pub garbler_ot_state: ServerOtState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerDriverState {
    pub runtime: SharedRuntimeState,
    pub garbler_session: ServerSessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerEvalOperation {
    Registration,
    TxSigning,
    LinkDevice,
    EmailRecovery,
    WarmSessionReconstruction,
    ExplicitKeyExport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerEvalStatus {
    Pending,
    InProgress,
    Finalized,
    Aborted,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalRelayerRoots {
    pub y_relayer: [u8; 32],
    pub tau_relayer: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalFinalizeOutput {
    pub canonical_seed_commitment: [u8; 32],
    pub x_relayer_base_left: DdhHssTransportBundle,
    pub x_relayer_base_right: DdhHssTransportBundle,
}

impl ServerEvalFinalizeOutput {
    pub fn from_hidden_eval_outputs(output: &DdhHiddenEvalOutputBundles) -> Self {
        Self {
            canonical_seed_commitment: output.canonical_seed.commitment,
            x_relayer_base_left: output.x_relayer_base_left.clone(),
            x_relayer_base_right: output.x_relayer_base_right.clone(),
        }
    }

    pub fn from_server_output_bundles(output: &DdhHiddenEvalServerOutputBundles) -> Self {
        Self {
            canonical_seed_commitment: output.canonical_seed_commitment,
            x_relayer_base_left: output.x_relayer_base_left.clone(),
            x_relayer_base_right: output.x_relayer_base_right.clone(),
        }
    }

    pub fn output_projection_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"prime_order_ddh_hidden_eval_server_output_projection_digest_v0");
        hasher.update(self.canonical_seed_commitment);
        hasher.update(self.x_relayer_base_left.commitment);
        hasher.update(self.x_relayer_base_right.commitment);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalFinalizeState {
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub output: ServerEvalFinalizeOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalMessageScheduleState {
    pub message_schedule: DdhHiddenEvalMessageScheduleContinuation,
    pub projector_inputs: DdhHiddenEvalProjectorInputs,
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalRoundCoreState {
    pub prior_execution_checkpoint_digest: [u8; 32],
    pub round_core: DdhHiddenEvalRoundCoreContinuation,
    pub projector_inputs: DdhHiddenEvalProjectorInputs,
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalOutputProjectionState {
    pub prior_execution_checkpoint_digest: [u8; 32],
    pub round_core: DdhHiddenEvalRoundCoreContinuation,
    pub projector_inputs: DdhHiddenEvalProjectorInputs,
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvalExecutionState {
    MessageSchedule(ServerEvalMessageScheduleState),
    RoundCore(ServerEvalRoundCoreState),
    OutputProjection(ServerEvalOutputProjectionState),
    Finalize(ServerEvalFinalizeState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEvalState {
    pub handle: ServerEvalHandle,
    pub context_binding: [u8; 32],
    pub transcript_id: TranscriptId,
    pub current_stage: ServerEvalStageId,
    pub current_transcript_digest: [u8; 32],
    pub operation: ServerEvalOperation,
    pub status: ServerEvalStatus,
    pub server_input_commitment: [u8; 32],
    pub ot_transcript: OtTranscript,
    pub last_request_digest: Option<[u8; 32]>,
    pub relayer_roots: Option<ServerEvalRelayerRoots>,
    pub hidden_eval_program: Option<HiddenEvalProgram>,
    pub execution_state: Option<ServerEvalExecutionState>,
}

impl ServerEvalState {
    pub fn new(
        handle: ServerEvalHandle,
        context_binding: [u8; 32],
        transcript_id: TranscriptId,
        current_transcript_digest: [u8; 32],
        operation: ServerEvalOperation,
        server_input_commitment: [u8; 32],
        ot_transcript: OtTranscript,
        relayer_roots: ServerEvalRelayerRoots,
    ) -> Self {
        Self {
            handle,
            context_binding,
            transcript_id,
            current_stage: ServerEvalStageId::add_stage(),
            current_transcript_digest,
            operation,
            status: ServerEvalStatus::Pending,
            server_input_commitment,
            ot_transcript,
            last_request_digest: None,
            relayer_roots: Some(relayer_roots),
            hidden_eval_program: None,
            execution_state: None,
        }
    }

    pub fn with_add_stage_materialization(
        &self,
        hidden_eval_program: HiddenEvalProgram,
        message_schedule: DdhHiddenEvalMessageScheduleContinuation,
        projector_inputs: DdhHiddenEvalProjectorInputs,
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> Self {
        let mut next = self.clone();
        next.relayer_roots = None;
        next.hidden_eval_program = Some(hidden_eval_program);
        next.execution_state = Some(ServerEvalExecutionState::MessageSchedule(
            ServerEvalMessageScheduleState {
                message_schedule,
                projector_inputs,
                client_input_commitment,
                server_input_commitment,
            },
        ));
        next
    }

    pub fn current_execution_checkpoint_digest(&self) -> Option<[u8; 32]> {
        match &self.execution_state {
            Some(ServerEvalExecutionState::MessageSchedule(state)) => {
                compute_message_schedule_completed_digest(&state.message_schedule).ok()
            }
            Some(ServerEvalExecutionState::RoundCore(state)) => {
                if state.round_core.rounds_completed == 0 {
                    Some(state.prior_execution_checkpoint_digest)
                } else {
                    compute_round_core_completed_digest(&state.round_core).ok()
                }
            }
            Some(ServerEvalExecutionState::OutputProjection(state)) => Some(
                compute_output_projection_continuation_digest(&state.projector_inputs),
            ),
            Some(ServerEvalExecutionState::Finalize(state)) => {
                Some(state.output.output_projection_digest())
            }
            None => None,
        }
    }

    pub fn prior_execution_checkpoint_digest(&self) -> Option<[u8; 32]> {
        match &self.execution_state {
            Some(ServerEvalExecutionState::MessageSchedule(state)) => {
                compute_message_schedule_completed_digest(&state.message_schedule).ok()
            }
            Some(ServerEvalExecutionState::RoundCore(state)) => {
                if state.round_core.rounds_completed == 0 {
                    Some(state.prior_execution_checkpoint_digest)
                } else {
                    compute_round_core_completed_digest(&state.round_core).ok()
                }
            }
            Some(ServerEvalExecutionState::OutputProjection(state)) => {
                Some(state.prior_execution_checkpoint_digest)
            }
            Some(ServerEvalExecutionState::Finalize(_)) | None => None,
        }
    }

    pub fn finalize_state(&self) -> Option<&ServerEvalFinalizeState> {
        match &self.execution_state {
            Some(ServerEvalExecutionState::MessageSchedule(_)) => None,
            Some(ServerEvalExecutionState::RoundCore(_)) => None,
            Some(ServerEvalExecutionState::OutputProjection(_)) => None,
            Some(ServerEvalExecutionState::Finalize(state)) => Some(state),
            None => None,
        }
    }

    pub fn stores_stage_local_continuation(&self) -> bool {
        self.execution_state.is_some()
    }

    pub fn relayer_roots(&self) -> Option<&ServerEvalRelayerRoots> {
        self.relayer_roots.as_ref()
    }

    pub fn retains_raw_relayer_roots(&self) -> bool {
        self.relayer_roots.is_some()
    }

    pub fn advance_after_add_stage(
        &self,
        next_transcript_digest: [u8; 32],
        request_digest: [u8; 32],
    ) -> Self {
        let mut next = self.clone();
        next.current_stage = ServerEvalStageId::message_schedule(0);
        next.current_transcript_digest = next_transcript_digest;
        next.status = ServerEvalStatus::InProgress;
        next.last_request_digest = Some(request_digest);
        next
    }

    pub fn advance_after_message_schedule(
        &self,
        next_transcript_digest: [u8; 32],
        request_digest: [u8; 32],
        next_message_schedule: Option<DdhHiddenEvalMessageScheduleContinuation>,
        next_round_core: Option<DdhHiddenEvalRoundCoreContinuation>,
    ) -> Self {
        let mut next = self.clone();
        let final_schedule_round =
            self.current_stage.ordinal + 1 >= ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS;
        next.execution_state = match (&self.execution_state, final_schedule_round) {
            (Some(ServerEvalExecutionState::MessageSchedule(state)), true) => Some(
                ServerEvalExecutionState::RoundCore(ServerEvalRoundCoreState {
                    prior_execution_checkpoint_digest: compute_message_schedule_completed_digest(
                        next_message_schedule
                            .as_ref()
                            .expect("final message-schedule transition requires next continuation"),
                    )
                    .unwrap_or(state.message_schedule.add_stage_digest),
                    round_core: next_round_core.expect(
                        "final message-schedule transition requires round-core continuation",
                    ),
                    projector_inputs: state.projector_inputs.clone(),
                    client_input_commitment: state.client_input_commitment,
                    server_input_commitment: state.server_input_commitment,
                }),
            ),
            (Some(ServerEvalExecutionState::MessageSchedule(state)), false) => Some(
                ServerEvalExecutionState::MessageSchedule(ServerEvalMessageScheduleState {
                    message_schedule: next_message_schedule
                        .expect("message-schedule transition requires next continuation"),
                    projector_inputs: state.projector_inputs.clone(),
                    client_input_commitment: state.client_input_commitment,
                    server_input_commitment: state.server_input_commitment,
                }),
            ),
            (other, _) => other.clone(),
        };
        next.current_stage = if final_schedule_round {
            ServerEvalStageId::round_core(0)
        } else {
            ServerEvalStageId::message_schedule(self.current_stage.ordinal + 1)
        };
        next.current_transcript_digest = next_transcript_digest;
        next.status = ServerEvalStatus::InProgress;
        next.last_request_digest = Some(request_digest);
        next
    }

    pub fn advance_after_round_core(
        &self,
        next_transcript_digest: [u8; 32],
        request_digest: [u8; 32],
        next_round_core: DdhHiddenEvalRoundCoreContinuation,
    ) -> Self {
        let mut next = self.clone();
        let final_round_core =
            self.current_stage.ordinal + 1 >= ServerEvalStageId::ROUND_CORE_ROUNDS;
        next.execution_state = match (&self.execution_state, final_round_core) {
            (Some(ServerEvalExecutionState::RoundCore(state)), true) => Some(
                ServerEvalExecutionState::OutputProjection(ServerEvalOutputProjectionState {
                    prior_execution_checkpoint_digest: compute_round_core_completed_digest(
                        &next_round_core,
                    )
                    .unwrap_or_else(|_| {
                        compute_output_projection_continuation_digest(&state.projector_inputs)
                    }),
                    round_core: next_round_core,
                    projector_inputs: state.projector_inputs.clone(),
                    client_input_commitment: state.client_input_commitment,
                    server_input_commitment: state.server_input_commitment,
                }),
            ),
            (Some(ServerEvalExecutionState::RoundCore(state)), false) => Some(
                ServerEvalExecutionState::RoundCore(ServerEvalRoundCoreState {
                    prior_execution_checkpoint_digest: state.prior_execution_checkpoint_digest,
                    round_core: next_round_core,
                    projector_inputs: state.projector_inputs.clone(),
                    client_input_commitment: state.client_input_commitment,
                    server_input_commitment: state.server_input_commitment,
                }),
            ),
            (other, _) => other.clone(),
        };
        next.current_stage = if final_round_core {
            ServerEvalStageId::output_projection()
        } else {
            ServerEvalStageId::round_core(self.current_stage.ordinal + 1)
        };
        next.current_transcript_digest = next_transcript_digest;
        next.status = ServerEvalStatus::InProgress;
        next.last_request_digest = Some(request_digest);
        next
    }

    pub fn advance_after_output_projection(
        &self,
        next_transcript_digest: [u8; 32],
        request_digest: [u8; 32],
        finalize: ServerEvalFinalizeState,
    ) -> Self {
        let mut next = self.clone();
        next.execution_state = match &self.execution_state {
            Some(ServerEvalExecutionState::OutputProjection(_)) => {
                Some(ServerEvalExecutionState::Finalize(finalize))
            }
            other => other.clone(),
        };
        next.current_stage = ServerEvalStageId::output_projection();
        next.current_transcript_digest = next_transcript_digest;
        next.status = ServerEvalStatus::Finalized;
        next.last_request_digest = Some(request_digest);
        next
    }
}
