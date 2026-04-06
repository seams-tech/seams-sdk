use serde::{Deserialize, Serialize};

use crate::ddh::DdhHiddenEvalRun;
use crate::ddh::ddh_hss::DdhHssPreparedOtSenderStateWord;
use crate::ddh::{DdhHssGarbler, DdhHssOtRemoteBundle, DdhHssOtSenderStateBundle};
use crate::runtime::SharedRuntimeState;
use crate::wire::{ClientOtOffer, OtTranscript, ServerEvalHandle, ServerEvalStageId, TranscriptId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOtState {
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
pub struct ServerEvalExecutionCheckpoints {
    pub add_stage_digest: [u8; 32],
    pub message_schedule_digest: [u8; 32],
    pub round_core_digest: [u8; 32],
    pub output_projection_digest: [u8; 32],
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
    pub relayer_roots: ServerEvalRelayerRoots,
    pub execution_checkpoints: Option<ServerEvalExecutionCheckpoints>,
    pub execution_run: Option<DdhHiddenEvalRun>,
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
            relayer_roots,
            execution_checkpoints: None,
            execution_run: None,
        }
    }

    pub fn with_execution_materialization(
        &self,
        execution_checkpoints: ServerEvalExecutionCheckpoints,
        execution_run: DdhHiddenEvalRun,
    ) -> Self {
        let mut next = self.clone();
        next.execution_checkpoints = Some(execution_checkpoints);
        next.execution_run = Some(execution_run);
        next
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
    ) -> Self {
        let mut next = self.clone();
        next.current_stage =
            if self.current_stage.ordinal + 1 >= ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
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
    ) -> Self {
        let mut next = self.clone();
        next.current_stage =
            if self.current_stage.ordinal + 1 >= ServerEvalStageId::ROUND_CORE_ROUNDS {
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
    ) -> Self {
        let mut next = self.clone();
        next.current_stage = ServerEvalStageId::output_projection();
        next.current_transcript_digest = next_transcript_digest;
        next.status = ServerEvalStatus::Finalized;
        next.last_request_digest = Some(request_digest);
        next
    }
}
