use crate::client::{ClientOtState, ClientSession};
use crate::ddh::{DdhHssBackendVersion, DdhHssShareSide, HiddenEvalInputOwner};
use crate::server::{ServerEvalState, ServerEvalStatus};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    AddStageRequestPayload, AddStageResponsePayload, ClientPacket, ClientStagePayload,
    ClientStageRequestPacket, MessageScheduleRequestPayload, MessageScheduleResponsePayload,
    OutputProjectionRequestPayload, OutputProjectionResponsePayload, RoundCoreRequestPayload,
    RoundCoreResponsePayload, ServerAssistInitPacket, ServerStagePayload,
    ServerStageResponsePacket,
};

fn ensure_stage_request_state_is_live(state: &ServerEvalState, label: &str) -> ProtoResult<()> {
    match state.status {
        ServerEvalStatus::Pending | ServerEvalStatus::InProgress => Ok(()),
        ServerEvalStatus::Finalized => Err(ProtoError::InvalidInput(format!(
            "{label} cannot be accepted after the server eval handle is finalized"
        ))),
        ServerEvalStatus::Aborted => Err(ProtoError::InvalidInput(format!(
            "{label} cannot be accepted after the server eval handle is aborted"
        ))),
        ServerEvalStatus::Expired => Err(ProtoError::InvalidInput(format!(
            "{label} cannot be accepted after the server eval handle is expired"
        ))),
    }
}

pub(crate) fn validate_client_packet_context(
    expected_context_binding: [u8; 32],
    expected_backend_version: DdhHssBackendVersion,
    packet: &ClientPacket,
) -> ProtoResult<()> {
    if packet.backend_version != expected_backend_version {
        return Err(ProtoError::InvalidInput(
            "client delivery packet backend version does not match expected session".to_string(),
        ));
    }
    if packet.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "client delivery packet context binding does not match expected session".to_string(),
        ));
    }
    if packet.y_client_request.owner != HiddenEvalInputOwner::Client
        || packet.tau_client_request.owner != HiddenEvalInputOwner::Client
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

pub(crate) fn validate_server_assist_init_packet(
    session: &ClientSession,
    client_packet: &ClientPacket,
    evaluator_ot_state: &ClientOtState,
    packet: &ServerAssistInitPacket,
) -> ProtoResult<()> {
    validate_client_packet_context(
        session.context_binding,
        session.ddh_evaluator.evaluation_key().backend_version,
        client_packet,
    )?;
    if packet.context_binding != session.context_binding {
        return Err(ProtoError::InvalidInput(
            "server assist init packet context binding does not match evaluator session"
                .to_string(),
        ));
    }
    if packet.y_client_response.owner != HiddenEvalInputOwner::Client
        || packet.tau_client_response.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT responses must be client-owned".to_string(),
        ));
    }
    if packet.y_client_response.label != "y_client_bits"
        || packet.tau_client_response.label != "tau_client_bits"
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT response labels are invalid".to_string(),
        ));
    }
    if packet.y_client_remote_release.owner != HiddenEvalInputOwner::Client
        || packet.tau_client_remote_release.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT remote-share releases must be client-owned".to_string(),
        ));
    }
    if packet.y_client_remote_release.label != "y_client_bits"
        || packet.tau_client_remote_release.label != "tau_client_bits"
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT remote-share release labels are invalid".to_string(),
        ));
    }
    if packet.y_client_remote_release.context_binding != packet.context_binding
        || packet.tau_client_remote_release.context_binding != packet.context_binding
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT remote-share release context binding is invalid".to_string(),
        ));
    }
    if packet.y_client_remote_release.share_side != DdhHssShareSide::Right
        || packet.tau_client_remote_release.share_side != DdhHssShareSide::Right
    {
        return Err(ProtoError::InvalidInput(
            "server assist init client OT remote-share releases must carry right-side shares"
                .to_string(),
        ));
    }
    if packet.y_client_remote_release.request_commitment
        != client_packet.y_client_request.commitment
        || packet.tau_client_remote_release.request_commitment
            != client_packet.tau_client_request.commitment
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT remote-share releases are not bound to the request transcript"
                .to_string(),
        ));
    }
    if packet.y_client_remote_release.response_commitment != packet.y_client_response.commitment
        || packet.tau_client_remote_release.response_commitment
            != packet.tau_client_response.commitment
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT remote-share releases are not bound to the response transcript"
                .to_string(),
        ));
    }
    if packet.y_client_remote_release.offer_commitment
        != evaluator_ot_state
            .offer_commitments
            .y_client_offer_commitment
        || packet.tau_client_remote_release.offer_commitment
            != evaluator_ot_state
                .offer_commitments
                .tau_client_offer_commitment
    {
        return Err(ProtoError::InvalidInput(
            "server assist init OT remote-share releases are not bound to the evaluator offer"
                .to_string(),
        ));
    }
    let transcript_digest =
        crate::protocol::transcript::compute_ot_transcript_digest_from_commitments(
            packet.context_binding,
            evaluator_ot_state
                .offer_commitments
                .y_client_offer_commitment,
            client_packet.y_client_request.commitment,
            packet.y_client_response.commitment,
            packet.y_client_remote_release.transcript_binding,
            evaluator_ot_state
                .offer_commitments
                .tau_client_offer_commitment,
            client_packet.tau_client_request.commitment,
            packet.tau_client_response.commitment,
            packet.tau_client_remote_release.transcript_binding,
        );
    let expected_transcript_id =
        crate::protocol::transcript::derive_server_assist_transcript_id_from_digest(
            packet.context_binding,
            transcript_digest,
            packet.server_input_commitment,
        );
    if packet.transcript_id != expected_transcript_id {
        return Err(ProtoError::InvalidInput(
            "server assist init transcript id is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_add_stage_request_packet(
    state: &ServerEvalState,
    packet: &ClientStageRequestPacket,
) -> ProtoResult<()> {
    ensure_stage_request_state_is_live(state, "add-stage request")?;
    if packet.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "client stage request context binding does not match server eval state".to_string(),
        ));
    }
    if packet.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "client stage request handle does not match server eval state".to_string(),
        ));
    }
    if packet.stage_id != state.current_stage {
        return Err(ProtoError::InvalidInput(
            "client stage request stage id does not match server eval state".to_string(),
        ));
    }
    if packet.prior_transcript_digest != state.current_transcript_digest {
        return Err(ProtoError::InvalidInput(
            "client stage request transcript digest does not match server eval state".to_string(),
        ));
    }
    let ClientStagePayload::AddStage(AddStageRequestPayload {
        client_input_commitment,
        client_stage_openings_digest,
        ..
    }) = &packet.client_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "client stage request payload must be add-stage for the add-stage round".to_string(),
        ));
    };
    if packet.client_stage_commitments.digests.len() < 2 {
        return Err(ProtoError::InvalidInput(
            "client stage request commitments must include add-stage digests".to_string(),
        ));
    }
    if packet.client_stage_commitments.digests[0] != *client_input_commitment
        || packet.client_stage_commitments.digests[1] != *client_stage_openings_digest
    {
        return Err(ProtoError::InvalidInput(
            "client stage request commitments are not bound to the add-stage payload".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_add_stage_response_packet(
    state: &ServerEvalState,
    request: &ClientStageRequestPacket,
    response: &ServerStageResponsePacket,
) -> ProtoResult<()> {
    if response.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "server stage response context binding does not match server eval state".to_string(),
        ));
    }
    if response.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "server stage response handle does not match server eval state".to_string(),
        ));
    }
    if response.stage_id != request.stage_id {
        return Err(ProtoError::InvalidInput(
            "server stage response stage id does not match the request".to_string(),
        ));
    }
    let ServerStagePayload::AddStage(AddStageResponsePayload {
        server_input_commitment,
        server_stage_digest,
        execution_checkpoint_digest,
        ..
    }) = &response.server_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "server stage response payload must be add-stage for the add-stage round".to_string(),
        ));
    };
    if *server_input_commitment != state.server_input_commitment {
        return Err(ProtoError::InvalidInput(
            "server stage response server input commitment does not match server eval state"
                .to_string(),
        ));
    }
    if response.next_transcript_digest != *server_stage_digest {
        return Err(ProtoError::InvalidInput(
            "server stage response next transcript digest does not match add-stage payload"
                .to_string(),
        ));
    }
    if response.server_stage_commitments.digests.len() < 3 {
        return Err(ProtoError::InvalidInput(
            "server stage response commitments must include add-stage digests".to_string(),
        ));
    }
    if response.server_stage_commitments.digests[0] != *server_input_commitment
        || response.server_stage_commitments.digests[1] != *server_stage_digest
        || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
    {
        return Err(ProtoError::InvalidInput(
            "server stage response commitments are not bound to the add-stage payload".to_string(),
        ));
    }
    if let Some(expected_execution_digest) = state.current_execution_checkpoint_digest() {
        if *execution_checkpoint_digest != expected_execution_digest {
            return Err(ProtoError::InvalidInput(
                "server stage response add-stage checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_message_schedule_request_packet(
    state: &ServerEvalState,
    packet: &ClientStageRequestPacket,
) -> ProtoResult<()> {
    ensure_stage_request_state_is_live(state, "message-schedule request")?;
    if packet.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "message-schedule request context binding does not match server eval state".to_string(),
        ));
    }
    if packet.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "message-schedule request handle does not match server eval state".to_string(),
        ));
    }
    if packet.stage_id != state.current_stage {
        return Err(ProtoError::InvalidInput(
            "message-schedule request stage id does not match server eval state".to_string(),
        ));
    }
    if packet.prior_transcript_digest != state.current_transcript_digest {
        return Err(ProtoError::InvalidInput(
            "message-schedule request transcript digest does not match server eval state"
                .to_string(),
        ));
    }
    let ClientStagePayload::MessageSchedule(MessageScheduleRequestPayload {
        schedule_step,
        client_schedule_digest,
        prior_server_stage_digest,
    }) = &packet.client_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "client stage request payload must be message-schedule for the message-schedule round"
                .to_string(),
        ));
    };
    if *schedule_step != packet.stage_id.ordinal {
        return Err(ProtoError::InvalidInput(
            "message-schedule request step does not match the stage ordinal".to_string(),
        ));
    }
    if packet.client_stage_commitments.digests.len() < 2 {
        return Err(ProtoError::InvalidInput(
            "message-schedule request commitments must include schedule digests".to_string(),
        ));
    }
    if packet.client_stage_commitments.digests[0] != *client_schedule_digest
        || packet.client_stage_commitments.digests[1] != *prior_server_stage_digest
    {
        return Err(ProtoError::InvalidInput(
            "message-schedule request commitments are not bound to the message-schedule payload"
                .to_string(),
        ));
    }
    if let Some(expected_prior_execution_digest) = state.prior_execution_checkpoint_digest() {
        if *prior_server_stage_digest != expected_prior_execution_digest {
            return Err(ProtoError::InvalidInput(
                "message-schedule request prior execution checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_message_schedule_response_packet(
    state: &ServerEvalState,
    request: &ClientStageRequestPacket,
    response: &ServerStageResponsePacket,
) -> ProtoResult<()> {
    if response.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "message-schedule response context binding does not match server eval state"
                .to_string(),
        ));
    }
    if response.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "message-schedule response handle does not match server eval state".to_string(),
        ));
    }
    if response.stage_id != request.stage_id {
        return Err(ProtoError::InvalidInput(
            "message-schedule response stage id does not match the request".to_string(),
        ));
    }
    let ServerStagePayload::MessageSchedule(MessageScheduleResponsePayload {
        schedule_step,
        server_schedule_digest,
        next_stage_token,
        execution_checkpoint_digest,
    }) = &response.server_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "server stage response payload must be message-schedule for the message-schedule round"
                .to_string(),
        ));
    };
    if *schedule_step != response.stage_id.ordinal {
        return Err(ProtoError::InvalidInput(
            "message-schedule response step does not match the stage ordinal".to_string(),
        ));
    }
    if response.next_transcript_digest != *server_schedule_digest {
        return Err(ProtoError::InvalidInput(
            "message-schedule response next transcript digest does not match the payload digest"
                .to_string(),
        ));
    }
    if response.server_stage_commitments.digests.len() < 3 {
        return Err(ProtoError::InvalidInput(
            "message-schedule response commitments must include schedule digests".to_string(),
        ));
    }
    if response.server_stage_commitments.digests[0] != *server_schedule_digest
        || response.server_stage_commitments.digests[1] != *next_stage_token
        || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
    {
        return Err(ProtoError::InvalidInput(
            "message-schedule response commitments are not bound to the message-schedule payload"
                .to_string(),
        ));
    }
    if let Some(expected_execution_digest) = state.current_execution_checkpoint_digest() {
        if *execution_checkpoint_digest != expected_execution_digest {
            return Err(ProtoError::InvalidInput(
                "message-schedule response execution checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_round_core_request_packet(
    state: &ServerEvalState,
    packet: &ClientStageRequestPacket,
) -> ProtoResult<()> {
    ensure_stage_request_state_is_live(state, "round-core request")?;
    if packet.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "round-core request context binding does not match server eval state".to_string(),
        ));
    }
    if packet.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "round-core request handle does not match server eval state".to_string(),
        ));
    }
    if packet.stage_id != state.current_stage {
        return Err(ProtoError::InvalidInput(
            "round-core request stage id does not match server eval state".to_string(),
        ));
    }
    if packet.prior_transcript_digest != state.current_transcript_digest {
        return Err(ProtoError::InvalidInput(
            "round-core request transcript digest does not match server eval state".to_string(),
        ));
    }
    let ClientStagePayload::RoundCore(RoundCoreRequestPayload {
        round_index,
        client_round_digest,
        prior_server_stage_digest,
    }) = &packet.client_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "client stage request payload must be round-core for the round-core round".to_string(),
        ));
    };
    if *round_index != packet.stage_id.ordinal {
        return Err(ProtoError::InvalidInput(
            "round-core request index does not match the stage ordinal".to_string(),
        ));
    }
    if packet.client_stage_commitments.digests.len() < 2 {
        return Err(ProtoError::InvalidInput(
            "round-core request commitments must include round digests".to_string(),
        ));
    }
    if packet.client_stage_commitments.digests[0] != *client_round_digest
        || packet.client_stage_commitments.digests[1] != *prior_server_stage_digest
    {
        return Err(ProtoError::InvalidInput(
            "round-core request commitments are not bound to the round-core payload".to_string(),
        ));
    }
    if let Some(current_execution_digest) = state.current_execution_checkpoint_digest() {
        let expected_prior_execution_digest = if *round_index == 0 {
            state
                .prior_execution_checkpoint_digest()
                .unwrap_or(current_execution_digest)
        } else {
            current_execution_digest
        };
        if *prior_server_stage_digest != expected_prior_execution_digest {
            return Err(ProtoError::InvalidInput(
                "round-core request prior execution checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_round_core_response_packet(
    state: &ServerEvalState,
    request: &ClientStageRequestPacket,
    response: &ServerStageResponsePacket,
) -> ProtoResult<()> {
    if response.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "round-core response context binding does not match server eval state".to_string(),
        ));
    }
    if response.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "round-core response handle does not match server eval state".to_string(),
        ));
    }
    if response.stage_id != request.stage_id {
        return Err(ProtoError::InvalidInput(
            "round-core response stage id does not match the request".to_string(),
        ));
    }
    let ServerStagePayload::RoundCore(RoundCoreResponsePayload {
        round_index,
        server_round_digest,
        next_stage_token,
        execution_checkpoint_digest,
    }) = &response.server_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "server stage response payload must be round-core for the round-core round".to_string(),
        ));
    };
    if *round_index != response.stage_id.ordinal {
        return Err(ProtoError::InvalidInput(
            "round-core response index does not match the stage ordinal".to_string(),
        ));
    }
    if response.next_transcript_digest != *server_round_digest {
        return Err(ProtoError::InvalidInput(
            "round-core response next transcript digest does not match the payload digest"
                .to_string(),
        ));
    }
    if response.server_stage_commitments.digests.len() < 3 {
        return Err(ProtoError::InvalidInput(
            "round-core response commitments must include round digests".to_string(),
        ));
    }
    if response.server_stage_commitments.digests[0] != *server_round_digest
        || response.server_stage_commitments.digests[1] != *next_stage_token
        || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
    {
        return Err(ProtoError::InvalidInput(
            "round-core response commitments are not bound to the round-core payload".to_string(),
        ));
    }
    let expected_execution_digest =
        if state.current_stage == crate::wire::ServerEvalStageId::output_projection() {
            state.prior_execution_checkpoint_digest()
        } else {
            state.current_execution_checkpoint_digest()
        };
    if let Some(expected_execution_digest) = expected_execution_digest {
        if *execution_checkpoint_digest != expected_execution_digest {
            return Err(ProtoError::InvalidInput(
                "round-core response execution checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_output_projection_request_packet(
    state: &ServerEvalState,
    packet: &ClientStageRequestPacket,
) -> ProtoResult<()> {
    ensure_stage_request_state_is_live(state, "output-projection request")?;
    if packet.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "output-projection request context binding does not match server eval state"
                .to_string(),
        ));
    }
    if packet.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "output-projection request handle does not match server eval state".to_string(),
        ));
    }
    if packet.stage_id != state.current_stage {
        return Err(ProtoError::InvalidInput(
            "output-projection request stage id does not match server eval state".to_string(),
        ));
    }
    if packet.prior_transcript_digest != state.current_transcript_digest {
        return Err(ProtoError::InvalidInput(
            "output-projection request transcript digest does not match server eval state"
                .to_string(),
        ));
    }
    let ClientStagePayload::OutputProjection(OutputProjectionRequestPayload {
        final_client_digest,
        prior_server_stage_digest,
        projection_mode,
    }) = &packet.client_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "client stage request payload must be output-projection for the output-projection round"
                .to_string(),
        ));
    };
    if packet.client_stage_commitments.digests.len() < 3 {
        return Err(ProtoError::InvalidInput(
            "output-projection request commitments must include final projection digests"
                .to_string(),
        ));
    }
    if packet.client_stage_commitments.digests[0] != *final_client_digest
        || packet.client_stage_commitments.digests[1] != *prior_server_stage_digest
        || packet.client_stage_commitments.digests[2]
            != crate::protocol::transcript::digest_output_projection_mode(projection_mode)
    {
        return Err(ProtoError::InvalidInput(
            "output-projection request commitments are not bound to the output-projection payload"
                .to_string(),
        ));
    }
    if let Some(expected_prior_execution_digest) = state.prior_execution_checkpoint_digest() {
        if *prior_server_stage_digest != expected_prior_execution_digest {
            return Err(ProtoError::InvalidInput(
                "output-projection request prior execution checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_output_projection_response_packet(
    state: &ServerEvalState,
    request: &ClientStageRequestPacket,
    response: &ServerStageResponsePacket,
) -> ProtoResult<()> {
    if response.context_binding != state.context_binding {
        return Err(ProtoError::InvalidInput(
            "output-projection response context binding does not match server eval state"
                .to_string(),
        ));
    }
    if response.server_eval_handle != state.handle {
        return Err(ProtoError::InvalidInput(
            "output-projection response handle does not match server eval state".to_string(),
        ));
    }
    if response.stage_id != request.stage_id {
        return Err(ProtoError::InvalidInput(
            "output-projection response stage id does not match the request".to_string(),
        ));
    }
    let ServerStagePayload::OutputProjection(OutputProjectionResponsePayload {
        final_server_digest,
        output_release_token,
        projection_mode,
        execution_checkpoint_digest,
        ..
    }) = &response.server_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "server stage response payload must be output-projection for the output-projection round"
                .to_string(),
        ));
    };
    if response.next_transcript_digest != *final_server_digest {
        return Err(ProtoError::InvalidInput(
            "output-projection response next transcript digest does not match the payload digest"
                .to_string(),
        ));
    }
    let ClientStagePayload::OutputProjection(OutputProjectionRequestPayload {
        projection_mode: request_projection_mode,
        ..
    }) = &request.client_stage_payload
    else {
        return Err(ProtoError::InvalidInput(
            "client stage request payload must be output-projection for the output-projection round"
                .to_string(),
        ));
    };
    if projection_mode != request_projection_mode {
        return Err(ProtoError::InvalidInput(
            "output-projection response projection mode does not match the request".to_string(),
        ));
    }
    if response.server_stage_commitments.digests.len() < 4 {
        return Err(ProtoError::InvalidInput(
            "output-projection response commitments must include final projection digests"
                .to_string(),
        ));
    }
    if response.server_stage_commitments.digests[0] != *final_server_digest
        || response.server_stage_commitments.digests[1] != *output_release_token
        || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
        || response.server_stage_commitments.digests[3]
            != crate::protocol::transcript::digest_output_projection_mode(projection_mode)
    {
        return Err(ProtoError::InvalidInput(
            "output-projection response commitments are not bound to the output-projection payload"
                .to_string(),
        ));
    }
    if let Some(expected_execution_digest) = state.current_execution_checkpoint_digest() {
        if *execution_checkpoint_digest != expected_execution_digest {
            return Err(ProtoError::InvalidInput(
                "output-projection response execution checkpoint digest does not match server eval state"
                    .to_string(),
            ));
        }
    }
    Ok(())
}
