use sha2::{Digest, Sha256};

use crate::ddh::{
    DdhHiddenEvalOutputBundles, DdhHssOtReleasedRemoteBundle, DdhHssOtResponseBundle,
    DdhHssShareSide, DdhHssTransportBundle, HiddenEvalInputOwner,
};
use crate::runtime::PrimeOrderCpuExecutionResult;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    ClientOtOffer, ClientOutputValueKind, ClientPacket, ClientStageRequestPacket, OtTranscript,
    OutputProjectionMode, OutputProjectorBinding, OutputProjectorBindingKind,
    OutputProjectorModulusId, ServerEvalHandle, ServerEvalStageId, TranscriptId,
};

fn bind_output_projection_mode(hasher: &mut Sha256, projection_mode: &OutputProjectionMode) {
    hasher.update(projection_mode.domain_tag());
    if let Some(mask_commitment) = projection_mode.mask_commitment() {
        hasher.update(mask_commitment);
    }
}

fn bind_output_projector_binding(hasher: &mut Sha256, binding: OutputProjectorBinding) {
    hasher.update(match binding.kind {
        OutputProjectorBindingKind::BindingV1 => b"binding_v1".as_slice(),
    });
    hasher.update(binding.scalar_width_bits.to_le_bytes());
    hasher.update(match binding.modulus_id {
        OutputProjectorModulusId::Ed25519L => b"ed25519_l".as_slice(),
    });
    hasher.update(binding.binding_digest);
}

pub(crate) fn digest_output_projection_mode(projection_mode: &OutputProjectionMode) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/projection-mode/v0");
    bind_output_projection_mode(&mut hasher, projection_mode);
    hasher.finalize().into()
}

pub(crate) fn compute_ot_transcript_digest_from_commitments(
    context_binding: [u8; 32],
    y_client_offer_commitment: [u8; 32],
    y_client_request_commitment: [u8; 32],
    y_client_response_commitment: [u8; 32],
    y_client_remote_release_binding: [u8; 32],
    tau_client_offer_commitment: [u8; 32],
    tau_client_request_commitment: [u8; 32],
    tau_client_response_commitment: [u8; 32],
    tau_client_remote_release_binding: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/ot-transcript/v0");
    hasher.update(context_binding);
    hasher.update(y_client_offer_commitment);
    hasher.update(y_client_request_commitment);
    hasher.update(y_client_response_commitment);
    hasher.update(y_client_remote_release_binding);
    hasher.update(tau_client_offer_commitment);
    hasher.update(tau_client_request_commitment);
    hasher.update(tau_client_response_commitment);
    hasher.update(tau_client_remote_release_binding);
    let digest = hasher.finalize();
    let mut transcript_digest = [0u8; 32];
    transcript_digest.copy_from_slice(&digest);
    transcript_digest
}

pub(crate) fn build_ot_transcript(
    context_binding: [u8; 32],
    client_ot_offer: &ClientOtOffer,
    client_packet: &ClientPacket,
    y_client_response: &DdhHssOtResponseBundle,
    tau_client_response: &DdhHssOtResponseBundle,
    y_client_remote_release: &DdhHssOtReleasedRemoteBundle,
    tau_client_remote_release: &DdhHssOtReleasedRemoteBundle,
) -> OtTranscript {
    let transcript_digest = compute_ot_transcript_digest_from_commitments(
        context_binding,
        client_ot_offer.y_client_offer.commitment,
        client_packet.y_client_request.commitment,
        y_client_response.commitment,
        y_client_remote_release.transcript_binding,
        client_ot_offer.tau_client_offer.commitment,
        client_packet.tau_client_request.commitment,
        tau_client_response.commitment,
        tau_client_remote_release.transcript_binding,
    );

    OtTranscript {
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

pub(crate) fn derive_server_assist_transcript_id(
    context_binding: [u8; 32],
    ot_transcript: &OtTranscript,
    server_input_commitment: [u8; 32],
) -> TranscriptId {
    derive_server_assist_transcript_id_from_digest(
        context_binding,
        ot_transcript.transcript_digest,
        server_input_commitment,
    )
}

pub(crate) fn derive_server_assist_transcript_id_from_digest(
    context_binding: [u8; 32],
    ot_transcript_digest: [u8; 32],
    server_input_commitment: [u8; 32],
) -> TranscriptId {
    let mut hasher = Sha256::new();
    hasher
        .update(b"succinct-garbling-proto/prime-order-succinct-hss/server-assist-transcript-id/v0");
    hasher.update(context_binding);
    hasher.update(ot_transcript_digest);
    hasher.update(server_input_commitment);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    TranscriptId { bytes }
}

pub(crate) fn derive_server_stage_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    transcript_id: TranscriptId,
    stage_id: ServerEvalStageId,
    server_input_commitment: [u8; 32],
    ot_transcript: &OtTranscript,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/server-stage-digest/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(transcript_id.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(server_input_commitment);
    hasher.update(ot_transcript.transcript_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn derive_server_stage_digest_from_ot_transcript_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    transcript_id: TranscriptId,
    stage_id: ServerEvalStageId,
    server_input_commitment: [u8; 32],
    ot_transcript_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/server-stage-digest/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(transcript_id.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(server_input_commitment);
    hasher.update(ot_transcript_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_add_stage_openings_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    client_stage_nonce: [u8; 16],
    client_input_commitment: [u8; 32],
    y_client_commitment: [u8; 32],
    tau_client_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/add-stage-request/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(client_stage_nonce);
    hasher.update(client_input_commitment);
    hasher.update(y_client_commitment);
    hasher.update(tau_client_commitment);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_client_stage_request_digest(
    packet: &ClientStageRequestPacket,
) -> crate::shared::ProtoResult<[u8; 32]> {
    let payload_bytes = bincode::serialize(&(
        &packet.stage_id,
        &packet.prior_transcript_digest,
        &packet.client_stage_payload,
        &packet.client_stage_commitments,
    ))
    .map_err(|err| {
        crate::shared::ProtoError::Decode(format!(
            "failed to serialize client stage request payload for digest: {err}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher
        .update(b"succinct-garbling-proto/prime-order-succinct-hss/client-stage-request-digest/v0");
    hasher.update(packet.context_binding);
    hasher.update(packet.server_eval_handle.bytes);
    hasher.update(payload_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub(crate) fn compute_add_stage_response_token(
    server_eval_handle: ServerEvalHandle,
    transcript_id: TranscriptId,
    stage_id: ServerEvalStageId,
    prior_transcript_digest: [u8; 32],
    request_digest: [u8; 32],
    server_input_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/add-stage-response-token/v0");
    hasher.update(server_eval_handle.bytes);
    hasher.update(transcript_id.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_transcript_digest);
    hasher.update(request_digest);
    hasher.update(server_input_commitment);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_add_stage_response_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    prior_transcript_digest: [u8; 32],
    server_input_commitment: [u8; 32],
    server_stage_token: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/add-stage-response-digest/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_transcript_digest);
    hasher.update(server_input_commitment);
    hasher.update(server_stage_token);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_message_schedule_request_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    schedule_step: u16,
    prior_server_stage_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/message-schedule-request/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(schedule_step.to_le_bytes());
    hasher.update(prior_server_stage_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_message_schedule_response_token(
    server_eval_handle: ServerEvalHandle,
    transcript_id: TranscriptId,
    stage_id: ServerEvalStageId,
    prior_transcript_digest: [u8; 32],
    request_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        b"succinct-garbling-proto/prime-order-succinct-hss/message-schedule-response-token/v0",
    );
    hasher.update(server_eval_handle.bytes);
    hasher.update(transcript_id.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_transcript_digest);
    hasher.update(request_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_message_schedule_response_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    schedule_step: u16,
    prior_server_stage_digest: [u8; 32],
    next_stage_token: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/message-schedule-response/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(schedule_step.to_le_bytes());
    hasher.update(prior_server_stage_digest);
    hasher.update(next_stage_token);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_round_core_request_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    round_index: u16,
    prior_server_stage_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/round-core-request/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(round_index.to_le_bytes());
    hasher.update(prior_server_stage_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_round_core_response_token(
    server_eval_handle: ServerEvalHandle,
    transcript_id: TranscriptId,
    stage_id: ServerEvalStageId,
    prior_transcript_digest: [u8; 32],
    request_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/round-core-response-token/v0");
    hasher.update(server_eval_handle.bytes);
    hasher.update(transcript_id.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_transcript_digest);
    hasher.update(request_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_round_core_response_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    round_index: u16,
    prior_server_stage_digest: [u8; 32],
    next_stage_token: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/round-core-response/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(round_index.to_le_bytes());
    hasher.update(prior_server_stage_digest);
    hasher.update(next_stage_token);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_output_projection_request_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    prior_server_stage_digest: [u8; 32],
    projection_mode: &OutputProjectionMode,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/output-projection-request/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_server_stage_digest);
    bind_output_projection_mode(&mut hasher, projection_mode);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_output_projection_response_token(
    server_eval_handle: ServerEvalHandle,
    transcript_id: TranscriptId,
    stage_id: ServerEvalStageId,
    prior_transcript_digest: [u8; 32],
    request_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        b"succinct-garbling-proto/prime-order-succinct-hss/output-projection-response-token/v0",
    );
    hasher.update(server_eval_handle.bytes);
    hasher.update(transcript_id.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_transcript_digest);
    hasher.update(request_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn compute_output_projection_response_digest(
    context_binding: [u8; 32],
    server_eval_handle: ServerEvalHandle,
    stage_id: ServerEvalStageId,
    prior_server_stage_digest: [u8; 32],
    output_release_token: [u8; 32],
    allowed_output_kind: crate::wire::AllowedOutputKind,
    projection_mode: &OutputProjectionMode,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher
        .update(b"succinct-garbling-proto/prime-order-succinct-hss/output-projection-response/v0");
    hasher.update(context_binding);
    hasher.update(server_eval_handle.bytes);
    hasher.update(match stage_id.kind {
        crate::wire::ServerEvalStageKind::AddStage => [0u8],
        crate::wire::ServerEvalStageKind::MessageSchedule => [1u8],
        crate::wire::ServerEvalStageKind::RoundCore => [2u8],
        crate::wire::ServerEvalStageKind::OutputProjection => [3u8],
    });
    hasher.update(stage_id.ordinal.to_le_bytes());
    hasher.update(prior_server_stage_digest);
    hasher.update(output_release_token);
    hasher.update(match allowed_output_kind {
        crate::wire::AllowedOutputKind::ClientOutputOnly => [0u8],
        crate::wire::AllowedOutputKind::ClientOutputAndSeedOutput => [1u8],
    });
    bind_output_projection_mode(&mut hasher, projection_mode);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn client_output_mask_commitment(
    context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    client_output_mask: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/client-output-mask/v0");
    hasher.update(context_binding);
    hasher.update(run_binding);
    hasher.update(evaluation_digest);
    hasher.update(client_output_mask);
    hasher.finalize().into()
}

pub(crate) fn client_output_packet_aad(
    context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    projection_mode: &OutputProjectionMode,
    value_kind: ClientOutputValueKind,
) -> Vec<u8> {
    let mut aad = output_packet_aad(
        b"client_output",
        context_binding,
        run_binding,
        evaluation_digest,
    );
    aad.extend_from_slice(b"/projection/");
    aad.extend_from_slice(projection_mode.domain_tag());
    if let Some(mask_commitment) = projection_mode.mask_commitment() {
        aad.extend_from_slice(&mask_commitment);
    }
    aad.extend_from_slice(b"/value-kind/");
    aad.extend_from_slice(value_kind.domain_tag());
    aad
}

pub(crate) fn output_packet_aad(
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

pub(crate) fn server_input_packet_aad(
    context_binding: [u8; 32],
    server_input_commitment: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(12 + 32 + 32);
    aad.extend_from_slice(b"server_input");
    aad.extend_from_slice(&context_binding);
    aad.extend_from_slice(&server_input_commitment);
    aad
}

pub(crate) fn server_output_value_commitment(
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<[u8; 32]> {
    if left.owner != HiddenEvalInputOwner::Server || right.owner != HiddenEvalInputOwner::Server {
        return Err(ProtoError::InvalidInput(
            "server output transport bundles must be server-owned".to_string(),
        ));
    }
    if left.label != "x_server_base" || right.label != "x_server_base" {
        return Err(ProtoError::InvalidInput(
            "server output transport bundles must carry x_server_base".to_string(),
        ));
    }
    if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
        return Err(ProtoError::InvalidInput(
            "server output transport bundles must be left/right".to_string(),
        ));
    }
    if left.words.len() != 256 || right.words.len() != 256 {
        return Err(ProtoError::InvalidInput(
            "server output transport bundles must contain 256 bits".to_string(),
        ));
    }
    let mut value = [0u8; 32];
    for (bit_idx, (left_word, right_word)) in left.words.iter().zip(&right.words).enumerate() {
        let joined = crate::ddh::ddh_hss::join_transport_word_pair_public(
            left.owner,
            right.owner,
            left_word,
            right_word,
        )?;
        if joined.width_bits != 1 {
            return Err(ProtoError::InvalidInput(
                "server output transport words must be 1-bit".to_string(),
            ));
        }
        let bit = ((joined.left_word + joined.right_word) & 1) as u8;
        value[bit_idx / 8] |= bit << (bit_idx % 8);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/server-output-value/v0");
    hasher.update(match left.owner {
        HiddenEvalInputOwner::Client => b"client".as_slice(),
        HiddenEvalInputOwner::Server => b"server".as_slice(),
        HiddenEvalInputOwner::Derived => b"derived".as_slice(),
    });
    hasher.update(left.label.as_bytes());
    hasher.update(value);
    Ok(hasher.finalize().into())
}

pub(crate) fn compute_evaluation_digest(
    artifact_digest: [u8; 32],
    run_binding: [u8; 32],
    executor_result: &PrimeOrderCpuExecutionResult,
    output: &DdhHiddenEvalOutputBundles,
) -> ProtoResult<[u8; 32]> {
    Ok(compute_evaluation_digest_from_output_commitments(
        artifact_digest,
        run_binding,
        executor_result,
        output.canonical_seed.commitment,
        output.client_output.value_kind,
        output.client_output.as_bundle().commitment,
        server_output_value_commitment(&output.x_server_base_left, &output.x_server_base_right)?,
        output.output_projector_binding,
    ))
}

pub(crate) fn compute_evaluation_digest_from_output_commitments(
    artifact_digest: [u8; 32],
    run_binding: [u8; 32],
    executor_result: &PrimeOrderCpuExecutionResult,
    canonical_seed_commitment: [u8; 32],
    client_output_value_kind: ClientOutputValueKind,
    client_output_commitment: [u8; 32],
    server_output_value_commitment: [u8; 32],
    output_projector_binding: OutputProjectorBinding,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/prime-order-succinct-hss/evaluation-digest/v0");
    hasher.update(artifact_digest);
    hasher.update(run_binding);
    hasher.update(executor_result.output_checksum.to_le_bytes());
    hasher.update(executor_result.final_point_compressed);
    hasher.update(canonical_seed_commitment);
    hasher.update(client_output_value_kind.domain_tag());
    hasher.update(client_output_commitment);
    hasher.update(server_output_value_commitment);
    bind_output_projector_binding(&mut hasher, output_projector_binding);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn nested_output_message_binding(
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
