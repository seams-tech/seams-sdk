use sha2::{Digest, Sha256};

use crate::client::ClientSession;
use crate::ddh::{DdhHssShareSide, HiddenEvalInputOwner};
use crate::server::ServerSession;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{ClientPacket, OtTranscript, ServerPacket};

pub(crate) fn validate_ot_transcript(
    expected_context_binding: [u8; 32],
    transcript: &OtTranscript,
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

pub(crate) fn validate_client_packet_context(
    expected_context_binding: [u8; 32],
    packet: &ClientPacket,
) -> ProtoResult<()> {
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

pub(crate) fn validate_garbler_server_packet(
    session: &ServerSession,
    packet: &ServerPacket,
) -> ProtoResult<()> {
    if packet.context_binding != session.context_binding {
        return Err(ProtoError::InvalidInput(
            "server delivery packet context binding does not match garbler session".to_string(),
        ));
    }
    validate_ot_transcript(packet.context_binding, &packet.ot_transcript)?;
    if packet.ot_transcript.y_client_offer_commitment
        != session.client_ot_offer.y_client_offer.commitment
        || packet.ot_transcript.tau_client_offer_commitment
            != session.client_ot_offer.tau_client_offer.commitment
    {
        return Err(ProtoError::InvalidInput(
            "server delivery packet OT transcript is not bound to the garbler session offer"
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
            "server delivery packet client OT remote-share releases must be owned by the client"
                .to_string(),
        ));
    }
    if packet.y_client_remote_release.label != "y_client_bits"
        || packet.tau_client_remote_release.label != "tau_client_bits"
    {
        return Err(ProtoError::InvalidInput(
            "server delivery packet client OT remote-share release labels are invalid".to_string(),
        ));
    }
    if packet.y_client_remote_release.context_binding != packet.context_binding
        || packet.tau_client_remote_release.context_binding != packet.context_binding
    {
        return Err(ProtoError::InvalidInput(
            "server delivery packet OT remote-share release context binding is invalid".to_string(),
        ));
    }
    if packet.y_client_remote_release.share_side != DdhHssShareSide::Right
        || packet.tau_client_remote_release.share_side != DdhHssShareSide::Right
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
    let opened_server_inputs = session.open_server_inputs_packet(&packet.server_inputs)?;
    let expected =
        opened_server_inputs.server_input_commitment(session.ddh_garbler.evaluation_key());
    if expected != packet.server_inputs.server_input_commitment {
        return Err(ProtoError::InvalidInput(
            "server delivery packet commitment is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_evaluator_server_packet(
    session: &ClientSession,
    packet: &ServerPacket,
) -> ProtoResult<()> {
    if packet.context_binding != session.context_binding {
        return Err(ProtoError::InvalidInput(
            "server delivery packet context binding does not match evaluator session".to_string(),
        ));
    }
    validate_ot_transcript(packet.context_binding, &packet.ot_transcript)?;
    if packet.ot_transcript.y_client_offer_commitment
        != session.client_ot_offer.y_client_offer.commitment
        || packet.ot_transcript.tau_client_offer_commitment
            != session.client_ot_offer.tau_client_offer.commitment
    {
        return Err(ProtoError::InvalidInput(
            "server delivery packet OT transcript is not bound to the evaluator offer".to_string(),
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
            "server delivery packet client OT remote-share release labels are invalid".to_string(),
        ));
    }
    if packet.y_client_remote_release.context_binding != packet.context_binding
        || packet.tau_client_remote_release.context_binding != packet.context_binding
    {
        return Err(ProtoError::InvalidInput(
            "server delivery packet OT remote-share release context binding is invalid".to_string(),
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
    let opened_server_inputs = session.open_server_inputs_packet(&packet.server_inputs)?;
    let expected =
        opened_server_inputs.server_input_commitment(session.ddh_evaluator.evaluation_key());
    if expected != packet.server_inputs.server_input_commitment {
        return Err(ProtoError::InvalidInput(
            "server delivery packet commitment is invalid".to_string(),
        ));
    }
    Ok(())
}
