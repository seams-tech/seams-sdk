use sha2::{Digest, Sha256};

use crate::ddh::{
    DdhHiddenEvalOutputBundles, DdhHssOtReleasedRemoteBundle, DdhHssOtResponseBundle,
};
use crate::runtime::PrimeOrderCpuExecutionResult;
use crate::wire::{ClientOtOffer, ClientPacket, OtTranscript};

pub(crate) fn build_ot_transcript(
    context_binding: [u8; 32],
    client_ot_offer: &ClientOtOffer,
    client_packet: &ClientPacket,
    y_client_response: &DdhHssOtResponseBundle,
    tau_client_response: &DdhHssOtResponseBundle,
    y_client_remote_release: &DdhHssOtReleasedRemoteBundle,
    tau_client_remote_release: &DdhHssOtReleasedRemoteBundle,
) -> OtTranscript {
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

pub(crate) fn compute_evaluation_digest(
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
    hasher.update(output.canonical_seed.commitment);
    hasher.update(output.x_client_base.commitment);
    hasher.update(output.x_relayer_base_left.commitment);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn server_output_payload_binding(
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
