use crate::ddh::{
    DdhHssGarbler, DdhHssShareSide, DdhHssTransportBundle, DdhHssTransportPurpose,
    HiddenEvalInputOwner,
};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    deserialize_transport_pair_payload, ServerOutputPacket, TransportKind, WireMessage,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOutputOpener {
    pub(crate) garbler: DdhHssGarbler,
    pub(crate) context_binding: [u8; 32],
}

impl ServerOutputOpener {
    pub fn open(&self, message: &WireMessage) -> ProtoResult<[u8; 32]> {
        let packet: ServerOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerOutput,
            message,
        )?;
        decode_server_output_packet(
            &self.garbler,
            self.context_binding,
            packet.context_binding,
            packet.run_binding,
            packet.evaluation_digest,
            packet.nonce,
            &packet.ciphertext,
            "x_relayer_base",
        )
    }
}

fn decode_server_output_packet(
    garbler: &DdhHssGarbler,
    expected_context_binding: [u8; 32],
    packet_context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    nonce: [u8; 12],
    ciphertext: &[u8],
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if packet_context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "output packet context binding does not match opener".to_string(),
        ));
    }
    let aad = crate::protocol::transcript::output_packet_aad(
        b"server_output",
        packet_context_binding,
        run_binding,
        evaluation_digest,
    );
    let plaintext = garbler.open_message(
        DdhHssTransportPurpose::ServerOutput,
        &aad,
        nonce,
        ciphertext,
    )?;
    let (left, right): (DdhHssTransportBundle, DdhHssTransportBundle) =
        deserialize_transport_pair_payload(DdhHssTransportPurpose::ServerOutput, &plaintext)?;
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
            payload.owner,
            &payload.label,
            HiddenEvalInputOwner::Server,
            expected_label,
        )
    }
}

fn decode_bundle_array_from_words(
    decoded: Vec<u8>,
    bundle_owner: HiddenEvalInputOwner,
    bundle_label: &str,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if bundle_owner != expected_owner {
        return Err(ProtoError::InvalidInput(format!(
            "input bundle owner mismatch for {expected_label}: expected {:?}, got {:?}",
            expected_owner, bundle_owner
        )));
    }
    if bundle_label != expected_label {
        return Err(ProtoError::InvalidInput(format!(
            "input bundle label mismatch: expected {expected_label}, got {bundle_label}"
        )));
    }
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        ProtoError::Decode(format!(
            "decoded input bundle {expected_label} must be exactly 32 bytes, got {}",
            decoded.len()
        ))
    })
}
