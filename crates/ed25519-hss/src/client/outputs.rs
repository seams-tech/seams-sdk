use crate::ddh::{
    DdhHssEvaluator, DdhHssInputShareBundle, DdhHssTransportPurpose, HiddenEvalInputOwner,
};
use crate::server::ServerOutputOpener;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    deserialize_encoded_bundle_payload, ClientOutputPacket, SeedOutputPacket, TransportKind,
    WireMessage,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOutputOpener {
    pub(crate) evaluator: DdhHssEvaluator,
    pub(crate) context_binding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedOutputOpener {
    pub(crate) evaluator: DdhHssEvaluator,
    pub(crate) context_binding: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputOpeners {
    pub client: ClientOutputOpener,
    pub seed: SeedOutputOpener,
    pub server: ServerOutputOpener,
}

impl ClientOutputOpener {
    pub fn open(&self, message: &WireMessage) -> ProtoResult<[u8; 32]> {
        let packet: ClientOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOutput,
            message,
        )?;
        decode_client_output_packet(
            &self.evaluator,
            self.context_binding,
            packet.context_binding,
            packet.run_binding,
            packet.evaluation_digest,
            packet.nonce,
            &packet.ciphertext,
            b"client_output",
            "x_client_base",
        )
    }
}

impl SeedOutputOpener {
    pub fn open(&self, message: &WireMessage) -> ProtoResult<[u8; 32]> {
        let packet: SeedOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::SeedOutput,
            message,
        )?;
        decode_client_output_packet(
            &self.evaluator,
            self.context_binding,
            packet.context_binding,
            packet.run_binding,
            packet.evaluation_digest,
            packet.nonce,
            &packet.ciphertext,
            b"seed_output",
            "canonical_seed",
        )
    }
}

fn decode_client_output_packet(
    evaluator: &DdhHssEvaluator,
    expected_context_binding: [u8; 32],
    packet_context_binding: [u8; 32],
    run_binding: [u8; 32],
    evaluation_digest: [u8; 32],
    nonce: [u8; 12],
    ciphertext: &[u8],
    purpose_tag: &[u8],
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if packet_context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "output packet context binding does not match opener".to_string(),
        ));
    }
    let aad = crate::protocol::transcript::output_packet_aad(
        purpose_tag,
        packet_context_binding,
        run_binding,
        evaluation_digest,
    );
    let plaintext = evaluator.open_message(
        DdhHssTransportPurpose::ClientOutput,
        &aad,
        nonce,
        ciphertext,
    )?;
    let payload =
        deserialize_encoded_bundle_payload(DdhHssTransportPurpose::ClientOutput, &plaintext)?;
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
