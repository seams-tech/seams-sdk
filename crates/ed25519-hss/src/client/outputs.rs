use crate::ddh::{
    DdhHssEvaluator, DdhHssInputShareBundle, DdhHssTransportPurpose, HiddenEvalInputOwner,
};
use crate::server::ServerOutputOpener;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    deserialize_encoded_bundle_payload, ClientOutputPacket, ClientOutputValueKind,
    OutputProjectionMode, SeedOutputPacket, TransportKind, WireMessage,
};
use curve25519_dalek::scalar::Scalar;

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
            &packet,
            packet.nonce,
            &packet.ciphertext,
            ClientOutputValueKind::UnmaskedClientBase,
        )
    }

    pub fn open_masked(
        &self,
        message: &WireMessage,
        client_output_mask: [u8; 32],
    ) -> ProtoResult<[u8; 32]> {
        let packet: ClientOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOutput,
            message,
        )?;
        let expected_mask_commitment = crate::protocol::transcript::client_output_mask_commitment(
            packet.context_binding,
            packet.run_binding,
            packet.evaluation_digest,
            client_output_mask,
        );
        if packet.projection_mode
            != OutputProjectionMode::client_masked_projection(expected_mask_commitment)
        {
            return Err(ProtoError::InvalidInput(
                "client output projection mode does not match the provided mask".to_string(),
            ));
        }
        let blinded = decode_client_output_packet(
            &self.evaluator,
            self.context_binding,
            &packet,
            packet.nonce,
            &packet.ciphertext,
            ClientOutputValueKind::ClientBlindedBase,
        )?;
        let unmasked = Scalar::from_bytes_mod_order(blinded)
            - Scalar::from_bytes_mod_order(client_output_mask);
        Ok(unmasked.to_bytes())
    }
}

impl SeedOutputOpener {
    pub fn open(&self, message: &WireMessage) -> ProtoResult<[u8; 32]> {
        let packet: SeedOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::SeedOutput,
            message,
        )?;
        let aad = crate::protocol::transcript::output_packet_aad(
            b"seed_output",
            packet.context_binding,
            packet.run_binding,
            packet.evaluation_digest,
        );
        decode_client_output_payload(
            &self.evaluator,
            self.context_binding,
            packet.context_binding,
            packet.nonce,
            &packet.ciphertext,
            &aad,
            "canonical_seed",
        )
    }
}

fn decode_client_output_packet(
    evaluator: &DdhHssEvaluator,
    expected_context_binding: [u8; 32],
    packet: &ClientOutputPacket,
    nonce: [u8; 12],
    ciphertext: &[u8],
    expected_value_kind: ClientOutputValueKind,
) -> ProtoResult<[u8; 32]> {
    if packet.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "output packet context binding does not match opener".to_string(),
        ));
    }
    if packet.value_kind != expected_value_kind {
        return Err(ProtoError::InvalidInput(
            "client output packet value kind does not match opener".to_string(),
        ));
    }
    if expected_value_kind == ClientOutputValueKind::UnmaskedClientBase
        && packet.projection_mode != OutputProjectionMode::trusted_server_projection()
    {
        return Err(ProtoError::InvalidInput(
            "trusted client output opener requires trusted-server projection".to_string(),
        ));
    }
    let aad = crate::protocol::transcript::client_output_packet_aad(
        packet.context_binding,
        packet.run_binding,
        packet.evaluation_digest,
        &packet.projection_mode,
        packet.value_kind,
    );
    decode_client_output_payload(
        evaluator,
        expected_context_binding,
        packet.context_binding,
        nonce,
        ciphertext,
        &aad,
        expected_value_kind.bundle_label(),
    )
}

fn decode_client_output_payload(
    evaluator: &DdhHssEvaluator,
    expected_context_binding: [u8; 32],
    packet_context_binding: [u8; 32],
    nonce: [u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    if packet_context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "output packet context binding does not match opener".to_string(),
        ));
    }
    let plaintext =
        evaluator.open_message(DdhHssTransportPurpose::ClientOutput, aad, nonce, ciphertext)?;
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
