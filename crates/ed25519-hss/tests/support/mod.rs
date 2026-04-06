use ed25519_hss::artifact::PrimeOrderEncodedArtifact;
use ed25519_hss::artifact::PrimeOrderSectionKind;
use ed25519_hss::ddh::ddh_hss::role_views_for_backend;
use ed25519_hss::ddh::{
    DdhHssBackend, DdhHssTransportBundle, DdhHssTransportPurpose, FixedFunctionHssBackend,
    HiddenEvalInputOwner,
};
use ed25519_hss::fixtures::{committed_fixture_corpus, FExpandFixture};
use ed25519_hss::protocol::PreparedSession;
use ed25519_hss::shared::{ProtoError, ProtoResult};
use ed25519_hss::wire::{
    ClientOtOffer, ClientOutputPacket, ClientPacket, WireMessage,
    PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    ClientOtOffer,
    ClientOtRequest,
    ServerAssistInit,
    ClientStageRequest,
    ServerStageResponse,
    ServerFinalize,
    ServerPacket,
    ClientOutput,
    SeedOutput,
    ServerOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TransportFrame {
    report_version: String,
    context_binding: [u8; 32],
    kind: TransportKind,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EncodedServerInputsPayload {
    y_relayer_left: DdhHssTransportBundle,
    y_relayer_right: DdhHssTransportBundle,
    tau_relayer_left: DdhHssTransportBundle,
    tau_relayer_right: DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ServerInputsPacket {
    context_binding: [u8; 32],
    server_input_commitment: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ServerPacket {
    context_binding: [u8; 32],
    ot_transcript: serde_json::Value,
    y_client_response: serde_json::Value,
    tau_client_response: serde_json::Value,
    y_client_remote_release: serde_json::Value,
    tau_client_remote_release: serde_json::Value,
    server_inputs: ServerInputsPacket,
}

pub fn first_fixture() -> FExpandFixture {
    committed_fixture_corpus()
        .expect("fixture corpus")
        .into_iter()
        .next()
        .expect("fixture")
}

pub fn section_bytes<'a>(
    artifact: &PrimeOrderEncodedArtifact,
    bytes: &'a [u8],
    kind: PrimeOrderSectionKind,
) -> &'a [u8] {
    let section = artifact
        .sections
        .iter()
        .find(|section| section.kind == kind)
        .expect("section present");
    let start = usize::try_from(section.offset_bytes).expect("offset fits usize");
    let end = start + usize::try_from(section.length_bytes).expect("length fits usize");
    &bytes[start..end]
}

pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

pub fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn decode_transport_message<T: DeserializeOwned>(
    expected_context_binding: [u8; 32],
    expected_kind: TransportKind,
    message: &WireMessage,
) -> ProtoResult<T> {
    let frame: TransportFrame = bincode::deserialize(&message.bytes).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode prime-order succinct HSS transport frame for {:?}: {err}",
            expected_kind
        ))
    })?;
    if frame.report_version != PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS transport frame version mismatch: {}",
            frame.report_version
        )));
    }
    if frame.context_binding != expected_context_binding {
        return Err(ProtoError::InvalidInput(
            "prime-order succinct HSS transport frame context binding does not match the runtime"
                .to_string(),
        ));
    }
    if frame.kind != expected_kind {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order succinct HSS transport frame kind mismatch: expected {:?}, got {:?}",
            expected_kind, frame.kind
        )));
    }
    bincode::deserialize(&frame.payload).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode transport payload for {:?}: {err}",
            expected_kind
        ))
    })
}

pub fn encode_transport_message<T: Serialize>(
    context_binding: [u8; 32],
    kind: TransportKind,
    payload: &T,
) -> ProtoResult<WireMessage> {
    let frame = TransportFrame {
        report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
        context_binding,
        kind,
        payload: bincode::serialize(payload).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to serialize transport payload for {:?}: {err}",
                kind
            ))
        })?,
    };
    let bytes = bincode::serialize(&frame).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize prime-order succinct HSS transport frame for {:?}: {err}",
            kind
        ))
    })?;
    Ok(WireMessage { bytes })
}

pub fn decode_client_offer(
    context_binding: [u8; 32],
    message: &WireMessage,
) -> ProtoResult<ClientOtOffer> {
    decode_transport_message(context_binding, TransportKind::ClientOtOffer, message)
}

pub fn decode_client_request(
    context_binding: [u8; 32],
    message: &WireMessage,
) -> ProtoResult<ClientPacket> {
    decode_transport_message(context_binding, TransportKind::ClientOtRequest, message)
}

pub fn decode_client_output_message(
    context_binding: [u8; 32],
    message: &WireMessage,
) -> ProtoResult<ClientOutputPacket> {
    decode_transport_message(context_binding, TransportKind::ClientOutput, message)
}

pub fn decode_server_input_delivery(
    session: &PreparedSession,
    server_message: &WireMessage,
) -> ProtoResult<([u8; 32], [u8; 32])> {
    let payload = open_server_inputs_payload(session, server_message)?;
    Ok((
        decode_transport_bundle_bits(
            session.ddh_backend(),
            &payload.y_relayer_left,
            &payload.y_relayer_right,
            HiddenEvalInputOwner::Server,
            "y_relayer_bits",
        )?,
        decode_transport_bundle_bits(
            session.ddh_backend(),
            &payload.tau_relayer_left,
            &payload.tau_relayer_right,
            HiddenEvalInputOwner::Server,
            "tau_relayer_bits",
        )?,
    ))
}

fn open_server_inputs_payload(
    session: &PreparedSession,
    server_message: &WireMessage,
) -> ProtoResult<EncodedServerInputsPayload> {
    let context_binding = session.candidate().context_binding;
    let server_packet: ServerPacket =
        decode_transport_message(context_binding, TransportKind::ServerPacket, server_message)?;
    open_server_inputs_packet(session.ddh_backend(), &server_packet.server_inputs)
}

fn open_server_inputs_packet(
    backend: &DdhHssBackend,
    packet: &ServerInputsPacket,
) -> ProtoResult<EncodedServerInputsPayload> {
    let roles = role_views_for_backend(backend);
    let aad = server_input_packet_aad(packet.context_binding, packet.server_input_commitment);
    let plaintext = roles.garbler.open_message(
        DdhHssTransportPurpose::ServerInput,
        &aad,
        packet.nonce,
        &packet.ciphertext,
    )?;
    bincode::deserialize(&plaintext).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode server input transport payload: {err}"
        ))
    })
}

fn decode_transport_bundle_bits(
    backend: &DdhHssBackend,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
    expected_owner: HiddenEvalInputOwner,
    expected_label: &str,
) -> ProtoResult<[u8; 32]> {
    let bundle = backend.join_share_bundle(left, right)?;
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
    bits_to_byte_array(backend.decode_words(&bundle.words)?)
}

fn bits_to_byte_array(bits: Vec<u8>) -> ProtoResult<[u8; 32]> {
    if bits.len() != 256 {
        return Err(ProtoError::Decode(format!(
            "expected 256 decoded bits, got {}",
            bits.len()
        )));
    }

    let mut out = [0u8; 32];
    for (idx, bit) in bits.into_iter().enumerate() {
        if bit > 1 {
            return Err(ProtoError::Decode(format!(
                "decoded bit value must be 0 or 1, got {bit}"
            )));
        }
        out[idx / 8] |= bit << (idx % 8);
    }
    Ok(out)
}

fn server_input_packet_aad(
    context_binding: [u8; 32],
    server_input_commitment: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(12 + 32 + 32);
    aad.extend_from_slice(b"server_input");
    aad.extend_from_slice(&context_binding);
    aad.extend_from_slice(&server_input_commitment);
    aad
}
