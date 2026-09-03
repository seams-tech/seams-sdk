use core::fmt;

use futures::StreamExt;
use router_ab_ed25519_yao::duplex::{YaoDuplexTransport, YaoInboundEvent, YaoTransportCompletion};
use router_ab_ed25519_yao::relay::{
    DirectionalEofEvidence, DirectionalWireDecoder, DirectionalWireEncoder, WireDirection,
    WireMessage,
};
use worker::{Env, EventStream, Method, Request, WebSocket, WebsocketEvent};
use zeroize::Zeroizing;

use crate::set_cloudflare_internal_service_auth_header_v1;
use router_ab_core::{
    Ed25519YaoDeriverAToBTargetProofPayloadV2, Ed25519YaoDeriverBToATargetProofPayloadV2,
    Ed25519YaoExecutionIdV1, Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleStartAcceptanceV1,
    ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2,
};

const DERIVER_B_BINDING: &str = "DERIVER_B";
const DERIVER_B_WEBSOCKET_URL: &str =
    "https://deriver-b.internal/router-ab/deriver-b/ed25519-yao/duplex";
const PAIR_WEBSOCKET_PROTOCOL_PREFIX: &str = "seams-ed25519-yao-p1-v1";
pub(crate) const READINESS_RECEIPT_HEADER: &str = "x-seams-yao-readiness-receipt";
pub(crate) const EXECUTION_ID_HEADER: &str = "x-seams-yao-execution-id";
pub(crate) const START_ACCEPTANCE_HEADER: &str = "x-seams-yao-start-acceptance";
const DIRECTIONAL_EOF: &[u8] = b"seams-ed25519-yao-directional-eof-v1";
const SEALED_COMPLETION_PREFIX: &[u8] = b"seams-ed25519-yao-sealed-completion-v1:";
const MAX_SEALED_COMPLETION_BYTES: usize = 1_048_576;

/// Fixed Yao circuit family selected before the WebSocket upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareEd25519YaoCircuitV1 {
    /// Registration, recovery, and refresh activation circuit.
    Activation,
    /// Explicit Ed25519 seed export circuit.
    Export,
    /// Recipient-isolated lane-materialization circuit.
    LaneMaterialization,
}

impl CloudflareEd25519YaoCircuitV1 {
    const fn protocol_label(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::Export => "export",
            Self::LaneMaterialization => "lane-materialization",
        }
    }

    fn parse(value: &str) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        match value {
            "activation" => Ok(Self::Activation),
            "export" => Ok(Self::Export),
            "lane-materialization" => Ok(Self::LaneMaterialization),
            _ => Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol),
        }
    }
}

/// Exact session and circuit identity authenticated by the WebSocket protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudflareEd25519YaoWebSocketBindingV1 {
    /// Fixed circuit selected for this ceremony.
    pub circuit: CloudflareEd25519YaoCircuitV1,
    /// Non-zero Router-admitted ceremony session.
    pub session: [u8; 32],
    /// Canonical A/B input-pair digest.
    pub pair_digest: [u8; 32],
}

impl CloudflareEd25519YaoWebSocketBindingV1 {
    /// Creates a pair-bound protocol binding for the Refactor 93 lifecycle.
    pub fn with_pair_digest(
        circuit: CloudflareEd25519YaoCircuitV1,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        if session.iter().all(|byte| *byte == 0) || pair_digest.iter().all(|byte| *byte == 0) {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol);
        }
        Ok(Self {
            circuit,
            session,
            pair_digest,
        })
    }

    /// Encodes the binding as a WebSocket subprotocol token.
    pub fn protocol(self) -> String {
        format!(
            "{PAIR_WEBSOCKET_PROTOCOL_PREFIX}.{}.{}.{}",
            self.circuit.protocol_label(),
            encode_hex(self.session),
            encode_hex(self.pair_digest)
        )
    }

    /// Parses and validates one WebSocket subprotocol token.
    pub fn parse_protocol(protocol: &str) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        let mut parts = protocol.split('.');
        let prefix = parts
            .next()
            .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
        let circuit = parts
            .next()
            .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
        let session = parts
            .next()
            .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
        let pair_digest = parts.next();
        let circuit = CloudflareEd25519YaoCircuitV1::parse(circuit)?;
        let session = decode_hex_32(session)?;
        match (prefix, pair_digest, parts.next()) {
            (PAIR_WEBSOCKET_PROTOCOL_PREFIX, Some(pair_digest), None) => {
                Self::with_pair_digest(circuit, session, decode_hex_32(pair_digest)?)
            }
            _ => Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol),
        }
    }
}

/// Service Binding WebSocket transport failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareEd25519YaoWebSocketErrorV1 {
    /// The binding, upgrade, or negotiated subprotocol is invalid.
    InvalidProtocol,
    /// The Deriver B Service Binding is absent or rejected the upgrade.
    ServiceBinding,
    /// A WebSocket event has an invalid shape or close state.
    WebSocketEvent,
    /// A directional envelope is malformed.
    Envelope,
    /// The transport state was already consumed.
    InvalidState,
}

impl fmt::Display for CloudflareEd25519YaoWebSocketErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProtocol => "invalid Ed25519 Yao WebSocket protocol binding",
            Self::ServiceBinding => "Ed25519 Yao Deriver B Service Binding failed",
            Self::WebSocketEvent => "Ed25519 Yao WebSocket event failed",
            Self::Envelope => "invalid Ed25519 Yao directional envelope",
            Self::InvalidState => "invalid Ed25519 Yao WebSocket transport state",
        })
    }
}

/// Clean WebSocket teardown evidence.
pub struct CloudflareEd25519YaoWebSocketCompletionV1 {
    /// Opaque peer-sealed execution delivered after authenticated protocol EOF.
    pub peer_sealed_completion: Option<Vec<u8>>,
}

impl YaoTransportCompletion for CloudflareEd25519YaoWebSocketCompletionV1 {}

/// Pair-bound WebSocket connection carrying B's signed start acceptance.
pub struct CloudflareEd25519YaoPairStartConnectionV1 {
    /// Upgraded directional socket.
    pub socket: WebSocket,
    /// Acceptance signed after B durably entered Running.
    pub acceptance: Ed25519YaoRoleStartAcceptanceV1,
}

/// Opens a pair-bound WebSocket and requires B's signed start acceptance.
pub async fn connect_cloudflare_ed25519_yao_deriver_b_with_start_acceptance_v1(
    env: &Env,
    binding: CloudflareEd25519YaoWebSocketBindingV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    readiness_receipt: &Ed25519YaoRoleReadinessReceiptV1,
    execution_id: Ed25519YaoExecutionIdV1,
) -> Result<CloudflareEd25519YaoPairStartConnectionV1, CloudflareEd25519YaoWebSocketErrorV1> {
    let (socket, acceptance) = connect_cloudflare_ed25519_yao_deriver_b_inner_v1(
        env,
        binding,
        trace_id,
        readiness_receipt,
        execution_id,
    )
    .await?;
    Ok(CloudflareEd25519YaoPairStartConnectionV1 { socket, acceptance })
}

async fn connect_cloudflare_ed25519_yao_deriver_b_inner_v1(
    env: &Env,
    binding: CloudflareEd25519YaoWebSocketBindingV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    readiness_receipt: &Ed25519YaoRoleReadinessReceiptV1,
    execution_id: Ed25519YaoExecutionIdV1,
) -> Result<(WebSocket, Ed25519YaoRoleStartAcceptanceV1), CloudflareEd25519YaoWebSocketErrorV1> {
    if binding.pair_digest.iter().all(|byte| *byte == 0) {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol);
    }
    let protocol = binding.protocol();
    let mut request = Request::new(DERIVER_B_WEBSOCKET_URL, Method::Get)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    let headers = request
        .headers_mut()
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    headers
        .set("Upgrade", "websocket")
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    headers
        .set("Sec-WebSocket-Protocol", &protocol)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    let serialized = serde_json::to_string(readiness_receipt)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
    headers
        .set(READINESS_RECEIPT_HEADER, &serialized)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    headers
        .set(EXECUTION_ID_HEADER, &encode_hex(execution_id.into_bytes()))
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    set_cloudflare_internal_service_auth_header_v1(
        env,
        headers,
        "Ed25519 Yao Deriver A to B WebSocket",
    )
    .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    if let Some(trace_id) = trace_id {
        crate::set_cloudflare_trace_id_header_v1(headers, trace_id)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    }
    let response = env
        .service(DERIVER_B_BINDING)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?
        .fetch_request(request)
        .await
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
    if response.status_code() != 101 {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding);
    }
    let negotiated = response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?
        .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
    if negotiated != protocol {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol);
    }
    let serialized = response
        .headers()
        .get(START_ACCEPTANCE_HEADER)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?
        .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
    let acceptance = serde_json::from_str::<Ed25519YaoRoleStartAcceptanceV1>(&serialized)
        .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)?;
    response
        .websocket()
        .ok_or(CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)
        .map(|socket| (socket, acceptance))
}

/// Canonical directional WebSocket adapter for one fixed Yao role.
pub struct CloudflareEd25519YaoWebSocketTransportV1<'socket> {
    socket: &'socket WebSocket,
    events: EventStream<'socket>,
    encoder: Option<DirectionalWireEncoder>,
    decoder: Option<DirectionalWireDecoder>,
    side: CloudflareEd25519YaoWebSocketSideV1,
    phase: CloudflareEd25519YaoWebSocketPhaseV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloudflareEd25519YaoWebSocketSideV1 {
    DeriverA,
    DeriverB,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloudflareEd25519YaoWebSocketPhaseV1 {
    Initial,
    PrefaceComplete,
    YaoStarted,
}

impl<'socket> CloudflareEd25519YaoWebSocketTransportV1<'socket> {
    /// Creates the Deriver A side of the fixed duplex channel.
    pub fn deriver_a(
        socket: &'socket WebSocket,
        session: [u8; 32],
    ) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        Self::new(
            socket,
            session,
            WireDirection::DeriverAToDeriverB,
            WireDirection::DeriverBToDeriverA,
            CloudflareEd25519YaoWebSocketSideV1::DeriverA,
        )
    }

    /// Creates the Deriver B side of the fixed duplex channel.
    pub fn deriver_b(
        socket: &'socket WebSocket,
        session: [u8; 32],
    ) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        Self::new(
            socket,
            session,
            WireDirection::DeriverBToDeriverA,
            WireDirection::DeriverAToDeriverB,
            CloudflareEd25519YaoWebSocketSideV1::DeriverB,
        )
    }

    fn new(
        socket: &'socket WebSocket,
        session: [u8; 32],
        outbound: WireDirection,
        inbound: WireDirection,
        side: CloudflareEd25519YaoWebSocketSideV1,
    ) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        socket
            .as_ref()
            .set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
        let events = socket
            .events()
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        socket
            .accept()
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        Ok(Self {
            socket,
            events,
            encoder: Some(
                DirectionalWireEncoder::new(outbound, session)
                    .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?,
            ),
            decoder: Some(
                DirectionalWireDecoder::new(inbound, session)
                    .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?,
            ),
            side,
            phase: CloudflareEd25519YaoWebSocketPhaseV1::Initial,
        })
    }

    /// Sends A's encrypted target proof and receives B's proof before Yao starts.
    pub async fn exchange_deriver_a_target_proof_preface_v2(
        &mut self,
        payload: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
    ) -> Result<Ed25519YaoDeriverBToATargetProofPayloadV2, CloudflareEd25519YaoWebSocketErrorV1>
    {
        if self.side != CloudflareEd25519YaoWebSocketSideV1::DeriverA
            || self.phase != CloudflareEd25519YaoWebSocketPhaseV1::Initial
        {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState);
        }
        let wire = Zeroizing::new(
            payload
                .encode_fixed_wire()
                .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?,
        );
        validate_preface_wire(&wire)?;
        let peer_wire = self.send_preface_and_receive_peer(&wire).await?;
        let peer_payload = Ed25519YaoDeriverBToATargetProofPayloadV2::decode_fixed_wire(&peer_wire)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?;
        self.phase = CloudflareEd25519YaoWebSocketPhaseV1::PrefaceComplete;
        Ok(peer_payload)
    }

    /// Sends B's encrypted target proof and receives A's proof before Yao starts.
    pub async fn exchange_deriver_b_target_proof_preface_v2(
        &mut self,
        payload: &Ed25519YaoDeriverBToATargetProofPayloadV2,
    ) -> Result<Ed25519YaoDeriverAToBTargetProofPayloadV2, CloudflareEd25519YaoWebSocketErrorV1>
    {
        if self.side != CloudflareEd25519YaoWebSocketSideV1::DeriverB
            || self.phase != CloudflareEd25519YaoWebSocketPhaseV1::Initial
        {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState);
        }
        let wire = Zeroizing::new(
            payload
                .encode_fixed_wire()
                .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?,
        );
        validate_preface_wire(&wire)?;
        let peer_wire = self.send_preface_and_receive_peer(&wire).await?;
        let peer_payload = Ed25519YaoDeriverAToBTargetProofPayloadV2::decode_fixed_wire(&peer_wire)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?;
        self.phase = CloudflareEd25519YaoWebSocketPhaseV1::PrefaceComplete;
        Ok(peer_payload)
    }

    async fn send_preface_and_receive_peer(
        &mut self,
        wire: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CloudflareEd25519YaoWebSocketErrorV1> {
        self.socket
            .send_with_bytes(wire)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        read_preface_wire(&mut self.events).await
    }

    fn require_target_preface(&mut self) -> Result<(), CloudflareEd25519YaoWebSocketErrorV1> {
        match self.phase {
            CloudflareEd25519YaoWebSocketPhaseV1::PrefaceComplete => {
                self.phase = CloudflareEd25519YaoWebSocketPhaseV1::YaoStarted;
                Ok(())
            }
            CloudflareEd25519YaoWebSocketPhaseV1::YaoStarted => Ok(()),
            CloudflareEd25519YaoWebSocketPhaseV1::Initial => {
                Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState)
            }
        }
    }

    /// Delivers B's durably committed sealed result before closing the socket.
    pub async fn finish_with_local_sealed_completion(
        self,
        sealed_completion: &[u8],
    ) -> Result<CloudflareEd25519YaoWebSocketCompletionV1, CloudflareEd25519YaoWebSocketErrorV1>
    {
        if self.side != CloudflareEd25519YaoWebSocketSideV1::DeriverB
            || self.phase != CloudflareEd25519YaoWebSocketPhaseV1::YaoStarted
            || self.encoder.is_some()
            || self.decoder.is_some()
            || sealed_completion.is_empty()
            || sealed_completion.len() > MAX_SEALED_COMPLETION_BYTES
        {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState);
        }
        let mut frame = Zeroizing::new(Vec::with_capacity(
            SEALED_COMPLETION_PREFIX.len() + sealed_completion.len(),
        ));
        frame.extend_from_slice(SEALED_COMPLETION_PREFIX);
        frame.extend_from_slice(sealed_completion);
        self.socket
            .send_with_bytes(&frame)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        self.socket
            .close(Some(1000), Some("complete"))
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        Ok(CloudflareEd25519YaoWebSocketCompletionV1 {
            peer_sealed_completion: None,
        })
    }

    fn decode_message(
        &mut self,
        bytes: &[u8],
    ) -> Result<YaoInboundEvent, CloudflareEd25519YaoWebSocketErrorV1> {
        if bytes == DIRECTIONAL_EOF {
            let evidence = self
                .decoder
                .take()
                .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidState)?
                .finish_at_transport_eof()
                .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?;
            return Ok(YaoInboundEvent::DirectionalEof(evidence));
        }
        if bytes.is_empty() {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
        }
        let decoder = self
            .decoder
            .as_mut()
            .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidState)?;
        let mut offset = 0;
        while offset < bytes.len() {
            let consumed = decoder
                .push(&bytes[offset..])
                .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?;
            if consumed == 0 {
                return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
            }
            offset += consumed;
        }
        let message = decoder
            .take_message()
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?
            .ok_or(CloudflareEd25519YaoWebSocketErrorV1::Envelope)?;
        if decoder
            .take_message()
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?
            .is_some()
        {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
        }
        Ok(YaoInboundEvent::Message(message))
    }
}

impl YaoDuplexTransport for CloudflareEd25519YaoWebSocketTransportV1<'_> {
    type Error = CloudflareEd25519YaoWebSocketErrorV1;
    type Completion = CloudflareEd25519YaoWebSocketCompletionV1;

    async fn send(&mut self, message: WireMessage) -> Result<Option<YaoInboundEvent>, Self::Error> {
        self.require_target_preface()?;
        let envelope = Zeroizing::new(
            self.encoder
                .as_mut()
                .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidState)?
                .encode(message)
                .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?,
        );
        self.socket
            .send_with_bytes(&envelope)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        Ok(None)
    }

    async fn receive(&mut self) -> Result<YaoInboundEvent, Self::Error> {
        self.require_target_preface()?;
        match self.events.next().await {
            Some(Ok(WebsocketEvent::Message(message))) => {
                let data = message.as_ref().data();
                if !data.is_object() {
                    return Err(CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent);
                }
                let array = worker::js_sys::Uint8Array::new(&data);
                let mut bytes = Zeroizing::new(vec![0_u8; array.length() as usize]);
                array.copy_to(bytes.as_mut_slice());
                array.fill(0, 0, array.length());
                self.decode_message(&bytes)
            }
            Some(Ok(WebsocketEvent::Close(close)))
                if close.was_clean() && close.code() == 1000 && self.decoder.is_none() =>
            {
                Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState)
            }
            _ => Err(CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent),
        }
    }

    async fn close_local_direction(
        &mut self,
    ) -> Result<(DirectionalEofEvidence, Option<YaoInboundEvent>), Self::Error> {
        self.require_target_preface()?;
        let evidence = self
            .encoder
            .take()
            .ok_or(CloudflareEd25519YaoWebSocketErrorV1::InvalidState)?
            .finish_after_transport_close()
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::Envelope)?;
        self.socket
            .send_with_bytes(DIRECTIONAL_EOF)
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        Ok((evidence, None))
    }

    async fn finish(mut self) -> Result<Self::Completion, Self::Error> {
        if self.phase != CloudflareEd25519YaoWebSocketPhaseV1::YaoStarted
            || self.encoder.is_some()
            || self.decoder.is_some()
        {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState);
        }
        let peer_sealed_completion = if self.side == CloudflareEd25519YaoWebSocketSideV1::DeriverA {
            Some(read_sealed_completion(&mut self.events).await?)
        } else {
            None
        };
        self.socket
            .close(Some(1000), Some("complete"))
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        Ok(CloudflareEd25519YaoWebSocketCompletionV1 {
            peer_sealed_completion,
        })
    }
}

fn validate_preface_wire(wire: &[u8]) -> Result<(), CloudflareEd25519YaoWebSocketErrorV1> {
    if wire.is_empty() || wire.len() > ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2 {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
    }
    Ok(())
}

async fn read_preface_wire(
    events: &mut EventStream<'_>,
) -> Result<Zeroizing<Vec<u8>>, CloudflareEd25519YaoWebSocketErrorV1> {
    let Some(Ok(WebsocketEvent::Message(message))) = events.next().await else {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent);
    };
    let data = message.as_ref().data();
    if !data.is_object() {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent);
    }
    let array = worker::js_sys::Uint8Array::new(&data);
    let frame_len = array.length() as usize;
    if frame_len == 0 || frame_len > ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2 {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
    }
    let mut frame = Zeroizing::new(vec![0_u8; frame_len]);
    array.copy_to(frame.as_mut_slice());
    array.fill(0, 0, array.length());
    Ok(frame)
}

async fn read_sealed_completion(
    events: &mut EventStream<'_>,
) -> Result<Vec<u8>, CloudflareEd25519YaoWebSocketErrorV1> {
    let Some(Ok(WebsocketEvent::Message(message))) = events.next().await else {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent);
    };
    let data = message.as_ref().data();
    if !data.is_object() {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent);
    }
    let array = worker::js_sys::Uint8Array::new(&data);
    let frame_len = array.length() as usize;
    if frame_len <= SEALED_COMPLETION_PREFIX.len()
        || frame_len > SEALED_COMPLETION_PREFIX.len() + MAX_SEALED_COMPLETION_BYTES
    {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
    }
    let mut frame = Zeroizing::new(vec![0_u8; frame_len]);
    array.copy_to(frame.as_mut_slice());
    array.fill(0, 0, array.length());
    if !frame.starts_with(SEALED_COMPLETION_PREFIX) {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::Envelope);
    }
    Ok(frame[SEALED_COMPLETION_PREFIX.len()..].to_vec())
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], CloudflareEd25519YaoWebSocketErrorV1> {
    if value.len() != 64 {
        return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol);
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let high = decode_nibble(value.as_bytes()[index * 2])?;
        let low = decode_nibble(value.as_bytes()[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, CloudflareEd25519YaoWebSocketErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CloudflareEd25519YaoCircuitV1, CloudflareEd25519YaoWebSocketBindingV1,
        CloudflareEd25519YaoWebSocketErrorV1,
    };

    #[test]
    fn pair_bound_protocol_round_trips_pair_digest() {
        let binding = CloudflareEd25519YaoWebSocketBindingV1::with_pair_digest(
            CloudflareEd25519YaoCircuitV1::Activation,
            [7_u8; 32],
            [8_u8; 32],
        )
        .unwrap();
        assert_eq!(
            CloudflareEd25519YaoWebSocketBindingV1::parse_protocol(&binding.protocol()).unwrap(),
            binding
        );
    }

    #[test]
    fn protocol_binding_rejects_zero_session_and_unknown_circuit() {
        assert_eq!(
            CloudflareEd25519YaoWebSocketBindingV1::with_pair_digest(
                CloudflareEd25519YaoCircuitV1::Export,
                [0_u8; 32],
                [8_u8; 32],
            ),
            Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)
        );
        assert_eq!(
            CloudflareEd25519YaoWebSocketBindingV1::parse_protocol(
                "seams-ed25519-yao-p1-v1.other.0707070707070707070707070707070707070707070707070707070707070707.0808080808080808080808080808080808080808080808080808080808080808"
            ),
            Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)
        );
    }
}
