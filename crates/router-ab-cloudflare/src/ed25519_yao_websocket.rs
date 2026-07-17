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

const DERIVER_B_BINDING: &str = "DERIVER_B";
const DERIVER_B_WEBSOCKET_URL: &str =
    "https://deriver-b.internal/router-ab/deriver-b/ed25519-yao/duplex";
const WEBSOCKET_PROTOCOL_PREFIX: &str = "seams-ed25519-yao-p0-v1";
const DIRECTIONAL_EOF: &[u8] = b"seams-ed25519-yao-directional-eof-v1";

/// Fixed Yao circuit family selected before the WebSocket upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareEd25519YaoCircuitV1 {
    /// Registration, recovery, and refresh activation circuit.
    Activation,
    /// Explicit Ed25519 seed export circuit.
    Export,
}

impl CloudflareEd25519YaoCircuitV1 {
    const fn protocol_label(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::Export => "export",
        }
    }

    fn parse(value: &str) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        match value {
            "activation" => Ok(Self::Activation),
            "export" => Ok(Self::Export),
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
}

impl CloudflareEd25519YaoWebSocketBindingV1 {
    /// Creates one exact protocol binding.
    pub fn new(
        circuit: CloudflareEd25519YaoCircuitV1,
        session: [u8; 32],
    ) -> Result<Self, CloudflareEd25519YaoWebSocketErrorV1> {
        if session.iter().all(|byte| *byte == 0) {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol);
        }
        Ok(Self { circuit, session })
    }

    /// Encodes the binding as a WebSocket subprotocol token.
    pub fn protocol(self) -> String {
        format!(
            "{WEBSOCKET_PROTOCOL_PREFIX}.{}.{}",
            self.circuit.protocol_label(),
            encode_hex(self.session)
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
        if prefix != WEBSOCKET_PROTOCOL_PREFIX || parts.next().is_some() {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol);
        }
        Self::new(
            CloudflareEd25519YaoCircuitV1::parse(circuit)?,
            decode_hex_32(session)?,
        )
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
pub struct CloudflareEd25519YaoWebSocketCompletionV1;

impl YaoTransportCompletion for CloudflareEd25519YaoWebSocketCompletionV1 {}

/// Opens the canonical same-account Service Binding WebSocket from A to B.
pub async fn connect_cloudflare_ed25519_yao_deriver_b_v1(
    env: &Env,
    binding: CloudflareEd25519YaoWebSocketBindingV1,
) -> Result<WebSocket, CloudflareEd25519YaoWebSocketErrorV1> {
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
    set_cloudflare_internal_service_auth_header_v1(
        env,
        headers,
        "Ed25519 Yao Deriver A to B WebSocket",
    )
    .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)?;
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
    response
        .websocket()
        .ok_or(CloudflareEd25519YaoWebSocketErrorV1::ServiceBinding)
}

/// Canonical directional WebSocket adapter for one fixed Yao role.
pub struct CloudflareEd25519YaoWebSocketTransportV1<'socket> {
    socket: &'socket WebSocket,
    events: EventStream<'socket>,
    encoder: Option<DirectionalWireEncoder>,
    decoder: Option<DirectionalWireDecoder>,
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
        )
    }

    fn new(
        socket: &'socket WebSocket,
        session: [u8; 32],
        outbound: WireDirection,
        inbound: WireDirection,
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

    async fn finish(self) -> Result<Self::Completion, Self::Error> {
        if self.encoder.is_some() || self.decoder.is_some() {
            return Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidState);
        }
        self.socket
            .close(Some(1000), Some("complete"))
            .map_err(|_| CloudflareEd25519YaoWebSocketErrorV1::WebSocketEvent)?;
        Ok(CloudflareEd25519YaoWebSocketCompletionV1)
    }
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
    fn protocol_binding_round_trips_exact_circuit_and_session() {
        let binding = CloudflareEd25519YaoWebSocketBindingV1::new(
            CloudflareEd25519YaoCircuitV1::Activation,
            [7_u8; 32],
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
            CloudflareEd25519YaoWebSocketBindingV1::new(
                CloudflareEd25519YaoCircuitV1::Export,
                [0_u8; 32],
            ),
            Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)
        );
        assert_eq!(
            CloudflareEd25519YaoWebSocketBindingV1::parse_protocol(
                "seams-ed25519-yao-p0-v1.other.0707070707070707070707070707070707070707070707070707070707070707"
            ),
            Err(CloudflareEd25519YaoWebSocketErrorV1::InvalidProtocol)
        );
    }
}
