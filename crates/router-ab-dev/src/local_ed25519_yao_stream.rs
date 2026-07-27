use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use router_ab_core::{
    Ed25519YaoExecutionIdV1, Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleStartAcceptanceV1,
};
use router_ab_ed25519_yao::relay::{
    ActivationDeriverACompletion, ActivationDeriverBCompletion, DirectionalWireDecoder,
    DirectionalWireEncoder, ExportDeriverACompletion, ExportDeriverBCompletion, RelayEvent,
    RelayInstruction, RelayStep, WireDirection, WireMessage, WireMessageKind,
};
use router_ab_ed25519_yao::{
    ActivationDeriverA, ActivationDeriverB, ExportDeriverA, ExportDeriverB,
};

use super::{
    local_router_ab_internal_service_auth_matches_v1, LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
};

const MAXIMUM_HTTP_HEAD_BYTES: usize = 8 * 1024;
const MAXIMUM_HTTP_CHUNK_BYTES: usize = 300 * 1024;
const STREAM_CONTENT_TYPE: &str = "application/vnd.seams.ed25519-yao-stream-v1";
const SESSION_HEADER: &str = "x-seams-ed25519-yao-session";
const PAIR_DIGEST_HEADER: &str = "x-seams-ed25519-yao-pair-digest";
const EXECUTION_ID_HEADER: &str = "x-seams-ed25519-yao-execution-id";
const READINESS_RECEIPT_HEADER: &str = "x-seams-yao-readiness-receipt";
const START_ACCEPTANCE_HEADER: &str = "x-seams-yao-start-acceptance";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum LocalEd25519YaoStreamErrorV1 {
    Io(io::Error),
    InvalidHttp(&'static str),
    Protocol(&'static str),
}

impl fmt::Display for LocalEd25519YaoStreamErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "local Ed25519 Yao stream I/O failed: {error}"),
            Self::InvalidHttp(message) => {
                write!(
                    formatter,
                    "invalid local Ed25519 Yao HTTP stream: {message}"
                )
            }
            Self::Protocol(message) => {
                write!(formatter, "local Ed25519 Yao protocol failed: {message}")
            }
        }
    }
}

impl std::error::Error for LocalEd25519YaoStreamErrorV1 {}

impl From<io::Error> for LocalEd25519YaoStreamErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

type StreamResult<T> = Result<T, LocalEd25519YaoStreamErrorV1>;

pub(crate) struct LocalEd25519YaoCompletedDeriverBResponseV1 {
    stream: TcpStream,
}

impl LocalEd25519YaoCompletedDeriverBResponseV1 {
    pub(crate) fn send_sealed_completion(mut self, completion: &[u8]) -> StreamResult<()> {
        if completion.is_empty() || completion.len() > MAXIMUM_HTTP_CHUNK_BYTES {
            return Err(protocol("sealed completion has an invalid size"));
        }
        write_http_chunk(&mut self.stream, completion)?;
        finish_http_chunks(&mut self.stream)?;
        Ok(())
    }

    fn finish_without_completion(mut self) -> StreamResult<()> {
        finish_http_chunks(&mut self.stream)?;
        Ok(())
    }
}

pub struct LocalEd25519YaoAuthenticatedDeriverBPeerV1 {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    session: [u8; 32],
    pair: Option<LocalEd25519YaoPairPeerContextV1>,
    start_acceptance: Option<Ed25519YaoRoleStartAcceptanceV1>,
}

/// Pair identity and the peer's signed readiness proof carried by the
/// authenticated A→B stream before B enters Running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoPairPeerContextV1 {
    pub pair_digest: [u8; 32],
    pub execution_id: Ed25519YaoExecutionIdV1,
    pub peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
}

impl LocalEd25519YaoAuthenticatedDeriverBPeerV1 {
    pub(crate) fn pair_context(&self) -> Option<&LocalEd25519YaoPairPeerContextV1> {
        self.pair.as_ref()
    }

    pub(crate) fn set_start_acceptance(
        &mut self,
        acceptance: Ed25519YaoRoleStartAcceptanceV1,
    ) -> StreamResult<()> {
        if self.pair.is_none() {
            return Err(protocol(
                "pair start acceptance requires a pair-bound stream",
            ));
        }
        self.start_acceptance = Some(acceptance);
        Ok(())
    }
}

trait LocalStreamingRole: Sized {
    type Completion;

    fn instruction(&self) -> StreamResult<RelayInstruction>;
    fn handle(self, event: RelayEvent) -> StreamResult<RelayStep<Self, Self::Completion>>;
}

macro_rules! implement_local_streaming_role {
    ($role:ty, $completion:ty) => {
        impl LocalStreamingRole for $role {
            type Completion = $completion;

            fn instruction(&self) -> StreamResult<RelayInstruction> {
                <$role>::instruction(self).map_err(|_| protocol("role instruction"))
            }

            fn handle(self, event: RelayEvent) -> StreamResult<RelayStep<Self, Self::Completion>> {
                <$role>::handle(self, event).map_err(|_| protocol("role event"))
            }
        }
    };
}

implement_local_streaming_role!(ActivationDeriverA, ActivationDeriverACompletion);
implement_local_streaming_role!(ActivationDeriverB, ActivationDeriverBCompletion);
implement_local_streaming_role!(ExportDeriverA, ExportDeriverACompletion);
implement_local_streaming_role!(ExportDeriverB, ExportDeriverBCompletion);

pub fn run_local_activation_deriver_a_http_v1(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    role: ActivationDeriverA,
) -> StreamResult<ActivationDeriverACompletion> {
    run_local_deriver_a_http_v1(address, session, internal_service_auth, role)
}

/// Runs one pair-bound activation over the authenticated local stream.
pub fn run_local_activation_deriver_a_pair_http_v1(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    pair_digest: [u8; 32],
    peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
    execution_id: Ed25519YaoExecutionIdV1,
    role: ActivationDeriverA,
) -> StreamResult<(
    ActivationDeriverACompletion,
    Ed25519YaoRoleStartAcceptanceV1,
    Vec<u8>,
)> {
    let (completion, acceptance, sealed_completion) = run_local_deriver_a_http_with_pair_v1(
        address,
        session,
        internal_service_auth,
        Some(LocalEd25519YaoPairPeerContextV1 {
            pair_digest,
            execution_id,
            peer_receipt,
        }),
        role,
    )?;
    let acceptance = acceptance.ok_or_else(|| protocol("pair start acceptance is missing"))?;
    let sealed_completion =
        sealed_completion.ok_or_else(|| protocol("pair sealed completion is missing"))?;
    Ok((completion, acceptance, sealed_completion))
}

pub fn run_local_export_deriver_a_http_v1(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    role: ExportDeriverA,
) -> StreamResult<ExportDeriverACompletion> {
    run_local_deriver_a_http_v1(address, session, internal_service_auth, role)
}

/// Runs one pair-bound export over the authenticated local stream.
pub fn run_local_export_deriver_a_pair_http_v1(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    pair_digest: [u8; 32],
    peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
    execution_id: Ed25519YaoExecutionIdV1,
    role: ExportDeriverA,
) -> StreamResult<(
    ExportDeriverACompletion,
    Ed25519YaoRoleStartAcceptanceV1,
    Vec<u8>,
)> {
    let (completion, acceptance, sealed_completion) = run_local_deriver_a_http_with_pair_v1(
        address,
        session,
        internal_service_auth,
        Some(LocalEd25519YaoPairPeerContextV1 {
            pair_digest,
            execution_id,
            peer_receipt,
        }),
        role,
    )?;
    let acceptance = acceptance.ok_or_else(|| protocol("pair start acceptance is missing"))?;
    let sealed_completion =
        sealed_completion.ok_or_else(|| protocol("pair sealed completion is missing"))?;
    Ok((completion, acceptance, sealed_completion))
}

fn run_local_deriver_a_http_v1<R>(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    role: R,
) -> StreamResult<R::Completion>
where
    R: LocalStreamingRole,
{
    let (completion, _, _) =
        run_local_deriver_a_http_with_pair_v1(address, session, internal_service_auth, None, role)?;
    Ok(completion)
}

fn run_local_deriver_a_http_with_pair_v1<R>(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    pair: Option<LocalEd25519YaoPairPeerContextV1>,
    mut role: R,
) -> StreamResult<(
    R::Completion,
    Option<Ed25519YaoRoleStartAcceptanceV1>,
    Option<Vec<u8>>,
)>
where
    R: LocalStreamingRole,
{
    let mut stream = TcpStream::connect(address)?;
    configure_stream(&stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    write_request_head_with_pair(&mut stream, session, internal_service_auth, pair.as_ref())?;
    let acceptance = read_response_head_with_pair(&mut reader)?;

    let mut a_to_b_encoder =
        DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session)
            .map_err(|_| protocol("A request encoder"))?;
    let mut b_to_a_decoder =
        DirectionalWireDecoder::new(WireDirection::DeriverBToDeriverA, session)
            .map_err(|_| protocol("A response decoder"))?;

    let offer = read_wire_message(&mut reader, &mut b_to_a_decoder)?;
    require_receive_instruction(&role, &offer)?;
    role = expect_continue(role.handle(RelayEvent::Inbound(offer))?)?;

    let (next, choices) = expect_send(role.handle(RelayEvent::Advance)?)?;
    role = next;
    write_wire_message(&mut stream, &mut a_to_b_encoder, choices)?;

    let (next, direct) = expect_send(role.handle(RelayEvent::Advance)?)?;
    role = next;
    write_wire_message(&mut stream, &mut a_to_b_encoder, direct)?;

    let extension = read_wire_message(&mut reader, &mut b_to_a_decoder)?;
    require_receive_instruction(&role, &extension)?;
    role = expect_continue(role.handle(RelayEvent::Inbound(extension))?)?;

    let (next, masked) = expect_send(role.handle(RelayEvent::Advance)?)?;
    role = next;
    write_wire_message(&mut stream, &mut a_to_b_encoder, masked)?;

    let (next, manifest) = expect_send(role.handle(RelayEvent::Advance)?)?;
    role = next;
    write_wire_message(&mut stream, &mut a_to_b_encoder, manifest)?;

    loop {
        let (next, message) = expect_send(role.handle(RelayEvent::Advance)?)?;
        role = next;
        let kind = message.kind();
        write_wire_message(&mut stream, &mut a_to_b_encoder, message)?;
        match kind {
            WireMessageKind::TableFrame => {}
            WireMessageKind::OutputTranslation => break,
            _ => return Err(protocol("A emitted unexpected stream message")),
        }
    }

    finish_http_chunks(&mut stream)?;
    let local_eof = a_to_b_encoder
        .finish_after_transport_close()
        .map_err(|_| protocol("A request EOF evidence"))?;
    role = expect_continue(role.handle(RelayEvent::LocalDirectionalEof(local_eof))?)?;

    let returned = read_wire_message(&mut reader, &mut b_to_a_decoder)?;
    require_receive_instruction(&role, &returned)?;
    role = expect_continue(role.handle(RelayEvent::Inbound(returned))?)?;
    let sealed_completion = if pair.is_some() {
        Some(
            read_http_chunk(&mut reader)?
                .ok_or_else(|| protocol("pair response ended before sealed completion"))?,
        )
    } else {
        None
    };
    require_http_eof(&mut reader)?;
    let peer_eof = b_to_a_decoder
        .finish_at_transport_eof()
        .map_err(|_| protocol("A response EOF evidence"))?;
    let completion = expect_complete(role.handle(RelayEvent::InboundDirectionalEof(peer_eof))?)?;
    Ok((completion, acceptance, sealed_completion))
}

pub fn run_local_activation_deriver_b_http_v1(
    stream: TcpStream,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
    role: ActivationDeriverB,
) -> StreamResult<ActivationDeriverBCompletion> {
    let peer = authenticate_local_ed25519_yao_deriver_b_peer_http_v1(
        stream,
        expected_session,
        expected_internal_service_auth,
    )?;
    run_local_activation_deriver_b_authenticated_http_v1(peer, role)
}

pub fn run_local_export_deriver_b_http_v1(
    stream: TcpStream,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
    role: ExportDeriverB,
) -> StreamResult<ExportDeriverBCompletion> {
    let peer = authenticate_local_ed25519_yao_deriver_b_peer_http_v1(
        stream,
        expected_session,
        expected_internal_service_auth,
    )?;
    run_local_export_deriver_b_authenticated_http_v1(peer, role)
}

pub fn authenticate_local_ed25519_yao_deriver_b_peer_http_v1(
    stream: TcpStream,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
) -> StreamResult<LocalEd25519YaoAuthenticatedDeriverBPeerV1> {
    authenticate_local_ed25519_yao_deriver_b_peer_http_with_pair_v1(
        stream,
        expected_session,
        expected_internal_service_auth,
    )
}

pub(crate) fn authenticate_local_ed25519_yao_deriver_b_peer_http_with_pair_v1(
    stream: TcpStream,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
) -> StreamResult<LocalEd25519YaoAuthenticatedDeriverBPeerV1> {
    configure_stream(&stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let pair = read_request_head_with_pair(
        &mut reader,
        expected_session,
        expected_internal_service_auth,
    )?;
    Ok(LocalEd25519YaoAuthenticatedDeriverBPeerV1 {
        stream,
        reader,
        session: expected_session,
        pair,
        start_acceptance: None,
    })
}

pub fn run_local_activation_deriver_b_authenticated_http_v1(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: ActivationDeriverB,
) -> StreamResult<ActivationDeriverBCompletion> {
    let (completion, response) = run_local_deriver_b_authenticated_http_open_v1(peer, role)?;
    response.finish_without_completion()?;
    Ok(completion)
}

pub fn run_local_export_deriver_b_authenticated_http_v1(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: ExportDeriverB,
) -> StreamResult<ExportDeriverBCompletion> {
    let (completion, response) = run_local_deriver_b_authenticated_http_open_v1(peer, role)?;
    response.finish_without_completion()?;
    Ok(completion)
}

pub(crate) fn run_local_activation_deriver_b_authenticated_http_open_v1(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: ActivationDeriverB,
) -> StreamResult<(
    ActivationDeriverBCompletion,
    LocalEd25519YaoCompletedDeriverBResponseV1,
)> {
    run_local_deriver_b_authenticated_http_open_v1(peer, role)
}

pub(crate) fn run_local_export_deriver_b_authenticated_http_open_v1(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: ExportDeriverB,
) -> StreamResult<(
    ExportDeriverBCompletion,
    LocalEd25519YaoCompletedDeriverBResponseV1,
)> {
    run_local_deriver_b_authenticated_http_open_v1(peer, role)
}

fn run_local_deriver_b_authenticated_http_open_v1<R>(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    mut role: R,
) -> StreamResult<(R::Completion, LocalEd25519YaoCompletedDeriverBResponseV1)>
where
    R: LocalStreamingRole,
{
    let LocalEd25519YaoAuthenticatedDeriverBPeerV1 {
        mut stream,
        mut reader,
        session,
        start_acceptance,
        ..
    } = peer;
    write_response_head_with_acceptance(&mut stream, start_acceptance.as_ref())?;

    let mut a_to_b_decoder =
        DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session)
            .map_err(|_| protocol("B request decoder"))?;
    let mut b_to_a_encoder =
        DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session)
            .map_err(|_| protocol("B response encoder"))?;

    let (next, offer) = expect_send(role.handle(RelayEvent::Advance)?)?;
    role = next;
    write_wire_message(&mut stream, &mut b_to_a_encoder, offer)?;

    let choices = read_wire_message(&mut reader, &mut a_to_b_decoder)?;
    require_receive_instruction(&role, &choices)?;
    role = expect_continue(role.handle(RelayEvent::Inbound(choices))?)?;

    let direct = read_wire_message(&mut reader, &mut a_to_b_decoder)?;
    require_receive_instruction(&role, &direct)?;
    let (next, extension) = expect_send(role.handle(RelayEvent::Inbound(direct))?)?;
    role = next;
    write_wire_message(&mut stream, &mut b_to_a_encoder, extension)?;

    let masked = read_wire_message(&mut reader, &mut a_to_b_decoder)?;
    require_receive_instruction(&role, &masked)?;
    role = expect_continue(role.handle(RelayEvent::Inbound(masked))?)?;

    let manifest = read_wire_message(&mut reader, &mut a_to_b_decoder)?;
    require_receive_instruction(&role, &manifest)?;
    role = expect_continue(role.handle(RelayEvent::Inbound(manifest))?)?;

    loop {
        let message = read_wire_message(&mut reader, &mut a_to_b_decoder)?;
        require_receive_instruction(&role, &message)?;
        let kind = message.kind();
        role = expect_continue(role.handle(RelayEvent::Inbound(message))?)?;
        match kind {
            WireMessageKind::TableFrame => {}
            WireMessageKind::OutputTranslation => break,
            _ => return Err(protocol("B received unexpected stream message")),
        }
    }

    require_http_eof(&mut reader)?;
    let peer_eof = a_to_b_decoder
        .finish_at_transport_eof()
        .map_err(|_| protocol("B request EOF evidence"))?;
    role = expect_continue(role.handle(RelayEvent::InboundDirectionalEof(peer_eof))?)?;

    let (next, returned) = expect_send(role.handle(RelayEvent::Advance)?)?;
    role = next;
    write_wire_message(&mut stream, &mut b_to_a_encoder, returned)?;
    let local_eof = b_to_a_encoder
        .finish_after_transport_close()
        .map_err(|_| protocol("B response EOF evidence"))?;
    let completion = expect_complete(role.handle(RelayEvent::LocalDirectionalEof(local_eof))?)?;
    Ok((
        completion,
        LocalEd25519YaoCompletedDeriverBResponseV1 { stream },
    ))
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

fn write_request_head_with_pair(
    stream: &mut TcpStream,
    session: [u8; 32],
    internal_service_auth: &str,
    pair: Option<&LocalEd25519YaoPairPeerContextV1>,
) -> io::Result<()> {
    write!(
        stream,
        "POST {LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH} HTTP/1.1\r\nhost: local-deriver-b\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\n{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: {internal_service_auth}\r\n{SESSION_HEADER}: {}\r\n",
        hex::encode(session)
    )?;
    if let Some(pair) = pair {
        let serialized_receipt = serde_json::to_string(&pair.peer_receipt)
            .map_err(|error| io::Error::other(format!("pair receipt encoding failed: {error}")))?;
        write!(
            stream,
            "{PAIR_DIGEST_HEADER}: {}\r\n{EXECUTION_ID_HEADER}: {}\r\n{READINESS_RECEIPT_HEADER}: {}\r\n",
            hex::encode(pair.pair_digest),
            hex::encode(pair.execution_id.into_bytes()),
            serialized_receipt,
        )?;
    }
    write!(stream, "connection: close\r\n\r\n")?;
    stream.flush()
}

fn read_request_head_with_pair<R: BufRead>(
    reader: &mut R,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
) -> StreamResult<Option<LocalEd25519YaoPairPeerContextV1>> {
    let lines = read_http_head(reader)?;
    let expected_request = format!("POST {LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH} HTTP/1.1");
    if lines.first() != Some(&expected_request) {
        return Err(invalid_http("wrong request line"));
    }
    require_header(&lines, "content-type", STREAM_CONTENT_TYPE)?;
    require_header(&lines, "transfer-encoding", "chunked")?;
    forbid_header(&lines, "content-length")?;
    require_secret_header(
        &lines,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
        expected_internal_service_auth,
    )?;
    require_header(&lines, SESSION_HEADER, &hex::encode(expected_session))?;
    let pair_headers = [
        header_values(&lines, PAIR_DIGEST_HEADER),
        header_values(&lines, EXECUTION_ID_HEADER),
        header_values(&lines, READINESS_RECEIPT_HEADER),
    ];
    let has_pair_header = pair_headers.iter().any(|values| !values.is_empty());
    if !has_pair_header {
        return Ok(None);
    }
    if pair_headers.iter().any(|values| values.len() != 1) {
        return Err(invalid_http("pair stream headers must be unique"));
    }
    let pair_digest = decode_hex_32(single_header(&lines, PAIR_DIGEST_HEADER)?)?;
    let execution_id =
        Ed25519YaoExecutionIdV1::new(decode_hex_32(single_header(&lines, EXECUTION_ID_HEADER)?)?)
            .map_err(|_| invalid_http("pair stream execution id is malformed"))?;
    let peer_receipt = serde_json::from_str::<Ed25519YaoRoleReadinessReceiptV1>(single_header(
        &lines,
        READINESS_RECEIPT_HEADER,
    )?)
    .map_err(|_| invalid_http("pair stream readiness receipt is malformed"))?;
    if peer_receipt.role() != router_ab_core::Ed25519YaoDeriverRoleV1::DeriverA
        || peer_receipt.session_bytes() != expected_session
        || peer_receipt.pair_digest().bytes != pair_digest
    {
        return Err(invalid_http(
            "pair stream readiness receipt identity mismatch",
        ));
    }
    Ok(Some(LocalEd25519YaoPairPeerContextV1 {
        pair_digest,
        execution_id,
        peer_receipt,
    }))
}

fn write_response_head_with_acceptance(
    stream: &mut TcpStream,
    acceptance: Option<&Ed25519YaoRoleStartAcceptanceV1>,
) -> io::Result<()> {
    let serialized_acceptance = acceptance
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| io::Error::other(format!("start acceptance encoding failed: {error}")))?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\n{}connection: close\r\n\r\n",
        serialized_acceptance
            .map(|value| format!("{START_ACCEPTANCE_HEADER}: {value}\r\n"))
            .unwrap_or_default()
    )?;
    stream.flush()
}

fn read_response_head_with_pair<R: BufRead>(
    reader: &mut R,
) -> StreamResult<Option<Ed25519YaoRoleStartAcceptanceV1>> {
    let lines = read_http_head(reader)?;
    if lines.first().map(String::as_str) != Some("HTTP/1.1 200 OK") {
        return Err(invalid_http("non-success response"));
    }
    require_header(&lines, "content-type", STREAM_CONTENT_TYPE)?;
    require_header(&lines, "transfer-encoding", "chunked")?;
    forbid_header(&lines, "content-length")?;
    let values = header_values(&lines, START_ACCEPTANCE_HEADER);
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(invalid_http("start acceptance header must be unique"));
    }
    let acceptance = serde_json::from_str::<Ed25519YaoRoleStartAcceptanceV1>(values[0])
        .map_err(|_| invalid_http("start acceptance header is malformed"))?;
    Ok(Some(acceptance))
}

fn read_http_head<R: BufRead>(reader: &mut R) -> StreamResult<Vec<String>> {
    let mut lines = Vec::new();
    let mut total = 0_usize;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Err(invalid_http("head ended before terminator"));
        }
        total = total
            .checked_add(bytes)
            .ok_or_else(|| invalid_http("head length overflow"))?;
        if total > MAXIMUM_HTTP_HEAD_BYTES {
            return Err(invalid_http("head exceeds limit"));
        }
        if line == "\r\n" {
            return Ok(lines);
        }
        let Some(line) = line.strip_suffix("\r\n") else {
            return Err(invalid_http("head line lacks CRLF"));
        };
        lines.push(line.to_owned());
    }
}

fn require_header(lines: &[String], name: &str, expected: &str) -> StreamResult<()> {
    let actual = single_header(lines, name)?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_http("required header mismatch"))
    }
}

fn require_secret_header(lines: &[String], name: &str, expected: &str) -> StreamResult<()> {
    let actual = single_header(lines, name)?;
    if local_router_ab_internal_service_auth_matches_v1(actual, expected) {
        Ok(())
    } else {
        Err(invalid_http("required header mismatch"))
    }
}

fn forbid_header(lines: &[String], name: &str) -> StreamResult<()> {
    if !header_values(lines, name).is_empty() {
        Err(invalid_http("forbidden header is present"))
    } else {
        Ok(())
    }
}

fn single_header<'a>(lines: &'a [String], name: &str) -> StreamResult<&'a str> {
    let values = header_values(lines, name);
    let value = values
        .first()
        .copied()
        .ok_or_else(|| invalid_http("required header is missing"))?;
    if values.len() != 1 {
        return Err(invalid_http("duplicate header is forbidden"));
    }
    Ok(value)
}

fn header_values<'a>(lines: &'a [String], name: &str) -> Vec<&'a str> {
    lines
        .iter()
        .skip(1)
        .filter_map(move |line| {
            let (candidate, value) = line.split_once(':')?;
            candidate.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .collect()
}

fn decode_hex_32(value: &str) -> StreamResult<[u8; 32]> {
    hex::decode(value)
        .map_err(|_| invalid_http("hex header is malformed"))?
        .try_into()
        .map_err(|_| invalid_http("hex header must contain 32 bytes"))
}

fn write_wire_message(
    stream: &mut TcpStream,
    encoder: &mut DirectionalWireEncoder,
    message: WireMessage,
) -> StreamResult<()> {
    let mut encoded = encoder
        .encode(message)
        .map_err(|_| protocol("wire envelope encode"))?;
    let write_result = write_http_chunk(stream, &encoded);
    encoded.fill(0);
    write_result?;
    Ok(())
}

fn read_wire_message(
    reader: &mut BufReader<TcpStream>,
    decoder: &mut DirectionalWireDecoder,
) -> StreamResult<WireMessage> {
    let mut encoded = read_http_chunk(reader)?
        .ok_or_else(|| protocol("direction ended before terminal message"))?;
    let encoded_len = encoded.len();
    let decode_result = decoder.push(&encoded);
    encoded.fill(0);
    let consumed = decode_result.map_err(|_| protocol("wire envelope decode"))?;
    if consumed != encoded_len {
        return Err(protocol("HTTP chunk did not contain exactly one envelope"));
    }
    decoder
        .take_message()
        .map_err(|_| protocol("wire envelope take"))?
        .ok_or_else(|| protocol("HTTP chunk did not contain one complete envelope"))
}

fn write_http_chunk(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    write!(stream, "{:x}\r\n", payload.len())?;
    stream.write_all(payload)?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

fn finish_http_chunks(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)
}

fn read_http_chunk<R: BufRead>(reader: &mut R) -> StreamResult<Option<Vec<u8>>> {
    let mut size_line = String::new();
    if reader.read_line(&mut size_line)? == 0 {
        return Err(invalid_http("chunk stream ended without zero chunk"));
    }
    let Some(size_hex) = size_line.strip_suffix("\r\n") else {
        return Err(invalid_http("chunk size lacks CRLF"));
    };
    if size_hex.is_empty() || size_hex.contains(';') {
        return Err(invalid_http("chunk extensions are forbidden"));
    }
    let size =
        usize::from_str_radix(size_hex, 16).map_err(|_| invalid_http("invalid chunk size"))?;
    if size > MAXIMUM_HTTP_CHUNK_BYTES {
        return Err(invalid_http("chunk exceeds limit"));
    }
    if size == 0 {
        let mut terminator = [0_u8; 2];
        std::io::Read::read_exact(reader, &mut terminator)?;
        if terminator != *b"\r\n" {
            return Err(invalid_http("zero chunk has trailers"));
        }
        return Ok(None);
    }
    let mut payload = vec![0_u8; size];
    if let Err(error) = std::io::Read::read_exact(reader, &mut payload) {
        payload.fill(0);
        return Err(error.into());
    }
    let mut terminator = [0_u8; 2];
    if let Err(error) = std::io::Read::read_exact(reader, &mut terminator) {
        payload.fill(0);
        return Err(error.into());
    }
    if terminator != *b"\r\n" {
        payload.fill(0);
        return Err(invalid_http("chunk payload lacks CRLF"));
    }
    Ok(Some(payload))
}

fn require_http_eof<R: BufRead>(reader: &mut R) -> StreamResult<()> {
    match read_http_chunk(reader)? {
        None if reader.fill_buf()?.is_empty() => Ok(()),
        None => Err(invalid_http("bytes follow zero chunk")),
        Some(mut trailing) => {
            trailing.fill(0);
            Err(protocol("message followed terminal envelope"))
        }
    }
}

fn require_receive_instruction<R: LocalStreamingRole>(
    role: &R,
    message: &WireMessage,
) -> StreamResult<()> {
    let expected = RelayInstruction::Receive {
        kind: message.kind(),
        payload_bytes: message.as_bytes().len(),
    };
    if role.instruction()? == expected {
        Ok(())
    } else {
        Err(protocol("role instruction does not match inbound message"))
    }
}

fn expect_continue<R, C>(step: RelayStep<R, C>) -> StreamResult<R> {
    match step {
        RelayStep::Continue(role) => Ok(role),
        _ => Err(protocol("expected role continuation")),
    }
}

fn expect_send<R, C>(step: RelayStep<R, C>) -> StreamResult<(R, WireMessage)> {
    match step {
        RelayStep::Send { role, message } => Ok((role, message)),
        _ => Err(protocol("expected outbound role message")),
    }
}

fn expect_complete<R, C>(step: RelayStep<R, C>) -> StreamResult<C> {
    match step {
        RelayStep::Complete(completion) => Ok(completion),
        _ => Err(protocol("expected role completion")),
    }
}

const fn protocol(message: &'static str) -> LocalEd25519YaoStreamErrorV1 {
    LocalEd25519YaoStreamErrorV1::Protocol(message)
}

const fn invalid_http(message: &'static str) -> LocalEd25519YaoStreamErrorV1 {
    LocalEd25519YaoStreamErrorV1::InvalidHttp(message)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        read_http_chunk, read_request_head_with_pair, read_response_head_with_pair,
        require_http_eof, LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1, SESSION_HEADER, STREAM_CONTENT_TYPE,
    };

    fn request_head(extra_header: &str) -> Vec<u8> {
        format!(
            "POST {LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH} HTTP/1.1\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\n{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: secret\r\n{SESSION_HEADER}: {}\r\n{extra_header}\r\n",
            hex::encode([7_u8; 32]),
        )
        .into_bytes()
    }

    #[test]
    fn exact_http_eof_requires_zero_chunk_and_physical_eof() {
        let mut exact = Cursor::new(b"0\r\n\r\n".as_slice());
        require_http_eof(&mut exact).expect("exact EOF");

        let mut missing_zero = Cursor::new(Vec::<u8>::new());
        assert!(require_http_eof(&mut missing_zero).is_err());

        let mut bytes_after_zero = Cursor::new(b"0\r\n\r\nsmuggled".as_slice());
        assert!(require_http_eof(&mut bytes_after_zero).is_err());
    }

    #[test]
    fn chunk_boundary_rejects_extensions_trailers_and_early_zero() {
        let mut extension = Cursor::new(b"1;x=1\r\na\r\n".as_slice());
        assert!(read_http_chunk(&mut extension).is_err());

        let mut trailer = Cursor::new(b"0\r\nx: y\r\n\r\n".as_slice());
        assert!(read_http_chunk(&mut trailer).is_err());

        let mut early_zero = Cursor::new(b"0\r\n\r\n".as_slice());
        assert_eq!(read_http_chunk(&mut early_zero).expect("zero chunk"), None);
    }

    #[test]
    fn request_head_rejects_duplicate_security_headers_and_content_length() {
        let duplicate_auth =
            format!("{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: secret\r\n");
        let mut duplicate_auth = Cursor::new(request_head(&duplicate_auth));
        assert!(read_request_head_with_pair(&mut duplicate_auth, [7_u8; 32], "secret").is_err());

        let mut transfer_encoding_and_content_length =
            Cursor::new(request_head("content-length: 0\r\n"));
        assert!(read_request_head_with_pair(
            &mut transfer_encoding_and_content_length,
            [7_u8; 32],
            "secret",
        )
        .is_err());

        let duplicate_session = format!("{SESSION_HEADER}: {}\r\n", hex::encode([7_u8; 32]));
        let mut duplicate_session = Cursor::new(request_head(&duplicate_session));
        assert!(read_request_head_with_pair(&mut duplicate_session, [7_u8; 32], "secret").is_err());
    }

    #[test]
    fn response_head_rejects_duplicate_transfer_encoding_and_content_length() {
        let mut duplicate_transfer_encoding = Cursor::new(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\ntransfer-encoding: chunked\r\n\r\n"
            )
            .into_bytes(),
        );
        assert!(read_response_head_with_pair(&mut duplicate_transfer_encoding).is_err());

        let mut transfer_encoding_and_content_length = Cursor::new(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\ncontent-length: 0\r\n\r\n"
            )
            .into_bytes(),
        );
        assert!(read_response_head_with_pair(&mut transfer_encoding_and_content_length).is_err());
    }
}
