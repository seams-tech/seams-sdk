use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use base64::Engine as _;
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{OsRng, TryRngCore};
use router_ab_core::{
    Ed25519YaoDeriverAToBTargetProofPayloadV2, Ed25519YaoDeriverBToATargetProofPayloadV2,
    Ed25519YaoExecutionIdV1, Ed25519YaoOuterBindingV2, Ed25519YaoRoleReadinessReceiptV1,
    Ed25519YaoRoleStartAcceptanceV1,
};
use router_ab_ed25519_yao::relay::{
    ActivationDeriverACompletion, ActivationDeriverBCompletion, DirectionalWireDecoder,
    DirectionalWireEncoder, ExportDeriverACompletion, ExportDeriverBCompletion, RelayEvent,
    RelayInstruction, RelayStep, WireDirection, WireMessage, WireMessageKind,
};
use router_ab_ed25519_yao::{
    ActivationDeriverA, ActivationDeriverB, ExportDeriverA, ExportDeriverB,
};
use zeroize::Zeroizing;

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
const TARGET_PROOF_A_TO_B_HEADER: &str = "x-seams-yao-target-proof-a-to-b";
const TARGET_PROOF_B_TO_A_HEADER: &str = "x-seams-yao-target-proof-b-to-a";
const TARGET_PROOF_HPKE_INFO_V2: &[u8] = b"seams/ed25519-yao/target-proof/hpke/v2";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

type TargetProofHpkeV2 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

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
    kind: LocalEd25519YaoPeerKindV1,
    start_acceptance: Option<Ed25519YaoRoleStartAcceptanceV1>,
}

enum LocalEd25519YaoPeerKindV1 {
    Refresh,
    Pair {
        context: LocalEd25519YaoPairPeerContextV1,
        target_proof: Ed25519YaoDeriverAToBTargetProofPayloadV2,
    },
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
        match &self.kind {
            LocalEd25519YaoPeerKindV1::Refresh => None,
            LocalEd25519YaoPeerKindV1::Pair { context, .. } => Some(context),
        }
    }

    pub(crate) fn target_proof_a_to_b(&self) -> Option<&Ed25519YaoDeriverAToBTargetProofPayloadV2> {
        match &self.kind {
            LocalEd25519YaoPeerKindV1::Refresh => None,
            LocalEd25519YaoPeerKindV1::Pair { target_proof, .. } => Some(target_proof),
        }
    }

    pub(crate) fn set_start_acceptance(
        &mut self,
        acceptance: Ed25519YaoRoleStartAcceptanceV1,
    ) -> StreamResult<()> {
        if self.pair_context().is_none() {
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

pub(crate) struct LocalEd25519YaoDeriverAPairConnectionV2 {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    session: [u8; 32],
    acceptance: Ed25519YaoRoleStartAcceptanceV1,
}

pub fn run_local_activation_deriver_a_http_v1(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    role: ActivationDeriverA,
) -> StreamResult<ActivationDeriverACompletion> {
    run_local_deriver_a_http_v1(address, session, internal_service_auth, role)
}

/// Connects A to B and completes the V2 target-proof transport preface.
pub(crate) fn connect_local_deriver_a_pair_http_v2(
    address: impl ToSocketAddrs,
    session: [u8; 32],
    internal_service_auth: &str,
    pair: &LocalEd25519YaoPairPeerContextV1,
    outbound: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
    private_key: &[u8; 32],
) -> StreamResult<(
    LocalEd25519YaoDeriverAPairConnectionV2,
    Ed25519YaoDeriverBToATargetProofPayloadV2,
    Zeroizing<Vec<u8>>,
)> {
    let mut stream = TcpStream::connect(address)?;
    configure_stream(&stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    write_request_head_with_pair_v2(&mut stream, session, internal_service_auth, pair, outbound)?;
    let (acceptance, inbound) = read_response_head_with_pair_v2(&mut reader)?;
    let plaintext = open_local_deriver_a_target_proof_v2(&inbound, private_key)?;
    Ok((
        LocalEd25519YaoDeriverAPairConnectionV2 {
            stream,
            reader,
            session,
            acceptance,
        },
        inbound,
        plaintext,
    ))
}

pub(crate) fn run_local_activation_deriver_a_pair_connected_v2(
    connection: LocalEd25519YaoDeriverAPairConnectionV2,
    role: ActivationDeriverA,
) -> StreamResult<(
    ActivationDeriverACompletion,
    Ed25519YaoRoleStartAcceptanceV1,
    Vec<u8>,
)> {
    let acceptance = connection.acceptance.clone();
    let (completion, _, sealed_completion) = run_local_deriver_a_stream_v1(
        connection.stream,
        connection.reader,
        connection.session,
        Some(acceptance.clone()),
        true,
        role,
    )?;
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

pub(crate) fn run_local_export_deriver_a_pair_connected_v2(
    connection: LocalEd25519YaoDeriverAPairConnectionV2,
    role: ExportDeriverA,
) -> StreamResult<(
    ExportDeriverACompletion,
    Ed25519YaoRoleStartAcceptanceV1,
    Vec<u8>,
)> {
    let acceptance = connection.acceptance.clone();
    let (completion, _, sealed_completion) = run_local_deriver_a_stream_v1(
        connection.stream,
        connection.reader,
        connection.session,
        Some(acceptance.clone()),
        true,
        role,
    )?;
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
    let mut stream = TcpStream::connect(address)?;
    configure_stream(&stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    write_request_head(&mut stream, session, internal_service_auth)?;
    let acceptance = read_response_head(&mut reader)?;
    let (completion, _, _) =
        run_local_deriver_a_stream_v1(stream, reader, session, acceptance, false, role)?;
    Ok(completion)
}

fn run_local_deriver_a_stream_v1<R>(
    mut stream: TcpStream,
    mut reader: BufReader<TcpStream>,
    session: [u8; 32],
    acceptance: Option<Ed25519YaoRoleStartAcceptanceV1>,
    pair: bool,
    mut role: R,
) -> StreamResult<(
    R::Completion,
    Option<Ed25519YaoRoleStartAcceptanceV1>,
    Option<Vec<u8>>,
)>
where
    R: LocalStreamingRole,
{
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
    let sealed_completion = if pair {
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
    configure_stream(&stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    read_request_head(
        &mut reader,
        expected_session,
        expected_internal_service_auth,
    )?;
    Ok(LocalEd25519YaoAuthenticatedDeriverBPeerV1 {
        stream,
        reader,
        session: expected_session,
        kind: LocalEd25519YaoPeerKindV1::Refresh,
        start_acceptance: None,
    })
}

pub(crate) fn authenticate_local_ed25519_yao_deriver_b_peer_http_with_pair_v2(
    stream: TcpStream,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
) -> StreamResult<LocalEd25519YaoAuthenticatedDeriverBPeerV1> {
    configure_stream(&stream)?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let (context, target_proof) = read_request_head_with_pair_v2(
        &mut reader,
        expected_session,
        expected_internal_service_auth,
    )?;
    Ok(LocalEd25519YaoAuthenticatedDeriverBPeerV1 {
        stream,
        reader,
        session: expected_session,
        kind: LocalEd25519YaoPeerKindV1::Pair {
            context,
            target_proof,
        },
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

pub(crate) fn run_local_activation_deriver_b_authenticated_http_open_v2(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: ActivationDeriverB,
    outbound_target_proof: Ed25519YaoDeriverBToATargetProofPayloadV2,
) -> StreamResult<(
    ActivationDeriverBCompletion,
    LocalEd25519YaoCompletedDeriverBResponseV1,
)> {
    run_local_deriver_b_authenticated_http_open_v2(peer, role, outbound_target_proof)
}

pub(crate) fn run_local_export_deriver_b_authenticated_http_open_v2(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: ExportDeriverB,
    outbound_target_proof: Ed25519YaoDeriverBToATargetProofPayloadV2,
) -> StreamResult<(
    ExportDeriverBCompletion,
    LocalEd25519YaoCompletedDeriverBResponseV1,
)> {
    run_local_deriver_b_authenticated_http_open_v2(peer, role, outbound_target_proof)
}

fn run_local_deriver_b_authenticated_http_open_v1<R>(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: R,
) -> StreamResult<(R::Completion, LocalEd25519YaoCompletedDeriverBResponseV1)>
where
    R: LocalStreamingRole,
{
    if peer.pair_context().is_some() {
        return Err(protocol("pair stream requires the V2 target-proof path"));
    }
    run_local_deriver_b_authenticated_http_stream_v1(peer, role, None)
}

fn run_local_deriver_b_authenticated_http_open_v2<R>(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    role: R,
    outbound_target_proof: Ed25519YaoDeriverBToATargetProofPayloadV2,
) -> StreamResult<(R::Completion, LocalEd25519YaoCompletedDeriverBResponseV1)>
where
    R: LocalStreamingRole,
{
    if peer.pair_context().is_none() || peer.target_proof_a_to_b().is_none() {
        return Err(protocol("V2 target-proof stream is not pair-bound"));
    }
    run_local_deriver_b_authenticated_http_stream_v1(peer, role, Some(outbound_target_proof))
}

fn run_local_deriver_b_authenticated_http_stream_v1<R>(
    peer: LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    mut role: R,
    outbound_target_proof: Option<Ed25519YaoDeriverBToATargetProofPayloadV2>,
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
    if let Some(target_proof) = outbound_target_proof.as_ref() {
        let acceptance = start_acceptance
            .as_ref()
            .ok_or_else(|| protocol("pair start acceptance is missing"))?;
        write_response_head_with_pair_v2(&mut stream, acceptance, target_proof)?;
    } else {
        if start_acceptance.is_some() {
            return Err(protocol("generic stream cannot carry pair acceptance"));
        }
        write_response_head(&mut stream)?;
    }

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

fn write_request_head(
    stream: &mut TcpStream,
    session: [u8; 32],
    internal_service_auth: &str,
) -> io::Result<()> {
    write_request_head_base(stream, session, internal_service_auth)?;
    write!(stream, "connection: close\r\n\r\n")?;
    stream.flush()
}

fn write_request_head_with_pair_v2(
    stream: &mut TcpStream,
    session: [u8; 32],
    internal_service_auth: &str,
    pair: &LocalEd25519YaoPairPeerContextV1,
    target_proof: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
) -> io::Result<()> {
    write_request_head_base(stream, session, internal_service_auth)?;
    let serialized_receipt = serde_json::to_string(&pair.peer_receipt)
        .map_err(|error| io::Error::other(format!("pair receipt encoding failed: {error}")))?;
    let target_proof = encode_a_target_proof_header(target_proof)?;
    write!(
        stream,
        "{PAIR_DIGEST_HEADER}: {}\r\n{EXECUTION_ID_HEADER}: {}\r\n{READINESS_RECEIPT_HEADER}: {}\r\n{TARGET_PROOF_A_TO_B_HEADER}: {target_proof}\r\n",
        hex::encode(pair.pair_digest),
        hex::encode(pair.execution_id.into_bytes()),
        serialized_receipt,
    )?;
    write!(stream, "connection: close\r\n\r\n")?;
    stream.flush()
}

fn write_request_head_base(
    stream: &mut TcpStream,
    session: [u8; 32],
    internal_service_auth: &str,
) -> io::Result<()> {
    write!(
        stream,
        "POST {LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH} HTTP/1.1\r\nhost: local-deriver-b\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\n{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: {internal_service_auth}\r\n{SESSION_HEADER}: {}\r\n",
        hex::encode(session)
    )
}

fn read_request_head<R: BufRead>(
    reader: &mut R,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
) -> StreamResult<()> {
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
    forbid_header(&lines, PAIR_DIGEST_HEADER)?;
    forbid_header(&lines, EXECUTION_ID_HEADER)?;
    forbid_header(&lines, READINESS_RECEIPT_HEADER)?;
    forbid_header(&lines, TARGET_PROOF_A_TO_B_HEADER)?;
    forbid_header(&lines, TARGET_PROOF_B_TO_A_HEADER)?;
    forbid_header(&lines, START_ACCEPTANCE_HEADER)?;
    Ok(())
}

fn read_request_head_with_pair_v2<R: BufRead>(
    reader: &mut R,
    expected_session: [u8; 32],
    expected_internal_service_auth: &str,
) -> StreamResult<(
    LocalEd25519YaoPairPeerContextV1,
    Ed25519YaoDeriverAToBTargetProofPayloadV2,
)> {
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
    let required_pair_headers = [
        PAIR_DIGEST_HEADER,
        EXECUTION_ID_HEADER,
        READINESS_RECEIPT_HEADER,
        TARGET_PROOF_A_TO_B_HEADER,
    ];
    for header in required_pair_headers {
        if header_values(&lines, header).len() != 1 {
            return Err(invalid_http("V2 pair stream header must be unique"));
        }
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
    let target_proof =
        decode_a_target_proof_header(single_header(&lines, TARGET_PROOF_A_TO_B_HEADER)?)?;
    Ok((
        LocalEd25519YaoPairPeerContextV1 {
            pair_digest,
            execution_id,
            peer_receipt,
        },
        target_proof,
    ))
}

fn write_response_head(stream: &mut TcpStream) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
    )?;
    stream.flush()
}

fn write_response_head_with_pair_v2(
    stream: &mut TcpStream,
    acceptance: &Ed25519YaoRoleStartAcceptanceV1,
    target_proof: &Ed25519YaoDeriverBToATargetProofPayloadV2,
) -> io::Result<()> {
    let serialized_acceptance = serde_json::to_string(acceptance)
        .map_err(|error| io::Error::other(format!("start acceptance encoding failed: {error}")))?;
    let target_proof = encode_b_target_proof_header(target_proof)?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: {STREAM_CONTENT_TYPE}\r\ntransfer-encoding: chunked\r\n{START_ACCEPTANCE_HEADER}: {serialized_acceptance}\r\n{TARGET_PROOF_B_TO_A_HEADER}: {target_proof}\r\nconnection: close\r\n\r\n",
    )?;
    stream.flush()
}

fn read_response_head<R: BufRead>(
    reader: &mut R,
) -> StreamResult<Option<Ed25519YaoRoleStartAcceptanceV1>> {
    let lines = read_http_head(reader)?;
    if lines.first().map(String::as_str) != Some("HTTP/1.1 200 OK") {
        return Err(invalid_http("non-success response"));
    }
    require_header(&lines, "content-type", STREAM_CONTENT_TYPE)?;
    require_header(&lines, "transfer-encoding", "chunked")?;
    forbid_header(&lines, "content-length")?;
    forbid_header(&lines, START_ACCEPTANCE_HEADER)?;
    forbid_header(&lines, TARGET_PROOF_A_TO_B_HEADER)?;
    forbid_header(&lines, TARGET_PROOF_B_TO_A_HEADER)?;
    Ok(None)
}

fn read_response_head_with_pair_v2<R: BufRead>(
    reader: &mut R,
) -> StreamResult<(
    Ed25519YaoRoleStartAcceptanceV1,
    Ed25519YaoDeriverBToATargetProofPayloadV2,
)> {
    let lines = read_http_head(reader)?;
    if lines.first().map(String::as_str) != Some("HTTP/1.1 200 OK") {
        return Err(invalid_http("non-success response"));
    }
    require_header(&lines, "content-type", STREAM_CONTENT_TYPE)?;
    require_header(&lines, "transfer-encoding", "chunked")?;
    forbid_header(&lines, "content-length")?;
    let acceptance = serde_json::from_str::<Ed25519YaoRoleStartAcceptanceV1>(single_header(
        &lines,
        START_ACCEPTANCE_HEADER,
    )?)
    .map_err(|_| invalid_http("start acceptance header is malformed"))?;
    let target_proof =
        decode_b_target_proof_header(single_header(&lines, TARGET_PROOF_B_TO_A_HEADER)?)?;
    if !header_values(&lines, TARGET_PROOF_A_TO_B_HEADER).is_empty() {
        return Err(invalid_http(
            "response carries the wrong target-proof direction",
        ));
    }
    Ok((acceptance, target_proof))
}

pub(crate) fn seal_local_deriver_a_target_proof_v2(
    binding: &Ed25519YaoOuterBindingV2,
    plaintext: &[u8],
    recipient_public_key: &[u8; 32],
) -> StreamResult<Ed25519YaoDeriverAToBTargetProofPayloadV2> {
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(recipient_public_key)
        .map_err(|_| protocol("Deriver B target-proof public key is malformed"))?;
    let aad = Ed25519YaoDeriverAToBTargetProofPayloadV2::aad_for_binding(binding)
        .map_err(|_| protocol("A target-proof binding is malformed"))?;
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    let (encapsulated_key, ciphertext) = TargetProofHpkeV2::seal_base(
        &mut rng,
        &public_key,
        TARGET_PROOF_HPKE_INFO_V2,
        &aad,
        plaintext,
    )
    .map_err(|_| protocol("A target-proof encryption failed"))?;
    let encapsulated_key = encapsulated_key
        .as_ref()
        .try_into()
        .map_err(|_| protocol("A target-proof encapsulated key is malformed"))?;
    Ed25519YaoDeriverAToBTargetProofPayloadV2::new(binding.clone(), encapsulated_key, ciphertext)
        .map_err(|_| protocol("A target-proof payload is malformed"))
}

pub(crate) fn open_local_deriver_a_target_proof_v2(
    payload: &Ed25519YaoDeriverBToATargetProofPayloadV2,
    private_key: &[u8; 32],
) -> StreamResult<Zeroizing<Vec<u8>>> {
    payload
        .validate()
        .map_err(|_| protocol("B target-proof payload is malformed"))?;
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(payload.encapsulated_key())
        .map_err(|_| protocol("B target-proof encapsulated key is malformed"))?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(private_key)
        .map_err(|_| protocol("Deriver A target-proof private key is malformed"))?;
    let aad = Ed25519YaoDeriverBToATargetProofPayloadV2::aad_for_binding(payload.binding())
        .map_err(|_| protocol("B target-proof binding is malformed"))?;
    TargetProofHpkeV2::open_base(
        &encapsulated_key,
        &private_key,
        TARGET_PROOF_HPKE_INFO_V2,
        &aad,
        payload.ciphertext(),
    )
    .map(Zeroizing::new)
    .map_err(|_| protocol("B target-proof decryption failed"))
}

pub(crate) fn seal_local_deriver_b_target_proof_v2(
    binding: &Ed25519YaoOuterBindingV2,
    plaintext: &[u8],
    recipient_public_key: &[u8; 32],
) -> StreamResult<Ed25519YaoDeriverBToATargetProofPayloadV2> {
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(recipient_public_key)
        .map_err(|_| protocol("Deriver A target-proof public key is malformed"))?;
    let aad = Ed25519YaoDeriverBToATargetProofPayloadV2::aad_for_binding(binding)
        .map_err(|_| protocol("B target-proof binding is malformed"))?;
    let mut os_rng = OsRng;
    let mut rng = os_rng.unwrap_mut();
    let (encapsulated_key, ciphertext) = TargetProofHpkeV2::seal_base(
        &mut rng,
        &public_key,
        TARGET_PROOF_HPKE_INFO_V2,
        &aad,
        plaintext,
    )
    .map_err(|_| protocol("B target-proof encryption failed"))?;
    let encapsulated_key = encapsulated_key
        .as_ref()
        .try_into()
        .map_err(|_| protocol("B target-proof encapsulated key is malformed"))?;
    Ed25519YaoDeriverBToATargetProofPayloadV2::new(binding.clone(), encapsulated_key, ciphertext)
        .map_err(|_| protocol("B target-proof payload is malformed"))
}

pub(crate) fn open_local_deriver_b_target_proof_v2(
    payload: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
    private_key: &[u8; 32],
) -> StreamResult<Zeroizing<Vec<u8>>> {
    payload
        .validate()
        .map_err(|_| protocol("A target-proof payload is malformed"))?;
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(payload.encapsulated_key())
        .map_err(|_| protocol("A target-proof encapsulated key is malformed"))?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(private_key)
        .map_err(|_| protocol("Deriver B target-proof private key is malformed"))?;
    let aad = Ed25519YaoDeriverAToBTargetProofPayloadV2::aad_for_binding(payload.binding())
        .map_err(|_| protocol("A target-proof binding is malformed"))?;
    TargetProofHpkeV2::open_base(
        &encapsulated_key,
        &private_key,
        TARGET_PROOF_HPKE_INFO_V2,
        &aad,
        payload.ciphertext(),
    )
    .map(Zeroizing::new)
    .map_err(|_| protocol("A target-proof decryption failed"))
}

fn encode_a_target_proof_header(
    payload: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
) -> io::Result<String> {
    let wire = payload
        .encode_fixed_wire()
        .map_err(|_| io::Error::other("A target-proof wire encoding failed"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire))
}

fn decode_a_target_proof_header(
    value: &str,
) -> StreamResult<Ed25519YaoDeriverAToBTargetProofPayloadV2> {
    let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_http("A target-proof header is malformed"))?;
    Ed25519YaoDeriverAToBTargetProofPayloadV2::decode_fixed_wire(&wire)
        .map_err(|_| invalid_http("A target-proof wire is malformed"))
}

fn encode_b_target_proof_header(
    payload: &Ed25519YaoDeriverBToATargetProofPayloadV2,
) -> io::Result<String> {
    let wire = payload
        .encode_fixed_wire()
        .map_err(|_| io::Error::other("B target-proof wire encoding failed"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire))
}

fn decode_b_target_proof_header(
    value: &str,
) -> StreamResult<Ed25519YaoDeriverBToATargetProofPayloadV2> {
    let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_http("B target-proof header is malformed"))?;
    Ed25519YaoDeriverBToATargetProofPayloadV2::decode_fixed_wire(&wire)
        .map_err(|_| invalid_http("B target-proof wire is malformed"))
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
