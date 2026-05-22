use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::artifact::PrimeOrderEvaluatorOps;
use crate::candidate::CandidateBackendFamily;
use crate::ddh::{
    DdhHssEvaluationKey, DdhHssInputShareBundle, DdhHssOtInputBundleOffer,
    DdhHssOtReleasedRemoteBundle, DdhHssOtResponseBundle, DdhHssOtSelectionBundle,
    DdhHssSharedWord, DdhHssTransportBundle, DdhHssTransportPurpose, HiddenEvalInputOwner,
};
use crate::shared::{ProtoError, ProtoResult};

pub const PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION: &str = "prime_order_succinct_hss_v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HiddenCoreMaterialization {
    DdhPrimitiveBaseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub encoder_version: String,
    pub artifact_bytes: u64,
    pub artifact_digest: [u8; 32],
    pub section_count: usize,
    pub context_binding: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub round_template_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunBindings {
    pub client_input_commitment: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorWitness {
    pub total_steps: usize,
    pub curve_cost_units: u64,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub output_checksum: u64,
    pub final_point_compressed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryMaterial {
    pub report_version: String,
    pub fixed_function_id: String,
    pub projection_mode: OutputProjectionMode,
    pub hidden_core_materialization: HiddenCoreMaterialization,
    pub artifact: ArtifactSummary,
    pub evaluation_key: DdhHssEvaluationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientPacket {
    pub context_binding: [u8; 32],
    pub y_client_request: DdhHssOtSelectionBundle,
    pub tau_client_request: DdhHssOtSelectionBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOtOffer {
    pub context_binding: [u8; 32],
    pub y_client_offer: DdhHssOtInputBundleOffer,
    pub tau_client_offer: DdhHssOtInputBundleOffer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransportKind {
    ClientOtOffer,
    ClientOtRequest,
    ServerAssistInit,
    ClientStageRequest,
    ServerStageResponse,
    ServerFinalize,
    #[cfg(test)]
    ServerPacket,
    ClientOutput,
    SeedOutput,
    ServerOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TransportFrame {
    pub(crate) report_version: String,
    pub(crate) context_binding: [u8; 32],
    pub(crate) kind: TransportKind,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    pub bytes: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPacket {
    pub context_binding: [u8; 32],
    pub ot_transcript: OtTranscript,
    pub y_client_response: DdhHssOtResponseBundle,
    pub tau_client_response: DdhHssOtResponseBundle,
    pub y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub server_inputs: ServerInputsPacket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSeparatedServerInputDeliveryPacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub transcript_id: TranscriptId,
    pub server_input_commitment: [u8; 32],
    pub y_client_response: DdhHssOtResponseBundle,
    pub tau_client_response: DdhHssOtResponseBundle,
    pub y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub server_inputs: RoleSeparatedServerInputsPacket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtTranscript {
    pub context_binding: [u8; 32],
    pub y_client_offer_commitment: [u8; 32],
    pub y_client_request_commitment: [u8; 32],
    pub y_client_response_commitment: [u8; 32],
    pub y_client_remote_release_binding: [u8; 32],
    pub tau_client_offer_commitment: [u8; 32],
    pub tau_client_request_commitment: [u8; 32],
    pub tau_client_response_commitment: [u8; 32],
    pub tau_client_remote_release_binding: [u8; 32],
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputProjectionMode {
    TrustedServerProjection,
    ClientMaskedProjection { mask_commitment: [u8; 32] },
}

impl OutputProjectionMode {
    pub fn trusted_server_projection() -> Self {
        Self::TrustedServerProjection
    }

    pub fn client_masked_projection(mask_commitment: [u8; 32]) -> Self {
        Self::ClientMaskedProjection { mask_commitment }
    }

    pub fn domain_tag(&self) -> &'static [u8] {
        match self {
            Self::TrustedServerProjection => b"trusted_server_projection",
            Self::ClientMaskedProjection { .. } => b"client_masked_projection",
        }
    }

    pub fn mask_commitment(&self) -> Option<[u8; 32]> {
        match self {
            Self::TrustedServerProjection => None,
            Self::ClientMaskedProjection { mask_commitment } => Some(*mask_commitment),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientOutputValueKind {
    UnmaskedClientBase,
    ClientBlindedBase,
}

impl ClientOutputValueKind {
    pub fn for_projection_mode(projection_mode: &OutputProjectionMode) -> Self {
        match projection_mode {
            OutputProjectionMode::TrustedServerProjection => Self::UnmaskedClientBase,
            OutputProjectionMode::ClientMaskedProjection { .. } => Self::ClientBlindedBase,
        }
    }

    pub fn domain_tag(&self) -> &'static [u8] {
        match self {
            Self::UnmaskedClientBase => b"unmasked_client_base",
            Self::ClientBlindedBase => b"client_blinded_base",
        }
    }

    pub fn bundle_label(&self) -> &'static str {
        match self {
            Self::UnmaskedClientBase => "x_client_base",
            Self::ClientBlindedBase => "x_client_base_blinded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOutputPacket {
    pub context_binding: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
    pub projection_mode: OutputProjectionMode,
    pub value_kind: ClientOutputValueKind,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedOutputPacket {
    pub context_binding: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOutputPacket {
    pub context_binding: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputDelivery {
    pub client: WireMessage,
    pub seed: WireMessage,
    pub server: WireMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleSeparatedOutputDeliveryPayload {
    ClientOutputOnly {
        client_output: WireMessage,
        client_output_binding: [u8; 32],
    },
    ClientOutputAndSeedOutput {
        client_output: WireMessage,
        client_output_binding: [u8; 32],
        seed_output: WireMessage,
        seed_output_binding: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSeparatedOutputDeliveryPacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub final_transcript_digest: [u8; 32],
    pub bindings: RunBindings,
    pub projection_mode: OutputProjectionMode,
    pub allowed_output_kind: AllowedOutputKind,
    pub payload: RoleSeparatedOutputDeliveryPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedEvaluatorArtifact {
    pub context_binding: [u8; 32],
    pub bindings: RunBindings,
    pub projection_mode: OutputProjectionMode,
    pub client_output_value_kind: ClientOutputValueKind,
    pub client_output_commitment: [u8; 32],
    pub evaluator_witness: EvaluatorWitness,
    pub client_output: WireMessage,
    pub client_output_binding: [u8; 32],
    pub seed_output: WireMessage,
    pub seed_output_binding: [u8; 32],
    pub server_output_payload_binding: [u8; 32],
    pub server_output_payload: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInputsPacket {
    pub context_binding: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSeparatedServerInputsPacket {
    pub context_binding: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerEvalHandle {
    pub bytes: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TranscriptId {
    pub bytes: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerEvalStageKind {
    AddStage,
    MessageSchedule,
    RoundCore,
    OutputProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerEvalStageId {
    pub kind: ServerEvalStageKind,
    pub ordinal: u16,
}

impl ServerEvalStageId {
    pub const MESSAGE_SCHEDULE_ROUNDS: u16 = 64;
    pub const ROUND_CORE_ROUNDS: u16 = 80;

    pub const fn add_stage() -> Self {
        Self {
            kind: ServerEvalStageKind::AddStage,
            ordinal: 0,
        }
    }

    pub const fn message_schedule(ordinal: u16) -> Self {
        Self {
            kind: ServerEvalStageKind::MessageSchedule,
            ordinal,
        }
    }

    pub const fn round_core(ordinal: u16) -> Self {
        Self {
            kind: ServerEvalStageKind::RoundCore,
            ordinal,
        }
    }

    pub const fn output_projection() -> Self {
        Self {
            kind: ServerEvalStageKind::OutputProjection,
            ordinal: 0,
        }
    }
}

impl ClientOtRequestCommitments {
    pub fn from_client_packet(packet: &ClientPacket) -> Self {
        Self {
            y_client_request_commitment: packet.y_client_request.commitment,
            tau_client_request_commitment: packet.tau_client_request.commitment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedOutputKind {
    ClientOutputOnly,
    ClientOutputAndSeedOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOtRequestCommitments {
    pub y_client_request_commitment: [u8; 32],
    pub tau_client_request_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStageCommitments {
    pub digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStageCommitments {
    pub digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddStageRequestPayload {
    pub client_input_commitment: [u8; 32],
    pub client_stage_openings_digest: [u8; 32],
    pub client_stage_nonce: [u8; 16],
    pub y_client_bundle_payload: Vec<u8>,
    pub tau_client_bundle_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSeparatedAddStageRequestPayload {
    pub client_input_commitment: [u8; 32],
    pub client_stage_openings_digest: [u8; 32],
    pub client_stage_nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddStageResponsePayload {
    pub server_stage_token: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub server_stage_digest: [u8; 32],
    pub execution_checkpoint_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageScheduleRequestPayload {
    pub schedule_step: u16,
    pub client_schedule_digest: [u8; 32],
    pub prior_server_stage_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageScheduleResponsePayload {
    pub schedule_step: u16,
    pub server_schedule_digest: [u8; 32],
    pub next_stage_token: [u8; 32],
    pub execution_checkpoint_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundCoreRequestPayload {
    pub round_index: u16,
    pub client_round_digest: [u8; 32],
    pub prior_server_stage_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundCoreResponsePayload {
    pub round_index: u16,
    pub server_round_digest: [u8; 32],
    pub next_stage_token: [u8; 32],
    pub execution_checkpoint_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputProjectionRequestPayload {
    pub final_client_digest: [u8; 32],
    pub prior_server_stage_digest: [u8; 32],
    pub projection_mode: OutputProjectionMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputProjectionResponsePayload {
    pub final_server_digest: [u8; 32],
    pub output_release_token: [u8; 32],
    pub allowed_output_kind: AllowedOutputKind,
    pub projection_mode: OutputProjectionMode,
    pub execution_checkpoint_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientStagePayload {
    AddStage(AddStageRequestPayload),
    MessageSchedule(MessageScheduleRequestPayload),
    RoundCore(RoundCoreRequestPayload),
    OutputProjection(OutputProjectionRequestPayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleSeparatedClientStagePayload {
    AddStage(RoleSeparatedAddStageRequestPayload),
    MessageSchedule(MessageScheduleRequestPayload),
    RoundCore(RoundCoreRequestPayload),
    OutputProjection(OutputProjectionRequestPayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerStagePayload {
    AddStage(AddStageResponsePayload),
    MessageSchedule(MessageScheduleResponsePayload),
    RoundCore(RoundCoreResponsePayload),
    OutputProjection(OutputProjectionResponsePayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOtRequestPacket {
    pub context_binding: [u8; 32],
    pub transcript_id: TranscriptId,
    pub client_ot_request: ClientPacket,
    pub client_request_commitments: ClientOtRequestCommitments,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAssistInitPacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub transcript_id: TranscriptId,
    pub server_input_commitment: [u8; 32],
    pub y_client_response: DdhHssOtResponseBundle,
    pub tau_client_response: DdhHssOtResponseBundle,
    pub y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStageRequestPacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub stage_id: ServerEvalStageId,
    pub prior_transcript_digest: [u8; 32],
    pub client_stage_payload: ClientStagePayload,
    pub client_stage_commitments: ClientStageCommitments,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSeparatedClientStageRequestPacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub stage_id: ServerEvalStageId,
    pub prior_transcript_digest: [u8; 32],
    pub client_stage_payload: RoleSeparatedClientStagePayload,
    pub client_stage_commitments: ClientStageCommitments,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStageResponsePacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub stage_id: ServerEvalStageId,
    pub next_transcript_digest: [u8; 32],
    pub server_stage_payload: ServerStagePayload,
    pub server_stage_commitments: ServerStageCommitments,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerFinalizePacket {
    pub context_binding: [u8; 32],
    pub server_eval_handle: ServerEvalHandle,
    pub final_transcript_digest: [u8; 32],
    pub allowed_output_kind: AllowedOutputKind,
    pub projection_mode: OutputProjectionMode,
    pub client_output: WireMessage,
    pub seed_output: Option<WireMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub report_version: String,
    pub backend_family: CandidateBackendFamily,
    pub fixed_function_id: String,
    pub hidden_core_materialization: HiddenCoreMaterialization,
    pub artifact: ArtifactSummary,
    pub bindings: RunBindings,
    pub projection_mode: OutputProjectionMode,
    pub evaluator_witness: EvaluatorWitness,
    pub output_delivery: OutputDelivery,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JointWordWire {
    pub(crate) width_bits: u16,
    pub(crate) left_word: u64,
    pub(crate) right_word: u64,
    pub(crate) left_commitment: [u8; 32],
    pub(crate) right_commitment: [u8; 32],
    pub(crate) provenance_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JointBundleWire {
    pub(crate) owner: HiddenEvalInputOwner,
    pub(crate) label: String,
    pub(crate) words: Vec<JointWordWire>,
    pub(crate) commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EncodedBundlePayload {
    pub(crate) bundle: JointBundleWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EncodedTransportPairPayload {
    pub(crate) left: DdhHssTransportBundle,
    pub(crate) right: DdhHssTransportBundle,
}

#[derive(Debug, Serialize)]
pub(crate) struct EncodedTransportPairPayloadRef<'a> {
    pub(crate) left: &'a DdhHssTransportBundle,
    pub(crate) right: &'a DdhHssTransportBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EncodedServerInputsPayload {
    pub(crate) y_relayer_left: DdhHssTransportBundle,
    pub(crate) y_relayer_right: DdhHssTransportBundle,
    pub(crate) tau_relayer_left: DdhHssTransportBundle,
    pub(crate) tau_relayer_right: DdhHssTransportBundle,
}

#[derive(Debug, Serialize)]
pub(crate) struct EncodedServerInputsPayloadRef<'a> {
    pub(crate) y_relayer_left: &'a DdhHssTransportBundle,
    pub(crate) y_relayer_right: &'a DdhHssTransportBundle,
    pub(crate) tau_relayer_left: &'a DdhHssTransportBundle,
    pub(crate) tau_relayer_right: &'a DdhHssTransportBundle,
}

pub(crate) fn encode_transport_message<T: Serialize>(
    context_binding: [u8; 32],
    kind: TransportKind,
    payload: &T,
) -> ProtoResult<WireMessage> {
    let payload_bytes = serialize_transport_payload_with_label("transport_frame", payload)?;
    let frame = TransportFrame {
        report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
        context_binding,
        kind,
        payload: payload_bytes,
    };
    let bytes = bincode::serialize(&frame).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize prime-order succinct HSS transport frame for {:?}: {err}",
            kind
        ))
    })?;
    Ok(WireMessage { bytes })
}

pub(crate) fn decode_transport_message<T: DeserializeOwned>(
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
    deserialize_transport_payload_with_label("transport_frame", &frame.payload)
}

fn serialize_transport_payload_with_label<T: Serialize>(
    label: &str,
    payload: &T,
) -> ProtoResult<Vec<u8>> {
    bincode::serialize(payload).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize transport payload for {}: {err}",
            label
        ))
    })
}

fn deserialize_transport_payload<T: DeserializeOwned>(
    purpose: DdhHssTransportPurpose,
    plaintext: &[u8],
) -> ProtoResult<T> {
    deserialize_transport_payload_with_label(purpose.as_str(), plaintext)
}

fn deserialize_transport_payload_with_label<T: DeserializeOwned>(
    label: &str,
    plaintext: &[u8],
) -> ProtoResult<T> {
    bincode::deserialize(plaintext).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode transport payload for {}: {err}",
            label
        ))
    })
}

fn wire_word_from_joint(word: &DdhHssSharedWord) -> JointWordWire {
    JointWordWire {
        width_bits: word.width_bits,
        left_word: word.left_word,
        right_word: word.right_word,
        left_commitment: word.left_commitment,
        right_commitment: word.right_commitment,
        provenance_digest: word.provenance_digest,
    }
}

fn joint_word_from_wire(word: JointWordWire) -> DdhHssSharedWord {
    DdhHssSharedWord {
        width_bits: word.width_bits,
        left_word: word.left_word,
        right_word: word.right_word,
        left_commitment: word.left_commitment,
        right_commitment: word.right_commitment,
        provenance_digest: word.provenance_digest,
    }
}

fn wire_bundle_from_joint(bundle: &DdhHssInputShareBundle) -> JointBundleWire {
    JointBundleWire {
        owner: bundle.owner,
        label: bundle.label.clone(),
        words: bundle.words.iter().map(wire_word_from_joint).collect(),
        commitment: bundle.commitment,
    }
}

fn joint_bundle_from_wire(bundle: JointBundleWire) -> DdhHssInputShareBundle {
    DdhHssInputShareBundle {
        owner: bundle.owner,
        label: bundle.label,
        words: bundle.words.into_iter().map(joint_word_from_wire).collect(),
        commitment: bundle.commitment,
    }
}

pub(crate) fn serialize_encoded_bundle_payload(
    bundle: &DdhHssInputShareBundle,
) -> ProtoResult<Vec<u8>> {
    let payload = EncodedBundlePayload {
        bundle: wire_bundle_from_joint(bundle),
    };
    serialize_transport_payload_with_label("encoded_bundle", &payload)
}

pub(crate) fn deserialize_encoded_bundle_payload(
    purpose: DdhHssTransportPurpose,
    plaintext: &[u8],
) -> ProtoResult<DdhHssInputShareBundle> {
    let payload: EncodedBundlePayload = deserialize_transport_payload(purpose, plaintext)?;
    Ok(joint_bundle_from_wire(payload.bundle))
}

pub(crate) fn deserialize_encoded_bundle_payload_unsealed(
    plaintext: &[u8],
) -> ProtoResult<DdhHssInputShareBundle> {
    let payload: EncodedBundlePayload =
        deserialize_transport_payload_with_label("encoded_bundle", plaintext)?;
    Ok(joint_bundle_from_wire(payload.bundle))
}

pub(crate) fn serialize_transport_pair_payload(
    label: &str,
    left: &DdhHssTransportBundle,
    right: &DdhHssTransportBundle,
) -> ProtoResult<Vec<u8>> {
    let payload = EncodedTransportPairPayloadRef { left, right };
    serialize_transport_payload_with_label(label, &payload)
}

pub(crate) fn deserialize_transport_pair_payload(
    purpose: DdhHssTransportPurpose,
    plaintext: &[u8],
) -> ProtoResult<(DdhHssTransportBundle, DdhHssTransportBundle)> {
    let payload: EncodedTransportPairPayload = deserialize_transport_payload(purpose, plaintext)?;
    Ok((payload.left, payload.right))
}

pub(crate) fn serialize_server_inputs_payload(
    y_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
    tau_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
) -> ProtoResult<Vec<u8>> {
    let payload = EncodedServerInputsPayloadRef {
        y_relayer_left: &y_relayer.0,
        y_relayer_right: &y_relayer.1,
        tau_relayer_left: &tau_relayer.0,
        tau_relayer_right: &tau_relayer.1,
    };
    serialize_transport_payload_with_label("server_inputs", &payload)
}

pub(crate) fn deserialize_server_inputs_payload(
    plaintext: &[u8],
) -> ProtoResult<EncodedServerInputsPayload> {
    deserialize_transport_payload(DdhHssTransportPurpose::ServerInput, plaintext)
}
