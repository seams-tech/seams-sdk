use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    ServerPacket,
    EvaluationResult,
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
pub struct ClientOutputPacket {
    pub context_binding: [u8; 32],
    pub run_binding: [u8; 32],
    pub evaluation_digest: [u8; 32],
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
pub struct EvaluationResult {
    pub context_binding: [u8; 32],
    pub bindings: RunBindings,
    pub evaluator_witness: EvaluatorWitness,
    pub client_output: WireMessage,
    pub client_output_binding: [u8; 32],
    pub seed_output: WireMessage,
    pub seed_output_binding: [u8; 32],
    pub server_output_payload_binding: [u8; 32],
    pub server_output_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInputsPacket {
    pub context_binding: [u8; 32],
    pub server_input_commitment: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub report_version: String,
    pub backend_family: CandidateBackendFamily,
    pub fixed_function_id: String,
    pub hidden_core_materialization: HiddenCoreMaterialization,
    pub artifact: ArtifactSummary,
    pub bindings: RunBindings,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenedServerInputs {
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

impl OpenedServerInputs {
    pub(crate) fn server_input_commitment(&self, evaluation_key: &DdhHssEvaluationKey) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"succinct-garbling-proto/ddh-hss/combined-input-commitment/v0");
        hasher.update(evaluation_key.key_id);
        hasher.update(b"server");
        for bundle in [
            (
                &self.y_relayer_left.commitment,
                self.y_relayer_left.label.as_bytes(),
            ),
            (
                &self.tau_relayer_left.commitment,
                self.tau_relayer_left.label.as_bytes(),
            ),
        ] {
            hasher.update(bundle.0);
            hasher.update(bundle.1);
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

pub(crate) fn deserialize_server_inputs_payload_opened(
    plaintext: &[u8],
) -> ProtoResult<OpenedServerInputs> {
    let payload: EncodedServerInputsPayload = deserialize_server_inputs_payload(plaintext)?;
    Ok(OpenedServerInputs {
        y_relayer_left: payload.y_relayer_left,
        y_relayer_right: payload.y_relayer_right,
        tau_relayer_left: payload.tau_relayer_left,
        tau_relayer_right: payload.tau_relayer_right,
    })
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
