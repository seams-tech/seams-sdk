//! Transport-neutral split-role driver for the passive viability protocol.
//!
//! This benchmark-only state machine models transport closure as explicit
//! consuming events. It owns no blocking I/O adapter and exposes no whole-body
//! table representation.

use core::fmt;
use core::marker::PhantomData;

use zeroize::{Zeroize, Zeroizing};

use super::ot::{
    ActivationOtFamily, BaseChoices, BaseOffer, ExportOtFamily, ExtensionMatrix, MaskedPayloads,
    OtError, OtFamily, ReceiverAwaitBaseChoices, ReceiverAwaitMaskedPayloads, ReceiverChoices,
    ReceiverStart, SenderAwaitExtension, SenderPayloads, SenderStart,
};
use super::packages::{EncodedRecipientPackage, RecipientPackageError};
#[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
use super::packages::{ACTIVATION_PACKAGE_BYTES, EXPORT_PACKAGE_BYTES};
use super::phase4::{
    activation_ot_session, activation_transcript_start, advance_transcript, evaluator_inputs,
    export_ot_session, export_transcript_start, prepare_labels, protocol_domain,
    Phase4CeremonyError, PreparedLabels,
};
use super::role_protocol_support::{
    complete_activation_deriver_a, complete_activation_deriver_b, complete_export_deriver_a,
    complete_export_deriver_b, CompletedDeriverAActivation, CompletedDeriverAExport,
    CompletedDeriverBActivation, CompletedDeriverBExport, ACTIVATION_DIRECT_MESSAGE_BYTES,
    ACTIVATION_RETURNED_MESSAGE_BYTES, ACTIVATION_TRANSLATION_MESSAGE_BYTES,
    EXPORT_DIRECT_MESSAGE_BYTES, EXPORT_RETURNED_MESSAGE_BYTES, EXPORT_TRANSLATION_MESSAGE_BYTES,
};
use super::roles::{
    ActivationADirectInputLabels, ActivationASelectedOutputLabels, ActivationBOutputDecodeBits,
    ActivationDeriverAStart, ActivationDeriverBStart, DecodedDeriverAActivationShares,
    DecodedDeriverAExportSeedShare, DecodedDeriverBActivationShares,
    DecodedDeriverBExportSeedShare, ExportADirectInputLabels, ExportASelectedOutputLabels,
    ExportBOutputDecodeBits, ExportDeriverAStart, ExportDeriverBStart, RoleBoundaryError,
    SecretPayload, TranscriptDigest32, ACTIVATION_INPUT_BITS_PER_ROLE,
    ACTIVATION_OUTPUT_BITS_PER_ROLE, EXPORT_INPUT_BITS_PER_ROLE, EXPORT_OUTPUT_BITS_PER_ROLE,
};
use super::runtime::{
    CircuitRunError, EvaluatorOutputTranslation, EvaluatorOwnedOutputLabels, ReturnedOutputDecoder,
    ReturnedOutputLabels,
};
#[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
use super::stream::STREAM_MANIFEST_BYTES;
use super::stream::{
    ActivationStream, ExactTableStreamReceipt, ExportStream, FixedChunkProfile, FixedStreamFamily,
    PassiveStreamManifest, StreamWireError, TableFrameDecoder, TableFrameEncoder,
    TABLE_FRAME_HEADER_BYTES,
};
use super::stream_runtime::{
    activation_evaluator_machine, activation_garbler_machine, export_evaluator_machine,
    export_garbler_machine, EvaluatorAdvance, EvaluatorBodyComplete, EvaluatorNeedsFrame,
    GarblerAdvance, GarblerMachine, StreamRuntimeError,
};
use super::{Evaluator, EvaluatorWire, Garbler, GarblerWire, GlobalDelta};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoleProtocolError {
    Ceremony(Phase4CeremonyError),
    Ot(OtError),
    Role(RoleBoundaryError),
    Circuit(CircuitRunError),
    Stream(StreamWireError),
    Runtime(StreamRuntimeError),
    Package(RecipientPackageError),
    ControlFrameLength,
    TableFrameLength,
    StateInvariant,
}

impl fmt::Display for RoleProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transport-neutral passive role protocol failed")
    }
}

impl From<Phase4CeremonyError> for RoleProtocolError {
    fn from(error: Phase4CeremonyError) -> Self {
        Self::Ceremony(error)
    }
}

impl From<OtError> for RoleProtocolError {
    fn from(error: OtError) -> Self {
        Self::Ot(error)
    }
}

impl From<RoleBoundaryError> for RoleProtocolError {
    fn from(error: RoleBoundaryError) -> Self {
        Self::Role(error)
    }
}

impl From<CircuitRunError> for RoleProtocolError {
    fn from(error: CircuitRunError) -> Self {
        Self::Circuit(error)
    }
}

impl From<StreamWireError> for RoleProtocolError {
    fn from(error: StreamWireError) -> Self {
        Self::Stream(error)
    }
}

impl From<StreamRuntimeError> for RoleProtocolError {
    fn from(error: StreamRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RecipientPackageError> for RoleProtocolError {
    fn from(error: RecipientPackageError) -> Self {
        Self::Package(error)
    }
}

impl From<getrandom::Error> for RoleProtocolError {
    fn from(error: getrandom::Error) -> Self {
        Self::Ceremony(error.into())
    }
}

mod sealed {
    pub trait Sealed {}
}

pub(super) trait ProtocolFamily: FixedStreamFamily + sealed::Sealed + Sized {
    type Ot: OtFamily;
    type AStart;
    type BStart;
    type AShare;
    type BShare;
    type ACompleted;
    type BCompleted;

    const INPUT_BITS_PER_ROLE: usize;
    const OUTPUT_BITS_PER_ROLE: usize;
    const DIRECT_MESSAGE_BYTES: usize;
    const TRANSLATION_MESSAGE_BYTES: usize;
    const RETURNED_MESSAGE_BYTES: usize;

    fn transcript_start(binding: Self::Binding) -> Result<TranscriptDigest32, Phase4CeremonyError>;
    fn ot_session(binding: Self::Binding) -> Result<super::ot::OtSessionId, Phase4CeremonyError>;
    fn gate_domain(binding: Self::Binding) -> u64;
    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    fn session(binding: Self::Binding) -> [u8; 32];
    fn a_binding(start: &Self::AStart) -> Self::Binding;
    fn prepare_a(
        start: Self::AStart,
        garbler: &Garbler,
    ) -> Result<(Self::Binding, PreparedLabels), Phase4CeremonyError>;
    fn prepare_b(
        start: Self::BStart,
    ) -> Result<(Self::Binding, ReceiverChoices<Self::Ot>), RoleProtocolError>;
    fn encode_direct(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError>;
    fn decode_direct(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError>;
    fn encode_translation(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError>;
    fn decode_translation(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError>;
    fn encode_returned(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError>;
    fn decode_returned(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError>;
    fn garbler_machine<C: FixedChunkProfile>(
        garbler: Garbler,
        inputs: Vec<GarblerWire>,
    ) -> Result<GarblerMachine<Self, C>, StreamRuntimeError>;
    fn evaluator_machine<C: FixedChunkProfile>(
        evaluator: Evaluator,
        inputs: Vec<EvaluatorWire>,
    ) -> Result<super::stream_runtime::EvaluatorMachine<Self, C>, StreamRuntimeError>;
    fn decode_a_share(decoded: &[u8]) -> Result<Self::AShare, RoleBoundaryError>;
    fn decode_b_share(decoded: &[u8]) -> Result<Self::BShare, RoleBoundaryError>;
    fn complete_a(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        share: Self::AShare,
    ) -> Result<Self::ACompleted, RecipientPackageError>;
    fn complete_b(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        share: Self::BShare,
    ) -> Result<Self::BCompleted, RecipientPackageError>;
}

impl sealed::Sealed for ActivationStream {}

impl ProtocolFamily for ActivationStream {
    type Ot = ActivationOtFamily;
    type AStart = ActivationDeriverAStart;
    type BStart = ActivationDeriverBStart;
    type AShare = DecodedDeriverAActivationShares;
    type BShare = DecodedDeriverBActivationShares;
    type ACompleted = CompletedDeriverAActivation;
    type BCompleted = CompletedDeriverBActivation;

    const INPUT_BITS_PER_ROLE: usize = ACTIVATION_INPUT_BITS_PER_ROLE;
    const OUTPUT_BITS_PER_ROLE: usize = ACTIVATION_OUTPUT_BITS_PER_ROLE;
    const DIRECT_MESSAGE_BYTES: usize = ACTIVATION_DIRECT_MESSAGE_BYTES;
    const TRANSLATION_MESSAGE_BYTES: usize = ACTIVATION_TRANSLATION_MESSAGE_BYTES;
    const RETURNED_MESSAGE_BYTES: usize = ACTIVATION_RETURNED_MESSAGE_BYTES;

    fn transcript_start(binding: Self::Binding) -> Result<TranscriptDigest32, Phase4CeremonyError> {
        activation_transcript_start(binding)
    }

    fn ot_session(binding: Self::Binding) -> Result<super::ot::OtSessionId, Phase4CeremonyError> {
        activation_ot_session(binding)
    }

    fn gate_domain(binding: Self::Binding) -> u64 {
        binding.gate_domain()
    }

    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    fn session(binding: Self::Binding) -> [u8; 32] {
        *binding.session_bytes()
    }

    fn a_binding(start: &Self::AStart) -> Self::Binding {
        start.binding()
    }

    fn prepare_a(
        start: Self::AStart,
        garbler: &Garbler,
    ) -> Result<(Self::Binding, PreparedLabels), Phase4CeremonyError> {
        let input = start.into_garbler_input();
        let binding = input.binding();
        let labels = prepare_labels(garbler, input.bitpacked_lsb0(), Self::INPUT_BITS_PER_ROLE)?;
        Ok((binding, labels))
    }

    fn prepare_b(
        start: Self::BStart,
    ) -> Result<(Self::Binding, ReceiverChoices<Self::Ot>), RoleProtocolError> {
        let choices = start.into_ot_choices();
        let binding = choices.binding();
        let encoded = choices.bitpacked_lsb0().to_vec();
        Ok((binding, ReceiverChoices::from_packed_bytes(encoded)?))
    }

    fn encode_direct(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError> {
        let message = ActivationADirectInputLabels::from_secret_payload(
            binding.bind_transcript(transcript),
            payload,
        )?;
        Ok(message.encode().as_slice().to_vec())
    }

    fn decode_direct(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError> {
        Ok(
            ActivationADirectInputLabels::decode(binding.bind_transcript(transcript), encoded)?
                .into_secret_payload(),
        )
    }

    fn encode_translation(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError> {
        let message = ActivationBOutputDecodeBits::from_secret_payload(
            binding.bind_transcript(transcript),
            payload,
        )?;
        Ok(message.encode().as_slice().to_vec())
    }

    fn decode_translation(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError> {
        Ok(
            ActivationBOutputDecodeBits::decode(binding.bind_transcript(transcript), encoded)?
                .into_secret_payload(),
        )
    }

    fn encode_returned(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError> {
        let message = ActivationASelectedOutputLabels::from_secret_payload(
            binding.bind_transcript(transcript),
            payload,
        )?;
        Ok(message.encode().as_slice().to_vec())
    }

    fn decode_returned(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError> {
        Ok(
            ActivationASelectedOutputLabels::decode(binding.bind_transcript(transcript), encoded)?
                .into_secret_payload(),
        )
    }

    fn garbler_machine<C: FixedChunkProfile>(
        garbler: Garbler,
        inputs: Vec<GarblerWire>,
    ) -> Result<GarblerMachine<Self, C>, StreamRuntimeError> {
        activation_garbler_machine::<C>(garbler, inputs, Self::OUTPUT_BITS_PER_ROLE)
    }

    fn evaluator_machine<C: FixedChunkProfile>(
        evaluator: Evaluator,
        inputs: Vec<EvaluatorWire>,
    ) -> Result<super::stream_runtime::EvaluatorMachine<Self, C>, StreamRuntimeError> {
        activation_evaluator_machine::<C>(evaluator, inputs, Self::OUTPUT_BITS_PER_ROLE)
    }

    fn decode_a_share(decoded: &[u8]) -> Result<Self::AShare, RoleBoundaryError> {
        DecodedDeriverAActivationShares::from_decoded_output(decoded)
    }

    fn decode_b_share(decoded: &[u8]) -> Result<Self::BShare, RoleBoundaryError> {
        DecodedDeriverBActivationShares::from_decoded_output(decoded)
    }

    fn complete_a(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        share: Self::AShare,
    ) -> Result<Self::ACompleted, RecipientPackageError> {
        complete_activation_deriver_a(binding, transcript, share)
    }

    fn complete_b(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        share: Self::BShare,
    ) -> Result<Self::BCompleted, RecipientPackageError> {
        complete_activation_deriver_b(binding, transcript, share)
    }
}

impl sealed::Sealed for ExportStream {}

impl ProtocolFamily for ExportStream {
    type Ot = ExportOtFamily;
    type AStart = ExportDeriverAStart;
    type BStart = ExportDeriverBStart;
    type AShare = DecodedDeriverAExportSeedShare;
    type BShare = DecodedDeriverBExportSeedShare;
    type ACompleted = CompletedDeriverAExport;
    type BCompleted = CompletedDeriverBExport;

    const INPUT_BITS_PER_ROLE: usize = EXPORT_INPUT_BITS_PER_ROLE;
    const OUTPUT_BITS_PER_ROLE: usize = EXPORT_OUTPUT_BITS_PER_ROLE;
    const DIRECT_MESSAGE_BYTES: usize = EXPORT_DIRECT_MESSAGE_BYTES;
    const TRANSLATION_MESSAGE_BYTES: usize = EXPORT_TRANSLATION_MESSAGE_BYTES;
    const RETURNED_MESSAGE_BYTES: usize = EXPORT_RETURNED_MESSAGE_BYTES;

    fn transcript_start(binding: Self::Binding) -> Result<TranscriptDigest32, Phase4CeremonyError> {
        export_transcript_start(binding)
    }

    fn ot_session(binding: Self::Binding) -> Result<super::ot::OtSessionId, Phase4CeremonyError> {
        export_ot_session(binding)
    }

    fn gate_domain(binding: Self::Binding) -> u64 {
        binding.gate_domain()
    }

    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    fn session(binding: Self::Binding) -> [u8; 32] {
        *binding.session_bytes()
    }

    fn a_binding(start: &Self::AStart) -> Self::Binding {
        start.binding()
    }

    fn prepare_a(
        start: Self::AStart,
        garbler: &Garbler,
    ) -> Result<(Self::Binding, PreparedLabels), Phase4CeremonyError> {
        let input = start.into_garbler_input();
        let binding = input.binding();
        let labels = prepare_labels(garbler, input.bitpacked_lsb0(), Self::INPUT_BITS_PER_ROLE)?;
        Ok((binding, labels))
    }

    fn prepare_b(
        start: Self::BStart,
    ) -> Result<(Self::Binding, ReceiverChoices<Self::Ot>), RoleProtocolError> {
        let choices = start.into_ot_choices();
        let binding = choices.binding();
        let encoded = choices.bitpacked_lsb0().to_vec();
        Ok((binding, ReceiverChoices::from_packed_bytes(encoded)?))
    }

    fn encode_direct(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError> {
        let message = ExportADirectInputLabels::from_secret_payload(
            binding.bind_transcript(transcript),
            payload,
        )?;
        Ok(message.encode().as_slice().to_vec())
    }

    fn decode_direct(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError> {
        Ok(
            ExportADirectInputLabels::decode(binding.bind_transcript(transcript), encoded)?
                .into_secret_payload(),
        )
    }

    fn encode_translation(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError> {
        let message = ExportBOutputDecodeBits::from_secret_payload(
            binding.bind_transcript(transcript),
            payload,
        )?;
        Ok(message.encode().as_slice().to_vec())
    }

    fn decode_translation(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError> {
        Ok(
            ExportBOutputDecodeBits::decode(binding.bind_transcript(transcript), encoded)?
                .into_secret_payload(),
        )
    }

    fn encode_returned(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        payload: &[u8],
    ) -> Result<Vec<u8>, RoleBoundaryError> {
        let message = ExportASelectedOutputLabels::from_secret_payload(
            binding.bind_transcript(transcript),
            payload,
        )?;
        Ok(message.encode().as_slice().to_vec())
    }

    fn decode_returned(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<SecretPayload, RoleBoundaryError> {
        Ok(
            ExportASelectedOutputLabels::decode(binding.bind_transcript(transcript), encoded)?
                .into_secret_payload(),
        )
    }

    fn garbler_machine<C: FixedChunkProfile>(
        garbler: Garbler,
        inputs: Vec<GarblerWire>,
    ) -> Result<GarblerMachine<Self, C>, StreamRuntimeError> {
        export_garbler_machine::<C>(garbler, inputs, Self::OUTPUT_BITS_PER_ROLE)
    }

    fn evaluator_machine<C: FixedChunkProfile>(
        evaluator: Evaluator,
        inputs: Vec<EvaluatorWire>,
    ) -> Result<super::stream_runtime::EvaluatorMachine<Self, C>, StreamRuntimeError> {
        export_evaluator_machine::<C>(evaluator, inputs, Self::OUTPUT_BITS_PER_ROLE)
    }

    fn decode_a_share(decoded: &[u8]) -> Result<Self::AShare, RoleBoundaryError> {
        DecodedDeriverAExportSeedShare::from_decoded_output(decoded)
    }

    fn decode_b_share(decoded: &[u8]) -> Result<Self::BShare, RoleBoundaryError> {
        DecodedDeriverBExportSeedShare::from_decoded_output(decoded)
    }

    fn complete_a(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        share: Self::AShare,
    ) -> Result<Self::ACompleted, RecipientPackageError> {
        Ok(complete_export_deriver_a(binding, transcript, share))
    }

    fn complete_b(
        binding: Self::Binding,
        transcript: TranscriptDigest32,
        share: Self::BShare,
    ) -> Result<Self::BCompleted, RecipientPackageError> {
        Ok(complete_export_deriver_b(binding, transcript, share))
    }
}

trait ControlKind<F: ProtocolFamily> {
    fn wire_bytes() -> usize;
}

struct OfferKind;
struct BaseChoicesKind;
struct DirectKind;
struct ExtensionKind;
struct MaskedKind;
struct TranslationKind;
struct ReturnedKind;

impl<F: ProtocolFamily> ControlKind<F> for OfferKind {
    fn wire_bytes() -> usize {
        BaseOffer::<F::Ot>::wire_bytes()
    }
}

impl<F: ProtocolFamily> ControlKind<F> for BaseChoicesKind {
    fn wire_bytes() -> usize {
        BaseChoices::<F::Ot>::wire_bytes()
    }
}

impl<F: ProtocolFamily> ControlKind<F> for DirectKind {
    fn wire_bytes() -> usize {
        F::DIRECT_MESSAGE_BYTES
    }
}

impl<F: ProtocolFamily> ControlKind<F> for ExtensionKind {
    fn wire_bytes() -> usize {
        ExtensionMatrix::<F::Ot>::wire_bytes()
    }
}

impl<F: ProtocolFamily> ControlKind<F> for MaskedKind {
    fn wire_bytes() -> usize {
        MaskedPayloads::<F::Ot>::wire_bytes()
    }
}

impl<F: ProtocolFamily> ControlKind<F> for TranslationKind {
    fn wire_bytes() -> usize {
        F::TRANSLATION_MESSAGE_BYTES
    }
}

impl<F: ProtocolFamily> ControlKind<F> for ReturnedKind {
    fn wire_bytes() -> usize {
        F::RETURNED_MESSAGE_BYTES
    }
}

struct EncodedControlMessage<F, K>
where
    F: ProtocolFamily,
    K: ControlKind<F>,
{
    bytes: Zeroizing<Vec<u8>>,
    marker: PhantomData<(F, K)>,
}

impl<F, K> EncodedControlMessage<F, K>
where
    F: ProtocolFamily,
    K: ControlKind<F>,
{
    fn from_encoded(bytes: Vec<u8>) -> Result<Self, RoleProtocolError> {
        if bytes.len() != K::wire_bytes() {
            return Err(RoleProtocolError::ControlFrameLength);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            marker: PhantomData,
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn into_transport_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut *self.bytes)
    }
}

impl<F, K> fmt::Debug for EncodedControlMessage<F, K>
where
    F: ProtocolFamily,
    K: ControlKind<F>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedControlMessage")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

struct EncodedStreamManifest<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    bytes: [u8; super::stream::STREAM_MANIFEST_BYTES],
    marker: PhantomData<(F, C)>,
}

impl<F, C> EncodedStreamManifest<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn from_manifest(manifest: PassiveStreamManifest<F, C>) -> Self {
        Self {
            bytes: manifest.encode(),
            marker: PhantomData,
        }
    }

    fn into_transport_bytes(self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    fn from_transport_bytes(bytes: Vec<u8>) -> Result<Self, RoleProtocolError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| RoleProtocolError::TableFrameLength)?;
        Ok(Self {
            bytes,
            marker: PhantomData,
        })
    }
}

struct EncodedTableFrame<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    bytes: Zeroizing<Vec<u8>>,
    marker: PhantomData<(F, C)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RoleStreamMetrics {
    table_payload_bytes: usize,
    body_bytes: u64,
    frame_count: u32,
    peak_table_buffer_bytes: usize,
    peak_arena_bytes: usize,
    runtime_chunk_to_wire_copy_bytes: usize,
    wire_frame_allocation_bytes: u64,
    peak_wire_frame_allocation_bytes: usize,
    combined_peak_table_buffer_bytes: usize,
}

struct RoleStreamMetricInput {
    table_payload_bytes: usize,
    frame_calls: u32,
    host_boundary_copy_bytes: usize,
    peak_table_buffer_bytes: usize,
    peak_arena_bytes: usize,
    runtime_chunk_to_wire_copy_bytes: usize,
    wire_frame_allocation_bytes: u64,
    peak_wire_frame_allocation_bytes: usize,
    combined_peak_table_buffer_bytes: usize,
}

impl RoleStreamMetrics {
    fn checked<F, C>(
        input: RoleStreamMetricInput,
        receipt: &ExactTableStreamReceipt<F, C>,
    ) -> Result<Self, RoleProtocolError>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        let expected_peak = core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES);
        if input.table_payload_bytes != F::TABLE_PAYLOAD_BYTES
            || input.frame_calls != receipt.frame_count()
            || input.host_boundary_copy_bytes != 0
            || input.peak_table_buffer_bytes != expected_peak
        {
            return Err(RoleProtocolError::StateInvariant);
        }
        Ok(Self {
            table_payload_bytes: input.table_payload_bytes,
            body_bytes: receipt.body_bytes(),
            frame_count: receipt.frame_count(),
            peak_table_buffer_bytes: input.peak_table_buffer_bytes,
            peak_arena_bytes: input.peak_arena_bytes,
            runtime_chunk_to_wire_copy_bytes: input.runtime_chunk_to_wire_copy_bytes,
            wire_frame_allocation_bytes: input.wire_frame_allocation_bytes,
            peak_wire_frame_allocation_bytes: input.peak_wire_frame_allocation_bytes,
            combined_peak_table_buffer_bytes: input.combined_peak_table_buffer_bytes,
        })
    }

    pub(super) const fn table_payload_bytes(self) -> usize {
        self.table_payload_bytes
    }

    pub(super) const fn body_bytes(self) -> u64 {
        self.body_bytes
    }

    pub(super) const fn frame_count(self) -> u32 {
        self.frame_count
    }

    pub(super) const fn peak_table_buffer_bytes(self) -> usize {
        self.peak_table_buffer_bytes
    }

    pub(super) const fn peak_arena_bytes(self) -> usize {
        self.peak_arena_bytes
    }

    pub(super) const fn runtime_chunk_to_wire_copy_bytes(self) -> usize {
        self.runtime_chunk_to_wire_copy_bytes
    }

    pub(super) const fn wire_frame_allocation_bytes(self) -> u64 {
        self.wire_frame_allocation_bytes
    }

    pub(super) const fn peak_wire_frame_allocation_bytes(self) -> usize {
        self.peak_wire_frame_allocation_bytes
    }

    pub(super) const fn combined_peak_table_buffer_bytes(self) -> usize {
        self.combined_peak_table_buffer_bytes
    }
}

impl<F, C> EncodedTableFrame<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn from_parts(
        header: &[u8; TABLE_FRAME_HEADER_BYTES],
        payload: &[u8],
    ) -> Result<Self, RoleProtocolError> {
        if payload.is_empty() || payload.len() > C::MAX_PAYLOAD_BYTES {
            return Err(RoleProtocolError::TableFrameLength);
        }
        let mut bytes =
            Zeroizing::new(Vec::with_capacity(TABLE_FRAME_HEADER_BYTES + payload.len()));
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(payload);
        Ok(Self {
            bytes,
            marker: PhantomData,
        })
    }

    fn from_transport_bytes(bytes: Vec<u8>) -> Result<Self, RoleProtocolError> {
        if bytes.len() <= TABLE_FRAME_HEADER_BYTES
            || bytes.len() > TABLE_FRAME_HEADER_BYTES + C::MAX_PAYLOAD_BYTES
        {
            return Err(RoleProtocolError::TableFrameLength);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            marker: PhantomData,
        })
    }

    fn into_transport_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut *self.bytes)
    }
}

impl<F, C> fmt::Debug for EncodedTableFrame<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedTableFrame")
            .field("wire_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

pub(super) struct DeriverAAwaitOffer<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    start: F::AStart,
    marker: PhantomData<C>,
}

impl<F, C> DeriverAAwaitOffer<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    pub(super) const fn new(start: F::AStart) -> Self {
        Self {
            start,
            marker: PhantomData,
        }
    }

    fn accept_offer(
        self,
        offer_message: EncodedControlMessage<F, OfferKind>,
    ) -> Result<DeriverAReadyBaseChoices<F, C>, RoleProtocolError> {
        let binding = F::a_binding(&self.start);
        let offer = BaseOffer::<F::Ot>::decode_for_session(
            offer_message.as_bytes(),
            F::ot_session(binding)?,
        )?;
        let garbler = Garbler::new(
            GlobalDelta::random()?,
            protocol_domain(F::gate_domain(binding))?,
        );
        let (
            binding,
            PreparedLabels {
                garbler_inputs,
                direct_labels,
                ot_pairs,
            },
        ) = F::prepare_a(self.start, &garbler)?;
        let mut transcript = F::transcript_start(binding)?;
        transcript = advance_transcript(transcript, offer_message.as_bytes())?;
        let payloads = SenderPayloads::<F::Ot>::new(ot_pairs)?;
        let (sender, base_choices) = SenderStart::<F::Ot>::new().begin_os(offer, payloads)?;

        let base_choices =
            EncodedControlMessage::<F, BaseChoicesKind>::from_encoded(base_choices.encode())?;
        transcript = advance_transcript(transcript, base_choices.as_bytes())?;

        Ok(DeriverAReadyBaseChoices {
            binding,
            transcript,
            garbler,
            garbler_inputs,
            sender,
            direct_labels,
            base_choices,
            marker: PhantomData,
        })
    }
}

struct DeriverAReadyBaseChoices<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    garbler: Garbler,
    garbler_inputs: Vec<GarblerWire>,
    sender: SenderAwaitExtension<F::Ot>,
    direct_labels: Zeroizing<Vec<u8>>,
    base_choices: EncodedControlMessage<F, BaseChoicesKind>,
    marker: PhantomData<C>,
}

impl<F, C> DeriverAReadyBaseChoices<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn emit_base_choices(self) -> DeriverABaseChoicesEmitted<F, C> {
        DeriverABaseChoicesEmitted {
            state: DeriverAReadyDirect {
                binding: self.binding,
                transcript: self.transcript,
                garbler: self.garbler,
                garbler_inputs: self.garbler_inputs,
                sender: self.sender,
                direct_labels: self.direct_labels,
                marker: PhantomData,
            },
            base_choices: self.base_choices,
        }
    }
}

struct DeriverABaseChoicesEmitted<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverAReadyDirect<F, C>,
    base_choices: EncodedControlMessage<F, BaseChoicesKind>,
}

struct DeriverAReadyDirect<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    garbler: Garbler,
    garbler_inputs: Vec<GarblerWire>,
    sender: SenderAwaitExtension<F::Ot>,
    direct_labels: Zeroizing<Vec<u8>>,
    marker: PhantomData<C>,
}

impl<F, C> DeriverAReadyDirect<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn emit_direct(mut self) -> Result<DeriverADirectEmitted<F, C>, RoleProtocolError> {
        let direct = EncodedControlMessage::<F, DirectKind>::from_encoded(F::encode_direct(
            self.binding,
            self.transcript,
            self.direct_labels.as_slice(),
        )?)?;
        self.direct_labels.zeroize();
        let transcript = advance_transcript(self.transcript, direct.as_bytes())?;
        Ok(DeriverADirectEmitted {
            state: DeriverAAwaitExtension {
                binding: self.binding,
                transcript,
                garbler: self.garbler,
                garbler_inputs: self.garbler_inputs,
                sender: self.sender,
                marker: PhantomData,
            },
            direct,
        })
    }
}

struct DeriverADirectEmitted<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverAAwaitExtension<F, C>,
    direct: EncodedControlMessage<F, DirectKind>,
}

struct DeriverAAwaitExtension<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    garbler: Garbler,
    garbler_inputs: Vec<GarblerWire>,
    sender: SenderAwaitExtension<F::Ot>,
    marker: PhantomData<C>,
}

impl<F, C> DeriverAAwaitExtension<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_extension(
        self,
        extension_message: EncodedControlMessage<F, ExtensionKind>,
    ) -> Result<DeriverAReadyMasked<F, C>, RoleProtocolError> {
        let extension = ExtensionMatrix::<F::Ot>::decode(extension_message.as_bytes())?;
        let mut transcript = advance_transcript(self.transcript, extension_message.as_bytes())?;
        let masked_payloads = self.sender.accept(extension)?;
        let masked =
            EncodedControlMessage::<F, MaskedKind>::from_encoded(masked_payloads.encode())?;
        transcript = advance_transcript(transcript, masked.as_bytes())?;

        let manifest = PassiveStreamManifest::<F, C>::new(self.binding, transcript);
        let machine = F::garbler_machine::<C>(self.garbler, self.garbler_inputs)?;
        Ok(DeriverAReadyMasked {
            binding: self.binding,
            masked,
            manifest,
            machine,
        })
    }
}

struct DeriverAReadyMasked<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    masked: EncodedControlMessage<F, MaskedKind>,
    manifest: PassiveStreamManifest<F, C>,
    machine: GarblerMachine<F, C>,
}

impl<F, C> DeriverAReadyMasked<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn emit_masked(self) -> DeriverAMaskedEmitted<F, C> {
        DeriverAMaskedEmitted {
            state: DeriverAReadyManifest {
                binding: self.binding,
                manifest: self.manifest,
                machine: self.machine,
            },
            masked: self.masked,
        }
    }
}

struct DeriverAMaskedEmitted<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverAReadyManifest<F, C>,
    masked: EncodedControlMessage<F, MaskedKind>,
}

struct DeriverAReadyManifest<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    manifest: PassiveStreamManifest<F, C>,
    machine: GarblerMachine<F, C>,
}

impl<F, C> DeriverAReadyManifest<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn emit_manifest(self) -> DeriverAManifestEmitted<F, C> {
        let encoded_manifest = EncodedStreamManifest::from_manifest(self.manifest);
        DeriverAManifestEmitted {
            state: DeriverAStreaming {
                binding: self.binding,
                encoder: self.manifest.encoder(),
                machine: self.machine,
            },
            manifest: encoded_manifest,
        }
    }
}

struct DeriverAManifestEmitted<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverAStreaming<F, C>,
    manifest: EncodedStreamManifest<F, C>,
}

struct DeriverAStreaming<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    encoder: TableFrameEncoder<F, C>,
    machine: GarblerMachine<F, C>,
}

// Keeping the continuation inline avoids a heap allocation at every frame boundary.
#[allow(clippy::large_enum_variant)]
enum DeriverAStreamAdvance<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    FrameReady {
        state: DeriverAStreaming<F, C>,
        frame: EncodedTableFrame<F, C>,
    },
    TranslationReady(DeriverATableClosed<F, C>),
}

impl<F, C> DeriverAStreaming<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn advance(self) -> Result<DeriverAStreamAdvance<F, C>, RoleProtocolError> {
        match self.machine.advance()? {
            GarblerAdvance::ChunkReady(chunk) => {
                let mut encoder = self.encoder;
                let header = encoder.encode_next_header(chunk.payload())?;
                let frame = EncodedTableFrame::from_parts(header.as_bytes(), chunk.payload())?;
                Ok(DeriverAStreamAdvance::FrameReady {
                    state: Self {
                        binding: self.binding,
                        encoder,
                        machine: chunk.resume(),
                    },
                    frame,
                })
            }
            GarblerAdvance::BodyComplete(body) => {
                let exact_receipt = self.encoder.complete()?.finish_exact_section();
                let outputs = body.finalize(exact_receipt)?;
                let metrics = RoleStreamMetrics::checked::<F, C>(
                    RoleStreamMetricInput {
                        table_payload_bytes: outputs.table_bytes,
                        frame_calls: outputs.frame_calls,
                        host_boundary_copy_bytes: outputs.host_boundary_copy_bytes,
                        peak_table_buffer_bytes: outputs.peak_table_buffer_bytes,
                        peak_arena_bytes: outputs.peak_arena_bytes,
                        runtime_chunk_to_wire_copy_bytes: outputs.table_bytes,
                        wire_frame_allocation_bytes: outputs.receipt.body_bytes(),
                        peak_wire_frame_allocation_bytes: TABLE_FRAME_HEADER_BYTES
                            + outputs.peak_table_buffer_bytes,
                        combined_peak_table_buffer_bytes: outputs.peak_table_buffer_bytes
                            + TABLE_FRAME_HEADER_BYTES
                            + outputs.peak_table_buffer_bytes,
                    },
                    &outputs.receipt,
                )?;
                let stream_transcript = outputs.receipt.final_transcript();
                let translation = EncodedControlMessage::<F, TranslationKind>::from_encoded(
                    F::encode_translation(
                        self.binding,
                        stream_transcript,
                        outputs.evaluator_translation.encoded_bits(),
                    )?,
                )?;
                let terminal_transcript =
                    advance_transcript(stream_transcript, translation.as_bytes())?;
                Ok(DeriverAStreamAdvance::TranslationReady(
                    DeriverATableClosed {
                        state: DeriverAAwaitReturned {
                            binding: self.binding,
                            transcript: terminal_transcript,
                            returned_decoder: outputs.returned_decoder,
                            metrics,
                            marker: PhantomData,
                        },
                        translation,
                    },
                ))
            }
        }
    }
}

struct DeriverATableClosed<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverAAwaitReturned<F, C>,
    translation: EncodedControlMessage<F, TranslationKind>,
}

struct DeriverAAwaitReturned<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    returned_decoder: ReturnedOutputDecoder,
    metrics: RoleStreamMetrics,
    marker: PhantomData<C>,
}

impl<F, C> DeriverAAwaitReturned<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_returned(
        self,
        returned_message: EncodedControlMessage<F, ReturnedKind>,
    ) -> Result<CompletedRoleA<F>, RoleProtocolError> {
        let returned_payload =
            F::decode_returned(self.binding, self.transcript, returned_message.as_bytes())?;
        let transcript = advance_transcript(self.transcript, returned_message.as_bytes())?;
        let returned_labels =
            ReturnedOutputLabels::decode(returned_payload.as_slice(), F::OUTPUT_BITS_PER_ROLE)?;
        let mut decoded = self.returned_decoder.decode(returned_labels)?;
        let parsed = F::decode_a_share(&decoded);
        decoded.zeroize();
        let role = F::complete_a(self.binding, transcript, parsed?)?;
        Ok(CompletedRoleA {
            role,
            final_transcript: transcript,
            #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
            session: F::session(self.binding),
            metrics: self.metrics,
            marker: PhantomData,
        })
    }
}

pub(super) struct CompletedRoleA<F: ProtocolFamily> {
    role: F::ACompleted,
    final_transcript: TranscriptDigest32,
    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    session: [u8; 32],
    metrics: RoleStreamMetrics,
    marker: PhantomData<F>,
}

impl<F: ProtocolFamily> CompletedRoleA<F> {
    pub(super) const fn final_transcript(&self) -> TranscriptDigest32 {
        self.final_transcript
    }

    pub(super) const fn stream_metrics(&self) -> RoleStreamMetrics {
        self.metrics
    }
}

impl CompletedRoleA<ActivationStream> {
    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    pub(super) fn client_commitment(&self) -> [u8; 32] {
        self.role.client_commitment()
    }

    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    pub(super) fn signing_worker_commitment(&self) -> [u8; 32] {
        self.role.signing_worker_commitment()
    }

    pub(super) fn encode_client_package(&self) -> EncodedRecipientPackage {
        self.role.encode_client_package()
    }

    pub(super) fn encode_signing_worker_package(&self) -> EncodedRecipientPackage {
        self.role.encode_signing_worker_package()
    }
}

impl CompletedRoleA<ExportStream> {
    pub(super) fn encode_package(&self) -> EncodedRecipientPackage {
        self.role.encode_package()
    }
}

pub(super) struct DeriverBStartState<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    start: F::BStart,
    marker: PhantomData<C>,
}

impl<F, C> DeriverBStartState<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    pub(super) const fn new(start: F::BStart) -> Self {
        Self {
            start,
            marker: PhantomData,
        }
    }

    fn begin(self) -> Result<DeriverBBegan<F, C>, RoleProtocolError> {
        let (binding, choices) = F::prepare_b(self.start)?;
        let mut transcript = F::transcript_start(binding)?;
        let (receiver, offer) =
            ReceiverStart::<F::Ot>::new().begin_os(F::ot_session(binding)?, choices)?;
        let offer = EncodedControlMessage::<F, OfferKind>::from_encoded(offer.encode())?;
        transcript = advance_transcript(transcript, offer.as_bytes())?;
        Ok(DeriverBBegan {
            state: DeriverBAwaitBaseChoices {
                binding,
                transcript,
                receiver,
                marker: PhantomData,
            },
            offer,
        })
    }
}

struct DeriverBBegan<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverBAwaitBaseChoices<F, C>,
    offer: EncodedControlMessage<F, OfferKind>,
}

struct DeriverBAwaitBaseChoices<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    receiver: ReceiverAwaitBaseChoices<F::Ot>,
    marker: PhantomData<C>,
}

impl<F, C> DeriverBAwaitBaseChoices<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_base_choices(
        self,
        message: EncodedControlMessage<F, BaseChoicesKind>,
    ) -> Result<DeriverBAwaitDirect<F, C>, RoleProtocolError> {
        let base_choices = BaseChoices::<F::Ot>::decode(message.as_bytes())?;
        let transcript = advance_transcript(self.transcript, message.as_bytes())?;
        Ok(DeriverBAwaitDirect {
            binding: self.binding,
            transcript,
            receiver: self.receiver,
            base_choices,
            marker: PhantomData,
        })
    }
}

struct DeriverBAwaitDirect<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    receiver: ReceiverAwaitBaseChoices<F::Ot>,
    base_choices: BaseChoices<F::Ot>,
    marker: PhantomData<C>,
}

impl<F, C> DeriverBAwaitDirect<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_direct(
        self,
        message: EncodedControlMessage<F, DirectKind>,
    ) -> Result<DeriverBDirectAccepted<F, C>, RoleProtocolError> {
        let direct_payload = F::decode_direct(self.binding, self.transcript, message.as_bytes())?;
        let mut transcript = advance_transcript(self.transcript, message.as_bytes())?;
        let (receiver, extension) = self.receiver.accept(self.base_choices)?;
        let extension =
            EncodedControlMessage::<F, ExtensionKind>::from_encoded(extension.encode())?;
        transcript = advance_transcript(transcript, extension.as_bytes())?;
        Ok(DeriverBDirectAccepted {
            state: DeriverBAwaitMasked {
                binding: self.binding,
                transcript,
                receiver,
                direct_payload,
                marker: PhantomData,
            },
            extension,
        })
    }
}

struct DeriverBDirectAccepted<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    state: DeriverBAwaitMasked<F, C>,
    extension: EncodedControlMessage<F, ExtensionKind>,
}

struct DeriverBAwaitMasked<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    receiver: ReceiverAwaitMaskedPayloads<F::Ot>,
    direct_payload: SecretPayload,
    marker: PhantomData<C>,
}

impl<F, C> DeriverBAwaitMasked<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_masked(
        self,
        message: EncodedControlMessage<F, MaskedKind>,
    ) -> Result<DeriverBAwaitManifest<F, C>, RoleProtocolError> {
        let masked = MaskedPayloads::<F::Ot>::decode(message.as_bytes())?;
        let transcript = advance_transcript(self.transcript, message.as_bytes())?;
        let selected = self.receiver.accept(masked)?;
        let inputs = evaluator_inputs(
            self.direct_payload.as_slice(),
            selected.as_slice(),
            F::INPUT_BITS_PER_ROLE,
        )?;
        Ok(DeriverBAwaitManifest {
            binding: self.binding,
            transcript,
            inputs,
            marker: PhantomData,
        })
    }
}

struct DeriverBAwaitManifest<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    transcript: TranscriptDigest32,
    inputs: Vec<EvaluatorWire>,
    marker: PhantomData<C>,
}

impl<F, C> DeriverBAwaitManifest<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_manifest(
        self,
        manifest: EncodedStreamManifest<F, C>,
    ) -> Result<DeriverBStreaming<F, C>, RoleProtocolError> {
        let manifest =
            PassiveStreamManifest::<F, C>::decode(self.binding, self.transcript, &manifest.bytes)?;
        let machine = F::evaluator_machine::<C>(
            Evaluator::new(protocol_domain(F::gate_domain(self.binding))?),
            self.inputs,
        )?;
        let EvaluatorAdvance::NeedsFrame(waiting) = machine.advance()? else {
            return Err(RoleProtocolError::StateInvariant);
        };
        Ok(DeriverBStreaming {
            binding: self.binding,
            decoder: manifest.decoder(),
            waiting,
        })
    }
}

struct DeriverBStreaming<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    decoder: TableFrameDecoder<F, C>,
    waiting: EvaluatorNeedsFrame<F, C>,
}

// Keeping the continuation inline avoids a heap allocation at every frame boundary.
#[allow(clippy::large_enum_variant)]
enum DeriverBFrameAdvance<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    NeedsFrame(DeriverBStreaming<F, C>),
    AwaitingTranslation(DeriverBAwaitTranslation<F, C>),
}

impl<F, C> DeriverBStreaming<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_frame(
        self,
        frame: EncodedTableFrame<F, C>,
    ) -> Result<DeriverBFrameAdvance<F, C>, RoleProtocolError> {
        let (header, payload) = frame.bytes.split_at(TABLE_FRAME_HEADER_BYTES);
        let pending = self.decoder.accept_header(header)?;
        let (decoder, validated) = pending.accept_payload(payload)?;
        let machine = self.waiting.accept_frame(validated)?;
        match machine.advance()? {
            EvaluatorAdvance::NeedsFrame(waiting) => Ok(DeriverBFrameAdvance::NeedsFrame(Self {
                binding: self.binding,
                decoder,
                waiting,
            })),
            EvaluatorAdvance::AwaitingExactEof(body) => {
                Ok(DeriverBFrameAdvance::AwaitingTranslation(
                    finish_evaluator_section::<F, C>(self.binding, decoder, body)?,
                ))
            }
        }
    }
}

fn finish_evaluator_section<F, C>(
    binding: F::Binding,
    decoder: TableFrameDecoder<F, C>,
    body: EvaluatorBodyComplete<F, C>,
) -> Result<DeriverBAwaitTranslation<F, C>, RoleProtocolError>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    let exact_receipt = decoder.finish_exact_section()?;
    let outputs = body.finalize(exact_receipt)?;
    let metrics = RoleStreamMetrics::checked::<F, C>(
        RoleStreamMetricInput {
            table_payload_bytes: outputs.table_bytes,
            frame_calls: outputs.frame_calls,
            host_boundary_copy_bytes: outputs.host_boundary_copy_bytes,
            peak_table_buffer_bytes: outputs.peak_table_buffer_bytes,
            peak_arena_bytes: outputs.peak_arena_bytes,
            runtime_chunk_to_wire_copy_bytes: 0,
            wire_frame_allocation_bytes: outputs.receipt.body_bytes(),
            peak_wire_frame_allocation_bytes: TABLE_FRAME_HEADER_BYTES
                + outputs.peak_table_buffer_bytes,
            combined_peak_table_buffer_bytes: TABLE_FRAME_HEADER_BYTES
                + outputs.peak_table_buffer_bytes,
        },
        &outputs.receipt,
    )?;
    Ok(DeriverBAwaitTranslation {
        binding,
        stream_transcript: outputs.receipt.final_transcript(),
        returned_labels: outputs.returned_labels,
        evaluator_labels: outputs.evaluator_labels,
        metrics,
        marker: PhantomData,
    })
}

struct DeriverBAwaitTranslation<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    binding: F::Binding,
    stream_transcript: TranscriptDigest32,
    returned_labels: ReturnedOutputLabels,
    evaluator_labels: EvaluatorOwnedOutputLabels,
    metrics: RoleStreamMetrics,
    marker: PhantomData<C>,
}

impl<F, C> DeriverBAwaitTranslation<F, C>
where
    F: ProtocolFamily,
    C: FixedChunkProfile,
{
    fn accept_translation(
        self,
        message: EncodedControlMessage<F, TranslationKind>,
    ) -> Result<DeriverBTerminal<F>, RoleProtocolError> {
        let translation_payload =
            F::decode_translation(self.binding, self.stream_transcript, message.as_bytes())?;
        let transcript = advance_transcript(self.stream_transcript, message.as_bytes())?;
        let translation = EvaluatorOutputTranslation::from_encoded_bits(
            translation_payload.as_slice().to_vec(),
            F::OUTPUT_BITS_PER_ROLE,
        )?;
        let mut decoded = translation.decode(self.evaluator_labels)?;
        let parsed = F::decode_b_share(&decoded);
        decoded.zeroize();
        let share = parsed?;

        let mut returned_payload = Zeroizing::new(self.returned_labels.encode());
        let returned = EncodedControlMessage::<F, ReturnedKind>::from_encoded(F::encode_returned(
            self.binding,
            transcript,
            returned_payload.as_slice(),
        )?)?;
        returned_payload.zeroize();
        let final_transcript = advance_transcript(transcript, returned.as_bytes())?;
        let role = F::complete_b(self.binding, final_transcript, share)?;
        Ok(DeriverBTerminal {
            completed: CompletedRoleB {
                role,
                final_transcript,
                #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
                session: F::session(self.binding),
                metrics: self.metrics,
                marker: PhantomData,
            },
            returned,
        })
    }
}

struct DeriverBTerminal<F: ProtocolFamily> {
    completed: CompletedRoleB<F>,
    returned: EncodedControlMessage<F, ReturnedKind>,
}

pub(super) struct CompletedRoleB<F: ProtocolFamily> {
    role: F::BCompleted,
    final_transcript: TranscriptDigest32,
    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    session: [u8; 32],
    metrics: RoleStreamMetrics,
    marker: PhantomData<F>,
}

impl<F: ProtocolFamily> CompletedRoleB<F> {
    pub(super) const fn final_transcript(&self) -> TranscriptDigest32 {
        self.final_transcript
    }

    pub(super) const fn stream_metrics(&self) -> RoleStreamMetrics {
        self.metrics
    }
}

impl CompletedRoleB<ActivationStream> {
    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    pub(super) fn client_commitment(&self) -> [u8; 32] {
        self.role.client_commitment()
    }

    #[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
    pub(super) fn signing_worker_commitment(&self) -> [u8; 32] {
        self.role.signing_worker_commitment()
    }

    pub(super) fn encode_client_package(&self) -> EncodedRecipientPackage {
        self.role.encode_client_package()
    }

    pub(super) fn encode_signing_worker_package(&self) -> EncodedRecipientPackage {
        self.role.encode_signing_worker_package()
    }
}

impl CompletedRoleB<ExportStream> {
    pub(super) fn encode_package(&self) -> EncodedRecipientPackage {
        self.role.encode_package()
    }
}

#[cfg(any(feature = "phase9-role-benchmark", feature = "local-protocol"))]
#[doc(hidden)]
pub mod benchmark {
    #![allow(missing_docs)]

    use super::*;
    #[cfg(feature = "local-protocol")]
    use crate::passive::packages::{
        derive_public_activation_receipt_bytes, verify_public_activation_receipt_bytes,
        DeriverAClientScalarPackage, DeriverAExportSeedPackage, DeriverASigningWorkerScalarPackage,
        DeriverBClientScalarPackage, DeriverBExportSeedPackage, DeriverBSigningWorkerScalarPackage,
    };
    #[cfg(feature = "phase9-role-benchmark")]
    use crate::passive::role_protocol_support::{
        activation_deriver_a_fixture_start, activation_deriver_b_fixture_start,
        export_deriver_a_fixture_start, export_deriver_b_fixture_start,
    };
    #[cfg(feature = "local-protocol")]
    use crate::passive::roles::{
        ActivationDeriverAInputs as PrivateActivationDeriverAInputs,
        ActivationDeriverBInputs as PrivateActivationDeriverBInputs, ActivationSessionBinding,
        DeriverAClientScalarOutputCoin, DeriverAClientTau, DeriverAClientY, DeriverASeedOutputCoin,
        DeriverAServerTau, DeriverAServerY, DeriverASigningWorkerScalarOutputCoin,
        DeriverBClientScalarOutputCoin, DeriverBClientTau, DeriverBClientY, DeriverBSeedOutputCoin,
        DeriverBServerTau, DeriverBServerY, DeriverBSigningWorkerScalarOutputCoin,
        ExportDeriverAInputs as PrivateExportDeriverAInputs,
        ExportDeriverBInputs as PrivateExportDeriverBInputs, ExportSessionBinding, SessionId,
    };
    use crate::passive::stream::Chunk128KiB;
    #[cfg(feature = "phase9-role-benchmark")]
    use crate::passive::stream::{Chunk256KiB, Chunk64KiB};

    const MAXIMUM_WIRE_MESSAGE_BYTES: usize = TABLE_FRAME_HEADER_BYTES + 256 * 1_024;
    const WIRE_ENVELOPE_MAGIC: &[u8; 8] = b"EYAORL01";
    const WIRE_ENVELOPE_VERSION: u8 = 1;
    pub const WIRE_ENVELOPE_HEADER_BYTES: usize = 16;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WireMessageKind {
        BaseOtOffer,
        BaseOtChoices,
        DirectInputLabels,
        OtExtensionMatrix,
        MaskedInputLabels,
        StreamManifest,
        TableFrame,
        OutputTranslation,
        ReturnedOutputLabels,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WireDirection {
        DeriverAToDeriverB,
        DeriverBToDeriverA,
    }

    impl WireDirection {
        const fn terminal_kind(self) -> WireMessageKind {
            match self {
                Self::DeriverAToDeriverB => WireMessageKind::OutputTranslation,
                Self::DeriverBToDeriverA => WireMessageKind::ReturnedOutputLabels,
            }
        }
    }

    impl WireMessageKind {
        const fn tag(self) -> u8 {
            match self {
                Self::BaseOtOffer => 1,
                Self::BaseOtChoices => 2,
                Self::DirectInputLabels => 3,
                Self::OtExtensionMatrix => 4,
                Self::MaskedInputLabels => 5,
                Self::StreamManifest => 6,
                Self::TableFrame => 7,
                Self::OutputTranslation => 8,
                Self::ReturnedOutputLabels => 9,
            }
        }

        fn from_tag(tag: u8) -> Result<Self, BenchmarkRoleError> {
            match tag {
                1 => Ok(Self::BaseOtOffer),
                2 => Ok(Self::BaseOtChoices),
                3 => Ok(Self::DirectInputLabels),
                4 => Ok(Self::OtExtensionMatrix),
                5 => Ok(Self::MaskedInputLabels),
                6 => Ok(Self::StreamManifest),
                7 => Ok(Self::TableFrame),
                8 => Ok(Self::OutputTranslation),
                9 => Ok(Self::ReturnedOutputLabels),
                _ => Err(BenchmarkRoleError),
            }
        }

        const fn is_direction_terminal(self) -> bool {
            matches!(self, Self::OutputTranslation | Self::ReturnedOutputLabels)
        }

        const fn direction(self) -> WireDirection {
            match self {
                Self::BaseOtOffer | Self::OtExtensionMatrix | Self::ReturnedOutputLabels => {
                    WireDirection::DeriverBToDeriverA
                }
                _ => WireDirection::DeriverAToDeriverB,
            }
        }
    }

    pub struct WireMessage {
        kind: WireMessageKind,
        bytes: Zeroizing<Vec<u8>>,
    }

    impl WireMessage {
        pub const fn kind(&self) -> WireMessageKind {
            self.kind
        }

        pub fn as_bytes(&self) -> &[u8] {
            self.bytes.as_slice()
        }

        fn into_envelope(mut self) -> Result<Vec<u8>, BenchmarkRoleError> {
            let payload_bytes = self.bytes.len();
            let encoded_payload_bytes =
                u32::try_from(payload_bytes).map_err(|_| BenchmarkRoleError)?;
            self.bytes
                .try_reserve_exact(WIRE_ENVELOPE_HEADER_BYTES)
                .map_err(|_| BenchmarkRoleError)?;
            self.bytes
                .resize(payload_bytes + WIRE_ENVELOPE_HEADER_BYTES, 0);
            self.bytes
                .copy_within(0..payload_bytes, WIRE_ENVELOPE_HEADER_BYTES);
            self.bytes[..8].copy_from_slice(WIRE_ENVELOPE_MAGIC);
            self.bytes[8] = WIRE_ENVELOPE_VERSION;
            self.bytes[9] = self.kind.tag();
            self.bytes[10..12].fill(0);
            self.bytes[12..16].copy_from_slice(&encoded_payload_bytes.to_be_bytes());
            Ok(core::mem::take(&mut *self.bytes))
        }

        fn from_envelope(mut encoded: Vec<u8>) -> Result<Self, BenchmarkRoleError> {
            if encoded.len() < WIRE_ENVELOPE_HEADER_BYTES
                || &encoded[..8] != WIRE_ENVELOPE_MAGIC
                || encoded[8] != WIRE_ENVELOPE_VERSION
                || encoded[10..12] != [0_u8; 2]
            {
                encoded.zeroize();
                return Err(BenchmarkRoleError);
            }
            let kind = WireMessageKind::from_tag(encoded[9])?;
            let payload_bytes =
                u32::from_be_bytes(encoded[12..16].try_into().map_err(|_| BenchmarkRoleError)?)
                    as usize;
            if payload_bytes == 0
                || payload_bytes > MAXIMUM_WIRE_MESSAGE_BYTES
                || encoded.len() != WIRE_ENVELOPE_HEADER_BYTES + payload_bytes
            {
                encoded.zeroize();
                return Err(BenchmarkRoleError);
            }
            encoded.copy_within(WIRE_ENVELOPE_HEADER_BYTES.., 0);
            encoded.truncate(payload_bytes);
            Ok(Self {
                kind,
                bytes: Zeroizing::new(encoded),
            })
        }
    }

    impl fmt::Debug for WireMessage {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("WireMessage")
                .field("kind", &self.kind)
                .field("bytes", &self.bytes.len())
                .finish()
        }
    }

    pub struct DirectionalEofEvidence {
        direction: WireDirection,
        session: [u8; 32],
        terminal_kind: WireMessageKind,
        source: EofEvidenceSource,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EofEvidenceSource {
        Encoder,
        Decoder,
    }

    impl fmt::Debug for DirectionalEofEvidence {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DirectionalEofEvidence")
                .field("direction", &self.direction)
                .field("terminal_kind", &self.terminal_kind)
                .finish()
        }
    }

    impl DirectionalEofEvidence {
        fn matches(
            &self,
            direction: WireDirection,
            session: [u8; 32],
            source: EofEvidenceSource,
        ) -> bool {
            self.direction == direction
                && self.session == session
                && self.terminal_kind == direction.terminal_kind()
                && self.source == source
        }
    }

    pub struct DirectionalWireEncoder {
        direction: WireDirection,
        session: [u8; 32],
        terminal_kind: WireMessageKind,
        terminal_seen: bool,
    }

    impl DirectionalWireEncoder {
        pub fn new(
            direction: WireDirection,
            session: [u8; 32],
        ) -> Result<Self, BenchmarkRoleError> {
            if session.iter().all(|byte| *byte == 0) {
                return Err(BenchmarkRoleError);
            }
            Ok(Self {
                direction,
                session,
                terminal_kind: direction.terminal_kind(),
                terminal_seen: false,
            })
        }

        pub fn encode(&mut self, message: WireMessage) -> Result<Vec<u8>, BenchmarkRoleError> {
            if self.terminal_seen || message.kind.direction() != self.direction {
                return Err(BenchmarkRoleError);
            }
            if message.kind == self.terminal_kind {
                self.terminal_seen = true;
            }
            message.into_envelope()
        }

        pub fn finish_after_transport_close(
            self,
        ) -> Result<DirectionalEofEvidence, BenchmarkRoleError> {
            if !self.terminal_seen {
                return Err(BenchmarkRoleError);
            }
            Ok(DirectionalEofEvidence {
                direction: self.direction,
                session: self.session,
                terminal_kind: self.terminal_kind,
                source: EofEvidenceSource::Encoder,
            })
        }
    }

    pub struct DirectionalWireDecoder {
        direction: WireDirection,
        session: [u8; 32],
        terminal_kind: WireMessageKind,
        terminal_seen: bool,
        buffer: Zeroizing<Vec<u8>>,
        expected_total_bytes: Option<usize>,
    }

    impl DirectionalWireDecoder {
        pub fn new(
            direction: WireDirection,
            session: [u8; 32],
        ) -> Result<Self, BenchmarkRoleError> {
            if session.iter().all(|byte| *byte == 0) {
                return Err(BenchmarkRoleError);
            }
            Ok(Self {
                direction,
                session,
                terminal_kind: direction.terminal_kind(),
                terminal_seen: false,
                buffer: Zeroizing::new(Vec::with_capacity(WIRE_ENVELOPE_HEADER_BYTES)),
                expected_total_bytes: None,
            })
        }

        pub fn push(&mut self, input: &[u8]) -> Result<usize, BenchmarkRoleError> {
            if self.message_ready() || self.terminal_seen {
                return Err(BenchmarkRoleError);
            }
            let mut consumed = 0_usize;
            if self.buffer.len() < WIRE_ENVELOPE_HEADER_BYTES {
                let needed = WIRE_ENVELOPE_HEADER_BYTES - self.buffer.len();
                let take = core::cmp::min(needed, input.len());
                self.buffer.extend_from_slice(&input[..take]);
                consumed += take;
                if self.buffer.len() < WIRE_ENVELOPE_HEADER_BYTES {
                    return Ok(consumed);
                }
                self.validate_header()?;
            }
            let expected = self.expected_total_bytes.ok_or(BenchmarkRoleError)?;
            let needed = expected - self.buffer.len();
            let take = core::cmp::min(needed, input.len() - consumed);
            self.buffer
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;
            Ok(consumed)
        }

        pub fn take_message(&mut self) -> Result<Option<WireMessage>, BenchmarkRoleError> {
            if !self.message_ready() {
                return Ok(None);
            }
            let encoded = core::mem::take(&mut *self.buffer);
            self.expected_total_bytes = None;
            let message = WireMessage::from_envelope(encoded)?;
            if message.kind.direction() != self.direction
                || (message.kind.is_direction_terminal() && message.kind != self.terminal_kind)
            {
                return Err(BenchmarkRoleError);
            }
            if message.kind == self.terminal_kind {
                self.terminal_seen = true;
            }
            Ok(Some(message))
        }

        pub fn finish_at_transport_eof(self) -> Result<DirectionalEofEvidence, BenchmarkRoleError> {
            if !self.terminal_seen || !self.buffer.is_empty() || self.expected_total_bytes.is_some()
            {
                return Err(BenchmarkRoleError);
            }
            Ok(DirectionalEofEvidence {
                direction: self.direction,
                session: self.session,
                terminal_kind: self.terminal_kind,
                source: EofEvidenceSource::Decoder,
            })
        }

        fn validate_header(&mut self) -> Result<(), BenchmarkRoleError> {
            if &self.buffer[..8] != WIRE_ENVELOPE_MAGIC
                || self.buffer[8] != WIRE_ENVELOPE_VERSION
                || self.buffer[10..12] != [0_u8; 2]
            {
                return Err(BenchmarkRoleError);
            }
            WireMessageKind::from_tag(self.buffer[9])?;
            let payload_bytes = u32::from_be_bytes(
                self.buffer[12..16]
                    .try_into()
                    .map_err(|_| BenchmarkRoleError)?,
            ) as usize;
            if payload_bytes == 0 || payload_bytes > MAXIMUM_WIRE_MESSAGE_BYTES {
                return Err(BenchmarkRoleError);
            }
            self.buffer
                .try_reserve_exact(payload_bytes)
                .map_err(|_| BenchmarkRoleError)?;
            self.expected_total_bytes = Some(WIRE_ENVELOPE_HEADER_BYTES + payload_bytes);
            Ok(())
        }

        fn message_ready(&self) -> bool {
            self.expected_total_bytes == Some(self.buffer.len())
        }
    }

    #[derive(Debug)]
    pub enum RelayEvent {
        Advance,
        Inbound(WireMessage),
        LocalDirectionalEof(DirectionalEofEvidence),
        InboundDirectionalEof(DirectionalEofEvidence),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RelayInstruction {
        Advance,
        Receive {
            kind: WireMessageKind,
            payload_bytes: usize,
        },
        CloseLocalDirection {
            terminal_kind: WireMessageKind,
        },
        ObservePeerEof {
            terminal_kind: WireMessageKind,
        },
    }

    #[derive(Debug)]
    pub enum RelayStep<R, C> {
        Continue(R),
        Send { role: R, message: WireMessage },
        Complete(C),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BenchmarkRoleError;

    impl fmt::Display for BenchmarkRoleError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fixed Phase 9 split-role benchmark failed")
        }
    }

    impl std::error::Error for BenchmarkRoleError {}

    impl From<RoleProtocolError> for BenchmarkRoleError {
        fn from(_: RoleProtocolError) -> Self {
            Self
        }
    }

    impl From<RoleBoundaryError> for BenchmarkRoleError {
        fn from(_: RoleBoundaryError) -> Self {
            Self
        }
    }

    impl From<RecipientPackageError> for BenchmarkRoleError {
        fn from(_: RecipientPackageError) -> Self {
            Self
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StreamMetrics {
        table_payload_bytes: usize,
        body_bytes: u64,
        frame_count: u32,
        peak_table_buffer_bytes: usize,
        peak_arena_bytes: usize,
        runtime_chunk_to_wire_copy_bytes: usize,
        wire_frame_allocation_bytes: u64,
        peak_wire_frame_allocation_bytes: usize,
        combined_peak_table_buffer_bytes: usize,
    }

    impl StreamMetrics {
        pub const fn table_payload_bytes(self) -> usize {
            self.table_payload_bytes
        }

        pub const fn body_bytes(self) -> u64 {
            self.body_bytes
        }

        pub const fn frame_count(self) -> u32 {
            self.frame_count
        }

        pub const fn peak_table_buffer_bytes(self) -> usize {
            self.peak_table_buffer_bytes
        }

        pub const fn peak_arena_bytes(self) -> usize {
            self.peak_arena_bytes
        }

        pub const fn runtime_chunk_to_wire_copy_bytes(self) -> usize {
            self.runtime_chunk_to_wire_copy_bytes
        }

        pub const fn wire_frame_allocation_bytes(self) -> u64 {
            self.wire_frame_allocation_bytes
        }

        pub const fn peak_wire_frame_allocation_bytes(self) -> usize {
            self.peak_wire_frame_allocation_bytes
        }

        pub const fn combined_peak_table_buffer_bytes(self) -> usize {
            self.combined_peak_table_buffer_bytes
        }
    }

    impl From<RoleStreamMetrics> for StreamMetrics {
        fn from(metrics: RoleStreamMetrics) -> Self {
            Self {
                table_payload_bytes: metrics.table_payload_bytes(),
                body_bytes: metrics.body_bytes(),
                frame_count: metrics.frame_count(),
                peak_table_buffer_bytes: metrics.peak_table_buffer_bytes(),
                peak_arena_bytes: metrics.peak_arena_bytes(),
                runtime_chunk_to_wire_copy_bytes: metrics.runtime_chunk_to_wire_copy_bytes(),
                wire_frame_allocation_bytes: metrics.wire_frame_allocation_bytes(),
                peak_wire_frame_allocation_bytes: metrics.peak_wire_frame_allocation_bytes(),
                combined_peak_table_buffer_bytes: metrics.combined_peak_table_buffer_bytes(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WireByteLedger {
        table_payload_bytes: u64,
        table_framing_payload_bytes: u64,
        table_protocol_bytes: u64,
        ot_payload_bytes: u64,
        other_control_payload_bytes: u64,
        envelope_header_bytes: u64,
        table_transport_bytes: u64,
        control_transport_bytes: u64,
        deriver_a_to_b_transport_bytes: u64,
        deriver_b_to_a_transport_bytes: u64,
        total_ab_transport_bytes: u64,
        ot_message_count: u32,
        ot_sequential_round_count: u32,
        transport_message_count: u32,
    }

    impl WireByteLedger {
        fn for_family<F: ProtocolFamily>(metrics: RoleStreamMetrics) -> Self {
            let table_payload_bytes = metrics.table_payload_bytes() as u64;
            let table_framing_payload_bytes = metrics.body_bytes() - table_payload_bytes;
            let table_protocol_bytes = metrics.body_bytes() + STREAM_MANIFEST_BYTES as u64;
            let ot_payload_bytes = (BaseOffer::<F::Ot>::wire_bytes()
                + BaseChoices::<F::Ot>::wire_bytes()
                + ExtensionMatrix::<F::Ot>::wire_bytes()
                + MaskedPayloads::<F::Ot>::wire_bytes()) as u64;
            let other_control_payload_bytes = (F::DIRECT_MESSAGE_BYTES
                + F::TRANSLATION_MESSAGE_BYTES
                + F::RETURNED_MESSAGE_BYTES) as u64;
            let table_message_count = metrics.frame_count() + 1;
            let control_message_count = 7_u32;
            let ot_message_count = 4_u32;
            // Offer -> choices -> extension -> masked payloads are four
            // sequentially dependent one-way protocol rounds.
            let ot_sequential_round_count = 4_u32;
            let transport_message_count = table_message_count + control_message_count;
            let envelope_header_bytes =
                transport_message_count as u64 * WIRE_ENVELOPE_HEADER_BYTES as u64;
            let table_transport_bytes = table_protocol_bytes
                + table_message_count as u64 * WIRE_ENVELOPE_HEADER_BYTES as u64;
            let control_transport_bytes = ot_payload_bytes
                + other_control_payload_bytes
                + control_message_count as u64 * WIRE_ENVELOPE_HEADER_BYTES as u64;
            let deriver_a_to_b_payload_bytes = BaseChoices::<F::Ot>::wire_bytes() as u64
                + F::DIRECT_MESSAGE_BYTES as u64
                + MaskedPayloads::<F::Ot>::wire_bytes() as u64
                + table_protocol_bytes
                + F::TRANSLATION_MESSAGE_BYTES as u64;
            let deriver_a_to_b_message_count = metrics.frame_count() + 5;
            let deriver_a_to_b_transport_bytes = deriver_a_to_b_payload_bytes
                + deriver_a_to_b_message_count as u64 * WIRE_ENVELOPE_HEADER_BYTES as u64;
            let deriver_b_to_a_payload_bytes = BaseOffer::<F::Ot>::wire_bytes() as u64
                + ExtensionMatrix::<F::Ot>::wire_bytes() as u64
                + F::RETURNED_MESSAGE_BYTES as u64;
            let deriver_b_to_a_transport_bytes =
                deriver_b_to_a_payload_bytes + 3 * WIRE_ENVELOPE_HEADER_BYTES as u64;
            let total_ab_transport_bytes =
                deriver_a_to_b_transport_bytes + deriver_b_to_a_transport_bytes;
            debug_assert_eq!(
                total_ab_transport_bytes,
                table_transport_bytes + control_transport_bytes
            );
            debug_assert_eq!(
                envelope_header_bytes,
                transport_message_count as u64 * WIRE_ENVELOPE_HEADER_BYTES as u64
            );
            Self {
                table_payload_bytes,
                table_framing_payload_bytes,
                table_protocol_bytes,
                ot_payload_bytes,
                other_control_payload_bytes,
                envelope_header_bytes,
                table_transport_bytes,
                control_transport_bytes,
                deriver_a_to_b_transport_bytes,
                deriver_b_to_a_transport_bytes,
                total_ab_transport_bytes,
                ot_message_count,
                ot_sequential_round_count,
                transport_message_count,
            }
        }

        pub const fn table_payload_bytes(self) -> u64 {
            self.table_payload_bytes
        }

        pub const fn table_framing_payload_bytes(self) -> u64 {
            self.table_framing_payload_bytes
        }

        pub const fn table_protocol_bytes(self) -> u64 {
            self.table_protocol_bytes
        }

        pub const fn ot_payload_bytes(self) -> u64 {
            self.ot_payload_bytes
        }

        pub const fn other_control_payload_bytes(self) -> u64 {
            self.other_control_payload_bytes
        }

        pub const fn envelope_header_bytes(self) -> u64 {
            self.envelope_header_bytes
        }

        pub const fn table_transport_bytes(self) -> u64 {
            self.table_transport_bytes
        }

        pub const fn control_transport_bytes(self) -> u64 {
            self.control_transport_bytes
        }

        pub const fn deriver_a_to_b_transport_bytes(self) -> u64 {
            self.deriver_a_to_b_transport_bytes
        }

        pub const fn deriver_b_to_a_transport_bytes(self) -> u64 {
            self.deriver_b_to_a_transport_bytes
        }

        pub const fn total_ab_transport_bytes(self) -> u64 {
            self.total_ab_transport_bytes
        }

        pub const fn ot_message_count(self) -> u32 {
            self.ot_message_count
        }

        pub const fn ot_sequential_round_count(self) -> u32 {
            self.ot_sequential_round_count
        }

        pub const fn transport_message_count(self) -> u32 {
            self.transport_message_count
        }
    }

    macro_rules! define_recipient_package {
        ($name:ident, $expected_bytes:expr) => {
            pub struct $name(Zeroizing<Vec<u8>>);

            impl $name {
                pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, BenchmarkRoleError> {
                    if bytes.len() != $expected_bytes {
                        bytes.zeroize();
                        return Err(BenchmarkRoleError);
                    }
                    Ok(Self(Zeroizing::new(bytes)))
                }

                pub fn as_bytes(&self) -> &[u8] {
                    self.0.as_slice()
                }

                pub fn into_bytes(mut self) -> Vec<u8> {
                    core::mem::take(&mut *self.0)
                }
            }

            impl fmt::Debug for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
                }
            }
        };
    }

    define_recipient_package!(ActivationDeriverAClientPackage, ACTIVATION_PACKAGE_BYTES);
    define_recipient_package!(
        ActivationDeriverASigningWorkerPackage,
        ACTIVATION_PACKAGE_BYTES
    );
    define_recipient_package!(ActivationDeriverBClientPackage, ACTIVATION_PACKAGE_BYTES);
    define_recipient_package!(
        ActivationDeriverBSigningWorkerPackage,
        ACTIVATION_PACKAGE_BYTES
    );
    define_recipient_package!(ExportDeriverAClientPackage, EXPORT_PACKAGE_BYTES);
    define_recipient_package!(ExportDeriverBClientPackage, EXPORT_PACKAGE_BYTES);

    #[cfg(feature = "local-protocol")]
    pub struct ClientBaseScalar(Zeroizing<[u8; 32]>);

    #[cfg(feature = "local-protocol")]
    impl ClientBaseScalar {
        pub fn into_bytes(mut self) -> [u8; 32] {
            core::mem::take(&mut *self.0)
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for ClientBaseScalar {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ClientBaseScalar([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    pub struct SigningWorkerBaseScalar(Zeroizing<[u8; 32]>);

    #[cfg(feature = "local-protocol")]
    impl SigningWorkerBaseScalar {
        pub fn into_bytes(mut self) -> [u8; 32] {
            core::mem::take(&mut *self.0)
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for SigningWorkerBaseScalar {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SigningWorkerBaseScalar([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    pub struct ExportedSeed32(Zeroizing<[u8; 32]>);

    #[cfg(feature = "local-protocol")]
    impl ExportedSeed32 {
        pub fn into_bytes(mut self) -> [u8; 32] {
            core::mem::take(&mut *self.0)
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for ExportedSeed32 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ExportedSeed32([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    fn activation_package_binding(
        session: [u8; 32],
        final_transcript: [u8; 32],
    ) -> Result<(ActivationSessionBinding, TranscriptDigest32), BenchmarkRoleError> {
        Ok((
            ActivationSessionBinding::new(SessionId::new(session)?),
            TranscriptDigest32::new(final_transcript)?,
        ))
    }

    #[cfg(feature = "local-protocol")]
    fn export_package_binding(
        session: [u8; 32],
        final_transcript: [u8; 32],
    ) -> Result<(ExportSessionBinding, TranscriptDigest32), BenchmarkRoleError> {
        Ok((
            ExportSessionBinding::new(SessionId::new(session)?),
            TranscriptDigest32::new(final_transcript)?,
        ))
    }

    #[cfg(feature = "local-protocol")]
    fn add_canonical_scalar_shares(
        left: &[u8; 32],
        right: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, BenchmarkRoleError> {
        use curve25519_dalek::scalar::Scalar;

        let left_option = Scalar::from_canonical_bytes(*left);
        let right_option = Scalar::from_canonical_bytes(*right);
        let valid = left_option.is_some() & right_option.is_some();
        let mut left_scalar = left_option.unwrap_or(Scalar::ZERO);
        let mut right_scalar = right_option.unwrap_or(Scalar::ZERO);
        let output = Zeroizing::new((left_scalar + right_scalar).to_bytes());
        left_scalar.zeroize();
        right_scalar.zeroize();
        if bool::from(valid) {
            Ok(output)
        } else {
            Err(BenchmarkRoleError)
        }
    }

    #[cfg(feature = "local-protocol")]
    pub fn combine_client_activation_packages(
        session: [u8; 32],
        final_transcript: [u8; 32],
        deriver_a: ActivationDeriverAClientPackage,
        deriver_b: ActivationDeriverBClientPackage,
    ) -> Result<ClientBaseScalar, BenchmarkRoleError> {
        let (binding, transcript) = activation_package_binding(session, final_transcript)?;
        let a = DeriverAClientScalarPackage::decode(binding, transcript, deriver_a.0.as_slice())?;
        let b = DeriverBClientScalarPackage::decode(binding, transcript, deriver_b.0.as_slice())?;
        Ok(ClientBaseScalar(add_canonical_scalar_shares(
            a.share_bytes(),
            b.share_bytes(),
        )?))
    }

    #[cfg(feature = "local-protocol")]
    pub fn combine_signing_worker_activation_packages(
        session: [u8; 32],
        final_transcript: [u8; 32],
        deriver_a: ActivationDeriverASigningWorkerPackage,
        deriver_b: ActivationDeriverBSigningWorkerPackage,
    ) -> Result<SigningWorkerBaseScalar, BenchmarkRoleError> {
        let (binding, transcript) = activation_package_binding(session, final_transcript)?;
        let a = DeriverASigningWorkerScalarPackage::decode(
            binding,
            transcript,
            deriver_a.0.as_slice(),
        )?;
        let b = DeriverBSigningWorkerScalarPackage::decode(
            binding,
            transcript,
            deriver_b.0.as_slice(),
        )?;
        Ok(SigningWorkerBaseScalar(add_canonical_scalar_shares(
            a.share_bytes(),
            b.share_bytes(),
        )?))
    }

    #[cfg(feature = "local-protocol")]
    pub fn combine_export_packages(
        session: [u8; 32],
        final_transcript: [u8; 32],
        deriver_a: ExportDeriverAClientPackage,
        deriver_b: ExportDeriverBClientPackage,
    ) -> Result<ExportedSeed32, BenchmarkRoleError> {
        let (binding, transcript) = export_package_binding(session, final_transcript)?;
        let a = DeriverAExportSeedPackage::decode(binding, transcript, deriver_a.0.as_slice())?;
        let b = DeriverBExportSeedPackage::decode(binding, transcript, deriver_b.0.as_slice())?;
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        for (index, output_byte) in output.iter_mut().enumerate() {
            let sum = a.share_bytes()[index] as u16 + b.share_bytes()[index] as u16 + carry;
            *output_byte = sum as u8;
            carry = sum >> 8;
        }
        Ok(ExportedSeed32(Zeroizing::new(output)))
    }

    #[cfg(feature = "local-protocol")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ActivationPublicCommitments {
        deriver_a_client: [u8; 32],
        deriver_b_client: [u8; 32],
        deriver_a_signing_worker: [u8; 32],
        deriver_b_signing_worker: [u8; 32],
    }

    #[cfg(feature = "local-protocol")]
    impl ActivationPublicCommitments {
        pub const fn new(
            deriver_a_client: [u8; 32],
            deriver_b_client: [u8; 32],
            deriver_a_signing_worker: [u8; 32],
            deriver_b_signing_worker: [u8; 32],
        ) -> Self {
            Self {
                deriver_a_client,
                deriver_b_client,
                deriver_a_signing_worker,
                deriver_b_signing_worker,
            }
        }
    }

    #[cfg(feature = "local-protocol")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ActivationPublicReceipt {
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
    }

    #[cfg(feature = "local-protocol")]
    impl ActivationPublicReceipt {
        pub const fn registered_public_key(&self) -> &[u8; 32] {
            &self.registered_public_key
        }

        pub const fn joined_client_commitment(&self) -> &[u8; 32] {
            &self.joined_client_commitment
        }

        pub const fn joined_signing_worker_commitment(&self) -> &[u8; 32] {
            &self.joined_signing_worker_commitment
        }
    }

    #[cfg(feature = "local-protocol")]
    pub fn derive_registration_receipt(
        commitments: ActivationPublicCommitments,
    ) -> Result<ActivationPublicReceipt, BenchmarkRoleError> {
        let receipt = derive_public_activation_receipt_bytes(
            commitments.deriver_a_client,
            commitments.deriver_b_client,
            commitments.deriver_a_signing_worker,
            commitments.deriver_b_signing_worker,
        )?;
        Ok(ActivationPublicReceipt {
            registered_public_key: *receipt.registered_public_key(),
            joined_client_commitment: *receipt.joined_client_commitment(),
            joined_signing_worker_commitment: *receipt.joined_signing_worker_commitment(),
        })
    }

    #[cfg(feature = "local-protocol")]
    pub fn verify_activation_continuity(
        registered_public_key: [u8; 32],
        commitments: ActivationPublicCommitments,
    ) -> Result<ActivationPublicReceipt, BenchmarkRoleError> {
        let receipt = verify_public_activation_receipt_bytes(
            registered_public_key,
            commitments.deriver_a_client,
            commitments.deriver_b_client,
            commitments.deriver_a_signing_worker,
            commitments.deriver_b_signing_worker,
        )?;
        Ok(ActivationPublicReceipt {
            registered_public_key: *receipt.registered_public_key(),
            joined_client_commitment: *receipt.joined_client_commitment(),
            joined_signing_worker_commitment: *receipt.joined_signing_worker_commitment(),
        })
    }

    fn recipient_package_bytes(package: EncodedRecipientPackage) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(package.as_slice().to_vec())
    }

    macro_rules! define_activation_completion {
        ($name:ident, $role:ty, $client_package:ident, $worker_package:ident) => {
            pub struct $name {
                inner: $role,
            }

            impl $name {
                pub fn final_transcript(&self) -> [u8; 32] {
                    *self.inner.final_transcript().as_bytes()
                }

                pub fn stream_metrics(&self) -> StreamMetrics {
                    self.inner.stream_metrics().into()
                }

                pub fn wire_byte_ledger(&self) -> WireByteLedger {
                    WireByteLedger::for_family::<ActivationStream>(self.inner.stream_metrics())
                }

                pub fn client_commitment(&self) -> [u8; 32] {
                    self.inner.client_commitment()
                }

                pub fn signing_worker_commitment(&self) -> [u8; 32] {
                    self.inner.signing_worker_commitment()
                }

                pub fn client_package(&self) -> $client_package {
                    $client_package(recipient_package_bytes(self.inner.encode_client_package()))
                }

                pub fn signing_worker_package(&self) -> $worker_package {
                    $worker_package(recipient_package_bytes(
                        self.inner.encode_signing_worker_package(),
                    ))
                }
            }
        };
    }

    macro_rules! define_export_completion {
        ($name:ident, $role:ty, $package:ident) => {
            pub struct $name {
                inner: $role,
            }

            impl $name {
                pub fn final_transcript(&self) -> [u8; 32] {
                    *self.inner.final_transcript().as_bytes()
                }

                pub fn stream_metrics(&self) -> StreamMetrics {
                    self.inner.stream_metrics().into()
                }

                pub fn wire_byte_ledger(&self) -> WireByteLedger {
                    WireByteLedger::for_family::<ExportStream>(self.inner.stream_metrics())
                }

                pub fn export_package(&self) -> $package {
                    $package(recipient_package_bytes(self.inner.encode_package()))
                }
            }
        };
    }

    define_activation_completion!(
        ActivationDeriverACompletion,
        CompletedRoleA<ActivationStream>,
        ActivationDeriverAClientPackage,
        ActivationDeriverASigningWorkerPackage
    );
    define_activation_completion!(
        ActivationDeriverBCompletion,
        CompletedRoleB<ActivationStream>,
        ActivationDeriverBClientPackage,
        ActivationDeriverBSigningWorkerPackage
    );
    define_export_completion!(
        ExportDeriverACompletion,
        CompletedRoleA<ExportStream>,
        ExportDeriverAClientPackage
    );
    define_export_completion!(
        ExportDeriverBCompletion,
        CompletedRoleB<ExportStream>,
        ExportDeriverBClientPackage
    );

    enum DeriverAState<F, C>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        AwaitOffer(DeriverAAwaitOffer<F, C>),
        ReadyBaseChoices(DeriverAReadyBaseChoices<F, C>),
        ReadyDirect(DeriverAReadyDirect<F, C>),
        AwaitExtension(DeriverAAwaitExtension<F, C>),
        ReadyMasked(DeriverAReadyMasked<F, C>),
        ReadyManifest(DeriverAReadyManifest<F, C>),
        Streaming(DeriverAStreaming<F, C>),
        AwaitLocalEof(DeriverAAwaitReturned<F, C>),
        AwaitReturned(DeriverAAwaitReturned<F, C>),
        AwaitPeerEof(CompletedRoleA<F>),
    }

    struct DeriverA<F, C>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        state: DeriverAState<F, C>,
    }

    enum InternalStep<R, C> {
        Continue(R),
        Send(R, WireMessage),
        Complete(C),
    }

    impl<F, C> DeriverA<F, C>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        fn new(start: F::AStart) -> Self {
            Self {
                state: DeriverAState::AwaitOffer(DeriverAAwaitOffer::new(start)),
            }
        }

        fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
            Ok(match &self.state {
                DeriverAState::AwaitOffer(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::BaseOtOffer,
                    payload_bytes: <OfferKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverAState::ReadyBaseChoices(_)
                | DeriverAState::ReadyDirect(_)
                | DeriverAState::ReadyMasked(_)
                | DeriverAState::ReadyManifest(_)
                | DeriverAState::Streaming(_) => RelayInstruction::Advance,
                DeriverAState::AwaitExtension(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::OtExtensionMatrix,
                    payload_bytes: <ExtensionKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverAState::AwaitLocalEof(_) => RelayInstruction::CloseLocalDirection {
                    terminal_kind: WireMessageKind::OutputTranslation,
                },
                DeriverAState::AwaitReturned(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::ReturnedOutputLabels,
                    payload_bytes: <ReturnedKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverAState::AwaitPeerEof(_) => RelayInstruction::ObservePeerEof {
                    terminal_kind: WireMessageKind::ReturnedOutputLabels,
                },
            })
        }

        fn handle(
            self,
            event: RelayEvent,
        ) -> Result<InternalStep<Self, CompletedRoleA<F>>, BenchmarkRoleError> {
            match (self.state, event) {
                (DeriverAState::AwaitOffer(state), RelayEvent::Inbound(message)) => {
                    let message =
                        take_control::<F, OfferKind>(message, WireMessageKind::BaseOtOffer)?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverAState::ReadyBaseChoices(state.accept_offer(message)?),
                    }))
                }
                (DeriverAState::ReadyBaseChoices(state), RelayEvent::Advance) => {
                    let emitted = state.emit_base_choices();
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverAState::ReadyDirect(emitted.state),
                        },
                        control_message(WireMessageKind::BaseOtChoices, emitted.base_choices),
                    ))
                }
                (DeriverAState::ReadyDirect(state), RelayEvent::Advance) => {
                    let emitted = state.emit_direct()?;
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverAState::AwaitExtension(emitted.state),
                        },
                        control_message(WireMessageKind::DirectInputLabels, emitted.direct),
                    ))
                }
                (DeriverAState::AwaitExtension(state), RelayEvent::Inbound(message)) => {
                    let message = take_control::<F, ExtensionKind>(
                        message,
                        WireMessageKind::OtExtensionMatrix,
                    )?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverAState::ReadyMasked(state.accept_extension(message)?),
                    }))
                }
                (DeriverAState::ReadyMasked(state), RelayEvent::Advance) => {
                    let emitted = state.emit_masked();
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverAState::ReadyManifest(emitted.state),
                        },
                        control_message(WireMessageKind::MaskedInputLabels, emitted.masked),
                    ))
                }
                (DeriverAState::ReadyManifest(state), RelayEvent::Advance) => {
                    let emitted = state.emit_manifest();
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverAState::Streaming(emitted.state),
                        },
                        manifest_message(emitted.manifest),
                    ))
                }
                (DeriverAState::Streaming(state), RelayEvent::Advance) => match state.advance()? {
                    DeriverAStreamAdvance::FrameReady { state, frame } => Ok(InternalStep::Send(
                        Self {
                            state: DeriverAState::Streaming(state),
                        },
                        table_message(frame),
                    )),
                    DeriverAStreamAdvance::TranslationReady(closed) => Ok(InternalStep::Send(
                        Self {
                            state: DeriverAState::AwaitLocalEof(closed.state),
                        },
                        control_message(WireMessageKind::OutputTranslation, closed.translation),
                    )),
                },
                (
                    DeriverAState::AwaitLocalEof(state),
                    RelayEvent::LocalDirectionalEof(evidence),
                ) if evidence.matches(
                    WireDirection::DeriverAToDeriverB,
                    F::session(state.binding),
                    EofEvidenceSource::Encoder,
                ) =>
                {
                    Ok(InternalStep::Continue(Self {
                        state: DeriverAState::AwaitReturned(state),
                    }))
                }
                (DeriverAState::AwaitReturned(state), RelayEvent::Inbound(message)) => {
                    let message = take_control::<F, ReturnedKind>(
                        message,
                        WireMessageKind::ReturnedOutputLabels,
                    )?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverAState::AwaitPeerEof(state.accept_returned(message)?),
                    }))
                }
                (
                    DeriverAState::AwaitPeerEof(completed),
                    RelayEvent::InboundDirectionalEof(evidence),
                ) if evidence.matches(
                    WireDirection::DeriverBToDeriverA,
                    completed.session,
                    EofEvidenceSource::Decoder,
                ) =>
                {
                    Ok(InternalStep::Complete(completed))
                }
                _ => Err(BenchmarkRoleError),
            }
        }
    }

    // Keeping the continuation inline avoids a heap allocation at every frame boundary.
    #[allow(clippy::large_enum_variant)]
    enum DeriverBState<F, C>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        Start(DeriverBStartState<F, C>),
        AwaitBaseChoices(DeriverBAwaitBaseChoices<F, C>),
        AwaitDirect(DeriverBAwaitDirect<F, C>),
        AwaitMasked(DeriverBAwaitMasked<F, C>),
        AwaitManifest(DeriverBAwaitManifest<F, C>),
        Streaming(DeriverBStreaming<F, C>),
        AwaitTranslation(DeriverBAwaitTranslation<F, C>),
        AwaitPeerEof {
            state: DeriverBAwaitTranslation<F, C>,
            translation: EncodedControlMessage<F, TranslationKind>,
        },
        ReadyReturned(DeriverBTerminal<F>),
        AwaitLocalEof(CompletedRoleB<F>),
    }

    struct DeriverB<F, C>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        state: DeriverBState<F, C>,
    }

    impl<F, C> DeriverB<F, C>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        fn new(start: F::BStart) -> Self {
            Self {
                state: DeriverBState::Start(DeriverBStartState::new(start)),
            }
        }

        fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
            Ok(match &self.state {
                DeriverBState::Start(_) | DeriverBState::ReadyReturned(_) => {
                    RelayInstruction::Advance
                }
                DeriverBState::AwaitBaseChoices(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::BaseOtChoices,
                    payload_bytes: <BaseChoicesKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverBState::AwaitDirect(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::DirectInputLabels,
                    payload_bytes: <DirectKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverBState::AwaitMasked(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::MaskedInputLabels,
                    payload_bytes: <MaskedKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverBState::AwaitManifest(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::StreamManifest,
                    payload_bytes: super::super::stream::STREAM_MANIFEST_BYTES,
                },
                DeriverBState::Streaming(state) => RelayInstruction::Receive {
                    kind: WireMessageKind::TableFrame,
                    payload_bytes: TABLE_FRAME_HEADER_BYTES
                        + state
                            .decoder
                            .expected_next_payload_bytes()
                            .map_err(|_| BenchmarkRoleError)?,
                },
                DeriverBState::AwaitTranslation(_) => RelayInstruction::Receive {
                    kind: WireMessageKind::OutputTranslation,
                    payload_bytes: <TranslationKind as ControlKind<F>>::wire_bytes(),
                },
                DeriverBState::AwaitPeerEof { .. } => RelayInstruction::ObservePeerEof {
                    terminal_kind: WireMessageKind::OutputTranslation,
                },
                DeriverBState::AwaitLocalEof(_) => RelayInstruction::CloseLocalDirection {
                    terminal_kind: WireMessageKind::ReturnedOutputLabels,
                },
            })
        }

        fn handle(
            self,
            event: RelayEvent,
        ) -> Result<InternalStep<Self, CompletedRoleB<F>>, BenchmarkRoleError> {
            match (self.state, event) {
                (DeriverBState::Start(state), RelayEvent::Advance) => {
                    let began = state.begin()?;
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverBState::AwaitBaseChoices(began.state),
                        },
                        control_message(WireMessageKind::BaseOtOffer, began.offer),
                    ))
                }
                (DeriverBState::AwaitBaseChoices(state), RelayEvent::Inbound(message)) => {
                    let message = take_control::<F, BaseChoicesKind>(
                        message,
                        WireMessageKind::BaseOtChoices,
                    )?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverBState::AwaitDirect(state.accept_base_choices(message)?),
                    }))
                }
                (DeriverBState::AwaitDirect(state), RelayEvent::Inbound(message)) => {
                    let message =
                        take_control::<F, DirectKind>(message, WireMessageKind::DirectInputLabels)?;
                    let accepted = state.accept_direct(message)?;
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverBState::AwaitMasked(accepted.state),
                        },
                        control_message(WireMessageKind::OtExtensionMatrix, accepted.extension),
                    ))
                }
                (DeriverBState::AwaitMasked(state), RelayEvent::Inbound(message)) => {
                    let message =
                        take_control::<F, MaskedKind>(message, WireMessageKind::MaskedInputLabels)?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverBState::AwaitManifest(state.accept_masked(message)?),
                    }))
                }
                (DeriverBState::AwaitManifest(state), RelayEvent::Inbound(message)) => {
                    let manifest = take_manifest::<F, C>(message)?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverBState::Streaming(state.accept_manifest(manifest)?),
                    }))
                }
                (DeriverBState::Streaming(state), RelayEvent::Inbound(message)) => {
                    let frame = take_table::<F, C>(message)?;
                    match state.accept_frame(frame)? {
                        DeriverBFrameAdvance::NeedsFrame(state) => {
                            Ok(InternalStep::Continue(Self {
                                state: DeriverBState::Streaming(state),
                            }))
                        }
                        DeriverBFrameAdvance::AwaitingTranslation(state) => {
                            Ok(InternalStep::Continue(Self {
                                state: DeriverBState::AwaitTranslation(state),
                            }))
                        }
                    }
                }
                (DeriverBState::AwaitTranslation(state), RelayEvent::Inbound(message)) => {
                    let translation = take_control::<F, TranslationKind>(
                        message,
                        WireMessageKind::OutputTranslation,
                    )?;
                    Ok(InternalStep::Continue(Self {
                        state: DeriverBState::AwaitPeerEof { state, translation },
                    }))
                }
                (
                    DeriverBState::AwaitPeerEof { state, translation },
                    RelayEvent::InboundDirectionalEof(evidence),
                ) if evidence.matches(
                    WireDirection::DeriverAToDeriverB,
                    F::session(state.binding),
                    EofEvidenceSource::Decoder,
                ) =>
                {
                    Ok(InternalStep::Continue(Self {
                        state: DeriverBState::ReadyReturned(state.accept_translation(translation)?),
                    }))
                }
                (DeriverBState::ReadyReturned(terminal), RelayEvent::Advance) => {
                    Ok(InternalStep::Send(
                        Self {
                            state: DeriverBState::AwaitLocalEof(terminal.completed),
                        },
                        control_message(WireMessageKind::ReturnedOutputLabels, terminal.returned),
                    ))
                }
                (
                    DeriverBState::AwaitLocalEof(completed),
                    RelayEvent::LocalDirectionalEof(evidence),
                ) if evidence.matches(
                    WireDirection::DeriverBToDeriverA,
                    completed.session,
                    EofEvidenceSource::Encoder,
                ) =>
                {
                    Ok(InternalStep::Complete(completed))
                }
                _ => Err(BenchmarkRoleError),
            }
        }
    }

    fn control_message<F, K>(
        kind: WireMessageKind,
        message: EncodedControlMessage<F, K>,
    ) -> WireMessage
    where
        F: ProtocolFamily,
        K: ControlKind<F>,
    {
        WireMessage {
            kind,
            bytes: Zeroizing::new(message.into_transport_bytes()),
        }
    }

    fn take_control<F, K>(
        mut message: WireMessage,
        expected: WireMessageKind,
    ) -> Result<EncodedControlMessage<F, K>, BenchmarkRoleError>
    where
        F: ProtocolFamily,
        K: ControlKind<F>,
    {
        if message.kind != expected {
            return Err(BenchmarkRoleError);
        }
        Ok(EncodedControlMessage::from_encoded(core::mem::take(
            &mut *message.bytes,
        ))?)
    }

    fn manifest_message<F, C>(manifest: EncodedStreamManifest<F, C>) -> WireMessage
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        WireMessage {
            kind: WireMessageKind::StreamManifest,
            bytes: Zeroizing::new(manifest.into_transport_bytes()),
        }
    }

    fn take_manifest<F, C>(
        mut message: WireMessage,
    ) -> Result<EncodedStreamManifest<F, C>, BenchmarkRoleError>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        if message.kind != WireMessageKind::StreamManifest {
            return Err(BenchmarkRoleError);
        }
        Ok(EncodedStreamManifest::from_transport_bytes(
            core::mem::take(&mut *message.bytes),
        )?)
    }

    fn table_message<F, C>(frame: EncodedTableFrame<F, C>) -> WireMessage
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        WireMessage {
            kind: WireMessageKind::TableFrame,
            bytes: Zeroizing::new(frame.into_transport_bytes()),
        }
    }

    fn take_table<F, C>(
        mut message: WireMessage,
    ) -> Result<EncodedTableFrame<F, C>, BenchmarkRoleError>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        if message.kind != WireMessageKind::TableFrame {
            return Err(BenchmarkRoleError);
        }
        Ok(EncodedTableFrame::from_transport_bytes(core::mem::take(
            &mut *message.bytes,
        ))?)
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn activation_a_start(
        session: [u8; 32],
    ) -> Result<ActivationDeriverAStart, BenchmarkRoleError> {
        activation_deriver_a_fixture_start(session).map_err(|_| BenchmarkRoleError)
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn activation_b_start(
        session: [u8; 32],
    ) -> Result<ActivationDeriverBStart, BenchmarkRoleError> {
        activation_deriver_b_fixture_start(session).map_err(|_| BenchmarkRoleError)
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn export_a_start(session: [u8; 32]) -> Result<ExportDeriverAStart, BenchmarkRoleError> {
        export_deriver_a_fixture_start(session).map_err(|_| BenchmarkRoleError)
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn export_b_start(session: [u8; 32]) -> Result<ExportDeriverBStart, BenchmarkRoleError> {
        export_deriver_b_fixture_start(session).map_err(|_| BenchmarkRoleError)
    }

    #[cfg(feature = "local-protocol")]
    pub struct ActivationDeriverAInputs {
        inner: PrivateActivationDeriverAInputs,
    }

    #[cfg(feature = "local-protocol")]
    impl ActivationDeriverAInputs {
        pub fn new(
            client_contribution: [u8; 32],
            server_contribution: [u8; 32],
            client_delta: [u8; 32],
            server_delta: [u8; 32],
        ) -> Result<Self, BenchmarkRoleError> {
            Ok(Self {
                inner: PrivateActivationDeriverAInputs::new(
                    DeriverAClientY::from_secret_bytes(client_contribution),
                    DeriverAServerY::from_secret_bytes(server_contribution),
                    DeriverAClientTau::from_canonical_secret_bytes(client_delta)?,
                    DeriverAServerTau::from_canonical_secret_bytes(server_delta)?,
                    DeriverAClientScalarOutputCoin::random_os()?,
                    DeriverASigningWorkerScalarOutputCoin::random_os()?,
                ),
            })
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for ActivationDeriverAInputs {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ActivationDeriverAInputs([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    pub struct ActivationDeriverBInputs {
        inner: PrivateActivationDeriverBInputs,
    }

    #[cfg(feature = "local-protocol")]
    impl ActivationDeriverBInputs {
        pub fn new(
            client_contribution: [u8; 32],
            server_contribution: [u8; 32],
            client_delta: [u8; 32],
            server_delta: [u8; 32],
        ) -> Result<Self, BenchmarkRoleError> {
            Ok(Self {
                inner: PrivateActivationDeriverBInputs::new(
                    DeriverBClientY::from_secret_bytes(client_contribution),
                    DeriverBServerY::from_secret_bytes(server_contribution),
                    DeriverBClientTau::from_canonical_secret_bytes(client_delta)?,
                    DeriverBServerTau::from_canonical_secret_bytes(server_delta)?,
                    DeriverBClientScalarOutputCoin::random_os()?,
                    DeriverBSigningWorkerScalarOutputCoin::random_os()?,
                ),
            })
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for ActivationDeriverBInputs {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ActivationDeriverBInputs([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    pub struct ExportDeriverAInputs {
        inner: PrivateExportDeriverAInputs,
    }

    #[cfg(feature = "local-protocol")]
    impl ExportDeriverAInputs {
        pub fn new(
            client_contribution: [u8; 32],
            server_contribution: [u8; 32],
        ) -> Result<Self, BenchmarkRoleError> {
            Ok(Self {
                inner: PrivateExportDeriverAInputs::new(
                    DeriverAClientY::from_secret_bytes(client_contribution),
                    DeriverAServerY::from_secret_bytes(server_contribution),
                    DeriverASeedOutputCoin::random_os()?,
                ),
            })
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for ExportDeriverAInputs {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ExportDeriverAInputs([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    pub struct ExportDeriverBInputs {
        inner: PrivateExportDeriverBInputs,
    }

    #[cfg(feature = "local-protocol")]
    impl ExportDeriverBInputs {
        pub fn new(
            client_contribution: [u8; 32],
            server_contribution: [u8; 32],
        ) -> Result<Self, BenchmarkRoleError> {
            Ok(Self {
                inner: PrivateExportDeriverBInputs::new(
                    DeriverBClientY::from_secret_bytes(client_contribution),
                    DeriverBServerY::from_secret_bytes(server_contribution),
                    DeriverBSeedOutputCoin::random_os()?,
                ),
            })
        }
    }

    #[cfg(feature = "local-protocol")]
    impl fmt::Debug for ExportDeriverBInputs {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ExportDeriverBInputs([REDACTED])")
        }
    }

    #[cfg(feature = "local-protocol")]
    fn activation_a_start_from_inputs(
        session: [u8; 32],
        inputs: ActivationDeriverAInputs,
    ) -> Result<ActivationDeriverAStart, BenchmarkRoleError> {
        let binding = ActivationSessionBinding::new(SessionId::new(session)?);
        Ok(ActivationDeriverAStart::new(binding, inputs.inner))
    }

    #[cfg(feature = "local-protocol")]
    fn activation_b_start_from_inputs(
        session: [u8; 32],
        inputs: ActivationDeriverBInputs,
    ) -> Result<ActivationDeriverBStart, BenchmarkRoleError> {
        let binding = ActivationSessionBinding::new(SessionId::new(session)?);
        Ok(ActivationDeriverBStart::new(binding, inputs.inner))
    }

    #[cfg(feature = "local-protocol")]
    fn export_a_start_from_inputs(
        session: [u8; 32],
        inputs: ExportDeriverAInputs,
    ) -> Result<ExportDeriverAStart, BenchmarkRoleError> {
        let binding = ExportSessionBinding::new(SessionId::new(session)?);
        Ok(ExportDeriverAStart::new(binding, inputs.inner))
    }

    #[cfg(feature = "local-protocol")]
    fn export_b_start_from_inputs(
        session: [u8; 32],
        inputs: ExportDeriverBInputs,
    ) -> Result<ExportDeriverBStart, BenchmarkRoleError> {
        let binding = ExportSessionBinding::new(SessionId::new(session)?);
        Ok(ExportDeriverBStart::new(binding, inputs.inner))
    }

    macro_rules! define_activation_profile {
        ($a:ident, $b:ident, $chunk:ty) => {
            pub struct $a {
                inner: DeriverA<ActivationStream, $chunk>,
            }

            impl $a {
                #[cfg(feature = "phase9-role-benchmark")]
                pub fn new(session: [u8; 32]) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverA::new(activation_a_start(session)?),
                    })
                }

                #[cfg(feature = "local-protocol")]
                pub fn with_inputs(
                    session: [u8; 32],
                    inputs: ActivationDeriverAInputs,
                ) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverA::new(activation_a_start_from_inputs(session, inputs)?),
                    })
                }

                pub fn handle(
                    self,
                    event: RelayEvent,
                ) -> Result<RelayStep<Self, ActivationDeriverACompletion>, BenchmarkRoleError> {
                    Ok(match self.inner.handle(event)? {
                        InternalStep::Continue(inner) => RelayStep::Continue(Self { inner }),
                        InternalStep::Send(inner, message) => RelayStep::Send {
                            role: Self { inner },
                            message,
                        },
                        InternalStep::Complete(inner) => {
                            RelayStep::Complete(ActivationDeriverACompletion { inner })
                        }
                    })
                }

                pub fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
                    self.inner.instruction()
                }
            }

            pub struct $b {
                inner: DeriverB<ActivationStream, $chunk>,
            }

            impl $b {
                #[cfg(feature = "phase9-role-benchmark")]
                pub fn new(session: [u8; 32]) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverB::new(activation_b_start(session)?),
                    })
                }

                #[cfg(feature = "local-protocol")]
                pub fn with_inputs(
                    session: [u8; 32],
                    inputs: ActivationDeriverBInputs,
                ) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverB::new(activation_b_start_from_inputs(session, inputs)?),
                    })
                }

                pub fn handle(
                    self,
                    event: RelayEvent,
                ) -> Result<RelayStep<Self, ActivationDeriverBCompletion>, BenchmarkRoleError> {
                    Ok(match self.inner.handle(event)? {
                        InternalStep::Continue(inner) => RelayStep::Continue(Self { inner }),
                        InternalStep::Send(inner, message) => RelayStep::Send {
                            role: Self { inner },
                            message,
                        },
                        InternalStep::Complete(inner) => {
                            RelayStep::Complete(ActivationDeriverBCompletion { inner })
                        }
                    })
                }

                pub fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
                    self.inner.instruction()
                }
            }
        };
    }

    macro_rules! define_export_profile {
        ($a:ident, $b:ident, $chunk:ty) => {
            pub struct $a {
                inner: DeriverA<ExportStream, $chunk>,
            }

            impl $a {
                #[cfg(feature = "phase9-role-benchmark")]
                pub fn new(session: [u8; 32]) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverA::new(export_a_start(session)?),
                    })
                }

                #[cfg(feature = "local-protocol")]
                pub fn with_inputs(
                    session: [u8; 32],
                    inputs: ExportDeriverAInputs,
                ) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverA::new(export_a_start_from_inputs(session, inputs)?),
                    })
                }

                pub fn handle(
                    self,
                    event: RelayEvent,
                ) -> Result<RelayStep<Self, ExportDeriverACompletion>, BenchmarkRoleError> {
                    Ok(match self.inner.handle(event)? {
                        InternalStep::Continue(inner) => RelayStep::Continue(Self { inner }),
                        InternalStep::Send(inner, message) => RelayStep::Send {
                            role: Self { inner },
                            message,
                        },
                        InternalStep::Complete(inner) => {
                            RelayStep::Complete(ExportDeriverACompletion { inner })
                        }
                    })
                }

                pub fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
                    self.inner.instruction()
                }
            }

            pub struct $b {
                inner: DeriverB<ExportStream, $chunk>,
            }

            impl $b {
                #[cfg(feature = "phase9-role-benchmark")]
                pub fn new(session: [u8; 32]) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverB::new(export_b_start(session)?),
                    })
                }

                #[cfg(feature = "local-protocol")]
                pub fn with_inputs(
                    session: [u8; 32],
                    inputs: ExportDeriverBInputs,
                ) -> Result<Self, BenchmarkRoleError> {
                    Ok(Self {
                        inner: DeriverB::new(export_b_start_from_inputs(session, inputs)?),
                    })
                }

                pub fn handle(
                    self,
                    event: RelayEvent,
                ) -> Result<RelayStep<Self, ExportDeriverBCompletion>, BenchmarkRoleError> {
                    Ok(match self.inner.handle(event)? {
                        InternalStep::Continue(inner) => RelayStep::Continue(Self { inner }),
                        InternalStep::Send(inner, message) => RelayStep::Send {
                            role: Self { inner },
                            message,
                        },
                        InternalStep::Complete(inner) => {
                            RelayStep::Complete(ExportDeriverBCompletion { inner })
                        }
                    })
                }

                pub fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
                    self.inner.instruction()
                }
            }
        };
    }

    #[cfg(feature = "phase9-role-benchmark")]
    define_activation_profile!(Activation64KiBDeriverA, Activation64KiBDeriverB, Chunk64KiB);
    define_activation_profile!(
        Activation128KiBDeriverA,
        Activation128KiBDeriverB,
        Chunk128KiB
    );
    #[cfg(feature = "phase9-role-benchmark")]
    define_activation_profile!(
        Activation256KiBDeriverA,
        Activation256KiBDeriverB,
        Chunk256KiB
    );
    #[cfg(feature = "phase9-role-benchmark")]
    define_export_profile!(Export64KiBDeriverA, Export64KiBDeriverB, Chunk64KiB);
    define_export_profile!(Export128KiBDeriverA, Export128KiBDeriverB, Chunk128KiB);
    #[cfg(feature = "phase9-role-benchmark")]
    define_export_profile!(Export256KiBDeriverA, Export256KiBDeriverB, Chunk256KiB);

    #[cfg(test)]
    mod codec_tests {
        use super::*;

        fn message(kind: WireMessageKind, payload_bytes: usize) -> WireMessage {
            WireMessage {
                kind,
                bytes: Zeroizing::new(vec![kind.tag(); payload_bytes]),
            }
        }

        fn direction(kind: WireMessageKind) -> WireDirection {
            match kind {
                WireMessageKind::BaseOtOffer
                | WireMessageKind::OtExtensionMatrix
                | WireMessageKind::ReturnedOutputLabels => WireDirection::DeriverBToDeriverA,
                _ => WireDirection::DeriverAToDeriverB,
            }
        }

        #[test]
        fn envelope_tags_lengths_and_incremental_chunks_are_canonical() {
            let session = [0x91; 32];
            let kinds = [
                WireMessageKind::BaseOtOffer,
                WireMessageKind::BaseOtChoices,
                WireMessageKind::DirectInputLabels,
                WireMessageKind::OtExtensionMatrix,
                WireMessageKind::MaskedInputLabels,
                WireMessageKind::StreamManifest,
                WireMessageKind::TableFrame,
                WireMessageKind::OutputTranslation,
                WireMessageKind::ReturnedOutputLabels,
            ];
            for (index, kind) in kinds.into_iter().enumerate() {
                let payload_bytes = index + 1;
                let direction = direction(kind);
                let mut encoder = DirectionalWireEncoder::new(direction, session).expect("encoder");
                let encoded = encoder
                    .encode(message(kind, payload_bytes))
                    .expect("envelope");
                assert_eq!(&encoded[..8], WIRE_ENVELOPE_MAGIC);
                assert_eq!(encoded[8], WIRE_ENVELOPE_VERSION);
                assert_eq!(encoded[9], kind.tag());
                assert_eq!(&encoded[10..12], &[0, 0]);
                assert_eq!(
                    u32::from_be_bytes(encoded[12..16].try_into().expect("length")) as usize,
                    payload_bytes
                );

                let mut decoder = DirectionalWireDecoder::new(direction, session).expect("decoder");
                for byte in &encoded {
                    assert_eq!(decoder.push(core::slice::from_ref(byte)).expect("byte"), 1);
                }
                let decoded = decoder.take_message().expect("decode").expect("message");
                assert_eq!(decoded.kind(), kind);
                assert_eq!(decoded.as_bytes(), vec![kind.tag(); payload_bytes]);
            }
        }

        #[test]
        fn envelope_rejects_corruption_truncation_and_wrong_terminal_direction() {
            let session = [0x92; 32];
            let mut encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("encoder");
            let encoded = encoder
                .encode(message(WireMessageKind::BaseOtChoices, 8))
                .expect("envelope");
            for offset in [0_usize, 8, 9, 10, 12] {
                let mut corrupted = encoded.clone();
                corrupted[offset] ^= 0xff;
                let mut decoder =
                    DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session)
                        .expect("decoder");
                let result = decoder.push(&corrupted);
                if result.is_ok() {
                    assert!(decoder.take_message().is_err());
                } else {
                    assert!(result.is_err());
                }
            }

            let mut truncated =
                DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("decoder");
            truncated.push(&encoded[..10]).expect("partial header");
            assert!(truncated.finish_at_transport_eof().is_err());

            let mut partial_payload =
                DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("decoder");
            partial_payload
                .push(&encoded[..encoded.len() - 1])
                .expect("partial payload");
            assert!(partial_payload.finish_at_transport_eof().is_err());

            let mut wrong_direction_encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("encoder");
            assert!(wrong_direction_encoder
                .encode(message(WireMessageKind::BaseOtOffer, 1))
                .is_err());

            let mut wrong_encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session)
                    .expect("encoder");
            let wrong_terminal = wrong_encoder
                .encode(message(WireMessageKind::ReturnedOutputLabels, 1))
                .expect("wrong terminal envelope");
            let mut decoder =
                DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("decoder");
            decoder.push(&wrong_terminal).expect("framed terminal");
            assert!(decoder.take_message().is_err());

            let mut terminal_encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("encoder");
            let terminal = terminal_encoder
                .encode(message(WireMessageKind::OutputTranslation, 1))
                .expect("terminal");
            let mut with_trailing = terminal.clone();
            with_trailing.push(0xaa);
            let mut decoder =
                DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("decoder");
            assert_eq!(
                decoder.push(&with_trailing).expect("terminal prefix"),
                terminal.len()
            );
            assert_eq!(
                decoder
                    .take_message()
                    .expect("terminal message")
                    .expect("message")
                    .kind(),
                WireMessageKind::OutputTranslation
            );
            assert!(decoder.push(&with_trailing[terminal.len()..]).is_err());
        }

        #[test]
        fn terminal_codec_rejects_duplicate_messages_and_binds_eof_evidence() {
            let session = [0x93; 32];
            let mut encoder =
                DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session)
                    .expect("encoder");
            encoder
                .encode(message(WireMessageKind::OutputTranslation, 1))
                .expect("translation");
            assert!(encoder
                .encode(message(WireMessageKind::TableFrame, 1))
                .is_err());
            let evidence = encoder
                .finish_after_transport_close()
                .expect("terminal close");
            assert!(evidence.matches(
                WireDirection::DeriverAToDeriverB,
                session,
                EofEvidenceSource::Encoder,
            ));
            assert!(!evidence.matches(
                WireDirection::DeriverAToDeriverB,
                [0x94; 32],
                EofEvidenceSource::Encoder,
            ));
            assert!(!evidence.matches(
                WireDirection::DeriverAToDeriverB,
                session,
                EofEvidenceSource::Decoder,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use super::*;
    use crate::passive::stream::{Chunk128KiB, Chunk256KiB, Chunk64KiB};

    const PACKAGE_TRANSCRIPT_RANGE: core::ops::Range<usize> = 112..144;
    const PACKAGE_SHARE_RANGE: core::ops::Range<usize> = 152..184;

    fn route_control<F, K>(
        message: EncodedControlMessage<F, K>,
    ) -> Result<EncodedControlMessage<F, K>, RoleProtocolError>
    where
        F: ProtocolFamily,
        K: ControlKind<F>,
    {
        EncodedControlMessage::from_encoded(message.into_transport_bytes())
    }

    fn route_manifest<F, C>(
        manifest: EncodedStreamManifest<F, C>,
    ) -> Result<EncodedStreamManifest<F, C>, RoleProtocolError>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        EncodedStreamManifest::from_transport_bytes(manifest.into_transport_bytes())
    }

    fn route_table_frame<F, C>(
        frame: EncodedTableFrame<F, C>,
    ) -> Result<EncodedTableFrame<F, C>, RoleProtocolError>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        EncodedTableFrame::from_transport_bytes(frame.into_transport_bytes())
    }

    fn run_roles<F, C>(
        a_start: F::AStart,
        b_start: F::BStart,
    ) -> Result<(CompletedRoleA<F>, CompletedRoleB<F>), RoleProtocolError>
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        let DeriverBBegan {
            state: b_await_base,
            offer,
        } = DeriverBStartState::<F, C>::new(b_start).begin()?;
        let a_ready_base =
            DeriverAAwaitOffer::<F, C>::new(a_start).accept_offer(route_control(offer)?)?;

        let DeriverABaseChoicesEmitted {
            state: a_ready_direct,
            base_choices,
        } = a_ready_base.emit_base_choices();
        let b_await_direct = b_await_base.accept_base_choices(route_control(base_choices)?)?;

        let DeriverADirectEmitted {
            state: a_await_extension,
            direct,
        } = a_ready_direct.emit_direct()?;
        let DeriverBDirectAccepted {
            state: b_await_masked,
            extension,
        } = b_await_direct.accept_direct(route_control(direct)?)?;

        let a_ready_masked = a_await_extension.accept_extension(route_control(extension)?)?;
        let DeriverAMaskedEmitted {
            state: a_ready_manifest,
            masked,
        } = a_ready_masked.emit_masked();
        let b_await_manifest = b_await_masked.accept_masked(route_control(masked)?)?;

        let DeriverAManifestEmitted {
            state: a_stream,
            manifest,
        } = a_ready_manifest.emit_manifest();
        let b_stream = b_await_manifest.accept_manifest(route_manifest(manifest)?)?;

        let mut a_stream = Some(a_stream);
        let mut b_stream = Some(b_stream);
        let mut b_await_translation = None;
        let a_table_closed = loop {
            let a = a_stream.take().ok_or(RoleProtocolError::StateInvariant)?;
            match a.advance()? {
                DeriverAStreamAdvance::FrameReady { state, frame } => {
                    a_stream = Some(state);
                    let b = b_stream.take().ok_or(RoleProtocolError::StateInvariant)?;
                    match b.accept_frame(route_table_frame(frame)?)? {
                        DeriverBFrameAdvance::NeedsFrame(state) => b_stream = Some(state),
                        DeriverBFrameAdvance::AwaitingTranslation(state) => {
                            b_await_translation = Some(state)
                        }
                    }
                }
                DeriverAStreamAdvance::TranslationReady(state) => break state,
            }
        };
        if b_stream.is_some() {
            return Err(RoleProtocolError::StateInvariant);
        }
        let DeriverATableClosed {
            state: a_await_returned,
            translation,
        } = a_table_closed;
        let DeriverBTerminal {
            completed: b_completed,
            returned,
        } = b_await_translation
            .ok_or(RoleProtocolError::StateInvariant)?
            .accept_translation(route_control(translation)?)?;
        let a_completed = a_await_returned.accept_returned(route_control(returned)?)?;
        Ok((a_completed, b_completed))
    }

    fn activation_starts(session_marker: u8) -> (ActivationDeriverAStart, ActivationDeriverBStart) {
        (
            super::super::role_protocol_support::activation_deriver_a_fixture_start(
                [session_marker; 32],
            )
            .expect("A fixture"),
            super::super::role_protocol_support::activation_deriver_b_fixture_start(
                [session_marker; 32],
            )
            .expect("B fixture"),
        )
    }

    fn export_starts(session_marker: u8) -> (ExportDeriverAStart, ExportDeriverBStart) {
        (
            super::super::role_protocol_support::export_deriver_a_fixture_start(
                [session_marker; 32],
            )
            .expect("A fixture"),
            super::super::role_protocol_support::export_deriver_b_fixture_start(
                [session_marker; 32],
            )
            .expect("B fixture"),
        )
    }

    fn assert_activation<C: FixedChunkProfile>(session_marker: u8) {
        let (a_start, b_start) = activation_starts(session_marker);
        let (a, b) = run_roles::<ActivationStream, C>(a_start, b_start).expect("role relay");
        assert_eq!(a.final_transcript(), b.final_transcript());
        assert_stream_metrics::<ActivationStream, C>(a.stream_metrics(), true);
        assert_stream_metrics::<ActivationStream, C>(b.stream_metrics(), false);

        let a_client = a.encode_client_package();
        let a_worker = a.encode_signing_worker_package();
        let b_client = b.encode_client_package();
        let b_worker = b.encode_signing_worker_package();
        assert_package_transcripts(
            a.final_transcript(),
            &[
                a_client.as_slice(),
                a_worker.as_slice(),
                b_client.as_slice(),
                b_worker.as_slice(),
            ],
        );
        let client = parse_scalar(package_share(a_client.as_slice()))
            + parse_scalar(package_share(b_client.as_slice()));
        let worker = parse_scalar(package_share(a_worker.as_slice()))
            + parse_scalar(package_share(b_worker.as_slice()));
        let registered =
            (client + client - worker) * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        assert_eq!(
            registered.compress().to_bytes(),
            [
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ]
        );
    }

    fn assert_export<C: FixedChunkProfile>(session_marker: u8) {
        let (a_start, b_start) = export_starts(session_marker);
        let (a, b) = run_roles::<ExportStream, C>(a_start, b_start).expect("role relay");
        assert_eq!(a.final_transcript(), b.final_transcript());
        assert_stream_metrics::<ExportStream, C>(a.stream_metrics(), true);
        assert_stream_metrics::<ExportStream, C>(b.stream_metrics(), false);

        let a_package = a.encode_package();
        let b_package = b.encode_package();
        assert_package_transcripts(
            a.final_transcript(),
            &[a_package.as_slice(), b_package.as_slice()],
        );
        assert_eq!(
            wrapping_add(
                package_share(a_package.as_slice()),
                package_share(b_package.as_slice()),
            ),
            super::super::role_protocol_support::FIXTURE_SEED
        );
    }

    fn assert_stream_metrics<F, C>(metrics: RoleStreamMetrics, is_garbler: bool)
    where
        F: ProtocolFamily,
        C: FixedChunkProfile,
    {
        let frames = F::TABLE_PAYLOAD_BYTES.div_ceil(C::MAX_PAYLOAD_BYTES);
        let body_bytes = F::TABLE_PAYLOAD_BYTES + frames * TABLE_FRAME_HEADER_BYTES;
        assert_eq!(metrics.table_payload_bytes(), F::TABLE_PAYLOAD_BYTES);
        assert_eq!(metrics.frame_count() as usize, frames);
        assert_eq!(metrics.body_bytes() as usize, body_bytes);
        assert_eq!(
            metrics.peak_table_buffer_bytes(),
            core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES)
        );
        assert_ne!(metrics.peak_arena_bytes(), 0);
        assert_eq!(
            metrics.runtime_chunk_to_wire_copy_bytes(),
            if is_garbler {
                F::TABLE_PAYLOAD_BYTES
            } else {
                0
            }
        );
        assert_eq!(metrics.wire_frame_allocation_bytes() as usize, body_bytes);
        let peak_wire =
            TABLE_FRAME_HEADER_BYTES + core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES);
        assert_eq!(metrics.peak_wire_frame_allocation_bytes(), peak_wire);
        assert_eq!(
            metrics.combined_peak_table_buffer_bytes(),
            if is_garbler {
                peak_wire + core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES)
            } else {
                peak_wire
            }
        );
    }

    fn assert_package_transcripts(transcript: TranscriptDigest32, packages: &[&[u8]]) {
        for package in packages {
            assert_eq!(
                &package[PACKAGE_TRANSCRIPT_RANGE],
                transcript.as_bytes().as_slice()
            );
        }
    }

    fn package_share(encoded: &[u8]) -> &[u8; 32] {
        encoded[PACKAGE_SHARE_RANGE]
            .try_into()
            .expect("package share")
    }

    fn parse_scalar(bytes: &[u8; 32]) -> Scalar {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).expect("canonical share")
    }

    fn wrapping_add(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        let mut index = 0_usize;
        while index < output.len() {
            let sum = left[index] as u16 + right[index] as u16 + carry;
            output[index] = sum as u8;
            carry = sum >> 8;
            index += 1;
        }
        output
    }

    #[test]
    fn activation_64kib_relay_is_role_separated() {
        assert_activation::<Chunk64KiB>(0x71);
    }

    #[test]
    fn activation_128kib_relay_is_role_separated() {
        assert_activation::<Chunk128KiB>(0x72);
    }

    #[test]
    fn activation_256kib_relay_is_role_separated() {
        assert_activation::<Chunk256KiB>(0x73);
    }

    #[test]
    fn export_64kib_relay_is_role_separated() {
        assert_export::<Chunk64KiB>(0x74);
    }

    #[test]
    fn export_128kib_relay_is_role_separated() {
        assert_export::<Chunk128KiB>(0x75);
    }

    #[test]
    fn export_256kib_relay_is_role_separated() {
        assert_export::<Chunk256KiB>(0x76);
    }

    #[test]
    fn transport_frames_have_exact_type_level_lengths() {
        assert_eq!(
            <OfferKind as ControlKind<ActivationStream>>::wire_bytes(),
            4_144
        );
        assert_eq!(
            <OfferKind as ControlKind<ExportStream>>::wire_bytes(),
            4_144
        );
        assert_eq!(
            <DirectKind as ControlKind<ActivationStream>>::wire_bytes(),
            ACTIVATION_DIRECT_MESSAGE_BYTES
        );
        assert_eq!(
            <DirectKind as ControlKind<ExportStream>>::wire_bytes(),
            EXPORT_DIRECT_MESSAGE_BYTES
        );
        assert_eq!(
            <TranslationKind as ControlKind<ActivationStream>>::wire_bytes(),
            ACTIVATION_TRANSLATION_MESSAGE_BYTES
        );
        assert_eq!(
            <ReturnedKind as ControlKind<ExportStream>>::wire_bytes(),
            EXPORT_RETURNED_MESSAGE_BYTES
        );
        assert!(
            EncodedControlMessage::<ActivationStream, OfferKind>::from_encoded(vec![0; 4_143])
                .is_err()
        );
        assert!(
            EncodedTableFrame::<ActivationStream, Chunk64KiB>::from_transport_bytes(vec![
            0;
            TABLE_FRAME_HEADER_BYTES
        ])
            .is_err()
        );
    }

    #[test]
    fn deriver_a_rejects_replayed_offer_from_another_session() {
        let (a_start, _) = export_starts(0x7a);
        let (_, b_start) = export_starts(0x7b);
        let began = DeriverBStartState::<ExportStream, Chunk64KiB>::new(b_start)
            .begin()
            .expect("B offer");
        assert_eq!(
            DeriverAAwaitOffer::<ExportStream, Chunk64KiB>::new(a_start)
                .accept_offer(began.offer)
                .err(),
            Some(RoleProtocolError::Ot(OtError::SessionMismatch))
        );
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn route_facade_message(
        message: benchmark::WireMessage,
        encoder: &mut benchmark::DirectionalWireEncoder,
        decoder: &mut benchmark::DirectionalWireDecoder,
    ) -> benchmark::WireMessage {
        let encoded = encoder.encode(message).expect("encode envelope");
        let mut offset = 0_usize;
        while offset < encoded.len() {
            let end = core::cmp::min(offset + 17, encoded.len());
            let consumed = decoder.push(&encoded[offset..end]).expect("decode chunk");
            assert_ne!(consumed, 0);
            offset += consumed;
        }
        decoder
            .take_message()
            .expect("take envelope")
            .expect("complete envelope")
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn expect_continue<R, C>(step: benchmark::RelayStep<R, C>) -> R {
        match step {
            benchmark::RelayStep::Continue(role) => role,
            _ => panic!("expected continuation"),
        }
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn expect_send<R, C>(step: benchmark::RelayStep<R, C>) -> (R, benchmark::WireMessage) {
        match step {
            benchmark::RelayStep::Send { role, message } => (role, message),
            _ => panic!("expected outbound message"),
        }
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn expect_complete<R, C>(step: benchmark::RelayStep<R, C>) -> C {
        match step {
            benchmark::RelayStep::Complete(completed) => completed,
            _ => panic!("expected completion"),
        }
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn assert_instruction<R>(
        role: &R,
        instruction: fn(&R) -> Result<benchmark::RelayInstruction, benchmark::BenchmarkRoleError>,
        expected: benchmark::RelayInstruction,
    ) {
        assert_eq!(instruction(role).expect("relay instruction"), expected);
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn receive_instruction(message: &benchmark::WireMessage) -> benchmark::RelayInstruction {
        benchmark::RelayInstruction::Receive {
            kind: message.kind(),
            payload_bytes: message.as_bytes().len(),
        }
    }

    #[cfg(feature = "phase9-role-benchmark")]
    fn run_facade<A, B, AC, BC>(
        session: [u8; 32],
        mut a: A,
        mut b: B,
        handle_a: fn(
            A,
            benchmark::RelayEvent,
        ) -> Result<benchmark::RelayStep<A, AC>, benchmark::BenchmarkRoleError>,
        handle_b: fn(
            B,
            benchmark::RelayEvent,
        ) -> Result<benchmark::RelayStep<B, BC>, benchmark::BenchmarkRoleError>,
        instruction_a: fn(&A) -> Result<benchmark::RelayInstruction, benchmark::BenchmarkRoleError>,
        instruction_b: fn(&B) -> Result<benchmark::RelayInstruction, benchmark::BenchmarkRoleError>,
    ) -> (AC, BC) {
        let mut a_to_b_encoder = benchmark::DirectionalWireEncoder::new(
            benchmark::WireDirection::DeriverAToDeriverB,
            session,
        )
        .expect("A encoder");
        let mut a_to_b_decoder = benchmark::DirectionalWireDecoder::new(
            benchmark::WireDirection::DeriverAToDeriverB,
            session,
        )
        .expect("B decoder");
        let mut b_to_a_encoder = benchmark::DirectionalWireEncoder::new(
            benchmark::WireDirection::DeriverBToDeriverA,
            session,
        )
        .expect("B encoder");
        let mut b_to_a_decoder = benchmark::DirectionalWireDecoder::new(
            benchmark::WireDirection::DeriverBToDeriverA,
            session,
        )
        .expect("A decoder");

        assert_instruction(&b, instruction_b, benchmark::RelayInstruction::Advance);
        let (next_b, offer) =
            expect_send(handle_b(b, benchmark::RelayEvent::Advance).expect("B offer"));
        b = next_b;
        let offer = route_facade_message(offer, &mut b_to_a_encoder, &mut b_to_a_decoder);
        assert_instruction(&a, instruction_a, receive_instruction(&offer));
        a = expect_continue(
            handle_a(a, benchmark::RelayEvent::Inbound(offer)).expect("A accepts offer"),
        );

        assert_instruction(&a, instruction_a, benchmark::RelayInstruction::Advance);
        let (next_a, base_choices) =
            expect_send(handle_a(a, benchmark::RelayEvent::Advance).expect("A base choices"));
        a = next_a;
        let base_choices =
            route_facade_message(base_choices, &mut a_to_b_encoder, &mut a_to_b_decoder);
        assert_instruction(&b, instruction_b, receive_instruction(&base_choices));
        b = expect_continue(
            handle_b(b, benchmark::RelayEvent::Inbound(base_choices))
                .expect("B accepts base choices"),
        );

        assert_instruction(&a, instruction_a, benchmark::RelayInstruction::Advance);
        let (next_a, direct) =
            expect_send(handle_a(a, benchmark::RelayEvent::Advance).expect("A direct"));
        a = next_a;
        let direct = route_facade_message(direct, &mut a_to_b_encoder, &mut a_to_b_decoder);
        assert_instruction(&b, instruction_b, receive_instruction(&direct));
        let (next_b, extension) =
            expect_send(handle_b(b, benchmark::RelayEvent::Inbound(direct)).expect("B extension"));
        b = next_b;
        let extension = route_facade_message(extension, &mut b_to_a_encoder, &mut b_to_a_decoder);
        assert_instruction(&a, instruction_a, receive_instruction(&extension));
        a = expect_continue(
            handle_a(a, benchmark::RelayEvent::Inbound(extension)).expect("A accepts extension"),
        );

        assert_instruction(&a, instruction_a, benchmark::RelayInstruction::Advance);
        let (next_a, masked) =
            expect_send(handle_a(a, benchmark::RelayEvent::Advance).expect("A masked"));
        a = next_a;
        let masked = route_facade_message(masked, &mut a_to_b_encoder, &mut a_to_b_decoder);
        assert_instruction(&b, instruction_b, receive_instruction(&masked));
        b = expect_continue(
            handle_b(b, benchmark::RelayEvent::Inbound(masked)).expect("B accepts masked"),
        );

        assert_instruction(&a, instruction_a, benchmark::RelayInstruction::Advance);
        let (next_a, manifest) =
            expect_send(handle_a(a, benchmark::RelayEvent::Advance).expect("A manifest"));
        a = next_a;
        let manifest = route_facade_message(manifest, &mut a_to_b_encoder, &mut a_to_b_decoder);
        assert_instruction(&b, instruction_b, receive_instruction(&manifest));
        b = expect_continue(
            handle_b(b, benchmark::RelayEvent::Inbound(manifest)).expect("B accepts manifest"),
        );

        let translation = loop {
            assert_instruction(&a, instruction_a, benchmark::RelayInstruction::Advance);
            let (next_a, message) =
                expect_send(handle_a(a, benchmark::RelayEvent::Advance).expect("A stream step"));
            a = next_a;
            match message.kind() {
                benchmark::WireMessageKind::TableFrame => {
                    let frame =
                        route_facade_message(message, &mut a_to_b_encoder, &mut a_to_b_decoder);
                    assert_instruction(&b, instruction_b, receive_instruction(&frame));
                    b = expect_continue(
                        handle_b(b, benchmark::RelayEvent::Inbound(frame))
                            .expect("B accepts frame"),
                    );
                }
                benchmark::WireMessageKind::OutputTranslation => break message,
                kind => panic!("unexpected A stream message: {kind:?}"),
            }
        };

        let translation =
            route_facade_message(translation, &mut a_to_b_encoder, &mut a_to_b_decoder);
        assert_instruction(&b, instruction_b, receive_instruction(&translation));
        b = expect_continue(
            handle_b(b, benchmark::RelayEvent::Inbound(translation))
                .expect("B accepts translation"),
        );
        let a_local_eof = a_to_b_encoder
            .finish_after_transport_close()
            .expect("A request EOF");
        assert_instruction(
            &a,
            instruction_a,
            benchmark::RelayInstruction::CloseLocalDirection {
                terminal_kind: benchmark::WireMessageKind::OutputTranslation,
            },
        );
        a = expect_continue(
            handle_a(a, benchmark::RelayEvent::LocalDirectionalEof(a_local_eof))
                .expect("A records request EOF"),
        );
        let b_peer_eof = a_to_b_decoder
            .finish_at_transport_eof()
            .expect("B observes request EOF");
        assert_instruction(
            &b,
            instruction_b,
            benchmark::RelayInstruction::ObservePeerEof {
                terminal_kind: benchmark::WireMessageKind::OutputTranslation,
            },
        );
        b = expect_continue(
            handle_b(b, benchmark::RelayEvent::InboundDirectionalEof(b_peer_eof))
                .expect("B records request EOF"),
        );

        assert_instruction(&b, instruction_b, benchmark::RelayInstruction::Advance);
        let (next_b, returned) =
            expect_send(handle_b(b, benchmark::RelayEvent::Advance).expect("B returned labels"));
        b = next_b;
        let returned = route_facade_message(returned, &mut b_to_a_encoder, &mut b_to_a_decoder);
        assert_instruction(&a, instruction_a, receive_instruction(&returned));
        a = expect_continue(
            handle_a(a, benchmark::RelayEvent::Inbound(returned))
                .expect("A accepts returned labels"),
        );
        let b_local_eof = b_to_a_encoder
            .finish_after_transport_close()
            .expect("B response EOF");
        assert_instruction(
            &b,
            instruction_b,
            benchmark::RelayInstruction::CloseLocalDirection {
                terminal_kind: benchmark::WireMessageKind::ReturnedOutputLabels,
            },
        );
        let b_completed = expect_complete(
            handle_b(b, benchmark::RelayEvent::LocalDirectionalEof(b_local_eof))
                .expect("B records response EOF"),
        );
        let a_peer_eof = b_to_a_decoder
            .finish_at_transport_eof()
            .expect("A observes response EOF");
        assert_instruction(
            &a,
            instruction_a,
            benchmark::RelayInstruction::ObservePeerEof {
                terminal_kind: benchmark::WireMessageKind::ReturnedOutputLabels,
            },
        );
        let a_completed = expect_complete(
            handle_a(a, benchmark::RelayEvent::InboundDirectionalEof(a_peer_eof))
                .expect("A records response EOF"),
        );
        (a_completed, b_completed)
    }

    #[cfg(feature = "phase9-role-benchmark")]
    #[test]
    fn public_activation_facade_relays_enveloped_chunks_and_terminal_eofs() {
        let session = [0x7c; 32];
        let (a, b) = run_facade(
            session,
            benchmark::Activation64KiBDeriverA::new(session).expect("A"),
            benchmark::Activation64KiBDeriverB::new(session).expect("B"),
            benchmark::Activation64KiBDeriverA::handle,
            benchmark::Activation64KiBDeriverB::handle,
            benchmark::Activation64KiBDeriverA::instruction,
            benchmark::Activation64KiBDeriverB::instruction,
        );
        assert_eq!(a.final_transcript(), b.final_transcript());
        assert_eq!(a.stream_metrics().frame_count(), 33);
        assert_eq!(b.stream_metrics().frame_count(), 33);
    }

    #[cfg(feature = "phase9-role-benchmark")]
    #[test]
    fn public_export_facade_relays_enveloped_chunks_and_rejects_wrong_event() {
        let session = [0x7d; 32];
        let wrong = benchmark::Export256KiBDeriverA::new(session).expect("wrong-event A");
        assert!(wrong.handle(benchmark::RelayEvent::Advance).is_err());
        let (a, b) = run_facade(
            session,
            benchmark::Export256KiBDeriverA::new(session).expect("A"),
            benchmark::Export256KiBDeriverB::new(session).expect("B"),
            benchmark::Export256KiBDeriverA::handle,
            benchmark::Export256KiBDeriverB::handle,
            benchmark::Export256KiBDeriverA::instruction,
            benchmark::Export256KiBDeriverB::instruction,
        );
        assert_eq!(a.final_transcript(), b.final_transcript());
        assert_eq!(a.stream_metrics().frame_count(), 1);
        assert_eq!(b.stream_metrics().frame_count(), 1);
    }

    #[cfg(feature = "phase9-role-benchmark")]
    #[test]
    fn remaining_public_activation_profiles_relay_terminal_eofs() {
        let session_128 = [0x7e; 32];
        let (a_128, b_128) = run_facade(
            session_128,
            benchmark::Activation128KiBDeriverA::new(session_128).expect("A128"),
            benchmark::Activation128KiBDeriverB::new(session_128).expect("B128"),
            benchmark::Activation128KiBDeriverA::handle,
            benchmark::Activation128KiBDeriverB::handle,
            benchmark::Activation128KiBDeriverA::instruction,
            benchmark::Activation128KiBDeriverB::instruction,
        );
        assert_eq!(a_128.final_transcript(), b_128.final_transcript());
        assert_eq!(a_128.stream_metrics().frame_count(), 17);
        let a_128_wire = a_128.wire_byte_ledger();
        assert_eq!(a_128_wire, b_128.wire_byte_ledger());
        assert_eq!(a_128_wire.table_payload_bytes(), 2_104_960);
        assert_eq!(a_128_wire.table_framing_payload_bytes(), 1_564);
        assert_eq!(a_128_wire.table_protocol_bytes(), 2_106_772);
        assert_eq!(a_128_wire.ot_payload_bytes(), 82_112);
        assert_eq!(a_128_wire.other_control_payload_bytes(), 33_300);
        assert_eq!(a_128_wire.envelope_header_bytes(), 400);
        assert_eq!(a_128_wire.table_transport_bytes(), 2_107_060);
        assert_eq!(a_128_wire.control_transport_bytes(), 115_524);
        assert_eq!(a_128_wire.deriver_a_to_b_transport_bytes(), 2_185_420);
        assert_eq!(a_128_wire.deriver_b_to_a_transport_bytes(), 37_164);
        assert_eq!(a_128_wire.total_ab_transport_bytes(), 2_222_584);
        assert_eq!(a_128_wire.transport_message_count(), 25);
        assert_eq!(a_128_wire.ot_message_count(), 4);
        assert_eq!(a_128_wire.ot_sequential_round_count(), 4);

        let session_256 = [0x7f; 32];
        let (a_256, b_256) = run_facade(
            session_256,
            benchmark::Activation256KiBDeriverA::new(session_256).expect("A256"),
            benchmark::Activation256KiBDeriverB::new(session_256).expect("B256"),
            benchmark::Activation256KiBDeriverA::handle,
            benchmark::Activation256KiBDeriverB::handle,
            benchmark::Activation256KiBDeriverA::instruction,
            benchmark::Activation256KiBDeriverB::instruction,
        );
        assert_eq!(a_256.final_transcript(), b_256.final_transcript());
        assert_eq!(a_256.stream_metrics().frame_count(), 9);
    }

    #[cfg(feature = "phase9-role-benchmark")]
    #[test]
    fn remaining_public_export_profiles_relay_terminal_eofs() {
        let session_64 = [0x80; 32];
        let (a_64, b_64) = run_facade(
            session_64,
            benchmark::Export64KiBDeriverA::new(session_64).expect("A64"),
            benchmark::Export64KiBDeriverB::new(session_64).expect("B64"),
            benchmark::Export64KiBDeriverA::handle,
            benchmark::Export64KiBDeriverB::handle,
            benchmark::Export64KiBDeriverA::instruction,
            benchmark::Export64KiBDeriverB::instruction,
        );
        assert_eq!(a_64.final_transcript(), b_64.final_transcript());
        assert_eq!(a_64.stream_metrics().frame_count(), 1);

        let session_128 = [0x81; 32];
        let (a_128, b_128) = run_facade(
            session_128,
            benchmark::Export128KiBDeriverA::new(session_128).expect("A128"),
            benchmark::Export128KiBDeriverB::new(session_128).expect("B128"),
            benchmark::Export128KiBDeriverA::handle,
            benchmark::Export128KiBDeriverB::handle,
            benchmark::Export128KiBDeriverA::instruction,
            benchmark::Export128KiBDeriverB::instruction,
        );
        assert_eq!(a_128.final_transcript(), b_128.final_transcript());
        assert_eq!(a_128.stream_metrics().frame_count(), 1);
    }

    #[test]
    fn production_role_source_has_no_blocking_or_joined_transport_path() {
        let production = include_str!("role_protocol.rs")
            .split_once("#[cfg(test)]")
            .expect("tests follow role protocol")
            .0;
        for forbidden in [
            "std::io",
            "UnixStream",
            "TcpStream",
            "Cursor<",
            "struct Paired",
            "whole_body",
            "IdealOt",
            "confirm_local_control_closed",
            "confirm_peer_control_eof",
        ] {
            assert!(
                !production.contains(forbidden),
                "role protocol contains forbidden transport path: {forbidden}"
            );
        }
        assert!(production.contains("finish_exact_section"));
    }

    #[test]
    fn split_role_spec_tracks_version_tags_fixture_and_terminal_order() {
        const SPEC: &str = include_str!("../../docs/passive-role-relay-v1.md");
        for required in [
            "EYAORL01",
            "Offer `1`",
            "BaseChoices `2`",
            "Direct `3`",
            "Extension `4`",
            "Masked `5`",
            "Manifest `6`",
            "TableFrame `7`",
            "Translation `8`",
            "ReturnedLabels `9`",
            "24732",
            "12444",
            "2,104,960",
            "40,800",
            "physical request EOF",
            "physical response EOF",
            "runtime-chunk-to-wire",
        ] {
            assert!(
                SPEC.contains(required),
                "missing split-role spec fact: {required}"
            );
        }
        assert!(SPEC.contains("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    }
}
