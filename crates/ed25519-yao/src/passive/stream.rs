//! Benchmark-only canonical wire grammar for the passive one-pass table stream.
//!
//! The grammar is digest-chained for benchmark corruption detection. It does
//! not authenticate either peer, the opening manifest, or any frame. Phase 6B
//! must add the selected deployment's authenticated manifest and session MAC
//! before any production use.
//!
//! Frame ranges use AND-table ordinals. XOR and inversion gates have no table
//! record, so these fields never claim to be full-schedule gate ordinals.

#![allow(dead_code)]

use core::fmt;
use core::marker::PhantomData;

use sha2::{Digest, Sha256};

use super::roles::{ActivationSessionBinding, ExportSessionBinding, TranscriptDigest32};

pub(super) const STREAM_MANIFEST_BYTES: usize = 248;
pub(super) const TABLE_FRAME_HEADER_BYTES: usize = 92;
pub(super) const TABLE_BYTES_PER_AND_GATE: usize = 32;

const MANIFEST_MAGIC: &[u8; 8] = b"EYAOSTM1";
const FRAME_MAGIC: &[u8; 8] = b"EYAOTF01";
const STREAM_WIRE_VERSION: u8 = 1;
const TABLE_FRAME_TYPE: u8 = 1;
const PROTOCOL_IDENTIFIER: &[u8; 32] = b"seams:ed25519-yao:stream:v1\0\0\0\0\0";
const CLAIM_IDENTIFIER: &[u8] = b"seams:ed25519-yao:passive-benchmark-one-pass:v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"seams:ed25519-yao:stream-manifest-digest:v1";
const CHAIN_START_DOMAIN: &[u8] = b"seams:ed25519-yao:stream-chain-start:v1";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"seams:ed25519-yao:stream-payload-digest:v1";
const FRAME_DIGEST_DOMAIN: &[u8] = b"seams:ed25519-yao:stream-frame-digest:v1";
const FINAL_TRANSCRIPT_DOMAIN: &[u8] = b"seams:ed25519-yao:stream-final-transcript:v1";

const ACTIVATION_FAMILY_TAG: u8 = 0x93;
const EXPORT_FAMILY_TAG: u8 = 0x94;
const ACTIVATION_AND_GATES: u32 = 65_780;
const EXPORT_AND_GATES: u32 = 1_275;
const ACTIVATION_TABLE_BYTES: usize = ACTIVATION_AND_GATES as usize * TABLE_BYTES_PER_AND_GATE;
const EXPORT_TABLE_BYTES: usize = EXPORT_AND_GATES as usize * TABLE_BYTES_PER_AND_GATE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamWireError {
    ManifestLength,
    ManifestMagic,
    Version,
    Family,
    ChunkProfile,
    ManifestReserved,
    ProtocolIdentifier,
    ClaimIdentifier,
    Session,
    GateDomain,
    CircuitDigest,
    ScheduleDigest,
    PreStreamTranscript,
    TablePayloadBytes,
    BodyBytes,
    FrameCount,
    MaximumFramePayload,
    AndGateCount,
    FrameHeaderBytes,
    FrameHeaderLength,
    FrameMagic,
    FrameType,
    FrameReserved,
    Sequence,
    AndTableOrdinalStart,
    AndTableRecordCount,
    PayloadLength,
    PayloadTooLarge,
    PayloadAlignment,
    PreviousFrameDigest,
    PayloadDigest,
    UnexpectedEof,
    TrailingBytes,
    IncompleteStream,
    FinalTranscript,
}

impl fmt::Display for StreamWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid passive benchmark stream wire value: {self:?}"
        )
    }
}

mod sealed {
    pub trait Sealed {}
}

pub(super) trait FixedChunkProfile: sealed::Sealed + Copy {
    const TAG: u8;
    const MAX_PAYLOAD_BYTES: usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Chunk64KiB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Chunk128KiB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Chunk256KiB;

impl sealed::Sealed for Chunk64KiB {}
impl sealed::Sealed for Chunk128KiB {}
impl sealed::Sealed for Chunk256KiB {}

impl FixedChunkProfile for Chunk64KiB {
    const TAG: u8 = 1;
    const MAX_PAYLOAD_BYTES: usize = 64 * 1_024;
}

impl FixedChunkProfile for Chunk128KiB {
    const TAG: u8 = 2;
    const MAX_PAYLOAD_BYTES: usize = 128 * 1_024;
}

impl FixedChunkProfile for Chunk256KiB {
    const TAG: u8 = 3;
    const MAX_PAYLOAD_BYTES: usize = 256 * 1_024;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BindingFields {
    session: [u8; 32],
    gate_domain: u64,
    circuit_digest: [u8; 32],
    schedule_digest: [u8; 32],
}

pub(super) trait FixedStreamFamily: sealed::Sealed + Copy {
    type Binding: Copy;

    const TAG: u8;
    const AND_GATE_COUNT: u32;
    const TABLE_PAYLOAD_BYTES: usize;

    fn binding_fields(binding: Self::Binding) -> BindingFields;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ActivationStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ExportStream;

impl sealed::Sealed for ActivationStream {}
impl sealed::Sealed for ExportStream {}

impl FixedStreamFamily for ActivationStream {
    type Binding = ActivationSessionBinding;

    const TAG: u8 = ACTIVATION_FAMILY_TAG;
    const AND_GATE_COUNT: u32 = ACTIVATION_AND_GATES;
    const TABLE_PAYLOAD_BYTES: usize = ACTIVATION_TABLE_BYTES;

    fn binding_fields(binding: Self::Binding) -> BindingFields {
        BindingFields {
            session: *binding.session_bytes(),
            gate_domain: binding.gate_domain(),
            circuit_digest: *binding.circuit_digest().as_bytes(),
            schedule_digest: *binding.schedule_digest().as_bytes(),
        }
    }
}

impl FixedStreamFamily for ExportStream {
    type Binding = ExportSessionBinding;

    const TAG: u8 = EXPORT_FAMILY_TAG;
    const AND_GATE_COUNT: u32 = EXPORT_AND_GATES;
    const TABLE_PAYLOAD_BYTES: usize = EXPORT_TABLE_BYTES;

    fn binding_fields(binding: Self::Binding) -> BindingFields {
        BindingFields {
            session: *binding.session_bytes(),
            gate_domain: binding.gate_domain(),
            circuit_digest: *binding.circuit_digest().as_bytes(),
            schedule_digest: *binding.schedule_digest().as_bytes(),
        }
    }
}

pub(super) type ActivationStreamManifest<C> = PassiveStreamManifest<ActivationStream, C>;
pub(super) type ExportStreamManifest<C> = PassiveStreamManifest<ExportStream, C>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PassiveStreamManifest<F: FixedStreamFamily, C: FixedChunkProfile> {
    binding: BindingFields,
    pre_stream_transcript: TranscriptDigest32,
    manifest_digest: [u8; 32],
    frame_count: u32,
    body_bytes: u64,
    marker: PhantomData<(F, C)>,
}

impl<F: FixedStreamFamily, C: FixedChunkProfile> fmt::Debug for PassiveStreamManifest<F, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PassiveStreamManifest")
            .field("family", &F::TAG)
            .field("chunk_profile", &C::TAG)
            .field("frame_count", &self.frame_count)
            .field("body_bytes", &self.body_bytes)
            .finish_non_exhaustive()
    }
}

impl<F: FixedStreamFamily, C: FixedChunkProfile> PassiveStreamManifest<F, C> {
    pub(super) fn new(binding: F::Binding, pre_stream_transcript: TranscriptDigest32) -> Self {
        let binding = F::binding_fields(binding);
        let frame_count = frame_count::<F, C>();
        let body_bytes = body_bytes::<F, C>();
        let mut manifest = Self {
            binding,
            pre_stream_transcript,
            manifest_digest: [0_u8; 32],
            frame_count,
            body_bytes,
            marker: PhantomData,
        };
        let encoded = manifest.encode_without_cached_digest();
        manifest.manifest_digest = manifest_digest(&encoded);
        manifest
    }

    pub(super) fn decode(
        binding: F::Binding,
        pre_stream_transcript: TranscriptDigest32,
        encoded: &[u8],
    ) -> Result<Self, StreamWireError> {
        if encoded.len() != STREAM_MANIFEST_BYTES {
            return Err(StreamWireError::ManifestLength);
        }
        let expected = Self::new(binding, pre_stream_transcript);
        validate_manifest::<F, C>(&expected, encoded)?;
        Ok(expected)
    }

    pub(super) fn encode(&self) -> [u8; STREAM_MANIFEST_BYTES] {
        self.encode_without_cached_digest()
    }

    pub(super) const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    pub(super) const fn body_bytes(&self) -> u64 {
        self.body_bytes
    }

    pub(super) const fn table_payload_bytes(&self) -> usize {
        F::TABLE_PAYLOAD_BYTES
    }

    pub(super) const fn maximum_frame_payload_bytes(&self) -> usize {
        C::MAX_PAYLOAD_BYTES
    }

    pub(super) const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    pub(super) fn encoder(self) -> TableFrameEncoder<F, C> {
        TableFrameEncoder::new(self)
    }

    pub(super) fn decoder(self) -> TableFrameDecoder<F, C> {
        TableFrameDecoder::new(self)
    }

    fn encode_without_cached_digest(&self) -> [u8; STREAM_MANIFEST_BYTES] {
        let mut encoded = [0_u8; STREAM_MANIFEST_BYTES];
        encoded[..8].copy_from_slice(MANIFEST_MAGIC);
        encoded[8] = STREAM_WIRE_VERSION;
        encoded[9] = F::TAG;
        encoded[10] = C::TAG;
        encoded[16..48].copy_from_slice(PROTOCOL_IDENTIFIER);
        encoded[48..80].copy_from_slice(&fixed_claim_identifier());
        encoded[80..112].copy_from_slice(&self.binding.session);
        encoded[112..120].copy_from_slice(&self.binding.gate_domain.to_be_bytes());
        encoded[120..152].copy_from_slice(&self.binding.circuit_digest);
        encoded[152..184].copy_from_slice(&self.binding.schedule_digest);
        encoded[184..216].copy_from_slice(self.pre_stream_transcript.as_bytes());
        encoded[216..224].copy_from_slice(&(F::TABLE_PAYLOAD_BYTES as u64).to_be_bytes());
        encoded[224..232].copy_from_slice(&self.body_bytes.to_be_bytes());
        encoded[232..236].copy_from_slice(&self.frame_count.to_be_bytes());
        encoded[236..240].copy_from_slice(&(C::MAX_PAYLOAD_BYTES as u32).to_be_bytes());
        encoded[240..244].copy_from_slice(&F::AND_GATE_COUNT.to_be_bytes());
        encoded[244..246].copy_from_slice(&(TABLE_FRAME_HEADER_BYTES as u16).to_be_bytes());
        encoded
    }
}

fn validate_manifest<F: FixedStreamFamily, C: FixedChunkProfile>(
    expected: &PassiveStreamManifest<F, C>,
    encoded: &[u8],
) -> Result<(), StreamWireError> {
    if &encoded[..8] != MANIFEST_MAGIC {
        return Err(StreamWireError::ManifestMagic);
    }
    if encoded[8] != STREAM_WIRE_VERSION {
        return Err(StreamWireError::Version);
    }
    if encoded[9] != F::TAG {
        return Err(StreamWireError::Family);
    }
    if encoded[10] != C::TAG {
        return Err(StreamWireError::ChunkProfile);
    }
    if encoded[11..16].iter().any(|byte| *byte != 0)
        || encoded[246..248].iter().any(|byte| *byte != 0)
    {
        return Err(StreamWireError::ManifestReserved);
    }
    if encoded[16..48] != *PROTOCOL_IDENTIFIER {
        return Err(StreamWireError::ProtocolIdentifier);
    }
    if encoded[48..80] != fixed_claim_identifier() {
        return Err(StreamWireError::ClaimIdentifier);
    }
    if encoded[80..112] != expected.binding.session {
        return Err(StreamWireError::Session);
    }
    if encoded[112..120] != expected.binding.gate_domain.to_be_bytes() {
        return Err(StreamWireError::GateDomain);
    }
    if encoded[120..152] != expected.binding.circuit_digest {
        return Err(StreamWireError::CircuitDigest);
    }
    if encoded[152..184] != expected.binding.schedule_digest {
        return Err(StreamWireError::ScheduleDigest);
    }
    if encoded[184..216] != *expected.pre_stream_transcript.as_bytes() {
        return Err(StreamWireError::PreStreamTranscript);
    }
    if encoded[216..224] != (F::TABLE_PAYLOAD_BYTES as u64).to_be_bytes() {
        return Err(StreamWireError::TablePayloadBytes);
    }
    if encoded[224..232] != expected.body_bytes.to_be_bytes() {
        return Err(StreamWireError::BodyBytes);
    }
    if encoded[232..236] != expected.frame_count.to_be_bytes() {
        return Err(StreamWireError::FrameCount);
    }
    if encoded[236..240] != (C::MAX_PAYLOAD_BYTES as u32).to_be_bytes() {
        return Err(StreamWireError::MaximumFramePayload);
    }
    if encoded[240..244] != F::AND_GATE_COUNT.to_be_bytes() {
        return Err(StreamWireError::AndGateCount);
    }
    if encoded[244..246] != (TABLE_FRAME_HEADER_BYTES as u16).to_be_bytes() {
        return Err(StreamWireError::FrameHeaderBytes);
    }
    Ok(())
}

fn fixed_claim_identifier() -> [u8; 32] {
    Sha256::digest(CLAIM_IDENTIFIER).into()
}

fn manifest_digest(encoded: &[u8; STREAM_MANIFEST_BYTES]) -> [u8; 32] {
    Sha256::new()
        .chain_update(MANIFEST_DIGEST_DOMAIN)
        .chain_update(encoded)
        .finalize()
        .into()
}

const fn frame_count<F: FixedStreamFamily, C: FixedChunkProfile>() -> u32 {
    let quotient = F::TABLE_PAYLOAD_BYTES / C::MAX_PAYLOAD_BYTES;
    let remainder = F::TABLE_PAYLOAD_BYTES % C::MAX_PAYLOAD_BYTES;
    if remainder == 0 {
        quotient as u32
    } else {
        (quotient + 1) as u32
    }
}

const fn body_bytes<F: FixedStreamFamily, C: FixedChunkProfile>() -> u64 {
    F::TABLE_PAYLOAD_BYTES as u64 + frame_count::<F, C>() as u64 * TABLE_FRAME_HEADER_BYTES as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StreamProgress {
    next_sequence: u32,
    next_and_gate: u32,
    payload_bytes: usize,
    body_bytes: u64,
    previous_frame_digest: [u8; 32],
}

impl StreamProgress {
    fn start<F: FixedStreamFamily, C: FixedChunkProfile>(
        manifest: &PassiveStreamManifest<F, C>,
    ) -> Self {
        let previous_frame_digest: [u8; 32] = Sha256::new()
            .chain_update(CHAIN_START_DOMAIN)
            .chain_update(manifest.manifest_digest)
            .finalize()
            .into();
        Self {
            next_sequence: 0,
            next_and_gate: 0,
            payload_bytes: 0,
            body_bytes: 0,
            previous_frame_digest,
        }
    }

    fn is_complete<F: FixedStreamFamily, C: FixedChunkProfile>(
        self,
        manifest: &PassiveStreamManifest<F, C>,
    ) -> bool {
        self.next_sequence == manifest.frame_count
            && self.next_and_gate == F::AND_GATE_COUNT
            && self.payload_bytes == F::TABLE_PAYLOAD_BYTES
            && self.body_bytes == manifest.body_bytes
    }

    fn expected_payload_bytes<F: FixedStreamFamily, C: FixedChunkProfile>(self) -> usize {
        let remaining = F::TABLE_PAYLOAD_BYTES - self.payload_bytes;
        core::cmp::min(remaining, C::MAX_PAYLOAD_BYTES)
    }
}

#[derive(Clone, Copy)]
pub(super) struct EncodedTableFrameHeader {
    encoded: [u8; TABLE_FRAME_HEADER_BYTES],
    payload_bytes: usize,
    and_table_ordinal_start: u32,
    and_table_record_count: u32,
}

impl fmt::Debug for EncodedTableFrameHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedTableFrameHeader")
            .field("payload_bytes", &self.payload_bytes)
            .field("and_table_ordinal_start", &self.and_table_ordinal_start)
            .field("and_table_record_count", &self.and_table_record_count)
            .finish()
    }
}

impl EncodedTableFrameHeader {
    pub(super) const fn as_bytes(&self) -> &[u8; TABLE_FRAME_HEADER_BYTES] {
        &self.encoded
    }

    pub(super) const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}

#[derive(Debug)]
pub(super) struct TableFrameEncoder<F: FixedStreamFamily, C: FixedChunkProfile> {
    manifest: PassiveStreamManifest<F, C>,
    progress: StreamProgress,
}

impl<F: FixedStreamFamily, C: FixedChunkProfile> TableFrameEncoder<F, C> {
    fn new(manifest: PassiveStreamManifest<F, C>) -> Self {
        let progress = StreamProgress::start(&manifest);
        Self { manifest, progress }
    }

    pub(super) fn encode_next_header(
        &mut self,
        payload: &[u8],
    ) -> Result<EncodedTableFrameHeader, StreamWireError> {
        if self.progress.is_complete(&self.manifest) {
            return Err(StreamWireError::TrailingBytes);
        }
        let expected_payload = self.progress.expected_payload_bytes::<F, C>();
        validate_payload_length::<C>(payload.len(), expected_payload)?;
        let and_table_record_count = u32::try_from(payload.len() / TABLE_BYTES_PER_AND_GATE)
            .map_err(|_| StreamWireError::AndTableRecordCount)?;
        let mut encoded = [0_u8; TABLE_FRAME_HEADER_BYTES];
        encoded[..8].copy_from_slice(FRAME_MAGIC);
        encoded[8] = STREAM_WIRE_VERSION;
        encoded[9] = TABLE_FRAME_TYPE;
        encoded[12..16].copy_from_slice(&self.progress.next_sequence.to_be_bytes());
        encoded[16..20].copy_from_slice(&self.progress.next_and_gate.to_be_bytes());
        encoded[20..24].copy_from_slice(&and_table_record_count.to_be_bytes());
        encoded[24..28].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded[28..60].copy_from_slice(&self.progress.previous_frame_digest);
        let payload_digest = frame_payload_digest(&self.manifest, &encoded[..60], payload);
        encoded[60..92].copy_from_slice(&payload_digest);
        let frame_digest = frame_digest(&self.manifest, &encoded, payload);

        let header = EncodedTableFrameHeader {
            encoded,
            payload_bytes: payload.len(),
            and_table_ordinal_start: self.progress.next_and_gate,
            and_table_record_count,
        };
        self.progress = advance_progress(
            self.progress,
            payload.len(),
            and_table_record_count,
            frame_digest,
        )?;
        Ok(header)
    }

    pub(super) fn complete(self) -> Result<CompletedTableFrameEncoder<F, C>, StreamWireError> {
        let receipt = finish_stream(self.manifest, self.progress)?;
        Ok(CompletedTableFrameEncoder {
            receipt,
            marker: PhantomData,
        })
    }
}

/// A completely encoded body whose transport has not yet confirmed close.
pub(super) struct CompletedTableFrameEncoder<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    receipt: PassiveStreamReceipt,
    marker: PhantomData<(F, C)>,
}

impl<F, C> CompletedTableFrameEncoder<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    /// Converts the locally complete encoding into release evidence only after
    /// the transport adapter has confirmed that the outbound body is closed.
    pub(super) fn confirm_body_closed(self) -> ExactTableStreamReceipt<F, C> {
        self.finish_exact_section()
    }

    /// Completes a typed table section embedded in a longer directional body.
    /// The fixed manifest and frame schedule provide the exact section boundary.
    pub(super) fn finish_exact_section(self) -> ExactTableStreamReceipt<F, C> {
        ExactTableStreamReceipt::new(self.receipt)
    }
}

#[derive(Debug)]
pub(super) struct TableFrameDecoder<F: FixedStreamFamily, C: FixedChunkProfile> {
    manifest: PassiveStreamManifest<F, C>,
    progress: StreamProgress,
}

#[derive(Debug)]
pub(super) struct PendingTableFrame<F: FixedStreamFamily, C: FixedChunkProfile> {
    manifest: PassiveStreamManifest<F, C>,
    progress: StreamProgress,
    encoded_header: [u8; TABLE_FRAME_HEADER_BYTES],
    payload_bytes: usize,
    and_table_ordinal_start: u32,
    and_table_record_count: u32,
}

pub(super) struct ValidatedTableFrame<'a, F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    and_table_ordinal_start: u32,
    and_table_record_count: u32,
    payload: &'a [u8],
    marker: PhantomData<(F, C)>,
}

type AcceptedTableFrame<'a, F, C> = (TableFrameDecoder<F, C>, ValidatedTableFrame<'a, F, C>);

impl<F, C> fmt::Debug for ValidatedTableFrame<'_, F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedTableFrame")
            .field("and_table_ordinal_start", &self.and_table_ordinal_start)
            .field("and_table_record_count", &self.and_table_record_count)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl<F, C> ValidatedTableFrame<'_, F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) const fn and_table_ordinal_start(&self) -> u32 {
        self.and_table_ordinal_start
    }

    pub(super) const fn and_table_record_count(&self) -> u32 {
        self.and_table_record_count
    }

    pub(super) const fn payload(&self) -> &[u8] {
        self.payload
    }
}

impl<F: FixedStreamFamily, C: FixedChunkProfile> TableFrameDecoder<F, C> {
    fn new(manifest: PassiveStreamManifest<F, C>) -> Self {
        let progress = StreamProgress::start(&manifest);
        Self { manifest, progress }
    }

    pub(super) fn expected_next_payload_bytes(&self) -> Result<usize, StreamWireError> {
        if self.progress.is_complete(&self.manifest) {
            return Err(StreamWireError::TrailingBytes);
        }
        Ok(self.progress.expected_payload_bytes::<F, C>())
    }

    pub(super) fn accept_header(
        self,
        encoded: &[u8],
    ) -> Result<PendingTableFrame<F, C>, StreamWireError> {
        if self.progress.is_complete(&self.manifest) {
            return Err(StreamWireError::TrailingBytes);
        }
        if encoded.len() != TABLE_FRAME_HEADER_BYTES {
            return Err(StreamWireError::FrameHeaderLength);
        }
        if &encoded[..8] != FRAME_MAGIC {
            return Err(StreamWireError::FrameMagic);
        }
        if encoded[8] != STREAM_WIRE_VERSION {
            return Err(StreamWireError::Version);
        }
        if encoded[9] != TABLE_FRAME_TYPE {
            return Err(StreamWireError::FrameType);
        }
        if encoded[10..12].iter().any(|byte| *byte != 0) {
            return Err(StreamWireError::FrameReserved);
        }

        let sequence = read_u32(&encoded[12..16]);
        let and_table_ordinal_start = read_u32(&encoded[16..20]);
        let and_table_record_count = read_u32(&encoded[20..24]);
        let payload_bytes = read_u32(&encoded[24..28]) as usize;
        if sequence != self.progress.next_sequence {
            return Err(StreamWireError::Sequence);
        }
        if and_table_ordinal_start != self.progress.next_and_gate {
            return Err(StreamWireError::AndTableOrdinalStart);
        }
        let expected_payload = self.progress.expected_payload_bytes::<F, C>();
        validate_payload_length::<C>(payload_bytes, expected_payload)?;
        let expected_record_count = u32::try_from(payload_bytes / TABLE_BYTES_PER_AND_GATE)
            .map_err(|_| StreamWireError::AndTableRecordCount)?;
        if and_table_record_count != expected_record_count
            || and_table_ordinal_start
                .checked_add(and_table_record_count)
                .is_none()
            || and_table_ordinal_start + and_table_record_count > F::AND_GATE_COUNT
        {
            return Err(StreamWireError::AndTableRecordCount);
        }
        if encoded[28..60] != self.progress.previous_frame_digest {
            return Err(StreamWireError::PreviousFrameDigest);
        }

        let mut encoded_header = [0_u8; TABLE_FRAME_HEADER_BYTES];
        encoded_header.copy_from_slice(encoded);
        Ok(PendingTableFrame {
            manifest: self.manifest,
            progress: self.progress,
            encoded_header,
            payload_bytes,
            and_table_ordinal_start,
            and_table_record_count,
        })
    }

    /// Finishes only after the transport adapter has observed exact body EOF.
    pub(super) fn finish_after_exact_eof(
        self,
    ) -> Result<ExactTableStreamReceipt<F, C>, StreamWireError> {
        self.finish_exact_section()
    }

    /// Completes a typed table section before the next non-table message in a
    /// longer directional body.
    pub(super) fn finish_exact_section(
        self,
    ) -> Result<ExactTableStreamReceipt<F, C>, StreamWireError> {
        if !self.progress.is_complete(&self.manifest) {
            return Err(StreamWireError::UnexpectedEof);
        }
        let receipt = finish_stream(self.manifest, self.progress)?;
        Ok(ExactTableStreamReceipt::new(receipt))
    }
}

impl<F: FixedStreamFamily, C: FixedChunkProfile> PendingTableFrame<F, C> {
    pub(super) const fn expected_payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub(super) fn accept_payload<'a>(
        self,
        payload: &'a [u8],
    ) -> Result<AcceptedTableFrame<'a, F, C>, StreamWireError> {
        if payload.len() != self.payload_bytes {
            return Err(StreamWireError::PayloadLength);
        }
        let expected_digest =
            frame_payload_digest(&self.manifest, &self.encoded_header[..60], payload);
        if self.encoded_header[60..92] != expected_digest {
            return Err(StreamWireError::PayloadDigest);
        }
        let frame_digest = frame_digest(&self.manifest, &self.encoded_header, payload);
        let progress = advance_progress(
            self.progress,
            payload.len(),
            self.and_table_record_count,
            frame_digest,
        )?;
        Ok((
            TableFrameDecoder {
                manifest: self.manifest,
                progress,
            },
            ValidatedTableFrame {
                and_table_ordinal_start: self.and_table_ordinal_start,
                and_table_record_count: self.and_table_record_count,
                payload,
                marker: PhantomData,
            },
        ))
    }

    pub(super) const fn finish_after_exact_eof(
        self,
    ) -> Result<ExactTableStreamReceipt<F, C>, StreamWireError> {
        Err(StreamWireError::UnexpectedEof)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PassiveStreamReceipt {
    final_transcript: TranscriptDigest32,
    manifest_digest: [u8; 32],
    final_frame_digest: [u8; 32],
    frame_count: u32,
    body_bytes: u64,
}

/// Move-only, family/profile-bound evidence that the transport body ended at
/// the canonical stream boundary.
pub(super) struct ExactTableStreamReceipt<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    receipt: PassiveStreamReceipt,
    marker: PhantomData<(F, C)>,
}

impl<F, C> ExactTableStreamReceipt<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn new(receipt: PassiveStreamReceipt) -> Self {
        Self {
            receipt,
            marker: PhantomData,
        }
    }

    pub(super) const fn final_transcript(&self) -> TranscriptDigest32 {
        self.receipt.final_transcript()
    }

    pub(super) const fn frame_count(&self) -> u32 {
        self.receipt.frame_count()
    }

    pub(super) const fn body_bytes(&self) -> u64 {
        self.receipt.body_bytes()
    }
}

impl<F, C> fmt::Debug for ExactTableStreamReceipt<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactTableStreamReceipt")
            .field("frame_count", &self.frame_count())
            .field("body_bytes", &self.body_bytes())
            .finish_non_exhaustive()
    }
}

impl<F, C> PartialEq for ExactTableStreamReceipt<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn eq(&self, other: &Self) -> bool {
        self.receipt == other.receipt
    }
}

impl<F, C> Eq for ExactTableStreamReceipt<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
}

impl PassiveStreamReceipt {
    pub(super) const fn final_transcript(&self) -> TranscriptDigest32 {
        self.final_transcript
    }

    pub(super) const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    pub(super) const fn body_bytes(&self) -> u64 {
        self.body_bytes
    }
}

fn validate_payload_length<C: FixedChunkProfile>(
    actual: usize,
    expected: usize,
) -> Result<(), StreamWireError> {
    if actual > C::MAX_PAYLOAD_BYTES {
        return Err(StreamWireError::PayloadTooLarge);
    }
    if actual == 0 || !actual.is_multiple_of(TABLE_BYTES_PER_AND_GATE) {
        return Err(StreamWireError::PayloadAlignment);
    }
    if actual != expected {
        return Err(StreamWireError::PayloadLength);
    }
    Ok(())
}

fn advance_progress(
    progress: StreamProgress,
    frame_payload_bytes: usize,
    and_table_record_count: u32,
    frame_digest: [u8; 32],
) -> Result<StreamProgress, StreamWireError> {
    let next_sequence = progress
        .next_sequence
        .checked_add(1)
        .ok_or(StreamWireError::Sequence)?;
    let next_and_gate = progress
        .next_and_gate
        .checked_add(and_table_record_count)
        .ok_or(StreamWireError::AndTableRecordCount)?;
    let payload_bytes = progress
        .payload_bytes
        .checked_add(frame_payload_bytes)
        .ok_or(StreamWireError::TablePayloadBytes)?;
    let body_bytes = progress
        .body_bytes
        .checked_add(TABLE_FRAME_HEADER_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(frame_payload_bytes as u64))
        .ok_or(StreamWireError::BodyBytes)?;
    Ok(StreamProgress {
        next_sequence,
        next_and_gate,
        payload_bytes,
        body_bytes,
        previous_frame_digest: frame_digest,
    })
}

fn frame_payload_digest<F: FixedStreamFamily, C: FixedChunkProfile>(
    manifest: &PassiveStreamManifest<F, C>,
    canonical_header_prefix: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(PAYLOAD_DIGEST_DOMAIN)
        .chain_update(manifest.manifest_digest)
        .chain_update(canonical_header_prefix)
        .chain_update(payload)
        .finalize()
        .into()
}

fn frame_digest<F: FixedStreamFamily, C: FixedChunkProfile>(
    manifest: &PassiveStreamManifest<F, C>,
    encoded_header: &[u8; TABLE_FRAME_HEADER_BYTES],
    payload: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(FRAME_DIGEST_DOMAIN)
        .chain_update(manifest.manifest_digest)
        .chain_update(encoded_header)
        .chain_update(payload)
        .finalize()
        .into()
}

fn finish_stream<F: FixedStreamFamily, C: FixedChunkProfile>(
    manifest: PassiveStreamManifest<F, C>,
    progress: StreamProgress,
) -> Result<PassiveStreamReceipt, StreamWireError> {
    if !progress.is_complete(&manifest) {
        return Err(StreamWireError::IncompleteStream);
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(FINAL_TRANSCRIPT_DOMAIN)
        .chain_update(manifest.pre_stream_transcript.as_bytes())
        .chain_update(manifest.manifest_digest)
        .chain_update(progress.previous_frame_digest)
        .chain_update(progress.body_bytes.to_be_bytes())
        .finalize()
        .into();
    let final_transcript =
        TranscriptDigest32::new(digest).map_err(|_| StreamWireError::FinalTranscript)?;
    Ok(PassiveStreamReceipt {
        final_transcript,
        manifest_digest: manifest.manifest_digest,
        final_frame_digest: progress.previous_frame_digest,
        frame_count: progress.next_sequence,
        body_bytes: progress.body_bytes,
    })
}

fn read_u32(encoded: &[u8]) -> u32 {
    u32::from_be_bytes(
        encoded
            .try_into()
            .expect("stream parser passes exactly four bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passive::roles::{SessionId, TranscriptDigest32};

    fn activation_binding(byte: u8) -> ActivationSessionBinding {
        ActivationSessionBinding::new(SessionId::new([byte; 32]).expect("session"))
    }

    fn export_binding(byte: u8) -> ExportSessionBinding {
        ExportSessionBinding::new(SessionId::new([byte; 32]).expect("session"))
    }

    fn transcript(byte: u8) -> TranscriptDigest32 {
        TranscriptDigest32::new([byte; 32]).expect("transcript")
    }

    #[test]
    fn normative_wire_spec_tracks_frozen_code_constants() {
        let specification = include_str!("../../docs/passive-stream-wire-v1.md");
        let code_domains = [
            MANIFEST_DIGEST_DOMAIN,
            CHAIN_START_DOMAIN,
            PAYLOAD_DIGEST_DOMAIN,
            FRAME_DIGEST_DOMAIN,
            FINAL_TRANSCRIPT_DOMAIN,
        ];
        for domain in code_domains {
            let domain = core::str::from_utf8(domain).expect("ASCII digest domain");
            assert!(
                specification.contains(domain),
                "missing digest domain {domain}"
            );
        }
        for frozen_literal in [
            "exactly 248 bytes",
            "92-byte header",
            "65,780",
            "2,104,960",
            "1,275",
            "40,800",
            "2,107,996",
            "2,106,524",
            "2,105,788",
            "EYAOSTM1",
            "EYAOTF01",
        ] {
            assert!(
                specification.contains(frozen_literal),
                "missing frozen literal {frozen_literal}"
            );
        }
    }

    fn payload(length: usize, sequence: u8) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(sequence))
            .collect()
    }

    type EncodedFrame = (Vec<u8>, Vec<u8>);
    type EncodedActivationStream<C> = (
        ActivationStreamManifest<C>,
        Vec<EncodedFrame>,
        ExactTableStreamReceipt<ActivationStream, C>,
    );

    fn encoded_activation_frames<C: FixedChunkProfile>() -> EncodedActivationStream<C> {
        let manifest = ActivationStreamManifest::<C>::new(activation_binding(1), transcript(2));
        let mut encoder = manifest.encoder();
        let mut frames = Vec::new();
        let mut remaining = manifest.table_payload_bytes();
        let mut sequence = 0_u8;
        while remaining != 0 {
            let chunk = core::cmp::min(remaining, manifest.maximum_frame_payload_bytes());
            let payload = payload(chunk, sequence);
            let header = encoder
                .encode_next_header(&payload)
                .expect("canonical frame header");
            frames.push((header.as_bytes().to_vec(), payload));
            remaining -= chunk;
            sequence = sequence.wrapping_add(1);
        }
        let receipt = encoder
            .complete()
            .expect("encoder complete")
            .confirm_body_closed();
        (manifest, frames, receipt)
    }

    fn decode_activation_frames<C: FixedChunkProfile>(
        manifest: ActivationStreamManifest<C>,
        frames: &[(Vec<u8>, Vec<u8>)],
    ) -> ExactTableStreamReceipt<ActivationStream, C> {
        let mut decoder = manifest.decoder();
        for (header, payload) in frames {
            let pending = decoder.accept_header(header).expect("header");
            assert_eq!(pending.expected_payload_bytes(), payload.len());
            let (next, validated) = pending.accept_payload(payload).expect("payload");
            assert_eq!(validated.payload(), payload);
            decoder = next;
        }
        decoder.finish_after_exact_eof().expect("exact EOF")
    }

    #[test]
    fn manifests_freeze_all_family_and_chunk_metrics() {
        let activation_64 =
            ActivationStreamManifest::<Chunk64KiB>::new(activation_binding(1), transcript(2));
        assert_eq!(activation_64.frame_count(), 33);
        assert_eq!(activation_64.body_bytes(), 2_107_996);
        assert_eq!(activation_64.table_payload_bytes(), 2_104_960);
        assert_eq!(activation_64.maximum_frame_payload_bytes(), 65_536);

        let activation_128 =
            ActivationStreamManifest::<Chunk128KiB>::new(activation_binding(1), transcript(2));
        assert_eq!(activation_128.frame_count(), 17);
        assert_eq!(activation_128.body_bytes(), 2_106_524);

        let activation_256 =
            ActivationStreamManifest::<Chunk256KiB>::new(activation_binding(1), transcript(2));
        assert_eq!(activation_256.frame_count(), 9);
        assert_eq!(activation_256.body_bytes(), 2_105_788);

        let export = ExportStreamManifest::<Chunk64KiB>::new(export_binding(1), transcript(2));
        assert_eq!(export.frame_count(), 1);
        assert_eq!(export.body_bytes(), 40_892);
        assert_eq!(export.table_payload_bytes(), 40_800);
    }

    #[test]
    fn manifest_round_trip_is_canonical_and_expected_context_is_mandatory() {
        let binding = activation_binding(1);
        let predecessor = transcript(2);
        let manifest = ActivationStreamManifest::<Chunk128KiB>::new(binding, predecessor);
        let encoded = manifest.encode();
        let decoded =
            ActivationStreamManifest::<Chunk128KiB>::decode(binding, predecessor, &encoded)
                .expect("manifest");
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.manifest_digest(), manifest.manifest_digest());

        assert_eq!(
            ActivationStreamManifest::<Chunk128KiB>::decode(
                activation_binding(3),
                predecessor,
                &encoded,
            )
            .unwrap_err(),
            StreamWireError::Session
        );
        assert_eq!(
            ActivationStreamManifest::<Chunk128KiB>::decode(binding, transcript(4), &encoded,)
                .unwrap_err(),
            StreamWireError::PreStreamTranscript
        );
        assert_eq!(
            ActivationStreamManifest::<Chunk64KiB>::decode(binding, predecessor, &encoded)
                .unwrap_err(),
            StreamWireError::ChunkProfile
        );
        assert_eq!(
            ExportStreamManifest::<Chunk128KiB>::decode(export_binding(1), predecessor, &encoded,)
                .unwrap_err(),
            StreamWireError::Family
        );
    }

    #[test]
    fn malformed_manifest_fields_are_rejected_individually() {
        let binding = activation_binding(1);
        let predecessor = transcript(2);
        let manifest = ActivationStreamManifest::<Chunk64KiB>::new(binding, predecessor);
        let encoded = manifest.encode();
        let cases = [
            (0, StreamWireError::ManifestMagic),
            (8, StreamWireError::Version),
            (9, StreamWireError::Family),
            (10, StreamWireError::ChunkProfile),
            (11, StreamWireError::ManifestReserved),
            (16, StreamWireError::ProtocolIdentifier),
            (48, StreamWireError::ClaimIdentifier),
            (80, StreamWireError::Session),
            (112, StreamWireError::GateDomain),
            (120, StreamWireError::CircuitDigest),
            (152, StreamWireError::ScheduleDigest),
            (184, StreamWireError::PreStreamTranscript),
            (216, StreamWireError::TablePayloadBytes),
            (224, StreamWireError::BodyBytes),
            (232, StreamWireError::FrameCount),
            (236, StreamWireError::MaximumFramePayload),
            (240, StreamWireError::AndGateCount),
            (244, StreamWireError::FrameHeaderBytes),
            (246, StreamWireError::ManifestReserved),
        ];
        for (offset, expected_error) in cases {
            let mut malformed = encoded;
            malformed[offset] ^= 0x80;
            assert_eq!(
                ActivationStreamManifest::<Chunk64KiB>::decode(binding, predecessor, &malformed,)
                    .unwrap_err(),
                expected_error,
                "offset {offset}"
            );
        }
        assert_eq!(
            ActivationStreamManifest::<Chunk64KiB>::decode(
                binding,
                predecessor,
                &encoded[..encoded.len() - 1],
            )
            .unwrap_err(),
            StreamWireError::ManifestLength
        );
    }

    #[test]
    fn all_fixed_chunk_profiles_round_trip_with_identical_terminal_transcripts_per_profile() {
        fn exercise<C: FixedChunkProfile>() {
            let (manifest, frames, encoder_receipt) = encoded_activation_frames::<C>();
            let decoder_receipt = decode_activation_frames(manifest, &frames);
            assert_eq!(encoder_receipt, decoder_receipt);
            assert_eq!(decoder_receipt.frame_count(), manifest.frame_count());
            assert_eq!(decoder_receipt.body_bytes(), manifest.body_bytes());
        }
        exercise::<Chunk64KiB>();
        exercise::<Chunk128KiB>();
        exercise::<Chunk256KiB>();
    }

    #[test]
    fn exact_sequence_duplicate_reordering_and_previous_digest_are_enforced() {
        let (manifest, frames, _) = encoded_activation_frames::<Chunk64KiB>();
        let first_pending = manifest
            .decoder()
            .accept_header(&frames[0].0)
            .expect("first");
        let (after_first, _) = first_pending
            .accept_payload(&frames[0].1)
            .expect("first payload");

        assert_eq!(
            after_first
                .clone_for_test()
                .accept_header(&frames[0].0)
                .unwrap_err(),
            StreamWireError::Sequence
        );
        assert_eq!(
            manifest.decoder().accept_header(&frames[1].0).unwrap_err(),
            StreamWireError::Sequence
        );

        let mut wrong_previous = frames[1].0.clone();
        wrong_previous[28] ^= 1;
        assert_eq!(
            after_first.accept_header(&wrong_previous).unwrap_err(),
            StreamWireError::PreviousFrameDigest
        );
    }

    #[test]
    fn and_table_ranges_and_payload_sizes_are_exact() {
        let (manifest, frames, _) = encoded_activation_frames::<Chunk64KiB>();
        let mutations = [
            (16, StreamWireError::AndTableOrdinalStart),
            (20, StreamWireError::AndTableRecordCount),
            (24, StreamWireError::PayloadTooLarge),
        ];
        for (offset, expected) in mutations {
            let mut malformed = frames[0].0.clone();
            malformed[offset + 3] ^= 1;
            assert_eq!(
                manifest.decoder().accept_header(&malformed).unwrap_err(),
                expected
            );
        }

        let mut encoder = manifest.encoder();
        assert_eq!(
            encoder.encode_next_header(&[0_u8; 31]).unwrap_err(),
            StreamWireError::PayloadAlignment
        );
        assert_eq!(
            encoder.encode_next_header(&vec![0_u8; 65_504]).unwrap_err(),
            StreamWireError::PayloadLength
        );
        assert_eq!(
            encoder.encode_next_header(&vec![0_u8; 65_568]).unwrap_err(),
            StreamWireError::PayloadTooLarge
        );
    }

    #[test]
    fn malformed_frame_header_and_payload_digest_are_rejected() {
        let (manifest, frames, _) = encoded_activation_frames::<Chunk64KiB>();
        let cases = [
            (0, StreamWireError::FrameMagic),
            (8, StreamWireError::Version),
            (9, StreamWireError::FrameType),
            (10, StreamWireError::FrameReserved),
        ];
        for (offset, expected) in cases {
            let mut malformed = frames[0].0.clone();
            malformed[offset] ^= 1;
            assert_eq!(
                manifest.decoder().accept_header(&malformed).unwrap_err(),
                expected
            );
        }
        assert_eq!(
            manifest
                .decoder()
                .accept_header(&frames[0].0[..91])
                .unwrap_err(),
            StreamWireError::FrameHeaderLength
        );

        let pending = manifest
            .decoder()
            .accept_header(&frames[0].0)
            .expect("header");
        assert_eq!(
            pending
                .accept_payload(&frames[0].1[..frames[0].1.len() - 1])
                .unwrap_err(),
            StreamWireError::PayloadLength
        );
        let pending = manifest
            .decoder()
            .accept_header(&frames[0].0)
            .expect("header");
        let mut corrupt_payload = frames[0].1.clone();
        corrupt_payload[0] ^= 1;
        assert_eq!(
            pending.accept_payload(&corrupt_payload).unwrap_err(),
            StreamWireError::PayloadDigest
        );
    }

    #[test]
    fn exact_eof_truncation_and_trailing_bytes_are_enforced() {
        let (manifest, frames, _) = encoded_activation_frames::<Chunk64KiB>();
        assert_eq!(
            manifest.decoder().finish_after_exact_eof().unwrap_err(),
            StreamWireError::UnexpectedEof
        );
        let pending = manifest
            .decoder()
            .accept_header(&frames[0].0)
            .expect("header");
        assert_eq!(
            pending.finish_after_exact_eof().unwrap_err(),
            StreamWireError::UnexpectedEof
        );

        let mut decoder = manifest.decoder();
        for (header, payload) in &frames {
            let pending = decoder.accept_header(header).expect("header");
            (decoder, _) = pending.accept_payload(payload).expect("payload");
        }
        assert_eq!(
            decoder.accept_header(&frames[0].0).unwrap_err(),
            StreamWireError::TrailingBytes
        );
    }

    #[test]
    fn export_single_frame_has_exact_and_table_range_and_eof() {
        let manifest = ExportStreamManifest::<Chunk256KiB>::new(export_binding(5), transcript(6));
        let data = payload(manifest.table_payload_bytes(), 7);
        let mut encoder = manifest.encoder();
        let header = encoder.encode_next_header(&data).expect("header");
        assert_eq!(header.payload_bytes(), 40_800);
        assert_eq!(header.and_table_ordinal_start, 0);
        assert_eq!(header.and_table_record_count, EXPORT_AND_GATES);
        let sender = encoder
            .complete()
            .expect("sender complete")
            .confirm_body_closed();

        let pending = manifest
            .decoder()
            .accept_header(header.as_bytes())
            .expect("header");
        let (decoder, validated) = pending.accept_payload(&data).expect("payload");
        assert_eq!(validated.and_table_ordinal_start(), 0);
        assert_eq!(validated.and_table_record_count(), EXPORT_AND_GATES);
        let receiver = decoder.finish_after_exact_eof().expect("EOF");
        assert_eq!(sender, receiver);
    }

    impl<F: FixedStreamFamily, C: FixedChunkProfile> TableFrameDecoder<F, C> {
        fn clone_for_test(&self) -> Self {
            Self {
                manifest: self.manifest,
                progress: self.progress,
            }
        }
    }
}
