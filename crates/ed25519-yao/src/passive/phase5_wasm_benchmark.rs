//! Transport-neutral Phase 5 benchmark surface for Worker-compatible WASM.
//!
//! This module exposes only the fixed passive viability suite. It does not use
//! blocking I/O and cannot construct a production ceremony.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::phase4::{
    activation_transcript_start, evaluator_inputs, export_transcript_start, prepare_labels,
    protocol_domain,
};
use super::roles::{
    ActivationSessionBinding, ExportSessionBinding, SessionId, TranscriptDigest32,
    ACTIVATION_INPUT_BITS_PER_ROLE, ACTIVATION_OUTPUT_BITS_PER_ROLE, EXPORT_INPUT_BITS_PER_ROLE,
    EXPORT_OUTPUT_BITS_PER_ROLE,
};
use super::stream::{
    ActivationStream, Chunk128KiB, Chunk256KiB, Chunk64KiB, ExportStream, FixedChunkProfile,
    FixedStreamFamily, PassiveStreamManifest, TableFrameDecoder, TableFrameEncoder,
    STREAM_MANIFEST_BYTES, TABLE_FRAME_HEADER_BYTES,
};
use super::stream_runtime::{
    activation_evaluator_machine, activation_garbler_machine, export_evaluator_machine,
    export_garbler_machine, EvaluatorAdvance, EvaluatorBodyComplete, EvaluatorMachine,
    EvaluatorNeedsFrame, GarblerAdvance, GarblerChunk, GarblerMachine,
    StreamedPrivateEvaluatorOutputs, StreamedPrivateGarblerOutputs,
};
use super::{Evaluator, Garbler, GlobalDelta};

/// Fixed circuit family exercised by the isolated WASM benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmBenchmarkFamily {
    /// Phase 4 private-output activation circuit.
    Activation,
    /// Phase 4 private-output export circuit.
    Export,
}

impl WasmBenchmarkFamily {
    /// Returns the stable lower-case benchmark label.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::Export => "export",
        }
    }
}

/// Compile-time-supported table-frame payload profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmChunkProfile {
    /// 64 KiB maximum table payload.
    KiB64,
    /// 128 KiB maximum table payload.
    KiB128,
    /// 256 KiB maximum table payload.
    KiB256,
}

impl WasmChunkProfile {
    /// Returns the exact maximum frame payload bytes.
    pub const fn maximum_payload_bytes(self) -> usize {
        match self {
            Self::KiB64 => 64 * 1_024,
            Self::KiB128 => 128 * 1_024,
            Self::KiB256 => 256 * 1_024,
        }
    }

    /// Returns the stable lower-case benchmark label.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KiB64 => "64kib",
            Self::KiB128 => "128kib",
            Self::KiB256 => "256kib",
        }
    }
}

/// Explicit copy and allocation counters at the Rust/WASM host boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WasmBoundaryMetrics {
    outbound_manifest_copy_bytes: u64,
    inbound_manifest_copy_bytes: u64,
    outbound_frame_copy_bytes: u64,
    inbound_frame_copy_bytes: u64,
    runtime_chunk_to_wire_copy_bytes: u64,
    rust_frame_allocations: u32,
    rust_frame_allocation_bytes: u64,
    peak_rust_frame_allocation_bytes: usize,
}

impl WasmBoundaryMetrics {
    /// Returns manifest bytes copied from WASM into host memory.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn outbound_manifest_copy_bytes(self) -> u64 {
        self.outbound_manifest_copy_bytes
    }

    /// Returns manifest bytes copied from host memory into WASM.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn inbound_manifest_copy_bytes(self) -> u64 {
        self.inbound_manifest_copy_bytes
    }

    /// Returns framed table bytes copied from WASM into host memory.
    pub const fn outbound_frame_copy_bytes(self) -> u64 {
        self.outbound_frame_copy_bytes
    }

    /// Returns framed table bytes copied from host memory into WASM.
    pub const fn inbound_frame_copy_bytes(self) -> u64 {
        self.inbound_frame_copy_bytes
    }

    /// Returns payload bytes copied from A's reusable runtime chunk into wire frames.
    ///
    /// This excludes each 92-byte header and all wasm-bindgen and JavaScript copies.
    pub const fn runtime_chunk_to_wire_copy_bytes(self) -> u64 {
        self.runtime_chunk_to_wire_copy_bytes
    }

    /// Returns the number of Rust-owned wire-frame allocations.
    pub const fn rust_frame_allocations(self) -> u32 {
        self.rust_frame_allocations
    }

    /// Returns the cumulative bytes allocated for Rust wire frames.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn rust_frame_allocation_bytes(self) -> u64 {
        self.rust_frame_allocation_bytes
    }

    /// Returns the largest live Rust wire-frame allocation.
    pub const fn peak_rust_frame_allocation_bytes(self) -> usize {
        self.peak_rust_frame_allocation_bytes
    }

    fn record_outbound_manifest(&mut self, bytes: usize) -> Result<(), WasmBenchmarkError> {
        self.outbound_manifest_copy_bytes =
            checked_add_bytes(self.outbound_manifest_copy_bytes, bytes)?;
        Ok(())
    }

    fn record_inbound_manifest(&mut self, bytes: usize) -> Result<(), WasmBenchmarkError> {
        self.inbound_manifest_copy_bytes =
            checked_add_bytes(self.inbound_manifest_copy_bytes, bytes)?;
        Ok(())
    }

    fn record_outbound_frame(
        &mut self,
        wire_bytes: usize,
        payload_bytes: usize,
    ) -> Result<(), WasmBenchmarkError> {
        self.outbound_frame_copy_bytes =
            checked_add_bytes(self.outbound_frame_copy_bytes, wire_bytes)?;
        self.runtime_chunk_to_wire_copy_bytes =
            checked_add_bytes(self.runtime_chunk_to_wire_copy_bytes, payload_bytes)?;
        self.rust_frame_allocation_bytes =
            checked_add_bytes(self.rust_frame_allocation_bytes, wire_bytes)?;
        self.rust_frame_allocations = self
            .rust_frame_allocations
            .checked_add(1)
            .ok_or(WasmBenchmarkError)?;
        self.peak_rust_frame_allocation_bytes =
            self.peak_rust_frame_allocation_bytes.max(wire_bytes);
        Ok(())
    }

    fn record_inbound_frame(&mut self, bytes: usize) -> Result<(), WasmBenchmarkError> {
        self.inbound_frame_copy_bytes = checked_add_bytes(self.inbound_frame_copy_bytes, bytes)?;
        Ok(())
    }
}

fn checked_add_bytes(current: u64, bytes: usize) -> Result<u64, WasmBenchmarkError> {
    let bytes = u64::try_from(bytes).map_err(|_| WasmBenchmarkError)?;
    current.checked_add(bytes).ok_or(WasmBenchmarkError)
}

/// Opaque failure from the transport-neutral Phase 5 WASM benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmBenchmarkError;

impl fmt::Display for WasmBenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("isolated Phase 5 WASM stream benchmark failed")
    }
}

impl std::error::Error for WasmBenchmarkError {}

/// One host-owned opening-manifest copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WasmOpeningManifest {
    bytes: Vec<u8>,
}

impl WasmOpeningManifest {
    /// Consumes the wrapper and transfers its allocation to the host adapter.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl fmt::Debug for WasmOpeningManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmOpeningManifest")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// One host-owned canonical table frame.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WasmTableFrame {
    bytes: Vec<u8>,
    payload_bytes: usize,
}

impl WasmTableFrame {
    /// Returns only this frame's table payload length.
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// Consumes the wrapper and transfers its allocation to the host adapter.
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl fmt::Debug for WasmTableFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmTableFrame")
            .field("wire_bytes", &self.bytes.len())
            .field("payload_bytes", &self.payload_bytes)
            .finish()
    }
}

/// Final scalar-only evidence from one incremental WASM stream benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmBenchmarkReport {
    family: WasmBenchmarkFamily,
    profile: WasmChunkProfile,
    table_payload_bytes: usize,
    body_bytes: u64,
    frame_count: u32,
    deriver_a_peak_table_buffer_bytes: usize,
    deriver_b_peak_table_buffer_bytes: usize,
    deriver_a_peak_arena_bytes: usize,
    deriver_b_peak_arena_bytes: usize,
    runtime_host_boundary_copy_bytes: usize,
    table_buffer_write_bytes: usize,
    and_records_decoded: usize,
    boundary: WasmBoundaryMetrics,
}

impl WasmBenchmarkReport {
    /// Returns the fixed circuit family.
    pub const fn family(self) -> WasmBenchmarkFamily {
        self.family
    }

    /// Returns the fixed chunk profile.
    pub const fn profile(self) -> WasmChunkProfile {
        self.profile
    }

    /// Returns the exact Half-Gates table payload bytes.
    pub const fn table_payload_bytes(self) -> usize {
        self.table_payload_bytes
    }

    /// Returns table payload plus canonical frame-header bytes.
    pub const fn body_bytes(self) -> u64 {
        self.body_bytes
    }

    /// Returns the exact number of canonical table frames.
    pub const fn frame_count(self) -> u32 {
        self.frame_count
    }

    /// Returns Deriver A's largest live table chunk.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn deriver_a_peak_table_buffer_bytes(self) -> usize {
        self.deriver_a_peak_table_buffer_bytes
    }

    /// Returns Deriver B's largest borrowed validated table frame.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn deriver_b_peak_table_buffer_bytes(self) -> usize {
        self.deriver_b_peak_table_buffer_bytes
    }

    /// Returns Deriver A's fixed-schedule wire arena allocation.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn deriver_a_peak_arena_bytes(self) -> usize {
        self.deriver_a_peak_arena_bytes
    }

    /// Returns Deriver B's fixed-schedule wire arena allocation.
    #[cfg(feature = "passive-wasm-benchmark")]
    pub const fn deriver_b_peak_arena_bytes(self) -> usize {
        self.deriver_b_peak_arena_bytes
    }

    /// Returns copies made by the transport-neutral runtime itself.
    pub const fn runtime_host_boundary_copy_bytes(self) -> usize {
        self.runtime_host_boundary_copy_bytes
    }

    /// Returns payload bytes copied from A's reusable chunk into Rust wire frames.
    pub const fn runtime_chunk_to_wire_copy_bytes(self) -> u64 {
        self.boundary.runtime_chunk_to_wire_copy_bytes()
    }

    /// Returns bytes written once into Deriver A's reusable chunk buffer.
    pub const fn table_buffer_write_bytes(self) -> usize {
        self.table_buffer_write_bytes
    }

    /// Returns the exact number of table records decoded by Deriver B.
    pub const fn and_records_decoded(self) -> usize {
        self.and_records_decoded
    }

    /// Returns explicit WASM-host copy and Rust-frame allocation counters.
    pub const fn boundary_metrics(self) -> WasmBoundaryMetrics {
        self.boundary
    }
}

trait FixedWasmFamily: FixedStreamFamily {
    const FAMILY: WasmBenchmarkFamily;
    const INPUT_BITS_PER_ROLE: usize;
    const OUTPUT_BITS_PER_ROLE: usize;

    fn binding(session: SessionId) -> Self::Binding;
    fn gate_domain(binding: Self::Binding) -> u64;
    fn transcript_start(binding: Self::Binding) -> Result<TranscriptDigest32, WasmBenchmarkError>;
    fn garbler_machine<C: FixedChunkProfile>(
        garbler: Garbler,
        inputs: Vec<super::GarblerWire>,
    ) -> Result<GarblerMachine<Self, C>, WasmBenchmarkError>;
    fn evaluator_machine<C: FixedChunkProfile>(
        evaluator: Evaluator,
        inputs: Vec<super::EvaluatorWire>,
    ) -> Result<EvaluatorMachine<Self, C>, WasmBenchmarkError>;
}

impl FixedWasmFamily for ActivationStream {
    const FAMILY: WasmBenchmarkFamily = WasmBenchmarkFamily::Activation;
    const INPUT_BITS_PER_ROLE: usize = ACTIVATION_INPUT_BITS_PER_ROLE;
    const OUTPUT_BITS_PER_ROLE: usize = ACTIVATION_OUTPUT_BITS_PER_ROLE;

    fn binding(session: SessionId) -> Self::Binding {
        ActivationSessionBinding::new(session)
    }

    fn gate_domain(binding: Self::Binding) -> u64 {
        binding.gate_domain()
    }

    fn transcript_start(binding: Self::Binding) -> Result<TranscriptDigest32, WasmBenchmarkError> {
        activation_transcript_start(binding).map_err(|_| WasmBenchmarkError)
    }

    fn garbler_machine<C: FixedChunkProfile>(
        garbler: Garbler,
        inputs: Vec<super::GarblerWire>,
    ) -> Result<GarblerMachine<Self, C>, WasmBenchmarkError> {
        activation_garbler_machine::<C>(garbler, inputs, Self::OUTPUT_BITS_PER_ROLE)
            .map_err(|_| WasmBenchmarkError)
    }

    fn evaluator_machine<C: FixedChunkProfile>(
        evaluator: Evaluator,
        inputs: Vec<super::EvaluatorWire>,
    ) -> Result<EvaluatorMachine<Self, C>, WasmBenchmarkError> {
        activation_evaluator_machine::<C>(evaluator, inputs, Self::OUTPUT_BITS_PER_ROLE)
            .map_err(|_| WasmBenchmarkError)
    }
}

impl FixedWasmFamily for ExportStream {
    const FAMILY: WasmBenchmarkFamily = WasmBenchmarkFamily::Export;
    const INPUT_BITS_PER_ROLE: usize = EXPORT_INPUT_BITS_PER_ROLE;
    const OUTPUT_BITS_PER_ROLE: usize = EXPORT_OUTPUT_BITS_PER_ROLE;

    fn binding(session: SessionId) -> Self::Binding {
        ExportSessionBinding::new(session)
    }

    fn gate_domain(binding: Self::Binding) -> u64 {
        binding.gate_domain()
    }

    fn transcript_start(binding: Self::Binding) -> Result<TranscriptDigest32, WasmBenchmarkError> {
        export_transcript_start(binding).map_err(|_| WasmBenchmarkError)
    }

    fn garbler_machine<C: FixedChunkProfile>(
        garbler: Garbler,
        inputs: Vec<super::GarblerWire>,
    ) -> Result<GarblerMachine<Self, C>, WasmBenchmarkError> {
        export_garbler_machine::<C>(garbler, inputs, Self::OUTPUT_BITS_PER_ROLE)
            .map_err(|_| WasmBenchmarkError)
    }

    fn evaluator_machine<C: FixedChunkProfile>(
        evaluator: Evaluator,
        inputs: Vec<super::EvaluatorWire>,
    ) -> Result<EvaluatorMachine<Self, C>, WasmBenchmarkError> {
        export_evaluator_machine::<C>(evaluator, inputs, Self::OUTPUT_BITS_PER_ROLE)
            .map_err(|_| WasmBenchmarkError)
    }
}

trait FixedWasmChunk: FixedChunkProfile {
    const PROFILE: WasmChunkProfile;
}

impl FixedWasmChunk for Chunk64KiB {
    const PROFILE: WasmChunkProfile = WasmChunkProfile::KiB64;
}

impl FixedWasmChunk for Chunk128KiB {
    const PROFILE: WasmChunkProfile = WasmChunkProfile::KiB128;
}

impl FixedWasmChunk for Chunk256KiB {
    const PROFILE: WasmChunkProfile = WasmChunkProfile::KiB256;
}

#[allow(clippy::large_enum_variant)]
enum FixedBenchmarkState<F, C>
where
    F: FixedWasmFamily,
    C: FixedWasmChunk,
{
    AwaitingManifest {
        binding: F::Binding,
        pre_stream_transcript: TranscriptDigest32,
        manifest: PassiveStreamManifest<F, C>,
        garbler: GarblerMachine<F, C>,
        evaluator: EvaluatorMachine<F, C>,
    },
    ManifestInFlight {
        binding: F::Binding,
        pre_stream_transcript: TranscriptDigest32,
        manifest: PassiveStreamManifest<F, C>,
        garbler: GarblerMachine<F, C>,
        evaluator: EvaluatorMachine<F, C>,
    },
    Ready {
        encoder: TableFrameEncoder<F, C>,
        decoder: TableFrameDecoder<F, C>,
        garbler: GarblerMachine<F, C>,
        evaluator: EvaluatorNeedsFrame<F, C>,
    },
    FrameInFlight {
        encoder: TableFrameEncoder<F, C>,
        decoder: TableFrameDecoder<F, C>,
        garbler: GarblerChunk<F, C>,
        evaluator: EvaluatorNeedsFrame<F, C>,
    },
    AwaitingOutboundClose {
        encoder: TableFrameEncoder<F, C>,
        decoder: TableFrameDecoder<F, C>,
        garbler: GarblerMachine<F, C>,
        evaluator: EvaluatorBodyComplete<F, C>,
    },
    AwaitingInboundEof {
        decoder: TableFrameDecoder<F, C>,
        garbler: StreamedPrivateGarblerOutputs<F, C>,
        evaluator: EvaluatorBodyComplete<F, C>,
    },
    Complete {
        garbler: StreamedPrivateGarblerOutputs<F, C>,
        evaluator: StreamedPrivateEvaluatorOutputs<F, C>,
    },
    Aborted,
}

struct FixedBenchmarkSession<F, C>
where
    F: FixedWasmFamily,
    C: FixedWasmChunk,
{
    state: FixedBenchmarkState<F, C>,
}

impl<F, C> FixedBenchmarkSession<F, C>
where
    F: FixedWasmFamily,
    C: FixedWasmChunk,
{
    fn expected_frame_count() -> u32 {
        u32::try_from(F::TABLE_PAYLOAD_BYTES.div_ceil(C::MAX_PAYLOAD_BYTES))
            .expect("fixed Phase 5 frame count fits u32")
    }

    fn expected_body_bytes() -> u64 {
        let headers = usize::try_from(Self::expected_frame_count())
            .expect("fixed Phase 5 frame count fits usize")
            * TABLE_FRAME_HEADER_BYTES;
        u64::try_from(F::TABLE_PAYLOAD_BYTES + headers).expect("fixed Phase 5 body length fits u64")
    }

    fn new() -> Result<Self, WasmBenchmarkError> {
        let session = SessionId::random_os().map_err(|_| WasmBenchmarkError)?;
        let binding = F::binding(session);
        let pre_stream_transcript = F::transcript_start(binding)?;
        let domain = protocol_domain(F::gate_domain(binding)).map_err(|_| WasmBenchmarkError)?;
        let garbler = Garbler::new(
            GlobalDelta::random().map_err(|_| WasmBenchmarkError)?,
            domain,
        );
        let input_bytes = Zeroizing::new(vec![0_u8; F::INPUT_BITS_PER_ROLE / 8]);
        let prepared = prepare_labels(&garbler, &input_bytes, F::INPUT_BITS_PER_ROLE)
            .map_err(|_| WasmBenchmarkError)?;
        let mut selected_labels = Zeroizing::new(Vec::with_capacity(F::INPUT_BITS_PER_ROLE));
        for (zero, _) in &prepared.ot_pairs {
            selected_labels.push(*zero);
        }
        let evaluator_inputs = evaluator_inputs(
            prepared.direct_labels.as_slice(),
            selected_labels.as_slice(),
            F::INPUT_BITS_PER_ROLE,
        )
        .map_err(|_| WasmBenchmarkError)?;
        let garbler_machine = F::garbler_machine::<C>(garbler, prepared.garbler_inputs)?;
        let evaluator_machine =
            F::evaluator_machine::<C>(Evaluator::new(domain), evaluator_inputs)?;
        let manifest = PassiveStreamManifest::<F, C>::new(binding, pre_stream_transcript);
        Ok(Self {
            state: FixedBenchmarkState::AwaitingManifest {
                binding,
                pre_stream_transcript,
                manifest,
                garbler: garbler_machine,
                evaluator: evaluator_machine,
            },
        })
    }

    fn take_opening_manifest(
        &mut self,
        metrics: &mut WasmBoundaryMetrics,
    ) -> Result<WasmOpeningManifest, WasmBenchmarkError> {
        let state = core::mem::replace(&mut self.state, FixedBenchmarkState::Aborted);
        let FixedBenchmarkState::AwaitingManifest {
            binding,
            pre_stream_transcript,
            manifest,
            garbler,
            evaluator,
        } = state
        else {
            return Err(WasmBenchmarkError);
        };
        let bytes = manifest.encode().to_vec();
        metrics.record_outbound_manifest(bytes.len())?;
        self.state = FixedBenchmarkState::ManifestInFlight {
            binding,
            pre_stream_transcript,
            manifest,
            garbler,
            evaluator,
        };
        Ok(WasmOpeningManifest { bytes })
    }

    fn accept_opening_manifest(
        &mut self,
        encoded: &[u8],
        metrics: &mut WasmBoundaryMetrics,
    ) -> Result<(), WasmBenchmarkError> {
        metrics.record_inbound_manifest(encoded.len())?;
        let state = core::mem::replace(&mut self.state, FixedBenchmarkState::Aborted);
        let FixedBenchmarkState::ManifestInFlight {
            binding,
            pre_stream_transcript,
            manifest,
            garbler,
            evaluator,
        } = state
        else {
            return Err(WasmBenchmarkError);
        };
        let accepted =
            PassiveStreamManifest::<F, C>::decode(binding, pre_stream_transcript, encoded)
                .map_err(|_| WasmBenchmarkError)?;
        if accepted.encode() != manifest.encode() {
            return Err(WasmBenchmarkError);
        }
        let evaluator = match evaluator.advance().map_err(|_| WasmBenchmarkError)? {
            EvaluatorAdvance::NeedsFrame(evaluator) => evaluator,
            EvaluatorAdvance::AwaitingExactEof(_) => return Err(WasmBenchmarkError),
        };
        self.state = FixedBenchmarkState::Ready {
            encoder: manifest.encoder(),
            decoder: accepted.decoder(),
            garbler,
            evaluator,
        };
        Ok(())
    }

    fn next_table_frame(
        &mut self,
        metrics: &mut WasmBoundaryMetrics,
    ) -> Result<WasmTableFrame, WasmBenchmarkError> {
        let state = core::mem::replace(&mut self.state, FixedBenchmarkState::Aborted);
        let FixedBenchmarkState::Ready {
            mut encoder,
            decoder,
            garbler,
            evaluator,
        } = state
        else {
            return Err(WasmBenchmarkError);
        };
        let chunk = match garbler.advance().map_err(|_| WasmBenchmarkError)? {
            GarblerAdvance::ChunkReady(chunk) => chunk,
            GarblerAdvance::BodyComplete(_) => return Err(WasmBenchmarkError),
        };
        let header = encoder
            .encode_next_header(chunk.payload())
            .map_err(|_| WasmBenchmarkError)?;
        let payload_bytes = chunk.payload().len();
        let wire_bytes = TABLE_FRAME_HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(WasmBenchmarkError)?;
        let mut bytes = Vec::with_capacity(wire_bytes);
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(chunk.payload());
        if bytes.len() != wire_bytes {
            bytes.zeroize();
            return Err(WasmBenchmarkError);
        }
        metrics.record_outbound_frame(bytes.len(), payload_bytes)?;
        self.state = FixedBenchmarkState::FrameInFlight {
            encoder,
            decoder,
            garbler: chunk,
            evaluator,
        };
        Ok(WasmTableFrame {
            bytes,
            payload_bytes,
        })
    }

    fn accept_table_frame(
        &mut self,
        encoded: &[u8],
        metrics: &mut WasmBoundaryMetrics,
    ) -> Result<(), WasmBenchmarkError> {
        metrics.record_inbound_frame(encoded.len())?;
        if encoded.len() < TABLE_FRAME_HEADER_BYTES {
            self.state = FixedBenchmarkState::Aborted;
            return Err(WasmBenchmarkError);
        }
        let state = core::mem::replace(&mut self.state, FixedBenchmarkState::Aborted);
        let FixedBenchmarkState::FrameInFlight {
            encoder,
            decoder,
            garbler,
            evaluator,
        } = state
        else {
            return Err(WasmBenchmarkError);
        };
        let (encoded_header, payload) = encoded.split_at(TABLE_FRAME_HEADER_BYTES);
        let pending = decoder
            .accept_header(encoded_header)
            .map_err(|_| WasmBenchmarkError)?;
        if pending.expected_payload_bytes() != payload.len() {
            return Err(WasmBenchmarkError);
        }
        let (decoder, frame) = pending
            .accept_payload(payload)
            .map_err(|_| WasmBenchmarkError)?;
        let evaluator = evaluator
            .accept_frame(frame)
            .map_err(|_| WasmBenchmarkError)?;
        let evaluator = evaluator.advance().map_err(|_| WasmBenchmarkError)?;
        let garbler = garbler.resume();
        self.state = match evaluator {
            EvaluatorAdvance::NeedsFrame(evaluator) => FixedBenchmarkState::Ready {
                encoder,
                decoder,
                garbler,
                evaluator,
            },
            EvaluatorAdvance::AwaitingExactEof(evaluator) => {
                FixedBenchmarkState::AwaitingOutboundClose {
                    encoder,
                    decoder,
                    garbler,
                    evaluator,
                }
            }
        };
        Ok(())
    }

    fn confirm_outbound_body_closed(&mut self) -> Result<(), WasmBenchmarkError> {
        let state = core::mem::replace(&mut self.state, FixedBenchmarkState::Aborted);
        let FixedBenchmarkState::AwaitingOutboundClose {
            encoder,
            decoder,
            garbler,
            evaluator,
        } = state
        else {
            return Err(WasmBenchmarkError);
        };
        let garbler = match garbler.advance().map_err(|_| WasmBenchmarkError)? {
            GarblerAdvance::BodyComplete(garbler) => garbler,
            GarblerAdvance::ChunkReady(_) => return Err(WasmBenchmarkError),
        };
        let receipt = encoder
            .complete()
            .map_err(|_| WasmBenchmarkError)?
            .confirm_body_closed();
        let garbler = garbler.finalize(receipt).map_err(|_| WasmBenchmarkError)?;
        self.state = FixedBenchmarkState::AwaitingInboundEof {
            decoder,
            garbler,
            evaluator,
        };
        Ok(())
    }

    fn confirm_inbound_exact_eof(&mut self) -> Result<(), WasmBenchmarkError> {
        let state = core::mem::replace(&mut self.state, FixedBenchmarkState::Aborted);
        let FixedBenchmarkState::AwaitingInboundEof {
            decoder,
            garbler,
            evaluator,
        } = state
        else {
            return Err(WasmBenchmarkError);
        };
        let receipt = decoder
            .finish_after_exact_eof()
            .map_err(|_| WasmBenchmarkError)?;
        let evaluator = evaluator
            .finalize(receipt)
            .map_err(|_| WasmBenchmarkError)?;
        self.state = FixedBenchmarkState::Complete { garbler, evaluator };
        Ok(())
    }

    fn finish(
        self,
        boundary: WasmBoundaryMetrics,
    ) -> Result<WasmBenchmarkReport, WasmBenchmarkError> {
        let FixedBenchmarkState::Complete { garbler, evaluator } = self.state else {
            return Err(WasmBenchmarkError);
        };
        finish_fixed_session::<F, C>(garbler, evaluator, boundary)
    }
}

fn finish_fixed_session<F, C>(
    garbler: StreamedPrivateGarblerOutputs<F, C>,
    evaluator: StreamedPrivateEvaluatorOutputs<F, C>,
    boundary: WasmBoundaryMetrics,
) -> Result<WasmBenchmarkReport, WasmBenchmarkError>
where
    F: FixedWasmFamily,
    C: FixedWasmChunk,
{
    if garbler.receipt != evaluator.receipt
        || garbler.table_bytes != F::TABLE_PAYLOAD_BYTES
        || evaluator.table_bytes != F::TABLE_PAYLOAD_BYTES
        || garbler.frame_calls != evaluator.frame_calls
        || usize::try_from(garbler.frame_calls) != Ok(boundary.rust_frame_allocations as usize)
        || garbler.table_buffer_write_bytes != F::TABLE_PAYLOAD_BYTES
        || evaluator.and_records_decoded != F::AND_GATE_COUNT as usize
    {
        return Err(WasmBenchmarkError);
    }
    let body_bytes = garbler.receipt.body_bytes();
    let frame_count = garbler.receipt.frame_count();
    if boundary.outbound_manifest_copy_bytes != STREAM_MANIFEST_BYTES as u64
        || boundary.inbound_manifest_copy_bytes != STREAM_MANIFEST_BYTES as u64
        || boundary.outbound_frame_copy_bytes != body_bytes
        || boundary.inbound_frame_copy_bytes != body_bytes
        || boundary.runtime_chunk_to_wire_copy_bytes != F::TABLE_PAYLOAD_BYTES as u64
        || boundary.rust_frame_allocations != frame_count
        || boundary.peak_rust_frame_allocation_bytes
            > C::MAX_PAYLOAD_BYTES + TABLE_FRAME_HEADER_BYTES
    {
        return Err(WasmBenchmarkError);
    }

    let runtime_host_boundary_copy_bytes = garbler
        .host_boundary_copy_bytes
        .checked_add(evaluator.host_boundary_copy_bytes)
        .ok_or(WasmBenchmarkError)?;
    let mut returned = garbler
        .returned_decoder
        .decode(evaluator.returned_labels)
        .map_err(|_| WasmBenchmarkError)?;
    let mut evaluator_owned = garbler
        .evaluator_translation
        .decode(evaluator.evaluator_labels)
        .map_err(|_| WasmBenchmarkError)?;
    let output_bytes_per_role = F::OUTPUT_BITS_PER_ROLE / 8;
    if returned.len() != output_bytes_per_role || evaluator_owned.len() != output_bytes_per_role {
        returned.zeroize();
        evaluator_owned.zeroize();
        return Err(WasmBenchmarkError);
    }
    returned.zeroize();
    evaluator_owned.zeroize();

    Ok(WasmBenchmarkReport {
        family: F::FAMILY,
        profile: C::PROFILE,
        table_payload_bytes: F::TABLE_PAYLOAD_BYTES,
        body_bytes,
        frame_count,
        deriver_a_peak_table_buffer_bytes: garbler.peak_table_buffer_bytes,
        deriver_b_peak_table_buffer_bytes: evaluator.peak_table_buffer_bytes,
        deriver_a_peak_arena_bytes: garbler.peak_arena_bytes,
        deriver_b_peak_arena_bytes: evaluator.peak_arena_bytes,
        runtime_host_boundary_copy_bytes,
        table_buffer_write_bytes: garbler.table_buffer_write_bytes,
        and_records_decoded: evaluator.and_records_decoded,
        boundary,
    })
}

#[allow(clippy::large_enum_variant)]
enum FixedSession {
    Activation64(FixedBenchmarkSession<ActivationStream, Chunk64KiB>),
    Activation128(FixedBenchmarkSession<ActivationStream, Chunk128KiB>),
    Activation256(FixedBenchmarkSession<ActivationStream, Chunk256KiB>),
    Export64(FixedBenchmarkSession<ExportStream, Chunk64KiB>),
    Export128(FixedBenchmarkSession<ExportStream, Chunk128KiB>),
    Export256(FixedBenchmarkSession<ExportStream, Chunk256KiB>),
}

/// Incremental paired-role benchmark state driven one host chunk at a time.
///
/// The host must transfer and return the opening manifest, then transfer and
/// return exactly one frame before requesting the next. Output release requires
/// separate outbound-close and inbound-exact-EOF confirmations.
pub struct WasmBenchmarkSession {
    inner: FixedSession,
    boundary: WasmBoundaryMetrics,
}

impl WasmBenchmarkSession {
    /// Creates one fresh fixed-family, fixed-profile benchmark session.
    pub fn new(
        family: WasmBenchmarkFamily,
        profile: WasmChunkProfile,
    ) -> Result<Self, WasmBenchmarkError> {
        let inner = match (family, profile) {
            (WasmBenchmarkFamily::Activation, WasmChunkProfile::KiB64) => {
                FixedSession::Activation64(FixedBenchmarkSession::new()?)
            }
            (WasmBenchmarkFamily::Activation, WasmChunkProfile::KiB128) => {
                FixedSession::Activation128(FixedBenchmarkSession::new()?)
            }
            (WasmBenchmarkFamily::Activation, WasmChunkProfile::KiB256) => {
                FixedSession::Activation256(FixedBenchmarkSession::new()?)
            }
            (WasmBenchmarkFamily::Export, WasmChunkProfile::KiB64) => {
                FixedSession::Export64(FixedBenchmarkSession::new()?)
            }
            (WasmBenchmarkFamily::Export, WasmChunkProfile::KiB128) => {
                FixedSession::Export128(FixedBenchmarkSession::new()?)
            }
            (WasmBenchmarkFamily::Export, WasmChunkProfile::KiB256) => {
                FixedSession::Export256(FixedBenchmarkSession::new()?)
            }
        };
        Ok(Self {
            inner,
            boundary: WasmBoundaryMetrics::default(),
        })
    }

    /// Returns the exact number of frames the host must relay.
    pub fn expected_frame_count(&self) -> u32 {
        match &self.inner {
            FixedSession::Activation64(_) => {
                FixedBenchmarkSession::<ActivationStream, Chunk64KiB>::expected_frame_count()
            }
            FixedSession::Activation128(_) => {
                FixedBenchmarkSession::<ActivationStream, Chunk128KiB>::expected_frame_count()
            }
            FixedSession::Activation256(_) => {
                FixedBenchmarkSession::<ActivationStream, Chunk256KiB>::expected_frame_count()
            }
            FixedSession::Export64(_) => {
                FixedBenchmarkSession::<ExportStream, Chunk64KiB>::expected_frame_count()
            }
            FixedSession::Export128(_) => {
                FixedBenchmarkSession::<ExportStream, Chunk128KiB>::expected_frame_count()
            }
            FixedSession::Export256(_) => {
                FixedBenchmarkSession::<ExportStream, Chunk256KiB>::expected_frame_count()
            }
        }
    }

    /// Returns the exact payload-plus-frame-header body length.
    pub fn expected_body_bytes(&self) -> u64 {
        match &self.inner {
            FixedSession::Activation64(_) => {
                FixedBenchmarkSession::<ActivationStream, Chunk64KiB>::expected_body_bytes()
            }
            FixedSession::Activation128(_) => {
                FixedBenchmarkSession::<ActivationStream, Chunk128KiB>::expected_body_bytes()
            }
            FixedSession::Activation256(_) => {
                FixedBenchmarkSession::<ActivationStream, Chunk256KiB>::expected_body_bytes()
            }
            FixedSession::Export64(_) => {
                FixedBenchmarkSession::<ExportStream, Chunk64KiB>::expected_body_bytes()
            }
            FixedSession::Export128(_) => {
                FixedBenchmarkSession::<ExportStream, Chunk128KiB>::expected_body_bytes()
            }
            FixedSession::Export256(_) => {
                FixedBenchmarkSession::<ExportStream, Chunk256KiB>::expected_body_bytes()
            }
        }
    }

    /// Copies the canonical opening manifest into a host-owned message.
    pub fn take_opening_manifest(&mut self) -> Result<WasmOpeningManifest, WasmBenchmarkError> {
        match &mut self.inner {
            FixedSession::Activation64(session) => {
                session.take_opening_manifest(&mut self.boundary)
            }
            FixedSession::Activation128(session) => {
                session.take_opening_manifest(&mut self.boundary)
            }
            FixedSession::Activation256(session) => {
                session.take_opening_manifest(&mut self.boundary)
            }
            FixedSession::Export64(session) => session.take_opening_manifest(&mut self.boundary),
            FixedSession::Export128(session) => session.take_opening_manifest(&mut self.boundary),
            FixedSession::Export256(session) => session.take_opening_manifest(&mut self.boundary),
        }
    }

    /// Accepts the host-returned opening manifest before table production.
    pub fn accept_opening_manifest(&mut self, encoded: &[u8]) -> Result<(), WasmBenchmarkError> {
        match &mut self.inner {
            FixedSession::Activation64(session) => {
                session.accept_opening_manifest(encoded, &mut self.boundary)
            }
            FixedSession::Activation128(session) => {
                session.accept_opening_manifest(encoded, &mut self.boundary)
            }
            FixedSession::Activation256(session) => {
                session.accept_opening_manifest(encoded, &mut self.boundary)
            }
            FixedSession::Export64(session) => {
                session.accept_opening_manifest(encoded, &mut self.boundary)
            }
            FixedSession::Export128(session) => {
                session.accept_opening_manifest(encoded, &mut self.boundary)
            }
            FixedSession::Export256(session) => {
                session.accept_opening_manifest(encoded, &mut self.boundary)
            }
        }
    }

    /// Produces one canonical table frame and pauses until the host returns it.
    pub fn next_table_frame(&mut self) -> Result<WasmTableFrame, WasmBenchmarkError> {
        match &mut self.inner {
            FixedSession::Activation64(session) => session.next_table_frame(&mut self.boundary),
            FixedSession::Activation128(session) => session.next_table_frame(&mut self.boundary),
            FixedSession::Activation256(session) => session.next_table_frame(&mut self.boundary),
            FixedSession::Export64(session) => session.next_table_frame(&mut self.boundary),
            FixedSession::Export128(session) => session.next_table_frame(&mut self.boundary),
            FixedSession::Export256(session) => session.next_table_frame(&mut self.boundary),
        }
    }

    /// Validates and evaluates exactly one host-returned canonical table frame.
    pub fn accept_table_frame(&mut self, encoded: &[u8]) -> Result<(), WasmBenchmarkError> {
        match &mut self.inner {
            FixedSession::Activation64(session) => {
                session.accept_table_frame(encoded, &mut self.boundary)
            }
            FixedSession::Activation128(session) => {
                session.accept_table_frame(encoded, &mut self.boundary)
            }
            FixedSession::Activation256(session) => {
                session.accept_table_frame(encoded, &mut self.boundary)
            }
            FixedSession::Export64(session) => {
                session.accept_table_frame(encoded, &mut self.boundary)
            }
            FixedSession::Export128(session) => {
                session.accept_table_frame(encoded, &mut self.boundary)
            }
            FixedSession::Export256(session) => {
                session.accept_table_frame(encoded, &mut self.boundary)
            }
        }
    }

    /// Confirms that the host closed A's outbound stream body.
    pub fn confirm_outbound_body_closed(&mut self) -> Result<(), WasmBenchmarkError> {
        match &mut self.inner {
            FixedSession::Activation64(session) => session.confirm_outbound_body_closed(),
            FixedSession::Activation128(session) => session.confirm_outbound_body_closed(),
            FixedSession::Activation256(session) => session.confirm_outbound_body_closed(),
            FixedSession::Export64(session) => session.confirm_outbound_body_closed(),
            FixedSession::Export128(session) => session.confirm_outbound_body_closed(),
            FixedSession::Export256(session) => session.confirm_outbound_body_closed(),
        }
    }

    /// Confirms B observed exact body EOF after the final validated frame.
    pub fn confirm_inbound_exact_eof(&mut self) -> Result<(), WasmBenchmarkError> {
        match &mut self.inner {
            FixedSession::Activation64(session) => session.confirm_inbound_exact_eof(),
            FixedSession::Activation128(session) => session.confirm_inbound_exact_eof(),
            FixedSession::Activation256(session) => session.confirm_inbound_exact_eof(),
            FixedSession::Export64(session) => session.confirm_inbound_exact_eof(),
            FixedSession::Export128(session) => session.confirm_inbound_exact_eof(),
            FixedSession::Export256(session) => session.confirm_inbound_exact_eof(),
        }
    }

    /// Consumes a terminal session and returns scalar-only benchmark evidence.
    pub fn finish(self) -> Result<WasmBenchmarkReport, WasmBenchmarkError> {
        match self.inner {
            FixedSession::Activation64(session) => session.finish(self.boundary),
            FixedSession::Activation128(session) => session.finish(self.boundary),
            FixedSession::Activation256(session) => session.finish(self.boundary),
            FixedSession::Export64(session) => session.finish(self.boundary),
            FixedSession::Export128(session) => session.finish(self.boundary),
            FixedSession::Export256(session) => session.finish(self.boundary),
        }
    }
}

impl fmt::Debug for WasmBenchmarkSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmBenchmarkSession")
            .field("state", &"[OPAQUE]")
            .field("boundary", &self.boundary)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(family: WasmBenchmarkFamily, profile: WasmChunkProfile) -> WasmBenchmarkReport {
        let mut session = WasmBenchmarkSession::new(family, profile).expect("fresh session");
        let expected_frames = session.expected_frame_count();
        let expected_body = session.expected_body_bytes();
        let mut manifest = session
            .take_opening_manifest()
            .expect("opening manifest")
            .into_bytes();
        assert_eq!(manifest.len(), STREAM_MANIFEST_BYTES);
        session
            .accept_opening_manifest(&manifest)
            .expect("accepted manifest");
        manifest.zeroize();

        let mut relayed_body_bytes = 0_u64;
        let mut sequence = 0_u32;
        while sequence < expected_frames {
            std::thread::yield_now();
            let frame = session.next_table_frame().expect("next bounded frame");
            assert!(frame.payload_bytes() <= profile.maximum_payload_bytes());
            let mut encoded = frame.into_bytes();
            relayed_body_bytes += u64::try_from(encoded.len()).expect("wire length fits u64");
            std::thread::yield_now();
            session
                .accept_table_frame(&encoded)
                .expect("accepted bounded frame");
            encoded.zeroize();
            sequence += 1;
        }
        assert_eq!(relayed_body_bytes, expected_body);
        session
            .confirm_outbound_body_closed()
            .expect("host confirmed outbound close");
        session
            .confirm_inbound_exact_eof()
            .expect("host confirmed exact inbound EOF");
        session.finish().expect("terminal scalar-only report")
    }

    #[test]
    fn supported_profiles_are_fixed_and_distinct() {
        assert_eq!(WasmChunkProfile::KiB64.maximum_payload_bytes(), 65_536);
        assert_eq!(WasmChunkProfile::KiB128.maximum_payload_bytes(), 131_072);
        assert_eq!(WasmChunkProfile::KiB256.maximum_payload_bytes(), 262_144);
        assert_ne!(WasmBenchmarkFamily::Activation, WasmBenchmarkFamily::Export);
    }

    #[test]
    fn all_family_profile_pairs_are_incremental_and_bounded() {
        let families = [WasmBenchmarkFamily::Activation, WasmBenchmarkFamily::Export];
        let profiles = [
            WasmChunkProfile::KiB64,
            WasmChunkProfile::KiB128,
            WasmChunkProfile::KiB256,
        ];
        for family in families {
            for profile in profiles {
                let report = exercise(family, profile);
                let boundary = report.boundary_metrics();
                assert_eq!(report.family(), family);
                assert_eq!(report.profile(), profile);
                assert_eq!(report.runtime_host_boundary_copy_bytes(), 0);
                assert_eq!(
                    report.runtime_chunk_to_wire_copy_bytes(),
                    report.table_payload_bytes() as u64
                );
                assert_eq!(
                    boundary.runtime_chunk_to_wire_copy_bytes(),
                    report.table_payload_bytes() as u64
                );
                assert_eq!(
                    report.table_buffer_write_bytes(),
                    report.table_payload_bytes()
                );
                assert_eq!(
                    report.and_records_decoded(),
                    report.table_payload_bytes() / super::super::AND_GATE_BYTES
                );
                assert_eq!(boundary.outbound_frame_copy_bytes(), report.body_bytes());
                assert_eq!(boundary.inbound_frame_copy_bytes(), report.body_bytes());
                assert_eq!(boundary.rust_frame_allocations(), report.frame_count());
                assert!(
                    boundary.peak_rust_frame_allocation_bytes()
                        <= profile.maximum_payload_bytes() + TABLE_FRAME_HEADER_BYTES
                );
            }
        }
    }

    #[test]
    fn close_eof_and_frame_return_are_mandatory_state_transitions() {
        let mut early =
            WasmBenchmarkSession::new(WasmBenchmarkFamily::Activation, WasmChunkProfile::KiB64)
                .expect("session");
        assert!(early.confirm_outbound_body_closed().is_err());

        let mut corrupted =
            WasmBenchmarkSession::new(WasmBenchmarkFamily::Export, WasmChunkProfile::KiB64)
                .expect("session");
        let mut manifest = corrupted
            .take_opening_manifest()
            .expect("manifest")
            .into_bytes();
        corrupted
            .accept_opening_manifest(&manifest)
            .expect("manifest accepted");
        manifest.zeroize();
        let mut frame = corrupted
            .next_table_frame()
            .expect("export frame")
            .into_bytes();
        let final_index = frame.len() - 1;
        frame[final_index] ^= 1;
        assert!(corrupted.accept_table_frame(&frame).is_err());
        frame.zeroize();

        let mut missing_eof =
            WasmBenchmarkSession::new(WasmBenchmarkFamily::Export, WasmChunkProfile::KiB64)
                .expect("session");
        assert!(missing_eof.confirm_inbound_exact_eof().is_err());
    }

    #[test]
    fn adapter_source_has_no_blocking_or_whole_body_transport() {
        let sources = [
            include_str!("phase5_wasm_benchmark.rs"),
            include_str!("../../wasm-bench/src/lib.rs"),
            include_str!("../../wasm-bench/scripts/run_phase5_streaming.mjs"),
        ];
        let forbidden = [
            ["std", "io"].join("::"),
            ["array", "Buffer"].join(""),
            [".", "text", "()"].join(""),
            ["base", "64"].join(""),
            ["post", "service", "json"].join("_"),
            ["Router", "relay"].join(" "),
            ["Vec", "<", "Vec", "<", "u8", ">", ">"].join(""),
        ];
        for source in sources {
            for token in &forbidden {
                assert!(!source.contains(token), "forbidden adapter token: {token}");
            }
        }
    }
}
