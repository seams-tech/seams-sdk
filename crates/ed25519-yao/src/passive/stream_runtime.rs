//! Resumable bounded-memory execution for the fixed passive Phase 4 circuits.

#![allow(dead_code)]

use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;

use zeroize::{Zeroize, Zeroizing};

use super::runtime::{
    empty_arena, install_inputs, partition_garbler_outputs, required_wire, take_outputs,
    CircuitRunError, EvaluatedExecution, EvaluatorOutputTranslation, EvaluatorOwnedOutputLabels,
    PrivateEvaluatorOutputs, ReturnedOutputDecoder, ReturnedOutputLabels,
};
use super::schedule::{self, GateRecord, ValidatedSchedule};
use super::stream::{
    ActivationStream, ExactTableStreamReceipt, ExportStream, FixedChunkProfile, FixedStreamFamily,
    ValidatedTableFrame,
};
use super::{Evaluator, EvaluatorWire, GarbledAndGate, Garbler, GarblerWire, AND_GATE_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamRuntimeError {
    Circuit(CircuitRunError),
    FrameOrdinal,
    FrameRecordCount,
    UnexpectedEndOfTables,
    ReceiptMismatch,
}

impl From<CircuitRunError> for StreamRuntimeError {
    fn from(error: CircuitRunError) -> Self {
        Self::Circuit(error)
    }
}

impl fmt::Display for StreamRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded passive circuit run failed: {self:?}")
    }
}

pub(super) struct StreamedPrivateGarblerOutputs<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) returned_decoder: ReturnedOutputDecoder,
    pub(super) evaluator_translation: EvaluatorOutputTranslation,
    pub(super) receipt: ExactTableStreamReceipt<F, C>,
    pub(super) peak_arena_bytes: usize,
    pub(super) peak_table_buffer_bytes: usize,
    pub(super) table_bytes: usize,
    pub(super) frame_calls: u32,
    pub(super) host_boundary_copy_bytes: usize,
    pub(super) table_buffer_write_bytes: usize,
}

pub(super) struct StreamedPrivateEvaluatorOutputs<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) returned_labels: ReturnedOutputLabels,
    pub(super) evaluator_labels: EvaluatorOwnedOutputLabels,
    pub(super) receipt: ExactTableStreamReceipt<F, C>,
    pub(super) peak_arena_bytes: usize,
    pub(super) peak_table_buffer_bytes: usize,
    pub(super) table_bytes: usize,
    pub(super) frame_calls: u32,
    pub(super) host_boundary_copy_bytes: usize,
    pub(super) and_records_decoded: usize,
}

pub(super) struct GarblerMachine<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    garbler: Garbler,
    schedule: &'static ValidatedSchedule<'static>,
    arena: Vec<Option<GarblerWire>>,
    gate_index: usize,
    returned_output_count: usize,
    table_chunk: Zeroizing<Vec<u8>>,
    table_bytes: usize,
    frame_calls: u32,
    table_buffer_write_bytes: usize,
    marker: PhantomData<(F, C)>,
}

// Keeping the continuation inline avoids one heap allocation at every frame boundary.
#[allow(clippy::large_enum_variant)]
pub(super) enum GarblerAdvance<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    ChunkReady(GarblerChunk<F, C>),
    BodyComplete(GarblerBodyComplete<F, C>),
}

pub(super) struct GarblerChunk<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    machine: GarblerMachine<F, C>,
}

pub(super) struct GarblerBodyComplete<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    returned_decoder: ReturnedOutputDecoder,
    evaluator_translation: EvaluatorOutputTranslation,
    peak_arena_bytes: usize,
    peak_table_buffer_bytes: usize,
    table_bytes: usize,
    frame_calls: u32,
    table_buffer_write_bytes: usize,
    marker: PhantomData<(F, C)>,
}

pub(super) fn activation_garbler_machine<C: FixedChunkProfile>(
    garbler: Garbler,
    inputs: Vec<GarblerWire>,
    returned_output_count: usize,
) -> Result<GarblerMachine<ActivationStream, C>, StreamRuntimeError> {
    GarblerMachine::new(
        garbler,
        schedule::phase4_activation().map_err(CircuitRunError::from)?,
        inputs,
        returned_output_count,
    )
}

pub(super) fn export_garbler_machine<C: FixedChunkProfile>(
    garbler: Garbler,
    inputs: Vec<GarblerWire>,
    returned_output_count: usize,
) -> Result<GarblerMachine<ExportStream, C>, StreamRuntimeError> {
    GarblerMachine::new(
        garbler,
        schedule::phase4_export().map_err(CircuitRunError::from)?,
        inputs,
        returned_output_count,
    )
}

impl<F, C> GarblerMachine<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn new(
        garbler: Garbler,
        schedule: &'static ValidatedSchedule<'static>,
        inputs: Vec<GarblerWire>,
        returned_output_count: usize,
    ) -> Result<Self, StreamRuntimeError> {
        if inputs.len() != schedule.input_count()
            || schedule.and_count().checked_mul(AND_GATE_BYTES) != Some(F::TABLE_PAYLOAD_BYTES)
        {
            return Err(CircuitRunError::InputCount.into());
        }
        let mut arena = empty_arena(schedule.slot_count());
        install_inputs(&mut arena, inputs);
        let chunk_bytes = core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES);
        Ok(Self {
            garbler,
            schedule,
            arena,
            gate_index: 0,
            returned_output_count,
            table_chunk: Zeroizing::new(Vec::with_capacity(chunk_bytes)),
            table_bytes: 0,
            frame_calls: 0,
            table_buffer_write_bytes: 0,
            marker: PhantomData,
        })
    }

    pub(super) fn advance(mut self) -> Result<GarblerAdvance<F, C>, StreamRuntimeError> {
        while self.gate_index < self.schedule.gate_count() {
            let gate = self
                .schedule
                .gate(self.gate_index)
                .ok_or(CircuitRunError::TableCursor)?;
            self.gate_index += 1;
            match gate {
                GateRecord::Xor {
                    left,
                    right,
                    output,
                } => {
                    let wire = self.garbler.xor(
                        required_wire(&self.arena, left)?,
                        required_wire(&self.arena, right)?,
                    );
                    self.arena[output] = Some(wire);
                }
                GateRecord::And {
                    ordinal,
                    left,
                    right,
                    output,
                } => {
                    let (wire, table) = self.garbler.garble_and(
                        ordinal,
                        required_wire(&self.arena, left)?,
                        required_wire(&self.arena, right)?,
                    );
                    table.append_encoded(&mut self.table_chunk);
                    self.table_bytes = self
                        .table_bytes
                        .checked_add(AND_GATE_BYTES)
                        .ok_or(CircuitRunError::TableLength)?;
                    self.table_buffer_write_bytes = self
                        .table_buffer_write_bytes
                        .checked_add(AND_GATE_BYTES)
                        .ok_or(CircuitRunError::TableLength)?;
                    self.arena[output] = Some(wire);
                    if self.table_chunk.len() == C::MAX_PAYLOAD_BYTES {
                        self.frame_calls = self
                            .frame_calls
                            .checked_add(1)
                            .ok_or(CircuitRunError::TableLength)?;
                        return Ok(GarblerAdvance::ChunkReady(GarblerChunk { machine: self }));
                    }
                }
                GateRecord::Invert { input, output } => {
                    let wire = self.garbler.invert(required_wire(&self.arena, input)?);
                    self.arena[output] = Some(wire);
                }
            }
        }

        if !self.table_chunk.is_empty() {
            self.frame_calls = self
                .frame_calls
                .checked_add(1)
                .ok_or(CircuitRunError::TableLength)?;
            return Ok(GarblerAdvance::ChunkReady(GarblerChunk { machine: self }));
        }
        if self.table_bytes != F::TABLE_PAYLOAD_BYTES {
            return Err(CircuitRunError::TableCursor.into());
        }

        let peak_arena_bytes = self
            .arena
            .capacity()
            .checked_mul(size_of::<Option<GarblerWire>>())
            .ok_or(CircuitRunError::TableLength)?;
        let output_zero_labels = take_outputs(&mut self.arena, self.schedule.output_slots())?;
        let (returned_decoder, evaluator_translation) = partition_garbler_outputs(
            self.garbler.delta,
            output_zero_labels,
            self.returned_output_count,
        )?;
        Ok(GarblerAdvance::BodyComplete(GarblerBodyComplete {
            returned_decoder,
            evaluator_translation,
            peak_arena_bytes,
            peak_table_buffer_bytes: self.table_chunk.capacity(),
            table_bytes: self.table_bytes,
            frame_calls: self.frame_calls,
            table_buffer_write_bytes: self.table_buffer_write_bytes,
            marker: PhantomData,
        }))
    }
}

impl<F, C> GarblerChunk<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) fn payload(&self) -> &[u8] {
        self.machine.table_chunk.as_slice()
    }

    pub(super) fn resume(mut self) -> GarblerMachine<F, C> {
        self.machine.table_chunk.as_mut_slice().zeroize();
        self.machine.table_chunk.clear();
        self.machine
    }
}

impl<F, C> GarblerBodyComplete<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) fn finalize(
        self,
        receipt: ExactTableStreamReceipt<F, C>,
    ) -> Result<StreamedPrivateGarblerOutputs<F, C>, StreamRuntimeError> {
        validate_receipt::<F, C>(&receipt)?;
        if self.frame_calls != receipt.frame_count()
            || self.table_bytes != F::TABLE_PAYLOAD_BYTES
            || self.table_buffer_write_bytes != self.table_bytes
        {
            return Err(StreamRuntimeError::ReceiptMismatch);
        }
        Ok(StreamedPrivateGarblerOutputs {
            returned_decoder: self.returned_decoder,
            evaluator_translation: self.evaluator_translation,
            receipt,
            peak_arena_bytes: self.peak_arena_bytes,
            peak_table_buffer_bytes: self.peak_table_buffer_bytes,
            table_bytes: self.table_bytes,
            frame_calls: self.frame_calls,
            host_boundary_copy_bytes: 0,
            table_buffer_write_bytes: self.table_buffer_write_bytes,
        })
    }
}

pub(super) struct EvaluatorMachine<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    evaluator: Evaluator,
    schedule: &'static ValidatedSchedule<'static>,
    arena: Vec<Option<EvaluatorWire>>,
    gate_index: usize,
    returned_output_count: usize,
    frame_calls: u32,
    and_records_decoded: usize,
    peak_table_buffer_bytes: usize,
    marker: PhantomData<(F, C)>,
}

// Keeping the continuation inline avoids one heap allocation at every frame boundary.
#[allow(clippy::large_enum_variant)]
pub(super) enum EvaluatorAdvance<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    NeedsFrame(EvaluatorNeedsFrame<F, C>),
    AwaitingExactEof(EvaluatorBodyComplete<F, C>),
}

pub(super) struct EvaluatorNeedsFrame<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    machine: EvaluatorMachine<F, C>,
}

pub(super) struct EvaluatorBodyComplete<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    returned_labels: ReturnedOutputLabels,
    evaluator_labels: EvaluatorOwnedOutputLabels,
    peak_arena_bytes: usize,
    peak_table_buffer_bytes: usize,
    table_bytes: usize,
    frame_calls: u32,
    and_records_decoded: usize,
    marker: PhantomData<(F, C)>,
}

pub(super) fn activation_evaluator_machine<C: FixedChunkProfile>(
    evaluator: Evaluator,
    inputs: Vec<EvaluatorWire>,
    returned_output_count: usize,
) -> Result<EvaluatorMachine<ActivationStream, C>, StreamRuntimeError> {
    EvaluatorMachine::new(
        evaluator,
        schedule::phase4_activation().map_err(CircuitRunError::from)?,
        inputs,
        returned_output_count,
    )
}

pub(super) fn export_evaluator_machine<C: FixedChunkProfile>(
    evaluator: Evaluator,
    inputs: Vec<EvaluatorWire>,
    returned_output_count: usize,
) -> Result<EvaluatorMachine<ExportStream, C>, StreamRuntimeError> {
    EvaluatorMachine::new(
        evaluator,
        schedule::phase4_export().map_err(CircuitRunError::from)?,
        inputs,
        returned_output_count,
    )
}

impl<F, C> EvaluatorMachine<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn new(
        evaluator: Evaluator,
        schedule: &'static ValidatedSchedule<'static>,
        inputs: Vec<EvaluatorWire>,
        returned_output_count: usize,
    ) -> Result<Self, StreamRuntimeError> {
        if inputs.len() != schedule.input_count()
            || schedule.and_count().checked_mul(AND_GATE_BYTES) != Some(F::TABLE_PAYLOAD_BYTES)
        {
            return Err(CircuitRunError::InputCount.into());
        }
        let mut arena = empty_arena(schedule.slot_count());
        install_inputs(&mut arena, inputs);
        Ok(Self {
            evaluator,
            schedule,
            arena,
            gate_index: 0,
            returned_output_count,
            frame_calls: 0,
            and_records_decoded: 0,
            peak_table_buffer_bytes: 0,
            marker: PhantomData,
        })
    }

    pub(super) fn advance(mut self) -> Result<EvaluatorAdvance<F, C>, StreamRuntimeError> {
        if self.process_non_and_gates()?.is_some() {
            return Ok(EvaluatorAdvance::NeedsFrame(EvaluatorNeedsFrame {
                machine: self,
            }));
        }
        if self.and_records_decoded != self.schedule.and_count() {
            return Err(StreamRuntimeError::UnexpectedEndOfTables);
        }
        let measured_peak_arena_bytes = self
            .arena
            .capacity()
            .checked_mul(size_of::<Option<EvaluatorWire>>())
            .ok_or(CircuitRunError::TableLength)?;
        let output_labels = take_outputs(&mut self.arena, self.schedule.output_slots())?;
        let PrivateEvaluatorOutputs {
            returned_labels,
            evaluator_labels,
            peak_arena_bytes,
        } = EvaluatedExecution {
            output_labels,
            peak_arena_bytes: measured_peak_arena_bytes,
        }
        .into_private_outputs(self.returned_output_count)?;
        if peak_arena_bytes != measured_peak_arena_bytes {
            return Err(CircuitRunError::TableLength.into());
        }
        Ok(EvaluatorAdvance::AwaitingExactEof(EvaluatorBodyComplete {
            returned_labels,
            evaluator_labels,
            peak_arena_bytes,
            peak_table_buffer_bytes: self.peak_table_buffer_bytes,
            table_bytes: self
                .and_records_decoded
                .checked_mul(AND_GATE_BYTES)
                .ok_or(CircuitRunError::TableLength)?,
            frame_calls: self.frame_calls,
            and_records_decoded: self.and_records_decoded,
            marker: PhantomData,
        }))
    }

    fn process_non_and_gates(&mut self) -> Result<Option<GateRecord>, StreamRuntimeError> {
        while self.gate_index < self.schedule.gate_count() {
            let gate = self
                .schedule
                .gate(self.gate_index)
                .ok_or(CircuitRunError::TableCursor)?;
            match gate {
                GateRecord::Xor {
                    left,
                    right,
                    output,
                } => {
                    let wire = self.evaluator.xor(
                        required_wire(&self.arena, left)?,
                        required_wire(&self.arena, right)?,
                    );
                    self.arena[output] = Some(wire);
                    self.gate_index += 1;
                }
                GateRecord::Invert { input, output } => {
                    let wire = self.evaluator.invert(required_wire(&self.arena, input)?);
                    self.arena[output] = Some(wire);
                    self.gate_index += 1;
                }
                GateRecord::And { .. } => return Ok(Some(gate)),
            }
        }
        Ok(None)
    }
}

impl<F, C> EvaluatorNeedsFrame<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) fn accept_frame(
        mut self,
        frame: ValidatedTableFrame<'_, F, C>,
    ) -> Result<EvaluatorMachine<F, C>, StreamRuntimeError> {
        let expected_start = u32::try_from(self.machine.and_records_decoded)
            .map_err(|_| StreamRuntimeError::FrameOrdinal)?;
        if frame.and_table_ordinal_start() != expected_start
            || frame.payload().len()
                != usize::try_from(frame.and_table_record_count())
                    .ok()
                    .and_then(|count| count.checked_mul(AND_GATE_BYTES))
                    .ok_or(StreamRuntimeError::FrameRecordCount)?
        {
            return Err(StreamRuntimeError::FrameRecordCount);
        }

        for encoded in frame.payload().chunks_exact(AND_GATE_BYTES) {
            let gate = self
                .machine
                .process_non_and_gates()?
                .ok_or(StreamRuntimeError::UnexpectedEndOfTables)?;
            let GateRecord::And {
                ordinal,
                left,
                right,
                output,
            } = gate
            else {
                return Err(StreamRuntimeError::UnexpectedEndOfTables);
            };
            let encoded: &[u8; AND_GATE_BYTES] = encoded
                .try_into()
                .map_err(|_| StreamRuntimeError::FrameRecordCount)?;
            let table = GarbledAndGate::decode(encoded);
            let wire = self.machine.evaluator.evaluate_and(
                ordinal,
                required_wire(&self.machine.arena, left)?,
                required_wire(&self.machine.arena, right)?,
                &table,
            );
            self.machine.arena[output] = Some(wire);
            self.machine.gate_index += 1;
            self.machine.and_records_decoded = self
                .machine
                .and_records_decoded
                .checked_add(1)
                .ok_or(CircuitRunError::TableLength)?;
        }
        self.machine.frame_calls = self
            .machine
            .frame_calls
            .checked_add(1)
            .ok_or(CircuitRunError::TableLength)?;
        self.machine.peak_table_buffer_bytes = self
            .machine
            .peak_table_buffer_bytes
            .max(frame.payload().len());
        Ok(self.machine)
    }
}

impl<F, C> EvaluatorBodyComplete<F, C>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) fn finalize(
        self,
        receipt: ExactTableStreamReceipt<F, C>,
    ) -> Result<StreamedPrivateEvaluatorOutputs<F, C>, StreamRuntimeError> {
        validate_receipt::<F, C>(&receipt)?;
        if self.frame_calls != receipt.frame_count()
            || self.table_bytes != F::TABLE_PAYLOAD_BYTES
            || self.and_records_decoded
                != usize::try_from(F::AND_GATE_COUNT)
                    .map_err(|_| StreamRuntimeError::ReceiptMismatch)?
        {
            return Err(StreamRuntimeError::ReceiptMismatch);
        }
        Ok(StreamedPrivateEvaluatorOutputs {
            returned_labels: self.returned_labels,
            evaluator_labels: self.evaluator_labels,
            receipt,
            peak_arena_bytes: self.peak_arena_bytes,
            peak_table_buffer_bytes: self.peak_table_buffer_bytes,
            table_bytes: self.table_bytes,
            frame_calls: self.frame_calls,
            host_boundary_copy_bytes: 0,
            and_records_decoded: self.and_records_decoded,
        })
    }
}

fn validate_receipt<F, C>(receipt: &ExactTableStreamReceipt<F, C>) -> Result<(), StreamRuntimeError>
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    let expected_frames = F::TABLE_PAYLOAD_BYTES.div_ceil(C::MAX_PAYLOAD_BYTES);
    let expected_body_bytes = expected_frames
        .checked_mul(super::stream::TABLE_FRAME_HEADER_BYTES)
        .and_then(|headers| F::TABLE_PAYLOAD_BYTES.checked_add(headers))
        .ok_or(StreamRuntimeError::ReceiptMismatch)?;
    if usize::try_from(receipt.frame_count()) != Ok(expected_frames)
        || usize::try_from(receipt.body_bytes()) != Ok(expected_body_bytes)
    {
        return Err(StreamRuntimeError::ReceiptMismatch);
    }
    Ok(())
}
