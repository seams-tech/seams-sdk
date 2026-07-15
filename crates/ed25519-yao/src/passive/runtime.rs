use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::schedule::ScheduleError;
#[cfg(test)]
use super::schedule::{self, GateRecord, ValidatedSchedule};
#[cfg(test)]
use super::{Evaluator, GarbledAndGate, Garbler, AND_GATE_BYTES};
use super::{EvaluatorWire, GarblerWire};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CircuitRunError {
    Schedule(ScheduleError),
    InputCount,
    MissingWire,
    TableLength,
    TableCursor,
    OutputWire,
    OutputCount,
    InvalidOutputLabel,
}

impl From<ScheduleError> for CircuitRunError {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

impl fmt::Display for CircuitRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "passive benchmark circuit run failed: {self:?}")
    }
}

#[cfg(test)]
pub(super) struct GarbledExecution {
    pub(super) tables: Vec<u8>,
    decoder: GarblerOutputDecoder,
}

pub(super) struct EvaluatedExecution {
    pub(super) output_labels: Vec<EvaluatorWire>,
    pub(super) peak_arena_bytes: usize,
}

#[cfg(test)]
pub(super) struct PrivateGarblerOutputs {
    pub(super) returned_decoder: ReturnedOutputDecoder,
    pub(super) evaluator_translation: EvaluatorOutputTranslation,
}

pub(super) struct PrivateEvaluatorOutputs {
    pub(super) returned_labels: ReturnedOutputLabels,
    pub(super) evaluator_labels: EvaluatorOwnedOutputLabels,
    pub(super) peak_arena_bytes: usize,
}

pub(super) struct ReturnedOutputDecoder {
    delta: super::GlobalDelta,
    output_zero_labels: Vec<GarblerWire>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct EvaluatorOutputTranslation {
    bits: Vec<u8>,
    output_count: usize,
}

pub(super) struct ReturnedOutputLabels(Vec<EvaluatorWire>);

pub(super) struct EvaluatorOwnedOutputLabels(Vec<EvaluatorWire>);

#[cfg(test)]
struct GarblerOutputDecoder {
    delta: super::GlobalDelta,
    output_zero_labels: Vec<GarblerWire>,
}

#[cfg(test)]
impl GarbledExecution {
    pub(super) fn into_private_outputs(
        self,
        returned_output_count: usize,
    ) -> Result<PrivateGarblerOutputs, CircuitRunError> {
        let GarbledExecution { decoder, .. } = self;
        let GarblerOutputDecoder {
            delta,
            output_zero_labels,
        } = decoder;
        let (returned_decoder, evaluator_translation) =
            partition_garbler_outputs(delta, output_zero_labels, returned_output_count)?;
        Ok(PrivateGarblerOutputs {
            returned_decoder,
            evaluator_translation,
        })
    }
}

pub(super) fn partition_garbler_outputs(
    delta: super::GlobalDelta,
    mut output_zero_labels: Vec<GarblerWire>,
    returned_output_count: usize,
) -> Result<(ReturnedOutputDecoder, EvaluatorOutputTranslation), CircuitRunError> {
    if returned_output_count == 0
        || returned_output_count >= output_zero_labels.len()
        || !returned_output_count.is_multiple_of(8)
        || !output_zero_labels.len().is_multiple_of(8)
    {
        return Err(CircuitRunError::OutputCount);
    }
    let evaluator_zero_labels = output_zero_labels.split_off(returned_output_count);
    let evaluator_translation =
        EvaluatorOutputTranslation::from_zero_labels(&evaluator_zero_labels);
    Ok((
        ReturnedOutputDecoder {
            delta,
            output_zero_labels,
        },
        evaluator_translation,
    ))
}

impl EvaluatedExecution {
    pub(super) fn into_private_outputs(
        self,
        returned_output_count: usize,
    ) -> Result<PrivateEvaluatorOutputs, CircuitRunError> {
        let EvaluatedExecution {
            mut output_labels,
            peak_arena_bytes,
        } = self;
        if returned_output_count == 0
            || returned_output_count >= output_labels.len()
            || !returned_output_count.is_multiple_of(8)
            || !output_labels.len().is_multiple_of(8)
        {
            return Err(CircuitRunError::OutputCount);
        }
        let evaluator_labels = output_labels.split_off(returned_output_count);
        Ok(PrivateEvaluatorOutputs {
            returned_labels: ReturnedOutputLabels(output_labels),
            evaluator_labels: EvaluatorOwnedOutputLabels(evaluator_labels),
            peak_arena_bytes,
        })
    }
}

impl ReturnedOutputDecoder {
    pub(super) fn decode(self, labels: ReturnedOutputLabels) -> Result<Vec<u8>, CircuitRunError> {
        decode_output_labels(&self.delta, &self.output_zero_labels, &labels.0)
    }
}

impl EvaluatorOutputTranslation {
    fn from_zero_labels(zero_labels: &[GarblerWire]) -> Self {
        let mut bits = vec![0_u8; zero_labels.len().div_ceil(8)];
        let mut index = 0_usize;
        while index < zero_labels.len() {
            bits[index / 8] |= zero_labels[index].zero.selection_bit().0 << (index % 8);
            index += 1;
        }
        Self {
            bits,
            output_count: zero_labels.len(),
        }
    }

    #[cfg(any(
        test,
        feature = "passive-benchmark",
        feature = "phase9-role-benchmark",
        feature = "local-protocol"
    ))]
    pub(super) fn encoded_bits(&self) -> &[u8] {
        &self.bits
    }

    #[cfg(any(
        test,
        feature = "passive-benchmark",
        feature = "phase9-role-benchmark",
        feature = "local-protocol"
    ))]
    pub(super) fn from_encoded_bits(
        bits: Vec<u8>,
        output_count: usize,
    ) -> Result<Self, CircuitRunError> {
        if output_count == 0 || !output_count.is_multiple_of(8) || bits.len() != output_count / 8 {
            return Err(CircuitRunError::OutputCount);
        }
        Ok(Self { bits, output_count })
    }

    pub(super) fn decode(
        self,
        labels: EvaluatorOwnedOutputLabels,
    ) -> Result<Vec<u8>, CircuitRunError> {
        if labels.0.len() != self.output_count || !self.output_count.is_multiple_of(8) {
            return Err(CircuitRunError::OutputCount);
        }
        let mut decoded = vec![0_u8; self.output_count / 8];
        let mut index = 0_usize;
        while index < self.output_count {
            let semantic = labels.0[index].active.selection_bit().0
                ^ ((self.bits[index / 8] >> (index % 8)) & 1);
            decoded[index / 8] |= semantic << (index % 8);
            index += 1;
        }
        Ok(decoded)
    }
}

impl ReturnedOutputLabels {
    #[cfg(any(
        test,
        feature = "passive-benchmark",
        feature = "phase9-role-benchmark",
        feature = "local-protocol"
    ))]
    pub(super) fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.0.len() * super::LABEL_BYTES);
        for label in &self.0 {
            label.append_secret_bytes(&mut encoded);
        }
        encoded
    }

    #[cfg(any(
        test,
        feature = "passive-benchmark",
        feature = "phase9-role-benchmark",
        feature = "local-protocol"
    ))]
    pub(super) fn decode(encoded: &[u8], output_count: usize) -> Result<Self, CircuitRunError> {
        let expected = output_count
            .checked_mul(super::LABEL_BYTES)
            .ok_or(CircuitRunError::OutputCount)?;
        if output_count == 0 || encoded.len() != expected {
            return Err(CircuitRunError::OutputCount);
        }
        let mut labels = Vec::with_capacity(output_count);
        for bytes in encoded.chunks_exact(super::LABEL_BYTES) {
            let active = bytes.try_into().map_err(|_| CircuitRunError::OutputCount)?;
            labels.push(EvaluatorWire::from_secret_bytes(active));
        }
        Ok(Self(labels))
    }
}

pub(super) fn decode_output_labels(
    delta: &super::GlobalDelta,
    output_zero_labels: &[GarblerWire],
    output_labels: &[EvaluatorWire],
) -> Result<Vec<u8>, CircuitRunError> {
    if output_zero_labels.len() != output_labels.len()
        || !output_zero_labels.len().is_multiple_of(8)
    {
        return Err(CircuitRunError::OutputCount);
    }
    let mut decoded = vec![0_u8; output_zero_labels.len() / 8];
    let mut invalid = 0_u8;
    let mut index = 0_usize;
    while index < output_zero_labels.len() {
        let zero = &output_zero_labels[index].zero;
        let one = zero.xor(delta.label());
        let active = &output_labels[index].active;
        let is_zero = labels_equal(active, zero);
        let is_one = labels_equal(active, &one);
        invalid |= (is_zero.0 | is_one.0) ^ 1;
        decoded[index / 8] |= is_one.0 << (index % 8);
        index += 1;
    }
    if invalid == 0 {
        Ok(decoded)
    } else {
        Err(CircuitRunError::InvalidOutputLabel)
    }
}

#[cfg(test)]
impl Garbler {
    pub(super) fn garble_phase4_activation(
        self,
        inputs: Vec<GarblerWire>,
    ) -> Result<GarbledExecution, CircuitRunError> {
        garble_fixed(self, schedule::phase4_activation()?, inputs)
    }

    pub(super) fn garble_phase4_export(
        self,
        inputs: Vec<GarblerWire>,
    ) -> Result<GarbledExecution, CircuitRunError> {
        garble_fixed(self, schedule::phase4_export()?, inputs)
    }
}

#[cfg(test)]
impl Evaluator {
    pub(super) fn evaluate_phase4_activation(
        self,
        inputs: Vec<EvaluatorWire>,
        tables: &[u8],
    ) -> Result<EvaluatedExecution, CircuitRunError> {
        evaluate_fixed(self, schedule::phase4_activation()?, inputs, tables)
    }

    pub(super) fn evaluate_phase4_export(
        self,
        inputs: Vec<EvaluatorWire>,
        tables: &[u8],
    ) -> Result<EvaluatedExecution, CircuitRunError> {
        evaluate_fixed(self, schedule::phase4_export()?, inputs, tables)
    }
}

#[cfg(test)]
fn garble_fixed(
    garbler: Garbler,
    schedule: &ValidatedSchedule<'_>,
    inputs: Vec<GarblerWire>,
) -> Result<GarbledExecution, CircuitRunError> {
    if inputs.len() != schedule.input_count() {
        return Err(CircuitRunError::InputCount);
    }
    let mut arena = empty_arena(schedule.slot_count());
    install_inputs(&mut arena, inputs);
    let table_bytes = schedule
        .and_count()
        .checked_mul(AND_GATE_BYTES)
        .ok_or(CircuitRunError::TableLength)?;
    let mut tables = Vec::with_capacity(table_bytes);

    for gate in schedule.gates() {
        match gate {
            GateRecord::Xor {
                left,
                right,
                output,
            } => {
                let wire = {
                    let left_wire = required_wire(&arena, left)?;
                    let right_wire = required_wire(&arena, right)?;
                    garbler.xor(left_wire, right_wire)
                };
                arena[output] = Some(wire);
            }
            GateRecord::And {
                ordinal,
                left,
                right,
                output,
            } => {
                let (wire, table) = {
                    let left_wire = required_wire(&arena, left)?;
                    let right_wire = required_wire(&arena, right)?;
                    garbler.garble_and(ordinal, left_wire, right_wire)
                };
                tables.extend_from_slice(&table.encode());
                arena[output] = Some(wire);
            }
            GateRecord::Invert { input, output } => {
                let wire = {
                    let input_wire = required_wire(&arena, input)?;
                    garbler.invert(input_wire)
                };
                arena[output] = Some(wire);
            }
        }
    }
    if tables.len() != table_bytes {
        return Err(CircuitRunError::TableCursor);
    }
    let output_zero_labels = take_outputs(&mut arena, schedule.output_slots())?;
    Ok(GarbledExecution {
        tables,
        decoder: GarblerOutputDecoder {
            delta: garbler.delta,
            output_zero_labels,
        },
    })
}

#[cfg(test)]
fn evaluate_fixed(
    evaluator: Evaluator,
    schedule: &ValidatedSchedule<'_>,
    inputs: Vec<EvaluatorWire>,
    tables: &[u8],
) -> Result<EvaluatedExecution, CircuitRunError> {
    if inputs.len() != schedule.input_count() {
        return Err(CircuitRunError::InputCount);
    }
    let expected_table_bytes = schedule
        .and_count()
        .checked_mul(AND_GATE_BYTES)
        .ok_or(CircuitRunError::TableLength)?;
    if tables.len() != expected_table_bytes {
        return Err(CircuitRunError::TableLength);
    }

    let mut arena = empty_arena(schedule.slot_count());
    install_inputs(&mut arena, inputs);
    let mut table_cursor = 0_usize;
    for gate in schedule.gates() {
        match gate {
            GateRecord::Xor {
                left,
                right,
                output,
            } => {
                let wire = {
                    let left_wire = required_wire(&arena, left)?;
                    let right_wire = required_wire(&arena, right)?;
                    evaluator.xor(left_wire, right_wire)
                };
                arena[output] = Some(wire);
            }
            GateRecord::And {
                ordinal,
                left,
                right,
                output,
            } => {
                let table_end = table_cursor
                    .checked_add(AND_GATE_BYTES)
                    .ok_or(CircuitRunError::TableCursor)?;
                let encoded: &[u8; AND_GATE_BYTES] = tables[table_cursor..table_end]
                    .try_into()
                    .map_err(|_| CircuitRunError::TableCursor)?;
                let table = GarbledAndGate::decode(encoded);
                let wire = {
                    let left_wire = required_wire(&arena, left)?;
                    let right_wire = required_wire(&arena, right)?;
                    evaluator.evaluate_and(ordinal, left_wire, right_wire, &table)
                };
                arena[output] = Some(wire);
                table_cursor = table_end;
            }
            GateRecord::Invert { input, output } => {
                let wire = {
                    let input_wire = required_wire(&arena, input)?;
                    evaluator.invert(input_wire)
                };
                arena[output] = Some(wire);
            }
        }
    }
    if table_cursor != tables.len() {
        return Err(CircuitRunError::TableCursor);
    }
    let peak_arena_bytes = arena
        .capacity()
        .checked_mul(size_of::<Option<EvaluatorWire>>())
        .ok_or(CircuitRunError::TableLength)?;
    let output_labels = take_outputs(&mut arena, schedule.output_slots())?;
    Ok(EvaluatedExecution {
        output_labels,
        peak_arena_bytes,
    })
}

pub(super) fn empty_arena<T>(length: usize) -> Vec<Option<T>> {
    let mut arena = Vec::with_capacity(length);
    let mut index = 0_usize;
    while index < length {
        arena.push(None);
        index += 1;
    }
    arena
}

pub(super) fn install_inputs<T>(arena: &mut [Option<T>], inputs: Vec<T>) {
    for (slot, input) in inputs.into_iter().enumerate() {
        arena[slot] = Some(input);
    }
}

pub(super) fn required_wire<T>(arena: &[Option<T>], slot: usize) -> Result<&T, CircuitRunError> {
    arena[slot].as_ref().ok_or(CircuitRunError::MissingWire)
}

pub(super) fn take_outputs<T>(
    arena: &mut [Option<T>],
    output_slots: impl ExactSizeIterator<Item = usize>,
) -> Result<Vec<T>, CircuitRunError> {
    let mut outputs = Vec::with_capacity(output_slots.len());
    for slot in output_slots {
        outputs.push(arena[slot].take().ok_or(CircuitRunError::OutputWire)?);
    }
    Ok(outputs)
}

fn labels_equal(left: &super::WireLabel, right: &super::WireLabel) -> super::ChoiceBit {
    let mut difference = 0_u8;
    let mut index = 0_usize;
    while index < super::LABEL_BYTES {
        difference |= left.0[index] ^ right.0[index];
        index += 1;
    }
    let nonzero = (difference | difference.wrapping_neg()) >> 7;
    super::ChoiceBit(nonzero ^ 1)
}
