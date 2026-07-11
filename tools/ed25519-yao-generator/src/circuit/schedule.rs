use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::ir::{CanonicalBooleanCircuitV1, Gate, WireId};

const SCHEDULE_MAGIC_V1: &[u8; 8] = b"EYAOSC01";
const SCHEDULE_HEADER_LEN_V1: usize = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduledGateKindV1 {
    Xor,
    And,
    Inv,
}

impl ScheduledGateKindV1 {
    const fn opcode(self) -> u8 {
        match self {
            Self::Xor => 1,
            Self::And => 2,
            Self::Inv => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledGateV1 {
    kind: ScheduledGateKindV1,
    left_slot: u32,
    right_slot: u32,
    output_slot: u32,
}

struct ScheduleEncodingInputsV1<'a> {
    component: u8,
    circuit_digest: [u8; 32],
    input_count: u32,
    output_count: u32,
    slot_count: u32,
    slot_width: u8,
    gates: &'a [ScheduledGateV1],
    output_slots: &'a [u32],
}

/// Metrics derived from a canonical provisional liveness schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalScheduleMetricsV1 {
    input_wire_count: u64,
    output_wire_count: u64,
    scheduled_gate_count: u64,
    reusable_slot_count: u64,
    slot_width_bytes: u8,
    gate_record_width_bytes: u8,
    encoded_schedule_bytes: u64,
}

impl ProvisionalScheduleMetricsV1 {
    /// Number of circuit input wires loaded into initial slots.
    pub const fn input_wire_count(self) -> u64 {
        self.input_wire_count
    }

    /// Number of pinned output-slot references.
    pub const fn output_wire_count(self) -> u64 {
        self.output_wire_count
    }

    /// Number of scheduled canonical gates.
    pub const fn scheduled_gate_count(self) -> u64 {
        self.scheduled_gate_count
    }

    /// Number of reusable evaluator slots required by the schedule.
    pub const fn reusable_slot_count(self) -> u64 {
        self.reusable_slot_count
    }

    /// Fixed encoded width of each slot identifier.
    pub const fn slot_width_bytes(self) -> u8 {
        self.slot_width_bytes
    }

    /// Fixed encoded width of each scheduled gate record.
    pub const fn gate_record_width_bytes(self) -> u8 {
        self.gate_record_width_bytes
    }

    /// Exact byte length of the canonical schedule encoding.
    pub const fn encoded_schedule_bytes(self) -> u64 {
        self.encoded_schedule_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScheduleBuildErrorV1 {
    CountOverflow,
    MissingOperandSlot,
    DuplicateFreeSlot,
    MissingOutputSlot,
    SlotWidthOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScheduleEvalErrorV1 {
    InputCountMismatch { expected: u32, actual: usize },
}

pub(super) struct CanonicalLivenessScheduleV1 {
    input_count: u32,
    gates: Vec<ScheduledGateV1>,
    output_slots: Vec<u32>,
    metrics: ProvisionalScheduleMetricsV1,
    canonical_encoding: Vec<u8>,
    digest: [u8; 32],
}

impl CanonicalLivenessScheduleV1 {
    pub(super) fn derive(circuit: &CanonicalBooleanCircuitV1) -> Self {
        derive_schedule(circuit).expect("canonical circuit has a valid liveness schedule")
    }

    pub(super) const fn metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.metrics
    }

    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn canonical_encoding(&self) -> &[u8] {
        &self.canonical_encoding
    }

    pub(super) fn evaluate(&self, inputs: &[bool]) -> Result<Vec<bool>, ScheduleEvalErrorV1> {
        if inputs.len() != self.input_count as usize {
            return Err(ScheduleEvalErrorV1::InputCountMismatch {
                expected: self.input_count,
                actual: inputs.len(),
            });
        }

        let mut slots = vec![false; self.metrics.reusable_slot_count as usize];
        slots[..inputs.len()].copy_from_slice(inputs);
        for gate in &self.gates {
            let left = slots[gate.left_slot as usize];
            let right = slots[gate.right_slot as usize];
            let output = match gate.kind {
                ScheduledGateKindV1::Xor => left ^ right,
                ScheduledGateKindV1::And => left & right,
                ScheduledGateKindV1::Inv => !left,
            };
            slots[gate.output_slot as usize] = output;
        }

        let mut outputs = Vec::with_capacity(self.output_slots.len());
        for slot in &self.output_slots {
            outputs.push(slots[*slot as usize]);
        }
        Ok(outputs)
    }

    #[cfg(test)]
    pub(super) fn records(&self) -> impl Iterator<Item = (u8, u32, u32, u32)> + '_ {
        self.gates.iter().map(|gate| {
            (
                gate.kind.opcode(),
                gate.left_slot,
                gate.right_slot,
                gate.output_slot,
            )
        })
    }

    #[cfg(test)]
    pub(super) fn output_slots(&self) -> &[u32] {
        &self.output_slots
    }
}

fn derive_schedule(
    circuit: &CanonicalBooleanCircuitV1,
) -> Result<CanonicalLivenessScheduleV1, ScheduleBuildErrorV1> {
    let input_count = circuit.input_count();
    let gate_count =
        u32::try_from(circuit.gates().len()).map_err(|_| ScheduleBuildErrorV1::CountOverflow)?;
    let output_count =
        u32::try_from(circuit.outputs().len()).map_err(|_| ScheduleBuildErrorV1::CountOverflow)?;
    let wire_count = input_count
        .checked_add(gate_count)
        .ok_or(ScheduleBuildErrorV1::CountOverflow)?;
    let last_uses = derive_last_uses(circuit, wire_count as usize);

    let mut wire_slots = vec![None; wire_count as usize];
    let mut free_slots = BTreeSet::new();
    for input in 0..input_count {
        if last_uses[input as usize].is_none() {
            if !free_slots.insert(input) {
                return Err(ScheduleBuildErrorV1::DuplicateFreeSlot);
            }
        } else {
            wire_slots[input as usize] = Some(input);
        }
    }

    let mut next_slot = input_count;
    let mut scheduled_gates = Vec::with_capacity(circuit.gates().len());
    for (gate_index, gate) in circuit.gates().iter().copied().enumerate() {
        let (left_wire, right_wire) = gate.operands();
        let left_slot =
            wire_slots[left_wire.index()].ok_or(ScheduleBuildErrorV1::MissingOperandSlot)?;
        let right_slot =
            wire_slots[right_wire.index()].ok_or(ScheduleBuildErrorV1::MissingOperandSlot)?;

        release_at_last_use(
            left_wire,
            gate_index,
            &last_uses,
            &mut wire_slots,
            &mut free_slots,
        )?;
        if right_wire != left_wire {
            release_at_last_use(
                right_wire,
                gate_index,
                &last_uses,
                &mut wire_slots,
                &mut free_slots,
            )?;
        }

        let output_slot = match take_smallest_slot(&mut free_slots) {
            Some(slot) => slot,
            None => {
                let allocated = next_slot;
                next_slot = next_slot
                    .checked_add(1)
                    .ok_or(ScheduleBuildErrorV1::CountOverflow)?;
                allocated
            }
        };
        let output_wire = input_count as usize + gate_index;
        wire_slots[output_wire] = Some(output_slot);
        scheduled_gates.push(ScheduledGateV1 {
            kind: scheduled_kind(gate),
            left_slot,
            right_slot,
            output_slot,
        });
    }

    let mut output_slots = Vec::with_capacity(circuit.outputs().len());
    for output in circuit.outputs() {
        output_slots
            .push(wire_slots[output.index()].ok_or(ScheduleBuildErrorV1::MissingOutputSlot)?);
    }

    let slot_width = encoded_slot_width(next_slot)?;
    let canonical_encoding = encode_schedule(ScheduleEncodingInputsV1 {
        component: circuit.component(),
        circuit_digest: circuit.digest(),
        input_count,
        output_count,
        slot_count: next_slot,
        slot_width,
        gates: &scheduled_gates,
        output_slots: &output_slots,
    })?;
    let digest = Sha256::digest(&canonical_encoding).into();
    let gate_record_width = 1u8
        .checked_add(
            slot_width
                .checked_mul(3)
                .ok_or(ScheduleBuildErrorV1::CountOverflow)?,
        )
        .ok_or(ScheduleBuildErrorV1::CountOverflow)?;
    let metrics = ProvisionalScheduleMetricsV1 {
        input_wire_count: u64::from(input_count),
        output_wire_count: u64::from(output_count),
        scheduled_gate_count: u64::from(gate_count),
        reusable_slot_count: u64::from(next_slot),
        slot_width_bytes: slot_width,
        gate_record_width_bytes: gate_record_width,
        encoded_schedule_bytes: u64::try_from(canonical_encoding.len())
            .map_err(|_| ScheduleBuildErrorV1::CountOverflow)?,
    };
    Ok(CanonicalLivenessScheduleV1 {
        input_count,
        gates: scheduled_gates,
        output_slots,
        metrics,
        canonical_encoding,
        digest,
    })
}

fn derive_last_uses(circuit: &CanonicalBooleanCircuitV1, wire_count: usize) -> Vec<Option<usize>> {
    let mut last_uses = vec![None; wire_count];
    for (gate_index, gate) in circuit.gates().iter().copied().enumerate() {
        let (left, right) = gate.operands();
        last_uses[left.index()] = Some(gate_index);
        last_uses[right.index()] = Some(gate_index);
    }
    let terminal_use = circuit.gates().len();
    for output in circuit.outputs() {
        last_uses[output.index()] = Some(terminal_use);
    }
    last_uses
}

fn release_at_last_use(
    wire: WireId,
    gate_index: usize,
    last_uses: &[Option<usize>],
    wire_slots: &mut [Option<u32>],
    free_slots: &mut BTreeSet<u32>,
) -> Result<(), ScheduleBuildErrorV1> {
    if last_uses[wire.index()] != Some(gate_index) {
        return Ok(());
    }
    let slot = wire_slots[wire.index()]
        .take()
        .ok_or(ScheduleBuildErrorV1::MissingOperandSlot)?;
    if !free_slots.insert(slot) {
        return Err(ScheduleBuildErrorV1::DuplicateFreeSlot);
    }
    Ok(())
}

fn take_smallest_slot(free_slots: &mut BTreeSet<u32>) -> Option<u32> {
    let slot = free_slots.iter().next().copied()?;
    free_slots.remove(&slot);
    Some(slot)
}

const fn scheduled_kind(gate: Gate) -> ScheduledGateKindV1 {
    match gate {
        Gate::Xor { .. } => ScheduledGateKindV1::Xor,
        Gate::And { .. } => ScheduledGateKindV1::And,
        Gate::Inv { .. } => ScheduledGateKindV1::Inv,
    }
}

pub(super) fn encoded_slot_width(slot_count: u32) -> Result<u8, ScheduleBuildErrorV1> {
    let maximum_slot = slot_count
        .checked_sub(1)
        .ok_or(ScheduleBuildErrorV1::SlotWidthOverflow)?;
    match maximum_slot {
        0..=0xff => Ok(1),
        0x100..=0xffff => Ok(2),
        0x1_0000..=0xff_ffff => Ok(3),
        _ => Ok(4),
    }
}

fn encode_schedule(inputs: ScheduleEncodingInputsV1<'_>) -> Result<Vec<u8>, ScheduleBuildErrorV1> {
    let gate_count =
        u32::try_from(inputs.gates.len()).map_err(|_| ScheduleBuildErrorV1::CountOverflow)?;
    let record_width = 1usize
        .checked_add(
            usize::from(inputs.slot_width)
                .checked_mul(3)
                .ok_or(ScheduleBuildErrorV1::CountOverflow)?,
        )
        .ok_or(ScheduleBuildErrorV1::CountOverflow)?;
    let gate_bytes = inputs
        .gates
        .len()
        .checked_mul(record_width)
        .ok_or(ScheduleBuildErrorV1::CountOverflow)?;
    let output_bytes = inputs
        .output_slots
        .len()
        .checked_mul(usize::from(inputs.slot_width))
        .ok_or(ScheduleBuildErrorV1::CountOverflow)?;
    let capacity = SCHEDULE_HEADER_LEN_V1
        .checked_add(gate_bytes)
        .and_then(|count| count.checked_add(output_bytes))
        .ok_or(ScheduleBuildErrorV1::CountOverflow)?;

    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(SCHEDULE_MAGIC_V1);
    encoded.push(inputs.component);
    encoded.push(inputs.slot_width);
    encoded.extend_from_slice(&inputs.circuit_digest);
    encoded.extend_from_slice(&inputs.input_count.to_be_bytes());
    encoded.extend_from_slice(&gate_count.to_be_bytes());
    encoded.extend_from_slice(&inputs.output_count.to_be_bytes());
    encoded.extend_from_slice(&inputs.slot_count.to_be_bytes());
    for gate in inputs.gates {
        encoded.push(gate.kind.opcode());
        encode_slot(gate.left_slot, inputs.slot_width, &mut encoded);
        encode_slot(gate.right_slot, inputs.slot_width, &mut encoded);
        encode_slot(gate.output_slot, inputs.slot_width, &mut encoded);
    }
    for output_slot in inputs.output_slots {
        encode_slot(*output_slot, inputs.slot_width, &mut encoded);
    }
    debug_assert_eq!(encoded.len(), capacity);
    Ok(encoded)
}

fn encode_slot(slot: u32, width: u8, output: &mut Vec<u8>) {
    let bytes = slot.to_be_bytes();
    output.extend_from_slice(&bytes[4 - usize::from(width)..]);
}
