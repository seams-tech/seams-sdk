use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

const CANONICAL_IR_MAGIC_V1: &[u8; 8] = b"EYAOIR01";
const CANONICAL_IR_BIT_ORDER_BYTE_MAJOR_LSB0_V1: u8 = 1;
const CANONICAL_IR_FIXED_SHA512_32_COMPONENT_V1: u8 = 0x81;
const CANONICAL_IR_PROVISIONAL_ACTIVATION_CORE_V1: u8 = 0x91;
const CANONICAL_IR_PROVISIONAL_EXPORT_CORE_V1: u8 = 0x92;
const CANONICAL_IR_HEADER_LEN_V1: usize = 86;
const CANONICAL_GATE_RECORD_LEN_V1: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct WireId(u32);

impl WireId {
    pub(super) fn index(self) -> usize {
        self.0 as usize
    }

    fn encode_be(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BuilderBit {
    Constant(bool),
    Wire(WireId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    Xor { left: WireId, right: WireId },
    And { left: WireId, right: WireId },
    Inv { input: WireId },
}

impl Gate {
    pub(super) fn opcode(self) -> u8 {
        match self {
            Self::Xor { .. } => 1,
            Self::And { .. } => 2,
            Self::Inv { .. } => 3,
        }
    }

    pub(super) fn operands(self) -> (WireId, WireId) {
        match self {
            Self::Xor { left, right } | Self::And { left, right } => (left, right),
            Self::Inv { input } => (input, input),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CircuitBuildError {
    EmptyInputs,
    EmptyGates,
    EmptyOutputs,
    InputSchemaWireCountMismatch,
    OutputSchemaWireCountMismatch,
    ConstantOutput,
    DuplicateOutput,
    CountOverflow,
    ForwardReference,
}

pub(super) struct CircuitBuilder {
    input_count: u32,
    pub(super) gates: Vec<Gate>,
}

impl CircuitBuilder {
    pub(super) fn new(input_count: u32) -> Result<Self, CircuitBuildError> {
        if input_count == 0 {
            return Err(CircuitBuildError::EmptyInputs);
        }
        Ok(Self {
            input_count,
            gates: Vec::new(),
        })
    }

    pub(super) fn input_bits(&self) -> Vec<BuilderBit> {
        let mut inputs = Vec::with_capacity(self.input_count as usize);
        for index in 0..self.input_count {
            inputs.push(BuilderBit::Wire(WireId(index)));
        }
        inputs
    }

    pub(super) fn xor(&mut self, left: BuilderBit, right: BuilderBit) -> BuilderBit {
        match (left, right) {
            (BuilderBit::Constant(left), BuilderBit::Constant(right)) => {
                BuilderBit::Constant(left ^ right)
            }
            (BuilderBit::Constant(false), bit) | (bit, BuilderBit::Constant(false)) => bit,
            (BuilderBit::Constant(true), bit) | (bit, BuilderBit::Constant(true)) => self.inv(bit),
            (BuilderBit::Wire(left), BuilderBit::Wire(right)) if left == right => {
                BuilderBit::Constant(false)
            }
            (BuilderBit::Wire(left), BuilderBit::Wire(right)) => {
                let (left, right) = canonical_pair(left, right);
                self.push_gate(Gate::Xor { left, right })
            }
        }
    }

    pub(super) fn and(&mut self, left: BuilderBit, right: BuilderBit) -> BuilderBit {
        match (left, right) {
            (BuilderBit::Constant(left), BuilderBit::Constant(right)) => {
                BuilderBit::Constant(left & right)
            }
            (BuilderBit::Constant(false), _) | (_, BuilderBit::Constant(false)) => {
                BuilderBit::Constant(false)
            }
            (BuilderBit::Constant(true), bit) | (bit, BuilderBit::Constant(true)) => bit,
            (BuilderBit::Wire(left), BuilderBit::Wire(right)) if left == right => {
                BuilderBit::Wire(left)
            }
            (BuilderBit::Wire(left), BuilderBit::Wire(right)) => {
                let (left, right) = canonical_pair(left, right);
                self.push_gate(Gate::And { left, right })
            }
        }
    }

    pub(super) fn inv(&mut self, input: BuilderBit) -> BuilderBit {
        match input {
            BuilderBit::Constant(value) => BuilderBit::Constant(!value),
            BuilderBit::Wire(input) => self.push_gate(Gate::Inv { input }),
        }
    }

    pub(super) fn finish_fixed_sha512_32(
        self,
        outputs: Vec<BuilderBit>,
    ) -> Result<CanonicalBooleanCircuitV1, CircuitBuildError> {
        if self.input_count != 256 {
            return Err(CircuitBuildError::InputSchemaWireCountMismatch);
        }
        if outputs.len() != 512 {
            return Err(CircuitBuildError::OutputSchemaWireCountMismatch);
        }
        self.finish_with_schema(
            outputs,
            CANONICAL_IR_FIXED_SHA512_32_COMPONENT_V1,
            super::FIXED_SHA512_32_INPUT_SCHEMA_V1.as_bytes(),
            super::FIXED_SHA512_32_OUTPUT_SCHEMA_V1.as_bytes(),
        )
    }

    pub(super) fn finish_provisional_activation_core(
        self,
        outputs: Vec<BuilderBit>,
    ) -> Result<CanonicalBooleanCircuitV1, CircuitBuildError> {
        if self.input_count != 2_048 {
            return Err(CircuitBuildError::InputSchemaWireCountMismatch);
        }
        if outputs.len() != 512 {
            return Err(CircuitBuildError::OutputSchemaWireCountMismatch);
        }
        self.finish_with_schema(
            outputs,
            CANONICAL_IR_PROVISIONAL_ACTIVATION_CORE_V1,
            super::families::PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1.as_bytes(),
            super::families::PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1.as_bytes(),
        )
    }

    pub(super) fn finish_provisional_export_core(
        self,
        outputs: Vec<BuilderBit>,
    ) -> Result<CanonicalBooleanCircuitV1, CircuitBuildError> {
        if self.input_count != 1_024 {
            return Err(CircuitBuildError::InputSchemaWireCountMismatch);
        }
        if outputs.len() != 256 {
            return Err(CircuitBuildError::OutputSchemaWireCountMismatch);
        }
        self.finish_with_schema(
            outputs,
            CANONICAL_IR_PROVISIONAL_EXPORT_CORE_V1,
            super::families::PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1.as_bytes(),
            super::families::PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1.as_bytes(),
        )
    }

    #[cfg(test)]
    pub(super) fn finish_test_circuit(
        self,
        outputs: Vec<BuilderBit>,
    ) -> Result<CanonicalBooleanCircuitV1, CircuitBuildError> {
        self.finish_with_schema(
            outputs,
            0xff,
            b"seams/router-ab/ed25519-yao/test-only/input/v1",
            b"seams/router-ab/ed25519-yao/test-only/output/v1",
        )
    }

    fn finish_with_schema(
        self,
        outputs: Vec<BuilderBit>,
        component: u8,
        input_schema: &[u8],
        output_schema: &[u8],
    ) -> Result<CanonicalBooleanCircuitV1, CircuitBuildError> {
        if self.gates.is_empty() {
            return Err(CircuitBuildError::EmptyGates);
        }
        if outputs.is_empty() {
            return Err(CircuitBuildError::EmptyOutputs);
        }

        let mut output_wires = Vec::with_capacity(outputs.len());
        let mut unique_outputs = BTreeSet::new();
        for output in outputs {
            let BuilderBit::Wire(wire) = output else {
                return Err(CircuitBuildError::ConstantOutput);
            };
            if !unique_outputs.insert(wire) {
                return Err(CircuitBuildError::DuplicateOutput);
            }
            output_wires.push(wire);
        }

        let (gates, output_wires) = prune_dead_gates(self.input_count, self.gates, output_wires)?;
        if gates.is_empty() {
            return Err(CircuitBuildError::EmptyGates);
        }
        CanonicalBooleanCircuitV1::from_parts(
            self.input_count,
            gates,
            output_wires,
            component,
            input_schema,
            output_schema,
        )
    }

    fn push_gate(&mut self, gate: Gate) -> BuilderBit {
        let gate_index = u32::try_from(self.gates.len()).expect("Boolean gate count fits in u32");
        let output = self
            .input_count
            .checked_add(gate_index)
            .expect("Boolean wire count fits in u32");
        self.gates.push(gate);
        BuilderBit::Wire(WireId(output))
    }
}

fn canonical_pair(left: WireId, right: WireId) -> (WireId, WireId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

/// Metrics recomputed from one finalized deterministic Boolean circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BooleanCircuitMetricsV1 {
    input_wire_count: u64,
    output_wire_count: u64,
    wire_count: u64,
    and_gate_count: u64,
    xor_gate_count: u64,
    inversion_gate_count: u64,
    total_gate_count: u64,
    circuit_depth: u64,
    and_depth: u64,
    canonical_encoding_bytes: u64,
}

impl BooleanCircuitMetricsV1 {
    /// Number of secret input wires.
    pub const fn input_wire_count(self) -> u64 {
        self.input_wire_count
    }

    /// Number of referenced output wires.
    pub const fn output_wire_count(self) -> u64 {
        self.output_wire_count
    }

    /// Number of input and gate-output wires.
    pub const fn wire_count(self) -> u64 {
        self.wire_count
    }

    /// Number of AND gates.
    pub const fn and_gate_count(self) -> u64 {
        self.and_gate_count
    }

    /// Number of XOR gates.
    pub const fn xor_gate_count(self) -> u64 {
        self.xor_gate_count
    }

    /// Number of inversion gates.
    pub const fn inversion_gate_count(self) -> u64 {
        self.inversion_gate_count
    }

    /// Number of all Boolean gates.
    pub const fn total_gate_count(self) -> u64 {
        self.total_gate_count
    }

    /// Maximum topological depth across every gate class.
    pub const fn circuit_depth(self) -> u64 {
        self.circuit_depth
    }

    /// Maximum number of AND gates on any input-to-output path.
    pub const fn and_depth(self) -> u64 {
        self.and_depth
    }

    /// Exact byte length of the canonical IR encoding.
    pub const fn canonical_encoding_bytes(self) -> u64 {
        self.canonical_encoding_bytes
    }
}

pub(super) struct CanonicalBooleanCircuitV1 {
    component: u8,
    input_count: u32,
    gates: Vec<Gate>,
    outputs: Vec<WireId>,
    metrics: BooleanCircuitMetricsV1,
    canonical_encoding: Vec<u8>,
    digest: [u8; 32],
}

impl CanonicalBooleanCircuitV1 {
    fn from_parts(
        input_count: u32,
        gates: Vec<Gate>,
        outputs: Vec<WireId>,
        component: u8,
        input_schema: &[u8],
        output_schema: &[u8],
    ) -> Result<Self, CircuitBuildError> {
        let gate_count =
            u32::try_from(gates.len()).map_err(|_| CircuitBuildError::CountOverflow)?;
        let output_count =
            u32::try_from(outputs.len()).map_err(|_| CircuitBuildError::CountOverflow)?;
        let wire_count = input_count
            .checked_add(gate_count)
            .ok_or(CircuitBuildError::CountOverflow)?;
        validate_topology(input_count, &gates, &outputs, wire_count)?;

        let input_schema_digest: [u8; 32] = Sha256::digest(input_schema).into();
        let output_schema_digest: [u8; 32] = Sha256::digest(output_schema).into();
        let canonical_encoding = encode_circuit(
            component,
            input_schema_digest,
            output_schema_digest,
            input_count,
            &gates,
            &outputs,
        )?;
        let digest = Sha256::digest(&canonical_encoding).into();
        let metrics = derive_metrics(
            input_count,
            output_count,
            wire_count,
            &gates,
            u64::try_from(canonical_encoding.len())
                .map_err(|_| CircuitBuildError::CountOverflow)?,
        );

        Ok(Self {
            component,
            input_count,
            gates,
            outputs,
            metrics,
            canonical_encoding,
            digest,
        })
    }

    pub(super) const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.metrics
    }

    pub(super) const fn component(&self) -> u8 {
        self.component
    }

    pub(super) const fn input_count(&self) -> u32 {
        self.input_count
    }

    pub(super) fn gates(&self) -> &[Gate] {
        &self.gates
    }

    pub(super) fn outputs(&self) -> &[WireId] {
        &self.outputs
    }

    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn canonical_encoding(&self) -> &[u8] {
        &self.canonical_encoding
    }

    #[cfg(test)]
    pub(super) fn evaluate(&self, inputs: &[bool]) -> Result<Vec<bool>, CircuitEvalError> {
        if inputs.len() != self.input_count as usize {
            return Err(CircuitEvalError::InputCountMismatch {
                expected: self.input_count,
                actual: inputs.len(),
            });
        }

        let mut wires = Vec::with_capacity(self.metrics.wire_count as usize);
        wires.extend_from_slice(inputs);
        for gate in &self.gates {
            let value = match *gate {
                Gate::Xor { left, right } => wires[left.index()] ^ wires[right.index()],
                Gate::And { left, right } => wires[left.index()] & wires[right.index()],
                Gate::Inv { input } => !wires[input.index()],
            };
            wires.push(value);
        }

        let mut outputs = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            outputs.push(wires[output.index()]);
        }
        Ok(outputs)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CircuitEvalError {
    InputCountMismatch { expected: u32, actual: usize },
}

fn validate_topology(
    input_count: u32,
    gates: &[Gate],
    outputs: &[WireId],
    wire_count: u32,
) -> Result<(), CircuitBuildError> {
    for (gate_index, gate) in gates.iter().enumerate() {
        let gate_index = u32::try_from(gate_index).map_err(|_| CircuitBuildError::CountOverflow)?;
        let output_wire = input_count
            .checked_add(gate_index)
            .ok_or(CircuitBuildError::CountOverflow)?;
        let (left, right) = gate.operands();
        if left.0 >= output_wire || right.0 >= output_wire {
            return Err(CircuitBuildError::ForwardReference);
        }
    }
    if outputs.iter().any(|output| output.0 >= wire_count) {
        return Err(CircuitBuildError::ForwardReference);
    }
    Ok(())
}

fn mark_live_gates(input_count: u32, gates: &[Gate], outputs: &[WireId]) -> Vec<bool> {
    let mut live_gates = vec![false; gates.len()];
    let mut pending_wires = outputs.to_vec();
    while let Some(wire) = pending_wires.pop() {
        if wire.0 < input_count {
            continue;
        }
        let gate_index = (wire.0 - input_count) as usize;
        if live_gates[gate_index] {
            continue;
        }
        live_gates[gate_index] = true;
        let (left, right) = gates[gate_index].operands();
        pending_wires.push(left);
        if right != left {
            pending_wires.push(right);
        }
    }
    live_gates
}

fn prune_dead_gates(
    input_count: u32,
    gates: Vec<Gate>,
    outputs: Vec<WireId>,
) -> Result<(Vec<Gate>, Vec<WireId>), CircuitBuildError> {
    let live_gates = mark_live_gates(input_count, &gates, &outputs);
    if live_gates.iter().all(|is_live| *is_live) {
        return Ok((gates, outputs));
    }

    let wire_count = (input_count as usize)
        .checked_add(gates.len())
        .ok_or(CircuitBuildError::CountOverflow)?;
    let mut remapped_wires = vec![None; wire_count];
    for input in 0..input_count {
        remapped_wires[input as usize] = Some(WireId(input));
    }

    let mut canonical_gates = Vec::with_capacity(live_gates.iter().filter(|live| **live).count());
    for (gate_index, gate) in gates.into_iter().enumerate() {
        if !live_gates[gate_index] {
            continue;
        }
        let canonical_gate = remap_gate(gate, &remapped_wires)?;
        let canonical_gate_index =
            u32::try_from(canonical_gates.len()).map_err(|_| CircuitBuildError::CountOverflow)?;
        let canonical_output = input_count
            .checked_add(canonical_gate_index)
            .ok_or(CircuitBuildError::CountOverflow)?;
        let old_output = (input_count as usize)
            .checked_add(gate_index)
            .ok_or(CircuitBuildError::CountOverflow)?;
        remapped_wires[old_output] = Some(WireId(canonical_output));
        canonical_gates.push(canonical_gate);
    }

    let mut canonical_outputs = Vec::with_capacity(outputs.len());
    for output in outputs {
        canonical_outputs
            .push(remapped_wires[output.index()].ok_or(CircuitBuildError::ForwardReference)?);
    }
    Ok((canonical_gates, canonical_outputs))
}

fn remap_gate(gate: Gate, remapped_wires: &[Option<WireId>]) -> Result<Gate, CircuitBuildError> {
    match gate {
        Gate::Xor { left, right } => Ok(Gate::Xor {
            left: remapped_wire(left, remapped_wires)?,
            right: remapped_wire(right, remapped_wires)?,
        }),
        Gate::And { left, right } => Ok(Gate::And {
            left: remapped_wire(left, remapped_wires)?,
            right: remapped_wire(right, remapped_wires)?,
        }),
        Gate::Inv { input } => Ok(Gate::Inv {
            input: remapped_wire(input, remapped_wires)?,
        }),
    }
}

fn remapped_wire(
    wire: WireId,
    remapped_wires: &[Option<WireId>],
) -> Result<WireId, CircuitBuildError> {
    remapped_wires
        .get(wire.index())
        .and_then(|mapped| *mapped)
        .ok_or(CircuitBuildError::ForwardReference)
}

fn encode_circuit(
    component: u8,
    input_schema_digest: [u8; 32],
    output_schema_digest: [u8; 32],
    input_count: u32,
    gates: &[Gate],
    outputs: &[WireId],
) -> Result<Vec<u8>, CircuitBuildError> {
    let gate_count = u32::try_from(gates.len()).map_err(|_| CircuitBuildError::CountOverflow)?;
    let output_count =
        u32::try_from(outputs.len()).map_err(|_| CircuitBuildError::CountOverflow)?;
    let gate_bytes = gates
        .len()
        .checked_mul(CANONICAL_GATE_RECORD_LEN_V1)
        .ok_or(CircuitBuildError::CountOverflow)?;
    let output_bytes = outputs
        .len()
        .checked_mul(4)
        .ok_or(CircuitBuildError::CountOverflow)?;
    let capacity = CANONICAL_IR_HEADER_LEN_V1
        .checked_add(gate_bytes)
        .and_then(|count| count.checked_add(output_bytes))
        .ok_or(CircuitBuildError::CountOverflow)?;

    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(CANONICAL_IR_MAGIC_V1);
    encoded.push(component);
    encoded.push(CANONICAL_IR_BIT_ORDER_BYTE_MAJOR_LSB0_V1);
    encoded.extend_from_slice(&input_schema_digest);
    encoded.extend_from_slice(&output_schema_digest);
    encoded.extend_from_slice(&input_count.to_be_bytes());
    encoded.extend_from_slice(&gate_count.to_be_bytes());
    encoded.extend_from_slice(&output_count.to_be_bytes());
    for gate in gates {
        encoded.push(gate.opcode());
        let (left, right) = gate.operands();
        left.encode_be(&mut encoded);
        right.encode_be(&mut encoded);
    }
    for output in outputs {
        output.encode_be(&mut encoded);
    }
    debug_assert_eq!(encoded.len(), capacity);
    Ok(encoded)
}

fn derive_metrics(
    input_count: u32,
    output_count: u32,
    wire_count: u32,
    gates: &[Gate],
    canonical_encoding_bytes: u64,
) -> BooleanCircuitMetricsV1 {
    let mut full_depths = vec![0u64; input_count as usize];
    let mut and_depths = vec![0u64; input_count as usize];
    let mut and_gate_count = 0u64;
    let mut xor_gate_count = 0u64;
    let mut inversion_gate_count = 0u64;

    for gate in gates {
        let (left, right) = gate.operands();
        let operand_full_depth = full_depths[left.index()].max(full_depths[right.index()]);
        let operand_and_depth = and_depths[left.index()].max(and_depths[right.index()]);
        let (full_depth, and_depth) = match gate {
            Gate::And { .. } => {
                and_gate_count += 1;
                (operand_full_depth + 1, operand_and_depth + 1)
            }
            Gate::Xor { .. } => {
                xor_gate_count += 1;
                (operand_full_depth + 1, operand_and_depth)
            }
            Gate::Inv { .. } => {
                inversion_gate_count += 1;
                (operand_full_depth + 1, operand_and_depth)
            }
        };
        full_depths.push(full_depth);
        and_depths.push(and_depth);
    }

    BooleanCircuitMetricsV1 {
        input_wire_count: u64::from(input_count),
        output_wire_count: u64::from(output_count),
        wire_count: u64::from(wire_count),
        and_gate_count,
        xor_gate_count,
        inversion_gate_count,
        total_gate_count: u64::try_from(gates.len()).expect("gate count already fits u32"),
        circuit_depth: full_depths.into_iter().max().unwrap_or(0),
        and_depth: and_depths.into_iter().max().unwrap_or(0),
        canonical_encoding_bytes,
    }
}
