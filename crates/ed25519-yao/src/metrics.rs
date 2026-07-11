use crate::{MetricField, ValidationError, ValidationResult};

/// Bytes sent per AND gate by the passive two-ciphertext Half-Gates construction.
pub const PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE: u64 = 32;

/// Validated Boolean gate counts for one fixed circuit artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateMetrics {
    and_gate_count: u64,
    xor_gate_count: u64,
    inversion_gate_count: u64,
    total_gate_count: u64,
    circuit_depth: u64,
    and_depth: u64,
}

impl GateMetrics {
    /// Validates required gate counts and their declared total.
    pub fn new(
        and_gate_count: u64,
        xor_gate_count: u64,
        inversion_gate_count: u64,
        total_gate_count: u64,
        circuit_depth: u64,
        and_depth: u64,
    ) -> ValidationResult<Self> {
        require_nonzero(MetricField::AndGateCount, and_gate_count)?;
        require_nonzero(MetricField::XorGateCount, xor_gate_count)?;
        require_nonzero(MetricField::TotalGateCount, total_gate_count)?;
        require_nonzero(MetricField::CircuitDepth, circuit_depth)?;
        require_nonzero(MetricField::AndDepth, and_depth)?;

        let computed = and_gate_count
            .checked_add(xor_gate_count)
            .and_then(|count| count.checked_add(inversion_gate_count))
            .ok_or(ValidationError::GateCountOverflow)?;
        if computed != total_gate_count {
            return Err(ValidationError::TotalGateCountMismatch {
                declared: total_gate_count,
                computed,
            });
        }
        if circuit_depth > total_gate_count {
            return Err(ValidationError::CircuitDepthExceedsTotalGateCount {
                depth: circuit_depth,
                total_gates: total_gate_count,
            });
        }
        if and_depth > circuit_depth {
            return Err(ValidationError::AndDepthExceedsCircuitDepth {
                and_depth,
                circuit_depth,
            });
        }
        if and_depth > and_gate_count {
            return Err(ValidationError::AndDepthExceedsAndGateCount {
                and_depth,
                and_gate_count,
            });
        }

        Ok(Self {
            and_gate_count,
            xor_gate_count,
            inversion_gate_count,
            total_gate_count,
            circuit_depth,
            and_depth,
        })
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

    /// Sum of all gate classes.
    pub const fn total_gate_count(self) -> u64 {
        self.total_gate_count
    }

    /// Maximum topological circuit depth.
    pub const fn circuit_depth(self) -> u64 {
        self.circuit_depth
    }

    /// Maximum number of AND gates along any circuit path.
    pub const fn and_depth(self) -> u64 {
        self.and_depth
    }
}

/// Validated compact-schedule and wire-liveness metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleMetrics {
    input_wire_count: u64,
    output_wire_count: u64,
    wire_count: u64,
    scheduled_gate_count: u64,
    peak_live_wire_count: u64,
    encoded_schedule_bytes: u64,
}

impl ScheduleMetrics {
    /// Validates input, output-reference, schedule, and liveness counts.
    pub fn new(
        input_wire_count: u64,
        output_wire_count: u64,
        wire_count: u64,
        scheduled_gate_count: u64,
        peak_live_wire_count: u64,
        encoded_schedule_bytes: u64,
    ) -> ValidationResult<Self> {
        require_nonzero(MetricField::InputWireCount, input_wire_count)?;
        require_nonzero(MetricField::OutputWireCount, output_wire_count)?;
        require_nonzero(MetricField::WireCount, wire_count)?;
        require_nonzero(MetricField::ScheduledGateCount, scheduled_gate_count)?;
        require_nonzero(MetricField::PeakLiveWireCount, peak_live_wire_count)?;
        require_nonzero(MetricField::EncodedScheduleBytes, encoded_schedule_bytes)?;

        if wire_count < input_wire_count {
            return Err(ValidationError::WireCountBelowInputWireCount {
                wire_count,
                input_wire_count,
            });
        }
        if output_wire_count > wire_count {
            return Err(ValidationError::OutputWireCountExceedsWireCount {
                output_wire_count,
                wire_count,
            });
        }
        if peak_live_wire_count > wire_count {
            return Err(ValidationError::PeakLiveWireCountExceedsWireCount {
                peak_live_wire_count,
                wire_count,
            });
        }

        Ok(Self {
            input_wire_count,
            output_wire_count,
            wire_count,
            scheduled_gate_count,
            peak_live_wire_count,
            encoded_schedule_bytes,
        })
    }

    /// Number of circuit input wires.
    pub const fn input_wire_count(self) -> u64 {
        self.input_wire_count
    }

    /// Number of circuit output wires.
    pub const fn output_wire_count(self) -> u64 {
        self.output_wire_count
    }

    /// Total number of logical circuit wires.
    pub const fn wire_count(self) -> u64 {
        self.wire_count
    }

    /// Number of gate entries in the compact schedule.
    pub const fn scheduled_gate_count(self) -> u64 {
        self.scheduled_gate_count
    }

    /// Maximum simultaneously live wire slots.
    pub const fn peak_live_wire_count(self) -> u64 {
        self.peak_live_wire_count
    }

    /// Encoded compact-schedule byte size.
    pub const fn encoded_schedule_bytes(self) -> u64 {
        self.encoded_schedule_bytes
    }
}

/// Complete validated metrics required by a circuit manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitMetrics {
    gates: GateMetrics,
    schedule: ScheduleMetrics,
    table_payload_bytes: u64,
}

impl CircuitMetrics {
    /// Validates cross-metric consistency and derives passive Half-Gates table bytes.
    pub fn new_passive_half_gates(
        gates: GateMetrics,
        schedule: ScheduleMetrics,
    ) -> ValidationResult<Self> {
        if schedule.scheduled_gate_count() != gates.total_gate_count() {
            return Err(ValidationError::ScheduledGateCountMismatch {
                scheduled: schedule.scheduled_gate_count(),
                total_gates: gates.total_gate_count(),
            });
        }
        let table_payload_bytes = gates
            .and_gate_count()
            .checked_mul(PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE)
            .ok_or(ValidationError::PassiveHalfGatesTablePayloadOverflow {
                and_gate_count: gates.and_gate_count(),
            })?;
        Ok(Self {
            gates,
            schedule,
            table_payload_bytes,
        })
    }

    /// Validated gate metrics.
    pub const fn gates(self) -> GateMetrics {
        self.gates
    }

    /// Validated schedule metrics.
    pub const fn schedule(self) -> ScheduleMetrics {
        self.schedule
    }

    /// Exact passive Half-Gates table payload bytes described by this artifact.
    pub const fn table_payload_bytes(self) -> u64 {
        self.table_payload_bytes
    }
}

fn require_nonzero(field: MetricField, value: u64) -> ValidationResult<()> {
    if value == 0 {
        return Err(ValidationError::ZeroMetric { field });
    }
    Ok(())
}
