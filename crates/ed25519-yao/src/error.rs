use core::fmt;

use crate::DIGEST32_LENGTH;

/// Result returned by validated manifest constructors.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// A required numeric manifest field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricField {
    /// Number of AND gates.
    AndGateCount,
    /// Number of XOR gates.
    XorGateCount,
    /// Total gate count.
    TotalGateCount,
    /// Circuit depth.
    CircuitDepth,
    /// AND-gate depth.
    AndDepth,
    /// Number of circuit input wires.
    InputWireCount,
    /// Number of circuit output wires.
    OutputWireCount,
    /// Total number of circuit wires.
    WireCount,
    /// Number of gate entries in the compact schedule.
    ScheduledGateCount,
    /// Maximum simultaneously live wire slots.
    PeakLiveWireCount,
    /// Encoded compact-schedule size.
    EncodedScheduleBytes,
}

impl MetricField {
    fn as_str(self) -> &'static str {
        match self {
            Self::AndGateCount => "and_gate_count",
            Self::XorGateCount => "xor_gate_count",
            Self::TotalGateCount => "total_gate_count",
            Self::CircuitDepth => "circuit_depth",
            Self::AndDepth => "and_depth",
            Self::InputWireCount => "input_wire_count",
            Self::OutputWireCount => "output_wire_count",
            Self::WireCount => "wire_count",
            Self::ScheduledGateCount => "scheduled_gate_count",
            Self::PeakLiveWireCount => "peak_live_wire_count",
            Self::EncodedScheduleBytes => "encoded_schedule_bytes",
        }
    }
}

/// Validation failures for public protocol and circuit-manifest metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A raw digest did not have exactly 32 bytes.
    DigestLength {
        /// Observed raw length.
        actual: usize,
    },
    /// An all-zero digest was rejected.
    ZeroDigest,
    /// A required metric was zero.
    ZeroMetric {
        /// Rejected metric.
        field: MetricField,
    },
    /// Gate class counts overflowed `u64` while being summed.
    GateCountOverflow,
    /// The declared total did not equal the sum of gate classes.
    TotalGateCountMismatch {
        /// Total stored in the manifest.
        declared: u64,
        /// Sum of AND, XOR, and inversion gates.
        computed: u64,
    },
    /// Circuit depth exceeded total gates.
    CircuitDepthExceedsTotalGateCount {
        /// Declared circuit depth.
        depth: u64,
        /// Validated total gate count.
        total_gates: u64,
    },
    /// AND depth exceeded the complete topological circuit depth.
    AndDepthExceedsCircuitDepth {
        /// Declared AND depth.
        and_depth: u64,
        /// Declared complete circuit depth.
        circuit_depth: u64,
    },
    /// AND depth exceeded the total number of AND gates.
    AndDepthExceedsAndGateCount {
        /// Declared AND depth.
        and_depth: u64,
        /// Validated total number of AND gates.
        and_gate_count: u64,
    },
    /// Total wires could not contain all input wires.
    WireCountBelowInputWireCount {
        /// Declared total wires.
        wire_count: u64,
        /// Declared input wires.
        input_wire_count: u64,
    },
    /// The output schema referenced more wires than the circuit contains.
    OutputWireCountExceedsWireCount {
        /// Declared output-wire references.
        output_wire_count: u64,
        /// Declared total wires.
        wire_count: u64,
    },
    /// The liveness schedule claimed more live slots than circuit wires.
    PeakLiveWireCountExceedsWireCount {
        /// Declared peak live slots.
        peak_live_wire_count: u64,
        /// Declared total wires.
        wire_count: u64,
    },
    /// The schedule did not contain exactly one entry per gate.
    ScheduledGateCountMismatch {
        /// Entries declared by the compact schedule.
        scheduled: u64,
        /// Validated total circuit gates.
        total_gates: u64,
    },
    /// The passive Half-Gates table byte derivation overflowed `u64`.
    PassiveHalfGatesTablePayloadOverflow {
        /// Validated AND-gate count that could not be multiplied by 32 bytes.
        and_gate_count: u64,
    },
    /// Activation and export reused a circuit digest.
    DuplicateCircuitDigest,
    /// Activation and export reused a schedule digest.
    DuplicateScheduleDigest,
    /// Activation and export reused an output-schema digest.
    DuplicateOutputSchemaDigest,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestLength { actual } => write!(
                formatter,
                "digest must be {DIGEST32_LENGTH} bytes (got {actual})"
            ),
            Self::ZeroDigest => formatter.write_str("digest must not be all zero"),
            Self::ZeroMetric { field } => {
                write!(formatter, "{} must be greater than zero", field.as_str())
            }
            Self::GateCountOverflow => formatter.write_str("gate class counts overflow u64"),
            Self::TotalGateCountMismatch { declared, computed } => write!(
                formatter,
                "total_gate_count {declared} does not equal gate class sum {computed}"
            ),
            Self::CircuitDepthExceedsTotalGateCount { depth, total_gates } => write!(
                formatter,
                "circuit_depth {depth} exceeds total_gate_count {total_gates}"
            ),
            Self::AndDepthExceedsCircuitDepth {
                and_depth,
                circuit_depth,
            } => write!(
                formatter,
                "and_depth {and_depth} exceeds circuit_depth {circuit_depth}"
            ),
            Self::AndDepthExceedsAndGateCount {
                and_depth,
                and_gate_count,
            } => write!(
                formatter,
                "and_depth {and_depth} exceeds and_gate_count {and_gate_count}"
            ),
            Self::WireCountBelowInputWireCount {
                wire_count,
                input_wire_count,
            } => write!(
                formatter,
                "wire_count {wire_count} is below input_wire_count {input_wire_count}"
            ),
            Self::OutputWireCountExceedsWireCount {
                output_wire_count,
                wire_count,
            } => write!(
                formatter,
                "output_wire_count {output_wire_count} exceeds wire_count {wire_count}"
            ),
            Self::PeakLiveWireCountExceedsWireCount {
                peak_live_wire_count,
                wire_count,
            } => write!(
                formatter,
                "peak_live_wire_count {peak_live_wire_count} exceeds wire_count {wire_count}"
            ),
            Self::ScheduledGateCountMismatch {
                scheduled,
                total_gates,
            } => write!(
                formatter,
                "scheduled_gate_count {scheduled} does not equal total_gate_count {total_gates}"
            ),
            Self::PassiveHalfGatesTablePayloadOverflow { and_gate_count } => write!(
                formatter,
                "passive Half-Gates table bytes overflow for and_gate_count {and_gate_count}"
            ),
            Self::DuplicateCircuitDigest => {
                formatter.write_str("activation and export circuit digests must differ")
            }
            Self::DuplicateScheduleDigest => {
                formatter.write_str("activation and export schedule digests must differ")
            }
            Self::DuplicateOutputSchemaDigest => {
                formatter.write_str("activation and export output-schema digests must differ")
            }
        }
    }
}

impl std::error::Error for ValidationError {}
