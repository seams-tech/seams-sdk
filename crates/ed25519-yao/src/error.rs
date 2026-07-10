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
    /// Garbled-table payload size described by the artifact.
    TablePayloadBytes,
}

impl MetricField {
    fn as_str(self) -> &'static str {
        match self {
            Self::AndGateCount => "and_gate_count",
            Self::XorGateCount => "xor_gate_count",
            Self::TotalGateCount => "total_gate_count",
            Self::CircuitDepth => "circuit_depth",
            Self::InputWireCount => "input_wire_count",
            Self::OutputWireCount => "output_wire_count",
            Self::WireCount => "wire_count",
            Self::ScheduledGateCount => "scheduled_gate_count",
            Self::PeakLiveWireCount => "peak_live_wire_count",
            Self::EncodedScheduleBytes => "encoded_schedule_bytes",
            Self::TablePayloadBytes => "table_payload_bytes",
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
    /// Input and output wire counts overflowed while being summed.
    BoundaryWireCountOverflow,
    /// Total wires could not contain all boundary wires.
    WireCountBelowBoundaryCount {
        /// Declared total wires.
        wire_count: u64,
        /// Sum of input and output wires.
        boundary_wire_count: u64,
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
            Self::BoundaryWireCountOverflow => {
                formatter.write_str("input and output wire counts overflow u64")
            }
            Self::WireCountBelowBoundaryCount {
                wire_count,
                boundary_wire_count,
            } => write!(
                formatter,
                "wire_count {wire_count} is below boundary wire count {boundary_wire_count}"
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
