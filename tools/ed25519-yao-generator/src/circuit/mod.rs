//! Deterministic generator-only Boolean-circuit foundations.

mod add256;
mod clamp;
mod families;
mod ir;
mod phase4_families;
mod scalar;
mod schedule;
mod sha512;

use ir::CanonicalBooleanCircuitV1;

pub use ir::BooleanCircuitMetricsV1;
pub use schedule::ProvisionalScheduleMetricsV1;

pub use families::{
    compile_provisional_activation_core_v1, compile_provisional_export_core_v1,
    ProvisionalActivationCoreDigest32V1, ProvisionalActivationCoreV1,
    ProvisionalActivationScheduleDigest32V1, ProvisionalExportCoreDigest32V1,
    ProvisionalExportCoreV1, ProvisionalExportScheduleDigest32V1,
    PublicSyntheticActivationCoreInputsV1, PublicSyntheticActivationCoreOutputsV1,
    PublicSyntheticActivationInputErrorV1, PublicSyntheticDeriverAActivationInputsV1,
    PublicSyntheticDeriverAExportInputsV1, PublicSyntheticDeriverBActivationInputsV1,
    PublicSyntheticDeriverBExportInputsV1, PublicSyntheticExportCoreInputsV1,
    PublicSyntheticExportCoreOutputV1, PublicSyntheticTauFieldV1,
    PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1, PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1,
    PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1, PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1,
};

pub use phase4_families::{
    compile_phase4_private_output_activation_core_v1, compile_phase4_private_output_export_core_v1,
    Phase4PrivateOutputActivationCoreDigest32V1, Phase4PrivateOutputActivationCoreV1,
    Phase4PrivateOutputActivationScheduleDigest32V1, Phase4PrivateOutputExportCoreDigest32V1,
    Phase4PrivateOutputExportCoreV1, Phase4PrivateOutputExportScheduleDigest32V1,
    PublicSyntheticPhase4ActivationInputsV1, PublicSyntheticPhase4ActivationOutputsV1,
    PublicSyntheticPhase4DeriverAActivationSharesV1,
    PublicSyntheticPhase4DeriverAClientScalarCoinV1, PublicSyntheticPhase4DeriverAExportSeedCoinV1,
    PublicSyntheticPhase4DeriverAExportShareV1,
    PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1,
    PublicSyntheticPhase4DeriverBActivationSharesV1,
    PublicSyntheticPhase4DeriverBClientScalarCoinV1, PublicSyntheticPhase4DeriverBExportSeedCoinV1,
    PublicSyntheticPhase4DeriverBExportShareV1,
    PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1, PublicSyntheticPhase4ExportInputsV1,
    PublicSyntheticPhase4ExportOutputsV1, PublicSyntheticPhase4ScalarCoinErrorV1,
    PHASE4_PRIVATE_OUTPUT_ACTIVATION_INPUT_SCHEMA_V1,
    PHASE4_PRIVATE_OUTPUT_ACTIVATION_OUTPUT_SCHEMA_V1,
    PHASE4_PRIVATE_OUTPUT_EXPORT_INPUT_SCHEMA_V1, PHASE4_PRIVATE_OUTPUT_EXPORT_OUTPUT_SCHEMA_V1,
};

pub use sha512::{
    FIXED_SHA512_32_BIT_ORDER_V1, FIXED_SHA512_32_INPUT_SCHEMA_V1, FIXED_SHA512_32_OUTPUT_SCHEMA_V1,
};

/// Opaque host-only benchmark component for SHA-512 over exactly 32 bytes.
///
/// This component exists to validate circuit lowering, bit order, gate counts,
/// and deterministic encoding. It is not a production circuit artifact and
/// cannot be promoted into one through this API.
pub struct FixedSha512CircuitV1 {
    circuit: CanonicalBooleanCircuitV1,
    schedule: schedule::CanonicalLivenessScheduleV1,
}

/// SHA-256 identity of a provisional generator-only benchmark component.
///
/// This purpose-specific type has no conversion into a production activation
/// or export circuit digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalBenchmarkComponentDigest32V1([u8; 32]);

impl ProvisionalBenchmarkComponentDigest32V1 {
    /// Exposes the public digest bytes for reproducibility checks and reports.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// SHA-256 identity of a provisional SHA benchmark liveness schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalBenchmarkScheduleDigest32V1([u8; 32]);

impl ProvisionalBenchmarkScheduleDigest32V1 {
    /// Exposes public digest bytes for reproducibility checks and reports.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl FixedSha512CircuitV1 {
    /// Evaluates the fixed circuit over public synthetic seed bytes.
    pub fn evaluate_public_synthetic_seed(&self, seed: [u8; 32]) -> [u8; 64] {
        sha512::evaluate_fixed_sha512_32(&self.schedule, seed)
    }

    /// Returns metrics derived from the finalized Boolean IR.
    pub const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit.metrics()
    }

    /// Returns the provisional SHA-256 identity of the canonical IR bytes.
    pub const fn benchmark_component_digest(&self) -> ProvisionalBenchmarkComponentDigest32V1 {
        ProvisionalBenchmarkComponentDigest32V1(self.circuit.digest())
    }

    /// Returns the exact canonical Boolean IR bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        self.circuit.canonical_encoding()
    }

    /// Returns metrics derived from the canonical liveness schedule.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule.metrics()
    }

    /// Returns the provisional liveness-schedule identity.
    pub const fn benchmark_schedule_digest(&self) -> ProvisionalBenchmarkScheduleDigest32V1 {
        ProvisionalBenchmarkScheduleDigest32V1(self.schedule.digest())
    }

    /// Returns the exact canonical liveness-schedule bytes.
    pub fn canonical_schedule_encoding(&self) -> &[u8] {
        self.schedule.canonical_encoding()
    }
}

/// Compiles the deterministic benchmark component for SHA-512 over 32 bytes.
pub fn compile_fixed_sha512_32_v1() -> FixedSha512CircuitV1 {
    let circuit = sha512::compile_fixed_sha512_32();
    let schedule = schedule::CanonicalLivenessScheduleV1::derive(&circuit);
    FixedSha512CircuitV1 { circuit, schedule }
}

#[cfg(test)]
mod combinator_tests;
#[cfg(test)]
mod family_tests;
#[cfg(test)]
mod phase4_family_tests;
#[cfg(test)]
mod schedule_tests;
#[cfg(test)]
mod tests;
