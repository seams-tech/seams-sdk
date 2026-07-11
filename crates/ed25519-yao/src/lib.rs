#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Validated draft-manifest types for the fixed Router A/B Ed25519 Yao protocol.
//!
//! This crate contains unreviewed public artifact metadata only. It exposes no
//! reviewed-active artifact state, garbler, evaluator, OT, streaming, or
//! runtime security-selection API.

mod digest;
mod error;
mod ids;
mod manifest;
mod metrics;

pub use digest::{
    ActivationOutputSchemaDigest32, CircuitDigest32, CompilerDigest32, ConstantsDigest32,
    DraftActivationManifestDigest32, DraftExportManifestDigest32, ExportOutputSchemaDigest32,
    InputSchemaDigest32, ScheduleDigest32, SourceIrDigest32, DIGEST32_LENGTH,
};
pub use error::{MetricField, ValidationError, ValidationResult};
pub use ids::{
    CircuitFamily, CircuitId, ProtocolId, ACTIVATION_CIRCUIT_ID, ACTIVATION_CIRCUIT_ID_STR,
    ACTIVATION_OUTPUT_SCHEMA_ID_STR, EXPORT_CIRCUIT_ID, EXPORT_CIRCUIT_ID_STR,
    EXPORT_OUTPUT_SCHEMA_ID_STR, PROTOCOL_ID, PROTOCOL_ID_STR,
};
pub use manifest::{
    ActivationCircuitArtifactDigests, ActivationOutputSchema, DraftActivationCircuitManifest,
    DraftExportCircuitManifest, DraftProtocolManifest, ExportCircuitArtifactDigests,
    ExportOutputSchema, ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE, DRAFT_MANIFEST_DIGEST_DOMAIN_V1,
    EXPORT_DRAFT_MANIFEST_FAMILY_BYTE,
};
pub use metrics::{
    CircuitMetrics, GateMetrics, ScheduleMetrics, PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE,
};
