#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Validated draft-manifest types for the fixed Router A/B Ed25519 Yao protocol.
//!
//! The crate also contains a private, non-promotable passive Half-Gates kernel
//! used only by internal tests and benchmarks. It exposes no reviewed-active
//! artifact state, OT, streaming, ceremony, or runtime security-selection API.

mod digest;
mod error;
mod ids;
mod manifest;
mod metrics;
#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "passive-wasm-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
mod passive;

#[cfg(feature = "passive-benchmark")]
#[doc(hidden)]
pub use passive::phase5_benchmark;
#[cfg(feature = "passive-benchmark")]
#[doc(hidden)]
pub use passive::phase5_transport::EofBodyWriter;
#[cfg(feature = "passive-benchmark")]
#[doc(hidden)]
pub use passive::phase5_transport::ExactEofBodyReader;
#[cfg(all(feature = "passive-benchmark", unix))]
#[doc(hidden)]
pub use passive::phase5_transport::UnixEofBodyWriter;
#[cfg(all(feature = "passive-benchmark", unix))]
#[doc(hidden)]
pub use passive::phase5_transport::UnixExactEofBodyReader;
#[cfg(feature = "passive-wasm-benchmark")]
#[doc(hidden)]
pub use passive::phase5_wasm_benchmark;
#[cfg(feature = "phase9-role-benchmark")]
#[doc(hidden)]
pub use passive::role_protocol::benchmark as phase9_role_benchmark;
#[cfg(feature = "local-protocol")]
/// Fixed 128 KiB local-product protocol surface.
pub mod local_protocol {
    pub use crate::passive::role_protocol::benchmark::{
        combine_client_activation_packages, combine_export_packages,
        combine_signing_worker_activation_packages, derive_registration_receipt,
        verify_activation_continuity, Activation128KiBDeriverA, Activation128KiBDeriverB,
        ActivationDeriverAClientPackage, ActivationDeriverACompletion, ActivationDeriverAInputs,
        ActivationDeriverASigningWorkerPackage, ActivationDeriverBClientPackage,
        ActivationDeriverBCompletion, ActivationDeriverBInputs,
        ActivationDeriverBSigningWorkerPackage, ActivationPublicCommitments,
        ActivationPublicReceipt, BenchmarkRoleError, ClientBaseScalar, DirectionalEofEvidence,
        DirectionalWireDecoder, DirectionalWireEncoder, Export128KiBDeriverA, Export128KiBDeriverB,
        ExportDeriverAClientPackage, ExportDeriverACompletion, ExportDeriverAInputs,
        ExportDeriverBClientPackage, ExportDeriverBCompletion, ExportDeriverBInputs,
        ExportedSeed32, RelayEvent, RelayInstruction, RelayStep, SigningWorkerBaseScalar,
        StreamMetrics, WireByteLedger, WireDirection, WireMessage, WireMessageKind,
    };
}

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
    DraftActivationManifestPreimage, DraftExportCircuitManifest, DraftExportManifestPreimage,
    DraftProtocolManifest, ExportCircuitArtifactDigests, ExportOutputSchema,
    ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE, ACTIVATION_DRAFT_MANIFEST_PREIMAGE_BYTES,
    DRAFT_MANIFEST_DIGEST_DOMAIN_V1, EXPORT_DRAFT_MANIFEST_FAMILY_BYTE,
    EXPORT_DRAFT_MANIFEST_PREIMAGE_BYTES,
};
pub use metrics::{
    CircuitMetrics, GateMetrics, ScheduleMetrics, PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE,
};
