use sha2::{Digest, Sha256};

use crate::{
    ActivationOutputSchemaDigest32, CircuitDigest32, CircuitFamily, CircuitId, CircuitMetrics,
    CompilerDigest32, ConstantsDigest32, DraftActivationManifestDigest32,
    DraftExportManifestDigest32, ExportOutputSchemaDigest32, InputSchemaDigest32, ProtocolId,
    ScheduleDigest32, SourceIrDigest32, ValidationError, ValidationResult, ACTIVATION_CIRCUIT_ID,
    ACTIVATION_OUTPUT_SCHEMA_ID_STR, EXPORT_CIRCUIT_ID, EXPORT_OUTPUT_SCHEMA_ID_STR, PROTOCOL_ID,
};

/// Domain and version prefix for canonical draft-manifest SHA-256 identities.
pub const DRAFT_MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"seams:router-ab:ed25519-yao:draft-manifest:v1";

/// Canonical family byte for a draft activation manifest.
pub const ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE: u8 = 0x01;
/// Canonical family byte for a draft export manifest.
pub const EXPORT_DRAFT_MANIFEST_FAMILY_BYTE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CircuitArtifactDigestsInner {
    circuit: CircuitDigest32,
    compiler: CompilerDigest32,
    source_ir: SourceIrDigest32,
    schedule: ScheduleDigest32,
    constants: ConstantsDigest32,
    input_schema: InputSchemaDigest32,
}

impl CircuitArtifactDigestsInner {
    const fn new(
        circuit: CircuitDigest32,
        compiler: CompilerDigest32,
        source_ir: SourceIrDigest32,
        schedule: ScheduleDigest32,
        constants: ConstantsDigest32,
        input_schema: InputSchemaDigest32,
    ) -> Self {
        Self {
            circuit,
            compiler,
            source_ir,
            schedule,
            constants,
            input_schema,
        }
    }
}

macro_rules! impl_artifact_digest_accessors {
    () => {
        /// Digest of the complete canonical circuit artifact.
        pub const fn circuit(self) -> CircuitDigest32 {
            self.0.circuit
        }

        /// Digest of the compiler version and parameters.
        pub const fn compiler(self) -> CompilerDigest32 {
            self.0.compiler
        }

        /// Digest of the canonical source IR.
        pub const fn source_ir(self) -> SourceIrDigest32 {
            self.0.source_ir
        }

        /// Digest of the compact gate schedule.
        pub const fn schedule(self) -> ScheduleDigest32 {
            self.0.schedule
        }

        /// Digest of embedded circuit constants.
        pub const fn constants(self) -> ConstantsDigest32 {
            self.0.constants
        }

        /// Digest of the fixed input schema.
        pub const fn input_schema(self) -> InputSchemaDigest32 {
            self.0.input_schema
        }
    };
}

/// Activation-family artifact digests required for deterministic regeneration.
///
/// Each constructor argument has a distinct role type. The complete bundle is
/// accepted only by `DraftActivationCircuitManifest`.
///
/// ```compile_fail
/// use ed25519_yao::{
///     ActivationCircuitArtifactDigests, CircuitDigest32, CompilerDigest32,
///     ConstantsDigest32, InputSchemaDigest32, ScheduleDigest32,
///     SourceIrDigest32,
/// };
///
/// fn swapped_roles(
///     circuit: CircuitDigest32,
///     compiler: CompilerDigest32,
///     source_ir: SourceIrDigest32,
///     schedule: ScheduleDigest32,
///     constants: ConstantsDigest32,
///     input_schema: InputSchemaDigest32,
/// ) {
///     let _ = ActivationCircuitArtifactDigests::new(
///         compiler,
///         circuit,
///         source_ir,
///         schedule,
///         constants,
///         input_schema,
///     );
/// }
/// ```
///
/// ```compile_fail
/// use ed25519_yao::{
///     ActivationCircuitArtifactDigests, CircuitMetrics,
///     DraftExportCircuitManifest, ExportOutputSchema,
/// };
///
/// fn reject_activation_bundle(
///     digests: ActivationCircuitArtifactDigests,
///     output_schema: ExportOutputSchema,
///     metrics: CircuitMetrics,
/// ) {
///     let _ = DraftExportCircuitManifest::new(digests, output_schema, metrics);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationCircuitArtifactDigests(CircuitArtifactDigestsInner);

impl ActivationCircuitArtifactDigests {
    /// Collects validated activation artifact digests by role.
    pub const fn new(
        circuit: CircuitDigest32,
        compiler: CompilerDigest32,
        source_ir: SourceIrDigest32,
        schedule: ScheduleDigest32,
        constants: ConstantsDigest32,
        input_schema: InputSchemaDigest32,
    ) -> Self {
        Self(CircuitArtifactDigestsInner::new(
            circuit,
            compiler,
            source_ir,
            schedule,
            constants,
            input_schema,
        ))
    }

    impl_artifact_digest_accessors!();
}

/// Export-family artifact digests required for deterministic regeneration.
///
/// The complete bundle is accepted only by `DraftExportCircuitManifest`.
///
/// ```compile_fail
/// use ed25519_yao::{
///     ActivationOutputSchema, CircuitMetrics, DraftActivationCircuitManifest,
///     ExportCircuitArtifactDigests,
/// };
///
/// fn reject_export_bundle(
///     digests: ExportCircuitArtifactDigests,
///     output_schema: ActivationOutputSchema,
///     metrics: CircuitMetrics,
/// ) {
///     let _ = DraftActivationCircuitManifest::new(digests, output_schema, metrics);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportCircuitArtifactDigests(CircuitArtifactDigestsInner);

impl ExportCircuitArtifactDigests {
    /// Collects validated export artifact digests by role.
    pub const fn new(
        circuit: CircuitDigest32,
        compiler: CompilerDigest32,
        source_ir: SourceIrDigest32,
        schedule: ScheduleDigest32,
        constants: ConstantsDigest32,
        input_schema: InputSchemaDigest32,
    ) -> Self {
        Self(CircuitArtifactDigestsInner::new(
            circuit,
            compiler,
            source_ir,
            schedule,
            constants,
            input_schema,
        ))
    }

    impl_artifact_digest_accessors!();
}

/// Fixed activation output-schema identity and its validated artifact digest.
///
/// This schema belongs only to activation-family circuits and must contain no
/// seed-export output wires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationOutputSchema {
    digest: ActivationOutputSchemaDigest32,
}

impl ActivationOutputSchema {
    /// Constructs the fixed activation schema around its validated digest.
    pub const fn new(digest: ActivationOutputSchemaDigest32) -> Self {
        Self { digest }
    }

    /// Returns the fixed activation output-schema identifier.
    pub const fn id_str(self) -> &'static str {
        ACTIVATION_OUTPUT_SCHEMA_ID_STR
    }

    /// Returns the activation output-schema artifact digest.
    pub const fn digest(self) -> ActivationOutputSchemaDigest32 {
        self.digest
    }
}

/// Fixed export output-schema identity and its validated artifact digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOutputSchema {
    digest: ExportOutputSchemaDigest32,
}

impl ExportOutputSchema {
    /// Constructs the fixed export schema around its validated digest.
    pub const fn new(digest: ExportOutputSchemaDigest32) -> Self {
        Self { digest }
    }

    /// Returns the fixed export output-schema identifier.
    pub const fn id_str(self) -> &'static str {
        EXPORT_OUTPUT_SCHEMA_ID_STR
    }

    /// Returns the export output-schema artifact digest.
    pub const fn digest(self) -> ExportOutputSchemaDigest32 {
        self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DraftCircuitManifestCore<Digests> {
    digests: Digests,
    metrics: CircuitMetrics,
}

impl<Digests> DraftCircuitManifestCore<Digests> {
    const fn new(digests: Digests, metrics: CircuitMetrics) -> Self {
        Self { digests, metrics }
    }
}

/// Draft manifest for registration, activation, recovery, and refresh derivation.
///
/// Its SHA-256 identity is computed internally from the canonical v1 layout.
/// The crate exposes no promotion into a reviewed or production-active state.
///
/// ```compile_fail
/// use ed25519_yao::{
///     ActivationCircuitArtifactDigests, CircuitMetrics,
///     DraftActivationCircuitManifest, ExportOutputSchema,
/// };
///
/// fn reject_export_schema(
///     digests: ActivationCircuitArtifactDigests,
///     output_schema: ExportOutputSchema,
///     metrics: CircuitMetrics,
/// ) {
///     let _ = DraftActivationCircuitManifest::new(digests, output_schema, metrics);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftActivationCircuitManifest {
    core: DraftCircuitManifestCore<ActivationCircuitArtifactDigests>,
    output_schema: ActivationOutputSchema,
    manifest_digest: DraftActivationManifestDigest32,
}

impl DraftActivationCircuitManifest {
    /// Constructs a draft activation manifest and computes its canonical identity.
    pub fn new(
        digests: ActivationCircuitArtifactDigests,
        output_schema: ActivationOutputSchema,
        metrics: CircuitMetrics,
    ) -> Self {
        let manifest_digest =
            DraftActivationManifestDigest32::from_computed_bytes(compute_draft_manifest_digest(
                ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE,
                digests.0,
                output_schema.id_str(),
                output_schema.digest().as_bytes(),
                metrics,
            ));
        Self {
            core: DraftCircuitManifestCore::new(digests, metrics),
            output_schema,
            manifest_digest,
        }
    }

    /// Returns the activation family.
    pub const fn family(self) -> CircuitFamily {
        CircuitFamily::Activation
    }

    /// Returns the fixed activation circuit identifier.
    pub const fn circuit_id(self) -> CircuitId {
        ACTIVATION_CIRCUIT_ID
    }

    /// Returns the validated activation artifact digests.
    pub const fn digests(self) -> ActivationCircuitArtifactDigests {
        self.core.digests
    }

    /// Returns the fixed activation output schema and its digest.
    pub const fn output_schema(self) -> ActivationOutputSchema {
        self.output_schema
    }

    /// Returns the validated artifact metrics.
    pub const fn metrics(self) -> CircuitMetrics {
        self.core.metrics
    }

    /// Returns the internally computed canonical draft-manifest identity.
    pub const fn manifest_digest(self) -> DraftActivationManifestDigest32 {
        self.manifest_digest
    }
}

/// Draft manifest for explicitly authorized seed export.
///
/// Its SHA-256 identity is computed internally from the canonical v1 layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftExportCircuitManifest {
    core: DraftCircuitManifestCore<ExportCircuitArtifactDigests>,
    output_schema: ExportOutputSchema,
    manifest_digest: DraftExportManifestDigest32,
}

impl DraftExportCircuitManifest {
    /// Constructs a draft export manifest and computes its canonical identity.
    pub fn new(
        digests: ExportCircuitArtifactDigests,
        output_schema: ExportOutputSchema,
        metrics: CircuitMetrics,
    ) -> Self {
        let manifest_digest =
            DraftExportManifestDigest32::from_computed_bytes(compute_draft_manifest_digest(
                EXPORT_DRAFT_MANIFEST_FAMILY_BYTE,
                digests.0,
                output_schema.id_str(),
                output_schema.digest().as_bytes(),
                metrics,
            ));
        Self {
            core: DraftCircuitManifestCore::new(digests, metrics),
            output_schema,
            manifest_digest,
        }
    }

    /// Returns the export family.
    pub const fn family(self) -> CircuitFamily {
        CircuitFamily::Export
    }

    /// Returns the fixed export circuit identifier.
    pub const fn circuit_id(self) -> CircuitId {
        EXPORT_CIRCUIT_ID
    }

    /// Returns the validated export artifact digests.
    pub const fn digests(self) -> ExportCircuitArtifactDigests {
        self.core.digests
    }

    /// Returns the fixed export output schema and its digest.
    pub const fn output_schema(self) -> ExportOutputSchema {
        self.output_schema
    }

    /// Returns the validated artifact metrics.
    pub const fn metrics(self) -> CircuitMetrics {
        self.core.metrics
    }

    /// Returns the internally computed canonical draft-manifest identity.
    pub const fn manifest_digest(self) -> DraftExportManifestDigest32 {
        self.manifest_digest
    }
}

/// Complete draft protocol manifest containing both disjoint circuit families.
///
/// This aggregate remains draft-only. There is no reviewed-active state or
/// runtime security-suite selector in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftProtocolManifest {
    activation: DraftActivationCircuitManifest,
    export: DraftExportCircuitManifest,
}

impl DraftProtocolManifest {
    /// Validates that the draft families use distinct artifacts and schemas.
    pub fn new(
        activation: DraftActivationCircuitManifest,
        export: DraftExportCircuitManifest,
    ) -> ValidationResult<Self> {
        let activation_digests = activation.digests();
        let export_digests = export.digests();
        if activation_digests.circuit().as_bytes() == export_digests.circuit().as_bytes() {
            return Err(ValidationError::DuplicateCircuitDigest);
        }
        if activation_digests.schedule().as_bytes() == export_digests.schedule().as_bytes() {
            return Err(ValidationError::DuplicateScheduleDigest);
        }
        if activation.output_schema().digest().as_bytes()
            == export.output_schema().digest().as_bytes()
        {
            return Err(ValidationError::DuplicateOutputSchemaDigest);
        }
        Ok(Self { activation, export })
    }

    /// Returns the fixed protocol identifier.
    pub const fn protocol_id(self) -> ProtocolId {
        PROTOCOL_ID
    }

    /// Returns the draft activation-family manifest.
    pub const fn activation(self) -> DraftActivationCircuitManifest {
        self.activation
    }

    /// Returns the draft export-family manifest.
    pub const fn export(self) -> DraftExportCircuitManifest {
        self.export
    }
}

fn compute_draft_manifest_digest(
    family_byte: u8,
    digests: CircuitArtifactDigestsInner,
    output_schema_id: &str,
    output_schema_digest: &[u8; 32],
    metrics: CircuitMetrics,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DRAFT_MANIFEST_DIGEST_DOMAIN_V1);
    hasher.update([family_byte]);
    hasher.update((output_schema_id.len() as u64).to_be_bytes());
    hasher.update(output_schema_id.as_bytes());

    hasher.update(digests.circuit.as_bytes());
    hasher.update(digests.compiler.as_bytes());
    hasher.update(digests.source_ir.as_bytes());
    hasher.update(digests.schedule.as_bytes());
    hasher.update(digests.constants.as_bytes());
    hasher.update(digests.input_schema.as_bytes());
    hasher.update(output_schema_digest);

    let gates = metrics.gates();
    hasher.update(gates.and_gate_count().to_be_bytes());
    hasher.update(gates.xor_gate_count().to_be_bytes());
    hasher.update(gates.inversion_gate_count().to_be_bytes());
    hasher.update(gates.total_gate_count().to_be_bytes());
    hasher.update(gates.circuit_depth().to_be_bytes());

    let schedule = metrics.schedule();
    hasher.update(schedule.input_wire_count().to_be_bytes());
    hasher.update(schedule.output_wire_count().to_be_bytes());
    hasher.update(schedule.wire_count().to_be_bytes());
    hasher.update(schedule.scheduled_gate_count().to_be_bytes());
    hasher.update(schedule.peak_live_wire_count().to_be_bytes());
    hasher.update(schedule.encoded_schedule_bytes().to_be_bytes());
    hasher.update(metrics.table_payload_bytes().to_be_bytes());

    hasher.finalize().into()
}
