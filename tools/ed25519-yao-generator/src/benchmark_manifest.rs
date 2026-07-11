//! Canonical generator-owned manifest for provisional benchmark artifacts.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    build_provisional_artifact_bundle_v1, compile_fixed_sha512_32_v1,
    compile_provisional_activation_core_v1, compile_provisional_export_core_v1,
    BooleanCircuitMetricsV1, ProvisionalScheduleMetricsV1, FIXED_SHA512_32_BIT_ORDER_V1,
    FIXED_SHA512_32_INPUT_SCHEMA_V1, FIXED_SHA512_32_OUTPUT_SCHEMA_V1,
    PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1, PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1,
    PROVISIONAL_ARTIFACT_ACTIVATION_IR_FILE_V1, PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1,
    PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1, PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1,
    PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1, PROVISIONAL_ARTIFACT_SHA512_IR_FILE_V1,
    PROVISIONAL_ARTIFACT_SHA512_SCHEDULE_FILE_V1, PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1,
    PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1,
};

/// Magic prefix for the canonical provisional benchmark manifest.
pub const PROVISIONAL_BENCHMARK_MANIFEST_MAGIC_V1: &[u8; 8] = b"EYAOBM01";
/// Manual compiler-contract identifier changed only by reviewed compiler semantics.
pub const PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1: &str =
    "seams/router-ab/ed25519-yao/provisional-benchmark/compiler/rust-boolean-ir/v1";
/// Exact topological wire-order contract shared by all three components.
pub const PROVISIONAL_BENCHMARK_WIRE_ORDER_V1: &str =
    "inputs-consecutive;gate-output=input-count+gate-index;outputs-ordered;commutative-operands-ascending";
/// Digest domain for one canonical provisional benchmark manifest.
pub const PROVISIONAL_BENCHMARK_MANIFEST_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provisional-benchmark/manifest-digest/v1";
/// Frozen byte length of the current Phase 2B candidate manifest.
pub const PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_BYTES_V1: usize = 1_973;
/// Frozen digest of the current Phase 2B candidate manifest.
pub const PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_DIGEST_V1: [u8; 32] = [
    0xc9, 0xc9, 0x69, 0xfd, 0x23, 0x99, 0x85, 0x09, 0xae, 0x07, 0xf0, 0x4f, 0xdc, 0x99, 0x82, 0xe2,
    0xf3, 0xb5, 0xb2, 0x1a, 0xa9, 0x2a, 0xac, 0x9c, 0xf6, 0x2d, 0xb5, 0xed, 0x2f, 0x0c, 0xce, 0x81,
];

const PROVISIONAL_BENCHMARK_MANIFEST_VERSION_V1: u16 = 1;
const BENCHMARK_ONLY_STATUS_TAG_V1: u8 = 1;
const BYTE_MAJOR_LSB0_TAG_V1: u8 = 1;
const COMPONENT_COUNT_V1: u8 = 3;
const SHA512_COMPONENT_TAG_V1: u8 = 0x81;
const ACTIVATION_COMPONENT_TAG_V1: u8 = 0x91;
const EXPORT_COMPONENT_TAG_V1: u8 = 0x92;
const PASSIVE_HALF_GATES_BYTES_PER_AND_V1: u64 = 32;

/// SHA-256 identity of the exact canonical benchmark-manifest bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProvisionalBenchmarkManifestDigest32V1([u8; 32]);

impl ProvisionalBenchmarkManifestDigest32V1 {
    /// Returns the exact public digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One compiler-derived benchmark component with no production conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalBenchmarkManifestComponentV1 {
    component_tag: u8,
    ir_filename: &'static str,
    schedule_filename: &'static str,
    input_schema: &'static str,
    output_schema: &'static str,
    ir_digest: [u8; 32],
    schedule_digest: [u8; 32],
    circuit_metrics: BooleanCircuitMetricsV1,
    schedule_metrics: ProvisionalScheduleMetricsV1,
    passive_half_gates_table_bytes: u64,
}

impl ProvisionalBenchmarkManifestComponentV1 {
    /// Returns the fixed component tag encoded in IR and schedule artifacts.
    pub const fn component_tag(&self) -> u8 {
        self.component_tag
    }

    /// Returns the fixed canonical IR filename.
    pub const fn ir_filename(&self) -> &'static str {
        self.ir_filename
    }

    /// Returns the fixed canonical schedule filename.
    pub const fn schedule_filename(&self) -> &'static str {
        self.schedule_filename
    }

    /// Returns the exact input-schema bytes hashed by the IR header.
    pub const fn input_schema(&self) -> &'static str {
        self.input_schema
    }

    /// Returns the exact output-schema bytes hashed by the IR header.
    pub const fn output_schema(&self) -> &'static str {
        self.output_schema
    }

    /// Returns the complete canonical IR digest.
    pub const fn ir_digest(&self) -> &[u8; 32] {
        &self.ir_digest
    }

    /// Returns the canonical liveness-schedule digest.
    pub const fn schedule_digest(&self) -> &[u8; 32] {
        &self.schedule_digest
    }

    /// Returns compiler-derived Boolean circuit counts.
    pub const fn circuit_metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit_metrics
    }

    /// Returns compiler-derived liveness-schedule counts.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule_metrics
    }

    /// Returns the exact passive Half-Gates table-byte estimate.
    pub const fn passive_half_gates_table_bytes(&self) -> u64 {
        self.passive_half_gates_table_bytes
    }
}

/// Complete canonical benchmark-only manifest derived without caller artifacts.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionalBenchmarkManifestV1 {
    bundle_index_digest: [u8; 32],
    bundle_index_bytes: u64,
    components: [ProvisionalBenchmarkManifestComponentV1; COMPONENT_COUNT_V1 as usize],
    canonical_encoding: Vec<u8>,
    digest: ProvisionalBenchmarkManifestDigest32V1,
}

impl ProvisionalBenchmarkManifestV1 {
    /// Returns the exact Phase 2A bundle-index digest wrapped by this manifest.
    pub const fn bundle_index_digest(&self) -> &[u8; 32] {
        &self.bundle_index_digest
    }

    /// Returns the exact Phase 2A bundle-index byte length.
    pub const fn bundle_index_bytes(&self) -> u64 {
        self.bundle_index_bytes
    }

    /// Returns the three fixed components in SHA, activation, export order.
    pub fn components(
        &self,
    ) -> impl ExactSizeIterator<Item = &ProvisionalBenchmarkManifestComponentV1> {
        self.components.iter()
    }

    /// Returns the exact canonical benchmark-manifest bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        &self.canonical_encoding
    }

    /// Returns the domain-separated manifest digest.
    pub const fn digest(&self) -> ProvisionalBenchmarkManifestDigest32V1 {
        self.digest
    }

    /// Strictly accepts only the exact manifest regenerated by this compiler contract.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ProvisionalBenchmarkManifestErrorV1> {
        validate_manifest_prefix(bytes)?;
        let expected = build_provisional_benchmark_manifest_v1();
        if bytes != expected.canonical_encoding {
            return Err(ProvisionalBenchmarkManifestErrorV1::NoncanonicalManifest);
        }
        Ok(expected)
    }
}

impl fmt::Debug for ProvisionalBenchmarkManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionalBenchmarkManifestV1")
            .field("status", &"benchmark-only")
            .field("bundle_index_digest", &"[computed SHA-256]")
            .field("components", &self.components)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Rejection from the strict canonical benchmark-manifest boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionalBenchmarkManifestErrorV1 {
    /// The manifest is shorter than its fixed prefix.
    Truncated,
    /// The magic prefix does not identify the benchmark-only format.
    WrongMagic,
    /// The format version is unknown or stale.
    WrongVersion,
    /// The status byte is not the benchmark-only status.
    WrongStatus,
    /// The manifest differs from exact compiler regeneration.
    NoncanonicalManifest,
}

impl fmt::Display for ProvisionalBenchmarkManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "provisional benchmark manifest is truncated",
            Self::WrongMagic => "provisional benchmark manifest magic mismatch",
            Self::WrongVersion => "provisional benchmark manifest version mismatch",
            Self::WrongStatus => "manifest is not explicitly benchmark-only",
            Self::NoncanonicalManifest => "manifest differs from canonical compiler output",
        })
    }
}

impl std::error::Error for ProvisionalBenchmarkManifestErrorV1 {}

/// Compiles the three fixed components and derives their benchmark-only manifest.
pub fn build_provisional_benchmark_manifest_v1() -> ProvisionalBenchmarkManifestV1 {
    let bundle = build_provisional_artifact_bundle_v1();
    let sha = compile_fixed_sha512_32_v1();
    let activation = compile_provisional_activation_core_v1();
    let export = compile_provisional_export_core_v1();
    let components = [
        component(
            SHA512_COMPONENT_TAG_V1,
            PROVISIONAL_ARTIFACT_SHA512_IR_FILE_V1,
            PROVISIONAL_ARTIFACT_SHA512_SCHEDULE_FILE_V1,
            FIXED_SHA512_32_INPUT_SCHEMA_V1,
            FIXED_SHA512_32_OUTPUT_SCHEMA_V1,
            sha.benchmark_component_digest().expose_public_bytes(),
            sha.benchmark_schedule_digest().expose_public_bytes(),
            sha.metrics(),
            sha.schedule_metrics(),
        ),
        component(
            ACTIVATION_COMPONENT_TAG_V1,
            PROVISIONAL_ARTIFACT_ACTIVATION_IR_FILE_V1,
            PROVISIONAL_ARTIFACT_ACTIVATION_SCHEDULE_FILE_V1,
            PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1,
            PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1,
            activation
                .benchmark_component_digest()
                .expose_public_bytes(),
            activation.benchmark_schedule_digest().expose_public_bytes(),
            activation.metrics(),
            activation.schedule_metrics(),
        ),
        component(
            EXPORT_COMPONENT_TAG_V1,
            PROVISIONAL_ARTIFACT_EXPORT_IR_FILE_V1,
            PROVISIONAL_ARTIFACT_EXPORT_SCHEDULE_FILE_V1,
            PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1,
            PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1,
            export.benchmark_component_digest().expose_public_bytes(),
            export.benchmark_schedule_digest().expose_public_bytes(),
            export.metrics(),
            export.schedule_metrics(),
        ),
    ];
    let bundle_index_digest = bundle.digest().expose_public_bytes();
    let bundle_index_bytes =
        u64::try_from(bundle.canonical_index().len()).expect("fixed bundle index fits u64");
    let canonical_encoding = encode_manifest(bundle_index_digest, bundle_index_bytes, &components);
    let mut digest_input = Vec::new();
    push_lp32(
        &mut digest_input,
        PROVISIONAL_BENCHMARK_MANIFEST_DIGEST_DOMAIN_V1,
    );
    push_lp32(&mut digest_input, &canonical_encoding);
    ProvisionalBenchmarkManifestV1 {
        bundle_index_digest,
        bundle_index_bytes,
        components,
        digest: ProvisionalBenchmarkManifestDigest32V1(Sha256::digest(digest_input).into()),
        canonical_encoding,
    }
}

#[allow(clippy::too_many_arguments)]
fn component(
    component_tag: u8,
    ir_filename: &'static str,
    schedule_filename: &'static str,
    input_schema: &'static str,
    output_schema: &'static str,
    ir_digest: [u8; 32],
    schedule_digest: [u8; 32],
    circuit_metrics: BooleanCircuitMetricsV1,
    schedule_metrics: ProvisionalScheduleMetricsV1,
) -> ProvisionalBenchmarkManifestComponentV1 {
    let passive_half_gates_table_bytes = circuit_metrics
        .and_gate_count()
        .checked_mul(PASSIVE_HALF_GATES_BYTES_PER_AND_V1)
        .expect("fixed benchmark AND count fits u64 table estimate");
    ProvisionalBenchmarkManifestComponentV1 {
        component_tag,
        ir_filename,
        schedule_filename,
        input_schema,
        output_schema,
        ir_digest,
        schedule_digest,
        circuit_metrics,
        schedule_metrics,
        passive_half_gates_table_bytes,
    }
}

fn encode_manifest(
    bundle_index_digest: [u8; 32],
    bundle_index_bytes: u64,
    components: &[ProvisionalBenchmarkManifestComponentV1; COMPONENT_COUNT_V1 as usize],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(PROVISIONAL_BENCHMARK_MANIFEST_MAGIC_V1);
    output.extend_from_slice(&PROVISIONAL_BENCHMARK_MANIFEST_VERSION_V1.to_be_bytes());
    output.push(BENCHMARK_ONLY_STATUS_TAG_V1);
    output.push(BYTE_MAJOR_LSB0_TAG_V1);
    push_lp32(
        &mut output,
        PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1.as_bytes(),
    );
    push_lp32(&mut output, FIXED_SHA512_32_BIT_ORDER_V1.as_bytes());
    push_lp32(&mut output, PROVISIONAL_BENCHMARK_WIRE_ORDER_V1.as_bytes());
    push_lp32(
        &mut output,
        PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1.as_bytes(),
    );
    output.extend_from_slice(&bundle_index_bytes.to_be_bytes());
    output.extend_from_slice(&bundle_index_digest);
    output.push(COMPONENT_COUNT_V1);
    for component in components {
        output.push(component.component_tag);
        push_lp32(&mut output, component.ir_filename.as_bytes());
        push_lp32(&mut output, component.schedule_filename.as_bytes());
        push_lp32(&mut output, component.input_schema.as_bytes());
        push_lp32(&mut output, component.output_schema.as_bytes());
        output.extend_from_slice(&component.ir_digest);
        output.extend_from_slice(&component.schedule_digest);
        encode_circuit_metrics(&mut output, component.circuit_metrics);
        encode_schedule_metrics(&mut output, component.schedule_metrics);
        output.extend_from_slice(&component.passive_half_gates_table_bytes.to_be_bytes());
    }
    output
}

fn encode_circuit_metrics(output: &mut Vec<u8>, metrics: BooleanCircuitMetricsV1) {
    for value in [
        metrics.input_wire_count(),
        metrics.output_wire_count(),
        metrics.wire_count(),
        metrics.and_gate_count(),
        metrics.xor_gate_count(),
        metrics.inversion_gate_count(),
        metrics.total_gate_count(),
        metrics.circuit_depth(),
        metrics.and_depth(),
        metrics.canonical_encoding_bytes(),
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_schedule_metrics(output: &mut Vec<u8>, metrics: ProvisionalScheduleMetricsV1) {
    for value in [
        metrics.input_wire_count(),
        metrics.output_wire_count(),
        metrics.scheduled_gate_count(),
        metrics.reusable_slot_count(),
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    output.push(metrics.slot_width_bytes());
    output.push(metrics.gate_record_width_bytes());
    output.extend_from_slice(&metrics.encoded_schedule_bytes().to_be_bytes());
}

fn validate_manifest_prefix(bytes: &[u8]) -> Result<(), ProvisionalBenchmarkManifestErrorV1> {
    if bytes.len() < 12 {
        return Err(ProvisionalBenchmarkManifestErrorV1::Truncated);
    }
    if &bytes[..8] != PROVISIONAL_BENCHMARK_MANIFEST_MAGIC_V1 {
        return Err(ProvisionalBenchmarkManifestErrorV1::WrongMagic);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != PROVISIONAL_BENCHMARK_MANIFEST_VERSION_V1 {
        return Err(ProvisionalBenchmarkManifestErrorV1::WrongVersion);
    }
    if bytes[10] != BENCHMARK_ONLY_STATUS_TAG_V1 {
        return Err(ProvisionalBenchmarkManifestErrorV1::WrongStatus);
    }
    Ok(())
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("fixed benchmark manifest field fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_manifest_round_trips_and_is_deterministic() {
        let first = build_provisional_benchmark_manifest_v1();
        let second = build_provisional_benchmark_manifest_v1();
        assert_eq!(first, second);
        assert_eq!(
            ProvisionalBenchmarkManifestV1::parse_canonical(first.canonical_encoding()),
            Ok(first)
        );
        assert_eq!(
            second.canonical_encoding().len(),
            PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_BYTES_V1
        );
        assert_eq!(
            second.digest().as_bytes(),
            &PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_DIGEST_V1
        );
    }

    #[test]
    fn component_order_and_artifact_names_are_fixed() {
        let manifest = build_provisional_benchmark_manifest_v1();
        let components = manifest.components().collect::<Vec<_>>();
        assert_eq!(
            components
                .iter()
                .map(|component| component.component_tag())
                .collect::<Vec<_>>(),
            [0x81, 0x91, 0x92]
        );
        assert_eq!(components[1].ir_filename(), "activation.ir.bin");
        assert_eq!(components[2].schedule_filename(), "export.schedule.bin");
        let bundle = build_provisional_artifact_bundle_v1();
        assert_eq!(
            manifest.bundle_index_digest(),
            &bundle.digest().expose_public_bytes()
        );
        assert_eq!(
            manifest.bundle_index_bytes(),
            bundle.canonical_index().len() as u64
        );
    }

    #[test]
    fn manifest_binds_exact_schemas_and_bit_wire_order() {
        let manifest = build_provisional_benchmark_manifest_v1();
        let bytes = manifest.canonical_encoding();
        assert!(contains(bytes, FIXED_SHA512_32_BIT_ORDER_V1.as_bytes()));
        assert!(contains(
            bytes,
            PROVISIONAL_BENCHMARK_WIRE_ORDER_V1.as_bytes()
        ));
        for component in manifest.components() {
            assert!(contains(bytes, component.input_schema().as_bytes()));
            assert!(contains(bytes, component.output_schema().as_bytes()));
        }
    }

    #[test]
    fn passive_table_counts_are_derived_from_and_gates() {
        let manifest = build_provisional_benchmark_manifest_v1();
        for component in manifest.components() {
            assert_eq!(
                component.passive_half_gates_table_bytes(),
                32 * component.circuit_metrics().and_gate_count()
            );
            assert_eq!(
                component.schedule_metrics().scheduled_gate_count(),
                component.circuit_metrics().total_gate_count()
            );
        }
    }

    #[test]
    fn unknown_stale_and_mutated_manifests_fail_closed() {
        let manifest = build_provisional_benchmark_manifest_v1();
        let mut wrong_magic = manifest.canonical_encoding().to_vec();
        wrong_magic[0] ^= 1;
        assert_eq!(
            ProvisionalBenchmarkManifestV1::parse_canonical(&wrong_magic),
            Err(ProvisionalBenchmarkManifestErrorV1::WrongMagic)
        );
        let mut stale = manifest.canonical_encoding().to_vec();
        stale[9] = 2;
        assert_eq!(
            ProvisionalBenchmarkManifestV1::parse_canonical(&stale),
            Err(ProvisionalBenchmarkManifestErrorV1::WrongVersion)
        );
        let mut mutated = manifest.canonical_encoding().to_vec();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert_eq!(
            ProvisionalBenchmarkManifestV1::parse_canonical(&mutated),
            Err(ProvisionalBenchmarkManifestErrorV1::NoncanonicalManifest)
        );
    }

    #[test]
    fn manifest_has_no_production_promotion_surface() {
        let source = include_str!("benchmark_manifest.rs");
        assert!(!source.contains(concat!("Reviewed", "Active")));
        assert!(!source.contains(concat!("Production", "Manifest")));
        assert!(!source.contains(concat!("security", "_profile")));
        assert!(!source.contains(concat!("from", "_artifact")));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
