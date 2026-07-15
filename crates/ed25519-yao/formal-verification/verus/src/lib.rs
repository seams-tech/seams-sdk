//! Verus mirror for the currently implemented Ed25519 Yao foundation.
//!
//! This crate covers public identifiers, manifest shape, metric relations,
//! proof-system-neutral provenance dispatch, and two clear-oracle helpers. It
//! contains no Yao protocol-security theorem.

use vstd::prelude::*;

/// Frozen protocol identifier mirrored from the production crate.
pub const PROTOCOL_ID_STR: &str = "router_ab_ed25519_yao_v1";
/// Frozen activation circuit identifier mirrored from the production crate.
pub const ACTIVATION_CIRCUIT_ID_STR: &str = "ed25519_yao_activation_v1";
/// Frozen export circuit identifier mirrored from the production crate.
pub const EXPORT_CIRCUIT_ID_STR: &str = "ed25519_yao_export_v1";
/// Frozen activation output-schema identifier mirrored from production.
pub const ACTIVATION_OUTPUT_SCHEMA_ID_STR: &str = "ed25519_yao_activation_output_schema_v1";
/// Frozen export output-schema identifier mirrored from production.
pub const EXPORT_OUTPUT_SCHEMA_ID_STR: &str = "ed25519_yao_export_output_schema_v1";
/// Canonical draft-manifest digest domain mirrored from production.
pub const DRAFT_MANIFEST_DIGEST_DOMAIN_V1: &[u8] = b"seams:router-ab:ed25519-yao:draft-manifest:v1";
/// Activation manifest preimage byte length mirrored from production.
pub const ACTIVATION_DRAFT_MANIFEST_PREIMAGE_BYTES: usize = 421;
/// Export manifest preimage byte length mirrored from production.
pub const EXPORT_DRAFT_MANIFEST_PREIMAGE_BYTES: usize = 417;
/// Provenance statement domain mirrored from the generator.
pub const PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/role-input-provenance-statement/v1";
/// Provenance pair domain mirrored from the generator.
pub const PROVENANCE_PAIR_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/role-input-provenance-pair/v1";
/// Executable mirror of the generator's RFC 8032 clamp boundary.
pub fn clamp_rfc8032(mut digest_prefix: [u8; 32]) -> [u8; 32] {
    digest_prefix[0] &= 248;
    digest_prefix[31] &= 63;
    digest_prefix[31] |= 64;
    digest_prefix
}

/// Executable mirror of little-endian addition modulo `2^256`.
pub fn wrapping_add_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut carry = 0u16;
    let mut index = 0usize;
    while index < 32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
        index += 1;
    }
    output
}

verus! {

/// Activation manifest family byte mirrored from production.
pub const ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE: u8 = 0x01;
/// Export manifest family byte mirrored from production.
pub const EXPORT_DRAFT_MANIFEST_FAMILY_BYTE: u8 = 0x02;
/// Number of independently typed artifact-digest roles in production.
pub const ARTIFACT_DIGEST_COUNT: usize = 6;
/// Artifact digests plus one family-specific output-schema digest.
pub const MANIFEST_DIGEST_SLOT_COUNT: usize = 7;
/// Gate, schedule, and table-payload scalar metrics in production.
pub const MANIFEST_METRIC_COUNT: usize = 13;
/// Passive Half-Gates table bytes per AND gate mirrored from production.
pub const PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE: u64 = 32;
/// Registration evaluation request tag mirrored from the generator.
pub const PROVENANCE_REGISTRATION_REQUEST_TAG_V1: u8 = 0x01;
/// Reserved activation request tag mirrored from the generator.
pub const PROVENANCE_ACTIVATION_REQUEST_TAG_V1: u8 = 0x02;
/// Recovery evaluation request tag mirrored from the generator.
pub const PROVENANCE_RECOVERY_REQUEST_TAG_V1: u8 = 0x03;
/// Refresh evaluation request tag mirrored from the generator.
pub const PROVENANCE_REFRESH_REQUEST_TAG_V1: u8 = 0x04;
/// Export evaluation request tag mirrored from the generator.
pub const PROVENANCE_EXPORT_REQUEST_TAG_V1: u8 = 0x05;
/// Deriver A provenance role tag mirrored from the generator.
pub const PROVENANCE_DERIVER_A_ROLE_TAG_V1: u8 = 0x01;
/// Deriver B provenance role tag mirrored from the generator.
pub const PROVENANCE_DERIVER_B_ROLE_TAG_V1: u8 = 0x02;

/// Circuit-family marker used by the current draft manifest.
pub enum CircuitFamilyModel {
    /// Seed-excluding activation-family artifacts.
    Activation,
    /// Explicit export-family artifacts.
    Export,
}

/// Typed digest roles in their canonical manifest-preimage order.
pub enum ManifestDigestRoleModel {
    /// Complete circuit artifact.
    Circuit,
    /// Compiler and parameter commitment.
    Compiler,
    /// Canonical source-IR commitment.
    SourceIr,
    /// Compact schedule commitment.
    Schedule,
    /// Embedded constants commitment.
    Constants,
    /// Input-schema commitment.
    InputSchema,
    /// Family-specific output-schema commitment.
    OutputSchema,
}

/// Seven role-typed digest byte sequences bound by one manifest.
pub struct ManifestDigestSlotsModel {
    /// Circuit digest bytes.
    pub circuit: Seq<u8>,
    /// Compiler digest bytes.
    pub compiler: Seq<u8>,
    /// Source-IR digest bytes.
    pub source_ir: Seq<u8>,
    /// Schedule digest bytes.
    pub schedule: Seq<u8>,
    /// Constants digest bytes.
    pub constants: Seq<u8>,
    /// Input-schema digest bytes.
    pub input_schema: Seq<u8>,
    /// Family-specific output-schema digest bytes.
    pub output_schema: Seq<u8>,
}

/// Thirteen scalar fields in canonical manifest order.
pub struct ManifestMetricsModel {
    /// AND-gate count.
    pub and_gate_count: nat,
    /// XOR-gate count.
    pub xor_gate_count: nat,
    /// Inversion-gate count.
    pub inversion_gate_count: nat,
    /// Total gate count.
    pub total_gate_count: nat,
    /// Complete circuit depth.
    pub circuit_depth: nat,
    /// AND depth.
    pub and_depth: nat,
    /// Input-wire count.
    pub input_wire_count: nat,
    /// Output-wire count.
    pub output_wire_count: nat,
    /// Logical wire count.
    pub wire_count: nat,
    /// Scheduled-gate count.
    pub scheduled_gate_count: nat,
    /// Peak live slot count.
    pub peak_live_wire_count: nat,
    /// Encoded schedule bytes.
    pub encoded_schedule_bytes: nat,
    /// Passive Half-Gates table bytes.
    pub table_payload_bytes: nat,
}

/// Lifecycle tag space used by proof-system-neutral provenance statements.
pub enum ProvenanceRequestKindModel {
    /// Registration evaluates the activation family.
    Registration,
    /// Activation consumes packages and has no provenance statement.
    Activation,
    /// Recovery evaluates the activation family.
    Recovery,
    /// Refresh evaluates the activation family.
    Refresh,
    /// Authorized export evaluates the export family.
    Export,
}

/// Frozen tag for one lifecycle kind.
pub open spec fn provenance_request_tag(kind: ProvenanceRequestKindModel) -> u8 {
    match kind {
        ProvenanceRequestKindModel::Registration => PROVENANCE_REGISTRATION_REQUEST_TAG_V1,
        ProvenanceRequestKindModel::Activation => PROVENANCE_ACTIVATION_REQUEST_TAG_V1,
        ProvenanceRequestKindModel::Recovery => PROVENANCE_RECOVERY_REQUEST_TAG_V1,
        ProvenanceRequestKindModel::Refresh => PROVENANCE_REFRESH_REQUEST_TAG_V1,
        ProvenanceRequestKindModel::Export => PROVENANCE_EXPORT_REQUEST_TAG_V1,
    }
}

/// Whether a lifecycle kind may own a Yao provenance statement.
pub open spec fn is_provenance_evaluation_request(kind: ProvenanceRequestKindModel) -> bool {
    match kind {
        ProvenanceRequestKindModel::Activation => false,
        _ => true,
    }
}

/// Circuit family derived from one evaluation request kind.
pub open spec fn provenance_circuit_family(kind: ProvenanceRequestKindModel) -> CircuitFamilyModel {
    match kind {
        ProvenanceRequestKindModel::Registration
        | ProvenanceRequestKindModel::Activation
        | ProvenanceRequestKindModel::Recovery
        | ProvenanceRequestKindModel::Refresh => CircuitFamilyModel::Activation,
        ProvenanceRequestKindModel::Export => CircuitFamilyModel::Export,
    }
}

/// Family discriminator encoded in the canonical manifest preimage.
pub open spec fn family_byte(family: CircuitFamilyModel) -> u8 {
    match family {
        CircuitFamilyModel::Activation => ACTIVATION_DRAFT_MANIFEST_FAMILY_BYTE,
        CircuitFamilyModel::Export => EXPORT_DRAFT_MANIFEST_FAMILY_BYTE,
    }
}

/// Canonical position assigned to each typed digest role.
pub open spec fn manifest_digest_role_position(role: ManifestDigestRoleModel) -> nat {
    match role {
        ManifestDigestRoleModel::Circuit => 0nat,
        ManifestDigestRoleModel::Compiler => 1nat,
        ManifestDigestRoleModel::SourceIr => 2nat,
        ManifestDigestRoleModel::Schedule => 3nat,
        ManifestDigestRoleModel::Constants => 4nat,
        ManifestDigestRoleModel::InputSchema => 5nat,
        ManifestDigestRoleModel::OutputSchema => 6nat,
    }
}

/// Exact-width, nonzero validation relation for every digest role.
pub open spec fn valid_nonzero_digest32(bytes: Seq<u8>) -> bool {
    bytes.len() == 32
        && exists |index: int| 0 <= index < bytes.len() && bytes[index] != 0u8
}

/// Exact draft-manifest domain bytes.
pub open spec fn draft_manifest_domain_bytes() -> Seq<u8> {
    seq![
        115u8, 101u8, 97u8, 109u8, 115u8, 58u8, 114u8, 111u8, 117u8, 116u8,
        101u8, 114u8, 45u8, 97u8, 98u8, 58u8, 101u8, 100u8, 50u8, 53u8, 53u8,
        49u8, 57u8, 45u8, 121u8, 97u8, 111u8, 58u8, 100u8, 114u8, 97u8,
        102u8, 116u8, 45u8, 109u8, 97u8, 110u8, 105u8, 102u8, 101u8, 115u8,
        116u8, 58u8, 118u8, 49u8
    ]
}

/// Exact activation output-schema identifier bytes.
pub open spec fn activation_output_schema_id_bytes() -> Seq<u8> {
    seq![
        101u8, 100u8, 50u8, 53u8, 53u8, 49u8, 57u8, 95u8, 121u8, 97u8, 111u8,
        95u8, 97u8, 99u8, 116u8, 105u8, 118u8, 97u8, 116u8, 105u8, 111u8,
        110u8, 95u8, 111u8, 117u8, 116u8, 112u8, 117u8, 116u8, 95u8, 115u8,
        99u8, 104u8, 101u8, 109u8, 97u8, 95u8, 118u8, 49u8
    ]
}

/// Exact export output-schema identifier bytes.
pub open spec fn export_output_schema_id_bytes() -> Seq<u8> {
    seq![
        101u8, 100u8, 50u8, 53u8, 53u8, 49u8, 57u8, 95u8, 121u8, 97u8, 111u8,
        95u8, 101u8, 120u8, 112u8, 111u8, 114u8, 116u8, 95u8, 111u8, 117u8,
        116u8, 112u8, 117u8, 116u8, 95u8, 115u8, 99u8, 104u8, 101u8, 109u8,
        97u8, 95u8, 118u8, 49u8
    ]
}

/// Canonical BE64 bytes used for schema lengths and all scalar metrics.
pub open spec fn be64_bytes(value: nat) -> Seq<u8>
    recommends value <= 0xffff_ffff_ffff_ffff,
{
    seq![
        (((value / 0x0100_0000_0000_0000) % 256) as u8),
        (((value / 0x0001_0000_0000_0000) % 256) as u8),
        (((value / 0x0000_0100_0000_0000) % 256) as u8),
        (((value / 0x0000_0001_0000_0000) % 256) as u8),
        (((value / 0x0000_0000_0100_0000) % 256) as u8),
        (((value / 0x0000_0000_0001_0000) % 256) as u8),
        (((value / 0x0000_0000_0000_0100) % 256) as u8),
        ((value % 256) as u8)
    ]
}

/// Canonical digest-slot concatenation in production order.
pub open spec fn manifest_digest_bytes(digests: ManifestDigestSlotsModel) -> Seq<u8> {
    digests.circuit
        + digests.compiler
        + digests.source_ir
        + digests.schedule
        + digests.constants
        + digests.input_schema
        + digests.output_schema
}

/// Canonical metric concatenation in production order.
pub open spec fn manifest_metric_bytes(metrics: ManifestMetricsModel) -> Seq<u8> {
    be64_bytes(metrics.and_gate_count)
        + be64_bytes(metrics.xor_gate_count)
        + be64_bytes(metrics.inversion_gate_count)
        + be64_bytes(metrics.total_gate_count)
        + be64_bytes(metrics.circuit_depth)
        + be64_bytes(metrics.and_depth)
        + be64_bytes(metrics.input_wire_count)
        + be64_bytes(metrics.output_wire_count)
        + be64_bytes(metrics.wire_count)
        + be64_bytes(metrics.scheduled_gate_count)
        + be64_bytes(metrics.peak_live_wire_count)
        + be64_bytes(metrics.encoded_schedule_bytes)
        + be64_bytes(metrics.table_payload_bytes)
}

/// Canonical manifest preimage before the trusted SHA-256 boundary.
pub open spec fn canonical_manifest_preimage(
    family: CircuitFamilyModel,
    schema_id: Seq<u8>,
    digests: ManifestDigestSlotsModel,
    metrics: ManifestMetricsModel,
) -> Seq<u8> {
    draft_manifest_domain_bytes()
        + seq![family_byte(family)]
        + be64_bytes(schema_id.len() as nat)
        + schema_id
        + manifest_digest_bytes(digests)
        + manifest_metric_bytes(metrics)
}

/// Number of independently typed artifact digests before the output schema.
pub open spec fn artifact_digest_count() -> nat {
    ARTIFACT_DIGEST_COUNT as nat
}

/// Number of digest slots bound by one family manifest.
pub open spec fn manifest_digest_slot_count() -> nat {
    MANIFEST_DIGEST_SLOT_COUNT as nat
}

/// Number of scalar metric fields bound by one family manifest.
pub open spec fn manifest_metric_count() -> nat {
    MANIFEST_METRIC_COUNT as nat
}

/// Gate-count relation enforced by `GateMetrics`.
pub open spec fn gate_total_is_consistent(
    and_count: nat,
    xor_count: nat,
    inversion_count: nat,
    total_count: nat,
) -> bool {
    and_count + xor_count + inversion_count == total_count
}

/// Gate-depth relation enforced by `GateMetrics`.
pub open spec fn gate_depths_are_consistent(
    and_count: nat,
    total_count: nat,
    circuit_depth: nat,
    and_depth: nat,
) -> bool {
    0nat < and_depth
        && and_depth <= and_count
        && and_depth <= circuit_depth
        && circuit_depth <= total_count
}

/// Input and output counts both refer to wires in the one logical wire set.
pub open spec fn schedule_wire_counts_are_consistent(
    input_count: nat,
    output_count: nat,
    wire_count: nat,
) -> bool {
    input_count <= wire_count && output_count <= wire_count
}

/// Passive Half-Gates table bytes derived from the AND-gate count.
pub open spec fn passive_half_gates_table_payload_bytes(and_count: nat) -> nat {
    and_count * PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE as nat
}

/// Complete validation relation mirrored from the production metric types.
pub open spec fn manifest_metrics_are_valid(metrics: ManifestMetricsModel) -> bool {
    0nat < metrics.and_gate_count
        && 0nat < metrics.xor_gate_count
        && 0nat < metrics.total_gate_count
        && 0nat < metrics.circuit_depth
        && 0nat < metrics.and_depth
        && 0nat < metrics.input_wire_count
        && 0nat < metrics.output_wire_count
        && 0nat < metrics.wire_count
        && 0nat < metrics.scheduled_gate_count
        && 0nat < metrics.peak_live_wire_count
        && 0nat < metrics.encoded_schedule_bytes
        && gate_total_is_consistent(
            metrics.and_gate_count,
            metrics.xor_gate_count,
            metrics.inversion_gate_count,
            metrics.total_gate_count,
        )
        && gate_depths_are_consistent(
            metrics.and_gate_count,
            metrics.total_gate_count,
            metrics.circuit_depth,
            metrics.and_depth,
        )
        && schedule_wire_counts_are_consistent(
            metrics.input_wire_count,
            metrics.output_wire_count,
            metrics.wire_count,
        )
        && metrics.peak_live_wire_count <= metrics.wire_count
        && metrics.scheduled_gate_count == metrics.total_gate_count
        && metrics.table_payload_bytes
            == passive_half_gates_table_payload_bytes(metrics.and_gate_count)
}

/// Executable checked-overflow mirror of the production gate-total relation.
pub fn gate_total_is_consistent_runtime(
    and_count: u64,
    xor_count: u64,
    inversion_count: u64,
    total_count: u64,
) -> (valid: bool)
    ensures valid == gate_total_is_consistent(
        and_count as nat,
        xor_count as nat,
        inversion_count as nat,
        total_count as nat,
    ),
{
    match and_count.checked_add(xor_count) {
        Some(and_xor_count) => match and_xor_count.checked_add(inversion_count) {
            Some(computed) => computed == total_count,
            None => false,
        },
        None => false,
    }
}

/// Circuit-family encodings are disjoint.
pub proof fn family_bytes_are_distinct()
    ensures
        family_byte(CircuitFamilyModel::Activation)
            != family_byte(CircuitFamilyModel::Export),
{
}

/// Distinct digest roles have distinct canonical positions.
pub proof fn manifest_digest_role_positions_are_injective(
    left: ManifestDigestRoleModel,
    right: ManifestDigestRoleModel,
)
    requires left != right,
    ensures manifest_digest_role_position(left) != manifest_digest_role_position(right),
{
}

/// Validated digest bytes have exact width and cannot be all zero.
pub proof fn valid_digest_has_exact_nonzero_shape(bytes: Seq<u8>)
    requires valid_nonzero_digest32(bytes),
    ensures
        bytes.len() == 32,
        exists |index: int| 0 <= index < bytes.len() && bytes[index] != 0u8,
{
}

/// The manifest binds six artifact digests and one family-specific output schema.
pub proof fn manifest_binds_seven_digest_slots()
    ensures
        manifest_digest_slot_count() == artifact_digest_count() + 1nat,
        manifest_digest_slot_count() == 7nat,
{
}

/// The current canonical manifest binds exactly thirteen metric fields.
pub proof fn manifest_binds_thirteen_metrics()
    ensures manifest_metric_count() == 13nat,
{
}

/// A valid gate-total relation determines the declared total.
pub proof fn valid_gate_total_matches_sum(
    and_count: nat,
    xor_count: nat,
    inversion_count: nat,
    total_count: nat,
)
    requires gate_total_is_consistent(and_count, xor_count, inversion_count, total_count),
    ensures total_count == and_count + xor_count + inversion_count,
{
}

/// Valid metric relations retain distinct complete and AND depths, wire references,
/// and the exact passive Half-Gates byte formula.
pub proof fn valid_metric_shape_matches_phase_two_schema(
    and_count: nat,
    total_count: nat,
    circuit_depth: nat,
    and_depth: nat,
    input_count: nat,
    output_count: nat,
    wire_count: nat,
)
    requires
        gate_depths_are_consistent(and_count, total_count, circuit_depth, and_depth),
        schedule_wire_counts_are_consistent(input_count, output_count, wire_count),
    ensures
        and_depth <= circuit_depth,
        and_depth <= and_count,
        input_count <= wire_count,
        output_count <= wire_count,
        passive_half_gates_table_payload_bytes(and_count)
            == and_count * PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE as nat,
{
}

/// The manifest preimage has the exact domain/family/schema/digest/metric order.
pub proof fn canonical_manifest_preimage_order_is_exact(
    family: CircuitFamilyModel,
    schema_id: Seq<u8>,
    digests: ManifestDigestSlotsModel,
    metrics: ManifestMetricsModel,
)
    ensures
        canonical_manifest_preimage(family, schema_id, digests, metrics)
            == draft_manifest_domain_bytes()
                + seq![family_byte(family)]
                + be64_bytes(schema_id.len() as nat)
                + schema_id
                + manifest_digest_bytes(digests)
                + manifest_metric_bytes(metrics),
{
}

/// A valid metric model enforces every production sum, bound, and derived byte relation.
pub proof fn valid_manifest_metrics_enforce_all_relations(metrics: ManifestMetricsModel)
    requires manifest_metrics_are_valid(metrics),
    ensures
        metrics.total_gate_count
            == metrics.and_gate_count + metrics.xor_gate_count + metrics.inversion_gate_count,
        metrics.and_depth <= metrics.and_gate_count,
        metrics.and_depth <= metrics.circuit_depth,
        metrics.circuit_depth <= metrics.total_gate_count,
        metrics.input_wire_count <= metrics.wire_count,
        metrics.output_wire_count <= metrics.wire_count,
        metrics.peak_live_wire_count <= metrics.wire_count,
        metrics.scheduled_gate_count == metrics.total_gate_count,
        metrics.table_payload_bytes
            == metrics.and_gate_count * PASSIVE_HALF_GATES_TABLE_BYTES_PER_AND_GATE as nat,
{
}

/// Activation is structurally excluded from the evaluation-statement space.
pub proof fn activation_has_no_provenance_statement()
    ensures !is_provenance_evaluation_request(ProvenanceRequestKindModel::Activation),
{
}

/// Every valid evaluation request derives the frozen circuit family.
pub proof fn provenance_evaluation_family_mapping_is_exact()
    ensures
        provenance_circuit_family(ProvenanceRequestKindModel::Registration)
            == CircuitFamilyModel::Activation,
        provenance_circuit_family(ProvenanceRequestKindModel::Recovery)
            == CircuitFamilyModel::Activation,
        provenance_circuit_family(ProvenanceRequestKindModel::Refresh)
            == CircuitFamilyModel::Activation,
        provenance_circuit_family(ProvenanceRequestKindModel::Export)
            == CircuitFamilyModel::Export,
{
}

/// The five lifecycle request tags are pairwise distinct.
pub proof fn provenance_request_tags_are_pairwise_distinct()
    ensures
        provenance_request_tag(ProvenanceRequestKindModel::Registration)
            != provenance_request_tag(ProvenanceRequestKindModel::Activation),
        provenance_request_tag(ProvenanceRequestKindModel::Registration)
            != provenance_request_tag(ProvenanceRequestKindModel::Recovery),
        provenance_request_tag(ProvenanceRequestKindModel::Registration)
            != provenance_request_tag(ProvenanceRequestKindModel::Refresh),
        provenance_request_tag(ProvenanceRequestKindModel::Registration)
            != provenance_request_tag(ProvenanceRequestKindModel::Export),
        provenance_request_tag(ProvenanceRequestKindModel::Activation)
            != provenance_request_tag(ProvenanceRequestKindModel::Recovery),
        provenance_request_tag(ProvenanceRequestKindModel::Activation)
            != provenance_request_tag(ProvenanceRequestKindModel::Refresh),
        provenance_request_tag(ProvenanceRequestKindModel::Activation)
            != provenance_request_tag(ProvenanceRequestKindModel::Export),
        provenance_request_tag(ProvenanceRequestKindModel::Recovery)
            != provenance_request_tag(ProvenanceRequestKindModel::Refresh),
        provenance_request_tag(ProvenanceRequestKindModel::Recovery)
            != provenance_request_tag(ProvenanceRequestKindModel::Export),
        provenance_request_tag(ProvenanceRequestKindModel::Refresh)
            != provenance_request_tag(ProvenanceRequestKindModel::Export),
{
}

/// The ordered provenance pair has distinct A-then-B role tags.
pub proof fn provenance_role_order_is_distinct()
    ensures
        PROVENANCE_DERIVER_A_ROLE_TAG_V1 < PROVENANCE_DERIVER_B_ROLE_TAG_V1,
        PROVENANCE_DERIVER_A_ROLE_TAG_V1 != PROVENANCE_DERIVER_B_ROLE_TAG_V1,
{
}

}
