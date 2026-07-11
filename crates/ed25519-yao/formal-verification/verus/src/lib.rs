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
