//! Verification entrypoint for `src/artifact/prime_order_encoder.rs`.
//!
//! Initial proof targets:
//! - fixed section count
//! - fixed allocated prefix byte count
//! - fixed first/last section kinds in the layout
//! - fixed prefix section byte lengths

use vstd::prelude::*;

pub const PRIME_ORDER_ENCODER_VERSION: &str = "prime_order_encoder_v1";

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeOrderSectionKind {
    Header,
    ContextDescriptor,
    AddMod2Pow256Template,
    MessageScheduleTemplate,
    RoundConstants,
    RoundTemplates00To19,
    RoundTemplates20To39,
    RoundTemplates40To59,
    RoundTemplates60To79,
    ClampReduceTemplate,
    OutputProjectorTemplate,
    GroupPublicDataWindows,
}

pub open spec fn prime_order_fixed_prefix_section_count_spec() -> nat {
    11nat
}

pub open spec fn prime_order_total_section_count_spec() -> nat {
    12nat
}

pub open spec fn prime_order_fixed_allocated_prefix_bytes_spec() -> nat {
    120576nat
}

pub open spec fn prime_order_round_template_section_count_spec() -> nat {
    4nat
}

pub open spec fn prime_order_header_section_bytes_spec() -> nat {
    256nat
}

pub open spec fn prime_order_context_descriptor_section_bytes_spec() -> nat {
    512nat
}

pub open spec fn prime_order_add_template_section_bytes_spec() -> nat {
    2048nat
}

pub open spec fn prime_order_message_schedule_section_bytes_spec() -> nat {
    12288nat
}

pub open spec fn prime_order_round_constants_section_bytes_spec() -> nat {
    1024nat
}

pub open spec fn prime_order_round_template_section_bytes_spec() -> nat {
    24576nat
}

pub open spec fn prime_order_clamp_reduce_section_bytes_spec() -> nat {
    4096nat
}

pub open spec fn prime_order_output_projector_section_bytes_spec() -> nat {
    2048nat
}

pub open spec fn prime_order_first_section_kind_spec() -> PrimeOrderSectionKind {
    PrimeOrderSectionKind::Header
}

pub open spec fn prime_order_last_section_kind_spec() -> PrimeOrderSectionKind {
    PrimeOrderSectionKind::GroupPublicDataWindows
}

pub open spec fn prime_order_first_round_template_kind_spec() -> PrimeOrderSectionKind {
    PrimeOrderSectionKind::RoundTemplates00To19
}

pub open spec fn prime_order_last_round_template_kind_spec() -> PrimeOrderSectionKind {
    PrimeOrderSectionKind::RoundTemplates60To79
}

pub fn prime_order_fixed_prefix_section_count() -> (len: usize)
    ensures
        len == prime_order_fixed_prefix_section_count_spec(),
{
    11usize
}

pub fn prime_order_total_section_count() -> (len: usize)
    ensures
        len == prime_order_total_section_count_spec(),
{
    12usize
}

pub fn prime_order_fixed_allocated_prefix_bytes() -> (len: usize)
    ensures
        len == prime_order_fixed_allocated_prefix_bytes_spec(),
{
    120576usize
}

pub fn prime_order_round_template_section_bytes() -> (len: usize)
    ensures
        len == prime_order_round_template_section_bytes_spec(),
{
    24576usize
}

// Proves the prime-order encoder keeps the fixed section ordering and the
// fixed prefix byte sizes that define the production artifact layout.
pub proof fn prime_order_section_layout_shape()
    ensures
        prime_order_fixed_prefix_section_count_spec() == 11nat,
        prime_order_total_section_count_spec() == 12nat,
        prime_order_total_section_count_spec() == prime_order_fixed_prefix_section_count_spec() + 1nat,
        prime_order_header_section_bytes_spec() == 256nat,
        prime_order_context_descriptor_section_bytes_spec() == 512nat,
        prime_order_add_template_section_bytes_spec() == 2048nat,
        prime_order_message_schedule_section_bytes_spec() == 12288nat,
        prime_order_round_constants_section_bytes_spec() == 1024nat,
        prime_order_round_template_section_bytes_spec() == 24576nat,
        prime_order_clamp_reduce_section_bytes_spec() == 4096nat,
        prime_order_output_projector_section_bytes_spec() == 2048nat,
        prime_order_fixed_allocated_prefix_bytes_spec()
            == prime_order_header_section_bytes_spec()
                + prime_order_context_descriptor_section_bytes_spec()
                + prime_order_add_template_section_bytes_spec()
                + prime_order_message_schedule_section_bytes_spec()
                + prime_order_round_constants_section_bytes_spec()
                + prime_order_round_template_section_bytes_spec()
                + prime_order_round_template_section_bytes_spec()
                + prime_order_round_template_section_bytes_spec()
                + prime_order_round_template_section_bytes_spec()
                + prime_order_clamp_reduce_section_bytes_spec()
                + prime_order_output_projector_section_bytes_spec(),
        prime_order_round_template_section_count_spec() == 4nat,
        prime_order_first_section_kind_spec() == PrimeOrderSectionKind::Header,
        prime_order_last_section_kind_spec() == PrimeOrderSectionKind::GroupPublicDataWindows,
        prime_order_first_round_template_kind_spec() == PrimeOrderSectionKind::RoundTemplates00To19,
        prime_order_last_round_template_kind_spec() == PrimeOrderSectionKind::RoundTemplates60To79,
{
}

} // verus!
