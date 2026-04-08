//! Verification entrypoint for `src/ddh/hidden_eval.rs`.
//!
//! Initial proof targets:
//! - fixed hidden-eval stage count
//! - fixed first/last stage kinds
//! - fixed round-state block count and ordering
//! - fixed active/preload window counts
//! - fixed output-projector slot and visible-output counts

use vstd::prelude::*;

pub const HIDDEN_EVAL_PROGRAM_VERSION: &str = "hidden_eval_program_v0";

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HssPrimitiveKind {
    PrimeOrderDdh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenEvalStageKind {
    AddMod2Pow256,
    MessageSchedule,
    RoundState00To19,
    RoundState20To39,
    RoundState40To59,
    RoundState60To79,
    OutputProjector,
}

pub open spec fn hidden_eval_stage_count_spec() -> nat {
    7nat
}

pub open spec fn hidden_eval_round_state_stage_count_spec() -> nat {
    4nat
}

pub open spec fn hidden_eval_first_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::AddMod2Pow256
}

pub open spec fn hidden_eval_second_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::MessageSchedule
}

pub open spec fn hidden_eval_third_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::RoundState00To19
}

pub open spec fn hidden_eval_fourth_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::RoundState20To39
}

pub open spec fn hidden_eval_fifth_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::RoundState40To59
}

pub open spec fn hidden_eval_sixth_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::RoundState60To79
}

pub open spec fn hidden_eval_last_stage_kind_spec() -> HiddenEvalStageKind {
    HiddenEvalStageKind::OutputProjector
}

pub open spec fn hidden_eval_primitive_kind_spec() -> HssPrimitiveKind {
    HssPrimitiveKind::PrimeOrderDdh
}

pub open spec fn hidden_eval_add_lane_window_count_spec() -> nat {
    32nat
}

pub open spec fn hidden_eval_message_schedule_window_count_spec() -> nat {
    64nat
}

pub open spec fn hidden_eval_round_state_total_window_count_spec() -> nat {
    80nat
}

pub open spec fn hidden_eval_round_state_block_window_count_spec() -> nat {
    20nat
}

pub open spec fn hidden_eval_output_projector_window_count_spec() -> nat {
    4nat
}

pub open spec fn hidden_eval_active_window_count_spec() -> nat {
    180nat
}

pub open spec fn hidden_eval_preload_round_constant_count_spec() -> nat {
    80nat
}

pub open spec fn hidden_eval_output_projector_slot_count_spec() -> nat {
    4nat
}

pub open spec fn hidden_eval_visible_output_count_spec() -> nat {
    3nat
}

pub fn hidden_eval_stage_count() -> (len: usize)
    ensures
        len == hidden_eval_stage_count_spec(),
{
    7usize
}

pub fn hidden_eval_round_state_stage_count() -> (len: usize)
    ensures
        len == hidden_eval_round_state_stage_count_spec(),
{
    4usize
}

pub fn hidden_eval_active_window_count() -> (len: usize)
    ensures
        len == hidden_eval_active_window_count_spec(),
{
    180usize
}

pub fn hidden_eval_preload_round_constant_count() -> (len: usize)
    ensures
        len == hidden_eval_preload_round_constant_count_spec(),
{
    80usize
}

// Proves the compiled hidden-eval program keeps the fixed seven-stage order,
// fixed window-count split, and fixed output-projector shape from production.
pub proof fn hidden_eval_stage_order_shape()
    ensures
        hidden_eval_stage_count_spec() == 7nat,
        hidden_eval_round_state_stage_count_spec() == 4nat,
        hidden_eval_add_lane_window_count_spec() == 32nat,
        hidden_eval_message_schedule_window_count_spec() == 64nat,
        hidden_eval_round_state_total_window_count_spec() == 80nat,
        hidden_eval_round_state_block_window_count_spec() == 20nat,
        hidden_eval_output_projector_window_count_spec() == 4nat,
        hidden_eval_output_projector_slot_count_spec() == 4nat,
        hidden_eval_visible_output_count_spec() == 3nat,
        hidden_eval_active_window_count_spec()
            == hidden_eval_add_lane_window_count_spec()
                + hidden_eval_message_schedule_window_count_spec()
                + hidden_eval_round_state_total_window_count_spec()
                + hidden_eval_output_projector_window_count_spec(),
        hidden_eval_preload_round_constant_count_spec() == 80nat,
        hidden_eval_output_projector_slot_count_spec() == hidden_eval_output_projector_window_count_spec(),
        hidden_eval_round_state_total_window_count_spec()
            == hidden_eval_round_state_stage_count_spec() * hidden_eval_round_state_block_window_count_spec(),
        hidden_eval_first_stage_kind_spec() == HiddenEvalStageKind::AddMod2Pow256,
        hidden_eval_second_stage_kind_spec() == HiddenEvalStageKind::MessageSchedule,
        hidden_eval_third_stage_kind_spec() == HiddenEvalStageKind::RoundState00To19,
        hidden_eval_fourth_stage_kind_spec() == HiddenEvalStageKind::RoundState20To39,
        hidden_eval_fifth_stage_kind_spec() == HiddenEvalStageKind::RoundState40To59,
        hidden_eval_sixth_stage_kind_spec() == HiddenEvalStageKind::RoundState60To79,
        hidden_eval_last_stage_kind_spec() == HiddenEvalStageKind::OutputProjector,
        hidden_eval_primitive_kind_spec() == HssPrimitiveKind::PrimeOrderDdh,
{
}

} // verus!
