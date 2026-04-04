use serde::{Deserialize, Serialize};

use crate::artifact::prime_order_decoder::{
    PrimeOrderDecodedArtifact, PrimeOrderWindowRecord, PrimeOrderWindowRecordClass,
};
use crate::artifact::prime_order_encoder::PrimeOrderSectionKind;
use crate::shared::{ProtoError, ProtoResult};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderEvaluatorOps {
    pub recoded_scalar_digits: u64,
    pub precomputed_window_bits_loaded: u64,
    pub bucket_accumulations: u64,
    pub bucket_reductions: u64,
    pub accumulator_curve_additions: u64,
    pub dependency_merges: u64,
    pub point_normalizations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderExecutionTrace {
    pub preload_round_constant_count: usize,
    pub preload_context_participant_count: usize,
    pub total_steps: usize,
    pub stage_count: usize,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub estimated_curve_cost_units: u64,
    pub checksum: u64,
    pub stages: Vec<PrimeOrderExecutionStage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderExecutionStage {
    pub label: &'static str,
    pub kind: PrimeOrderExecutionStageKind,
    pub source_kind: PrimeOrderSectionKind,
    pub step_count: usize,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub estimated_curve_cost_units: u64,
    pub steps: Vec<PrimeOrderExecutionStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderExecutionStep {
    pub record_index: u16,
    pub kind: PrimeOrderExecutionStepKind,
    pub source_offset: u32,
    pub logical_span: u16,
    pub dependency_left: Option<u16>,
    pub dependency_right: Option<u16>,
    pub evaluator_ops: PrimeOrderEvaluatorOps,
    pub estimated_curve_cost_units: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeOrderExecutionStageKind {
    AddMod2Pow256,
    MessageSchedule,
    RoundState00To19,
    RoundState20To39,
    RoundState40To59,
    RoundState60To79,
    OutputProjector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeOrderExecutionStepKind {
    AddLane,
    ScheduleDerivedWord,
    RoundState,
    OutputProjector,
}

pub fn build_prime_order_execution_trace(
    decoded: &PrimeOrderDecodedArtifact,
) -> ProtoResult<PrimeOrderExecutionTrace> {
    let mut stages = vec![
        PrimeOrderExecutionStage::empty(
            "add_mod_2pow256",
            PrimeOrderExecutionStageKind::AddMod2Pow256,
            PrimeOrderSectionKind::AddMod2Pow256Template,
        ),
        PrimeOrderExecutionStage::empty(
            "message_schedule",
            PrimeOrderExecutionStageKind::MessageSchedule,
            PrimeOrderSectionKind::MessageScheduleTemplate,
        ),
        PrimeOrderExecutionStage::empty(
            "round_state_00_to_19",
            PrimeOrderExecutionStageKind::RoundState00To19,
            PrimeOrderSectionKind::RoundTemplates00To19,
        ),
        PrimeOrderExecutionStage::empty(
            "round_state_20_to_39",
            PrimeOrderExecutionStageKind::RoundState20To39,
            PrimeOrderSectionKind::RoundTemplates20To39,
        ),
        PrimeOrderExecutionStage::empty(
            "round_state_40_to_59",
            PrimeOrderExecutionStageKind::RoundState40To59,
            PrimeOrderSectionKind::RoundTemplates40To59,
        ),
        PrimeOrderExecutionStage::empty(
            "round_state_60_to_79",
            PrimeOrderExecutionStageKind::RoundState60To79,
            PrimeOrderSectionKind::RoundTemplates60To79,
        ),
        PrimeOrderExecutionStage::empty(
            "output_projector",
            PrimeOrderExecutionStageKind::OutputProjector,
            PrimeOrderSectionKind::OutputProjectorTemplate,
        ),
    ];

    let mut preload_round_constant_count = 0usize;
    let mut preload_context_participant_count = 0usize;

    for record in &decoded.windows.records {
        match record.class {
            PrimeOrderWindowRecordClass::RoundConstant => preload_round_constant_count += 1,
            PrimeOrderWindowRecordClass::ContextParticipant => {
                preload_context_participant_count += 1
            }
            PrimeOrderWindowRecordClass::AddLane => {
                push_step(&mut stages[0], record, PrimeOrderExecutionStepKind::AddLane);
            }
            PrimeOrderWindowRecordClass::ScheduleDerivedWord => {
                push_step(
                    &mut stages[1],
                    record,
                    PrimeOrderExecutionStepKind::ScheduleDerivedWord,
                );
            }
            PrimeOrderWindowRecordClass::RoundState => {
                let stage_idx = match record.source_kind {
                    PrimeOrderSectionKind::RoundTemplates00To19 => 2,
                    PrimeOrderSectionKind::RoundTemplates20To39 => 3,
                    PrimeOrderSectionKind::RoundTemplates40To59 => 4,
                    PrimeOrderSectionKind::RoundTemplates60To79 => 5,
                    other => {
                        return Err(ProtoError::Decode(format!(
                            "round-state record mapped to unexpected section {}",
                            other.as_str()
                        )))
                    }
                };
                push_step(
                    &mut stages[stage_idx],
                    record,
                    PrimeOrderExecutionStepKind::RoundState,
                );
            }
            PrimeOrderWindowRecordClass::OutputProjector => {
                push_step(
                    &mut stages[6],
                    record,
                    PrimeOrderExecutionStepKind::OutputProjector,
                );
            }
        }
    }

    let total_steps = stages.iter().map(|stage| stage.step_count).sum::<usize>();
    let mut evaluator_ops = PrimeOrderEvaluatorOps::default();
    let mut estimated_curve_cost_units = 0u64;
    let checksum = stages.iter().fold(0u64, |acc, stage| {
        evaluator_ops.accumulate(&stage.evaluator_ops);
        estimated_curve_cost_units += stage.estimated_curve_cost_units;
        acc.wrapping_add(stage.steps.iter().fold(0u64, |inner, step| {
            inner
                .wrapping_add(u64::from(step.record_index))
                .wrapping_add(step.estimated_curve_cost_units)
                .wrapping_add(u64::from(step.logical_span))
                .wrapping_add(u64::from(step.source_offset))
                .wrapping_add(u64::from(step.dependency_left.unwrap_or(u16::MAX)))
                .wrapping_add(u64::from(step.dependency_right.unwrap_or(u16::MAX)))
        }))
    });

    Ok(PrimeOrderExecutionTrace {
        preload_round_constant_count,
        preload_context_participant_count,
        total_steps,
        stage_count: stages.len(),
        evaluator_ops,
        estimated_curve_cost_units,
        checksum,
        stages,
    })
}

fn push_step(
    stage: &mut PrimeOrderExecutionStage,
    record: &PrimeOrderWindowRecord,
    kind: PrimeOrderExecutionStepKind,
) {
    let evaluator_ops = evaluator_ops_for_record(record);
    let estimated_curve_cost_units = evaluator_ops.estimated_curve_cost_units();
    stage.steps.push(PrimeOrderExecutionStep {
        record_index: record.index,
        kind,
        source_offset: record.source_offset,
        logical_span: record.logical_span,
        dependency_left: record.dependency_left,
        dependency_right: record.dependency_right,
        evaluator_ops: evaluator_ops.clone(),
        estimated_curve_cost_units,
    });
    stage.step_count += 1;
    stage.evaluator_ops.accumulate(&evaluator_ops);
    stage.estimated_curve_cost_units += estimated_curve_cost_units;
}

fn evaluator_ops_for_record(record: &PrimeOrderWindowRecord) -> PrimeOrderEvaluatorOps {
    let digit_count = u64::from(record.digit_count);
    let window_bits = u64::from(record.window_bits);
    let bucket_count = u64::from(record.bucket_count);
    let dependency_count = dependency_count(record);
    let bucket_reductions = bucket_count.saturating_sub(1);

    match record.class {
        PrimeOrderWindowRecordClass::AddLane => PrimeOrderEvaluatorOps {
            recoded_scalar_digits: digit_count,
            precomputed_window_bits_loaded: window_bits * digit_count,
            bucket_accumulations: digit_count,
            bucket_reductions,
            accumulator_curve_additions: 1,
            dependency_merges: 0,
            point_normalizations: 1,
        },
        PrimeOrderWindowRecordClass::ScheduleDerivedWord => PrimeOrderEvaluatorOps {
            recoded_scalar_digits: digit_count + dependency_count,
            precomputed_window_bits_loaded: window_bits * digit_count,
            bucket_accumulations: digit_count + dependency_count,
            bucket_reductions,
            accumulator_curve_additions: 1 + dependency_count,
            dependency_merges: dependency_count,
            point_normalizations: 1,
        },
        PrimeOrderWindowRecordClass::RoundState => PrimeOrderEvaluatorOps {
            recoded_scalar_digits: digit_count + dependency_count * 2,
            precomputed_window_bits_loaded: window_bits * (digit_count + dependency_count),
            bucket_accumulations: bucket_count + dependency_count,
            bucket_reductions,
            accumulator_curve_additions: 2 + dependency_count * 2,
            dependency_merges: dependency_count * 2,
            point_normalizations: 1,
        },
        PrimeOrderWindowRecordClass::OutputProjector => PrimeOrderEvaluatorOps {
            recoded_scalar_digits: digit_count,
            precomputed_window_bits_loaded: window_bits * digit_count,
            bucket_accumulations: bucket_count,
            bucket_reductions,
            accumulator_curve_additions: 2,
            dependency_merges: 0,
            point_normalizations: 2,
        },
        PrimeOrderWindowRecordClass::RoundConstant
        | PrimeOrderWindowRecordClass::ContextParticipant => PrimeOrderEvaluatorOps::default(),
    }
}

fn dependency_count(record: &PrimeOrderWindowRecord) -> u64 {
    u64::from(record.dependency_left.is_some()) + u64::from(record.dependency_right.is_some())
}

impl PrimeOrderEvaluatorOps {
    pub fn estimated_curve_cost_units(&self) -> u64 {
        self.recoded_scalar_digits * 2
            + self.precomputed_window_bits_loaded
            + self.bucket_accumulations * 4
            + self.bucket_reductions * 5
            + self.accumulator_curve_additions * 8
            + self.dependency_merges * 6
            + self.point_normalizations * 12
    }

    fn accumulate(&mut self, other: &Self) {
        self.recoded_scalar_digits += other.recoded_scalar_digits;
        self.precomputed_window_bits_loaded += other.precomputed_window_bits_loaded;
        self.bucket_accumulations += other.bucket_accumulations;
        self.bucket_reductions += other.bucket_reductions;
        self.accumulator_curve_additions += other.accumulator_curve_additions;
        self.dependency_merges += other.dependency_merges;
        self.point_normalizations += other.point_normalizations;
    }
}

impl PrimeOrderExecutionStage {
    fn empty(
        label: &'static str,
        kind: PrimeOrderExecutionStageKind,
        source_kind: PrimeOrderSectionKind,
    ) -> Self {
        Self {
            label,
            kind,
            source_kind,
            step_count: 0,
            evaluator_ops: PrimeOrderEvaluatorOps::default(),
            estimated_curve_cost_units: 0,
            steps: Vec::new(),
        }
    }
}
