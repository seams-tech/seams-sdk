use serde::{Deserialize, Serialize};

use crate::candidate::CandidateBackendFamily;
use crate::prime_order_decoder::{
    PrimeOrderDecodedArtifact, PrimeOrderWindowRecord, PrimeOrderWindowRecordClass,
};
use crate::prime_order_encoder::PrimeOrderSectionKind;
use crate::{ProtoError, ProtoResult};

pub const HIDDEN_EVAL_PROGRAM_VERSION: &str = "hidden_eval_program_v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HssPrimitiveKind {
    PrimeOrderDdh,
    LatticeRlwe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HiddenEvalInputOwner {
    Client,
    Server,
    Derived,
}

pub trait FixedFunctionHssBackend {
    type SharedValue;

    fn primitive_kind(&self) -> HssPrimitiveKind;
    fn share_input(
        &self,
        owner: HiddenEvalInputOwner,
        label: &str,
        input: &[u8],
    ) -> ProtoResult<Vec<Self::SharedValue>>;
    fn eval_add(
        &self,
        left: &Self::SharedValue,
        right: &Self::SharedValue,
    ) -> ProtoResult<Self::SharedValue>;
    fn eval_mul(
        &self,
        left: &Self::SharedValue,
        right: &Self::SharedValue,
    ) -> ProtoResult<Self::SharedValue>;
    fn decode_words(&self, values: &[Self::SharedValue]) -> ProtoResult<Vec<u8>>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenEvalOpInventory {
    pub share_encodes: u64,
    pub xor_linear_ops: u64,
    pub and_nonlinear_ops: u64,
    pub carry_chain_adders: u64,
    pub choose_ops: u64,
    pub majority_ops: u64,
    pub clamp_ops: u64,
    pub scalar_reductions: u64,
    pub output_share_projections: u64,
    pub basepoint_muls: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenEvalProgram {
    pub program_version: String,
    pub backend_family: CandidateBackendFamily,
    pub primitive_kind: HssPrimitiveKind,
    pub total_window_records: usize,
    pub active_window_records: usize,
    pub preload_round_constant_count: usize,
    pub preload_context_participant_count: usize,
    pub dependency_edge_count: usize,
    pub total_inventory: HiddenEvalOpInventory,
    pub stages: Vec<HiddenEvalStage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenEvalStage {
    pub label: String,
    pub kind: HiddenEvalStageKind,
    pub windows: Vec<HiddenEvalWindow>,
    pub op_inventory: HiddenEvalOpInventory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HiddenEvalStageKind {
    AddMod2Pow256,
    MessageSchedule,
    RoundState00To19,
    RoundState20To39,
    RoundState40To59,
    RoundState60To79,
    OutputProjector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenEvalWindow {
    pub record_index: u16,
    pub kind: HiddenEvalWindowKind,
    pub source_kind: PrimeOrderSectionKind,
    pub class_value: u16,
    pub class_slot: u16,
    pub dependency_left: Option<u16>,
    pub dependency_right: Option<u16>,
    pub op_inventory: HiddenEvalOpInventory,
    pub ops: Vec<HiddenEvalOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HiddenEvalWindowKind {
    AddLane,
    ScheduleDerivedWord,
    RoundState,
    OutputProjector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenEvalOp {
    AddCarryChain { width_bits: u16, input_count: u8 },
    RotateXor { width_bits: u16, rotates: [u8; 3] },
    ChooseBits { width_bits: u16 },
    MajorityBits { width_bits: u16 },
    ClampPrefix { byte_len: u16 },
    ReduceModGroupOrder { input_bytes: u16, output_bytes: u16 },
    OutputShareProject { output_count: u8 },
    BasepointMul { scalar_bytes: u16 },
}

pub fn compile_prime_order_hidden_eval_program(
    decoded: &PrimeOrderDecodedArtifact,
) -> ProtoResult<HiddenEvalProgram> {
    let mut stages = vec![
        HiddenEvalStage::empty("add_mod_2pow256", HiddenEvalStageKind::AddMod2Pow256),
        HiddenEvalStage::empty("message_schedule", HiddenEvalStageKind::MessageSchedule),
        HiddenEvalStage::empty(
            "round_state_00_to_19",
            HiddenEvalStageKind::RoundState00To19,
        ),
        HiddenEvalStage::empty(
            "round_state_20_to_39",
            HiddenEvalStageKind::RoundState20To39,
        ),
        HiddenEvalStage::empty(
            "round_state_40_to_59",
            HiddenEvalStageKind::RoundState40To59,
        ),
        HiddenEvalStage::empty(
            "round_state_60_to_79",
            HiddenEvalStageKind::RoundState60To79,
        ),
        HiddenEvalStage::empty("output_projector", HiddenEvalStageKind::OutputProjector),
    ];

    let mut preload_round_constant_count = 0usize;
    let mut preload_context_participant_count = 0usize;
    let mut dependency_edge_count = 0usize;

    for record in &decoded.windows.records {
        dependency_edge_count += usize::from(record.dependency_left.is_some());
        dependency_edge_count += usize::from(record.dependency_right.is_some());

        match record.class {
            PrimeOrderWindowRecordClass::RoundConstant => preload_round_constant_count += 1,
            PrimeOrderWindowRecordClass::ContextParticipant => {
                preload_context_participant_count += 1
            }
            PrimeOrderWindowRecordClass::AddLane => {
                stages[0].push_window(compile_window(record)?);
            }
            PrimeOrderWindowRecordClass::ScheduleDerivedWord => {
                stages[1].push_window(compile_window(record)?);
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
                stages[stage_idx].push_window(compile_window(record)?);
            }
            PrimeOrderWindowRecordClass::OutputProjector => {
                stages[6].push_window(compile_window(record)?);
            }
        }
    }

    let mut total_inventory = HiddenEvalOpInventory::default();
    for stage in &stages {
        total_inventory.accumulate(&stage.op_inventory);
    }

    Ok(HiddenEvalProgram {
        program_version: HIDDEN_EVAL_PROGRAM_VERSION.to_string(),
        backend_family: CandidateBackendFamily::PrimeOrderSizeOptimized,
        primitive_kind: HssPrimitiveKind::PrimeOrderDdh,
        total_window_records: decoded.windows.records.len(),
        active_window_records: stages.iter().map(|stage| stage.windows.len()).sum(),
        preload_round_constant_count,
        preload_context_participant_count,
        dependency_edge_count,
        total_inventory,
        stages,
    })
}

fn compile_window(record: &PrimeOrderWindowRecord) -> ProtoResult<HiddenEvalWindow> {
    let (kind, ops, op_inventory) = match record.class {
        PrimeOrderWindowRecordClass::AddLane => compile_add_lane_window(record),
        PrimeOrderWindowRecordClass::ScheduleDerivedWord => compile_schedule_derived_window(record),
        PrimeOrderWindowRecordClass::RoundState => compile_round_state_window(record),
        PrimeOrderWindowRecordClass::OutputProjector => compile_output_projector_window(record),
        PrimeOrderWindowRecordClass::RoundConstant
        | PrimeOrderWindowRecordClass::ContextParticipant => {
            return Err(ProtoError::Decode(format!(
                "window compiler does not compile preload-only record class {:?}",
                record.class
            )))
        }
    };

    Ok(HiddenEvalWindow {
        record_index: record.index,
        kind,
        source_kind: record.source_kind,
        class_value: record.class_value,
        class_slot: record.class_slot,
        dependency_left: record.dependency_left,
        dependency_right: record.dependency_right,
        op_inventory,
        ops,
    })
}

fn compile_add_lane_window(
    record: &PrimeOrderWindowRecord,
) -> (
    HiddenEvalWindowKind,
    Vec<HiddenEvalOp>,
    HiddenEvalOpInventory,
) {
    let input_count = if record.class_slot == 0 { 2 } else { 3 };
    let ops = vec![HiddenEvalOp::AddCarryChain {
        width_bits: record.logical_span,
        input_count,
    }];

    let mut inventory = HiddenEvalOpInventory::default();
    inventory.share_encodes += 2;
    inventory.carry_chain_adders += 1;
    inventory.xor_linear_ops += u64::from(record.logical_span);
    inventory.and_nonlinear_ops += u64::from(record.logical_span);

    (HiddenEvalWindowKind::AddLane, ops, inventory)
}

fn compile_schedule_derived_window(
    _record: &PrimeOrderWindowRecord,
) -> (
    HiddenEvalWindowKind,
    Vec<HiddenEvalOp>,
    HiddenEvalOpInventory,
) {
    let ops = vec![
        HiddenEvalOp::RotateXor {
            width_bits: 64,
            rotates: [1, 8, 7],
        },
        HiddenEvalOp::RotateXor {
            width_bits: 64,
            rotates: [19, 61, 6],
        },
        HiddenEvalOp::AddCarryChain {
            width_bits: 64,
            input_count: 4,
        },
    ];

    let mut inventory = HiddenEvalOpInventory::default();
    inventory.carry_chain_adders += 1;
    inventory.xor_linear_ops += 128;
    inventory.and_nonlinear_ops += 64;

    (HiddenEvalWindowKind::ScheduleDerivedWord, ops, inventory)
}

fn compile_round_state_window(
    _record: &PrimeOrderWindowRecord,
) -> (
    HiddenEvalWindowKind,
    Vec<HiddenEvalOp>,
    HiddenEvalOpInventory,
) {
    let ops = vec![
        HiddenEvalOp::RotateXor {
            width_bits: 64,
            rotates: [14, 18, 41],
        },
        HiddenEvalOp::ChooseBits { width_bits: 64 },
        HiddenEvalOp::AddCarryChain {
            width_bits: 64,
            input_count: 5,
        },
        HiddenEvalOp::RotateXor {
            width_bits: 64,
            rotates: [28, 34, 39],
        },
        HiddenEvalOp::MajorityBits { width_bits: 64 },
        HiddenEvalOp::AddCarryChain {
            width_bits: 64,
            input_count: 2,
        },
        HiddenEvalOp::AddCarryChain {
            width_bits: 64,
            input_count: 2,
        },
    ];

    let mut inventory = HiddenEvalOpInventory::default();
    inventory.carry_chain_adders += 3;
    inventory.choose_ops += 1;
    inventory.majority_ops += 1;
    inventory.xor_linear_ops += 128;
    inventory.and_nonlinear_ops += 128;

    (HiddenEvalWindowKind::RoundState, ops, inventory)
}

fn compile_output_projector_window(
    record: &PrimeOrderWindowRecord,
) -> (
    HiddenEvalWindowKind,
    Vec<HiddenEvalOp>,
    HiddenEvalOpInventory,
) {
    let (ops, inventory) = match record.class_slot {
        0 => {
            let ops = vec![HiddenEvalOp::ClampPrefix { byte_len: 32 }];
            let mut inventory = HiddenEvalOpInventory::default();
            inventory.clamp_ops += 1;
            (ops, inventory)
        }
        1 => {
            let ops = vec![HiddenEvalOp::ReduceModGroupOrder {
                input_bytes: 32,
                output_bytes: 32,
            }];
            let mut inventory = HiddenEvalOpInventory::default();
            inventory.scalar_reductions += 1;
            (ops, inventory)
        }
        2 => {
            let ops = vec![HiddenEvalOp::OutputShareProject { output_count: 3 }];
            let mut inventory = HiddenEvalOpInventory::default();
            inventory.output_share_projections += 1;
            (ops, inventory)
        }
        3 => {
            let ops = vec![HiddenEvalOp::BasepointMul { scalar_bytes: 32 }];
            let mut inventory = HiddenEvalOpInventory::default();
            inventory.basepoint_muls += 1;
            (ops, inventory)
        }
        other => {
            let ops = vec![HiddenEvalOp::OutputShareProject { output_count: 0 }];
            let mut inventory = HiddenEvalOpInventory::default();
            inventory.output_share_projections += 1;
            inventory.xor_linear_ops += u64::from(other);
            (ops, inventory)
        }
    };

    (HiddenEvalWindowKind::OutputProjector, ops, inventory)
}

impl HiddenEvalOpInventory {
    fn accumulate(&mut self, other: &Self) {
        self.share_encodes += other.share_encodes;
        self.xor_linear_ops += other.xor_linear_ops;
        self.and_nonlinear_ops += other.and_nonlinear_ops;
        self.carry_chain_adders += other.carry_chain_adders;
        self.choose_ops += other.choose_ops;
        self.majority_ops += other.majority_ops;
        self.clamp_ops += other.clamp_ops;
        self.scalar_reductions += other.scalar_reductions;
        self.output_share_projections += other.output_share_projections;
        self.basepoint_muls += other.basepoint_muls;
    }
}

impl HiddenEvalStage {
    fn empty(label: &'static str, kind: HiddenEvalStageKind) -> Self {
        Self {
            label: label.to_string(),
            kind,
            windows: Vec::new(),
            op_inventory: HiddenEvalOpInventory::default(),
        }
    }

    fn push_window(&mut self, window: HiddenEvalWindow) {
        self.op_inventory.accumulate(&window.op_inventory);
        self.windows.push(window);
    }
}
