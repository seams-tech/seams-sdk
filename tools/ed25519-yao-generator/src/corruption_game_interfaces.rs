//! Profile-neutral corruption markers and uninstantiated real/ideal interfaces.
//!
//! These declarations freeze admissible corruption sets and type relationships.
//! They supply no adversary, simulator, comparison relation, theorem, or profile
//! satisfaction claim.

use core::marker::PhantomData;

mod sealed {
    pub trait Sealed {}
}

/// Exactly ten supported static corruption-set labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyCorruptionKindV1 {
    /// Every protocol role follows its prescribed behavior.
    HonestExecution,
    /// Router alone is corrupted.
    RouterOnly,
    /// Deriver A alone is passively corrupted.
    PassiveDeriverA,
    /// Deriver B alone is passively corrupted.
    PassiveDeriverB,
    /// Router and passive Deriver A are corrupted.
    RouterAndPassiveDeriverA,
    /// Router and passive Deriver B are corrupted.
    RouterAndPassiveDeriverB,
    /// Deriver A alone is actively corrupted.
    ActiveDeriverA,
    /// Deriver B alone is actively corrupted.
    ActiveDeriverB,
    /// Router and active Deriver A are corrupted.
    RouterAndActiveDeriverA,
    /// Router and active Deriver B are corrupted.
    RouterAndActiveDeriverB,
}

impl HostOnlyCorruptionKindV1 {
    /// Returns the frozen source label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HonestExecution => "honest_execution",
            Self::RouterOnly => "router_only",
            Self::PassiveDeriverA => "passive_deriver_a",
            Self::PassiveDeriverB => "passive_deriver_b",
            Self::RouterAndPassiveDeriverA => "router_and_passive_deriver_a",
            Self::RouterAndPassiveDeriverB => "router_and_passive_deriver_b",
            Self::ActiveDeriverA => "active_deriver_a",
            Self::ActiveDeriverB => "active_deriver_b",
            Self::RouterAndActiveDeriverA => "router_and_active_deriver_a",
            Self::RouterAndActiveDeriverB => "router_and_active_deriver_b",
        }
    }
}

/// Frozen corruption-set order consumed by strict corpus guards.
pub const HOST_ONLY_CORRUPTION_KINDS_V1: [HostOnlyCorruptionKindV1; 10] = [
    HostOnlyCorruptionKindV1::HonestExecution,
    HostOnlyCorruptionKindV1::RouterOnly,
    HostOnlyCorruptionKindV1::PassiveDeriverA,
    HostOnlyCorruptionKindV1::PassiveDeriverB,
    HostOnlyCorruptionKindV1::RouterAndPassiveDeriverA,
    HostOnlyCorruptionKindV1::RouterAndPassiveDeriverB,
    HostOnlyCorruptionKindV1::ActiveDeriverA,
    HostOnlyCorruptionKindV1::ActiveDeriverB,
    HostOnlyCorruptionKindV1::RouterAndActiveDeriverA,
    HostOnlyCorruptionKindV1::RouterAndActiveDeriverB,
];

/// Exactly four profile-neutral corruption-game interface shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyCorruptionGameInterfaceShapeV1 {
    /// Inputs exposed to the corrupted-role view.
    CorruptedViewInput,
    /// Selected construction's real execution.
    SelectedProfileRealExecution,
    /// Selected construction's ideal simulator.
    SelectedProfileIdealSimulator,
    /// Relation between the selected real and ideal shapes.
    SelectedProfileSecurityExperiment,
}

impl HostOnlyCorruptionGameInterfaceShapeV1 {
    /// Returns the exact authoritative label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorruptedViewInput => "corrupted_view_input",
            Self::SelectedProfileRealExecution => "selected_profile_real_execution",
            Self::SelectedProfileIdealSimulator => "selected_profile_ideal_simulator",
            Self::SelectedProfileSecurityExperiment => "selected_profile_security_experiment",
        }
    }
}

/// Frozen corruption-game interface-shape order.
pub const HOST_ONLY_CORRUPTION_GAME_INTERFACE_SHAPES_V1: [HostOnlyCorruptionGameInterfaceShapeV1;
    4] = [
    HostOnlyCorruptionGameInterfaceShapeV1::CorruptedViewInput,
    HostOnlyCorruptionGameInterfaceShapeV1::SelectedProfileRealExecution,
    HostOnlyCorruptionGameInterfaceShapeV1::SelectedProfileIdealSimulator,
    HostOnlyCorruptionGameInterfaceShapeV1::SelectedProfileSecurityExperiment,
];

/// Sealed type-level member of the closed static corruption-set universe.
pub trait HostOnlyCorruptionMarkerV1: sealed::Sealed {
    /// Corresponding frozen corpus label.
    const KIND: HostOnlyCorruptionKindV1;
}

macro_rules! define_corruption_marker {
    ($name:ident, $kind:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(PhantomData<()>);

        impl sealed::Sealed for $name {}

        impl HostOnlyCorruptionMarkerV1 for $name {
            const KIND: HostOnlyCorruptionKindV1 = HostOnlyCorruptionKindV1::$kind;
        }
    };
}

define_corruption_marker!(
    HonestExecutionV1,
    HonestExecution,
    "Type marker for honest execution."
);
define_corruption_marker!(
    RouterOnlyV1,
    RouterOnly,
    "Type marker for Router-only corruption."
);
define_corruption_marker!(
    PassiveDeriverAV1,
    PassiveDeriverA,
    "Type marker for passive Deriver A corruption."
);
define_corruption_marker!(
    PassiveDeriverBV1,
    PassiveDeriverB,
    "Type marker for passive Deriver B corruption."
);
define_corruption_marker!(
    RouterAndPassiveDeriverAV1,
    RouterAndPassiveDeriverA,
    "Type marker for Router with passive Deriver A corruption."
);
define_corruption_marker!(
    RouterAndPassiveDeriverBV1,
    RouterAndPassiveDeriverB,
    "Type marker for Router with passive Deriver B corruption."
);
define_corruption_marker!(
    ActiveDeriverAV1,
    ActiveDeriverA,
    "Type marker for active Deriver A corruption."
);
define_corruption_marker!(
    ActiveDeriverBV1,
    ActiveDeriverB,
    "Type marker for active Deriver B corruption."
);
define_corruption_marker!(
    RouterAndActiveDeriverAV1,
    RouterAndActiveDeriverA,
    "Type marker for Router with active Deriver A corruption."
);
define_corruption_marker!(
    RouterAndActiveDeriverBV1,
    RouterAndActiveDeriverB,
    "Type marker for Router with active Deriver B corruption."
);

/// Typed inputs made available to a later real execution or ideal simulator.
pub trait CorruptedViewInputV1<Corruption>
where
    Corruption: HostOnlyCorruptionMarkerV1,
{
    /// Common public leakage fixed by the semantic trace.
    type PublicLeakage;
    /// Prescribed inputs owned by corrupted roles.
    type CorruptedInputs;
    /// Local randomness owned by corrupted roles.
    type CorruptedRandomness;
    /// Prescribed outputs owned by corrupted roles.
    type PrescribedOutputs;
    /// Success or uniform-abort terminal observation.
    type TerminalObservation;
}

/// Interface for a selected construction's real execution trace.
pub trait SelectedProfileRealExecutionV1<Corruption, Input>
where
    Corruption: HostOnlyCorruptionMarkerV1,
    Input: CorruptedViewInputV1<Corruption>,
{
    /// Opaque selected-construction execution trace.
    type RealTrace;
    /// Corrupted roles' projected view of that trace.
    type CorruptedView;
}

/// Interface for a selected construction's ideal-world simulator.
pub trait SelectedProfileIdealSimulatorV1<Corruption, Input>
where
    Corruption: HostOnlyCorruptionMarkerV1,
    Input: CorruptedViewInputV1<Corruption>,
{
    /// Opaque active strategy, if the selected corruption marker requires one.
    type ActiveAdversaryStrategy;
    /// Simulated corrupted-role view produced from the typed ideal input.
    type SimulatedCorruptedView;
}

/// Interface relating one selected construction's real and ideal worlds.
pub trait SelectedProfileSecurityExperimentV1<Corruption, Input, Real, Ideal>
where
    Corruption: HostOnlyCorruptionMarkerV1,
    Input: CorruptedViewInputV1<Corruption>,
    Real: SelectedProfileRealExecutionV1<Corruption, Input>,
    Ideal: SelectedProfileIdealSimulatorV1<Corruption, Input>,
{
    /// Construction-specific comparison relation selected after profile review.
    type ComparisonRelation;
    /// Construction-specific advantage measure selected after profile review.
    type AdvantageMeasure;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_corruption_markers_have_exact_order_and_unique_labels() {
        assert_eq!(HOST_ONLY_CORRUPTION_KINDS_V1.len(), 10);
        for (index, kind) in HOST_ONLY_CORRUPTION_KINDS_V1.iter().enumerate() {
            assert!(!kind.as_str().is_empty());
            assert!(!HOST_ONLY_CORRUPTION_KINDS_V1[..index].contains(kind));
        }
        assert_eq!(
            RouterAndActiveDeriverAV1::KIND,
            HostOnlyCorruptionKindV1::RouterAndActiveDeriverA
        );
        assert_eq!(HOST_ONLY_CORRUPTION_GAME_INTERFACE_SHAPES_V1.len(), 4);
    }
}
