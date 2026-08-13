//! Isolated local lane-materialization role adapter.
//!
//! The public runtime surface accepts one Deriver's source contributions and
//! one fresh offset share. It never receives or combines the other Deriver's
//! shares. A production Yao evaluator must provide these values from the
//! distinct `lane_materialization` circuit and returns a role-isolated
//! streaming state machine.

use router_ab_core::Ed25519YaoLaneJobV1;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    LaneMaterializationDeriverA, LaneMaterializationDeriverB, YaoLaneDeriverAInputs,
    YaoLaneDeriverBInputs,
};

/// Failure while constructing one Deriver's lane role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneMaterializationError {
    /// A role-local canonical scalar is malformed.
    NonCanonicalScalar,
    /// The lane job is malformed.
    InvalidJob,
}

impl core::fmt::Display for LaneMaterializationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::NonCanonicalScalar => "lane role-local scalar is not canonical",
            Self::InvalidJob => "lane job binding is invalid",
        })
    }
}

impl std::error::Error for LaneMaterializationError {}

/// Deriver A's role-local lane contributions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoLaneDeriverAContributionV1 {
    /// Raw Client KDF y contribution for Deriver A.
    pub y_client: [u8; 32],
    /// Raw server KDF y contribution for Deriver A.
    pub y_server: [u8; 32],
    /// Canonical Client KDF tau contribution for Deriver A.
    pub tau_client: [u8; 32],
    /// Canonical server KDF tau contribution for Deriver A.
    pub tau_server: [u8; 32],
    /// Fresh lane offset share produced for Deriver A.
    pub offset: [u8; 32],
}

/// Deriver B's role-local lane contributions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoLaneDeriverBContributionV1 {
    /// Raw Client KDF y contribution for Deriver B.
    pub y_client: [u8; 32],
    /// Raw server KDF y contribution for Deriver B.
    pub y_server: [u8; 32],
    /// Canonical Client KDF tau contribution for Deriver B.
    pub tau_client: [u8; 32],
    /// Canonical server KDF tau contribution for Deriver B.
    pub tau_server: [u8; 32],
    /// Fresh lane offset share produced for Deriver B.
    pub offset: [u8; 32],
}

/// Builds the selected streaming-Yao Deriver A lane role from A-owned shares.
pub fn build_lane_materialization_deriver_a(
    job: &Ed25519YaoLaneJobV1,
    contribution: Ed25519YaoLaneDeriverAContributionV1,
) -> Result<LaneMaterializationDeriverA, LaneMaterializationError> {
    job.validate()
        .map_err(|_| LaneMaterializationError::InvalidJob)?;
    if job.yao_request_kind.operation() != router_ab_core::Ed25519YaoOperationV1::LaneProvisioning
        && job.yao_request_kind.operation() != router_ab_core::Ed25519YaoOperationV1::LaneRefresh
    {
        return Err(LaneMaterializationError::InvalidJob);
    }
    let session = job
        .session_v1()
        .map_err(|_| LaneMaterializationError::InvalidJob)?;
    let inputs = YaoLaneDeriverAInputs::new(
        contribution.y_client,
        contribution.y_server,
        contribution.tau_client,
        contribution.tau_server,
        contribution.offset,
    )
    .map_err(|_| LaneMaterializationError::NonCanonicalScalar)?;
    LaneMaterializationDeriverA::with_inputs(session, inputs)
        .map_err(|_| LaneMaterializationError::InvalidJob)
}

/// Builds the selected streaming-Yao Deriver B lane role from B-owned shares.
pub fn build_lane_materialization_deriver_b(
    job: &Ed25519YaoLaneJobV1,
    contribution: Ed25519YaoLaneDeriverBContributionV1,
) -> Result<LaneMaterializationDeriverB, LaneMaterializationError> {
    job.validate()
        .map_err(|_| LaneMaterializationError::InvalidJob)?;
    let session = job
        .session_v1()
        .map_err(|_| LaneMaterializationError::InvalidJob)?;
    let inputs = YaoLaneDeriverBInputs::new(
        contribution.y_client,
        contribution.y_server,
        contribution.tau_client,
        contribution.tau_server,
        contribution.offset,
    )
    .map_err(|_| LaneMaterializationError::NonCanonicalScalar)?;
    LaneMaterializationDeriverB::with_inputs(session, inputs)
        .map_err(|_| LaneMaterializationError::InvalidJob)
}
