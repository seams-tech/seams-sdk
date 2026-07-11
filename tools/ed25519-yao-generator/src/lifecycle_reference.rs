//! Host-only synthetic lifecycle-continuity reference arithmetic.
//!
//! This module models only a correlated zero-sum adjustment over public fixture
//! contributions. It does not model production delta generation, credentials,
//! packages, persistence, transport, or active security.

use curve25519_dalek::scalar::Scalar;

use crate::joint_refresh_delta::HostOnlyJointRefreshDeltaV1;
use crate::{
    wrapping_add_le_256, DeriverAContribution, DeriverBContribution, RawDeriverAContribution,
    RawDeriverBContribution,
};

pub(crate) struct HostOnlyContinuityTransitionV1 {
    deriver_a: DeriverAContribution,
    deriver_b: DeriverBContribution,
}

impl HostOnlyContinuityTransitionV1 {
    pub(crate) fn into_parts(self) -> (DeriverAContribution, DeriverBContribution) {
        (self.deriver_a, self.deriver_b)
    }
}

/// Applies `+delta` to A's synthetic server contribution and `-delta` to B's.
///
/// Client contributions are copied byte-for-byte. The returned role values pass
/// the same canonical scalar validation as every other oracle input.
pub(crate) fn apply_host_only_joint_refresh_delta_v1(
    deriver_a: &DeriverAContribution,
    deriver_b: &DeriverBContribution,
    delta: &HostOnlyJointRefreshDeltaV1,
) -> HostOnlyContinuityTransitionV1 {
    let delta_y = delta.delta_y();
    let delta_tau = delta.delta_tau();
    let deriver_a_server_tau = canonical_scalar(deriver_a.tau_server().expose_bytes());
    let deriver_b_server_tau = canonical_scalar(deriver_b.tau_server().expose_bytes());

    let refreshed_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: deriver_a.y_client().expose_bytes(),
        y_server: wrapping_add_le_256(deriver_a.y_server().expose_bytes(), delta_y),
        tau_client: deriver_a.tau_client().expose_bytes(),
        tau_server: (deriver_a_server_tau + delta_tau).to_bytes(),
    })
    .expect("canonical scalar arithmetic keeps the synthetic A contribution valid");
    let refreshed_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: deriver_b.y_client().expose_bytes(),
        y_server: wrapping_sub_le_256(deriver_b.y_server().expose_bytes(), delta_y),
        tau_client: deriver_b.tau_client().expose_bytes(),
        tau_server: (deriver_b_server_tau - delta_tau).to_bytes(),
    })
    .expect("canonical scalar arithmetic keeps the synthetic B contribution valid");

    HostOnlyContinuityTransitionV1 {
        deriver_a: refreshed_a,
        deriver_b: refreshed_b,
    }
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("validated oracle contribution contains a canonical scalar")
}

pub(crate) fn wrapping_sub_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = false;
    for index in 0..32 {
        let (without_right, right_borrow) = left[index].overflowing_sub(right[index]);
        let (difference, prior_borrow) = without_right.overflowing_sub(u8::from(borrow));
        output[index] = difference;
        borrow = right_borrow || prior_borrow;
    }
    output
}
