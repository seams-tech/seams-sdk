//! Construction-independent host-only ideal refresh-delta randomness.
//!
//! Each Deriver contributes one public synthetic fixture value in both refresh
//! domains. The ideal result is their sum and must be nonzero in both domains.
//! This module models no commitment, reveal, proof, entropy, or production
//! protocol.

use core::fmt;

use curve25519_dalek::scalar::Scalar;

use crate::wrapping_add_le_256;

/// Failure while validating host-only joint refresh-delta fixture coins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyJointRefreshDeltaErrorV1 {
    /// Deriver A's scalar-domain contribution was not canonical.
    NonCanonicalDeriverATau,
    /// Deriver B's scalar-domain contribution was not canonical.
    NonCanonicalDeriverBTau,
    /// The combined seed-domain delta was the additive identity.
    ZeroJointDeltaY,
    /// The combined scalar-domain delta was the additive identity.
    ZeroJointDeltaTau,
}

impl fmt::Display for HostOnlyJointRefreshDeltaErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalDeriverATau => {
                formatter.write_str("Deriver A refresh delta_tau contribution is noncanonical")
            }
            Self::NonCanonicalDeriverBTau => {
                formatter.write_str("Deriver B refresh delta_tau contribution is noncanonical")
            }
            Self::ZeroJointDeltaY => formatter.write_str("joint refresh delta_y must be nonzero"),
            Self::ZeroJointDeltaTau => {
                formatter.write_str("joint refresh delta_tau must be nonzero")
            }
        }
    }
}

impl std::error::Error for HostOnlyJointRefreshDeltaErrorV1 {}

macro_rules! define_role_contribution {
    ($name:ident, $error:expr, $role:literal) => {
        #[doc = concat!($role, "'s host-only ideal refresh-delta contribution.")]
        pub struct $name {
            delta_y: [u8; 32],
            delta_tau: Scalar,
        }

        impl $name {
            #[doc = concat!("Validates ", $role, "'s public synthetic fixture contribution.")]
            pub fn from_host_only_fixture(
                delta_y: [u8; 32],
                delta_tau: [u8; 32],
            ) -> Result<Self, HostOnlyJointRefreshDeltaErrorV1> {
                let delta_tau = Option::<Scalar>::from(Scalar::from_canonical_bytes(delta_tau))
                    .ok_or($error)?;
                Ok(Self { delta_y, delta_tau })
            }

            /// Exposes the public synthetic seed-domain fixture bytes.
            pub const fn delta_y_fixture_bytes(&self) -> [u8; 32] {
                self.delta_y
            }

            /// Exposes the public synthetic scalar-domain fixture bytes.
            pub fn delta_tau_fixture_bytes(&self) -> [u8; 32] {
                self.delta_tau.to_bytes()
            }
        }
    };
}

define_role_contribution!(
    HostOnlyDeriverARefreshDeltaContributionV1,
    HostOnlyJointRefreshDeltaErrorV1::NonCanonicalDeriverATau,
    "Deriver A"
);
define_role_contribution!(
    HostOnlyDeriverBRefreshDeltaContributionV1,
    HostOnlyJointRefreshDeltaErrorV1::NonCanonicalDeriverBTau,
    "Deriver B"
);

/// Move-owned pair of A/B ideal refresh-delta fixture contributions.
pub struct HostOnlyJointRefreshDeltaCoinsV1 {
    deriver_a: HostOnlyDeriverARefreshDeltaContributionV1,
    deriver_b: HostOnlyDeriverBRefreshDeltaContributionV1,
}

impl HostOnlyJointRefreshDeltaCoinsV1 {
    /// Pairs the two role-local contributions without exposing a combined constructor.
    pub const fn new(
        deriver_a: HostOnlyDeriverARefreshDeltaContributionV1,
        deriver_b: HostOnlyDeriverBRefreshDeltaContributionV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
        }
    }
}

pub(crate) struct HostOnlyJointRefreshDeltaV1 {
    delta_y: [u8; 32],
    delta_tau: Scalar,
}

impl HostOnlyJointRefreshDeltaV1 {
    pub(crate) const fn delta_y(&self) -> [u8; 32] {
        self.delta_y
    }

    pub(crate) fn delta_tau(&self) -> Scalar {
        self.delta_tau
    }
}

pub(crate) fn derive_host_only_joint_refresh_delta_v1(
    coins: HostOnlyJointRefreshDeltaCoinsV1,
) -> Result<HostOnlyJointRefreshDeltaV1, HostOnlyJointRefreshDeltaErrorV1> {
    let delta_y = wrapping_add_le_256(coins.deriver_a.delta_y, coins.deriver_b.delta_y);
    if delta_y == [0_u8; 32] {
        return Err(HostOnlyJointRefreshDeltaErrorV1::ZeroJointDeltaY);
    }
    let delta_tau = coins.deriver_a.delta_tau + coins.deriver_b.delta_tau;
    if delta_tau == Scalar::ZERO {
        return Err(HostOnlyJointRefreshDeltaErrorV1::ZeroJointDeltaTau);
    }
    Ok(HostOnlyJointRefreshDeltaV1 { delta_y, delta_tau })
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use super::{
        derive_host_only_joint_refresh_delta_v1, HostOnlyDeriverARefreshDeltaContributionV1,
        HostOnlyDeriverBRefreshDeltaContributionV1, HostOnlyJointRefreshDeltaCoinsV1,
        HostOnlyJointRefreshDeltaErrorV1,
    };

    const SCALAR_ORDER_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    fn contributions(
        a_y: [u8; 32],
        a_tau: Scalar,
        b_y: [u8; 32],
        b_tau: Scalar,
    ) -> HostOnlyJointRefreshDeltaCoinsV1 {
        HostOnlyJointRefreshDeltaCoinsV1::new(
            HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(
                a_y,
                a_tau.to_bytes(),
            )
            .expect("A fixture is canonical"),
            HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(
                b_y,
                b_tau.to_bytes(),
            )
            .expect("B fixture is canonical"),
        )
    }

    #[test]
    fn two_role_contributions_derive_the_exact_joint_delta() {
        let delta = derive_host_only_joint_refresh_delta_v1(contributions(
            [0x3c; 32],
            Scalar::from(5_u64),
            [0x69; 32],
            Scalar::from(12_u64),
        ))
        .expect("joint delta is nonzero");
        assert_eq!(delta.delta_y(), [0xa5; 32]);
        assert_eq!(delta.delta_tau(), Scalar::from(17_u64));
    }

    #[test]
    fn either_local_contribution_may_be_zero() {
        let a_zero = derive_host_only_joint_refresh_delta_v1(contributions(
            [0; 32],
            Scalar::ZERO,
            [1; 32],
            Scalar::ONE,
        ))
        .expect("only the joint result must be nonzero");
        assert_eq!(a_zero.delta_y(), [1; 32]);
        assert_eq!(a_zero.delta_tau(), Scalar::ONE);

        let b_zero = derive_host_only_joint_refresh_delta_v1(contributions(
            [1; 32],
            Scalar::ONE,
            [0; 32],
            Scalar::ZERO,
        ))
        .expect("either role-local contribution may be zero");
        assert_eq!(b_zero.delta_y(), [1; 32]);
        assert_eq!(b_zero.delta_tau(), Scalar::ONE);
    }

    #[test]
    fn wrapping_seed_contributions_are_added_modulo_two_to_256() {
        let mut b = [0_u8; 32];
        b[0] = 2;
        let delta = derive_host_only_joint_refresh_delta_v1(contributions(
            [0xff; 32],
            Scalar::ONE,
            b,
            Scalar::ONE,
        ))
        .expect("wrapped result is nonzero");
        let mut expected = [0_u8; 32];
        expected[0] = 1;
        assert_eq!(delta.delta_y(), expected);
    }

    #[test]
    fn cancelling_seed_contributions_are_rejected() {
        assert!(matches!(
            derive_host_only_joint_refresh_delta_v1(contributions(
                [
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0
                ],
                Scalar::ONE,
                [0xff; 32],
                Scalar::ONE,
            )),
            Err(HostOnlyJointRefreshDeltaErrorV1::ZeroJointDeltaY)
        ));
    }

    #[test]
    fn cancelling_scalar_contributions_are_rejected() {
        assert!(matches!(
            derive_host_only_joint_refresh_delta_v1(contributions(
                [1; 32],
                Scalar::ONE,
                [1; 32],
                -Scalar::ONE,
            )),
            Err(HostOnlyJointRefreshDeltaErrorV1::ZeroJointDeltaTau)
        ));
    }

    #[test]
    fn each_noncanonical_role_scalar_is_rejected_precisely() {
        assert_eq!(
            HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(
                [1; 32],
                SCALAR_ORDER_LE,
            )
            .err(),
            Some(HostOnlyJointRefreshDeltaErrorV1::NonCanonicalDeriverATau)
        );
        assert_eq!(
            HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(
                [1; 32],
                SCALAR_ORDER_LE,
            )
            .err(),
            Some(HostOnlyJointRefreshDeltaErrorV1::NonCanonicalDeriverBTau)
        );
    }
}
