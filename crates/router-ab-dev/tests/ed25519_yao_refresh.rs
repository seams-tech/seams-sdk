use curve25519_dalek::scalar::Scalar;
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoEpochTransitionV1, Ed25519YaoOperationV1,
    Ed25519YaoRefreshBindingV1, Ed25519YaoRefreshEpochsV1, Ed25519YaoSessionIdV1,
    Ed25519YaoStableKeyContextBindingV1, Ed25519YaoStateEpochV1, ExpensiveWorkKindV1,
    LifecycleScopeV1, RootShareEpoch,
};
use router_ab_dev::{
    LocalEd25519YaoDeriverAEffectiveStateV1, LocalEd25519YaoDeriverBEffectiveStateV1,
};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_joint_refresh_delta_v1, Ed25519YaoDeriverARefreshDeltaContributionV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBRefreshDeltaContributionV1,
    Ed25519YaoDeriverBServerContributionV1,
};

#[test]
fn role_local_refresh_state_rotates_effective_contributions_only_on_promotion() {
    let epoch_1 = Ed25519YaoStateEpochV1::new(1).expect("epoch 1");
    let epoch_4 = Ed25519YaoStateEpochV1::new(4).expect("epoch 4");
    let transition = Ed25519YaoEpochTransitionV1::new(epoch_1, epoch_4).expect("transition");
    let registration = ceremony(
        Ed25519YaoOperationV1::Registration,
        ExpensiveWorkKindV1::RegistrationPrepare,
        [0x41; 32],
    );
    let refresh = Ed25519YaoRefreshBindingV1::new(
        ceremony(
            Ed25519YaoOperationV1::Refresh,
            ExpensiveWorkKindV1::ServerShareRefresh,
            [0x42; 32],
        ),
        [0x71; 32],
        Ed25519YaoRefreshEpochsV1 {
            deriver_a: transition,
            deriver_b: transition,
            signing_worker: transition,
        },
    )
    .expect("refresh binding");

    let initial_a = server_a(10, 100);
    let initial_b = server_b(20, 200);
    let mut state_a =
        LocalEd25519YaoDeriverAEffectiveStateV1::from_initial(&registration, epoch_1, initial_a)
            .expect("A state");
    let mut state_b =
        LocalEd25519YaoDeriverBEffectiveStateV1::from_initial(&registration, epoch_1, initial_b)
            .expect("B state");
    let delta = derive_ed25519_yao_joint_refresh_delta_v1(
        Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(
            little_endian_u8(1),
            Scalar::from(5_u64).to_bytes(),
        )
        .expect("A delta"),
        Ed25519YaoDeriverBRefreshDeltaContributionV1::from_secret_bytes(
            little_endian_u8(2),
            Scalar::from(7_u64).to_bytes(),
        )
        .expect("B delta"),
    )
    .expect("joint delta");

    let prepared_a = state_a
        .prepare_refresh(&refresh, &delta)
        .expect("prepare A");
    let prepared_b = state_b
        .prepare_refresh(&refresh, &delta)
        .expect("prepare B");
    assert_eq!(contribution_bytes_a(state_a.active_contribution()).0[0], 10);
    assert_eq!(contribution_bytes_b(state_b.active_contribution()).0[0], 20);
    assert_eq!(
        contribution_bytes_a(prepared_a.candidate_contribution()).0[0],
        13
    );
    assert_eq!(
        contribution_bytes_b(prepared_b.candidate_contribution()).0[0],
        17
    );

    state_a.promote(prepared_a).expect("promote A");
    state_b.promote(prepared_b).expect("promote B");
    assert_eq!(state_a.active_epoch(), epoch_4);
    assert_eq!(state_b.active_epoch(), epoch_4);
    let (a_y, a_tau) = contribution_bytes_a(state_a.active_contribution());
    let (b_y, b_tau) = contribution_bytes_b(state_b.active_contribution());
    assert_eq!(u16::from(a_y[0]) + u16::from(b_y[0]), 30);
    assert_eq!(
        canonical_scalar(a_tau) + canonical_scalar(b_tau),
        Scalar::from(300_u64)
    );
    assert!(state_a.prepare_refresh(&refresh, &delta).is_err());
    assert!(state_b.prepare_refresh(&refresh, &delta).is_err());
}

fn ceremony(
    operation: Ed25519YaoOperationV1,
    work_kind: ExpensiveWorkKindV1,
    session: [u8; 32],
) -> Ed25519YaoCeremonyBindingV1 {
    Ed25519YaoCeremonyBindingV1::new(
        LifecycleScopeV1::new(
            "lifecycle-1",
            work_kind,
            RootShareEpoch::new("root-epoch-1").expect("root epoch"),
            "account-1",
            "wallet-session-1",
            "signer-set-1",
            "signing-worker-1",
        )
        .expect("lifecycle"),
        operation,
        Ed25519YaoSessionIdV1::new(session).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new([0x51; 32]),
    )
    .expect("ceremony")
}

fn little_endian_u8(value: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[0] = value;
    bytes
}

fn server_a(y: u8, tau: u64) -> Ed25519YaoDeriverAServerContributionV1 {
    Ed25519YaoDeriverAServerContributionV1::from_secret_bytes(
        little_endian_u8(y),
        Scalar::from(tau).to_bytes(),
    )
}

fn server_b(y: u8, tau: u64) -> Ed25519YaoDeriverBServerContributionV1 {
    Ed25519YaoDeriverBServerContributionV1::from_secret_bytes(
        little_endian_u8(y),
        Scalar::from(tau).to_bytes(),
    )
}

fn contribution_bytes_a(
    contribution: Ed25519YaoDeriverAServerContributionV1,
) -> ([u8; 32], [u8; 32]) {
    let (y, tau) = contribution.into_parts();
    (y.into_bytes(), tau.into_bytes())
}

fn contribution_bytes_b(
    contribution: Ed25519YaoDeriverBServerContributionV1,
) -> ([u8; 32], [u8; 32]) {
    let (y, tau) = contribution.into_parts();
    (y.into_bytes(), tau.into_bytes())
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("canonical scalar")
}
