use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    derive_synthetic_client_contributions_v1, derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1, evaluate_full_clear_reference_export_v1,
    prepare_host_only_refresh_reference_v1, wrapping_add_le_256, DeriverAContribution,
    DeriverBContribution, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, ExportOracleOutput,
    HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1,
    HostOnlyJointRefreshDeltaCoinsV1, HostOnlyJointRefreshDeltaErrorV1,
    HostOnlyRefreshReferenceErrorV1, HostOnlyRefreshReferenceInputsV1, RawDeriverAContribution,
    RawDeriverBContribution, StableKeyDerivationContext, SyntheticClientDerivationRootV1,
    SyntheticDeriverADerivationRootV1, SyntheticDeriverBDerivationRootV1,
};

fn stable_context() -> StableKeyDerivationContext {
    let application_binding = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-fixture").expect("valid wallet id"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_fixture")
            .expect("valid signing key id"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project-fixture:env-fixture")
            .expect("valid signing root id"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1)
            .expect("valid key-creation signer slot"),
    );
    StableKeyDerivationContext::new(*application_binding.digest().as_bytes(), 1, 2)
        .expect("valid stable context")
}

fn derived_contributions(client_root_byte: u8) -> (DeriverAContribution, DeriverBContribution) {
    let context = stable_context();
    let client = derive_synthetic_client_contributions_v1(
        &SyntheticClientDerivationRootV1::from_fixture_bytes([client_root_byte; 32]),
        &context,
    );
    let server_a = derive_synthetic_deriver_a_server_contribution_v1(
        &SyntheticDeriverADerivationRootV1::from_fixture_bytes([0x22; 32]),
        &context,
    );
    let server_b = derive_synthetic_deriver_b_server_contribution_v1(
        &SyntheticDeriverBDerivationRootV1::from_fixture_bytes([0x33; 32]),
        &context,
    );
    let deriver_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: client.deriver_a().y().expose_fixture_bytes(),
        y_server: server_a.y().expose_fixture_bytes(),
        tau_client: client.deriver_a().tau().expose_fixture_bytes(),
        tau_server: server_a.tau().expose_fixture_bytes(),
    })
    .expect("derived A input is valid");
    let deriver_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: client.deriver_b().y().expose_fixture_bytes(),
        y_server: server_b.y().expose_fixture_bytes(),
        tau_client: client.deriver_b().tau().expose_fixture_bytes(),
        tau_server: server_b.tau().expose_fixture_bytes(),
    })
    .expect("derived B input is valid");
    (deriver_a, deriver_b)
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("canonical fixture scalar")
}

fn joined_y(deriver_a: &DeriverAContribution, deriver_b: &DeriverBContribution) -> [u8; 32] {
    let y_a = wrapping_add_le_256(
        deriver_a.y_client().expose_bytes(),
        deriver_a.y_server().expose_bytes(),
    );
    let y_b = wrapping_add_le_256(
        deriver_b.y_client().expose_bytes(),
        deriver_b.y_server().expose_bytes(),
    );
    wrapping_add_le_256(y_a, y_b)
}

fn joined_tau(deriver_a: &DeriverAContribution, deriver_b: &DeriverBContribution) -> [u8; 32] {
    (canonical_scalar(deriver_a.tau_client().expose_bytes())
        + canonical_scalar(deriver_a.tau_server().expose_bytes())
        + canonical_scalar(deriver_b.tau_client().expose_bytes())
        + canonical_scalar(deriver_b.tau_server().expose_bytes()))
    .to_bytes()
}

fn assert_identity_equal(left: &ExportOracleOutput, right: &ExportOracleOutput) {
    assert_eq!(left.seed().expose_bytes(), right.seed().expose_bytes());
    assert_eq!(
        left.material().sha512_digest().expose_bytes(),
        right.material().sha512_digest().expose_bytes()
    );
    assert_eq!(
        left.material().clamped_scalar_bytes().expose_bytes(),
        right.material().clamped_scalar_bytes().expose_bytes()
    );
    assert_eq!(
        left.material().signing_scalar().expose_bytes(),
        right.material().signing_scalar().expose_bytes()
    );
    assert_eq!(
        left.material().tau().expose_bytes(),
        right.material().tau().expose_bytes()
    );
    assert_eq!(
        left.material().x_client_base().expose_bytes(),
        right.material().x_client_base().expose_bytes()
    );
    assert_eq!(
        left.material().x_server_base().expose_bytes(),
        right.material().x_server_base().expose_bytes()
    );
    assert_eq!(
        left.material().x_client().expose_bytes(),
        right.material().x_client().expose_bytes()
    );
    assert_eq!(
        left.material().x_server().expose_bytes(),
        right.material().x_server().expose_bytes()
    );
    assert_eq!(
        left.material().public_key().expose_bytes(),
        right.material().public_key().expose_bytes()
    );
}

fn joint_delta_coins(
    a_y: [u8; 32],
    a_tau: Scalar,
    b_y: [u8; 32],
    b_tau: Scalar,
) -> HostOnlyJointRefreshDeltaCoinsV1 {
    HostOnlyJointRefreshDeltaCoinsV1::new(
        HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(a_y, a_tau.to_bytes())
            .expect("canonical A contribution"),
        HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(b_y, b_tau.to_bytes())
            .expect("canonical B contribution"),
    )
}

#[test]
fn correlated_server_delta_preserves_every_joined_identity_value() {
    let (deriver_a, deriver_b) = derived_contributions(0x11);
    let delta = joint_delta_coins(
        [0x3c; 32],
        Scalar::from(5_u64),
        [0x69; 32],
        Scalar::from(12_u64),
    );
    let before_joined_y = joined_y(&deriver_a, &deriver_b);
    let before_joined_tau = joined_tau(&deriver_a, &deriver_b);
    let before = evaluate_full_clear_reference_export_v1(&deriver_a, &deriver_b);

    let transitioned = prepare_host_only_refresh_reference_v1(
        HostOnlyRefreshReferenceInputsV1::new(&deriver_a, &deriver_b, delta),
    )
    .expect("joint refresh preserves continuity");
    let refreshed_a = transitioned.refreshed_deriver_a();
    let refreshed_b = transitioned.refreshed_deriver_b();
    let after = evaluate_full_clear_reference_export_v1(refreshed_a, refreshed_b);

    assert_eq!(
        deriver_a.y_client().expose_bytes(),
        refreshed_a.y_client().expose_bytes()
    );
    assert_eq!(
        deriver_a.tau_client().expose_bytes(),
        refreshed_a.tau_client().expose_bytes()
    );
    assert_eq!(
        deriver_b.y_client().expose_bytes(),
        refreshed_b.y_client().expose_bytes()
    );
    assert_eq!(
        deriver_b.tau_client().expose_bytes(),
        refreshed_b.tau_client().expose_bytes()
    );
    assert_ne!(
        deriver_a.y_server().expose_bytes(),
        refreshed_a.y_server().expose_bytes()
    );
    assert_ne!(
        deriver_a.tau_server().expose_bytes(),
        refreshed_a.tau_server().expose_bytes()
    );
    assert_ne!(
        deriver_b.y_server().expose_bytes(),
        refreshed_b.y_server().expose_bytes()
    );
    assert_ne!(
        deriver_b.tau_server().expose_bytes(),
        refreshed_b.tau_server().expose_bytes()
    );
    assert_eq!(before_joined_y, joined_y(refreshed_a, refreshed_b));
    assert_eq!(before_joined_tau, joined_tau(refreshed_a, refreshed_b));
    assert_eq!(before_joined_y, before.seed().expose_bytes());
    assert_eq!(before_joined_tau, before.material().tau().expose_bytes());
    assert_identity_equal(&before, &after);
}

#[test]
fn cancelling_joint_deltas_are_rejected_precisely() {
    let (deriver_a, deriver_b) = derived_contributions(0x11);
    let error = prepare_host_only_refresh_reference_v1(HostOnlyRefreshReferenceInputsV1::new(
        &deriver_a,
        &deriver_b,
        joint_delta_coins(
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Scalar::ONE,
            [0xff; 32],
            Scalar::ONE,
        ),
    ))
    .err();
    assert_eq!(
        error,
        Some(HostOnlyRefreshReferenceErrorV1::InvalidJointDelta(
            HostOnlyJointRefreshDeltaErrorV1::ZeroJointDeltaY
        ))
    );
}

#[test]
fn same_logical_client_root_rederives_identical_contributions_and_identity() {
    let (first_a, first_b) = derived_contributions(0x11);
    let (repeat_a, repeat_b) = derived_contributions(0x11);

    assert_eq!(
        first_a.y_client().expose_bytes(),
        repeat_a.y_client().expose_bytes()
    );
    assert_eq!(
        first_a.tau_client().expose_bytes(),
        repeat_a.tau_client().expose_bytes()
    );
    assert_eq!(
        first_b.y_client().expose_bytes(),
        repeat_b.y_client().expose_bytes()
    );
    assert_eq!(
        first_b.tau_client().expose_bytes(),
        repeat_b.tau_client().expose_bytes()
    );
    assert_eq!(
        first_a.y_server().expose_bytes(),
        repeat_a.y_server().expose_bytes()
    );
    assert_eq!(
        first_a.tau_server().expose_bytes(),
        repeat_a.tau_server().expose_bytes()
    );
    assert_eq!(
        first_b.y_server().expose_bytes(),
        repeat_b.y_server().expose_bytes()
    );
    assert_eq!(
        first_b.tau_server().expose_bytes(),
        repeat_b.tau_server().expose_bytes()
    );
    assert_identity_equal(
        &evaluate_full_clear_reference_export_v1(&first_a, &first_b),
        &evaluate_full_clear_reference_export_v1(&repeat_a, &repeat_b),
    );
}

#[test]
fn changed_client_root_fails_identity_continuity() {
    let (baseline_a, baseline_b) = derived_contributions(0x11);
    let (changed_a, changed_b) = derived_contributions(0x12);
    let baseline = evaluate_full_clear_reference_export_v1(&baseline_a, &baseline_b);
    let changed = evaluate_full_clear_reference_export_v1(&changed_a, &changed_b);

    assert_ne!(
        baseline_a.y_client().expose_bytes(),
        changed_a.y_client().expose_bytes()
    );
    assert_ne!(
        baseline_b.tau_client().expose_bytes(),
        changed_b.tau_client().expose_bytes()
    );
    assert_ne!(
        baseline.seed().expose_bytes(),
        changed.seed().expose_bytes()
    );
    assert_ne!(
        baseline.material().public_key().expose_bytes(),
        changed.material().public_key().expose_bytes()
    );
}
