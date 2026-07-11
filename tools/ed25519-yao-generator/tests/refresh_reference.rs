use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    evaluate_host_only_refresh_output_sharing_v1, prepare_host_only_refresh_reference_v1,
    reconstruct_host_only_client_scalar_output_v1,
    reconstruct_host_only_signing_worker_scalar_output_v1, DeriverAContribution,
    DeriverBContribution, HostOnlyActivationOutputCoinsV1, HostOnlyClientScalarOutputCoinV1,
    HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1,
    HostOnlyJointRefreshDeltaCoinsV1, HostOnlyPreparedRefreshReferenceV1,
    HostOnlyRefreshIdealCoinsV1, HostOnlyRefreshReferenceInputsV1,
    HostOnlySigningWorkerScalarOutputCoinV1, RawDeriverAContribution, RawDeriverBContribution,
};

const SCALAR_ORDER_MINUS_ONE_BYTES: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

struct RefreshFixture {
    deriver_a: DeriverAContribution,
    deriver_b: DeriverBContribution,
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn refresh_fixture(
    y_server_a: [u8; 32],
    tau_server_a: [u8; 32],
    y_server_b: [u8; 32],
    tau_server_b: [u8; 32],
) -> RefreshFixture {
    RefreshFixture {
        deriver_a: DeriverAContribution::try_from(RawDeriverAContribution {
            y_client: [0x11; 32],
            y_server: y_server_a,
            tau_client: scalar_bytes(3),
            tau_server: tau_server_a,
        })
        .expect("valid synthetic Deriver A contribution"),
        deriver_b: DeriverBContribution::try_from(RawDeriverBContribution {
            y_client: [0x33; 32],
            y_server: y_server_b,
            tau_client: scalar_bytes(7),
            tau_server: tau_server_b,
        })
        .expect("valid synthetic Deriver B contribution"),
    }
}

fn canonical_fixture() -> RefreshFixture {
    refresh_fixture([0x22; 32], scalar_bytes(5), [0x44; 32], scalar_bytes(11))
}

fn refresh_delta(delta_y: [u8; 32], delta_tau: [u8; 32]) -> HostOnlyJointRefreshDeltaCoinsV1 {
    HostOnlyJointRefreshDeltaCoinsV1::new(
        HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(delta_y, delta_tau)
            .expect("canonical Deriver A delta contribution"),
        HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(
            [0; 32],
            Scalar::ZERO.to_bytes(),
        )
        .expect("zero Deriver B contribution is canonical"),
    )
}

fn prepare(
    fixture: &RefreshFixture,
    delta: HostOnlyJointRefreshDeltaCoinsV1,
) -> HostOnlyPreparedRefreshReferenceV1 {
    prepare_host_only_refresh_reference_v1(HostOnlyRefreshReferenceInputsV1::new(
        &fixture.deriver_a,
        &fixture.deriver_b,
        delta,
    ))
    .expect("typed opposite delta preserves activation identity")
}

fn independent_add_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}

fn independent_sub_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
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

fn assert_client_fields_preserved(
    fixture: &RefreshFixture,
    prepared: &HostOnlyPreparedRefreshReferenceV1,
) {
    assert_eq!(
        fixture.deriver_a.y_client().expose_bytes(),
        prepared.refreshed_deriver_a().y_client().expose_bytes()
    );
    assert_eq!(
        fixture.deriver_a.tau_client().expose_bytes(),
        prepared.refreshed_deriver_a().tau_client().expose_bytes()
    );
    assert_eq!(
        fixture.deriver_b.y_client().expose_bytes(),
        prepared.refreshed_deriver_b().y_client().expose_bytes()
    );
    assert_eq!(
        fixture.deriver_b.tau_client().expose_bytes(),
        prepared.refreshed_deriver_b().tau_client().expose_bytes()
    );
}

fn assert_activation_outputs_equal(prepared: &HostOnlyPreparedRefreshReferenceV1) {
    let current = prepared.current_activation().material();
    let refreshed = prepared.refreshed_activation().material();
    assert_eq!(
        current.sha512_digest().expose_bytes(),
        refreshed.sha512_digest().expose_bytes()
    );
    assert_eq!(
        current.clamped_scalar_bytes().expose_bytes(),
        refreshed.clamped_scalar_bytes().expose_bytes()
    );
    assert_eq!(
        current.signing_scalar().expose_bytes(),
        refreshed.signing_scalar().expose_bytes()
    );
    assert_eq!(current.tau().expose_bytes(), refreshed.tau().expose_bytes());
    assert_eq!(
        current.x_client_base().expose_bytes(),
        refreshed.x_client_base().expose_bytes()
    );
    assert_eq!(
        current.x_server_base().expose_bytes(),
        refreshed.x_server_base().expose_bytes()
    );
    assert_eq!(
        current.x_client().expose_bytes(),
        refreshed.x_client().expose_bytes()
    );
    assert_eq!(
        current.x_server().expose_bytes(),
        refreshed.x_server().expose_bytes()
    );
    assert_eq!(
        current.public_key().expose_bytes(),
        refreshed.public_key().expose_bytes()
    );
}

#[test]
fn validated_delta_applies_exact_opposite_server_updates_and_preserves_clients() {
    let fixture = canonical_fixture();
    let delta_y = [0xa5; 32];
    let delta_tau = Scalar::from(17u64);
    let prepared = prepare(&fixture, refresh_delta(delta_y, delta_tau.to_bytes()));

    assert_client_fields_preserved(&fixture, &prepared);
    assert_eq!(
        prepared.refreshed_deriver_a().y_server().expose_bytes(),
        independent_add_le_256(fixture.deriver_a.y_server().expose_bytes(), delta_y)
    );
    assert_eq!(
        prepared.refreshed_deriver_b().y_server().expose_bytes(),
        independent_sub_le_256(fixture.deriver_b.y_server().expose_bytes(), delta_y)
    );
    assert_eq!(
        prepared.refreshed_deriver_a().tau_server().expose_bytes(),
        (Scalar::from(5u64) + delta_tau).to_bytes()
    );
    assert_eq!(
        prepared.refreshed_deriver_b().tau_server().expose_bytes(),
        (Scalar::from(11u64) - delta_tau).to_bytes()
    );
}

#[test]
fn prepared_refresh_checks_every_joined_and_activation_field_equal() {
    let fixture = canonical_fixture();
    let prepared = prepare(
        &fixture,
        refresh_delta([0xa5; 32], Scalar::from(17u64).to_bytes()),
    );

    let current_joined_seed = independent_add_le_256(
        independent_add_le_256(
            fixture.deriver_a.y_client().expose_bytes(),
            fixture.deriver_a.y_server().expose_bytes(),
        ),
        independent_add_le_256(
            fixture.deriver_b.y_client().expose_bytes(),
            fixture.deriver_b.y_server().expose_bytes(),
        ),
    );
    let refreshed_joined_seed = independent_add_le_256(
        independent_add_le_256(
            prepared.refreshed_deriver_a().y_client().expose_bytes(),
            prepared.refreshed_deriver_a().y_server().expose_bytes(),
        ),
        independent_add_le_256(
            prepared.refreshed_deriver_b().y_client().expose_bytes(),
            prepared.refreshed_deriver_b().y_server().expose_bytes(),
        ),
    );
    assert_eq!(current_joined_seed, refreshed_joined_seed);
    let _witness = prepared.continuity_witness();
    assert_activation_outputs_equal(&prepared);
}

#[test]
fn unit_delta_wraps_seed_and_scalar_server_domains_exactly() {
    let fixture = refresh_fixture(
        [0xff; 32],
        SCALAR_ORDER_MINUS_ONE_BYTES,
        [0u8; 32],
        [0u8; 32],
    );
    let prepared = prepare(&fixture, refresh_delta(scalar_bytes(1), scalar_bytes(1)));

    assert_eq!(
        prepared.refreshed_deriver_a().y_server().expose_bytes(),
        [0u8; 32]
    );
    assert_eq!(
        prepared.refreshed_deriver_a().tau_server().expose_bytes(),
        [0u8; 32]
    );
    assert_eq!(
        prepared.refreshed_deriver_b().y_server().expose_bytes(),
        [0xff; 32]
    );
    assert_eq!(
        prepared.refreshed_deriver_b().tau_server().expose_bytes(),
        SCALAR_ORDER_MINUS_ONE_BYTES
    );
    assert_client_fields_preserved(&fixture, &prepared);
    assert_activation_outputs_equal(&prepared);
}

#[test]
fn maximum_nonzero_deltas_wrap_both_opposite_paths_exactly() {
    let fixture = refresh_fixture(
        [0u8; 32],
        [0u8; 32],
        [0xff; 32],
        SCALAR_ORDER_MINUS_ONE_BYTES,
    );
    let prepared = prepare(
        &fixture,
        refresh_delta([0xff; 32], SCALAR_ORDER_MINUS_ONE_BYTES),
    );

    assert_eq!(
        prepared.refreshed_deriver_a().y_server().expose_bytes(),
        [0xff; 32]
    );
    assert_eq!(
        prepared.refreshed_deriver_a().tau_server().expose_bytes(),
        SCALAR_ORDER_MINUS_ONE_BYTES
    );
    assert_eq!(
        prepared.refreshed_deriver_b().y_server().expose_bytes(),
        [0u8; 32]
    );
    assert_eq!(
        prepared.refreshed_deriver_b().tau_server().expose_bytes(),
        [0u8; 32]
    );
    assert_client_fields_preserved(&fixture, &prepared);
    assert_activation_outputs_equal(&prepared);
}

#[test]
fn prepared_refresh_output_shares_reconstruct_zero_small_and_boundary_coins() {
    let fixture = canonical_fixture();

    for (client_coin, signing_worker_coin) in [
        (Scalar::ZERO, Scalar::ZERO),
        (Scalar::ONE, Scalar::from(2u64)),
        (
            Scalar::ZERO - Scalar::ONE,
            Scalar::ZERO - Scalar::from(2u64),
        ),
    ] {
        let prepared = prepare(
            &fixture,
            refresh_delta([0xa5; 32], Scalar::from(17u64).to_bytes()),
        );
        let expected_client = prepared
            .refreshed_activation()
            .material()
            .x_client_base()
            .expose_bytes();
        let expected_signing_worker = prepared
            .refreshed_activation()
            .material()
            .x_server_base()
            .expose_bytes();
        let coins = HostOnlyActivationOutputCoinsV1::new(
            HostOnlyClientScalarOutputCoinV1::from_canonical_fixture_bytes(client_coin.to_bytes())
                .expect("canonical client fixture coin"),
            HostOnlySigningWorkerScalarOutputCoinV1::from_canonical_fixture_bytes(
                signing_worker_coin.to_bytes(),
            )
            .expect("canonical SigningWorker fixture coin"),
        );
        let success = evaluate_host_only_refresh_output_sharing_v1(
            prepared,
            HostOnlyRefreshIdealCoinsV1::from_host_only_fixture(coins),
        );
        assert_eq!(
            reconstruct_host_only_client_scalar_output_v1(
                success.output_shares().deriver_a().client(),
                success.output_shares().deriver_b().client(),
            )
            .expose_bytes(),
            expected_client
        );
        assert_eq!(
            reconstruct_host_only_signing_worker_scalar_output_v1(
                success.output_shares().deriver_a().signing_worker(),
                success.output_shares().deriver_b().signing_worker(),
            )
            .expose_bytes(),
            expected_signing_worker
        );
        assert_activation_outputs_equal(success.prepared());
    }
}

#[test]
fn source_guards_keep_refresh_call_local_synthetic_nonserializable_and_nonproduction() {
    let source = include_str!("../src/refresh_reference.rs");

    for forbidden in [
        "serde",
        "Serialize",
        "Deserialize",
        "rand::",
        "rand_core",
        "getrandom",
        "OsRng",
        "Authorization",
        "Credential",
        "Ciphertext",
        "Package",
        "Receipt",
        "Persistence",
        "wire::",
        "worker::",
        "wasm_bindgen",
        "cloudflare",
        "evaluate_refresh_v1(",
        "evaluate_export",
        "pub const fn seed",
        "pub fn seed",
        "delta: SyntheticCorrelatedServerDeltaV1",
    ] {
        assert!(
            !source.contains(forbidden),
            "blocked dependency or overstated surface `{forbidden}` entered refresh reference"
        );
    }
    assert!(source.contains("delta_coins: HostOnlyJointRefreshDeltaCoinsV1"));

    for declaration in source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub struct ") || line.starts_with("pub enum "))
    {
        let type_name = declaration
            .split_ascii_whitespace()
            .nth(2)
            .expect("public type declaration name")
            .trim_end_matches("<'a>");
        assert!(
            type_name.starts_with("HostOnly"),
            "public refresh type lacks HostOnly prefix: {type_name}"
        );
    }
}
