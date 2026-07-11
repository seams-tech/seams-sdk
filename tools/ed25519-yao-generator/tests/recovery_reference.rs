use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    derive_synthetic_client_contributions_v1, derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1,
    evaluate_host_only_recovery_output_sharing_v1, prepare_host_only_recovery_reference_v1,
    reconstruct_host_only_client_scalar_output_v1,
    reconstruct_host_only_signing_worker_scalar_output_v1, DeriverAContribution,
    DeriverBContribution, HostOnlyActivationOutputCoinsV1, HostOnlyClientScalarOutputCoinV1,
    HostOnlyPreparedRecoveryReferenceV1, HostOnlyRecoveryIdealCoinsV1,
    HostOnlyRecoveryReferenceErrorV1, HostOnlyRecoveryReferenceInputsV1,
    HostOnlySigningWorkerScalarOutputCoinV1, RawDeriverAContribution, RawDeriverBContribution,
    StableKeyDerivationContext, SyntheticClientContributionsV1, SyntheticClientDerivationRootV1,
    SyntheticDeriverADerivationRootV1, SyntheticDeriverBDerivationRootV1,
};

struct RecoveryFixture {
    context: StableKeyDerivationContext,
    current_root: SyntheticClientDerivationRootV1,
    deriver_a: DeriverAContribution,
    deriver_b: DeriverBContribution,
}

fn recovery_fixture() -> RecoveryFixture {
    let context = StableKeyDerivationContext::new([0x42; 32], 1, 2)
        .expect("synthetic stable context is valid");
    let current_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x11; 32]);
    let client = derive_synthetic_client_contributions_v1(&current_root, &context);
    let server_a = derive_synthetic_deriver_a_server_contribution_v1(
        &SyntheticDeriverADerivationRootV1::from_fixture_bytes([0x22; 32]),
        &context,
    );
    let server_b = derive_synthetic_deriver_b_server_contribution_v1(
        &SyntheticDeriverBDerivationRootV1::from_fixture_bytes([0x33; 32]),
        &context,
    );

    RecoveryFixture {
        deriver_a: deriver_a_from_fields(
            &client,
            server_a.y().expose_fixture_bytes(),
            server_a.tau().expose_fixture_bytes(),
        ),
        deriver_b: deriver_b_from_fields(
            &client,
            server_b.y().expose_fixture_bytes(),
            server_b.tau().expose_fixture_bytes(),
        ),
        context,
        current_root,
    }
}

fn deriver_a_from_fields(
    client: &SyntheticClientContributionsV1,
    y_server: [u8; 32],
    tau_server: [u8; 32],
) -> DeriverAContribution {
    DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: client.deriver_a().y().expose_fixture_bytes(),
        y_server,
        tau_client: client.deriver_a().tau().expose_fixture_bytes(),
        tau_server,
    })
    .expect("synthetic Deriver A contribution is valid")
}

fn deriver_b_from_fields(
    client: &SyntheticClientContributionsV1,
    y_server: [u8; 32],
    tau_server: [u8; 32],
) -> DeriverBContribution {
    DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: client.deriver_b().y().expose_fixture_bytes(),
        y_server,
        tau_client: client.deriver_b().tau().expose_fixture_bytes(),
        tau_server,
    })
    .expect("synthetic Deriver B contribution is valid")
}

fn prepare<'a>(
    fixture: &'a RecoveryFixture,
    recovered_root: &'a SyntheticClientDerivationRootV1,
) -> Result<HostOnlyPreparedRecoveryReferenceV1, HostOnlyRecoveryReferenceErrorV1> {
    prepare_with_contributions(
        fixture,
        recovered_root,
        &fixture.deriver_a,
        &fixture.deriver_b,
    )
}

fn prepare_with_contributions(
    fixture: &RecoveryFixture,
    recovered_root: &SyntheticClientDerivationRootV1,
    deriver_a: &DeriverAContribution,
    deriver_b: &DeriverBContribution,
) -> Result<HostOnlyPreparedRecoveryReferenceV1, HostOnlyRecoveryReferenceErrorV1> {
    prepare_host_only_recovery_reference_v1(HostOnlyRecoveryReferenceInputsV1::new(
        &fixture.current_root,
        recovered_root,
        &fixture.context,
        deriver_a,
        deriver_b,
    ))
}

fn changed_canonical_scalar(bytes: [u8; 32]) -> [u8; 32] {
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("validated fixture scalar remains canonical");
    (scalar + Scalar::ONE).to_bytes()
}

fn assert_activation_outputs_equal(prepared: &HostOnlyPreparedRecoveryReferenceV1) {
    let current = prepared.current_activation().material();
    let recovered = prepared.recovered_activation().material();
    assert_eq!(
        current.sha512_digest().expose_bytes(),
        recovered.sha512_digest().expose_bytes()
    );
    assert_eq!(
        current.clamped_scalar_bytes().expose_bytes(),
        recovered.clamped_scalar_bytes().expose_bytes()
    );
    assert_eq!(
        current.signing_scalar().expose_bytes(),
        recovered.signing_scalar().expose_bytes()
    );
    assert_eq!(current.tau().expose_bytes(), recovered.tau().expose_bytes());
    assert_eq!(
        current.x_client_base().expose_bytes(),
        recovered.x_client_base().expose_bytes()
    );
    assert_eq!(
        current.x_server_base().expose_bytes(),
        recovered.x_server_base().expose_bytes()
    );
    assert_eq!(
        current.x_client().expose_bytes(),
        recovered.x_client().expose_bytes()
    );
    assert_eq!(
        current.x_server().expose_bytes(),
        recovered.x_server().expose_bytes()
    );
    assert_eq!(
        current.public_key().expose_bytes(),
        recovered.public_key().expose_bytes()
    );
}

#[test]
fn same_root_preparation_rederives_clients_and_checks_all_activation_fields_equal() {
    let fixture = recovery_fixture();
    let recovered_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x11; 32]);
    let prepared = prepare(&fixture, &recovered_root).expect("same-root recovery must prepare");

    assert_eq!(
        prepared
            .rederived_client()
            .deriver_a()
            .y()
            .expose_fixture_bytes(),
        fixture.deriver_a.y_client().expose_bytes()
    );
    assert_eq!(
        prepared
            .rederived_client()
            .deriver_a()
            .tau()
            .expose_fixture_bytes(),
        fixture.deriver_a.tau_client().expose_bytes()
    );
    assert_eq!(
        prepared
            .rederived_client()
            .deriver_b()
            .y()
            .expose_fixture_bytes(),
        fixture.deriver_b.y_client().expose_bytes()
    );
    assert_eq!(
        prepared
            .rederived_client()
            .deriver_b()
            .tau()
            .expose_fixture_bytes(),
        fixture.deriver_b.tau_client().expose_bytes()
    );
    let _witness = prepared.continuity_witness();
    assert_activation_outputs_equal(&prepared);
}

#[test]
fn changed_recovered_root_is_rejected_without_consuming_retry_inputs() {
    let fixture = recovery_fixture();
    let changed_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x12; 32]);
    assert!(matches!(
        prepare(&fixture, &changed_root),
        Err(HostOnlyRecoveryReferenceErrorV1::RecoveredClientRootMismatch)
    ));

    let retry_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x11; 32]);
    let retry = prepare(&fixture, &retry_root).expect("borrowed inputs remain available for retry");
    assert_activation_outputs_equal(&retry);
}

#[test]
fn deriver_a_client_y_and_tau_mismatches_are_rejected_precisely() {
    let fixture = recovery_fixture();
    let recovered_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x11; 32]);
    let wrong_y = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: [0xfe; 32],
        y_server: fixture.deriver_a.y_server().expose_bytes(),
        tau_client: fixture.deriver_a.tau_client().expose_bytes(),
        tau_server: fixture.deriver_a.tau_server().expose_bytes(),
    })
    .expect("mutated A y remains structurally valid");
    assert!(matches!(
        prepare_with_contributions(&fixture, &recovered_root, &wrong_y, &fixture.deriver_b),
        Err(HostOnlyRecoveryReferenceErrorV1::DeriverAClientYContributionMismatch)
    ));

    let wrong_tau = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: fixture.deriver_a.y_client().expose_bytes(),
        y_server: fixture.deriver_a.y_server().expose_bytes(),
        tau_client: changed_canonical_scalar(fixture.deriver_a.tau_client().expose_bytes()),
        tau_server: fixture.deriver_a.tau_server().expose_bytes(),
    })
    .expect("mutated A tau remains canonical");
    assert!(matches!(
        prepare_with_contributions(&fixture, &recovered_root, &wrong_tau, &fixture.deriver_b),
        Err(HostOnlyRecoveryReferenceErrorV1::DeriverAClientTauContributionMismatch)
    ));
}

#[test]
fn deriver_b_client_y_and_tau_mismatches_are_rejected_precisely() {
    let fixture = recovery_fixture();
    let recovered_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x11; 32]);
    let wrong_y = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: [0xfd; 32],
        y_server: fixture.deriver_b.y_server().expose_bytes(),
        tau_client: fixture.deriver_b.tau_client().expose_bytes(),
        tau_server: fixture.deriver_b.tau_server().expose_bytes(),
    })
    .expect("mutated B y remains structurally valid");
    assert!(matches!(
        prepare_with_contributions(&fixture, &recovered_root, &fixture.deriver_a, &wrong_y),
        Err(HostOnlyRecoveryReferenceErrorV1::DeriverBClientYContributionMismatch)
    ));

    let wrong_tau = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: fixture.deriver_b.y_client().expose_bytes(),
        y_server: fixture.deriver_b.y_server().expose_bytes(),
        tau_client: changed_canonical_scalar(fixture.deriver_b.tau_client().expose_bytes()),
        tau_server: fixture.deriver_b.tau_server().expose_bytes(),
    })
    .expect("mutated B tau remains canonical");
    assert!(matches!(
        prepare_with_contributions(&fixture, &recovered_root, &fixture.deriver_a, &wrong_tau),
        Err(HostOnlyRecoveryReferenceErrorV1::DeriverBClientTauContributionMismatch)
    ));
}

#[test]
fn validated_server_fields_are_preserved_and_shared_outputs_reconstruct() {
    let mut fixture = recovery_fixture();
    let client = derive_synthetic_client_contributions_v1(&fixture.current_root, &fixture.context);
    fixture.deriver_a = deriver_a_from_fields(&client, [0xa1; 32], Scalar::from(101u64).to_bytes());
    fixture.deriver_b = deriver_b_from_fields(&client, [0xb2; 32], Scalar::from(103u64).to_bytes());
    let recovered_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x11; 32]);
    let prepared = prepare(&fixture, &recovered_root).expect("arbitrary server state is accepted");
    assert_eq!(
        prepared.recovered_deriver_a().y_server().expose_bytes(),
        fixture.deriver_a.y_server().expose_bytes()
    );
    assert_eq!(
        prepared.recovered_deriver_a().tau_server().expose_bytes(),
        fixture.deriver_a.tau_server().expose_bytes()
    );
    assert_eq!(
        prepared.recovered_deriver_b().y_server().expose_bytes(),
        fixture.deriver_b.y_server().expose_bytes()
    );
    assert_eq!(
        prepared.recovered_deriver_b().tau_server().expose_bytes(),
        fixture.deriver_b.tau_server().expose_bytes()
    );

    let expected_client = prepared
        .recovered_activation()
        .material()
        .x_client_base()
        .expose_bytes();
    let expected_signing_worker = prepared
        .recovered_activation()
        .material()
        .x_server_base()
        .expose_bytes();
    for (client_coin, signing_worker_coin) in [
        (Scalar::ZERO, Scalar::ZERO),
        (Scalar::ONE, Scalar::from(2u64)),
        (
            Scalar::ZERO - Scalar::ONE,
            Scalar::ZERO - Scalar::from(2u64),
        ),
    ] {
        let prepared = prepare(&fixture, &recovered_root)
            .expect("same recovery state supports each public fixture coin pair");
        let coins = HostOnlyActivationOutputCoinsV1::new(
            HostOnlyClientScalarOutputCoinV1::from_canonical_fixture_bytes(client_coin.to_bytes())
                .expect("canonical client fixture coin"),
            HostOnlySigningWorkerScalarOutputCoinV1::from_canonical_fixture_bytes(
                signing_worker_coin.to_bytes(),
            )
            .expect("canonical SigningWorker fixture coin"),
        );
        let success = evaluate_host_only_recovery_output_sharing_v1(
            prepared,
            HostOnlyRecoveryIdealCoinsV1::from_host_only_fixture(coins),
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
fn source_guards_keep_recovery_public_synthetic_nonserializable_and_nonproduction() {
    let source = include_str!("../src/recovery_reference.rs");

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
        "evaluate_recovery_v1(",
        "evaluate_export",
        "pub const fn seed",
        "pub fn seed",
    ] {
        assert!(
            !source.contains(forbidden),
            "blocked dependency or overstated surface `{forbidden}` entered recovery reference"
        );
    }

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
            "public recovery type lacks HostOnly prefix: {type_name}"
        );
    }
}
