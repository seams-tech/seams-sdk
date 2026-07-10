use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    derive_synthetic_client_contributions_v1, derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1, StableKeyDerivationContext,
    SyntheticClientDerivationRootV1, SyntheticDeriverADerivationRootV1,
    SyntheticDeriverBDerivationRootV1, CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
    CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1, CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1,
    CONTRIBUTION_KDF_EXTRACT_SALT_V1, CONTRIBUTION_KDF_ROLE_A_TAG_V1,
    CONTRIBUTION_KDF_ROLE_B_TAG_V1, CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
    CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1, CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
};

fn context(application_byte: u8, first: u16, second: u16) -> StableKeyDerivationContext {
    StableKeyDerivationContext::new([application_byte; 32], first, second)
        .expect("fixed synthetic context is valid")
}

fn client_root(byte: u8) -> SyntheticClientDerivationRootV1 {
    SyntheticClientDerivationRootV1::from_fixture_bytes([byte; 32])
}

fn deriver_a_root(byte: u8) -> SyntheticDeriverADerivationRootV1 {
    SyntheticDeriverADerivationRootV1::from_fixture_bytes([byte; 32])
}

fn deriver_b_root(byte: u8) -> SyntheticDeriverBDerivationRootV1 {
    SyntheticDeriverBDerivationRootV1::from_fixture_bytes([byte; 32])
}

#[test]
fn fixed_domains_and_tags_are_frozen() {
    assert_eq!(
        CONTRIBUTION_KDF_EXTRACT_SALT_V1,
        b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/extract/v1"
    );
    assert_eq!(
        CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1,
        b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/expand/v1"
    );
    assert_eq!(
        CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1,
        CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1.len() + 36
    );
    assert_eq!(CONTRIBUTION_KDF_ROLE_A_TAG_V1, 0x01);
    assert_eq!(CONTRIBUTION_KDF_ROLE_B_TAG_V1, 0x02);
    assert_eq!(CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1, 0x01);
    assert_eq!(CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1, 0x02);
    assert_eq!(CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1, 0x01);
    assert_eq!(CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1, 0x02);
}

#[test]
fn derivation_is_deterministic_and_binds_the_stable_context() {
    let stable = context(0x42, 1, 2);
    let changed = context(0x43, 1, 2);
    let root = client_root(0x11);

    let first = derive_synthetic_client_contributions_v1(&root, &stable);
    let repeat = derive_synthetic_client_contributions_v1(&root, &stable);
    let changed_context = derive_synthetic_client_contributions_v1(&root, &changed);

    assert_eq!(
        first.deriver_a().y().expose_fixture_bytes(),
        repeat.deriver_a().y().expose_fixture_bytes()
    );
    assert_eq!(
        first.deriver_b().tau().expose_fixture_bytes(),
        repeat.deriver_b().tau().expose_fixture_bytes()
    );
    assert_ne!(
        first.deriver_a().y().expose_fixture_bytes(),
        changed_context.deriver_a().y().expose_fixture_bytes()
    );
    assert_ne!(
        first.deriver_b().tau().expose_fixture_bytes(),
        changed_context.deriver_b().tau().expose_fixture_bytes()
    );
}

#[test]
fn role_source_and_output_domains_are_disjoint() {
    let stable = context(0x42, 1, 2);
    let client = derive_synthetic_client_contributions_v1(&client_root(0x55), &stable);
    let server_a =
        derive_synthetic_deriver_a_server_contribution_v1(&deriver_a_root(0x55), &stable);
    let server_b =
        derive_synthetic_deriver_b_server_contribution_v1(&deriver_b_root(0x55), &stable);

    let y_values = [
        client.deriver_a().y().expose_fixture_bytes(),
        client.deriver_b().y().expose_fixture_bytes(),
        server_a.y().expose_fixture_bytes(),
        server_b.y().expose_fixture_bytes(),
    ];
    let tau_values = [
        client.deriver_a().tau().expose_fixture_bytes(),
        client.deriver_b().tau().expose_fixture_bytes(),
        server_a.tau().expose_fixture_bytes(),
        server_b.tau().expose_fixture_bytes(),
    ];

    for left in 0..y_values.len() {
        for right in left + 1..y_values.len() {
            assert_ne!(y_values[left], y_values[right]);
            assert_ne!(tau_values[left], tau_values[right]);
        }
        assert_ne!(y_values[left], tau_values[left]);
        assert!(bool::from(
            Scalar::from_canonical_bytes(tau_values[left]).is_some()
        ));
    }
}

#[test]
fn participant_order_and_lifecycle_independent_reuse_preserve_contributions() {
    let forward = context(0x42, 1, 2);
    let reversed = context(0x42, 2, 1);
    let root = deriver_a_root(0x22);

    let registration = derive_synthetic_deriver_a_server_contribution_v1(&root, &forward);
    let later_ceremony = derive_synthetic_deriver_a_server_contribution_v1(&root, &reversed);

    assert_eq!(
        registration.y().expose_fixture_bytes(),
        later_ceremony.y().expose_fixture_bytes()
    );
    assert_eq!(
        registration.tau().expose_fixture_bytes(),
        later_ceremony.tau().expose_fixture_bytes()
    );
}
