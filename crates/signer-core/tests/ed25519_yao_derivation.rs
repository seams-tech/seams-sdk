#![cfg(feature = "ed25519-yao-derivation")]

use curve25519_dalek::scalar::Scalar;
use serde_json::Value;
use signer_core::ed25519_yao_derivation::{
    apply_ed25519_yao_refresh_delta_to_deriver_a_v1,
    apply_ed25519_yao_refresh_delta_to_deriver_b_v1, derive_ed25519_yao_client_contributions_v1,
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, derive_ed25519_yao_joint_refresh_delta_v1,
    Ed25519YaoApplicationBindingFactsV1, Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientDerivationRootV1,
    Ed25519YaoDeriverADerivationRootV1, Ed25519YaoDeriverARefreshDeltaContributionV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBRefreshDeltaContributionV1, Ed25519YaoDeriverBServerContributionV1,
    Ed25519YaoStableKeyDerivationContextV1,
};

const KDF_CORPUS: &str =
    include_str!("../../../tools/ed25519-yao-generator/vectors/ed25519-yao-kdf-v1.json");

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex") as u8;
            let low = (pair[1] as char).to_digit(16).expect("hex") as u8;
            (high << 4) | low
        })
        .collect()
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    decode_hex(value).try_into().expect("32-byte hex")
}

fn string<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut current = value;
    for key in path {
        current = &current[*key];
    }
    current.as_str().expect("string field")
}

#[test]
fn production_kdf_matches_the_committed_independent_corpus() {
    let corpus: Value = serde_json::from_str(KDF_CORPUS).expect("KDF corpus");
    let case = &corpus["cases"][0];
    let application = &case["application_binding"];
    let facts = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse(string(application, &["wallet_id"]))
            .expect("wallet"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse(string(
            application,
            &["near_ed25519_signing_key_id"],
        ))
        .expect("key id"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse(string(
            application,
            &["signing_root_id"],
        ))
        .expect("root id"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(
            application["key_creation_signer_slot"]
                .as_u64()
                .expect("slot") as u32,
        )
        .expect("slot"),
    );
    assert_eq!(
        facts.encode(),
        decode_hex(string(application, &["encoded_hex"]))
    );
    assert_eq!(
        facts.digest(),
        decode_hex_32(string(application, &["digest_sha256_hex"]))
    );

    let context =
        Ed25519YaoStableKeyDerivationContextV1::new(facts.digest(), 2, 1).expect("context");
    assert_eq!(
        context.encode().as_slice(),
        decode_hex(string(case, &["context", "encoded_hex"]))
    );
    assert_eq!(
        context.binding_digest(),
        decode_hex_32(string(case, &["context", "binding_sha256_hex"]))
    );

    let client_root = Ed25519YaoClientDerivationRootV1::from_secret_bytes(decode_hex_32(string(
        case,
        &["synthetic_roots", "client_root_hex"],
    )));
    let deriver_a_root = Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(decode_hex_32(
        string(case, &["synthetic_roots", "deriver_a_root_hex"]),
    ));
    let deriver_b_root = Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(decode_hex_32(
        string(case, &["synthetic_roots", "deriver_b_root_hex"]),
    ));

    let (client_a, client_b) = derive_ed25519_yao_client_contributions_v1(&client_root, &context)
        .expect("client contributions")
        .into_parts();
    let (client_a_y, client_a_tau) = client_a.into_parts();
    let (client_b_y, client_b_tau) = client_b.into_parts();
    assert_eq!(
        client_a_y.into_bytes(),
        decode_hex_32(string(case, &["contributions", "y_client_a_hex"]))
    );
    assert_eq!(
        client_a_tau.into_bytes(),
        decode_hex_32(string(case, &["contributions", "tau_client_a_hex"]))
    );
    assert_eq!(
        client_b_y.into_bytes(),
        decode_hex_32(string(case, &["contributions", "y_client_b_hex"]))
    );
    assert_eq!(
        client_b_tau.into_bytes(),
        decode_hex_32(string(case, &["contributions", "tau_client_b_hex"]))
    );

    let (server_a_y, server_a_tau) =
        derive_ed25519_yao_deriver_a_server_contribution_v1(&deriver_a_root, &context)
            .expect("server A")
            .into_parts();
    let (server_b_y, server_b_tau) =
        derive_ed25519_yao_deriver_b_server_contribution_v1(&deriver_b_root, &context)
            .expect("server B")
            .into_parts();
    assert_eq!(
        server_a_y.into_bytes(),
        decode_hex_32(string(case, &["contributions", "y_server_a_hex"]))
    );
    assert_eq!(
        server_a_tau.into_bytes(),
        decode_hex_32(string(case, &["contributions", "tau_server_a_hex"]))
    );
    assert_eq!(
        server_b_y.into_bytes(),
        decode_hex_32(string(case, &["contributions", "y_server_b_hex"]))
    );
    assert_eq!(
        server_b_tau.into_bytes(),
        decode_hex_32(string(case, &["contributions", "tau_server_b_hex"]))
    );
}

#[test]
fn boundary_rejects_mutable_or_ambiguous_context_shapes() {
    assert!(Ed25519YaoApplicationBindingWalletIdV1::parse("").is_err());
    assert!(Ed25519YaoApplicationBindingSigningKeyIdV1::parse("key id with spaces").is_err());
    assert!(Ed25519YaoApplicationBindingSigningRootIdV1::parse("root\nline").is_err());
    assert!(Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(0).is_err());
    assert!(Ed25519YaoStableKeyDerivationContextV1::new([1; 32], 0, 2).is_err());
    assert!(Ed25519YaoStableKeyDerivationContextV1::new([1; 32], 2, 2).is_err());
    assert_eq!(
        Ed25519YaoStableKeyDerivationContextV1::new([1; 32], 2, 1)
            .expect("reverse")
            .encode(),
        Ed25519YaoStableKeyDerivationContextV1::new([1; 32], 1, 2)
            .expect("forward")
            .encode()
    );
}

#[test]
fn refresh_delta_rotates_role_contributions_and_preserves_the_joined_values() {
    let mut delta_a_y = [0_u8; 32];
    delta_a_y[0] = 1;
    let mut delta_b_y = [0_u8; 32];
    delta_b_y[0] = 2;
    let delta = derive_ed25519_yao_joint_refresh_delta_v1(
        Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(
            delta_a_y,
            Scalar::from(5_u64).to_bytes(),
        )
        .expect("A delta"),
        Ed25519YaoDeriverBRefreshDeltaContributionV1::from_secret_bytes(
            delta_b_y,
            Scalar::from(7_u64).to_bytes(),
        )
        .expect("B delta"),
    )
    .expect("joint delta");
    assert_eq!(delta.delta_y_bytes()[0], 3);
    assert_eq!(delta.delta_tau_bytes(), Scalar::from(12_u64).to_bytes());

    let mut current_a_y = [0_u8; 32];
    current_a_y[0] = 10;
    let mut current_b_y = [0_u8; 32];
    current_b_y[0] = 20;
    let refreshed_a = apply_ed25519_yao_refresh_delta_to_deriver_a_v1(
        Ed25519YaoDeriverAServerContributionV1::from_secret_bytes(
            current_a_y,
            Scalar::from(100_u64).to_bytes(),
        ),
        &delta,
    )
    .expect("refresh A");
    let refreshed_b = apply_ed25519_yao_refresh_delta_to_deriver_b_v1(
        Ed25519YaoDeriverBServerContributionV1::from_secret_bytes(
            current_b_y,
            Scalar::from(200_u64).to_bytes(),
        ),
        &delta,
    )
    .expect("refresh B");
    let (refreshed_a_y, refreshed_a_tau) = refreshed_a.into_parts();
    let (refreshed_b_y, refreshed_b_tau) = refreshed_b.into_parts();
    assert_eq!(refreshed_a_y.into_bytes()[0], 13);
    assert_eq!(refreshed_b_y.into_bytes()[0], 17);
    assert_eq!(
        Scalar::from_canonical_bytes(refreshed_a_tau.into_bytes())
            .into_option()
            .expect("A tau")
            + Scalar::from_canonical_bytes(refreshed_b_tau.into_bytes())
                .into_option()
                .expect("B tau"),
        Scalar::from(300_u64)
    );
}

#[test]
fn refresh_delta_rejects_joint_cancellation_and_noncanonical_tau() {
    let mut one = [0_u8; 32];
    one[0] = 1;
    assert!(derive_ed25519_yao_joint_refresh_delta_v1(
        Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(
            one,
            Scalar::ONE.to_bytes(),
        )
        .expect("A delta"),
        Ed25519YaoDeriverBRefreshDeltaContributionV1::from_secret_bytes(
            [0xff; 32],
            Scalar::ONE.to_bytes(),
        )
        .expect("B delta"),
    )
    .is_err());
    assert!(derive_ed25519_yao_joint_refresh_delta_v1(
        Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(
            one,
            Scalar::ONE.to_bytes(),
        )
        .expect("A delta"),
        Ed25519YaoDeriverBRefreshDeltaContributionV1::from_secret_bytes(
            one,
            (-Scalar::ONE).to_bytes(),
        )
        .expect("B delta"),
    )
    .is_err());
    assert!(
        Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(one, [0xff; 32]).is_err()
    );
}
