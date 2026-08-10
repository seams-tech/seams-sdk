use router_ab_ecdsa_derivation::{
    derive_client_share, derive_ecdsa_lane_delta_from_source_share32_v1,
    derive_relayer_share_for_client_public, rebind_ecdsa_lane_relayer_share_bytes_v1,
    sample_ecdsa_lane_client_share_v1, EcdsaLanePublicIdentityBindingV1,
    RouterAbEcdsaDerivationStableKeyContext,
};

fn context() -> RouterAbEcdsaDerivationStableKeyContext {
    RouterAbEcdsaDerivationStableKeyContext::new([0x51; 32])
}

#[test]
fn additive_rebind_preserves_threshold_public_identity() {
    let context = context();
    let source_client = derive_client_share(&context, [0x11; 32]).expect("source client");
    let (source_relayer, source_identity) = derive_relayer_share_for_client_public(
        &context,
        [0x22; 32],
        &source_client.derivation_client_share_public_key33,
        source_client.retry_counter,
    )
    .expect("source relayer");
    let target_client = sample_ecdsa_lane_client_share_v1([0x33; 32]).expect("target client");
    let delta = derive_ecdsa_lane_delta_from_source_share32_v1(
        source_client.x_client32,
        &target_client,
    )
    .expect("delta");
    let rebound = rebind_ecdsa_lane_relayer_share_bytes_v1(
        source_relayer.x_relayer32,
        &EcdsaLanePublicIdentityBindingV1 {
            source_client_public_key33: source_identity.derivation_client_share_public_key33,
            source_relayer_public_key33: source_identity.relayer_public_key33,
            threshold_public_key33: source_identity.threshold_public_key33,
            threshold_ethereum_address20: source_identity.threshold_ethereum_address20,
        },
        &delta,
        *target_client.public_key33(),
    )
    .expect("target relayer");

    assert_eq!(
        rebound.target_threshold_public_key33,
        source_identity.threshold_public_key33
    );
    assert_eq!(
        rebound.target_ethereum_address20,
        source_identity.threshold_ethereum_address20
    );
    assert_eq!(
        format!("{rebound:?}").contains("<redacted>"),
        true,
        "rebind debug must redact the target relayer scalar",
    );
}

#[test]
fn additive_rebind_rejects_target_commitment_substitution() {
    let context = context();
    let source_client = derive_client_share(&context, [0x11; 32]).expect("source client");
    let (source_relayer, source_identity) = derive_relayer_share_for_client_public(
        &context,
        [0x22; 32],
        &source_client.derivation_client_share_public_key33,
        source_client.retry_counter,
    )
    .expect("source relayer");
    let target_client = sample_ecdsa_lane_client_share_v1([0x33; 32]).expect("target client");
    let delta = derive_ecdsa_lane_delta_from_source_share32_v1(
        source_client.x_client32,
        &target_client,
    )
    .expect("delta");
    let mut substituted_target = *target_client.public_key33();
    substituted_target[1] ^= 1;
    let result = rebind_ecdsa_lane_relayer_share_bytes_v1(
        source_relayer.x_relayer32,
        &EcdsaLanePublicIdentityBindingV1 {
            source_client_public_key33: source_identity.derivation_client_share_public_key33,
            source_relayer_public_key33: source_identity.relayer_public_key33,
            threshold_public_key33: source_identity.threshold_public_key33,
            threshold_ethereum_address20: source_identity.threshold_ethereum_address20,
        },
        &delta,
        substituted_target,
    );
    assert!(result.is_err());
}
