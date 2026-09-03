use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverAPrefaceInFlightV2,
    Ed25519YaoDeriverAToBTargetProofPayloadV2, Ed25519YaoDeriverBPrefaceInFlightV2,
    Ed25519YaoDeriverBToATargetProofPayloadV2, Ed25519YaoInputKindV1, Ed25519YaoOperationV1,
    Ed25519YaoOuterBindingV2, Ed25519YaoPairSessionIdV2, Ed25519YaoPrefaceStateV2,
    Ed25519YaoStableKeyContextBindingV1, LifecycleScopeV1, MpcMaterialActivationRefV1,
    PublicDigest32, RootShareEpoch, RouterAbEd25519YaoPrefaceRequestV2,
};
use threshold_prf::{
    generate_signing_root, prepare_ed25519_deriver_a_target_v1,
    prepare_ed25519_deriver_b_target_v1, split_signing_root, SigningRootShareCommitment,
    ThresholdPolicy,
};

const STABLE_CONTEXT_BINDING: [u8; 32] = [2; 32];

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn ceremony() -> Ed25519YaoCeremonyBindingV1 {
    Ed25519YaoCeremonyBindingV1::new(
        LifecycleScopeV1::new(
            "lifecycle-1",
            router_ab_core::ExpensiveWorkKindV1::RegistrationPrepare,
            RootShareEpoch::new("epoch-1").expect("epoch"),
            "account-1",
            "session-1",
            "signer-set-1",
            "server-1",
        )
        .expect("lifecycle"),
        Ed25519YaoOperationV1::Registration,
        router_ab_core::Ed25519YaoSessionIdV1::new([1; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(STABLE_CONTEXT_BINDING),
        MpcMaterialActivationRefV1::new(
            "activation-1",
            "capability-1",
            "account-1",
            "key-1",
            "lifecycle-1",
            "server-1",
        )
        .expect("activation"),
    )
    .expect("ceremony")
}

fn outer_binding() -> Ed25519YaoOuterBindingV2 {
    Ed25519YaoOuterBindingV2::new(
        Ed25519YaoPairSessionIdV2::new([1; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(STABLE_CONTEXT_BINDING),
        PublicDigest32::new([3; 32]),
        [4; 16],
        10,
        100,
    )
    .expect("outer binding")
}

#[test]
fn outer_binding_is_epoch_bound_and_directional_payloads_are_fixed() {
    let binding = outer_binding();
    let wire = serde_json::to_vec(&binding).expect("binding wire");
    let decoded = serde_json::from_slice::<Ed25519YaoOuterBindingV2>(&wire).expect("binding");
    assert_eq!(decoded, binding);
    assert!(Ed25519YaoOuterBindingV2::new(
        Ed25519YaoPairSessionIdV2::new([1; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(STABLE_CONTEXT_BINDING),
        PublicDigest32::new([3; 32]),
        [4; 16],
        10,
        100 + router_ab_core::ED25519_YAO_OUTER_MAX_LIFETIME_MS_V2,
    )
    .is_err());

    let a_to_b = Ed25519YaoDeriverAToBTargetProofPayloadV2::new(
        binding,
        [5; 32],
        vec![6; threshold_prf::Ed25519DeriverAToBTargetProofBundleV1::LEN + 16],
    )
    .expect("A-to-B payload");
    let b_to_a = Ed25519YaoDeriverBToATargetProofPayloadV2::new(
        binding,
        [7; 32],
        vec![8; threshold_prf::Ed25519DeriverBToATargetProofBundleV1::LEN + 16],
    )
    .expect("B-to-A payload");
    assert!(a_to_b.decode_plaintext(&[0; 164]).is_err());
    assert!(b_to_a.decode_plaintext(&[0; 164]).is_err());

    let request = RouterAbEd25519YaoPrefaceRequestV2::new(
        ceremony(),
        binding,
        router_ab_core::Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            router_ab_core::Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            [1; 32],
            STABLE_CONTEXT_BINDING,
            [5; 32],
            vec![6; 32],
        )
        .expect("A input"),
        router_ab_core::Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            router_ab_core::Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoOperationV1::Registration,
            [1; 32],
            STABLE_CONTEXT_BINDING,
            [7; 32],
            vec![8; 32],
        )
        .expect("B input"),
        a_to_b,
        b_to_a,
    )
    .expect("preface request");
    let wire = serde_json::to_vec(&request).expect("request wire");
    assert!(serde_json::from_slice::<RouterAbEd25519YaoPrefaceRequestV2>(&wire).is_ok());
}

#[test]
fn directional_payload_fixed_wires_round_trip_and_reject_role_swaps() {
    let binding = outer_binding();
    let a_to_b = Ed25519YaoDeriverAToBTargetProofPayloadV2::new(
        binding,
        [5; 32],
        vec![6; threshold_prf::Ed25519DeriverAToBTargetProofBundleV1::LEN + 16],
    )
    .expect("A-to-B payload");
    let b_to_a = Ed25519YaoDeriverBToATargetProofPayloadV2::new(
        binding,
        [7; 32],
        vec![8; threshold_prf::Ed25519DeriverBToATargetProofBundleV1::LEN + 16],
    )
    .expect("B-to-A payload");

    let a_wire = a_to_b.encode_fixed_wire().expect("A-to-B wire");
    let b_wire = b_to_a.encode_fixed_wire().expect("B-to-A wire");
    assert_eq!(
        Ed25519YaoDeriverAToBTargetProofPayloadV2::decode_fixed_wire(&a_wire)
            .expect("A-to-B decode"),
        a_to_b
    );
    assert_eq!(
        Ed25519YaoDeriverBToATargetProofPayloadV2::decode_fixed_wire(&b_wire)
            .expect("B-to-A decode"),
        b_to_a
    );
    assert!(Ed25519YaoDeriverBToATargetProofPayloadV2::decode_fixed_wire(&a_wire).is_err());
    assert!(Ed25519YaoDeriverAToBTargetProofPayloadV2::decode_fixed_wire(&b_wire).is_err());

    let mut changed_binding = a_wire;
    changed_binding[0] ^= 1;
    assert!(
        Ed25519YaoDeriverAToBTargetProofPayloadV2::decode_fixed_wire(&changed_binding).is_err()
    );
}

#[test]
fn preface_state_completes_only_the_local_target() {
    let mut setup_rng = seeded_rng(1);
    let root = generate_signing_root(&mut setup_rng);
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("policy");
    let mut shares = split_signing_root(&root, policy, &mut setup_rng).expect("shares");
    let share_a = shares.remove(0);
    let share_b = shares.remove(0);
    let (prepared_a, a_to_b) = prepare_ed25519_deriver_a_target_v1(
        &share_a,
        SigningRootShareCommitment::from_share(&share_b),
        b"stable-context",
        &mut seeded_rng(2),
    )
    .expect("A prepare");
    let (prepared_b, b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &share_b,
        SigningRootShareCommitment::from_share(&share_a),
        b"stable-context",
        &mut seeded_rng(3),
    )
    .expect("B prepare");
    let a_to_b_plaintext = *a_to_b.as_bytes();
    let b_to_a_plaintext = *b_to_a.as_bytes();
    let binding = outer_binding();
    let incoming_b_to_a = Ed25519YaoDeriverBToATargetProofPayloadV2::new(
        binding,
        [7; 32],
        vec![8; threshold_prf::Ed25519DeriverBToATargetProofBundleV1::LEN + 16],
    )
    .expect("B-to-A payload");
    let incoming_a_to_b = Ed25519YaoDeriverAToBTargetProofPayloadV2::new(
        binding,
        [5; 32],
        vec![6; threshold_prf::Ed25519DeriverAToBTargetProofBundleV1::LEN + 16],
    )
    .expect("A-to-B payload");

    let a_state = Ed25519YaoPrefaceStateV2::DeriverAAwaiting(
        Ed25519YaoDeriverAPrefaceInFlightV2::new(binding, prepared_a, a_to_b).expect("A state"),
    )
    .complete_deriver_a(&incoming_b_to_a, &b_to_a_plaintext)
    .expect("A complete");
    let b_state = Ed25519YaoPrefaceStateV2::DeriverBAwaiting(
        Ed25519YaoDeriverBPrefaceInFlightV2::new(binding, prepared_b, b_to_a).expect("B state"),
    )
    .complete_deriver_b(&incoming_a_to_b, &a_to_b_plaintext)
    .expect("B complete");

    match a_state {
        Ed25519YaoPrefaceStateV2::DeriverAReady(ready) => {
            assert_ne!(
                *ready.into_threshold_prf_root().into_secret_bytes(),
                [0; 32]
            );
        }
        _ => panic!("A must enter its typed ready state"),
    }
    match b_state {
        Ed25519YaoPrefaceStateV2::DeriverBReady(ready) => {
            assert_ne!(
                *ready.into_threshold_prf_root().into_secret_bytes(),
                [0; 32]
            );
        }
        _ => panic!("B must enter its typed ready state"),
    }
}
