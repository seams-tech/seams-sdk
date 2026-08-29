use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::reference::evaluate_direct_reference;
use threshold_prf::{
    apply_two_party_root_share_refresh, complete_ed25519_deriver_a_target_v1,
    complete_ed25519_deriver_b_target_v1, generate_signing_root,
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1, split_signing_root,
    Ed25519DeriverAToBTargetProofBundleV1, Ed25519DeriverBToATargetProofBundleV1, PrfContext,
    PrfPurpose, RootShareRefreshCoefficient, SigningRootShare, SigningRootShareCommitment, SuiteId,
    ThresholdPolicy, ThresholdPrfError, TwoPartyDeriverRole,
};

const STABLE_CONTEXT: &[u8] = b"ed25519-yao/stable-context/v1/test";

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn shares() -> (SigningRootShare, SigningRootShare) {
    let mut rng = seeded_rng(1);
    let root = generate_signing_root(&mut rng);
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("2-of-2 policy");
    let mut shares = split_signing_root(&root, policy, &mut rng).expect("shares");
    (shares.remove(0), shares.remove(0))
}

fn direct_output(root: &threshold_prf::SigningRootScalar, purpose: PrfPurpose) -> [u8; 32] {
    evaluate_direct_reference(
        root,
        &PrfContext::new(SuiteId::Ristretto255Sha512, purpose, STABLE_CONTEXT),
    )
    .expect("direct output")
    .into_bytes()
}

#[test]
fn exact_directions_complete_only_their_role_target_and_match_direct_reference() {
    let (share_a, share_b) = shares();
    let root = threshold_prf::recovery::reconstruct_signing_root(
        &threshold_prf::ValidatedThresholdSet::from_signing_root_shares(
            ThresholdPolicy::from_u16s(2, 2).unwrap(),
            vec![share_a.clone(), share_b.clone()],
        )
        .unwrap(),
    )
    .unwrap();
    let commitment_a = SigningRootShareCommitment::from_share(&share_a);
    let commitment_b = SigningRootShareCommitment::from_share(&share_b);
    let (prepared_a, a_to_b) = prepare_ed25519_deriver_a_target_v1(
        &share_a,
        commitment_b,
        STABLE_CONTEXT,
        &mut seeded_rng(2),
    )
    .unwrap();
    let (prepared_b, b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &share_b,
        commitment_a,
        STABLE_CONTEXT,
        &mut seeded_rng(3),
    )
    .unwrap();

    assert_eq!(
        complete_ed25519_deriver_a_target_v1(prepared_a, &b_to_a)
            .unwrap()
            .into_secret_bytes(),
        direct_output(&root, PrfPurpose::Ed25519DeriverAContributionRoot)
    );
    assert_eq!(
        complete_ed25519_deriver_b_target_v1(prepared_b, &a_to_b)
            .unwrap()
            .into_secret_bytes(),
        direct_output(&root, PrfPurpose::Ed25519DeriverBContributionRoot)
    );
    assert_ne!(
        direct_output(&root, PrfPurpose::Ed25519DeriverAContributionRoot),
        direct_output(&root, PrfPurpose::Ed25519DeriverBContributionRoot)
    );
}

#[test]
fn refresh_preserves_both_role_target_outputs() {
    let (share_a, share_b) = shares();
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(4));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(5));
    let contribution_a_to_b = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverA))
        .unwrap();
    let contribution_b_to_a = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(TwoPartyDeriverRole::DeriverA))
        .unwrap();
    let contribution_a_to_b_for_b = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB))
        .unwrap();
    let contribution_b_to_a_for_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(TwoPartyDeriverRole::DeriverB))
        .unwrap();
    let refreshed_a =
        apply_two_party_root_share_refresh(&share_a, contribution_a_to_b, contribution_b_to_a)
            .unwrap();
    let refreshed_b = apply_two_party_root_share_refresh(
        &share_b,
        contribution_a_to_b_for_b,
        contribution_b_to_a_for_b,
    )
    .unwrap();

    let (prepared_a, a_to_b) = prepare_ed25519_deriver_a_target_v1(
        &refreshed_a,
        SigningRootShareCommitment::from_share(&refreshed_b),
        STABLE_CONTEXT,
        &mut seeded_rng(6),
    )
    .unwrap();
    let (prepared_b, b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &refreshed_b,
        SigningRootShareCommitment::from_share(&refreshed_a),
        STABLE_CONTEXT,
        &mut seeded_rng(7),
    )
    .unwrap();
    let refreshed_output_a = complete_ed25519_deriver_a_target_v1(prepared_a, &b_to_a)
        .unwrap()
        .into_secret_bytes();
    let refreshed_output_b = complete_ed25519_deriver_b_target_v1(prepared_b, &a_to_b)
        .unwrap()
        .into_secret_bytes();

    let (prepared_a, a_to_b) = prepare_ed25519_deriver_a_target_v1(
        &share_a,
        SigningRootShareCommitment::from_share(&share_b),
        STABLE_CONTEXT,
        &mut seeded_rng(8),
    )
    .unwrap();
    let (prepared_b, b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &share_b,
        SigningRootShareCommitment::from_share(&share_a),
        STABLE_CONTEXT,
        &mut seeded_rng(9),
    )
    .unwrap();
    assert_eq!(
        refreshed_output_a,
        complete_ed25519_deriver_a_target_v1(prepared_a, &b_to_a)
            .unwrap()
            .into_secret_bytes()
    );
    assert_eq!(
        refreshed_output_b,
        complete_ed25519_deriver_b_target_v1(prepared_b, &a_to_b)
            .unwrap()
            .into_secret_bytes()
    );
}

#[test]
fn direction_context_commitment_and_proof_substitution_fail_closed() {
    let (share_a, share_b) = shares();
    let (prepared_a, a_to_b) = prepare_ed25519_deriver_a_target_v1(
        &share_a,
        SigningRootShareCommitment::from_share(&share_b),
        STABLE_CONTEXT,
        &mut seeded_rng(10),
    )
    .unwrap();
    assert_eq!(
        Ed25519DeriverBToATargetProofBundleV1::from_slice(a_to_b.as_bytes()).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );

    let (_, b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &share_b,
        SigningRootShareCommitment::from_share(&share_a),
        b"wrong-context",
        &mut seeded_rng(11),
    )
    .unwrap();
    assert_eq!(
        complete_ed25519_deriver_a_target_v1(prepared_a, &b_to_a).unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );

    let (prepared_a, _) = prepare_ed25519_deriver_a_target_v1(
        &share_a,
        SigningRootShareCommitment::from_share(&share_b),
        STABLE_CONTEXT,
        &mut seeded_rng(12),
    )
    .unwrap();
    let (_, valid_b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &share_b,
        SigningRootShareCommitment::from_share(&share_a),
        STABLE_CONTEXT,
        &mut seeded_rng(13),
    )
    .unwrap();
    let mut mutated = *valid_b_to_a.as_bytes();
    mutated[Ed25519DeriverBToATargetProofBundleV1::LEN - 1] ^= 1;
    let mutated = Ed25519DeriverBToATargetProofBundleV1::from_slice(&mutated).unwrap();
    assert_eq!(
        complete_ed25519_deriver_a_target_v1(prepared_a, &mutated).unwrap_err(),
        ThresholdPrfError::InvalidDleqProof
    );

    assert_eq!(Ed25519DeriverAToBTargetProofBundleV1::LEN, 164);
    assert_eq!(Ed25519DeriverBToATargetProofBundleV1::LEN, 164);
}
