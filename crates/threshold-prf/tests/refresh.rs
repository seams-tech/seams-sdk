use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::recovery::reconstruct_signing_root;
use threshold_prf::{
    apply_two_party_root_share_refresh, derive_two_party_root_share_refresh_commitments,
    generate_signing_root, generate_two_party_root_share, prove_root_share_knowledge,
    split_signing_root, verify_root_share_knowledge, verify_two_party_root_share_refresh,
    RootShareKnowledgeProof, RootShareRefreshCoefficient, RootShareRefreshCoefficientCommitment,
    RootShareRefreshContributionWire, SigningRootShare, SigningRootShareCommitment,
    ThresholdPolicy, ThresholdPrfError, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
    ValidatedThresholdSet,
};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn canonical_scalar(value: Scalar) -> [u8; 32] {
    value.to_bytes()
}

fn fixed_coefficient(role: TwoPartyDeriverRole, value: Scalar) -> RootShareRefreshCoefficient {
    RootShareRefreshCoefficient::from_canonical_bytes(role, canonical_scalar(value))
        .expect("fixed non-zero refresh coefficient")
}

fn initial_shares() -> (ThresholdPolicy, Vec<SigningRootShare>) {
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("fixed 2-of-2 policy");
    let mut rng = seeded_rng(1);
    let root = generate_signing_root(&mut rng);
    let shares = split_signing_root(&root, policy, &mut rng).expect("fixed root sharing");
    (policy, shares)
}

fn refresh_role_share(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> Result<SigningRootShare, ThresholdPrfError> {
    let verified_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(recipient))?;
    let verified_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))?;
    apply_two_party_root_share_refresh(current, verified_a, verified_b)
}

#[test]
fn distributed_creation_samples_one_nonzero_share_inside_each_role() {
    let share_a = generate_two_party_root_share(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(91));
    let share_b = generate_two_party_root_share(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(92));

    assert_eq!(share_a.id(), TwoPartyDeriverRole::DeriverA.share_id());
    assert_eq!(share_b.id(), TwoPartyDeriverRole::DeriverB.share_id());
    assert_ne!(share_a.to_bytes(), [0_u8; 32]);
    assert_ne!(share_b.to_bytes(), [0_u8; 32]);
    TwoPartyRootShareCommitments::from_shares(&share_a, &share_b)
        .expect("independent role shares define one non-identity tenant root");
}

#[test]
fn contributory_refresh_changes_both_shares_and_preserves_root() {
    let (policy, current) = initial_shares();
    let coefficient_a = fixed_coefficient(TwoPartyDeriverRole::DeriverA, Scalar::from(17_u64));
    let coefficient_b = fixed_coefficient(TwoPartyDeriverRole::DeriverB, Scalar::from(29_u64));
    let next_a = refresh_role_share(
        &current[0],
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    )
    .expect("Deriver A refreshes");
    let next_b = refresh_role_share(
        &current[1],
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    )
    .expect("Deriver B refreshes");

    assert_ne!(next_a.to_bytes(), current[0].to_bytes());
    assert_ne!(next_b.to_bytes(), current[1].to_bytes());
    let current_commitments =
        TwoPartyRootShareCommitments::from_shares(&current[0], &current[1]).unwrap();
    let next_commitments = TwoPartyRootShareCommitments::from_shares(&next_a, &next_b).unwrap();
    let derived_commitments = derive_two_party_root_share_refresh_commitments(
        &current_commitments,
        coefficient_a.commitment(),
        coefficient_b.commitment(),
    )
    .expect("public commitments predict both refreshed shares");
    assert_eq!(derived_commitments, next_commitments);
    verify_two_party_root_share_refresh(&current_commitments, &next_commitments)
        .expect("public root continuity");
    assert_eq!(current_commitments.root(), next_commitments.root());

    let current_root = reconstruct_signing_root(
        &ValidatedThresholdSet::from_signing_root_shares(
            policy,
            vec![current[0].clone(), current[1].clone()],
        )
        .unwrap(),
    )
    .unwrap();
    let next_root = reconstruct_signing_root(
        &ValidatedThresholdSet::from_signing_root_shares(policy, vec![next_a, next_b]).unwrap(),
    )
    .unwrap();
    assert_eq!(current_root.to_bytes(), next_root.to_bytes());
}

#[test]
fn recipient_specific_contributions_have_fixed_wires_and_reject_substitution() {
    let coefficient = fixed_coefficient(TwoPartyDeriverRole::DeriverA, Scalar::from(31_u64));
    let commitment = coefficient.commitment();
    let for_a = coefficient.contribution_for(TwoPartyDeriverRole::DeriverA);
    let for_b = coefficient.contribution_for(TwoPartyDeriverRole::DeriverB);

    assert_eq!(RootShareRefreshCoefficientCommitment::LEN, 34);
    assert_eq!(RootShareRefreshContributionWire::LEN, 36);
    assert_ne!(for_a.to_bytes(), for_b.to_bytes());
    assert_eq!(
        RootShareRefreshCoefficientCommitment::from_bytes(commitment.to_bytes()).unwrap(),
        commitment,
    );
    commitment
        .verify_contribution(RootShareRefreshContributionWire::decode(for_a.to_bytes()).unwrap())
        .expect("A-target contribution verifies");
    commitment
        .verify_contribution(RootShareRefreshContributionWire::decode(for_b.to_bytes()).unwrap())
        .expect("B-target contribution verifies");

    let mut role_swapped = for_b.to_bytes();
    role_swapped[..2].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        commitment
            .verify_contribution(RootShareRefreshContributionWire::decode(role_swapped).unwrap())
            .unwrap_err(),
        ThresholdPrfError::InvalidRefreshContribution,
    );

    let mut scalar_mutated = for_b.to_bytes();
    scalar_mutated[4] ^= 1;
    let scalar_mutated = RootShareRefreshContributionWire::decode(scalar_mutated)
        .expect("mutated scalar remains canonical");
    assert_eq!(
        commitment.verify_contribution(scalar_mutated).unwrap_err(),
        ThresholdPrfError::InvalidRefreshContribution,
    );
}

#[test]
fn cancellation_and_zero_next_share_are_rejected() {
    let (_, current) = initial_shares();
    let current_commitments =
        TwoPartyRootShareCommitments::from_shares(&current[0], &current[1]).unwrap();
    let coefficient_a = fixed_coefficient(TwoPartyDeriverRole::DeriverA, Scalar::from(5_u64));
    let coefficient_b = fixed_coefficient(TwoPartyDeriverRole::DeriverB, -Scalar::from(5_u64));
    assert_eq!(
        derive_two_party_root_share_refresh_commitments(
            &current_commitments,
            coefficient_a.commitment(),
            coefficient_b.commitment(),
        )
        .unwrap_err(),
        ThresholdPrfError::RefreshNoOp,
    );
    assert_eq!(
        refresh_role_share(
            &current[0],
            TwoPartyDeriverRole::DeriverA,
            &coefficient_a,
            &coefficient_b,
        )
        .unwrap_err(),
        ThresholdPrfError::RefreshNoOp,
    );

    let current_a = Option::<Scalar>::from(Scalar::from_canonical_bytes(current[0].to_bytes()))
        .expect("current share scalar");
    let coefficient_a = fixed_coefficient(TwoPartyDeriverRole::DeriverA, Scalar::ONE);
    let coefficient_b = fixed_coefficient(TwoPartyDeriverRole::DeriverB, -current_a - Scalar::ONE);
    assert_eq!(
        derive_two_party_root_share_refresh_commitments(
            &current_commitments,
            coefficient_a.commitment(),
            coefficient_b.commitment(),
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidRootCommitment,
    );
    assert_eq!(
        refresh_role_share(
            &current[0],
            TwoPartyDeriverRole::DeriverA,
            &coefficient_a,
            &coefficient_b,
        )
        .unwrap_err(),
        ThresholdPrfError::ZeroScalar,
    );
}

#[test]
fn public_refresh_rejects_swapped_and_duplicate_coefficient_roles() {
    let (_, current) = initial_shares();
    let current_commitments =
        TwoPartyRootShareCommitments::from_shares(&current[0], &current[1]).unwrap();
    let coefficient_a = fixed_coefficient(TwoPartyDeriverRole::DeriverA, Scalar::from(5_u64));
    let coefficient_b = fixed_coefficient(TwoPartyDeriverRole::DeriverB, Scalar::from(7_u64));

    assert_eq!(
        derive_two_party_root_share_refresh_commitments(
            &current_commitments,
            coefficient_b.commitment(),
            coefficient_a.commitment(),
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidRefreshRole,
    );
    assert_eq!(
        derive_two_party_root_share_refresh_commitments(
            &current_commitments,
            coefficient_a.commitment(),
            coefficient_a.commitment(),
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidRefreshRole,
    );
}

#[test]
fn public_refresh_rejects_collapsed_next_pair() {
    let current_a = SigningRootShare::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA.share_id(),
        Scalar::from(12_u64).to_bytes(),
    )
    .unwrap();
    let current_b = SigningRootShare::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB.share_id(),
        Scalar::from(19_u64).to_bytes(),
    )
    .unwrap();
    let current = TwoPartyRootShareCommitments::from_shares(&current_a, &current_b).unwrap();
    let coefficient_a = fixed_coefficient(TwoPartyDeriverRole::DeriverA, Scalar::ONE);
    let coefficient_b = fixed_coefficient(TwoPartyDeriverRole::DeriverB, -Scalar::from(8_u64));

    assert_eq!(
        derive_two_party_root_share_refresh_commitments(
            &current,
            coefficient_a.commitment(),
            coefficient_b.commitment(),
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidRootCommitment,
    );
}

#[test]
fn public_continuity_rejects_unrelated_next_share_pair() {
    let (_, current) = initial_shares();
    let unrelated_a = SigningRootShare::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA.share_id(),
        Scalar::from(101_u64).to_bytes(),
    )
    .unwrap();
    let unrelated_b = SigningRootShare::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB.share_id(),
        Scalar::from(103_u64).to_bytes(),
    )
    .unwrap();
    let current_commitments =
        TwoPartyRootShareCommitments::from_shares(&current[0], &current[1]).unwrap();
    let unrelated_commitments =
        TwoPartyRootShareCommitments::from_shares(&unrelated_a, &unrelated_b).unwrap();
    assert_eq!(
        verify_two_party_root_share_refresh(&current_commitments, &unrelated_commitments),
        Err(ThresholdPrfError::RefreshContinuityMismatch),
    );
}

#[test]
fn knowledge_proof_round_trips_and_binds_transcript_and_commitment() {
    let (_, shares) = initial_shares();
    let commitment = SigningRootShareCommitment::from_share(&shares[0]);
    let transcript = b"seams/tenant-root-refresh/test-transcript/v1";
    let mut rng = seeded_rng(7);
    let proof = prove_root_share_knowledge(&shares[0], transcript, &mut rng).unwrap();

    assert_eq!(RootShareKnowledgeProof::LEN, 64);
    let decoded = RootShareKnowledgeProof::from_bytes(proof.to_bytes()).unwrap();
    verify_root_share_knowledge(&commitment, transcript, &decoded).unwrap();
    assert_eq!(
        verify_root_share_knowledge(&commitment, b"different transcript", &decoded),
        Err(ThresholdPrfError::InvalidKnowledgeProof),
    );
    let other_commitment = SigningRootShareCommitment::from_share(&shares[1]);
    assert_eq!(
        verify_root_share_knowledge(&other_commitment, transcript, &decoded),
        Err(ThresholdPrfError::InvalidKnowledgeProof),
    );

    let mut identity_nonce = proof.to_bytes();
    identity_nonce[..32].copy_from_slice(&[0_u8; 32]);
    assert_eq!(
        RootShareKnowledgeProof::from_bytes(identity_nonce),
        Err(ThresholdPrfError::InvalidKnowledgeProofEncoding),
    );
}
