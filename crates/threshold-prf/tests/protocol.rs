use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::reference::evaluate_direct_reference;
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    combine_verified_partials, evaluate_partial, evaluate_partial_with_dleq_proof,
    generate_signing_root, split_signing_root, PrfDleqProof, PrfPartial, PrfPartialWire,
    SigningRootShareCommitment, SigningRootShareWire, ThresholdPolicy, ThresholdShareId,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfOutputEncoding, PrfPurpose, SuiteId, ThresholdPrfError};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn policy_3_of_5() -> ThresholdPolicy {
    ThresholdPolicy::from_u16s(3, 5).expect("valid test policy")
}

fn context(label: &[u8]) -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
        PrfPurpose::EcdsaHssYServer,
        label.to_vec(),
    )
}

fn production_purpose_cases() -> [(PrfPurpose, &'static str); 5] {
    [
        (PrfPurpose::EcdsaHssYServer, "ecdsa-hss/y_server"),
        (PrfPurpose::Ed25519HssYServer, "ed25519-hss/y_server"),
        (PrfPurpose::Ed25519HssTauServer, "ed25519-hss/tau_server"),
        (
            PrfPurpose::RouterAbXClientBaseV1,
            "router-ab/x_client_base/v1",
        ),
        (
            PrfPurpose::RouterAbXServerBaseV1,
            "router-ab/x_server_base/v1",
        ),
    ]
}

fn generated_context(case_index: u8, purpose: PrfPurpose, label: &str) -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        format!("threshold-prf/canonical/test/{case_index}/{label}").into_bytes(),
    )
}

fn partial_set(
    policy: ThresholdPolicy,
    partials: Vec<PrfPartial>,
) -> ValidatedThresholdSet<PrfPartial> {
    ValidatedThresholdSet::from_partials(policy, partials).expect("valid test partial set")
}

fn compressed_fixture_point(value: u64) -> [u8; 32] {
    (Scalar::from(value) * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes()
}

#[test]
fn wire_widths_are_pinned() {
    assert_eq!(SigningRootShareWire::LEN, 34);
    assert_eq!(PrfPartialWire::LEN, 66);
    assert_eq!(SigningRootShareCommitment::LEN, 34);
    assert_eq!(PrfDleqProof::LEN, 64);
}

#[test]
fn generated_outputs_match_direct_reference_for_all_purposes() {
    for (case_index, (purpose, label)) in production_purpose_cases().into_iter().enumerate() {
        let policy = policy_3_of_5();
        let mut rng = seeded_rng(case_index as u8 + 1);
        let root = generate_signing_root(&mut rng);
        let shares = split_signing_root(&root, policy, &mut rng).expect("split succeeds");
        let context = generated_context(case_index as u8, purpose, label);
        let direct = evaluate_direct_reference(&root, &context).expect("direct reference");

        for ids in [[0usize, 1, 2], [0, 1, 4], [0, 2, 4], [1, 2, 3], [2, 3, 4]] {
            let partials = ids
                .into_iter()
                .map(|index| evaluate_partial(&shares[index], &context).expect("partial"))
                .collect();
            let set = partial_set(policy, partials);
            let combined = combine_partials(&set, &context).expect("combine succeeds");
            assert_eq!(combined, direct);
        }
    }
}

#[test]
fn partial_combine_rejects_bad_subsets_and_wrong_context() {
    let policy = policy_3_of_5();
    let mut rng = seeded_rng(11);
    let root = generate_signing_root(&mut rng);
    let shares = split_signing_root(&root, policy, &mut rng).expect("split succeeds");
    let ctx = context(b"combine/rejects");
    let partial_0 = evaluate_partial(&shares[0], &ctx).expect("partial");
    let partial_1 = evaluate_partial(&shares[1], &ctx).expect("partial");
    let partial_2 = evaluate_partial(&shares[2], &ctx).expect("partial");

    assert_eq!(
        ValidatedThresholdSet::from_partials(policy, vec![partial_0.clone(), partial_1.clone()])
            .unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
    assert_eq!(
        ValidatedThresholdSet::from_partials(
            policy,
            vec![partial_0.clone(), partial_0.clone(), partial_2.clone()]
        )
        .unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );

    let set = partial_set(policy, vec![partial_0, partial_1, partial_2]);
    assert_eq!(
        combine_partials(&set, &context(b"other-context")).unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );
}

#[test]
fn verified_dleq_bundles_combine_to_direct_reference() {
    let policy = policy_3_of_5();
    let mut root_rng = seeded_rng(21);
    let root = generate_signing_root(&mut root_rng);
    let shares = split_signing_root(&root, policy, &mut root_rng).expect("split succeeds");
    let context = context(b"dleq/combine");
    let direct = evaluate_direct_reference(&root, &context).expect("direct reference");
    let mut proof_rng = seeded_rng(22);

    let bundles = ValidatedThresholdSet::from_proof_bundles(
        policy,
        vec![
            evaluate_partial_with_dleq_proof(&shares[0], &context, &mut proof_rng).expect("proof"),
            evaluate_partial_with_dleq_proof(&shares[2], &context, &mut proof_rng).expect("proof"),
            evaluate_partial_with_dleq_proof(&shares[4], &context, &mut proof_rng).expect("proof"),
        ],
    )
    .expect("valid proof bundle set");

    assert_eq!(
        combine_verified_partials(&bundles, &context).expect("verified combine"),
        direct
    );
}

#[test]
fn verified_dleq_rejects_tampered_proof_wrong_context_and_duplicate() {
    let policy = policy_3_of_5();
    let mut root_rng = seeded_rng(31);
    let root = generate_signing_root(&mut root_rng);
    let shares = split_signing_root(&root, policy, &mut root_rng).expect("split succeeds");
    let ctx = context(b"dleq/rejects");
    let mut proof_rng = seeded_rng(32);
    let good_0 = evaluate_partial_with_dleq_proof(&shares[0], &ctx, &mut proof_rng).expect("proof");
    let good_1 = evaluate_partial_with_dleq_proof(&shares[1], &ctx, &mut proof_rng).expect("proof");
    let good_2 = evaluate_partial_with_dleq_proof(&shares[2], &ctx, &mut proof_rng).expect("proof");

    assert_eq!(
        ValidatedThresholdSet::from_proof_bundles(
            policy,
            vec![good_0.clone(), good_0.clone(), good_2.clone()]
        )
        .unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );

    let mut mismatched_commitment = good_0.clone();
    mismatched_commitment.commitment = SigningRootShareCommitment::from_share(&shares[1]);
    assert_eq!(
        ValidatedThresholdSet::from_proof_bundles(
            policy,
            vec![mismatched_commitment, good_1.clone(), good_2.clone()]
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidDleqProof
    );

    let wrong_context_set = ValidatedThresholdSet::from_proof_bundles(
        policy,
        vec![good_0.clone(), good_1.clone(), good_2.clone()],
    )
    .expect("valid proof bundle set");
    assert_eq!(
        combine_verified_partials(&wrong_context_set, &context(b"dleq/other")).unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );

    let mut tampered = good_0;
    tampered.proof = PrfDleqProof::from_bytes([0u8; PrfDleqProof::LEN]).expect("zero proof bytes");
    let tampered_set =
        ValidatedThresholdSet::from_proof_bundles(policy, vec![tampered, good_1, good_2])
            .expect("valid proof bundle set");
    assert_eq!(
        combine_verified_partials(&tampered_set, &ctx).unwrap_err(),
        ThresholdPrfError::InvalidDleqProof
    );
}

#[test]
fn partial_wire_roundtrips_and_rejects_bad_encoding() {
    let share_id = ThresholdShareId::from_u16(2).expect("valid share id");
    let partial = PrfPartial::from_compressed(share_id, [7u8; 32], compressed_fixture_point(9))
        .expect("valid partial");
    let wire = PrfPartialWire::from_partial(&partial);
    assert_eq!(wire.id(), share_id);
    assert_eq!(wire.context_tag(), &[7u8; 32]);
    assert_eq!(wire.compressed_point(), partial.to_compressed());

    let decoded = PrfPartialWire::decode(wire.to_bytes())
        .expect("wire decodes")
        .to_partial()
        .expect("partial decodes");
    assert_eq!(decoded.id(), partial.id());
    assert_eq!(decoded.context_tag(), partial.context_tag());
    assert_eq!(decoded.to_compressed(), partial.to_compressed());

    assert_eq!(
        PrfPartialWire::decode_slice(&wire.to_bytes()[..65]).unwrap_err(),
        ThresholdPrfError::InvalidPartialEncoding
    );

    let mut invalid_share_id = wire.to_bytes();
    invalid_share_id[0] = 0;
    invalid_share_id[1] = 0;
    assert_eq!(
        PrfPartialWire::decode(invalid_share_id).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );

    let mut invalid_point = wire.to_bytes();
    invalid_point[34..].fill(0xff);
    assert_eq!(
        PrfPartialWire::decode(invalid_point).unwrap_err(),
        ThresholdPrfError::InvalidPointEncoding
    );
}

#[test]
fn commitment_and_dleq_wire_roundtrip_and_reject_bad_encodings() {
    let policy = ThresholdPolicy::from_u16s(1, 1).expect("valid policy");
    let mut rng = seeded_rng(41);
    let root = generate_signing_root(&mut rng);
    let share = split_signing_root(&root, policy, &mut rng)
        .expect("split succeeds")
        .remove(0);
    let commitment = SigningRootShareCommitment::from_share(&share);
    assert_eq!(
        SigningRootShareCommitment::from_bytes(commitment.to_bytes()).expect("commitment"),
        commitment
    );

    let mut invalid_commitment = commitment.to_bytes();
    invalid_commitment[0] = 0;
    invalid_commitment[1] = 0;
    assert_eq!(
        SigningRootShareCommitment::from_bytes(invalid_commitment).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );

    let mut invalid_point = commitment.to_bytes();
    invalid_point[2..].fill(0xff);
    assert_eq!(
        SigningRootShareCommitment::from_bytes(invalid_point).unwrap_err(),
        ThresholdPrfError::InvalidCommitmentEncoding
    );

    let proof = PrfDleqProof::from_bytes([0u8; PrfDleqProof::LEN]).expect("zero proof is encoded");
    assert_eq!(
        PrfDleqProof::from_slice(&proof.to_bytes()).expect("proof roundtrip"),
        proof
    );

    let mut invalid_proof = proof.to_bytes();
    invalid_proof[..32].fill(0xff);
    assert_eq!(
        PrfDleqProof::from_bytes(invalid_proof).unwrap_err(),
        ThresholdPrfError::InvalidDleqProofEncoding
    );
}

#[test]
fn router_ab_and_tau_outputs_are_canonical_scalar_bytes() {
    let policy = policy_3_of_5();
    let mut rng = seeded_rng(51);
    let root = generate_signing_root(&mut rng);
    let shares = split_signing_root(&root, policy, &mut rng).expect("split succeeds");

    for purpose in [
        PrfPurpose::Ed25519HssTauServer,
        PrfPurpose::RouterAbXClientBaseV1,
        PrfPurpose::RouterAbXServerBaseV1,
    ] {
        assert_eq!(
            purpose.output_encoding(),
            PrfOutputEncoding::CanonicalEd25519Scalar32
        );
        let context = PrfContext::new(
            SuiteId::Ristretto255Sha512,
            purpose,
            b"scalar-output".to_vec(),
        );
        let partials = partial_set(
            policy,
            vec![
                evaluate_partial(&shares[0], &context).expect("partial"),
                evaluate_partial(&shares[2], &context).expect("partial"),
                evaluate_partial(&shares[4], &context).expect("partial"),
            ],
        );
        let output = combine_partials(&partials, &context).expect("combine");
        assert!(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(output.into_bytes())).is_some()
        );
    }
}
