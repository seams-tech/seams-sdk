use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, Error as RandError, RngCore, SeedableRng};
use threshold_prf::{
    combine_partials, combine_verified_partials, derive_output_from_signing_root_share_wires,
    derive_output_from_signing_root_shares,
    evaluate_direct_reference as evaluate_direct_reference_result,
    evaluate_partial as evaluate_partial_result, evaluate_partial_with_dleq_proof,
    generate_signing_root, reconstruct_signing_root_2_of_3, refresh_signing_root_shares_2_of_3,
    split_signing_root_2_of_3, verify_partial_dleq_proof, PrfContext, PrfDleqProofV1, PrfOutput32,
    PrfPartial, PrfPartialWireV1, PrfPurpose, SigningRootScalar, SigningRootShare,
    SigningRootShareCommitmentV1, SigningRootShareId, SigningRootShareWireV1, SuiteId,
    ThresholdPrfError,
};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn wallet_context(label: &[u8]) -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        PrfPurpose::EcdsaHssYRelayer,
        label,
    )
}

fn fixture() -> (SigningRootScalar, [SigningRootShare; 3], PrfContext) {
    let mut rng = seeded_rng(7);
    let root = generate_signing_root(&mut rng);
    let shares = split_signing_root_2_of_3(&root, &mut rng);
    let context = wallet_context(b"project:alpha/wallet:0");
    (root, shares, context)
}

fn evaluate_direct_reference(root: &SigningRootScalar, context: &PrfContext) -> PrfOutput32 {
    evaluate_direct_reference_result(root, context).expect("fixture context is valid")
}

fn evaluate_partial(share: &SigningRootShare, context: &PrfContext) -> PrfPartial {
    evaluate_partial_result(share, context).expect("fixture context is valid")
}

#[test]
fn every_two_share_subset_matches_direct_reference() {
    let (root, shares, context) = fixture();
    let direct = evaluate_direct_reference(&root, &context);

    for (left, right) in [(0, 1), (0, 2), (1, 2)] {
        let reconstructed =
            reconstruct_signing_root_2_of_3(&[shares[left].clone(), shares[right].clone()])
                .expect("two distinct shares reconstruct");
        assert_eq!(reconstructed.to_bytes(), root.to_bytes());

        let partial_left = evaluate_partial(&shares[left], &context);
        let partial_right = evaluate_partial(&shares[right], &context);

        let combined_forward =
            combine_partials(&[partial_left.clone(), partial_right.clone()], &context)
                .expect("two distinct partials combine");
        let combined_reverse = combine_partials(&[partial_right, partial_left], &context)
            .expect("combining order does not matter");

        assert_eq!(combined_forward, direct);
        assert_eq!(combined_reverse, direct);
    }
}

#[test]
fn option_a_and_option_b_have_identical_outputs() {
    let (_root, shares, context) = fixture();

    let option_a_left = evaluate_partial(&shares[0], &context);
    let option_a_right = evaluate_partial(&shares[2], &context);
    let option_a =
        combine_partials(&[option_a_left.clone(), option_a_right.clone()], &context).unwrap();

    let option_b_left = PrfPartialWireV1::decode(
        &context,
        PrfPartialWireV1::from_partial(&option_a_left).to_bytes(),
    )
    .unwrap();
    let option_b_right = PrfPartialWireV1::decode(
        &context,
        PrfPartialWireV1::from_partial(&option_a_right).to_bytes(),
    )
    .unwrap();
    let option_b = combine_partials(&[option_b_left, option_b_right], &context).unwrap();

    assert_eq!(option_a, option_b);
}

#[test]
fn derive_output_from_signing_root_shares_uses_option_a_semantics() {
    let (root, shares, context) = fixture();
    let direct = evaluate_direct_reference(&root, &context);
    let manual_option_a = combine_partials(
        &[
            evaluate_partial(&shares[0], &context),
            evaluate_partial(&shares[2], &context),
        ],
        &context,
    )
    .unwrap();
    let helper_option_a =
        derive_output_from_signing_root_shares(&[shares[0].clone(), shares[2].clone()], &context)
            .unwrap();
    let helper_reverse =
        derive_output_from_signing_root_shares(&[shares[2].clone(), shares[0].clone()], &context)
            .unwrap();

    assert_eq!(helper_option_a, manual_option_a);
    assert_eq!(helper_option_a, helper_reverse);
    assert_eq!(helper_option_a, direct);
}

#[test]
fn signing_root_share_wire_roundtrips_and_derives_output() {
    let (root, shares, context) = fixture();
    let direct = evaluate_direct_reference(&root, &context);

    let left_wire = SigningRootShareWireV1::from_share(&shares[0]);
    let right_wire = SigningRootShareWireV1::from_share(&shares[2]);
    let left_bytes = left_wire.to_bytes();
    let right_bytes = right_wire.to_bytes();

    assert_eq!(left_bytes[0], shares[0].id().get());
    assert_eq!(&left_bytes[1..], &shares[0].to_bytes());
    assert_eq!(
        format!("{left_wire:?}"),
        "SigningRootShareWireV1([redacted])"
    );

    let decoded_left = SigningRootShareWireV1::decode(left_bytes)
        .unwrap()
        .to_share()
        .unwrap();
    let decoded_right = SigningRootShareWireV1::decode_slice(&right_bytes)
        .unwrap()
        .to_share()
        .unwrap();
    let derived =
        derive_output_from_signing_root_shares(&[decoded_left, decoded_right], &context).unwrap();
    let derived_from_wires =
        derive_output_from_signing_root_share_wires(&[left_wire, right_wire], &context).unwrap();

    assert_eq!(derived, direct);
    assert_eq!(derived_from_wires, direct);
}

#[test]
fn purpose_and_context_domain_separate_outputs() {
    let (_root, shares, context) = fixture();
    let base = combine_partials(
        &[
            evaluate_partial(&shares[0], &context),
            evaluate_partial(&shares[1], &context),
        ],
        &context,
    )
    .unwrap();

    let ed25519_context = PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        PrfPurpose::Ed25519HssYRelayer,
        b"project:alpha/wallet:0",
    );
    let different_purpose = combine_partials(
        &[
            evaluate_partial(&shares[0], &ed25519_context),
            evaluate_partial(&shares[1], &ed25519_context),
        ],
        &ed25519_context,
    )
    .unwrap();

    let different_wallet = wallet_context(b"project:alpha/wallet:1");
    let different_context = combine_partials(
        &[
            evaluate_partial(&shares[0], &different_wallet),
            evaluate_partial(&shares[1], &different_wallet),
        ],
        &different_wallet,
    )
    .unwrap();

    assert_ne!(base, different_purpose);
    assert_ne!(base, different_context);
}

#[test]
fn ed25519_tau_relayer_output_is_canonical_scalar_bytes() {
    let (_root, shares, _context) = fixture();
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        PrfPurpose::Ed25519HssTauRelayer,
        b"project:alpha/wallet:0",
    );
    let output = combine_partials(
        &[
            evaluate_partial(&shares[0], &context),
            evaluate_partial(&shares[1], &context),
        ],
        &context,
    )
    .unwrap();

    assert!(bool::from(
        Scalar::from_canonical_bytes(*output.as_bytes()).is_some()
    ));
}

#[test]
fn invalid_share_subsets_are_rejected() {
    let (_root, shares, context) = fixture();
    let left = evaluate_partial(&shares[0], &context);
    let right = evaluate_partial(&shares[1], &context);

    assert_eq!(
        combine_partials(&[left.clone()], &context).unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
    assert_eq!(
        combine_partials(&[left.clone(), right.clone(), left.clone()], &context).unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
    assert_eq!(
        combine_partials(&[left.clone(), left], &context).unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );
    assert_eq!(
        reconstruct_signing_root_2_of_3(&[shares[0].clone(), shares[0].clone()]).unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );
    assert_eq!(
        reconstruct_signing_root_2_of_3(&[shares[0].clone()]).unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
    assert_eq!(
        derive_output_from_signing_root_shares(&[shares[0].clone()], &context).unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
    assert_eq!(
        derive_output_from_signing_root_shares(&[shares[0].clone(), shares[0].clone()], &context)
            .unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );
    assert_eq!(
        derive_output_from_signing_root_shares(
            &[shares[0].clone(), shares[1].clone(), shares[2].clone()],
            &context,
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );

    let wire0 = SigningRootShareWireV1::from_share(&shares[0]);
    let wire1 = SigningRootShareWireV1::from_share(&shares[1]);
    assert_eq!(
        derive_output_from_signing_root_share_wires(&[wire0.clone()], &context).unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
    assert_eq!(
        derive_output_from_signing_root_share_wires(&[wire0.clone(), wire0], &context).unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );
    assert_eq!(
        derive_output_from_signing_root_share_wires(
            &[
                SigningRootShareWireV1::from_share(&shares[0]),
                wire1,
                SigningRootShareWireV1::from_share(&shares[2]),
            ],
            &context,
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidThresholdSubset
    );
}

#[test]
fn mixed_context_partials_are_rejected() {
    let (_root, shares, context) = fixture();
    let other_context = wallet_context(b"project:alpha/wallet:1");
    let left = evaluate_partial(&shares[0], &context);
    let right = evaluate_partial(&shares[1], &other_context);

    assert_eq!(
        combine_partials(&[left, right], &context).unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );
}

#[test]
fn partial_wire_roundtrips_and_rejects_bad_encoding() {
    let (_root, shares, context) = fixture();
    let partial = evaluate_partial(&shares[0], &context);
    let wire = PrfPartialWireV1::from_partial(&partial);
    let wire_bytes = wire.to_bytes();

    assert_eq!(wire_bytes[0], shares[0].id().get());
    assert_eq!(&wire_bytes[1..33], partial.context_tag());
    assert_eq!(&wire_bytes[33..], partial.to_compressed());

    let decoded = PrfPartialWireV1::decode(&context, wire_bytes).unwrap();
    let combined = combine_partials(&[partial, decoded], &context).unwrap_err();
    assert_eq!(combined, ThresholdPrfError::DuplicateShareId);

    assert_eq!(
        PrfPartialWireV1::decode_slice(&context, &wire_bytes[..64]).unwrap_err(),
        ThresholdPrfError::InvalidPartialEncoding
    );

    let mut invalid_share_id = wire_bytes;
    invalid_share_id[0] = 0;
    assert_eq!(
        PrfPartialWireV1::decode(&context, invalid_share_id).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );

    let mut invalid_context_tag = wire_bytes;
    invalid_context_tag[1] ^= 1;
    assert_eq!(
        PrfPartialWireV1::decode(&context, invalid_context_tag).unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );

    let mut invalid_point = wire_bytes;
    invalid_point[33..].fill(0xff);
    assert_eq!(
        PrfPartialWireV1::decode(&context, invalid_point).unwrap_err(),
        ThresholdPrfError::InvalidPointEncoding
    );
}

#[test]
fn dleq_proof_roundtrips_and_verifies() {
    let (_root, shares, context) = fixture();
    let mut rng = seeded_rng(123);
    let bundle =
        evaluate_partial_with_dleq_proof(&shares[0], &context, &mut rng).expect("proof succeeds");

    verify_partial_dleq_proof(&bundle.commitment, &bundle.partial, &context, &bundle.proof)
        .expect("valid proof verifies");

    let commitment_bytes = bundle.commitment.to_bytes();
    assert_eq!(commitment_bytes[0], shares[0].id().get());
    assert_eq!(
        SigningRootShareCommitmentV1::from_bytes(commitment_bytes)
            .unwrap()
            .to_bytes(),
        commitment_bytes
    );

    let proof_bytes = bundle.proof.to_bytes();
    assert_eq!(
        PrfDleqProofV1::from_bytes(proof_bytes).unwrap().to_bytes(),
        proof_bytes
    );
}

#[test]
fn verified_dleq_bundles_combine_to_direct_reference() {
    let (root, shares, context) = fixture();
    let direct = evaluate_direct_reference(&root, &context);
    let left = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(126))
        .expect("left proof succeeds");
    let right = evaluate_partial_with_dleq_proof(&shares[2], &context, &mut seeded_rng(127))
        .expect("right proof succeeds");

    let combined_forward = combine_verified_partials(&[left.clone(), right.clone()], &context)
        .expect("verified bundles combine");
    let combined_reverse = combine_verified_partials(&[right, left], &context)
        .expect("verified bundle order does not matter");

    assert_eq!(combined_forward, direct);
    assert_eq!(combined_reverse, direct);
}

#[test]
fn verified_dleq_combine_rejects_invalid_proof_context_and_duplicate() {
    let (_root, shares, context) = fixture();
    let other_context = wallet_context(b"project:alpha/wallet:1");
    let left = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(128))
        .expect("left proof succeeds");
    let right = evaluate_partial_with_dleq_proof(&shares[1], &context, &mut seeded_rng(129))
        .expect("right proof succeeds");

    let mut tampered = right.clone();
    let mut tampered_proof_bytes = tampered.proof.to_bytes();
    tampered_proof_bytes[0] ^= 1;
    tampered.proof = PrfDleqProofV1::from_bytes(tampered_proof_bytes).unwrap();
    assert_eq!(
        combine_verified_partials(&[left.clone(), tampered], &context).unwrap_err(),
        ThresholdPrfError::InvalidDleqProof
    );

    assert_eq!(
        combine_verified_partials(&[left.clone(), right], &other_context).unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );

    assert_eq!(
        combine_verified_partials(&[left.clone(), left], &context).unwrap_err(),
        ThresholdPrfError::DuplicateShareId
    );
}

#[test]
fn dleq_proof_retries_zero_nonce() {
    let (_root, shares, context) = fixture();
    let mut rng = ZeroThenChaChaRng::new(seeded_rng(125));
    let bundle =
        evaluate_partial_with_dleq_proof(&shares[0], &context, &mut rng).expect("proof succeeds");

    assert!(rng.used_zero_fill);
    assert!(rng.used_fallback_fill);
    verify_partial_dleq_proof(&bundle.commitment, &bundle.partial, &context, &bundle.proof)
        .expect("valid proof verifies after retrying zero nonce");
}

#[test]
fn dleq_proof_rejects_wrong_context_commitment_and_tampering() {
    let (_root, shares, context) = fixture();
    let other_context = wallet_context(b"project:alpha/wallet:1");
    let mut rng = seeded_rng(124);
    let bundle =
        evaluate_partial_with_dleq_proof(&shares[0], &context, &mut rng).expect("proof succeeds");

    assert_eq!(
        verify_partial_dleq_proof(
            &bundle.commitment,
            &bundle.partial,
            &other_context,
            &bundle.proof,
        )
        .unwrap_err(),
        ThresholdPrfError::ContextMismatch
    );

    let wrong_commitment = SigningRootShareCommitmentV1::from_share(&shares[1]);
    assert_eq!(
        verify_partial_dleq_proof(&wrong_commitment, &bundle.partial, &context, &bundle.proof)
            .unwrap_err(),
        ThresholdPrfError::InvalidDleqProof
    );

    let mut tampered_proof_bytes = bundle.proof.to_bytes();
    tampered_proof_bytes[0] ^= 1;
    let tampered_proof = PrfDleqProofV1::from_bytes(tampered_proof_bytes).unwrap();
    assert_eq!(
        verify_partial_dleq_proof(
            &bundle.commitment,
            &bundle.partial,
            &context,
            &tampered_proof,
        )
        .unwrap_err(),
        ThresholdPrfError::InvalidDleqProof
    );
}

#[test]
fn dleq_wire_rejects_bad_encodings() {
    let (_root, shares, _context) = fixture();
    let commitment = SigningRootShareCommitmentV1::from_share(&shares[0]);
    let commitment_bytes = commitment.to_bytes();

    assert_eq!(
        SigningRootShareCommitmentV1::from_slice(&commitment_bytes[..32]).unwrap_err(),
        ThresholdPrfError::InvalidCommitmentEncoding
    );

    let mut invalid_commitment_id = commitment_bytes;
    invalid_commitment_id[0] = 0;
    assert_eq!(
        SigningRootShareCommitmentV1::from_bytes(invalid_commitment_id).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );

    let mut invalid_commitment_point = commitment_bytes;
    invalid_commitment_point[1..].fill(0xff);
    assert_eq!(
        SigningRootShareCommitmentV1::from_bytes(invalid_commitment_point).unwrap_err(),
        ThresholdPrfError::InvalidCommitmentEncoding
    );

    assert_eq!(
        PrfDleqProofV1::from_slice(&[0u8; 63]).unwrap_err(),
        ThresholdPrfError::InvalidDleqProofEncoding
    );

    assert_eq!(
        PrfDleqProofV1::from_bytes([0xffu8; 64]).unwrap_err(),
        ThresholdPrfError::InvalidDleqProofEncoding
    );
}

#[test]
fn invalid_encodings_are_rejected() {
    assert_eq!(
        SigningRootShareId::new(0).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );
    assert_eq!(
        SigningRootShareId::new(4).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );
    assert_eq!(
        SigningRootScalar::from_canonical_bytes([0u8; 32]).unwrap_err(),
        ThresholdPrfError::ZeroScalar
    );
    assert_eq!(
        SigningRootScalar::from_canonical_bytes([0xffu8; 32]).unwrap_err(),
        ThresholdPrfError::InvalidScalarEncoding
    );
    assert_eq!(
        SigningRootShareWireV1::decode_slice(&[0u8; 32]).unwrap_err(),
        ThresholdPrfError::InvalidShareEncoding
    );
    let mut invalid_share_wire = [0u8; SigningRootShareWireV1::LEN];
    invalid_share_wire[0] = 4;
    assert_eq!(
        SigningRootShareWireV1::decode(invalid_share_wire).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );
    invalid_share_wire[0] = 1;
    invalid_share_wire[1..].copy_from_slice(&[0xffu8; 32]);
    assert_eq!(
        SigningRootShareWireV1::decode(invalid_share_wire).unwrap_err(),
        ThresholdPrfError::InvalidScalarEncoding
    );

    let id = SigningRootShareId::new(1).unwrap();
    let zero_share = SigningRootShare::from_canonical_bytes(id, [0u8; 32]).unwrap();
    assert_eq!(zero_share.id(), id);
    assert_eq!(zero_share.to_bytes(), [0u8; 32]);

    let context = wallet_context(b"project:alpha/wallet:0");
    let mut rng = seeded_rng(11);
    let root = generate_signing_root(&mut rng);
    let shares = split_signing_root_2_of_3(&root, &mut rng);
    let partial = evaluate_partial(&shares[0], &context);
    let mut invalid_partial_wire = PrfPartialWireV1::from_partial(&partial).to_bytes();
    invalid_partial_wire[33..].copy_from_slice(&[0xffu8; 32]);
    assert_eq!(
        PrfPartialWireV1::decode(&context, invalid_partial_wire).unwrap_err(),
        ThresholdPrfError::InvalidPointEncoding
    );
}

#[test]
fn split_outputs_are_parseable_shares() {
    let (root, shares, _context) = fixture();
    assert_ne!(root.to_bytes(), [0u8; 32]);

    for share in shares {
        assert!(SigningRootShare::from_canonical_bytes(share.id(), share.to_bytes()).is_ok());
    }
}

#[test]
fn debug_output_redacts_secret_material() {
    let (root, shares, context) = fixture();
    let partial = evaluate_partial(&shares[0], &context);
    let output = evaluate_direct_reference(&root, &context);

    assert_eq!(format!("{root:?}"), "SigningRootScalar([redacted])");
    assert!(format!("{:?}", shares[0]).contains("value: \"[redacted]\""));
    assert!(format!("{partial:?}").contains("point: \"[redacted]\""));
    assert_eq!(format!("{output:?}"), "PrfOutput32([redacted])");
}

#[test]
fn share_refresh_preserves_signing_root_outputs() {
    let (_root, shares, context) = fixture();
    let before = combine_partials(
        &[
            evaluate_partial(&shares[0], &context),
            evaluate_partial(&shares[1], &context),
        ],
        &context,
    )
    .unwrap();

    let mut refresh_rng = seeded_rng(99);
    let refreshed = refresh_signing_root_shares_2_of_3(
        &[shares[0].clone(), shares[2].clone()],
        &mut refresh_rng,
    )
    .unwrap();
    let after = combine_partials(
        &[
            evaluate_partial(&refreshed[1], &context),
            evaluate_partial(&refreshed[2], &context),
        ],
        &context,
    )
    .unwrap();

    assert_eq!(before, after);
    assert!(shares
        .iter()
        .zip(refreshed.iter())
        .any(|(old, new)| old.to_bytes() != new.to_bytes()));
}

struct ZeroThenChaChaRng {
    used_zero_fill: bool,
    used_fallback_fill: bool,
    fallback: ChaCha20Rng,
}

impl ZeroThenChaChaRng {
    fn new(fallback: ChaCha20Rng) -> Self {
        Self {
            used_zero_fill: false,
            used_fallback_fill: false,
            fallback,
        }
    }
}

impl RngCore for ZeroThenChaChaRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.used_zero_fill {
            self.used_zero_fill = true;
            dest.fill(0);
            return;
        }
        self.used_fallback_fill = true;
        self.fallback.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ZeroThenChaChaRng {}
