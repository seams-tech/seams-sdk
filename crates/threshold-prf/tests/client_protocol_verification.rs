use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_ecdsa_client_protocol::{
    finalize_ecdsa_prf_two_party_output_v1, verify_ecdsa_prf_public_dleq_proof_v1,
    EcdsaClientProtocolError, EcdsaDeriverRoleV1, EcdsaPrfPublicContextV1,
    EcdsaPrfPublicProofBundleV1, EcdsaPrfPurposeV1, EcdsaRoleBoundPrfProofV1,
};
use threshold_prf::{
    combine_verified_partials, evaluate_partial_with_dleq_proof, generate_signing_root,
    split_signing_root, PrfContext, PrfPartialProofBundle, PrfPartialWire, PrfPurpose, SuiteId,
    ThresholdPolicy, ValidatedThresholdSet,
};

fn producer_context(purpose: PrfPurpose) -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        b"canonical-router-transcript".to_vec(),
    )
}

fn public_context(purpose: EcdsaPrfPurposeV1) -> EcdsaPrfPublicContextV1 {
    EcdsaPrfPublicContextV1 {
        purpose,
        context_bytes: b"canonical-router-transcript".to_vec(),
    }
}

fn public_bundle(bundle: &PrfPartialProofBundle) -> EcdsaPrfPublicProofBundleV1 {
    EcdsaPrfPublicProofBundleV1 {
        partial_wire: PrfPartialWire::from_partial(&bundle.partial).to_bytes(),
        commitment_wire: bundle.commitment.to_bytes(),
        proof_wire: bundle.proof.to_bytes(),
    }
}

#[test]
fn client_verifier_and_finalizer_match_threshold_prf_producer() {
    let mut rng = ChaCha20Rng::from_seed([0x61; 32]);
    let root = generate_signing_root(&mut rng);
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("threshold policy");
    let shares = split_signing_root(&root, policy, &mut rng).expect("root shares");
    let producer_context = producer_context(PrfPurpose::RouterAbXClientBaseV1);
    let bundle_a = evaluate_partial_with_dleq_proof(&shares[0], &producer_context, &mut rng)
        .expect("producer proof A");
    let bundle_b = evaluate_partial_with_dleq_proof(&shares[1], &producer_context, &mut rng)
        .expect("producer proof B");
    let public_bundle_a = public_bundle(&bundle_a);
    let public_bundle_b = public_bundle(&bundle_b);
    let public_context = public_context(EcdsaPrfPurposeV1::XClientBase);
    verify_ecdsa_prf_public_dleq_proof_v1(&public_context, &public_bundle_a)
        .expect("public proof verifies");
    let expected = combine_verified_partials(
        &ValidatedThresholdSet::from_proof_bundles(policy, vec![bundle_a, bundle_b])
            .expect("proof set"),
        &producer_context,
    )
    .expect("producer combine");
    let finalized = finalize_ecdsa_prf_two_party_output_v1(
        &public_context,
        &EcdsaRoleBoundPrfProofV1 {
            role: EcdsaDeriverRoleV1::A,
            proof: public_bundle_a,
        },
        &EcdsaRoleBoundPrfProofV1 {
            role: EcdsaDeriverRoleV1::B,
            proof: public_bundle_b,
        },
    )
    .expect("client finalizer");

    assert_eq!(&finalized, expected.as_bytes());
}

#[test]
fn client_finalizer_rejects_proof_mutation_role_swap_and_mixed_purpose() {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let root = generate_signing_root(&mut rng);
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("threshold policy");
    let shares = split_signing_root(&root, policy, &mut rng).expect("root shares");
    let client_context = producer_context(PrfPurpose::RouterAbXClientBaseV1);
    let server_context = producer_context(PrfPurpose::RouterAbXServerBaseV1);
    let bundle_a = public_bundle(
        &evaluate_partial_with_dleq_proof(&shares[0], &client_context, &mut rng)
            .expect("client-purpose proof A"),
    );
    let bundle_b = public_bundle(
        &evaluate_partial_with_dleq_proof(&shares[1], &client_context, &mut rng)
            .expect("client-purpose proof B"),
    );
    let mixed_bundle_b = public_bundle(
        &evaluate_partial_with_dleq_proof(&shares[1], &server_context, &mut rng)
            .expect("server-purpose proof B"),
    );
    let context = public_context(EcdsaPrfPurposeV1::XClientBase);
    let mut mutated_bundle_a = bundle_a.clone();
    mutated_bundle_a.proof_wire[0] ^= 1;
    assert_eq!(
        verify_ecdsa_prf_public_dleq_proof_v1(&context, &mutated_bundle_a),
        Err(EcdsaClientProtocolError::InvalidDleqProof),
    );
    assert_eq!(
        finalize_ecdsa_prf_two_party_output_v1(
            &context,
            &EcdsaRoleBoundPrfProofV1 {
                role: EcdsaDeriverRoleV1::B,
                proof: bundle_a.clone(),
            },
            &EcdsaRoleBoundPrfProofV1 {
                role: EcdsaDeriverRoleV1::A,
                proof: bundle_b.clone(),
            },
        ),
        Err(EcdsaClientProtocolError::InvalidDleqProof),
    );
    assert_eq!(
        finalize_ecdsa_prf_two_party_output_v1(
            &context,
            &EcdsaRoleBoundPrfProofV1 {
                role: EcdsaDeriverRoleV1::A,
                proof: bundle_a,
            },
            &EcdsaRoleBoundPrfProofV1 {
                role: EcdsaDeriverRoleV1::B,
                proof: mixed_bundle_b,
            },
        ),
        Err(EcdsaClientProtocolError::ContextMismatch),
    );
}
