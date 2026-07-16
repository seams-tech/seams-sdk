use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_ecdsa_client_protocol::{
    authenticate_ecdsa_commitment_registry_v1, finalize_ecdsa_prf_two_party_output_v1,
    verify_ecdsa_prf_public_dleq_proof_v1, EcdsaAuthenticatedCommitmentRegistryV1,
    EcdsaClientProtocolError, EcdsaCommitmentAuthorityV1, EcdsaCommitmentPolicyManifestV1,
    EcdsaCommitmentPolicyPinsV1, EcdsaCommitmentRegistryBindingV1, EcdsaCommitmentStatementV1,
    EcdsaDeriverRoleV1, EcdsaPrfPublicContextV1, EcdsaPrfPublicProofBundleV1, EcdsaPrfPurposeV1,
    EcdsaRoleBoundPrfProofV1, EcdsaSignedCommitmentPolicyV1, EcdsaSignedCommitmentRecordV1,
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

struct CommitmentFixture {
    pins: EcdsaCommitmentPolicyPinsV1,
    policy: EcdsaSignedCommitmentPolicyV1,
    binding: EcdsaCommitmentRegistryBindingV1,
    signer_a_record: EcdsaSignedCommitmentRecordV1,
    signer_b_record: EcdsaSignedCommitmentRecordV1,
}

fn commitment_authority(
    role: EcdsaDeriverRoleV1,
    identity: &str,
    signing_key: &SigningKey,
) -> EcdsaCommitmentAuthorityV1 {
    EcdsaCommitmentAuthorityV1 {
        role,
        operator_identity: identity.to_owned(),
        authority_key_epoch: 4,
        valid_from_ms: 1_000,
        valid_until_ms: 9_000,
        verifying_key: signing_key.verifying_key().to_bytes(),
    }
}

fn signed_commitment_record(
    role: EcdsaDeriverRoleV1,
    share_id: u16,
    identity: &str,
    commitment_wire: [u8; 34],
    signing_key: &SigningKey,
) -> EcdsaSignedCommitmentRecordV1 {
    let statement = EcdsaCommitmentStatementV1 {
        role,
        share_id,
        root_id: "root-1".to_owned(),
        root_version: 3,
        root_share_epoch: "root-epoch-1".to_owned(),
        commitment_wire,
        operator_identity: identity.to_owned(),
        authority_key_epoch: 4,
        valid_from_ms: 1_000,
        valid_until_ms: 9_000,
    };
    let signed_digest = statement.digest().expect("statement digest");
    let signature = signing_key
        .sign(&statement.signing_bytes().expect("statement bytes"))
        .to_bytes();
    EcdsaSignedCommitmentRecordV1 {
        statement,
        signed_digest,
        signature,
    }
}

fn commitment_fixture(
    signer_a_commitment: [u8; 34],
    signer_b_commitment: [u8; 34],
) -> CommitmentFixture {
    let release_key = SigningKey::from_bytes(&[0x31; 32]);
    let signer_a_key = SigningKey::from_bytes(&[0x41; 32]);
    let signer_b_key = SigningKey::from_bytes(&[0x51; 32]);
    let manifest = EcdsaCommitmentPolicyManifestV1 {
        release_epoch: 7,
        minimum_root_version: 3,
        minimum_authority_key_epoch: 4,
        revoked_authority_key_epochs: Vec::new(),
        revoked_record_digests: Vec::new(),
        signer_a_authority: commitment_authority(EcdsaDeriverRoleV1::A, "deriver-a", &signer_a_key),
        signer_b_authority: commitment_authority(EcdsaDeriverRoleV1::B, "deriver-b", &signer_b_key),
    };
    let manifest_digest = manifest.digest().expect("manifest digest");
    let release_authority_signature = release_key
        .sign(&manifest.signing_bytes().expect("manifest bytes"))
        .to_bytes();
    CommitmentFixture {
        pins: EcdsaCommitmentPolicyPinsV1 {
            release_authority_public_key: release_key.verifying_key().to_bytes(),
            exact_policy_digest: manifest_digest,
            minimum_release_epoch: 7,
        },
        policy: EcdsaSignedCommitmentPolicyV1 {
            manifest,
            manifest_digest,
            release_authority_signature,
        },
        binding: EcdsaCommitmentRegistryBindingV1 {
            now_ms: 5_000,
            root_share_epoch: "root-epoch-1".to_owned(),
            signer_a_identity: "deriver-a".to_owned(),
            signer_b_identity: "deriver-b".to_owned(),
        },
        signer_a_record: signed_commitment_record(
            EcdsaDeriverRoleV1::A,
            1,
            "deriver-a",
            signer_a_commitment,
            &signer_a_key,
        ),
        signer_b_record: signed_commitment_record(
            EcdsaDeriverRoleV1::B,
            2,
            "deriver-b",
            signer_b_commitment,
            &signer_b_key,
        ),
    }
}

fn authenticate_fixture(fixture: &CommitmentFixture) -> EcdsaAuthenticatedCommitmentRegistryV1 {
    authenticate_ecdsa_commitment_registry_v1(
        &fixture.pins,
        &fixture.policy,
        &fixture.binding,
        &fixture.signer_a_record,
        &fixture.signer_b_record,
    )
    .expect("authenticated commitment registry")
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
    let commitment_fixture = commitment_fixture(
        public_bundle_a.commitment_wire,
        public_bundle_b.commitment_wire,
    );
    let commitment_registry = authenticate_fixture(&commitment_fixture);

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
        &commitment_registry,
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
    let commitment_fixture = commitment_fixture(bundle_a.commitment_wire, bundle_b.commitment_wire);
    let commitment_registry = authenticate_fixture(&commitment_fixture);

    let mut mutated_bundle_a = bundle_a.clone();
    mutated_bundle_a.proof_wire[0] ^= 1;
    assert_eq!(
        verify_ecdsa_prf_public_dleq_proof_v1(&context, &mutated_bundle_a),
        Err(EcdsaClientProtocolError::InvalidDleqProof),
    );
    assert_eq!(
        finalize_ecdsa_prf_two_party_output_v1(
            &context,
            &commitment_registry,
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
            &commitment_registry,
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

#[test]
fn client_commitment_registry_rejects_substituted_record() {
    let mut commitment_a = [0x11; 34];
    commitment_a[..2].copy_from_slice(&1_u16.to_be_bytes());
    let mut commitment_b = [0x22; 34];
    commitment_b[..2].copy_from_slice(&2_u16.to_be_bytes());
    let mut fixture = commitment_fixture(commitment_a, commitment_b);
    fixture.signer_b_record.statement.root_id = "substituted-root".to_owned();

    assert_eq!(
        authenticate_ecdsa_commitment_registry_v1(
            &fixture.pins,
            &fixture.policy,
            &fixture.binding,
            &fixture.signer_a_record,
            &fixture.signer_b_record,
        ),
        Err(EcdsaClientProtocolError::InvalidCommitmentRecord),
    );
}
