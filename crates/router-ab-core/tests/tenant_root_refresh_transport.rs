use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha_09::ChaCha20Rng as HpkeRng;
use rand_core::SeedableRng;
use rand_core_09::SeedableRng as SeedableRng09;
use router_ab_core::{
    seal_tenant_root_refresh_contribution_v1, RouterAbDerivationErrorCode,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId, TenantRootIdentityV1,
    TenantRootRefreshCommitmentTranscriptV1, TenantRootRefreshContributionAadV1,
    TenantRootRefreshHpkeKeypairV1, TenantRootRefreshHpkePublicKeyV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedRefreshContributionV1,
    TenantRootSignedShareInstallationEvidenceV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{
    prove_root_share_knowledge, RootShareRefreshCoefficient, SigningRootShare,
    SigningRootShareCommitment, TwoPartyDeriverRole,
};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn hpke_rng(seed: u8) -> HpkeRng {
    HpkeRng::from_seed([seed; 32])
}

fn context(session_seed: u8) -> TenantRootCeremonyContextV1 {
    context_for_epochs(session_seed, 7, 8)
}

fn context_for_epochs(
    session_seed: u8,
    current_epoch: u64,
    next_epoch: u64,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .unwrap()
            .digest()
            .unwrap(),
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(current_epoch).unwrap(),
            TenantRootShareEpoch::new(next_epoch).unwrap(),
        )
        .unwrap(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn coefficient(role: TwoPartyDeriverRole, scalar: u64) -> RootShareRefreshCoefficient {
    RootShareRefreshCoefficient::from_canonical_bytes(role, Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn verified_commitment(
    context: TenantRootCeremonyContextV1,
    coefficient: &RootShareRefreshCoefficient,
    signing_key: &SigningKey,
) -> router_ab_core::VerifiedTenantRootRefreshCommitmentV1 {
    let transcript =
        TenantRootRefreshCommitmentTranscriptV1::new(context, coefficient.commitment()).unwrap();
    TenantRootSignedRefreshCommitmentV1::sign(transcript, &signing_key.to_bytes())
        .unwrap()
        .verify(signing_key.verifying_key().as_bytes())
        .unwrap()
}

fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

#[test]
fn refresh_hpke_public_key_rejects_noncanonical_x25519_aliases() {
    assert!(TenantRootRefreshHpkePublicKeyV1::from_bytes([0_u8; 32]).is_err());

    let keypair = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32]).unwrap();
    let mut high_bit_alias = *keypair.public_key().as_bytes();
    high_bit_alias[31] |= 0x80;
    assert!(TenantRootRefreshHpkePublicKeyV1::from_bytes(high_bit_alias).is_err());
    let mut reduced_alias = [0xff; 32];
    reduced_alias[0] = 0xf6;
    reduced_alias[31] = 0x7f;
    assert!(TenantRootRefreshHpkePublicKeyV1::from_bytes(reduced_alias).is_err());
}

#[test]
fn both_refresh_contribution_directions_are_signed_encrypted_and_exact() {
    let context = context(0x21);
    let signing_a = signing_key(0x51);
    let signing_b = signing_key(0x61);
    let hpke_a = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32]).unwrap();
    let hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32]).unwrap();
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let coefficient_b = coefficient(TwoPartyDeriverRole::DeriverB, 29);

    let commitment_a = verified_commitment(context.clone(), &coefficient_a, &signing_a);
    let commitment_b = verified_commitment(context, &coefficient_b, &signing_b);
    let aad_a_to_b = TenantRootRefreshContributionAadV1::new(
        commitment_a,
        "deriver-b-hpke-key-8",
        hpke_b.public_key(),
    )
    .unwrap();
    let aad_b_to_a = TenantRootRefreshContributionAadV1::new(
        commitment_b,
        "deriver-a-hpke-key-8",
        hpke_a.public_key(),
    )
    .unwrap();

    let contribution_a = coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB);
    let envelope_a =
        seal_tenant_root_refresh_contribution_v1(&aad_a_to_b, &contribution_a, &mut hpke_rng(0x71))
            .unwrap();
    let signed_a =
        TenantRootSignedRefreshContributionV1::sign(&aad_a_to_b, envelope_a, &signing_a.to_bytes())
            .unwrap();
    let opened_a = signed_a
        .verify_and_open(&aad_a_to_b, signing_a.verifying_key().as_bytes(), &hpke_b)
        .unwrap();
    assert_eq!(opened_a.to_bytes(), contribution_a.to_bytes());
    aad_a_to_b
        .coefficient_commitment()
        .verify_contribution(opened_a)
        .unwrap();

    let contribution_b = coefficient_b.contribution_for(TwoPartyDeriverRole::DeriverA);
    let envelope_b =
        seal_tenant_root_refresh_contribution_v1(&aad_b_to_a, &contribution_b, &mut hpke_rng(0x81))
            .unwrap();
    let signed_b =
        TenantRootSignedRefreshContributionV1::sign(&aad_b_to_a, envelope_b, &signing_b.to_bytes())
            .unwrap();
    let opened_b = signed_b
        .verify_and_open(&aad_b_to_a, signing_b.verifying_key().as_bytes(), &hpke_a)
        .unwrap();
    assert_eq!(opened_b.to_bytes(), contribution_b.to_bytes());
    aad_b_to_a
        .coefficient_commitment()
        .verify_contribution(opened_b)
        .unwrap();

    assert_eq!(
        hex::encode(aad_a_to_b.digest().unwrap().as_bytes()),
        "601f93771e5415a5aaf3e8b88964a111610d7677c41713f26db70bd0563f6729",
    );
    assert_eq!(
        hex::encode(Sha256::digest(
            signed_a.envelope().canonical_bytes().unwrap()
        )),
        "d357a35074b88b90aad8bed8b52d065a4d32ba370ab5a49762b961c04ad9066e",
    );
}

#[test]
fn session_recipient_role_and_signature_substitutions_fail_closed() {
    let original_context = context(0x22);
    let signing_a = signing_key(0x51);
    let wrong_signing_key = signing_key(0x52);
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32]).unwrap();
    let other_hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb2; 32]).unwrap();
    let signed_commitment = TenantRootSignedRefreshCommitmentV1::sign(
        TenantRootRefreshCommitmentTranscriptV1::new(context(0x22), coefficient_a.commitment())
            .unwrap(),
        &signing_a.to_bytes(),
    )
    .unwrap();
    assert_eq!(
        signed_commitment
            .verify(wrong_signing_key.verifying_key().as_bytes())
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );
    let verified = verified_commitment(original_context, &coefficient_a, &signing_a);
    let aad = TenantRootRefreshContributionAadV1::new(
        verified,
        "deriver-b-hpke-key-8",
        hpke_b.public_key(),
    )
    .unwrap();
    let contribution = coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB);
    let envelope =
        seal_tenant_root_refresh_contribution_v1(&aad, &contribution, &mut hpke_rng(0x71)).unwrap();
    let signed =
        TenantRootSignedRefreshContributionV1::sign(&aad, envelope, &signing_a.to_bytes()).unwrap();

    assert_eq!(
        signed
            .verify_and_open(&aad, wrong_signing_key.verifying_key().as_bytes(), &hpke_b,)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );
    assert_eq!(
        signed
            .verify_and_open(&aad, signing_a.verifying_key().as_bytes(), &other_hpke_b,)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let next_epoch =
        verified_commitment(context_for_epochs(0x22, 8, 9), &coefficient_a, &signing_a);
    let next_epoch_aad = TenantRootRefreshContributionAadV1::new(
        next_epoch,
        "deriver-b-hpke-key-8",
        hpke_b.public_key(),
    )
    .unwrap();
    assert_eq!(
        signed
            .verify_and_open(
                &next_epoch_aad,
                signing_a.verifying_key().as_bytes(),
                &hpke_b,
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let substituted_coefficient = coefficient(TwoPartyDeriverRole::DeriverA, 18);
    let substituted_commitment =
        verified_commitment(context(0x22), &substituted_coefficient, &signing_a);
    let substituted_commitment_aad = TenantRootRefreshContributionAadV1::new(
        substituted_commitment,
        "deriver-b-hpke-key-8",
        hpke_b.public_key(),
    )
    .unwrap();
    assert_eq!(
        signed
            .verify_and_open(
                &substituted_commitment_aad,
                signing_a.verifying_key().as_bytes(),
                &hpke_b,
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let restarted = verified_commitment(context(0x23), &coefficient_a, &signing_a);
    let restarted_aad = TenantRootRefreshContributionAadV1::new(
        restarted,
        "deriver-b-hpke-key-8",
        hpke_b.public_key(),
    )
    .unwrap();
    assert_eq!(
        signed
            .verify_and_open(
                &restarted_aad,
                signing_a.verifying_key().as_bytes(),
                &hpke_b,
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let substituted_recipient_aad = TenantRootRefreshContributionAadV1::new(
        verified_commitment(context(0x22), &coefficient_a, &signing_a),
        "deriver-b-hpke-key-8",
        other_hpke_b.public_key(),
    )
    .unwrap();
    assert_eq!(
        signed
            .verify_and_open(
                &substituted_recipient_aad,
                signing_a.verifying_key().as_bytes(),
                &other_hpke_b,
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let coefficient_b = coefficient(TwoPartyDeriverRole::DeriverB, 29);
    let wrong_direction = coefficient_b.contribution_for(TwoPartyDeriverRole::DeriverA);
    assert_eq!(
        seal_tenant_root_refresh_contribution_v1(&aad, &wrong_direction, &mut hpke_rng(0x81),)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let creation_context = TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .unwrap()
            .digest()
            .unwrap(),
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x24; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap();
    assert!(TenantRootRefreshCommitmentTranscriptV1::new(
        creation_context,
        coefficient_a.commitment(),
    )
    .is_err());
}

#[test]
fn installation_evidence_is_role_signed_and_transcript_bound() {
    let context = context(0x24);
    let signing_a = signing_key(0x51);
    let signing_b = signing_key(0x61);
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context,
        TwoPartyDeriverRole::DeriverA,
        SigningRootShareCommitment::from_share(&share_a),
        SigningRootShareCommitment::from_share(&share_b),
    )
    .unwrap();
    let proof = prove_root_share_knowledge(
        &share_a,
        &transcript.canonical_bytes().unwrap(),
        &mut seeded_rng(7),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let signed =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_a.to_bytes()).unwrap();

    signed.verify(signing_a.verifying_key().as_bytes()).unwrap();
    assert_eq!(
        signed
            .verify(signing_b.verifying_key().as_bytes())
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );
}
