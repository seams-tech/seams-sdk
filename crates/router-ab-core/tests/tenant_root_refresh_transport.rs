use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_chacha::ChaCha20Rng;
use rand_chacha_09::ChaCha20Rng as HpkeRng;
use rand_core::SeedableRng;
use rand_core_09::SeedableRng as SeedableRng09;
use router_ab_core::{
    seal_tenant_root_refresh_contribution_v1, RouterAbDerivationErrorCode,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId,
    TenantRootEncryptedRefreshContributionV1, TenantRootIdentityV1,
    TenantRootRefreshCommitmentTranscriptV1, TenantRootRefreshContributionAadV1,
    TenantRootRefreshHpkeKeypairV1, TenantRootRefreshHpkePublicKeyV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedRefreshContributionV1,
    TenantRootSignedShareInstallationEvidenceV1, VerifiedTenantRootRefreshCommitmentPairV1,
};
use sha2::{Digest, Sha256};
use std::ops::Range;
use threshold_prf::{
    prove_root_share_knowledge, RootShareRefreshCoefficient, RootShareRefreshContributionWire,
    SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole,
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

fn recipient(role: TwoPartyDeriverRole) -> (&'static str, TenantRootRefreshHpkePublicKeyV1) {
    match role {
        TwoPartyDeriverRole::DeriverA => (
            "deriver-a-hpke-key-7",
            TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32])
                .unwrap()
                .public_key(),
        ),
        TwoPartyDeriverRole::DeriverB => (
            "deriver-b-hpke-key-8",
            TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32])
                .unwrap()
                .public_key(),
        ),
    }
}

fn coefficient(role: TwoPartyDeriverRole, scalar: u64) -> RootShareRefreshCoefficient {
    RootShareRefreshCoefficient::from_canonical_bytes(role, Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn signed_refresh_commitment(
    context: TenantRootCeremonyContextV1,
    coefficient: &RootShareRefreshCoefficient,
    signing_key: &SigningKey,
) -> TenantRootSignedRefreshCommitmentV1 {
    let (recipient_key_id, recipient_public_key) = recipient(coefficient.commitment().source());
    let transcript = TenantRootRefreshCommitmentTranscriptV1::new(
        context,
        coefficient.commitment(),
        recipient_key_id,
        recipient_public_key,
    )
    .unwrap();
    TenantRootSignedRefreshCommitmentV1::sign(transcript, &signing_key.to_bytes()).unwrap()
}

fn verified_commitment(
    context: TenantRootCeremonyContextV1,
    coefficient: &RootShareRefreshCoefficient,
    signing_key: &SigningKey,
) -> router_ab_core::VerifiedTenantRootRefreshCommitmentV1 {
    let (recipient_key_id, recipient_public_key) = recipient(coefficient.commitment().source());
    let transcript = TenantRootRefreshCommitmentTranscriptV1::new(
        context,
        coefficient.commitment(),
        recipient_key_id,
        recipient_public_key,
    )
    .unwrap();
    TenantRootSignedRefreshCommitmentV1::sign(transcript, &signing_key.to_bytes())
        .unwrap()
        .verify(signing_key.verifying_key().as_bytes())
        .unwrap()
}

fn verified_commitment_pair(
    context: TenantRootCeremonyContextV1,
    coefficient_a: &RootShareRefreshCoefficient,
    signing_a: &SigningKey,
    coefficient_b: &RootShareRefreshCoefficient,
    signing_b: &SigningKey,
) -> VerifiedTenantRootRefreshCommitmentPairV1 {
    VerifiedTenantRootRefreshCommitmentPairV1::new(
        verified_commitment(context.clone(), coefficient_a, signing_a),
        verified_commitment(context, coefficient_b, signing_b),
    )
    .unwrap()
}

fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn next_len32_field_range(wire: &[u8], offset: &mut usize) -> Range<usize> {
    let length_end = *offset + 4;
    let length = u32::from_be_bytes(wire[*offset..length_end].try_into().unwrap()) as usize;
    let value_end = length_end + length;
    *offset = value_end;
    length_end..value_end
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
fn signed_refresh_commitment_wire_round_trips_and_retains_public_authentication() {
    let context = context(0x1f);
    let signing_a = signing_key(0x51);
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let signed = signed_refresh_commitment(context.clone(), &coefficient_a, &signing_a);
    let wire = signed.canonical_bytes().unwrap();

    let decoded = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&wire).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), wire);
    assert_eq!(decoded.transcript(), signed.transcript());
    assert_eq!(decoded.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(decoded.signing_key_id(), "deriver-a-signing-key-7");
    assert_eq!(
        decoded.transcript().recipient_key_id(),
        "deriver-a-hpke-key-7"
    );
    assert_eq!(
        decoded.transcript().recipient_public_key(),
        TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32])
            .unwrap()
            .public_key()
    );
    assert_eq!(decoded.signature(), signed.signature());

    let verified = TenantRootSignedRefreshCommitmentV1::decode_and_verify_canonical_bytes(
        &wire,
        &context,
        TwoPartyDeriverRole::DeriverA,
        "deriver-a-signing-key-7",
        signing_a.verifying_key().as_bytes(),
    )
    .unwrap();
    assert_eq!(verified.transcript(), signed.transcript());
    assert_eq!(verified.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(verified.signing_key_id(), signed.signing_key_id());
    assert_eq!(verified.signature(), signed.signature());
    assert_eq!(verified.canonical_bytes(), wire.as_slice());
    assert_eq!(verified.into_canonical_bytes(), wire);
}

#[test]
fn signed_refresh_commitment_wire_rejects_malformed_and_substituted_fields() {
    let context = context(0x20);
    let signing_a = signing_key(0x51);
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let signed = signed_refresh_commitment(context.clone(), &coefficient_a, &signing_a);
    let wire = signed.canonical_bytes().unwrap();

    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&trailing).is_err());
    assert!(
        TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&wire[..wire.len() - 1])
            .is_err()
    );

    let mut wrong_domain = wire.clone();
    wrong_domain[4] ^= 1;
    assert!(TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&wrong_domain).is_err());

    let mut wrong_role = wire.clone();
    let mut offset = 0;
    next_len32_field_range(&wrong_role, &mut offset);
    next_len32_field_range(&wrong_role, &mut offset);
    let role_label = next_len32_field_range(&wrong_role, &mut offset);
    wrong_role[role_label].copy_from_slice(b"deriver_b");
    let role_share_id = next_len32_field_range(&wrong_role, &mut offset);
    wrong_role[role_share_id].copy_from_slice(&2_u16.to_be_bytes());
    assert!(TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&wrong_role).is_err());

    let mut wrong_key_id = wire.clone();
    let mut offset = 0;
    for _ in 0..4 {
        next_len32_field_range(&wrong_key_id, &mut offset);
    }
    let key_id = next_len32_field_range(&wrong_key_id, &mut offset);
    wrong_key_id[key_id.end - 1] ^= 1;
    assert!(TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&wrong_key_id).is_err());

    let mut substituted_recipient = signed.canonical_bytes().unwrap();
    let mut outer_offset = 0;
    next_len32_field_range(&substituted_recipient, &mut outer_offset);
    let transcript_range = next_len32_field_range(&substituted_recipient, &mut outer_offset);
    let mut transcript = substituted_recipient[transcript_range.clone()].to_vec();
    let mut transcript_offset = 0;
    for _ in 0..11 {
        next_len32_field_range(&transcript, &mut transcript_offset);
    }
    let recipient_key_id = next_len32_field_range(&transcript, &mut transcript_offset);
    transcript[recipient_key_id.end - 1] ^= 1;
    substituted_recipient[transcript_range].copy_from_slice(&transcript);
    let substituted_recipient_signed =
        TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&substituted_recipient)
            .unwrap();
    assert_eq!(
        substituted_recipient_signed
            .verify_strict(
                &context,
                TwoPartyDeriverRole::DeriverA,
                "deriver-a-signing-key-7",
                signing_a.verifying_key().as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );

    let mut substituted_context = wire.clone();
    let mut outer_offset = 0;
    next_len32_field_range(&substituted_context, &mut outer_offset);
    let transcript_range = next_len32_field_range(&substituted_context, &mut outer_offset);
    let mut transcript = substituted_context[transcript_range.clone()].to_vec();
    let mut transcript_offset = 0;
    for _ in 0..7 {
        next_len32_field_range(&transcript, &mut transcript_offset);
    }
    let session_id = next_len32_field_range(&transcript, &mut transcript_offset);
    transcript[session_id.start] ^= 1;
    substituted_context[transcript_range].copy_from_slice(&transcript);
    let substituted_context_signed =
        TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&substituted_context).unwrap();
    assert_eq!(
        substituted_context_signed
            .verify_strict(
                &context,
                TwoPartyDeriverRole::DeriverA,
                "deriver-a-signing-key-7",
                signing_a.verifying_key().as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let mut wrong_signature = wire;
    let mut offset = 0;
    for _ in 0..5 {
        next_len32_field_range(&wrong_signature, &mut offset);
    }
    let signature = next_len32_field_range(&wrong_signature, &mut offset);
    wrong_signature[signature.start] ^= 1;
    let substituted_signature =
        TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&wrong_signature).unwrap();
    assert_eq!(
        substituted_signature
            .verify_strict(
                &context,
                TwoPartyDeriverRole::DeriverA,
                "deriver-a-signing-key-7",
                signing_a.verifying_key().as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );

    assert_eq!(
        signed
            .verify_strict(
                &context,
                TwoPartyDeriverRole::DeriverB,
                "deriver-b-signing-key-9",
                signing_a.verifying_key().as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );
    assert_eq!(
        signed
            .verify_strict(
                &context,
                TwoPartyDeriverRole::DeriverA,
                "deriver-a-signing-key-8",
                signing_a.verifying_key().as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );
}

#[test]
fn refresh_commit_barrier_requires_both_roles_in_one_ceremony() {
    let signing_a = signing_key(0x51);
    let signing_b = signing_key(0x61);
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let coefficient_b = coefficient(TwoPartyDeriverRole::DeriverB, 29);
    let commitment_a = verified_commitment(context(0x20), &coefficient_a, &signing_a);
    let commitment_b = verified_commitment(context(0x20), &coefficient_b, &signing_b);

    assert!(
        VerifiedTenantRootRefreshCommitmentPairV1::new(commitment_a.clone(), commitment_b,).is_ok()
    );
    assert!(
        VerifiedTenantRootRefreshCommitmentPairV1::new(commitment_a.clone(), commitment_a,)
            .is_err()
    );

    let mixed_context_a = verified_commitment(context(0x20), &coefficient_a, &signing_a);
    let mixed_context_b = verified_commitment(context(0x21), &coefficient_b, &signing_b);
    assert!(
        VerifiedTenantRootRefreshCommitmentPairV1::new(mixed_context_a, mixed_context_b,).is_err()
    );
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

    let commitment_pair = verified_commitment_pair(
        context,
        &coefficient_a,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let aad_a_to_b = TenantRootRefreshContributionAadV1::deriver_a_to_b(&commitment_pair).unwrap();
    let aad_b_to_a = TenantRootRefreshContributionAadV1::deriver_b_to_a(&commitment_pair).unwrap();

    let contribution_a = coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB);
    let envelope_a =
        seal_tenant_root_refresh_contribution_v1(&aad_a_to_b, &contribution_a, &mut hpke_rng(0x71))
            .unwrap();
    let signed_a =
        TenantRootSignedRefreshContributionV1::sign(&aad_a_to_b, envelope_a, &signing_a.to_bytes())
            .unwrap();
    let signed_a_wire = signed_a.canonical_bytes().unwrap();
    let decoded_signed_a =
        TenantRootSignedRefreshContributionV1::decode_canonical_bytes(&signed_a_wire).unwrap();
    assert_eq!(decoded_signed_a.canonical_bytes().unwrap(), signed_a_wire);
    let publicly_verified_a = decoded_signed_a
        .verify_signature(&aad_a_to_b, signing_a.verifying_key().as_bytes())
        .unwrap();
    assert_eq!(publicly_verified_a.source(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(
        publicly_verified_a.recipient(),
        TwoPartyDeriverRole::DeriverB
    );
    assert_eq!(
        publicly_verified_a.canonical_bytes(),
        signed_a_wire.as_slice()
    );
    assert_eq!(
        decoded_signed_a
            .verify_signature(&aad_a_to_b, signing_b.verifying_key().as_bytes())
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );
    let opened_a = decoded_signed_a
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
    assert_eq!(
        hex::encode(Sha256::digest(&signed_a_wire)),
        "f8333d288e2a89d2a94a67e7dedef765415312f7561dc9bca1a4935141f4f3d7",
    );
}

#[test]
fn refresh_open_rejects_plaintext_roles_swapped_inside_valid_signed_envelope() {
    let context = context(0x25);
    let signing_a = signing_key(0x51);
    let signing_b = signing_key(0x61);
    let hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32]).unwrap();
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let coefficient_b = coefficient(TwoPartyDeriverRole::DeriverB, 29);
    let commitments = verified_commitment_pair(
        context,
        &coefficient_a,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let aad = TenantRootRefreshContributionAadV1::deriver_a_to_b(&commitments).unwrap();
    let contribution = coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB);
    let envelope =
        seal_tenant_root_refresh_contribution_v1(&aad, &contribution, &mut hpke_rng(0x71)).unwrap();

    let mut swapped_bytes = contribution.to_bytes();
    swapped_bytes[..2].copy_from_slice(
        &TwoPartyDeriverRole::DeriverB
            .share_id()
            .get()
            .get()
            .to_be_bytes(),
    );
    swapped_bytes[2..4].copy_from_slice(
        &TwoPartyDeriverRole::DeriverA
            .share_id()
            .get()
            .get()
            .to_be_bytes(),
    );
    let swapped = RootShareRefreshContributionWire::decode(swapped_bytes).unwrap();
    let recipient_key =
        DhKemX25519HkdfSha256::pk_from_bytes(aad.recipient_public_key().as_bytes()).unwrap();
    let aad_bytes = aad.canonical_bytes().unwrap();
    let (encapsulated_key, ciphertext) =
        Hpke::<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>::seal_base(
            &mut hpke_rng(0x91),
            &recipient_key,
            b"seams/tenant-root-refresh/hpke-x25519-hkdf-sha256-aes256gcm/v1",
            &aad_bytes,
            &swapped.to_bytes(),
        )
        .unwrap();

    let mut envelope_wire = envelope.canonical_bytes().unwrap();
    let mut offset = 0;
    for _ in 0..9 {
        next_len32_field_range(&envelope_wire, &mut offset);
    }
    let encapsulated_key_range = next_len32_field_range(&envelope_wire, &mut offset);
    let ciphertext_range = next_len32_field_range(&envelope_wire, &mut offset);
    envelope_wire[encapsulated_key_range].copy_from_slice(encapsulated_key.as_ref());
    envelope_wire[ciphertext_range].copy_from_slice(&ciphertext);
    let swapped_envelope =
        TenantRootEncryptedRefreshContributionV1::decode_canonical_bytes(&envelope_wire).unwrap();
    let swapped_signed =
        TenantRootSignedRefreshContributionV1::sign(&aad, swapped_envelope, &signing_a.to_bytes())
            .unwrap();

    let error = swapped_signed
        .verify_and_open(&aad, signing_a.verifying_key().as_bytes(), &hpke_b)
        .unwrap_err();
    assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn signed_refresh_wire_parser_rejects_malformed_and_substituted_fields() {
    let signing_a = signing_key(0x51);
    let signing_b = signing_key(0x61);
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let coefficient_b = coefficient(TwoPartyDeriverRole::DeriverB, 29);
    let commitments = verified_commitment_pair(
        context(0x21),
        &coefficient_a,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let aad = TenantRootRefreshContributionAadV1::deriver_a_to_b(&commitments).unwrap();
    let contribution = coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB);
    let envelope =
        seal_tenant_root_refresh_contribution_v1(&aad, &contribution, &mut hpke_rng(0x71)).unwrap();
    let signed =
        TenantRootSignedRefreshContributionV1::sign(&aad, envelope, &signing_a.to_bytes()).unwrap();
    let wire = signed.canonical_bytes().unwrap();

    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(TenantRootSignedRefreshContributionV1::decode_canonical_bytes(&trailing).is_err());
    assert!(
        TenantRootSignedRefreshContributionV1::decode_canonical_bytes(&wire[..wire.len() - 1])
            .is_err()
    );

    let mut wrong_domain = wire.clone();
    wrong_domain[4] ^= 1;
    assert!(TenantRootSignedRefreshContributionV1::decode_canonical_bytes(&wrong_domain).is_err());

    let mut wrong_authentication_role = wire;
    let mut offset = 0;
    next_len32_field_range(&wrong_authentication_role, &mut offset);
    next_len32_field_range(&wrong_authentication_role, &mut offset);
    let role_label = next_len32_field_range(&wrong_authentication_role, &mut offset);
    wrong_authentication_role[role_label].copy_from_slice(b"deriver_b");
    let role_share_id = next_len32_field_range(&wrong_authentication_role, &mut offset);
    wrong_authentication_role[role_share_id].copy_from_slice(&2_u16.to_be_bytes());
    assert!(
        TenantRootSignedRefreshContributionV1::decode_canonical_bytes(&wrong_authentication_role)
            .is_err()
    );
}

#[test]
fn session_recipient_role_and_signature_substitutions_fail_closed() {
    let original_context = context(0x22);
    let signing_a = signing_key(0x51);
    let signing_b = signing_key(0x61);
    let wrong_signing_key = signing_key(0x52);
    let coefficient_a = coefficient(TwoPartyDeriverRole::DeriverA, 17);
    let coefficient_b = coefficient(TwoPartyDeriverRole::DeriverB, 29);
    let hpke_a = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32]).unwrap();
    let hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32]).unwrap();
    let other_hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb2; 32]).unwrap();
    let signed_commitment = TenantRootSignedRefreshCommitmentV1::sign(
        TenantRootRefreshCommitmentTranscriptV1::new(
            context(0x22),
            coefficient_a.commitment(),
            "deriver-a-hpke-key-7",
            hpke_a.public_key(),
        )
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
    let verified = verified_commitment_pair(
        original_context,
        &coefficient_a,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let aad = TenantRootRefreshContributionAadV1::deriver_a_to_b(&verified).unwrap();
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

    let next_epoch = verified_commitment_pair(
        context_for_epochs(0x22, 8, 9),
        &coefficient_a,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let next_epoch_aad = TenantRootRefreshContributionAadV1::deriver_a_to_b(&next_epoch).unwrap();
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
    let substituted_commitment = verified_commitment_pair(
        context(0x22),
        &substituted_coefficient,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let substituted_commitment_aad =
        TenantRootRefreshContributionAadV1::deriver_a_to_b(&substituted_commitment).unwrap();
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

    let restarted = verified_commitment_pair(
        context(0x23),
        &coefficient_a,
        &signing_a,
        &coefficient_b,
        &signing_b,
    );
    let restarted_aad = TenantRootRefreshContributionAadV1::deriver_a_to_b(&restarted).unwrap();
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

    let substituted_b = TenantRootSignedRefreshCommitmentV1::sign(
        TenantRootRefreshCommitmentTranscriptV1::new(
            context(0x22),
            coefficient_b.commitment(),
            "deriver-b-hpke-key-9",
            other_hpke_b.public_key(),
        )
        .unwrap(),
        &signing_b.to_bytes(),
    )
    .unwrap()
    .verify(signing_b.verifying_key().as_bytes())
    .unwrap();
    let substituted_recipient_pair = VerifiedTenantRootRefreshCommitmentPairV1::new(
        verified_commitment(context(0x22), &coefficient_a, &signing_a),
        substituted_b,
    )
    .unwrap();
    let substituted_recipient_aad =
        TenantRootRefreshContributionAadV1::deriver_a_to_b(&substituted_recipient_pair).unwrap();
    assert_eq!(
        substituted_recipient_aad.recipient_key_id(),
        "deriver-b-hpke-key-9"
    );
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
        "deriver-a-hpke-key-7",
        hpke_a.public_key(),
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
