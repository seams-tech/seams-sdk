use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCreationCommitmentTranscriptV1, TenantRootCustodyLineageId, TenantRootIdentityV1,
    TenantRootShareEpoch, TenantRootSignedCreationCommitmentV1,
    VerifiedTenantRootCreationCommitmentPairV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole};

fn context(session_seed: u8) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .unwrap()
            .digest()
            .unwrap(),
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    match role {
        TwoPartyDeriverRole::DeriverA => SigningKey::from_bytes(&[0x51; 32]),
        TwoPartyDeriverRole::DeriverB => SigningKey::from_bytes(&[0x61; 32]),
    }
}

fn signing_key_id(role: TwoPartyDeriverRole) -> &'static str {
    match role {
        TwoPartyDeriverRole::DeriverA => "deriver-a-signing-key-7",
        TwoPartyDeriverRole::DeriverB => "deriver-b-signing-key-9",
    }
}

fn share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn signed_commitment(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    scalar: u64,
) -> TenantRootSignedCreationCommitmentV1 {
    let transcript = TenantRootCreationCommitmentTranscriptV1::new(
        context,
        role,
        SigningRootShareCommitment::from_share(&share(role, scalar)),
    )
    .unwrap();
    let key = signing_key(role);
    TenantRootSignedCreationCommitmentV1::sign(transcript, &key.to_bytes()).unwrap()
}

fn verified_commitment(
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    scalar: u64,
) -> router_ab_core::VerifiedTenantRootCreationCommitmentV1 {
    let signed = signed_commitment(context.clone(), role, scalar);
    let wire = signed.canonical_bytes().unwrap();
    let key = signing_key(role);
    TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
        &wire,
        context,
        role,
        signing_key_id(role),
        key.verifying_key().as_bytes(),
    )
    .unwrap()
}

fn next_field_range(wire: &[u8], offset: &mut usize) -> std::ops::Range<usize> {
    let length_end = *offset + 4;
    let length = u32::from_be_bytes(wire[*offset..length_end].try_into().unwrap()) as usize;
    let value_end = length_end + length;
    *offset = value_end;
    length_end..value_end
}

fn field_range(wire: &[u8], field_index: usize) -> std::ops::Range<usize> {
    let mut offset = 0;
    for index in 0..=field_index {
        let field = next_field_range(wire, &mut offset);
        if index == field_index {
            return field;
        }
    }
    unreachable!()
}

fn nested_field_range(
    wire: &[u8],
    outer_field: usize,
    nested_field: usize,
) -> std::ops::Range<usize> {
    let mut offset = 0;
    let mut nested = None;
    for index in 0..=outer_field {
        let field = next_field_range(wire, &mut offset);
        if index == outer_field {
            nested = Some(field);
        }
    }
    let nested = nested.unwrap();
    let mut offset = nested.start;
    for index in 0..=nested_field {
        let field = next_field_range(wire, &mut offset);
        if index == nested_field {
            return field;
        }
    }
    unreachable!()
}

fn append_len32(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

#[test]
fn creation_commitment_a_b_wires_round_trip_and_retain_exact_digest() {
    let ceremony_context = context(0x21);
    let signed_a = signed_commitment(ceremony_context.clone(), TwoPartyDeriverRole::DeriverA, 12);
    let signed_b = signed_commitment(ceremony_context.clone(), TwoPartyDeriverRole::DeriverB, 19);
    let wire_a = signed_a.canonical_bytes().unwrap();
    let wire_b = signed_b.canonical_bytes().unwrap();

    for (signed, role, wire) in [
        (&signed_a, TwoPartyDeriverRole::DeriverA, wire_a.clone()),
        (&signed_b, TwoPartyDeriverRole::DeriverB, wire_b.clone()),
    ] {
        let decoded = TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded.canonical_bytes().unwrap(), wire);
        let key = signing_key(role);
        let verified = decoded
            .verify_strict(
                &ceremony_context,
                role,
                signing_key_id(role),
                key.verifying_key().as_bytes(),
            )
            .unwrap();
        assert_eq!(verified.canonical_bytes(), wire.as_slice());
        let expected_digest: [u8; 32] = Sha256::digest(&wire).into();
        assert_eq!(verified.digest().as_bytes(), &expected_digest);
        assert_eq!(signed.transcript().context(), verified.context());
        assert_eq!(signed.role(), verified.role());
    }

    let verified_a = TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
        &wire_a,
        &ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        signing_key_id(TwoPartyDeriverRole::DeriverA),
        signing_key(TwoPartyDeriverRole::DeriverA)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    let verified_b = TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
        &wire_b,
        &ceremony_context,
        TwoPartyDeriverRole::DeriverB,
        signing_key_id(TwoPartyDeriverRole::DeriverB),
        signing_key(TwoPartyDeriverRole::DeriverB)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    let pair = VerifiedTenantRootCreationCommitmentPairV1::new(verified_a, verified_b).unwrap();

    let mut expected_pair_wire = Vec::new();
    append_len32(
        &mut expected_pair_wire,
        b"tenant_root_creation_commitment_pair_v1",
    );
    append_len32(&mut expected_pair_wire, &wire_a);
    append_len32(&mut expected_pair_wire, &wire_b);
    assert_eq!(pair.canonical_bytes(), expected_pair_wire.as_slice());
    let expected_pair_digest: [u8; 32] = Sha256::digest(&expected_pair_wire).into();
    assert_eq!(pair.digest().as_bytes(), &expected_pair_digest);
    assert_eq!(pair.deriver_a().role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(pair.deriver_b().role(), TwoPartyDeriverRole::DeriverB);
    assert_eq!(pair.context(), &ceremony_context);
}

#[test]
fn creation_commitment_rejects_non_creation_context_and_wrong_share_id() {
    let refresh_context = TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .unwrap()
            .digest()
            .unwrap(),
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(7).unwrap(),
            TenantRootShareEpoch::new(8).unwrap(),
        )
        .unwrap(),
        TenantRootCeremonySessionIdV1::from_bytes([0x22; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap();
    assert!(TenantRootCreationCommitmentTranscriptV1::new(
        refresh_context,
        TwoPartyDeriverRole::DeriverA,
        SigningRootShareCommitment::from_share(&share(TwoPartyDeriverRole::DeriverA, 12)),
    )
    .is_err());

    assert!(TenantRootCreationCommitmentTranscriptV1::new(
        context(0x21),
        TwoPartyDeriverRole::DeriverA,
        SigningRootShareCommitment::from_share(&share(TwoPartyDeriverRole::DeriverB, 12)),
    )
    .is_err());
}

#[test]
fn signed_creation_wire_rejects_role_key_signature_context_and_commitment_substitution() {
    let ceremony_context = context(0x31);
    let signed_a = signed_commitment(ceremony_context.clone(), TwoPartyDeriverRole::DeriverA, 12);
    let wire = signed_a.canonical_bytes().unwrap();

    let mut wrong_role = wire.clone();
    let role_label = field_range(&wrong_role, 2);
    wrong_role[role_label].copy_from_slice(b"deriver_b");
    let role_id = field_range(&wrong_role, 3);
    wrong_role[role_id].copy_from_slice(&2_u16.to_be_bytes());
    assert!(TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wrong_role).is_err());

    let signed_b = signed_commitment(ceremony_context.clone(), TwoPartyDeriverRole::DeriverB, 19);
    let wire_b = signed_b.canonical_bytes().unwrap();
    let mut wrong_share_id = wire.clone();
    let commitment = nested_field_range(&wrong_share_id, 1, 4);
    let other_commitment = nested_field_range(&wire_b, 1, 4);
    wrong_share_id[commitment].copy_from_slice(&wire_b[other_commitment]);
    assert!(TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wrong_share_id).is_err());

    let other_context_wire = signed_commitment(context(0x32), TwoPartyDeriverRole::DeriverA, 12)
        .canonical_bytes()
        .unwrap();
    let mut wrong_context = wire.clone();
    let context_field = nested_field_range(&wrong_context, 1, 1);
    let other_context_field = nested_field_range(&other_context_wire, 1, 1);
    wrong_context[context_field].copy_from_slice(&other_context_wire[other_context_field]);
    let decoded_context =
        TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wrong_context).unwrap();
    assert_eq!(
        decoded_context
            .verify_strict(
                &ceremony_context,
                TwoPartyDeriverRole::DeriverA,
                signing_key_id(TwoPartyDeriverRole::DeriverA),
                signing_key(TwoPartyDeriverRole::DeriverA)
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let mut wrong_key_id = wire.clone();
    let key_id = field_range(&wrong_key_id, 4);
    wrong_key_id[key_id].copy_from_slice(b"deriver-b-signing-key-9");
    assert!(TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wrong_key_id).is_err());

    let mut wrong_signature = wire.clone();
    let signature = field_range(&wrong_signature, 5);
    wrong_signature[signature.start] ^= 1;
    let decoded_signature =
        TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wrong_signature).unwrap();
    assert_eq!(
        decoded_signature
            .verify_strict(
                &ceremony_context,
                TwoPartyDeriverRole::DeriverA,
                signing_key_id(TwoPartyDeriverRole::DeriverA),
                signing_key(TwoPartyDeriverRole::DeriverA)
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );

    let decoded_with_wrong_key =
        TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wire).unwrap();
    assert_eq!(
        decoded_with_wrong_key
            .verify_strict(
                &ceremony_context,
                TwoPartyDeriverRole::DeriverA,
                signing_key_id(TwoPartyDeriverRole::DeriverA),
                signing_key(TwoPartyDeriverRole::DeriverB)
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );

    assert!(
        TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&wire[..wire.len() - 1])
            .is_err()
    );
    let mut trailing = wire;
    trailing.push(0);
    assert!(TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&trailing).is_err());
}

#[test]
fn creation_commitment_pair_rejects_order_duplicates_equal_points_and_identity_root() {
    let ceremony_context = context(0x41);
    let a = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverA, 12);
    let b = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverB, 19);
    assert!(VerifiedTenantRootCreationCommitmentPairV1::new(b, a).is_err());

    let duplicate_a = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverA, 12);
    let duplicate_b = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverB, 12);
    assert!(VerifiedTenantRootCreationCommitmentPairV1::new(duplicate_a, duplicate_b).is_err());

    let identity_a = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverA, 1);
    let identity_b = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverB, 2);
    assert!(VerifiedTenantRootCreationCommitmentPairV1::new(identity_a, identity_b).is_err());

    let context_b = context(0x42);
    let mismatched_a = verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverA, 12);
    let mismatched_b = verified_commitment(&context_b, TwoPartyDeriverRole::DeriverB, 19);
    assert!(VerifiedTenantRootCreationCommitmentPairV1::new(mismatched_a, mismatched_b).is_err());
}

#[test]
fn creation_commitment_pair_digest_changes_when_a_signed_wire_is_substituted() {
    let ceremony_context = context(0x51);
    let pair = VerifiedTenantRootCreationCommitmentPairV1::new(
        verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverA, 12),
        verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverB, 19),
    )
    .unwrap();
    let substituted = VerifiedTenantRootCreationCommitmentPairV1::new(
        verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverA, 13),
        verified_commitment(&ceremony_context, TwoPartyDeriverRole::DeriverB, 19),
    )
    .unwrap();
    assert_ne!(pair.canonical_bytes(), substituted.canonical_bytes());
    assert_ne!(pair.digest(), substituted.digest());
}
