mod support;

use curve25519_dalek::scalar::Scalar;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityV1, TenantRootShareInstallationEvidenceV1,
    TenantRootShareInstallationTranscriptV1, TenantRootSignedShareInstallationEvidenceV1,
};
use sha2::{Digest, Sha256};
use std::ops::Range;
use threshold_prf::{
    prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole,
};

fn context(epochs: TenantRootCeremonyEpochsV1, session_seed: u8) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .unwrap()
            .digest()
            .unwrap(),
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        epochs,
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn signed_evidence(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share_scalar: u64,
    peer_scalar: u64,
    proof_seed: u8,
) -> TenantRootSignedShareInstallationEvidenceV1 {
    let share = fixed_share(role, share_scalar);
    let peer = fixed_share(role.peer(), peer_scalar);
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context,
        role,
        SigningRootShareCommitment::from_share(&share),
        SigningRootShareCommitment::from_share(&peer),
    )
    .unwrap();
    let proof = prove_root_share_knowledge(
        &share,
        &transcript.canonical_bytes().unwrap(),
        &mut support::rng06(proof_seed),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let signing_key = support::signing_key(role);
    TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes()).unwrap()
}

fn next_field_range(wire: &[u8], offset: &mut usize) -> Range<usize> {
    let length_end = *offset + 4;
    let length = u32::from_be_bytes(wire[*offset..length_end].try_into().unwrap()) as usize;
    let value_end = length_end + length;
    *offset = value_end;
    length_end..value_end
}

fn field_range(wire: &[u8], field_index: usize) -> Range<usize> {
    let mut offset = 0;
    for index in 0..=field_index {
        let field = next_field_range(wire, &mut offset);
        if index == field_index {
            return field;
        }
    }
    unreachable!()
}

fn nested_field_range(wire: &[u8], outer_field: usize, nested_field: usize) -> Range<usize> {
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

#[test]
fn creation_and_refresh_installation_evidence_wires_round_trip() {
    let cases = [
        (TenantRootCeremonyEpochsV1::create(), 0x21, 0x23, 12, 19),
        (
            TenantRootCeremonyEpochsV1::refresh(
                router_ab_core::TenantRootShareEpoch::new(7).unwrap(),
                router_ab_core::TenantRootShareEpoch::new(8).unwrap(),
            )
            .unwrap(),
            0x22,
            0x24,
            13,
            20,
        ),
    ];

    for (epochs, session_seed, proof_seed, share_scalar, peer_scalar) in cases {
        let signed = signed_evidence(
            context(epochs, session_seed),
            TwoPartyDeriverRole::DeriverA,
            share_scalar,
            peer_scalar,
            proof_seed,
        );
        let wire = signed.canonical_bytes().unwrap();
        let decoded =
            TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded.canonical_bytes().unwrap(), wire);
        decoded
            .verify(
                support::signing_key(TwoPartyDeriverRole::DeriverA)
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap();
    }
}

#[test]
fn verified_wire_boundary_retains_exact_bytes_and_rejects_wrong_authentication() {
    let signed = signed_evidence(
        context(TenantRootCeremonyEpochsV1::create(), 0x31),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    assert_eq!(signed.signing_key_id(), "deriver-a-signing-key-7");
    let wire = signed.canonical_bytes().unwrap();
    let verifying_key = support::signing_key(TwoPartyDeriverRole::DeriverA)
        .verifying_key()
        .to_bytes();
    let verified = TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &wire,
        &verifying_key,
    )
    .unwrap();
    assert_eq!(verified.canonical_bytes(), wire);
    let expected_receipt_digest: [u8; 32] = Sha256::digest(&wire).into();
    assert_eq!(
        verified.lifecycle_receipt_digest().unwrap().as_bytes(),
        &expected_receipt_digest,
    );
    assert_eq!(
        verified.evidence().transcript().role(),
        TwoPartyDeriverRole::DeriverA
    );

    let wrong_key = support::signing_key(TwoPartyDeriverRole::DeriverB)
        .verifying_key()
        .to_bytes();
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &wire, &wrong_key,
        )
        .is_err()
    );

    let mut trailing = wire;
    trailing.push(0);
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &trailing,
            &verifying_key,
        )
        .is_err()
    );
}

#[test]
fn ceremony_context_wires_round_trip_for_create_and_refresh() {
    let cases = [
        (TenantRootCeremonyEpochsV1::create(), 0x2e),
        (
            TenantRootCeremonyEpochsV1::refresh(
                router_ab_core::TenantRootShareEpoch::new(7).unwrap(),
                router_ab_core::TenantRootShareEpoch::new(8).unwrap(),
            )
            .unwrap(),
            0x2f,
        ),
    ];

    for (epochs, session_seed) in cases {
        let expected = context(epochs, session_seed);
        let wire = expected.canonical_bytes().unwrap();
        let decoded = TenantRootCeremonyContextV1::decode_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.canonical_bytes().unwrap(), wire);
    }
}

#[test]
fn ceremony_context_wire_rejects_bad_domain_truncation_and_trailing_bytes() {
    let wire = context(TenantRootCeremonyEpochsV1::create(), 0x30)
        .canonical_bytes()
        .unwrap();

    let mut bad_domain = wire.clone();
    let domain = field_range(&bad_domain, 0);
    bad_domain[domain.start] ^= 1;
    assert!(TenantRootCeremonyContextV1::decode_canonical_bytes(&bad_domain).is_err());

    assert!(TenantRootCeremonyContextV1::decode_canonical_bytes(&wire[..wire.len() - 1]).is_err());

    let mut trailing = wire;
    trailing.push(0);
    assert!(TenantRootCeremonyContextV1::decode_canonical_bytes(&trailing).is_err());
}

#[test]
fn installation_evidence_wire_rejects_role_key_signature_proof_and_transcript_substitution() {
    let ceremony_context = context(
        TenantRootCeremonyEpochsV1::refresh(
            router_ab_core::TenantRootShareEpoch::new(7).unwrap(),
            router_ab_core::TenantRootShareEpoch::new(8).unwrap(),
        )
        .unwrap(),
        0x25,
    );
    let signed = signed_evidence(
        ceremony_context.clone(),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x26,
    );
    let wire = signed.canonical_bytes().unwrap();

    let mut wrong_role = wire.clone();
    let role_label = field_range(&wrong_role, 2);
    wrong_role[role_label].copy_from_slice(b"deriver_b");
    let role_share_id = field_range(&wrong_role, 3);
    wrong_role[role_share_id].copy_from_slice(&2_u16.to_be_bytes());
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&wrong_role).is_err()
    );

    let mut wrong_key_id = wire.clone();
    let mut offset = 0;
    for _ in 0..4 {
        next_field_range(&wrong_key_id, &mut offset);
    }
    let key_id = next_field_range(&wrong_key_id, &mut offset);
    wrong_key_id[key_id].copy_from_slice(b"deriver-z-signing-key-7");
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&wrong_key_id).is_err()
    );

    let mut wrong_signature = wire.clone();
    let mut offset = 0;
    for _ in 0..5 {
        next_field_range(&wrong_signature, &mut offset);
    }
    let signature = next_field_range(&wrong_signature, &mut offset);
    wrong_signature[signature.start] ^= 1;
    let decoded =
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&wrong_signature)
            .unwrap();
    assert_eq!(
        decoded
            .verify(
                support::signing_key(TwoPartyDeriverRole::DeriverA)
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );

    let substituted = signed_evidence(
        ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        18,
        19,
        0x27,
    )
    .canonical_bytes()
    .unwrap();
    let mut wrong_proof = wire.clone();
    let proof = nested_field_range(&wrong_proof, 1, 2);
    let substituted_proof = nested_field_range(&substituted, 1, 2);
    wrong_proof[proof].copy_from_slice(&substituted[substituted_proof]);
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&wrong_proof).is_err()
    );

    let substituted_transcript = signed_evidence(
        context(
            TenantRootCeremonyEpochsV1::refresh(
                router_ab_core::TenantRootShareEpoch::new(7).unwrap(),
                router_ab_core::TenantRootShareEpoch::new(8).unwrap(),
            )
            .unwrap(),
            0x28,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x29,
    )
    .canonical_bytes()
    .unwrap();
    let mut wrong_transcript = wire;
    let transcript = nested_field_range(&wrong_transcript, 1, 1);
    let substituted_transcript_field = nested_field_range(&substituted_transcript, 1, 1);
    wrong_transcript[transcript]
        .copy_from_slice(&substituted_transcript[substituted_transcript_field]);
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&wrong_transcript)
            .is_err()
    );
}

#[test]
fn installation_evidence_wire_rejects_truncation_and_trailing_unknown_bytes() {
    let signed = signed_evidence(
        context(TenantRootCeremonyEpochsV1::create(), 0x2a),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x2b,
    );
    let wire = signed.canonical_bytes().unwrap();

    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(
            &wire[..wire.len() - 1]
        )
        .is_err()
    );
    let mut trailing = wire;
    trailing.push(0);
    assert!(
        TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&trailing).is_err()
    );
}

#[test]
fn installation_evidence_wire_digest_is_frozen() {
    let signed = signed_evidence(
        context(
            TenantRootCeremonyEpochsV1::refresh(
                router_ab_core::TenantRootShareEpoch::new(7).unwrap(),
                router_ab_core::TenantRootShareEpoch::new(8).unwrap(),
            )
            .unwrap(),
            0x2c,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x2d,
    );
    let wire = signed.canonical_bytes().unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(wire)),
        "09c1d5e1d49de66caf0f3673d1a5fa54bf6dc0d8412c6a1e9e061280d9f11fe6",
    );
}
