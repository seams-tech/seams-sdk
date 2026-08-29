use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    verify_tenant_root_creation_evidence_v1, verify_tenant_root_refresh_evidence_v1,
    RouterAbDerivationErrorCode, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityV1, TenantRootShareEpoch, TenantRootShareInstallationEvidenceV1,
    TenantRootShareInstallationTranscriptV1, TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{
    apply_two_party_root_share_refresh, prove_root_share_knowledge, RootShareRefreshCoefficient,
    SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole,
    TwoPartyRootShareCommitments,
};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .expect("fixed non-zero share")
}

fn identity_digest() -> router_ab_core::TenantRootIdentityDigestV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .unwrap()
        .digest()
        .unwrap()
}

fn ceremony_context(
    epochs: TenantRootCeremonyEpochsV1,
    session_seed: u8,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity_digest(),
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

fn evidence(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    peer: &SigningRootShare,
    proof_seed: u8,
) -> TenantRootShareInstallationEvidenceV1 {
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context,
        role,
        SigningRootShareCommitment::from_share(share),
        SigningRootShareCommitment::from_share(peer),
    )
    .unwrap();
    let proof = prove_root_share_knowledge(
        share,
        &transcript.canonical_bytes().unwrap(),
        &mut seeded_rng(proof_seed),
    )
    .unwrap();
    TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap()
}

fn signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x51,
            TwoPartyDeriverRole::DeriverB => 0x61,
        }; 32],
    )
}

fn authenticated_evidence(
    evidence: TenantRootShareInstallationEvidenceV1,
) -> VerifiedTenantRootShareInstallationEvidenceV1 {
    let key = signing_key(evidence.transcript().role());
    TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &key.to_bytes())
        .unwrap()
        .verify(key.verifying_key().as_bytes())
        .unwrap()
}

fn refreshed_share(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> SigningRootShare {
    let contribution_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(recipient))
        .unwrap();
    let contribution_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))
        .unwrap();
    apply_two_party_root_share_refresh(current, contribution_a, contribution_b).unwrap()
}

#[test]
fn creation_context_and_installation_evidence_are_canonical_and_exact() {
    let context = ceremony_context(TenantRootCeremonyEpochsV1::create(), 0x21);
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let evidence_a = evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &share_a,
        &share_b,
        1,
    );
    let evidence_b = evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        &share_b,
        &share_a,
        2,
    );

    let verified_a = authenticated_evidence(evidence_a.clone());
    let verified_b = authenticated_evidence(evidence_b);
    let commitments = verify_tenant_root_creation_evidence_v1(&verified_a, &verified_b).unwrap();
    assert_eq!(
        commitments,
        TwoPartyRootShareCommitments::from_shares(&share_a, &share_b).unwrap(),
    );
    assert_eq!(
        hex::encode(Sha256::digest(
            evidence_a.transcript().canonical_bytes().unwrap()
        )),
        "5250935617494484c7878dc4d79e2bafadc108d914548ba7d6792be368267e7c",
    );
    assert_eq!(
        hex::encode(context.canonical_bytes().unwrap()),
        "0000001574656e616e745f726f6f745f6372656174655f7631\
         00000006637265617465\
         000000209c5d583ae4693793ce3b51590c788651ba0df4c2339b25b84676665fce44aa8b\
         0000001031313131313131313131313131313131\
         000000080000000000000001\
         0000001021212121212121212121212121212121\
         000000204141414141414141414141414141414141414141414141414141414141414141\
         0000000800000000000f4240\
         0000000800000000000fb770\
         00000017646572697665722d612d7369676e696e672d6b65792d37\
         00000017646572697665722d622d7369676e696e672d6b65792d39"
            .replace(char::is_whitespace, ""),
    );
}

#[test]
fn refresh_evidence_preserves_root_and_rejects_session_peer_and_root_substitution() {
    let current_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let current_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let current = TwoPartyRootShareCommitments::from_shares(&current_a, &current_b).unwrap();
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(3));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(4));
    let next_a = refreshed_share(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let epochs = TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).unwrap(),
        TenantRootShareEpoch::new(8).unwrap(),
    )
    .unwrap();
    let context = ceremony_context(epochs, 0x22);
    let evidence_a = evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &next_a,
        &next_b,
        5,
    );
    let evidence_b = evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        &next_b,
        &next_a,
        6,
    );

    let verified_a = authenticated_evidence(evidence_a.clone());
    let verified_b = authenticated_evidence(evidence_b);
    let next = verify_tenant_root_refresh_evidence_v1(&current, &verified_a, &verified_b).unwrap();
    assert_eq!(current.root(), next.root());

    let other_session = ceremony_context(epochs, 0x23);
    let other_b = evidence(
        other_session,
        TwoPartyDeriverRole::DeriverB,
        &next_b,
        &next_a,
        7,
    );
    assert_eq!(
        verify_tenant_root_refresh_evidence_v1(
            &current,
            &verified_a,
            &authenticated_evidence(other_b),
        )
        .unwrap_err()
        .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let unrelated_a = fixed_share(TwoPartyDeriverRole::DeriverA, 77);
    let peer_substituted_b = evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        &next_b,
        &unrelated_a,
        8,
    );
    assert_eq!(
        verify_tenant_root_refresh_evidence_v1(
            &current,
            &verified_a,
            &authenticated_evidence(peer_substituted_b),
        )
        .unwrap_err()
        .code(),
        RouterAbDerivationErrorCode::MalformedInput,
    );

    let unrelated_current = TwoPartyRootShareCommitments::from_shares(
        &fixed_share(TwoPartyDeriverRole::DeriverA, 51),
        &fixed_share(TwoPartyDeriverRole::DeriverB, 83),
    )
    .unwrap();
    assert_eq!(
        verify_tenant_root_refresh_evidence_v1(&unrelated_current, &verified_a, &verified_b,)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );
}

#[test]
fn epoch_time_session_nonce_and_restart_invariants_fail_closed() {
    assert!(TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).unwrap(),
        TenantRootShareEpoch::new(9).unwrap(),
    )
    .is_err());
    assert!(TenantRootCeremonySessionIdV1::from_bytes([0; 16]).is_err());
    assert!(TenantRootCeremonyNonceV1::from_bytes([0; 32]).is_err());

    let context = ceremony_context(TenantRootCeremonyEpochsV1::create(), 0x24);
    context.validate_at(940_000).unwrap();
    context.validate_at(1_090_000).unwrap();
    assert!(context.validate_at(939_999).is_err());
    assert!(context.validate_at(1_090_001).is_err());

    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let original = evidence(
        context,
        TwoPartyDeriverRole::DeriverA,
        &share_a,
        &share_b,
        9,
    );
    let restarted_transcript = TenantRootShareInstallationTranscriptV1::new(
        ceremony_context(TenantRootCeremonyEpochsV1::create(), 0x25),
        TwoPartyDeriverRole::DeriverA,
        SigningRootShareCommitment::from_share(&share_a),
        SigningRootShareCommitment::from_share(&share_b),
    )
    .unwrap();
    assert!(
        TenantRootShareInstallationEvidenceV1::new(restarted_transcript, original.proof(),)
            .is_err()
    );
}
