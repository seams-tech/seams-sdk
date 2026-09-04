use ed25519_dalek::SigningKey;
use router_ab_core::{
    TenantRootRecoveryReshareHpkeKeypairV1, TenantRootSignedRecoveryReshareContributionV1,
    TenantRootSignedRecoveryShareInstallationEvidenceV1, VerifiedTenantRootRecoveryResharePairV1,
};
use threshold_prf::{
    SigningRootShareCommitment, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
};

mod support;

use support::{
    fixed_share, recovery_reshare_fixture as fixture, rng06, rng09, EXPIRES_AT_MS, ISSUED_AT_MS,
};

#[test]
fn dedicated_reshare_is_role_separated_fresh_and_root_continuous() {
    let fixture = fixture();
    let verified_commitment_a = fixture
        .signed_commitment_a
        .verify(
            &fixture.context,
            fixture.signing_a.verifying_key().as_bytes(),
        )
        .unwrap();
    let verified_commitment_b = fixture
        .signed_commitment_b
        .verify(
            &fixture.context,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .unwrap();
    let hpke_a = TenantRootRecoveryReshareHpkeKeypairV1::derive_from_ikm([0x71; 32]).unwrap();
    let hpke_b = TenantRootRecoveryReshareHpkeKeypairV1::derive_from_ikm([0x81; 32]).unwrap();
    let contribution_a_to_b = TenantRootSignedRecoveryReshareContributionV1::seal(
        &fixture.context,
        &fixture.coefficient_a,
        &verified_commitment_a,
        "recovery-reshare-hpke-b-1",
        hpke_b.public_key(),
        &mut rng09(0x91),
        &fixture.signing_a.to_bytes(),
    )
    .unwrap();
    let contribution_b_to_a = TenantRootSignedRecoveryReshareContributionV1::seal(
        &fixture.context,
        &fixture.coefficient_b,
        &verified_commitment_b,
        "recovery-reshare-hpke-a-1",
        hpke_a.public_key(),
        &mut rng09(0xa1),
        &fixture.signing_b.to_bytes(),
    )
    .unwrap();
    assert_eq!(
        (
            contribution_a_to_b.source(),
            contribution_a_to_b.recipient()
        ),
        (TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB)
    );
    assert_eq!(
        (
            contribution_b_to_a.source(),
            contribution_b_to_a.recipient()
        ),
        (TwoPartyDeriverRole::DeriverB, TwoPartyDeriverRole::DeriverA)
    );
    let verified_b_for_a = contribution_b_to_a
        .verify_and_open(
            &fixture.context,
            &verified_commitment_b,
            "recovery-reshare-hpke-a-1",
            &hpke_a,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .unwrap();
    let verified_a_for_b = contribution_a_to_b
        .verify_and_open(
            &fixture.context,
            &verified_commitment_a,
            "recovery-reshare-hpke-b-1",
            &hpke_b,
            fixture.signing_a.verifying_key().as_bytes(),
        )
        .unwrap();
    let pending_a = router_ab_core::PendingTenantRootRecoveryShareV1::derive(
        &fixture.context,
        &fixture.active_a,
        &fixture.coefficient_a,
        &verified_commitment_a,
        verified_b_for_a,
    )
    .unwrap();
    let pending_b = router_ab_core::PendingTenantRootRecoveryShareV1::derive(
        &fixture.context,
        &fixture.active_b,
        &fixture.coefficient_b,
        &verified_commitment_b,
        verified_a_for_b,
    )
    .unwrap();

    let expected_a = fixed_share(TwoPartyDeriverRole::DeriverA, 30);
    let expected_b = fixed_share(TwoPartyDeriverRole::DeriverB, 55);
    assert_eq!(
        pending_a.commitment(),
        SigningRootShareCommitment::from_share(&expected_a)
    );
    assert_eq!(
        pending_b.commitment(),
        SigningRootShareCommitment::from_share(&expected_b)
    );
    assert_ne!(
        pending_a.commitment(),
        SigningRootShareCommitment::from_share(&fixture.active_a)
    );
    assert_ne!(
        pending_b.commitment(),
        SigningRootShareCommitment::from_share(&fixture.active_b)
    );

    let evidence_a = pending_a
        .prove(&fixture.context, pending_b.commitment(), &mut rng06(0xb1))
        .unwrap();
    let evidence_b = pending_b
        .prove(&fixture.context, pending_a.commitment(), &mut rng06(0xc1))
        .unwrap();
    let signed_evidence_a = TenantRootSignedRecoveryShareInstallationEvidenceV1::sign(
        &fixture.context,
        evidence_a,
        &fixture.signing_a.to_bytes(),
    )
    .unwrap();
    let signed_evidence_b = TenantRootSignedRecoveryShareInstallationEvidenceV1::sign(
        &fixture.context,
        evidence_b,
        &fixture.signing_b.to_bytes(),
    )
    .unwrap();
    let verified_pair = VerifiedTenantRootRecoveryResharePairV1::verify(
        &fixture.context,
        &signed_evidence_a,
        &signed_evidence_b,
        fixture.signing_a.verifying_key().as_bytes(),
        fixture.signing_b.verifying_key().as_bytes(),
    )
    .unwrap();
    let expected_pair =
        TwoPartyRootShareCommitments::from_shares(&expected_a, &expected_b).unwrap();
    assert_eq!(verified_pair.stable_root_commitment(), expected_pair.root());
    assert_eq!(
        verified_pair.stable_root_commitment(),
        fixture.context.stable_root_commitment()
    );

    let verified_a = pending_a.finalize(&verified_pair).unwrap();
    let verified_b = pending_b.finalize(&verified_pair).unwrap();
    assert_eq!(verified_a.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(verified_b.role(), TwoPartyDeriverRole::DeriverB);
    assert_eq!(
        verified_a.recovery_set_id(),
        fixture.context.recovery_set_id()
    );
    assert_eq!(
        verified_b.recovery_set_id(),
        fixture.context.recovery_set_id()
    );
    assert_ne!(
        verified_a.recipient_fingerprint(),
        verified_b.recipient_fingerprint()
    );
}

#[test]
fn context_commitment_signature_recipient_and_active_share_substitution_fail_closed() {
    let fixture = fixture();
    let wrong_signing_key = SigningKey::from_bytes(&[0xee; 32]);
    assert!(fixture
        .signed_commitment_a
        .verify(
            &fixture.context,
            wrong_signing_key.verifying_key().as_bytes()
        )
        .is_err());

    let verified_commitment_a = fixture
        .signed_commitment_a
        .verify(
            &fixture.context,
            fixture.signing_a.verifying_key().as_bytes(),
        )
        .unwrap();
    let verified_commitment_b = fixture
        .signed_commitment_b
        .verify(
            &fixture.context,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .unwrap();
    let hpke_a = TenantRootRecoveryReshareHpkeKeypairV1::derive_from_ikm([0x71; 32]).unwrap();
    let wrong_hpke_a = TenantRootRecoveryReshareHpkeKeypairV1::derive_from_ikm([0x72; 32]).unwrap();
    let contribution_b_to_a = TenantRootSignedRecoveryReshareContributionV1::seal(
        &fixture.context,
        &fixture.coefficient_b,
        &verified_commitment_b,
        "recovery-reshare-hpke-a-1",
        hpke_a.public_key(),
        &mut rng09(0xa1),
        &fixture.signing_b.to_bytes(),
    )
    .unwrap();
    assert!(contribution_b_to_a
        .verify_and_open(
            &fixture.context,
            &verified_commitment_b,
            "recovery-reshare-hpke-a-1",
            &wrong_hpke_a,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .is_err());
    assert!(contribution_b_to_a
        .verify_and_open(
            &fixture.context,
            &verified_commitment_b,
            "recovery-reshare-hpke-a-substituted",
            &hpke_a,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .is_err());
    let verified_b_for_a = contribution_b_to_a
        .verify_and_open(
            &fixture.context,
            &verified_commitment_b,
            "recovery-reshare-hpke-a-1",
            &hpke_a,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .unwrap();
    let wrong_active_a = fixed_share(TwoPartyDeriverRole::DeriverA, 13);
    assert!(router_ab_core::PendingTenantRootRecoveryShareV1::derive(
        &fixture.context,
        &wrong_active_a,
        &fixture.coefficient_a,
        &verified_commitment_a,
        verified_b_for_a,
    )
    .is_err());
}

#[test]
fn canonical_context_freezes_recovery_namespace_and_clock_window() {
    let fixture = fixture();
    assert!(fixture.context.validate_at(ISSUED_AT_MS).is_ok());
    assert!(fixture.context.validate_at(EXPIRES_AT_MS + 60_000).is_ok());
    assert!(fixture.context.validate_at(EXPIRES_AT_MS + 60_001).is_err());
    assert_eq!(
        hex::encode(fixture.context.digest().unwrap().into_bytes()),
        "fdc7deffdc60f3ebee3796ab40a21bb8d9aedb3caeb0df1118a9c5665ac5f7d6"
    );
}
