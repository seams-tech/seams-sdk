use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    PendingTenantRootInitialRoleAttemptV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootControlPlaneAuthorityIdV1,
    TenantRootCreationJournalV1, TenantRootCustodyLineageId, TenantRootIdentityV1,
    TenantRootRoleCreationCommandV1, TenantRootSignedCreationCommitmentV1, TwoPartyDeriverRole,
    VerifiedTenantRootCreationCommitmentPairV1, VerifiedTenantRootCreationCommitmentV1,
    VerifiedTenantRootRoleCreationCommandV1,
};
use threshold_prf::SigningRootShareCommitment;

const ISSUER_KEY_BYTES: [u8; 32] = [0x41; 32];
const ISSUER_KEY_ID: &str = "tenant-root-issuer-v1";
const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("fixed tenant-root identity")
}

fn context(session_seed: u8, nonce_seed: u8) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity().digest().expect("identity digest"),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session"),
        TenantRootCeremonyNonceV1::from_bytes([nonce_seed; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("fixed creation context")
}

fn journal(context: &TenantRootCeremonyContextV1) -> TenantRootCreationJournalV1 {
    TenantRootCreationJournalV1::started(identity(), context.custody_lineage(), context.clone())
        .expect("fixed Started journal")
}

fn role_key_bytes(role: TwoPartyDeriverRole) -> [u8; 32] {
    match role {
        TwoPartyDeriverRole::DeriverA => [0x51; 32],
        TwoPartyDeriverRole::DeriverB => [0x61; 32],
    }
}

fn role_verifying_key_bytes(role: TwoPartyDeriverRole) -> [u8; 32] {
    SigningKey::from_bytes(&role_key_bytes(role))
        .verifying_key()
        .to_bytes()
}

fn command(
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
) -> VerifiedTenantRootRoleCreationCommandV1 {
    let command = TenantRootRoleCreationCommandV1::sign(
        &journal(context),
        context,
        role,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect("signed role creation command");
    let issuer_key = SigningKey::from_bytes(&ISSUER_KEY_BYTES);
    command
        .verify(
            &journal(context),
            context,
            role,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUER_KEY_ID,
            issuer_key.verifying_key().as_bytes(),
        )
        .expect("verified role creation command")
}

fn pending(
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    now_ms: u64,
    rng_seed: u8,
) -> PendingTenantRootInitialRoleAttemptV1 {
    let mut rng = ChaCha20Rng::from_seed([rng_seed; 32]);
    PendingTenantRootInitialRoleAttemptV1::new(
        command(context, role),
        context.clone(),
        &role_key_bytes(role),
        &role_verifying_key_bytes(role),
        now_ms,
        &mut rng,
    )
    .expect("pending initial role attempt")
}

fn verified_commitment(
    pending: &PendingTenantRootInitialRoleAttemptV1,
) -> VerifiedTenantRootCreationCommitmentV1 {
    let role = pending.role();
    let context = pending.commitment().context();
    let key = SigningKey::from_bytes(&role_key_bytes(role));
    TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
        pending.commitment_bytes(),
        context,
        role,
        context.signing_key_id(role),
        key.verifying_key().as_bytes(),
    )
    .expect("verified commitment wire")
}

fn pair(
    pending_a: &PendingTenantRootInitialRoleAttemptV1,
    pending_b: &PendingTenantRootInitialRoleAttemptV1,
) -> VerifiedTenantRootCreationCommitmentPairV1 {
    VerifiedTenantRootCreationCommitmentPairV1::new(
        verified_commitment(pending_a),
        verified_commitment(pending_b),
    )
    .expect("verified commitment pair")
}

fn proof_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

#[test]
fn both_roles_finalize_against_the_exact_commitment_pair() {
    let ceremony_context = context(0x11, 0x33);
    let pending_a = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        ISSUED_AT_MS + 10,
        0x51,
    );
    let pending_b = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverB,
        ISSUED_AT_MS + 10,
        0x61,
    );
    assert_eq!(
        pending_a.commitment_bytes(),
        pending_a.commitment().canonical_bytes()
    );
    assert_eq!(
        pending_b.commitment_bytes(),
        pending_b.commitment().canonical_bytes()
    );

    let pair_for_a = pair(&pending_a, &pending_b);
    let pair_for_b = pair(&pending_a, &pending_b);
    let mut proof_rng_a = proof_rng(0x71);
    let mut proof_rng_b = proof_rng(0x81);
    let completed_a = pending_a
        .finalize(
            pair_for_a,
            &role_key_bytes(TwoPartyDeriverRole::DeriverA),
            &mut proof_rng_a,
        )
        .expect("Deriver A initial attempt");
    let completed_b = pending_b
        .finalize(
            pair_for_b,
            &role_key_bytes(TwoPartyDeriverRole::DeriverB),
            &mut proof_rng_b,
        )
        .expect("Deriver B initial attempt");

    let (command_a, share_a, evidence_a) = completed_a.into_parts();
    let (command_b, share_b, evidence_b) = completed_b.into_parts();
    assert_eq!(command_a.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(command_b.role(), TwoPartyDeriverRole::DeriverB);
    let share_a = share_a.to_share().expect("Deriver A share wire");
    let share_b = share_b.to_share().expect("Deriver B share wire");
    assert_eq!(share_a.id(), TwoPartyDeriverRole::DeriverA.share_id());
    assert_eq!(share_b.id(), TwoPartyDeriverRole::DeriverB.share_id());
    assert_ne!(
        SigningRootShareCommitment::from_share(&share_a),
        SigningRootShareCommitment::from_share(&share_b)
    );
    assert_eq!(
        evidence_a.evidence().transcript().context(),
        &ceremony_context
    );
    assert_eq!(
        evidence_b.evidence().transcript().context(),
        &ceremony_context
    );
    assert_eq!(
        evidence_a.evidence().transcript().commitment(),
        SigningRootShareCommitment::from_share(&share_a)
    );
    assert_eq!(
        evidence_b.evidence().transcript().commitment(),
        SigningRootShareCommitment::from_share(&share_b)
    );
    assert_eq!(
        evidence_a.evidence().transcript().peer_commitment(),
        evidence_b.evidence().transcript().commitment()
    );
    assert_eq!(
        evidence_b.evidence().transcript().peer_commitment(),
        evidence_a.evidence().transcript().commitment()
    );
    assert!(!evidence_a.canonical_bytes().is_empty());
    assert!(!evidence_b.canonical_bytes().is_empty());
}

#[test]
fn pending_attempt_rejects_context_and_role_key_substitution() {
    let original_context = context(0x21, 0x43);
    let changed_context = context(0x22, 0x44);
    let mut rng = proof_rng(0x91);
    let wrong_context = PendingTenantRootInitialRoleAttemptV1::new(
        command(&original_context, TwoPartyDeriverRole::DeriverA),
        changed_context,
        &role_key_bytes(TwoPartyDeriverRole::DeriverA),
        &role_verifying_key_bytes(TwoPartyDeriverRole::DeriverA),
        ISSUED_AT_MS + 10,
        &mut rng,
    );
    assert!(wrong_context.is_err());

    let mut rng = proof_rng(0x92);
    let wrong_role_key = PendingTenantRootInitialRoleAttemptV1::new(
        command(&original_context, TwoPartyDeriverRole::DeriverA),
        original_context,
        &role_key_bytes(TwoPartyDeriverRole::DeriverB),
        &role_verifying_key_bytes(TwoPartyDeriverRole::DeriverA),
        ISSUED_AT_MS + 10,
        &mut rng,
    );
    assert!(wrong_role_key.is_err());
}

#[test]
fn finalize_rejects_a_pair_with_a_changed_local_commitment_or_context() {
    let ceremony_context = context(0x31, 0x53);
    let pending_a = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        ISSUED_AT_MS + 10,
        0xa1,
    );
    let pending_b = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverB,
        ISSUED_AT_MS + 10,
        0xb1,
    );
    let changed_a = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        ISSUED_AT_MS + 10,
        0xa2,
    );
    assert_ne!(pending_a.commitment_bytes(), changed_a.commitment_bytes());
    let bad_pair = pair(&changed_a, &pending_b);
    let mut rng = proof_rng(0xc1);
    assert!(pending_a
        .finalize(
            bad_pair,
            &role_key_bytes(TwoPartyDeriverRole::DeriverA),
            &mut rng,
        )
        .is_err());

    let changed_context = context(0x32, 0x54);
    let pending_a = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        ISSUED_AT_MS + 10,
        0xa3,
    );
    let changed_a = pending(
        &changed_context,
        TwoPartyDeriverRole::DeriverA,
        ISSUED_AT_MS + 10,
        0xa4,
    );
    let changed_b = pending(
        &changed_context,
        TwoPartyDeriverRole::DeriverB,
        ISSUED_AT_MS + 10,
        0xb4,
    );
    let bad_pair = pair(&changed_a, &changed_b);
    let mut rng = proof_rng(0xc2);
    assert!(pending_a
        .finalize(
            bad_pair,
            &role_key_bytes(TwoPartyDeriverRole::DeriverA),
            &mut rng,
        )
        .is_err());
}

#[test]
fn pending_attempt_accepts_only_the_inclusive_command_freshness_endpoints() {
    let before_issued = context(0x41, 0x61);
    let command_before_issued = command(&before_issued, TwoPartyDeriverRole::DeriverA);
    let mut rng = proof_rng(0xd1);
    assert!(PendingTenantRootInitialRoleAttemptV1::new(
        command_before_issued,
        before_issued.clone(),
        &role_key_bytes(TwoPartyDeriverRole::DeriverA),
        &role_verifying_key_bytes(TwoPartyDeriverRole::DeriverA),
        ISSUED_AT_MS,
        &mut rng,
    )
    .is_err());

    let issued = context(0x42, 0x62);
    let command_at_issued = command(&issued, TwoPartyDeriverRole::DeriverA);
    let mut rng = proof_rng(0xd2);
    assert!(PendingTenantRootInitialRoleAttemptV1::new(
        command_at_issued,
        issued.clone(),
        &role_key_bytes(TwoPartyDeriverRole::DeriverA),
        &role_verifying_key_bytes(TwoPartyDeriverRole::DeriverA),
        ISSUED_AT_MS + 1,
        &mut rng,
    )
    .is_ok());

    let expires = context(0x43, 0x63);
    let command_at_expires = command(&expires, TwoPartyDeriverRole::DeriverA);
    let mut rng = proof_rng(0xd3);
    assert!(PendingTenantRootInitialRoleAttemptV1::new(
        command_at_expires,
        expires.clone(),
        &role_key_bytes(TwoPartyDeriverRole::DeriverA),
        &role_verifying_key_bytes(TwoPartyDeriverRole::DeriverA),
        EXPIRES_AT_MS - 1,
        &mut rng,
    )
    .is_ok());

    let after_expires = context(0x44, 0x64);
    let command_after_expires = command(&after_expires, TwoPartyDeriverRole::DeriverA);
    let mut rng = proof_rng(0xd4);
    assert!(PendingTenantRootInitialRoleAttemptV1::new(
        command_after_expires,
        after_expires,
        &role_key_bytes(TwoPartyDeriverRole::DeriverA),
        &role_verifying_key_bytes(TwoPartyDeriverRole::DeriverA),
        EXPIRES_AT_MS,
        &mut rng,
    )
    .is_err());
}

#[test]
fn completed_attempt_parts_are_consuming_and_keep_exact_verified_evidence_wire() {
    let ceremony_context = context(0x51, 0x71);
    let pending_a = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverA,
        ISSUED_AT_MS + 10,
        0xe1,
    );
    let pending_b = pending(
        &ceremony_context,
        TwoPartyDeriverRole::DeriverB,
        ISSUED_AT_MS + 10,
        0xf1,
    );
    let commitment_bytes = pending_a.commitment_bytes().to_vec();
    let commitment_context = pending_a.commitment().context().clone();
    let commitment_role = pending_a.role();
    let expected_commitment = pending_a.commitment().commitment();
    let commitment_pair = pair(&pending_a, &pending_b);
    let mut rng = proof_rng(0xe2);
    let completed = pending_a
        .finalize(
            commitment_pair,
            &role_key_bytes(TwoPartyDeriverRole::DeriverA),
            &mut rng,
        )
        .expect("completed initial role attempt");
    let (_command, _share_wire, evidence) = completed.into_parts();
    assert_eq!(
        TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
            &commitment_bytes,
            &commitment_context,
            commitment_role,
            commitment_context.signing_key_id(commitment_role),
            SigningKey::from_bytes(&role_key_bytes(commitment_role))
                .verifying_key()
                .as_bytes(),
        )
        .expect("commitment decodes from the exact retained wire")
        .commitment(),
        expected_commitment
    );
    assert_eq!(
        evidence.evidence().transcript().commitment(),
        expected_commitment
    );
    assert!(!evidence.canonical_bytes().is_empty());
}
