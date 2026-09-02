//! Authorized pending-cleanup contract.
//!
//! Cleanup destroys a role's share, so the authorization has to be narrower
//! than anything else in R120: one role, one row, one revision, once.

use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootProtocolDigestV1, TenantRootRoleCleanupCommandV1, TenantRootRoleCleanupTargetV1,
    TenantRootShareEpoch, TENANT_ROOT_MAX_LIFETIME_MS_V1,
    TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1,
};
use threshold_prf::TwoPartyDeriverRole;

const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const ISSUER_SEED: [u8; 32] = [0x81; 32];
const OTHER_SEED: [u8; 32] = [0x82; 32];
const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;

fn verifying_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn authority() -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32])
}

fn target(role: TwoPartyDeriverRole, revision: i64) -> TenantRootRoleCleanupTargetV1 {
    TenantRootRoleCleanupTargetV1 {
        identity_digest: TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
        custody_lineage: TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        role,
        epoch: TenantRootShareEpoch::INITIAL,
        expected_row_revision: revision,
        session_id: TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).expect("session"),
        ceremony_nonce: TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).expect("ceremony nonce"),
        installation_evidence_digest: TenantRootProtocolDigestV1::from_bytes([0x55; 32])
            .expect("evidence digest"),
    }
}

fn sign(target: &TenantRootRoleCleanupTargetV1, seed: &[u8; 32]) -> TenantRootRoleCleanupCommandV1 {
    TenantRootRoleCleanupCommandV1::sign(
        target,
        authority(),
        TenantRootCeremonyNonceV1::from_bytes([0x66; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        ISSUER_KEY_ID,
        seed,
    )
    .expect("signed cleanup command")
}

#[test]
fn a_cleanup_command_round_trips_and_authorizes_exactly_one_row() {
    let expected = target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&expected, &ISSUER_SEED);
    let bytes = signed.canonical_bytes().expect("canonical");
    let decoded = TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&bytes).expect("decoded");
    assert_eq!(decoded, signed);

    let verified = decoded
        .verify(
            &expected,
            TwoPartyDeriverRole::DeriverB,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .expect("verified");
    assert_eq!(verified.role(), TwoPartyDeriverRole::DeriverB);
    assert_eq!(verified.epoch(), TenantRootShareEpoch::INITIAL);
    assert_eq!(verified.expected_row_revision(), 1);
    assert!(verified.require_fresh(ISSUED_AT_MS + 1).is_ok());
    assert!(verified.require_fresh(ISSUED_AT_MS).is_err());
    assert!(verified.require_fresh(EXPIRES_AT_MS).is_err());
}

/// The row must not have moved. A revision bump means a different row state,
/// and an authorization for the old one must not destroy the new one.
#[test]
fn a_cleanup_command_is_refused_after_the_row_revision_moves() {
    let authorized = target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&authorized, &ISSUER_SEED);
    let moved = target(TwoPartyDeriverRole::DeriverB, 2);
    assert_eq!(
        signed
            .verify(
                &moved,
                TwoPartyDeriverRole::DeriverB,
                authority(),
                ISSUER_KEY_ID,
                &verifying_key(&ISSUER_SEED),
            )
            .expect_err("revision moved")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

/// A role may only clean its own row, and the expected role comes from the
/// verifier, never from the command.
#[test]
fn a_role_cannot_clean_its_peers_row() {
    let b_target = target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&b_target, &ISSUER_SEED);
    assert!(signed
        .verify(
            &b_target,
            TwoPartyDeriverRole::DeriverA,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .is_err());

    // A target claiming the other role is refused even under that role.
    let mismatched = target(TwoPartyDeriverRole::DeriverA, 1);
    assert!(signed
        .verify(
            &mismatched,
            TwoPartyDeriverRole::DeriverA,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .is_err());
}

#[test]
fn a_cleanup_command_binds_every_row_coordinate() {
    let authorized = target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&authorized, &ISSUER_SEED);
    let key = verifying_key(&ISSUER_SEED);

    let mut foreign_identity = authorized.clone();
    foreign_identity.identity_digest = TenantRootIdentityDigestV1::from_bytes([0x99; 32]);
    let mut foreign_lineage = authorized.clone();
    foreign_lineage.custody_lineage =
        TenantRootCustodyLineageId::from_bytes([0x98; 16]).expect("lineage");
    let mut foreign_session = authorized.clone();
    foreign_session.session_id =
        TenantRootCeremonySessionIdV1::from_bytes([0x97; 16]).expect("session");
    let mut foreign_ceremony_nonce = authorized.clone();
    foreign_ceremony_nonce.ceremony_nonce =
        TenantRootCeremonyNonceV1::from_bytes([0x96; 32]).expect("nonce");
    let mut foreign_evidence = authorized.clone();
    foreign_evidence.installation_evidence_digest =
        TenantRootProtocolDigestV1::from_bytes([0x95; 32]).expect("digest");

    for (label, candidate) in [
        ("identity", foreign_identity),
        ("lineage", foreign_lineage),
        ("session", foreign_session),
        ("ceremony nonce", foreign_ceremony_nonce),
        ("evidence digest", foreign_evidence),
    ] {
        assert!(
            signed
                .verify(
                    &candidate,
                    TwoPartyDeriverRole::DeriverB,
                    authority(),
                    ISSUER_KEY_ID,
                    &key,
                )
                .is_err(),
            "{label} must be bound"
        );
    }
}

#[test]
fn authority_and_issuer_substitutions_fail_closed() {
    let authorized = target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&authorized, &ISSUER_SEED);

    // A different control-plane authority.
    assert!(signed
        .verify(
            &authorized,
            TwoPartyDeriverRole::DeriverB,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x45; 32]),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .is_err());

    // A trusted key that did not sign it.
    assert_eq!(
        signed
            .verify(
                &authorized,
                TwoPartyDeriverRole::DeriverB,
                authority(),
                ISSUER_KEY_ID,
                &verifying_key(&OTHER_SEED),
            )
            .expect_err("untrusted issuer")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    // A verifier expecting a different issuer key id.
    assert!(signed
        .verify(
            &authorized,
            TwoPartyDeriverRole::DeriverB,
            authority(),
            "control-plane-issuer-v2",
            &verifying_key(&ISSUER_SEED),
        )
        .is_err());
}

#[test]
fn the_authorized_window_is_bounded() {
    let authorized = target(TwoPartyDeriverRole::DeriverB, 1);
    assert!(TenantRootRoleCleanupCommandV1::sign(
        &authorized,
        authority(),
        TenantRootCeremonyNonceV1::from_bytes([0x66; 32]).expect("nonce"),
        ISSUED_AT_MS,
        ISSUED_AT_MS + TENANT_ROOT_MAX_LIFETIME_MS_V1 + 1,
        ISSUER_KEY_ID,
        &ISSUER_SEED,
    )
    .is_err());
    // A non-positive revision is not a row.
    let mut zero_revision = authorized.clone();
    zero_revision.expected_row_revision = 0;
    assert!(TenantRootRoleCleanupCommandV1::sign(
        &zero_revision,
        authority(),
        TenantRootCeremonyNonceV1::from_bytes([0x66; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        ISSUER_KEY_ID,
        &ISSUER_SEED,
    )
    .is_err());
}

#[test]
fn every_cleanup_wire_mutation_fails_closed() {
    let authorized = target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&authorized, &ISSUER_SEED);
    let bytes = signed.canonical_bytes().expect("canonical");
    let key = verifying_key(&ISSUER_SEED);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&trailing).is_err());

    for end in 0..bytes.len() {
        assert!(
            TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&bytes[..end]).is_err(),
            "truncation at {end} must fail closed"
        );
    }

    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 0xff;
        assert!(
            TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&mutated)
                .ok()
                .and_then(|command| command
                    .verify(
                        &authorized,
                        TwoPartyDeriverRole::DeriverB,
                        authority(),
                        ISSUER_KEY_ID,
                        &key,
                    )
                    .ok())
                .is_none(),
            "mutated byte {index} must fail closed"
        );
    }

    assert!(TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&[]).is_err());
    assert!(
        TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&vec![
            0u8;
            TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}
