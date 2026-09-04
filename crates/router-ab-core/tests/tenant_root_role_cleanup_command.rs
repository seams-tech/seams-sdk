//! Authorized pending- and retired-cleanup contract.
//!
//! Cleanup destroys a role's share, so the authorization has to be narrower
//! than anything else in R120: one role, one exact row state, once.

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

fn epoch(value: u64) -> TenantRootShareEpoch {
    TenantRootShareEpoch::new(value).expect("epoch")
}

fn pending_target_with(
    identity: [u8; 32],
    lineage: [u8; 16],
    role: TwoPartyDeriverRole,
    target_epoch: TenantRootShareEpoch,
    expected_row_revision: i64,
    session: [u8; 16],
    ceremony_nonce: [u8; 32],
    evidence: [u8; 32],
) -> TenantRootRoleCleanupTargetV1 {
    TenantRootRoleCleanupTargetV1::Pending {
        identity_digest: TenantRootIdentityDigestV1::from_bytes(identity),
        custody_lineage: TenantRootCustodyLineageId::from_bytes(lineage).expect("lineage"),
        role,
        epoch: target_epoch,
        expected_row_revision,
        session_id: TenantRootCeremonySessionIdV1::from_bytes(session).expect("session"),
        ceremony_nonce: TenantRootCeremonyNonceV1::from_bytes(ceremony_nonce)
            .expect("ceremony nonce"),
        installation_evidence_digest: TenantRootProtocolDigestV1::from_bytes(evidence)
            .expect("evidence digest"),
    }
}

fn pending_target(role: TwoPartyDeriverRole, revision: i64) -> TenantRootRoleCleanupTargetV1 {
    pending_target_with(
        [0x11; 32],
        [0x22; 16],
        role,
        TenantRootShareEpoch::INITIAL,
        revision,
        [0x33; 16],
        [0x44; 32],
        [0x55; 32],
    )
}

fn retired_target_with(
    identity: [u8; 32],
    lineage: [u8; 16],
    role: TwoPartyDeriverRole,
    retired_epoch: TenantRootShareEpoch,
    expected_retired_revision: i64,
    expected_active_epoch: TenantRootShareEpoch,
    expected_active_revision: i64,
) -> TenantRootRoleCleanupTargetV1 {
    TenantRootRoleCleanupTargetV1::Retired {
        identity_digest: TenantRootIdentityDigestV1::from_bytes(identity),
        custody_lineage: TenantRootCustodyLineageId::from_bytes(lineage).expect("lineage"),
        role,
        retired_epoch,
        expected_retired_revision,
        expected_active_epoch,
        expected_active_revision,
    }
}

fn retired_target(
    role: TwoPartyDeriverRole,
    retired_revision: i64,
    active_epoch: TenantRootShareEpoch,
    active_revision: i64,
) -> TenantRootRoleCleanupTargetV1 {
    retired_target_with(
        [0x11; 32],
        [0x22; 16],
        role,
        TenantRootShareEpoch::INITIAL,
        retired_revision,
        active_epoch,
        active_revision,
    )
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
fn a_pending_cleanup_command_round_trips_and_authorizes_exactly_one_row() {
    let expected = pending_target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&expected, &ISSUER_SEED);
    let bytes = signed.canonical_bytes().expect("canonical");
    let decoded = TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&bytes).expect("decoded");
    assert_eq!(decoded, signed);
    assert_eq!(decoded.operation(), "cleanup_pending_share");

    let verified = decoded
        .verify(
            &expected,
            TwoPartyDeriverRole::DeriverB,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .expect("verified");
    assert_eq!(verified.target(), &expected);
    assert_eq!(verified.role(), TwoPartyDeriverRole::DeriverB);
    assert_eq!(verified.epoch(), TenantRootShareEpoch::INITIAL);
    assert_eq!(verified.expected_row_revision(), 1);
    assert!(verified.require_fresh(ISSUED_AT_MS + 1).is_ok());
    assert!(verified.require_fresh(ISSUED_AT_MS).is_err());
    assert!(verified.require_fresh(EXPIRES_AT_MS).is_err());
}

#[test]
fn a_retired_cleanup_command_round_trips_and_binds_the_successor() {
    let expected = retired_target(TwoPartyDeriverRole::DeriverB, 4, epoch(2), 3);
    let signed = sign(&expected, &ISSUER_SEED);
    let bytes = signed.canonical_bytes().expect("canonical");
    let decoded = TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&bytes).expect("decoded");
    assert_eq!(decoded, signed);
    assert_eq!(decoded.operation(), "cleanup_retired_share");
    assert_eq!(decoded.claimed_target(), expected);

    let verified = decoded
        .verify(
            &expected,
            TwoPartyDeriverRole::DeriverB,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .expect("verified");
    assert_eq!(verified.target(), &expected);
    assert_eq!(verified.epoch(), TenantRootShareEpoch::INITIAL);
    assert_eq!(verified.expected_row_revision(), 4);
    assert_eq!(verified.operation(), "cleanup_retired_share");
}

#[test]
fn a_retired_cleanup_command_requires_adjacent_epoch_and_positive_revisions() {
    let non_adjacent = retired_target(TwoPartyDeriverRole::DeriverB, 4, epoch(3), 3);
    assert!(TenantRootRoleCleanupCommandV1::sign(
        &non_adjacent,
        authority(),
        TenantRootCeremonyNonceV1::from_bytes([0x66; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        ISSUER_KEY_ID,
        &ISSUER_SEED,
    )
    .is_err());

    for (retired_revision, active_revision) in [(0, 3), (4, 0)] {
        let target = retired_target(
            TwoPartyDeriverRole::DeriverB,
            retired_revision,
            epoch(2),
            active_revision,
        );
        assert!(TenantRootRoleCleanupCommandV1::sign(
            &target,
            authority(),
            TenantRootCeremonyNonceV1::from_bytes([0x66; 32]).expect("nonce"),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            ISSUER_KEY_ID,
            &ISSUER_SEED,
        )
        .is_err());
    }
}

/// The row must not have moved. A revision bump means a different row state,
/// and an authorization for the old one must not destroy the new one.
#[test]
fn a_pending_cleanup_command_is_refused_after_the_row_revision_moves() {
    let authorized = pending_target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&authorized, &ISSUER_SEED);
    let moved = pending_target(TwoPartyDeriverRole::DeriverB, 2);
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
    let b_target = pending_target(TwoPartyDeriverRole::DeriverB, 1);
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
    let mismatched = pending_target(TwoPartyDeriverRole::DeriverA, 1);
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
fn a_pending_cleanup_command_binds_every_row_coordinate() {
    let authorized = pending_target(TwoPartyDeriverRole::DeriverB, 1);
    let signed = sign(&authorized, &ISSUER_SEED);
    let key = verifying_key(&ISSUER_SEED);

    let foreign_identity = pending_target_with(
        [0x99; 32],
        [0x22; 16],
        TwoPartyDeriverRole::DeriverB,
        TenantRootShareEpoch::INITIAL,
        1,
        [0x33; 16],
        [0x44; 32],
        [0x55; 32],
    );
    let foreign_lineage = pending_target_with(
        [0x11; 32],
        [0x98; 16],
        TwoPartyDeriverRole::DeriverB,
        TenantRootShareEpoch::INITIAL,
        1,
        [0x33; 16],
        [0x44; 32],
        [0x55; 32],
    );
    let foreign_session = pending_target_with(
        [0x11; 32],
        [0x22; 16],
        TwoPartyDeriverRole::DeriverB,
        TenantRootShareEpoch::INITIAL,
        1,
        [0x97; 16],
        [0x44; 32],
        [0x55; 32],
    );
    let foreign_ceremony_nonce = pending_target_with(
        [0x11; 32],
        [0x22; 16],
        TwoPartyDeriverRole::DeriverB,
        TenantRootShareEpoch::INITIAL,
        1,
        [0x33; 16],
        [0x96; 32],
        [0x55; 32],
    );
    let foreign_evidence = pending_target_with(
        [0x11; 32],
        [0x22; 16],
        TwoPartyDeriverRole::DeriverB,
        TenantRootShareEpoch::INITIAL,
        1,
        [0x33; 16],
        [0x44; 32],
        [0x95; 32],
    );

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
fn a_retired_cleanup_command_binds_both_cas_revisions_and_successor_epoch() {
    let authorized = retired_target(TwoPartyDeriverRole::DeriverB, 4, epoch(2), 3);
    let signed = sign(&authorized, &ISSUER_SEED);
    let key = verifying_key(&ISSUER_SEED);

    let candidates = [
        (
            "identity",
            retired_target_with(
                [0x99; 32],
                [0x22; 16],
                TwoPartyDeriverRole::DeriverB,
                TenantRootShareEpoch::INITIAL,
                4,
                epoch(2),
                3,
            ),
        ),
        (
            "lineage",
            retired_target_with(
                [0x11; 32],
                [0x98; 16],
                TwoPartyDeriverRole::DeriverB,
                TenantRootShareEpoch::INITIAL,
                4,
                epoch(2),
                3,
            ),
        ),
        (
            "retired revision",
            retired_target(TwoPartyDeriverRole::DeriverB, 5, epoch(2), 3),
        ),
        (
            "successor epoch",
            retired_target_with(
                [0x11; 32],
                [0x22; 16],
                TwoPartyDeriverRole::DeriverB,
                TenantRootShareEpoch::INITIAL,
                4,
                epoch(3),
                3,
            ),
        ),
        (
            "successor revision",
            retired_target(TwoPartyDeriverRole::DeriverB, 4, epoch(2), 4),
        ),
    ];

    for (label, candidate) in candidates {
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
fn pending_and_retired_authorizations_are_disjoint() {
    let pending = pending_target(TwoPartyDeriverRole::DeriverB, 1);
    let retired = retired_target(TwoPartyDeriverRole::DeriverB, 4, epoch(2), 3);
    let pending_command = sign(&pending, &ISSUER_SEED);
    let retired_command = sign(&retired, &ISSUER_SEED);

    assert!(pending_command
        .verify(
            &retired,
            TwoPartyDeriverRole::DeriverB,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .is_err());
    assert!(retired_command
        .verify(
            &pending,
            TwoPartyDeriverRole::DeriverB,
            authority(),
            ISSUER_KEY_ID,
            &verifying_key(&ISSUER_SEED),
        )
        .is_err());
    assert_ne!(
        pending_command.canonical_bytes().expect("pending bytes"),
        retired_command.canonical_bytes().expect("retired bytes")
    );
}

#[test]
fn authority_and_issuer_substitutions_fail_closed() {
    let authorized = pending_target(TwoPartyDeriverRole::DeriverB, 1);
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
    let authorized = pending_target(TwoPartyDeriverRole::DeriverB, 1);
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
    let zero_revision = pending_target(TwoPartyDeriverRole::DeriverB, 0);
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
fn every_pending_cleanup_wire_mutation_fails_closed() {
    let authorized = pending_target(TwoPartyDeriverRole::DeriverB, 1);
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
                .and_then(|command| {
                    command
                        .verify(
                            &authorized,
                            TwoPartyDeriverRole::DeriverB,
                            authority(),
                            ISSUER_KEY_ID,
                            &key,
                        )
                        .ok()
                })
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
