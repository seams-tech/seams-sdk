use std::ops::Range;

use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCommandScopeV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCreationJournalV1, TenantRootIdentityV1,
    TenantRootRoleCreationCommandV1, TenantRootShareEpoch, VerifiedTenantRootRoleCreationCommandV1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_EPOCH_V1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1, TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1,
};
use threshold_prf::TwoPartyDeriverRole;

const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_KEY_BYTES)
}

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("fixed tenant-root identity")
}

fn context(session_seed: u8, nonce_seed: u8) -> TenantRootCeremonyContextV1 {
    let identity = identity();
    TenantRootCeremonyContextV1::new(
        identity.digest().expect("identity digest"),
        lineage(0x22),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session id"),
        TenantRootCeremonyNonceV1::from_bytes([nonce_seed; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("fixed creation context")
}

fn lineage(seed: u8) -> router_ab_core::TenantRootCustodyLineageId {
    router_ab_core::TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("lineage")
}

fn journal(context: &TenantRootCeremonyContextV1) -> TenantRootCreationJournalV1 {
    TenantRootCreationJournalV1::started(identity(), lineage(0x22), context.clone())
        .expect("fixed Started journal")
}

fn command(
    role: TwoPartyDeriverRole,
    context: &TenantRootCeremonyContextV1,
) -> TenantRootRoleCreationCommandV1 {
    TenantRootRoleCreationCommandV1::sign(
        &journal(context),
        context,
        role,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .expect("signed role creation command")
}

fn verify(
    command: &TenantRootRoleCreationCommandV1,
    role: TwoPartyDeriverRole,
    context: &TenantRootCeremonyContextV1,
) -> VerifiedTenantRootRoleCreationCommandV1 {
    command
        .verify(
            &journal(context),
            context,
            role,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUER_KEY_ID,
            &signing_key().verifying_key().to_bytes(),
        )
        .expect("verified role creation command")
}

#[test]
fn sign_decode_verify_round_trip_projects_only_the_authorization_scope() {
    let context = context(0x11, 0x33);
    let raw = command(TwoPartyDeriverRole::DeriverA, &context);
    let bytes = raw.canonical_bytes().expect("canonical command");
    let decoded =
        TenantRootRoleCreationCommandV1::decode_canonical_bytes(&bytes).expect("decoded command");
    assert_eq!(decoded, raw);
    assert_eq!(
        decoded.operation(),
        TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1
    );
    assert_eq!(decoded.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(
        decoded.epoch(),
        TenantRootShareEpoch::new(TENANT_ROOT_ROLE_CREATION_COMMAND_EPOCH_V1).unwrap()
    );
    assert_eq!(
        decoded.expected_control_plane_revision(),
        TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1
    );
    assert_eq!(decoded.session_id(), context.session_id());
    assert_eq!(decoded.nonce(), context.nonce());
    assert_eq!(decoded.creation_context_digest(), context.digest().unwrap());
    assert_eq!(
        decoded.started_journal_digest(),
        journal(&context).digest().unwrap()
    );
    assert_eq!(decoded.issued_at_ms(), ISSUED_AT_MS + 1);
    assert_eq!(decoded.expires_at_ms(), EXPIRES_AT_MS - 1);
    assert_eq!(decoded.issuer_key_id(), ISSUER_KEY_ID);

    let verified = verify(&decoded, TwoPartyDeriverRole::DeriverA, &context);
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.digest(), decoded.digest().unwrap());
    assert_eq!(
        verified.operation(),
        TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1
    );
    assert_eq!(verified.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(verified.identity_digest(), identity().digest().unwrap());
    assert_eq!(verified.custody_lineage(), lineage(0x22));
    assert_eq!(
        verified.started_journal_digest(),
        decoded.started_journal_digest()
    );
    assert_eq!(
        verified.creation_context_digest(),
        decoded.creation_context_digest()
    );
    assert_eq!(
        verified.authority_id(),
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32])
    );
    assert_eq!(verified.issuer_key_id(), ISSUER_KEY_ID);

    let scope: TenantRootCommandScopeV1 = verified.scope();
    assert_eq!(scope.key().identity_digest(), identity().digest().unwrap());
    assert_eq!(scope.key().custody_lineage(), lineage(0x22));
    assert_eq!(scope.key().session_id(), context.session_id());
    assert_eq!(scope.key().nonce(), context.nonce());
    assert_eq!(scope.key().role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(scope.epoch(), TenantRootShareEpoch::INITIAL);
    assert_eq!(scope.expected_control_plane_revision(), 1);

    assert!(verified.require_fresh(verified.issued_at_ms()).is_ok());
    assert!(verified.require_fresh(verified.expires_at_ms()).is_ok());
    assert!(verified.require_fresh(verified.issued_at_ms() - 1).is_err());
    assert!(verified
        .require_fresh(verified.expires_at_ms() + 1)
        .is_err());
}

#[test]
fn role_a_and_role_b_are_exactly_distinct() {
    let context = context(0x11, 0x33);
    let a = command(TwoPartyDeriverRole::DeriverA, &context);
    let b = command(TwoPartyDeriverRole::DeriverB, &context);
    assert_ne!(
        a.canonical_bytes().unwrap(),
        b.canonical_bytes().unwrap(),
        "role substitution must change the signed command"
    );

    let verified_a = verify(&a, TwoPartyDeriverRole::DeriverA, &context);
    let verified_b = verify(&b, TwoPartyDeriverRole::DeriverB, &context);
    assert_eq!(
        verified_a.scope().key().role(),
        TwoPartyDeriverRole::DeriverA
    );
    assert_eq!(
        verified_b.scope().key().role(),
        TwoPartyDeriverRole::DeriverB
    );
    assert!(a
        .verify(
            &journal(&context),
            &context,
            TwoPartyDeriverRole::DeriverB,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUER_KEY_ID,
            &signing_key().verifying_key().to_bytes(),
        )
        .is_err());
}

#[test]
fn wrong_signature_key_and_issuer_key_id_fail_closed() {
    let context = context(0x11, 0x33);
    let raw = command(TwoPartyDeriverRole::DeriverA, &context);
    let wrong_key = SigningKey::from_bytes(&[0x42; 32]);
    assert_eq!(
        raw.verify(
            &journal(&context),
            &context,
            TwoPartyDeriverRole::DeriverA,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUER_KEY_ID,
            &wrong_key.verifying_key().to_bytes(),
        )
        .expect_err("wrong issuer key")
        .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
    assert_eq!(
        raw.verify(
            &journal(&context),
            &context,
            TwoPartyDeriverRole::DeriverA,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            "another-control-plane-issuer-v1",
            &signing_key().verifying_key().to_bytes(),
        )
        .expect_err("issuer key id substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn journal_context_identity_and_authority_substitutions_fail_closed() {
    let base_context = context(0x11, 0x33);
    let raw = command(TwoPartyDeriverRole::DeriverA, &base_context);
    let changed_context = context(0x12, 0x33);
    let changed_journal = journal(&changed_context);
    assert!(TenantRootRoleCreationCommandV1::sign(
        &journal(&base_context),
        &changed_context,
        TwoPartyDeriverRole::DeriverA,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());

    for (label, expected_journal, expected_context, authority) in [
        (
            "changed journal",
            &changed_journal,
            &changed_context,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        ),
        (
            "changed context",
            &journal(&base_context),
            &changed_context,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        ),
        (
            "changed authority",
            &journal(&base_context),
            &base_context,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x45; 32]),
        ),
    ] {
        assert!(
            raw.verify(
                expected_journal,
                expected_context,
                TwoPartyDeriverRole::DeriverA,
                authority,
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .is_err(),
            "{label} must fail"
        );
    }
}

#[test]
fn every_wire_binding_mutation_fails_closed() {
    let context = context(0x11, 0x33);
    let raw = command(TwoPartyDeriverRole::DeriverA, &context);
    let bytes = raw.canonical_bytes().unwrap();
    let fields = field_ranges(&bytes);

    for (index, marker) in [
        (2, 0x12),  // identity
        (3, 0x23),  // lineage
        (4, 0x34),  // Started journal digest
        (5, 0x45),  // creation context digest
        (10, 0x56), // session
        (11, 0x67), // nonce
        (12, 0x78), // authority
        (13, 0x89), // issue time
        (14, 0x9a), // expiry
        (16, 0xab), // issuer key id
    ] {
        let tampered = replace_field(&bytes, index, &vec![marker; fields[index].len()]);
        if let Ok(decoded) = TenantRootRoleCreationCommandV1::decode_canonical_bytes(&tampered) {
            assert!(
                decoded
                    .verify(
                        &journal(&context),
                        &context,
                        TwoPartyDeriverRole::DeriverA,
                        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
                        ISSUER_KEY_ID,
                        &signing_key().verifying_key().to_bytes(),
                    )
                    .is_err(),
                "field {index} substitution must fail verification"
            );
        }
    }

    let mut signature = bytes.clone();
    signature[fields[17].start] ^= 1;
    let decoded_signature = TenantRootRoleCreationCommandV1::decode_canonical_bytes(&signature)
        .expect("signature tamper remains structurally valid");
    assert_eq!(
        decoded_signature
            .verify(
                &journal(&context),
                &context,
                TwoPartyDeriverRole::DeriverA,
                TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("signature substitution")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let payload = replace_field(&bytes, 15, &[0x01; 32]);
    assert!(
        TenantRootRoleCreationCommandV1::decode_canonical_bytes(&payload).is_err(),
        "derived authorization payload digest substitution must fail decoding"
    );

    let epoch = replace_field(&bytes, 8, &2_u64.to_be_bytes());
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&epoch).is_err());
    let revision = replace_field(&bytes, 9, &2_u64.to_be_bytes());
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&revision).is_err());
    let role_label = replace_field(&bytes, 6, b"deriver_x");
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&role_label).is_err());
    let role_share = replace_field(&bytes, 7, &2_u16.to_be_bytes());
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&role_share).is_err());

    let mut domain = bytes.clone();
    domain[fields[0].start] ^= 1;
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&domain).is_err());
    let mut operation = bytes.clone();
    operation[fields[1].start] = b'x';
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&operation).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&trailing).is_err());
    assert!(
        TenantRootRoleCreationCommandV1::decode_canonical_bytes(&bytes[..bytes.len() - 1]).is_err()
    );
    assert!(TenantRootRoleCreationCommandV1::decode_canonical_bytes(&[]).is_err());
    assert!(
        TenantRootRoleCreationCommandV1::decode_canonical_bytes(&vec![
            0_u8;
            TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}

#[test]
fn signing_requires_command_window_inside_creation_ceremony_window() {
    let context = context(0x11, 0x33);
    let journal = journal(&context);
    let authority = TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]);
    assert!(TenantRootRoleCreationCommandV1::sign(
        &journal,
        &context,
        TwoPartyDeriverRole::DeriverA,
        authority,
        ISSUED_AT_MS - 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());
    assert!(TenantRootRoleCreationCommandV1::sign(
        &journal,
        &context,
        TwoPartyDeriverRole::DeriverA,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS + 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());
}

fn field_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let start = offset + 4;
        ranges.push(start..start + length);
        offset = start + length;
    }
    assert_eq!(offset, bytes.len());
    ranges
}

fn replace_field(bytes: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
    let range = field_ranges(bytes)[index].clone();
    assert_eq!(range.len(), replacement.len());
    let mut result = bytes.to_vec();
    result[range].copy_from_slice(replacement);
    result
}
