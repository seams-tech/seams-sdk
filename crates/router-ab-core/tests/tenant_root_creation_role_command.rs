use std::ops::Range;

use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCommandScopeV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCreationJournalV1, TenantRootIdentityV1,
    TenantRootRoleCreationCommandPackageV1, TenantRootRoleCreationCommandV1, TenantRootShareEpoch,
    VerifiedTenantRootRoleCreationCommandPackageV1, VerifiedTenantRootRoleCreationCommandV1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_EPOCH_V1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1, TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1,
    TENANT_ROOT_ROLE_CREATION_COMMAND_PACKAGE_MAX_BYTES_V1,
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

// --- Self-contained Router-attested role command package -------------------
//
// The package carries the exact signed command plus the public Started journal
// and ceremony context preimages, so a Deriver holding no Router-local state
// can reach a verified authorization through the existing command verifier.

const PACKAGE_DOMAIN: &[u8] = b"tenant_root_role_creation_command_package_v1";
const AUTHORITY_ID_BYTES: [u8; 32] = [0x44; 32];

fn authority() -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes(AUTHORITY_ID_BYTES)
}

fn issuer_verifying_key() -> [u8; 32] {
    signing_key().verifying_key().to_bytes()
}

fn package(
    role: TwoPartyDeriverRole,
    context: &TenantRootCeremonyContextV1,
) -> TenantRootRoleCreationCommandPackageV1 {
    TenantRootRoleCreationCommandPackageV1::new(journal(context), command(role, context))
        .expect("packaged role creation command")
}

/// Encodes a package wire from arbitrary parts, bypassing the constructor's
/// preimage check so substitution can be exercised at the decode boundary.
fn encode_package_parts(journal_bytes: &[u8], command_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in [PACKAGE_DOMAIN, journal_bytes, command_bytes] {
        bytes.extend_from_slice(
            &u32::try_from(field.len())
                .expect("field length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(field);
    }
    bytes
}

fn verify_package(
    package: &TenantRootRoleCreationCommandPackageV1,
    role: TwoPartyDeriverRole,
) -> Result<VerifiedTenantRootRoleCreationCommandPackageV1, RouterAbDerivationErrorCode> {
    package
        .verify(role, authority(), ISSUER_KEY_ID, &issuer_verifying_key())
        .map_err(|error| error.code())
}

#[test]
fn package_round_trip_verifies_through_the_existing_command_verifier() {
    let context = context(0x11, 0x33);
    for role in [TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB] {
        let packaged = package(role, &context);
        let bytes = packaged.canonical_bytes().expect("canonical package");
        let decoded = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&bytes)
            .expect("decoded package");
        assert_eq!(decoded, packaged);

        let verified = verify_package(&decoded, role).expect("verified package");
        assert_eq!(verified.command().role(), role);
        // The context is recovered from the journal, never carried separately.
        assert_eq!(verified.creation_context(), &context);
        assert_eq!(
            decoded.creation_context().expect("recovered context"),
            context
        );
        assert_eq!(
            verified.command().operation(),
            TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1
        );

        // The package projects exactly the scope the command verifier projects.
        let direct = verify(&command(role, &context), role, &context);
        assert_eq!(verified.into_command().scope(), direct.scope());
    }
}

#[test]
fn package_role_is_caller_supplied_and_cross_role_verification_fails_closed() {
    let context = context(0x11, 0x33);
    // A package carries no role authority of its own. Verifying a Deriver A
    // command as Deriver B must fail, otherwise a Deriver could replay its
    // peer's Router-signed command.
    for (packaged_role, expected_role) in [
        (TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB),
        (TwoPartyDeriverRole::DeriverB, TwoPartyDeriverRole::DeriverA),
    ] {
        let packaged = package(packaged_role, &context);
        assert_eq!(
            verify_package(&packaged, expected_role).err(),
            Some(RouterAbDerivationErrorCode::ReplayMismatch)
        );
        assert!(verify_package(&packaged, packaged_role).is_ok());
    }
}

#[test]
fn package_journal_substitution_fails_closed_at_decode() {
    let foreign = context(0x55, 0x66);
    let context = context(0x11, 0x33);
    let packaged = package(TwoPartyDeriverRole::DeriverA, &context);

    let journal_bytes = journal(&context).canonical_bytes().expect("journal bytes");
    let command_bytes = command(TwoPartyDeriverRole::DeriverA, &context)
        .canonical_bytes()
        .expect("command bytes");
    let foreign_journal_bytes = journal(&foreign).canonical_bytes().expect("journal bytes");
    let foreign_command_bytes = command(TwoPartyDeriverRole::DeriverA, &foreign)
        .canonical_bytes()
        .expect("command bytes");

    // Baseline: the honest pair decodes.
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&encode_package_parts(
            &journal_bytes,
            &command_bytes,
        ))
        .expect("honest package"),
        packaged
    );

    // A foreign ceremony's journal under this command.
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&encode_package_parts(
            &foreign_journal_bytes,
            &command_bytes,
        ))
        .expect_err("journal substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    // A foreign ceremony's command under this journal.
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&encode_package_parts(
            &journal_bytes,
            &foreign_command_bytes,
        ))
        .expect_err("command substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    // A coherent foreign ceremony pair still cannot be verified as this one:
    // it decodes, because journal and command agree with each other, but the
    // caller's expected authority still pins it.
    let foreign_package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(
        &encode_package_parts(&foreign_journal_bytes, &foreign_command_bytes),
    )
    .expect("coherent foreign package");
    assert_ne!(foreign_package, packaged);
    assert_eq!(
        foreign_package
            .creation_context()
            .expect("recovered foreign context"),
        foreign
    );
}

#[test]
fn package_context_is_bound_by_the_journal_and_cannot_be_supplied_separately() {
    let foreign = context(0x55, 0x66);
    let context = context(0x11, 0x33);
    let packaged = package(TwoPartyDeriverRole::DeriverA, &context);

    // The wire has exactly three fields: domain, journal, command. A fourth
    // field — a separately supplied context — is not accepted.
    let journal_bytes = journal(&context).canonical_bytes().expect("journal bytes");
    let command_bytes = command(TwoPartyDeriverRole::DeriverA, &context)
        .canonical_bytes()
        .expect("command bytes");
    let foreign_context_bytes = foreign.canonical_bytes().expect("context bytes");
    let mut four_fields = encode_package_parts(&journal_bytes, &command_bytes);
    four_fields.extend_from_slice(
        &u32::try_from(foreign_context_bytes.len())
            .unwrap()
            .to_be_bytes(),
    );
    four_fields.extend_from_slice(&foreign_context_bytes);
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&four_fields)
            .expect_err("trailing context field")
            .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    // The recovered context is exactly the one the journal was opened with.
    assert_eq!(
        packaged.creation_context().expect("recovered context"),
        context
    );
    assert_ne!(
        packaged.creation_context().expect("recovered context"),
        foreign
    );
}

#[test]
fn package_constructor_rejects_mismatched_preimages() {
    let foreign = context(0x55, 0x66);
    let context = context(0x11, 0x33);

    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::new(
            journal(&foreign),
            command(TwoPartyDeriverRole::DeriverA, &context),
        )
        .expect_err("foreign journal")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn package_authority_and_issuer_substitutions_fail_closed() {
    let context = context(0x11, 0x33);
    let packaged = package(TwoPartyDeriverRole::DeriverA, &context);

    // Wrong control-plane authority id.
    assert_eq!(
        packaged
            .verify(
                TwoPartyDeriverRole::DeriverA,
                TenantRootControlPlaneAuthorityIdV1::from_bytes([0x45; 32]),
                ISSUER_KEY_ID,
                &issuer_verifying_key(),
            )
            .expect_err("foreign authority")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    // Wrong issuer key id.
    assert!(packaged
        .verify(
            TwoPartyDeriverRole::DeriverA,
            authority(),
            "control-plane-issuer-v2",
            &issuer_verifying_key(),
        )
        .is_err());

    // Right issuer key id, untrusted verifying key.
    assert_eq!(
        packaged
            .verify(
                TwoPartyDeriverRole::DeriverA,
                authority(),
                ISSUER_KEY_ID,
                &SigningKey::from_bytes(&[0x42; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .expect_err("untrusted issuer key")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn package_freshness_is_preserved_through_the_package() {
    let context = context(0x11, 0x33);
    let packaged = package(TwoPartyDeriverRole::DeriverA, &context);
    let verified = verify_package(&packaged, TwoPartyDeriverRole::DeriverA)
        .expect("verified package")
        .into_command();

    assert!(verified.require_fresh(ISSUED_AT_MS + 1).is_ok());
    assert!(verified.require_fresh(EXPIRES_AT_MS - 1).is_ok());
    assert!(verified.require_fresh(ISSUED_AT_MS).is_err());
    assert!(verified.require_fresh(EXPIRES_AT_MS).is_err());
}

#[test]
fn every_package_wire_mutation_fails_closed() {
    let context = context(0x11, 0x33);
    let packaged = package(TwoPartyDeriverRole::DeriverA, &context);
    let bytes = packaged.canonical_bytes().expect("canonical package");

    // Trailing bytes.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&trailing).is_err());

    // Truncation at every prefix.
    for end in 0..bytes.len() {
        assert!(
            TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&bytes[..end]).is_err(),
            "truncated package at {end} must fail closed"
        );
    }

    // Wrong domain.
    let journal_bytes = journal(&context).canonical_bytes().expect("journal bytes");
    let command_bytes = command(TwoPartyDeriverRole::DeriverA, &context)
        .canonical_bytes()
        .expect("command bytes");
    let mut wrong_domain = Vec::new();
    for field in [
        b"tenant_root_role_creation_command_package_v2".as_slice(),
        &journal_bytes,
        &command_bytes,
    ] {
        wrong_domain.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        wrong_domain.extend_from_slice(field);
    }
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&wrong_domain)
            .expect_err("wrong domain")
            .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    // Every single-byte mutation.
    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 0xff;
        assert!(
            TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&mutated)
                .ok()
                .and_then(|package| verify_package(&package, TwoPartyDeriverRole::DeriverA).ok())
                .is_none(),
            "mutated package byte {index} must fail closed"
        );
    }

    // Empty and oversized wires.
    assert!(TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&[]).is_err());
    assert!(
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(&vec![
            0u8;
            TENANT_ROOT_ROLE_CREATION_COMMAND_PACKAGE_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}

// --- Tenant, lineage and nonce separation --------------------------------
//
// The shared fixtures above pin one identity and one custody lineage, so the
// pre-existing suite never varies either. These exercise the axes a package
// crossing a service boundary actually has to separate.

fn identity_for(org: &str) -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new(org, "project-2", "production", "root-main", "v3")
        .expect("tenant-root identity")
}

fn ceremony_for(
    org: &str,
    lineage_seed: u8,
    session_seed: u8,
    nonce_seed: u8,
) -> (TenantRootCeremonyContextV1, TenantRootCreationJournalV1) {
    let identity = identity_for(org);
    let context = TenantRootCeremonyContextV1::new(
        identity.digest().expect("identity digest"),
        lineage(lineage_seed),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session id"),
        TenantRootCeremonyNonceV1::from_bytes([nonce_seed; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("ceremony context");
    let journal =
        TenantRootCreationJournalV1::started(identity, lineage(lineage_seed), context.clone())
            .expect("Started journal");
    (context, journal)
}

fn command_for(
    role: TwoPartyDeriverRole,
    context: &TenantRootCeremonyContextV1,
    journal: &TenantRootCreationJournalV1,
) -> TenantRootRoleCreationCommandV1 {
    TenantRootRoleCreationCommandV1::sign(
        journal,
        context,
        role,
        authority(),
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .expect("signed role creation command")
}

#[test]
fn packages_from_different_tenants_do_not_cross() {
    let (context_a, journal_a) = ceremony_for("org-1", 0x22, 0x11, 0x33);
    let (context_b, journal_b) = ceremony_for("org-2", 0x22, 0x11, 0x33);

    // Same lineage, session and nonce; only the tenant differs. The journals
    // and commands must still be non-interchangeable.
    assert_ne!(
        journal_a.digest().expect("digest"),
        journal_b.digest().expect("digest")
    );
    assert_ne!(
        context_a.digest().expect("digest"),
        context_b.digest().expect("digest")
    );

    let command_a = command_for(TwoPartyDeriverRole::DeriverA, &context_a, &journal_a);
    let command_b = command_for(TwoPartyDeriverRole::DeriverA, &context_b, &journal_b);

    // Tenant A's journal under tenant B's command, and the reverse.
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::new(journal_a.clone(), command_b.clone())
            .expect_err("cross-tenant package")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::new(journal_b, command_a)
            .expect_err("cross-tenant package")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn packages_from_different_custody_lineages_do_not_cross() {
    let (context_one, journal_one) = ceremony_for("org-1", 0x22, 0x11, 0x33);
    let (context_two, journal_two) = ceremony_for("org-1", 0x23, 0x11, 0x33);

    assert_ne!(
        context_one.digest().expect("digest"),
        context_two.digest().expect("digest")
    );

    let command_one = command_for(TwoPartyDeriverRole::DeriverA, &context_one, &journal_one);
    let command_two = command_for(TwoPartyDeriverRole::DeriverA, &context_two, &journal_two);

    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::new(journal_one, command_two)
            .expect_err("cross-lineage package")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        TenantRootRoleCreationCommandPackageV1::new(journal_two, command_one)
            .expect_err("cross-lineage package")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn nonce_and_session_are_separated_independently() {
    let (base_context, base_journal) = ceremony_for("org-1", 0x22, 0x11, 0x33);
    // Same session, different nonce.
    let (nonce_context, nonce_journal) = ceremony_for("org-1", 0x22, 0x11, 0x34);
    // Same nonce, different session.
    let (session_context, session_journal) = ceremony_for("org-1", 0x22, 0x12, 0x33);

    assert_eq!(base_context.session_id(), nonce_context.session_id());
    assert_ne!(base_context.nonce(), nonce_context.nonce());
    assert_eq!(base_context.nonce(), session_context.nonce());
    assert_ne!(base_context.session_id(), session_context.session_id());

    let base_command = command_for(TwoPartyDeriverRole::DeriverA, &base_context, &base_journal);
    for (label, other_journal) in [
        ("nonce varied", nonce_journal.clone()),
        ("session varied", session_journal.clone()),
    ] {
        assert_eq!(
            TenantRootRoleCreationCommandPackageV1::new(other_journal, base_command.clone())
                .expect_err(label)
                .code(),
            RouterAbDerivationErrorCode::ReplayMismatch,
            "{label} must not be interchangeable"
        );
    }

    // Each coherent ceremony still verifies as itself.
    for (context, journal) in [
        (base_context, base_journal),
        (nonce_context, nonce_journal),
        (session_context, session_journal),
    ] {
        let command = command_for(TwoPartyDeriverRole::DeriverA, &context, &journal);
        let packaged = TenantRootRoleCreationCommandPackageV1::new(journal, command)
            .expect("coherent package");
        assert!(verify_package(&packaged, TwoPartyDeriverRole::DeriverA).is_ok());
    }
}
