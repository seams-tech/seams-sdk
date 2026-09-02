use std::ops::Range;

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use router_ab_core::{
    resolve_active_tenant_root_pair_binding_v1, MpcPrfShareCommitmentWireV1,
    RouterAbDerivationErrorCode, TenantRootActiveRoleBindingV1, TenantRootActiveRoleResolutionV1,
    TenantRootActiveRoleRowKeyV1, TenantRootActiveRootPairV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCommandScopeV1, TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootManagedRestoreRoleV1, TenantRootRoleRefreshCommandV1, TenantRootShareEpoch,
    VerifiedTenantRootRoleRefreshCommandV1, TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1,
    TENANT_ROOT_ROLE_REFRESH_COMMAND_OPERATION_V1,
};
use threshold_prf::{SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole};

const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;
const ACTIVE_EPOCH: u64 = 7;
const NEXT_EPOCH: u64 = 8;
const EXPECTED_REVISION: u64 = 4;

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("fixed tenant-root identity")
}

fn identity_digest() -> TenantRootIdentityDigestV1 {
    identity().digest().expect("identity digest")
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("lineage")
}

fn context(
    session_seed: u8,
    nonce_seed: u8,
    current: u64,
    next: u64,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity_digest(),
        lineage(0x31),
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(current).expect("current epoch"),
            TenantRootShareEpoch::new(next).expect("next epoch"),
        )
        .expect("refresh epochs"),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session id"),
        TenantRootCeremonyNonceV1::from_bytes([nonce_seed; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("refresh context")
}

fn share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .expect("share")
}

fn commitment_wire(role: TwoPartyDeriverRole, scalar: u64) -> MpcPrfShareCommitmentWireV1 {
    MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(&share(role, scalar))
            .to_bytes()
            .to_vec(),
    )
    .expect("commitment wire")
}

fn make_active_pair(
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: u64,
    receipt_seed: u8,
    deriver_a_scalar: u64,
    deriver_b_scalar: u64,
) -> TenantRootActiveRootPairV1 {
    let epoch = TenantRootShareEpoch::new(epoch).expect("active epoch");
    let receipt = TenantRootLifecycleReceiptDigestV1::from_bytes([receipt_seed; 32])
        .expect("activation receipt");
    let deriver_a = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            epoch,
            TenantRootManagedRestoreRoleV1::DeriverA,
        ),
        commitment_wire(TwoPartyDeriverRole::DeriverA, deriver_a_scalar),
        receipt,
    )
    .expect("Deriver A active binding");
    let deriver_b = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            epoch,
            TenantRootManagedRestoreRoleV1::DeriverB,
        ),
        commitment_wire(TwoPartyDeriverRole::DeriverB, deriver_b_scalar),
        receipt,
    )
    .expect("Deriver B active binding");
    resolve_active_tenant_root_pair_binding_v1(
        identity_digest,
        &TenantRootActiveRoleResolutionV1::Active(deriver_a),
        &TenantRootActiveRoleResolutionV1::Active(deriver_b),
    )
    .expect("active pair resolution")
    .require_active()
    .expect("active pair")
    .clone()
}

fn pair() -> TenantRootActiveRootPairV1 {
    make_active_pair(identity_digest(), lineage(0x31), ACTIVE_EPOCH, 0x71, 12, 19)
}

fn authority(seed: u8) -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes([seed; 32])
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_KEY_BYTES)
}

fn command(
    role: TwoPartyDeriverRole,
    active_pair: &TenantRootActiveRootPairV1,
    refresh_context: &TenantRootCeremonyContextV1,
) -> TenantRootRoleRefreshCommandV1 {
    TenantRootRoleRefreshCommandV1::sign(
        active_pair,
        refresh_context,
        role,
        EXPECTED_REVISION,
        authority(0x44),
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .expect("signed refresh role command")
}

fn verify(
    command: &TenantRootRoleRefreshCommandV1,
    active_pair: &TenantRootActiveRootPairV1,
    refresh_context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
) -> VerifiedTenantRootRoleRefreshCommandV1 {
    command
        .verify(
            active_pair,
            refresh_context,
            role,
            EXPECTED_REVISION,
            authority(0x44),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .expect("verified refresh role command")
}

#[test]
fn sign_decode_verify_round_trip_projects_the_refresh_scope() {
    let refresh_context = context(0x11, 0x33, ACTIVE_EPOCH, NEXT_EPOCH);
    let active_pair = pair();
    let raw = command(
        TwoPartyDeriverRole::DeriverA,
        &active_pair,
        &refresh_context,
    );
    let bytes = raw.canonical_bytes().expect("canonical command");
    assert_eq!(
        hex::encode(raw.digest().unwrap().as_bytes()),
        "76d9da2b7393805765848000282335502e267ed07e152f8b3c0b1f054efa8bf3"
    );
    let decoded =
        TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&bytes).expect("decoded command");
    assert_eq!(decoded, raw);
    assert_eq!(
        decoded.operation(),
        TENANT_ROOT_ROLE_REFRESH_COMMAND_OPERATION_V1
    );
    assert_eq!(decoded.identity_digest(), identity_digest());
    assert_eq!(decoded.custody_lineage(), lineage(0x31));
    assert_eq!(
        decoded.deriver_a_share_commitment().as_bytes(),
        active_pair.deriver_a().share_commitment().as_bytes()
    );
    assert_eq!(
        decoded.deriver_b_share_commitment().as_bytes(),
        active_pair.deriver_b().share_commitment().as_bytes()
    );
    assert_eq!(
        decoded.active_root_commitment(),
        active_pair.root_commitment()
    );
    assert_eq!(
        decoded.active_activation_receipt_digest(),
        active_pair.activation_receipt_digest()
    );
    assert_eq!(
        decoded.refresh_context_digest(),
        refresh_context.digest().unwrap()
    );
    assert_eq!(decoded.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(
        decoded.current_epoch(),
        TenantRootShareEpoch::new(ACTIVE_EPOCH).unwrap()
    );
    assert_eq!(
        decoded.next_epoch(),
        TenantRootShareEpoch::new(NEXT_EPOCH).unwrap()
    );
    assert_eq!(decoded.expected_control_plane_revision(), EXPECTED_REVISION);
    assert_eq!(decoded.session_id(), refresh_context.session_id());
    assert_eq!(decoded.nonce(), refresh_context.nonce());
    assert_eq!(decoded.authority_id(), authority(0x44));
    assert_eq!(decoded.issued_at_ms(), ISSUED_AT_MS + 1);
    assert_eq!(decoded.expires_at_ms(), EXPIRES_AT_MS - 1);
    assert_eq!(decoded.issuer_key_id(), ISSUER_KEY_ID);

    let verified = verify(
        &decoded,
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
    );
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.digest(), decoded.digest().unwrap());
    assert_eq!(
        verified.operation(),
        TENANT_ROOT_ROLE_REFRESH_COMMAND_OPERATION_V1
    );
    assert_eq!(verified.role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(
        verified.current_epoch(),
        TenantRootShareEpoch::new(ACTIVE_EPOCH).unwrap()
    );
    assert_eq!(
        verified.next_epoch(),
        TenantRootShareEpoch::new(NEXT_EPOCH).unwrap()
    );

    let scope: TenantRootCommandScopeV1 = verified.scope();
    assert_eq!(scope.key().identity_digest(), identity_digest());
    assert_eq!(scope.key().custody_lineage(), lineage(0x31));
    assert_eq!(scope.key().session_id(), refresh_context.session_id());
    assert_eq!(scope.key().nonce(), refresh_context.nonce());
    assert_eq!(scope.key().role(), TwoPartyDeriverRole::DeriverA);
    assert_eq!(
        scope.epoch(),
        TenantRootShareEpoch::new(NEXT_EPOCH).unwrap()
    );
    assert_eq!(scope.expected_control_plane_revision(), EXPECTED_REVISION);

    assert!(verified.require_fresh(verified.issued_at_ms()).is_ok());
    assert!(verified.require_fresh(verified.expires_at_ms()).is_ok());
    assert!(verified.require_fresh(verified.issued_at_ms() - 1).is_err());
    assert!(verified
        .require_fresh(verified.expires_at_ms() + 1)
        .is_err());
    assert_eq!(verified.into_canonical_bytes(), bytes);
}

#[test]
fn role_a_and_role_b_are_exactly_distinct() {
    let refresh_context = context(0x11, 0x33, ACTIVE_EPOCH, NEXT_EPOCH);
    let active_pair = pair();
    let command_a = command(
        TwoPartyDeriverRole::DeriverA,
        &active_pair,
        &refresh_context,
    );
    let command_b = command(
        TwoPartyDeriverRole::DeriverB,
        &active_pair,
        &refresh_context,
    );
    assert_ne!(
        command_a.canonical_bytes().unwrap(),
        command_b.canonical_bytes().unwrap(),
        "role substitution must change the signed command"
    );
    let verified_a = verify(
        &command_a,
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
    );
    let verified_b = verify(
        &command_b,
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverB,
    );
    assert_eq!(
        verified_a.scope().key().role(),
        TwoPartyDeriverRole::DeriverA
    );
    assert_eq!(
        verified_b.scope().key().role(),
        TwoPartyDeriverRole::DeriverB
    );
    assert!(command_a
        .verify(
            &active_pair,
            &refresh_context,
            TwoPartyDeriverRole::DeriverB,
            EXPECTED_REVISION,
            authority(0x44),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .is_err());
}

#[test]
fn every_public_binding_substitution_fails_before_signature_acceptance() {
    let refresh_context = context(0x11, 0x33, ACTIVE_EPOCH, NEXT_EPOCH);
    let active_pair = pair();
    let raw = command(
        TwoPartyDeriverRole::DeriverA,
        &active_pair,
        &refresh_context,
    );
    let changed_pair =
        make_active_pair(identity_digest(), lineage(0x31), ACTIVE_EPOCH, 0x71, 13, 19);
    let changed_receipt =
        make_active_pair(identity_digest(), lineage(0x31), ACTIVE_EPOCH, 0x72, 12, 19);
    let changed_context = context(0x12, 0x34, ACTIVE_EPOCH, NEXT_EPOCH);

    assert_eq!(
        raw.verify(
            &changed_pair,
            &refresh_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION,
            authority(0x44),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .expect_err("active pair substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        raw.verify(
            &changed_receipt,
            &refresh_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION,
            authority(0x44),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .expect_err("activation receipt substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        raw.verify(
            &active_pair,
            &changed_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION,
            authority(0x44),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .expect_err("refresh context substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        raw.verify(
            &active_pair,
            &refresh_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION + 1,
            authority(0x44),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .expect_err("revision substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        raw.verify(
            &active_pair,
            &refresh_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION,
            authority(0x45),
            ISSUER_KEY_ID,
            signing_key().verifying_key().as_bytes(),
        )
        .expect_err("authority substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        raw.verify(
            &active_pair,
            &refresh_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION,
            authority(0x44),
            "another-control-plane-issuer-v1",
            signing_key().verifying_key().as_bytes(),
        )
        .expect_err("issuer key id substitution")
        .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    let wrong_key = SigningKey::from_bytes(&[0x42; 32]);
    assert_eq!(
        raw.verify(
            &active_pair,
            &refresh_context,
            TwoPartyDeriverRole::DeriverA,
            EXPECTED_REVISION,
            authority(0x44),
            ISSUER_KEY_ID,
            wrong_key.verifying_key().as_bytes(),
        )
        .expect_err("issuer signing key substitution")
        .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn strict_wire_decoding_rejects_field_substitution_and_truncation() {
    let refresh_context = context(0x11, 0x33, ACTIVE_EPOCH, NEXT_EPOCH);
    let active_pair = pair();
    let raw = command(
        TwoPartyDeriverRole::DeriverA,
        &active_pair,
        &refresh_context,
    );
    let bytes = raw.canonical_bytes().unwrap();
    let fields = field_ranges(&bytes);

    for (index, marker) in [
        (2, 0x12),  // identity
        (3, 0x23),  // lineage
        (4, 0x34),  // Deriver A commitment
        (5, 0x45),  // Deriver B commitment
        (6, 0x56),  // root commitment
        (7, 0x67),  // activation receipt
        (8, 0x78),  // refresh context digest
        (13, 0x89), // revision
        (14, 0x9a), // session
        (15, 0xab), // nonce
        (16, 0xbc), // authority
        (17, 0xcd), // issue time
        (18, 0xde), // expiry
        (20, 0xef), // issuer key id
    ] {
        let tampered = replace_field(&bytes, index, &vec![marker; fields[index].len()]);
        if let Ok(decoded) = TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&tampered) {
            assert!(
                decoded
                    .verify(
                        &active_pair,
                        &refresh_context,
                        TwoPartyDeriverRole::DeriverA,
                        EXPECTED_REVISION,
                        authority(0x44),
                        ISSUER_KEY_ID,
                        signing_key().verifying_key().as_bytes(),
                    )
                    .is_err(),
                "field {index} substitution must fail verification"
            );
        }
    }

    let mut signature = bytes.clone();
    signature[fields[21].start] ^= 1;
    let decoded_signature = TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&signature)
        .expect("signature tamper remains structurally valid");
    assert_eq!(
        decoded_signature
            .verify(
                &active_pair,
                &refresh_context,
                TwoPartyDeriverRole::DeriverA,
                EXPECTED_REVISION,
                authority(0x44),
                ISSUER_KEY_ID,
                signing_key().verifying_key().as_bytes(),
            )
            .expect_err("signature substitution")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let payload = replace_field(&bytes, 19, &[0x01; 32]);
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&payload).is_err());
    let role_label = replace_field(&bytes, 9, b"deriver_x");
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&role_label).is_err());
    let role_share = replace_field(&bytes, 10, &2_u16.to_be_bytes());
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&role_share).is_err());
    let current_epoch = replace_field(&bytes, 11, &6_u64.to_be_bytes());
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&current_epoch).is_err());
    let next_epoch = replace_field(&bytes, 12, &9_u64.to_be_bytes());
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&next_epoch).is_err());
    let mut domain = bytes.clone();
    domain[fields[0].start] ^= 1;
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&domain).is_err());
    let mut operation = bytes.clone();
    operation[fields[1].start] = b'x';
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&operation).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&trailing).is_err());
    assert!(
        TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&bytes[..bytes.len() - 1]).is_err()
    );
    assert!(TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&[]).is_err());
    assert!(
        TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&vec![
            0_u8;
            TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}

#[test]
fn signing_requires_authoritative_refresh_context_pair_and_command_window() {
    let refresh_context = context(0x11, 0x33, ACTIVE_EPOCH, NEXT_EPOCH);
    let active_pair = pair();
    let authority = authority(0x44);
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        0,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS - 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS + 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &active_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS + 1,
        ISSUED_AT_MS + 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());

    let creation_context = TenantRootCeremonyContextV1::new(
        identity_digest(),
        lineage(0x31),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x11; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap();
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &active_pair,
        &creation_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());

    let changed_identity =
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-other", "v3")
            .unwrap()
            .digest()
            .unwrap();
    let changed_identity_pair =
        make_active_pair(changed_identity, lineage(0x31), ACTIVE_EPOCH, 0x71, 12, 19);
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &changed_identity_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());

    let changed_lineage_pair =
        make_active_pair(identity_digest(), lineage(0x32), ACTIVE_EPOCH, 0x71, 12, 19);
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &changed_lineage_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .is_err());

    let changed_epoch_pair = make_active_pair(
        identity_digest(),
        lineage(0x31),
        ACTIVE_EPOCH - 1,
        0x71,
        12,
        19,
    );
    assert!(TenantRootRoleRefreshCommandV1::sign(
        &changed_epoch_pair,
        &refresh_context,
        TwoPartyDeriverRole::DeriverA,
        EXPECTED_REVISION,
        authority,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
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
