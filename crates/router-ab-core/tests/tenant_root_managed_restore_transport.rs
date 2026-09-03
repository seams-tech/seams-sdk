use ed25519_dalek::SigningKey;
use router_ab_core::{
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId, TenantRootEmptyCreationV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreAvailableV1,
    TenantRootManagedRestoreCapabilityV1, TenantRootManagedRestoreRoleV1,
    TenantRootRoleUnavailableReceiptV1, TenantRootShareEpoch,
    TenantRootSignedManagedRestoreCapabilityV1,
    TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_OPERATION_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};
use threshold_prf::TwoPartyDeriverRole;

mod support;

const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const ISSUER_KEY_BYTES: [u8; 32] = [0x81; 32];
const ISSUED_AT_MS: u64 = 1_023_000;
const EXPIRES_AT_MS: u64 = 1_050_000;

fn digest(marker: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([marker; 32]).expect("non-zero digest")
}

fn identity() -> router_ab_core::TenantRootIdentityV1 {
    router_ab_core::TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("identity")
}

fn lineage() -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage")
}

fn context() -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity().digest().expect("identity digest"),
        lineage(),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).expect("session"),
        TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).expect("nonce"),
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-v1",
        "deriver-b-signing-key-v1",
    )
    .expect("context")
}

fn unavailable_state() -> (
    router_ab_core::TenantRootManagedRestoreRoleUnavailableV1,
    router_ab_core::TenantRootActiveRefreshV1,
) {
    let share_a = support::fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = support::fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let context = context();
    let fixture =
        support::initial_activation_evidence_fixture(context.clone(), &share_a, &share_b, 21, 22);
    let support::InitialActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let verified = TenantRootEmptyCreationV1::new(identity(), lineage())
        .start(&context)
        .expect("start")
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .expect("verify");
    let active = verified
        .activate(support::initial_activation_receipt(&bundle, 1_020_000))
        .expect("activate")
        .into_refresh_state();
    let unavailable = TenantRootManagedRestoreAvailableV1::new(active.clone())
        .expect("managed restore availability")
        .mark_role_unavailable(
            TenantRootRoleUnavailableReceiptV1::new(
                digest(0x90),
                TenantRootManagedRestoreRoleV1::DeriverA,
                1_022_000,
            )
            .expect("unavailability"),
        )
        .expect("unavailable state");
    (unavailable, active)
}

fn capability(
    active: &router_ab_core::TenantRootActiveRefreshV1,
) -> TenantRootManagedRestoreCapabilityV1 {
    TenantRootManagedRestoreCapabilityV1::new(
        digest(0x91),
        active.identity().digest().expect("identity digest"),
        active.custody_lineage(),
        TenantRootManagedRestoreRoleV1::DeriverA,
        active.current().epoch(),
        active.current().activation().digest(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
    )
    .expect("capability")
}

#[test]
fn signed_restore_capability_round_trips_and_binds_lifecycle_state() {
    let (state, active) = unavailable_state();
    let signed = TenantRootSignedManagedRestoreCapabilityV1::sign(
        capability(&active),
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect("signed capability");
    let bytes = signed.canonical_bytes().expect("canonical bytes");
    let decoded = TenantRootSignedManagedRestoreCapabilityV1::decode_canonical_bytes(&bytes)
        .expect("decoded capability");
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.operation(),
        TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_OPERATION_V1
    );
    assert_eq!(decoded.issuer_key_id(), ISSUER_KEY_ID);

    let verifying_key = SigningKey::from_bytes(&ISSUER_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let verified = decoded
        .verify(&state, ISSUER_KEY_ID, &verifying_key)
        .expect("verified capability");
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.capability_digest(), digest(0x91));
    assert_eq!(verified.role(), TenantRootManagedRestoreRoleV1::DeriverA);
    assert!(verified.require_fresh(ISSUED_AT_MS).is_ok());
    assert!(verified.require_fresh(EXPIRES_AT_MS).is_ok());
    assert!(verified.require_fresh(EXPIRES_AT_MS + 1).is_err());

    let installing = state
        .start_restore(verified.into_capability(), ISSUED_AT_MS + 1)
        .expect("restore begins only from verified capability");
    assert!(matches!(
        installing,
        router_ab_core::TenantRootManagedRestoreInstallingV1::RestoringA(_)
    ));
}

#[test]
fn restore_capability_rejects_state_substitution_and_wire_mutation() {
    let (state, active) = unavailable_state();
    let signed = TenantRootSignedManagedRestoreCapabilityV1::sign(
        capability(&active),
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect("signed capability");
    let verifying_key = SigningKey::from_bytes(&ISSUER_KEY_BYTES)
        .verifying_key()
        .to_bytes();

    let mut trailing = signed.canonical_bytes().expect("canonical bytes");
    trailing.push(0);
    assert!(TenantRootSignedManagedRestoreCapabilityV1::decode_canonical_bytes(&trailing).is_err());

    let mut tampered_signature = signed.canonical_bytes().expect("canonical bytes");
    let last = tampered_signature.len() - 1;
    tampered_signature[last] ^= 1;
    let decoded =
        TenantRootSignedManagedRestoreCapabilityV1::decode_canonical_bytes(&tampered_signature)
            .expect("signature bytes remain canonical");
    assert!(decoded
        .verify(&state, ISSUER_KEY_ID, &verifying_key)
        .is_err());

    let wrong_key = SigningKey::from_bytes(&[0x82; 32])
        .verifying_key()
        .to_bytes();
    assert!(signed.verify(&state, ISSUER_KEY_ID, &wrong_key).is_err());
    assert!(signed
        .verify(&state, "other-issuer-v1", &verifying_key)
        .is_err());

    let mut wrong_role_capability = capability(&active);
    wrong_role_capability = TenantRootManagedRestoreCapabilityV1::new(
        wrong_role_capability.digest(),
        wrong_role_capability.identity_digest(),
        wrong_role_capability.custody_lineage(),
        TenantRootManagedRestoreRoleV1::DeriverB,
        wrong_role_capability.epoch(),
        wrong_role_capability.activation_receipt_digest(),
        wrong_role_capability.issued_at_ms(),
        wrong_role_capability.expires_at_ms(),
    )
    .expect("wrong-role capability");
    let wrong_role_signed = TenantRootSignedManagedRestoreCapabilityV1::sign(
        wrong_role_capability,
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect("wrong-role signature");
    assert!(wrong_role_signed
        .verify(&state, ISSUER_KEY_ID, &verifying_key)
        .is_err());
}

#[test]
fn restore_capability_lifetime_is_frozen() {
    let (_, active) = unavailable_state();
    let too_long = TenantRootManagedRestoreCapabilityV1::new(
        digest(0x92),
        active.identity().digest().expect("identity digest"),
        active.custody_lineage(),
        TenantRootManagedRestoreRoleV1::DeriverA,
        TenantRootShareEpoch::INITIAL,
        active.current().activation().digest(),
        1_000_000,
        1_000_000 + TENANT_ROOT_MAX_LIFETIME_MS_V1 + 1,
    )
    .expect("domain capability");
    assert!(TenantRootSignedManagedRestoreCapabilityV1::sign(
        too_long,
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .is_err());
}
