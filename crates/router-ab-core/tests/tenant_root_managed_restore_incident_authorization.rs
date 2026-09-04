use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootManagedRestoreIncidentAuthorizationBindingV1,
    TenantRootManagedRestoreIncidentNonceV1, TenantRootManagedRestoreRoleV1, TenantRootShareEpoch,
    TenantRootSignedManagedRestoreIncidentAuthorizationV1,
    TENANT_ROOT_MANAGED_RESTORE_INCIDENT_CUSTODY_OPERATION_V1,
    TENANT_ROOT_MANAGED_RESTORE_INCIDENT_OPERATIONS_OPERATION_V1,
};

const FIRST_SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
const SECOND_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];

fn identity(seed: u8) -> TenantRootIdentityDigestV1 {
    TenantRootIdentityDigestV1::from_bytes([seed; 32])
}

fn digest(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).expect("digest")
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("lineage")
}

fn authority(seed: u8) -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes([seed; 32])
}

fn epoch(value: u64) -> TenantRootShareEpoch {
    TenantRootShareEpoch::new(value).expect("epoch")
}

fn nonce(seed: u8) -> TenantRootManagedRestoreIncidentNonceV1 {
    TenantRootManagedRestoreIncidentNonceV1::from_bytes([seed; 32]).expect("nonce")
}

fn binding_with(
    incident_id: &str,
    identity_digest: TenantRootIdentityDigestV1,
    unavailable_role: TenantRootManagedRestoreRoleV1,
    current_epoch: TenantRootShareEpoch,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    outage_observation_digest: TenantRootLifecycleReceiptDigestV1,
) -> TenantRootManagedRestoreIncidentAuthorizationBindingV1 {
    TenantRootManagedRestoreIncidentAuthorizationBindingV1::new(
        incident_id,
        identity_digest,
        lineage(0x22),
        unavailable_role,
        current_epoch,
        activation_receipt_digest,
        outage_observation_digest,
        1_000_000,
        1_030_000,
        nonce(0x33),
        authority(0x51),
        "operations-v1",
        authority(0x52),
        "custody-v1",
    )
    .expect("binding")
}

fn binding() -> TenantRootManagedRestoreIncidentAuthorizationBindingV1 {
    binding_with(
        "incident-2026-0001",
        identity(0x11),
        TenantRootManagedRestoreRoleV1::DeriverA,
        epoch(7),
        digest(0x44),
        digest(0x55),
    )
}

fn signed() -> TenantRootSignedManagedRestoreIncidentAuthorizationV1 {
    TenantRootSignedManagedRestoreIncidentAuthorizationV1::sign(
        binding(),
        &FIRST_SIGNING_KEY_BYTES,
        &SECOND_SIGNING_KEY_BYTES,
    )
    .expect("signed authorization")
}

fn trusted_keys() -> ([u8; 32], [u8; 32]) {
    (
        SigningKey::from_bytes(&FIRST_SIGNING_KEY_BYTES)
            .verifying_key()
            .to_bytes(),
        SigningKey::from_bytes(&SECOND_SIGNING_KEY_BYTES)
            .verifying_key()
            .to_bytes(),
    )
}

#[test]
fn incident_authorization_round_trips_and_verifies_both_approvals() {
    let expected = binding();
    let signed = signed();
    let bytes = signed.canonical_bytes().expect("canonical bytes");
    let decoded =
        TenantRootSignedManagedRestoreIncidentAuthorizationV1::decode_canonical_bytes(&bytes)
            .expect("decoded authorization");
    assert_eq!(decoded, signed);
    assert_eq!(decoded.binding(), &expected);
    assert_eq!(decoded.binding().operations_key_id(), "operations-v1");
    assert_eq!(decoded.binding().custody_key_id(), "custody-v1");

    let (first_key, second_key) = trusted_keys();
    let verified = decoded
        .verify(&expected, &first_key, &second_key)
        .expect("verified authorization");
    assert_eq!(verified.incident_id(), "incident-2026-0001");
    assert_eq!(verified.identity_digest(), identity(0x11));
    assert_eq!(verified.custody_lineage(), lineage(0x22));
    assert_eq!(
        verified.unavailable_role(),
        TenantRootManagedRestoreRoleV1::DeriverA
    );
    assert_eq!(verified.current_epoch(), epoch(7));
    assert_eq!(verified.activation_receipt_digest(), digest(0x44));
    assert_eq!(verified.outage_observation_digest(), digest(0x55));
    assert_eq!(verified.nonce(), nonce(0x33));
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.into_canonical_bytes(), bytes);
}

#[test]
fn incident_authorization_requires_fixed_operations() {
    let signed_authorization = signed();
    let bytes = signed_authorization
        .canonical_bytes()
        .expect("canonical bytes");

    for operation in [
        TENANT_ROOT_MANAGED_RESTORE_INCIDENT_OPERATIONS_OPERATION_V1,
        TENANT_ROOT_MANAGED_RESTORE_INCIDENT_CUSTODY_OPERATION_V1,
    ] {
        let mut tampered = bytes.clone();
        let operation_start = tampered
            .windows(operation.len())
            .position(|field| field == operation.as_bytes())
            .expect("operation field");
        tampered[operation_start] ^= 1;
        let error = TenantRootSignedManagedRestoreIncidentAuthorizationV1::decode_canonical_bytes(
            &tampered,
        )
        .expect_err("unknown operation must be rejected");
        assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
    }
}

#[test]
fn incident_authorization_rejects_tenant_role_epoch_and_receipt_substitution() {
    let (first_key, second_key) = trusted_keys();
    let candidates = [
        (
            "tenant",
            binding_with(
                "incident-2026-0001",
                identity(0x12),
                TenantRootManagedRestoreRoleV1::DeriverA,
                epoch(7),
                digest(0x44),
                digest(0x55),
            ),
        ),
        (
            "role",
            binding_with(
                "incident-2026-0001",
                identity(0x11),
                TenantRootManagedRestoreRoleV1::DeriverB,
                epoch(7),
                digest(0x44),
                digest(0x55),
            ),
        ),
        (
            "epoch",
            binding_with(
                "incident-2026-0001",
                identity(0x11),
                TenantRootManagedRestoreRoleV1::DeriverA,
                epoch(8),
                digest(0x44),
                digest(0x55),
            ),
        ),
        (
            "activation receipt",
            binding_with(
                "incident-2026-0001",
                identity(0x11),
                TenantRootManagedRestoreRoleV1::DeriverA,
                epoch(7),
                digest(0x45),
                digest(0x55),
            ),
        ),
        (
            "outage observation",
            binding_with(
                "incident-2026-0001",
                identity(0x11),
                TenantRootManagedRestoreRoleV1::DeriverA,
                epoch(7),
                digest(0x44),
                digest(0x56),
            ),
        ),
    ];

    for (label, candidate) in candidates {
        let signed = signed();
        assert_eq!(
            signed
                .verify(&candidate, &first_key, &second_key)
                .expect_err(label)
                .code(),
            RouterAbDerivationErrorCode::ReplayMismatch,
            "{label} substitution must fail",
        );
    }
}

#[test]
fn incident_authorization_rejects_duplicate_authorities_and_keys() {
    let duplicate_authority = TenantRootManagedRestoreIncidentAuthorizationBindingV1::new(
        "incident-2026-0001",
        identity(0x11),
        lineage(0x22),
        TenantRootManagedRestoreRoleV1::DeriverA,
        epoch(7),
        digest(0x44),
        digest(0x55),
        1_000_000,
        1_030_000,
        nonce(0x33),
        authority(0x51),
        "operations-v1",
        authority(0x51),
        "custody-v1",
    )
    .expect_err("duplicate authority");
    assert_eq!(
        duplicate_authority.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    let duplicate_key_id = TenantRootManagedRestoreIncidentAuthorizationBindingV1::new(
        "incident-2026-0001",
        identity(0x11),
        lineage(0x22),
        TenantRootManagedRestoreRoleV1::DeriverA,
        epoch(7),
        digest(0x44),
        digest(0x55),
        1_000_000,
        1_030_000,
        nonce(0x33),
        authority(0x51),
        "same-key-id",
        authority(0x52),
        "same-key-id",
    )
    .expect_err("duplicate key id");
    assert_eq!(
        duplicate_key_id.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    let duplicate_key = TenantRootSignedManagedRestoreIncidentAuthorizationV1::sign(
        binding(),
        &FIRST_SIGNING_KEY_BYTES,
        &FIRST_SIGNING_KEY_BYTES,
    )
    .expect_err("duplicate signing key");
    assert_eq!(
        duplicate_key.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
}

#[test]
fn incident_authorization_rejects_one_bad_signature_and_duplicate_trusted_key() {
    let signed_authorization = signed();
    let bytes = signed_authorization
        .canonical_bytes()
        .expect("canonical bytes");
    let (first_key, second_key) = trusted_keys();

    let mut first_tampered = bytes.clone();
    let first_signature_start = first_tampered.len() - (4 + 64) - (4 + 64) + 4;
    first_tampered[first_signature_start] ^= 1;
    let first_tampered =
        TenantRootSignedManagedRestoreIncidentAuthorizationV1::decode_canonical_bytes(
            &first_tampered,
        )
        .expect("first signature wire remains structurally valid");
    let first_signature_error = first_tampered
        .verify(&binding(), &first_key, &second_key)
        .expect_err("first signature must fail");
    assert_eq!(
        first_signature_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let mut second_tampered = bytes;
    let last = second_tampered.len() - 1;
    second_tampered[last] ^= 1;
    let second_tampered =
        TenantRootSignedManagedRestoreIncidentAuthorizationV1::decode_canonical_bytes(
            &second_tampered,
        )
        .expect("second signature wire remains structurally valid");
    let second_signature_error = second_tampered
        .verify(&binding(), &first_key, &second_key)
        .expect_err("second signature must fail");
    assert_eq!(
        second_signature_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let duplicate_trusted_key = signed()
        .verify(&binding(), &first_key, &first_key)
        .expect_err("duplicate trusted key");
    assert_eq!(
        duplicate_trusted_key.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn incident_authorization_enforces_one_use_nonce_and_expiry_window() {
    assert!(TenantRootManagedRestoreIncidentNonceV1::from_bytes([0; 32]).is_err());

    let (first_key, second_key) = trusted_keys();
    let verified = signed()
        .verify(&binding(), &first_key, &second_key)
        .expect("verified authorization");
    assert!(verified.require_fresh(1_000_000).is_ok());
    assert!(verified.require_fresh(1_030_000).is_ok());
    assert!(verified.require_fresh(999_999).is_err());
    assert!(verified.require_fresh(1_030_001).is_err());

    let too_long = TenantRootManagedRestoreIncidentAuthorizationBindingV1::new(
        "incident-2026-0001",
        identity(0x11),
        lineage(0x22),
        TenantRootManagedRestoreRoleV1::DeriverA,
        epoch(7),
        digest(0x44),
        digest(0x55),
        1_000_000,
        1_300_001,
        nonce(0x33),
        authority(0x51),
        "operations-v1",
        authority(0x52),
        "custody-v1",
    )
    .expect_err("maximum lifetime");
    assert_eq!(too_long.code(), RouterAbDerivationErrorCode::MalformedInput);
}
