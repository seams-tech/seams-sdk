use std::ops::Range;

use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootControlPlaneAuthorityIdV1,
    TenantRootCreationCapabilityNonceV1, TenantRootCreationCapabilityV1,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootProtocolDigestV1,
    TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1,
    TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1, TENANT_ROOT_CREATION_CAPABILITY_OPERATION_V1,
    TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_KEY_BYTES)
}

fn identity_digest(marker: u8) -> TenantRootIdentityDigestV1 {
    TenantRootIdentityDigestV1::from_bytes([marker; 32])
}

fn lineage(marker: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([marker; 16]).expect("non-zero lineage")
}

fn journal_digest(marker: u8) -> TenantRootProtocolDigestV1 {
    TenantRootProtocolDigestV1::from_bytes([marker; 32]).expect("non-zero journal digest")
}

fn authority_id(marker: u8) -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes([marker; 32])
}

fn nonce(marker: u8) -> TenantRootCreationCapabilityNonceV1 {
    TenantRootCreationCapabilityNonceV1::from_bytes([marker; 32]).expect("non-zero nonce")
}

fn capability() -> TenantRootCreationCapabilityV1 {
    sign_capability_with_times(1_000, 1_030).expect("signed creation capability")
}

fn sign_capability_with_times(
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<TenantRootCreationCapabilityV1, router_ab_core::RouterAbDerivationError> {
    TenantRootCreationCapabilityV1::sign(
        identity_digest(0x11),
        lineage(0x22),
        journal_digest(0x33),
        authority_id(0x44),
        nonce(0x55),
        issued_at_ms,
        expires_at_ms,
        ISSUER_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
}

fn verify(
    capability: &TenantRootCreationCapabilityV1,
) -> router_ab_core::VerifiedTenantRootCreationCapabilityV1 {
    verify_result(capability).expect("verified creation capability")
}

fn verify_result(
    capability: &TenantRootCreationCapabilityV1,
) -> Result<
    router_ab_core::VerifiedTenantRootCreationCapabilityV1,
    router_ab_core::RouterAbDerivationError,
> {
    capability.verify(
        identity_digest(0x11),
        lineage(0x22),
        journal_digest(0x33),
        TENANT_ROOT_CREATION_CAPABILITY_EXPECTED_REVISION_V1,
        authority_id(0x44),
        ISSUER_KEY_ID,
        &signing_key().verifying_key().to_bytes(),
    )
}

#[test]
fn sign_decode_verify_round_trip_binds_every_public_field() {
    let raw = capability();
    let bytes = raw.canonical_bytes().expect("canonical capability");
    let decoded =
        TenantRootCreationCapabilityV1::decode_canonical_bytes(&bytes).expect("decoded capability");
    assert_eq!(decoded, raw);
    assert_eq!(
        decoded.operation(),
        TENANT_ROOT_CREATION_CAPABILITY_OPERATION_V1
    );
    assert_eq!(decoded.identity_digest(), identity_digest(0x11));
    assert_eq!(decoded.custody_lineage(), lineage(0x22));
    assert_eq!(decoded.started_journal_digest(), journal_digest(0x33));
    assert_eq!(decoded.expected_revision(), 1);
    assert_eq!(decoded.authority_id(), authority_id(0x44));
    assert_eq!(decoded.nonce(), nonce(0x55));
    assert_eq!(decoded.issued_at_ms(), 1_000);
    assert_eq!(decoded.expires_at_ms(), 1_030);
    assert_eq!(decoded.issuer_key_id(), ISSUER_KEY_ID);

    let verified = verify(&decoded);
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(
        verified.digest(),
        decoded.digest().expect("capability digest")
    );
    assert_eq!(
        verified.operation(),
        TENANT_ROOT_CREATION_CAPABILITY_OPERATION_V1
    );
    assert_eq!(verified.identity_digest(), identity_digest(0x11));
    assert_eq!(verified.custody_lineage(), lineage(0x22));
    assert_eq!(verified.started_journal_digest(), journal_digest(0x33));
    assert_eq!(verified.expected_revision(), 1);
    assert_eq!(verified.authority_id(), authority_id(0x44));
    assert_eq!(verified.nonce(), nonce(0x55));
    assert_eq!(verified.issued_at_ms(), 1_000);
    assert_eq!(verified.expires_at_ms(), 1_030);
    assert_eq!(verified.issuer_key_id(), ISSUER_KEY_ID);
    assert_eq!(verified.into_canonical_bytes(), bytes);
}

#[test]
fn verification_rejects_wrong_expected_bindings_and_issuer() {
    let raw = capability();
    let expected = [
        (
            "identity",
            raw.verify(
                identity_digest(0x12),
                lineage(0x22),
                journal_digest(0x33),
                1,
                authority_id(0x44),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            ),
        ),
        (
            "lineage",
            raw.verify(
                identity_digest(0x11),
                lineage(0x23),
                journal_digest(0x33),
                1,
                authority_id(0x44),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            ),
        ),
        (
            "journal",
            raw.verify(
                identity_digest(0x11),
                lineage(0x22),
                journal_digest(0x34),
                1,
                authority_id(0x44),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            ),
        ),
        (
            "revision",
            raw.verify(
                identity_digest(0x11),
                lineage(0x22),
                journal_digest(0x33),
                2,
                authority_id(0x44),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            ),
        ),
        (
            "authority",
            raw.verify(
                identity_digest(0x11),
                lineage(0x22),
                journal_digest(0x33),
                1,
                authority_id(0x45),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            ),
        ),
        (
            "issuer",
            raw.verify(
                identity_digest(0x11),
                lineage(0x22),
                journal_digest(0x33),
                1,
                authority_id(0x44),
                "another-issuer-v1",
                &signing_key().verifying_key().to_bytes(),
            ),
        ),
    ];
    for (field, result) in expected {
        assert_eq!(
            result.expect_err(field).code(),
            RouterAbDerivationErrorCode::ReplayMismatch,
            "{field} substitution must fail as a binding mismatch",
        );
    }

    let wrong_key = SigningKey::from_bytes(&[0x42; 32]);
    assert_eq!(
        raw.verify(
            identity_digest(0x11),
            lineage(0x22),
            journal_digest(0x33),
            1,
            authority_id(0x44),
            ISSUER_KEY_ID,
            &wrong_key.verifying_key().to_bytes(),
        )
        .expect_err("wrong issuer key")
        .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn canonical_wire_rejects_operation_binding_tampering_and_malformed_shapes() {
    let bytes = capability()
        .canonical_bytes()
        .expect("canonical capability");
    let fields = field_ranges(&bytes);

    let mut domain = bytes.clone();
    domain[fields[0].start] ^= 1;
    assert!(TenantRootCreationCapabilityV1::decode_canonical_bytes(&domain).is_err());

    let mut operation = bytes.clone();
    operation[fields[1].start] = b'x';
    assert!(TenantRootCreationCapabilityV1::decode_canonical_bytes(&operation).is_err());

    for (index, marker) in [(2, 0x12), (3, 0x23), (4, 0x34), (6, 0x45), (7, 0x56)] {
        let tampered = replace_field(&bytes, index, &vec![marker; fields[index].len()]);
        let decoded = TenantRootCreationCapabilityV1::decode_canonical_bytes(&tampered)
            .expect("binding tamper remains structurally valid");
        assert!(
            decoded
                .verify(
                    identity_digest(0x11),
                    lineage(0x22),
                    journal_digest(0x33),
                    1,
                    authority_id(0x44),
                    ISSUER_KEY_ID,
                    &signing_key().verifying_key().to_bytes(),
                )
                .is_err(),
            "field {index} tamper must fail verification"
        );
    }

    let revision = replace_field(&bytes, 5, &2_u64.to_be_bytes());
    assert!(TenantRootCreationCapabilityV1::decode_canonical_bytes(&revision).is_err());

    let mut signature = bytes.clone();
    signature[fields[11].start] ^= 1;
    let decoded_signature = TenantRootCreationCapabilityV1::decode_canonical_bytes(&signature)
        .expect("signature tamper remains structurally valid");
    assert_eq!(
        decoded_signature
            .verify(
                identity_digest(0x11),
                lineage(0x22),
                journal_digest(0x33),
                1,
                authority_id(0x44),
                ISSUER_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("signature tamper")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    for (index, value) in [(8, 1_001_u64), (9, 1_031_u64)] {
        let tampered = replace_field(&bytes, index, &value.to_be_bytes());
        let decoded = TenantRootCreationCapabilityV1::decode_canonical_bytes(&tampered)
            .expect("timestamp tamper remains structurally valid");
        assert_eq!(
            verify_result(&decoded)
                .expect_err("timestamp tamper must fail signature verification")
                .code(),
            RouterAbDerivationErrorCode::OutputVerificationFailed,
            "field {index} tamper must fail verification",
        );
    }

    let mut issuer = bytes.clone();
    issuer[fields[10].start] ^= 1;
    let decoded_issuer = TenantRootCreationCapabilityV1::decode_canonical_bytes(&issuer)
        .expect("issuer tamper remains structurally valid");
    assert_eq!(
        verify_result(&decoded_issuer)
            .expect_err("issuer tamper must fail expected-issuer binding")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootCreationCapabilityV1::decode_canonical_bytes(&trailing).is_err());
    assert!(
        TenantRootCreationCapabilityV1::decode_canonical_bytes(&bytes[..bytes.len() - 1]).is_err()
    );
    assert!(TenantRootCreationCapabilityV1::decode_canonical_bytes(&[]).is_err());
    assert!(
        TenantRootCreationCapabilityV1::decode_canonical_bytes(&vec![
            0;
            TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}

#[test]
fn signing_rejects_invalid_lifetime_and_nonce() {
    assert!(sign_capability_with_times(0, 1).is_err());
    assert!(sign_capability_with_times(1_000, 1_000).is_err());
    assert!(sign_capability_with_times(1_000, 999).is_err());
    assert!(sign_capability_with_times(1_000, 1_000 + TENANT_ROOT_MAX_LIFETIME_MS_V1 + 1).is_err());
    assert!(sign_capability_with_times(1_000, 1_000 + TENANT_ROOT_MAX_LIFETIME_MS_V1).is_ok());
    assert!(TenantRootCreationCapabilityNonceV1::from_bytes([0; 32]).is_err());
}

#[test]
fn verified_freshness_is_separate_from_signature_and_binding_verification() {
    let raw = capability();
    let expired_verified = raw
        .verify(
            identity_digest(0x11),
            lineage(0x22),
            journal_digest(0x33),
            1,
            authority_id(0x44),
            ISSUER_KEY_ID,
            &signing_key().verifying_key().to_bytes(),
        )
        .expect("expired capability still authenticates");
    assert!(expired_verified.require_fresh(999).is_err());
    assert!(expired_verified.require_fresh(1_000).is_ok());
    assert!(expired_verified.require_fresh(1_015).is_ok());
    assert!(expired_verified.require_fresh(1_030).is_ok());
    assert!(expired_verified.require_fresh(1_031).is_err());
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
