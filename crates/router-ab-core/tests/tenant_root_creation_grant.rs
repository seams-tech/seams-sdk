//! Genesis authorization contract.
//!
//! A creation grant is the one R120 artifact that cannot be derived from
//! authoritative state, so it is the only place an external authority speaks.
//! These fix what it may say, and what it must refuse.

use ed25519_dalek::SigningKey;
use router_ab_core::{
    RouterAbDerivationErrorCode, TenantRootCreationGrantNonceV1, TenantRootCreationGrantV1,
    TenantRootCustodyLineageId, TenantRootIdentityV1, TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1,
    TENANT_ROOT_CREATION_GRANT_OPERATION_LABEL_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const GRANT_KEY_ID: &str = "provisioning-authority-v1";
const GRANT_SEED: [u8; 32] = [0x61; 32];
const OTHER_SEED: [u8; 32] = [0x62; 32];
const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;

fn verifying_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn identity(org: &str) -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new(org, "project-2", "production", "root-main", "v3")
        .expect("tenant-root identity")
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("custody lineage")
}

fn nonce(seed: u8) -> TenantRootCreationGrantNonceV1 {
    TenantRootCreationGrantNonceV1::from_bytes([seed; 32]).expect("grant nonce")
}

fn grant(org: &str, lineage_seed: u8, nonce_seed: u8) -> TenantRootCreationGrantV1 {
    TenantRootCreationGrantV1::sign(
        &identity(org),
        lineage(lineage_seed),
        nonce(nonce_seed),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        GRANT_KEY_ID,
        &GRANT_SEED,
    )
    .expect("signed grant")
}

#[test]
fn sign_decode_verify_round_trip_exposes_only_the_authorized_scope() {
    let signed = grant("org-1", 0x22, 0x33);
    let bytes = signed.canonical_bytes().expect("canonical grant");
    let decoded = TenantRootCreationGrantV1::decode_canonical_bytes(&bytes).expect("decoded grant");
    assert_eq!(decoded, signed);
    assert_eq!(decoded.grant_key_id(), GRANT_KEY_ID);

    let verified = decoded
        .verify(GRANT_KEY_ID, &verifying_key(&GRANT_SEED))
        .expect("verified grant");
    assert_eq!(verified.identity(), &identity("org-1"));
    assert_eq!(
        verified.identity_digest(),
        identity("org-1").digest().expect("identity digest")
    );
    assert_eq!(verified.custody_lineage(), lineage(0x22));
    assert_eq!(verified.nonce(), nonce(0x33));
    assert_eq!(verified.grant_key_id(), GRANT_KEY_ID);
    assert_eq!(verified.issued_at_ms(), ISSUED_AT_MS);
    assert_eq!(verified.expires_at_ms(), EXPIRES_AT_MS);
    // The operation label is fixed by the protocol, not carried as a choice.
    assert_eq!(
        TENANT_ROOT_CREATION_GRANT_OPERATION_LABEL_V1,
        "tenant_root_authorize_create_v1"
    );
}

#[test]
fn the_verifier_supplies_its_own_authority_and_cross_authority_fails_closed() {
    let signed = grant("org-1", 0x22, 0x33);

    // Right key id, untrusted key.
    assert_eq!(
        signed
            .verify(GRANT_KEY_ID, &verifying_key(&OTHER_SEED))
            .expect_err("untrusted authority")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    // Trusted key, but the verifier expects a different authority id. A
    // verifier that took the id from the grant would accept this.
    assert_eq!(
        signed
            .verify("provisioning-authority-v2", &verifying_key(&GRANT_SEED))
            .expect_err("foreign expected key id")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    // A grant signed by a different authority does not verify under ours, even
    // when it names the same key id.
    let forged = TenantRootCreationGrantV1::sign(
        &identity("org-1"),
        lineage(0x22),
        nonce(0x33),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        GRANT_KEY_ID,
        &OTHER_SEED,
    )
    .expect("forged grant");
    assert!(forged
        .verify(GRANT_KEY_ID, &verifying_key(&GRANT_SEED))
        .is_err());
}

#[test]
fn grants_do_not_cross_tenant_lineage_or_nonce() {
    let base = grant("org-1", 0x22, 0x33);
    let key = verifying_key(&GRANT_SEED);
    let verified = base.verify(GRANT_KEY_ID, &key).expect("verified");

    for (label, other) in [
        ("tenant", grant("org-2", 0x22, 0x33)),
        ("lineage", grant("org-1", 0x23, 0x33)),
        ("nonce", grant("org-1", 0x22, 0x34)),
    ] {
        let other_verified = other.verify(GRANT_KEY_ID, &key).expect("verified");
        let differs = other_verified.identity() != verified.identity()
            || other_verified.custody_lineage() != verified.custody_lineage()
            || other_verified.nonce() != verified.nonce();
        assert!(differs, "{label} must not be interchangeable");
        // Distinct authorizations produce distinct wires and digests, so a
        // consumed grant cannot be replayed as a different authorization.
        assert_ne!(
            other.canonical_bytes().expect("bytes"),
            base.canonical_bytes().expect("bytes")
        );
        assert_ne!(
            other.digest().expect("digest"),
            base.digest().expect("digest")
        );
    }
}

#[test]
fn the_authorized_window_is_bounded_and_enforced() {
    let signed = grant("org-1", 0x22, 0x33);
    let verified = signed
        .verify(GRANT_KEY_ID, &verifying_key(&GRANT_SEED))
        .expect("verified");

    assert!(verified.require_fresh(ISSUED_AT_MS + 1).is_ok());
    assert!(verified.require_fresh(EXPIRES_AT_MS - 1).is_ok());
    assert!(verified.require_fresh(ISSUED_AT_MS).is_err());
    assert!(verified.require_fresh(EXPIRES_AT_MS).is_err());
    assert!(verified.require_fresh(0).is_err());

    // A window longer than the frozen maximum cannot be signed at all.
    assert!(TenantRootCreationGrantV1::sign(
        &identity("org-1"),
        lineage(0x22),
        nonce(0x33),
        ISSUED_AT_MS,
        ISSUED_AT_MS + TENANT_ROOT_MAX_LIFETIME_MS_V1 + 1,
        GRANT_KEY_ID,
        &GRANT_SEED,
    )
    .is_err());
    // Exactly the maximum is allowed.
    assert!(TenantRootCreationGrantV1::sign(
        &identity("org-1"),
        lineage(0x22),
        nonce(0x33),
        ISSUED_AT_MS,
        ISSUED_AT_MS + TENANT_ROOT_MAX_LIFETIME_MS_V1,
        GRANT_KEY_ID,
        &GRANT_SEED,
    )
    .is_ok());
    // Zero issue time, and an expiry at or before issue, fail closed.
    for (issued, expires) in [
        (0, EXPIRES_AT_MS),
        (ISSUED_AT_MS, ISSUED_AT_MS),
        (ISSUED_AT_MS, ISSUED_AT_MS - 1),
    ] {
        assert!(TenantRootCreationGrantV1::sign(
            &identity("org-1"),
            lineage(0x22),
            nonce(0x33),
            issued,
            expires,
            GRANT_KEY_ID,
            &GRANT_SEED,
        )
        .is_err());
    }
}

#[test]
fn a_zero_nonce_is_rejected() {
    assert!(TenantRootCreationGrantNonceV1::from_bytes([0; 32]).is_err());
    assert!(TenantRootCreationGrantNonceV1::from_bytes([1; 32]).is_ok());
}

#[test]
fn every_grant_wire_mutation_fails_closed() {
    let signed = grant("org-1", 0x22, 0x33);
    let bytes = signed.canonical_bytes().expect("canonical grant");
    let key = verifying_key(&GRANT_SEED);

    // Trailing bytes.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TenantRootCreationGrantV1::decode_canonical_bytes(&trailing).is_err());

    // Every truncation prefix.
    for end in 0..bytes.len() {
        assert!(
            TenantRootCreationGrantV1::decode_canonical_bytes(&bytes[..end]).is_err(),
            "truncation at {end} must fail closed"
        );
    }

    // Every single-byte mutation either fails to decode or fails to verify.
    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 0xff;
        assert!(
            TenantRootCreationGrantV1::decode_canonical_bytes(&mutated)
                .ok()
                .and_then(|grant| grant.verify(GRANT_KEY_ID, &key).ok())
                .is_none(),
            "mutated byte {index} must fail closed"
        );
    }

    // Empty and oversized wires.
    assert!(TenantRootCreationGrantV1::decode_canonical_bytes(&[]).is_err());
    assert!(TenantRootCreationGrantV1::decode_canonical_bytes(&vec![
        0u8;
        TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1
            + 1
    ])
    .is_err());
}
