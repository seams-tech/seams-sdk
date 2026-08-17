//! The Rust↔TypeScript wire contract for wallet custody records, as a fixture.
//!
//! Each side of this boundary tests only itself, which is how the seed-binding
//! drift shipped: TypeScript emitted five fields the Rust parser had stopped
//! accepting, and both suites stayed green. This fixture is the meeting point.
//! Rust generates it from the production types and seal functions with fixed
//! inputs, asserts it byte-for-byte on every run, and the TypeScript unit test
//! (`tests/unit/walletCustodyWireContract.unit.test.ts`) parses the very same
//! file through its production parsers and rebuilds the bindings through its
//! production builders. Either side drifting from the fixture fails that side.
//!
//! Regenerate (never hand-edit):
//!
//! ```text
//! UPDATE_WALLET_CUSTODY_WIRE_FIXTURES=1 cargo test --test wire_fixtures
//! ```
//!
//! Every secret in here is deterministic test-only material.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Value};
use signer_core::passkey_custody::{
    open_wallet_custody_seed_envelope_v1, seal_wallet_custody_seed_envelope_v1,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodySecretBindingV1, WalletCustodyEnvelopeFactorV1,
    EMAIL_OTP_FACTOR_KEK_VERSION_V1, PASSKEY_CUSTODY_KEK_VERSION_V1,
    WALLET_SEED_DERIVATION_SCHEME_V1,
};
use signer_core::wallet_recovery_custody::{
    derive_wallet_recovery_key_id_v1, seal_wallet_recovery_entry_v1,
    seal_wallet_recovery_manifest_kek_v1, WALLET_RECOVERY_CODE_COUNT,
};
use signer_core::wallet_seed_derivation::{
    establish_wallet_key_set_manifest_v1, WalletKeySetKindV1, WalletKeySetManifestV1,
};
use wallet_custody_ceremony::ceremony::{
    CeremonySeedHeldV1, EstablishedCustodyRecordsV1, EvmFamilyPublicFactsRecordV1,
    SealedRecoveryWrapRecordV1, WalletCustodyCommitPayloadV1,
};

const UPDATE_ENV: &str = "UPDATE_WALLET_CUSTODY_WIRE_FIXTURES";
const FIXTURE_VERSION: &str = "wallet_custody_wire_v1";
const TEST_SECRET_WARNING: &str =
    "Deterministic test-only secret material. Do not use outside tests.";

const WALLET_ID: &str = "alice.testnet";
const ENVELOPE_ID: &str = "wallet-custody-envelope-1";
const ENROLLMENT_ID: &str = "enrollment-1";
const ENROLLMENT_SEAL_KEY_VERSION: &str = "seal-v1";
const RP_ID: &str = "example.localhost";
const EVM_SLOT_ID: &str = "wallet-key:evm-family:alice.testnet:root-1:v1";
const NEAR_SIGNING_KEY_ID: &str = "near-ed25519-key-1";

const SEED: [u8; 32] = [0x13; 32];
const FACTOR_SECRET: [u8; 32] = [0x07; 32];
const MANIFEST_KEK: [u8; 32] = [0x21; 32];
const ENVELOPE_NONCE: [u8; 12] = [0x0a; 12];
const ENTRY_NONCE: [u8; 12] = [0x0b; 12];
const CREDENTIAL_ID: [u8; 16] = [0x5c; 16];
const ECDSA_READY_STATE_BLOB: [u8; 4] = [1, 2, 3, 4];
const NEAR_REGISTERED_PUBLIC_KEY: [u8; 32] = [0x2f; 32];

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("wallet-custody-wire-v1.json")
}

fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn decode(value: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(value).expect("fixture base64url")
}

fn evm_client_root_public_key33() -> [u8; 33] {
    let mut key = [0x11u8; 33];
    key[0] = 0x02;
    key
}

fn wrap_nonce(index: usize) -> [u8; 12] {
    [0x30 + index as u8; 12]
}

fn recovery_code_bytes(index: usize) -> Vec<u8> {
    vec![index as u8 + 1; 20]
}

/// The real derivation, not a production-shaped stand-in.
///
/// This is the cross-boundary vector: TypeScript's `deriveWalletRecoveryKeyId`
/// hashes the same frozen tuple, so the fixture pins that both sides compute
/// one id from a code and a wallet. The previous stand-in hashed an index and
/// only *looked* right, which is what let the two sides disagree unnoticed.
fn recovery_key_id(index: usize) -> String {
    derive_wallet_recovery_key_id_v1(WALLET_ID, &recovery_code_bytes(index))
        .expect("recovery key id")
}

fn email_otp_binding() -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: WALLET_ID.to_string(),
        envelope_id: ENVELOPE_ID.to_string(),
        factor: WalletCustodyEnvelopeFactorV1::EmailOtp {
            enrollment_id: ENROLLMENT_ID.to_string(),
            enrollment_seal_key_version: ENROLLMENT_SEAL_KEY_VERSION.to_string(),
            kek_version: EMAIL_OTP_FACTOR_KEK_VERSION_V1.to_string(),
        },
        envelope_revision: 1,
        binding: PasskeyCustodySecretBindingV1::WalletCustodySeed {
            derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.to_string(),
        },
    }
}

fn passkey_binding() -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: WALLET_ID.to_string(),
        envelope_id: ENVELOPE_ID.to_string(),
        factor: WalletCustodyEnvelopeFactorV1::Passkey {
            rp_id: RP_ID.to_string(),
            credential_id_b64u: b64u(&CREDENTIAL_ID),
            kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.to_string(),
        },
        envelope_revision: 1,
        binding: PasskeyCustodySecretBindingV1::WalletCustodySeed {
            derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.to_string(),
        },
    }
}

/// The establishing run's payload, sealed with fixed nonces so the ciphertext
/// is byte-stable. The struct fields are the production ones: a field added to
/// or removed from the payload cannot leave this fixture unchanged, because
/// serde serializes the struct, not a hand-written map.
fn establish_commit_payload() -> WalletCustodyCommitPayloadV1 {
    let binding = email_otp_binding();
    let sealed =
        seal_wallet_custody_seed_envelope_v1(&FACTOR_SECRET, &binding, &ENVELOPE_NONCE, &SEED)
            .expect("seal fixture envelope");

    let mut wraps = Vec::with_capacity(WALLET_RECOVERY_CODE_COUNT);
    for index in 0..WALLET_RECOVERY_CODE_COUNT {
        let wrap = seal_wallet_recovery_manifest_kek_v1(
            &recovery_code_bytes(index),
            WALLET_ID,
            &recovery_key_id(index),
            &wrap_nonce(index),
            &MANIFEST_KEK,
        )
        .expect("seal fixture code wrap");
        wraps.push(SealedRecoveryWrapRecordV1 {
            recovery_key_id: recovery_key_id(index),
            nonce_b64u: b64u(&wrap_nonce(index)),
            ciphertext_b64u: wrap.ciphertext_b64u(),
            aad_hash_b64u: wrap.aad_hash_b64u(),
        });
    }
    let entry = seal_wallet_recovery_entry_v1(&MANIFEST_KEK, WALLET_ID, &ENTRY_NONCE, &SEED)
        .expect("seal fixture recovery entry");

    let manifest = establish_wallet_key_set_manifest_v1(&WalletKeySetManifestV1::EvmFamilyEcdsa {
        wallet_id: WALLET_ID.to_string(),
        evm_family_signing_key_slot_id: EVM_SLOT_ID.to_string(),
        client_root_public_key33: evm_client_root_public_key33(),
    })
    .expect("fixture EVM manifest");

    WalletCustodyCommitPayloadV1 {
        wallet_id: WALLET_ID.to_string(),
        key_set: WalletKeySetKindV1::EvmFamilyEcdsa.as_str().to_string(),
        key_manifest_digest_b64u: manifest.digest_b64u(),
        established_custody: Some(EstablishedCustodyRecordsV1 {
            envelope_id: ENVELOPE_ID.to_string(),
            envelope_binding_json: serde_json::to_string(&binding).expect("binding JSON"),
            envelope_nonce_b64u: b64u(&ENVELOPE_NONCE),
            sealed_custody_secret_b64u: sealed.ciphertext_b64u(),
            envelope_aad_hash_b64u: sealed.aad_hash_b64u(),
            envelope_ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
            recovery_manifest_kek_wraps: wraps,
            recovery_entry_nonce_b64u: b64u(&ENTRY_NONCE),
            recovery_entry_ciphertext_b64u: entry.ciphertext_b64u(),
            recovery_entry_aad_hash_b64u: entry.aad_hash_b64u(),
        }),
        recovery_replacement_envelope: None,
        registered_public_key_b64u: None,
        // An EVM run seals no Ed25519 continuity cache.
        ed25519_local_material_b64u: None,
        ed25519_local_material_nonce_b64u: None,
        ed25519_application_binding_digest_b64u: None,
        client_root_public_key33_b64u: Some(b64u(&evm_client_root_public_key33())),
        ecdsa_ready_state_blob_b64u: Some(b64u(&ECDSA_READY_STATE_BLOB)),
        ecdsa_public_facts: Some(EvmFamilyPublicFactsRecordV1 {
            context_binding32_b64u: b64u(&[0x31; 32]),
            derivation_client_share_public_key33_b64u: b64u(&evm_client_root_public_key33()),
            client_verifying_share33_b64u: b64u(&evm_client_root_public_key33()),
            relayer_public_key33_b64u: b64u(&evm_client_root_public_key33()),
            group_public_key33_b64u: b64u(&evm_client_root_public_key33()),
            ethereum_address: "0x2929292929292929292929292929292929292929".to_string(),
            client_share_retry_counter: 0,
            relayer_share_retry_counter: 0,
        }),
    }
}

const NEAR_LOCAL_MATERIAL: [u8; 89] = [0x4c; 89];
const NEAR_LOCAL_MATERIAL_NONCE: [u8; 12] = [0x4d; 12];

/// A joining NEAR run's payload: a manifest digest and its registered key,
/// no custody records.
fn join_commit_payload() -> WalletCustodyCommitPayloadV1 {
    let manifest = establish_wallet_key_set_manifest_v1(&WalletKeySetManifestV1::NearEd25519 {
        wallet_id: WALLET_ID.to_string(),
        near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID.to_string(),
        registered_public_key: NEAR_REGISTERED_PUBLIC_KEY,
    })
    .expect("fixture NEAR manifest");

    WalletCustodyCommitPayloadV1 {
        wallet_id: WALLET_ID.to_string(),
        key_set: WalletKeySetKindV1::NearEd25519.as_str().to_string(),
        key_manifest_digest_b64u: manifest.digest_b64u(),
        established_custody: None,
        recovery_replacement_envelope: None,
        registered_public_key_b64u: Some(b64u(&NEAR_REGISTERED_PUBLIC_KEY)),
        // Deterministic stand-ins: a real seal draws a random nonce, which a
        // byte-compared fixture cannot carry.
        ed25519_local_material_b64u: Some(b64u(&NEAR_LOCAL_MATERIAL)),
        ed25519_local_material_nonce_b64u: Some(b64u(&NEAR_LOCAL_MATERIAL_NONCE)),
        ed25519_application_binding_digest_b64u: Some(b64u(&[0x5b; 32])),
        client_root_public_key33_b64u: None,
        ecdsa_ready_state_blob_b64u: None,
        // A NEAR run has no EVM identity.
        ecdsa_public_facts: None,
    }
}

/// What the TypeScript driver's `custodyJson` carries to a joining run —
/// the shape `JoinCustodyWireV1` parses at the wasm boundary.
fn join_custody_wire(payload: &WalletCustodyCommitPayloadV1) -> Value {
    let custody = payload
        .established_custody
        .as_ref()
        .expect("establishing payload carries custody records");
    json!({
        "envelopeBinding": serde_json::from_str::<Value>(&custody.envelope_binding_json)
            .expect("binding JSON"),
        "nonceB64u": custody.envelope_nonce_b64u,
        "sealedCustodySecretB64u": custody.sealed_custody_secret_b64u,
        "aadHashB64u": custody.envelope_aad_hash_b64u,
        "ciphertextDigestB64u": custody.envelope_ciphertext_digest_b64u,
    })
}

fn build_fixture_doc() -> Value {
    let establish = establish_commit_payload();
    let join_custody = join_custody_wire(&establish);
    json!({
        "fixtureVersion": FIXTURE_VERSION,
        "warning": TEST_SECRET_WARNING,
        "inputs": {
            "walletId": WALLET_ID,
            "envelopeId": ENVELOPE_ID,
            "seedB64u": b64u(&SEED),
            "factorSecretB64u": b64u(&FACTOR_SECRET),
            "manifestKekB64u": b64u(&MANIFEST_KEK),
            "enrollmentId": ENROLLMENT_ID,
            "enrollmentSealKeyVersion": ENROLLMENT_SEAL_KEY_VERSION,
            "rpId": RP_ID,
            "credentialIdB64u": b64u(&CREDENTIAL_ID),
            "evmFamilySigningKeySlotId": EVM_SLOT_ID,
            "nearEd25519SigningKeyId": NEAR_SIGNING_KEY_ID,
            "recoveryCodes": (0..WALLET_RECOVERY_CODE_COUNT)
                .map(|index| json!({
                    "recoveryKeyId": recovery_key_id(index),
                    "codeBytesB64u": b64u(&recovery_code_bytes(index)),
                }))
                .collect::<Vec<_>>(),
        },
        "establishCommitPayload": serde_json::to_value(&establish).expect("establish payload"),
        "joinCommitPayload": serde_json::to_value(join_commit_payload()).expect("join payload"),
        "passkeyEnvelopeBinding": serde_json::to_value(passkey_binding()).expect("passkey binding"),
        "joinCustody": join_custody,
    })
}

#[test]
fn the_wallet_custody_wire_fixture_is_reproduced_and_live() {
    let path = fixture_path();
    let rebuilt = build_fixture_doc();

    if std::env::var(UPDATE_ENV).as_deref() == Ok("1") {
        let generated = serde_json::to_string_pretty(&rebuilt).expect("serialize fixture");
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture dir");
        std::fs::write(&path, format!("{generated}\n")).expect("write fixture");
        return;
    }

    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", path.display());
        }))
        .expect("parse fixture");

    // Byte-level contract: the production types with fixed inputs reproduce the
    // checked-in fixture exactly. A drifted field name, a renamed variant, or a
    // changed encoding all land here.
    for section in [
        "fixtureVersion",
        "warning",
        "inputs",
        "establishCommitPayload",
        "joinCommitPayload",
        "passkeyEnvelopeBinding",
        "joinCustody",
    ] {
        assert_eq!(
            stored[section], rebuilt[section],
            "fixture section {section} drifted; regenerate with {UPDATE_ENV}=1 only if the \
             change is an intended wire-contract change on BOTH sides"
        );
    }

    // Both binding variants parse under the deny-unknown-fields parser — the
    // exact gate that rejected TypeScript's output during the seed-binding
    // drift.
    let stored_binding = serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(
        stored["establishCommitPayload"]["establishedCustody"]["envelopeBindingJson"]
            .as_str()
            .expect("embedded binding JSON"),
    )
    .expect("email OTP binding parses");
    assert_eq!(stored_binding, email_otp_binding());
    let stored_passkey = serde_json::from_value::<PasskeyCustodyEnvelopeBindingV1>(
        stored["passkeyEnvelopeBinding"].clone(),
    )
    .expect("passkey binding parses");
    assert_eq!(stored_passkey, passkey_binding());

    // The fixture envelope is live, not just well-shaped: the factor secret
    // opens it back to the seed, and a joining ceremony accepts it.
    let (opened, admitted) = open_wallet_custody_seed_envelope_v1(
        &FACTOR_SECRET,
        &stored_binding,
        &decode(stored["joinCustody"]["nonceB64u"].as_str().expect("nonce")),
        &decode(
            stored["joinCustody"]["sealedCustodySecretB64u"]
                .as_str()
                .expect("ciphertext"),
        ),
        &decode(
            stored["joinCustody"]["aadHashB64u"]
                .as_str()
                .expect("aad hash"),
        ),
        &decode(
            stored["joinCustody"]["ciphertextDigestB64u"]
                .as_str()
                .expect("ciphertext digest"),
        ),
    )
    .expect("fixture envelope opens");
    assert_eq!(opened.as_slice(), &SEED);
    assert_eq!(admitted.wallet_id(), WALLET_ID);

    CeremonySeedHeldV1::join_existing_custody(
        &FACTOR_SECRET,
        &stored_binding,
        &decode(stored["joinCustody"]["nonceB64u"].as_str().expect("nonce")),
        &decode(
            stored["joinCustody"]["sealedCustodySecretB64u"]
                .as_str()
                .expect("ciphertext"),
        ),
        &decode(
            stored["joinCustody"]["aadHashB64u"]
                .as_str()
                .expect("aad hash"),
        ),
        &decode(
            stored["joinCustody"]["ciphertextDigestB64u"]
                .as_str()
                .expect("ciphertext digest"),
        ),
    )
    .expect("a joining ceremony accepts the fixture custody");
}
