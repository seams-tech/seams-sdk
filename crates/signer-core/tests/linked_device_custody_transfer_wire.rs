#![cfg(feature = "linked-device-custody-transfer")]

//! The Rust half of the linked-device custody transfer wire contract.
//!
//! `LinkedDeviceCustodyTransferBindingV1` is authenticated as AEAD additional
//! data, so its serialized field names, nesting, and the absence of extras are
//! part of the cryptography rather than a formatting detail: a drift between
//! the TypeScript serializer and this struct would not be a parse warning, it
//! would be a transfer that silently fails to open on the other device.
//!
//! Both sides pin the same literal. The TypeScript half is
//! `tests/unit/linkedDeviceCustodyTransferContract.unit.test.ts`; a change on
//! either side fails here or there rather than in a browser.

use signer_core::linked_device_custody_transfer::LinkedDeviceCustodyTransferBindingV1;
use signer_core::passkey_custody::{
    PasskeyCustodySecretBindingV1, WALLET_SEED_DERIVATION_SCHEME_V1,
};

/// Byte-identical to `EXPECTED_BINDING_JSON` in the TypeScript contract test.
/// The recipient key is 32 bytes of 0x15, matching that fixture's key.
const TRANSFER_BINDING_JSON: &str = concat!(
    r#"{"walletId":"alice.testnet","enrollmentId":"enrollment:device-2","deviceId":"device:2","#,
    r#""recipientPublicKeyB64u":"FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRU","#,
    r#""binding":{"kind":"wallet_custody_seed_v1","derivationScheme":"wallet_seed_parallel_hkdf_sha256_v1"}}"#
);

#[test]
fn deserializes_the_typescript_transfer_binding_verbatim() {
    let binding: LinkedDeviceCustodyTransferBindingV1 =
        serde_json::from_str(TRANSFER_BINDING_JSON).expect("TypeScript transfer binding");
    assert_eq!(binding.wallet_id, "alice.testnet");
    assert_eq!(binding.enrollment_id, "enrollment:device-2");
    assert_eq!(binding.device_id, "device:2");
    assert_eq!(
        binding.recipient_public_key_b64u,
        "FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRU"
    );
    match binding.binding {
        PasskeyCustodySecretBindingV1::WalletCustodySeed { derivation_scheme } => {
            assert_eq!(derivation_scheme, WALLET_SEED_DERIVATION_SCHEME_V1);
        }
        other => panic!("expected the wallet custody seed binding, got {other:?}"),
    }
}

#[test]
fn re_serializes_to_the_same_bytes_the_typescript_side_sends() {
    let binding: LinkedDeviceCustodyTransferBindingV1 =
        serde_json::from_str(TRANSFER_BINDING_JSON).expect("TypeScript transfer binding");
    assert_eq!(
        serde_json::to_string(&binding).expect("serialize"),
        TRANSFER_BINDING_JSON
    );
}

#[test]
fn rejects_a_binding_carrying_any_field_the_contract_does_not_define() {
    // `deny_unknown_fields` is what stops an extra field from being dropped
    // silently on this side while the other side folded it into the AAD.
    let with_extra = TRANSFER_BINDING_JSON.replace(
        r#""binding":{"#,
        r#""keyManifestDigestB64u":"unexpected","binding":{"#,
    );
    assert!(serde_json::from_str::<LinkedDeviceCustodyTransferBindingV1>(&with_extra).is_err());

    let nested_extra = TRANSFER_BINDING_JSON.replace(
        r#""kind":"wallet_custody_seed_v1","#,
        r#""kind":"wallet_custody_seed_v1","laneId":"lane:1","#,
    );
    assert!(serde_json::from_str::<LinkedDeviceCustodyTransferBindingV1>(&nested_extra).is_err());
}

#[test]
fn rejects_a_binding_missing_any_field_the_contract_requires() {
    for omitted in [
        r#""walletId":"alice.testnet","#,
        r#""enrollmentId":"enrollment:device-2","#,
        r#""deviceId":"device:2","#,
        r#""recipientPublicKeyB64u":"FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRU","#,
    ] {
        let truncated = TRANSFER_BINDING_JSON.replace(omitted, "");
        assert!(
            serde_json::from_str::<LinkedDeviceCustodyTransferBindingV1>(&truncated).is_err(),
            "a binding without {omitted} must not deserialize"
        );
    }
}
