use ed25519_yao_generator::{
    Ed25519YaoApplicationBindingErrorV1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingFieldV1, Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1,
    ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
    ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
};

fn facts(
    wallet_id: &str,
    signing_key_id: &str,
    signing_root_id: &str,
    key_creation_signer_slot: u32,
) -> Ed25519YaoApplicationBindingFactsV1 {
    Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse(wallet_id).expect("valid wallet id"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse(signing_key_id)
            .expect("valid signing key id"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse(signing_root_id)
            .expect("valid signing root id"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(key_creation_signer_slot)
            .expect("valid key-creation signer slot"),
    )
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let encoded = core::str::from_utf8(pair).expect("hex is UTF-8");
            u8::from_str_radix(encoded, 16).expect("valid hex byte")
        })
        .collect()
}

#[test]
fn domain_labels_encoding_and_digest_are_frozen() {
    assert_eq!(
        ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1,
        b"seams/router-ab/ed25519-yao/application-binding/v1"
    );
    assert_eq!(
        ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
        b"walletId"
    );
    assert_eq!(
        ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
        b"nearEd25519SigningKeyId"
    );
    assert_eq!(
        ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
        b"signingRootId"
    );
    assert_eq!(
        ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
        b"keyCreationSignerSlot"
    );

    let binding = facts(
        "wallet-fixture",
        "ed25519ks_fixture",
        "project-fixture:env-fixture",
        1,
    );
    let expected_encoding = decode_hex(concat!(
        "000000327365616d732f726f757465722d61622f656432353531392d79616f2f6170706c6963",
        "6174696f6e2d62696e64696e672f76310000000877616c6c657449640000000e77616c6c6574",
        "2d66697874757265000000176e656172456432353531395369676e696e674b6579496400000011",
        "656432353531396b735f666978747572650000000d7369676e696e67526f6f7449640000001b70",
        "726f6a6563742d666978747572653a656e762d66697874757265000000156b65794372656174",
        "696f6e5369676e6572536c6f740000000400000001"
    ));
    let expected_digest =
        decode_hex("b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121");

    assert_eq!(binding.encode().as_bytes(), expected_encoding);
    assert_eq!(binding.digest().as_bytes().as_slice(), expected_digest);
}

#[test]
fn every_immutable_fact_changes_the_digest() {
    let baseline = facts("wallet", "ed25519ks_key", "project:env", 1)
        .digest()
        .as_bytes()
        .to_owned();
    let changed_wallet = facts("wallet-2", "ed25519ks_key", "project:env", 1);
    let changed_key = facts("wallet", "ed25519ks_key_2", "project:env", 1);
    let changed_root = facts("wallet", "ed25519ks_key", "project:env-2", 1);
    let changed_slot = facts("wallet", "ed25519ks_key", "project:env", 2);

    assert_ne!(baseline, *changed_wallet.digest().as_bytes());
    assert_ne!(baseline, *changed_key.digest().as_bytes());
    assert_ne!(baseline, *changed_root.digest().as_bytes());
    assert_ne!(baseline, *changed_slot.digest().as_bytes());
}

#[test]
fn empty_non_ascii_whitespace_and_control_identifiers_are_rejected() {
    assert_eq!(
        Ed25519YaoApplicationBindingWalletIdV1::parse(""),
        Err(Ed25519YaoApplicationBindingErrorV1::Empty {
            field: Ed25519YaoApplicationBindingFieldV1::WalletId,
        })
    );
    assert_eq!(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet id"),
        Err(
            Ed25519YaoApplicationBindingErrorV1::InvalidIdentifierGrammar {
                field: Ed25519YaoApplicationBindingFieldV1::WalletId,
            }
        )
    );
    assert_eq!(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet\0id"),
        Err(
            Ed25519YaoApplicationBindingErrorV1::InvalidIdentifierGrammar {
                field: Ed25519YaoApplicationBindingFieldV1::WalletId,
            }
        )
    );
    assert_eq!(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallét"),
        Err(
            Ed25519YaoApplicationBindingErrorV1::InvalidIdentifierGrammar {
                field: Ed25519YaoApplicationBindingFieldV1::WalletId,
            }
        )
    );
    assert_eq!(
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_key\n"),
        Err(
            Ed25519YaoApplicationBindingErrorV1::InvalidIdentifierGrammar {
                field: Ed25519YaoApplicationBindingFieldV1::NearEd25519SigningKeyId,
            }
        )
    );
    assert_eq!(
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:\u{2003}env"),
        Err(
            Ed25519YaoApplicationBindingErrorV1::InvalidIdentifierGrammar {
                field: Ed25519YaoApplicationBindingFieldV1::SigningRootId,
            }
        )
    );
    assert_eq!(
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(0),
        Err(Ed25519YaoApplicationBindingErrorV1::ZeroKeyCreationSignerSlot)
    );
}
