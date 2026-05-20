use ecdsa_hss::{
    context_binding_v1, derive_client_share_v1, derive_relayer_share_for_client_public_v1,
    encode_context_v1, export_authorization_digest_v1, public_transcript_digest_v1,
    reconstruct_export_key_v1, EcdsaHssStableKeyContextV1, ExplicitExportAuthorizationV1,
    PublicIdentityV1, ServerEvalOperationV1,
};
use signer_core::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_public_key_33_to_ethereum_address_20,
};

fn context() -> EcdsaHssStableKeyContextV1 {
    EcdsaHssStableKeyContextV1::new(
        "parity.test.near",
        "parity-subject",
        "ehss-parity",
        "parity-root",
        "root-v1",
        "evm-signing",
        "v1",
    )
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("valid hex")
        .try_into()
        .expect("32-byte hex")
}

#[test]
fn context_encoding_matches_evm_family_scope() {
    let context = context();
    let bytes = encode_context_v1(&context).expect("context");
    assert!(bytes
        .windows(ecdsa_hss::ECDSA_HSS_V1_SCHEME_ID.len())
        .any(|window| window == ecdsa_hss::ECDSA_HSS_V1_SCHEME_ID.as_bytes()));
    assert!(bytes
        .windows(ecdsa_hss::ECDSA_HSS_V1_CURVE.len())
        .any(|window| window == ecdsa_hss::ECDSA_HSS_V1_CURVE.as_bytes()));
    assert!(bytes
        .windows("evm-family".len())
        .any(|window| window == b"evm-family"));
    assert_eq!(context_binding_v1(&context), context_binding_v1(&context));
}

#[test]
fn role_local_identity_matches_public_key_addition() {
    let context = context();
    let client_share = derive_client_share_v1(&context, [0x11u8; 32]).expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public_v1(
        &context,
        [0x22u8; 32],
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    let threshold_public_key33 = add_secp256k1_public_keys_33(
        &client_share.client_public_key33,
        &relayer_share.relayer_public_key33,
    )
    .expect("public key sum");
    let address20 =
        secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33).expect("address");

    assert_eq!(
        identity.threshold_public_key33.as_slice(),
        threshold_public_key33
    );
    assert_eq!(identity.threshold_ethereum_address20.as_slice(), address20);
    assert_eq!(
        identity.client_share_retry_counter,
        client_share.retry_counter
    );
    assert_eq!(
        identity.relayer_share_retry_counter,
        relayer_share.retry_counter
    );
}

#[test]
fn role_local_derivation_is_deterministic() {
    let context = context();
    let first_client = derive_client_share_v1(&context, [0x33u8; 32]).expect("first client");
    let second_client = derive_client_share_v1(&context, [0x33u8; 32]).expect("second client");
    assert_eq!(first_client, second_client);

    let first_relayer = derive_relayer_share_for_client_public_v1(
        &context,
        [0x44u8; 32],
        &first_client.client_public_key33,
        first_client.retry_counter,
    )
    .expect("first relayer");
    let second_relayer = derive_relayer_share_for_client_public_v1(
        &context,
        [0x44u8; 32],
        &second_client.client_public_key33,
        second_client.retry_counter,
    )
    .expect("second relayer");
    assert_eq!(first_relayer, second_relayer);
}

#[test]
fn committed_fixture_context_frame_and_binding_match() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/role_local_v1.json"))
            .expect("fixture json");
    let context_json = &fixture["context"];
    let context = EcdsaHssStableKeyContextV1::new(
        context_json["wallet_session_user_id"]
            .as_str()
            .expect("wallet id"),
        context_json["subject_id"].as_str().expect("subject id"),
        context_json["ecdsa_threshold_key_id"]
            .as_str()
            .expect("threshold key id"),
        context_json["signing_root_id"]
            .as_str()
            .expect("signing root id"),
        context_json["signing_root_version"]
            .as_str()
            .expect("signing root version"),
        context_json["key_purpose"].as_str().expect("key purpose"),
        context_json["key_version"].as_str().expect("key version"),
    );

    assert_eq!(
        fixture["context_encoding_hex"]
            .as_str()
            .expect("context encoding"),
        hex::encode(encode_context_v1(&context).expect("context encoding"))
    );
    assert_eq!(
        fixture["context_binding32_hex"]
            .as_str()
            .expect("context binding"),
        hex::encode(context_binding_v1(&context).expect("context binding"))
    );

    let inputs_json = &fixture["inputs"];
    let client_share = derive_client_share_v1(
        &context,
        hex32(
            inputs_json["y_client32_le_hex"]
                .as_str()
                .expect("client root"),
        ),
    )
    .expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public_v1(
        &context,
        hex32(
            inputs_json["y_relayer32_le_hex"]
                .as_str()
                .expect("relayer root"),
        ),
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer identity");
    let public_identity = PublicIdentityV1 {
        context_bytes: encode_context_v1(&context).expect("context encoding"),
        context_binding32: context_binding_v1(&context).expect("context binding"),
        client_public_key33: identity.client_public_key33,
        relayer_public_key33: identity.relayer_public_key33,
        threshold_public_key33: identity.threshold_public_key33,
        threshold_ethereum_address20: identity.threshold_ethereum_address20,
        client_share_retry_counter: identity.client_share_retry_counter,
        relayer_share_retry_counter: identity.relayer_share_retry_counter,
    };
    let x_export32 =
        reconstruct_export_key_v1(&client_share, &relayer_share.x_relayer32, &public_identity)
            .expect("export key");
    let derived_json = &fixture["derived"];
    assert_eq!(
        derived_json["x_client32_hex"].as_str().expect("x client"),
        hex::encode(client_share.x_client32)
    );
    assert_eq!(
        derived_json["x_relayer32_hex"].as_str().expect("x relayer"),
        hex::encode(relayer_share.x_relayer32)
    );
    assert_eq!(
        derived_json["mapped_client_share32_hex"]
            .as_str()
            .expect("mapped client share"),
        hex::encode(client_share.mapped_client_share32)
    );
    assert_eq!(
        derived_json["mapped_relayer_share32_hex"]
            .as_str()
            .expect("mapped relayer share"),
        hex::encode(relayer_share.mapped_relayer_share32)
    );
    assert_eq!(
        derived_json["x_export32_hex"].as_str().expect("export key"),
        hex::encode(x_export32)
    );
    let authorization_json = &fixture["export_authorization"];
    let authorization = ExplicitExportAuthorizationV1 {
        wallet_session_user_id: authorization_json["wallet_session_user_id"]
            .as_str()
            .expect("wallet id")
            .to_string(),
        ecdsa_threshold_key_id: authorization_json["ecdsa_threshold_key_id"]
            .as_str()
            .expect("threshold key id")
            .to_string(),
        client_device_id: authorization_json["client_device_id"]
            .as_str()
            .expect("client device id")
            .to_string(),
        client_session_id: authorization_json["client_session_id"]
            .as_str()
            .expect("client session id")
            .to_string(),
        relayer_key_id: authorization_json["relayer_key_id"]
            .as_str()
            .expect("relayer key id")
            .to_string(),
        export_request_nonce32: hex32(
            authorization_json["export_request_nonce32_hex"]
                .as_str()
                .expect("export nonce"),
        ),
        confirmation_digest32: hex32(
            authorization_json["confirmation_digest32_hex"]
                .as_str()
                .expect("confirmation digest"),
        ),
        authorization_digest32: hex32(
            authorization_json["authorization_digest32_hex"]
                .as_str()
                .expect("authorization digest"),
        ),
        issued_at_unix_ms: authorization_json["issued_at_unix_ms"]
            .as_u64()
            .expect("issued at"),
        expires_at_unix_ms: authorization_json["expires_at_unix_ms"]
            .as_u64()
            .expect("expires at"),
    };
    assert_eq!(
        authorization.authorization_digest32,
        export_authorization_digest_v1(
            ServerEvalOperationV1::ExplicitKeyExport,
            &public_identity,
            &authorization,
        )
        .expect("authorization digest")
    );
    assert_eq!(
        fixture["public_transcript_digest32_hex"]
            .as_str()
            .expect("public transcript digest"),
        hex::encode(
            public_transcript_digest_v1(
                ServerEvalOperationV1::ExplicitKeyExport,
                &public_identity,
            )
            .expect("public transcript digest")
        )
    );
}
