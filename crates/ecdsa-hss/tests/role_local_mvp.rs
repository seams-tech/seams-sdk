use ecdsa_hss::{
    context_binding, derive_client_share, derive_relayer_share_for_client_public, encode_context,
    public_transcript_digest, reconstruct_export_key, EcdsaHssStableKeyContext,
    ServerEvalOperation,
};
use signer_core::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20,
};

fn context() -> EcdsaHssStableKeyContext {
    EcdsaHssStableKeyContext::new(
        "wallet.testnet",
        "localhost",
        "ecdsa-threshold-key",
        "signing-root",
        "default",
        "evm-signing",
        "key-current",
    )
}

fn fixed_inputs() -> ([u8; 32], [u8; 32]) {
    ([0x11u8; 32], [0x22u8; 32])
}

#[test]
fn context_uses_wallet_and_rp_identity() {
    let context = context();
    let encoded = encode_context(&context).expect("context encoding");
    let encoded_text = String::from_utf8_lossy(&encoded);

    assert!(encoded.starts_with(b"ecdsa-hss:context:v2"));
    assert!(encoded_text.contains("ecdsa-hss-v2"));
    assert!(encoded_text.contains("wallet.testnet"));
    assert!(encoded_text.contains("localhost"));
}

#[test]
fn role_local_public_identity_matches_share_sum() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    assert_eq!(
        identity.context_binding32,
        context_binding(&context).unwrap()
    );
    assert_eq!(identity.context_bytes, encode_context(&context).unwrap());
    assert_eq!(
        identity.client_public_key33,
        client_share.client_public_key33
    );
    assert_eq!(
        identity.relayer_public_key33,
        relayer_share.relayer_public_key33
    );
    assert_eq!(
        identity.client_share_retry_counter,
        client_share.retry_counter
    );
    assert_eq!(
        identity.relayer_share_retry_counter,
        relayer_share.retry_counter
    );

    let summed = add_secp256k1_public_keys_33(
        &client_share.client_public_key33,
        &relayer_share.relayer_public_key33,
    )
    .expect("public key sum");
    assert_eq!(summed, identity.threshold_public_key33);

    let address = secp256k1_public_key_33_to_ethereum_address_20(&identity.threshold_public_key33)
        .expect("ethereum address");
    assert_eq!(address, identity.threshold_ethereum_address20);
}

#[test]
fn explicit_export_reconstructs_key_on_client_side() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    let export_key32 = reconstruct_export_key(&client_share, &relayer_share.x_relayer32, &identity)
        .expect("export key");
    let export_public_key33 =
        secp256k1_private_key_32_to_public_key_33(&export_key32).expect("export public key");

    assert_eq!(export_public_key33, identity.threshold_public_key33);
}

#[test]
fn export_reconstruction_rejects_public_identity_mismatch() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let (relayer_share, mut identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");
    identity.threshold_ethereum_address20 = [0x44u8; 20];

    let err = reconstruct_export_key(&client_share, &relayer_share.x_relayer32, &identity)
        .expect_err("mismatched identity must fail");
    assert!(err.message.contains("ethereum address"));
}

#[test]
fn transcript_digest_depends_on_operation() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let (_, identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    let session_digest =
        public_transcript_digest(ServerEvalOperation::SessionBootstrap, &identity).unwrap();
    let export_digest =
        public_transcript_digest(ServerEvalOperation::ExplicitKeyExport, &identity).unwrap();

    assert_ne!(session_digest, export_digest);
}

#[test]
fn invalid_inputs_are_rejected() {
    let mut invalid_context = context();
    invalid_context.wallet_id = String::new();
    assert!(encode_context(&invalid_context).is_err());

    let context = context();
    let invalid_public_key = [0u8; 33];
    derive_relayer_share_for_client_public(&context, [0x22u8; 32], &invalid_public_key, 0)
        .expect_err("invalid public key must fail");
}

#[test]
fn debug_output_redacts_secret_bearing_fields() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let (relayer_share, _) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    assert!(format!("{client_share:?}").contains("<redacted>"));
    assert!(format!("{relayer_share:?}").contains("<redacted>"));
}
