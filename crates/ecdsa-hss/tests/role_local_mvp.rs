use ecdsa_hss::shared::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20,
};
use ecdsa_hss::{
    compose_public_identity_from_public_keys, context_binding, derive_client_share,
    derive_relayer_share_for_client_public, encode_context, public_transcript_digest,
    reconstruct_export_key, EcdsaHssStableKeyContext, ServerEvalOperation,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RoleLocalFixture {
    format_version: u32,
    context: RoleLocalFixtureContext,
    context_encoding_hex: String,
    context_binding32_hex: String,
    inputs: RoleLocalFixtureInputs,
    identity: RoleLocalFixtureIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleLocalFixtureContext {
    wallet_id: String,
    rp_id: String,
    ecdsa_threshold_key_id: String,
    signing_root_id: String,
    signing_root_version: String,
    key_purpose: String,
    key_version: String,
}

impl RoleLocalFixtureContext {
    fn to_context(&self) -> EcdsaHssStableKeyContext {
        EcdsaHssStableKeyContext::new(
            self.wallet_id.clone(),
            self.rp_id.clone(),
            self.ecdsa_threshold_key_id.clone(),
            self.signing_root_id.clone(),
            self.signing_root_version.clone(),
            self.key_purpose.clone(),
            self.key_version.clone(),
        )
    }
}

#[derive(Debug, Deserialize)]
struct RoleLocalFixtureInputs {
    relayer_key_id: String,
    y_client32_le_hex: String,
    y_relayer32_le_hex: String,
}

#[derive(Debug, Deserialize)]
struct RoleLocalFixtureIdentity {
    client_public_key33_hex: String,
    relayer_public_key33_hex: String,
    threshold_public_key33_hex: String,
    threshold_ethereum_address20_hex: String,
    client_share_retry_counter: u32,
    relayer_share_retry_counter: u32,
}

fn committed_fixture() -> RoleLocalFixture {
    serde_json::from_str(include_str!("../fixtures/role_local_v2.json"))
        .expect("role_local_v2 fixture parses")
}

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

fn hex32(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("hex decodes");
    bytes.try_into().expect("32-byte fixture")
}

fn hex_vec(value: &str) -> Vec<u8> {
    hex::decode(value).expect("hex decodes")
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
fn committed_role_local_v2_vector_matches_derivation() {
    let fixture = committed_fixture();
    assert_eq!(fixture.format_version, 2);
    assert!(!fixture.inputs.relayer_key_id.trim().is_empty());

    let context = fixture.context.to_context();
    let context_encoding = encode_context(&context).expect("context encoding");
    assert_eq!(hex::encode(&context_encoding), fixture.context_encoding_hex);
    assert_eq!(
        hex::encode(context_binding(&context).expect("context binding")),
        fixture.context_binding32_hex
    );

    let y_client32_le = hex32(&fixture.inputs.y_client32_le_hex);
    let y_relayer32_le = hex32(&fixture.inputs.y_relayer32_le_hex);
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    assert_eq!(
        secp256k1_private_key_32_to_public_key_33(&client_share.x_client32)
            .expect("client scalar public key"),
        client_share.client_public_key33
    );
    assert_eq!(
        secp256k1_private_key_32_to_public_key_33(&relayer_share.x_relayer32)
            .expect("relayer scalar public key"),
        relayer_share.relayer_public_key33
    );
    assert_eq!(
        hex::encode(identity.client_public_key33),
        fixture.identity.client_public_key33_hex
    );
    assert_eq!(
        hex::encode(identity.relayer_public_key33),
        fixture.identity.relayer_public_key33_hex
    );
    assert_eq!(
        hex::encode(identity.threshold_public_key33),
        fixture.identity.threshold_public_key33_hex
    );
    assert_eq!(
        hex::encode(identity.threshold_ethereum_address20),
        fixture.identity.threshold_ethereum_address20_hex
    );
    assert_eq!(
        identity.client_share_retry_counter,
        fixture.identity.client_share_retry_counter
    );
    assert_eq!(
        identity.relayer_share_retry_counter,
        fixture.identity.relayer_share_retry_counter
    );

    let summed = add_secp256k1_public_keys_33(
        &client_share.client_public_key33,
        &relayer_share.relayer_public_key33,
    )
    .expect("public key sum");
    assert_eq!(
        summed,
        hex_vec(&fixture.identity.threshold_public_key33_hex)
    );

    let address = secp256k1_public_key_33_to_ethereum_address_20(&identity.threshold_public_key33)
        .expect("ethereum address");
    assert_eq!(
        address,
        hex_vec(&fixture.identity.threshold_ethereum_address20_hex)
    );

    let export_key32 = reconstruct_export_key(&client_share, &relayer_share.x_relayer32, &identity)
        .expect("export key");
    let export_public_key33 =
        secp256k1_private_key_32_to_public_key_33(&export_key32).expect("export public key");
    assert_eq!(export_public_key33, identity.threshold_public_key33);
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
fn zero_sum_public_identity_is_rejected_for_retry() {
    let context = context();
    let (y_client32_le, _) = fixed_inputs();
    let client_share = derive_client_share(&context, y_client32_le).expect("client share");
    let client_public_key =
        PublicKey::from_sec1_bytes(&client_share.client_public_key33).expect("client public key");
    let negative_client_point = -ProjectivePoint::from(*client_public_key.as_affine());
    let negative_client_key33 = negative_client_point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("negative client key");

    let err = compose_public_identity_from_public_keys(
        &context,
        &client_share.client_public_key33,
        client_share.retry_counter,
        &negative_client_key33,
        0,
    )
    .expect_err("identity public-key sum rejects");

    assert!(err.message.contains("identity point"));
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
