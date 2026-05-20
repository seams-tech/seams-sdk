use ecdsa_hss::{
    context_binding_v1, derive_client_share_v1, encode_context_v1, export_authorization_digest_v1,
    public_transcript_digest_v1, reconstruct_export_key_v1, EcdsaHssStableKeyContextV1,
    EvmThresholdClientBootstrapV1, EvmThresholdRelayerBootstrapV1, ExplicitExportAuthorizationV1,
    PrepareEnvelopeV1, PublicIdentityV1, RespondRequestV1, ServerEvalOperationV1,
    ServerPrepareInputsV1, StagedServerSessionV1, ThresholdRespondRequestV1,
};
use serde_json::json;

fn main() {
    let context = EcdsaHssStableKeyContextV1::new(
        "fixture-wallet-session-user",
        "fixture-subject",
        "fixture-ecdsa-threshold-key",
        "fixture-signing-root",
        "1",
        "evm-family",
        "1",
    );
    let y_client32_le = [0x11u8; 32];
    let y_relayer32_le = [0x22u8; 32];
    let relayer_key_id = "fixture-relayer-key-1".to_string();
    let context_encoding = encode_context_v1(&context).expect("context encoding");
    let context_binding32 = context_binding_v1(&context).expect("context binding");
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::SessionBootstrap,
            context: context.clone(),
            relayer_key_id: relayer_key_id.clone(),
        },
        y_relayer32_le,
    })
    .expect("stage server");
    let result = staged
        .respond(&RespondRequestV1::Threshold(ThresholdRespondRequestV1 {
            client_public_key33: client_share.client_public_key33,
            client_share_retry_counter: client_share.retry_counter,
            expected_relayer_key_id: relayer_key_id.clone(),
        }))
        .expect("respond");
    let client_bootstrap =
        EvmThresholdClientBootstrapV1::from_client_response(&result.client_response, &client_share)
            .expect("client bootstrap");
    let relayer_bootstrap = EvmThresholdRelayerBootstrapV1::from_finalized_server_session(
        &result.finalized_server_session,
    )
    .expect("relayer bootstrap");
    let public_identity = PublicIdentityV1 {
        context_bytes: context_encoding.clone(),
        context_binding32,
        client_public_key33: client_bootstrap.identity.client_verifying_share33,
        relayer_public_key33: client_bootstrap.identity.relayer_verifying_share33,
        threshold_public_key33: client_bootstrap.identity.group_public_key33,
        threshold_ethereum_address20: client_bootstrap.identity.ethereum_address20,
        client_share_retry_counter: client_bootstrap.identity.client_share_retry_counter,
        relayer_share_retry_counter: client_bootstrap.identity.relayer_share_retry_counter,
    };
    let mut export_authorization = ExplicitExportAuthorizationV1 {
        wallet_session_user_id: "fixture-wallet-session-user".to_string(),
        ecdsa_threshold_key_id: "fixture-ecdsa-threshold-key".to_string(),
        client_device_id: "fixture-client-device".to_string(),
        client_session_id: "fixture-client-session".to_string(),
        relayer_key_id: relayer_key_id.clone(),
        export_request_nonce32: [0x55u8; 32],
        confirmation_digest32: [0x66u8; 32],
        authorization_digest32: [0u8; 32],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    };
    let public_transcript_digest32 =
        public_transcript_digest_v1(ServerEvalOperationV1::ExplicitKeyExport, &public_identity)
            .expect("public transcript digest");
    let x_export32 = reconstruct_export_key_v1(
        &client_share,
        &relayer_bootstrap.material.additive_share32,
        &public_identity,
    )
    .expect("export key");
    export_authorization.authorization_digest32 = export_authorization_digest_v1(
        ServerEvalOperationV1::ExplicitKeyExport,
        &public_identity,
        &export_authorization,
    )
    .expect("export authorization digest");

    let fixture = json!({
        "format_version": 1,
        "context": {
            "wallet_session_user_id": context.wallet_session_user_id,
            "subject_id": context.subject_id,
            "ecdsa_threshold_key_id": context.ecdsa_threshold_key_id,
            "signing_root_id": context.signing_root_id,
            "signing_root_version": context.signing_root_version,
            "key_purpose": context.key_purpose,
            "key_version": context.key_version,
        },
        "context_encoding_hex": hex::encode(context_encoding),
        "context_binding32_hex": hex::encode(context_binding32),
        "inputs": {
            "relayer_key_id": relayer_key_id,
            "y_client32_le_hex": hex::encode(y_client32_le),
            "y_relayer32_le_hex": hex::encode(y_relayer32_le),
        },
        "identity": {
            "participant_ids": client_bootstrap.identity.participant_ids,
            "client_public_key33_hex": hex::encode(client_bootstrap.identity.client_verifying_share33),
            "relayer_public_key33_hex": hex::encode(client_bootstrap.identity.relayer_verifying_share33),
            "threshold_public_key33_hex": hex::encode(client_bootstrap.identity.group_public_key33),
            "threshold_ethereum_address20_hex": hex::encode(client_bootstrap.identity.ethereum_address20),
            "client_share_retry_counter": client_bootstrap.identity.client_share_retry_counter,
            "relayer_share_retry_counter": client_bootstrap.identity.relayer_share_retry_counter,
        },
        "derived": {
            "x_client32_hex": hex::encode(client_share.x_client32),
            "x_relayer32_hex": hex::encode(relayer_bootstrap.material.additive_share32),
            "mapped_client_share32_hex": hex::encode(client_bootstrap.material.threshold_private_share32),
            "mapped_relayer_share32_hex": hex::encode(relayer_bootstrap.material.threshold_private_share32),
            "x_export32_hex": hex::encode(x_export32),
        },
        "public_transcript_digest32_hex": hex::encode(public_transcript_digest32),
        "export_authorization": {
            "wallet_session_user_id": export_authorization.wallet_session_user_id,
            "ecdsa_threshold_key_id": export_authorization.ecdsa_threshold_key_id,
            "client_device_id": export_authorization.client_device_id,
            "client_session_id": export_authorization.client_session_id,
            "relayer_key_id": export_authorization.relayer_key_id,
            "export_request_nonce32_hex": hex::encode(export_authorization.export_request_nonce32),
            "confirmation_digest32_hex": hex::encode(export_authorization.confirmation_digest32),
            "authorization_digest32_hex": hex::encode(export_authorization.authorization_digest32),
            "issued_at_unix_ms": export_authorization.issued_at_unix_ms,
            "expires_at_unix_ms": export_authorization.expires_at_unix_ms,
        },
        "operation": format!("{:?}", ServerEvalOperationV1::SessionBootstrap),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&fixture).expect("fixture should serialize")
    );
}
