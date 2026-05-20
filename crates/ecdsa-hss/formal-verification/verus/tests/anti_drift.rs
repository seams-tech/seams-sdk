use ecdsa_hss::{
    derive_client_share_v1, derive_relayer_share_for_client_public_v1,
    export_authorization_digest_v1, AllowedOutputKindV1, ClientOutputV1,
    EcdsaHssStableKeyContextV1, ExplicitExportAuthorizationV1, ExplicitExportClientOutputV1,
    ExplicitExportRespondRequestV1, ExportNonceReplayGuardV1, NonExportClientOutputV1,
    PrepareEnvelopeV1, PublicIdentityV1, RespondRequestV1, ServerEvalOperationV1,
    ServerPrepareInputsV1, ServerRespondResultV1, StagedServerSessionV1, ThresholdRespondRequestV1,
};

fn context() -> EcdsaHssStableKeyContextV1 {
    EcdsaHssStableKeyContextV1::new(
        "anti-drift.test.near",
        "anti-drift-subject",
        "ehss-anti-drift",
        "anti-drift-root",
        "root-v1",
        "evm-signing",
        "v1",
    )
}

fn relayer_key_id() -> String {
    "anti-drift-relayer-key-1".to_string()
}

fn export_authorization(
    context: &EcdsaHssStableKeyContextV1,
    relayer_key_id: &str,
    identity: &PublicIdentityV1,
) -> ExplicitExportAuthorizationV1 {
    let mut authorization = ExplicitExportAuthorizationV1 {
        wallet_session_user_id: context.wallet_session_user_id.clone(),
        ecdsa_threshold_key_id: context.ecdsa_threshold_key_id.clone(),
        client_device_id: "anti-drift-device".to_string(),
        client_session_id: "anti-drift-session".to_string(),
        relayer_key_id: relayer_key_id.to_string(),
        export_request_nonce32: [0x55u8; 32],
        confirmation_digest32: [0x66u8; 32],
        authorization_digest32: [0u8; 32],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    };
    authorization.authorization_digest32 = export_authorization_digest_v1(
        ServerEvalOperationV1::ExplicitKeyExport,
        identity,
        &authorization,
    )
    .expect("authorization digest");
    authorization
}

fn sample_response(operation: ServerEvalOperationV1) -> ServerRespondResultV1 {
    let context = context();
    let relayer_key_id = relayer_key_id();
    let y_relayer32_le = [0x42u8; 32];
    let client_share = derive_client_share_v1(&context, [0x24u8; 32]).expect("client share");
    let (_, identity) = derive_relayer_share_for_client_public_v1(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer identity");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation,
            context: context.clone(),
            relayer_key_id: relayer_key_id.clone(),
        },
        y_relayer32_le,
    })
    .expect("prepare");

    if operation == ServerEvalOperationV1::ExplicitKeyExport {
        let mut replay_guard = ExportNonceReplayGuardV1::new();
        staged
            .respond_explicit_export(
                &ExplicitExportRespondRequestV1 {
                    client_public_key33: client_share.client_public_key33,
                    client_share_retry_counter: client_share.retry_counter,
                    authorization: export_authorization(&context, &relayer_key_id, &identity),
                },
                &mut replay_guard,
                1_500,
            )
            .expect("respond explicit export")
    } else {
        staged
            .respond(&RespondRequestV1::Threshold(ThresholdRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                expected_relayer_key_id: relayer_key_id,
            }))
            .expect("respond")
    }
}

#[test]
fn anti_drift_operation_policy_has_no_canonical_secret_variant() {
    assert_eq!(
        ServerEvalOperationV1::NonExportSign.allowed_output_kind(),
        AllowedOutputKindV1::ThresholdMaterialOnly
    );
    assert_eq!(
        ServerEvalOperationV1::ExplicitKeyExport.allowed_output_kind(),
        AllowedOutputKindV1::ThresholdMaterialAndRelayerExportShare
    );
}

#[test]
fn anti_drift_respond_request_shape_is_public_client_commitment() {
    let context = context();
    let client_share = derive_client_share_v1(&context, [0x24u8; 32]).expect("client share");
    let request = RespondRequestV1::Threshold(ThresholdRespondRequestV1 {
        client_public_key33: client_share.client_public_key33,
        client_share_retry_counter: client_share.retry_counter,
        expected_relayer_key_id: relayer_key_id(),
    });

    let RespondRequestV1::Threshold(request) = request else {
        panic!("threshold request should use threshold branch");
    };
    assert_eq!(
        request.client_public_key33,
        client_share.client_public_key33
    );
    assert_eq!(
        request.client_share_retry_counter,
        client_share.retry_counter
    );
    assert_eq!(request.expected_relayer_key_id, relayer_key_id());
}

#[test]
fn anti_drift_non_export_output_shape_excludes_secret_shares() {
    let response = sample_response(ServerEvalOperationV1::NonExportSign);
    let ClientOutputV1::NonExport(NonExportClientOutputV1 {
        client_public_key33,
        relayer_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        client_share_retry_counter,
        relayer_share_retry_counter,
    }) = response.client_response.client_output
    else {
        panic!("non-export operation must return non-export output");
    };

    assert_eq!(
        client_public_key33,
        response.client_response.finalize.client_public_key33
    );
    assert_eq!(
        relayer_public_key33,
        response.client_response.finalize.relayer_public_key33
    );
    assert_eq!(
        threshold_public_key33,
        response.client_response.finalize.threshold_public_key33
    );
    assert_eq!(
        threshold_ethereum_address20,
        response.client_response.finalize.threshold_ethereum_address20
    );
    assert_eq!(
        client_share_retry_counter,
        response.client_response.finalize.client_share_retry_counter
    );
    assert_eq!(
        relayer_share_retry_counter,
        response.client_response.finalize.relayer_share_retry_counter
    );
}

#[test]
fn anti_drift_explicit_export_output_releases_only_relayer_export_share() {
    let response = sample_response(ServerEvalOperationV1::ExplicitKeyExport);
    let ClientOutputV1::ExplicitExport(ExplicitExportClientOutputV1 {
        relayer_export_share32,
        client_public_key33,
        relayer_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        client_share_retry_counter,
        relayer_share_retry_counter,
    }) = response.client_response.client_output
    else {
        panic!("explicit export operation must return export output");
    };

    assert_eq!(
        relayer_export_share32,
        response.finalized_server_session.retained.relayer_share32
    );
    assert_eq!(
        client_public_key33,
        response.client_response.finalize.client_public_key33
    );
    assert_eq!(
        relayer_public_key33,
        response.client_response.finalize.relayer_public_key33
    );
    assert_eq!(
        threshold_public_key33,
        response.client_response.finalize.threshold_public_key33
    );
    assert_eq!(
        threshold_ethereum_address20,
        response.client_response.finalize.threshold_ethereum_address20
    );
    assert_eq!(
        client_share_retry_counter,
        response.client_response.finalize.client_share_retry_counter
    );
    assert_eq!(
        relayer_share_retry_counter,
        response.client_response.finalize.relayer_share_retry_counter
    );
}
