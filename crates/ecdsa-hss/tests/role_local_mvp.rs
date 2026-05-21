use ecdsa_hss::{
    compose_public_identity_v1, context_binding_v1, derive_client_share_v1,
    derive_relayer_share_for_client_public_v1, encode_context_v1, export_authorization_digest_v1,
    export_from_respond_response_v1, public_transcript_digest_v1, reconstruct_export_key_v1,
    sign_with_role_materials_v1, ClientOutputV1, ClientRoleShareV1, EcdsaHssStableKeyContextV1,
    EvmThresholdClientBootstrapV1, EvmThresholdRelayerBootstrapV1, ExplicitExportAuthorizationV1,
    ExplicitExportClientOutputV1, ExplicitExportRespondRequestV1, ExportNonceReplayGuardV1,
    PrepareEnvelopeV1, PublicIdentityV1, RelayerRoleShareV1, RespondRequestV1, RespondResponseV1,
    ServerEvalOperationV1, ServerPrepareInputsV1, StagedServerSessionV1, ThresholdRespondRequestV1,
};
use k256::{FieldBytes, SecretKey};
use signer_core::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20,
};

fn context() -> EcdsaHssStableKeyContextV1 {
    EcdsaHssStableKeyContextV1::new(
        "wallet-session-user",
        "subject",
        "ecdsa-threshold-key",
        "signing-root",
        "1",
        "evm-family",
        "1",
    )
}

fn fixed_inputs() -> ([u8; 32], [u8; 32]) {
    ([0x11u8; 32], [0x22u8; 32])
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("valid hex")
        .try_into()
        .expect("32-byte hex")
}

fn relayer_key_id() -> String {
    "relayer-key-1".to_string()
}

fn export_authorization(
    context: &EcdsaHssStableKeyContextV1,
    relayer_key_id: &str,
    identity: &PublicIdentityV1,
) -> ExplicitExportAuthorizationV1 {
    let mut authorization = ExplicitExportAuthorizationV1 {
        wallet_session_user_id: context.wallet_session_user_id.clone(),
        ecdsa_threshold_key_id: context.ecdsa_threshold_key_id.clone(),
        client_device_id: "client-device-1".to_string(),
        client_session_id: "client-session-1".to_string(),
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

fn explicit_export_authorization_for_client_share(
    context: &EcdsaHssStableKeyContextV1,
    y_relayer32_le: [u8; 32],
    relayer_key_id: &str,
    client_share: &ClientRoleShareV1,
) -> ExplicitExportAuthorizationV1 {
    let (_, identity) = derive_relayer_share_for_client_public_v1(
        context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer identity");
    export_authorization(context, relayer_key_id, &identity)
}

fn negated_secret32(secret32: &[u8; 32]) -> [u8; 32] {
    let scalar = SecretKey::from_slice(secret32)
        .expect("valid test secret")
        .to_nonzero_scalar();
    let negated = -scalar;
    let bytes = FieldBytes::from(&negated);
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}

struct BootstrapRoles {
    client_share: ClientRoleShareV1,
    client_response: RespondResponseV1,
    client_bootstrap: EvmThresholdClientBootstrapV1,
    relayer_bootstrap: EvmThresholdRelayerBootstrapV1,
}

fn bootstrap_roles(
    operation: ServerEvalOperationV1,
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
) -> BootstrapRoles {
    let relayer_key_id = relayer_key_id();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation,
            context: context.clone(),
            relayer_key_id: relayer_key_id.clone(),
        },
        y_relayer32_le,
    })
    .expect("stage server");
    let result = if operation == ServerEvalOperationV1::ExplicitKeyExport {
        let mut replay_guard = ExportNonceReplayGuardV1::new();
        let authorization = explicit_export_authorization_for_client_share(
            &context,
            y_relayer32_le,
            &relayer_key_id,
            &client_share,
        );
        staged
            .respond_explicit_export(
                &ExplicitExportRespondRequestV1 {
                    client_public_key33: client_share.client_public_key33,
                    client_share_retry_counter: client_share.retry_counter,
                    authorization,
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
    };
    let client_bootstrap =
        EvmThresholdClientBootstrapV1::from_client_response(&result.client_response, &client_share)
            .expect("client bootstrap");
    let relayer_bootstrap = EvmThresholdRelayerBootstrapV1::from_finalized_server_session(
        &result.finalized_server_session,
    )
    .expect("relayer bootstrap");
    BootstrapRoles {
        client_share,
        client_response: result.client_response.clone(),
        client_bootstrap,
        relayer_bootstrap,
    }
}

#[test]
fn role_local_public_identity_matches_share_sum() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public_v1(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    let expected_threshold = add_secp256k1_public_keys_33(
        &client_share.client_public_key33,
        &relayer_share.relayer_public_key33,
    )
    .expect("public key sum");
    let expected_address =
        secp256k1_public_key_33_to_ethereum_address_20(&expected_threshold).expect("address");

    assert_eq!(
        identity.client_public_key33,
        client_share.client_public_key33
    );
    assert_eq!(
        identity.relayer_public_key33,
        relayer_share.relayer_public_key33
    );
    assert_eq!(
        identity.threshold_public_key33.as_slice(),
        expected_threshold
    );
    assert_eq!(
        identity.threshold_ethereum_address20.as_slice(),
        expected_address
    );
}

#[test]
fn committed_role_local_fixture_matches_derivation() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/role_local_v1.json")).expect("fixture json");
    let context_json = &fixture["context"];
    let inputs_json = &fixture["inputs"];
    let identity_json = &fixture["identity"];
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
    let y_client32_le = hex32(
        inputs_json["y_client32_le_hex"]
            .as_str()
            .expect("client root"),
    );
    let y_relayer32_le = hex32(
        inputs_json["y_relayer32_le_hex"]
            .as_str()
            .expect("relayer root"),
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

    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let (relayer_share, identity) = derive_relayer_share_for_client_public_v1(
        &context,
        y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");

    assert_eq!(
        fixture["operation"].as_str().expect("operation"),
        "SessionBootstrap"
    );
    assert_eq!(
        inputs_json["relayer_key_id"]
            .as_str()
            .expect("relayer key id"),
        "fixture-relayer-key-1"
    );
    assert_eq!(
        identity_json["client_public_key33_hex"]
            .as_str()
            .expect("client public key"),
        hex::encode(client_share.client_public_key33)
    );
    assert_eq!(
        identity_json["relayer_public_key33_hex"]
            .as_str()
            .expect("relayer public key"),
        hex::encode(identity.relayer_public_key33)
    );
    assert_eq!(
        identity_json["threshold_public_key33_hex"]
            .as_str()
            .expect("threshold public key"),
        hex::encode(identity.threshold_public_key33)
    );
    assert_eq!(
        identity_json["threshold_ethereum_address20_hex"]
            .as_str()
            .expect("threshold address"),
        hex::encode(identity.threshold_ethereum_address20)
    );
    assert_eq!(
        identity_json["client_share_retry_counter"]
            .as_u64()
            .expect("client retry"),
        u64::from(identity.client_share_retry_counter)
    );
    assert_eq!(
        identity_json["relayer_share_retry_counter"]
            .as_u64()
            .expect("relayer retry"),
        u64::from(identity.relayer_share_retry_counter)
    );
    let x_export32 =
        reconstruct_export_key_v1(&client_share, &relayer_share.x_relayer32, &identity)
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
            &identity,
            &authorization
        )
        .expect("authorization digest")
    );
    assert_eq!(
        fixture["public_transcript_digest32_hex"]
            .as_str()
            .expect("public transcript digest"),
        hex::encode(
            public_transcript_digest_v1(ServerEvalOperationV1::ExplicitKeyExport, &identity)
                .expect("public transcript digest")
        )
    );
}

#[test]
fn server_respond_accepts_public_client_commitment_only() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage server");

    let result = staged
        .respond(&RespondRequestV1::Threshold(ThresholdRespondRequestV1 {
            client_public_key33: client_share.client_public_key33,
            client_share_retry_counter: client_share.retry_counter,
            expected_relayer_key_id: relayer_key_id(),
        }))
        .expect("respond");

    assert_eq!(
        result.finalized_server_session.retained.client_public_key33,
        client_share.client_public_key33
    );
    assert_ne!(
        result.finalized_server_session.retained.relayer_share32,
        [0u8; 32]
    );
}

#[test]
fn relayer_key_id_mismatch_rejects_threshold_response() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage server");

    let err = staged
        .respond(&RespondRequestV1::Threshold(ThresholdRespondRequestV1 {
            client_public_key33: client_share.client_public_key33,
            client_share_retry_counter: client_share.retry_counter,
            expected_relayer_key_id: "rotated-relayer-key".to_string(),
        }))
        .expect_err("mismatched relayer key id should fail");

    assert!(err.message.contains("relayer_key_mismatch"));
}

#[test]
fn explicit_export_reconstructs_key_on_client_side() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let bootstrap = bootstrap_roles(
        ServerEvalOperationV1::ExplicitKeyExport,
        context,
        y_client32_le,
        y_relayer32_le,
    );
    let export =
        export_from_respond_response_v1(&bootstrap.client_response, &bootstrap.client_share)
            .expect("export");

    let derived_public_key =
        secp256k1_private_key_32_to_public_key_33(&export.x_export32).expect("export public key");
    assert_eq!(derived_public_key.as_slice(), export.threshold_public_key33);
    assert_eq!(export.export_public_key33, export.threshold_public_key33);
    assert_eq!(
        export.export_ethereum_address20,
        export.threshold_ethereum_address20
    );
}

#[test]
fn explicit_export_requires_fresh_authorization_nonce() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let authorization = explicit_export_authorization_for_client_share(
        &context,
        y_relayer32_le,
        &relayer_key_id(),
        &client_share,
    );
    let mut replay_guard = ExportNonceReplayGuardV1::new();

    let first_staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage first server");
    first_staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization: authorization.clone(),
            },
            &mut replay_guard,
            1_500,
        )
        .expect("first export");

    let second_staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context,
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage second server");
    let err = second_staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization,
            },
            &mut replay_guard,
            1_500,
        )
        .expect_err("replayed export nonce should fail");

    assert!(err.message.contains("export_nonce_replay"));
}

#[test]
fn explicit_export_rejects_relayer_key_id_mismatch() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage server");
    let mut replay_guard = ExportNonceReplayGuardV1::new();

    let err = staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization: explicit_export_authorization_for_client_share(
                    &context,
                    y_relayer32_le,
                    "rotated-relayer-key",
                    &client_share,
                ),
            },
            &mut replay_guard,
            1_500,
        )
        .expect_err("relayer key mismatch should fail");

    assert!(err.message.contains("relayer_key_mismatch"));
}

#[test]
fn expired_explicit_export_authorization_is_rejected() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage server");
    let mut replay_guard = ExportNonceReplayGuardV1::new();

    let err = staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization: explicit_export_authorization_for_client_share(
                    &context,
                    y_relayer32_le,
                    &relayer_key_id(),
                    &client_share,
                ),
            },
            &mut replay_guard,
            2_001,
        )
        .expect_err("expired authorization should fail");

    assert!(err.message.contains("export_authorization_expired"));

    let retry_staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage retry server");
    let retry_err = retry_staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization: explicit_export_authorization_for_client_share(
                    &context,
                    y_relayer32_le,
                    &relayer_key_id(),
                    &client_share,
                ),
            },
            &mut replay_guard,
            1_500,
        )
        .expect_err("failed export nonce should be consumed");

    assert!(retry_err.message.contains("export_nonce_replay"));
}

#[test]
fn explicit_export_rejects_authorization_digest_mismatch() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let mut authorization = explicit_export_authorization_for_client_share(
        &context,
        y_relayer32_le,
        &relayer_key_id(),
        &client_share,
    );
    authorization.confirmation_digest32[0] ^= 0x01;
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage server");
    let mut replay_guard = ExportNonceReplayGuardV1::new();

    let err = staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization,
            },
            &mut replay_guard,
            1_500,
        )
        .expect_err("digest mismatch should fail");

    assert!(err.message.contains("export_authorization_digest_mismatch"));

    let retry_staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
            relayer_key_id: relayer_key_id(),
        },
        y_relayer32_le,
    })
    .expect("stage retry server");
    let retry_err = retry_staged
        .respond_explicit_export(
            &ExplicitExportRespondRequestV1 {
                client_public_key33: client_share.client_public_key33,
                client_share_retry_counter: client_share.retry_counter,
                authorization: explicit_export_authorization_for_client_share(
                    &context,
                    y_relayer32_le,
                    &relayer_key_id(),
                    &client_share,
                ),
            },
            &mut replay_guard,
            1_500,
        )
        .expect_err("failed export nonce should be consumed");

    assert!(retry_err.message.contains("export_nonce_replay"));
}

#[test]
fn non_export_output_excludes_private_key_material() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let bootstrap = bootstrap_roles(
        ServerEvalOperationV1::NonExportSign,
        context,
        y_client32_le,
        y_relayer32_le,
    );

    let ClientOutputV1::NonExport(output) = &bootstrap.client_response.client_output else {
        panic!("non-export response should use non-export output");
    };

    assert_ne!(output.client_public_key33, [0u8; 33]);
    assert_ne!(output.relayer_public_key33, [0u8; 33]);
    assert_ne!(output.threshold_public_key33, [0u8; 33]);
    assert_ne!(output.threshold_ethereum_address20, [0u8; 20]);
}

#[test]
fn signing_uses_role_local_shares() {
    let context = context();
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let bootstrap = bootstrap_roles(
        ServerEvalOperationV1::NonExportSign,
        context,
        y_client32_le,
        y_relayer32_le,
    );
    let signature = sign_with_role_materials_v1(
        &bootstrap.client_bootstrap,
        &bootstrap.relayer_bootstrap,
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .expect("sign");
    assert_eq!(signature.len(), 65);
}

#[test]
fn debug_output_redacts_secret_bearing_fields() {
    let (y_client, y_relayer) = fixed_inputs();
    let ctx = context();
    let roles = bootstrap_roles(
        ServerEvalOperationV1::SessionBootstrap,
        ctx.clone(),
        y_client,
        y_relayer,
    );
    let auth = explicit_export_authorization_for_client_share(
        &ctx,
        y_relayer,
        &relayer_key_id(),
        &roles.client_share,
    );
    let explicit_client_output = ClientOutputV1::ExplicitExport(ExplicitExportClientOutputV1 {
        relayer_export_share32: [0x77; 32],
        client_public_key33: roles.client_bootstrap.identity.client_verifying_share33,
        relayer_public_key33: roles.client_bootstrap.identity.relayer_verifying_share33,
        threshold_public_key33: roles.client_bootstrap.identity.group_public_key33,
        threshold_ethereum_address20: roles.client_bootstrap.identity.ethereum_address20,
        client_share_retry_counter: roles.client_bootstrap.identity.client_share_retry_counter,
        relayer_share_retry_counter: roles.client_bootstrap.identity.relayer_share_retry_counter,
    });

    let debug_text = format!(
        "{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
        roles.client_share,
        roles.client_response,
        roles.client_bootstrap,
        auth,
        explicit_client_output
    );

    for redacted_field in [
        "x_client32",
        "mapped_client_share32",
        "relayer_export_share32",
        "additive_share32",
        "threshold_private_share32",
        "export_request_nonce32",
    ] {
        assert!(
            debug_text.contains(&format!("{redacted_field}: \"<redacted>\"")),
            "missing redaction marker for {redacted_field}: {debug_text}"
        );
    }
}

#[test]
fn context_binding_uses_evm_family_scope() {
    let left = context();
    let right = context();

    assert_eq!(
        context_binding_v1(&left).expect("left context"),
        context_binding_v1(&right).expect("right context")
    );
    let (y_client32_le, y_relayer32_le) = fixed_inputs();
    let left_bootstrap = bootstrap_roles(
        ServerEvalOperationV1::SessionBootstrap,
        left,
        y_client32_le,
        y_relayer32_le,
    );
    let right_bootstrap = bootstrap_roles(
        ServerEvalOperationV1::SessionBootstrap,
        right,
        y_client32_le,
        y_relayer32_le,
    );
    assert_eq!(
        left_bootstrap.client_bootstrap.identity.group_public_key33,
        right_bootstrap.client_bootstrap.identity.group_public_key33
    );
    assert_eq!(
        left_bootstrap.client_bootstrap.identity.ethereum_address20,
        right_bootstrap.client_bootstrap.identity.ethereum_address20
    );
}

#[test]
fn invalid_client_public_key_is_rejected() {
    let context = context();
    let (_, y_relayer32_le) = fixed_inputs();
    let mut bad_public_key = [0u8; 33];
    bad_public_key[0] = 0x04;

    let err =
        derive_relayer_share_for_client_public_v1(&context, y_relayer32_le, &bad_public_key, 0)
            .expect_err("invalid public key should fail");
    assert!(err.message.contains("public key"));
}

#[test]
fn zero_canonical_key_identity_sum_is_rejected() {
    let context = context();
    let (y_client32_le, _) = fixed_inputs();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
    let x_relayer32 = negated_secret32(&client_share.x_client32);
    let relayer_public_key33 =
        secp256k1_private_key_32_to_public_key_33(&x_relayer32).expect("relayer public key");

    let relayer_share = RelayerRoleShareV1 {
        context_bytes: client_share.context_bytes.clone(),
        context_binding32: client_share.context_binding32,
        retry_counter: 0,
        x_relayer32,
        relayer_public_key33: relayer_public_key33
            .try_into()
            .expect("compressed relayer public key"),
        mapped_relayer_share32: [0u8; 32],
    };

    let err = compose_public_identity_v1(
        &context,
        &client_share.client_public_key33,
        client_share.retry_counter,
        &relayer_share,
    )
    .expect_err("identity threshold public key should fail");

    assert!(err.message.contains("identity point"));
}
