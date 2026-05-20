use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ecdsa_hss::{
    complete_presign_roundtrip_v1, context_binding_v1, derive_client_share_v1,
    derive_relayer_share_for_client_public_v1, export_authorization_digest_v1,
    export_from_respond_response_v1, sign_with_role_materials_v1, ClientRoleShareV1,
    EcdsaHssStableKeyContextV1, EvmThresholdClientBootstrapV1, EvmThresholdRelayerBootstrapV1,
    ExplicitExportAuthorizationV1, ExplicitExportRespondRequestV1, ExportNonceReplayGuardV1,
    PrepareEnvelopeV1, PublicIdentityV1, RespondRequestV1, RespondResponseV1,
    ServerEvalOperationV1, ServerPrepareInputsV1, StagedServerSessionV1, ThresholdRespondRequestV1,
};
use sha2::{Digest, Sha512};

#[derive(Clone)]
struct BenchmarkFixture {
    name: &'static str,
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
}

fn representative_fixture() -> BenchmarkFixture {
    BenchmarkFixture {
        name: "role-local",
        context: EcdsaHssStableKeyContextV1::new(
            "bench-wallet-session-user",
            "bench-subject",
            "bench-ecdsa-threshold-key",
            "bench-signing-root",
            "1",
            "evm-family",
            "1",
        ),
        y_client32_le: [0x11u8; 32],
        y_relayer32_le: [0x22u8; 32],
    }
}

fn fixed_digest32(label: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(label);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn relayer_key_id() -> String {
    "bench-relayer-key-1".to_string()
}

fn export_authorization(
    context: &EcdsaHssStableKeyContextV1,
    relayer_key_id: &str,
    identity: &PublicIdentityV1,
) -> ExplicitExportAuthorizationV1 {
    let mut authorization = ExplicitExportAuthorizationV1 {
        wallet_session_user_id: context.wallet_session_user_id.clone(),
        ecdsa_threshold_key_id: context.ecdsa_threshold_key_id.clone(),
        client_device_id: "bench-client-device".to_string(),
        client_session_id: "bench-client-session".to_string(),
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

#[derive(Clone)]
struct BenchmarkBootstrap {
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
) -> BenchmarkBootstrap {
    let relayer_key_id = relayer_key_id();
    let client_share = derive_client_share_v1(&context, y_client32_le).expect("client share");
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
    .expect("stage server");
    let result = if operation == ServerEvalOperationV1::ExplicitKeyExport {
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
    };
    let client_bootstrap =
        EvmThresholdClientBootstrapV1::from_client_response(&result.client_response, &client_share)
            .expect("client bootstrap");
    let relayer_bootstrap = EvmThresholdRelayerBootstrapV1::from_finalized_server_session(
        &result.finalized_server_session,
    )
    .expect("relayer bootstrap");
    BenchmarkBootstrap {
        client_share,
        client_response: result.client_response.clone(),
        client_bootstrap,
        relayer_bootstrap,
    }
}

fn bench_derivation_paths(c: &mut Criterion) {
    let fixture = representative_fixture();
    let client_share =
        derive_client_share_v1(&fixture.context, fixture.y_client32_le).expect("client share");

    let mut group = c.benchmark_group("derivation_paths");
    group.sample_size(20);
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("context_binding", fixture.name),
        &fixture,
        |b, fixture| b.iter(|| context_binding_v1(black_box(&fixture.context)).expect("context")),
    );

    group.bench_with_input(
        BenchmarkId::new("client_share", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                derive_client_share_v1(
                    black_box(&fixture.context),
                    black_box(fixture.y_client32_le),
                )
                .expect("client share")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("relayer_share_and_identity", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                derive_relayer_share_for_client_public_v1(
                    black_box(&fixture.context),
                    black_box(fixture.y_relayer32_le),
                    black_box(&client_share.client_public_key33),
                    black_box(client_share.retry_counter),
                )
                .expect("relayer share")
            })
        },
    );

    group.finish();
}

fn bench_integration_paths(c: &mut Criterion) {
    let fixture = representative_fixture();
    let digest32 = fixed_digest32(b"ecdsa-hss/bench/digest");
    let entropy32 = fixed_digest32(b"ecdsa-hss/bench/entropy");
    let bootstrap = bootstrap_roles(
        ServerEvalOperationV1::NonExportSign,
        fixture.context.clone(),
        fixture.y_client32_le,
        fixture.y_relayer32_le,
    );
    let signing_pair = (
        bootstrap.client_bootstrap.clone(),
        bootstrap.relayer_bootstrap.clone(),
    );

    let mut group = c.benchmark_group("integration_paths");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("bootstrap_adapter", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                bootstrap_roles(
                    black_box(ServerEvalOperationV1::NonExportSign),
                    black_box(fixture.context.clone()),
                    black_box(fixture.y_client32_le),
                    black_box(fixture.y_relayer32_le),
                )
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("first_presign_roundtrip", fixture.name),
        &signing_pair,
        |b, (client, relayer)| {
            b.iter(|| {
                complete_presign_roundtrip_v1(black_box(client), black_box(relayer))
                    .expect("presign roundtrip")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("sign_bridge_full", fixture.name),
        &signing_pair,
        |b, (client, relayer)| {
            b.iter(|| {
                sign_with_role_materials_v1(
                    black_box(client),
                    black_box(relayer),
                    black_box(&digest32),
                    black_box(&entropy32),
                )
                .expect("sign bridge")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("explicit_export", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                let bootstrap = bootstrap_roles(
                    black_box(ServerEvalOperationV1::ExplicitKeyExport),
                    black_box(fixture.context.clone()),
                    black_box(fixture.y_client32_le),
                    black_box(fixture.y_relayer32_le),
                );
                export_from_respond_response_v1(
                    black_box(&bootstrap.client_response),
                    black_box(&bootstrap.client_share),
                )
                .expect("export")
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_derivation_paths, bench_integration_paths);
criterion_main!(benches);
