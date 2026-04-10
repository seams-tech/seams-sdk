use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use ecdsa_hss::fixtures::committed_fixture_corpus;
use ecdsa_hss::{
    bootstrap_evm_threshold_v1, compute_client_signature_share_v1, derive_additive_shares_v1,
    derive_canonical_secret_v1, export_evm_threshold_v1, finalize_signature_v1,
    init_client_presign_session_v1, init_relayer_presign_session_v1, parse_presignature97_v1,
    prepare_signing_session_v1, sign_with_session_v1, EcdsaHssContextV1,
    EvmThresholdBootstrapAdapterV1, EvmThresholdBootstrapRequestV1, EvmThresholdExportRequestV1,
    EvmThresholdPresignatureV1, EvmThresholdSigningOperationV1, RootShareInputsV1,
    ServerEvalOperationV1,
};
use sha2::{Digest, Sha512};
use signer_core::threshold_ecdsa::ThresholdEcdsaPresignSession;

#[derive(Clone)]
struct BenchmarkFixture {
    name: &'static str,
    context: EcdsaHssContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
    canonical_x32: [u8; 32],
}

fn representative_fixture() -> BenchmarkFixture {
    let fixtures = committed_fixture_corpus().expect("committed fixture corpus");
    let fixture = fixtures
        .into_iter()
        .find(|fixture| fixture.name == "derived-beta")
        .expect("derived-beta fixture");
    BenchmarkFixture {
        name: "derived-beta",
        context: fixture.context,
        y_client32_le: fixture.y_client32_le,
        y_relayer32_le: fixture.y_relayer32_le,
        canonical_x32: fixture.canonical.x32,
    }
}

fn fixed_digest32(label: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(label);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

struct PrimedPresignState {
    client: ThresholdEcdsaPresignSession,
    relayer: ThresholdEcdsaPresignSession,
}

fn init_presign_state(adapter: &EvmThresholdBootstrapAdapterV1) -> PrimedPresignState {
    let client = init_client_presign_session_v1(adapter).expect("client presign init");
    let relayer = init_relayer_presign_session_v1(adapter).expect("relayer presign init");

    PrimedPresignState { client, relayer }
}

fn run_until_triples_done(adapter: &EvmThresholdBootstrapAdapterV1) -> PrimedPresignState {
    let mut state = init_presign_state(adapter);

    for _ in 0..64 {
        if state.client.stage() == "triples_done" && state.relayer.stage() == "triples_done" {
            return state;
        }

        pump_presign_pair_until_wait_or_done(
            &mut state.client,
            &mut state.relayer,
            adapter.client.participant_id,
            adapter.relayer.participant_id,
        );
    }

    panic!("presign protocol did not reach triples_done within step budget");
}

fn finish_started_presign(
    adapter: &EvmThresholdBootstrapAdapterV1,
    mut state: PrimedPresignState,
) -> (EvmThresholdPresignatureV1, EvmThresholdPresignatureV1) {
    for _ in 0..64 {
        pump_presign_pair_until_wait_or_done(
            &mut state.client,
            &mut state.relayer,
            adapter.client.participant_id,
            adapter.relayer.participant_id,
        );

        if state.client.is_done() && state.relayer.is_done() {
            let client_presignature = parse_presignature97_v1(
                &state
                    .client
                    .take_presignature_97()
                    .expect("client presignature bytes"),
            )
            .expect("parse client presignature");
            let relayer_presignature = parse_presignature97_v1(
                &state
                    .relayer
                    .take_presignature_97()
                    .expect("relayer presignature bytes"),
            )
            .expect("parse relayer presignature");
            assert_eq!(client_presignature.big_r33, relayer_presignature.big_r33);
            return (client_presignature, relayer_presignature);
        }
    }

    panic!("presign protocol did not complete within step budget");
}

fn start_presign_on_state(mut state: PrimedPresignState) -> PrimedPresignState {
    state.client.start_presign().expect("client start presign");
    state
        .relayer
        .start_presign()
        .expect("relayer start presign");
    state
}

fn run_presign_protocol(
    adapter: &EvmThresholdBootstrapAdapterV1,
) -> (EvmThresholdPresignatureV1, EvmThresholdPresignatureV1) {
    let state = start_presign_on_state(run_until_triples_done(adapter));
    finish_started_presign(adapter, state)
}

fn run_presign_protocol_before_start(adapter: &EvmThresholdBootstrapAdapterV1) {
    let _ = run_until_triples_done(adapter);
}

fn pump_presign_pair_until_wait_or_done(
    client: &mut ThresholdEcdsaPresignSession,
    relayer: &mut ThresholdEcdsaPresignSession,
    client_participant_id: u32,
    relayer_participant_id: u32,
) {
    loop {
        let mut progressed = false;

        let client_progress = client.poll().expect("client poll");
        if client_progress.event != "none" || !client_progress.outgoing.is_empty() {
            progressed = true;
        }
        for msg in client_progress.outgoing {
            relayer
                .message(client_participant_id, &msg)
                .expect("deliver client->relayer");
        }

        let relayer_progress = relayer.poll().expect("relayer poll");
        if relayer_progress.event != "none" || !relayer_progress.outgoing.is_empty() {
            progressed = true;
        }
        for msg in relayer_progress.outgoing {
            client
                .message(relayer_participant_id, &msg)
                .expect("deliver relayer->client");
        }

        if client.is_done() && relayer.is_done() {
            return;
        }
        if !progressed {
            return;
        }
    }
}

fn bench_derivation_paths(c: &mut Criterion) {
    let fixture = representative_fixture();
    let root_shares = RootShareInputsV1::new(fixture.y_client32_le, fixture.y_relayer32_le);

    let mut group = c.benchmark_group("derivation_paths");
    group.sample_size(20);
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("canonical_derivation", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                derive_canonical_secret_v1(black_box(&root_shares), black_box(&fixture.context))
                    .expect("canonical derivation")
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("share_derivation", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                derive_additive_shares_v1(
                    black_box(&fixture.canonical_x32),
                    black_box(&fixture.context),
                )
                .expect("share derivation")
            });
        },
    );

    group.finish();
}

fn bench_integration_paths(c: &mut Criterion) {
    let fixture = representative_fixture();
    let digest32 = fixed_digest32(b"ecdsa-hss/bench/digest");
    let entropy32 = fixed_digest32(b"ecdsa-hss/bench/entropy");
    let bootstrap_request = EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: fixture.context.clone(),
        y_client32_le: fixture.y_client32_le,
        y_relayer32_le: fixture.y_relayer32_le,
    };
    let export_request = EvmThresholdExportRequestV1 {
        context: fixture.context.clone(),
        y_client32_le: fixture.y_client32_le,
        y_relayer32_le: fixture.y_relayer32_le,
    };
    let bootstrap = bootstrap_evm_threshold_v1(bootstrap_request.clone()).expect("bootstrap");
    let (client_presignature, relayer_presignature) = run_presign_protocol(&bootstrap.adapter);
    let client_signature_share32 = compute_client_signature_share_v1(
        &bootstrap.adapter,
        &client_presignature,
        &digest32,
        &entropy32,
    )
    .expect("client signature share");
    let signing_session = prepare_signing_session_v1(
        EvmThresholdSigningOperationV1::NonExportSign,
        fixture.context.clone(),
        fixture.y_client32_le,
        fixture.y_relayer32_le,
    )
    .expect("prepare signing session");

    let mut group = c.benchmark_group("integration_paths");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("bootstrap_adapter", fixture.name),
        &bootstrap_request,
        |b, request| {
            b.iter(|| bootstrap_evm_threshold_v1(black_box(request.clone())).expect("bootstrap"))
        },
    );

    group.bench_with_input(
        BenchmarkId::new("sign_session_prepare", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                prepare_signing_session_v1(
                    black_box(EvmThresholdSigningOperationV1::NonExportSign),
                    black_box(fixture.context.clone()),
                    black_box(fixture.y_client32_le),
                    black_box(fixture.y_relayer32_le),
                )
                .expect("prepare signing session")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("presign_session_init_pair", fixture.name),
        &bootstrap,
        |b, bootstrap| {
            b.iter(|| {
                let client =
                    init_client_presign_session_v1(black_box(&bootstrap.adapter)).expect("client");
                let relayer = init_relayer_presign_session_v1(black_box(&bootstrap.adapter))
                    .expect("relayer");
                black_box((client, relayer))
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("sign_bridge_full", fixture.name),
        &signing_session,
        |b, session| {
            b.iter(|| {
                sign_with_session_v1(
                    black_box(&session.clone()),
                    black_box(&digest32),
                    black_box(&entropy32),
                )
                .expect("sign bridge")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("presign_protocol_roundtrip", fixture.name),
        &bootstrap,
        |b, bootstrap| b.iter(|| run_presign_protocol(black_box(&bootstrap.adapter))),
    );

    group.bench_with_input(
        BenchmarkId::new("presign_before_start", fixture.name),
        &bootstrap,
        |b, bootstrap| b.iter(|| run_presign_protocol_before_start(black_box(&bootstrap.adapter))),
    );

    group.bench_with_input(
        BenchmarkId::new("presign_start_transition", fixture.name),
        &bootstrap,
        |b, bootstrap| {
            b.iter_batched(
                || run_until_triples_done(&bootstrap.adapter),
                |state| {
                    let _ = black_box(start_presign_on_state(state));
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        BenchmarkId::new("presign_after_start", fixture.name),
        &bootstrap,
        |b, bootstrap| {
            b.iter_batched(
                || start_presign_on_state(run_until_triples_done(&bootstrap.adapter)),
                |state| {
                    let _ = finish_started_presign(black_box(&bootstrap.adapter), state);
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        BenchmarkId::new("client_signature_share_compute", fixture.name),
        &bootstrap,
        |b, bootstrap| {
            b.iter(|| {
                compute_client_signature_share_v1(
                    black_box(&bootstrap.adapter),
                    black_box(&client_presignature),
                    black_box(&digest32),
                    black_box(&entropy32),
                )
                .expect("client signature share")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("signature_finalize", fixture.name),
        &bootstrap,
        |b, bootstrap| {
            b.iter(|| {
                finalize_signature_v1(
                    black_box(&bootstrap.adapter),
                    black_box(&relayer_presignature),
                    black_box(&digest32),
                    black_box(&entropy32),
                    black_box(&client_signature_share32),
                )
                .expect("finalize signature")
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("explicit_export", fixture.name),
        &export_request,
        |b, request| {
            b.iter(|| export_evm_threshold_v1(black_box(request.clone())).expect("export"))
        },
    );

    group.finish();
}

criterion_group!(benches, bench_derivation_paths, bench_integration_paths);
criterion_main!(benches);
