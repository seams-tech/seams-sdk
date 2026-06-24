use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ecdsa_hss::{
    derive_client_share, derive_relayer_share_for_client_public, public_transcript_digest,
    reconstruct_export_key, EcdsaHssStableKeyContext, ServerEvalOperation,
};

#[derive(Clone)]
struct BenchmarkFixture {
    name: &'static str,
    context: EcdsaHssStableKeyContext,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
}

fn representative_fixture() -> BenchmarkFixture {
    BenchmarkFixture {
        name: "role-local-v4",
        context: EcdsaHssStableKeyContext::new(fixed_digest32(
            b"ecdsa-hss/bench/application-binding",
        )),
        y_client32_le: fixed_digest32(b"ecdsa-hss/bench/client-root"),
        y_relayer32_le: fixed_digest32(b"ecdsa-hss/bench/relayer-root"),
    }
}

fn fixed_digest32(label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(label).into()
}

pub fn bench_role_local(c: &mut Criterion) {
    let fixture = representative_fixture();
    let mut group = c.benchmark_group("ecdsa_hss_role_local");
    group.throughput(Throughput::Elements(1));

    group.bench_with_input(
        BenchmarkId::new("client_share", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                derive_client_share(
                    black_box(&fixture.context),
                    black_box(fixture.y_client32_le),
                )
                .expect("client share")
            })
        },
    );

    let client_share =
        derive_client_share(&fixture.context, fixture.y_client32_le).expect("client share");
    group.bench_with_input(
        BenchmarkId::new("relayer_share_and_identity", fixture.name),
        &fixture,
        |b, fixture| {
            b.iter(|| {
                derive_relayer_share_for_client_public(
                    black_box(&fixture.context),
                    black_box(fixture.y_relayer32_le),
                    black_box(&client_share.client_public_key33),
                    black_box(client_share.retry_counter),
                )
                .expect("relayer share")
            })
        },
    );

    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &fixture.context,
        fixture.y_relayer32_le,
        &client_share.client_public_key33,
        client_share.retry_counter,
    )
    .expect("relayer share");
    group.bench_function("public_transcript_digest", |b| {
        b.iter(|| {
            public_transcript_digest(
                black_box(ServerEvalOperation::SessionBootstrap),
                black_box(&identity),
            )
            .expect("public transcript")
        })
    });
    group.bench_function("export_reconstruct", |b| {
        b.iter(|| {
            reconstruct_export_key(
                black_box(&client_share),
                black_box(&relayer_share.x_relayer32),
                black_box(&identity),
            )
            .expect("export key")
        })
    });

    group.finish();
}

criterion_group!(benches, bench_role_local);
criterion_main!(benches);
