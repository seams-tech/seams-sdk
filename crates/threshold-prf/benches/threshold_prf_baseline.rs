use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::{
    combine_partials, derive_output_from_signing_root_shares, evaluate_direct_reference,
    evaluate_partial, evaluate_partial_with_dleq_proof, generate_signing_root,
    refresh_signing_root_shares_2_of_3, split_signing_root_2_of_3, verify_partial_dleq_proof,
    PrfContext, PrfOutput32, PrfPartial, PrfPurpose, SigningRootScalar, SigningRootShare, SuiteId,
};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn wallet_context() -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        PrfPurpose::EcdsaHssYRelayer,
        b"project:alpha/wallet:0",
    )
}

fn direct_reference(root: &SigningRootScalar, context: &PrfContext) -> PrfOutput32 {
    evaluate_direct_reference(root, context).expect("benchmark context is valid")
}

fn partial(share: &SigningRootShare, context: &PrfContext) -> PrfPartial {
    evaluate_partial(share, context).expect("benchmark context is valid")
}

fn bench_threshold_prf(c: &mut Criterion) {
    let mut setup_rng = seeded_rng(42);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root_2_of_3(&root, &mut setup_rng);
    let context = wallet_context();
    let partials = [partial(&shares[0], &context), partial(&shares[1], &context)];

    let mut group = c.benchmark_group("threshold_prf");

    group.bench_function("generate_signing_root", |b| {
        b.iter_batched(
            || seeded_rng(1),
            |mut rng| generate_signing_root(black_box(&mut rng)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("split_signing_root_2_of_3", |b| {
        b.iter_batched(
            || seeded_rng(2),
            |mut rng| split_signing_root_2_of_3(black_box(&root), black_box(&mut rng)),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("evaluate_direct_reference", |b| {
        b.iter(|| direct_reference(black_box(&root), black_box(&context)))
    });

    group.bench_function("evaluate_partial", |b| {
        b.iter(|| partial(black_box(&shares[0]), black_box(&context)))
    });

    group.bench_function("combine_partials", |b| {
        b.iter(|| combine_partials(black_box(&partials), black_box(&context)).unwrap())
    });

    group.bench_function("option_a_evaluate_two_partials_and_combine", |b| {
        b.iter(|| {
            let left = partial(black_box(&shares[0]), black_box(&context));
            let right = partial(black_box(&shares[2]), black_box(&context));
            combine_partials(black_box(&[left, right]), black_box(&context)).unwrap()
        })
    });

    group.bench_function("derive_output_from_signing_root_shares", |b| {
        b.iter(|| {
            derive_output_from_signing_root_shares(
                black_box(&[shares[0].clone(), shares[2].clone()]),
                black_box(&context),
            )
            .unwrap()
        })
    });

    group.bench_function("evaluate_partial_with_dleq_proof", |b| {
        b.iter_batched(
            || seeded_rng(4),
            |mut rng| {
                evaluate_partial_with_dleq_proof(
                    black_box(&shares[0]),
                    black_box(&context),
                    black_box(&mut rng),
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    let proof_bundle = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(5))
        .expect("benchmark proof fixture");
    group.bench_function("verify_partial_dleq_proof", |b| {
        b.iter(|| {
            verify_partial_dleq_proof(
                black_box(&proof_bundle.commitment),
                black_box(&proof_bundle.partial),
                black_box(&context),
                black_box(&proof_bundle.proof),
            )
            .unwrap()
        })
    });

    group.bench_function("refresh_signing_root_shares_2_of_3", |b| {
        b.iter_batched(
            || ([shares[0].clone(), shares[2].clone()], seeded_rng(3)),
            |(shares, mut rng)| {
                refresh_signing_root_shares_2_of_3(black_box(&shares), black_box(&mut rng)).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_threshold_prf);
criterion_main!(benches);
