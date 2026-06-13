use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::reference::evaluate_direct_reference;
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    combine_verified_partials, evaluate_partial, evaluate_partial_with_dleq_proof,
    generate_signing_root, split_signing_root, verify_partial_dleq_proof, PrfPartial,
    SigningRootScalar, SigningRootShare, ThresholdPolicy, ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfOutput32, PrfPurpose, SuiteId};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn policy(threshold: u16, share_count: u16) -> ThresholdPolicy {
    ThresholdPolicy::from_u16s(threshold, share_count).expect("benchmark policy is valid")
}

fn wallet_context() -> PrfContext {
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
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
    let policy_2_of_3 = policy(2, 3);
    let policy_3_of_5 = policy(3, 5);
    let context = wallet_context();
    let shares_2_of_3 =
        split_signing_root(&root, policy_2_of_3, &mut setup_rng).expect("benchmark split succeeds");
    let shares_3_of_5 =
        split_signing_root(&root, policy_3_of_5, &mut setup_rng).expect("benchmark split succeeds");
    let partials_2_of_3 = ValidatedThresholdSet::from_partials(
        policy_2_of_3,
        vec![
            partial(&shares_2_of_3[0], &context),
            partial(&shares_2_of_3[2], &context),
        ],
    )
    .expect("benchmark partial set is valid");
    let partials_3_of_5 = ValidatedThresholdSet::from_partials(
        policy_3_of_5,
        vec![
            partial(&shares_3_of_5[0], &context),
            partial(&shares_3_of_5[2], &context),
            partial(&shares_3_of_5[4], &context),
        ],
    )
    .expect("benchmark partial set is valid");

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
            || seeded_rng(12),
            |mut rng| {
                split_signing_root(
                    black_box(&root),
                    black_box(policy_2_of_3),
                    black_box(&mut rng),
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("split_signing_root_3_of_5", |b| {
        b.iter_batched(
            || seeded_rng(13),
            |mut rng| {
                split_signing_root(
                    black_box(&root),
                    black_box(policy_3_of_5),
                    black_box(&mut rng),
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("evaluate_direct_reference", |b| {
        b.iter(|| direct_reference(black_box(&root), black_box(&context)))
    });

    group.bench_function("evaluate_partial", |b| {
        b.iter(|| partial(black_box(&shares_3_of_5[0]), black_box(&context)))
    });

    group.bench_function("combine_partials_2_of_3", |b| {
        b.iter(|| combine_partials(black_box(&partials_2_of_3), black_box(&context)).unwrap())
    });

    group.bench_function("combine_partials_3_of_5", |b| {
        b.iter(|| combine_partials(black_box(&partials_3_of_5), black_box(&context)).unwrap())
    });

    group.bench_function("one_runtime_evaluate_2_of_3_partials_and_combine", |b| {
        b.iter(|| {
            let set = ValidatedThresholdSet::from_partials(
                policy_2_of_3,
                vec![
                    partial(black_box(&shares_2_of_3[0]), black_box(&context)),
                    partial(black_box(&shares_2_of_3[2]), black_box(&context)),
                ],
            )
            .unwrap();
            combine_partials(black_box(&set), black_box(&context)).unwrap()
        })
    });

    group.bench_function("one_runtime_evaluate_3_of_5_partials_and_combine", |b| {
        b.iter(|| {
            let set = ValidatedThresholdSet::from_partials(
                policy_3_of_5,
                vec![
                    partial(black_box(&shares_3_of_5[0]), black_box(&context)),
                    partial(black_box(&shares_3_of_5[2]), black_box(&context)),
                    partial(black_box(&shares_3_of_5[4]), black_box(&context)),
                ],
            )
            .unwrap();
            combine_partials(black_box(&set), black_box(&context)).unwrap()
        })
    });

    group.bench_function("evaluate_partial_with_dleq_proof", |b| {
        b.iter_batched(
            || seeded_rng(14),
            |mut rng| {
                evaluate_partial_with_dleq_proof(
                    black_box(&shares_3_of_5[0]),
                    black_box(&context),
                    black_box(&mut rng),
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    let proof_bundle =
        evaluate_partial_with_dleq_proof(&shares_3_of_5[0], &context, &mut seeded_rng(15))
            .expect("benchmark proof fixture");
    let proof_bundles = ValidatedThresholdSet::from_proof_bundles(
        policy_3_of_5,
        vec![
            proof_bundle.clone(),
            evaluate_partial_with_dleq_proof(&shares_3_of_5[2], &context, &mut seeded_rng(16))
                .expect("benchmark proof fixture"),
            evaluate_partial_with_dleq_proof(&shares_3_of_5[4], &context, &mut seeded_rng(17))
                .expect("benchmark proof fixture"),
        ],
    )
    .expect("benchmark proof set is valid");
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

    group.bench_function("combine_verified_partials_3_of_5", |b| {
        b.iter(|| {
            combine_verified_partials(black_box(&proof_bundles), black_box(&context)).unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_threshold_prf);
criterion_main!(benches);
