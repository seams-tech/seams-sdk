use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    plan_mpc_prf_combine_v1, plan_mpc_prf_partial_verification_v1, AccountScope, CandidateId,
    CorrectnessLevel, DerivationContext, MpcPrfCombinerInputV1, MpcPrfDleqProofWireV1,
    MpcPrfOutputEncodingV1, MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1, MpcPrfPartialBindingV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialVerificationInputV1, MpcPrfPartialWireV1,
    MpcPrfPurposeBindingPlanV1, MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialInputV1,
    MpcPrfSignerPartialV1, MpcPrfSuiteId, MpcPrfVerifiedPartialV1, OpenedShareKind, RequestKind,
    Role, RootShareEpoch, SignerSetBinding, TranscriptBinding, MPC_PRF_COMMITMENT_WIRE_V1_LEN,
    MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
};
use threshold_prf::{
    combine_verified_partials, evaluate_partial_with_dleq_proof, generate_signing_root,
    split_signing_root, verify_partial_dleq_proof, SigningRootShare, ThresholdPolicy,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext as ThresholdPrfContext, PrfPurpose, SuiteId};

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn sample_context() -> DerivationContext {
    sample_context_for(CandidateId::MpcThresholdPrfV1)
}

fn sample_context_for(candidate_id: CandidateId) -> DerivationContext {
    DerivationContext::new(
        candidate_id,
        RequestKind::Registration,
        CorrectnessLevel::MinimumLevelC,
        AccountScope::new(
            "near-testnet",
            "alice.testnet",
            "ed25519:11111111111111111111111111111111",
        )
        .expect("account scope"),
        RootShareEpoch::new("epoch-1").expect("epoch"),
        "ceremony-1",
    )
    .expect("context")
}

fn sample_transcript(context: DerivationContext) -> TranscriptBinding {
    TranscriptBinding::new(
        context,
        "role:router:local:sha256-router",
        SignerSetBinding::v1_all2(
            "signer-set-v1",
            "role:signer-a:local:sha256-a",
            "key-epoch-a-1",
            "role:signer-b:local:sha256-b",
            "key-epoch-b-1",
        )
        .expect("signer set"),
        "role:server:local:sha256-r",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "role:client:local:sha256-c",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript")
}

fn output_request() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(
        OpenedShareKind::XClientBase,
        Role::Client,
        "role:client:local:sha256-c",
    )
    .expect("output request")
}

fn signer_input(role: Role, identity: &str) -> MpcPrfSignerPartialInputV1 {
    let context = sample_context_for(CandidateId::MpcThresholdPrfV1);
    let transcript = sample_transcript(context.clone());
    MpcPrfSignerPartialInputV1::new(
        context,
        transcript,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512,
        role,
        identity,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        vec![output_request()],
    )
    .expect("signer input")
}

fn mpc_prf_purpose_plan() -> MpcPrfPurposeBindingPlanV1 {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let request = output_request();
    router_ab_core::plan_mpc_prf_purpose_binding_v1(&input, &request).expect("purpose plan")
}

fn threshold_purpose(output_purpose: MpcPrfOutputPurposeV1) -> PrfPurpose {
    match output_purpose {
        MpcPrfOutputPurposeV1::RouterAbXClientBase => PrfPurpose::RouterAbXClientBaseV1,
        MpcPrfOutputPurposeV1::RouterAbXServerBase => PrfPurpose::RouterAbXServerBaseV1,
    }
}

fn threshold_context(plan: &MpcPrfPurposeBindingPlanV1) -> ThresholdPrfContext {
    assert_eq!(
        plan.output_encoding,
        MpcPrfOutputEncodingV1::CanonicalEd25519Scalar32
    );
    ThresholdPrfContext::new(
        SuiteId::Ristretto255Sha512,
        threshold_purpose(plan.output_purpose),
        plan.threshold_prf_context_bytes.clone(),
    )
}

fn mpc_prf_threshold_policy() -> ThresholdPolicy {
    ThresholdPolicy::from_u16s(2, 3).expect("Router/A/B benchmark policy")
}

fn mpc_prf_crypto_fixture() -> (Vec<SigningRootShare>, ThresholdPolicy, ThresholdPrfContext) {
    let mut setup_rng = seeded_rng(42);
    let root = generate_signing_root(&mut setup_rng);
    let policy = mpc_prf_threshold_policy();
    let shares = split_signing_root(&root, policy, &mut setup_rng).expect("threshold shares");
    let plan = mpc_prf_purpose_plan();
    (shares, policy, threshold_context(&plan))
}

fn signer_partial(role: Role, identity: &str, byte: u8) -> MpcPrfSignerPartialV1 {
    let input = signer_input(role, identity);
    let binding = MpcPrfPartialBindingV1::from_signer_input(&input, &input.output_requests[0])
        .expect("partial binding");
    MpcPrfSignerPartialV1::new(
        binding,
        MpcPrfPartialWireV1::new(vec![byte; MPC_PRF_PARTIAL_WIRE_V1_LEN]).expect("partial wire"),
    )
    .expect("signer partial")
}

fn proof_bundle(role: Role, identity: &str, byte: u8) -> MpcPrfPartialProofBundleV1 {
    MpcPrfPartialProofBundleV1::new(
        signer_partial(role, identity, byte),
        MpcPrfShareCommitmentWireV1::new(vec![byte; MPC_PRF_COMMITMENT_WIRE_V1_LEN])
            .expect("commitment"),
        MpcPrfDleqProofWireV1::new(vec![byte; MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN]).expect("proof"),
    )
    .expect("proof bundle")
}

fn verified_partial(role: Role, identity: &str, byte: u8) -> MpcPrfVerifiedPartialV1 {
    MpcPrfVerifiedPartialV1::from_verified_parts(
        signer_partial(role, identity, byte),
        MpcPrfShareCommitmentWireV1::new(vec![byte; MPC_PRF_COMMITMENT_WIRE_V1_LEN])
            .expect("commitment"),
    )
    .expect("verified partial")
}

fn bench_context_encoding(c: &mut Criterion) {
    let context = sample_context();

    c.bench_function("router_ab_context_encode_v1", |b| {
        b.iter(|| black_box(context.encode_context_v1().expect("context encoding")))
    });
}

fn bench_mpc_prf_signer_input_validation(c: &mut Criterion) {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");

    c.bench_function("router_ab_mpc_prf_signer_input_validate_v1", |b| {
        b.iter(|| black_box(input.validate().expect("signer input validation")))
    });
}

fn bench_mpc_prf_partial_verification_plan(c: &mut Criterion) {
    let context = sample_context_for(CandidateId::MpcThresholdPrfV1);
    let transcript = sample_transcript(context);
    let proof_bundle = proof_bundle(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a);
    let input = MpcPrfPartialVerificationInputV1 {
        transcript,
        proof_bundle,
    };

    c.bench_function("router_ab_mpc_prf_partial_verification_plan_v1", |b| {
        b.iter(|| {
            black_box(
                plan_mpc_prf_partial_verification_v1(input.clone())
                    .expect("partial verification plan"),
            )
        })
    });
}

fn bench_mpc_prf_purpose_binding_plan(c: &mut Criterion) {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let request = output_request();

    c.bench_function("router_ab_mpc_prf_purpose_binding_plan_v1", |b| {
        b.iter(|| {
            black_box(
                router_ab_core::plan_mpc_prf_purpose_binding_v1(
                    black_box(&input),
                    black_box(&request),
                )
                .expect("purpose plan"),
            )
        })
    });
}

fn bench_mpc_prf_crypto_evaluate_partial_with_dleq(c: &mut Criterion) {
    let (shares, _policy, context) = mpc_prf_crypto_fixture();

    c.bench_function(
        "router_ab_mpc_prf_crypto_evaluate_partial_with_dleq_v1",
        |b| {
            b.iter_batched(
                || seeded_rng(21),
                |mut rng| {
                    evaluate_partial_with_dleq_proof(
                        black_box(&shares[0]),
                        black_box(&context),
                        black_box(&mut rng),
                    )
                    .expect("proof")
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_mpc_prf_crypto_verify_partial_dleq(c: &mut Criterion) {
    let (shares, _policy, context) = mpc_prf_crypto_fixture();
    let bundle = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(22))
        .expect("proof fixture");

    c.bench_function("router_ab_mpc_prf_crypto_verify_partial_dleq_v1", |b| {
        b.iter(|| {
            black_box(
                verify_partial_dleq_proof(
                    black_box(&bundle.commitment),
                    black_box(&bundle.partial),
                    black_box(&context),
                    black_box(&bundle.proof),
                )
                .expect("proof verifies"),
            )
        })
    });
}

fn bench_mpc_prf_crypto_combine_verified_partials(c: &mut Criterion) {
    let (shares, policy, context) = mpc_prf_crypto_fixture();
    let left = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(23))
        .expect("left proof");
    let right = evaluate_partial_with_dleq_proof(&shares[2], &context, &mut seeded_rng(24))
        .expect("right proof");
    let bundles =
        ValidatedThresholdSet::from_proof_bundles(policy, vec![left, right]).expect("proof set");

    c.bench_function(
        "router_ab_mpc_prf_crypto_combine_verified_partials_v1",
        |b| {
            b.iter(|| {
                black_box(
                    combine_verified_partials(black_box(&bundles), black_box(&context))
                        .expect("verified combine"),
                )
            })
        },
    );
}

fn bench_mpc_prf_crypto_two_proofs_and_combine(c: &mut Criterion) {
    let (shares, policy, context) = mpc_prf_crypto_fixture();

    c.bench_function("router_ab_mpc_prf_crypto_two_proofs_and_combine_v1", |b| {
        b.iter_batched(
            || (seeded_rng(25), seeded_rng(26)),
            |(mut left_rng, mut right_rng)| {
                let left = evaluate_partial_with_dleq_proof(
                    black_box(&shares[0]),
                    black_box(&context),
                    black_box(&mut left_rng),
                )
                .expect("left proof");
                let right = evaluate_partial_with_dleq_proof(
                    black_box(&shares[2]),
                    black_box(&context),
                    black_box(&mut right_rng),
                )
                .expect("right proof");
                let bundles = ValidatedThresholdSet::from_proof_bundles(policy, vec![left, right])
                    .expect("proof set");
                combine_verified_partials(black_box(&bundles), black_box(&context))
                    .expect("verified combine")
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_mpc_prf_combiner_plan(c: &mut Criterion) {
    let context = sample_context_for(CandidateId::MpcThresholdPrfV1);
    let transcript = sample_transcript(context);
    let input = MpcPrfCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: verified_partial(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a),
        right: verified_partial(Role::SignerB, "role:signer-b:local:sha256-b", 0x0b),
    };

    c.bench_function("router_ab_mpc_prf_combiner_plan_v1", |b| {
        b.iter(|| black_box(plan_mpc_prf_combine_v1(input.clone()).expect("combiner plan")))
    });
}

criterion_group!(
    benches,
    bench_context_encoding,
    bench_mpc_prf_signer_input_validation,
    bench_mpc_prf_partial_verification_plan,
    bench_mpc_prf_purpose_binding_plan,
    bench_mpc_prf_crypto_evaluate_partial_with_dleq,
    bench_mpc_prf_crypto_verify_partial_dleq,
    bench_mpc_prf_crypto_combine_verified_partials,
    bench_mpc_prf_crypto_two_proofs_and_combine,
    bench_mpc_prf_combiner_plan
);
criterion_main!(benches);
