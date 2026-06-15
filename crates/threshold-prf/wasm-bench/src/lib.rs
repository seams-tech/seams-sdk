#![forbid(unsafe_code)]

use std::hint::black_box;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    combine_verified_partials, evaluate_partial, evaluate_partial_with_dleq_proof,
    generate_signing_root, split_signing_root, verify_partial_dleq_proof, SigningRootShare,
    ThresholdPolicy, ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn benchmark_one_runtime_2_of_3(iterations: u32) -> u8 {
    let (policy, shares, context) = fixture(2, 3);
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let partials = ValidatedThresholdSet::from_partials(
            policy,
            vec![
                evaluate_partial(black_box(&shares[0]), black_box(&context))
                    .expect("benchmark context is valid"),
                evaluate_partial(black_box(&shares[2]), black_box(&context))
                    .expect("benchmark context is valid"),
            ],
        )
        .expect("benchmark partial set is valid");
        let output =
            combine_partials(black_box(&partials), black_box(&context)).expect("partials combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_one_runtime_3_of_5(iterations: u32) -> u8 {
    let (policy, shares, context) = fixture(3, 5);
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let partials = ValidatedThresholdSet::from_partials(
            policy,
            vec![
                evaluate_partial(black_box(&shares[0]), black_box(&context))
                    .expect("benchmark context is valid"),
                evaluate_partial(black_box(&shares[2]), black_box(&context))
                    .expect("benchmark context is valid"),
                evaluate_partial(black_box(&shares[4]), black_box(&context))
                    .expect("benchmark context is valid"),
            ],
        )
        .expect("benchmark partial set is valid");
        let output =
            combine_partials(black_box(&partials), black_box(&context)).expect("partials combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_prove(iterations: u32) -> u8 {
    let (_, shares, context) = fixture(3, 5);
    let mut rng = seeded_rng(8);
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let bundle = evaluate_partial_with_dleq_proof(
            black_box(&shares[0]),
            black_box(&context),
            black_box(&mut rng),
        )
        .expect("benchmark proof generation succeeds");
        checksum ^= bundle.proof.to_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_combine_verified_3_of_5(iterations: u32) -> u8 {
    let (policy, shares, context) = fixture(3, 5);
    let proof_bundles = ValidatedThresholdSet::from_proof_bundles(
        policy,
        vec![
            evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(9))
                .expect("benchmark proof fixture"),
            evaluate_partial_with_dleq_proof(&shares[2], &context, &mut seeded_rng(10))
                .expect("benchmark proof fixture"),
            evaluate_partial_with_dleq_proof(&shares[4], &context, &mut seeded_rng(11))
                .expect("benchmark proof fixture"),
        ],
    )
    .expect("benchmark proof set is valid");
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let output = combine_verified_partials(black_box(&proof_bundles), black_box(&context))
            .expect("benchmark verified combine succeeds");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_verify(iterations: u32) -> u8 {
    let (_, shares, context) = fixture(3, 5);
    let mut rng = seeded_rng(12);
    let bundle = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut rng)
        .expect("benchmark proof fixture");
    let mut checksum = 0u8;

    for _ in 0..iterations {
        verify_partial_dleq_proof(
            black_box(&bundle.commitment),
            black_box(&bundle.partial),
            black_box(&context),
            black_box(&bundle.proof),
        )
        .expect("benchmark proof verifies");
        checksum ^= bundle.proof.challenge_bytes()[0];
    }

    checksum
}

fn fixture(
    threshold: u16,
    share_count: u16,
) -> (ThresholdPolicy, Vec<SigningRootShare>, PrfContext) {
    let mut rng = seeded_rng(42);
    let root = generate_signing_root(&mut rng);
    let policy =
        ThresholdPolicy::from_u16s(threshold, share_count).expect("benchmark policy is valid");
    let shares = split_signing_root(&root, policy, &mut rng).expect("benchmark split succeeds");
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512,
        PrfPurpose::EcdsaHssYServer,
        b"project:alpha/wallet:0",
    );
    (policy, shares, context)
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}
