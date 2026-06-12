#![forbid(unsafe_code)]

use std::hint::black_box;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::{
    combine_partials, combine_verified_partials, derive_output_from_signing_root_share_wires,
    derive_output_from_signing_root_shares, evaluate_partial, evaluate_partial_with_dleq_proof,
    generate_signing_root, split_signing_root_2_of_3, verify_partial_dleq_proof, PrfContext,
    PrfPurpose, SigningRootShareWireV1, SuiteId,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn benchmark_option_a(iterations: u32) -> u8 {
    let (shares, context) = fixture();
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let left = evaluate_partial(black_box(&shares[0]), black_box(&context))
            .expect("benchmark context is valid");
        let right = evaluate_partial(black_box(&shares[2]), black_box(&context))
            .expect("benchmark context is valid");
        let output = combine_partials(black_box(&[left, right]), black_box(&context))
            .expect("benchmark partials combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_option_a_helper(iterations: u32) -> u8 {
    let (shares, context) = fixture();
    let share_pair = [shares[0].clone(), shares[2].clone()];
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let output =
            derive_output_from_signing_root_shares(black_box(&share_pair), black_box(&context))
                .expect("benchmark shares combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_option_a_share_wires(iterations: u32) -> u8 {
    let (shares, context) = fixture();
    let share_wires = [
        SigningRootShareWireV1::from_share(&shares[0]),
        SigningRootShareWireV1::from_share(&shares[2]),
    ];
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let output =
            derive_output_from_signing_root_share_wires(black_box(&share_wires), black_box(&context))
                .expect("benchmark share wires combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_prove(iterations: u32) -> u8 {
    let (shares, context) = fixture();
    let mut rng = seeded_rng(4);
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
pub fn benchmark_dleq_combine_verified(iterations: u32) -> u8 {
    let (shares, context) = fixture();
    let left = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(6))
        .expect("benchmark proof fixture");
    let right = evaluate_partial_with_dleq_proof(&shares[2], &context, &mut seeded_rng(7))
        .expect("benchmark proof fixture");
    let proof_bundles = [left, right];
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
    let (shares, context) = fixture();
    let mut rng = seeded_rng(5);
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

fn fixture() -> ([threshold_prf::SigningRootShare; 3], PrfContext) {
    let mut rng = seeded_rng(42);
    let root = generate_signing_root(&mut rng);
    let shares = split_signing_root_2_of_3(&root, &mut rng);
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        PrfPurpose::EcdsaHssYRelayer,
        b"project:alpha/wallet:0",
    );
    (shares, context)
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}
