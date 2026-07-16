use k256::{elliptic_curve::ff::PrimeField, Scalar};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use router_ab_ecdsa_presign::{
    proofs::TripleIndex,
    triples::base_rot::{
        extension::{
            mta::{
                receive_client_mta_ciphertexts, start_client_multiplication_sender,
                ClientMtaCiphertextMessage, ClientMultiplicationOperands,
                SigningWorkerMtaResponseMessage, SigningWorkerMultiplicationOperands,
                MTA_INSTANCE_COUNT, MTA_OT_COUNT,
            },
            start_client_extension_sender, start_signing_worker_extension_receiver,
        },
        receive_signing_worker_base_rot_sender_hello, start_signing_worker_base_rot_sender,
    },
};
use router_ab_ecdsa_wire::{
    PairContextDigest, PresignPairContext, ScalarBytes, SigningScopeDigest,
};

const EXPECTED_CIPHERTEXT_0_0: &str =
    "b64257459c450edcfbc93eca3071422658e0c38ec60aea07b46da43c12c0242a";
const EXPECTED_CIPHERTEXT_0_1: &str =
    "078bd6e93a380f41177835cf271440e487b900ff0b7b71ea310887c5801a9bcf";
const EXPECTED_CIPHERTEXT_767_0: &str =
    "ef1e019ee1d2a6c6997e031bada9e62964794e6e1edc7b3a7c042082c30c18eb";
const EXPECTED_CIPHERTEXT_767_1: &str =
    "3b78ca5275703decf1b5e3fe443980ac8e761127d1d1b3b74b9ee4242581c4ff";
const EXPECTED_CHI_FIRST_0: &str =
    "04791bc6dc9b14b17d31d3c4ff1cd96329e05bf592bafc9b8518484e412b24cd";
const EXPECTED_CHI_FIRST_1: &str =
    "5cc2b0cb876998d8c7ac3a154fbb4882070ddc1f5af1daa398699f3ce07a8329";
const EXPECTED_SEED_0: &str = "c0579fdc21c3e1338c85757fa1e91ddf2d9f0ecaf52950f069bd3d94853bd2e8";
const EXPECTED_SEED_1: &str = "58672b87593a8f4ecc40287ffc3b422514d0f66c537dfd554e8bab517cf5b48a";
const EXPECTED_CLIENT_SHARE: &str =
    "1d5114b125691dfe981ff4f35d91ce9fce5eaca11aa5454cf6c231f3271d77bb";
const EXPECTED_WORKER_SHARE: &str =
    "e2aeeb4eda96e20167e00b0ca26e315eec50304594a35aeec9102c99a918cbb6";

fn binding() -> PresignPairContext {
    PresignPairContext::new(
        SigningScopeDigest::new([0x24; 32]),
        PairContextDigest::new([0x42; 32]),
    )
}

fn scalar_bytes(value: u64) -> ScalarBytes {
    ScalarBytes::new(Scalar::from(value).to_bytes().into())
}

fn parse_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).expect("canonical scalar")
}

#[test]
fn fixed_corrected_mta_vector_is_stable_and_reconstructs_the_product() {
    let mut base_sender_rng = ChaCha20Rng::from_seed([0x61; 32]);
    let mut base_receiver_rng = ChaCha20Rng::from_seed([0x62; 32]);
    let (worker_base_state, hello) =
        start_signing_worker_base_rot_sender(binding(), TripleIndex::Zero, &mut base_sender_rng)
            .expect("base sender starts");
    let (client_base_output, response) = receive_signing_worker_base_rot_sender_hello(
        binding(),
        TripleIndex::Zero,
        hello,
        &mut base_receiver_rng,
    )
    .expect("base receiver responds");
    let worker_base_output = worker_base_state
        .receive(response)
        .expect("base sender finishes");
    let mut extension_receiver_rng = ChaCha20Rng::from_seed([0x63; 32]);
    let mut extension_sender_rng = ChaCha20Rng::from_seed([0x64; 32]);
    let (worker_extension_state, correlation) =
        start_signing_worker_extension_receiver(worker_base_output, &mut extension_receiver_rng)
            .expect("extension receiver starts");
    let (client_extension_state, challenge) = start_client_extension_sender(
        binding(),
        TripleIndex::Zero,
        client_base_output,
        correlation,
        &mut extension_sender_rng,
    )
    .expect("extension sender starts");
    let (worker_accept_state, proof) = worker_extension_state
        .receive(challenge)
        .expect("extension proof");
    let (client_random_ot, acceptance) = client_extension_state
        .receive(proof)
        .expect("extension proof accepted");
    let worker_random_ot = worker_accept_state
        .receive(acceptance)
        .expect("extension receiver releases output");

    let client_operands = ClientMultiplicationOperands::from_parts(
        binding(),
        TripleIndex::Zero,
        scalar_bytes(7),
        scalar_bytes(11),
    )
    .expect("client operands");
    let worker_operands = SigningWorkerMultiplicationOperands::from_parts(
        binding(),
        TripleIndex::Zero,
        scalar_bytes(13),
        scalar_bytes(17),
    )
    .expect("worker operands");
    let mut mta_sender_rng = ChaCha20Rng::from_seed([0x65; 32]);
    let mut mta_receiver_rng = ChaCha20Rng::from_seed([0x66; 32]);
    let (client_mta_state, ciphertexts) =
        start_client_multiplication_sender(client_random_ot, client_operands, &mut mta_sender_rng)
            .expect("MTA sender starts");
    let (ciphertext_context, ciphertext_index, ciphertext_values) = ciphertexts.into_parts();
    let first_ciphertext = ciphertext_values[0][0];
    let last_ciphertext = ciphertext_values[MTA_INSTANCE_COUNT - 1][MTA_OT_COUNT - 1];
    let ciphertexts = ClientMtaCiphertextMessage::from_parts(
        ciphertext_context,
        ciphertext_index,
        ciphertext_values,
    )
    .expect("ciphertexts round trip");
    let (worker_share, response) = receive_client_mta_ciphertexts(
        binding(),
        worker_random_ot,
        worker_operands,
        ciphertexts,
        &mut mta_receiver_rng,
    )
    .expect("MTA receiver responds");
    let (response_context, response_index, chi_first, seeds) = response.into_parts();
    let response = SigningWorkerMtaResponseMessage::from_parts(
        response_context,
        response_index,
        chi_first,
        seeds,
    )
    .expect("response round trip");
    let client_share = client_mta_state
        .receive(response)
        .expect("MTA sender finishes");
    let (_, _, client_share_bytes) = client_share.into_test_parts();
    let (_, _, worker_share_bytes) = worker_share.into_test_parts();

    assert_eq!(
        parse_scalar(client_share_bytes) + parse_scalar(worker_share_bytes),
        Scalar::from(20u64) * Scalar::from(28u64)
    );

    assert_eq!(hex::encode(first_ciphertext[0]), EXPECTED_CIPHERTEXT_0_0);
    assert_eq!(hex::encode(first_ciphertext[1]), EXPECTED_CIPHERTEXT_0_1);
    assert_eq!(hex::encode(last_ciphertext[0]), EXPECTED_CIPHERTEXT_767_0);
    assert_eq!(hex::encode(last_ciphertext[1]), EXPECTED_CIPHERTEXT_767_1);
    assert_eq!(hex::encode(chi_first[0]), EXPECTED_CHI_FIRST_0);
    assert_eq!(hex::encode(chi_first[1]), EXPECTED_CHI_FIRST_1);
    assert_eq!(hex::encode(seeds[0]), EXPECTED_SEED_0);
    assert_eq!(hex::encode(seeds[1]), EXPECTED_SEED_1);
    assert_eq!(hex::encode(client_share_bytes), EXPECTED_CLIENT_SHARE);
    assert_eq!(hex::encode(worker_share_bytes), EXPECTED_WORKER_SHARE);
}
