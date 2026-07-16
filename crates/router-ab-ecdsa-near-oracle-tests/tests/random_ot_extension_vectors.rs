use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use router_ab_ecdsa_presign::{
    proofs::TripleIndex,
    triples::base_rot::{
        extension::{
            start_client_extension_sender, start_signing_worker_extension_receiver,
            ClientExtensionAcceptanceMessage, ClientExtensionChallengeMessage, EXTENDED_OT_COUNT,
        },
        receive_signing_worker_base_rot_sender_hello, start_signing_worker_base_rot_sender,
    },
};
use router_ab_ecdsa_wire::{PairContextDigest, PresignPairContext, SigningScopeDigest};

const EXPECTED_CHOICES: &str = "a39e3fdc48488539f80d2109aad8ede399a262fe0b8a669ad20a042c4c449d696ae4c8def0248ea6e6cbe1982114e82c5d201ebee502a0aca7e995a482d308d36533c684945ab4c145c6f49d9e5142b73b02a82bcc84ca6be589069deac70b84";
const EXPECTED_CHALLENGE: &str = "0864b3c4fa82ea4d8195e0896d74056587662768cef7d16e191334c7980c68fa";
const EXPECTED_ACCEPTANCE: &str =
    "126cfc3fc300eaca1aa1cbfeef367cd57b4a498a3f1f8cb9f0c2abe41ced8358";
const EXPECTED_SENDER_0_0: &str =
    "318f882c0cf76678484b025ef7345b629d986721f8c5506450aec61352f22769";
const EXPECTED_SENDER_0_1: &str =
    "82d907cfaaea66dc63f9f963edd75a1f871f8178ed7e78828d1c08299082e05d";
const EXPECTED_RECEIVER_0: &str =
    "82d907cfaaea66dc63f9f963edd75a1f871f8178ed7e78828d1c08299082e05d";
const EXPECTED_SENDER_767_0: &str =
    "cd43523b37995047eeb922444776ace98fa404aaec5c73225b7930600e3e14b4";
const EXPECTED_SENDER_767_1: &str =
    "199e1aeecb36e76e46f10326de06476cb9a0c7649f51ab9f2b13f40170b3c0de";
const EXPECTED_RECEIVER_767: &str =
    "199e1aeecb36e76e46f10326de06476cb9a0c7649f51ab9f2b13f40170b3c0de";

fn binding() -> PresignPairContext {
    PresignPairContext::new(
        SigningScopeDigest::new([0x24; 32]),
        PairContextDigest::new([0x42; 32]),
    )
}

fn choice_at(choices: &[u8], index: usize) -> usize {
    usize::from((choices[index / 8] >> (index % 8)) & 1)
}

#[test]
fn corrected_random_ot_extension_vector_is_stable_and_correlated() {
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
    let (worker_state, correlation) =
        start_signing_worker_extension_receiver(worker_base_output, &mut extension_receiver_rng)
            .expect("extension receiver starts");
    let (client_state, challenge) = start_client_extension_sender(
        binding(),
        TripleIndex::Zero,
        client_base_output,
        correlation,
        &mut extension_sender_rng,
    )
    .expect("extension sender starts");
    let (challenge_context, challenge_index, challenge_seed) = challenge.into_parts();
    let challenge = ClientExtensionChallengeMessage::from_parts(
        challenge_context,
        challenge_index,
        challenge_seed,
    );
    let (worker_accept_state, proof) = worker_state.receive(challenge).expect("proof created");
    let (client_output, acceptance) = client_state.receive(proof).expect("proof accepted");
    let (acceptance_context, acceptance_index, acceptance_digest) = acceptance.into_parts();
    let acceptance = ClientExtensionAcceptanceMessage::from_parts(
        acceptance_context,
        acceptance_index,
        acceptance_digest,
    );
    let worker_output = worker_accept_state
        .receive(acceptance)
        .expect("receiver releases output");
    let sender_values = client_output.into_test_values();
    let (choices, receiver_values) = worker_output.into_test_parts();

    for index in 0..EXTENDED_OT_COUNT {
        assert_eq!(
            receiver_values[index],
            sender_values[index][choice_at(&choices, index)]
        );
    }

    assert_eq!(hex::encode(choices), EXPECTED_CHOICES);
    assert_eq!(hex::encode(challenge_seed), EXPECTED_CHALLENGE);
    assert_eq!(hex::encode(acceptance_digest), EXPECTED_ACCEPTANCE);
    assert_eq!(
        hex::encode(sender_values[0][0].to_bytes()),
        EXPECTED_SENDER_0_0
    );
    assert_eq!(
        hex::encode(sender_values[0][1].to_bytes()),
        EXPECTED_SENDER_0_1
    );
    assert_eq!(
        hex::encode(receiver_values[0].to_bytes()),
        EXPECTED_RECEIVER_0
    );
    assert_eq!(
        hex::encode(sender_values[EXTENDED_OT_COUNT - 1][0].to_bytes()),
        EXPECTED_SENDER_767_0
    );
    assert_eq!(
        hex::encode(sender_values[EXTENDED_OT_COUNT - 1][1].to_bytes()),
        EXPECTED_SENDER_767_1
    );
    assert_eq!(
        hex::encode(receiver_values[EXTENDED_OT_COUNT - 1].to_bytes()),
        EXPECTED_RECEIVER_767
    );
}
