use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use router_ab_ecdsa_presign::{
    proofs::TripleIndex,
    triples::base_rot::{
        receive_client_base_rot_sender_hello, start_client_base_rot_sender, BASE_OT_COUNT,
    },
};
use router_ab_ecdsa_wire::{PairContextDigest, PresignPairContext, SigningScopeDigest};

const EXPECTED_CHOICES: &str = "477078fa3f4cdc359d609930e477a458";
const EXPECTED_SENDER_0_0: &str = "b22b05c99f27c44b9027d5d4daad7b40";
const EXPECTED_SENDER_0_1: &str = "e1427d957dd2cd95f962a39d426c93e6";
const EXPECTED_RECEIVER_0: &str = "e1427d957dd2cd95f962a39d426c93e6";
const EXPECTED_SENDER_127_0: &str = "9d381be046218fb3621ec33b5a21caea";
const EXPECTED_SENDER_127_1: &str = "ea0670e766144da36b45cba6f3d6500a";
const EXPECTED_RECEIVER_127: &str = "9d381be046218fb3621ec33b5a21caea";

fn binding() -> PresignPairContext {
    PresignPairContext::new(
        SigningScopeDigest::new([0x24; 32]),
        PairContextDigest::new([0x42; 32]),
    )
}

fn choice_at(choices: &[u8; 16], index: usize) -> usize {
    usize::from((choices[index / 8] >> (index % 8)) & 1)
}

#[test]
fn fixed_base_rot_vector_is_stable_and_correlated() {
    let mut sender_rng = ChaCha20Rng::from_seed([0x51; 32]);
    let mut receiver_rng = ChaCha20Rng::from_seed([0x52; 32]);
    let (sender_state, hello) =
        start_client_base_rot_sender(binding(), TripleIndex::Zero, &mut sender_rng)
            .expect("sender starts");
    let (receiver_output, response) = receive_client_base_rot_sender_hello(
        binding(),
        TripleIndex::Zero,
        hello,
        &mut receiver_rng,
    )
    .expect("receiver responds");
    let sender_output = sender_state.receive(response).expect("sender finishes");
    let sender_keys = sender_output.into_test_keys();
    let (choices, receiver_keys) = receiver_output.into_test_parts();

    for index in 0..BASE_OT_COUNT {
        assert_eq!(
            receiver_keys[index],
            sender_keys[index][choice_at(&choices, index)]
        );
    }

    assert_eq!(hex::encode(choices), EXPECTED_CHOICES);
    assert_eq!(hex::encode(sender_keys[0][0]), EXPECTED_SENDER_0_0);
    assert_eq!(hex::encode(sender_keys[0][1]), EXPECTED_SENDER_0_1);
    assert_eq!(hex::encode(receiver_keys[0]), EXPECTED_RECEIVER_0);
    assert_eq!(hex::encode(sender_keys[127][0]), EXPECTED_SENDER_127_0);
    assert_eq!(hex::encode(sender_keys[127][1]), EXPECTED_SENDER_127_1);
    assert_eq!(hex::encode(receiver_keys[127]), EXPECTED_RECEIVER_127);
}
