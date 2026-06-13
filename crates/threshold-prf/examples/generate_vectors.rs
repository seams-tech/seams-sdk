use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use threshold_prf::reference::evaluate_direct_reference;
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    evaluate_partial, generate_signing_root, split_signing_root, PrfPartial, PrfPartialWire,
    SigningRootShare, SigningRootShareWire, ThresholdPolicy, ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};

#[derive(Serialize)]
struct ProtocolCorpus {
    schema_id: &'static str,
    vectors: Vec<ProtocolVector>,
}

#[derive(Serialize)]
struct ProtocolVector {
    suite_id: String,
    purpose: String,
    context_hex: String,
    policy: PolicyVector,
    root_seed_hex: String,
    split_seed_hex: String,
    root_scalar_hex: String,
    shares: Vec<ShareVector>,
    partials: Vec<PartialVector>,
    direct_output_hex: String,
    threshold_outputs: Vec<ThresholdOutputVector>,
}

#[derive(Serialize)]
struct PolicyVector {
    threshold: u16,
    share_count: u16,
}

#[derive(Serialize)]
struct ShareVector {
    id: u16,
    scalar_hex: String,
    wire_hex: String,
}

#[derive(Serialize)]
struct PartialVector {
    id: u16,
    context_tag_hex: String,
    compressed_point_hex: String,
    wire_hex: String,
}

#[derive(Serialize)]
struct ThresholdOutputVector {
    ids: Vec<u16>,
    output_hex: String,
}

fn main() {
    let corpus = ProtocolCorpus {
        schema_id: "threshold-prf/protocol-t-of-n-fixtures/v1",
        vectors: vec![
            vector_for(
                ThresholdPolicy::from_u16s(2, 3).expect("valid canonical policy"),
                [0x91; 32],
                [0x92; 32],
                PrfPurpose::EcdsaHssYRelayer,
                b"threshold-prf/vector:2-of-3".to_vec(),
            ),
            vector_for(
                ThresholdPolicy::from_u16s(3, 5).expect("valid canonical policy"),
                [0xa1; 32],
                [0xa2; 32],
                PrfPurpose::RouterAbXRelayerBaseV1,
                b"threshold-prf/vector:3-of-5".to_vec(),
            ),
            vector_for(
                ThresholdPolicy::from_u16s(2, 3).expect("valid canonical policy"),
                [0xb1; 32],
                [0xb2; 32],
                PrfPurpose::RouterAbXRelayerBaseV1,
                router_ab_relayer_context_v1(),
            ),
        ],
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&corpus).expect("canonical fixture corpus serializes")
    );
}

fn vector_for(
    policy: ThresholdPolicy,
    root_seed: [u8; 32],
    split_seed: [u8; 32],
    purpose: PrfPurpose,
    context_bytes: Vec<u8>,
) -> ProtocolVector {
    let mut root_rng = ChaCha20Rng::from_seed(root_seed);
    let mut split_rng = ChaCha20Rng::from_seed(split_seed);
    let root = generate_signing_root(&mut root_rng);
    let shares =
        split_signing_root(&root, policy, &mut split_rng).expect("canonical split succeeds");
    let context = PrfContext::new(SuiteId::Ristretto255Sha512, purpose.clone(), context_bytes);
    let partials = shares
        .iter()
        .map(|share| evaluate_partial(share, &context).expect("canonical partial succeeds"))
        .collect::<Vec<_>>();

    ProtocolVector {
        suite_id: String::from_utf8(SuiteId::Ristretto255Sha512.as_bytes().to_vec()).unwrap(),
        purpose: String::from_utf8(purpose.as_bytes().to_vec()).unwrap(),
        context_hex: hex(&context.context_bytes),
        policy: PolicyVector {
            threshold: policy.threshold().get(),
            share_count: policy.share_count().get(),
        },
        root_seed_hex: hex(&root_seed),
        split_seed_hex: hex(&split_seed),
        root_scalar_hex: hex(&root.to_bytes()),
        shares: shares.iter().map(share_vector).collect(),
        partials: partials.iter().map(partial_vector).collect(),
        direct_output_hex: hex(evaluate_direct_reference(&root, &context)
            .expect("canonical direct succeeds")
            .as_bytes()),
        threshold_outputs: threshold_outputs(policy, &partials, &context),
    }
}

fn share_vector(share: &SigningRootShare) -> ShareVector {
    ShareVector {
        id: share.id().get().get(),
        scalar_hex: hex(&share.to_bytes()),
        wire_hex: hex(&SigningRootShareWire::from_share(share).to_bytes()),
    }
}

fn partial_vector(partial: &PrfPartial) -> PartialVector {
    PartialVector {
        id: partial.id().get().get(),
        context_tag_hex: hex(partial.context_tag()),
        compressed_point_hex: hex(&partial.to_compressed()),
        wire_hex: hex(&PrfPartialWire::from_partial(partial).to_bytes()),
    }
}

fn threshold_outputs(
    policy: ThresholdPolicy,
    partials: &[PrfPartial],
    context: &PrfContext,
) -> Vec<ThresholdOutputVector> {
    threshold_subsets(policy.threshold().get(), policy.share_count().get())
        .into_iter()
        .map(|ids| {
            let selected = ids
                .iter()
                .map(|id| {
                    partials
                        .iter()
                        .find(|partial| partial.id().get().get() == *id)
                        .expect("partial id exists")
                        .clone()
                })
                .collect();
            let set = ValidatedThresholdSet::from_partials(policy, selected)
                .expect("canonical threshold set validates");
            let output = combine_partials(&set, context).expect("canonical partials combine");
            ThresholdOutputVector {
                ids,
                output_hex: hex(output.as_bytes()),
            }
        })
        .collect()
}

fn threshold_subsets(threshold: u16, share_count: u16) -> Vec<Vec<u16>> {
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(usize::from(threshold));
    push_threshold_subsets(1, threshold, share_count, &mut current, &mut out);
    out
}

fn push_threshold_subsets(
    next_id: u16,
    threshold: u16,
    share_count: u16,
    current: &mut Vec<u16>,
    out: &mut Vec<Vec<u16>>,
) {
    if current.len() == usize::from(threshold) {
        out.push(current.clone());
        return;
    }
    for id in next_id..=share_count {
        current.push(id);
        push_threshold_subsets(id + 1, threshold, share_count, current, out);
        current.pop();
    }
}

fn router_ab_relayer_context_v1() -> Vec<u8> {
    hex_to_bytes(
        "0000002d726f757465722d61622d64657269766174696f6e2f6d70632d7072662f636f6e746578742d62797465732f7631000000217468726573686f6c645f7072665f72697374726574746f3235355f736861353132000000217468726573686f6c642d7072662f72697374726574746f3235352d7368613531320000001b726f757465722d61622f785f72656c617965725f626173652f76310000001b63616e6f6e6963616c5f656432353531395f7363616c61725f333200000020b87b29b1a50ce49c58ea33f6341715f68890c77f41d73582f166744085bf70580000000e785f72656c617965725f626173650000000772656c617965720000001b726f6c653a72656c617965723a6c6f63616c3a7368613235362d72",
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len() / 2)
        .map(|index| {
            (hex_nibble(hex.as_bytes()[index * 2]) << 4) | hex_nibble(hex.as_bytes()[index * 2 + 1])
        })
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => 10 + (byte - b'a'),
        b'A'..=b'F' => 10 + (byte - b'A'),
        _ => panic!("invalid hex byte"),
    }
}
