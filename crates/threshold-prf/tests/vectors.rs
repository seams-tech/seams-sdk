use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use threshold_prf::{
    combine_partials, evaluate_direct_reference, evaluate_partial, generate_signing_root,
    split_signing_root, PrfDleqProof, PrfPartial, PrfPartialWire, SigningRootShare,
    SigningRootShareCommitment, SigningRootShareWire, ThresholdPolicy, ThresholdShareId,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};

#[derive(Debug, Deserialize)]
struct WireCorpus {
    schema_id: String,
    vectors: Vec<WireVector>,
}

#[derive(Debug, Deserialize)]
struct ProtocolCorpus {
    schema_id: String,
    vectors: Vec<ProtocolVector>,
}

#[derive(Debug, Deserialize)]
struct WireVector {
    policy: PolicyVector,
    share_id: u16,
    share_scalar_hex: String,
    signing_root_share_wire_hex: String,
    partial: WirePartialVector,
    share_commitment_wire_hex: String,
    dleq_proof_wire_hex: String,
}

#[derive(Debug, Deserialize)]
struct ProtocolVector {
    suite_id: String,
    purpose: String,
    context_hex: String,
    policy: PolicyVector,
    root_seed_hex: String,
    split_seed_hex: String,
    root_scalar_hex: String,
    shares: Vec<ShareVector>,
    partials: Vec<ProtocolPartialVector>,
    direct_output_hex: String,
    threshold_outputs: Vec<ThresholdOutputVector>,
}

#[derive(Debug, Deserialize)]
struct PolicyVector {
    threshold: u16,
    share_count: u16,
}

#[derive(Debug, Deserialize)]
struct WirePartialVector {
    context_tag_hex: String,
    compressed_point_hex: String,
    wire_hex: String,
}

#[derive(Debug, Deserialize)]
struct ProtocolPartialVector {
    id: u16,
    context_tag_hex: String,
    compressed_point_hex: String,
    wire_hex: String,
}

#[derive(Debug, Deserialize)]
struct ShareVector {
    id: u16,
    scalar_hex: String,
    wire_hex: String,
}

#[derive(Debug, Deserialize)]
struct ThresholdOutputVector {
    ids: Vec<u16>,
    output_hex: String,
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    decode_hex_array::<32>(hex)
}

fn decode_hex_34(hex: &str) -> [u8; 34] {
    decode_hex_array::<34>(hex)
}

fn decode_hex_64(hex: &str) -> [u8; 64] {
    decode_hex_array::<64>(hex)
}

fn decode_hex_66(hex: &str) -> [u8; 66] {
    decode_hex_array::<66>(hex)
}

fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut out = [0u8; N];
    for index in 0..N {
        out[index] = (hex_nibble(hex.as_bytes()[index * 2]) << 4)
            | hex_nibble(hex.as_bytes()[index * 2 + 1]);
    }
    out
}

fn decode_hex_vec(hex: &str) -> Vec<u8> {
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

fn load_wire_corpus() -> WireCorpus {
    serde_json::from_str(include_str!("../fixtures/protocol-wire.json"))
        .expect("canonical wire vector fixture is valid JSON")
}

fn load_protocol_corpus() -> ProtocolCorpus {
    serde_json::from_str(include_str!("../fixtures/protocol-t-of-n.json"))
        .expect("canonical protocol vector fixture is valid JSON")
}

fn vector_context(vector: &ProtocolVector) -> PrfContext {
    assert_eq!(vector.suite_id, "threshold-prf/ristretto255-sha512");
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose_from_str(&vector.purpose),
        decode_hex_vec(&vector.context_hex),
    )
}

fn purpose_from_str(purpose: &str) -> PrfPurpose {
    match purpose {
        "ecdsa-hss/y_relayer" => PrfPurpose::EcdsaHssYRelayer,
        "ed25519-hss/y_relayer" => PrfPurpose::Ed25519HssYRelayer,
        "ed25519-hss/tau_relayer" => PrfPurpose::Ed25519HssTauRelayer,
        "router-ab/x_client_base/v1" => PrfPurpose::RouterAbXClientBaseV1,
        "router-ab/x_relayer_base/v1" => PrfPurpose::RouterAbXRelayerBaseV1,
        purpose => panic!("unexpected vector purpose: {purpose}"),
    }
}

#[test]
fn committed_wire_vectors_match_implementation() {
    let corpus = load_wire_corpus();
    assert_eq!(corpus.schema_id, "threshold-prf/protocol-wire-fixtures/v1");
    assert_eq!(corpus.vectors.len(), 1);

    for vector in &corpus.vectors {
        assert_wire_vector_matches_implementation(vector);
    }
}

#[test]
fn committed_protocol_vectors_match_implementation() {
    let corpus = load_protocol_corpus();
    assert_eq!(
        corpus.schema_id,
        "threshold-prf/protocol-t-of-n-fixtures/v1"
    );
    assert_eq!(corpus.vectors.len(), 3);

    for vector in &corpus.vectors {
        assert_protocol_vector_matches_implementation(vector);
    }
}

fn assert_wire_vector_matches_implementation(vector: &WireVector) {
    let policy =
        ThresholdPolicy::from_u16s(vector.policy.threshold, vector.policy.share_count).unwrap();
    let share_id = ThresholdShareId::from_u16(vector.share_id).unwrap();
    let share =
        SigningRootShare::from_canonical_bytes(share_id, decode_hex_32(&vector.share_scalar_hex))
            .unwrap();
    let validated = ValidatedThresholdSet::from_signing_root_shares(policy, vec![share.clone()])
        .expect("canonical vector share belongs to policy");
    assert_eq!(validated.values()[0].id(), share_id);

    let share_wire = SigningRootShareWire::from_share(&share);
    assert_eq!(
        share_wire.to_bytes(),
        decode_hex_34(&vector.signing_root_share_wire_hex)
    );
    let decoded_share_wire =
        SigningRootShareWire::decode(decode_hex_34(&vector.signing_root_share_wire_hex)).unwrap();
    let decoded_share = decoded_share_wire.to_share().unwrap();
    assert_eq!(decoded_share.id(), share_id);
    assert_eq!(decoded_share.to_bytes(), share.to_bytes());

    let partial = PrfPartial::from_compressed(
        share_id,
        decode_hex_32(&vector.partial.context_tag_hex),
        decode_hex_32(&vector.partial.compressed_point_hex),
    )
    .unwrap();
    assert_eq!(
        PrfPartialWire::from_partial(&partial).to_bytes(),
        decode_hex_66(&vector.partial.wire_hex)
    );
    let decoded_partial_wire =
        PrfPartialWire::decode(decode_hex_66(&vector.partial.wire_hex)).unwrap();
    let decoded_partial = decoded_partial_wire.to_partial().unwrap();
    assert_eq!(decoded_partial.id(), share_id);
    assert_eq!(decoded_partial.context_tag(), partial.context_tag());
    assert_eq!(decoded_partial.to_compressed(), partial.to_compressed());

    let commitment = SigningRootShareCommitment::from_share(&share);
    assert_eq!(
        commitment.to_bytes(),
        decode_hex_34(&vector.share_commitment_wire_hex)
    );
    assert_eq!(
        SigningRootShareCommitment::from_bytes(decode_hex_34(&vector.share_commitment_wire_hex,))
            .unwrap()
            .to_bytes(),
        decode_hex_34(&vector.share_commitment_wire_hex)
    );

    let proof = PrfDleqProof::from_bytes(decode_hex_64(&vector.dleq_proof_wire_hex)).unwrap();
    assert_eq!(proof.to_bytes(), decode_hex_64(&vector.dleq_proof_wire_hex));
}

fn assert_protocol_vector_matches_implementation(vector: &ProtocolVector) {
    let policy =
        ThresholdPolicy::from_u16s(vector.policy.threshold, vector.policy.share_count).unwrap();
    let mut root_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.root_seed_hex));
    let mut split_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.split_seed_hex));
    let root = generate_signing_root(&mut root_rng);
    let shares = split_signing_root(&root, policy, &mut split_rng).unwrap();
    let context = vector_context(vector);

    assert_eq!(root.to_bytes(), decode_hex_32(&vector.root_scalar_hex));
    assert_eq!(vector.shares.len(), usize::from(policy.share_count().get()));
    for share_vector in &vector.shares {
        let share = share_by_id(&shares, share_vector.id);
        assert_eq!(share.to_bytes(), decode_hex_32(&share_vector.scalar_hex));
        assert_eq!(
            SigningRootShareWire::from_share(share).to_bytes(),
            decode_hex_34(&share_vector.wire_hex)
        );
    }

    let partials = shares
        .iter()
        .map(|share| evaluate_partial(share, &context).expect("canonical partial succeeds"))
        .collect::<Vec<_>>();
    assert_eq!(vector.partials.len(), partials.len());
    for partial_vector in &vector.partials {
        let partial = partial_by_id(&partials, partial_vector.id);
        assert_eq!(
            partial.context_tag(),
            &decode_hex_32(&partial_vector.context_tag_hex)
        );
        assert_eq!(
            partial.to_compressed(),
            decode_hex_32(&partial_vector.compressed_point_hex)
        );
        assert_eq!(
            PrfPartialWire::from_partial(partial).to_bytes(),
            decode_hex_66(&partial_vector.wire_hex)
        );
    }

    let direct = evaluate_direct_reference(&root, &context).expect("canonical direct succeeds");
    assert_eq!(direct.as_bytes(), &decode_hex_32(&vector.direct_output_hex));

    for output_vector in &vector.threshold_outputs {
        let selected = output_vector
            .ids
            .iter()
            .map(|id| partial_by_id(&partials, *id).clone())
            .collect();
        let set = ValidatedThresholdSet::from_partials(policy, selected).unwrap();
        assert_eq!(
            combine_partials(&set, &context).unwrap().as_bytes(),
            &decode_hex_32(&output_vector.output_hex)
        );
    }
}

fn share_by_id(shares: &[SigningRootShare], id: u16) -> &SigningRootShare {
    shares
        .iter()
        .find(|share| share.id().get().get() == id)
        .expect("canonical share id exists")
}

fn partial_by_id(partials: &[PrfPartial], id: u16) -> &PrfPartial {
    partials
        .iter()
        .find(|partial| partial.id().get().get() == id)
        .expect("canonical partial id exists")
}
