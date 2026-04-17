use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use threshold_prf::{
    combine_partials, evaluate_direct_reference, evaluate_partial,
    evaluate_partial_with_dleq_proof, generate_signing_root, refresh_signing_root_shares_2_of_3,
    split_signing_root_2_of_3, verify_partial_dleq_proof, PrfContext, PrfDleqProofV1,
    PrfPartialWireV1, PrfPurpose, SigningRootShareCommitmentV1, SigningRootShareWireV1, SuiteId,
};

#[derive(Debug, Deserialize)]
struct ProtocolCorpus {
    schema_id: String,
    vectors: Vec<ProtocolVector>,
}

#[derive(Debug, Deserialize)]
struct ProtocolVector {
    suite_id: String,
    purpose: String,
    context_hex: String,
    root_seed_hex: String,
    split_seed_hex: String,
    root_scalar_hex: String,
    shares: Vec<ShareVector>,
    partials: Vec<PartialVector>,
    direct_output_hex: String,
    pairwise_outputs: Vec<PairwiseOutputVector>,
    refresh_seed_hex: String,
    refresh_input_share_ids: [u8; 2],
    refreshed_shares: Vec<ShareVector>,
    refreshed_pairwise_outputs: Vec<PairwiseOutputVector>,
    invalid_cases: Vec<InvalidCaseVector>,
}

#[derive(Debug, Deserialize)]
struct ShareVector {
    id: u8,
    scalar_hex: String,
    wire_hex: String,
}

#[derive(Debug, Deserialize)]
struct PartialVector {
    id: u8,
    context_tag_hex: String,
    compressed_point_hex: String,
    wire_hex: String,
    share_commitment_wire_hex: String,
    dleq_proof_seed_hex: String,
    dleq_proof_wire_hex: String,
}

#[derive(Debug, Deserialize)]
struct PairwiseOutputVector {
    ids: [u8; 2],
    output_hex: String,
}

#[derive(Debug, Deserialize)]
struct InvalidCaseVector {
    name: String,
    expected_error: String,
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    decode_hex_array::<32>(hex)
}

fn decode_hex_33(hex: &str) -> [u8; 33] {
    decode_hex_array::<33>(hex)
}

fn decode_hex_64(hex: &str) -> [u8; 64] {
    decode_hex_array::<64>(hex)
}

fn decode_hex_65(hex: &str) -> [u8; 65] {
    decode_hex_array::<65>(hex)
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

fn load_corpus() -> ProtocolCorpus {
    serde_json::from_str(include_str!("../fixtures/protocol-v1.json"))
        .expect("protocol vector fixture is valid JSON")
}

fn vector_context(vector: &ProtocolVector) -> PrfContext {
    assert_eq!(vector.suite_id, "threshold-prf/ristretto255-sha512/v1");
    let purpose = match vector.purpose.as_str() {
        "ecdsa-hss/y_relayer" => PrfPurpose::EcdsaHssYRelayer,
        "ed25519-hss/y_relayer" => PrfPurpose::Ed25519HssYRelayer,
        "ed25519-hss/tau_relayer" => PrfPurpose::Ed25519HssTauRelayer,
        purpose => panic!("unexpected vector purpose: {purpose}"),
    };
    PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        purpose,
        decode_hex_vec(&vector.context_hex),
    )
}

fn vector_index(id: u8) -> usize {
    usize::from(id.checked_sub(1).expect("share ids are one-based"))
}

#[test]
fn committed_v1_vectors_match_implementation() {
    let corpus = load_corpus();
    assert_eq!(corpus.schema_id, "threshold-prf/protocol-v1-fixtures/v1");
    assert_eq!(corpus.vectors.len(), 3);
    for vector in &corpus.vectors {
        assert_vector_matches_implementation(vector);
    }
}

fn assert_vector_matches_implementation(vector: &ProtocolVector) {
    let mut root_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.root_seed_hex));
    let mut split_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.split_seed_hex));
    let root = generate_signing_root(&mut root_rng);
    let shares = split_signing_root_2_of_3(&root, &mut split_rng);
    let context = vector_context(&vector);

    assert_eq!(root.to_bytes(), decode_hex_32(&vector.root_scalar_hex));
    assert_eq!(vector.shares.len(), 3);
    for share_vector in &vector.shares {
        let share = &shares[vector_index(share_vector.id)];
        assert_eq!(share.id().get(), share_vector.id);
        assert_eq!(share.to_bytes(), decode_hex_32(&share_vector.scalar_hex));
        let share_wire = SigningRootShareWireV1::from_share(share);
        assert_eq!(share_wire.to_bytes(), decode_hex_33(&share_vector.wire_hex));
        let decoded_wire =
            SigningRootShareWireV1::decode(decode_hex_33(&share_vector.wire_hex)).unwrap();
        let decoded_share = decoded_wire.to_share().unwrap();
        assert_eq!(decoded_share.id(), share.id());
        assert_eq!(decoded_share.to_bytes(), share.to_bytes());
    }

    let partials = shares
        .iter()
        .map(|share| evaluate_partial(share, &context).expect("fixture context is valid"))
        .collect::<Vec<_>>();

    assert_eq!(vector.partials.len(), 3);
    for partial_vector in &vector.partials {
        let partial = &partials[vector_index(partial_vector.id)];
        assert_eq!(partial.id().get(), partial_vector.id);
        assert_eq!(
            partial.context_tag(),
            &decode_hex_32(&partial_vector.context_tag_hex)
        );
        assert_eq!(
            partial.to_compressed(),
            decode_hex_32(&partial_vector.compressed_point_hex)
        );
        assert_eq!(
            PrfPartialWireV1::from_partial(partial).to_bytes(),
            decode_hex_65(&partial_vector.wire_hex)
        );

        let decoded =
            PrfPartialWireV1::decode(&context, decode_hex_65(&partial_vector.wire_hex)).unwrap();
        assert_eq!(decoded.id(), partial.id());
        assert_eq!(decoded.to_compressed(), partial.to_compressed());

        let commitment = SigningRootShareCommitmentV1::from_bytes(decode_hex_33(
            &partial_vector.share_commitment_wire_hex,
        ))
        .unwrap();
        let proof =
            PrfDleqProofV1::from_bytes(decode_hex_64(&partial_vector.dleq_proof_wire_hex)).unwrap();
        verify_partial_dleq_proof(&commitment, partial, &context, &proof).unwrap();

        let share = &shares[vector_index(partial_vector.id)];
        let mut proof_rng =
            ChaCha20Rng::from_seed(decode_hex_32(&partial_vector.dleq_proof_seed_hex));
        let regenerated_bundle =
            evaluate_partial_with_dleq_proof(share, &context, &mut proof_rng).unwrap();
        assert_eq!(
            regenerated_bundle.commitment.to_bytes(),
            decode_hex_33(&partial_vector.share_commitment_wire_hex)
        );
        assert_eq!(
            regenerated_bundle.proof.to_bytes(),
            decode_hex_64(&partial_vector.dleq_proof_wire_hex)
        );
    }

    let direct = evaluate_direct_reference(&root, &context).expect("fixture context is valid");
    assert_eq!(direct.as_bytes(), &decode_hex_32(&vector.direct_output_hex));

    for pairwise_output in &vector.pairwise_outputs {
        let left = partials[vector_index(pairwise_output.ids[0])].clone();
        let right = partials[vector_index(pairwise_output.ids[1])].clone();
        let combined = combine_partials(&[left, right], &context).unwrap();
        assert_eq!(
            combined.as_bytes(),
            &decode_hex_32(&pairwise_output.output_hex)
        );
    }

    let mut refresh_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.refresh_seed_hex));
    let refresh_inputs = [
        shares[vector_index(vector.refresh_input_share_ids[0])].clone(),
        shares[vector_index(vector.refresh_input_share_ids[1])].clone(),
    ];
    let refreshed = refresh_signing_root_shares_2_of_3(&refresh_inputs, &mut refresh_rng).unwrap();

    assert_eq!(vector.refreshed_shares.len(), 3);
    for share_vector in &vector.refreshed_shares {
        let share = &refreshed[vector_index(share_vector.id)];
        assert_eq!(share.id().get(), share_vector.id);
        assert_eq!(share.to_bytes(), decode_hex_32(&share_vector.scalar_hex));
        let share_wire = SigningRootShareWireV1::from_share(share);
        assert_eq!(share_wire.to_bytes(), decode_hex_33(&share_vector.wire_hex));
    }

    let refreshed_partials = refreshed
        .iter()
        .map(|share| evaluate_partial(share, &context).expect("fixture context is valid"))
        .collect::<Vec<_>>();
    for pairwise_output in &vector.refreshed_pairwise_outputs {
        let left = refreshed_partials[vector_index(pairwise_output.ids[0])].clone();
        let right = refreshed_partials[vector_index(pairwise_output.ids[1])].clone();
        let combined = combine_partials(&[left, right], &context).unwrap();
        assert_eq!(
            combined.as_bytes(),
            &decode_hex_32(&pairwise_output.output_hex)
        );
    }

    assert_eq!(vector.invalid_cases.len(), 4);
    for invalid_case in &vector.invalid_cases {
        assert!(!invalid_case.name.is_empty());
        assert!(!invalid_case.expected_error.is_empty());
    }
}
