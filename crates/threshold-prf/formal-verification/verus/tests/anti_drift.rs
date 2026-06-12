use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use threshold_prf::{
    combine_partials, combine_verified_partials, derive_output_from_signing_root_share_wires,
    evaluate_direct_reference, evaluate_partial, evaluate_partial_with_dleq_proof,
    generate_signing_root, refresh_signing_root_shares_2_of_3, split_signing_root_2_of_3,
    verify_partial_dleq_proof, PrfContext, PrfDleqProofV1, PrfPartialWireV1, PrfPurpose,
    SigningRootShareCommitmentV1, SigningRootShareWireV1, SuiteId, ThresholdPrfError,
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

#[test]
fn committed_protocol_vectors_match_production_helpers() {
    let corpus: ProtocolCorpus =
        serde_json::from_str(include_str!("../../../fixtures/protocol-v1.json"))
            .expect("protocol vector fixture is valid JSON");

    assert_eq!(corpus.schema_id, "threshold-prf/protocol-v1-fixtures/v1");
    assert_eq!(corpus.vectors.len(), 5);
    for vector in &corpus.vectors {
        assert_vector_matches_production(vector);
        assert_invalid_cases_match_production(vector);
    }
    assert_signing_root_share_wire_rejections_match_production();
}

fn assert_vector_matches_production(vector: &ProtocolVector) {
    let mut root_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.root_seed_hex));
    let mut split_rng = ChaCha20Rng::from_seed(decode_hex_32(&vector.split_seed_hex));
    let root = generate_signing_root(&mut root_rng);
    let shares = split_signing_root_2_of_3(&root, &mut split_rng);
    let context = vector_context(vector);

    assert_eq!(root.to_bytes(), decode_hex_32(&vector.root_scalar_hex));
    assert_eq!(vector.shares.len(), 3);
    for share_vector in &vector.shares {
        let share = &shares[vector_index(share_vector.id)];
        assert_eq!(share.id().get(), share_vector.id);
        assert_eq!(share.to_bytes(), decode_hex_32(&share_vector.scalar_hex));

        let share_wire = SigningRootShareWireV1::from_share(share);
        let share_wire_bytes = share_wire.to_bytes();
        assert_eq!(share_wire_bytes[0], share_vector.id);
        assert_eq!(
            &share_wire_bytes[1..],
            &decode_hex_32(&share_vector.scalar_hex)
        );
        assert_eq!(share_wire.to_share().unwrap().to_bytes(), share.to_bytes());
    }

    let partials = shares
        .iter()
        .map(|share| evaluate_partial(share, &context).expect("fixture context is valid"))
        .collect::<Vec<_>>();
    let proof_bundles = vector
        .partials
        .iter()
        .map(|partial_vector| {
            let share = &shares[vector_index(partial_vector.id)];
            let mut proof_rng =
                ChaCha20Rng::from_seed(decode_hex_32(&partial_vector.dleq_proof_seed_hex));
            evaluate_partial_with_dleq_proof(share, &context, &mut proof_rng).unwrap()
        })
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
        let verified_left = proof_bundles[vector_index(pairwise_output.ids[0])].clone();
        let verified_right = proof_bundles[vector_index(pairwise_output.ids[1])].clone();
        let verified_combined =
            combine_verified_partials(&[verified_left, verified_right], &context).unwrap();
        let left_share_wire =
            SigningRootShareWireV1::from_share(&shares[vector_index(pairwise_output.ids[0])]);
        let right_share_wire =
            SigningRootShareWireV1::from_share(&shares[vector_index(pairwise_output.ids[1])]);
        let share_wire_combined = derive_output_from_signing_root_share_wires(
            &[left_share_wire, right_share_wire],
            &context,
        )
        .unwrap();
        assert_eq!(
            combined.as_bytes(),
            &decode_hex_32(&pairwise_output.output_hex)
        );
        assert_eq!(verified_combined.as_bytes(), combined.as_bytes());
        assert_eq!(share_wire_combined.as_bytes(), combined.as_bytes());
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
}

fn assert_invalid_cases_match_production(vector: &ProtocolVector) {
    let context = vector_context(vector);
    let first_wire = decode_hex_65(&vector.partials[0].wire_hex);
    for invalid_case in &vector.invalid_cases {
        let actual = match invalid_case.name.as_str() {
            "short_partial_wire" => {
                PrfPartialWireV1::decode_slice(&context, &first_wire[..64]).unwrap_err()
            }
            "invalid_share_id" => {
                let mut wire = first_wire;
                wire[0] = 0;
                PrfPartialWireV1::decode(&context, wire).unwrap_err()
            }
            "wrong_context_tag" => {
                let mut wire = first_wire;
                wire[1] ^= 1;
                PrfPartialWireV1::decode(&context, wire).unwrap_err()
            }
            "invalid_compressed_point" => {
                let mut wire = first_wire;
                wire[33..].fill(0xff);
                PrfPartialWireV1::decode(&context, wire).unwrap_err()
            }
            name => panic!("unexpected invalid case name: {name}"),
        };
        assert_eq!(
            format!("{actual:?}"),
            invalid_case.expected_error,
            "invalid case {}",
            invalid_case.name
        );
    }
}

fn assert_signing_root_share_wire_rejections_match_production() {
    assert_eq!(
        SigningRootShareWireV1::decode_slice(&[0u8; 32]).unwrap_err(),
        ThresholdPrfError::InvalidShareEncoding
    );

    let mut invalid_share_id_wire = [0u8; SigningRootShareWireV1::LEN];
    invalid_share_id_wire[0] = 4;
    assert_eq!(
        SigningRootShareWireV1::decode(invalid_share_id_wire).unwrap_err(),
        ThresholdPrfError::InvalidShareId
    );

    let mut invalid_scalar_wire = [0u8; SigningRootShareWireV1::LEN];
    invalid_scalar_wire[0] = 1;
    invalid_scalar_wire[1..].copy_from_slice(&[0xffu8; 32]);
    assert_eq!(
        SigningRootShareWireV1::decode(invalid_scalar_wire).unwrap_err(),
        ThresholdPrfError::InvalidScalarEncoding
    );
}

fn vector_context(vector: &ProtocolVector) -> PrfContext {
    assert_eq!(vector.suite_id, "threshold-prf/ristretto255-sha512/v1");
    let purpose = match vector.purpose.as_str() {
        "ecdsa-hss/y_relayer" => PrfPurpose::EcdsaHssYRelayer,
        "ed25519-hss/y_relayer" => PrfPurpose::Ed25519HssYRelayer,
        "ed25519-hss/tau_relayer" => PrfPurpose::Ed25519HssTauRelayer,
        "router-ab/x_client_base/v1" => PrfPurpose::RouterAbXClientBaseV1,
        "router-ab/x_relayer_base/v1" => PrfPurpose::RouterAbXRelayerBaseV1,
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
