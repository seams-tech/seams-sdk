use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use threshold_prf::reference::evaluate_direct_reference;
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    apply_two_party_root_share_refresh, evaluate_partial, generate_signing_root,
    split_signing_root, PrfPartialWire, RootShareKnowledgeProof, RootShareRefreshCoefficient,
    RootShareRefreshCoefficientCommitment, SigningRootShare, SigningRootShareWire, ThresholdPolicy,
    ThresholdPrfError, TwoPartyDeriverRole, TwoPartyRootShareCommitments, ValidatedThresholdSet,
    VerifiedRootShareRefreshContribution,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};
use threshold_prf_verus::model as mirror;

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
struct ShareVector {
    id: u16,
    scalar_hex: String,
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
struct ThresholdOutputVector {
    ids: Vec<u16>,
    output_hex: String,
}

fn scalar_bytes(value: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[0] = value;
    bytes
}

fn fixed_refresh_share(role: TwoPartyDeriverRole, scalar: u8) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), scalar_bytes(scalar))
        .expect("fixed refresh share is canonical")
}

fn refresh_contribution_scalar_bytes(
    coefficient: &RootShareRefreshCoefficient,
    recipient: TwoPartyDeriverRole,
) -> [u8; 32] {
    coefficient.contribution_for(recipient).to_bytes()[4..]
        .try_into()
        .expect("fixed refresh contribution scalar width")
}

fn fixed_refresh_coefficient(role: TwoPartyDeriverRole, scalar: u8) -> RootShareRefreshCoefficient {
    RootShareRefreshCoefficient::from_canonical_bytes(role, scalar_bytes(scalar))
        .expect("fixed refresh coefficient is canonical and non-zero")
}

fn verified_refresh_contribution(
    coefficient: &RootShareRefreshCoefficient,
    recipient: TwoPartyDeriverRole,
) -> VerifiedRootShareRefreshContribution {
    coefficient
        .commitment()
        .verify_contribution(coefficient.contribution_for(recipient))
        .expect("production refresh contribution verifies against its commitment")
}

fn apply_refresh_for_role(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> Result<SigningRootShare, ThresholdPrfError> {
    apply_two_party_root_share_refresh(
        current,
        verified_refresh_contribution(coefficient_a, recipient),
        verified_refresh_contribution(coefficient_b, recipient),
    )
}

#[test]
fn refresh_model_constants_match_production_roles_and_wires() {
    let mut order_minus_one = mirror::RISTRETTO_SCALAR_ORDER_LE_BYTES;
    order_minus_one[0] = order_minus_one[0]
        .checked_sub(1)
        .expect("Ristretto scalar order is non-zero");
    assert_eq!((Scalar::ZERO - Scalar::ONE).to_bytes(), order_minus_one);
    assert!(bool::from(
        Scalar::from_canonical_bytes(order_minus_one).is_some()
    ));
    assert!(!bool::from(
        Scalar::from_canonical_bytes(mirror::RISTRETTO_SCALAR_ORDER_LE_BYTES).is_some()
    ));
    assert_eq!(
        mirror::TWO_PARTY_DERIVER_A_SHARE_ID,
        TwoPartyDeriverRole::DeriverA.share_id().get().get()
    );
    assert_eq!(
        mirror::TWO_PARTY_DERIVER_B_SHARE_ID,
        TwoPartyDeriverRole::DeriverB.share_id().get().get()
    );
    assert_eq!(
        mirror::TWO_PARTY_REFRESH_COMMITMENT_WIRE_LEN,
        RootShareRefreshCoefficientCommitment::LEN
    );
    assert_eq!(
        mirror::TWO_PARTY_REFRESH_CONTRIBUTION_WIRE_LEN,
        threshold_prf::RootShareRefreshContributionWire::LEN
    );
    assert_eq!(
        mirror::TWO_PARTY_ROOT_SHARE_KNOWLEDGE_PROOF_WIRE_LEN,
        RootShareKnowledgeProof::LEN
    );
}

#[test]
fn refresh_formula_matches_production_share_updates_and_continuity() {
    let current_a = fixed_refresh_share(TwoPartyDeriverRole::DeriverA, 41);
    let current_b = fixed_refresh_share(TwoPartyDeriverRole::DeriverB, 13);
    let coefficient_a = fixed_refresh_coefficient(TwoPartyDeriverRole::DeriverA, 5);
    let coefficient_b = fixed_refresh_coefficient(TwoPartyDeriverRole::DeriverB, 7);
    assert_eq!(
        refresh_contribution_scalar_bytes(&coefficient_a, TwoPartyDeriverRole::DeriverA),
        Scalar::from(5_u64).to_bytes(),
    );
    assert_eq!(
        refresh_contribution_scalar_bytes(&coefficient_a, TwoPartyDeriverRole::DeriverB),
        Scalar::from(10_u64).to_bytes(),
    );
    assert_eq!(
        refresh_contribution_scalar_bytes(&coefficient_b, TwoPartyDeriverRole::DeriverA),
        Scalar::from(7_u64).to_bytes(),
    );
    assert_eq!(
        refresh_contribution_scalar_bytes(&coefficient_b, TwoPartyDeriverRole::DeriverB),
        Scalar::from(14_u64).to_bytes(),
    );
    let next_a = apply_refresh_for_role(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    )
    .expect("production derives next A share");
    let next_b = apply_refresh_for_role(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    )
    .expect("production derives next B share");

    assert_eq!(next_a.to_bytes(), scalar_bytes(53));
    assert_eq!(next_b.to_bytes(), scalar_bytes(37));

    let current_commitments =
        TwoPartyRootShareCommitments::from_shares(&current_a, &current_b).unwrap();
    let next_commitments = TwoPartyRootShareCommitments::from_shares(&next_a, &next_b).unwrap();
    threshold_prf::verify_two_party_root_share_refresh(&current_commitments, &next_commitments)
        .expect("production continuity check accepts the modelled refresh");
}

#[test]
fn committed_t_of_n_vectors_match_production_helpers() {
    let corpus: ProtocolCorpus =
        serde_json::from_str(include_str!("../../../fixtures/protocol-t-of-n.json"))
            .expect("canonical protocol vector fixture is valid JSON");

    assert_eq!(
        corpus.schema_id,
        "threshold-prf/protocol-t-of-n-fixtures/v1"
    );
    assert_eq!(corpus.vectors.len(), 3);
    for vector in &corpus.vectors {
        assert_vector_matches_production(vector);
    }
}

fn assert_vector_matches_production(vector: &ProtocolVector) {
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
        let share = shares
            .iter()
            .find(|share| share.id().get().get() == share_vector.id)
            .expect("canonical share id exists");
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
        let partial = partials
            .iter()
            .find(|partial| partial.id().get().get() == partial_vector.id)
            .expect("canonical partial id exists");
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

    let direct = evaluate_direct_reference(&root, &context).unwrap();
    assert_eq!(direct.as_bytes(), &decode_hex_32(&vector.direct_output_hex));

    for output_vector in &vector.threshold_outputs {
        assert_eq!(
            output_vector.ids.len(),
            usize::from(policy.threshold().get())
        );
        let selected = output_vector
            .ids
            .iter()
            .map(|id| {
                partials
                    .iter()
                    .find(|partial| partial.id().get().get() == *id)
                    .expect("canonical threshold partial exists")
                    .clone()
            })
            .collect();
        let partial_set = ValidatedThresholdSet::from_partials(policy, selected).unwrap();
        assert_eq!(
            combine_partials(&partial_set, &context).unwrap().as_bytes(),
            &decode_hex_32(&output_vector.output_hex)
        );
    }
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
        "router-ab-ecdsa-derivation/y-server/v1" => PrfPurpose::RouterAbEcdsaDerivationYServer,
        "router-ab/x_client_base/v1" => PrfPurpose::RouterAbXClientBaseV1,
        "router-ab/x_server_base/v1" => PrfPurpose::RouterAbXServerBaseV1,
        purpose => panic!("unexpected vector purpose: {purpose}"),
    }
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    decode_hex_array::<32>(hex)
}

fn decode_hex_34(hex: &str) -> [u8; 34] {
    decode_hex_array::<34>(hex)
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
