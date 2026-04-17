use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use threshold_prf::{
    combine_partials, evaluate_direct_reference, evaluate_partial,
    evaluate_partial_with_dleq_proof, generate_signing_root, refresh_signing_root_shares_2_of_3,
    split_signing_root_2_of_3, PrfContext, PrfPartialWireV1, PrfPurpose, SigningRootShare,
    SigningRootShareWireV1, SuiteId,
};

const ROOT_SEED: [u8; 32] = [7u8; 32];
const SPLIT_SEED: [u8; 32] = [8u8; 32];
const REFRESH_SEED: [u8; 32] = [99u8; 32];
const REFRESH_INPUT_SHARE_IDS: [u8; 2] = [1, 3];
const ECDSA_HSS_PROOF_SEED_BASE: u8 = 40;
const ED25519_HSS_Y_PROOF_SEED_BASE: u8 = 50;
const ED25519_HSS_TAU_PROOF_SEED_BASE: u8 = 60;
const SIGNING_ROOT_ID: &str = "project-alpha:dev";

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

#[derive(Serialize)]
struct ShareVector {
    id: u8,
    scalar_hex: String,
    wire_hex: String,
}

#[derive(Serialize)]
struct PartialVector {
    id: u8,
    context_tag_hex: String,
    compressed_point_hex: String,
    wire_hex: String,
    share_commitment_wire_hex: String,
    dleq_proof_seed_hex: String,
    dleq_proof_wire_hex: String,
}

#[derive(Serialize)]
struct PairwiseOutputVector {
    ids: [u8; 2],
    output_hex: String,
}

#[derive(Serialize)]
struct InvalidCaseVector {
    name: &'static str,
    expected_error: &'static str,
}

fn main() {
    let corpus = ProtocolCorpus {
        schema_id: "threshold-prf/protocol-v1-fixtures/v1",
        vectors: vec![
            vector_for(
                PrfPurpose::EcdsaHssYRelayer,
                ecdsa_hss_context_v1(SIGNING_ROOT_ID, "alice.near", "wallet", "v1"),
                ECDSA_HSS_PROOF_SEED_BASE,
            ),
            vector_for(
                PrfPurpose::Ed25519HssYRelayer,
                ed25519_hss_context_digest_v1(
                    SIGNING_ROOT_ID,
                    "alice.near",
                    "wallet",
                    "v1",
                    &[1, 2],
                    1,
                )
                .to_vec(),
                ED25519_HSS_Y_PROOF_SEED_BASE,
            ),
            vector_for(
                PrfPurpose::Ed25519HssTauRelayer,
                ed25519_hss_context_digest_v1(
                    SIGNING_ROOT_ID,
                    "alice.near",
                    "wallet",
                    "v1",
                    &[1, 2],
                    1,
                )
                .to_vec(),
                ED25519_HSS_TAU_PROOF_SEED_BASE,
            ),
        ],
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&corpus).expect("fixture corpus serializes")
    );
}

fn vector_for(purpose: PrfPurpose, context_bytes: Vec<u8>, proof_seed_base: u8) -> ProtocolVector {
    let mut root_rng = ChaCha20Rng::from_seed(ROOT_SEED);
    let mut split_rng = ChaCha20Rng::from_seed(SPLIT_SEED);
    let root = generate_signing_root(&mut root_rng);
    let shares = split_signing_root_2_of_3(&root, &mut split_rng);
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512V1,
        purpose.clone(),
        context_bytes,
    );
    let proof_bundles = shares
        .iter()
        .map(|share| {
            let proof_seed = proof_seed_for(proof_seed_base, share.id().get());
            let mut proof_rng = ChaCha20Rng::from_seed(proof_seed);
            evaluate_partial_with_dleq_proof(share, &context, &mut proof_rng)
                .expect("fixture context is valid")
        })
        .collect::<Vec<_>>();
    let partials = proof_bundles
        .iter()
        .map(|bundle| bundle.partial.clone())
        .collect::<Vec<_>>();
    let mut refresh_rng = ChaCha20Rng::from_seed(REFRESH_SEED);
    let refresh_inputs = [
        share_by_id(&shares, REFRESH_INPUT_SHARE_IDS[0]).clone(),
        share_by_id(&shares, REFRESH_INPUT_SHARE_IDS[1]).clone(),
    ];
    let refreshed = refresh_signing_root_shares_2_of_3(&refresh_inputs, &mut refresh_rng).unwrap();
    let refreshed_partials = refreshed
        .iter()
        .map(|share| evaluate_partial(share, &context).expect("fixture context is valid"))
        .collect::<Vec<_>>();

    ProtocolVector {
        suite_id: String::from_utf8(SuiteId::Ristretto255Sha512V1.as_bytes().to_vec()).unwrap(),
        purpose: String::from_utf8(purpose.as_bytes().to_vec()).unwrap(),
        context_hex: hex(&context.context_bytes),
        root_seed_hex: hex(&ROOT_SEED),
        split_seed_hex: hex(&SPLIT_SEED),
        root_scalar_hex: hex(&root.to_bytes()),
        shares: shares.iter().map(share_vector).collect(),
        partials: proof_bundles
            .iter()
            .map(|bundle| {
                let partial = &bundle.partial;
                let proof_seed = proof_seed_for(proof_seed_base, partial.id().get());
                PartialVector {
                    id: partial.id().get(),
                    context_tag_hex: hex(partial.context_tag()),
                    compressed_point_hex: hex(&partial.to_compressed()),
                    wire_hex: hex(&PrfPartialWireV1::from_partial(partial).to_bytes()),
                    share_commitment_wire_hex: hex(&bundle.commitment.to_bytes()),
                    dleq_proof_seed_hex: hex(&proof_seed),
                    dleq_proof_wire_hex: hex(&bundle.proof.to_bytes()),
                }
            })
            .collect(),
        direct_output_hex: hex(evaluate_direct_reference(&root, &context)
            .expect("fixture context is valid")
            .as_bytes()),
        pairwise_outputs: pairwise_outputs(&partials, &context),
        refresh_seed_hex: hex(&REFRESH_SEED),
        refresh_input_share_ids: REFRESH_INPUT_SHARE_IDS,
        refreshed_shares: refreshed.iter().map(share_vector).collect(),
        refreshed_pairwise_outputs: pairwise_outputs(&refreshed_partials, &context),
        invalid_cases: invalid_cases(),
    }
}

fn share_by_id(shares: &[SigningRootShare; 3], id: u8) -> &SigningRootShare {
    shares
        .iter()
        .find(|share| share.id().get() == id)
        .expect("static fixture share id exists")
}

fn share_vector(share: &SigningRootShare) -> ShareVector {
    ShareVector {
        id: share.id().get(),
        scalar_hex: hex(&share.to_bytes()),
        wire_hex: hex(&SigningRootShareWireV1::from_share(share).to_bytes()),
    }
}

fn proof_seed_for(base: u8, share_id: u8) -> [u8; 32] {
    let mut seed = [base; 32];
    seed[31] = share_id;
    seed
}

fn pairwise_outputs(
    partials: &[threshold_prf::PrfPartial],
    context: &PrfContext,
) -> Vec<PairwiseOutputVector> {
    [(0, 1), (0, 2), (1, 2)]
        .into_iter()
        .map(|(left, right)| {
            let output =
                combine_partials(&[partials[left].clone(), partials[right].clone()], context)
                    .expect("fixture partials combine");
            PairwiseOutputVector {
                ids: [partials[left].id().get(), partials[right].id().get()],
                output_hex: hex(output.as_bytes()),
            }
        })
        .collect()
}

fn invalid_cases() -> Vec<InvalidCaseVector> {
    vec![
        InvalidCaseVector {
            name: "short_partial_wire",
            expected_error: "InvalidPartialEncoding",
        },
        InvalidCaseVector {
            name: "invalid_share_id",
            expected_error: "InvalidShareId",
        },
        InvalidCaseVector {
            name: "wrong_context_tag",
            expected_error: "ContextMismatch",
        },
        InvalidCaseVector {
            name: "invalid_compressed_point",
            expected_error: "InvalidPointEncoding",
        },
    ]
}

fn ecdsa_hss_context_v1(
    signing_root_id: &str,
    near_account_id: &str,
    key_purpose: &str,
    key_version: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ecdsa-hss:context:v1");
    push_len16(&mut out, b"ecdsa-hss-v1");
    push_len16(&mut out, b"secp256k1");
    push_len16(&mut out, signing_root_id.as_bytes());
    push_len16(&mut out, near_account_id.as_bytes());
    push_len16(&mut out, key_purpose.as_bytes());
    push_len16(&mut out, key_version.as_bytes());
    out.push(2);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    out
}

fn ed25519_hss_context_digest_v1(
    signing_root_id: &str,
    account_id: &str,
    key_purpose: &str,
    key_version: &str,
    participant_ids: &[u16],
    derivation_version: u32,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"succinct-garbling-proto/context-binding/v1");
    update_len32(&mut digest, signing_root_id.as_bytes());
    update_len32(&mut digest, account_id.as_bytes());
    update_len32(&mut digest, key_purpose.as_bytes());
    update_len32(&mut digest, key_version.as_bytes());
    digest.update((participant_ids.len() as u32).to_be_bytes());
    for id in participant_ids {
        digest.update(id.to_be_bytes());
    }
    digest.update(derivation_version.to_be_bytes());
    digest.finalize().into()
}

fn push_len16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn update_len32(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u32).to_be_bytes());
    digest.update(bytes);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
