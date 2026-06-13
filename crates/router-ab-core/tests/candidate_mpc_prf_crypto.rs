use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    plan_mpc_prf_purpose_binding_v1, AccountScope, CandidateId, CorrectnessLevel,
    DerivationContext, MpcPrfOutputEncodingV1, MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1,
    MpcPrfSignerPartialInputV1, MpcPrfSuiteId, OpenedShareKind, PublicDigest32, RequestKind, Role,
    RootShareEpoch, SignerSetBinding, TranscriptBinding,
};
use threshold_prf::{
    combine_verified_partials, evaluate_direct_reference, evaluate_partial_with_dleq_proof,
    generate_signing_root, split_signing_root, verify_partial_dleq_proof, ThresholdPolicy,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfOutputEncoding, PrfPurpose, SuiteId};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn context() -> DerivationContext {
    DerivationContext::new(
        CandidateId::MpcThresholdPrfV1,
        RequestKind::Registration,
        CorrectnessLevel::MinimumLevelC,
        AccountScope::new(
            "near-testnet",
            "alice.testnet",
            "ed25519:11111111111111111111111111111111",
        )
        .expect("account scope"),
        RootShareEpoch::new("epoch-1").expect("epoch"),
        "ceremony-1",
    )
    .expect("context")
}

fn transcript(context: DerivationContext) -> TranscriptBinding {
    TranscriptBinding::new(
        context,
        "role:router:local:sha256-router",
        SignerSetBinding::v1_all2(
            "signer-set-v1",
            "role:signer-a:local:sha256-a",
            "key-epoch-a-1",
            "role:signer-b:local:sha256-b",
            "key-epoch-b-1",
        )
        .expect("signer set"),
        "role:relayer:local:sha256-r",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "role:client:local:sha256-c",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript")
}

fn output_request(opened_share_kind: OpenedShareKind) -> MpcPrfOutputRequestV1 {
    match opened_share_kind {
        OpenedShareKind::XClientBase => MpcPrfOutputRequestV1::new(
            OpenedShareKind::XClientBase,
            Role::Client,
            "role:client:local:sha256-c",
        ),
        OpenedShareKind::XRelayerBase => MpcPrfOutputRequestV1::new(
            OpenedShareKind::XRelayerBase,
            Role::Relayer,
            "role:relayer:local:sha256-r",
        ),
    }
    .expect("output request")
}

fn signer_input(output_requests: Vec<MpcPrfOutputRequestV1>) -> MpcPrfSignerPartialInputV1 {
    let context = context();
    let transcript = transcript(context.clone());
    MpcPrfSignerPartialInputV1::new(
        context,
        transcript,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        RootShareEpoch::new("epoch-1").expect("epoch"),
        output_requests,
    )
    .expect("signer input")
}

fn threshold_purpose(output_purpose: MpcPrfOutputPurposeV1) -> PrfPurpose {
    match output_purpose {
        MpcPrfOutputPurposeV1::RouterAbXClientBase => PrfPurpose::RouterAbXClientBaseV1,
        MpcPrfOutputPurposeV1::RouterAbXRelayerBase => PrfPurpose::RouterAbXRelayerBaseV1,
    }
}

fn threshold_context(plan: &router_ab_core::MpcPrfPurposeBindingPlanV1) -> PrfContext {
    assert_eq!(
        plan.threshold_prf_suite_label,
        "threshold-prf/ristretto255-sha512"
    );
    assert_eq!(
        plan.output_encoding,
        MpcPrfOutputEncodingV1::CanonicalEd25519Scalar32
    );
    let purpose = threshold_purpose(plan.output_purpose);
    assert_eq!(
        purpose.output_encoding(),
        PrfOutputEncoding::CanonicalEd25519Scalar32
    );
    PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        plan.threshold_prf_context_bytes.clone(),
    )
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn policy() -> ThresholdPolicy {
    ThresholdPolicy::from_u16s(2, 3).expect("2-of-3 policy")
}

#[test]
fn purpose_binding_plan_drives_threshold_prf_proof_and_combine_path() {
    let request = output_request(OpenedShareKind::XClientBase);
    let signer_input = signer_input(vec![request.clone()]);
    let plan = plan_mpc_prf_purpose_binding_v1(&signer_input, &request).expect("purpose plan");
    let threshold_context = threshold_context(&plan);

    let mut setup_rng = seeded_rng(42);
    let root = generate_signing_root(&mut setup_rng);
    let policy = policy();
    let shares = split_signing_root(&root, policy, &mut setup_rng).expect("split");

    let left =
        evaluate_partial_with_dleq_proof(&shares[0], &threshold_context, &mut seeded_rng(10))
            .expect("left proof");
    let right =
        evaluate_partial_with_dleq_proof(&shares[2], &threshold_context, &mut seeded_rng(11))
            .expect("right proof");

    verify_partial_dleq_proof(
        &left.commitment,
        &left.partial,
        &threshold_context,
        &left.proof,
    )
    .expect("left proof verifies");

    let proof_set =
        ValidatedThresholdSet::from_proof_bundles(policy, vec![left, right]).expect("proof set");
    let combined =
        combine_verified_partials(&proof_set, &threshold_context).expect("verified combine");
    let direct = evaluate_direct_reference(&root, &threshold_context).expect("direct reference");

    assert_eq!(combined, direct);
}

#[test]
fn client_and_relayer_purpose_plans_produce_distinct_outputs() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let relayer_request = output_request(OpenedShareKind::XRelayerBase);
    let signer_input = signer_input(vec![client_request.clone(), relayer_request.clone()]);
    let client_plan =
        plan_mpc_prf_purpose_binding_v1(&signer_input, &client_request).expect("client plan");
    let relayer_plan =
        plan_mpc_prf_purpose_binding_v1(&signer_input, &relayer_request).expect("relayer plan");
    let client_context = threshold_context(&client_plan);
    let relayer_context = threshold_context(&relayer_plan);

    let mut setup_rng = seeded_rng(43);
    let root = generate_signing_root(&mut setup_rng);
    let _shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");

    let client_output = evaluate_direct_reference(&root, &client_context).expect("client");
    let relayer_output = evaluate_direct_reference(&root, &relayer_context).expect("relayer");

    assert_ne!(client_output, relayer_output);
}
