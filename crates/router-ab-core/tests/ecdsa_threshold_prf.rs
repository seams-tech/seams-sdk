use router_ab_core::{
    plan_mpc_prf_combine_v1, plan_mpc_prf_partial_verification_v1, plan_mpc_prf_purpose_binding_v1,
    AccountScope, DerivationContext, MpcPrfCombinerInputV1, MpcPrfDleqProofWireV1,
    MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1, MpcPrfPartialBindingV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialVerificationInputV1, MpcPrfPartialWireV1,
    MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialInputV1, MpcPrfSignerPartialV1,
    MpcPrfVerifiedPartialV1, OpenedShareKind, RequestKind, Role, RootShareEpoch,
    RouterAbDerivationErrorCode, SignerSetBinding, TranscriptBinding,
    MPC_PRF_COMMITMENT_WIRE_V1_LEN, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
};

fn context() -> DerivationContext {
    DerivationContext::new(
        RequestKind::Registration,
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
        "role:server:local:sha256-r",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "role:client:local:sha256-c",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript")
}

fn output_request() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(
        OpenedShareKind::XClientBase,
        Role::Client,
        "role:client:local:sha256-c",
    )
    .expect("output request")
}

fn server_output_request() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(
        OpenedShareKind::XServerBase,
        Role::Server,
        "role:server:local:sha256-r",
    )
    .expect("server output request")
}

fn signer_input(role: Role, identity: &str) -> MpcPrfSignerPartialInputV1 {
    signer_input_with_requests(role, identity, vec![output_request()])
}

fn signer_input_with_requests(
    role: Role,
    identity: &str,
    output_requests: Vec<MpcPrfOutputRequestV1>,
) -> MpcPrfSignerPartialInputV1 {
    let context = context();
    let transcript = transcript(context.clone());
    MpcPrfSignerPartialInputV1::new(
        context,
        transcript,
        role,
        identity,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        output_requests,
    )
    .expect("signer input")
}

fn fixed_share_wire_bytes(role: Role, fill: u8, len: usize) -> Vec<u8> {
    let share_id = match role {
        Role::SignerA => 1u16,
        Role::SignerB => 2u16,
        _ => panic!("fixed share wire requires a Deriver role"),
    };
    let mut bytes = vec![fill; len];
    bytes[..2].copy_from_slice(&share_id.to_be_bytes());
    bytes
}

fn verified_partial(role: Role, identity: &str, byte: u8) -> MpcPrfVerifiedPartialV1 {
    let partial = signer_partial(role, identity, byte);
    MpcPrfVerifiedPartialV1::from_verified_parts(
        partial,
        MpcPrfShareCommitmentWireV1::new(fixed_share_wire_bytes(
            role,
            byte,
            MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        ))
        .expect("commitment"),
    )
    .expect("verified partial")
}

fn signer_partial(role: Role, identity: &str, byte: u8) -> MpcPrfSignerPartialV1 {
    let input = signer_input(role, identity);
    let binding = MpcPrfPartialBindingV1::from_signer_input(&input, &input.output_requests[0])
        .expect("partial binding");
    MpcPrfSignerPartialV1::new(
        binding,
        MpcPrfPartialWireV1::new(fixed_share_wire_bytes(
            role,
            byte,
            MPC_PRF_PARTIAL_WIRE_V1_LEN,
        ))
        .expect("partial wire"),
    )
    .expect("signer partial")
}

fn proof_bundle(role: Role, identity: &str, byte: u8) -> MpcPrfPartialProofBundleV1 {
    MpcPrfPartialProofBundleV1::new(
        signer_partial(role, identity, byte),
        MpcPrfShareCommitmentWireV1::new(fixed_share_wire_bytes(
            role,
            byte,
            MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        ))
        .expect("commitment"),
        MpcPrfDleqProofWireV1::new(vec![byte; MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN]).expect("proof"),
    )
    .expect("proof bundle")
}

#[test]
fn signer_partial_input_accepts_transcript_bound_signer() {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");

    assert_eq!(input.signer_role, Role::SignerA);
    assert_eq!(input.output_requests.len(), 1);
}

#[test]
fn signer_partial_input_rejects_identity_mismatch() {
    let context = context();
    let transcript = transcript(context.clone());
    let err = MpcPrfSignerPartialInputV1::new(
        context,
        transcript,
        Role::SignerA,
        "role:signer-a:local:sha256-wrong",
        RootShareEpoch::new("epoch-1").expect("epoch"),
        vec![output_request()],
    )
    .expect_err("identity mismatch should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::SignerIdentityMismatch
    );
}

#[test]
fn output_request_rejects_wrong_recipient_role() {
    let err = MpcPrfOutputRequestV1::new(
        OpenedShareKind::XClientBase,
        Role::Server,
        "role:server:local:sha256-r",
    )
    .expect_err("wrong recipient should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn partial_wire_debug_is_redacted_and_length_checked() {
    let partial = MpcPrfPartialWireV1::new(fixed_share_wire_bytes(
        Role::SignerA,
        7,
        MPC_PRF_PARTIAL_WIRE_V1_LEN,
    ))
    .expect("partial wire");

    assert_eq!(partial.as_bytes().len(), MPC_PRF_PARTIAL_WIRE_V1_LEN);
    assert_eq!(format!("{partial:?}"), "MpcPrfPartialWireV1([redacted])");

    let err = MpcPrfPartialWireV1::new(vec![7; MPC_PRF_PARTIAL_WIRE_V1_LEN - 1])
        .expect_err("short partial wire should fail");
    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);

    let mut invalid_id = vec![0u8; MPC_PRF_PARTIAL_WIRE_V1_LEN];
    invalid_id[..2].copy_from_slice(&3u16.to_be_bytes());
    assert_eq!(
        MpcPrfPartialWireV1::new(invalid_id)
            .expect_err("share id outside fixed A/B policy must fail")
            .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
}

#[test]
fn proof_wire_constructors_check_lengths() {
    let commitment = MpcPrfShareCommitmentWireV1::new(fixed_share_wire_bytes(
        Role::SignerA,
        9,
        MPC_PRF_COMMITMENT_WIRE_V1_LEN,
    ))
    .expect("commitment");
    let proof = MpcPrfDleqProofWireV1::new(vec![9; MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN]).expect("proof");

    assert_eq!(commitment.as_bytes().len(), MPC_PRF_COMMITMENT_WIRE_V1_LEN);
    assert_eq!(proof.as_bytes().len(), MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN);

    assert_eq!(
        MpcPrfShareCommitmentWireV1::new(vec![9; MPC_PRF_COMMITMENT_WIRE_V1_LEN - 1])
            .expect_err("short commitment should fail")
            .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
    assert_eq!(
        MpcPrfDleqProofWireV1::new(vec![9; MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN - 1])
            .expect_err("short proof should fail")
            .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
}

#[test]
fn purpose_binding_plan_is_signer_neutral_for_same_output() {
    let request = output_request();
    let signer_a = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let signer_b = signer_input(Role::SignerB, "role:signer-b:local:sha256-b");

    let plan_a = plan_mpc_prf_purpose_binding_v1(&signer_a, &request).expect("plan A");
    let plan_b = plan_mpc_prf_purpose_binding_v1(&signer_b, &request).expect("plan B");

    assert_eq!(
        plan_a.threshold_prf_context_bytes,
        plan_b.threshold_prf_context_bytes
    );
    assert_eq!(
        plan_a.threshold_prf_context_digest,
        plan_b.threshold_prf_context_digest
    );
    assert_eq!(
        plan_a.output_purpose,
        MpcPrfOutputPurposeV1::RouterAbXClientBase
    );
    assert_eq!(
        plan_a.threshold_prf_purpose_label,
        "router-ab/x_client_base/v1"
    );
}

#[test]
fn purpose_binding_plan_separates_client_and_server_outputs() {
    let client_request = output_request();
    let server_request = server_output_request();
    let signer = signer_input_with_requests(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![client_request.clone(), server_request.clone()],
    );

    let client_plan =
        plan_mpc_prf_purpose_binding_v1(&signer, &client_request).expect("client plan");
    let server_plan =
        plan_mpc_prf_purpose_binding_v1(&signer, &server_request).expect("server plan");

    assert_eq!(
        server_plan.output_purpose,
        MpcPrfOutputPurposeV1::RouterAbXServerBase
    );
    assert_eq!(
        server_plan.threshold_prf_purpose_label,
        "router-ab/x_server_base/v1"
    );
    assert_ne!(
        client_plan.threshold_prf_context_digest,
        server_plan.threshold_prf_context_digest
    );
}

#[test]
fn purpose_binding_plan_rejects_request_missing_from_signer_input() {
    let signer = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let err = plan_mpc_prf_purpose_binding_v1(&signer, &server_output_request())
        .expect_err("missing request should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn partial_verification_plan_accepts_transcript_bound_bundle() {
    let transcript = transcript(context());
    let bundle = proof_bundle(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a);
    let plan = plan_mpc_prf_partial_verification_v1(MpcPrfPartialVerificationInputV1 {
        transcript,
        proof_bundle: bundle,
    })
    .expect("verification plan");

    assert_eq!(plan.signer_role, Role::SignerA);
    assert_eq!(plan.partial_wire_len, MPC_PRF_PARTIAL_WIRE_V1_LEN);
    assert_eq!(plan.commitment_wire_len, MPC_PRF_COMMITMENT_WIRE_V1_LEN);
    assert_eq!(plan.proof_wire_len, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN);
}

#[test]
fn partial_verification_plan_rejects_transcript_mismatch() {
    let mismatched_context = DerivationContext::new(
        RequestKind::Registration,
        AccountScope::new(
            "near-testnet",
            "alice.testnet",
            "ed25519:11111111111111111111111111111111",
        )
        .expect("account scope"),
        RootShareEpoch::new("epoch-1").expect("epoch"),
        "ceremony-2",
    )
    .expect("context");
    let mismatched_transcript = transcript(mismatched_context);
    let bundle = proof_bundle(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a);
    let err = plan_mpc_prf_partial_verification_v1(MpcPrfPartialVerificationInputV1 {
        transcript: mismatched_transcript,
        proof_bundle: bundle,
    })
    .expect_err("transcript mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::TranscriptMismatch);
}

#[test]
fn partial_verification_plan_rejects_root_epoch_mismatch() {
    let context = context();
    let transcript = transcript(context);
    let mut bundle = proof_bundle(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a);
    bundle.signer_partial.binding.root_share_epoch = RootShareEpoch::new("epoch-2").expect("epoch");

    let err = plan_mpc_prf_partial_verification_v1(MpcPrfPartialVerificationInputV1 {
        transcript,
        proof_bundle: bundle,
    })
    .expect_err("root epoch mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RootEpochMismatch);
}

#[test]
fn combiner_plan_accepts_distinct_signer_partials() {
    let context = context();
    let transcript = transcript(context);
    let plan = plan_mpc_prf_combine_v1(MpcPrfCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: verified_partial(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a),
        right: verified_partial(Role::SignerB, "role:signer-b:local:sha256-b", 0x0b),
    })
    .expect("combine plan");

    assert_eq!(plan.signer_roles, [Role::SignerA, Role::SignerB]);
}

#[test]
fn combiner_plan_rejects_duplicate_signer_roles() {
    let context = context();
    let transcript = transcript(context);
    let err = plan_mpc_prf_combine_v1(MpcPrfCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: verified_partial(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a),
        right: verified_partial(Role::SignerA, "role:signer-a:local:sha256-a", 0x0b),
    })
    .expect_err("duplicate signer roles should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::DuplicateSignerIdentity
    );
}
