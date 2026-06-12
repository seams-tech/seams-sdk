use router_ab_core::{
    combine_split_root_verified_output_shares_v1, derive_split_root_output_share_v1,
    plan_split_root_combine_v1, plan_split_root_output_share_v1, plan_split_root_refresh_v1,
    AccountScope, CandidateId, CorrectnessLevel, DerivationContext, OpenedShareKind,
    PublicDigest32, RefreshScope, RequestKind, Role, RootShareEpoch, RouterAbDerivationErrorCode,
    SignerSetBinding, SplitRootCombinerInputV1, SplitRootOutputRequestV1,
    SplitRootOutputShareBindingV1, SplitRootOutputShareWireV1, SplitRootRefreshModeV1,
    SplitRootRefreshPlanInputV1, SplitRootSecretShareV1, SplitRootSignerInputV1,
    SplitRootSignerOutputShareV1, SplitRootSuiteId, SplitRootVerifiedOutputShareV1,
    TranscriptBinding, SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN, SPLIT_ROOT_SECRET_SHARE_V1_LEN,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn account_scope() -> AccountScope {
    AccountScope::new(
        "near-testnet",
        "alice.testnet",
        "ed25519:11111111111111111111111111111111",
    )
    .expect("account scope")
}

fn context(candidate_id: CandidateId) -> DerivationContext {
    DerivationContext::new(
        candidate_id,
        RequestKind::Registration,
        CorrectnessLevel::MinimumLevelC,
        account_scope(),
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

fn output_request() -> SplitRootOutputRequestV1 {
    SplitRootOutputRequestV1::new(
        OpenedShareKind::XClientBase,
        Role::Client,
        "role:client:local:sha256-c",
    )
    .expect("output request")
}

fn relayer_output_request() -> SplitRootOutputRequestV1 {
    SplitRootOutputRequestV1::new(
        OpenedShareKind::XRelayerBase,
        Role::Relayer,
        "role:relayer:local:sha256-r",
    )
    .expect("relayer output request")
}

fn signer_input(role: Role, identity: &str) -> SplitRootSignerInputV1 {
    signer_input_with_requests(role, identity, vec![output_request()])
}

fn signer_input_with_requests(
    role: Role,
    identity: &str,
    output_requests: Vec<SplitRootOutputRequestV1>,
) -> SplitRootSignerInputV1 {
    let context = context(CandidateId::SplitRootDerivationV1);
    let transcript = transcript(context.clone());
    SplitRootSignerInputV1::new(
        context,
        transcript,
        SplitRootSuiteId::HashToScalarSha512V1,
        role,
        identity,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        output_requests,
    )
    .expect("signer input")
}

fn root_share(role: Role, byte: u8) -> SplitRootSecretShareV1 {
    SplitRootSecretShareV1::new(
        role,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        vec![byte; SPLIT_ROOT_SECRET_SHARE_V1_LEN],
    )
    .expect("root share")
}

fn signer_share(role: Role, identity: &str, byte: u8) -> SplitRootSignerOutputShareV1 {
    let input = signer_input(role, identity);
    let binding =
        SplitRootOutputShareBindingV1::from_signer_input(&input, &input.output_requests[0])
            .expect("share binding");
    SplitRootSignerOutputShareV1::new(
        binding,
        SplitRootOutputShareWireV1::new(vec![byte; SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN])
            .expect("share wire"),
    )
    .expect("signer share")
}

fn verified_share(role: Role, identity: &str, byte: u8) -> SplitRootVerifiedOutputShareV1 {
    SplitRootVerifiedOutputShareV1::from_verified_share(signer_share(role, identity, byte))
        .expect("verified share")
}

#[test]
fn secret_share_debug_is_redacted_and_length_checked() {
    let share = SplitRootSecretShareV1::new(
        Role::SignerA,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        vec![7; SPLIT_ROOT_SECRET_SHARE_V1_LEN],
    )
    .expect("secret share");

    assert_eq!(share.signer_role(), Role::SignerA);
    assert_eq!(share.as_bytes().len(), SPLIT_ROOT_SECRET_SHARE_V1_LEN);
    assert!(format!("{share:?}").contains("[redacted]"));

    let err = SplitRootSecretShareV1::new(
        Role::SignerA,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        vec![7; SPLIT_ROOT_SECRET_SHARE_V1_LEN - 1],
    )
    .expect_err("short secret share should fail");
    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn signer_input_rejects_wrong_candidate() {
    let context = context(CandidateId::MpcThresholdPrfV1);
    let transcript = transcript(context.clone());
    let err = SplitRootSignerInputV1::new(
        context,
        transcript,
        SplitRootSuiteId::HashToScalarSha512V1,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        RootShareEpoch::new("epoch-1").expect("epoch"),
        vec![output_request()],
    )
    .expect_err("wrong candidate should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::UnsupportedCandidate
    );
}

#[test]
fn signer_input_rejects_identity_mismatch() {
    let context = context(CandidateId::SplitRootDerivationV1);
    let transcript = transcript(context.clone());
    let err = SplitRootSignerInputV1::new(
        context,
        transcript,
        SplitRootSuiteId::HashToScalarSha512V1,
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
    let err = SplitRootOutputRequestV1::new(
        OpenedShareKind::XClientBase,
        Role::Relayer,
        "role:relayer:local:sha256-r",
    )
    .expect_err("wrong recipient should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn output_share_plan_accepts_transcript_bound_input() {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let binding =
        plan_split_root_output_share_v1(&input, &input.output_requests[0]).expect("binding");

    assert_eq!(binding.signer_role, Role::SignerA);
    assert_eq!(binding.opened_share_kind, OpenedShareKind::XClientBase);
}

#[test]
fn output_share_wire_debug_is_redacted_and_length_checked() {
    let share = SplitRootOutputShareWireV1::new(vec![7; SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN])
        .expect("share wire");

    assert_eq!(share.as_bytes().len(), SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN);
    assert_eq!(
        format!("{share:?}"),
        "SplitRootOutputShareWireV1([redacted])"
    );

    let err = SplitRootOutputShareWireV1::new(vec![7; SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN - 1])
        .expect_err("short share wire should fail");
    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn derives_output_share_from_role_local_root() {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let share = derive_split_root_output_share_v1(
        &input,
        &input.output_requests[0],
        &root_share(Role::SignerA, 0x11),
    )
    .expect("derived share");

    assert_eq!(share.binding.signer_role, Role::SignerA);
    assert_eq!(
        share.share_wire.as_bytes().len(),
        SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN
    );
}

#[test]
fn derive_output_share_rejects_root_role_mismatch() {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let err = derive_split_root_output_share_v1(
        &input,
        &input.output_requests[0],
        &root_share(Role::SignerB, 0x11),
    )
    .expect_err("root role mismatch should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::SignerIdentityMismatch
    );
}

#[test]
fn derive_output_share_rejects_missing_request() {
    let input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let err = derive_split_root_output_share_v1(
        &input,
        &relayer_output_request(),
        &root_share(Role::SignerA, 0x11),
    )
    .expect_err("missing request should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn combines_derived_output_shares_for_recipient() {
    let request = output_request();
    let left_input = signer_input(Role::SignerA, "role:signer-a:local:sha256-a");
    let right_input = signer_input(Role::SignerB, "role:signer-b:local:sha256-b");
    let left =
        derive_split_root_output_share_v1(&left_input, &request, &root_share(Role::SignerA, 0x11))
            .expect("left share");
    let right =
        derive_split_root_output_share_v1(&right_input, &request, &root_share(Role::SignerB, 0x22))
            .expect("right share");
    let transcript = transcript(context(CandidateId::SplitRootDerivationV1));

    let output = combine_split_root_verified_output_shares_v1(SplitRootCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: SplitRootVerifiedOutputShareV1::from_verified_share(left).expect("left verified"),
        right: SplitRootVerifiedOutputShareV1::from_verified_share(right).expect("right verified"),
    })
    .expect("combined output");

    assert_eq!(output.opened_share_kind, OpenedShareKind::XClientBase);
    assert_eq!(output.output_material.as_bytes().len(), 32);
    assert!(format!("{output:?}").contains("[redacted]"));
}

#[test]
fn client_and_relayer_outputs_are_domain_separated() {
    let client_request = output_request();
    let relayer_request = relayer_output_request();
    let left_input = signer_input_with_requests(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![client_request.clone(), relayer_request.clone()],
    );
    let right_input = signer_input_with_requests(
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        vec![client_request.clone(), relayer_request.clone()],
    );
    let left_root = root_share(Role::SignerA, 0x11);
    let right_root = root_share(Role::SignerB, 0x22);
    let client_left = derive_split_root_output_share_v1(&left_input, &client_request, &left_root)
        .expect("client left");
    let client_right =
        derive_split_root_output_share_v1(&right_input, &client_request, &right_root)
            .expect("client right");
    let relayer_left = derive_split_root_output_share_v1(&left_input, &relayer_request, &left_root)
        .expect("relayer left");
    let relayer_right =
        derive_split_root_output_share_v1(&right_input, &relayer_request, &right_root)
            .expect("relayer right");
    let context = context(CandidateId::SplitRootDerivationV1);

    let client = combine_split_root_verified_output_shares_v1(SplitRootCombinerInputV1 {
        transcript: transcript(context.clone()),
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: SplitRootVerifiedOutputShareV1::from_verified_share(client_left)
            .expect("client left verified"),
        right: SplitRootVerifiedOutputShareV1::from_verified_share(client_right)
            .expect("client right verified"),
    })
    .expect("client output");
    let relayer = combine_split_root_verified_output_shares_v1(SplitRootCombinerInputV1 {
        transcript: transcript(context),
        opened_share_kind: OpenedShareKind::XRelayerBase,
        recipient_role: Role::Relayer,
        recipient_identity: "role:relayer:local:sha256-r".to_owned(),
        left: SplitRootVerifiedOutputShareV1::from_verified_share(relayer_left)
            .expect("relayer left verified"),
        right: SplitRootVerifiedOutputShareV1::from_verified_share(relayer_right)
            .expect("relayer right verified"),
    })
    .expect("relayer output");

    assert_ne!(client.output_material, relayer.output_material);
}

#[test]
fn combine_rejects_noncanonical_output_share_wire() {
    let context = context(CandidateId::SplitRootDerivationV1);
    let transcript = transcript(context);
    let mut left = signer_share(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a);
    left.share_wire =
        SplitRootOutputShareWireV1::new(vec![0xff; SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN])
            .expect("length-valid noncanonical wire");

    let err = combine_split_root_verified_output_shares_v1(SplitRootCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: SplitRootVerifiedOutputShareV1::from_verified_share(left).expect("left verified"),
        right: verified_share(Role::SignerB, "role:signer-b:local:sha256-b", 0x0b),
    })
    .expect_err("noncanonical share should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn combiner_plan_accepts_distinct_signer_shares() {
    let context = context(CandidateId::SplitRootDerivationV1);
    let transcript = transcript(context);
    let plan = plan_split_root_combine_v1(SplitRootCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: verified_share(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a),
        right: verified_share(Role::SignerB, "role:signer-b:local:sha256-b", 0x0b),
    })
    .expect("combine plan");

    assert_eq!(plan.signer_roles, [Role::SignerA, Role::SignerB]);
}

#[test]
fn combiner_plan_rejects_duplicate_signer_roles() {
    let context = context(CandidateId::SplitRootDerivationV1);
    let transcript = transcript(context);
    let err = plan_split_root_combine_v1(SplitRootCombinerInputV1 {
        transcript,
        opened_share_kind: OpenedShareKind::XClientBase,
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        left: verified_share(Role::SignerA, "role:signer-a:local:sha256-a", 0x0a),
        right: verified_share(Role::SignerA, "role:signer-a:local:sha256-a", 0x0b),
    })
    .expect_err("duplicate signer roles should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::DuplicateSignerIdentity
    );
}

#[test]
fn refresh_plan_requires_new_verified_output_relation() {
    let plan = plan_split_root_refresh_v1(SplitRootRefreshPlanInputV1 {
        refresh_scope: RefreshScope {
            old_root_share_epoch: RootShareEpoch::new("epoch-1").expect("old epoch"),
            new_root_share_epoch: RootShareEpoch::new("epoch-2").expect("new epoch"),
            refresh_id: "refresh-1".to_owned(),
            account_scope: account_scope(),
            old_signer_set_id: "signer-set-old".to_owned(),
            new_signer_set_id: "signer-set-new".to_owned(),
            expected_router_id: "role:router:local:sha256-router".to_owned(),
            expected_client_id: "role:client:local:sha256-c".to_owned(),
            expected_relayer_id: "role:relayer:local:sha256-r".to_owned(),
            address_verification_requirement: "required".to_owned(),
        },
        refresh_mode: SplitRootRefreshModeV1::FutureEpochNewOutputRelation,
    })
    .expect("refresh plan");

    assert!(!plan.preserves_existing_output_relation);
    assert_eq!(
        plan.activation_gate,
        "address_verification_required_before_epoch_activation"
    );
}
