use router_ab_core::{
    abort_ceremony, accept_signer_inputs, begin_requested, bind_outputs, complete_coordination,
    create_role_envelopes, mark_delivered, verify_ceremony, AccountScope, BeginCeremonyInput,
    CandidateId, CeremonyStateLabel, ContentKind, CorrectnessLevel, CreateRoleEnvelopesInput,
    DeliveryReceiptInput, DerivationContext, EnvelopeHeaderV1, EnvelopeKind, EnvelopeVersion,
    MinimumLevelCEvidenceV1, MinimumLevelCEvidenceVersion, OutputBindingInput, PublicDigest32,
    RequestKind, Role, RootShareEpoch, RouterAbDerivationErrorCode, SignerInputAcceptance,
    SignerSetBinding, TranscriptBinding, VerifiedMinimumLevelCEvidenceV1,
};

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
        "role:server:local:sha256-r",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "role:client:local:sha256-c",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript")
}

fn signer_envelope(
    context: &DerivationContext,
    transcript_digest: PublicDigest32,
    envelope_kind: EnvelopeKind,
    recipient_role: Role,
    recipient_identity: &str,
    ciphertext_digest: PublicDigest32,
) -> EnvelopeHeaderV1 {
    EnvelopeHeaderV1::new(
        EnvelopeVersion::V1,
        envelope_kind,
        context.candidate_id(),
        context.request_kind(),
        context.correctness_level(),
        context.ceremony_id().to_owned(),
        context.root_share_epoch().clone(),
        transcript_digest,
        Role::Router,
        "role:router:local:sha256-router",
        recipient_role,
        recipient_identity,
        ContentKind::SignerInput,
        ciphertext_digest,
        128,
    )
    .expect("envelope header")
}

fn requested() -> router_ab_core::CeremonyRequested {
    let context = context();
    let transcript = transcript(context.clone());
    begin_requested(BeginCeremonyInput {
        context,
        transcript,
        replay_cache_key: digest(0x99),
    })
    .expect("requested")
}

fn role_envelopes() -> router_ab_core::RoleEnvelopesCreated {
    let requested = requested();
    let context = requested.context.clone();
    let transcript_digest = requested.transcript_digest;

    create_role_envelopes(CreateRoleEnvelopesInput {
        state: requested,
        signer_a_envelope: signer_envelope(
            &context,
            transcript_digest,
            EnvelopeKind::RouterToSignerA,
            Role::SignerA,
            "role:signer-a:local:sha256-a",
            digest(0x0a),
        ),
        signer_b_envelope: signer_envelope(
            &context,
            transcript_digest,
            EnvelopeKind::RouterToSignerB,
            Role::SignerB,
            "role:signer-b:local:sha256-b",
            digest(0x0b),
        ),
    })
    .expect("role envelopes")
}

#[test]
fn ceremony_can_progress_to_verified_through_branch_builders() {
    let role_envelopes = role_envelopes();
    let transcript_digest = role_envelopes.requested.transcript_digest;

    let signer_inputs = accept_signer_inputs(SignerInputAcceptance {
        state: role_envelopes,
        signer_a_acceptance_digest: digest(0xa1),
        signer_b_acceptance_digest: digest(0xb1),
    })
    .expect("signer inputs");

    let coordination = complete_coordination(router_ab_core::CoordinationCompletionInput {
        state: signer_inputs,
        coordination_commitments: vec![digest(0xc1)],
    })
    .expect("coordination");

    let outputs = bind_outputs(OutputBindingInput {
        state: coordination,
        client_package_commitments: vec![digest(0xc2), digest(0xc4)],
        server_package_commitments: vec![digest(0xc3), digest(0xc5)],
        signer_a_output_receipt_digest: digest(0xa2),
        signer_b_output_receipt_digest: digest(0xb2),
    })
    .expect("outputs");

    let delivered = mark_delivered(DeliveryReceiptInput {
        state: outputs,
        delivery_receipt_digests: vec![digest(0xd1)],
        delivery_attempts: 1,
    })
    .expect("delivered");

    let verified = verify_ceremony(router_ab_core::VerificationInput {
        state: delivered,
        verified_evidence: VerifiedMinimumLevelCEvidenceV1::new(
            MinimumLevelCEvidenceV1::new(
                MinimumLevelCEvidenceVersion::V1,
                CorrectnessLevel::MinimumLevelC,
                digest(0xe1),
                transcript_digest,
                digest(0xa3),
                digest(0xb3),
                vec![digest(0xc2), digest(0xc4)],
                vec![digest(0xc3), digest(0xc5)],
                digest(0x99),
            )
            .expect("evidence"),
        )
        .expect("verified evidence"),
        verifier_identity: "role:router:local:sha256-router".to_owned(),
        verifier_sequence: 1,
    })
    .expect("verified");

    assert_eq!(verified.verifier_sequence, 1);
}

#[test]
fn output_binding_requires_client_and_server_commitments() {
    let signer_inputs = accept_signer_inputs(SignerInputAcceptance {
        state: role_envelopes(),
        signer_a_acceptance_digest: digest(0xa1),
        signer_b_acceptance_digest: digest(0xb1),
    })
    .expect("signer inputs");
    let coordination = complete_coordination(router_ab_core::CoordinationCompletionInput {
        state: signer_inputs,
        coordination_commitments: vec![digest(0xc1)],
    })
    .expect("coordination");

    let err = bind_outputs(OutputBindingInput {
        state: coordination,
        client_package_commitments: Vec::new(),
        server_package_commitments: vec![digest(0xc3)],
        signer_a_output_receipt_digest: digest(0xa2),
        signer_b_output_receipt_digest: digest(0xb2),
    })
    .expect_err("missing client commitments should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn abort_ceremony_records_redacted_terminal_state() {
    let aborted = abort_ceremony(router_ab_core::AbortInput {
        last_active_state: CeremonyStateLabel::Requested,
        ceremony_id: "ceremony-1".to_owned(),
        transcript_digest: None,
        error_code: RouterAbDerivationErrorCode::ReplayMismatch,
        redacted_reason: "replay mismatch".to_owned(),
    })
    .expect("abort");

    assert_eq!(aborted.last_active_state, CeremonyStateLabel::Requested);
    assert_eq!(
        aborted.error_code,
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}
