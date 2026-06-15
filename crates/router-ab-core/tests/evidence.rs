use router_ab_core::{
    package_commitment_v1, transcript_digest_v1, verify_minimum_level_c_v1,
    AcceptedReplayCacheDecisionV1, AccountScope, AuthenticatedSignerReceiptV1, CandidateId,
    ContentKind, CorrectnessLevel, DeliveryPackageV1, DerivationContext, EnvelopeHeaderV1,
    EnvelopeKind, EnvelopeVersion, MinimumLevelCVerificationInputV1, PublicDigest32, RequestKind,
    Role, RootShareEpoch, RouterAbDerivationErrorCode, SignerReceiptVersion, SignerSetBinding,
    TranscriptBinding,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn context() -> DerivationContext {
    DerivationContext::new(
        CandidateId::SplitRootDerivationV1,
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

fn package(
    context: &DerivationContext,
    transcript_digest: PublicDigest32,
    envelope_kind: EnvelopeKind,
    sender_role: Role,
    sender_identity: &str,
    recipient_role: Role,
    recipient_identity: &str,
    content_kind: ContentKind,
    ciphertext_seed: u8,
) -> DeliveryPackageV1 {
    DeliveryPackageV1::new(
        EnvelopeHeaderV1::new(
            EnvelopeVersion::V1,
            envelope_kind,
            context.candidate_id(),
            context.request_kind(),
            context.correctness_level(),
            context.ceremony_id().to_owned(),
            context.root_share_epoch().clone(),
            transcript_digest,
            sender_role,
            sender_identity,
            recipient_role,
            recipient_identity,
            content_kind,
            digest(ciphertext_seed),
            128,
        )
        .expect("header"),
    )
    .expect("package")
}

fn accepted_input() -> MinimumLevelCVerificationInputV1 {
    let context = context();
    let transcript = transcript(context.clone());
    let transcript_digest = transcript_digest_v1(&transcript).expect("transcript digest");

    let a_client = package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerAToClient,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        0xa1,
    );
    let b_client = package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerBToClient,
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        0xb1,
    );
    let a_server = package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerAToServer,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Server,
        "role:server:local:sha256-r",
        ContentKind::ServerOutputShare,
        0xa2,
    );
    let b_server = package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerBToServer,
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        Role::Server,
        "role:server:local:sha256-r",
        ContentKind::ServerOutputShare,
        0xb2,
    );

    let signer_a_receipt = AuthenticatedSignerReceiptV1::new(
        SignerReceiptVersion::V1,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        transcript_digest,
        context.root_share_epoch().clone(),
        vec![
            package_commitment_v1(&a_client).expect("a client commitment"),
            package_commitment_v1(&a_server).expect("a server commitment"),
        ],
    )
    .expect("signer A receipt");
    let signer_b_receipt = AuthenticatedSignerReceiptV1::new(
        SignerReceiptVersion::V1,
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        transcript_digest,
        context.root_share_epoch().clone(),
        vec![
            package_commitment_v1(&b_client).expect("b client commitment"),
            package_commitment_v1(&b_server).expect("b server commitment"),
        ],
    )
    .expect("signer B receipt");

    MinimumLevelCVerificationInputV1 {
        context,
        transcript,
        signer_a_receipt,
        signer_b_receipt,
        client_packages: vec![a_client, b_client],
        server_packages: vec![a_server, b_server],
        replay_cache_decision: AcceptedReplayCacheDecisionV1 {
            replay_cache_key: digest(0x99),
            accepted_transcript_digest: transcript_digest,
        },
    }
}

#[test]
fn minimum_level_c_accepts_consistent_transcript_and_packages() {
    let verified =
        verify_minimum_level_c_v1(accepted_input()).expect("valid evidence should verify");

    assert_eq!(
        verified.evidence().correctness_level(),
        CorrectnessLevel::MinimumLevelC
    );
    assert_eq!(verified.evidence().client_package_commitments().len(), 2);
    assert_eq!(verified.evidence().server_package_commitments().len(), 2);
}

#[test]
fn minimum_level_c_rejects_replay_mismatch() {
    let mut input = accepted_input();
    input.replay_cache_decision.accepted_transcript_digest = digest(0x42);

    let err = verify_minimum_level_c_v1(input).expect_err("replay mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn minimum_level_c_rejects_wrong_recipient() {
    let mut input = accepted_input();
    let transcript_digest = transcript_digest_v1(&input.transcript).expect("transcript digest");
    input.client_packages[0] = package(
        &input.context,
        transcript_digest,
        EnvelopeKind::SignerAToClient,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:other:sha256-c",
        ContentKind::ClientOutputShare,
        0xa1,
    );

    let err = verify_minimum_level_c_v1(input).expect_err("recipient mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn minimum_level_c_rejects_receipt_commitment_mismatch() {
    let mut input = accepted_input();
    let mut commitments = input.signer_a_receipt.output_package_commitments().to_vec();
    commitments[0] = digest(0xfe);
    input.signer_a_receipt = AuthenticatedSignerReceiptV1::new(
        SignerReceiptVersion::V1,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        transcript_digest_v1(&input.transcript).expect("transcript digest"),
        input.context.root_share_epoch().clone(),
        commitments,
    )
    .expect("well-shaped mismatched receipt");

    let err = verify_minimum_level_c_v1(input).expect_err("receipt mismatch should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::PackageCommitmentMismatch
    );
}

#[test]
fn minimum_level_c_rejects_missing_signer_package() {
    let mut input = accepted_input();
    input
        .client_packages
        .retain(|package| package.header().envelope_kind() != EnvelopeKind::SignerBToClient);

    let err = verify_minimum_level_c_v1(input).expect_err("missing package should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::PackageCommitmentMismatch
    );
}

#[test]
fn minimum_level_c_rejects_duplicate_signer_package() {
    let mut input = accepted_input();
    input.client_packages[1] = input.client_packages[0].clone();

    let err = verify_minimum_level_c_v1(input).expect_err("duplicate package should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::PackageCommitmentMismatch
    );
}
