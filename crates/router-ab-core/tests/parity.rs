use router_ab_core::{
    context_digest_v1, AccountScope, CandidateId, CorrectnessLevel, DerivationContext,
    PublicDigest32, QuorumPolicy, RequestKind, RootShareEpoch, RouterAbDerivationErrorCode,
    SignerSetBinding, TranscriptBinding,
};

fn sample_context(candidate_id: CandidateId) -> DerivationContext {
    DerivationContext::new(
        candidate_id,
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

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn sample_signer_set() -> SignerSetBinding {
    SignerSetBinding::v1_all2(
        "signer-set-v1",
        "role:signer-a:local:sha256-a",
        "key-epoch-a-1",
        "role:signer-b:local:sha256-b",
        "key-epoch-b-1",
    )
    .expect("signer set")
}

#[test]
fn context_encoding_is_stable_for_same_context() {
    let context = sample_context(CandidateId::SplitRootDerivationV1);

    assert_eq!(
        context.encode_context_v1().expect("left"),
        context.encode_context_v1().expect("right")
    );
}

#[test]
fn context_digest_is_stable_for_same_context() {
    let context = sample_context(CandidateId::SplitRootDerivationV1);

    assert_eq!(
        context_digest_v1(&context).expect("left"),
        context_digest_v1(&context).expect("right")
    );
}

#[test]
fn transcript_rejects_duplicate_signer_identities() {
    let err = SignerSetBinding::v1_all2(
        "signer-set-v1",
        "same-signer",
        "key-epoch-a-1",
        "same-signer",
        "key-epoch-b-1",
    )
    .expect_err("duplicate signers should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::DuplicateSignerIdentity
    );
}

#[test]
fn transcript_rejects_non_all2_quorum_policy() {
    let context = sample_context(CandidateId::SplitRootDerivationV1);
    let signer_set = SignerSetBinding {
        signer_set_id: "signer-set-v1".to_owned(),
        quorum_policy: QuorumPolicy::All { signer_count: 3 },
        signers: sample_signer_set().signers,
    };

    let err = TranscriptBinding::new(
        context,
        "router-local",
        signer_set,
        "role:relayer:local:sha256-r",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "role:client:local:sha256-c",
        "x25519:client-ephemeral-public-key",
    )
    .expect_err("v1 should reject non-all2 quorum");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn candidate_entry_points_are_explicitly_gated() {
    let context = sample_context(CandidateId::SplitRootDerivationV1);
    let transcript = TranscriptBinding::new(
        context.clone(),
        "router-local",
        sample_signer_set(),
        "role:relayer:local:sha256-r",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "role:client:local:sha256-c",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript");

    let input = router_ab_core::SplitRootCandidateInput {
        context,
        transcript,
    };

    let err = router_ab_core::evaluate_split_root_candidate(&input)
        .expect_err("candidate should be gated");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::NotImplemented);
}
