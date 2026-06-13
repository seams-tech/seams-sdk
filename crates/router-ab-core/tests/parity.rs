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
    let context = sample_context(CandidateId::MpcThresholdPrfV1);

    assert_eq!(
        context.encode_context_v1().expect("left"),
        context.encode_context_v1().expect("right")
    );
}

#[test]
fn context_digest_is_stable_for_same_context() {
    let context = sample_context(CandidateId::MpcThresholdPrfV1);

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
    let err = SignerSetBinding::from_indexed_v1(
        "signer-set-v1",
        QuorumPolicy::All { signer_count: 3 },
        sample_signer_set().signers().to_vec(),
    )
    .expect_err("v1 should reject non-all2 quorum");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}
