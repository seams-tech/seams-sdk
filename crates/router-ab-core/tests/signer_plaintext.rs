use router_ab_core::{
    decode_signer_input_plaintext_v1, CandidateId, MpcPrfOutputRequestV1, MpcPrfSuiteId,
    OpenedShareKind, PublicDigest32, RequestKind, Role, RootShareEpoch,
    RouterAbDerivationErrorCode, SignerInputPlaintextV1, SignerInputQuorumPolicyV1,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

fn client_output() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(OpenedShareKind::XClientBase, Role::Client, "client-1")
        .expect("client output")
}

fn relayer_output() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(OpenedShareKind::XRelayerBase, Role::Relayer, "relayer-a")
        .expect("relayer output")
}

fn plaintext() -> SignerInputPlaintextV1 {
    SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "signer-set-v1",
        SignerInputQuorumPolicyV1::All2,
        Role::SignerA,
        "signer-a",
        "signer-key-epoch-a",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![client_output(), relayer_output()],
    )
    .expect("signer input plaintext")
}

#[test]
fn signer_input_plaintext_decodes_canonical_bytes() {
    let plaintext = plaintext();
    let decoded = decode_signer_input_plaintext_v1(
        &plaintext
            .canonical_bytes()
            .expect("canonical signer input plaintext"),
    )
    .expect("decode signer input plaintext");

    assert_eq!(decoded, plaintext);
}

#[test]
fn signer_input_plaintext_decoder_rejects_trailing_bytes() {
    let mut bytes = plaintext()
        .canonical_bytes()
        .expect("canonical signer input plaintext");
    bytes.extend_from_slice(b"joined_d");

    let err = decode_signer_input_plaintext_v1(&bytes).expect_err("trailing bytes must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn signer_input_plaintext_rejects_unsupported_candidate() {
    let err = SignerInputPlaintextV1::new(
        CandidateId::SplitRootDerivationV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "signer-set-v1",
        SignerInputQuorumPolicyV1::All2,
        Role::SignerA,
        "signer-a",
        "signer-key-epoch-a",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![client_output()],
    )
    .expect_err("split-root candidate must fail at signer input plaintext");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::UnsupportedCandidate
    );
}

#[test]
fn signer_input_plaintext_rejects_duplicate_output_request() {
    let err = SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "signer-set-v1",
        SignerInputQuorumPolicyV1::All2,
        Role::SignerA,
        "signer-a",
        "signer-key-epoch-a",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![client_output(), client_output()],
    )
    .expect_err("duplicate output request must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn signer_input_plaintext_rejects_relayer_recipient_mismatch() {
    let wrong_relayer_output =
        MpcPrfOutputRequestV1::new(OpenedShareKind::XRelayerBase, Role::Relayer, "relayer-b")
            .expect("wrong relayer output");
    let err = SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "signer-set-v1",
        SignerInputQuorumPolicyV1::All2,
        Role::SignerA,
        "signer-a",
        "signer-key-epoch-a",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![wrong_relayer_output],
    )
    .expect_err("wrong relayer recipient must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn signer_input_plaintext_rejects_non_signer_recipient_role() {
    let err = SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "signer-set-v1",
        SignerInputQuorumPolicyV1::All2,
        Role::Router,
        "router",
        "router-key-epoch",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![client_output()],
    )
    .expect_err("non-signer recipient role must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn signer_input_plaintext_rejects_joined_state_marker_in_metadata() {
    let err = SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "joined-state-set",
        SignerInputQuorumPolicyV1::All2,
        Role::SignerA,
        "signer-a",
        "signer-key-epoch-a",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![client_output()],
    )
    .expect_err("joined-state marker must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn signer_input_plaintext_rejects_joined_state_marker_in_output_recipient() {
    let marked_client_output =
        MpcPrfOutputRequestV1::new(OpenedShareKind::XClientBase, Role::Client, "client-joined")
            .expect("output request");
    let err = SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        "lifecycle-1",
        "signer-set-v1",
        SignerInputQuorumPolicyV1::All2,
        Role::SignerA,
        "signer-a",
        "signer-key-epoch-a",
        root_epoch(),
        "relayer-a",
        "relayer-key-epoch",
        digest(0x11),
        digest(0x22),
        digest(0x33),
        vec![marked_client_output],
    )
    .expect_err("joined-state marker must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}
