use router_ab_core::{
    parse_context_v1, parse_envelope_header_v1, parse_minimum_level_c_evidence_v1,
    parse_transcript_v1, CandidateId, CorrectnessLevel, EnvelopeKind, RawAccountScopeV1,
    RawContextV1, RawEnvelopeHeaderV1, RawIndexedSignerBindingV1, RawMinimumLevelCEvidenceV1,
    RawPublicDigest32V1, RawSignerSetBindingV1, RawTranscriptV1, RequestKind, Role,
    RouterAbDerivationErrorCode,
};

fn digest(seed: u8) -> RawPublicDigest32V1 {
    RawPublicDigest32V1 {
        bytes: vec![seed; 32],
    }
}

fn raw_context() -> RawContextV1 {
    RawContextV1 {
        candidate_id: "mpc_threshold_prf_v1".to_owned(),
        request_kind: "registration".to_owned(),
        correctness_level: "minimum_level_c".to_owned(),
        account_scope: RawAccountScopeV1 {
            network_id: "near-testnet".to_owned(),
            account_id: "alice.testnet".to_owned(),
            account_public_key: "ed25519:11111111111111111111111111111111".to_owned(),
        },
        root_share_epoch: "epoch-1".to_owned(),
        ceremony_id: "ceremony-1".to_owned(),
    }
}

fn raw_signer_set(quorum_policy: &str) -> RawSignerSetBindingV1 {
    RawSignerSetBindingV1 {
        signer_set_id: "signer-set-v1".to_owned(),
        quorum_policy: quorum_policy.to_owned(),
        signers: vec![
            RawIndexedSignerBindingV1 {
                signer_index: 0,
                role: "signer_a".to_owned(),
                signer_id: "role:signer-a:local:sha256-a".to_owned(),
                key_epoch: "key-epoch-a-1".to_owned(),
            },
            RawIndexedSignerBindingV1 {
                signer_index: 1,
                role: "signer_b".to_owned(),
                signer_id: "role:signer-b:local:sha256-b".to_owned(),
                key_epoch: "key-epoch-b-1".to_owned(),
            },
        ],
    }
}

fn raw_transcript() -> RawTranscriptV1 {
    RawTranscriptV1 {
        context: raw_context(),
        router_id: "role:router:local:sha256-router".to_owned(),
        signer_set: raw_signer_set("all(2)"),
        selected_server_id: "role:server:local:sha256-r".to_owned(),
        selected_server_recipient_encryption_key:
            "x25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        client_id: "role:client:local:sha256-c".to_owned(),
        client_ephemeral_public_key: "x25519:client-ephemeral-public-key".to_owned(),
    }
}

fn raw_envelope_header() -> RawEnvelopeHeaderV1 {
    RawEnvelopeHeaderV1 {
        envelope_version: "v1".to_owned(),
        envelope_kind: "signer_a_to_client".to_owned(),
        candidate_id: "mpc_threshold_prf_v1".to_owned(),
        request_kind: "registration".to_owned(),
        correctness_level: "minimum_level_c".to_owned(),
        ceremony_id: "ceremony-1".to_owned(),
        root_share_epoch: "epoch-1".to_owned(),
        transcript_digest: digest(0x11),
        sender_role: "signer_a".to_owned(),
        sender_identity: "role:signer-a:local:sha256-a".to_owned(),
        recipient_role: "client".to_owned(),
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        content_kind: "client_output_share".to_owned(),
        ciphertext_digest: digest(0x22),
        ciphertext_len: 128,
    }
}

fn raw_evidence() -> RawMinimumLevelCEvidenceV1 {
    RawMinimumLevelCEvidenceV1 {
        evidence_version: "v1".to_owned(),
        correctness_level: "minimum_level_c".to_owned(),
        context_digest: digest(0x01),
        transcript_digest: digest(0x02),
        signer_a_receipt_digest: digest(0x03),
        signer_b_receipt_digest: digest(0x04),
        client_package_commitments: vec![digest(0xa1), digest(0xb1)],
        server_package_commitments: vec![digest(0xa2), digest(0xb2)],
        replay_cache_key: digest(0x99),
    }
}

#[test]
fn parse_context_accepts_raw_boundary_shape() {
    let context = parse_context_v1(raw_context()).expect("context parses");

    assert_eq!(context.candidate_id(), CandidateId::MpcThresholdPrfV1);
    assert_eq!(context.request_kind(), RequestKind::Registration);
    assert_eq!(context.correctness_level(), CorrectnessLevel::MinimumLevelC);
}

#[test]
fn parse_context_rejects_unknown_candidate() {
    let mut raw = raw_context();
    raw.candidate_id = "prototype_candidate_v1".to_owned();

    let err = parse_context_v1(raw).expect_err("unknown candidate should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::UnsupportedCandidate
    );
}

#[test]
fn parse_context_rejects_retired_split_root_candidate() {
    let mut raw = raw_context();
    raw.candidate_id = "split_root_derivation_v1".to_owned();

    let err = parse_context_v1(raw).expect_err("retired candidate should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::UnsupportedCandidate
    );
}

#[test]
fn parse_transcript_rejects_non_v1_quorum() {
    let mut raw = raw_transcript();
    raw.signer_set = raw_signer_set("all(3)");

    let err = parse_transcript_v1(raw).expect_err("all(3) should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn parse_envelope_header_accepts_role_bound_shape() {
    let header = parse_envelope_header_v1(raw_envelope_header()).expect("header parses");

    assert_eq!(header.envelope_kind(), EnvelopeKind::SignerAToClient);
    assert_eq!(header.sender_role(), Role::SignerA);
    assert_eq!(header.recipient_role(), Role::Client);
}

#[test]
fn parse_envelope_header_rejects_kind_role_mismatch() {
    let mut raw = raw_envelope_header();
    raw.recipient_role = "server".to_owned();

    let err = parse_envelope_header_v1(raw).expect_err("role mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn parse_minimum_level_c_evidence_accepts_public_evidence() {
    let evidence = parse_minimum_level_c_evidence_v1(raw_evidence()).expect("evidence parses");

    assert_eq!(
        evidence.correctness_level(),
        CorrectnessLevel::MinimumLevelC
    );
    assert_eq!(evidence.client_package_commitments().len(), 2);
    assert_eq!(evidence.server_package_commitments().len(), 2);
}

#[test]
fn parse_minimum_level_c_evidence_rejects_bad_digest_length() {
    let mut raw = raw_evidence();
    raw.signer_a_receipt_digest = RawPublicDigest32V1 {
        bytes: vec![0x03; 31],
    };

    let err = parse_minimum_level_c_evidence_v1(raw).expect_err("short digest should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}
