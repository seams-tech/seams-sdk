use router_ab_core::{
    generated_contract_vectors_json_v1, generated_contract_vectors_v1, CandidateId,
    ContractVectorCorpusV1, OpenedShareKind, RequestKind, RouterAbDerivationErrorCode,
    CONTRACT_VECTOR_VERSION_V1, MPC_PRF_COMMITMENT_WIRE_V1_LEN, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
    MPC_PRF_PARTIAL_WIRE_V1_LEN,
};

const COMMITTED_CONTRACT_VECTORS: &str =
    include_str!("../fixtures/derivation/contract/contract-vectors-v1.json");

#[test]
fn generated_contract_vectors_are_stable() {
    assert_eq!(
        generated_contract_vectors_json_v1().expect("left"),
        generated_contract_vectors_json_v1().expect("right")
    );
}

#[test]
fn generated_contract_vectors_include_required_sections() {
    let corpus = generated_contract_vectors_v1().expect("vectors");

    assert_eq!(corpus.vector_version, CONTRACT_VECTOR_VERSION_V1);
    assert_eq!(corpus.context_transcripts.len(), 3);
    for request_kind in [
        RequestKind::Registration,
        RequestKind::Export,
        RequestKind::Refresh,
    ] {
        let vector = corpus
            .context_transcripts
            .iter()
            .find(|vector| vector.request_kind == request_kind)
            .unwrap_or_else(|| panic!("missing context vector: {request_kind:?}"));
        assert_eq!(
            vector.quorum_policy, "all(2)",
            "v1 vectors must enforce all(2)"
        );
        assert_eq!(vector.selected_relayer_id, "role:relayer:local:sha256-r");
        assert!(!vector.context_digest_hex.is_empty());
        assert!(!vector.transcript_digest_hex.is_empty());
    }

    assert!(!corpus.envelope.aad_hex.is_empty());
    assert!(!corpus.envelope.package_commitment_hex.is_empty());
    assert!(!corpus.envelope.idempotency_key_hex.is_empty());
    assert_eq!(
        corpus.diagnostic.error_code,
        RouterAbDerivationErrorCode::TranscriptMismatch
    );
    assert_eq!(corpus.minimum_level_c_cases.len(), 3);
    for case in &corpus.minimum_level_c_cases {
        assert_eq!(case.evidence.client_package_commitments().len(), 2);
        assert_eq!(case.evidence.relayer_package_commitments().len(), 2);
    }
    assert_eq!(corpus.candidate_output_cases.len(), 6);
    for candidate_id in [
        CandidateId::SplitRootDerivationV1,
        CandidateId::MpcThresholdPrfV1,
    ] {
        for request_kind in [
            RequestKind::Registration,
            RequestKind::Export,
            RequestKind::Refresh,
        ] {
            let vector = corpus
                .candidate_output_cases
                .iter()
                .find(|vector| {
                    vector.candidate_id == candidate_id && vector.request_kind == request_kind
                })
                .unwrap_or_else(|| {
                    panic!("missing candidate vector: {candidate_id:?}/{request_kind:?}")
                });
            assert_eq!(
                vector.expected_error_code,
                RouterAbDerivationErrorCode::NotImplemented
            );
            assert!(!vector.context_digest_hex.is_empty());
            assert!(!vector.transcript_digest_hex.is_empty());
        }
    }
    assert_eq!(corpus.mpc_threshold_prf_backend_cases.len(), 6);
    for request_kind in [
        RequestKind::Registration,
        RequestKind::Export,
        RequestKind::Refresh,
    ] {
        for opened_share_kind in [OpenedShareKind::XClientBase, OpenedShareKind::XRelayerBase] {
            let vector = corpus
                .mpc_threshold_prf_backend_cases
                .iter()
                .find(|vector| {
                    vector.request_kind == request_kind
                        && vector.opened_share_kind == opened_share_kind
                })
                .unwrap_or_else(|| {
                    panic!("missing Candidate A backend vector: {request_kind:?}/{opened_share_kind:?}")
                });
            assert_eq!(
                vector.signer_a_partial_wire_hex.len(),
                MPC_PRF_PARTIAL_WIRE_V1_LEN * 2
            );
            assert_eq!(
                vector.signer_b_partial_wire_hex.len(),
                MPC_PRF_PARTIAL_WIRE_V1_LEN * 2
            );
            assert_eq!(
                vector.signer_a_commitment_wire_hex.len(),
                MPC_PRF_COMMITMENT_WIRE_V1_LEN * 2
            );
            assert_eq!(
                vector.signer_b_commitment_wire_hex.len(),
                MPC_PRF_COMMITMENT_WIRE_V1_LEN * 2
            );
            assert_eq!(
                vector.signer_a_proof_wire_hex.len(),
                MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN * 2
            );
            assert_eq!(
                vector.signer_b_proof_wire_hex.len(),
                MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN * 2
            );
            assert_eq!(vector.combined_output_hex.len(), 64);
            assert!(!vector.context_digest_hex.is_empty());
            assert!(!vector.transcript_digest_hex.is_empty());
        }
    }

    let expected_mpc_rejections = [
        (
            "mpc_threshold_prf_backend_bad_dleq_proof_v1",
            RouterAbDerivationErrorCode::OutputVerificationFailed,
        ),
        (
            "mpc_threshold_prf_backend_transcript_mismatch_v1",
            RouterAbDerivationErrorCode::TranscriptMismatch,
        ),
        (
            "mpc_threshold_prf_backend_duplicate_signer_role_v1",
            RouterAbDerivationErrorCode::DuplicateSignerIdentity,
        ),
        (
            "mpc_threshold_prf_backend_recipient_mismatch_v1",
            RouterAbDerivationErrorCode::RecipientMismatch,
        ),
        (
            "mpc_threshold_prf_backend_wrong_share_id_v1",
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
        ),
        (
            "mpc_threshold_prf_backend_wrong_root_epoch_v1",
            RouterAbDerivationErrorCode::RootEpochMismatch,
        ),
    ];

    assert_eq!(
        corpus.mpc_threshold_prf_backend_rejection_cases.len(),
        expected_mpc_rejections.len()
    );
    for (case_id, expected_error_code) in expected_mpc_rejections {
        let vector = corpus
            .mpc_threshold_prf_backend_rejection_cases
            .iter()
            .find(|vector| vector.case_id == case_id)
            .unwrap_or_else(|| panic!("missing Candidate A backend rejection vector: {case_id}"));
        assert_eq!(vector.expected_error_code, expected_error_code, "{case_id}");
    }

    let expected_rejections = [
        (
            "minimum_level_c_replay_mismatch_v1",
            RouterAbDerivationErrorCode::ReplayMismatch,
        ),
        (
            "minimum_level_c_recipient_mismatch_v1",
            RouterAbDerivationErrorCode::RecipientMismatch,
        ),
        (
            "minimum_level_c_receipt_commitment_mismatch_v1",
            RouterAbDerivationErrorCode::PackageCommitmentMismatch,
        ),
        (
            "minimum_level_c_signer_identity_mismatch_v1",
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
        ),
        (
            "minimum_level_c_root_epoch_mismatch_v1",
            RouterAbDerivationErrorCode::RootEpochMismatch,
        ),
        (
            "minimum_level_c_package_context_mismatch_v1",
            RouterAbDerivationErrorCode::TranscriptMismatch,
        ),
        (
            "transcript_duplicate_signer_identity_v1",
            RouterAbDerivationErrorCode::DuplicateSignerIdentity,
        ),
        (
            "transcript_non_all2_quorum_v1",
            RouterAbDerivationErrorCode::MalformedInput,
        ),
        (
            "refresh_same_old_new_epoch_v1",
            RouterAbDerivationErrorCode::RootEpochMismatch,
        ),
    ];

    assert_eq!(corpus.rejection_cases.len(), expected_rejections.len());
    for (case_id, expected_error_code) in expected_rejections {
        let vector = corpus
            .rejection_cases
            .iter()
            .find(|vector| vector.case_id == case_id)
            .unwrap_or_else(|| panic!("missing rejection vector: {case_id}"));
        assert_eq!(vector.expected_error_code, expected_error_code, "{case_id}");
    }
}

#[test]
fn generated_contract_vector_json_round_trips() {
    let json = generated_contract_vectors_json_v1().expect("json");
    let corpus: ContractVectorCorpusV1 = serde_json::from_str(&json).expect("round trip");

    assert_eq!(corpus.vector_version, CONTRACT_VECTOR_VERSION_V1);
}

#[test]
fn committed_contract_vector_fixture_matches_generator() {
    let committed: ContractVectorCorpusV1 =
        serde_json::from_str(COMMITTED_CONTRACT_VECTORS).expect("committed fixture parses");
    let generated = generated_contract_vectors_v1().expect("generated vectors");

    assert_eq!(committed, generated);
    assert_eq!(
        COMMITTED_CONTRACT_VECTORS.trim_end(),
        generated_contract_vectors_json_v1().expect("generated json")
    );
}
