#[path = "support/ecdsa_commitment.rs"]
mod ecdsa_commitment;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    combine_mpc_prf_batch_outputs_with_threshold_backend_v1,
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_partial_with_threshold_backend_v1,
    verify_mpc_prf_partial_with_threshold_backend_v1, AccountScope, DerivationContext,
    MpcPrfDleqProofWireV1, MpcPrfOutputRequestV1, MpcPrfPartialProofBundleV1,
    MpcPrfPartialVerificationInputV1, MpcPrfSignerPartialInputV1, MpcPrfSigningRootShareWireV1,
    MpcPrfThresholdBatchCombineInputV1, MpcPrfThresholdCombineInputV1,
    MpcPrfThresholdSignerBatchInputV1, MpcPrfThresholdSignerBatchOutputV1,
    MpcPrfThresholdSignerInputV1, OpenedShareKind, RequestKind, Role,
    RootShareCommitmentRegistryV1, RootShareEpoch, RouterAbDerivationErrorCode, SignerSetBinding,
    TranscriptBinding,
};
use threshold_prf::reference::evaluate_direct_reference;
use threshold_prf::{
    generate_signing_root, split_signing_root, SigningRootShareWire, ThresholdPolicy,
};
use threshold_prf::{PrfContext, PrfOutputEncoding, PrfPurpose, SuiteId};

fn context() -> DerivationContext {
    context_with_epoch("epoch-1")
}

fn context_with_epoch(epoch: &str) -> DerivationContext {
    DerivationContext::new(
        RequestKind::Registration,
        AccountScope::new(
            "near-testnet",
            "alice.testnet",
            "ed25519:11111111111111111111111111111111",
        )
        .expect("account scope"),
        RootShareEpoch::new(epoch).expect("epoch"),
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

fn output_request(opened_share_kind: OpenedShareKind) -> MpcPrfOutputRequestV1 {
    match opened_share_kind {
        OpenedShareKind::XClientBase => MpcPrfOutputRequestV1::new(
            OpenedShareKind::XClientBase,
            Role::Client,
            "role:client:local:sha256-c",
        ),
        OpenedShareKind::XServerBase => MpcPrfOutputRequestV1::new(
            OpenedShareKind::XServerBase,
            Role::Server,
            "role:server:local:sha256-r",
        ),
    }
    .expect("output request")
}

fn signer_input(
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

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn policy() -> ThresholdPolicy {
    ThresholdPolicy::from_u16s(2, 2).expect("2-of-2 policy")
}

fn share_wire(bytes: [u8; 34]) -> MpcPrfSigningRootShareWireV1 {
    MpcPrfSigningRootShareWireV1::new(bytes.to_vec()).expect("share wire")
}

fn share_wires() -> [MpcPrfSigningRootShareWireV1; 2] {
    let mut setup_rng = seeded_rng(99);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");
    [
        share_wire(SigningRootShareWire::from_share(&shares[0]).to_bytes()),
        share_wire(SigningRootShareWire::from_share(&shares[1]).to_bytes()),
    ]
}

fn client_bundles() -> (
    TranscriptBinding,
    MpcPrfPartialProofBundleV1,
    MpcPrfPartialProofBundleV1,
) {
    let request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    let signer_b = signer_input(
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        vec![request.clone()],
    );
    let [share_a, share_b] = share_wires();
    let bundle_a = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: request.clone(),
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(100),
    )
    .expect("signer A bundle");
    let bundle_b = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_b,
            output_request: request,
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(101),
    )
    .expect("signer B bundle");
    (signer_a.transcript, bundle_a, bundle_b)
}

fn commitment_registry(
    transcript: &TranscriptBinding,
    signer_a_bundle: &MpcPrfPartialProofBundleV1,
    signer_b_bundle: &MpcPrfPartialProofBundleV1,
) -> RootShareCommitmentRegistryV1 {
    ecdsa_commitment::authenticated_registry(
        transcript,
        &signer_a_bundle.commitment_wire,
        &signer_b_bundle.commitment_wire,
    )
}

fn batch_bundle_for_kind(
    output: &MpcPrfThresholdSignerBatchOutputV1,
    opened_share_kind: OpenedShareKind,
) -> MpcPrfPartialProofBundleV1 {
    output
        .proof_bundles
        .iter()
        .find(|bundle| bundle.signer_partial.binding.opened_share_kind == opened_share_kind)
        .cloned()
        .expect("proof bundle for opened share kind")
}

fn threshold_context_from_router_plan(
    plan: &router_ab_core::MpcPrfPurposeBindingPlanV1,
) -> PrfContext {
    let purpose = match plan.output_purpose {
        router_ab_core::MpcPrfOutputPurposeV1::RouterAbXClientBase => {
            PrfPurpose::RouterAbXClientBaseV1
        }
        router_ab_core::MpcPrfOutputPurposeV1::RouterAbXServerBase => {
            PrfPurpose::RouterAbXServerBaseV1
        }
    };
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

#[test]
fn threshold_backend_evaluates_verifies_and_combines_client_output() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![client_request.clone()],
    );
    let signer_b = signer_input(
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        vec![client_request.clone()],
    );
    let mut setup_rng = seeded_rng(42);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");
    let share_a = share_wire(SigningRootShareWire::from_share(&shares[0]).to_bytes());
    let share_b = share_wire(SigningRootShareWire::from_share(&shares[1]).to_bytes());

    let bundle_a = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: client_request.clone(),
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(10),
    )
    .expect("signer A bundle");
    let bundle_b = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_b.clone(),
            output_request: client_request.clone(),
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(11),
    )
    .expect("signer B bundle");
    let registry = commitment_registry(&signer_a.transcript, &bundle_a, &bundle_b);

    let verified_a =
        verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
            transcript: signer_a.transcript.clone(),
            proof_bundle: bundle_a.clone(),
            authenticated_commitment: registry
                .commitment_for(Role::SignerA)
                .expect("Signer A commitment")
                .clone(),
        })
        .expect("verified A");
    assert_eq!(verified_a.signer_partial.binding.signer_role, Role::SignerA);

    let combined =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript.clone(),
            commitment_registry: registry,
            opened_share_kind: OpenedShareKind::XClientBase,
            recipient_role: Role::Client,
            recipient_identity: "role:client:local:sha256-c".to_owned(),
            left: bundle_a,
            right: bundle_b,
        })
        .expect("combined output");
    let plan = router_ab_core::plan_mpc_prf_purpose_binding_v1(&signer_a, &client_request)
        .expect("purpose plan");
    let direct = evaluate_direct_reference(&root, &threshold_context_from_router_plan(&plan))
        .expect("direct output");

    assert_eq!(combined.opened_share_kind, OpenedShareKind::XClientBase);
    assert_eq!(combined.recipient_role, Role::Client);
    assert_eq!(combined.output_material.as_bytes(), direct.as_bytes());
}

#[test]
fn threshold_backend_separates_client_and_server_outputs() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let server_request = output_request(OpenedShareKind::XServerBase);
    let requests = vec![client_request.clone(), server_request.clone()];
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        requests.clone(),
    );
    let signer_b = signer_input(Role::SignerB, "role:signer-b:local:sha256-b", requests);
    let mut setup_rng = seeded_rng(43);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");

    let client_a = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: client_request.clone(),
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[0]).to_bytes(),
            ),
        },
        &mut seeded_rng(12),
    )
    .expect("client A");
    let client_b = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_b.clone(),
            output_request: client_request,
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[1]).to_bytes(),
            ),
        },
        &mut seeded_rng(13),
    )
    .expect("client B");
    let server_a = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: server_request.clone(),
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[0]).to_bytes(),
            ),
        },
        &mut seeded_rng(14),
    )
    .expect("server A");
    let server_b = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_b,
            output_request: server_request,
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[1]).to_bytes(),
            ),
        },
        &mut seeded_rng(15),
    )
    .expect("server B");
    let registry = commitment_registry(&signer_a.transcript, &client_a, &client_b);

    let client =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript.clone(),
            commitment_registry: registry.clone(),
            opened_share_kind: OpenedShareKind::XClientBase,
            recipient_role: Role::Client,
            recipient_identity: "role:client:local:sha256-c".to_owned(),
            left: client_a,
            right: client_b,
        })
        .expect("client output");
    let server =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript,
            commitment_registry: registry,
            opened_share_kind: OpenedShareKind::XServerBase,
            recipient_role: Role::Server,
            recipient_identity: "role:server:local:sha256-r".to_owned(),
            left: server_a,
            right: server_b,
        })
        .expect("server output");

    assert_ne!(client.output_material, server.output_material);
}

#[test]
fn threshold_backend_batch_evaluates_all_requested_outputs() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let server_request = output_request(OpenedShareKind::XServerBase);
    let requests = vec![client_request, server_request];
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        requests.clone(),
    );
    let signer_b = signer_input(Role::SignerB, "role:signer-b:local:sha256-b", requests);
    let [share_a, share_b] = share_wires();

    let batch_a = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_a.clone(),
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(16),
    )
    .expect("signer A batch");
    let batch_b = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_b,
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(17),
    )
    .expect("signer B batch");

    assert_eq!(batch_a.signer_role, Role::SignerA);
    assert_eq!(batch_b.signer_role, Role::SignerB);
    assert_eq!(batch_a.proof_bundles.len(), 2);
    assert_eq!(batch_b.proof_bundles.len(), 2);
    assert_eq!(
        batch_a.proof_bundles[0]
            .signer_partial
            .binding
            .opened_share_kind,
        OpenedShareKind::XClientBase
    );
    assert_eq!(
        batch_a.proof_bundles[1]
            .signer_partial
            .binding
            .opened_share_kind,
        OpenedShareKind::XServerBase
    );
    let registry = commitment_registry(
        &signer_a.transcript,
        &batch_a.proof_bundles[0],
        &batch_b.proof_bundles[0],
    );

    let client =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript.clone(),
            commitment_registry: registry.clone(),
            opened_share_kind: OpenedShareKind::XClientBase,
            recipient_role: Role::Client,
            recipient_identity: "role:client:local:sha256-c".to_owned(),
            left: batch_bundle_for_kind(&batch_a, OpenedShareKind::XClientBase),
            right: batch_bundle_for_kind(&batch_b, OpenedShareKind::XClientBase),
        })
        .expect("client output");
    let server =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript,
            commitment_registry: registry,
            opened_share_kind: OpenedShareKind::XServerBase,
            recipient_role: Role::Server,
            recipient_identity: "role:server:local:sha256-r".to_owned(),
            left: batch_bundle_for_kind(&batch_a, OpenedShareKind::XServerBase),
            right: batch_bundle_for_kind(&batch_b, OpenedShareKind::XServerBase),
        })
        .expect("server output");

    assert_eq!(client.opened_share_kind, OpenedShareKind::XClientBase);
    assert_eq!(server.opened_share_kind, OpenedShareKind::XServerBase);
    assert_ne!(client.output_material, server.output_material);
}

#[test]
fn threshold_backend_batch_combines_all_matching_outputs() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let server_request = output_request(OpenedShareKind::XServerBase);
    let requests = vec![client_request, server_request];
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        requests.clone(),
    );
    let signer_b = signer_input(Role::SignerB, "role:signer-b:local:sha256-b", requests);
    let [share_a, share_b] = share_wires();
    let batch_a = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_a.clone(),
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(19),
    )
    .expect("signer A batch");
    let batch_b = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_b,
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(20),
    )
    .expect("signer B batch");
    let registry = commitment_registry(
        &signer_a.transcript,
        &batch_a.proof_bundles[0],
        &batch_b.proof_bundles[0],
    );

    let combined = combine_mpc_prf_batch_outputs_with_threshold_backend_v1(
        MpcPrfThresholdBatchCombineInputV1 {
            transcript: signer_a.transcript,
            commitment_registry: registry,
            left: batch_a,
            right: batch_b,
        },
    )
    .expect("combined batch");

    assert_eq!(combined.outputs.len(), 2);
    assert_eq!(
        combined.outputs[0].opened_share_kind,
        OpenedShareKind::XClientBase
    );
    assert_eq!(
        combined.outputs[1].opened_share_kind,
        OpenedShareKind::XServerBase
    );
    assert_ne!(
        combined.outputs[0].output_material,
        combined.outputs[1].output_material
    );
}

#[test]
fn threshold_backend_batch_combine_rejects_missing_peer_output() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let server_request = output_request(OpenedShareKind::XServerBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![client_request.clone(), server_request],
    );
    let signer_b = signer_input(
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        vec![client_request],
    );
    let [share_a, share_b] = share_wires();
    let batch_a = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_a.clone(),
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(21),
    )
    .expect("signer A batch");
    let batch_b = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_b,
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(22),
    )
    .expect("signer B batch");
    let registry = commitment_registry(
        &signer_a.transcript,
        &batch_a.proof_bundles[0],
        &batch_b.proof_bundles[0],
    );

    let err = combine_mpc_prf_batch_outputs_with_threshold_backend_v1(
        MpcPrfThresholdBatchCombineInputV1 {
            transcript: signer_a.transcript,
            commitment_registry: registry,
            left: batch_a,
            right: batch_b,
        },
    )
    .expect_err("missing server peer output must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn threshold_backend_batch_rejects_duplicate_output_requests() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![client_request.clone(), client_request],
    );
    let [share_a, _] = share_wires();

    let err = evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(
        MpcPrfThresholdSignerBatchInputV1 {
            signer_input: signer_a,
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(18),
    )
    .expect_err("duplicate output requests must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn threshold_backend_rejects_share_id_for_wrong_signer_role() {
    let request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    let mut setup_rng = seeded_rng(44);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");

    let err = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a,
            output_request: request,
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[1]).to_bytes(),
            ),
        },
        &mut seeded_rng(16),
    )
    .expect_err("wrong share id should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::SignerIdentityMismatch
    );
}

#[test]
fn threshold_backend_rejects_non_signer_role() {
    let request = output_request(OpenedShareKind::XClientBase);
    let mut signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    signer_a.signer_role = Role::Server;
    let [share_a, _share_b] = share_wires();

    let err = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a,
            output_request: request,
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(20),
    )
    .expect_err("non-signer role should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::SignerIdentityMismatch
    );
}

#[test]
fn threshold_backend_rejects_wrong_root_epoch() {
    let request = output_request(OpenedShareKind::XClientBase);
    let mut signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    signer_a.root_share_epoch = RootShareEpoch::new("epoch-2").expect("epoch");
    let [share_a, _share_b] = share_wires();

    let err = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a,
            output_request: request,
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(21),
    )
    .expect_err("wrong root epoch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RootEpochMismatch);
}

#[test]
fn threshold_backend_rejects_malformed_share_wire() {
    let err =
        MpcPrfSigningRootShareWireV1::new(vec![1; 32]).expect_err("short share wire should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn threshold_backend_rejects_non_ab_share_id_at_wire_boundary() {
    let mut bytes = vec![0u8; 34];
    bytes[..2].copy_from_slice(&3u16.to_be_bytes());
    let err = MpcPrfSigningRootShareWireV1::new(bytes)
        .expect_err("share id outside fixed A/B policy must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn threshold_backend_rejects_transcript_mismatch() {
    let request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    let [share_a, share_b] = share_wires();
    let bundle = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: request,
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(22),
    )
    .expect("bundle");
    let peer_bundle = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_input(
                Role::SignerB,
                "role:signer-b:local:sha256-b",
                vec![output_request(OpenedShareKind::XClientBase)],
            ),
            output_request: output_request(OpenedShareKind::XClientBase),
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(23),
    )
    .expect("peer bundle");
    let original_transcript = signer_a.transcript;
    let registry = commitment_registry(&original_transcript, &bundle, &peer_bundle);
    let mismatched_transcript = router_ab_core::TranscriptBinding::new(
        original_transcript.context().clone(),
        "role:router:local:sha256-other",
        original_transcript.signer_set().clone(),
        original_transcript.selected_server_id(),
        original_transcript.selected_server_recipient_encryption_key(),
        original_transcript.client_id(),
        original_transcript.client_ephemeral_public_key(),
    )
    .expect("mismatched transcript");

    let err = verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
        transcript: mismatched_transcript,
        proof_bundle: bundle,
        authenticated_commitment: registry
            .commitment_for(Role::SignerA)
            .expect("Signer A commitment")
            .clone(),
    })
    .expect_err("transcript mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::TranscriptMismatch);
}

#[test]
fn threshold_backend_rejects_bad_dleq_proof() {
    let request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    let mut setup_rng = seeded_rng(45);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");
    let mut bundle = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: request,
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[0]).to_bytes(),
            ),
        },
        &mut seeded_rng(17),
    )
    .expect("bundle");
    let peer_bundle = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_input(
                Role::SignerB,
                "role:signer-b:local:sha256-b",
                vec![output_request(OpenedShareKind::XClientBase)],
            ),
            output_request: output_request(OpenedShareKind::XClientBase),
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[1]).to_bytes(),
            ),
        },
        &mut seeded_rng(18),
    )
    .expect("peer bundle");
    let registry = commitment_registry(&signer_a.transcript, &bundle, &peer_bundle);
    bundle = MpcPrfPartialProofBundleV1::new(
        bundle.signer_partial,
        bundle.commitment_wire,
        MpcPrfDleqProofWireV1::new(vec![0; 64]).expect("zero proof wire"),
    )
    .expect("tampered bundle");

    let err = verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
        transcript: signer_a.transcript,
        proof_bundle: bundle,
        authenticated_commitment: registry
            .commitment_for(Role::SignerA)
            .expect("Signer A commitment")
            .clone(),
    })
    .expect_err("bad proof should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn threshold_backend_rejects_deriver_substituted_commitment_before_dleq() {
    let (transcript, bundle_a, bundle_b) = client_bundles();
    let registry = commitment_registry(&transcript, &bundle_a, &bundle_b);
    let mut substituted_commitment = vec![0u8; router_ab_core::MPC_PRF_COMMITMENT_WIRE_V1_LEN];
    substituted_commitment[..2].copy_from_slice(&1u16.to_be_bytes());
    let substituted_bundle = MpcPrfPartialProofBundleV1::new(
        bundle_a.signer_partial,
        router_ab_core::MpcPrfShareCommitmentWireV1::new(substituted_commitment)
            .expect("substituted commitment"),
        bundle_a.proof_wire,
    )
    .expect("substituted bundle");

    let err = verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
        transcript,
        proof_bundle: substituted_bundle,
        authenticated_commitment: registry
            .commitment_for(Role::SignerA)
            .expect("Signer A commitment")
            .clone(),
    })
    .expect_err("Deriver-supplied commitment substitution must fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::CommitmentMismatch);
}

#[test]
fn threshold_backend_rejects_duplicate_signer_role_combine() {
    let request = output_request(OpenedShareKind::XClientBase);
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        vec![request.clone()],
    );
    let [share_a, share_b] = share_wires();
    let left = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: request.clone(),
            signing_root_share_wire: share_a.clone(),
        },
        &mut seeded_rng(23),
    )
    .expect("left bundle");
    let right = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: request,
            signing_root_share_wire: share_a,
        },
        &mut seeded_rng(24),
    )
    .expect("right bundle");
    let peer = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_input(
                Role::SignerB,
                "role:signer-b:local:sha256-b",
                vec![output_request(OpenedShareKind::XClientBase)],
            ),
            output_request: output_request(OpenedShareKind::XClientBase),
            signing_root_share_wire: share_b,
        },
        &mut seeded_rng(25),
    )
    .expect("peer bundle");
    let registry = commitment_registry(&signer_a.transcript, &left, &peer);

    let err =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript,
            commitment_registry: registry,
            opened_share_kind: OpenedShareKind::XClientBase,
            recipient_role: Role::Client,
            recipient_identity: "role:client:local:sha256-c".to_owned(),
            left,
            right,
        })
        .expect_err("duplicate signer role should fail");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::DuplicateSignerIdentity
    );
}

#[test]
fn threshold_backend_rejects_wrong_recipient_combine() {
    let (transcript, left, right) = client_bundles();
    let registry = commitment_registry(&transcript, &left, &right);

    let err =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript,
            commitment_registry: registry,
            opened_share_kind: OpenedShareKind::XClientBase,
            recipient_role: Role::Client,
            recipient_identity: "role:client:local:sha256-wrong".to_owned(),
            left,
            right,
        })
        .expect_err("wrong recipient should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn threshold_backend_rejects_wrong_purpose_combine() {
    let client_request = output_request(OpenedShareKind::XClientBase);
    let server_request = output_request(OpenedShareKind::XServerBase);
    let requests = vec![client_request.clone(), server_request.clone()];
    let signer_a = signer_input(
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        requests.clone(),
    );
    let signer_b = signer_input(Role::SignerB, "role:signer-b:local:sha256-b", requests);
    let mut setup_rng = seeded_rng(46);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root(&root, policy(), &mut setup_rng).expect("split");
    let client_a = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a.clone(),
            output_request: client_request,
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[0]).to_bytes(),
            ),
        },
        &mut seeded_rng(18),
    )
    .expect("client A");
    let server_b = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_b,
            output_request: server_request,
            signing_root_share_wire: share_wire(
                SigningRootShareWire::from_share(&shares[1]).to_bytes(),
            ),
        },
        &mut seeded_rng(19),
    )
    .expect("server B");
    let registry = commitment_registry(&signer_a.transcript, &client_a, &server_b);

    let err =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: signer_a.transcript,
            commitment_registry: registry,
            opened_share_kind: OpenedShareKind::XClientBase,
            recipient_role: Role::Client,
            recipient_identity: "role:client:local:sha256-c".to_owned(),
            left: client_a,
            right: server_b,
        })
        .expect_err("mixed purposes should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}
