use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::PublicRouterRequestV1;
use router_ab_core::{
    ab_derivation_proof_batch_payload_digest_v1, ab_derivation_proof_batch_recipient_view_v1,
    ab_peer_message_authentication_input_digest_v1, build_mpc_prf_signer_partial_input_v1,
    build_mpc_prf_threshold_signer_batch_input_v1,
    combine_mpc_prf_recipient_output_from_ab_proof_batches_v1,
    decode_ab_derivation_proof_batch_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    decode_and_validate_signer_envelope_aead_payload_v1, decode_recipient_output_ciphertext_v1,
    decode_recipient_proof_bundle_ciphertext_v1, decode_recipient_proof_bundle_payload_v1,
    decode_router_to_signer_payload_v1, decode_signer_envelope_aead_payload_v1,
    encode_ab_derivation_proof_batch_payload_v1, encode_recipient_output_ciphertext_aad_v1,
    encode_recipient_proof_bundle_ciphertext_aad_v1, encode_recipient_proof_bundle_ciphertext_v1,
    encode_recipient_proof_bundle_payload_v1, encode_wire_message_v1,
    encrypt_recipient_proof_bundle_payload_v1, recipient_output_ciphertext_aad_digest_v1,
    recipient_proof_bundle_ciphertext_aad_digest_v1, recipient_proof_bundle_payload_digest_v1,
    recipient_proof_bundle_payload_from_ab_proof_batch_v1,
    recipient_proof_bundle_wire_message_from_ab_proof_batch_v1, role_encrypted_envelope_digest_v1,
    router_transcript_digest_v1, sign_ab_derivation_proof_batch_peer_payload_v1,
    sign_ab_peer_message_ed25519_authentication_v1, validate_signer_input_plaintext_binding_v1,
    verify_ab_peer_message_ed25519_signature_v1, verify_client_output_package_v1,
    verify_recipient_proof_bundle_ciphertext_payload_v1, verify_relayer_output_package_v1,
    wire_message_digest_v1, AbDerivationProofBatchPayloadV1, AbPeerMessageAuthenticationV1,
    AbPeerMessagePayloadV1, AbPeerMessageSignatureSchemeV1, AbPeerMessageVerifyingKeyV1,
    AccountScope, AuditEventV1, AuditSink, AuthorityVerifiedFallbackReasonV1, CandidateId,
    CanonicalWireBytesV1, ClientOutputPackageV1, Clock, CorrectnessLevel, Csprng,
    DerivationContext, EncryptedPayloadV1, ExpensiveWorkGateDecisionV1, ExpensiveWorkKindV1,
    GateDeferReasonV1, LifecycleScopeV1, MpcPrfOutputRequestV1, MpcPrfSignerPartialInputV1,
    MpcPrfSigningRootShareWireV1, MpcPrfSuiteId, MpcPrfThresholdSignerBatchInputV1,
    MpcPrfThresholdSignerBatchOutputV1, NormalSigningScopeV1, PeerTransport,
    RecipientOutputCiphertextV1, RecipientOutputEncryptionAlgorithmV1,
    RecipientOutputEncryptionRequestV1, RecipientOutputPackageV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RecipientProofBundlePayloadV1, RelayerActivationPayloadV1, RelayerEngine, RelayerIdentityV1,
    RelayerOutputPackageV1, RequestKind, RoleEncryptedEnvelopeV1, RoleEnvelopeAadV1,
    RoleEnvelopeAssignmentV1, RouterAbDerivationErrorCode, RouterAbLifecycleStateV1,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, RouterEngine, RouterEnvelopeDigestSetV1,
    RouterToSignerPayloadV1, RouterTranscriptMetadataV1, SignerAEngine, SignerBEngine,
    SignerEnvelopeAeadPayloadV1, SignerIdentityV1, SignerInputPlaintextV1,
    SignerInputQuorumPolicyV1, SignerKeyStore, SignerResponsePayloadV1, SignerSetBinding,
    SignerSetV1, SigningRootShareStore, TranscriptBinding, WireMessageKindV1, WireMessageV1,
    SIGNER_ENVELOPE_AEAD_TAG_LEN_V1,
};
use router_ab_core::{OpenedShareKind, PublicDigest32, Role, RootShareEpoch, SecretMaterial32};
use threshold_prf::{generate_signing_root, split_signing_root_2_of_3, SigningRootShareWireV1};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

struct TestRecipientProofBundleEncryptor;

impl RecipientProofBundleEncryptorV1 for TestRecipientProofBundleEncryptor {
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
        request.validate()?;
        RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            [0x51; 12],
            EncryptedPayloadV1::new(request.plaintext().to_vec())?,
        )
    }
}

fn peer_authentication(
    from: &SignerIdentityV1,
    to: &SignerIdentityV1,
    transcript_digest: PublicDigest32,
    payload: &CanonicalWireBytesV1,
) -> AbPeerMessageAuthenticationV1 {
    let auth_digest =
        ab_peer_message_authentication_input_digest_v1(from, to, transcript_digest, payload);
    AbPeerMessageAuthenticationV1::new(
        AbPeerMessageSignatureSchemeV1::Ed25519V1,
        auth_digest,
        CanonicalWireBytesV1::new(vec![0xed, 0x19]).expect("signature"),
    )
    .expect("peer authentication")
}

fn signed_peer_message(
    signing_key: &SigningKey,
) -> (AbPeerMessagePayloadV1, AbPeerMessageVerifyingKeyV1) {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let transcript_digest = digest(0x09);
    let payload_body = CanonicalWireBytesV1::new(vec![0xab]).expect("payload");
    let authentication = sign_ab_peer_message_ed25519_authentication_v1(
        signing_key.as_bytes(),
        &signer_a,
        &signer_b,
        transcript_digest,
        &payload_body,
    )
    .expect("peer authentication");
    let message = AbPeerMessagePayloadV1::new(
        signer_a.clone(),
        signer_b,
        transcript_digest,
        payload_body,
        authentication,
    )
    .expect("peer message");
    let verifying_key =
        AbPeerMessageVerifyingKeyV1::new(signer_a, signing_key.verifying_key().to_bytes())
            .expect("peer verifying key");
    (message, verifying_key)
}

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

fn scope(work_kind: ExpensiveWorkKindV1) -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        "lifecycle-1",
        work_kind,
        root_epoch(),
        "wallet-1",
        "session-1",
        "signer-set-v1",
        "relayer-a",
    )
    .expect("lifecycle scope")
}

fn signer_set() -> SignerSetV1 {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");
    SignerSetV1::v1_all2("signer-set-v1", signer_a, signer_b, relayer).expect("signer set")
}

fn transcript_metadata() -> RouterTranscriptMetadataV1 {
    RouterTranscriptMetadataV1::new(
        "near-testnet",
        "ed25519:11111111111111111111111111111111",
        "router",
        "client-1",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript metadata")
}

fn envelope_digest_set_for_assignment(
    assignment: &RoleEnvelopeAssignmentV1,
) -> RouterEnvelopeDigestSetV1 {
    let assignment_digest = role_encrypted_envelope_digest_v1(&assignment.envelope)
        .expect("assignment envelope digest");
    let (signer_a_envelope_digest, signer_b_envelope_digest) = match assignment.signer.role {
        Role::SignerA => (assignment_digest, digest(0x0b)),
        Role::SignerB => (digest(0x0a), assignment_digest),
        _ => unreachable!("assignment signer role"),
    };
    RouterEnvelopeDigestSetV1::new(signer_a_envelope_digest, signer_b_envelope_digest)
}

fn router_to_signer_a_payload(
    lifecycle: LifecycleScopeV1,
    assignment: RoleEnvelopeAssignmentV1,
) -> RouterAbProtocolResult<RouterToSignerPayloadV1> {
    let envelope_digest_set = envelope_digest_set_for_assignment(&assignment);
    RouterToSignerPayloadV1::signer_a(
        lifecycle,
        signer_set(),
        transcript_metadata(),
        envelope_digest_set,
        digest(0x33),
        assignment,
    )
}

fn router_to_signer_a_payload_with_reconstructed_transcript(
    lifecycle: LifecycleScopeV1,
    assignment: RoleEnvelopeAssignmentV1,
    root_share_epoch: RootShareEpoch,
) -> RouterAbProtocolResult<RouterToSignerPayloadV1> {
    let envelope_digest_set = envelope_digest_set_for_assignment(&assignment);
    let signer_set = signer_set();
    let transcript_digest = router_transcript_digest_v1(
        &lifecycle,
        &signer_set,
        &transcript_metadata(),
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_share_epoch,
    )?;
    RouterToSignerPayloadV1::signer_a(
        lifecycle,
        signer_set,
        transcript_metadata(),
        envelope_digest_set,
        transcript_digest,
        assignment,
    )
}

fn client_output_request() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(OpenedShareKind::XClientBase, Role::Client, "client-1")
        .expect("client output")
}

fn relayer_output_request() -> MpcPrfOutputRequestV1 {
    MpcPrfOutputRequestV1::new(OpenedShareKind::XRelayerBase, Role::Relayer, "relayer-a")
        .expect("relayer output")
}

fn mpc_context() -> DerivationContext {
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
        root_epoch(),
        "ceremony-1",
    )
    .expect("mpc context")
}

fn mpc_transcript(context: DerivationContext) -> TranscriptBinding {
    TranscriptBinding::new(
        context,
        "router",
        SignerSetBinding::v1_all2(
            "signer-set-v1",
            "signer-a",
            "epoch-a",
            "signer-b",
            "epoch-b",
        )
        .expect("signer set binding"),
        "relayer-a",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "client-1",
        "x25519:client-ephemeral-public-key",
    )
    .expect("mpc transcript")
}

fn mpc_signer_input(role: Role) -> MpcPrfSignerPartialInputV1 {
    let context = mpc_context();
    let signer_identity = match role {
        Role::SignerA => "signer-a",
        Role::SignerB => "signer-b",
        _ => panic!("test helper requires signer role"),
    };
    MpcPrfSignerPartialInputV1::new(
        context.clone(),
        mpc_transcript(context),
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        role,
        signer_identity,
        root_epoch(),
        vec![client_output_request(), relayer_output_request()],
    )
    .expect("mpc signer input")
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn mpc_share_wires() -> [MpcPrfSigningRootShareWireV1; 2] {
    let mut setup_rng = seeded_rng(88);
    let root = generate_signing_root(&mut setup_rng);
    let shares = split_signing_root_2_of_3(&root, &mut setup_rng);
    [
        MpcPrfSigningRootShareWireV1::new(
            SigningRootShareWireV1::from_share(&shares[0])
                .to_bytes()
                .to_vec(),
        )
        .expect("signer a share wire"),
        MpcPrfSigningRootShareWireV1::new(
            SigningRootShareWireV1::from_share(&shares[2])
                .to_bytes()
                .to_vec(),
        )
        .expect("signer b share wire"),
    ]
}

fn signer_a_mpc_batch() -> MpcPrfThresholdSignerBatchOutputV1 {
    let signer_a = SignerAEngine::new(DummyHost);
    let [share_a, _] = mpc_share_wires();
    signer_a
        .evaluate_mpc_prf_output_batch(
            MpcPrfThresholdSignerBatchInputV1 {
                signer_input: mpc_signer_input(Role::SignerA),
                signing_root_share_wire: share_a,
            },
            &mut seeded_rng(24),
        )
        .expect("signer A batch")
}

fn public_router_request_with_valid_transcript() -> PublicRouterRequestV1 {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_set = signer_set();
    let transcript_digest = router_transcript_digest_v1(
        &lifecycle,
        &signer_set,
        &transcript_metadata(),
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_epoch(),
    )
    .expect("public request transcript digest");
    PublicRouterRequestV1::new(
        "request-nonce-1",
        2_000,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set,
        "near-testnet",
        "ed25519:11111111111111111111111111111111",
        "router",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        scoped_test_role_envelope(Role::SignerA, 0xa0),
        scoped_test_role_envelope(Role::SignerB, 0xb0),
    )
    .expect("public router request with valid transcript")
}

fn scoped_test_role_envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(1)])
            .expect("scoped test envelope payload"),
    )
    .expect("scoped test role envelope")
}

fn router_scoped_ab_proof_batches() -> (
    RouterToSignerPayloadV1,
    AbDerivationProofBatchPayloadV1,
    AbDerivationProofBatchPayloadV1,
) {
    let request = public_router_request_with_valid_transcript();
    let (payload_a, payload_b) = request.to_signer_payloads().expect("signer payloads");
    let [share_a, share_b] = mpc_share_wires();
    let request_context_digest = request
        .request_context_digest()
        .expect("request context digest");
    let plaintext_a = signer_input_plaintext(&payload_a, request_context_digest, root_epoch());
    let plaintext_b = signer_input_plaintext(&payload_b, request_context_digest, root_epoch());
    let input_a = build_mpc_prf_threshold_signer_batch_input_v1(&payload_a, &plaintext_a, share_a)
        .expect("signer a threshold batch input");
    let input_b = build_mpc_prf_threshold_signer_batch_input_v1(&payload_b, &plaintext_b, share_b)
        .expect("signer b threshold batch input");
    let output_a = SignerAEngine::new(DummyHost)
        .evaluate_mpc_prf_output_batch(input_a, &mut seeded_rng(31))
        .expect("signer a threshold output");
    let output_b = SignerBEngine::new(DummyHost)
        .evaluate_mpc_prf_output_batch(input_b, &mut seeded_rng(32))
        .expect("signer b threshold output");
    let proof_batch_a = AbDerivationProofBatchPayloadV1::new(
        payload_a.signer_set().signer_a.clone(),
        payload_a.signer_set().signer_b.clone(),
        output_a.transcript_digest,
        output_a.root_share_epoch,
        output_a.proof_bundles,
    )
    .expect("signer a proof batch");
    let proof_batch_b = AbDerivationProofBatchPayloadV1::new(
        payload_b.signer_set().signer_b.clone(),
        payload_b.signer_set().signer_a.clone(),
        output_b.transcript_digest,
        output_b.root_share_epoch,
        output_b.proof_bundles,
    )
    .expect("signer b proof batch");
    (payload_a, proof_batch_a, proof_batch_b)
}

fn signed_proof_batch_peer_payload(
    proof_batch: AbDerivationProofBatchPayloadV1,
) -> AbPeerMessagePayloadV1 {
    let batch_output = MpcPrfThresholdSignerBatchOutputV1 {
        transcript_digest: proof_batch.transcript_digest,
        signer_role: proof_batch.from.role,
        signer_identity: proof_batch.from.signer_id.clone(),
        root_share_epoch: proof_batch.root_share_epoch,
        proof_bundles: proof_batch.proof_bundles,
    };
    sign_ab_derivation_proof_batch_peer_payload_v1(
        SigningKey::from_bytes(&[0xa1; 32]).as_bytes(),
        proof_batch.from,
        proof_batch.to,
        batch_output,
    )
    .expect("peer payload")
}

fn signer_input_plaintext(
    payload: &RouterToSignerPayloadV1,
    router_request_digest: PublicDigest32,
    root_share_epoch: RootShareEpoch,
) -> SignerInputPlaintextV1 {
    let assignment = payload.assignment();
    let signer_set = payload.signer_set();
    SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        payload.lifecycle().primitive_request_kind,
        payload.lifecycle().lifecycle_id.clone(),
        signer_set.signer_set_id.clone(),
        SignerInputQuorumPolicyV1::All2,
        assignment.signer.role,
        assignment.signer.signer_id.clone(),
        assignment.signer.key_epoch.clone(),
        root_share_epoch,
        signer_set.selected_relayer.relayer_id.clone(),
        signer_set.selected_relayer.key_epoch.clone(),
        payload.transcript_digest(),
        router_request_digest,
        assignment.envelope.aad_digest,
        vec![client_output_request(), relayer_output_request()],
    )
    .expect("signer input plaintext")
}

fn client_output(transcript_digest: PublicDigest32) -> ClientOutputPackageV1 {
    let package_commitment = digest(0xc1);
    ClientOutputPackageV1::new(
        transcript_digest,
        package_commitment,
        output_ciphertext(
            transcript_digest,
            package_commitment,
            Role::Client,
            OpenedShareKind::XClientBase,
            "client",
            "x25519:client-ephemeral-public-key",
            0xc1,
        ),
    )
    .expect("client output")
}

fn relayer_output(transcript_digest: PublicDigest32) -> RelayerOutputPackageV1 {
    let package_commitment = digest(0xc2);
    RelayerOutputPackageV1::new(
        transcript_digest,
        package_commitment,
        output_ciphertext(
            transcript_digest,
            package_commitment,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
            "relayer-a",
            "relayer-key-epoch:relayer-key-epoch-1",
            0xc2,
        ),
    )
    .expect("relayer output")
}

#[allow(clippy::too_many_arguments)]
fn output_ciphertext(
    transcript_digest: PublicDigest32,
    package_commitment: PublicDigest32,
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    recipient_identity: &str,
    recipient_encryption_key: &str,
    seed: u8,
) -> RecipientOutputCiphertextV1 {
    RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        recipient_role,
        opened_share_kind,
        recipient_identity,
        recipient_encryption_key,
        transcript_digest,
        package_commitment,
        [seed; 12],
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(1)]).expect("output ciphertext"),
    )
    .expect("recipient output ciphertext")
}

#[test]
fn recovery_lifecycle_maps_to_export_primitive() {
    let scope = scope(ExpensiveWorkKindV1::Recovery);

    assert_eq!(
        scope.primitive_request_kind,
        router_ab_core::RequestKind::Export
    );
}

#[test]
fn lifecycle_applies_gate_decision_into_branch_specific_state() {
    let scope = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let state = RouterAbLifecycleStateV1::apply_gate_decision(
        scope,
        ExpensiveWorkGateDecisionV1::accepted("request-1").expect("accepted"),
    )
    .expect("state");

    match state {
        RouterAbLifecycleStateV1::GateAccepted { request_id, .. } => {
            assert_eq!(request_id, "request-1");
        }
        other => panic!("unexpected state: {other:?}"),
    }
}

#[test]
fn lifecycle_rejects_empty_scope_identity() {
    let err = LifecycleScopeV1::new(
        "",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch(),
        "wallet-1",
        "session-1",
        "signer-set-v1",
        "role:relayer:local:sha256-r",
    )
    .expect_err("empty lifecycle id must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn lifecycle_models_authority_verified_fallback_when_prepare_disabled() {
    let scope = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let state = RouterAbLifecycleStateV1::authority_verified_fallback(
        scope,
        AuthorityVerifiedFallbackReasonV1::EarlyPrepareDisabled,
    )
    .expect("fallback");

    match state {
        RouterAbLifecycleStateV1::AuthorityVerifiedFallback { reason, .. } => {
            assert_eq!(
                reason,
                AuthorityVerifiedFallbackReasonV1::EarlyPrepareDisabled
            );
        }
        other => panic!("unexpected state: {other:?}"),
    }
}

#[test]
fn gate_defer_reason_maps_to_authority_verified_fallback_reason() {
    assert_eq!(
        AuthorityVerifiedFallbackReasonV1::from(GateDeferReasonV1::ShortWindowSaturated),
        AuthorityVerifiedFallbackReasonV1::ShortWindowSaturated
    );
    assert_eq!(
        AuthorityVerifiedFallbackReasonV1::from(GateDeferReasonV1::SignerQueueSaturated),
        AuthorityVerifiedFallbackReasonV1::SignerQueueSaturated
    );
}

#[test]
fn normal_signing_scope_stays_outside_derivation_lifecycle() {
    let scope =
        NormalSigningScopeV1::new("sign-1", "wallet-1", "session-1", "relayer-a").expect("scope");

    assert_eq!(scope.request_id, "sign-1");
    assert_eq!(scope.relayer_id, "relayer-a");
}

#[test]
fn normal_signing_scope_rejects_empty_identity_fields() {
    let err = NormalSigningScopeV1::new("", "wallet-1", "session-1", "relayer-a")
        .expect_err("empty request id must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn encrypted_envelope_accepts_only_signer_recipients() {
    let payload = EncryptedPayloadV1::new(vec![1, 2, 3]).expect("payload");
    let envelope = RoleEncryptedEnvelopeV1::new(Role::SignerA, digest(0x01), digest(0x02), payload)
        .expect("signer envelope");

    assert_eq!(envelope.recipient_role, Role::SignerA);

    let payload = EncryptedPayloadV1::new(vec![1, 2, 3]).expect("payload");
    let err = RoleEncryptedEnvelopeV1::new(Role::Router, digest(0x01), digest(0x02), payload)
        .expect_err("router recipient must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn encrypted_payload_debug_redacts_bytes() {
    let payload = EncryptedPayloadV1::new(vec![1, 2, 3]).expect("payload");
    let debug = format!("{payload:?}");

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("1, 2, 3"));
}

fn signer_envelope_aead_payload() -> SignerEnvelopeAeadPayloadV1 {
    SignerEnvelopeAeadPayloadV1::new(
        Role::SignerA,
        "envelope-key-epoch-a",
        digest(0x02),
        [0xa1; 12],
        vec![
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf, 0xd0, 0xd1,
        ],
    )
    .expect("signer envelope AEAD payload")
}

#[test]
fn signer_envelope_aead_payload_round_trips_and_validates_outer_envelope() {
    let aead = signer_envelope_aead_payload();
    let envelope = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(aead.canonical_bytes()).expect("encrypted payload"),
    )
    .expect("outer envelope");

    let decoded =
        decode_and_validate_signer_envelope_aead_payload_v1(&envelope, "envelope-key-epoch-a")
            .expect("decoded AEAD payload");

    assert_eq!(decoded.recipient_role, Role::SignerA);
    assert_eq!(decoded.key_epoch, "envelope-key-epoch-a");
    assert_eq!(decoded.aad_digest, digest(0x02));
    assert_eq!(decoded.nonce(), &[0xa1; 12]);
    assert_eq!(decoded.ciphertext_and_tag(), aead.ciphertext_and_tag());
}

#[test]
fn signer_envelope_aead_payload_rejects_wrong_key_epoch() {
    let aead = signer_envelope_aead_payload();
    let envelope = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(aead.canonical_bytes()).expect("encrypted payload"),
    )
    .expect("outer envelope");

    let err =
        decode_and_validate_signer_envelope_aead_payload_v1(&envelope, "envelope-key-epoch-b")
            .expect_err("wrong key epoch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_envelope_aead_payload_rejects_wrong_outer_aad_digest() {
    let aead = signer_envelope_aead_payload();
    let envelope = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x03),
        EncryptedPayloadV1::new(aead.canonical_bytes()).expect("encrypted payload"),
    )
    .expect("outer envelope");

    let err =
        decode_and_validate_signer_envelope_aead_payload_v1(&envelope, "envelope-key-epoch-a")
            .expect_err("AAD mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_envelope_aead_payload_rejects_short_ciphertext_and_tag() {
    let err = SignerEnvelopeAeadPayloadV1::new(
        Role::SignerA,
        "envelope-key-epoch-a",
        digest(0x02),
        [0xa1; 12],
        vec![0xc0; SIGNER_ENVELOPE_AEAD_TAG_LEN_V1],
    )
    .expect_err("tag-only payload must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_envelope_aead_payload_rejects_trailing_bytes() {
    let mut bytes = signer_envelope_aead_payload().canonical_bytes();
    bytes.push(0xff);

    let err = decode_signer_envelope_aead_payload_v1(&bytes)
        .expect_err("trailing AEAD payload bytes must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_envelope_aead_payload_rejects_bad_tag_length() {
    let mut bytes = signer_envelope_aead_payload().canonical_bytes();
    let tag_len = (SIGNER_ENVELOPE_AEAD_TAG_LEN_V1 as u32).to_be_bytes();
    let offset = bytes
        .windows(tag_len.len())
        .rposition(|window| window == tag_len)
        .expect("tag length offset");
    bytes[offset + 3] = 15;

    let err = decode_signer_envelope_aead_payload_v1(&bytes)
        .expect_err("non-16-byte AEAD tag length must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_envelope_aead_payload_debug_redacts_nonce_and_ciphertext() {
    let debug = format!("{:?}", signer_envelope_aead_payload());

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("161"));
    assert!(!debug.contains("192"));
}

#[test]
fn role_envelope_aad_binds_identity_and_expiry() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");
    let aad = RoleEnvelopeAadV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        "signer-set-v1",
        signer_a,
        relayer,
        digest(0x01),
        digest(0x02),
        1_000,
    )
    .expect("aad");

    assert_eq!(
        aad.primitive_request_kind,
        router_ab_core::RequestKind::Registration
    );
    assert_eq!(
        aad.canonical_bytes(),
        router_ab_core::encode_role_envelope_aad_v1(&aad)
    );
    assert_eq!(
        aad.digest(),
        router_ab_core::role_envelope_aad_digest_v1(&aad)
    );
}

#[test]
fn role_envelope_aad_rejects_zero_expiry() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");
    let err = RoleEnvelopeAadV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        "signer-set-v1",
        signer_a,
        relayer,
        digest(0x01),
        digest(0x02),
        0,
    )
    .expect_err("zero expiry must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn wire_message_requires_non_empty_payload() {
    let err = CanonicalWireBytesV1::new(Vec::new()).expect_err("empty payload must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let message = WireMessageV1::new(
        WireMessageKindV1::RouterToSignerA,
        digest(0x01),
        CanonicalWireBytesV1::new(vec![0xaa]).expect("payload"),
    )
    .expect("wire message");

    assert_eq!(message.kind, WireMessageKindV1::RouterToSignerA);
}

#[test]
fn wire_message_encoding_is_stable_and_length_prefixed() {
    let message = WireMessageV1::new(
        WireMessageKindV1::RouterToSignerA,
        digest(0x11),
        CanonicalWireBytesV1::new(vec![0xaa, 0xbb]).expect("payload"),
    )
    .expect("wire message");

    let encoded = encode_wire_message_v1(&message);
    let label = b"router-ab-protocol/wire-message/v1";
    let label_len = u32::from_be_bytes(encoded[0..4].try_into().expect("length prefix"));
    assert_eq!(label_len as usize, label.len());
    assert_eq!(&encoded[4..4 + label.len()], label);
    assert_eq!(message.canonical_bytes(), encoded);
    assert_eq!(message.digest(), wire_message_digest_v1(&message));
}

#[test]
fn wire_message_digest_binds_message_kind() {
    let payload = CanonicalWireBytesV1::new(vec![0xaa, 0xbb]).expect("payload");
    let left = WireMessageV1::new(WireMessageKindV1::RouterToSignerA, digest(0x11), payload)
        .expect("left");
    let payload = CanonicalWireBytesV1::new(vec![0xaa, 0xbb]).expect("payload");
    let right = WireMessageV1::new(WireMessageKindV1::RouterToSignerB, digest(0x11), payload)
        .expect("right");

    assert_ne!(left.digest(), right.digest());
}

#[test]
fn output_packages_bind_recipient_and_opened_share_kind() {
    let client = client_output(digest(0x01));
    assert_eq!(client.recipient_role(), Role::Client);
    assert_eq!(client.opened_share_kind(), OpenedShareKind::XClientBase);

    let relayer = relayer_output(digest(0x03));
    assert_eq!(relayer.recipient_role(), Role::Relayer);
    assert_eq!(relayer.opened_share_kind(), OpenedShareKind::XRelayerBase);
}

#[test]
fn client_output_verification_requires_expected_transcript() {
    let client = client_output(digest(0x01));

    verify_client_output_package_v1(&client, digest(0x01)).expect("client output verifies");
    let err = verify_client_output_package_v1(&client, digest(0x99))
        .expect_err("client transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn relayer_output_verification_requires_expected_transcript() {
    let relayer = relayer_output(digest(0x03));

    verify_relayer_output_package_v1(&relayer, digest(0x03)).expect("relayer output verifies");
    let err = verify_relayer_output_package_v1(&relayer, digest(0x99))
        .expect_err("relayer transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn recipient_output_package_preserves_branch_semantics() {
    let client = RecipientOutputPackageV1::client(client_output(digest(0x01)));
    assert_eq!(client.recipient_role(), Role::Client);
    assert_eq!(client.opened_share_kind(), OpenedShareKind::XClientBase);

    let relayer = RecipientOutputPackageV1::relayer(relayer_output(digest(0x03)));
    assert_eq!(relayer.recipient_role(), Role::Relayer);
    assert_eq!(relayer.opened_share_kind(), OpenedShareKind::XRelayerBase);
}

#[test]
fn output_package_debug_redacts_ciphertext() {
    let client = client_output(digest(0x01));
    let debug = format!("{client:?}");

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("1, 2, 3"));
}

#[test]
fn recipient_output_ciphertext_aad_binds_delivery_metadata() {
    let transcript_digest = digest(0x01);
    let package_commitment = digest(0x02);
    let left = output_ciphertext(
        transcript_digest,
        package_commitment,
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        "x25519:client-ephemeral-public-key",
        0xc1,
    );
    let right = output_ciphertext(
        transcript_digest,
        package_commitment,
        Role::Client,
        OpenedShareKind::XClientBase,
        "client-rotated",
        "x25519:client-ephemeral-public-key",
        0xc1,
    );

    assert_ne!(
        encode_recipient_output_ciphertext_aad_v1(&left).expect("left aad"),
        encode_recipient_output_ciphertext_aad_v1(&right).expect("right aad")
    );
    assert_ne!(
        recipient_output_ciphertext_aad_digest_v1(&left).expect("left aad digest"),
        recipient_output_ciphertext_aad_digest_v1(&right).expect("right aad digest")
    );
}

#[test]
fn recipient_output_ciphertext_aad_excludes_ciphertext_bytes() {
    let transcript_digest = digest(0x01);
    let package_commitment = digest(0x02);
    let left = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        package_commitment,
        [0xab; 12],
        EncryptedPayloadV1::new(vec![0x01, 0x02]).expect("left ciphertext"),
    )
    .expect("left recipient ciphertext");
    let right = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        package_commitment,
        [0xab; 12],
        EncryptedPayloadV1::new(vec![0x03, 0x04]).expect("right ciphertext"),
    )
    .expect("right recipient ciphertext");

    assert_eq!(
        encode_recipient_output_ciphertext_aad_v1(&left).expect("left aad"),
        encode_recipient_output_ciphertext_aad_v1(&right).expect("right aad")
    );
    assert_ne!(
        left.canonical_bytes().expect("left canonical"),
        right.canonical_bytes().expect("right canonical")
    );
}

#[test]
fn recipient_output_ciphertext_accepts_hpke_x25519_key() {
    let envelope = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        digest(0x01),
        digest(0x02),
        [0xab; 12],
        EncryptedPayloadV1::new(vec![0x51, 0x52, 0x53]).expect("hpke ciphertext"),
    )
    .expect("hpke recipient ciphertext");
    let decoded = decode_recipient_output_ciphertext_v1(
        &envelope
            .canonical_bytes()
            .expect("hpke canonical ciphertext"),
    )
    .expect("decode hpke recipient ciphertext");

    assert_eq!(
        decoded.algorithm,
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1
    );
}

#[test]
fn recipient_output_ciphertext_rejects_hpke_non_x25519_key() {
    let err = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        "aes-256-gcm:key-epoch-1",
        digest(0x01),
        digest(0x02),
        [0xab; 12],
        EncryptedPayloadV1::new(vec![0x51, 0x52, 0x53]).expect("hpke ciphertext"),
    )
    .expect_err("hpke recipient ciphertext must require x25519 key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn client_output_package_rejects_ciphertext_metadata_mismatch() {
    let ciphertext = output_ciphertext(
        digest(0x99),
        digest(0x02),
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        "x25519:client-ephemeral-public-key",
        0xc1,
    );

    let err = ClientOutputPackageV1::new(digest(0x01), digest(0x02), ciphertext)
        .expect_err("mismatched ciphertext metadata must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn recipient_output_encryption_request_rejects_invalid_binding() {
    let plaintext = SecretMaterial32::new([0x11; 32]);

    let err = RecipientOutputEncryptionRequestV1::new(
        Role::Client,
        OpenedShareKind::XRelayerBase,
        "client",
        "x25519:client-ephemeral-public-key",
        digest(0x01),
        digest(0x02),
        &plaintext,
    )
    .err()
    .expect("invalid recipient/opened-share binding must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_set_enforces_all2_roles_and_distinct_ids() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");

    let signer_set =
        SignerSetV1::v1_all2("signer-set-v1", signer_a, signer_b, relayer).expect("signer set");
    assert_eq!(signer_set.signer_set_id, "signer-set-v1");
}

#[test]
fn signer_set_rejects_duplicate_signer_ids() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer", "epoch-b").expect("signer b identity");
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");

    let err = SignerSetV1::v1_all2("signer-set-v1", signer_a, signer_b, relayer)
        .expect_err("duplicate signer ids must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_identity_rejects_non_signer_roles() {
    let err = SignerIdentityV1::new(Role::Router, "router", "epoch")
        .expect_err("router is not a signer identity");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn role_envelope_assignment_requires_matching_role() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_b = RoleEncryptedEnvelopeV1::new(
        Role::SignerB,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xb0]).expect("payload"),
    )
    .expect("envelope b");

    let err = RoleEnvelopeAssignmentV1::new(signer_a, envelope_b)
        .expect_err("assignment must reject role mismatch");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn router_to_signer_payload_enforces_branch_role() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");

    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");
    assert!(matches!(payload, RouterToSignerPayloadV1::SignerA { .. }));

    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let envelope_b = RoleEncryptedEnvelopeV1::new(
        Role::SignerB,
        digest(0x03),
        digest(0x04),
        EncryptedPayloadV1::new(vec![0xb0]).expect("payload"),
    )
    .expect("envelope b");
    let assignment_b = RoleEnvelopeAssignmentV1::new(signer_b, envelope_b).expect("assignment b");
    let err = router_to_signer_a_payload(lifecycle, assignment_b)
        .expect_err("router-to-a payload must reject signer b assignment");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn router_to_signer_payload_requires_assignment_from_signer_set() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let other_signer_a =
        SignerIdentityV1::new(Role::SignerA, "other-signer-a", "epoch-a").expect("signer a");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a =
        RoleEnvelopeAssignmentV1::new(other_signer_a, envelope_a).expect("assignment a");

    let err = router_to_signer_a_payload(lifecycle, assignment_a)
        .expect_err("assignment identity must match signer set");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn router_to_signer_payload_requires_lifecycle_signer_set_binding() {
    let lifecycle = LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch(),
        "wallet-1",
        "session-1",
        "other-signer-set",
        "relayer-a",
    )
    .expect("lifecycle scope");
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");

    let err = router_to_signer_a_payload(lifecycle, assignment_a)
        .expect_err("lifecycle signer-set mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn router_to_signer_payload_requires_lifecycle_relayer_binding() {
    let lifecycle = LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch(),
        "wallet-1",
        "session-1",
        "signer-set-v1",
        "other-relayer",
    )
    .expect("lifecycle scope");
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");

    let err = router_to_signer_a_payload(lifecycle, assignment_a)
        .expect_err("lifecycle relayer mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn router_to_signer_payload_decodes_canonical_bytes() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");

    let decoded = decode_router_to_signer_payload_v1(&payload.canonical_bytes())
        .expect("canonical payload decodes");

    assert_eq!(decoded, payload);
}

#[test]
fn router_to_signer_payload_decoder_rejects_trailing_bytes() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");
    let mut bytes = payload.canonical_bytes();
    bytes.push(0);

    let err = decode_router_to_signer_payload_v1(&bytes).expect_err("trailing byte must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_to_signer_payload_decoder_rejects_branch_role_mismatch() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");
    let mut bytes = payload.canonical_bytes();
    let branch = b"signer_a";
    let index = bytes
        .windows(branch.len())
        .position(|window| window == branch)
        .expect("branch marker");
    bytes[index + branch.len() - 1] = b'b';

    let err =
        decode_router_to_signer_payload_v1(&bytes).expect_err("branch role mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn signer_input_plaintext_binding_accepts_matching_payload() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let router_request_digest = digest(0x44);
    let root_share_epoch = root_epoch();
    let payload = router_to_signer_a_payload_with_reconstructed_transcript(
        lifecycle,
        assignment_a,
        root_share_epoch.clone(),
    )
    .expect("router-to-a payload");
    let plaintext =
        signer_input_plaintext(&payload, router_request_digest, root_share_epoch.clone());

    validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        router_request_digest,
        &root_share_epoch,
    )
    .expect("matching signer input plaintext binding");
}

#[test]
fn mpc_prf_signer_input_builder_accepts_matching_plaintext() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let router_request_digest = digest(0x44);
    let root_share_epoch = root_epoch();
    let payload = router_to_signer_a_payload_with_reconstructed_transcript(
        lifecycle,
        assignment_a,
        root_share_epoch.clone(),
    )
    .expect("router-to-a payload");
    let plaintext =
        signer_input_plaintext(&payload, router_request_digest, root_share_epoch.clone());
    let [share_a, _] = mpc_share_wires();

    validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        router_request_digest,
        &root_share_epoch,
    )
    .expect("matching signer input plaintext binding");
    let signer_input =
        build_mpc_prf_signer_partial_input_v1(&payload, &plaintext).expect("signer partial input");
    let batch_input = build_mpc_prf_threshold_signer_batch_input_v1(&payload, &plaintext, share_a)
        .expect("signer batch input");

    assert_eq!(signer_input.signer_role, Role::SignerA);
    assert_eq!(signer_input.signer_identity, "signer-a");
    assert_eq!(signer_input.output_requests.len(), 2);
    assert_eq!(batch_input.signer_input, signer_input);
}

#[test]
fn mpc_prf_signer_input_builder_rejects_transcript_mismatch() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload_with_reconstructed_transcript(
        lifecycle,
        assignment_a,
        root_epoch(),
    )
    .expect("router-to-a payload");
    let mut plaintext = signer_input_plaintext(&payload, digest(0x44), root_epoch());
    plaintext.transcript_digest = digest(0x99);

    let err = build_mpc_prf_signer_partial_input_v1(&payload, &plaintext)
        .expect_err("transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_input_plaintext_binding_rejects_recipient_identity_mismatch() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");
    let router_request_digest = digest(0x44);
    let root_share_epoch = root_epoch();
    let mut plaintext =
        signer_input_plaintext(&payload, router_request_digest, root_share_epoch.clone());
    plaintext.recipient_signer_id = "other-signer-a".to_owned();

    let err = validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        router_request_digest,
        &root_share_epoch,
    )
    .expect_err("recipient identity mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_input_plaintext_binding_rejects_request_digest_mismatch() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");
    let router_request_digest = digest(0x44);
    let root_share_epoch = root_epoch();
    let plaintext =
        signer_input_plaintext(&payload, router_request_digest, root_share_epoch.clone());

    let err = validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        digest(0x55),
        &root_share_epoch,
    )
    .expect_err("request digest mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_input_plaintext_binding_rejects_root_epoch_mismatch() {
    let lifecycle = scope(ExpensiveWorkKindV1::RegistrationPrepare);
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let envelope_a = RoleEncryptedEnvelopeV1::new(
        Role::SignerA,
        digest(0x01),
        digest(0x02),
        EncryptedPayloadV1::new(vec![0xa0]).expect("payload"),
    )
    .expect("envelope a");
    let assignment_a = RoleEnvelopeAssignmentV1::new(signer_a, envelope_a).expect("assignment a");
    let payload = router_to_signer_a_payload(lifecycle, assignment_a).expect("router-to-a payload");
    let router_request_digest = digest(0x44);
    let plaintext = signer_input_plaintext(&payload, router_request_digest, root_epoch());
    let other_epoch = RootShareEpoch::new("epoch-2").expect("other epoch");

    let err = validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        router_request_digest,
        &other_epoch,
    )
    .expect_err("root epoch mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn ab_peer_message_payload_requires_cross_signer_direction() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let transcript_digest = digest(0x09);
    let payload = CanonicalWireBytesV1::new(vec![0xab]).expect("payload");
    let authentication = peer_authentication(&signer_a, &signer_b, transcript_digest, &payload);

    let message = AbPeerMessagePayloadV1::new(
        signer_a.clone(),
        signer_b.clone(),
        transcript_digest,
        payload.clone(),
        authentication,
    )
    .expect("peer message");
    assert_eq!(message.from.role, Role::SignerA);

    let other_a = SignerIdentityV1::new(Role::SignerA, "signer-a2", "epoch-a")
        .expect("second signer a identity");
    let err = AbPeerMessagePayloadV1::new(
        signer_a,
        other_a,
        transcript_digest,
        payload.clone(),
        peer_authentication(&signer_b, &signer_b, transcript_digest, &payload),
    )
    .expect_err("same-role peer message must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn ab_peer_message_payload_binds_authentication_digest() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let transcript_digest = digest(0x09);
    let payload = CanonicalWireBytesV1::new(vec![0xab]).expect("payload");
    let wrong_auth = AbPeerMessageAuthenticationV1::new(
        AbPeerMessageSignatureSchemeV1::Ed25519V1,
        digest(0xff),
        CanonicalWireBytesV1::new(vec![0xed, 0x19]).expect("signature"),
    )
    .expect("peer authentication");

    let err =
        AbPeerMessagePayloadV1::new(signer_a, signer_b, transcript_digest, payload, wrong_auth)
            .expect_err("wrong authentication digest must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ab_peer_message_ed25519_signature_verifies() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let (message, verifying_key) = signed_peer_message(&signing_key);

    verify_ab_peer_message_ed25519_signature_v1(&message, &verifying_key)
        .expect("peer signature should verify");
}

#[test]
fn ab_peer_message_ed25519_signature_rejects_wrong_key() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let wrong_signing_key = SigningKey::from_bytes(&[8u8; 32]);
    let (message, _) = signed_peer_message(&signing_key);
    let wrong_key = AbPeerMessageVerifyingKeyV1::new(
        message.from.clone(),
        wrong_signing_key.verifying_key().to_bytes(),
    )
    .expect("wrong peer verifying key");

    let err = verify_ab_peer_message_ed25519_signature_v1(&message, &wrong_key)
        .expect_err("wrong peer key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn ab_derivation_proof_batch_payload_round_trips_and_matches_peer_envelope() {
    let batch = signer_a_mpc_batch();
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let payload = AbDerivationProofBatchPayloadV1::new(
        signer_a,
        signer_b,
        batch.transcript_digest,
        batch.root_share_epoch,
        batch.proof_bundles,
    )
    .expect("proof batch payload");

    let encoded = encode_ab_derivation_proof_batch_payload_v1(&payload);
    let decoded =
        decode_ab_derivation_proof_batch_payload_v1(&encoded).expect("decoded proof batch");
    let peer_payload = signed_proof_batch_peer_payload(decoded.clone());
    let from_peer = decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)
        .expect("peer proof batch");

    assert_eq!(decoded, payload);
    assert_eq!(from_peer, payload);
    assert_eq!(
        ab_derivation_proof_batch_payload_digest_v1(&payload),
        payload.digest()
    );
}

#[test]
fn ab_derivation_proof_batch_recipient_view_keeps_only_requested_output() {
    let (_, proof_batch_a, _) = router_scoped_ab_proof_batches();

    let client_view = ab_derivation_proof_batch_recipient_view_v1(
        proof_batch_a.clone(),
        OpenedShareKind::XClientBase,
        Role::Client,
        "client-1",
    )
    .expect("client proof-batch view");
    let relayer_view = ab_derivation_proof_batch_recipient_view_v1(
        proof_batch_a.clone(),
        OpenedShareKind::XRelayerBase,
        Role::Relayer,
        "relayer-a",
    )
    .expect("relayer proof-batch view");

    assert_eq!(client_view.proof_bundles.len(), 1);
    assert_eq!(relayer_view.proof_bundles.len(), 1);
    assert_eq!(
        client_view.proof_bundles[0]
            .signer_partial
            .binding
            .opened_share_kind,
        OpenedShareKind::XClientBase
    );
    assert_eq!(
        client_view.proof_bundles[0]
            .signer_partial
            .binding
            .recipient_role,
        Role::Client
    );
    assert_eq!(
        relayer_view.proof_bundles[0]
            .signer_partial
            .binding
            .opened_share_kind,
        OpenedShareKind::XRelayerBase
    );
    assert_eq!(
        relayer_view.proof_bundles[0]
            .signer_partial
            .binding
            .recipient_role,
        Role::Relayer
    );

    let err = ab_derivation_proof_batch_recipient_view_v1(
        proof_batch_a,
        OpenedShareKind::XClientBase,
        Role::Client,
        "other-client",
    )
    .expect_err("missing recipient identity must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn recipient_proof_bundle_payload_round_trips_and_enforces_scope() {
    let (router_payload, proof_batch_a, _) = router_scoped_ab_proof_batches();
    let lifecycle_id = router_payload.lifecycle().lifecycle_id.clone();

    let payload = recipient_proof_bundle_payload_from_ab_proof_batch_v1(
        &lifecycle_id,
        proof_batch_a,
        OpenedShareKind::XClientBase,
        Role::Client,
        "client-1",
    )
    .expect("recipient proof-bundle payload");
    let encoded = encode_recipient_proof_bundle_payload_v1(&payload);
    let decoded =
        decode_recipient_proof_bundle_payload_v1(&encoded).expect("decoded recipient payload");

    assert_eq!(decoded, payload);
    assert_eq!(payload.proof_batch.proof_bundles.len(), 1);
    assert_eq!(payload.recipient_role, Role::Client);
    assert_eq!(payload.opened_share_kind, OpenedShareKind::XClientBase);
    assert_eq!(payload.recipient_identity, "client-1");
    assert_eq!(
        recipient_proof_bundle_payload_digest_v1(&payload),
        payload.digest()
    );
}

#[test]
fn recipient_proof_bundle_payload_rejects_wrong_recipient_scope() {
    let (_, proof_batch_a, _) = router_scoped_ab_proof_batches();
    let relayer_view = ab_derivation_proof_batch_recipient_view_v1(
        proof_batch_a,
        OpenedShareKind::XRelayerBase,
        Role::Relayer,
        "relayer-a",
    )
    .expect("relayer proof-batch view");

    let err = RecipientProofBundlePayloadV1::new(
        "lifecycle-1",
        relayer_view.from.clone(),
        Role::Client,
        OpenedShareKind::XClientBase,
        "client-1",
        relayer_view.transcript_digest,
        relayer_view,
    )
    .expect_err("wrong recipient scope must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn recipient_proof_bundle_payload_builder_rejects_missing_binding() {
    let (_, proof_batch_a, _) = router_scoped_ab_proof_batches();

    let err = recipient_proof_bundle_payload_from_ab_proof_batch_v1(
        "lifecycle-1",
        proof_batch_a,
        OpenedShareKind::XClientBase,
        Role::Client,
        "other-client",
    )
    .expect_err("missing recipient binding must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn recipient_proof_bundle_ciphertext_round_trips_and_binds_payload() {
    let (router_payload, proof_batch_a, _) = router_scoped_ab_proof_batches();
    let payload = recipient_proof_bundle_payload_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch_a,
        OpenedShareKind::XClientBase,
        Role::Client,
        "client-1",
    )
    .expect("recipient proof-bundle payload");
    let mut encryptor = TestRecipientProofBundleEncryptor;
    let envelope = encrypt_recipient_proof_bundle_payload_v1(
        &payload,
        "local-client-recipient-key",
        &mut encryptor,
    )
    .expect("recipient proof-bundle encrypts");
    let encoded = encode_recipient_proof_bundle_ciphertext_v1(&envelope)
        .expect("recipient proof-bundle ciphertext encodes");
    let decoded = decode_recipient_proof_bundle_ciphertext_v1(&encoded)
        .expect("recipient proof-bundle ciphertext decodes");
    let plaintext =
        decode_recipient_proof_bundle_payload_v1(decoded.ciphertext_and_tag().as_bytes())
            .expect("deterministic proof-bundle plaintext decodes");

    assert_eq!(decoded, envelope);
    assert_eq!(plaintext, payload);
    assert_eq!(envelope.recipient_role, Role::Client);
    assert_eq!(envelope.opened_share_kind, OpenedShareKind::XClientBase);
    assert_eq!(envelope.recipient_identity, "client-1");
    assert_eq!(envelope.transcript_digest, payload.transcript_digest);
    assert_eq!(envelope.payload_digest, payload.digest());
    assert!(!encode_recipient_proof_bundle_ciphertext_aad_v1(&envelope)
        .expect("recipient proof-bundle AAD")
        .is_empty());
    assert_ne!(
        recipient_proof_bundle_ciphertext_aad_digest_v1(&envelope)
            .expect("recipient proof-bundle AAD digest"),
        digest(0)
    );
    verify_recipient_proof_bundle_ciphertext_payload_v1(&envelope, &payload)
        .expect("recipient proof-bundle envelope matches payload");
}

#[test]
fn recipient_proof_bundle_wire_message_carries_opaque_ciphertext() {
    let (router_payload, proof_batch_a, _) = router_scoped_ab_proof_batches();
    let mut encryptor = TestRecipientProofBundleEncryptor;
    let message = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch_a,
        OpenedShareKind::XClientBase,
        Role::Client,
        "client-1",
        "local-client-recipient-key",
        &mut encryptor,
    )
    .expect("recipient proof-bundle wire message");
    let envelope = decode_recipient_proof_bundle_ciphertext_v1(message.payload.as_bytes())
        .expect("recipient proof-bundle ciphertext");

    assert_eq!(message.kind, WireMessageKindV1::RecipientProofBundle);
    assert_eq!(
        message.transcript_digest,
        router_payload.transcript_digest()
    );
    assert_eq!(
        envelope.signer,
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity")
    );
    assert_eq!(envelope.recipient_role, Role::Client);
    assert_eq!(envelope.opened_share_kind, OpenedShareKind::XClientBase);
    assert_eq!(envelope.recipient_identity, "client-1");
}

#[test]
fn recipient_proof_bundle_ciphertext_rejects_payload_mismatch() {
    let (router_payload, proof_batch_a, _) = router_scoped_ab_proof_batches();
    let payload = recipient_proof_bundle_payload_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch_a,
        OpenedShareKind::XClientBase,
        Role::Client,
        "client-1",
    )
    .expect("recipient proof-bundle payload");
    let wrong_digest_envelope = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        payload.signer.clone(),
        Role::Client,
        OpenedShareKind::XClientBase,
        "client-1",
        "local-client-recipient-key",
        payload.transcript_digest,
        digest(0xee),
        [0x51; 12],
        EncryptedPayloadV1::new(payload.canonical_bytes()).expect("ciphertext bytes"),
    )
    .expect("wrong-digest proof-bundle envelope");

    let err = verify_recipient_proof_bundle_ciphertext_payload_v1(&wrong_digest_envelope, &payload)
        .expect_err("wrong payload digest must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn mpc_prf_recipient_scoped_combine_opens_only_requested_output() {
    let (payload, proof_batch_a, proof_batch_b) = router_scoped_ab_proof_batches();

    let client_output = combine_mpc_prf_recipient_output_from_ab_proof_batches_v1(
        &payload,
        proof_batch_a.clone(),
        proof_batch_b.clone(),
        OpenedShareKind::XClientBase,
        Role::Client,
        "client-1",
    )
    .expect("client recipient output");
    let relayer_output = combine_mpc_prf_recipient_output_from_ab_proof_batches_v1(
        &payload,
        proof_batch_a,
        proof_batch_b,
        OpenedShareKind::XRelayerBase,
        Role::Relayer,
        "relayer-a",
    )
    .expect("relayer recipient output");

    assert_eq!(
        client_output.opened_share_kind,
        OpenedShareKind::XClientBase
    );
    assert_eq!(client_output.recipient_role, Role::Client);
    assert_eq!(client_output.recipient_identity, "client-1");
    assert_eq!(
        relayer_output.opened_share_kind,
        OpenedShareKind::XRelayerBase
    );
    assert_eq!(relayer_output.recipient_role, Role::Relayer);
    assert_eq!(relayer_output.recipient_identity, "relayer-a");
    assert_ne!(
        client_output.output_material.as_bytes(),
        relayer_output.output_material.as_bytes()
    );
}

#[test]
fn mpc_prf_recipient_scoped_combine_rejects_missing_output_binding() {
    let (payload, proof_batch_a, proof_batch_b) = router_scoped_ab_proof_batches();

    let err = combine_mpc_prf_recipient_output_from_ab_proof_batches_v1(
        &payload,
        proof_batch_a,
        proof_batch_b,
        OpenedShareKind::XClientBase,
        Role::Client,
        "other-client",
    )
    .expect_err("missing recipient output binding must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ab_derivation_proof_batch_peer_payload_rejects_outer_transcript_mismatch() {
    let batch = signer_a_mpc_batch();
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let payload = AbDerivationProofBatchPayloadV1::new(
        signer_a.clone(),
        signer_b.clone(),
        batch.transcript_digest,
        batch.root_share_epoch,
        batch.proof_bundles,
    )
    .expect("proof batch payload");
    let inner = CanonicalWireBytesV1::new(payload.canonical_bytes()).expect("proof batch bytes");
    let outer_transcript = digest(0xee);
    let authentication = sign_ab_peer_message_ed25519_authentication_v1(
        SigningKey::from_bytes(&[0xa1; 32]).as_bytes(),
        &signer_a,
        &signer_b,
        outer_transcript,
        &inner,
    )
    .expect("peer authentication");
    let peer_payload =
        AbPeerMessagePayloadV1::new(signer_a, signer_b, outer_transcript, inner, authentication)
            .expect("peer payload");

    let err = decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)
        .expect_err("inner and outer transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ab_derivation_proof_batch_rejects_wrong_sender_binding() {
    let batch = signer_a_mpc_batch();
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let err = AbDerivationProofBatchPayloadV1::new(
        signer_b,
        signer_a,
        batch.transcript_digest,
        batch.root_share_epoch,
        batch.proof_bundles,
    )
    .expect_err("proof bundle sender mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn ab_derivation_proof_batch_signer_refuses_batch_sender_mismatch() {
    let batch = signer_a_mpc_batch();
    let signer_b =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b identity");
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");

    let err = sign_ab_derivation_proof_batch_peer_payload_v1(
        SigningKey::from_bytes(&[0xb1; 32]).as_bytes(),
        signer_b,
        signer_a,
        batch,
    )
    .expect_err("sender mismatch must fail before signing");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_response_payload_binds_output_transcripts() {
    let signer_a =
        SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a identity");
    let response = SignerResponsePayloadV1::new(
        "lifecycle-1",
        signer_a.clone(),
        digest(0x07),
        client_output(digest(0x07)),
        digest(0x08),
    )
    .expect("signer response");
    assert_eq!(response.signer, signer_a);

    let err = SignerResponsePayloadV1::new(
        "lifecycle-1",
        signer_a,
        digest(0x07),
        client_output(digest(0x99)),
        digest(0x08),
    )
    .expect_err("client output transcript mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn relayer_activation_payload_binds_output_transcript() {
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");
    let payload = RelayerActivationPayloadV1::new(
        "lifecycle-1",
        relayer,
        digest(0x07),
        relayer_output(digest(0x07)),
    )
    .expect("activation");
    assert_eq!(payload.lifecycle_id, "lifecycle-1");

    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");
    let err = RelayerActivationPayloadV1::new(
        "lifecycle-1",
        relayer,
        digest(0x07),
        relayer_output(digest(0x99)),
    )
    .expect_err("relayer output transcript mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[derive(Debug, Clone)]
struct DummyHost;

impl Clock for DummyHost {
    fn now_unix_ms(&self) -> u64 {
        1_000
    }
}

impl Csprng for DummyHost {
    fn fill_random(&mut self, out: &mut [u8]) -> RouterAbProtocolResult<()> {
        out.fill(0x42);
        Ok(())
    }
}

impl SignerKeyStore for DummyHost {
    fn signer_identity(&self, role: Role) -> RouterAbProtocolResult<String> {
        Ok(role.as_str().to_owned())
    }

    fn signer_verifying_key(
        &self,
        signer: &SignerIdentityV1,
    ) -> RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        AbPeerMessageVerifyingKeyV1::new(
            signer.clone(),
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        )
    }
}

impl SigningRootShareStore for DummyHost {
    fn has_root_share(&self, _role: Role, _epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool> {
        Ok(true)
    }
}

impl PeerTransport for DummyHost {
    fn send_peer_message(&self, message: WireMessageV1) -> RouterAbProtocolResult<WireMessageV1> {
        Ok(message)
    }
}

impl AuditSink for DummyHost {
    fn record_audit_event(&self, _event: AuditEventV1) -> RouterAbProtocolResult<()> {
        Ok(())
    }
}

#[test]
fn engines_are_host_injected() {
    let router = RouterEngine::new(DummyHost);
    let signer_a = SignerAEngine::new(DummyHost);
    let signer_b = SignerBEngine::new(DummyHost);
    let relayer = RelayerEngine::new(DummyHost);

    assert_eq!(router.host().now_unix_ms(), 1_000);
    assert_eq!(signer_a.host().now_unix_ms(), 1_000);
    assert_eq!(signer_b.host().now_unix_ms(), 1_000);
    assert_eq!(relayer.host().now_unix_ms(), 1_000);
}

#[test]
fn signer_engines_evaluate_role_specific_mpc_prf_batches() {
    let signer_a = SignerAEngine::new(DummyHost);
    let signer_b = SignerBEngine::new(DummyHost);
    let [share_a, share_b] = mpc_share_wires();

    let batch_a = signer_a
        .evaluate_mpc_prf_output_batch(
            MpcPrfThresholdSignerBatchInputV1 {
                signer_input: mpc_signer_input(Role::SignerA),
                signing_root_share_wire: share_a,
            },
            &mut seeded_rng(21),
        )
        .expect("signer A batch");
    let batch_b = signer_b
        .evaluate_mpc_prf_output_batch(
            MpcPrfThresholdSignerBatchInputV1 {
                signer_input: mpc_signer_input(Role::SignerB),
                signing_root_share_wire: share_b.clone(),
            },
            &mut seeded_rng(22),
        )
        .expect("signer B batch");

    assert_eq!(batch_a.signer_role, Role::SignerA);
    assert_eq!(batch_b.signer_role, Role::SignerB);
    assert_eq!(batch_a.proof_bundles.len(), 2);
    assert_eq!(batch_b.proof_bundles.len(), 2);

    let err = signer_a
        .evaluate_mpc_prf_output_batch(
            MpcPrfThresholdSignerBatchInputV1 {
                signer_input: mpc_signer_input(Role::SignerB),
                signing_root_share_wire: share_b,
            },
            &mut seeded_rng(23),
        )
        .expect_err("Signer A must reject Signer B batch input");

    assert_eq!(
        err.code(),
        RouterAbDerivationErrorCode::SignerIdentityMismatch
    );
}

#[test]
fn protocol_crate_has_no_platform_adapter_imports() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("protocol");
    let mut sources = Vec::new();
    collect_rs_files(&root, &mut sources);

    let forbidden = [
        "worker::",
        "cloudflare",
        "std::fs",
        "std::env",
        "std::net",
        "SystemTime",
        "thread_rng",
        "reqwest",
        "axum",
    ];

    for source in sources {
        let text = fs::read_to_string(&source).expect("read source");
        for pattern in forbidden {
            assert!(
                !text.contains(pattern),
                "{} contains forbidden platform pattern {}",
                source.display(),
                pattern
            );
        }
    }
}

fn collect_rs_files(path: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}
