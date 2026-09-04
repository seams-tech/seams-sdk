use core::fmt::Debug;
use std::collections::BTreeMap;

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoOperationV1, Ed25519YaoSessionIdV1,
    Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1,
    MpcMaterialActivationRefV1, RootShareEpoch, StableTenantDerivationContextV2,
};
use router_ab_ecdsa_derivation::shared::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20,
};
use router_ab_ed25519_yao::recipient::{
    client::{combine_client_activation_packages, combine_export_packages},
    signing_worker::combine_signing_worker_activation_packages,
};
use router_ab_ed25519_yao::relay::{
    derive_registration_receipt, verify_activation_continuity, ActivationPublicCommitments,
    DirectionalWireDecoder, DirectionalWireEncoder, RelayEvent, RelayInstruction, RelayStep,
    WireDirection, WireMessage, WireMessageKind,
};
use router_ab_ed25519_yao::{
    build_activation_deriver_a, build_activation_deriver_b, build_export_deriver_a,
    build_export_deriver_b, ActivationDeriverA, ActivationDeriverAContribution, ActivationDeriverB,
    ActivationDeriverBContribution, ExportDeriverA, ExportDeriverAContribution, ExportDeriverB,
    ExportDeriverBContribution,
};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1,
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientRootV1,
    Ed25519YaoDeriverAClientContributionV1, Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBDerivationRootV1, Ed25519YaoDeriverBServerContributionV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
use signer_core::near_ed25519_recovery::{
    build_near_ed25519_seed_export_artifact_v1, expand_ed25519_seed,
};
use signer_core::near_threshold_ed25519::{
    aggregate_signature, build_signing_package, client_round1_commit,
    client_round2_signature_share, key_package_from_signing_share_bytes,
    verifying_share_bytes_from_signing_share_bytes,
};
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
use threshold_prf::{
    apply_two_party_root_share_refresh, combine_verified_partials,
    complete_ed25519_deriver_a_target_v1, complete_ed25519_deriver_b_target_v1,
    evaluate_partial_with_dleq_proof, generate_two_party_root_share,
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1, PrfContext,
    PrfPurpose, RootShareRefreshCoefficient, SigningRootShare, SigningRootShareCommitment, SuiteId,
    ThresholdPolicy, TwoPartyDeriverRole, ValidatedThresholdSet,
};
use zeroize::{Zeroize, Zeroizing};

fn lifecycle(work_kind: ExpensiveWorkKindV1) -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        "local-lifecycle-1",
        work_kind,
        RootShareEpoch::new("epoch-1").expect("root epoch"),
        "account-1",
        "wallet-session-1",
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("lifecycle")
}

fn binding(
    operation: Ed25519YaoOperationV1,
    work_kind: ExpensiveWorkKindV1,
    session: [u8; 32],
) -> Ed25519YaoCeremonyBindingV1 {
    Ed25519YaoCeremonyBindingV1::new(
        lifecycle(work_kind),
        operation,
        Ed25519YaoSessionIdV1::new(session).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(decode_hex_32(
            "b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655",
        )),
        MpcMaterialActivationRefV1::new(
            "activation-1",
            "capability-1",
            "account-1",
            "key-1",
            "local-lifecycle-1",
            "signing-worker-1",
        )
        .expect("material activation"),
    )
    .expect("binding")
}

fn expect_continue<R, C>(step: RelayStep<R, C>) -> R {
    match step {
        RelayStep::Continue(role) => role,
        _ => panic!("expected continuation"),
    }
}

fn expect_send<R, C>(step: RelayStep<R, C>) -> (R, WireMessage) {
    match step {
        RelayStep::Send { role, message } => (role, message),
        _ => panic!("expected outbound message"),
    }
}

fn expect_complete<R, C>(step: RelayStep<R, C>) -> C {
    match step {
        RelayStep::Complete(completion) => completion,
        _ => panic!("expected completion"),
    }
}

fn route_message(
    message: WireMessage,
    encoder: &mut DirectionalWireEncoder,
    decoder: &mut DirectionalWireDecoder,
) -> WireMessage {
    let encoded = encoder.encode(message).expect("encode envelope");
    let mut offset = 0;
    while offset < encoded.len() {
        let end = core::cmp::min(offset + 19, encoded.len());
        let consumed = decoder.push(&encoded[offset..end]).expect("decode chunk");
        assert_ne!(consumed, 0);
        offset += consumed;
    }
    decoder
        .take_message()
        .expect("decode envelope")
        .expect("complete envelope")
}

fn receive_instruction(message: &WireMessage) -> RelayInstruction {
    RelayInstruction::Receive {
        kind: message.kind(),
        payload_bytes: message.as_bytes().len(),
    }
}

fn run_roles<A, B, AC, BC, E>(
    session: [u8; 32],
    mut a: A,
    mut b: B,
    handle_a: fn(A, RelayEvent) -> Result<RelayStep<A, AC>, E>,
    handle_b: fn(B, RelayEvent) -> Result<RelayStep<B, BC>, E>,
    instruction_a: fn(&A) -> Result<RelayInstruction, E>,
    instruction_b: fn(&B) -> Result<RelayInstruction, E>,
) -> (AC, BC)
where
    E: Debug,
{
    let mut a_to_b_encoder =
        DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session).expect("A encoder");
    let mut a_to_b_decoder =
        DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session).expect("B decoder");
    let mut b_to_a_encoder =
        DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session).expect("B encoder");
    let mut b_to_a_decoder =
        DirectionalWireDecoder::new(WireDirection::DeriverBToDeriverA, session).expect("A decoder");

    assert_eq!(
        instruction_b(&b).expect("B instruction"),
        RelayInstruction::Advance
    );
    let (next_b, offer) = expect_send(handle_b(b, RelayEvent::Advance).expect("B offer"));
    b = next_b;
    let offer = route_message(offer, &mut b_to_a_encoder, &mut b_to_a_decoder);
    assert_eq!(
        instruction_a(&a).expect("A receive offer"),
        receive_instruction(&offer)
    );
    a = expect_continue(handle_a(a, RelayEvent::Inbound(offer)).expect("A accepts offer"));

    let (next_a, choices) = expect_send(handle_a(a, RelayEvent::Advance).expect("A choices"));
    a = next_a;
    let choices = route_message(choices, &mut a_to_b_encoder, &mut a_to_b_decoder);
    b = expect_continue(handle_b(b, RelayEvent::Inbound(choices)).expect("B accepts choices"));

    let (next_a, direct) = expect_send(handle_a(a, RelayEvent::Advance).expect("A direct"));
    a = next_a;
    let direct = route_message(direct, &mut a_to_b_encoder, &mut a_to_b_decoder);
    let (next_b, extension) =
        expect_send(handle_b(b, RelayEvent::Inbound(direct)).expect("B extension"));
    b = next_b;
    let extension = route_message(extension, &mut b_to_a_encoder, &mut b_to_a_decoder);
    a = expect_continue(handle_a(a, RelayEvent::Inbound(extension)).expect("A accepts extension"));

    let (next_a, masked) = expect_send(handle_a(a, RelayEvent::Advance).expect("A masked"));
    a = next_a;
    let masked = route_message(masked, &mut a_to_b_encoder, &mut a_to_b_decoder);
    b = expect_continue(handle_b(b, RelayEvent::Inbound(masked)).expect("B accepts masked"));

    let (next_a, manifest) = expect_send(handle_a(a, RelayEvent::Advance).expect("A manifest"));
    a = next_a;
    let manifest = route_message(manifest, &mut a_to_b_encoder, &mut a_to_b_decoder);
    b = expect_continue(handle_b(b, RelayEvent::Inbound(manifest)).expect("B accepts manifest"));

    let translation = loop {
        let (next_a, message) =
            expect_send(handle_a(a, RelayEvent::Advance).expect("A stream step"));
        a = next_a;
        match message.kind() {
            WireMessageKind::TableFrame => {
                let frame = route_message(message, &mut a_to_b_encoder, &mut a_to_b_decoder);
                b = expect_continue(
                    handle_b(b, RelayEvent::Inbound(frame)).expect("B accepts frame"),
                );
            }
            WireMessageKind::OutputTranslation => break message,
            kind => panic!("unexpected stream message: {kind:?}"),
        }
    };

    let translation = route_message(translation, &mut a_to_b_encoder, &mut a_to_b_decoder);
    b = expect_continue(
        handle_b(b, RelayEvent::Inbound(translation)).expect("B accepts translation"),
    );

    let a_local_eof = a_to_b_encoder
        .finish_after_transport_close()
        .expect("A local EOF");
    a = expect_continue(
        handle_a(a, RelayEvent::LocalDirectionalEof(a_local_eof)).expect("A records EOF"),
    );
    let b_peer_eof = a_to_b_decoder
        .finish_at_transport_eof()
        .expect("B peer EOF");
    b = expect_continue(
        handle_b(b, RelayEvent::InboundDirectionalEof(b_peer_eof)).expect("B records peer EOF"),
    );

    let (next_b, returned) =
        expect_send(handle_b(b, RelayEvent::Advance).expect("B returned labels"));
    b = next_b;
    let returned = route_message(returned, &mut b_to_a_encoder, &mut b_to_a_decoder);
    a = expect_continue(
        handle_a(a, RelayEvent::Inbound(returned)).expect("A accepts returned labels"),
    );

    let b_local_eof = b_to_a_encoder
        .finish_after_transport_close()
        .expect("B local EOF");
    let b_completion = expect_complete(
        handle_b(b, RelayEvent::LocalDirectionalEof(b_local_eof)).expect("B completes"),
    );
    let a_peer_eof = b_to_a_decoder
        .finish_at_transport_eof()
        .expect("A peer EOF");
    let a_completion = expect_complete(
        handle_a(a, RelayEvent::InboundDirectionalEof(a_peer_eof)).expect("A completes"),
    );
    (a_completion, b_completion)
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];
    assert_eq!(value.len(), 64);
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).expect("hex") as u8;
        let low = (pair[1] as char).to_digit(16).expect("hex") as u8;
        output[index] = (high << 4) | low;
    }
    output
}

fn derive_vector_contributions() -> (
    Ed25519YaoStableKeyDerivationContextV1,
    Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1,
    Ed25519YaoDeriverBServerContributionV1,
) {
    let application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-fixture").expect("wallet"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_fixture")
            .expect("signing key"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project-fixture:env-fixture")
            .expect("signing root"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1).expect("slot"),
    );
    let context = Ed25519YaoStableKeyDerivationContextV1::new(application.digest(), 1, 2)
        .expect("stable context");
    let client_root = Ed25519YaoClientRootV1::from_secret_bytes([0x11; 32]);
    let deriver_a_root = Ed25519YaoDeriverADerivationRootV1::from_secret_bytes([0x22; 32]);
    let deriver_b_root = Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes([0x33; 32]);
    let (client_a, client_b) = derive_ed25519_yao_client_contributions_v1(&client_root, &context)
        .expect("client KDF")
        .into_parts();
    let server_a = derive_ed25519_yao_deriver_a_server_contribution_v1(&deriver_a_root, &context)
        .expect("A server KDF");
    let server_b = derive_ed25519_yao_deriver_b_server_contribution_v1(&deriver_b_root, &context)
        .expect("B server KDF");
    (context, client_a, client_b, server_a, server_b)
}

#[test]
fn real_role_inputs_complete_activation_and_export() {
    let (context, client_a, client_b, server_a, server_b) = derive_vector_contributions();
    let expected_public_key =
        decode_hex_32("ccd255d0b88721771947038f1a7c29b49eee3902d6aa732e5e448251537bf077");
    let expected_seed =
        decode_hex_32("c6db6124f7fea8e20ec7ce7472d75210d647062c04d53d9311b3dab6d34bdfdc");
    let activation_session = [0x51; 32];
    let activation_binding = binding(
        Ed25519YaoOperationV1::Registration,
        ExpensiveWorkKindV1::RegistrationPrepare,
        activation_session,
    );
    let activation_a = build_activation_deriver_a(
        &activation_binding,
        ActivationDeriverAContribution::base(&context, client_a, server_a),
    )
    .expect("activation A");
    let activation_b = build_activation_deriver_b(
        &activation_binding,
        ActivationDeriverBContribution::base(&context, client_b, server_b),
    )
    .expect("activation B");
    let (activation_a, activation_b) = run_roles(
        activation_session,
        activation_a,
        activation_b,
        ActivationDeriverA::handle,
        ActivationDeriverB::handle,
        ActivationDeriverA::instruction,
        ActivationDeriverB::instruction,
    );
    assert_eq!(
        activation_a.final_transcript(),
        activation_b.final_transcript()
    );
    assert_eq!(activation_a.stream_metrics().frame_count(), 17);
    let commitments = ActivationPublicCommitments::new(
        activation_a.client_commitment(),
        activation_b.client_commitment(),
        activation_a.signing_worker_commitment(),
        activation_b.signing_worker_commitment(),
    );
    let receipt = derive_registration_receipt(commitments).expect("registration receipt");
    assert_eq!(receipt.registered_public_key(), &expected_public_key);
    assert_eq!(
        verify_activation_continuity(*receipt.registered_public_key(), commitments)
            .expect("activation continuity"),
        receipt
    );
    let mut wrong_public_key = *receipt.registered_public_key();
    wrong_public_key[0] ^= 1;
    assert!(verify_activation_continuity(wrong_public_key, commitments).is_err());
    let transcript = activation_a.final_transcript();
    let mut client_scalar = Zeroizing::new(
        combine_client_activation_packages(
            activation_session,
            transcript,
            activation_a.client_package(),
            activation_b.client_package(),
        )
        .expect("Client package combination")
        .into_bytes(),
    );
    let mut signing_worker_scalar = Zeroizing::new(
        combine_signing_worker_activation_packages(
            activation_session,
            transcript,
            activation_a.signing_worker_package(),
            activation_b.signing_worker_package(),
        )
        .expect("SigningWorker package combination")
        .into_bytes(),
    );
    let derived_public_key = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &verifying_share_bytes_from_signing_share_bytes(&client_scalar),
        &verifying_share_bytes_from_signing_share_bytes(&signing_worker_scalar),
        1,
        2,
    )
    .expect("group public key");
    assert_eq!(&derived_public_key, receipt.registered_public_key());

    let client_id = frost_ed25519::Identifier::try_from(1_u16).expect("Client identifier");
    let signing_worker_id =
        frost_ed25519::Identifier::try_from(2_u16).expect("SigningWorker identifier");
    let mut client_key_package = key_package_from_signing_share_bytes(
        &client_scalar,
        receipt.registered_public_key(),
        client_id,
    )
    .expect("Client key package");
    let mut signing_worker_key_package = key_package_from_signing_share_bytes(
        &signing_worker_scalar,
        receipt.registered_public_key(),
        signing_worker_id,
    )
    .expect("SigningWorker key package");
    client_scalar.zeroize();
    signing_worker_scalar.zeroize();

    let mut client_round1 = client_round1_commit(&client_key_package).expect("Client round 1");
    let mut signing_worker_round1 =
        client_round1_commit(&signing_worker_key_package).expect("SigningWorker round 1");
    let admitted_signing_digest = [0x42_u8; 32];
    let signing_package = build_signing_package(
        &admitted_signing_digest,
        BTreeMap::from([
            (client_id, client_round1.commitments),
            (signing_worker_id, signing_worker_round1.commitments),
        ]),
    );
    let client_signature_share =
        client_round2_signature_share(&signing_package, &client_round1.nonces, &client_key_package)
            .expect("Client round 2");
    let signing_worker_signature_share = client_round2_signature_share(
        &signing_package,
        &signing_worker_round1.nonces,
        &signing_worker_key_package,
    )
    .expect("SigningWorker round 2");
    client_round1.nonces.zeroize();
    signing_worker_round1.nonces.zeroize();
    let threshold_signature = aggregate_signature(
        &signing_package,
        *client_key_package.verifying_key(),
        BTreeMap::from([
            (client_id, *client_key_package.verifying_share()),
            (
                signing_worker_id,
                *signing_worker_key_package.verifying_share(),
            ),
        ]),
        BTreeMap::from([
            (client_id, client_signature_share),
            (signing_worker_id, signing_worker_signature_share),
        ]),
    )
    .expect("aggregate threshold signature");
    let verifying_key = VerifyingKey::from_bytes(receipt.registered_public_key())
        .expect("registered verifying key");
    verifying_key
        .verify(
            &admitted_signing_digest,
            &Signature::from_bytes(&threshold_signature),
        )
        .expect("standard verification of threshold signature");
    client_key_package.zeroize();
    signing_worker_key_package.zeroize();

    let export_session = [0x61; 32];
    let export_binding = binding(
        Ed25519YaoOperationV1::Export,
        ExpensiveWorkKindV1::KeyExport,
        export_session,
    );
    let (context, client_a, client_b, server_a, server_b) = derive_vector_contributions();
    let export_a = build_export_deriver_a(
        &export_binding,
        ExportDeriverAContribution::from_derived(&context, client_a, server_a),
    )
    .expect("export A");
    let export_b = build_export_deriver_b(
        &export_binding,
        ExportDeriverBContribution::from_derived(&context, client_b, server_b),
    )
    .expect("export B");
    let (export_a, export_b) = run_roles(
        export_session,
        export_a,
        export_b,
        ExportDeriverA::handle,
        ExportDeriverB::handle,
        ExportDeriverA::instruction,
        ExportDeriverB::instruction,
    );
    assert_eq!(export_a.final_transcript(), export_b.final_transcript());
    assert_eq!(export_a.stream_metrics().frame_count(), 1);
    let mut exported_seed = Zeroizing::new(
        combine_export_packages(
            export_session,
            export_a.final_transcript(),
            export_a.export_package(),
            export_b.export_package(),
        )
        .expect("export package combination")
        .into_bytes(),
    );
    assert_eq!(*exported_seed, expected_seed);
    let expanded = expand_ed25519_seed(*exported_seed);
    assert_eq!(expanded.public_key_bytes, expected_public_key);
    let near_public_key = format!(
        "ed25519:{}",
        bs58::encode(expected_public_key).into_string()
    );
    let export_artifact =
        build_near_ed25519_seed_export_artifact_v1(*exported_seed, &near_public_key)
            .expect("seed export artifact");
    assert_eq!(export_artifact.public_key, near_public_key);

    let signing_key = SigningKey::from_bytes(&exported_seed);
    assert_eq!(signing_key.verifying_key().to_bytes(), expected_public_key);
    let export_proof_message = b"seams Phase 9C exact Ed25519 seed export";
    let standard_signature = signing_key.sign(export_proof_message);
    signing_key
        .verifying_key()
        .verify(export_proof_message, &standard_signature)
        .expect("standard signature from exported seed");
    exported_seed.zeroize();
}

#[test]
fn builders_reject_wrong_family_and_cross_lifecycle_activation_shapes() {
    let export_binding = binding(
        Ed25519YaoOperationV1::Export,
        ExpensiveWorkKindV1::KeyExport,
        [0x71; 32],
    );
    let (context, client_a, _, server_a, _) = derive_vector_contributions();
    assert!(build_activation_deriver_a(
        &export_binding,
        ActivationDeriverAContribution::base(&context, client_a, server_a),
    )
    .is_err());

    let refresh_binding = binding(
        Ed25519YaoOperationV1::Refresh,
        ExpensiveWorkKindV1::ServerShareRefresh,
        [0x72; 32],
    );
    let (context, _, client_b, _, server_b) = derive_vector_contributions();
    assert!(build_activation_deriver_b(
        &refresh_binding,
        ActivationDeriverBContribution::base(&context, client_b, server_b),
    )
    .is_err());

    let (context, _, client_b, _, server_b) = derive_vector_contributions();
    assert!(build_activation_deriver_b(
        &refresh_binding,
        ActivationDeriverBContribution::refresh(&context, client_b, server_b),
    )
    .is_ok());
}

fn preservation_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn refresh_preservation_share(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> SigningRootShare {
    let contribution_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(recipient))
        .expect("Deriver A refresh contribution verifies");
    let contribution_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))
        .expect("Deriver B refresh contribution verifies");
    apply_two_party_root_share_refresh(current, contribution_a, contribution_b)
        .expect("tenant root share refresh succeeds")
}

fn evaluate_ecdsa_preservation_output(
    shares: &[SigningRootShare],
    stable_context: &StableTenantDerivationContextV2,
    purpose: PrfPurpose,
    proof_seed: u8,
) -> [u8; 32] {
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        stable_context.canonical_context_bytes(),
    );
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("fixed 2-of-2 policy");
    let mut proof_rng = preservation_rng(proof_seed);
    let bundles = ValidatedThresholdSet::from_proof_bundles(
        policy,
        shares
            .iter()
            .map(|share| {
                evaluate_partial_with_dleq_proof(share, &context, &mut proof_rng)
                    .expect("ECDSA partial proof evaluates")
            })
            .collect(),
    )
    .expect("ECDSA proof set validates");
    combine_verified_partials(&bundles, &context)
        .expect("ECDSA partials combine")
        .into_bytes()
}

fn ecdsa_preservation_identity(
    shares: &[SigningRootShare],
    stable_context: &StableTenantDerivationContextV2,
    proof_seed: u8,
) -> (Vec<u8>, Vec<u8>) {
    let client_base = evaluate_ecdsa_preservation_output(
        shares,
        stable_context,
        PrfPurpose::RouterAbXClientBaseV1,
        proof_seed,
    );
    let server_base = evaluate_ecdsa_preservation_output(
        shares,
        stable_context,
        PrfPurpose::RouterAbXServerBaseV1,
        proof_seed.wrapping_add(1),
    );
    let client_public_key =
        secp256k1_private_key_32_to_public_key_33(&client_base).expect("ECDSA client public key");
    let server_public_key =
        secp256k1_private_key_32_to_public_key_33(&server_base).expect("ECDSA server public key");
    let threshold_public_key = add_secp256k1_public_keys_33(&client_public_key, &server_public_key)
        .expect("ECDSA threshold public key");
    let address = secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key)
        .expect("ECDSA Ethereum address");
    (threshold_public_key, address)
}

fn ed25519_preservation_roots(
    shares: &[SigningRootShare],
    stable_context_bytes: &[u8],
    proof_seed: u8,
) -> ([u8; 32], [u8; 32]) {
    let deriver_a_commitment = SigningRootShareCommitment::from_share(&shares[0]);
    let deriver_b_commitment = SigningRootShareCommitment::from_share(&shares[1]);
    let mut proof_rng = preservation_rng(proof_seed);
    let (prepared_a, proof_a_to_b) = prepare_ed25519_deriver_a_target_v1(
        &shares[0],
        deriver_b_commitment,
        stable_context_bytes,
        &mut proof_rng,
    )
    .expect("Ed25519 Deriver A target prepares");
    let (prepared_b, proof_b_to_a) = prepare_ed25519_deriver_b_target_v1(
        &shares[1],
        deriver_a_commitment,
        stable_context_bytes,
        &mut proof_rng,
    )
    .expect("Ed25519 Deriver B target prepares");
    let root_a = complete_ed25519_deriver_a_target_v1(prepared_a, &proof_b_to_a)
        .expect("Ed25519 Deriver A target completes")
        .into_secret_bytes();
    let root_b = complete_ed25519_deriver_b_target_v1(prepared_b, &proof_a_to_b)
        .expect("Ed25519 Deriver B target completes")
        .into_secret_bytes();
    (*root_a, *root_b)
}

fn ed25519_preservation_public_key(
    context: &Ed25519YaoStableKeyDerivationContextV1,
    client_a: Ed25519YaoDeriverAClientContributionV1,
    client_b: Ed25519YaoDeriverBClientContributionV1,
    root_a: [u8; 32],
    root_b: [u8; 32],
) -> [u8; 32] {
    let server_a = derive_ed25519_yao_deriver_a_server_contribution_v1(
        &Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(root_a),
        context,
    )
    .expect("Ed25519 Deriver A server KDF");
    let server_b = derive_ed25519_yao_deriver_b_server_contribution_v1(
        &Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(root_b),
        context,
    )
    .expect("Ed25519 Deriver B server KDF");
    let activation_session = [0x51; 32];
    let activation_binding = binding(
        Ed25519YaoOperationV1::Registration,
        ExpensiveWorkKindV1::RegistrationPrepare,
        activation_session,
    );
    let activation_a = build_activation_deriver_a(
        &activation_binding,
        ActivationDeriverAContribution::base(context, client_a, server_a),
    )
    .expect("Ed25519 activation A");
    let activation_b = build_activation_deriver_b(
        &activation_binding,
        ActivationDeriverBContribution::base(context, client_b, server_b),
    )
    .expect("Ed25519 activation B");
    let (activation_a, activation_b) = run_roles(
        activation_session,
        activation_a,
        activation_b,
        ActivationDeriverA::handle,
        ActivationDeriverB::handle,
        ActivationDeriverA::instruction,
        ActivationDeriverB::instruction,
    );
    let commitments = ActivationPublicCommitments::new(
        activation_a.client_commitment(),
        activation_b.client_commitment(),
        activation_a.signing_worker_commitment(),
        activation_b.signing_worker_commitment(),
    );
    *derive_registration_receipt(commitments)
        .expect("Ed25519 registration receipt")
        .registered_public_key()
}

#[test]
fn tenant_root_resharing_preserves_ecdsa_and_ed25519_public_keys() {
    let initial = vec![
        generate_two_party_root_share(TwoPartyDeriverRole::DeriverA, &mut preservation_rng(1)),
        generate_two_party_root_share(TwoPartyDeriverRole::DeriverB, &mut preservation_rng(2)),
    ];
    let coefficient_a = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA,
        Scalar::from(17_u64).to_bytes(),
    )
    .expect("Deriver A refresh coefficient");
    let coefficient_b = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB,
        Scalar::from(29_u64).to_bytes(),
    )
    .expect("Deriver B refresh coefficient");
    let refreshed = vec![
        refresh_preservation_share(
            &initial[0],
            TwoPartyDeriverRole::DeriverA,
            &coefficient_a,
            &coefficient_b,
        ),
        refresh_preservation_share(
            &initial[1],
            TwoPartyDeriverRole::DeriverB,
            &coefficient_a,
            &coefficient_b,
        ),
    ];
    assert_ne!(initial[0].to_bytes(), refreshed[0].to_bytes());
    assert_ne!(initial[1].to_bytes(), refreshed[1].to_bytes());

    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let before_ecdsa = ecdsa_preservation_identity(&initial, &stable_context, 10);
    let after_ecdsa = ecdsa_preservation_identity(&refreshed, &stable_context, 20);
    assert_eq!(before_ecdsa, after_ecdsa);

    let (context_before, client_a_before, client_b_before, _, _) = derive_vector_contributions();
    let (context_after, client_a_after, client_b_after, _, _) = derive_vector_contributions();
    let context_bytes = context_before.encode();
    let (root_a_before, root_b_before) = ed25519_preservation_roots(&initial, &context_bytes, 30);
    let (root_a_after, root_b_after) =
        ed25519_preservation_roots(&refreshed, &context_after.encode(), 40);
    assert_eq!(root_a_before, root_a_after);
    assert_eq!(root_b_before, root_b_after);
    let before_ed25519 = ed25519_preservation_public_key(
        &context_before,
        client_a_before,
        client_b_before,
        root_a_before,
        root_b_before,
    );
    let after_ed25519 = ed25519_preservation_public_key(
        &context_after,
        client_a_after,
        client_b_after,
        root_a_after,
        root_b_after,
    );
    assert_eq!(before_ed25519, after_ed25519);
}
