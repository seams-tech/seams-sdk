use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoOperationV1,
    Ed25519YaoPackageKindV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
    Ed25519YaoStateEpochV1, ExpensiveWorkKindV1, LifecycleScopeV1, MpcMaterialActivationRefV1,
    RootShareEpoch, RouterAbEd25519YaoActivationAdmissionReceiptV1,
    RouterAbEd25519YaoActivationKeysetV1, RouterAbEd25519YaoActivationPublicReceiptV1,
    RouterAbEd25519YaoActivationResultV1, RouterAbEd25519YaoApplicationBindingFactsV1,
};
use router_ab_dev::{
    build_local_activation_deriver_a_v1, build_local_activation_deriver_b_v1,
    generate_local_ed25519_yao_recipient_key_pair_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1, seal_local_ed25519_yao_package_v1,
    LocalDeriverAWorkerConfigV1, LocalDeriverBWorkerConfigV1,
};
use router_ab_ed25519_yao::{
    relay::{
        derive_registration_receipt, ActivationPublicCommitments, DirectionalWireDecoder,
        DirectionalWireEncoder, RelayEvent, RelayStep, WireDirection, WireMessage, WireMessageKind,
    },
    stable_key_derivation_context_v1, ActivationDeriverA, ActivationDeriverB,
};
use router_ab_ed25519_yao_client::{
    client_application_binding_digest_v1, complete_client_activation_v1,
    import_activated_client_material_v1, import_activated_client_under_custody_seed_v1,
    prepare_client_registration_with_root_v1, seal_activated_client_under_custody_seed_v1,
    ActivatedClientV1, ClientActivationEntropyV1, ClientActivationError, ClientActivationStateV1,
    LocalMaterialError, LocalMaterialSealDomainV1,
};
use signer_core::ed25519_yao_derivation::Ed25519YaoClientDerivationRootV1;
use signer_core::wallet_seed_derivation::derive_ed25519_yao_client_root_from_seed_v1;

#[test]
fn client_activation_entropy_rejects_zero_and_reused_seeds() {
    assert_eq!(
        ClientActivationEntropyV1::new([0; 32], [0x72; 32], [0x73; 32]).expect_err("zero entropy"),
        ClientActivationError::InvalidEntropy
    );
    assert_eq!(
        ClientActivationEntropyV1::new([0x71; 32], [0x71; 32], [0x73; 32])
            .expect_err("reused entropy"),
        ClientActivationError::InvalidEntropy
    );
}

#[derive(Clone, Copy)]
struct ActivationEntropyBytes {
    recipient_key_material: [u8; 32],
    deriver_a_seal_seed: [u8; 32],
    deriver_b_seal_seed: [u8; 32],
}

struct SeedRootActivationCase {
    /// Registration from a Client root the caller derived from the wallet
    /// custody seed, which is how Refactor 100 registers.
    session_byte: u8,
    wallet_custody_seed: [u8; 32],
    entropy: ActivationEntropyBytes,
}

struct ClientActivationCircuitResult {
    state: ClientActivationStateV1,
    result: RouterAbEd25519YaoActivationResultV1,
}

fn activation_entropy(first_byte: u8) -> ActivationEntropyBytes {
    ActivationEntropyBytes {
        recipient_key_material: [first_byte; 32],
        deriver_a_seal_seed: [first_byte + 1; 32],
        deriver_b_seal_seed: [first_byte + 2; 32],
    }
}

fn prepare_client_activation(
    case: &SeedRootActivationCase,
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> router_ab_ed25519_yao_client::PreparedClientActivationV1 {
    let entropy = case.entropy;
    let entropy = ClientActivationEntropyV1::new(
        entropy.recipient_key_material,
        entropy.deriver_a_seal_seed,
        entropy.deriver_b_seal_seed,
    )
    .expect("activation entropy");
    let digest = client_application_binding_digest_v1(application, participant_ids)
        .expect("application binding digest");
    let root = derive_ed25519_yao_client_root_from_seed_v1(&case.wallet_custody_seed, &digest)
        .expect("seed-derived Client root");
    prepare_client_registration_with_root_v1(
        admission,
        application,
        participant_ids,
        Ed25519YaoClientDerivationRootV1::from_secret_bytes(*root),
        entropy,
    )
    .expect("prepare seed-root registration")
}

fn run_client_activation(case: SeedRootActivationCase) -> ClientActivationCircuitResult {
    let application = application();
    let participant_ids = [1, 2];
    let context = stable_key_derivation_context_v1(&application, participant_ids)
        .expect("stable derivation context");
    let material_activation = material_activation(case.session_byte);
    let binding = Ed25519YaoCeremonyBindingV1::new(
        lifecycle(ExpensiveWorkKindV1::RegistrationPrepare, case.session_byte),
        Ed25519YaoOperationV1::Registration,
        Ed25519YaoSessionIdV1::new([case.session_byte; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(context.binding_digest()),
        material_activation.clone(),
    )
    .expect("binding");
    let deriver_a_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Deriver A recipient");
    let deriver_b_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Deriver B recipient");
    let signing_worker_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("SigningWorker recipient");
    let keyset = RouterAbEd25519YaoActivationKeysetV1::new(
        deriver_a_recipient.public_key,
        deriver_b_recipient.public_key,
        signing_worker_recipient.public_key,
    )
    .expect("activation keyset");
    let admission = RouterAbEd25519YaoActivationAdmissionReceiptV1::new(binding.clone(), keyset)
        .expect("admission");
    let recipient_key_material = case.entropy.recipient_key_material;
    let prepared = prepare_client_activation(&case, &admission, &application, participant_ids);
    let (execute, state) = prepared.into_parts();
    let request_a = open_local_ed25519_yao_activation_deriver_a_input_v1(
        execute.deriver_a_input(),
        &deriver_a_recipient.private_key,
    )
    .expect("open Deriver A input");
    let request_b = open_local_ed25519_yao_activation_deriver_b_input_v1(
        execute.deriver_b_input(),
        &deriver_b_recipient.private_key,
    )
    .expect("open Deriver B input");
    assert_eq!(
        request_a.binding.operation,
        Ed25519YaoOperationV1::Registration
    );
    assert_eq!(
        request_b.binding.operation,
        Ed25519YaoOperationV1::Registration
    );
    assert_eq!(request_a.recipients, request_b.recipients);
    assert_eq!(
        request_a.recipients.signing_worker_public_key,
        signing_worker_recipient.public_key
    );

    let (_, role_a) = build_local_activation_deriver_a_v1(&deriver_a_config(), request_a)
        .expect("build Deriver A");
    let (_, role_b) = build_local_activation_deriver_b_v1(&deriver_b_config(), request_b)
        .expect("build Deriver B");
    let (completion_a, completion_b) = run_roles(binding.session_id.into_bytes(), role_a, role_b);
    let transcript = completion_a.final_transcript();
    assert_eq!(transcript, completion_b.final_transcript());
    let commitments = ActivationPublicCommitments::new(
        completion_a.client_commitment(),
        completion_b.client_commitment(),
        completion_a.signing_worker_commitment(),
        completion_b.signing_worker_commitment(),
    );
    let receipt = derive_registration_receipt(commitments).expect("public activation receipt");
    let client_public_key = derive_client_public_key(recipient_key_material);
    let package_a = seal_client_package(
        router_ab_core::Ed25519YaoDeriverRoleV1::DeriverA,
        binding.session_id.into_bytes(),
        transcript,
        client_public_key,
        completion_a.client_package().into_bytes(),
    );
    let package_b = seal_client_package(
        router_ab_core::Ed25519YaoDeriverRoleV1::DeriverB,
        binding.session_id.into_bytes(),
        transcript,
        client_public_key,
        completion_b.client_package().into_bytes(),
    );
    let public_receipt = RouterAbEd25519YaoActivationPublicReceiptV1::new(
        transcript,
        *receipt.registered_public_key(),
        *receipt.joined_client_commitment(),
        *receipt.joined_signing_worker_commitment(),
        *receipt.joined_signing_worker_commitment(),
        Ed25519YaoStateEpochV1::new(1).expect("state epoch"),
        material_activation,
    )
    .expect("Router public receipt");
    let result =
        RouterAbEd25519YaoActivationResultV1::new(binding, package_a, package_b, public_receipt)
            .expect("Router result");
    ClientActivationCircuitResult { state, result }
}

fn derive_client_public_key(input_key_material: [u8; 32]) -> [u8; 32] {
    use hpke_ng::{DhKemX25519HkdfSha256, Kem};

    let (_, public_key) = DhKemX25519HkdfSha256::derive_key_pair(&input_key_material)
        .expect("Client recipient keypair");
    DhKemX25519HkdfSha256::pk_to_bytes(&public_key)
        .as_slice()
        .try_into()
        .expect("X25519 public key")
}

fn seal_client_package(
    deriver: router_ab_core::Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
    public_key: [u8; 32],
    plaintext: Vec<u8>,
) -> Ed25519YaoEncryptedPackageV1 {
    seal_local_ed25519_yao_package_v1(
        Ed25519YaoPackageKindV1::ActivationClient,
        deriver,
        session,
        transcript,
        public_key,
        &plaintext,
    )
    .expect("seal Client package")
}

fn application() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
    RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-client-e2e",
        "ed25519ks_client_e2e",
        "project-client:local",
        1,
    )
    .expect("application")
}

fn lifecycle(work_kind: ExpensiveWorkKindV1, session_byte: u8) -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        format!("client-e2e-lifecycle-{session_byte:02x}"),
        work_kind,
        RootShareEpoch::new("epoch-1").expect("root epoch"),
        "account-1",
        format!("wallet-session-{session_byte:02x}"),
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("lifecycle")
}

fn material_activation(session_byte: u8) -> MpcMaterialActivationRefV1 {
    MpcMaterialActivationRefV1::new(
        format!("client-e2e-material-{session_byte:02x}"),
        "near-ed25519-mpc-signing",
        "account-1",
        "ed25519ks_client_e2e",
        format!("client-e2e-lifecycle-{session_byte:02x}"),
        "signing-worker-1",
    )
    .expect("material activation")
}

fn deriver_a_config() -> LocalDeriverAWorkerConfigV1 {
    LocalDeriverAWorkerConfigV1 {
        deriver_a_url: "http://127.0.0.1:1".to_owned(),
        deriver_b_url: "http://127.0.0.1:2".to_owned(),
        envelope_hpke_private_key: "local-test".to_owned(),
        root_share_wire_secret: "local-test".to_owned(),
        ed25519_yao_derivation_root_hex: "22".repeat(32),
        peer_signing_key: "local-test".to_owned(),
        deriver_a_peer_verifying_key: "local-test".to_owned(),
        deriver_b_peer_verifying_key: "local-test".to_owned(),
        role_private_storage_path: "/tmp/local-test-a-root".to_owned(),
        sealed_root_shares_path: "/tmp/local-test-a-sealed".to_owned(),
    }
}

fn deriver_b_config() -> LocalDeriverBWorkerConfigV1 {
    LocalDeriverBWorkerConfigV1 {
        deriver_b_url: "http://127.0.0.1:2".to_owned(),
        deriver_a_url: "http://127.0.0.1:1".to_owned(),
        envelope_hpke_private_key: "local-test".to_owned(),
        root_share_wire_secret: "local-test".to_owned(),
        ed25519_yao_derivation_root_hex: "33".repeat(32),
        peer_signing_key: "local-test".to_owned(),
        deriver_a_peer_verifying_key: "local-test".to_owned(),
        deriver_b_peer_verifying_key: "local-test".to_owned(),
        role_private_storage_path: "/tmp/local-test-b-root".to_owned(),
        sealed_root_shares_path: "/tmp/local-test-b-sealed".to_owned(),
    }
}

fn run_roles(
    session: [u8; 32],
    mut role_a: ActivationDeriverA,
    mut role_b: ActivationDeriverB,
) -> (
    router_ab_ed25519_yao::relay::ActivationDeriverACompletion,
    router_ab_ed25519_yao::relay::ActivationDeriverBCompletion,
) {
    let mut a_to_b_encoder =
        DirectionalWireEncoder::new(WireDirection::DeriverAToDeriverB, session).expect("A encoder");
    let mut a_to_b_decoder =
        DirectionalWireDecoder::new(WireDirection::DeriverAToDeriverB, session).expect("B decoder");
    let mut b_to_a_encoder =
        DirectionalWireEncoder::new(WireDirection::DeriverBToDeriverA, session).expect("B encoder");
    let mut b_to_a_decoder =
        DirectionalWireDecoder::new(WireDirection::DeriverBToDeriverA, session).expect("A decoder");

    let (next_b, offer) = expect_send(role_b.handle(RelayEvent::Advance).expect("B offer"));
    role_b = next_b;
    let offer = route_message(offer, &mut b_to_a_encoder, &mut b_to_a_decoder);
    role_a = expect_continue(
        role_a
            .handle(RelayEvent::Inbound(offer))
            .expect("A accepts offer"),
    );
    let (next_a, choices) = expect_send(role_a.handle(RelayEvent::Advance).expect("A choices"));
    role_a = next_a;
    let choices = route_message(choices, &mut a_to_b_encoder, &mut a_to_b_decoder);
    role_b = expect_continue(
        role_b
            .handle(RelayEvent::Inbound(choices))
            .expect("B accepts choices"),
    );
    let (next_a, direct) = expect_send(role_a.handle(RelayEvent::Advance).expect("A direct"));
    role_a = next_a;
    let direct = route_message(direct, &mut a_to_b_encoder, &mut a_to_b_decoder);
    let (next_b, extension) = expect_send(
        role_b
            .handle(RelayEvent::Inbound(direct))
            .expect("B extension"),
    );
    role_b = next_b;
    let extension = route_message(extension, &mut b_to_a_encoder, &mut b_to_a_decoder);
    role_a = expect_continue(
        role_a
            .handle(RelayEvent::Inbound(extension))
            .expect("A accepts extension"),
    );
    let (next_a, masked) = expect_send(role_a.handle(RelayEvent::Advance).expect("A masked"));
    role_a = next_a;
    let masked = route_message(masked, &mut a_to_b_encoder, &mut a_to_b_decoder);
    role_b = expect_continue(
        role_b
            .handle(RelayEvent::Inbound(masked))
            .expect("B accepts masked"),
    );
    let (next_a, manifest) = expect_send(role_a.handle(RelayEvent::Advance).expect("A manifest"));
    role_a = next_a;
    let manifest = route_message(manifest, &mut a_to_b_encoder, &mut a_to_b_decoder);
    role_b = expect_continue(
        role_b
            .handle(RelayEvent::Inbound(manifest))
            .expect("B accepts manifest"),
    );
    let translation = loop {
        let (next_a, message) = expect_send(role_a.handle(RelayEvent::Advance).expect("A stream"));
        role_a = next_a;
        match message.kind() {
            WireMessageKind::TableFrame => {
                let frame = route_message(message, &mut a_to_b_encoder, &mut a_to_b_decoder);
                role_b = expect_continue(
                    role_b
                        .handle(RelayEvent::Inbound(frame))
                        .expect("B accepts frame"),
                );
            }
            WireMessageKind::OutputTranslation => break message,
            kind => panic!("unexpected stream message: {kind:?}"),
        }
    };
    let translation = route_message(translation, &mut a_to_b_encoder, &mut a_to_b_decoder);
    role_b = expect_continue(
        role_b
            .handle(RelayEvent::Inbound(translation))
            .expect("B accepts translation"),
    );
    role_a = expect_continue(
        role_a
            .handle(RelayEvent::LocalDirectionalEof(
                a_to_b_encoder
                    .finish_after_transport_close()
                    .expect("A local EOF"),
            ))
            .expect("A records EOF"),
    );
    role_b = expect_continue(
        role_b
            .handle(RelayEvent::InboundDirectionalEof(
                a_to_b_decoder
                    .finish_at_transport_eof()
                    .expect("B peer EOF"),
            ))
            .expect("B records EOF"),
    );
    let (next_b, returned) = expect_send(
        role_b
            .handle(RelayEvent::Advance)
            .expect("B returned labels"),
    );
    role_b = next_b;
    let returned = route_message(returned, &mut b_to_a_encoder, &mut b_to_a_decoder);
    role_a = expect_continue(
        role_a
            .handle(RelayEvent::Inbound(returned))
            .expect("A accepts returned labels"),
    );
    let completion_b = expect_complete(
        role_b
            .handle(RelayEvent::LocalDirectionalEof(
                b_to_a_encoder
                    .finish_after_transport_close()
                    .expect("B local EOF"),
            ))
            .expect("B completes"),
    );
    let completion_a = expect_complete(
        role_a
            .handle(RelayEvent::InboundDirectionalEof(
                b_to_a_decoder
                    .finish_at_transport_eof()
                    .expect("A peer EOF"),
            ))
            .expect("A completes"),
    );
    (completion_a, completion_b)
}

fn route_message(
    message: WireMessage,
    encoder: &mut DirectionalWireEncoder,
    decoder: &mut DirectionalWireDecoder,
) -> WireMessage {
    let encoded = encoder.encode(message).expect("encode envelope");
    decoder.push(&encoded).expect("decode envelope");
    decoder
        .take_message()
        .expect("decode message")
        .expect("complete message")
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

#[test]
fn seed_derived_registration_completes_the_real_a_b_circuit() {
    let activation = run_client_activation(SeedRootActivationCase {
        session_byte: 0x53,
        wallet_custody_seed: [0x22; 32],
        entropy: activation_entropy(0x73),
    });
    let receipt = activation.result.public_receipt().clone();
    let activated = complete_client_activation_v1(activation.state, &activation.result)
        .expect("Client activation");
    let scalar = Scalar::from_canonical_bytes(*activated.client_scalar_share())
        .into_option()
        .expect("canonical Client scalar");
    assert_eq!(
        (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes(),
        receipt.joined_client_commitment()
    );
    assert_eq!(
        activated.registered_public_key(),
        receipt.registered_public_key()
    );
    assert_eq!(activated.state_epoch(), 1);
}

#[test]
fn a_different_wallet_custody_seed_registers_a_different_key() {
    // The seed is the only secret input, so two seeds must not converge on one
    // registered public key.
    let first = run_client_activation(SeedRootActivationCase {
        session_byte: 0x54,
        wallet_custody_seed: [0x22; 32],
        entropy: activation_entropy(0x74),
    });
    let second = run_client_activation(SeedRootActivationCase {
        session_byte: 0x54,
        wallet_custody_seed: [0x23; 32],
        entropy: activation_entropy(0x74),
    });
    assert_ne!(
        first.result.public_receipt().registered_public_key(),
        second.result.public_receipt().registered_public_key()
    );
}

/// Refactor 100. The same-device continuity cache, sealed under the wallet
/// custody seed rather than a factor.
///
/// The point of the seed domain is that the record stops belonging to whichever
/// factor happened to register. These run against a real activated Client from
/// the A/B circuit above, because a cache that round-trips synthetic bytes
/// proves nothing about whether the material it returns can actually sign.
const CACHE_BINDING: &[u8] = b"wallet:alice.testnet|key:near-ed25519-key-1|epoch:1";
const CACHE_NONCE: [u8; 12] = [0x5a; 12];

fn activated_for_cache() -> (ActivatedClientV1, [u8; 32], [u8; 32]) {
    let activation = run_client_activation(SeedRootActivationCase {
        session_byte: 0x61,
        wallet_custody_seed: [0x31; 32],
        entropy: activation_entropy(0x81),
    });
    let receipt = activation.result.public_receipt().clone();
    let activated = complete_client_activation_v1(activation.state, &activation.result)
        .expect("Client activation");
    let registered_public_key = activated.registered_public_key();
    (
        activated,
        registered_public_key,
        receipt.signing_worker_verifying_share(),
    )
}

#[test]
fn a_seed_sealed_cache_returns_material_that_reproduces_the_registered_key() {
    let (activated, registered_public_key, verifying_share) = activated_for_cache();
    let cache_key = [0x44; 32];
    let scalar_share = *activated.client_scalar_share();

    let sealed = seal_activated_client_under_custody_seed_v1(
        &activated,
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
    )
    .expect("seal");

    let opened = import_activated_client_under_custody_seed_v1(
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
        &sealed,
        &registered_public_key,
        activated.state_epoch(),
        [1, 2],
        &verifying_share,
    )
    .expect("import");

    assert_eq!(*opened.client_scalar_share(), scalar_share);
    assert_eq!(opened.registered_public_key(), registered_public_key);
    assert_eq!(opened.state_epoch(), activated.state_epoch());
}

#[test]
fn a_seed_sealed_cache_does_not_open_under_the_passkey_factor_domain() {
    // A record sealed for the wallet must never open as though a passkey factor
    // had sealed it, even when both paths receive identical bytes.
    let (activated, registered_public_key, verifying_share) = activated_for_cache();
    let secret = [0x44; 32];
    let sealed = seal_activated_client_under_custody_seed_v1(
        &activated,
        &secret,
        CACHE_BINDING,
        &CACHE_NONCE,
    )
    .expect("seal");

    let opened = import_activated_client_material_v1(
        &secret,
        CACHE_BINDING,
        &CACHE_NONCE,
        &sealed,
        &registered_public_key,
        activated.state_epoch(),
        [1, 2],
        &verifying_share,
        LocalMaterialSealDomainV1::PasskeyPrfFirst,
    );
    assert_eq!(opened.err(), Some(LocalMaterialError::SealFailed));
}

#[test]
fn a_cache_record_is_bound_to_its_wallet_and_its_key() {
    let (activated, registered_public_key, verifying_share) = activated_for_cache();
    let cache_key = [0x44; 32];
    let sealed = seal_activated_client_under_custody_seed_v1(
        &activated,
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
    )
    .expect("seal");

    // A different binding is a different wallet or key set. The binding is both
    // HKDF input and AEAD associated data, so this fails at the seal layer
    // rather than producing openable material for the wrong wallet.
    let wrong_binding = import_activated_client_under_custody_seed_v1(
        &cache_key,
        b"wallet:mallory.testnet|key:near-ed25519-key-1|epoch:1",
        &CACHE_NONCE,
        &sealed,
        &registered_public_key,
        activated.state_epoch(),
        [1, 2],
        &verifying_share,
    );
    assert_eq!(wrong_binding.err(), Some(LocalMaterialError::SealFailed));

    // Another wallet's seed yields another cache key and opens nothing.
    let wrong_key = import_activated_client_under_custody_seed_v1(
        &[0x45; 32],
        CACHE_BINDING,
        &CACHE_NONCE,
        &sealed,
        &registered_public_key,
        activated.state_epoch(),
        [1, 2],
        &verifying_share,
    );
    assert_eq!(wrong_key.err(), Some(LocalMaterialError::SealFailed));
}

#[test]
fn a_cache_record_is_refused_when_it_names_another_identity_or_epoch() {
    // The record decrypts here — the caller holds the right cache key — so
    // these are the checks that stand between a stale cache and material
    // installed against the wrong key or a superseded epoch.
    let (activated, registered_public_key, verifying_share) = activated_for_cache();
    let cache_key = [0x44; 32];
    let sealed = seal_activated_client_under_custody_seed_v1(
        &activated,
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
    )
    .expect("seal");

    let wrong_public_key = import_activated_client_under_custody_seed_v1(
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
        &sealed,
        &[0x77; 32],
        activated.state_epoch(),
        [1, 2],
        &verifying_share,
    );
    assert_eq!(
        wrong_public_key.err(),
        Some(LocalMaterialError::IdentityMismatch)
    );

    let wrong_epoch = import_activated_client_under_custody_seed_v1(
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
        &sealed,
        &registered_public_key,
        activated.state_epoch() + 1,
        [1, 2],
        &verifying_share,
    );
    assert_eq!(
        wrong_epoch.err(),
        Some(LocalMaterialError::IdentityMismatch)
    );
}

#[test]
fn a_cache_record_is_refused_when_its_share_cannot_reproduce_the_key() {
    // The public-relation check. Without it a record that decrypts and names
    // the right key could still install a share that recombines to something
    // else entirely — material signing under a key the wallet does not own.
    let (activated, registered_public_key, _) = activated_for_cache();
    let cache_key = [0x44; 32];
    let sealed = seal_activated_client_under_custody_seed_v1(
        &activated,
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
    )
    .expect("seal");

    let opened = import_activated_client_under_custody_seed_v1(
        &cache_key,
        CACHE_BINDING,
        &CACHE_NONCE,
        &sealed,
        &registered_public_key,
        activated.state_epoch(),
        [1, 2],
        // A verifying share the SigningWorker never held.
        &[0x66; 32],
    );
    assert_eq!(
        opened.err(),
        Some(LocalMaterialError::PublicRelationMismatch)
    );
}
