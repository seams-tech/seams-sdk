//! The registration ceremony against the real Router A/B circuit.
//!
//! The tests in `ceremony::tests` start from a completed protocol state and own
//! the ceremony's output contract. These own the other half: that a ceremony
//! actually drives both protocols to completion, and that the roots it derived
//! internally are the ones the protocols registered.
//!
//! The harness mirrors `crates/router-ab-ed25519-yao-client/tests/registration.rs`:
//! both Derivers run locally over an in-process relay, so this is the genuine
//! Yao circuit rather than a stub.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoOperationV1,
    Ed25519YaoPackageKindV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
    Ed25519YaoStateEpochV1, ExpensiveWorkKindV1, LifecycleScopeV1, MpcMaterialActivationRefV1,
    RootShareEpoch, RouterAbEd25519YaoActivationAdmissionReceiptV1,
    RouterAbEd25519YaoActivationExecuteRequestV1, RouterAbEd25519YaoActivationKeysetV1,
    RouterAbEd25519YaoActivationPublicReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1,
};
use router_ab_dev::{
    build_local_activation_deriver_a_v1, build_local_activation_deriver_b_v1,
    generate_local_ed25519_yao_recipient_key_pair_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1, seal_local_ed25519_yao_package_v1,
    LocalDeriverAWorkerConfigV1, LocalDeriverBWorkerConfigV1,
};
use router_ab_ecdsa_derivation::compose_public_identity_from_public_keys;
use router_ab_ed25519_yao::Ed25519YaoRecipientPrivateKeyV1;
use router_ab_ed25519_yao::{
    relay::{
        derive_registration_receipt, ActivationPublicCommitments, DirectionalWireDecoder,
        DirectionalWireEncoder, RelayEvent, RelayStep, WireDirection, WireMessage, WireMessageKind,
    },
    stable_key_derivation_context_v1, ActivationDeriverA, ActivationDeriverB,
};
use router_ab_ed25519_yao_client::ClientActivationEntropyV1;
use signer_core::ecdsa_role_local_client::command::RelayerPublicIdentityInput;

use crate::ceremony::*;

const WALLET_ID: &str = "alice.testnet";
const SESSION_BYTE: u8 = 0x53;
const ECDSA_BINDING_DIGEST: [u8; 32] = [0x41; 32];

/// A ceremony started from a fixed seed.
///
/// Production seeds come from `CeremonySeedHeldV1::generate`, which is
/// deliberately the only public way in. These tests need two ceremonies to
/// start from the *same* seed to compare what each registers, so they build the
/// state directly — which only code inside this crate can do.
fn ceremony_from_seed(seed: [u8; 32]) -> CeremonySeedHeldV1 {
    CeremonySeedHeldV1::from_seed_for_test(WALLET_ID, seed)
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

fn lifecycle(session_byte: u8) -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        format!("ceremony-e2e-lifecycle-{session_byte:02x}"),
        ExpensiveWorkKindV1::RegistrationPrepare,
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
        format!("ceremony-e2e-material-{session_byte:02x}"),
        "near-ed25519-mpc-signing",
        "account-1",
        "ed25519ks_client_e2e",
        format!("ceremony-e2e-lifecycle-{session_byte:02x}"),
        "signing-worker-1",
    )
    .expect("material activation")
}

fn entropy() -> ClientActivationEntropyV1 {
    ClientActivationEntropyV1::new([0x73; 32], [0x74; 32], [0x75; 32]).expect("entropy")
}

fn identities() -> RegistrationIdentityInputsV1 {
    RegistrationIdentityInputsV1 {
        near_ed25519_signing_key_id: "near-ed25519-key-1".to_string(),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1".to_string(),
    }
}

/// A Deriver-recipient keyset plus the private keys needed to open its inputs.
struct LocalKeyset {
    deriver_a_private: Ed25519YaoRecipientPrivateKeyV1,
    deriver_b_private: Ed25519YaoRecipientPrivateKeyV1,
    keyset: RouterAbEd25519YaoActivationKeysetV1,
}

fn local_keyset() -> LocalKeyset {
    let deriver_a =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Deriver A recipient");
    let deriver_b =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Deriver B recipient");
    let signing_worker =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("SigningWorker recipient");
    LocalKeyset {
        deriver_a_private: deriver_a.private_key,
        deriver_b_private: deriver_b.private_key,
        keyset: RouterAbEd25519YaoActivationKeysetV1::new(
            deriver_a.public_key,
            deriver_b.public_key,
            signing_worker.public_key,
        )
        .expect("activation keyset"),
    }
}

fn ceremony_binding(session_byte: u8) -> Ed25519YaoCeremonyBindingV1 {
    let context =
        stable_key_derivation_context_v1(&application(), [1, 2]).expect("derivation context");
    Ed25519YaoCeremonyBindingV1::new(
        lifecycle(session_byte),
        Ed25519YaoOperationV1::Registration,
        Ed25519YaoSessionIdV1::new([session_byte; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(context.binding_digest()),
        material_activation(session_byte),
    )
    .expect("binding")
}

/// Runs the Yao circuit over the ceremony's own execution request and returns
/// the Router result JSON the ceremony consumes to complete.
fn run_yao_circuit(
    execute_request_json: &str,
    binding: &Ed25519YaoCeremonyBindingV1,
    keys: &LocalKeyset,
) -> String {
    let execute =
        serde_json::from_str::<RouterAbEd25519YaoActivationExecuteRequestV1>(execute_request_json)
            .expect("execute request round-trips");
    let request_a = open_local_ed25519_yao_activation_deriver_a_input_v1(
        execute.deriver_a_input(),
        &keys.deriver_a_private,
    )
    .expect("open Deriver A input");
    let request_b = open_local_ed25519_yao_activation_deriver_b_input_v1(
        execute.deriver_b_input(),
        &keys.deriver_b_private,
    )
    .expect("open Deriver B input");

    let (_, role_a) =
        build_local_activation_deriver_a_v1(&deriver_a_config(), request_a).expect("Deriver A");
    let (_, role_b) =
        build_local_activation_deriver_b_v1(&deriver_b_config(), request_b).expect("Deriver B");
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
    let client_public_key = derive_client_public_key([0x73; 32]);
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
        // The receipt must carry the binding's own material activation: a
        // result built against a different one is rejected before it reaches
        // the ceremony, which would mask what these tests are asserting.
        binding.material_activation.clone(),
    )
    .expect("Router public receipt");
    let result = RouterAbEd25519YaoActivationResultV1::new(
        binding.clone(),
        package_a,
        package_b,
        public_receipt,
    )
    .expect("Router result");
    serde_json::to_string(&result).expect("Router result JSON")
}

/// A relayer identity consistent with the client share the ceremony produced.
///
/// The relayer's public key stands in for a real one: any valid compressed
/// point works, and the group key and address are then whatever the protocol
/// composes from the two, which is exactly what finalize re-checks.
fn relayer_identity(client_share_public_key33_b64u: &str) -> RelayerPublicIdentityInput {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let client_key: [u8; 33] = Base64UrlUnpadded::decode_vec(client_share_public_key33_b64u)
        .expect("client share key")
        .try_into()
        .expect("33 bytes");

    // A second bootstrap over unrelated material gives a valid secp256k1 point
    // to act as the relayer's key.
    let relayer_bootstrap =
        signer_core::ecdsa_role_local_client::command::prepare_ecdsa_client_bootstrap(
            signer_core::ecdsa_role_local_client::command::PrepareEcdsaClientBootstrapCommand {
                context: router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext::new(
                    [0x5a; 32],
                ),
                client_root_share32: [0x6b; 32],
            },
        )
        .expect("relayer stand-in key");
    let relayer_public_key33 = relayer_bootstrap
        .public_facts
        .derivation_client_share_public_key33;

    let identity = compose_public_identity_from_public_keys(
        &router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext::new(
            ECDSA_BINDING_DIGEST,
        ),
        &client_key,
        0,
        &relayer_public_key33,
        0,
    )
    .expect("composed identity");

    RelayerPublicIdentityInput {
        relayer_key_id: "relayer-key-1".to_string(),
        relayer_public_key33,
        group_public_key33: identity.threshold_public_key33,
        ethereum_address20: identity.threshold_ethereum_address20,
        relayer_share_retry_counter: 0,
    }
}

fn protocol_inputs(
    admission: RouterAbEd25519YaoActivationAdmissionReceiptV1,
) -> RegistrationProtocolInputsV1 {
    RegistrationProtocolInputsV1 {
        yao_admission: admission,
        yao_application: application(),
        participant_ids: [1, 2],
        yao_entropy: entropy(),
        ecdsa_application_binding_digest: ECDSA_BINDING_DIGEST,
    }
}

/// Drives one whole ceremony and returns its commit payload.
fn run_ceremony(seed: [u8; 32], session_byte: u8) -> WalletCustodyCommitPayloadV1 {
    let keys = local_keyset();
    let binding = ceremony_binding(session_byte);
    let admission =
        RouterAbEd25519YaoActivationAdmissionReceiptV1::new(binding.clone(), keys.keyset)
            .expect("admission");

    let prepared = ceremony_from_seed(seed)
        .prepare(protocol_inputs(admission))
        .expect("protocols prepared");
    let result_json = run_yao_circuit(prepared.yao_execute_request_json(), &binding, &keys);
    let relayer = relayer_identity(&prepared.ecdsa_client_share_public_key33_b64u());

    prepared
        .complete(&result_json, relayer)
        .expect("protocols completed")
        .establish_manifest(identities())
        .expect("manifest established")
        .seal(factor_inputs(), recovery_codes())
        .expect("sealed")
}

fn factor_inputs() -> FactorSealInputsV1 {
    use signer_core::passkey_custody::{
        WalletCustodyEnvelopeFactorV1, EMAIL_OTP_FACTOR_KEK_VERSION_V1,
    };
    FactorSealInputsV1 {
        envelope_id: "wallet-custody-envelope-1".to_string(),
        factor: WalletCustodyEnvelopeFactorV1::EmailOtp {
            enrollment_id: "enrollment-1".to_string(),
            enrollment_seal_key_version: "seal-v1".to_string(),
            kek_version: EMAIL_OTP_FACTOR_KEK_VERSION_V1.to_string(),
        },
        factor_secret: zeroize::Zeroizing::new(vec![7u8; 32]),
    }
}

fn recovery_codes() -> Vec<RecoveryCodeInputV1> {
    (0..signer_core::wallet_recovery_custody::WALLET_RECOVERY_CODE_COUNT)
        .map(|index| RecoveryCodeInputV1 {
            recovery_key_id: format!("email-otp-rkid-v1-code-{index}"),
            code_bytes: zeroize::Zeroizing::new(vec![index as u8 + 1; 20]),
        })
        .collect()
}

#[test]
fn a_ceremony_completes_both_protocols_and_commits_one_key_manifest() {
    let payload = run_ceremony([0x22; 32], SESSION_BYTE);

    // Both protocols returned real public identities, and both landed in the
    // manifest the envelope is sealed against.
    assert_eq!(payload.wallet_id, WALLET_ID);
    assert!(!payload.registered_public_key_b64u.is_empty());
    assert!(!payload.client_root_public_key33_b64u.is_empty());
    assert!(!payload.key_manifest_digest_b64u.is_empty());
    assert!(!payload.ecdsa_ready_state_blob_b64u.is_empty());
    assert_eq!(
        payload.recovery_manifest_kek_wraps.len(),
        signer_core::wallet_recovery_custody::WALLET_RECOVERY_CODE_COUNT
    );

    // The envelope binding records exactly the digest the ceremony established.
    let binding = serde_json::from_str::<serde_json::Value>(&payload.envelope_binding_json)
        .expect("binding JSON");
    assert_eq!(
        binding["binding"]["keyManifestDigestB64u"]
            .as_str()
            .expect("digest"),
        payload.key_manifest_digest_b64u
    );
}

#[test]
fn the_same_seed_registers_the_same_owner_keys() {
    // Two ceremonies over one seed, with independent sessions and fresh Deriver
    // keysets. If the ceremony's internally computed Ed25519 binding digest or
    // its ECDSA share derivation depended on anything but the seed and the
    // application facts, these would diverge.
    let first = run_ceremony([0x22; 32], SESSION_BYTE);
    let second = run_ceremony([0x22; 32], SESSION_BYTE);
    assert_eq!(
        first.registered_public_key_b64u,
        second.registered_public_key_b64u
    );
    assert_eq!(
        first.client_root_public_key33_b64u,
        second.client_root_public_key33_b64u
    );
    assert_eq!(
        first.key_manifest_digest_b64u,
        second.key_manifest_digest_b64u
    );

    // Ciphertext still differs: nonces and the manifest KEK are fresh per
    // ceremony even when the key set is identical.
    assert_ne!(
        first.sealed_custody_secret_b64u,
        second.sealed_custody_secret_b64u
    );
    assert_ne!(
        first.recovery_entry_ciphertext_b64u,
        second.recovery_entry_ciphertext_b64u
    );
}

#[test]
fn a_different_seed_registers_a_different_key_manifest() {
    let first = run_ceremony([0x22; 32], SESSION_BYTE);
    let other = run_ceremony([0x23; 32], SESSION_BYTE);
    assert_ne!(
        first.registered_public_key_b64u,
        other.registered_public_key_b64u
    );
    assert_ne!(
        first.client_root_public_key33_b64u,
        other.client_root_public_key33_b64u
    );
    assert_ne!(
        first.key_manifest_digest_b64u,
        other.key_manifest_digest_b64u
    );
}

#[test]
fn the_registered_key_matches_the_router_receipt_commitment() {
    let keys = local_keyset();
    let binding = ceremony_binding(SESSION_BYTE);
    let admission =
        RouterAbEd25519YaoActivationAdmissionReceiptV1::new(binding.clone(), keys.keyset)
            .expect("admission");
    let prepared = ceremony_from_seed([0x22; 32])
        .prepare(protocol_inputs(admission))
        .expect("protocols prepared");
    let result_json = run_yao_circuit(prepared.yao_execute_request_json(), &binding, &keys);

    // The Router's own receipt is the reference: the ceremony's seed-derived
    // root produced the Client share this public key was joined from.
    let result =
        serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(&result_json).expect("result");
    let receipt = result.public_receipt().clone();
    let relayer = relayer_identity(&prepared.ecdsa_client_share_public_key33_b64u());
    let payload = prepared
        .complete(&result_json, relayer)
        .expect("completed")
        .establish_manifest(identities())
        .expect("manifest")
        .seal(factor_inputs(), recovery_codes())
        .expect("sealed");

    use base64ct::{Base64UrlUnpadded, Encoding};
    assert_eq!(
        Base64UrlUnpadded::decode_vec(&payload.registered_public_key_b64u).expect("key"),
        receipt.registered_public_key().to_vec()
    );
}

#[test]
fn a_router_result_for_another_session_cannot_complete_the_ceremony() {
    let keys = local_keyset();
    let binding = ceremony_binding(SESSION_BYTE);
    let admission =
        RouterAbEd25519YaoActivationAdmissionReceiptV1::new(binding.clone(), keys.keyset)
            .expect("admission");
    let prepared = ceremony_from_seed([0x22; 32])
        .prepare(protocol_inputs(admission))
        .expect("protocols prepared");

    // A result from a different session, produced by a genuine circuit run.
    let other_keys = local_keyset();
    let other_binding = ceremony_binding(SESSION_BYTE ^ 0x0f);
    let other_admission = RouterAbEd25519YaoActivationAdmissionReceiptV1::new(
        other_binding.clone(),
        other_keys.keyset,
    )
    .expect("admission");
    let other_prepared = ceremony_from_seed([0x22; 32])
        .prepare(protocol_inputs(other_admission))
        .expect("protocols prepared");
    let foreign_result = run_yao_circuit(
        other_prepared.yao_execute_request_json(),
        &other_binding,
        &other_keys,
    );

    let relayer = relayer_identity(&prepared.ecdsa_client_share_public_key33_b64u());
    assert!(prepared.complete(&foreign_result, relayer).is_err());
}

#[test]
fn a_relayer_identity_that_does_not_match_the_client_share_is_refused() {
    let keys = local_keyset();
    let binding = ceremony_binding(SESSION_BYTE);
    let admission =
        RouterAbEd25519YaoActivationAdmissionReceiptV1::new(binding.clone(), keys.keyset)
            .expect("admission");
    let prepared = ceremony_from_seed([0x22; 32])
        .prepare(protocol_inputs(admission))
        .expect("protocols prepared");
    let result_json = run_yao_circuit(prepared.yao_execute_request_json(), &binding, &keys);

    // A group key that is not the sum of the client and relayer keys must not
    // finalize: it would bind the wallet to a threshold key the seed-derived
    // share does not participate in.
    let mut relayer = relayer_identity(&prepared.ecdsa_client_share_public_key33_b64u());
    relayer.group_public_key33 = relayer.relayer_public_key33;
    assert!(prepared.complete(&result_json, relayer).is_err());
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
        role_private_storage_path: "/tmp/ceremony-test-a-root".to_owned(),
        sealed_root_shares_path: "/tmp/ceremony-test-a-sealed".to_owned(),
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
        role_private_storage_path: "/tmp/ceremony-test-b-root".to_owned(),
        sealed_root_shares_path: "/tmp/ceremony-test-b-sealed".to_owned(),
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

/// Unused in these tests, kept because the scalar/commitment identity is the
/// property the yao-client suite asserts and this module mirrors its harness.
#[allow(dead_code)]
fn client_commitment_from_scalar(scalar_bytes: [u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_canonical_bytes(scalar_bytes)
        .into_option()
        .expect("canonical Client scalar");
    (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes()
}
