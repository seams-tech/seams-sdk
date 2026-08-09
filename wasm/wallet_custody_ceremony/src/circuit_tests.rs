//! The custody ceremony against the real Router A/B circuit.
//!
//! The tests in `ceremony::tests` start from a completed protocol state and own
//! the ceremony's output contract. These own the other half: that a run drives
//! its protocol to completion, that the root it derived internally is the one
//! that protocol registered, and — the property this refactor exists for — that
//! the two key sets are provisioned independently over one shared wallet
//! custody seed.
//!
//! The seam under test is establish-then-join. An EVM-family run establishes
//! custody with the Yao circuit never running, and a NEAR run reaches the same
//! seed by opening the envelope that run sealed. Nothing here builds a ceremony
//! from a fixed seed: a joining run's seed arrives the way production's does, so
//! the tests cannot pass by agreeing with themselves about what the seed was.
//!
//! The harness mirrors `crates/router-ab-ed25519-yao-client/tests/registration.rs`:
//! both Derivers run locally over an in-process relay, so this is the genuine
//! Yao circuit rather than a stub.

use base64ct::{Base64UrlUnpadded, Encoding};
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
use router_ab_ed25519_yao_client::{
    client_application_binding_digest_v1, ed25519_local_material_binding_v1,
    import_activated_client_under_custody_seed_v1, ClientActivationEntropyV1,
};
use signer_core::ecdsa_role_local_client::command::RelayerPublicIdentityInput;
use signer_core::passkey_custody::open_wallet_custody_seed_envelope_v1;
use signer_core::passkey_custody::{
    PasskeyCustodyEnvelopeBindingV1, EMAIL_OTP_FACTOR_KEK_VERSION_V1,
};
use signer_core::wallet_seed_derivation::{
    derive_ed25519_local_material_cache_key_from_seed_v1, WalletKeySetKindV1,
};

use crate::ceremony::*;

const WALLET_ID: &str = "alice.testnet";
const PARTICIPANT_IDS: [u16; 2] = [1, 2];
const ECDSA_BINDING_DIGEST: [u8; 32] = [0x41; 32];
const FACTOR_SECRET: [u8; 32] = [7u8; 32];
const NEAR_SIGNING_KEY_ID: &str = "near-ed25519-key-1";
const EVM_SLOT_ID: &str = "wallet-key:evm-family:alice.testnet:root-1:v1";

fn application() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
    RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-client-e2e",
        "ed25519ks_client_e2e",
        "project-client:local",
        1,
    )
    .expect("application")
}

fn lifecycle(session_byte: u8, work_kind: ExpensiveWorkKindV1) -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        format!("ceremony-e2e-lifecycle-{session_byte:02x}"),
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

fn near_identity() -> KeySetIdentityInputsV1 {
    KeySetIdentityInputsV1::NearEd25519 {
        near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID.to_string(),
    }
}

fn evm_identity() -> KeySetIdentityInputsV1 {
    KeySetIdentityInputsV1::EvmFamilyEcdsa {
        evm_family_signing_key_slot_id: EVM_SLOT_ID.to_string(),
    }
}

fn factor_inputs() -> FactorSealInputsV1 {
    use signer_core::passkey_custody::WalletCustodyEnvelopeFactorV1;
    FactorSealInputsV1 {
        envelope_id: "wallet-custody-envelope-1".to_string(),
        factor: WalletCustodyEnvelopeFactorV1::EmailOtp {
            enrollment_id: "enrollment-1".to_string(),
            enrollment_seal_key_version: "seal-v1".to_string(),
            kek_version: EMAIL_OTP_FACTOR_KEK_VERSION_V1.to_string(),
        },
        factor_secret: zeroize::Zeroizing::new(FACTOR_SECRET.to_vec()),
    }
}

fn recovery_codes() -> Vec<RecoveryCodeInputV1> {
    (0..signer_core::wallet_recovery_custody::WALLET_RECOVERY_CODE_COUNT)
        .map(|index| RecoveryCodeInputV1 {
            code_bytes: zeroize::Zeroizing::new(vec![index as u8 + 1; 20]),
        })
        .collect()
}

fn decode(value: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(value).expect("base64url")
}

fn custody_records(payload: &WalletCustodyCommitPayloadV1) -> &EstablishedCustodyRecordsV1 {
    payload
        .established_custody
        .as_ref()
        .expect("an establishing run writes custody records")
}

/// Completes an EVM-family run. No Router circuit is involved: the ECDSA
/// bootstrap is local, and its counterparty is the relayer.
fn complete_evm_family_run(held: CeremonySeedHeldV1) -> CeremonyProtocolCompletedV1 {
    let prepared = held
        .prepare(KeySetProtocolInputsV1::EvmFamilyEcdsa {
            application_binding_digest: ECDSA_BINDING_DIGEST,
        })
        .expect("ECDSA bootstrap prepared");

    // There is no Router execution request, so there is nothing the Yao circuit
    // could be asked to do — the EVM-family key set is provisioned without it.
    assert!(
        prepared.yao_execute_request_json().is_none(),
        "an EVM-family run must not produce Yao work"
    );

    let relayer = relayer_identity(
        &prepared
            .ecdsa_client_share_public_key33_b64u()
            .expect("an EVM-family run publishes its client share key"),
    );
    prepared
        .complete_evm_family(relayer)
        .expect("ECDSA finalized")
}

/// The wallet's first key set: an EVM-family run that establishes custody.
fn establish_custody_with_evm_key_set() -> WalletCustodyCommitPayloadV1 {
    complete_evm_family_run(CeremonySeedHeldV1::establish(WALLET_ID).expect("custody established"))
        .establish_manifest(evm_identity(), None)
        .expect("EVM manifest established")
        .finish(Some((factor_inputs(), recovery_codes())))
        .expect("custody committed")
}

#[test]
fn evm_custody_commit_is_ready_before_activation_and_seed_free_completion_matches() {
    let prepared = CeremonySeedHeldV1::establish(WALLET_ID)
        .expect("custody established")
        .prepare(KeySetProtocolInputsV1::EvmFamilyEcdsa {
            application_binding_digest: ECDSA_BINDING_DIGEST,
        })
        .expect("ECDSA bootstrap prepared");
    let relayer = relayer_identity(
        &prepared
            .ecdsa_client_share_public_key33_b64u()
            .expect("client share key"),
    );
    let (pending, commit) = prepared
        .prepare_evm_activation(
            EVM_SLOT_ID.to_string(),
            None,
            Some((factor_inputs(), recovery_codes())),
        )
        .expect("pre-activation custody commit");

    assert!(commit.established_custody.is_some());
    assert!(commit.ecdsa_ready_state_blob_b64u.is_none());
    assert!(commit.ecdsa_public_facts.is_none());

    let completed = pending.complete(relayer).expect("activation completed");
    assert_eq!(
        completed.key_manifest_digest_b64u,
        commit.key_manifest_digest_b64u
    );
    assert_eq!(
        completed.client_root_public_key33_b64u,
        commit
            .client_root_public_key33_b64u
            .expect("pre-activation client root")
    );
    assert!(!completed.ecdsa_ready_state_blob_b64u.is_empty());
}

/// Reaches the wallet's seed the way a later key set does: by opening the
/// envelope the establishing run sealed.
fn join_custody(records: &EstablishedCustodyRecordsV1) -> CeremonySeedHeldV1 {
    let binding =
        serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(&records.envelope_binding_json)
            .expect("envelope binding round-trips");
    CeremonySeedHeldV1::join_existing_custody(
        &FACTOR_SECRET,
        &binding,
        &decode(&records.envelope_nonce_b64u),
        &decode(&records.sealed_custody_secret_b64u),
        &decode(&records.envelope_aad_hash_b64u),
        &decode(&records.envelope_ciphertext_digest_b64u),
    )
    .expect("custody envelope opens")
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

fn ceremony_binding(
    session_byte: u8,
    operation: Ed25519YaoOperationV1,
) -> Ed25519YaoCeremonyBindingV1 {
    let context = stable_key_derivation_context_v1(&application(), PARTICIPANT_IDS)
        .expect("derivation context");
    Ed25519YaoCeremonyBindingV1::new(
        lifecycle(session_byte, work_kind_for(operation)),
        operation,
        Ed25519YaoSessionIdV1::new([session_byte; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(context.binding_digest()),
        material_activation(session_byte),
    )
    .expect("binding")
}

/// A run with continuity is a recovery, and the Router admission, the lifecycle
/// work kind and the state epoch all have to say so.
fn work_kind_for(operation: Ed25519YaoOperationV1) -> ExpensiveWorkKindV1 {
    match operation {
        Ed25519YaoOperationV1::Recovery => ExpensiveWorkKindV1::Recovery,
        _ => ExpensiveWorkKindV1::RegistrationPrepare,
    }
}

fn state_epoch_for(operation: Ed25519YaoOperationV1) -> u64 {
    match operation {
        Ed25519YaoOperationV1::Recovery => 2,
        _ => 1,
    }
}

/// A NEAR Ed25519 run prepared against a fresh session and Deriver keyset.
struct PreparedNearRun {
    prepared: CeremonyProtocolPreparedV1,
    binding: Ed25519YaoCeremonyBindingV1,
    keys: LocalKeyset,
    state_epoch: u64,
}

impl PreparedNearRun {
    /// Drives the real circuit and returns the Router result the ceremony
    /// consumes to complete.
    fn run_circuit(&self) -> String {
        run_yao_circuit(
            self.prepared
                .yao_execute_request_json()
                .expect("a NEAR run has a Router execution request"),
            &self.binding,
            &self.keys,
            self.state_epoch,
        )
    }

    fn complete(self) -> Result<CeremonyProtocolCompletedV1, CeremonyError> {
        let result_json = self.run_circuit();
        self.prepared.complete_near_ed25519(&result_json)
    }
}

fn prepare_near_ed25519(
    held: CeremonySeedHeldV1,
    session_byte: u8,
    continuity: Option<[u8; 32]>,
) -> PreparedNearRun {
    let keys = local_keyset();
    let operation = match continuity {
        Some(_) => Ed25519YaoOperationV1::Recovery,
        None => Ed25519YaoOperationV1::Registration,
    };
    let binding = ceremony_binding(session_byte, operation);
    let admission =
        RouterAbEd25519YaoActivationAdmissionReceiptV1::new(binding.clone(), keys.keyset)
            .expect("admission");
    let prepared = held
        .prepare(KeySetProtocolInputsV1::NearEd25519 {
            yao_admission: admission,
            yao_application: application(),
            participant_ids: PARTICIPANT_IDS,
            yao_entropy: entropy(),
            continuity,
        })
        .expect("Yao protocol prepared");
    PreparedNearRun {
        prepared,
        binding,
        keys,
        state_epoch: state_epoch_for(operation),
    }
}

/// Runs the Yao circuit over the ceremony's own execution request and returns
/// the Router result JSON the ceremony consumes to complete.
fn run_yao_circuit(
    execute_request_json: &str,
    binding: &Ed25519YaoCeremonyBindingV1,
    keys: &LocalKeyset,
    state_epoch: u64,
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
        Ed25519YaoStateEpochV1::new(state_epoch).expect("state epoch"),
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
    let client_key: [u8; 33] = decode(client_share_public_key33_b64u)
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

#[test]
fn an_evm_family_run_establishes_custody_without_the_yao_circuit() {
    let payload = establish_custody_with_evm_key_set();

    assert_eq!(payload.wallet_id, WALLET_ID);
    assert_eq!(
        payload.key_set,
        WalletKeySetKindV1::EvmFamilyEcdsa.as_str(),
        "the run provisioned one key set, and it is the EVM-family one"
    );
    assert!(payload.client_root_public_key33_b64u.is_some());
    assert!(payload.ecdsa_ready_state_blob_b64u.is_some());
    assert!(
        payload.registered_public_key_b64u.is_none(),
        "no Ed25519 registration exists: the Yao protocol never ran"
    );

    // Custody is fully established: the seed is sealed under the factor and the
    // whole recovery set is issued, before the NEAR key set exists at all.
    let records = custody_records(&payload);
    assert!(!records.sealed_custody_secret_b64u.is_empty());
    assert_eq!(
        records.recovery_manifest_kek_wraps.len(),
        signer_core::wallet_recovery_custody::WALLET_RECOVERY_CODE_COUNT
    );

    // The envelope binds the seed, not this key set's manifest: nothing about
    // the NEAR key set has to exist for the envelope to be well formed. The
    // positive assertions are what keep the negative one meaningful — without
    // them a renamed field would make it pass against an empty object.
    let binding = serde_json::from_str::<serde_json::Value>(&records.envelope_binding_json)
        .expect("binding JSON");
    assert_eq!(binding["walletId"].as_str(), Some(WALLET_ID));
    let secret_binding = binding["binding"]
        .as_object()
        .expect("the envelope names what it holds");
    assert_eq!(
        secret_binding["kind"].as_str(),
        Some("wallet_custody_seed_v1")
    );
    assert!(secret_binding.contains_key("derivationScheme"));
    assert!(
        !secret_binding.contains_key("keyManifestDigestB64u"),
        "the seed envelope must not bind a key manifest"
    );
}

#[test]
fn a_near_run_joins_that_custody_and_writes_only_its_manifest() {
    let evm = establish_custody_with_evm_key_set();

    let near = prepare_near_ed25519(join_custody(custody_records(&evm)), 0x53, None)
        .complete()
        .expect("Yao protocol completed")
        .establish_manifest(near_identity(), None)
        .expect("NEAR manifest established")
        .finish(None)
        .expect("key set committed");

    assert_eq!(near.key_set, WalletKeySetKindV1::NearEd25519.as_str());
    assert!(near.registered_public_key_b64u.is_some());
    assert!(
        near.established_custody.is_none(),
        "the wallet already has a seed envelope and a recovery set"
    );
    assert_ne!(
        near.key_manifest_digest_b64u, evm.key_manifest_digest_b64u,
        "each key set records its own manifest"
    );
}

#[test]
fn both_key_sets_derive_from_the_one_wallet_custody_seed() {
    let evm = establish_custody_with_evm_key_set();
    let records = custody_records(&evm);

    // Two joins of the same custody, each with its own session and its own
    // fresh Deriver keyset. The registered key is the same because the root
    // behind it is a function of the seed and the application facts alone.
    let first = prepare_near_ed25519(join_custody(records), 0x53, None)
        .complete()
        .expect("first NEAR run completed");
    let second = prepare_near_ed25519(join_custody(records), 0x54, None)
        .complete()
        .expect("second NEAR run completed");

    let first = first
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");
    let second = second
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");

    assert_eq!(
        first.registered_public_key_b64u,
        second.registered_public_key_b64u
    );
    assert_eq!(
        first.key_manifest_digest_b64u,
        second.key_manifest_digest_b64u
    );
}

#[test]
fn a_re_derived_evm_key_set_reproduces_its_recorded_manifest() {
    // What recovery has to be able to do: reach the seed through custody and
    // re-derive a key set that already has a manifest recorded against it.
    let evm = establish_custody_with_evm_key_set();
    let recorded = decode(&evm.key_manifest_digest_b64u);

    let reproduced = complete_evm_family_run(join_custody(custody_records(&evm)))
        .establish_manifest(evm_identity(), Some(&recorded))
        .expect("the re-derived key set matches its recorded manifest")
        .finish(None)
        .expect("committed");

    assert_eq!(
        reproduced.client_root_public_key33_b64u,
        evm.client_root_public_key33_b64u
    );
    assert_eq!(
        reproduced.key_manifest_digest_b64u,
        evm.key_manifest_digest_b64u
    );
    assert!(reproduced.established_custody.is_none());
}

#[test]
fn a_near_re_run_reproduces_the_recorded_key_or_fails() {
    let evm = establish_custody_with_evm_key_set();
    let records = custody_records(&evm);

    let registered = prepare_near_ed25519(join_custody(records), 0x53, None)
        .complete()
        .expect("first NEAR run completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed")
        .registered_public_key_b64u
        .expect("a NEAR run reports its registered key");
    let registered_bytes: [u8; 32] = decode(&registered).try_into().expect("32 bytes");

    // A re-run over the recorded key takes the recovery seam and must land on
    // the identical key.
    let again = prepare_near_ed25519(join_custody(records), 0x55, Some(registered_bytes))
        .complete()
        .expect("continuity run completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");
    assert_eq!(
        again.registered_public_key_b64u.as_deref(),
        Some(&registered[..])
    );

    // And a re-run told to preserve a key this seed does not produce fails
    // rather than registering a replacement.
    let mut wrong = registered_bytes;
    wrong[0] ^= 0xff;
    assert!(
        prepare_near_ed25519(join_custody(records), 0x56, Some(wrong))
            .complete()
            .is_err(),
        "a continuity mismatch must end the run"
    );
}

#[test]
fn a_run_that_joined_existing_custody_cannot_seal_a_second_seed() {
    // The join origin here came from a real envelope open, so this is the
    // production path refusing, not a hand-built state.
    let evm = establish_custody_with_evm_key_set();
    let committed = complete_evm_family_run(join_custody(custody_records(&evm)))
        .establish_manifest(evm_identity(), Some(&decode(&evm.key_manifest_digest_b64u)))
        .expect("manifest")
        .finish(Some((factor_inputs(), recovery_codes())));

    assert!(
        committed.is_err(),
        "sealing here would give the wallet a second seed and a second recovery set"
    );
}

#[test]
fn the_registered_key_matches_the_router_receipt_commitment() {
    let evm = establish_custody_with_evm_key_set();
    let run = prepare_near_ed25519(join_custody(custody_records(&evm)), 0x53, None);
    let result_json = run.run_circuit();

    // The Router's own receipt is the reference: the ceremony's seed-derived
    // root produced the Client share this public key was joined from.
    let result =
        serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(&result_json).expect("result");
    let receipt = result.public_receipt().clone();
    let payload = run
        .prepared
        .complete_near_ed25519(&result_json)
        .expect("completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");

    assert_eq!(
        decode(&payload.registered_public_key_b64u.expect("registered key")),
        receipt.registered_public_key().to_vec()
    );
}

#[test]
fn a_router_result_for_another_session_cannot_complete_the_ceremony() {
    let evm = establish_custody_with_evm_key_set();
    let records = custody_records(&evm);
    let run = prepare_near_ed25519(join_custody(records), 0x53, None);

    // A result from a different session, produced by a genuine circuit run.
    let foreign_result = prepare_near_ed25519(join_custody(records), 0x5c, None).run_circuit();

    assert!(run.prepared.complete_near_ed25519(&foreign_result).is_err());
}

#[test]
fn a_relayer_identity_that_does_not_match_the_client_share_is_refused() {
    let prepared = CeremonySeedHeldV1::establish(WALLET_ID)
        .expect("custody established")
        .prepare(KeySetProtocolInputsV1::EvmFamilyEcdsa {
            application_binding_digest: ECDSA_BINDING_DIGEST,
        })
        .expect("ECDSA bootstrap prepared");

    // A group key that is not the sum of the client and relayer keys must not
    // finalize: it would bind the wallet to a threshold key the seed-derived
    // share does not participate in.
    let mut relayer = relayer_identity(
        &prepared
            .ecdsa_client_share_public_key33_b64u()
            .expect("client share key"),
    );
    relayer.group_public_key33 = relayer.relayer_public_key33;
    assert!(prepared.complete_evm_family(relayer).is_err());
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

/// The continuity cache a NEAR run seals, opened the way a later unlock opens
/// it: factor → custody envelope → seed → cache key → material.
///
/// This is the property the whole seed-sealed design exists for. The run below
/// *joins* custody established by an EVM run, so the factor that opens the
/// envelope here is not tied to whichever ceremony first sealed it — which is
/// exactly a wallet unlocking under a factor enrolled after registration.
///
/// The material must come back able to sign: the check is that its share
/// recombines with the SigningWorker's verifying share to the registered public
/// key, not merely that the bytes round-trip.
#[test]
fn a_near_run_seals_a_cache_the_custody_seed_can_open() {
    let evm = establish_custody_with_evm_key_set();
    let records = custody_records(&evm);
    let run = prepare_near_ed25519(join_custody(records), 0x53, None);
    let result_json = run.run_circuit();
    let result =
        serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(&result_json).expect("result");
    let receipt = result.public_receipt().clone();
    let payload = run
        .prepared
        .complete_near_ed25519(&result_json)
        .expect("completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");

    let sealed = decode(&payload.ed25519_local_material_b64u.expect("cache record"));
    let nonce = decode(
        &payload
            .ed25519_local_material_nonce_b64u
            .expect("cache nonce"),
    );

    // The seed, reached the only way a client can reach it: by opening the
    // wallet's custody envelope with a factor.
    let binding =
        serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(&records.envelope_binding_json)
            .expect("binding");
    let (seed, _) = open_wallet_custody_seed_envelope_v1(
        &FACTOR_SECRET,
        &binding,
        &decode(&records.envelope_nonce_b64u),
        &decode(&records.sealed_custody_secret_b64u),
        &decode(&records.envelope_aad_hash_b64u),
        &decode(&records.envelope_ciphertext_digest_b64u),
    )
    .expect("envelope opens");

    let application_binding_digest =
        client_application_binding_digest_v1(&application(), [1, 2]).expect("binding digest");
    let cache_key =
        derive_ed25519_local_material_cache_key_from_seed_v1(&seed, &application_binding_digest)
            .expect("cache key");
    let cache_binding = ed25519_local_material_binding_v1(
        &application_binding_digest,
        &receipt.registered_public_key(),
        [1, 2],
        state_epoch_for(Ed25519YaoOperationV1::Registration),
    );

    let opened = import_activated_client_under_custody_seed_v1(
        &cache_key,
        &cache_binding,
        &nonce,
        &sealed,
        &receipt.registered_public_key(),
        state_epoch_for(Ed25519YaoOperationV1::Registration),
        [1, 2],
        &receipt.signing_worker_verifying_share(),
    )
    .expect("cache opens");

    assert_eq!(
        opened.registered_public_key(),
        receipt.registered_public_key()
    );
}

/// A wallet cannot open another wallet's cache, even holding the record.
#[test]
fn another_wallets_seed_does_not_open_the_cache() {
    let evm = establish_custody_with_evm_key_set();
    let run = prepare_near_ed25519(join_custody(custody_records(&evm)), 0x53, None);
    let result_json = run.run_circuit();
    let result =
        serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(&result_json).expect("result");
    let receipt = result.public_receipt().clone();
    let payload = run
        .prepared
        .complete_near_ed25519(&result_json)
        .expect("completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");

    let application_binding_digest =
        client_application_binding_digest_v1(&application(), [1, 2]).expect("binding digest");
    let foreign_cache_key = derive_ed25519_local_material_cache_key_from_seed_v1(
        &[0x99; 32],
        &application_binding_digest,
    )
    .expect("cache key");

    assert!(import_activated_client_under_custody_seed_v1(
        &foreign_cache_key,
        &ed25519_local_material_binding_v1(
            &application_binding_digest,
            &receipt.registered_public_key(),
            [1, 2],
            state_epoch_for(Ed25519YaoOperationV1::Registration),
        ),
        &decode(&payload.ed25519_local_material_nonce_b64u.expect("nonce")),
        &decode(&payload.ed25519_local_material_b64u.expect("record")),
        &receipt.registered_public_key(),
        state_epoch_for(Ed25519YaoOperationV1::Registration),
        [1, 2],
        &receipt.signing_worker_verifying_share(),
    )
    .is_err());
}

/// The cache binding names the key set and nothing that names a factor.
///
/// Rebuilt here from its parts rather than compared against the production
/// builder's own output: a test that calls the builder on both sides passes no
/// matter what fields are added, including a credential id — which is exactly
/// the coupling the seed-sealed cache exists to remove. Adding, removing, or
/// reordering any field breaks this.
#[test]
fn the_cache_binding_carries_no_factor_identity() {
    let digest = [0x21u8; 32];
    let registered_public_key = [0x22u8; 32];

    fn field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
        out.extend_from_slice(&(label.len() as u32).to_be_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut expected = Vec::new();
    field(
        &mut expected,
        b"context",
        b"seams/wallet-custody/ed25519-local-material-cache/v1",
    );
    field(&mut expected, b"applicationBindingDigest", &digest);
    field(
        &mut expected,
        b"registeredPublicKey",
        &registered_public_key,
    );
    field(&mut expected, b"participantIds", &[0, 1, 0, 2]);
    field(&mut expected, b"stateEpoch", &7u64.to_be_bytes());

    assert_eq!(
        ed25519_local_material_binding_v1(&digest, &registered_public_key, [1, 2], 7),
        expected
    );
}

/// The EVM run reports the identity its own finalize computed.
///
/// These facts are what the client's capability manifest is built from — the
/// threshold group key, the address it projects to, and both shares' public
/// keys. The run once returned only the sealed blob, which left an installer
/// holding material it could not describe. Recomputing them outside the
/// ceremony would be worse than reporting them: it would mean trusting a
/// second computation to agree with the one that produced the material.
#[test]
fn an_evm_run_reports_the_identity_its_own_finalize_produced() {
    let payload = establish_custody_with_evm_key_set();
    let facts = payload.ecdsa_public_facts.expect("EVM public facts");

    // The relayer stand-in composed the same identity from the same public
    // keys, so the ceremony's report must agree with it exactly.
    let expected = relayer_identity(
        payload
            .client_root_public_key33_b64u
            .as_deref()
            .expect("client root key"),
    );
    assert_eq!(
        decode(&facts.group_public_key33_b64u),
        expected.group_public_key33.to_vec()
    );
    assert_eq!(
        decode(&facts.relayer_public_key33_b64u),
        expected.relayer_public_key33.to_vec()
    );

    // The address is the one the threshold key projects to, spelled the way
    // the wasm boundary's decoder reads one.
    let mut address = String::from("0x");
    for byte in expected.ethereum_address20 {
        address.push_str(&format!("{byte:02x}"));
    }
    assert_eq!(facts.ethereum_address, address);

    // The client share the manifest records is this run's own, and the context
    // binding is the one its stable-key context produced.
    assert_eq!(
        facts.derivation_client_share_public_key33_b64u,
        payload
            .client_root_public_key33_b64u
            .expect("client root key")
    );
    assert_eq!(decode(&facts.context_binding32_b64u).len(), 32);
}

/// A NEAR run carries no EVM identity, and an EVM run carries no NEAR cache.
#[test]
fn each_key_set_reports_only_its_own_material() {
    let evm = establish_custody_with_evm_key_set();
    assert!(evm.ecdsa_public_facts.is_some());
    assert!(evm.ed25519_local_material_b64u.is_none());
    assert!(evm.ed25519_local_material_nonce_b64u.is_none());

    let run = prepare_near_ed25519(join_custody(custody_records(&evm)), 0x53, None);
    let result_json = run.run_circuit();
    let near = run
        .prepared
        .complete_near_ed25519(&result_json)
        .expect("completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");

    assert!(near.ed25519_local_material_b64u.is_some());
    assert!(near.ecdsa_public_facts.is_none());
    assert!(near.ecdsa_ready_state_blob_b64u.is_none());
}

/// The property this whole refactor exists to provide: a wallet registered
/// under one factor unlocks under a factor enrolled *afterwards*.
///
/// The continuity cache is sealed under the wallet custody seed, so it belongs
/// to the wallet rather than to whichever credential created it. Adding a
/// factor reseals the *envelope* — it derives nothing and re-registers
/// nothing — and the new factor then opens the same cache the first one did.
///
/// Under the per-factor records this replaces, the second factor would have
/// found no cache at all and had to reproduce the material through a Router
/// round on every unlock.
#[test]
fn a_factor_enrolled_after_registration_opens_the_same_cache() {
    use router_ab_ed25519_yao_client::{
        open_wallet_custody_ed25519_material_v1, OpenWalletCustodyEd25519MaterialV1,
    };
    use signer_core::passkey_custody::reseal_wallet_custody_seed_under_new_factor_v1;

    // Register: an EVM run establishes custody, a NEAR run joins it and seals
    // the continuity cache.
    let evm = establish_custody_with_evm_key_set();
    let records = custody_records(&evm);
    let run = prepare_near_ed25519(join_custody(records), 0x53, None);
    let result_json = run.run_circuit();
    let result =
        serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(&result_json).expect("result");
    let receipt = result.public_receipt().clone();
    let payload = run
        .prepared
        .complete_near_ed25519(&result_json)
        .expect("completed")
        .establish_manifest(near_identity(), None)
        .expect("manifest")
        .finish(None)
        .expect("committed");

    let binding =
        serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(&records.envelope_binding_json)
            .expect("binding");

    // Enrol a second factor: the seed is opened with the first and resealed
    // under the second. Nothing is derived and no key set is touched.
    let (seed, admitted) = open_wallet_custody_seed_envelope_v1(
        &FACTOR_SECRET,
        &binding,
        &decode(&records.envelope_nonce_b64u),
        &decode(&records.sealed_custody_secret_b64u),
        &decode(&records.envelope_aad_hash_b64u),
        &decode(&records.envelope_ciphertext_digest_b64u),
    )
    .expect("first factor opens the envelope");

    const SECOND_FACTOR_SECRET: [u8; 32] = [0x2b; 32];
    let second_nonce = [0x3c; 12];
    let resealed = reseal_wallet_custody_seed_under_new_factor_v1(
        &SECOND_FACTOR_SECRET,
        &binding,
        &admitted,
        &second_nonce,
        &seed,
    )
    .expect("reseal under the second factor");

    // Unlock with the *second* factor only.
    let application_binding_digest =
        client_application_binding_digest_v1(&application(), [1, 2]).expect("binding digest");
    let cache_binding = ed25519_local_material_binding_v1(
        &application_binding_digest,
        &receipt.registered_public_key(),
        [1, 2],
        state_epoch_for(Ed25519YaoOperationV1::Registration),
    );
    let opened = open_wallet_custody_ed25519_material_v1(OpenWalletCustodyEd25519MaterialV1 {
        factor_secret: &SECOND_FACTOR_SECRET,
        envelope_binding: &binding,
        envelope_nonce: &second_nonce,
        envelope_ciphertext: &decode(&resealed.ciphertext_b64u()),
        envelope_aad_hash: &decode(&resealed.aad_hash_b64u()),
        envelope_ciphertext_digest: &decode(&resealed.ciphertext_digest_b64u()),
        application_binding_digest: &application_binding_digest,
        binding: &cache_binding,
        nonce: &decode(
            &payload
                .ed25519_local_material_nonce_b64u
                .clone()
                .expect("nonce"),
        ),
        ciphertext: &decode(&payload.ed25519_local_material_b64u.clone().expect("record")),
        expected_registered_public_key: &receipt.registered_public_key(),
        expected_state_epoch: state_epoch_for(Ed25519YaoOperationV1::Registration),
        participant_ids: [1, 2],
        signing_worker_verifying_share: &receipt.signing_worker_verifying_share(),
    })
    .expect("the second factor opens the wallet's cache");

    assert_eq!(
        opened.registered_public_key(),
        receipt.registered_public_key()
    );
}

/// Every issued code opens the wallet's seed, and only for its own wallet.
///
/// This is the recovery read side against a real ceremony's output: the codes
/// the run issued, the wraps it sealed, and the entry it wrote. The ceremony
/// derives each code's id as it seals; recovery derives the same id from the
/// code the user typed and finds the wrap by it, so the two cannot disagree
/// about which wrap a code opens.
#[test]
fn any_issued_recovery_code_opens_the_wallets_seed() {
    use signer_core::wallet_recovery_custody::{
        open_wallet_custody_seed_with_recovery_code_v1, WalletRecoveryManifestKekWrapV1,
    };

    let payload = establish_custody_with_evm_key_set();
    let records = custody_records(&payload);
    let codes = recovery_codes();

    let nonces: Vec<Vec<u8>> = records
        .recovery_manifest_kek_wraps
        .iter()
        .map(|wrap| decode(&wrap.nonce_b64u))
        .collect();
    let ciphertexts: Vec<Vec<u8>> = records
        .recovery_manifest_kek_wraps
        .iter()
        .map(|wrap| decode(&wrap.ciphertext_b64u))
        .collect();
    let wraps: Vec<WalletRecoveryManifestKekWrapV1<'_>> = records
        .recovery_manifest_kek_wraps
        .iter()
        .enumerate()
        .map(|(index, wrap)| WalletRecoveryManifestKekWrapV1 {
            recovery_key_id: &wrap.recovery_key_id,
            nonce: &nonces[index],
            ciphertext: &ciphertexts[index],
        })
        .collect();

    let entry_nonce = decode(&records.recovery_entry_nonce_b64u);
    let entry_ciphertext = decode(&records.recovery_entry_ciphertext_b64u);

    // All ten reach the same seed: losing nine codes still recovers the wallet.
    for code in &codes {
        let seed = open_wallet_custody_seed_with_recovery_code_v1(
            WALLET_ID,
            &code.code_bytes,
            &wraps,
            &entry_nonce,
            &entry_ciphertext,
        )
        .expect("recovery open")
        .expect("a wrap for this code");
        assert_eq!(seed.len(), 32);
    }

    // A code this wallet never issued finds no wrap — reported as "no such
    // code" rather than tried against every row.
    assert!(open_wallet_custody_seed_with_recovery_code_v1(
        WALLET_ID,
        &[0x9f; 20],
        &wraps,
        &entry_nonce,
        &entry_ciphertext,
    )
    .expect("recovery open")
    .is_none());

    // A real code against another wallet derives a different id, so it finds
    // nothing here either.
    assert!(open_wallet_custody_seed_with_recovery_code_v1(
        "mallory.testnet",
        &codes[0].code_bytes,
        &wraps,
        &entry_nonce,
        &entry_ciphertext,
    )
    .expect("recovery open")
    .is_none());
}
