use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoOperationV1,
    Ed25519YaoPackageKindV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
    Ed25519YaoStateEpochV1, ExpensiveWorkKindV1, LifecycleScopeV1, RootShareEpoch,
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoActivationKeysetV1,
    RouterAbEd25519YaoActivationPublicReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoExportAdmissionReceiptV1,
    RouterAbEd25519YaoExportBindingV1, RouterAbEd25519YaoExportResultV1,
};
use router_ab_dev::{
    build_local_activation_deriver_a_v1, build_local_activation_deriver_b_v1,
    build_local_export_deriver_a_v1, build_local_export_deriver_b_v1,
    generate_local_ed25519_yao_recipient_key_pair_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1,
    open_local_ed25519_yao_export_deriver_a_input_v1,
    open_local_ed25519_yao_export_deriver_b_input_v1, run_local_export_deriver_a_http_v1,
    run_local_export_deriver_b_http_v1, seal_local_ed25519_yao_package_v1,
    LocalDeriverAWorkerConfigV1, LocalDeriverBWorkerConfigV1,
};
use router_ab_ed25519_yao::{
    relay::{
        derive_registration_receipt, ActivationPublicCommitments, DirectionalWireDecoder,
        DirectionalWireEncoder, RelayEvent, RelayStep, WireDirection, WireMessage, WireMessageKind,
    },
    stable_key_derivation_context_v1, ActivationDeriverA, ActivationDeriverB, ExportDeriverA,
    ExportDeriverB,
};
use router_ab_ed25519_yao_client::{
    complete_client_activation_v1, complete_client_export_v1, prepare_email_otp_client_export_v1,
    prepare_email_otp_client_registration_v1, prepare_passkey_client_export_v1,
    prepare_passkey_client_recovery_v1, prepare_passkey_client_registration_v1,
    ClientActivationEntropyV1, ClientActivationError, ClientActivationStateV1,
};

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

#[test]
fn client_registration_boundary_completes_real_a_b_circuit() {
    let activation = run_client_activation(ClientActivationTestCase::Registration {
        session_byte: 0x51,
        passkey_prf_first: [0x11; 32],
        entropy: activation_entropy(0x71),
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
fn same_root_recovery_preserves_the_exact_registered_public_key() {
    let passkey_prf_first = [0x21; 32];
    let registration = run_client_activation(ClientActivationTestCase::Registration {
        session_byte: 0x52,
        passkey_prf_first,
        entropy: activation_entropy(0x74),
    });
    let registered = complete_client_activation_v1(registration.state, &registration.result)
        .expect("registration activation");
    let registered_public_key = registered.registered_public_key();

    let recovery = run_client_activation(ClientActivationTestCase::Recovery {
        session_byte: 0x53,
        passkey_prf_first,
        expected_registered_public_key: registered_public_key,
        entropy: activation_entropy(0x77),
    });
    assert_eq!(
        recovery.result.public_receipt().registered_public_key(),
        registered_public_key
    );
    let recovered = complete_client_activation_v1(recovery.state, &recovery.result)
        .expect("same-root recovery activation");
    assert_eq!(recovered.registered_public_key(), registered_public_key);
    assert_eq!(recovered.state_epoch(), 2);
}

#[test]
fn different_root_recovery_is_rejected_by_public_key_continuity() {
    let registration = run_client_activation(ClientActivationTestCase::Registration {
        session_byte: 0x54,
        passkey_prf_first: [0x31; 32],
        entropy: activation_entropy(0x7a),
    });
    let registered = complete_client_activation_v1(registration.state, &registration.result)
        .expect("registration activation");
    let registered_public_key = registered.registered_public_key();

    let recovery = run_client_activation(ClientActivationTestCase::Recovery {
        session_byte: 0x55,
        passkey_prf_first: [0x32; 32],
        expected_registered_public_key: registered_public_key,
        entropy: activation_entropy(0x7d),
    });
    assert_ne!(
        recovery.result.public_receipt().registered_public_key(),
        registered_public_key
    );
    assert_eq!(
        complete_client_activation_v1(recovery.state, &recovery.result)
            .expect_err("different-root recovery must fail continuity"),
        ClientActivationError::PublicKeyContinuityMismatch
    );
}

#[test]
fn client_export_reconstructs_seed_matching_registered_public_key() {
    let passkey_prf_first = [0x41; 32];
    let registration = run_client_activation(ClientActivationTestCase::Registration {
        session_byte: 0x61,
        passkey_prf_first,
        entropy: activation_entropy(0x81),
    });
    let registered_public_key = registration.result.public_receipt().registered_public_key();
    let export = run_client_export(
        ClientExportFactor::PasskeyPrfFirst(passkey_prf_first),
        registered_public_key,
        0x62,
    );
    let seed = complete_client_export_v1(export.state, &export.result).expect("Client export");
    assert_eq!(
        signer_core::near_ed25519_recovery::expand_ed25519_seed(*seed.as_bytes()).public_key_bytes,
        registered_public_key
    );
}

#[test]
fn email_otp_client_export_reconstructs_seed_matching_registered_public_key() {
    let email_otp_factor = [0x44; 32];
    let registration = run_client_activation(ClientActivationTestCase::EmailOtpRegistration {
        session_byte: 0x65,
        email_otp_factor,
        entropy: activation_entropy(0x87),
    });
    let registered_public_key = registration.result.public_receipt().registered_public_key();
    let export = run_client_export(
        ClientExportFactor::EmailOtp(email_otp_factor),
        registered_public_key,
        0x66,
    );
    let seed = complete_client_export_v1(export.state, &export.result).expect("Client export");
    assert_eq!(
        signer_core::near_ed25519_recovery::expand_ed25519_seed(*seed.as_bytes()).public_key_bytes,
        registered_public_key
    );
}

#[test]
fn client_export_rejects_registered_public_key_substitution() {
    let export = run_client_export(
        ClientExportFactor::PasskeyPrfFirst([0x42; 32]),
        [0x99; 32],
        0x63,
    );
    assert_eq!(
        complete_client_export_v1(export.state, &export.result)
            .expect_err("substituted public key must fail"),
        ClientActivationError::PublicKeyContinuityMismatch
    );
}

#[test]
fn export_result_rejects_transcript_and_role_package_substitution() {
    let export = run_client_export(
        ClientExportFactor::PasskeyPrfFirst([0x43; 32]),
        [0x98; 32],
        0x64,
    );
    let binding = export.result.binding().clone();
    let transcript = export.result.transcript();
    let package_a = export.result.deriver_a_client_package().clone();
    let package_b = export.result.deriver_b_client_package().clone();
    let mut wrong_transcript = transcript;
    wrong_transcript[0] ^= 1;
    assert!(RouterAbEd25519YaoExportResultV1::new(
        binding.clone(),
        wrong_transcript,
        package_a.clone(),
        package_b.clone(),
    )
    .is_err());
    assert!(
        RouterAbEd25519YaoExportResultV1::new(binding, transcript, package_b, package_a,).is_err()
    );
}

struct ClientExportCircuitResult {
    state: router_ab_ed25519_yao_client::ClientExportStateV1,
    result: RouterAbEd25519YaoExportResultV1,
}

enum ClientExportFactor {
    PasskeyPrfFirst([u8; 32]),
    EmailOtp([u8; 32]),
}

fn run_client_export(
    factor: ClientExportFactor,
    registered_public_key: [u8; 32],
    session_byte: u8,
) -> ClientExportCircuitResult {
    let application = application();
    let participant_ids = [1, 2];
    let context = stable_key_derivation_context_v1(&application, participant_ids)
        .expect("stable derivation context");
    let ceremony = Ed25519YaoCeremonyBindingV1::new(
        lifecycle(ExpensiveWorkKindV1::KeyExport, session_byte),
        Ed25519YaoOperationV1::Export,
        Ed25519YaoSessionIdV1::new([session_byte; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(context.binding_digest()),
    )
    .expect("export ceremony");
    let binding = RouterAbEd25519YaoExportBindingV1::new(
        ceremony.clone(),
        registered_public_key,
        Ed25519YaoStateEpochV1::new(1).expect("state epoch"),
        [0x91; 32],
        [0x92; 32],
    )
    .expect("export binding");
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
    .expect("keyset");
    let admission = RouterAbEd25519YaoExportAdmissionReceiptV1::new(binding.clone(), keyset)
        .expect("export admission");
    let entropy_bytes = activation_entropy(0x84);
    let recipient_key_material = entropy_bytes.recipient_key_material;
    let entropy = ClientActivationEntropyV1::new(
        entropy_bytes.recipient_key_material,
        entropy_bytes.deriver_a_seal_seed,
        entropy_bytes.deriver_b_seal_seed,
    )
    .expect("export entropy");
    let prepared = match factor {
        ClientExportFactor::PasskeyPrfFirst(passkey_prf_first) => prepare_passkey_client_export_v1(
            &admission,
            &application,
            participant_ids,
            passkey_prf_first,
            entropy,
        ),
        ClientExportFactor::EmailOtp(email_otp_factor) => prepare_email_otp_client_export_v1(
            &admission,
            &application,
            participant_ids,
            email_otp_factor,
            entropy,
        ),
    }
    .expect("prepare export");
    let (execute, state) = prepared.into_parts();
    let request_a = open_local_ed25519_yao_export_deriver_a_input_v1(
        execute.deriver_a_input(),
        &deriver_a_recipient.private_key,
    )
    .expect("open export A");
    let request_b = open_local_ed25519_yao_export_deriver_b_input_v1(
        execute.deriver_b_input(),
        &deriver_b_recipient.private_key,
    )
    .expect("open export B");
    let (_, role_a) =
        build_local_export_deriver_a_v1(&deriver_a_config(), request_a).expect("build export A");
    let (_, role_b) =
        build_local_export_deriver_b_v1(&deriver_b_config(), request_b).expect("build export B");
    let (completion_a, completion_b) =
        run_export_roles(ceremony.session_id.into_bytes(), role_a, role_b);
    let transcript = completion_a.final_transcript();
    assert_eq!(transcript, completion_b.final_transcript());
    let client_public_key = derive_client_public_key(recipient_key_material);
    let package_a = seal_local_ed25519_yao_package_v1(
        router_ab_core::Ed25519YaoPackageKindV1::ExportClient,
        router_ab_core::Ed25519YaoDeriverRoleV1::DeriverA,
        ceremony.session_id.into_bytes(),
        transcript,
        client_public_key,
        completion_a.export_package().as_bytes(),
    )
    .expect("seal export A package");
    let package_b = seal_local_ed25519_yao_package_v1(
        router_ab_core::Ed25519YaoPackageKindV1::ExportClient,
        router_ab_core::Ed25519YaoDeriverRoleV1::DeriverB,
        ceremony.session_id.into_bytes(),
        transcript,
        client_public_key,
        completion_b.export_package().as_bytes(),
    )
    .expect("seal export B package");
    let result = RouterAbEd25519YaoExportResultV1::new(binding, transcript, package_a, package_b)
        .expect("export result");
    ClientExportCircuitResult { state, result }
}

#[derive(Clone, Copy)]
struct ActivationEntropyBytes {
    recipient_key_material: [u8; 32],
    deriver_a_seal_seed: [u8; 32],
    deriver_b_seal_seed: [u8; 32],
}

enum ClientActivationTestCase {
    Registration {
        session_byte: u8,
        passkey_prf_first: [u8; 32],
        entropy: ActivationEntropyBytes,
    },
    EmailOtpRegistration {
        session_byte: u8,
        email_otp_factor: [u8; 32],
        entropy: ActivationEntropyBytes,
    },
    Recovery {
        session_byte: u8,
        passkey_prf_first: [u8; 32],
        expected_registered_public_key: [u8; 32],
        entropy: ActivationEntropyBytes,
    },
}

struct ClientActivationCircuitResult {
    state: ClientActivationStateV1,
    result: RouterAbEd25519YaoActivationResultV1,
}

impl ClientActivationTestCase {
    fn operation(&self) -> Ed25519YaoOperationV1 {
        match self {
            Self::Registration { .. } | Self::EmailOtpRegistration { .. } => {
                Ed25519YaoOperationV1::Registration
            }
            Self::Recovery { .. } => Ed25519YaoOperationV1::Recovery,
        }
    }

    fn work_kind(&self) -> ExpensiveWorkKindV1 {
        match self {
            Self::Registration { .. } | Self::EmailOtpRegistration { .. } => {
                ExpensiveWorkKindV1::RegistrationPrepare
            }
            Self::Recovery { .. } => ExpensiveWorkKindV1::Recovery,
        }
    }

    fn state_epoch(&self) -> u64 {
        match self {
            Self::Registration { .. } | Self::EmailOtpRegistration { .. } => 1,
            Self::Recovery { .. } => 2,
        }
    }

    fn session_byte(&self) -> u8 {
        match self {
            Self::Registration { session_byte, .. }
            | Self::EmailOtpRegistration { session_byte, .. }
            | Self::Recovery { session_byte, .. } => *session_byte,
        }
    }

    fn entropy(&self) -> ActivationEntropyBytes {
        match self {
            Self::Registration { entropy, .. }
            | Self::EmailOtpRegistration { entropy, .. }
            | Self::Recovery { entropy, .. } => *entropy,
        }
    }
}

fn activation_entropy(first_byte: u8) -> ActivationEntropyBytes {
    ActivationEntropyBytes {
        recipient_key_material: [first_byte; 32],
        deriver_a_seal_seed: [first_byte + 1; 32],
        deriver_b_seal_seed: [first_byte + 2; 32],
    }
}

fn prepare_client_activation(
    case: &ClientActivationTestCase,
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> router_ab_ed25519_yao_client::PreparedClientActivationV1 {
    let entropy = case.entropy();
    let entropy = ClientActivationEntropyV1::new(
        entropy.recipient_key_material,
        entropy.deriver_a_seal_seed,
        entropy.deriver_b_seal_seed,
    )
    .expect("activation entropy");
    match case {
        ClientActivationTestCase::Registration {
            passkey_prf_first, ..
        } => prepare_passkey_client_registration_v1(
            admission,
            application,
            participant_ids,
            *passkey_prf_first,
            entropy,
        )
        .expect("prepare registration"),
        ClientActivationTestCase::EmailOtpRegistration {
            email_otp_factor, ..
        } => prepare_email_otp_client_registration_v1(
            admission,
            application,
            participant_ids,
            *email_otp_factor,
            entropy,
        )
        .expect("prepare Email OTP registration"),
        ClientActivationTestCase::Recovery {
            passkey_prf_first,
            expected_registered_public_key,
            ..
        } => prepare_passkey_client_recovery_v1(
            admission,
            application,
            participant_ids,
            *passkey_prf_first,
            *expected_registered_public_key,
            entropy,
        )
        .expect("prepare recovery"),
    }
}

fn run_client_activation(case: ClientActivationTestCase) -> ClientActivationCircuitResult {
    let application = application();
    let participant_ids = [1, 2];
    let context = stable_key_derivation_context_v1(&application, participant_ids)
        .expect("stable derivation context");
    let binding = Ed25519YaoCeremonyBindingV1::new(
        lifecycle(case.work_kind(), case.session_byte()),
        case.operation(),
        Ed25519YaoSessionIdV1::new([case.session_byte(); 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(context.binding_digest()),
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
    let recipient_key_material = case.entropy().recipient_key_material;
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
    assert_eq!(request_a.binding.operation, case.operation());
    assert_eq!(request_b.binding.operation, case.operation());
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
        Ed25519YaoStateEpochV1::new(case.state_epoch()).expect("state epoch"),
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
        root_share_storage_path: "/tmp/local-test-a-root".to_owned(),
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
        root_share_storage_path: "/tmp/local-test-b-root".to_owned(),
        sealed_root_shares_path: "/tmp/local-test-b-sealed".to_owned(),
    }
}

fn run_export_roles(
    session: [u8; 32],
    role_a: ExportDeriverA,
    role_b: ExportDeriverB,
) -> (
    router_ab_ed25519_yao::relay::ExportDeriverACompletion,
    router_ab_ed25519_yao::relay::ExportDeriverBCompletion,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("export listener");
    let address = listener.local_addr().expect("export listener address");
    let deriver_b = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept export A");
        run_local_export_deriver_b_http_v1(stream, session, "client-export-test", role_b)
            .expect("run export B")
    });
    let completion_a =
        run_local_export_deriver_a_http_v1(address, session, "client-export-test", role_a)
            .expect("run export A");
    let completion_b = deriver_b.join().expect("join export B");
    (completion_a, completion_b)
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
