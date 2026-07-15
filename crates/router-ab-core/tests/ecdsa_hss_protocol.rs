use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json,
    parse_router_ab_ecdsa_hss_deriver_envelope_plaintext_v1_json,
    parse_router_ab_ecdsa_hss_evm_digest_signing_finalize_request_v1_json,
    parse_router_ab_ecdsa_hss_evm_digest_signing_prepare_response_v1_json,
    parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json,
    parse_router_ab_ecdsa_hss_explicit_export_request_v1_json,
    parse_router_ab_ecdsa_hss_normal_signing_scope_v1_json,
    parse_router_ab_ecdsa_hss_recovery_request_v1_json,
    parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json,
    router_ab_ecdsa_hss_active_state_session_id_v1, EncryptedPayloadV1, ExpensiveWorkKindV1,
    LifecycleScopeV1, PublicDigest32, Role, RoleEncryptedEnvelopeV1, RootShareEpoch,
    RouterAbEcdsaHssActivationRefreshRequestV1, RouterAbEcdsaHssDeriverEnvelopePlaintextV1,
    RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1, RouterAbEcdsaHssEvmDigestSigningRequestV1,
    RouterAbEcdsaHssEvmDigestSigningResponseV1, RouterAbEcdsaHssExplicitExportRequestV1,
    RouterAbEcdsaHssNormalSigningScopeV1, RouterAbEcdsaHssOutputKindV1,
    RouterAbEcdsaHssPublicIdentityV1, RouterAbEcdsaHssRecoveryRequestV1,
    RouterAbEcdsaHssRegistrationBootstrapRequestV1, RouterAbEcdsaHssStableKeyContextV1,
    RouterAbProtocolErrorCode, ServerIdentityV1, SignerIdentityV1, SignerSetV1,
    ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1, ROUTER_AB_ECDSA_HSS_SECP256K1_PROTOCOL_VERSION_V1,
};
use sha2::{Digest, Sha256};

fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn digest_b64u(bytes: &[u8]) -> String {
    b64u(digest(bytes).as_bytes())
}

const ECDSA_HSS_WALLET_KEY_ID: &str = "wallet-key-1";
const ECDSA_HSS_WALLET_ID: &str = "wallet-1";
const ECDSA_HSS_THRESHOLD_KEY_ID: &str = "ecdsa-threshold-key-1";
const ECDSA_HSS_SIGNING_ROOT_ID: &str = "signing-root-1";
const ECDSA_HSS_SIGNING_ROOT_VERSION: &str = "root-v1";

fn context() -> RouterAbEcdsaHssStableKeyContextV1 {
    RouterAbEcdsaHssStableKeyContextV1::new(b64u(&[0x42; 32])).expect("context")
}

fn server_identity() -> ServerIdentityV1 {
    ServerIdentityV1::new("signing-worker-1", "worker-epoch-1", "x25519-public-key-1")
        .expect("server identity")
}

fn signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        "signer-set-1",
        SignerIdentityV1::new(Role::SignerA, "deriver-a-1", "deriver-a-epoch-1").expect("signer a"),
        SignerIdentityV1::new(Role::SignerB, "deriver-b-1", "deriver-b-epoch-1").expect("signer b"),
        server_identity(),
    )
    .expect("signer set")
}

fn lifecycle_at_epoch(
    work_kind: ExpensiveWorkKindV1,
    lifecycle_id: &str,
    activation_epoch: &str,
) -> LifecycleScopeV1 {
    let root_share_epoch = RootShareEpoch::new(activation_epoch).expect("root epoch");
    let session_id = router_ab_ecdsa_hss_active_state_session_id_v1(
        ECDSA_HSS_THRESHOLD_KEY_ID,
        ECDSA_HSS_SIGNING_ROOT_ID,
        ECDSA_HSS_SIGNING_ROOT_VERSION,
        root_share_epoch.as_str(),
    )
    .expect("ECDSA-HSS active state session id");
    LifecycleScopeV1::new(
        lifecycle_id,
        work_kind,
        root_share_epoch,
        ECDSA_HSS_WALLET_ID,
        session_id,
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("lifecycle")
}

fn lifecycle(work_kind: ExpensiveWorkKindV1, lifecycle_id: &str) -> LifecycleScopeV1 {
    lifecycle_at_epoch(work_kind, lifecycle_id, "root-epoch-1")
}

fn envelope(role: Role, label: &[u8]) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(&[label, b":header"].concat()),
        digest(&[label, b":aad"].concat()),
        EncryptedPayloadV1::new([label, b":ciphertext"].concat()).expect("ciphertext"),
    )
    .expect("envelope")
}

fn public_key33(prefix: u8, tail: u8) -> String {
    let mut bytes = [tail; 33];
    bytes[0] = prefix;
    b64u(&bytes)
}

fn public_identity() -> RouterAbEcdsaHssPublicIdentityV1 {
    let context = context();
    RouterAbEcdsaHssPublicIdentityV1::new(
        b64u(
            context
                .context_binding_digest()
                .expect("binding")
                .as_bytes(),
        ),
        public_key33(0x02, 0x11),
        public_key33(0x03, 0x22),
        public_key33(0x02, 0x33),
        b64u(&[0x44; 20]),
        0,
        1,
    )
    .expect("public identity")
}

fn registration_request() -> RouterAbEcdsaHssRegistrationBootstrapRequestV1 {
    RouterAbEcdsaHssRegistrationBootstrapRequestV1::new(
        context(),
        lifecycle(
            ExpensiveWorkKindV1::RegistrationPrepare,
            "ecdsa-registration-lifecycle-1",
        ),
        signer_set(),
        "router-1",
        "client-device-1",
        "client-ephemeral-public-key-1",
        "registration-nonce-1",
        1_900_000_000_000,
        public_key33(0x02, 0x11),
        0,
        envelope(Role::SignerA, b"a"),
        envelope(Role::SignerB, b"b"),
    )
    .expect("registration request")
}

fn export_request() -> RouterAbEcdsaHssExplicitExportRequestV1 {
    RouterAbEcdsaHssExplicitExportRequestV1 {
        context: context(),
        lifecycle: lifecycle(ExpensiveWorkKindV1::KeyExport, "ecdsa-export-lifecycle-1"),
        public_identity: public_identity(),
        signer_set: signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-device-1".to_owned(),
        client_ephemeral_public_key: "client-ephemeral-public-key-1".to_owned(),
        export_authorization_digest_b64u: digest_b64u(b"export authorization"),
        export_nonce: "export-nonce-1".to_owned(),
        expires_at_ms: 1_900_000_000_000,
        deriver_a_export_envelope: envelope(Role::SignerA, b"export-a"),
        deriver_b_export_envelope: envelope(Role::SignerB, b"export-b"),
    }
}

fn recovery_request() -> RouterAbEcdsaHssRecoveryRequestV1 {
    RouterAbEcdsaHssRecoveryRequestV1 {
        context: context(),
        lifecycle: lifecycle(ExpensiveWorkKindV1::Recovery, "ecdsa-recovery-lifecycle-1"),
        public_identity: public_identity(),
        signer_set: signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-device-1".to_owned(),
        client_ephemeral_public_key: "client-recovery-ephemeral-public-key-1".to_owned(),
        recovery_authorization_digest_b64u: digest_b64u(b"recovery authorization"),
        recovery_nonce: "recovery-nonce-1".to_owned(),
        expires_at_ms: 1_900_000_000_000,
        deriver_a_recovery_envelope: envelope(Role::SignerA, b"recovery-a"),
        deriver_b_recovery_envelope: envelope(Role::SignerB, b"recovery-b"),
    }
}

fn activation_refresh_request() -> RouterAbEcdsaHssActivationRefreshRequestV1 {
    RouterAbEcdsaHssActivationRefreshRequestV1 {
        context: context(),
        lifecycle: lifecycle_at_epoch(
            ExpensiveWorkKindV1::ServerShareRefresh,
            "ecdsa-refresh-lifecycle-1",
            "root-epoch-2",
        ),
        public_identity: public_identity(),
        signer_set: signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "operator-device-1".to_owned(),
        signing_worker_ephemeral_public_key: "signing-worker-refresh-ephemeral-key-1".to_owned(),
        refresh_authorization_digest_b64u: digest_b64u(b"refresh authorization"),
        refresh_nonce: "refresh-nonce-1".to_owned(),
        previous_activation_epoch: "root-epoch-1".to_owned(),
        next_activation_epoch: "root-epoch-2".to_owned(),
        expires_at_ms: 1_900_000_000_000,
        deriver_a_refresh_envelope: envelope(Role::SignerA, b"refresh-a"),
        deriver_b_refresh_envelope: envelope(Role::SignerB, b"refresh-b"),
    }
}

fn normal_signing_scope() -> RouterAbEcdsaHssNormalSigningScopeV1 {
    RouterAbEcdsaHssNormalSigningScopeV1::new(
        ECDSA_HSS_WALLET_KEY_ID,
        ECDSA_HSS_WALLET_ID,
        ECDSA_HSS_THRESHOLD_KEY_ID,
        ECDSA_HSS_SIGNING_ROOT_ID,
        ECDSA_HSS_SIGNING_ROOT_VERSION,
        context(),
        public_identity(),
        server_identity(),
        "root-epoch-1",
    )
    .expect("normal signing scope")
}

fn normal_signing_request() -> RouterAbEcdsaHssEvmDigestSigningRequestV1 {
    RouterAbEcdsaHssEvmDigestSigningRequestV1::new(
        normal_signing_scope(),
        "ecdsa-sign-request-1",
        "server-presignature-1",
        1_900_000_000_000,
        b64u(&[0x66; 32]),
    )
    .expect("normal signing request")
}

fn normal_signing_finalize_request() -> RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1 {
    RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1::new(
        normal_signing_scope(),
        "ecdsa-sign-request-1",
        1_900_000_000_000,
        b64u(&[0x66; 32]),
        "server-presignature-1",
        b64u(&[0x77; 32]),
    )
    .expect("normal signing finalize request")
}

fn normal_signing_prepare_response() -> RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1 {
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &normal_signing_request(),
        "server-presignature-1",
        public_key33(0x03, 0x99),
        b64u(&[0x55; 32]),
        1_800_000_000_000,
    )
    .expect("normal signing prepare response")
}

#[test]
fn ecdsa_hss_protocol_version_and_scope_are_frozen() {
    assert_eq!(
        ROUTER_AB_ECDSA_HSS_SECP256K1_PROTOCOL_VERSION_V1,
        "router_ab_ecdsa_hss_secp256k1_v1"
    );
    assert_eq!(ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1, "evm-family");
}

#[test]
fn ecdsa_hss_context_rejects_non_digest_binding() {
    let err = RouterAbEcdsaHssStableKeyContextV1::new(b64u(&[0x42; 31]))
        .expect_err("wrong digest length rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_registration_request_parses_strict_json() {
    let request = registration_request();
    let json = serde_json::to_vec(&request).expect("serialize");
    let parsed =
        parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json(&json).expect("parse");

    assert_eq!(
        parsed.request_digest().expect("digest"),
        request.request_digest().expect("digest")
    );
}

#[test]
fn ecdsa_hss_registration_request_rejects_unknown_json_fields() {
    let mut value = serde_json::to_value(registration_request()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_registration_request_rejects_swapped_deriver_envelope() {
    let err = RouterAbEcdsaHssRegistrationBootstrapRequestV1::new(
        context(),
        lifecycle(
            ExpensiveWorkKindV1::RegistrationPrepare,
            "ecdsa-registration-lifecycle-1",
        ),
        signer_set(),
        "router-1",
        "client-device-1",
        "client-ephemeral-public-key-1",
        "registration-nonce-1",
        1_900_000_000_000,
        public_key33(0x02, 0x11),
        0,
        envelope(Role::SignerB, b"wrong-a"),
        envelope(Role::SignerB, b"b"),
    )
    .expect_err("wrong role rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn ecdsa_hss_registration_request_builds_fixed_threshold_prf_request() {
    let request = registration_request();
    let public_request = request
        .to_threshold_prf_request()
        .expect("public router request");

    public_request
        .validate()
        .expect("generic request validates");
    assert_eq!(public_request.request_nonce, request.replay_nonce);
    assert_eq!(public_request.lifecycle, request.lifecycle);
    assert_eq!(public_request.signer_a_envelope, request.deriver_a_envelope);
    assert_eq!(public_request.signer_b_envelope, request.deriver_b_envelope);
}

#[test]
fn ecdsa_hss_deriver_registration_plaintext_binds_request_and_envelope() {
    let request = registration_request();
    let plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::registration_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_envelope.aad_digest,
    )
    .expect("registration plaintext");

    plaintext
        .validate_for_envelope(&request.deriver_a_envelope)
        .expect("plaintext binds envelope");
    assert_eq!(
        plaintext.output_kind(),
        RouterAbEcdsaHssOutputKindV1::SigningWorkerActivation
    );
    assert_eq!(
        plaintext.common().request_digest,
        request.request_digest().expect("request digest")
    );
    assert_eq!(plaintext.common().recipient_deriver, signer_set().signer_a);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_swapped_envelope() {
    let request = registration_request();
    let plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::registration_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_envelope.aad_digest,
    )
    .expect("registration plaintext");

    let err = plaintext
        .validate_for_envelope(&request.deriver_b_envelope)
        .expect_err("swapped envelope rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_aad_drift() {
    let request = registration_request();
    let plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::registration_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_envelope.aad_digest,
    )
    .expect("registration plaintext");
    let mut envelope = request.deriver_a_envelope.clone();
    envelope.aad_digest = digest(b"drifted aad");

    let err = plaintext
        .validate_for_envelope(&envelope)
        .expect_err("AAD drift rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_deriver_plaintext_parses_strict_json() {
    let request = export_request();
    let plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::export_for_request(
        &request,
        Role::SignerB,
        request.deriver_b_export_envelope.aad_digest,
    )
    .expect("export plaintext");
    let json = serde_json::to_vec(&plaintext).expect("serialize");
    let parsed =
        parse_router_ab_ecdsa_hss_deriver_envelope_plaintext_v1_json(&json).expect("parse");

    parsed
        .validate_for_envelope(&request.deriver_b_export_envelope)
        .expect("parsed plaintext binds envelope");
    assert_eq!(
        parsed.plaintext_digest().expect("parsed digest"),
        plaintext.plaintext_digest().expect("plaintext digest")
    );
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_unknown_json_fields() {
    let request = export_request();
    let plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::export_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_export_envelope.aad_digest,
    )
    .expect("export plaintext");
    let mut value = serde_json::to_value(plaintext).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_deriver_envelope_plaintext_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_wrong_output_kind() {
    let request = export_request();
    let mut plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::export_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_export_envelope.aad_digest,
    )
    .expect("export plaintext");
    match &mut plaintext {
        RouterAbEcdsaHssDeriverEnvelopePlaintextV1::ExplicitKeyExport(inner) => {
            inner.output_kind = RouterAbEcdsaHssOutputKindV1::SigningWorkerActivation;
        }
        _ => unreachable!("expected export plaintext"),
    }

    let err = plaintext.validate().expect_err("wrong output kind rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_wrong_work_kind() {
    let mut request = export_request();
    request.lifecycle = lifecycle(ExpensiveWorkKindV1::Recovery, "wrong-export-work-kind");

    let err = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::export_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_export_envelope.aad_digest,
    )
    .expect_err("wrong work kind rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_wrong_recipient_role() {
    let request = registration_request();

    let err = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::registration_for_request(
        &request,
        Role::Server,
        request.deriver_a_envelope.aad_digest,
    )
    .expect_err("non-Deriver recipient rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_wrong_signing_worker_identity() {
    let mut request = registration_request();
    request.lifecycle = LifecycleScopeV1::new(
        "wrong-signing-worker-lifecycle",
        ExpensiveWorkKindV1::RegistrationPrepare,
        RootShareEpoch::new("root-epoch-1").expect("root epoch"),
        ECDSA_HSS_WALLET_ID,
        router_ab_ecdsa_hss_active_state_session_id_v1(
            ECDSA_HSS_THRESHOLD_KEY_ID,
            ECDSA_HSS_SIGNING_ROOT_ID,
            ECDSA_HSS_SIGNING_ROOT_VERSION,
            "root-epoch-1",
        )
        .expect("session id"),
        "signer-set-1",
        "different-signing-worker",
    )
    .expect("lifecycle");

    let err = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::registration_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_envelope.aad_digest,
    )
    .expect_err("wrong SigningWorker rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_deriver_plaintext_rejects_wrong_deriver_identity() {
    let request = registration_request();
    let mut plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::registration_for_request(
        &request,
        Role::SignerA,
        request.deriver_a_envelope.aad_digest,
    )
    .expect("registration plaintext");

    match &mut plaintext {
        RouterAbEcdsaHssDeriverEnvelopePlaintextV1::RegistrationBootstrap(inner) => {
            inner.common.recipient_deriver =
                SignerIdentityV1::new(Role::SignerA, "different-deriver-a", "deriver-a-epoch-1")
                    .expect("wrong deriver identity");
        }
        _ => unreachable!("expected registration plaintext"),
    }

    let err = plaintext
        .validate()
        .expect_err("wrong Deriver identity rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn ecdsa_hss_deriver_plaintext_covers_recovery_and_refresh_branches() {
    let recovery = recovery_request();
    let recovery_plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::recovery_for_request(
        &recovery,
        Role::SignerA,
        recovery.deriver_a_recovery_envelope.aad_digest,
    )
    .expect("recovery plaintext");
    recovery_plaintext
        .validate_for_envelope(&recovery.deriver_a_recovery_envelope)
        .expect("recovery plaintext binds envelope");

    let refresh = activation_refresh_request();
    let refresh_plaintext = RouterAbEcdsaHssDeriverEnvelopePlaintextV1::refresh_for_request(
        &refresh,
        Role::SignerB,
        refresh.deriver_b_refresh_envelope.aad_digest,
    )
    .expect("refresh plaintext");
    refresh_plaintext
        .validate_for_envelope(&refresh.deriver_b_refresh_envelope)
        .expect("refresh plaintext binds envelope");

    assert_ne!(
        recovery_plaintext
            .plaintext_digest()
            .expect("recovery digest"),
        refresh_plaintext
            .plaintext_digest()
            .expect("refresh digest")
    );
}

#[test]
fn ecdsa_hss_public_identity_rejects_context_binding_mismatch() {
    let mut identity = public_identity();
    identity.context_binding_b64u = b64u(&[0x99; 32]);

    let err = identity
        .validate_for_context(&context())
        .expect_err("context mismatch rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_request_digests_bind_replay_nonces() {
    let registration = registration_request();
    let mut changed_registration = registration.clone();
    changed_registration.replay_nonce = "different-registration-nonce".to_owned();
    assert_ne!(
        changed_registration
            .request_digest()
            .expect("changed registration digest"),
        registration.request_digest().expect("registration digest")
    );

    let export = export_request();
    let mut changed_export = export.clone();
    changed_export.export_nonce = "different-export-nonce".to_owned();
    assert_ne!(
        changed_export
            .request_digest()
            .expect("changed export digest"),
        export.request_digest().expect("export digest")
    );

    let recovery = recovery_request();
    let mut changed_recovery = recovery.clone();
    changed_recovery.recovery_nonce = "different-recovery-nonce".to_owned();
    assert_ne!(
        changed_recovery
            .request_digest()
            .expect("changed recovery digest"),
        recovery.request_digest().expect("recovery digest")
    );

    let refresh = activation_refresh_request();
    let mut changed_refresh = refresh.clone();
    changed_refresh.refresh_nonce = "different-refresh-nonce".to_owned();
    assert_ne!(
        changed_refresh
            .request_digest()
            .expect("changed refresh digest"),
        refresh.request_digest().expect("refresh digest")
    );
}

#[test]
fn ecdsa_hss_export_request_parses_and_binds_public_identity() {
    let request = export_request();
    let json = serde_json::to_vec(&request).expect("serialize");
    let parsed = parse_router_ab_ecdsa_hss_explicit_export_request_v1_json(&json).expect("parse");

    assert_eq!(
        parsed.request_digest().expect("digest"),
        request.request_digest().expect("digest")
    );
}

#[test]
fn ecdsa_hss_export_request_builds_fixed_threshold_prf_request() {
    let request = export_request();
    let public_request = request
        .to_threshold_prf_request()
        .expect("public router request");

    public_request
        .validate()
        .expect("generic request validates");
    assert_eq!(public_request.request_nonce, request.export_nonce);
    assert_eq!(public_request.lifecycle, request.lifecycle);
    assert_eq!(
        public_request.signer_a_envelope,
        request.deriver_a_export_envelope
    );
    assert_eq!(
        public_request.signer_b_envelope,
        request.deriver_b_export_envelope
    );
}

#[test]
fn ecdsa_hss_export_request_rejects_bad_authorization_digest() {
    let mut request = export_request();
    request.export_authorization_digest_b64u = b64u(&[0x55; 31]);

    let err = request.validate().expect_err("bad digest rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_recovery_request_parses_and_uses_recovery_domain() {
    let request = recovery_request();
    let json = serde_json::to_vec(&request).expect("serialize");
    let parsed = parse_router_ab_ecdsa_hss_recovery_request_v1_json(&json).expect("parse");

    assert_eq!(
        parsed.request_digest().expect("digest"),
        request.request_digest().expect("digest")
    );
    assert_ne!(
        parsed.request_digest().expect("recovery digest"),
        export_request().request_digest().expect("export digest")
    );
}

#[test]
fn ecdsa_hss_recovery_request_rejects_wrong_lifecycle_kind() {
    let mut request = recovery_request();
    request.lifecycle = lifecycle(ExpensiveWorkKindV1::KeyExport, "wrong-recovery-lifecycle");

    let err = request
        .validate()
        .expect_err("wrong recovery lifecycle rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_recovery_request_rejects_swapped_deriver_envelope() {
    let mut request = recovery_request();
    request.deriver_a_recovery_envelope = envelope(Role::SignerB, b"wrong-recovery-a");

    let err = request
        .validate()
        .expect_err("wrong recovery envelope role rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn ecdsa_hss_recovery_request_rejects_unknown_json_fields() {
    let mut value = serde_json::to_value(recovery_request()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_recovery_request_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_recovery_request_builds_fixed_threshold_prf_request() {
    let request = recovery_request();
    let public_request = request
        .to_threshold_prf_request()
        .expect("public router request");

    public_request
        .validate()
        .expect("generic request validates");
    assert_eq!(public_request.request_nonce, request.recovery_nonce);
    assert_eq!(public_request.lifecycle, request.lifecycle);
    assert_eq!(
        public_request.signer_a_envelope,
        request.deriver_a_recovery_envelope
    );
    assert_eq!(
        public_request.signer_b_envelope,
        request.deriver_b_recovery_envelope
    );
}

#[test]
fn ecdsa_hss_activation_refresh_request_parses_and_binds_epoch_advance() {
    let request = activation_refresh_request();
    let json = serde_json::to_vec(&request).expect("serialize");
    let parsed =
        parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json(&json).expect("parse");

    assert_eq!(
        parsed.request_digest().expect("digest"),
        request.request_digest().expect("digest")
    );
    assert_eq!(parsed.previous_activation_epoch, "root-epoch-1");
    assert_eq!(parsed.next_activation_epoch, "root-epoch-2");
}

#[test]
fn ecdsa_hss_activation_refresh_request_rejects_same_activation_epoch() {
    let mut request = activation_refresh_request();
    request.next_activation_epoch = request.previous_activation_epoch.clone();

    let err = request
        .validate()
        .expect_err("same activation epoch rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_activation_refresh_request_rejects_wrong_lifecycle_kind() {
    let mut request = activation_refresh_request();
    request.lifecycle = lifecycle(ExpensiveWorkKindV1::RegistrationPrepare, "wrong-refresh");

    let err = request
        .validate()
        .expect_err("wrong refresh lifecycle rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_activation_refresh_request_rejects_unknown_json_fields() {
    let mut value = serde_json::to_value(activation_refresh_request()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_activation_refresh_request_builds_fixed_threshold_prf_request() {
    let request = activation_refresh_request();
    let public_request = request
        .to_threshold_prf_request()
        .expect("public router request");

    public_request
        .validate()
        .expect("generic request validates");
    assert_eq!(public_request.request_nonce, request.refresh_nonce);
    assert_eq!(public_request.lifecycle, request.lifecycle);
    assert_eq!(
        public_request.client_ephemeral_public_key,
        request.signing_worker_ephemeral_public_key
    );
    assert_eq!(
        public_request.signer_a_envelope,
        request.deriver_a_refresh_envelope
    );
    assert_eq!(
        public_request.signer_b_envelope,
        request.deriver_b_refresh_envelope
    );
}

#[test]
fn ecdsa_hss_normal_signing_scope_parses_and_binds_activation_identity() {
    let scope = normal_signing_scope();
    let json = serde_json::to_vec(&scope).expect("serialize");
    let parsed = parse_router_ab_ecdsa_hss_normal_signing_scope_v1_json(&json).expect("parse");

    assert_eq!(
        parsed.scope_digest().expect("digest"),
        scope.scope_digest().expect("digest")
    );
}

#[test]
fn ecdsa_hss_normal_signing_request_parses_and_binds_digest() {
    let request = normal_signing_request();
    let json = serde_json::to_vec(&request).expect("serialize");
    let parsed =
        parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json(&json).expect("parse");

    assert_eq!(
        parsed.request_digest().expect("digest"),
        request.request_digest().expect("digest")
    );
    assert_eq!(
        parsed.signing_digest().expect("signing digest"),
        PublicDigest32::new([0x66; 32])
    );
}

#[test]
fn ecdsa_hss_normal_signing_request_rejects_unknown_json_fields() {
    let mut value = serde_json::to_value(normal_signing_request()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_normal_signing_request_requires_client_presignature_id() {
    let mut value = serde_json::to_value(normal_signing_request()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .remove("client_presignature_id");

    let err = parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("missing client presignature id rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_normal_signing_request_rejects_bad_digest() {
    let mut request = normal_signing_request();
    request.signing_digest_b64u = b64u(&[0x66; 31]);

    let err = request.validate().expect_err("bad digest rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_normal_signing_request_rejects_expired_router_time() {
    let request = normal_signing_request();

    let err = request
        .validate_at(request.expires_at_ms)
        .expect_err("expired request rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn ecdsa_hss_prepare_response_parses_and_binds_request_digest() {
    let request = normal_signing_request();
    let response = normal_signing_prepare_response();
    let json = serde_json::to_vec(&response).expect("serialize");
    let parsed = parse_router_ab_ecdsa_hss_evm_digest_signing_prepare_response_v1_json(&json)
        .expect("parse");

    parsed
        .validate_for_request(&request)
        .expect("prepare response binds request");
    assert_eq!(
        parsed.request_digest,
        request.request_digest().expect("request digest")
    );
    assert_eq!(
        parsed.signing_digest,
        request.signing_digest().expect("signing digest")
    );
}

#[test]
fn ecdsa_hss_prepare_response_rejects_unknown_json_fields() {
    let mut value = serde_json::to_value(normal_signing_prepare_response()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_evm_digest_signing_prepare_response_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_prepare_response_rejects_bad_server_presignature_point() {
    let request = normal_signing_request();

    let err = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request,
        "server-presignature-1",
        b64u(&[0x99; 33]),
        b64u(&[0x55; 32]),
        1_800_000_000_000,
    )
    .expect_err("bad point rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_prepare_response_rejects_bad_rerandomization_entropy() {
    let request = normal_signing_request();

    let err = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request,
        "server-presignature-1",
        public_key33(0x03, 0x99),
        b64u(&[0x55; 31]),
        1_800_000_000_000,
    )
    .expect_err("bad entropy rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_prepare_response_rejects_request_drift() {
    let mut response = normal_signing_prepare_response();
    response.request_id = "different-request".to_owned();

    let err = response
        .validate_for_request(&normal_signing_request())
        .expect_err("request drift rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_prepare_response_rejects_presignature_id_drift() {
    let mut request = normal_signing_request();
    request.client_presignature_id = "different-presignature".to_owned();

    let err = normal_signing_prepare_response()
        .validate_for_request(&request)
        .expect_err("presignature id drift rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn ecdsa_hss_prepare_response_rejects_expired_response_time() {
    let request = normal_signing_request();

    let err = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request,
        "server-presignature-1",
        public_key33(0x03, 0x99),
        b64u(&[0x55; 32]),
        request.expires_at_ms,
    )
    .expect_err("expired response rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}

#[test]
fn ecdsa_hss_finalize_request_parses_and_binds_prepare_digest() {
    let request = normal_signing_finalize_request();
    let json = serde_json::to_vec(&request).expect("serialize");
    let parsed = parse_router_ab_ecdsa_hss_evm_digest_signing_finalize_request_v1_json(&json)
        .expect("parse");
    let prepare_request = normal_signing_request();

    assert_eq!(
        parsed.prepare_request_digest().expect("prepare digest"),
        prepare_request.request_digest().expect("prepare digest")
    );
    assert_eq!(
        parsed.signing_digest().expect("signing digest"),
        PublicDigest32::new([0x66; 32])
    );
    assert_eq!(
        parsed
            .client_signature_share32()
            .expect("client signature share"),
        [0x77; 32]
    );
}

#[test]
fn ecdsa_hss_finalize_request_rejects_unknown_json_fields() {
    let mut value = serde_json::to_value(normal_signing_finalize_request()).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .insert("legacy_v1".to_owned(), serde_json::json!(true));

    let err = parse_router_ab_ecdsa_hss_evm_digest_signing_finalize_request_v1_json(
        serde_json::to_string(&value).expect("json").as_bytes(),
    )
    .expect_err("unknown field rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_finalize_request_rejects_bad_client_signature_share() {
    let mut request = normal_signing_finalize_request();
    request.client_signature_share32_b64u = b64u(&[0x77; 31]);

    let err = request.validate().expect_err("bad client share rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_finalize_request_rejects_expired_router_time() {
    let request = normal_signing_finalize_request();

    let err = request
        .validate_at(request.expires_at_ms)
        .expect_err("expired finalize request rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn ecdsa_hss_evm_digest_signing_response_binds_request_digest() {
    let request = normal_signing_request();
    let response =
        RouterAbEcdsaHssEvmDigestSigningResponseV1::new_for_request(&request, b64u(&[0x88; 65]))
            .expect("signing response");

    response
        .validate_for_request(&request)
        .expect("response binds request");
    assert_eq!(
        response.request_digest,
        request.request_digest().expect("request digest")
    );
    assert_eq!(
        response.signing_digest,
        request.signing_digest().expect("signing digest")
    );
}

#[test]
fn ecdsa_hss_evm_digest_signing_response_rejects_bad_signature_length() {
    let request = normal_signing_request();

    let err =
        RouterAbEcdsaHssEvmDigestSigningResponseV1::new_for_request(&request, b64u(&[0x88; 64]))
            .expect_err("bad signature rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn ecdsa_hss_registration_request_rejects_expired_router_time() {
    let request = registration_request();

    let err = request
        .validate_at(request.expires_at_ms)
        .expect_err("expired request rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}
