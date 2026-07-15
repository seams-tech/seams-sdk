use router_ab_core::{
    EcdsaThresholdPrfRequestContextV1, EcdsaThresholdPrfRequestV1, EncryptedPayloadV1,
    ExpensiveWorkKindV1, LifecycleScopeV1, LocalServiceRoleV1, MpcPrfOutputRequestV1,
    OpenedShareKind, PublicDigest32, Role, RoleEncryptedEnvelopeV1, RootShareEpoch,
    RouterAbProtocolErrorCode, ServerIdentityV1, SignerIdentityV1, SignerSetV1,
    SigningWorkerActivationContextV1,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

fn lifecycle() -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch(),
        "account.near",
        "session-1",
        "signer-set-v1",
        "signing-worker-1",
    )
    .expect("lifecycle")
}

fn signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        SignerIdentityV1::new(Role::SignerA, "deriver-a", "deriver-a-key-epoch")
            .expect("deriver a"),
        SignerIdentityV1::new(Role::SignerB, "deriver-b", "deriver-b-key-epoch")
            .expect("deriver b"),
        ServerIdentityV1::new(
            "signing-worker-1",
            "signing-worker-key-epoch",
            "x25519:signing-worker-recipient-key",
        )
        .expect("signing worker"),
    )
    .expect("signer set")
}

fn envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(1)]).expect("ciphertext"),
    )
    .expect("role envelope")
}

fn transcript_digest() -> PublicDigest32 {
    EcdsaThresholdPrfRequestContextV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
    )
    .expect("request context")
    .derivation_transcript_digest()
    .expect("transcript digest")
}

fn threshold_prf_request() -> EcdsaThresholdPrfRequestV1 {
    EcdsaThresholdPrfRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest(),
        envelope(Role::SignerA, 0xa0),
        envelope(Role::SignerB, 0xb0),
    )
    .expect("public request")
}

#[test]
fn production_service_roles_match_router_ab_fv_role_set() {
    assert_eq!(LocalServiceRoleV1::Router.as_str(), "router");
    assert_eq!(LocalServiceRoleV1::DeriverA.as_str(), "deriver_a");
    assert_eq!(LocalServiceRoleV1::DeriverB.as_str(), "deriver_b");
    assert_eq!(LocalServiceRoleV1::SigningWorker.as_str(), "signing_worker");
}

#[test]
fn production_output_authorization_matches_fv_opened_value_model() {
    MpcPrfOutputRequestV1::new(OpenedShareKind::XClientBase, Role::Client, "client-1")
        .expect("client can open x_client_base");
    MpcPrfOutputRequestV1::new(
        OpenedShareKind::XServerBase,
        Role::Server,
        "signing-worker-1",
    )
    .expect("SigningWorker cryptographic output uses the x_server_base label");

    MpcPrfOutputRequestV1::new(OpenedShareKind::XClientBase, Role::Server, "server-1")
        .expect_err("server label cannot open x_client_base");
    MpcPrfOutputRequestV1::new(OpenedShareKind::XServerBase, Role::Client, "client-1")
        .expect_err("client cannot open x_server_base");
}

#[test]
fn signing_worker_activation_context_matches_public_transcript_state() {
    let request = threshold_prf_request();
    let (payload_a, payload_b) = request.to_signer_payloads().expect("signer payloads");
    let context_a = SigningWorkerActivationContextV1::from_router_payload(&payload_a)
        .expect("activation context from A payload");
    let context_b = SigningWorkerActivationContextV1::from_router_payload(&payload_b)
        .expect("activation context from B payload");
    let metadata = request
        .transcript_metadata()
        .expect("request transcript metadata");

    assert_ne!(payload_a.digest(), payload_b.digest());
    assert_eq!(context_a, context_b);
    assert_eq!(context_a.lifecycle(), &request.lifecycle);
    assert_eq!(context_a.signer_set(), &request.signer_set);
    assert_eq!(context_a.transcript_metadata(), &metadata);
    assert_eq!(context_a.transcript_digest(), request.transcript_digest);
}

#[test]
fn signing_worker_activation_context_rejects_digest_and_epoch_drift() {
    let request = threshold_prf_request();
    let (payload_a, _) = request.to_signer_payloads().expect("signer payloads");
    let context = SigningWorkerActivationContextV1::from_router_payload(&payload_a)
        .expect("activation context");

    let digest_err = SigningWorkerActivationContextV1::new(
        context.lifecycle.clone(),
        context.signer_set.clone(),
        context.transcript_metadata.clone(),
        digest(0xee),
    )
    .expect_err("tampered transcript digest rejected");
    assert_eq!(
        digest_err.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );

    let mut tampered_lifecycle = context.lifecycle.clone();
    tampered_lifecycle.root_share_epoch = RootShareEpoch::new("epoch-2").expect("epoch 2");
    let epoch_err = SigningWorkerActivationContextV1::new(
        tampered_lifecycle,
        context.signer_set,
        context.transcript_metadata,
        context.transcript_digest,
    )
    .expect_err("tampered root epoch rejected");
    assert_eq!(
        epoch_err.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );
}
