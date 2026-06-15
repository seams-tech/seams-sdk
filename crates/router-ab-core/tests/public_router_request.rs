use router_ab_core::{
    role_encrypted_envelope_digest_v1, CandidateId, EncryptedPayloadV1, ExpensiveWorkKindV1,
    LifecycleScopeV1, PublicDigest32, PublicRouterRequestContextV1, PublicRouterRequestV1, Role,
    RoleEncryptedEnvelopeV1, RootShareEpoch, RouterAbProtocolErrorCode, ServerIdentityV1,
    SignerIdentityV1, SignerSetV1, WireMessageKindV1,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn lifecycle() -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        RootShareEpoch::new("epoch-1").expect("root epoch"),
        "account.near",
        "session-1",
        "signer-set-v1",
        "server-a",
    )
    .expect("lifecycle")
}

fn signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        SignerIdentityV1::new(Role::SignerA, "signer-a", "key-epoch-a").expect("signer a"),
        SignerIdentityV1::new(Role::SignerB, "signer-b", "key-epoch-b").expect("signer b"),
        ServerIdentityV1::new(
            "server-a",
            "server-epoch",
            "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("server"),
    )
    .expect("signer set")
}

fn envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed + 1),
        EncryptedPayloadV1::new(vec![seed, seed + 1]).expect("ciphertext"),
    )
    .expect("envelope")
}

fn transcript_digest() -> PublicDigest32 {
    PublicRouterRequestContextV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
    )
    .expect("request context")
    .derivation_transcript_digest()
    .expect("derivation transcript digest")
}

fn public_request() -> PublicRouterRequestV1 {
    PublicRouterRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest(),
        envelope(Role::SignerA, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect("public request")
}

#[test]
fn public_router_request_builds_router_to_signer_wire_messages() {
    let request = public_request();
    let digest = request.router_replay_digest();
    let context_digest = request
        .request_context_digest()
        .expect("request context digest");
    let (to_a, to_b) = request.to_signer_wire_messages().expect("wire messages");

    assert_ne!(digest, request.transcript_digest);
    assert_ne!(context_digest, request.transcript_digest);
    assert_ne!(context_digest, digest);
    assert_eq!(to_a.kind, WireMessageKindV1::RouterToSignerA);
    assert_eq!(to_b.kind, WireMessageKindV1::RouterToSignerB);
    assert_eq!(to_a.transcript_digest, request.transcript_digest);
    assert_eq!(to_b.transcript_digest, request.transcript_digest);
    let metadata = request.transcript_metadata().expect("transcript metadata");
    let envelope_digest_set = request.envelope_digest_set().expect("envelope digest set");
    assert_eq!(
        metadata.client_ephemeral_public_key,
        "x25519:client-ephemeral-public-key"
    );
    assert_eq!(
        envelope_digest_set.signer_a_envelope_digest,
        role_encrypted_envelope_digest_v1(&request.signer_a_envelope).expect("signer a hash")
    );
    assert_eq!(
        envelope_digest_set.signer_b_envelope_digest,
        role_encrypted_envelope_digest_v1(&request.signer_b_envelope).expect("signer b hash")
    );
    assert!(!to_a.payload.as_bytes().is_empty());
    assert!(!to_b.payload.as_bytes().is_empty());
}

#[test]
fn public_router_request_context_digest_excludes_envelopes_and_transcript_digest() {
    let request = public_request();
    let context_digest = request
        .request_context_digest()
        .expect("request context digest");
    let replay_digest = request.router_replay_digest();
    let mut changed = request.clone();
    changed.transcript_digest = digest(0x99);
    changed.signer_a_envelope = envelope(Role::SignerA, 0x70);
    changed.signer_b_envelope = envelope(Role::SignerB, 0x80);

    assert_eq!(
        changed
            .request_context_digest()
            .expect("changed context digest"),
        context_digest
    );
    assert_ne!(changed.router_replay_digest(), replay_digest);
}

#[test]
fn public_router_request_context_digest_binds_public_context() {
    let request = public_request();
    let context_digest = request
        .request_context_digest()
        .expect("request context digest");
    let mut changed = request.clone();
    changed.client_ephemeral_public_key = "x25519:other-client-key".to_owned();

    assert_ne!(
        changed
            .request_context_digest()
            .expect("changed context digest"),
        context_digest
    );
}

#[test]
fn public_router_request_rejects_transcript_digest_mismatch() {
    let err = PublicRouterRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        digest(0x33),
        envelope(Role::SignerA, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect_err("transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn public_router_request_rejects_wrong_role_envelope() {
    let err = PublicRouterRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest(),
        envelope(Role::SignerB, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect_err("signer a envelope role must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn public_router_request_rejects_lifecycle_signer_set_mismatch() {
    let mut lifecycle = lifecycle();
    lifecycle.signer_set_id = "other-signer-set".to_owned();
    let err = PublicRouterRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        digest(0x33),
        envelope(Role::SignerA, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect_err("signer set mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn public_router_request_rejects_expired_request() {
    let request = public_request();
    let err = request
        .validate_at(2_000)
        .expect_err("request expiring at current time must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn public_router_request_rejects_empty_nonce() {
    let err = PublicRouterRequestV1::new(
        "",
        2_000,
        lifecycle(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        digest(0x33),
        envelope(Role::SignerA, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect_err("empty nonce must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn public_router_request_rejects_empty_client_ephemeral_key() {
    let err = PublicRouterRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "",
        digest(0x33),
        envelope(Role::SignerA, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect_err("empty client ephemeral key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn public_router_request_rejects_derivation_downgrade() {
    let err = PublicRouterRequestV1::new(
        "nonce-1",
        2_000,
        lifecycle(),
        CandidateId::SplitRootDerivationV1,
        signer_set(),
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        digest(0x33),
        envelope(Role::SignerA, 0x10),
        envelope(Role::SignerB, 0x20),
    )
    .expect_err("unsupported derivation candidate must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::DowngradeRejected);
}
