use router_ab_core::{
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    decode_relayer_activation_payload_v1, decode_signer_response_payload_v1,
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    router_transcript_digest_v1, validate_local_env_keys_v1, verify_client_output_package_v1,
    verify_relayer_output_package_v1, AbDerivationProofBatchPayloadV1, CanonicalWireBytesV1,
    EncryptedPayloadV1, ExpensiveWorkKindV1, LifecycleScopeV1, LocalClientRouterRequestV1,
    LocalDeterministicSignerEnvelopeDecryptorV1, LocalEnvSnapshotV1, LocalHttpMethodV1,
    LocalHttpPathV1, LocalHttpRequestV1, LocalHttpStatusV1, LocalPersistenceSeedV1,
    LocalPersistenceSqlDialectV1, LocalPersistenceSqlSeedExecutorV1,
    LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1, LocalReplayCacheV1,
    LocalRouterEndpointV1, LocalRouterServiceV1, LocalSealedRootShareRecordV1,
    LocalServiceEndpointV1, LocalServiceRoleV1, LocalServiceStackV1, LocalServiceStartupV1,
    LocalSignerARelayerEndpointV1, LocalSignerARelayerServiceV1, LocalSignerBEndpointV1,
    LocalSignerBServiceV1, LocalSignerEnvelopeDecryptorV1, LocalSignerHandlerContextV1,
    LocalSignerHandlerOutputV1, LocalSigningRootMetadataV1, LocalTransportEnvelopeV1,
    LocalTransportRouteV1, PublicRouterRequestV1, RelayerActivationPayloadV1, RelayerIdentityV1,
    RoleEncryptedEnvelopeV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterTranscriptMetadataV1, SignerIdentityV1, SignerResponsePayloadV1,
    SignerSetV1, WireMessageKindV1, WireMessageV1,
};
use router_ab_core::{
    CandidateId, CorrectnessLevel, OpenedShareKind, PublicDigest32, Role, RootShareEpoch,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn wire(kind: WireMessageKindV1) -> WireMessageV1 {
    wire_with_digest(kind, local_valid_transcript_digest())
}

fn transport(route: LocalTransportRouteV1, kind: WireMessageKindV1) -> LocalTransportEnvelopeV1 {
    LocalTransportEnvelopeV1::new(route, wire(kind)).expect("transport envelope")
}

fn http_request(
    path: LocalHttpPathV1,
    route: LocalTransportRouteV1,
    kind: WireMessageKindV1,
) -> LocalHttpRequestV1 {
    LocalHttpRequestV1::new(LocalHttpMethodV1::Post, path, transport(route, kind))
        .expect("http request")
}

fn http_request_with_digest(
    path: LocalHttpPathV1,
    route: LocalTransportRouteV1,
    kind: WireMessageKindV1,
    transcript_digest: PublicDigest32,
) -> LocalHttpRequestV1 {
    let envelope = LocalTransportEnvelopeV1::new(route, wire_with_digest(kind, transcript_digest))
        .expect("transport envelope");
    LocalHttpRequestV1::new(LocalHttpMethodV1::Post, path, envelope).expect("http request")
}

fn client_router_request() -> LocalClientRouterRequestV1 {
    LocalClientRouterRequestV1::new(
        "lifecycle-1",
        "request-nonce-1",
        2_000,
        http_request(
            LocalHttpPathV1::RouterToSignerA,
            LocalTransportRouteV1::RouterToSignerA,
            WireMessageKindV1::RouterToSignerA,
        ),
        http_request(
            LocalHttpPathV1::RouterToSignerB,
            LocalTransportRouteV1::RouterToSignerB,
            WireMessageKindV1::RouterToSignerB,
        ),
    )
    .expect("client router request")
}

fn wire_with_digest(kind: WireMessageKindV1, transcript_digest: PublicDigest32) -> WireMessageV1 {
    if matches!(
        kind,
        WireMessageKindV1::RouterToSignerA | WireMessageKindV1::RouterToSignerB
    ) {
        return router_to_signer_wire(kind, transcript_digest);
    }
    WireMessageV1::new(
        kind,
        transcript_digest,
        CanonicalWireBytesV1::new(vec![0xab]).expect("payload"),
    )
    .expect("wire message")
}

fn malformed_router_to_signer_wire(
    kind: WireMessageKindV1,
    transcript_digest: PublicDigest32,
) -> WireMessageV1 {
    WireMessageV1::new(
        kind,
        transcript_digest,
        CanonicalWireBytesV1::new(b"opaque malformed signer payload".to_vec())
            .expect("opaque payload"),
    )
    .expect("wire message")
}

fn decode_local_peer_proof_batch(
    envelope: &LocalTransportEnvelopeV1,
) -> AbDerivationProofBatchPayloadV1 {
    let peer_payload = decode_ab_peer_message_payload_v1(envelope.message.payload.as_bytes())
        .expect("peer payload decodes");
    assert_eq!(
        peer_payload.transcript_digest,
        envelope.message.transcript_digest
    );
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)
        .expect("proof batch validates")
}

fn decode_local_signer_response(envelope: &LocalTransportEnvelopeV1) -> SignerResponsePayloadV1 {
    assert_eq!(
        envelope.route.expected_wire_kind(),
        WireMessageKindV1::SignerResponse
    );
    decode_signer_response_payload_v1(envelope.message.payload.as_bytes())
        .expect("signer response decodes")
}

fn decode_local_relayer_activation(
    envelope: &LocalTransportEnvelopeV1,
) -> RelayerActivationPayloadV1 {
    assert_eq!(
        envelope.route.expected_wire_kind(),
        WireMessageKindV1::RelayerActivation
    );
    decode_relayer_activation_payload_v1(envelope.message.payload.as_bytes())
        .expect("relayer activation decodes")
}

fn router_to_signer_wire(
    kind: WireMessageKindV1,
    transcript_digest: PublicDigest32,
) -> WireMessageV1 {
    let request = public_router_request();
    let (signer_a, signer_b) = request
        .to_signer_wire_messages()
        .expect("router-to-signer messages");
    let mut message = match kind {
        WireMessageKindV1::RouterToSignerA => signer_a,
        WireMessageKindV1::RouterToSignerB => signer_b,
        _ => panic!("test helper requires Router-to-signer kind"),
    };
    message.transcript_digest = transcript_digest;
    message
}

fn public_router_request() -> PublicRouterRequestV1 {
    PublicRouterRequestV1::new(
        "request-nonce-1",
        2_000,
        lifecycle_scope(),
        CandidateId::MpcThresholdPrfV1,
        signer_set(),
        "near-testnet",
        "ed25519:local-dev-account-public-key",
        "local-router",
        "client",
        "x25519:local-dev-client-ephemeral-public-key",
        local_valid_transcript_digest(),
        role_envelope(Role::SignerA, 0xa0),
        role_envelope(Role::SignerB, 0xb0),
    )
    .expect("public router request")
}

fn local_valid_transcript_digest() -> PublicDigest32 {
    router_transcript_digest_v1(
        &lifecycle_scope(),
        &signer_set(),
        &transcript_metadata(),
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_epoch(),
    )
    .expect("local transcript digest")
}

fn transcript_metadata() -> RouterTranscriptMetadataV1 {
    RouterTranscriptMetadataV1::new(
        "near-testnet",
        "ed25519:local-dev-account-public-key",
        "local-router",
        "client",
        "x25519:local-dev-client-ephemeral-public-key",
    )
    .expect("transcript metadata")
}

fn lifecycle_scope() -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch(),
        "alice.testnet",
        "session-1",
        "signer-set-v1",
        "relayer-a",
    )
    .expect("lifecycle scope")
}

fn signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        signer_a_identity(),
        signer_b_identity(),
        relayer_identity(),
    )
    .expect("signer set")
}

fn role_envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(2)]).expect("ciphertext"),
    )
    .expect("role envelope")
}

fn router_endpoint() -> LocalRouterEndpointV1 {
    LocalRouterEndpointV1::new(
        "http://127.0.0.1:8787",
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
    )
    .expect("router endpoint")
}

fn signer_a_endpoint() -> LocalSignerARelayerEndpointV1 {
    LocalSignerARelayerEndpointV1::new(
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
        "local-relayer-output",
    )
    .expect("signer a endpoint")
}

fn signer_b_endpoint() -> LocalSignerBEndpointV1 {
    LocalSignerBEndpointV1::new("http://127.0.0.1:8789", "http://127.0.0.1:8788")
        .expect("signer b endpoint")
}

fn signer_a_identity() -> SignerIdentityV1 {
    SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a").expect("signer a")
}

fn signer_b_identity() -> SignerIdentityV1 {
    SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b").expect("signer b")
}

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

fn relayer_identity() -> RelayerIdentityV1 {
    RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer")
}

fn local_router_request_digest() -> PublicDigest32 {
    digest(0x44)
}

fn signer_a_context() -> LocalSignerHandlerContextV1 {
    LocalSignerHandlerContextV1::new(
        "lifecycle-1",
        local_router_request_digest(),
        root_epoch(),
        signer_b_identity(),
        relayer_identity(),
    )
    .expect("signer a context")
}

fn signer_b_context() -> LocalSignerHandlerContextV1 {
    LocalSignerHandlerContextV1::new(
        "lifecycle-1",
        local_router_request_digest(),
        root_epoch(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer b context")
}

fn signing_root_metadata() -> LocalSigningRootMetadataV1 {
    LocalSigningRootMetadataV1::new(
        "signer-set-v1",
        "signing-root-v1",
        root_epoch(),
        "alice.testnet",
    )
    .expect("root metadata")
}

fn sealed_share_record(role: Role) -> LocalSealedRootShareRecordV1 {
    let (signer, storage_key, commitment_seed) = match role {
        Role::SignerA => (signer_a_identity(), "sealed/share/a", 0xa1),
        Role::SignerB => (signer_b_identity(), "sealed/share/b", 0xb1),
        _ => panic!("test helper requires signer role"),
    };
    LocalSealedRootShareRecordV1::new(
        "signer-set-v1",
        signer,
        root_epoch(),
        storage_key,
        digest(commitment_seed),
        33,
    )
    .expect("sealed share")
}

fn local_persistence_seed() -> LocalPersistenceSeedV1 {
    LocalPersistenceSeedV1::new(
        signing_root_metadata(),
        sealed_share_record(Role::SignerA),
        sealed_share_record(Role::SignerB),
    )
    .expect("local persistence seed")
}

#[derive(Default)]
struct RecordingSqlExecutor {
    calls: Vec<(
        LocalPersistenceSqlDialectV1,
        u32,
        LocalPersistenceSqlStatementV1,
    )>,
}

impl LocalPersistenceSqlSeedExecutorV1 for RecordingSqlExecutor {
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        dialect: LocalPersistenceSqlDialectV1,
        statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()> {
        self.calls
            .push((dialect, statement_index, statement.clone()));
        Ok(())
    }
}

#[derive(Default)]
struct FailingSqlExecutor {
    calls: Vec<u32>,
}

impl LocalPersistenceSqlSeedExecutorV1 for FailingSqlExecutor {
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        _dialect: LocalPersistenceSqlDialectV1,
        statement_index: u32,
        _statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()> {
        self.calls.push(statement_index);
        if statement_index == 1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "injected local SQL failure",
            ));
        }
        Ok(())
    }
}

fn router_env_snapshot() -> LocalEnvSnapshotV1 {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::Router,
        vec![
            "ROUTER_PUBLIC_URL".to_owned(),
            "SIGNER_A_URL".to_owned(),
            "SIGNER_B_URL".to_owned(),
        ],
    )
    .expect("router env snapshot")
}

fn signer_a_env_snapshot() -> LocalEnvSnapshotV1 {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SignerARelayer,
        vec![
            "SIGNER_A_ENVELOPE_AEAD_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "RELAYER_OUTPUT_STORAGE".to_owned(),
            "SIGNER_B_URL".to_owned(),
        ],
    )
    .expect("signer a env snapshot")
}

fn signer_b_env_snapshot() -> LocalEnvSnapshotV1 {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SignerB,
        vec![
            "SIGNER_B_ENVELOPE_AEAD_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "SIGNER_A_URL".to_owned(),
        ],
    )
    .expect("signer b env snapshot")
}

#[test]
fn local_service_endpoint_preserves_role_branch() {
    let router = LocalServiceEndpointV1::router(router_endpoint()).expect("router service");
    assert_eq!(router.role(), LocalServiceRoleV1::Router);

    let signer_a =
        LocalServiceEndpointV1::signer_a_relayer(signer_a_endpoint()).expect("signer a service");
    assert_eq!(signer_a.role(), LocalServiceRoleV1::SignerARelayer);

    let signer_b = LocalServiceEndpointV1::signer_b(signer_b_endpoint()).expect("signer b service");
    assert_eq!(signer_b.role(), LocalServiceRoleV1::SignerB);
}

#[test]
fn local_router_endpoint_requires_all_routing_urls() {
    let err = LocalRouterEndpointV1::new("http://127.0.0.1:8787", "", "http://127.0.0.1:8789")
        .expect_err("missing signer a url must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn local_router_env_keys_forbid_signer_and_relayer_secrets() {
    let err = validate_local_env_keys_v1(
        LocalServiceRoleV1::Router,
        &[
            "ROUTER_PUBLIC_URL",
            "SIGNER_A_URL",
            "SIGNER_B_URL",
            "SIGNER_A_ENVELOPE_AEAD_KEY",
        ],
    )
    .expect_err("router must reject signer decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_signer_a_relayer_env_keys_require_a_and_relayer_bindings() {
    validate_local_env_keys_v1(
        LocalServiceRoleV1::SignerARelayer,
        &[
            "SIGNER_A_ENVELOPE_AEAD_KEY",
            "SIGNING_ROOT_SHARE_A_KEK",
            "RELAYER_OUTPUT_STORAGE",
            "SIGNER_B_URL",
        ],
    )
    .expect("signer a relayer bindings");

    let err = validate_local_env_keys_v1(
        LocalServiceRoleV1::SignerARelayer,
        &["SIGNER_A_ENVELOPE_AEAD_KEY", "SIGNING_ROOT_SHARE_A_KEK"],
    )
    .expect_err("missing relayer storage must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn local_signer_a_relayer_env_keys_forbid_b_material() {
    let err = validate_local_env_keys_v1(
        LocalServiceRoleV1::SignerARelayer,
        &[
            "SIGNER_A_ENVELOPE_AEAD_KEY",
            "SIGNING_ROOT_SHARE_A_KEK",
            "RELAYER_OUTPUT_STORAGE",
            "SIGNER_B_ENVELOPE_AEAD_KEY",
        ],
    )
    .expect_err("signer a relayer must reject signer b material");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_signer_b_env_keys_forbid_relayer_activation_storage() {
    let err = validate_local_env_keys_v1(
        LocalServiceRoleV1::SignerB,
        &[
            "SIGNER_B_ENVELOPE_AEAD_KEY",
            "SIGNING_ROOT_SHARE_B_KEK",
            "RELAYER_OUTPUT_STORAGE",
        ],
    )
    .expect_err("signer b must reject relayer storage");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_env_snapshot_validates_binding_keys_for_role() {
    let snapshot = LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SignerARelayer,
        vec![
            "SIGNER_A_ENVELOPE_AEAD_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "RELAYER_OUTPUT_STORAGE".to_owned(),
            "SIGNER_B_URL".to_owned(),
        ],
    )
    .expect("signer a env snapshot");

    assert_eq!(snapshot.role, LocalServiceRoleV1::SignerARelayer);
}

#[test]
fn local_env_snapshot_rejects_empty_binding_names() {
    let err = LocalEnvSnapshotV1::new(LocalServiceRoleV1::Router, vec!["".to_owned()])
        .expect_err("empty binding key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn local_env_snapshot_rejects_role_forbidden_bindings() {
    let err = LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SignerB,
        vec![
            "SIGNER_B_ENVELOPE_AEAD_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "RELAYER_OUTPUT_STORAGE".to_owned(),
        ],
    )
    .expect_err("signer b env snapshot must reject relayer storage");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_persistence_seed_accepts_matching_root_metadata_and_sealed_shares() {
    let seed = LocalPersistenceSeedV1::new(
        signing_root_metadata(),
        sealed_share_record(Role::SignerA),
        sealed_share_record(Role::SignerB),
    )
    .expect("local persistence seed");

    assert_eq!(seed.root_metadata.signer_set_id, "signer-set-v1");
    assert_eq!(seed.signer_a_share.signer.role, Role::SignerA);
    assert_eq!(seed.signer_b_share.signer.role, Role::SignerB);
}

#[test]
fn local_persistence_seed_rejects_wrong_share_role() {
    let err = LocalPersistenceSeedV1::new(
        signing_root_metadata(),
        sealed_share_record(Role::SignerB),
        sealed_share_record(Role::SignerB),
    )
    .expect_err("wrong signer a share role must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn local_persistence_seed_rejects_epoch_mismatch() {
    let mut signer_a_share = sealed_share_record(Role::SignerA);
    signer_a_share.root_share_epoch = RootShareEpoch::new("epoch-2").expect("epoch 2");

    let err = LocalPersistenceSeedV1::new(
        signing_root_metadata(),
        signer_a_share,
        sealed_share_record(Role::SignerB),
    )
    .expect_err("epoch mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn local_persistence_seed_rejects_empty_sealed_share() {
    let err = LocalSealedRootShareRecordV1::new(
        "signer-set-v1",
        signer_a_identity(),
        root_epoch(),
        "sealed/share/a",
        digest(0xa1),
        0,
    )
    .expect_err("empty sealed share must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn local_persistence_seed_sql_plan_generates_postgres_statements() {
    let plan = local_persistence_seed_sql_plan_v1(
        &local_persistence_seed(),
        LocalPersistenceSqlDialectV1::Postgres,
    )
    .expect("postgres seed plan");

    assert_eq!(plan.dialect, LocalPersistenceSqlDialectV1::Postgres);
    assert_eq!(plan.statements.len(), 3);

    let root_statement = &plan.statements[0];
    assert!(root_statement.sql.contains("local_signing_roots"));
    assert!(root_statement.sql.contains("VALUES ($1, $2, $3, $4)"));
    assert!(root_statement
        .sql
        .contains("ON CONFLICT (signer_set_id, root_share_epoch)"));
    assert_eq!(
        root_statement.values,
        vec![
            LocalPersistenceSqlValueV1::Text("signer-set-v1".to_owned()),
            LocalPersistenceSqlValueV1::Text("signing-root-v1".to_owned()),
            LocalPersistenceSqlValueV1::Text("epoch-1".to_owned()),
            LocalPersistenceSqlValueV1::Text("alice.testnet".to_owned()),
        ]
    );

    let signer_a_statement = &plan.statements[1];
    assert!(signer_a_statement.sql.contains("local_sealed_root_shares"));
    assert!(signer_a_statement.sql.contains("$8"));
    assert_eq!(signer_a_statement.values.len(), 8);
    assert_eq!(
        signer_a_statement.values[1],
        LocalPersistenceSqlValueV1::Text("signer_a".to_owned())
    );
    assert_eq!(
        signer_a_statement.values[2],
        LocalPersistenceSqlValueV1::Text("signer-a".to_owned())
    );
    assert_eq!(
        signer_a_statement.values[3],
        LocalPersistenceSqlValueV1::Text("epoch-a".to_owned())
    );
    assert_eq!(
        signer_a_statement.values[6],
        LocalPersistenceSqlValueV1::Text("a1".repeat(32))
    );
    assert_eq!(
        signer_a_statement.values[7],
        LocalPersistenceSqlValueV1::U32(33)
    );

    let signer_b_statement = &plan.statements[2];
    assert_eq!(
        signer_b_statement.values[1],
        LocalPersistenceSqlValueV1::Text("signer_b".to_owned())
    );
    assert_eq!(
        signer_b_statement.values[6],
        LocalPersistenceSqlValueV1::Text("b1".repeat(32))
    );
}

#[test]
fn local_persistence_seed_sql_plan_generates_sqlite_placeholders() {
    let plan = local_persistence_seed_sql_plan_v1(
        &local_persistence_seed(),
        LocalPersistenceSqlDialectV1::Sqlite,
    )
    .expect("sqlite seed plan");

    assert_eq!(plan.dialect, LocalPersistenceSqlDialectV1::Sqlite);
    assert_eq!(plan.statements.len(), 3);
    assert!(plan.statements[0].sql.contains("VALUES (?1, ?2, ?3, ?4)"));
    assert!(plan.statements[1].sql.contains("?8"));
    assert!(plan
        .statements
        .iter()
        .all(|statement| !statement.sql.contains('$')));
}

#[test]
fn local_persistence_seed_sql_plan_rejects_invalid_seed() {
    let mut seed = local_persistence_seed();
    seed.signer_b_share.root_share_epoch = RootShareEpoch::new("epoch-2").expect("epoch 2");

    let err = local_persistence_seed_sql_plan_v1(&seed, LocalPersistenceSqlDialectV1::Postgres)
        .expect_err("invalid seed must fail before SQL generation");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn local_persistence_sql_execution_harness_runs_statements_in_order() {
    let plan = local_persistence_seed_sql_plan_v1(
        &local_persistence_seed(),
        LocalPersistenceSqlDialectV1::Sqlite,
    )
    .expect("sqlite seed plan");
    let mut executor = RecordingSqlExecutor::default();

    let receipt = execute_local_persistence_sql_seed_plan_v1(&plan, &mut executor)
        .expect("execute seed plan");

    assert_eq!(receipt.dialect, LocalPersistenceSqlDialectV1::Sqlite);
    assert_eq!(receipt.executed_statement_count, 3);
    assert_eq!(executor.calls.len(), 3);
    assert_eq!(executor.calls[0].0, LocalPersistenceSqlDialectV1::Sqlite);
    assert_eq!(executor.calls[0].1, 0);
    assert!(executor.calls[0].2.sql.contains("local_signing_roots"));
    assert_eq!(executor.calls[1].1, 1);
    assert!(executor.calls[1].2.sql.contains("local_sealed_root_shares"));
    assert_eq!(executor.calls[2].1, 2);
    assert_eq!(
        executor.calls[2].2.values[1],
        LocalPersistenceSqlValueV1::Text("signer_b".to_owned())
    );
}

#[test]
fn local_persistence_sql_execution_harness_stops_on_executor_error() {
    let plan = local_persistence_seed_sql_plan_v1(
        &local_persistence_seed(),
        LocalPersistenceSqlDialectV1::Postgres,
    )
    .expect("postgres seed plan");
    let mut executor = FailingSqlExecutor::default();

    let err = execute_local_persistence_sql_seed_plan_v1(&plan, &mut executor)
        .expect_err("executor failure must stop seed execution");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
    assert_eq!(executor.calls, vec![0, 1]);
}

#[test]
fn local_service_startup_pairs_service_with_matching_env_snapshot() {
    let router =
        LocalServiceStartupV1::router(router_endpoint(), router_env_snapshot()).expect("router");
    assert_eq!(router.role(), LocalServiceRoleV1::Router);

    let signer_a = LocalServiceStartupV1::signer_a_relayer(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
        signer_a_env_snapshot(),
    )
    .expect("signer a startup");
    assert_eq!(signer_a.role(), LocalServiceRoleV1::SignerARelayer);

    let signer_b = LocalServiceStartupV1::signer_b(
        signer_b_endpoint(),
        signer_b_identity(),
        signer_b_env_snapshot(),
    )
    .expect("signer b startup");
    assert_eq!(signer_b.role(), LocalServiceRoleV1::SignerB);
}

#[test]
fn local_service_startup_rejects_env_role_mismatch() {
    let err = LocalServiceStartupV1::router(router_endpoint(), signer_b_env_snapshot())
        .expect_err("router startup must reject signer b env");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn local_service_stack_runs_in_process_ceremony_from_startup_configs() {
    let stack = LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint(), router_env_snapshot()).expect("router"),
        LocalServiceStartupV1::signer_a_relayer(
            signer_a_endpoint(),
            signer_a_identity(),
            relayer_identity(),
            signer_a_env_snapshot(),
        )
        .expect("signer a startup"),
        LocalServiceStartupV1::signer_b(
            signer_b_endpoint(),
            signer_b_identity(),
            signer_b_env_snapshot(),
        )
        .expect("signer b startup"),
    )
    .expect("local service stack");
    let result = stack
        .run_deterministic_ceremony(
            "lifecycle-1",
            wire(WireMessageKindV1::RouterToSignerA),
            wire(WireMessageKindV1::RouterToSignerB),
        )
        .expect("in-process ceremony");

    assert_eq!(
        result.collected_responses.signer_a_response.route,
        LocalTransportRouteV1::SignerAToRouter
    );
    assert_eq!(
        result.collected_responses.signer_b_response.route,
        LocalTransportRouteV1::SignerBToRouter
    );
    assert_eq!(
        result.signer_a_peer_message.route,
        LocalTransportRouteV1::SignerAToSignerB
    );
    assert_eq!(
        result.signer_b_peer_message.route,
        LocalTransportRouteV1::SignerBToSignerA
    );
    assert_eq!(
        result.relayer_activation.route,
        LocalTransportRouteV1::SignerBToSignerARelayer
    );
    assert_eq!(
        result.relayer_activation_receipt.relayer,
        relayer_identity()
    );

    let signer_a_response =
        decode_local_signer_response(&result.collected_responses.signer_a_response);
    let signer_b_response =
        decode_local_signer_response(&result.collected_responses.signer_b_response);
    let activation = decode_local_relayer_activation(&result.relayer_activation);
    assert_eq!(
        signer_a_response.transcript_digest,
        local_valid_transcript_digest()
    );
    assert_eq!(
        signer_b_response.transcript_digest,
        local_valid_transcript_digest()
    );
    assert_eq!(
        signer_a_response.client_output.package_commitment(),
        signer_b_response.client_output.package_commitment()
    );
    verify_client_output_package_v1(
        &signer_a_response.client_output,
        local_valid_transcript_digest(),
    )
    .expect("client output verifies");
    assert_eq!(
        activation.transcript_digest,
        local_valid_transcript_digest()
    );
    verify_relayer_output_package_v1(&activation.relayer_output, local_valid_transcript_digest())
        .expect("relayer output verifies");
    assert_ne!(
        signer_a_response.client_output.package_commitment(),
        activation.relayer_output.package_commitment()
    );
}

#[test]
fn local_http_request_binds_method_path_and_route() {
    let request = http_request(
        LocalHttpPathV1::RouterToSignerA,
        LocalTransportRouteV1::RouterToSignerA,
        WireMessageKindV1::RouterToSignerA,
    );

    assert_eq!(request.method, LocalHttpMethodV1::Post);
    assert_eq!(request.path.as_str(), "/local/router/signer-a");
    assert_eq!(
        request.path.expected_route(),
        LocalTransportRouteV1::RouterToSignerA
    );
}

#[test]
fn local_http_request_rejects_non_post_method() {
    let err = LocalHttpRequestV1::new(
        LocalHttpMethodV1::Get,
        LocalHttpPathV1::RouterToSignerA,
        transport(
            LocalTransportRouteV1::RouterToSignerA,
            WireMessageKindV1::RouterToSignerA,
        ),
    )
    .expect_err("GET request must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest
    );
}

#[test]
fn local_http_request_rejects_path_route_mismatch() {
    let err = LocalHttpRequestV1::new(
        LocalHttpMethodV1::Post,
        LocalHttpPathV1::RouterToSignerA,
        transport(
            LocalTransportRouteV1::RouterToSignerB,
            WireMessageKindV1::RouterToSignerB,
        ),
    )
    .expect_err("path and route mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest
    );
}

#[test]
fn local_service_stack_runs_http_ceremony_from_router_requests() {
    let stack = LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint(), router_env_snapshot()).expect("router"),
        LocalServiceStartupV1::signer_a_relayer(
            signer_a_endpoint(),
            signer_a_identity(),
            relayer_identity(),
            signer_a_env_snapshot(),
        )
        .expect("signer a startup"),
        LocalServiceStartupV1::signer_b(
            signer_b_endpoint(),
            signer_b_identity(),
            signer_b_env_snapshot(),
        )
        .expect("signer b startup"),
    )
    .expect("local service stack");

    let result = stack
        .run_deterministic_http_ceremony(
            "lifecycle-1",
            http_request(
                LocalHttpPathV1::RouterToSignerA,
                LocalTransportRouteV1::RouterToSignerA,
                WireMessageKindV1::RouterToSignerA,
            ),
            http_request(
                LocalHttpPathV1::RouterToSignerB,
                LocalTransportRouteV1::RouterToSignerB,
                WireMessageKindV1::RouterToSignerB,
            ),
        )
        .expect("http ceremony");

    assert_eq!(result.signer_a_response.status, LocalHttpStatusV1::Ok);
    assert_eq!(result.signer_a_response.status.status_code(), 200);
    assert_eq!(
        result.signer_a_peer_request.path,
        LocalHttpPathV1::SignerAToSignerB
    );
    assert_eq!(
        result.signer_b_peer_request.path,
        LocalHttpPathV1::SignerBToSignerA
    );
    assert_eq!(
        result.relayer_activation_request.path,
        LocalHttpPathV1::SignerBToSignerARelayer
    );
    assert_eq!(
        result.relayer_activation_receipt.relayer,
        relayer_identity()
    );
}

#[test]
fn local_signer_a_rejects_signer_b_router_request() {
    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a relayer service");
    let context = signer_a_context();
    let err = signer_a
        .handle_router_request(
            context,
            transport(
                LocalTransportRouteV1::RouterToSignerB,
                WireMessageKindV1::RouterToSignerB,
            ),
        )
        .expect_err("signer a must reject signer b router request");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_signer_b_rejects_signer_a_router_request() {
    let signer_b =
        LocalSignerBServiceV1::new(signer_b_endpoint(), signer_b_identity()).expect("signer b");
    let context = signer_b_context();
    let err = signer_b
        .handle_router_request(
            context,
            transport(
                LocalTransportRouteV1::RouterToSignerA,
                WireMessageKindV1::RouterToSignerA,
            ),
        )
        .expect_err("signer b must reject signer a router request");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_router_rejects_peer_message_as_signer_response() {
    let router = LocalRouterServiceV1::new(router_endpoint()).expect("router service");
    let signer_a_peer = transport(
        LocalTransportRouteV1::SignerAToSignerB,
        WireMessageKindV1::SignerAToSignerB,
    );
    let signer_b_response = transport(
        LocalTransportRouteV1::SignerBToRouter,
        WireMessageKindV1::SignerResponse,
    );
    let err = router
        .collect_signer_responses(signer_a_peer, signer_b_response)
        .expect_err("router must reject peer message as signer response");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_relayer_activation_rejects_signer_response_payload_kind() {
    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a relayer service");
    let signer_b_response = transport(
        LocalTransportRouteV1::SignerBToRouter,
        WireMessageKindV1::SignerResponse,
    );
    let err = signer_a
        .accept_relayer_activation(signer_b_response)
        .expect_err("relayer activation must reject signer response payload kind");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_relayer_activation_route_rejects_signer_response_wire_kind() {
    let err = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::SignerBToSignerARelayer,
        wire(WireMessageKindV1::SignerResponse),
    )
    .expect_err("relayer activation route must reject signer response wire kind");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_service_stack_handles_one_client_router_request() {
    let stack = LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint(), router_env_snapshot()).expect("router"),
        LocalServiceStartupV1::signer_a_relayer(
            signer_a_endpoint(),
            signer_a_identity(),
            relayer_identity(),
            signer_a_env_snapshot(),
        )
        .expect("signer a startup"),
        LocalServiceStartupV1::signer_b(
            signer_b_endpoint(),
            signer_b_identity(),
            signer_b_env_snapshot(),
        )
        .expect("signer b startup"),
    )
    .expect("local service stack");
    let result = stack
        .handle_local_client_request(1_000, client_router_request())
        .expect("client request");

    assert_eq!(result.signer_a_response.status, LocalHttpStatusV1::Ok);
    assert_eq!(result.signer_b_response.status, LocalHttpStatusV1::Ok);
    assert_eq!(
        result.relayer_activation_request.path,
        LocalHttpPathV1::SignerBToSignerARelayer
    );
}

#[test]
fn local_client_router_request_rejects_transcript_mismatch() {
    let err = LocalClientRouterRequestV1::new(
        "lifecycle-1",
        "request-nonce-1",
        2_000,
        http_request_with_digest(
            LocalHttpPathV1::RouterToSignerA,
            LocalTransportRouteV1::RouterToSignerA,
            WireMessageKindV1::RouterToSignerA,
            digest(0x11),
        ),
        http_request_with_digest(
            LocalHttpPathV1::RouterToSignerB,
            LocalTransportRouteV1::RouterToSignerB,
            WireMessageKindV1::RouterToSignerB,
            digest(0x22),
        ),
    )
    .expect_err("client request transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn local_client_router_request_rejects_expired_request() {
    let request = client_router_request();
    let err = request
        .validate_at(2_000)
        .expect_err("expired request must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn local_replay_cache_rejects_replayed_client_request_nonce() {
    let stack = LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint(), router_env_snapshot()).expect("router"),
        LocalServiceStartupV1::signer_a_relayer(
            signer_a_endpoint(),
            signer_a_identity(),
            relayer_identity(),
            signer_a_env_snapshot(),
        )
        .expect("signer a startup"),
        LocalServiceStartupV1::signer_b(
            signer_b_endpoint(),
            signer_b_identity(),
            signer_b_env_snapshot(),
        )
        .expect("signer b startup"),
    )
    .expect("local service stack");
    let mut replay_cache = LocalReplayCacheV1::new();

    stack
        .handle_local_client_request_with_replay_cache(
            1_000,
            &mut replay_cache,
            client_router_request(),
        )
        .expect("first request");
    let err = stack
        .handle_local_client_request_with_replay_cache(
            1_000,
            &mut replay_cache,
            client_router_request(),
        )
        .expect_err("replayed request must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
}

#[test]
fn local_transport_route_binds_expected_wire_kind() {
    let envelope = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::RouterToSignerA,
        wire(WireMessageKindV1::RouterToSignerA),
    )
    .expect("local transport envelope");

    assert_eq!(envelope.route.source(), LocalServiceRoleV1::Router);
    assert_eq!(
        envelope.route.destination(),
        LocalServiceRoleV1::SignerARelayer
    );
    assert_eq!(
        envelope.route.expected_wire_kind(),
        WireMessageKindV1::RouterToSignerA
    );
}

#[test]
fn local_transport_route_rejects_wrong_wire_kind() {
    let err = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::RouterToSignerA,
        wire(WireMessageKindV1::RouterToSignerB),
    )
    .expect_err("wrong wire kind must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_transport_models_relayer_activation_to_signer_a() {
    let envelope = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::SignerBToSignerARelayer,
        wire(WireMessageKindV1::RelayerActivation),
    )
    .expect("relayer activation transport");

    assert_eq!(envelope.route.source(), LocalServiceRoleV1::SignerB);
    assert_eq!(
        envelope.route.destination(),
        LocalServiceRoleV1::SignerARelayer
    );
}

#[test]
fn local_router_service_dispatches_and_collects_checked_envelopes() {
    let router = LocalRouterServiceV1::new(router_endpoint()).expect("router service");
    let dispatch = router
        .dispatch_signer_requests(
            wire(WireMessageKindV1::RouterToSignerA),
            wire(WireMessageKindV1::RouterToSignerB),
        )
        .expect("dispatch");

    assert_eq!(
        dispatch.to_signer_a.route,
        LocalTransportRouteV1::RouterToSignerA
    );
    assert_eq!(
        dispatch.to_signer_b.route,
        LocalTransportRouteV1::RouterToSignerB
    );

    let signer_a_response = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::SignerAToRouter,
        wire(WireMessageKindV1::SignerResponse),
    )
    .expect("signer a response");
    let signer_b_response = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::SignerBToRouter,
        wire(WireMessageKindV1::SignerResponse),
    )
    .expect("signer b response");
    let collected = router
        .collect_signer_responses(signer_a_response, signer_b_response)
        .expect("collected");

    assert_eq!(
        collected.signer_a_response.route,
        LocalTransportRouteV1::SignerAToRouter
    );
    assert_eq!(
        collected.signer_b_response.route,
        LocalTransportRouteV1::SignerBToRouter
    );
}

#[test]
fn local_router_dispatches_opaque_signer_payloads_without_plaintext_access() {
    let router = LocalRouterServiceV1::new(router_endpoint()).expect("router service");
    let transcript_digest = digest(0x33);
    let dispatch = router
        .dispatch_signer_requests(
            malformed_router_to_signer_wire(WireMessageKindV1::RouterToSignerA, transcript_digest),
            malformed_router_to_signer_wire(WireMessageKindV1::RouterToSignerB, transcript_digest),
        )
        .expect("router should forward opaque signer payloads");

    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a");
    let err = signer_a
        .handle_router_request(signer_a_context(), dispatch.to_signer_a)
        .expect_err("signer decodes and rejects malformed payload");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn local_router_service_rejects_transcript_mismatch() {
    let router = LocalRouterServiceV1::new(router_endpoint()).expect("router service");
    let err = router
        .dispatch_signer_requests(
            wire_with_digest(WireMessageKindV1::RouterToSignerA, digest(0x11)),
            wire_with_digest(WireMessageKindV1::RouterToSignerB, digest(0x22)),
        )
        .expect_err("transcript mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn local_signer_handlers_return_peer_proof_batch_envelopes() {
    let router = LocalRouterServiceV1::new(router_endpoint()).expect("router service");
    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a relayer service");
    let signer_b =
        LocalSignerBServiceV1::new(signer_b_endpoint(), signer_b_identity()).expect("signer b");
    let dispatch = router
        .dispatch_signer_requests(
            wire(WireMessageKindV1::RouterToSignerA),
            wire(WireMessageKindV1::RouterToSignerB),
        )
        .expect("dispatch");

    let signer_a_context = signer_a_context();
    let signer_b_context = signer_b_context();
    let signer_a_output = signer_a
        .handle_router_request(signer_a_context, dispatch.to_signer_a)
        .expect("signer a output");
    let signer_b_output = signer_b
        .handle_router_request(signer_b_context, dispatch.to_signer_b)
        .expect("signer b output");

    let signer_a_proof_batch = match &signer_a_output {
        LocalSignerHandlerOutputV1::SignerA { peer_message } => {
            assert_eq!(peer_message.route, LocalTransportRouteV1::SignerAToSignerB);
            let proof_batch = decode_local_peer_proof_batch(peer_message);
            assert_eq!(proof_batch.from, signer_a_identity());
            assert_eq!(proof_batch.to, signer_b_identity());
            assert_eq!(proof_batch.root_share_epoch, root_epoch());
            assert_eq!(proof_batch.proof_bundles.len(), 2);
            assert!(proof_batch.proof_bundles.iter().any(|bundle| {
                bundle.signer_partial.binding.opened_share_kind == OpenedShareKind::XClientBase
            }));
            assert!(proof_batch.proof_bundles.iter().any(|bundle| {
                bundle.signer_partial.binding.opened_share_kind == OpenedShareKind::XRelayerBase
            }));
            proof_batch
        }
        other => panic!("unexpected signer a output: {other:?}"),
    };

    let signer_b_proof_batch = match &signer_b_output {
        LocalSignerHandlerOutputV1::SignerB { peer_message } => {
            assert_eq!(peer_message.route, LocalTransportRouteV1::SignerBToSignerA);
            let proof_batch = decode_local_peer_proof_batch(peer_message);
            assert_eq!(proof_batch.from, signer_b_identity());
            assert_eq!(proof_batch.to, signer_a_identity());
            assert_eq!(proof_batch.root_share_epoch, root_epoch());
            assert_eq!(proof_batch.proof_bundles.len(), 2);
            proof_batch
        }
        other => panic!("unexpected signer b output: {other:?}"),
    };

    assert_eq!(
        signer_a_proof_batch.transcript_digest,
        signer_b_proof_batch.transcript_digest
    );
}

#[test]
fn local_deterministic_decryptor_returns_bound_signer_input_plaintext() {
    let request = public_router_request();
    let (payload_a, _) = request.to_signer_payloads().expect("signer payloads");
    let context = signer_a_context();
    let plaintext = LocalDeterministicSignerEnvelopeDecryptorV1
        .decrypt_signer_input_plaintext(&context, &payload_a)
        .expect("local signer input plaintext");

    assert_eq!(plaintext.recipient_role, Role::SignerA);
    assert_eq!(plaintext.recipient_signer_id, "signer-a");
    assert_eq!(plaintext.root_share_epoch, root_epoch());
    assert_eq!(
        plaintext.router_request_digest,
        local_router_request_digest()
    );
    assert_eq!(plaintext.selected_relayer_id, "relayer-a");
}

#[test]
fn local_signer_handler_rejects_wrong_router_route() {
    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a relayer service");
    let context = signer_a_context();
    let wrong_route = LocalTransportEnvelopeV1::new(
        LocalTransportRouteV1::RouterToSignerB,
        wire(WireMessageKindV1::RouterToSignerB),
    )
    .expect("wrong route");
    let err = signer_a
        .handle_router_request(context, wrong_route)
        .expect_err("wrong route must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn local_signer_handler_rejects_malformed_router_payload() {
    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a relayer service");
    let context = signer_a_context();
    let malformed_message = WireMessageV1::new(
        WireMessageKindV1::RouterToSignerA,
        digest(0x33),
        CanonicalWireBytesV1::new(vec![0xab]).expect("payload"),
    )
    .expect("wire message");
    let request =
        LocalTransportEnvelopeV1::new(LocalTransportRouteV1::RouterToSignerA, malformed_message)
            .expect("transport envelope");

    let err = signer_a
        .handle_router_request(context, request)
        .expect_err("malformed Router payload must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn local_signer_handler_rejects_payload_for_other_local_signer() {
    let signer_a = LocalSignerARelayerServiceV1::new(
        signer_a_endpoint(),
        signer_a_identity(),
        relayer_identity(),
    )
    .expect("signer a relayer service");
    let other_signer_a =
        SignerIdentityV1::new(Role::SignerA, "other-signer-a", "epoch-a").expect("other signer a");
    let signer_set = SignerSetV1::v1_all2(
        "signer-set-v1",
        other_signer_a,
        signer_b_identity(),
        relayer_identity(),
    )
    .expect("signer set");
    let lifecycle = lifecycle_scope();
    let transcript_digest = router_transcript_digest_v1(
        &lifecycle,
        &signer_set,
        &transcript_metadata(),
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_epoch(),
    )
    .expect("custom signer-set transcript digest");
    let public_request = PublicRouterRequestV1::new(
        "request-nonce-1",
        2_000,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set,
        "near-testnet",
        "ed25519:local-dev-account-public-key",
        "local-router",
        "client",
        "x25519:local-dev-client-ephemeral-public-key",
        transcript_digest,
        role_envelope(Role::SignerA, 0xa0),
        role_envelope(Role::SignerB, 0xb0),
    )
    .expect("public request");
    let (signer_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("router-to-signer messages");
    let request =
        LocalTransportEnvelopeV1::new(LocalTransportRouteV1::RouterToSignerA, signer_a_message)
            .expect("transport envelope");
    let context = signer_a_context();

    let err = signer_a
        .handle_router_request(context, request)
        .expect_err("other signer assignment must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}
