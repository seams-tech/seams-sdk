use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ed25519_hss::role_signing::{
    RoleSeparatedEd25519Round1SecretV1, RoleSeparatedEd25519Round1StateV1,
};
use router_ab_cloudflare::{
    derive_cloudflare_router_trusted_admission_from_provider_v1,
    handle_cloudflare_durable_object_call_v1,
    handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2,
    CloudflareActiveSigningWorkerStateLookupV1, CloudflareDurableObjectBindingV1,
    CloudflareDurableObjectCallV1, CloudflareDurableObjectMemoryStorageV1,
    CloudflareDurableObjectRequestV1, CloudflareDurableObjectScopeV1, CloudflarePeerBindingV1,
    CloudflareRouterAbuseCheckV1, CloudflareRouterAdmissionBindingsV1,
    CloudflareRouterAdmissionChecksV1, CloudflareRouterAdmissionProviderOutputV1,
    CloudflareRouterAdmissionProviderV1, CloudflareRouterAdmissionStoreBindingsV1,
    CloudflareRouterAuthContextV1, CloudflareRouterBindingsV1,
    CloudflareRouterJwtVerifierBindingV1,
    CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterPublicAdmissionPlanV1, CloudflareRouterQuotaCheckV1,
    CloudflareRouterTrustedRequestMetadataV1, CloudflareRouterVerifiedWalletSessionV1,
    CloudflareRouterWorkerRuntimeV1, CloudflareSecretMaterial32V1,
    CloudflareServerOutputMaterialRecordV1,
    CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    CloudflareSigningWorkerNormalSigningFinalizeHandlerV2,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    CloudflareSigningWorkerRecipientProofBundleActivationV1, CloudflareSigningWorkerRound1RecordV1,
    CloudflareWorkerRoleV1,
};
use router_ab_core::{
    decode_router_to_signer_payload_v1, router_transcript_digest_v1, ActiveSigningWorkerStateV1,
    CandidateId, CanonicalWireBytesV1, EncryptedPayloadV1, ExpensiveWorkKindV1, LifecycleScopeV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningResponseV1, NormalSigningScopeV1,
    OpenedShareKind, PublicDigest32, PublicRouterRequestV1, RecipientOutputEncryptionAlgorithmV1,
    RecipientProofBundleCiphertextV1, Role, RoleEncryptedEnvelopeV1, RootShareEpoch,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningIntentV2, RouterAbEd25519NormalSigningPrepareBindingV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519SigningPayloadV2,
    RouterAbEd25519TwoPartyFrostFinalizeProtocolV2, RouterAbLifecycleStateV1,
    RouterAbNearNetworkIdV2, RouterAbNearTransactionIntentV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, RouterToSignerPayloadV1,
    RouterTranscriptMetadataV1, ServerIdentityV1, SignerIdentityV1, SignerSetV1, WireMessageKindV1,
    WireMessageV1,
};
use sha2::{Digest as Sha2Digest, Sha256};

fn bench_router_admission_and_simulated_roundtrips(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_ab_setup_export_simulated_roundtrips_v1");
    for (operation, work_kind) in setup_export_refresh_work_kinds() {
        for round_trips in [1usize, 2, 3, 4] {
            group.bench_function(format!("{operation}_{round_trips}_roundtrips"), |b| {
                b.iter_batched(
                    || BenchmarkFixture::new(work_kind, round_trips),
                    |mut fixture| black_box(fixture.run()),
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn bench_router_normal_signing_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_ab_normal_signing_hot_path_v1");
    group.bench_function("router_to_signing_worker", |b| {
        b.iter_batched(
            NormalSigningBenchmarkFixture::new,
            |mut fixture| black_box(fixture.run()),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_ecdsa_hss_signing_worker_activation_storage(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_ab_ecdsa_hss_activation_storage_v1");
    group.bench_function("activate_and_lookup_active_state", |b| {
        b.iter_batched(
            ActivationBenchmarkFixture::new,
            |fixture| black_box(fixture.run()),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

struct BenchmarkFixture {
    runtime: CloudflareRouterWorkerRuntimeV1,
    request: PublicRouterRequestV1,
    provider: StaticAdmissionProvider,
    executor: SimulatedRoundTripExecutor,
}

struct NormalSigningBenchmarkFixture {
    runtime: CloudflareRouterWorkerRuntimeV1,
    prepare_request: RouterAbEd25519NormalSigningPrepareRequestV2,
    finalize_request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    wallet_session: CloudflareRouterVerifiedWalletSessionV1,
    checks: CloudflareRouterAdmissionChecksV1,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
    round1: CloudflareSigningWorkerRound1RecordV1,
    handler: BenchmarkNormalSigningHandler,
}

struct ActivationBenchmarkFixture {
    activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    material: CloudflareServerOutputMaterialRecordV1,
}

impl ActivationBenchmarkFixture {
    fn new() -> Self {
        let activation = signing_worker_activation();
        let material = activation_server_output_material_record(&activation);
        Self {
            activation,
            material,
        }
    }

    fn run(self) -> RouterAbProtocolResult<()> {
        let binding = signing_worker_output_binding();
        let activation_call = CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            binding.clone(),
            CloudflareDurableObjectRequestV1::signing_worker_output_activate(
                self.activation,
                self.material,
                1_000,
            )?,
        )?;
        let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
        let activation_response =
            handle_cloudflare_durable_object_call_v1(&activation_call, &mut storage)?;
        black_box(activation_response);

        let active_lookup_call = CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SigningWorker,
            binding,
            CloudflareDurableObjectRequestV1::signing_worker_output_active_state_get(
                CloudflareActiveSigningWorkerStateLookupV1::new(
                    "account.near",
                    "session-1",
                    "server-a",
                )?,
            )?,
        )?;
        let active_response =
            handle_cloudflare_durable_object_call_v1(&active_lookup_call, &mut storage)?;
        black_box(active_response);
        Ok(())
    }
}

impl NormalSigningBenchmarkFixture {
    fn new() -> Self {
        Self {
            runtime: router_runtime(),
            prepare_request: normal_signing_v2_prepare_request(2_000),
            finalize_request: normal_signing_v2_finalize_request(2_000),
            wallet_session: normal_signing_v2_wallet_session(3_000),
            checks: allow_checks("normal-signing-gate-request-1"),
            active_signing_worker: active_signing_worker_state_for_normal_signing(),
            material: normal_signing_material_record(),
            round1: normal_signing_round1_record(),
            handler: BenchmarkNormalSigningHandler,
        }
    }

    fn run(&mut self) -> RouterAbProtocolResult<()> {
        let prepare_admission =
            CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
                &self.wallet_session,
                &self.prepare_request,
                1_000,
            )?;
        let prepare_calls = self
            .runtime
            .normal_signing_v2_prepare_admission_store_calls_at(
                1_000,
                &self.prepare_request,
                &prepare_admission,
            )?;
        black_box(prepare_calls.project_policy.storage_key());
        black_box(prepare_calls.quota.storage_key());
        black_box(prepare_calls.abuse.storage_key());
        let replay_call = self
            .runtime
            .normal_signing_v2_prepare_replay_reserve_call(&self.prepare_request)?;
        black_box(replay_call.storage_key());

        let finalize_admission =
            CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
                &self.wallet_session,
                &self.finalize_request,
                1_000,
            )?;
        let admission_calls = self
            .runtime
            .normal_signing_v2_finalize_admission_store_calls_at(
                1_000,
                &self.finalize_request,
                &finalize_admission,
            )?;
        black_box(admission_calls.project_policy.storage_key());
        black_box(admission_calls.quota.storage_key());
        black_box(admission_calls.abuse.storage_key());
        let trusted_admission = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
            finalize_admission.to_v1_trusted_metadata()?,
            self.checks.to_gate_decision()?,
        )?;
        if !trusted_admission.allows_signing_worker_forwarding()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "benchmark normal-signing admission did not allow forwarding",
            ));
        }
        let response = handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2(
            &self.handler,
            1_000,
            CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
                self.finalize_request.clone(),
                trusted_admission,
            )?,
            self.active_signing_worker.clone(),
            self.material.clone(),
            self.round1.clone(),
        )?;
        response.validate_for_v2_finalize_request(&self.finalize_request)?;
        black_box(response);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkNormalSigningHandler;

impl CloudflareSigningWorkerNormalSigningFinalizeHandlerV2 for BenchmarkNormalSigningHandler {
    fn handle_normal_signing_finalize_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1> {
        request.validate()?;
        let finalize_request = &request.request.request;
        NormalSigningResponseV1::new(
            finalize_request.scope.clone(),
            finalize_request.signing_payload_digest(),
            request.active_signing_worker.signing_worker.clone(),
            finalize_request.protocol.signature_scheme(),
            CanonicalWireBytesV1::new(vec![0x9a; 64]).expect("normal signing signature"),
            request.active_signing_worker.activated_at_ms + 1,
        )
    }
}

impl BenchmarkFixture {
    fn new(work_kind: ExpensiveWorkKindV1, round_trips: usize) -> Self {
        Self {
            runtime: router_runtime(),
            request: public_router_request(work_kind, 2_000),
            provider: StaticAdmissionProvider::new(
                CloudflareRouterAdmissionProviderOutputV1::new(
                    trusted_metadata(work_kind),
                    allow_checks("gate-request-1"),
                )
                .expect("provider output"),
            ),
            executor: SimulatedRoundTripExecutor::new(round_trips),
        }
    }

    fn run(&mut self) -> RouterAbProtocolResult<()> {
        let trusted_admission = derive_cloudflare_router_trusted_admission_from_provider_v1(
            &self.request,
            &mut self.provider,
        )?;
        let plan = self.runtime.public_request_admission_plan_at(
            1_000,
            self.request.clone(),
            trusted_admission,
        )?;
        black_box(plan.replay_reserve_call().storage_key());
        black_box(plan.lifecycle_put_call().storage_key());
        if let CloudflareRouterPublicAdmissionPlanV1::Forward {
            deriver_a_message,
            deriver_b_message,
            ..
        } = &plan
        {
            self.executor.send_signer_message(deriver_a_message)?;
            self.executor.send_signer_message(deriver_b_message)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct StaticAdmissionProvider {
    output: CloudflareRouterAdmissionProviderOutputV1,
}

impl StaticAdmissionProvider {
    fn new(output: CloudflareRouterAdmissionProviderOutputV1) -> Self {
        Self { output }
    }
}

impl CloudflareRouterAdmissionProviderV1 for StaticAdmissionProvider {
    fn evaluate_public_request_admission(
        &mut self,
        _request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1> {
        Ok(self.output.clone())
    }
}

struct SimulatedRoundTripExecutor {
    round_trips: usize,
}

impl SimulatedRoundTripExecutor {
    fn new(round_trips: usize) -> Self {
        Self { round_trips }
    }
}

impl SimulatedRoundTripExecutor {
    fn send_signer_message(&mut self, message: &WireMessageV1) -> RouterAbProtocolResult<()> {
        for _ in 0..self.round_trips {
            let json = serde_json::to_vec(message).map_err(|err| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("benchmark wire JSON encode failed: {err}"),
                )
            })?;
            let decoded: WireMessageV1 = serde_json::from_slice(&json).map_err(|err| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("benchmark wire JSON decode failed: {err}"),
                )
            })?;
            black_box(decoded.digest());
            black_box(decoded.canonical_bytes());
        }
        Ok(())
    }
}

fn router_runtime() -> CloudflareRouterWorkerRuntimeV1 {
    CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::SignerA, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime")
}

fn do_binding(
    scope: CloudflareDurableObjectScopeV1,
    binding_name: &str,
) -> CloudflareDurableObjectBindingV1 {
    CloudflareDurableObjectBindingV1::new(
        scope,
        binding_name,
        format!("{binding_name}-object"),
        format!("{binding_name}:"),
    )
    .expect("durable object binding")
}

fn signing_worker_output_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::ServerOutput {
            owner_role: CloudflareWorkerRoleV1::SigningWorker,
        },
        "SIGNING_WORKER_SERVER_OUTPUT_DO",
    )
}

fn router_admission_bindings() -> CloudflareRouterAdmissionBindingsV1 {
    CloudflareRouterAdmissionBindingsV1::new(
        CloudflareRouterJwtVerifierBindingV1::new(
            "https://issuer.example",
            "router-ab",
            "https://issuer.example/.well-known/jwks.json",
        )
        .expect("jwt verifier binding"),
        CloudflareRouterAdmissionStoreBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterProjectPolicy,
                "ROUTER_PROJECT_POLICY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterQuota,
                "ROUTER_QUOTA_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterAbuse,
                "ROUTER_ABUSE_DO",
            ),
        )
        .expect("admission store bindings"),
    )
    .expect("router admission bindings")
}

fn peer(peer_role: CloudflareWorkerRoleV1, binding_name: &str) -> CloudflarePeerBindingV1 {
    CloudflarePeerBindingV1::new(peer_role, binding_name).expect("peer binding")
}

fn setup_export_refresh_work_kinds() -> [(&'static str, ExpensiveWorkKindV1); 3] {
    [
        ("registration", ExpensiveWorkKindV1::RegistrationPrepare),
        ("export", ExpensiveWorkKindV1::KeyExport),
        ("refresh", ExpensiveWorkKindV1::ServerShareRefresh),
    ]
}

fn trusted_metadata(work_kind: ExpensiveWorkKindV1) -> CloudflareRouterTrustedRequestMetadataV1 {
    CloudflareRouterTrustedRequestMetadataV1::new(
        work_kind,
        "org-1",
        "project-1",
        "dev",
        "account.near",
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
    )
    .expect("trusted metadata")
}

fn allow_checks(request_id: &str) -> CloudflareRouterAdmissionChecksV1 {
    CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Allowed,
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: request_id.to_owned(),
        },
    )
    .expect("admission checks")
}

fn public_router_request(
    work_kind: ExpensiveWorkKindV1,
    expires_at_ms: u64,
) -> PublicRouterRequestV1 {
    let lifecycle = lifecycle_scope(work_kind);
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    PublicRouterRequestV1::new(
        "request-nonce-1",
        expires_at_ms,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set,
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        role_envelope(Role::SignerA, 0x10),
        role_envelope(Role::SignerB, 0x20),
    )
    .expect("public router request")
}

fn signing_worker_activation() -> CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    let router_payload = router_payload_for_signing_worker_activation();
    let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
        server_proof_bundle_wire(&router_payload, Role::SignerA, 0x46),
        server_proof_bundle_wire(&router_payload, Role::SignerB, 0x47),
    )
    .expect("strict SigningWorker proof-bundle activation");
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1::new(router_payload, activation)
        .expect("strict SigningWorker activation request")
}

fn activation_server_output_material_record(
    activation: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
) -> CloudflareServerOutputMaterialRecordV1 {
    let selected_server = &activation.activation_context.signer_set().selected_server;
    CloudflareServerOutputMaterialRecordV1::new(
        activation.activation_context.transcript_digest(),
        OpenedShareKind::XServerBase,
        Role::Server,
        selected_server.server_id.clone(),
        CloudflareSecretMaterial32V1::new([0x5a; 32]),
    )
    .expect("server output material record")
}

fn router_payload_for_signing_worker_activation() -> RouterToSignerPayloadV1 {
    let (deriver_a, _) = public_router_request(ExpensiveWorkKindV1::RegistrationPrepare, 2_000)
        .to_signer_wire_messages()
        .expect("router-to-signer messages");
    decode_router_to_signer_payload_v1(deriver_a.payload.as_bytes()).expect("router payload")
}

fn server_proof_bundle_wire(
    router_payload: &RouterToSignerPayloadV1,
    signer_role: Role,
    nonce_seed: u8,
) -> WireMessageV1 {
    let server = &router_payload.signer_set().selected_server;
    let envelope = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        signer_identity(signer_role),
        Role::Server,
        OpenedShareKind::XServerBase,
        server.server_id.clone(),
        server.recipient_encryption_key.clone(),
        router_payload.transcript_digest(),
        digest(nonce_seed.wrapping_add(0x10)),
        [nonce_seed; 12],
        EncryptedPayloadV1::new(vec![nonce_seed, nonce_seed.wrapping_add(1)])
            .expect("proof-bundle ciphertext"),
    )
    .expect("recipient proof-bundle envelope");
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        router_payload.transcript_digest(),
        CanonicalWireBytesV1::new(envelope.canonical_bytes().expect("proof-bundle bytes"))
            .expect("wire payload"),
    )
    .expect("recipient proof-bundle wire")
}

fn signer_identity(role: Role) -> SignerIdentityV1 {
    match role {
        Role::SignerA => signer_set().signer_a,
        Role::SignerB => signer_set().signer_b,
        _ => panic!("activation benchmark signer role must be Signer A or Signer B"),
    }
}

fn normal_signing_v2_wallet_session(expires_at_ms: u64) -> CloudflareRouterVerifiedWalletSessionV1 {
    CloudflareRouterVerifiedWalletSessionV1::new(
        "user-1",
        "account.near",
        "session-1",
        "org-1",
        "project-1",
        "dev",
        "normal-signing",
        "server-a",
        digest(0x90),
        expires_at_ms,
    )
    .expect("normal signing wallet session")
}

fn normal_signing_v2_prepare_request(
    expires_at_ms: u64,
) -> RouterAbEd25519NormalSigningPrepareRequestV2 {
    let unsigned_transaction_borsh = normal_signing_v2_unsigned_transaction_borsh();
    let unsigned_transaction_borsh_b64u = b64u(&unsigned_transaction_borsh);
    let intent = RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
        operation_id: "operation-1".to_owned(),
        operation_fingerprint: "fingerprint-1".to_owned(),
        near_account_id: "account.near".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        transactions: vec![RouterAbNearTransactionIntentV1::new(
            "receiver.near",
            normal_signing_v2_action_fingerprint(),
        )
        .expect("transaction intent")],
        unsigned_transaction_borsh_b64u: unsigned_transaction_borsh_b64u.clone(),
    };
    let signing_payload = RouterAbEd25519SigningPayloadV2::NearUnsignedTransactionBorshV1 {
        unsigned_transaction_borsh_b64u,
        expected_signing_digest_b64u: sha256_digest_b64u(&unsigned_transaction_borsh),
    };
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        NormalSigningScopeV1::new("sign-request-1", "account.near", "session-1", "server-a")
            .expect("normal signing scope"),
        expires_at_ms,
        intent,
        signing_payload,
    )
    .expect("normal signing v2 prepare request")
}

fn normal_signing_v2_finalize_request(
    expires_at_ms: u64,
) -> RouterAbEd25519NormalSigningFinalizeRequestV2 {
    let prepare = normal_signing_v2_prepare_request(expires_at_ms);
    let material = prepare.admission_material().expect("admission material");
    let prepare_binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        prepare.round1_binding_digest().expect("round1 binding"),
        material.intent_digest,
        material.signing_payload_digest,
    )
    .expect("prepare binding");
    let protocol = RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
        RouterAbEd25519TwoPartyFrostFinalizeProtocolV2::new(
            NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                b64u(&[0x11; 32]),
                b64u(&[0x12; 32]),
            )
            .expect("client commitments"),
            NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                b64u(&[0x21; 32]),
                b64u(&[0x22; 32]),
            )
            .expect("server commitments"),
            b64u(&[0x31; 32]),
            b64u(&[0x32; 32]),
            b64u(&[0x41; 32]),
        )
        .expect("finalize protocol"),
    );
    RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        NormalSigningScopeV1::new("sign-request-1", "account.near", "session-1", "server-a")
            .expect("normal signing scope"),
        expires_at_ms,
        prepare_binding,
        protocol,
    )
    .expect("normal signing v2 finalize request")
}

fn active_signing_worker_state_for_normal_signing() -> ActiveSigningWorkerStateV1 {
    ActiveSigningWorkerStateV1::new(
        "account.near",
        "session-1",
        "ed25519:account-public-key",
        signer_set().selected_server,
        digest(0x81),
        digest(0x82),
        "signing-worker-output/lifecycle-1/material",
        1_000,
    )
    .expect("active SigningWorker state")
}

fn normal_signing_material_record() -> CloudflareServerOutputMaterialRecordV1 {
    CloudflareServerOutputMaterialRecordV1::new(
        digest(0x81),
        router_ab_core::OpenedShareKind::XServerBase,
        Role::Server,
        "server-a",
        CloudflareSecretMaterial32V1::new([0x5a; 32]),
    )
    .expect("normal signing material")
}

fn normal_signing_round1_record() -> CloudflareSigningWorkerRound1RecordV1 {
    let prepare = normal_signing_v2_prepare_request(2_000);
    let material = prepare.admission_material().expect("admission material");
    CloudflareSigningWorkerRound1RecordV1::new(
        active_signing_worker_state_for_normal_signing(),
        "server-round1/sign-request-1",
        prepare.round1_binding_digest().expect("round1 binding"),
        material.admitted_signing_digest,
        RoleSeparatedEd25519Round1StateV1::new(
            RoleSeparatedEd25519Round1SecretV1::new(scalar_bytes(11), scalar_bytes(12))
                .expect("round1 secret"),
        )
        .expect("round1 state"),
        1_000,
        2_000,
    )
    .expect("normal signing round1 record")
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn lifecycle_scope(work_kind: ExpensiveWorkKindV1) -> LifecycleScopeV1 {
    let operation = work_kind.primitive_request_kind().as_str();
    RouterAbLifecycleStateV1::requested(
        LifecycleScopeV1::new(
            format!("lifecycle-{operation}-1"),
            work_kind,
            root_epoch(),
            "account.near",
            "session-1",
            "signer-set-v1",
            "server-a",
        )
        .expect("lifecycle scope"),
    )
    .expect("lifecycle state")
    .scope()
    .clone()
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

fn public_request_transcript_digest(
    lifecycle: &LifecycleScopeV1,
    signer_set: &SignerSetV1,
) -> PublicDigest32 {
    router_transcript_digest_v1(
        lifecycle,
        signer_set,
        &RouterTranscriptMetadataV1::new(
            "near-mainnet",
            "ed25519:account-public-key",
            "router-1",
            "client-1",
            "x25519:client-ephemeral-public-key",
        )
        .expect("transcript metadata"),
        CandidateId::MpcThresholdPrfV1,
        router_ab_core::CorrectnessLevel::MinimumLevelC,
        root_epoch(),
    )
    .expect("public request transcript digest")
}

fn role_envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed + 1),
        router_ab_core::EncryptedPayloadV1::new(vec![seed, seed + 1]).expect("ciphertext"),
    )
    .expect("role envelope")
}

fn digest(byte: u8) -> PublicDigest32 {
    PublicDigest32::new([byte; 32])
}

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_digest_b64u(bytes: &[u8]) -> String {
    b64u(&Sha256::digest(bytes))
}

fn push_borsh_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_borsh_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn normal_signing_v2_unsigned_transaction_borsh() -> Vec<u8> {
    let mut out = Vec::new();
    push_borsh_string(&mut out, "account.near");
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out.extend_from_slice(&7_u64.to_le_bytes());
    push_borsh_string(&mut out, "receiver.near");
    out.extend_from_slice(&[0x44; 32]);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(2);
    push_borsh_string(&mut out, "transfer");
    push_borsh_bytes(&mut out, br#"{"amount":"1"}"#);
    out.extend_from_slice(&30_000_000_000_000_u64.to_le_bytes());
    out.extend_from_slice(&0_u128.to_le_bytes());
    out
}

fn normal_signing_v2_action_fingerprint() -> String {
    sha256_digest_b64u(
        r#"[{"action_type":"FunctionCall","args":"{\"amount\":\"1\"}","deposit":"0","gas":"30000000000000","method_name":"transfer"}]"#
            .as_bytes(),
    )
}

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

criterion_group!(
    benches,
    bench_router_admission_and_simulated_roundtrips,
    bench_router_normal_signing_hot_path,
    bench_ecdsa_hss_signing_worker_activation_storage
);
criterion_main!(benches);
