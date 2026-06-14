use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use router_ab_cloudflare::{
    build_cloudflare_router_to_signing_worker_normal_signing_request_v1,
    derive_cloudflare_router_normal_signing_trusted_admission_v1,
    derive_cloudflare_router_trusted_admission_from_provider_v1,
    handle_cloudflare_signing_worker_normal_signing_private_request_v1,
    CloudflareDurableObjectBindingV1, CloudflareDurableObjectScopeV1, CloudflarePeerBindingV1,
    CloudflareRelayerOutputMaterialRecordV1, CloudflareRouterAbuseCheckV1,
    CloudflareRouterAdmissionBindingsV1, CloudflareRouterAdmissionChecksV1,
    CloudflareRouterAdmissionProviderOutputV1, CloudflareRouterAdmissionProviderV1,
    CloudflareRouterAdmissionStoreBindingsV1, CloudflareRouterAuthContextV1,
    CloudflareRouterBindingsV1, CloudflareRouterJwtVerifierBindingV1,
    CloudflareRouterNormalSigningTrustedMetadataV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterPublicAdmissionPlanV1, CloudflareRouterQuotaCheckV1,
    CloudflareRouterTrustedRequestMetadataV1, CloudflareRouterWorkerRuntimeV1,
    CloudflareSecretMaterial32V1, CloudflareSigningWorkerAdmittedNormalSigningRequestV1,
    CloudflareSigningWorkerMaterializedNormalSigningRequestV1,
    CloudflareSigningWorkerNormalSigningHandlerV1, CloudflareWorkerRoleV1,
};
use router_ab_core::{
    router_transcript_digest_v1, ActiveSigningWorkerStateV1, CandidateId, CanonicalWireBytesV1,
    ExpensiveWorkKindV1, LifecycleScopeV1, NormalSigningRequestV1, NormalSigningResponseV1,
    NormalSigningScopeV1, NormalSigningSignatureSchemeV1, PublicDigest32, PublicRouterRequestV1,
    RelayerIdentityV1, Role, RoleEncryptedEnvelopeV1, RootShareEpoch, RouterAbLifecycleStateV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
    RouterTranscriptMetadataV1, SignerIdentityV1, SignerSetV1, WireMessageV1,
};

fn bench_router_admission_and_simulated_roundtrips(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_ab_setup_export_simulated_roundtrips_v1");
    for round_trips in [1usize, 2, 3, 4] {
        group.bench_function(format!("{round_trips}_roundtrips"), |b| {
            b.iter_batched(
                || BenchmarkFixture::new(round_trips),
                |mut fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            )
        });
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

struct BenchmarkFixture {
    runtime: CloudflareRouterWorkerRuntimeV1,
    request: PublicRouterRequestV1,
    provider: StaticAdmissionProvider,
    executor: SimulatedRoundTripExecutor,
}

struct NormalSigningBenchmarkFixture {
    runtime: CloudflareRouterWorkerRuntimeV1,
    request: NormalSigningRequestV1,
    metadata: CloudflareRouterNormalSigningTrustedMetadataV1,
    checks: CloudflareRouterAdmissionChecksV1,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareRelayerOutputMaterialRecordV1,
    handler: BenchmarkNormalSigningHandler,
}

impl NormalSigningBenchmarkFixture {
    fn new() -> Self {
        Self {
            runtime: router_runtime(),
            request: normal_signing_request(2_000),
            metadata: normal_signing_trusted_metadata(),
            checks: allow_checks("normal-signing-gate-request-1"),
            active_signing_worker: active_signing_worker_state_for_normal_signing(),
            material: normal_signing_material_record(),
            handler: BenchmarkNormalSigningHandler,
        }
    }

    fn run(&mut self) -> RouterAbProtocolResult<()> {
        let admission = derive_cloudflare_router_normal_signing_trusted_admission_v1(
            &self.request,
            self.metadata.clone(),
            self.checks.clone(),
        )?;
        if !admission.allows_signing_worker_forwarding()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "benchmark normal-signing admission did not allow forwarding",
            ));
        }
        let admission_calls = self.runtime.normal_signing_admission_store_calls_at(
            1_000,
            &self.request,
            self.metadata.clone(),
        )?;
        black_box(admission_calls.project_policy.storage_key());
        black_box(admission_calls.quota.storage_key());
        black_box(admission_calls.abuse.storage_key());
        let replay_call = self
            .runtime
            .normal_signing_replay_reserve_call(&self.request)?;
        black_box(replay_call.storage_key());
        let forwarded = build_cloudflare_router_to_signing_worker_normal_signing_request_v1(
            1_000,
            self.request.clone(),
            self.active_signing_worker.clone(),
        )?;
        forwarded.validate()?;
        black_box(forwarded);
        let response = handle_cloudflare_signing_worker_normal_signing_private_request_v1(
            &self.handler,
            1_000,
            CloudflareSigningWorkerAdmittedNormalSigningRequestV1::new(
                self.request.clone(),
                admission,
            )?,
            self.active_signing_worker.clone(),
            self.material.clone(),
        )?;
        response.validate_for_request(&self.request)?;
        black_box(response);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkNormalSigningHandler;

impl CloudflareSigningWorkerNormalSigningHandlerV1 for BenchmarkNormalSigningHandler {
    fn handle_normal_signing_request(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningRequestV1,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1> {
        request.validate()?;
        let forwarded = &request.forwarded;
        NormalSigningResponseV1::new(
            forwarded.request.scope.clone(),
            forwarded.request.signing_payload_digest(),
            forwarded.active_signing_worker.signing_worker.clone(),
            NormalSigningSignatureSchemeV1::Ed25519V1,
            CanonicalWireBytesV1::new(vec![0x9a; 64]).expect("normal signing signature"),
            forwarded.active_signing_worker.activated_at_ms + 1,
        )
    }
}

impl BenchmarkFixture {
    fn new(round_trips: usize) -> Self {
        Self {
            runtime: router_runtime(),
            request: public_router_request(2_000),
            provider: StaticAdmissionProvider::new(
                CloudflareRouterAdmissionProviderOutputV1::new(
                    trusted_metadata(),
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

fn trusted_metadata() -> CloudflareRouterTrustedRequestMetadataV1 {
    CloudflareRouterTrustedRequestMetadataV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
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

fn normal_signing_trusted_metadata() -> CloudflareRouterNormalSigningTrustedMetadataV1 {
    CloudflareRouterNormalSigningTrustedMetadataV1::new(
        "org-1",
        "project-1",
        "dev",
        "account.near",
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
        digest(0x91),
    )
    .expect("normal signing trusted metadata")
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

fn public_router_request(expires_at_ms: u64) -> PublicRouterRequestV1 {
    let lifecycle = lifecycle_scope();
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

fn normal_signing_request(expires_at_ms: u64) -> NormalSigningRequestV1 {
    NormalSigningRequestV1::new(
        NormalSigningScopeV1::new("sign-request-1", "account.near", "session-1", "relayer-a")
            .expect("normal signing scope"),
        expires_at_ms,
        digest(0x91),
        CanonicalWireBytesV1::new(vec![0x7a, 0x7b, 0x7c]).expect("normal signing payload"),
    )
    .expect("normal signing request")
}

fn active_signing_worker_state_for_normal_signing() -> ActiveSigningWorkerStateV1 {
    ActiveSigningWorkerStateV1::new(
        "account.near",
        "session-1",
        signer_set().selected_relayer,
        digest(0x81),
        digest(0x82),
        "signing-worker-output/lifecycle-1/material",
        1_000,
    )
    .expect("active SigningWorker state")
}

fn normal_signing_material_record() -> CloudflareRelayerOutputMaterialRecordV1 {
    CloudflareRelayerOutputMaterialRecordV1::new(
        digest(0x81),
        router_ab_core::OpenedShareKind::XRelayerBase,
        Role::Relayer,
        "relayer-a",
        CloudflareSecretMaterial32V1::new([0x5a; 32]),
    )
    .expect("normal signing material")
}

fn lifecycle_scope() -> LifecycleScopeV1 {
    RouterAbLifecycleStateV1::requested(
        LifecycleScopeV1::new(
            "lifecycle-1",
            ExpensiveWorkKindV1::RegistrationPrepare,
            root_epoch(),
            "account.near",
            "session-1",
            "signer-set-v1",
            "relayer-a",
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
        RelayerIdentityV1::new(
            "relayer-a",
            "relayer-epoch",
            "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("relayer"),
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

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

criterion_group!(
    benches,
    bench_router_admission_and_simulated_roundtrips,
    bench_router_normal_signing_hot_path
);
criterion_main!(benches);
