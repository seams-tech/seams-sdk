use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use router_ab_cloudflare::{
    derive_cloudflare_router_trusted_admission_from_provider_v1,
    execute_cloudflare_router_public_admission_plan_v1, CloudflareDurableObjectBindingV1,
    CloudflareDurableObjectCallV1, CloudflareDurableObjectRequestV1,
    CloudflareDurableObjectResponseV1, CloudflareDurableObjectScopeV1,
    CloudflareLifecyclePutReceiptV1, CloudflarePeerBindingV1, CloudflareReplayReserveResponseV1,
    CloudflareRouterAbuseCheckV1, CloudflareRouterAdmissionChecksV1,
    CloudflareRouterAdmissionProviderOutputV1, CloudflareRouterAdmissionProviderV1,
    CloudflareRouterAuthContextV1, CloudflareRouterBindingsV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterPublicPlanExecutorV1, CloudflareRouterQuotaCheckV1,
    CloudflareRouterTrustedRequestMetadataV1, CloudflareRouterWorkerRuntimeV1,
    CloudflareWorkerRoleV1,
};
use router_ab_core::{
    router_transcript_digest_v1, CandidateId, CanonicalWireBytesV1, ExpensiveWorkKindV1,
    LifecycleScopeV1, PublicDigest32, PublicRouterRequestV1, RelayerIdentityV1, Role,
    RoleEncryptedEnvelopeV1, RootShareEpoch, RouterAbLifecycleStateV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, RouterTranscriptMetadataV1,
    SignerIdentityV1, SignerSetV1, WireMessageKindV1, WireMessageV1,
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

struct BenchmarkFixture {
    runtime: CloudflareRouterWorkerRuntimeV1,
    request: PublicRouterRequestV1,
    provider: StaticAdmissionProvider,
    executor: SimulatedRoundTripExecutor,
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
        let response = execute_cloudflare_router_public_admission_plan_v1(
            &self.runtime,
            &plan,
            &mut self.executor,
        )?;
        black_box(response);
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

impl CloudflareRouterPublicPlanExecutorV1 for SimulatedRoundTripExecutor {
    fn execute_durable_object_call(
        &mut self,
        call: &CloudflareDurableObjectCallV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
        call.validate()?;
        match &call.request {
            CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => {
                CloudflareDurableObjectResponseV1::router_replay_reserve(
                    CloudflareReplayReserveResponseV1::new(request.request_id.clone(), true)?,
                )
            }
            CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
                CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                    CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
                )
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "benchmark executor received unexpected Durable Object operation",
            )),
        }
    }

    fn send_signer_message(
        &mut self,
        _peer: &CloudflarePeerBindingV1,
        message: &WireMessageV1,
    ) -> RouterAbProtocolResult<WireMessageV1> {
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
        signer_response(message.transcript_digest, 0x80)
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
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

fn signer_response(
    transcript_digest: PublicDigest32,
    seed: u8,
) -> RouterAbProtocolResult<WireMessageV1> {
    WireMessageV1::new(
        WireMessageKindV1::SignerResponse,
        transcript_digest,
        CanonicalWireBytesV1::new(vec![seed, seed + 1]).expect("signer response bytes"),
    )
}

fn digest(byte: u8) -> PublicDigest32 {
    PublicDigest32::new([byte; 32])
}

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

criterion_group!(benches, bench_router_admission_and_simulated_roundtrips);
criterion_main!(benches);
